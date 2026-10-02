using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises actual historical-return HTTP and PostgreSQL transactions with synthetic paid attestations.</summary>
public sealed class HistoricalReturnPostgreSqlTests
{
    /// <summary>A paid return creates one present-day ownership and receipt, preserving the exact key and unrelated authority.</summary>
    [Fact]
    public async Task ActiveExpired_AdoptsAndPaysExactlyOnce()
    {
        await using var f = await Fixture.CreateAsync(); var before = await f.ReadAsync();
        var request = await RequestAsync(f);
        using var response = await f.Client.PostAsJsonAsync(ReturnUrl(f), request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var replay = await f.Client.PostAsJsonAsync(ReturnUrl(f), request);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var after = await f.ReadAsync();
        Assert.Equal(before.LicenseKey, after.LicenseKey); Assert.True(after.IsActive);
        Assert.Equal(f.Start.AddDays(30), after.ExpirationDate);
        Assert.Equal(before.HardwareId, after.HardwareId); Assert.Equal(before.ActivationDate, after.ActivationDate);
        Assert.Null(after.ProvisioningRequestId);
        await using var db = f.Db();
        Assert.Single(await db.RuntimeRecoveryCommercialOwnerships.ToListAsync());
        Assert.Single(await db.LicenseHistories.ToListAsync());
        Assert.Empty(await db.LicenseProvisioningRequests.ToListAsync());
        Assert.Empty(await db.RuntimeRecoveryGrantOwnerships.ToListAsync());
        Assert.Empty(await db.LicenseSeats.ToListAsync());
    }

    /// <summary>All omissions and duplicate aliases fail before creating present-day authority.</summary>
    [Fact]
    public async Task StrictEnvelope_RejectsMissingUnknownAndDuplicateFields()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        foreach (var group in new[] { "", "Historical", "Payment", "ExpectedType", "DesiredType" })
        {
            var obj = group == "" ? request : request[group]!.AsObject();
            foreach (var key in obj.Select(p => p.Key).ToArray())
            {
                var invalid = request.DeepClone().AsObject();
                (group == "" ? invalid : invalid[group]!.AsObject()).Remove(key);
                await AssertStatusAsync(f, invalid, HttpStatusCode.BadRequest);
            }
        }
        var extra = request.DeepClone().AsObject(); extra["Unknown"] = true;
        await AssertStatusAsync(f, extra, HttpStatusCode.BadRequest);
        var alias = request.DeepClone().AsObject(); alias["operationId"] = request["OperationId"]!.DeepClone();
        await AssertStatusAsync(f, alias, HttpStatusCode.BadRequest);
        await AssertUnownedAsync(f);
    }

    /// <summary>Existing ownership of every state blocks adoption, including retained terminal lineage.</summary>
    [Theory]
    [InlineData("ACTIVE")]
    [InlineData("REVOKED")]
    [InlineData("TRANSFERRED")]
    [InlineData("PENDING_TRANSFER")]
    public async Task ExistingOwnership_AllStatesRefused(string state)
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        await using var db = f.Db();
        db.Add(new RuntimeRecoveryCommercialOwnership { Id = f.OwnershipId, ProductId = f.ProductId,
            LicenseId = f.LicenseId, OwnerSubjectId = f.SubjectId, State = state, CreatedAtUtc = f.Start.AddDays(-5),
            EndedAtUtc = state == "ACTIVE" ? null : f.Start.AddDays(-1) });
        await db.SaveChangesAsync();
        await AssertStatusAsync(f, request, HttpStatusCode.Conflict);
        Assert.Single(await db.RuntimeRecoveryCommercialOwnerships.ToListAsync());
        Assert.Empty(await db.LicenseHistories.ToListAsync());
    }

    /// <summary>Paid declarations cannot adopt resellers, new licenses, free types or changed configuration.</summary>
    [Theory]
    [InlineData("partner")]
    [InlineData("new-license")]
    [InlineData("free")]
    [InlineData("configuration")]
    [InlineData("security")]
    public async Task ProtectedAuthority_IsNotAdopted(string change)
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f); await using var db = f.Db();
        if (change == "partner") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"PartnerCode\"='reseller-fixture' WHERE \"Id\"={f.LicenseId}");
        if (change == "new-license") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"CreationDate\"={f.Start.AddMonths(1)} WHERE \"Id\"={f.LicenseId}");
        if (change == "free") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"IsFree\"=true WHERE \"ProductId\"={f.ProductId}");
        if (change == "configuration") await f.ChangeTypeAsync("parameter");
        if (change == "security") await f.SecurityRevokeAsync();
        await AssertStatusAsync(f, request, HttpStatusCode.Conflict); await AssertUnownedAsync(f);
    }

    /// <summary>Nonpaid, refunded, disputed, stale and ambiguous funding never creates ownership.</summary>
    [Fact]
    public async Task InvalidPayment_AndIdentityAreRejected()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        foreach (var pair in new (string Key, JsonNode? Value)[] { ("AmountPaidCents", JsonValue.Create(0)),
            ("RefundFree", JsonValue.Create(false)), ("DisputeFree", JsonValue.Create(false)),
            ("Currency", JsonValue.Create("EUR")), ("PaymentIntentId", JsonValue.Create(" pi-leading")),
            ("PeriodEndUtc", JsonValue.Create(f.Start.AddDays(-1))) })
        {
            var invalid = request.DeepClone().AsObject(); invalid["Payment"]![pair.Key] = pair.Value;
            await AssertStatusAsync(f, invalid, HttpStatusCode.BadRequest);
        }
        var wrong = request.DeepClone().AsObject(); wrong["Historical"]!["ProviderLicenseId"] = Guid.NewGuid().ToString();
        await AssertStatusAsync(f, wrong, HttpStatusCode.BadRequest);
        var key = request.DeepClone().AsObject(); key["Historical"]!["LicenseKey"] = Guid.NewGuid().ToString();
        await AssertStatusAsync(f, key, HttpStatusCode.Conflict);
        await AssertUnownedAsync(f);
    }

    /// <summary>An explicit terminal attestation can clear only its exact observed legacy cause after paid replacement.</summary>
    [Fact]
    public async Task LegacyTerminated_RequiresCompleteAdministrativeAttestation()
    {
        await using var f = await Fixture.CreateAsync(); await using var db = f.Db();
        var revoked = f.Start.AddDays(-1);
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\"=false, \"RevocationReason\"='Stripe renewal failed (invoice in-old)', \"RevokedAt\"={revoked} WHERE \"Id\"={f.LicenseId}");
        var request = await RequestAsync(f); request["Mode"] = "LEGACY_TERMINATED";
        await AssertStatusAsync(f, request, HttpStatusCode.BadRequest);
        request["Terminal"] = JsonSerializer.SerializeToNode(new { InvoiceId = "in-old", SubscriptionId = "sub-old", CustomerId = "cus-fixture",
            LedgerId = "termination-fixture", LedgerSha256 = new string('b',64), GraceStartedAtUtc = revoked.AddHours(-24),
            TerminatedAtUtc = revoked, InvoiceVoidedAtUtc = revoked, SubscriptionCanceledAtUtc = revoked,
            ProviderRevokedAtUtc = revoked, DeactivationCorrelationId = "7caa21aa-a612-5fc3-aa21-572ea684191b", InvoiceVoid = true, SubscriptionCanceled = true });
        foreach (var field in new[] { "InvoiceVoid", "SubscriptionCanceled" })
        {
            var incomplete = request.DeepClone().AsObject(); incomplete["Terminal"]![field] = false;
            await AssertStatusAsync(f, incomplete, HttpStatusCode.Conflict);
        }
        var foreign = request.DeepClone().AsObject(); foreign["Terminal"]!["CustomerId"] = "cus-other";
        await AssertStatusAsync(f, foreign, HttpStatusCode.Conflict);
        // Legacy Website terminates at H24. Even one microsecond earlier is not an authorized terminal cause.
        var premature = request.DeepClone().AsObject();
        premature["Terminal"]!["GraceStartedAtUtc"] = JsonValue.Create(revoked.AddHours(-24).AddTicks(10));
        await AssertStatusAsync(f, premature, HttpStatusCode.Conflict);
        await AssertUnownedAsync(f);
        await AssertStatusAsync(f, request, HttpStatusCode.OK);
        var after = await f.ReadAsync(); Assert.True(after.IsActive); Assert.Null(after.RevocationReason);
        Assert.Equal(f.Start.AddDays(30), after.ExpirationDate);
        var history = Assert.Single(await db.LicenseHistories.ToListAsync());
        Assert.Equal("HISTORICAL_RETURN_PAID_V1", history.Action); Assert.Contains("WEBSITE_HISTORICAL_RETURN_V1", history.Details);
        Assert.DoesNotContain("SUSPEND", history.Details); Assert.DoesNotContain("ISSUED", history.Details);
    }

    /// <summary>Freshness is per attempt: outage recovery retains operation/payment identity and replay cannot revive a later revoke.</summary>
    [Fact]
    public async Task DelayedFirstAttempt_AndLostResponseRetainStableOperation()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        f.Clock.Now = f.Start.AddMinutes(2);
        await AssertStatusAsync(f, request, HttpStatusCode.Conflict); await AssertUnownedAsync(f);
        request["Payment"]!["ObservedAtUtc"] = JsonValue.Create(f.Clock.Now);
        await AssertStatusAsync(f, request, HttpStatusCode.OK);
        f.Clock.Now = f.Start.AddMinutes(5);
        request["Payment"]!["ObservedAtUtc"] = JsonValue.Create(f.Clock.Now);
        await AssertStatusAsync(f, request, HttpStatusCode.OK);
        var changed = request.DeepClone().AsObject(); changed["Payment"]!["AmountPaidCents"] = 2001;
        await AssertStatusAsync(f, changed, HttpStatusCode.Conflict);
        await f.SecurityRevokeAsync();
        await AssertStatusAsync(f, request, HttpStatusCode.Conflict);
        Assert.False((await f.ReadAsync()).IsActive);
    }

    /// <summary>Two competing subjects cannot both acquire one key; stale authority cannot bypass the winning ownership.</summary>
    [Fact]
    public async Task ConcurrentAdoption_HasOnlyOneWinner()
    {
        await using var f = await Fixture.CreateAsync(); var first = await RequestAsync(f); var second = await RequestAsync(f);
        second["CommercialSubjectId"] = Guid.NewGuid().ToString(); second["Payment"]!["InvoiceId"] = "in-other";
        second["Payment"]!["PaymentIntentId"] = "pi-other";
        var responses = await Task.WhenAll(f.Client.PostAsJsonAsync(ReturnUrl(f),first), f.Client.PostAsJsonAsync(ReturnUrl(f),second));
        try { Assert.Single(responses, r => r.StatusCode == HttpStatusCode.OK);
            Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Conflict); }
        finally { foreach (var response in responses) response.Dispose(); }
        await using var db = f.Db(); Assert.Single(await db.RuntimeRecoveryCommercialOwnerships.ToListAsync());
        Assert.Single(await db.LicenseHistories.ToListAsync());
    }

    /// <summary>A provider SQL writer winning the license lock invalidates the already frozen request.</summary>
    [Fact]
    public async Task RevokeDuringRequest_IsProtectedByCurrentCas()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        await using var db = f.Db(); await using var tx = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\"=false, \"RevocationReason\"='security_review', \"RevokedAt\"={f.Start} WHERE \"Id\"={f.LicenseId}");
        var pending = f.Client.PostAsJsonAsync(ReturnUrl(f), request); await f.WaitForLockAsync("999831");
        await tx.CommitAsync(); using var response = await pending; Assert.Equal(HttpStatusCode.Conflict,response.StatusCode);
        await AssertUnownedAsync(f);
    }

    /// <summary>A late receipt failure rolls back both paid authority and the new ownership.</summary>
    [Fact]
    public async Task ReceiptFailure_RollsBackEverything()
    {
        await using var f = await Fixture.CreateAsync(); var before = await f.ReadAsync(); var request = await RequestAsync(f);
        await using var db = f.Db();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION fixture_reject_return() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic receipt failure'; END $$;
            CREATE TRIGGER fixture_reject_return BEFORE INSERT ON "LicenseHistories"
            FOR EACH ROW EXECUTE FUNCTION fixture_reject_return();
            """);
        using var response = await f.Client.PostAsJsonAsync(ReturnUrl(f),request);
        Assert.Equal(HttpStatusCode.InternalServerError,response.StatusCode);
        Assert.Equal(before.AuthorityVersion,(await f.ReadAsync()).AuthorityVersion); await AssertUnownedAsync(f);
    }

    /// <summary>Checks actual HTTP status with bounded synthetic diagnostics.</summary>
    private static async Task AssertStatusAsync(Fixture f, JsonObject request, HttpStatusCode expected)
    {
        using var response = await f.Client.PostAsJsonAsync(ReturnUrl(f),request);
        Assert.True(response.StatusCode == expected, $"Expected {expected}, got {response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
    }

    /// <summary>Verifies refused operations leave no ownership or successful receipt in PostgreSQL.</summary>
    private static async Task AssertUnownedAsync(Fixture f)
    {
        await using var db = f.Db(); Assert.Empty(await db.RuntimeRecoveryCommercialOwnerships.ToListAsync());
        Assert.Empty(await db.LicenseHistories.ToListAsync());
    }

    /// <summary>A payment intent, invoice or frozen historical identity cannot be reused for another key.</summary>
    [Fact]
    public async Task FundingAndHistoricalIdentity_AreUniqueAcrossLicenses()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f); var first = await f.ReadAsync();
        await AssertStatusAsync(f, request, HttpStatusCode.OK);
        await using var db = f.Db();
        var second = new License { ProductId = f.ProductId, LicenseKey = Guid.NewGuid().ToString("D"),
            LicenseTypeId = first.LicenseTypeId, CreationDate = first.CreationDate, ExpirationDate = first.ExpirationDate,
            IsActive = true, MaxSeats = first.MaxSeats };
        db.Add(second); await db.SaveChangesAsync(); await db.Entry(second).ReloadAsync();
        foreach (var boundary in new[] { "invoice", "payment-intent", "historical-identity" })
        {
            var duplicate = request.DeepClone().AsObject(); duplicate["OperationId"] = Guid.NewGuid().ToString();
            duplicate["LicenseId"] = second.Id.ToString(); duplicate["ExpectedAuthorityVersion"] = second.AuthorityVersion.ToString();
            duplicate["Historical"]!["ProviderLicenseId"] = second.Id.ToString(); duplicate["Historical"]!["LicenseKey"] = second.LicenseKey;
            if (boundary != "historical-identity") duplicate["Historical"]!["LocalLicenseId"] = "second-historical";
            if (boundary != "invoice") duplicate["Payment"]!["InvoiceId"] = "in-second";
            if (boundary != "payment-intent") duplicate["Payment"]!["PaymentIntentId"] = "pi-second";
            using var response = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{second.LicenseKey}/historical-return-conditional",duplicate);
            Assert.Equal(HttpStatusCode.Conflict,response.StatusCode);
        }
        Assert.Single(await db.RuntimeRecoveryCommercialOwnerships.ToListAsync());
        Assert.Single(await db.LicenseHistories.ToListAsync());
        Assert.Equal(second.AuthorityVersion,(await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == second.Id)).AuthorityVersion);
    }

    /// <summary>An uncommitted terminal SQL insertion wins before the adoption's all-state read, with no inferred restoration.</summary>
    [Fact]
    public async Task TerminalOwnershipInsertedDuringRequest_IsObservedUnderLocks()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        await using var db = f.Db(); await using var tx = await db.Database.BeginTransactionAsync();
        db.Add(new RuntimeRecoveryCommercialOwnership { Id = f.OwnershipId, ProductId = f.ProductId, LicenseId = f.LicenseId,
            OwnerSubjectId = f.SubjectId, State = "REVOKED", CreatedAtUtc = f.Start.AddDays(-2), EndedAtUtc = f.Start.AddDays(-1) });
        await db.SaveChangesAsync();
        var pending = f.Client.PostAsJsonAsync(ReturnUrl(f),request); await f.WaitForLockAsync("FOR UPDATE");
        await tx.CommitAsync(); using var response = await pending; Assert.Equal(HttpStatusCode.Conflict,response.StatusCode);
        Assert.Equal("REVOKED",(await db.RuntimeRecoveryCommercialOwnerships.SingleAsync()).State);
        Assert.Empty(await db.LicenseHistories.ToListAsync());
    }

    /// <summary>Transferred ownership invalidates replay even when the license authority itself is unchanged.</summary>
    [Fact]
    public async Task TransferAfterReturn_InvalidatesReplay()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        await AssertStatusAsync(f,request,HttpStatusCode.OK); await using var db = f.Db();
        var owner = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync();
        var target = new RuntimeRecoveryCommercialSubject { Id = Guid.NewGuid(), ProductId = f.ProductId, CreatedAtUtc = f.Start };
        db.Add(target); await db.SaveChangesAsync();
        using var response = await f.Client.PostAsJsonAsync($"/api/admin/products/{f.ProductId}/runtime-recovery-commercial-ownership-commands",
            new { CommandId = Guid.NewGuid(), Operation = "TRANSFER_OWNERSHIP", LicenseId = f.LicenseId,
                ExpectedOwnershipId = owner.Id, TargetCommercialSubjectId = target.Id });
        Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        await AssertStatusAsync(f,request,HttpStatusCode.Conflict);
    }

    /// <summary>Both missing authentication and a different product credential fail before disclosing or changing ownership.</summary>
    [Fact]
    public async Task AuthenticationAndProductScope_AreRequired()
    {
        await using var f = await Fixture.CreateAsync(); var request = await RequestAsync(f);
        f.Client.DefaultRequestHeaders.Remove("X-Admin-Secret");
        await AssertStatusAsync(f,request,HttpStatusCode.Unauthorized);
        await using var db = f.Db(); db.Add(new Product { Name = "unrelated", ApiSecret = "synthetic-other-product" }); await db.SaveChangesAsync();
        f.Client.DefaultRequestHeaders.Add("X-Admin-Secret","synthetic-other-product");
        await AssertStatusAsync(f,request,HttpStatusCode.Unauthorized); await AssertUnownedAsync(f);
    }

    /// <summary>Matching legacy text does not authorize a security cause, and terminal identity omissions remain closed.</summary>
    [Fact]
    public async Task InactiveSecurityCause_CannotBeAttestedAsBilling()
    {
        await using var f = await Fixture.CreateAsync(); await f.SecurityRevokeAsync();
        var request = await RequestAsync(f);
        await AssertStatusAsync(f,request,HttpStatusCode.Conflict);
        request["Mode"] = "LEGACY_TERMINATED";
        await AssertStatusAsync(f,request,HttpStatusCode.BadRequest); await AssertUnownedAsync(f);
    }

    /// <summary>The additive receipt does not change the existing exact-owner observation and subsequent PAID protocol.</summary>
    [Fact]
    public async Task ExistingBillingConsumer_AcceptsCurrentAdoptedOwner()
    {
        await using var f = await Fixture.CreateAsync(); await AssertStatusAsync(f,await RequestAsync(f),HttpStatusCode.OK);
        await using var db = f.Db(); var owner = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(); var current = await f.ReadAsync();
        using var observation = await f.Client.PostAsJsonAsync(f.AuthorityUrl,
            new AdminController.LicenseBillingAuthorityRequest(current.Id,current.ProductId,f.SubjectId,owner.Id,current.AuthorityVersion));
        Assert.Equal(HttpStatusCode.OK,observation.StatusCode);
        var paid = await f.RequestAsync("PAID");
        paid = paid with { ExpectedOwnershipId = owner.Id, PeriodEndUtc = f.Start.AddDays(60), InvoiceId = "in-following", SubscriptionId = "sub-new" };
        await f.OkAsync(paid); Assert.Equal(f.Start.AddDays(60),(await f.ReadAsync()).ExpirationDate);
        Assert.Single(await db.RuntimeRecoveryCommercialOwnerships.ToListAsync());
        Assert.Equal(2,await db.LicenseHistories.CountAsync());
    }

    /// <summary>Builds a complete versioned Website declaration; no real billing or identity data is used.</summary>
    private static async Task<JsonObject> RequestAsync(Fixture f)
    {
        var l = await f.ReadAsync(); var type = await f.TypeAsync(l.LicenseTypeId);
        return JsonSerializer.SerializeToNode(new {
            OperationId = Guid.NewGuid(), Provenance = "WEBSITE_HISTORICAL_RETURN_V1", Mode = "ACTIVE_EXPIRED",
            LicenseId = l.Id, ProductId = l.ProductId, CommercialSubjectId = f.SubjectId,
            ExpectedOwnershipState = "ABSENT", ExpectedAuthorityVersion = l.AuthorityVersion,
            ExpectedAuthorityIsActive = l.IsActive, ExpectedRevocationReason = l.RevocationReason,
            ExpectedRevokedAt = l.RevokedAt, ExpectedExpirationUtc = l.ExpirationDate,
            ExpectedMaxSeats = l.MaxSeats, ExpectedType = type, DesiredType = type, DesiredMaxSeats = l.MaxSeats,
            Historical = new { LocalLicenseId = "historical-fixture", UserId = "user-fixture", LicenseKey = l.LicenseKey,
                ProviderLicenseId = l.Id, SubscriptionId = "sub-old", LicenseCreatedAtUtc = f.Start.AddDays(-30),
                RecordedAtUtc = f.Start, SnapshotSha256 = new string('a',64) },
            Payment = new { OrderId = "order-new", CustomerId = "cus-fixture", SubscriptionId = "sub-new",
                InvoiceId = "in-new", PaymentIntentId = "pi-new", AmountPaidCents = 2000L, Currency = "eur",
                PeriodStartUtc = f.Start, PeriodEndUtc = f.Start.AddDays(30), PaidAtUtc = f.Start,
                ObservedAtUtc = f.Start, RefundFree = true, DisputeFree = true },
            Terminal = (object?)null
        })!.AsObject();
    }

    /// <summary>Uses the same synthetic key as the existing billing fixture through a separate additive route.</summary>
    private static string ReturnUrl(Fixture f) => f.Url.Replace("billing-conditional", "historical-return-conditional", StringComparison.Ordinal);
    /// <summary>Mutable deterministic test clock, registered only in the isolated HTTP host.</summary>
    private sealed class Clock : TimeProvider
    {
        /// <summary>Exact UTC instant chosen by each boundary test, without real-time sleeps.</summary>
        public DateTime Now { get; set; } = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);
        /// <summary>Returns the explicitly controlled test instant.</summary>
        public override DateTimeOffset GetUtcNow() => new(Now);
    }

    /// <summary>HTTP-only hook for observing a concurrent blocked writer immediately before the owned UPDATE.</summary>
    private sealed class UpdateInterceptor : DbCommandInterceptor
    {
        /// <summary>One-shot callback that must observe contention without awaiting the blocked operation.</summary>
        public Func<Task>? Callback { get; set; }
        /// <summary>Runs a single concurrency checkpoint before SQL execution; independent fixture contexts bypass it.</summary>
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (Callback is { } callback && command.CommandText.Contains("UPDATE \"Licenses\"", StringComparison.Ordinal))
            { Callback = null; await callback(); }
            return result;
        }
    }

    /// <summary>Owns one generated local database and HTTP host; always disposes both, including initialization failures.</summary>
    private sealed class Fixture : IAsyncDisposable
    {
        /// <summary>Explicit loopback maintenance endpoint; never read from production configuration.</summary>
        private readonly string maintenance;
        /// <summary>Generated, validated ASCII database name exclusively owned by this fixture.</summary>
        private readonly string database;
        /// <summary>Private ephemeral PostgreSQL connection, never logged by fixture code.</summary>
        private readonly string connection;
        /// <summary>Owned local HTTP host with all database services replaced before startup.</summary>
        private readonly WebApplicationFactory<Program> host;
        /// <summary>Per-fixture concurrency hook used only by HTTP requests.</summary>
        private readonly UpdateInterceptor interceptor = new();
        /// <summary>Stable synthetic commercial subject, independent from the fixture email.</summary>
        public Guid SubjectId { get; } = Guid.NewGuid();
        /// <summary>Stable synthetic initial ownership ID; transfer creates a different successor.</summary>
        public Guid OwnershipId { get; } = Guid.NewGuid();
        /// <summary>Stable license UUID shared by HTTP and independent SQL assertions.</summary>
        public Guid LicenseId { get; } = Guid.NewGuid();
        /// <summary>Exact product UUID captured during synthetic initialization.</summary>
        public Guid ProductId { get; private set; }
        /// <summary>Exact synthetic key; retained only in test memory and isolated PostgreSQL.</summary>
        private string Key { get; } = Guid.NewGuid().ToString("D");
        /// <summary>Fixed initial period boundary, independent from subsequent injected clock movement.</summary>
        public DateTime Start { get; } = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);
        /// <summary>Clock used by the conditional billing route, not by unrelated providers.</summary>
        public Clock Clock { get; } = new();
        /// <summary>Authenticated TestServer client; no actual Stripe or external HTTP service is configured.</summary>
        public HttpClient Client { get; }
        /// <summary>Local relative route containing the fixture-owned license key.</summary>
        public string Url => $"/api/admin/licenses/{Key}/billing-conditional";
        /// <summary>Read-only exact-owner authority route, independent of any billing operation receipt.</summary>
        public string AuthorityUrl => $"/api/admin/licenses/{Key}/billing-authority";
        /// <summary>Installs a one-shot test-only checkpoint before the next license UPDATE.</summary>
        public Func<Task>? BeforeUpdate { set => interceptor.Callback = value; }

        /// <summary>Configures isolated HTTP services and explicit synthetic auth before creating the client.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance; this.database = database; this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.ConfigureLogging(logging => logging.ClearProviders());
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", "tkt1011-local-fixture-secret");
                builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
                // Replace every database registration so no production connection can be resolved.
                builder.ConfigureServices(services => {
                    // Background processors are outside this contract and must not race fixture migrations or disposal.
                    services.RemoveAll<IHostedService>();
                    services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                    services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                    services.RemoveAll<IDbContextFactory<LicenseDbContext>>(); services.RemoveAll<LicenseDbContext>();
                    services.AddDbContextFactory<LicenseDbContext>(o => o.UseNpgsql(connection).AddInterceptors(interceptor));
                    services.AddSingleton<TimeProvider>(Clock);
                });
            });
            Client = host.CreateClient();
            Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt1011-local-fixture-secret");
        }

        /// <summary>Creates a fresh observation context without HTTP interception or stale tracking.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);
        /// <summary>Reads committed license state from the actual fixture database.</summary>
        public async Task<License> ReadAsync() { await using var db = Db(); return await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == LicenseId); }
        /// <summary>Posts one exact body over HTTP; callers own and dispose the response.</summary>
        public Task<HttpResponseMessage> PostAsync(AdminController.ConditionalLicenseBillingRequest request) => Client.PostAsJsonAsync(Url, request);
        /// <summary>Reads historical receipt evidence with the exact immutable body; no command is reapplied.</summary>
        public Task<HttpResponseMessage> ObserveAsync(AdminController.ConditionalLicenseBillingRequest request) =>
            Client.PostAsJsonAsync($"/api/admin/licenses/{Key}/billing-receipt", request);
        /// <summary>Checks status and includes only synthetic response diagnostics on failure.</summary>
        public async Task StatusAsync(AdminController.ConditionalLicenseBillingRequest request, HttpStatusCode expected)
        { using var response = await PostAsync(request); Assert.True(response.StatusCode == expected, $"Expected {expected}, got {response.StatusCode}: {await response.Content.ReadAsStringAsync()}"); }
        /// <summary>Requires a real HTTP acknowledgement; its body is intentionally not used as SQL evidence.</summary>
        public Task OkAsync(AdminController.ConditionalLicenseBillingRequest request) => StatusAsync(request, HttpStatusCode.OK);

        /// <summary>Builds an exact complete configuration from PostgreSQL for the requested type.</summary>
        public async Task<AdminController.BillingTypeSnapshot> TypeAsync(Guid id)
        {
            await using var db = Db(); var t = await db.LicenseTypes.Include(x => x.CustomParams).SingleAsync(x => x.Id == id);
            return new(t.Id, t.Slug, t.DefaultDurationDays, t.IsRecurring, t.DefaultAllowedVersions, t.DefaultMaxSeats,
                t.MaxActivationsPerDay, t.AllowAnonymous, t.IsFree, t.EnforceSingleUsePerHardwareId, t.DisableNewActivations,
                t.CustomParams.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new AdminController.BillingParameter(p.Key, p.Value)).ToArray());
        }

        /// <summary>Constructs fresh expected authority while retaining one exact synthetic billing cycle.</summary>
        public async Task<AdminController.ConditionalLicenseBillingRequest> RequestAsync(string command, Guid? previous = null)
        {
            var l = await ReadAsync(); var t = await TypeAsync(l.LicenseTypeId);
            return new(Guid.NewGuid(), command, l.Id, l.ProductId, SubjectId, OwnershipId, l.AuthorityVersion,
                l.IsActive, l.RevocationReason, l.RevokedAt, l.ExpirationDate, l.MaxSeats, t, t, l.MaxSeats,
                "cycle-fixture", "cus-fixture", "sub-fixture", "in-fixture", Start, Start.AddDays(30), Start,
                command == "PAID" ? Clock.Now : null, previous, null);
        }

        /// <summary>Creates actual GRACE and SUSPEND receipts by advancing only the injected HTTP clock.</summary>
        public async Task<AdminController.ConditionalLicenseBillingRequest> SuspendAsync()
        {
            var grace = await RequestAsync("GRACE"); await OkAsync(grace); Clock.Now = Start.AddHours(24);
            var suspend = await RequestAsync("SUSPEND", grace.OperationId); await OkAsync(suspend); return suspend;
        }

        /// <summary>Executes a true ownership transfer in global/license/ownership order without changing the key.</summary>
        public async Task TransferAsync()
        {
            await using var db = Db(); await using var tx = await db.Database.BeginTransactionAsync();
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT \"Id\" FROM \"Licenses\" WHERE \"Id\" = {LicenseId} FOR UPDATE");
            var previous = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync(o => o.Id == OwnershipId);
            previous.State = "TRANSFERRED"; previous.EndedAtUtc = Start;
            var next = new RuntimeRecoveryCommercialSubject { ProductId = ProductId, CreatedAtUtc = Start };
            db.Add(next); await db.SaveChangesAsync();
            db.Add(new RuntimeRecoveryCommercialOwnership { LicenseId = LicenseId, ProductId = ProductId,
                OwnerSubjectId = next.Id, PreviousOwnershipId = previous.Id, State = "ACTIVE", CreatedAtUtc = Start });
            await db.SaveChangesAsync(); await tx.CommitAsync();
        }

        /// <summary>Uses an independent SQL writer and actual authority trigger to simulate a newer security revocation.</summary>
        public async Task SecurityRevokeAsync()
        { await using var db = Db(); await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevocationReason\" = 'security_review', \"RevokedAt\" = {Start} WHERE \"Id\" = {LicenseId}"); }

        /// <summary>Mutates shared type configuration using real DML, including an insertion phantom.</summary>
        public async Task ChangeTypeAsync(string mutation)
        {
            var l = await ReadAsync(); await using var db = Db();
            if (mutation == "parameter") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypeCustomParams\" SET \"Value\" = 'false' WHERE \"LicenseTypeId\" = {l.LicenseTypeId}");
            else if (mutation == "type") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"DefaultMaxSeats\" = 7 WHERE \"Id\" = {l.LicenseTypeId}");
            else { db.Add(new LicenseTypeCustomParam { LicenseTypeId = l.LicenseTypeId, Key = "new_parameter", Name = "Fixture", Value = "true" }); await db.SaveChangesAsync(); }
        }

        /// <summary>Requires observed PostgreSQL contention rather than guessing that a delay means a lock.</summary>
        public async Task WaitForLockAsync(string marker)
        {
            await using var observer = new NpgsqlConnection(connection); await observer.OpenAsync();
            for (var i = 0; i < 150; i++)
            {
                await using var cmd = new NpgsqlCommand("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE @pattern", observer);
                cmd.Parameters.AddWithValue("pattern", "%" + marker + "%");
                if (Convert.ToInt64(await cmd.ExecuteScalarAsync()) > 0) return;
                await Task.Delay(20);
            }
            Assert.Fail("No PostgreSQL lock observed for " + marker);
        }

        /// <summary>Creates/migrates a uniquely owned database on an explicitly configured loopback PostgreSQL server.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var settings = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES")
                ?? throw new InvalidOperationException("Local test PostgreSQL connection required"));
            if (settings.Host is not ("localhost" or "127.0.0.1" or "::1")) throw new InvalidOperationException("Loopback test host required");
            settings.Database = "postgres"; var maintenance = settings.ConnectionString;
            var database = "tkt1011_" + Guid.NewGuid().ToString("N");
            await using (var admin = new NpgsqlConnection(maintenance)) { await admin.OpenAsync();
                await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", admin); await cmd.ExecuteNonQueryAsync(); }
            settings.Database = database;
            Fixture? f = null;
            try
            {
                f = new Fixture(maintenance, database, settings.ConnectionString);
                await using var db = f.Db(); await db.Database.MigrateAsync();
                var product = new Product { Name = "TIAConnect", ApiSecret = "tkt1011-product-fixture" };
                var type = new LicenseType { Product = product, Name = "Fixture Pro", Slug = "TKT1011-PRO", IsRecurring = true, DefaultMaxSeats = 3 };
                type.CustomParams.Add(new LicenseTypeCustomParam { Key = "copilot", Name = "Fixture", Value = "true" });
                db.AddRange(product, type); await db.SaveChangesAsync(); f.ProductId = product.Id;
                db.Add(new License { Id = f.LicenseId, LicenseKey = f.Key, ProductId = product.Id, LicenseTypeId = type.Id,
                    CustomerEmail = "fixture@example.test", CreationDate = f.Start.AddDays(-30), IsActive = true, ExpirationDate = f.Start.AddDays(-1), MaxSeats = 3 });
                db.Add(new RuntimeRecoveryCommercialSubject { Id = f.SubjectId, ProductId = product.Id, CreatedAtUtc = f.Start });
                await db.SaveChangesAsync();
                // The historical case intentionally starts without ownership in any state.
                Assert.Empty(await db.RuntimeRecoveryCommercialOwnerships.ToListAsync());
                return f;
            }
            catch
            {
                if (f is not null) await f.DisposeAsync();
                else
                {
                    // Host construction may fail before the fixture exists. The database name
                    // is still the locally generated UUID above and must not leak on this path.
                    await using var admin = new NpgsqlConnection(maintenance); await admin.OpenAsync();
                    await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)", admin);
                    await cmd.ExecuteNonQueryAsync();
                }
                throw;
            }
        }

        /// <summary>Stops the owned HTTP host before dropping only its generated fixture database.</summary>
        public async ValueTask DisposeAsync()
        {
            Client.Dispose(); await host.DisposeAsync(); NpgsqlConnection.ClearAllPools();
            await using var admin = new NpgsqlConnection(maintenance); await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)", admin); await cmd.ExecuteNonQueryAsync();
        }
    }
}

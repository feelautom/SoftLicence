using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Real PostgreSQL compatibility regressions separating ordinary licensing from paid-pass authority.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Replays the unchanged pre-correction signing path with a synthetic sixty-second bound. Both exact
    /// consumers must reject that historical token with their own time error; no validator is reimplemented.
    /// This contract witness supplements the actual pre-patch PG failures retained in the recipe.
    /// </summary>
    [Theory]
    [InlineData("v2.3.647")] [InlineData("v2.3.924")]
    public async Task Compat991_TaggedConsumerRejectsHistoricalTruncatedToken(string tag)
    {
        var consumer = TaggedCapabilityConsumer.For(tag);
        using var scenario = await CreateCompatScenarioAsync(false);
        var now = DateTimeOffset.UtcNow;
        var token = scenario.Crypto.SignCapability(Guid.Parse(scenario.Request.EnrollmentId!), 1, 1,
            scenario.Request.InstallationId!, scenario.Request.ReleaseVersion!, scenario.Request.SessionId!,
            scenario.Request.Binaries!, scenario.Request.Audience!, scenario.Request.Scope!, scenario.Spki,
            now, Guid.NewGuid().ToString("D"), RuntimeEnrollmentCryptoService.BoundCapabilityExpiry(now, now.AddSeconds(60)));
        Assert.Equal("capability_time_invalid", consumer.Validate(token, scenario.Options.Issuer,
            scenario.Crypto.ActiveSigningKeyId, scenario.Signing, scenario.Request, scenario.Spki, now.UtcDateTime));
    }

    /// <summary>Both exact brokers reject expired replay and lost authority after one HTTP attempt, without automatic renewal.</summary>
    [Theory]
    [InlineData("v2.3.647", 409, "capability_expired", "capability_rejected")]
    [InlineData("v2.3.924", 409, "capability_expired", "capability_rejected")]
    [InlineData("v2.3.647", 422, "authority_ineligible", "capability_authority_rejected")]
    [InlineData("v2.3.924", 422, "authority_ineligible", "capability_authority_rejected")]
    public async Task Compat991_TaggedBrokerMapsAuthorityErrorsWithoutRetry(string tag, int status, string error, string expected)
    {
        var result = await TaggedCapabilityConsumer.For(tag).MapResponseAsync(status, error);
        Assert.Equal(expected, result.Error);
        Assert.Equal(1, result.Requests);
    }

    /// <summary>
    /// A historically signed and sealed expired receipt cannot be renewed by replay even while ordinary
    /// license authority remains valid. A genuinely new proof may acquire a new 120-second capability.
    /// The fixture backdates only its synthetic receipt to avoid a two-minute wall-clock test.
    /// </summary>
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Compat991_ExpiredReceiptNeverExtendsOnReplay(bool legacy)
    {
        using var scenario = await CreateCompatScenarioAsync(legacy);
        await scenario.IssueAsync();
        await scenario.ReplaceReceiptWithHistoricalAsync();
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.IssueAsync());
        Assert.Equal("capability_expired", denied.ErrorCode);
        var fresh = await scenario.IssueAsync(newNonce: true);
        Assert.False(fresh.Idempotent);
        Assert.Equal(120, CompatLifetime(fresh.Response.CapabilityToken));
    }

    /// <summary>
    /// An uncommitted administrative type/ledger mutation must block capability classification until
    /// its final state is visible. For expiry, hold the type row before setting a future database
    /// deadline, then prove the reader waits through that deadline and re-reads current time.
    /// Observe PostgreSQL blocking and clock facts with a separate autocommit connection.
    /// Roll back on every assertion failure and await the worker so no background query escapes the test.
    /// </summary>
    [Theory]
    [InlineData("slug")] [InlineData("license-type")] [InlineData("ledger")]
    [InlineData("expiry-during-wait")]
    public async Task Compat991_ClassificationWaitsForConcurrentAuthorityRows(string mutation)
    {
        using var scenario = await CreateCompatScenarioAsync(false);
        if (mutation != "expiry-during-wait")
            await scenario.MakePassAsync(DateTime.UtcNow.AddSeconds(90), true);
        await using var writer = await scenario.Factory.CreateDbContextAsync();
        var replacement = new LicenseType { ProductId = scenario.ProductId, Name = "Ordinary replacement", Slug = "ordinary" };
        writer.Add(replacement);
        await writer.SaveChangesAsync();
        await using var transaction = await writer.Database.BeginTransactionAsync();
        if (mutation == "expiry-during-wait")
            await writer.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"Name\"='Still ordinary' WHERE \"Id\"={scenario.TypeId}");
        else if (mutation == "slug")
            await writer.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"Slug\"='renamed-pass' WHERE \"Id\"={scenario.TypeId}");
        else if (mutation == "license-type")
            await writer.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"LicenseTypeId\"={replacement.Id} WHERE \"Id\"={scenario.LicenseId}");
        else
            await writer.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"PersonalDayPasses\" SET \"PaidThroughUtc\"=\"PaidThroughUtc\" + interval '10 seconds' WHERE \"LicenseId\"={scenario.LicenseId}");
        DateTime? expiryDuringWait = null;
        if (mutation == "expiry-during-wait")
        {
            // Set the ordinary licence deadline after the writer holds its type row. The service
            // must enter its FOR SHARE classification wait before expiry, and its lock timeout
            // must outlast that bounded wait so a 503 cannot substitute for the expected 422.
            scenario.Options.LockTimeoutMilliseconds = 12000;
            scenario.Options.StatementTimeoutMilliseconds = 20000;
            expiryDuringWait = (await scenario.DatabaseNowAsync()).AddSeconds(6);
            await scenario.SetExpiryAsync(expiryDuringWait);
        }
        var pending = scenario.IssueAsync();
        try
        {
            // The observer must target the scenario's own isolated database: pg_stat_activity is
            // filtered by current_database(), so the shared harness database would never show the wait.
            await using var observer = new NpgsqlConnection(scenario.AdminConnection);
            await observer.OpenAsync();
            var deadline = DateTime.UtcNow.AddSeconds(5);
            var observedWait = false;
            while (!pending.IsCompleted && DateTime.UtcNow < deadline)
            {
                var blockedTable = mutation switch
                {
                    "license-type" => "Licenses",
                    "ledger" => "PersonalDayPasses",
                    _ => "LicenseTypes"
                };
                await using var command = new NpgsqlCommand("""
                    SELECT EXISTS (
                        SELECT 1 FROM pg_catalog.pg_stat_activity
                        WHERE datname = pg_catalog.current_database()
                          AND usename = 'softlicence_runtime_test_app'
                          AND wait_event_type = 'Lock'
                          AND query LIKE @table_pattern
                          AND pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0)
                    """, observer);
                command.Parameters.AddWithValue("table_pattern", $"%{blockedTable}%");
                observedWait = (bool)(await command.ExecuteScalarAsync())!;
                if (observedWait) break;
                await Task.Delay(20);
            }
            Assert.True(observedWait, "Capability completed without observing a row-classification lock wait.");
            if (mutation == "expiry-during-wait")
            {
                // The type remains ordinary and coherent: only real elapsed database time can cause rejection.
                await using var clock = new NpgsqlCommand("SELECT pg_catalog.clock_timestamp() >= @expiry", observer);
                clock.Parameters.AddWithValue("expiry", expiryDuringWait!.Value);
                deadline = DateTime.UtcNow.AddSeconds(8);
                while (!(bool)(await clock.ExecuteScalarAsync())!)
                {
                    Assert.True(DateTime.UtcNow < deadline, "PostgreSQL did not reach the fixture deadline within the bounded lock test.");
                    await Task.Delay(20);
                }
                Assert.False(pending.IsCompleted);
            }
            await transaction.CommitAsync();
            var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => pending);
            Assert.Equal("authority_ineligible", denied.ErrorCode);
        }
        finally
        {
            if (transaction.GetDbTransaction().Connection is not null) await transaction.RollbackAsync();
            try { await pending; } catch (RuntimeEnrollmentException) { }
        }
    }

    /// <summary>
    /// Ordinary modern JWTs must be accepted by both immutable Desktop validators, including the last
    /// paid second; legacy JWTs retain their separate eleven-field shape. Replays preserve exact bytes.
    /// Compile consumers before setting short authority deadlines so compiler time cannot expire the fixture.
    /// </summary>
    [Theory]
    [InlineData(false, -1)] [InlineData(false, 3600)] [InlineData(false, 120)]
    [InlineData(false, 119)] [InlineData(false, 60)] [InlineData(false, 1)]
    [InlineData(true, -1)] [InlineData(true, 3600)] [InlineData(true, 120)]
    [InlineData(true, 119)] [InlineData(true, 60)] [InlineData(true, 1)]
    public async Task Compat991_OrdinaryFreshAndReplayRetain120Seconds(bool legacy, double seconds)
    {
        var consumers = legacy ? [] : new[] { TaggedCapabilityConsumer.For("v2.3.647"), TaggedCapabilityConsumer.For("v2.3.924") };
        using var scenario = await CreateCompatScenarioAsync(legacy);
        await scenario.SetExpiryAsync(seconds < 0 ? null : (await scenario.DatabaseNowAsync()).AddSeconds(seconds));
        var issued = await scenario.IssueAsync();
        // Invoke the actual validators before an assertion on TTL, preserving the observed consumer failure in red evidence.
        var consumerErrors = consumers.Select(consumer => consumer.Validate(issued.Response.CapabilityToken, scenario.Options.Issuer,
            scenario.Crypto.ActiveSigningKeyId, scenario.Signing, scenario.Request, scenario.Spki, DateTime.UtcNow)).ToArray();
        Assert.True(consumerErrors.All(error => error is null), "647/924 actual validator errors: " + string.Join(",", consumerErrors));
        Assert.Equal(120, CompatLifetime(issued.Response.CapabilityToken));
        using var token = JsonDocument.Parse(DecodeBase64Url(issued.Response.CapabilityToken.Split('.')[1]));
        Assert.Equal(legacy ? 11 : 15, token.RootElement.EnumerateObject().Count());
        Assert.Equal(DateTimeOffset.Parse(issued.Response.ExpiresAtUtc, CultureInfo.InvariantCulture).ToUnixTimeSeconds(), token.RootElement.GetProperty("exp").GetInt64());
        var replay = await scenario.IssueAsync();
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, replay.ExactResponseBody);
    }

    /// <summary>Exercises the same fresh/replay contract with only 900 milliseconds of ordinary authority remaining.</summary>
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public Task Compat991_OrdinarySubsecondFreshAndReplayRetain120Seconds(bool legacy) =>
        Compat991_OrdinaryFreshAndReplayRetain120Seconds(legacy, 0.9);

    /// <summary>
    /// A still-valid shortened ordinary license may replay its original token and obtain a new 120-second
    /// token with a new nonce. Expiration, revocation and inactivity must reject both paths independently.
    /// </summary>
    [Theory]
    [InlineData(false, "shortened")] [InlineData(true, "shortened")]
    [InlineData(false, "expired")] [InlineData(true, "expired")]
    [InlineData(false, "revoked")] [InlineData(true, "revoked")]
    [InlineData(false, "inactive")] [InlineData(true, "inactive")]
    public async Task Compat991_OrdinaryReplayRevalidatesAuthorityWithoutReissuing(bool legacy, string mutation)
    {
        using var scenario = await CreateCompatScenarioAsync(legacy);
        var issued = await scenario.IssueAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            if (mutation == "revoked")
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"RevokedAt\"=now() WHERE \"Id\"={scenario.LicenseId}");
            else if (mutation == "inactive")
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\"=false WHERE \"Id\"={scenario.LicenseId}");
            else
                await scenario.SetExpiryAsync((await scenario.DatabaseNowAsync()).AddSeconds(mutation == "shortened" ? 60 : -1));
        }
        if (mutation == "shortened")
        {
            var replay = await scenario.IssueAsync();
            Assert.True(replay.Idempotent);
            Assert.Equal(issued.ExactResponseBody, replay.ExactResponseBody);
            var fresh = await scenario.IssueAsync(newNonce: true);
            Assert.False(fresh.Idempotent);
            Assert.Equal(120, CompatLifetime(fresh.Response.CapabilityToken));
            Assert.NotEqual(issued.Response.CapabilityToken, fresh.Response.CapabilityToken);
        }
        else
        {
            var replay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.IssueAsync());
            var fresh = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.IssueAsync(newNonce: true));
            Assert.Equal("authority_ineligible", replay.ErrorCode);
            Assert.Equal("authority_ineligible", fresh.ErrorCode);
        }
    }

    /// <summary>
    /// Paid-period identity is established by the existing ledger, not by the shared Pro slug alone.
    /// A changed type, missing date or divergent horizon must never fall through to ordinary TTL.
    /// An ordinary Pro licence without a ledger retains the established 120-second capability contract.
    /// Valid case-folded reserved slugs retain the existing IsPassType semantics.
    /// </summary>
    [Theory]
    [InlineData(false, "valid")] [InlineData(true, "valid")]
    [InlineData(false, "lowercase")] [InlineData(true, "lowercase")]
    [InlineData(false, "renamed")] [InlineData(true, "renamed")]
    [InlineData(false, "type-swapped")] [InlineData(true, "type-swapped")]
    [InlineData(false, "missing-ledger")] [InlineData(true, "missing-ledger")]
    [InlineData(false, "missing-expiry")] [InlineData(true, "missing-expiry")]
    [InlineData(false, "divergent-expiry")] [InlineData(true, "divergent-expiry")]
    [InlineData(false, "free-type")] [InlineData(true, "free-type")]
    [InlineData(false, "nonrecurring-type")] [InlineData(true, "nonrecurring-type")]
    [InlineData(false, "anonymous-type")] [InlineData(true, "anonymous-type")]
    [InlineData(false, "singleuse-type")] [InlineData(true, "singleuse-type")]
    public async Task Compat991_PassClassificationCannotEscapePaidAuthority(bool legacy, string mutation)
    {
        using var scenario = await CreateCompatScenarioAsync(legacy);
        var expiry = DateTimeOffset.FromUnixTimeSeconds(new DateTimeOffset(await scenario.DatabaseNowAsync()).ToUnixTimeSeconds() + 60).UtcDateTime;
        await scenario.MakePassAsync(expiry, mutation != "missing-ledger");
        if (mutation != "missing-ledger") await scenario.IssueAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            if (mutation == "lowercase" || mutation == "renamed")
            {
                var slug = mutation == "lowercase" ? "tia-connect-pro" : "ordinary-renamed";
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"Slug\"={slug} WHERE \"Id\"={scenario.TypeId}");
            }
            else if (mutation == "type-swapped")
            {
                var ordinary = new LicenseType { ProductId = scenario.ProductId, Name = "Ordinary replacement", Slug = "ordinary" };
                db.Add(ordinary);
                await db.SaveChangesAsync();
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"LicenseTypeId\"={ordinary.Id} WHERE \"Id\"={scenario.LicenseId}");
            }
            else if (mutation == "free-type")
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"IsFree\"=true WHERE \"Id\"={scenario.TypeId}");
            else if (mutation == "nonrecurring-type")
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"IsRecurring\"=false WHERE \"Id\"={scenario.TypeId}");
            else if (mutation == "anonymous-type")
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"AllowAnonymous\"=true WHERE \"Id\"={scenario.TypeId}");
            else if (mutation == "singleuse-type")
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"EnforceSingleUsePerHardwareId\"=true WHERE \"Id\"={scenario.TypeId}");
            else if (mutation == "missing-expiry") await scenario.SetExpiryAsync(null);
            else if (mutation == "divergent-expiry") await scenario.SetExpiryAsync(expiry.AddSeconds(15));
        }
        if (mutation is "valid" or "lowercase")
        {
            var issued = await scenario.IssueAsync();
            Assert.InRange(CompatLifetime(issued.Response.CapabilityToken), 1, 60);
            Assert.Equal(new DateTimeOffset(expiry), DateTimeOffset.Parse(issued.Response.ExpiresAtUtc, CultureInfo.InvariantCulture));
            Assert.Equal(issued.ExactResponseBody, (await scenario.IssueAsync()).ExactResponseBody);
            // Shrinking both authoritative dates retains a coherent pass, but cannot make the old receipt valid.
            await scenario.SetPassExpiryAsync(expiry.AddSeconds(-20));
            var stale = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.IssueAsync());
            Assert.Equal("capability_expired", stale.ErrorCode);
            var fresh = await scenario.IssueAsync(newNonce: true);
            Assert.Equal(new DateTimeOffset(expiry.AddSeconds(-20)), DateTimeOffset.Parse(fresh.Response.ExpiresAtUtc, CultureInfo.InvariantCulture));
        }
        else if (mutation == "missing-ledger")
        {
            var ordinary = await scenario.IssueAsync(newNonce: true);
            Assert.Equal(120, CompatLifetime(ordinary.Response.CapabilityToken));
        }
        else
        {
            var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.IssueAsync());
            Assert.Equal("authority_ineligible", denied.ErrorCode);
            var freshDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.IssueAsync(newNonce: true));
            Assert.Equal("authority_ineligible", freshDenied.ErrorCode);
        }
    }

    /// <summary>Returns the signed whole-second duration without changing or re-signing any token.</summary>
    private static long CompatLifetime(string token)
    {
        using var payload = JsonDocument.Parse(DecodeBase64Url(token.Split('.')[1]));
        return payload.RootElement.GetProperty("exp").GetInt64() - payload.RootElement.GetProperty("iat").GetInt64();
    }

    /// <summary>Serializes the one-time creation of <see cref="_compatConnections"/>.</summary>
    private static readonly SemaphoreSlim CompatProvisioningLock = new(1, 1);

    /// <summary>
    /// Freshly migrated database shared by every compatibility scenario of this test process. All
    /// scenarios configure the same signing keys, so they may share it, while fixtures configuring
    /// other keys never write to it. One database per process keeps provisioning load bounded: one
    /// database per scenario (dozens of full migrations) slowed the shared harness database enough to
    /// time out unrelated tests.
    /// </summary>
    private static (string Admin, string App)? _compatConnections;

    /// <summary>
    /// Creates and confirms a synthetic enrollment on the compatibility database; the returned scenario
    /// owns all in-memory keys. A dedicated database is required because the service validates that the
    /// live key registry equals exactly this scenario's configuration, and other fixtures add their own
    /// signing keys to the shared harness database during the same test run.
    /// </summary>
    private static async Task<CompatScenario> CreateCompatScenarioAsync(bool legacy)
    {
        (string Admin, string App) connections;
        await CompatProvisioningLock.WaitAsync();
        try
        {
            _compatConnections ??= await ProvisionIsolatedAsync();
            connections = _compatConnections.Value;
        }
        finally
        {
            CompatProvisioningLock.Release();
        }
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, RuntimeEnrollmentService.LegacyCapabilityReleaseVersion);
        var signing = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var key = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, signing, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, new RuntimeEnrollmentAuthorityService(factory, Options.Create(options)),
            new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options)), crypto, Options.Create(options));
        var prepare = PrepareRequest(fixture, Guid.NewGuid().ToString("D"), key);
        prepare.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var prepared = await service.PrepareAsync("website-step1", Sha256("compat991-prepare"), prepare);
        var id = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest { Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion, EnrollmentId = id.ToString("D"), Epoch = 1 };
        var digest = Sha256("compat991-confirm");
        await service.ConfirmAsync(id, digest, confirm, Proof(key, "confirm", id, options.ConfirmAudience,
            prepared.Response.Challenge, digest), IPAddress.Loopback);
        var request = new RuntimeEnrollmentCapabilityRequest { Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion, EnrollmentId = id.ToString("D"), Epoch = 1,
            SecurityEpoch = 1, Audience = "https://broker.example.test", Scope = ["runtime.execute"] };
        if (!legacy)
        {
            request.InstallationId = fixture.InstallationId; request.ReleaseVersion = fixture.Version;
            request.SessionId = Guid.NewGuid().ToString("D"); request.Binaries = CapabilityBinaries();
        }
        await using var db = await factory.CreateDbContextAsync();
        var licenseId = await db.DistributionInstallationBindings.Where(b => b.Id == fixture.BindingId).Select(b => b.LicenseId).SingleAsync();
        var typeId = await db.Licenses.Where(l => l.Id == licenseId).Select(l => l.LicenseTypeId).SingleAsync();
        return new(factory, service, crypto, options, signing, key, request, licenseId, typeId, fixture.ProductId,
            connections.Admin);
    }

    /// <summary>Owns synthetic enrollment keys and exposes bounded database mutations for compatibility scenarios.</summary>
    private sealed class CompatScenario(TestDbFactory factory, RuntimeEnrollmentService service,
        RuntimeEnrollmentCryptoService crypto, RuntimeEnrollmentOptions options, RSA signing, RSA key,
        RuntimeEnrollmentCapabilityRequest request, Guid licenseId, Guid typeId, Guid productId,
        string adminConnection) : IDisposable
    {
        /// <summary>Fixture DB factory restricted to the explicitly configured disposable PostgreSQL database.</summary>
        internal TestDbFactory Factory { get; } = factory;
        /// <summary>Actual service under test using the real authority lease and encryption/signing implementations.</summary>
        internal RuntimeEnrollmentService Service { get; } = service;
        /// <summary>In-memory signer, disposed with this scenario.</summary>
        internal RuntimeEnrollmentCryptoService Crypto { get; } = crypto;
        /// <summary>Synthetic issuer and encryption/signing configuration.</summary>
        internal RuntimeEnrollmentOptions Options { get; } = options;
        /// <summary>Synthetic signing key used solely to give the consumer its public pin.</summary>
        internal RSA Signing { get; } = signing;
        /// <summary>Exact modern or legacy wire request; optional legacy fields are never set.</summary>
        internal RuntimeEnrollmentCapabilityRequest Request { get; } = request;
        /// <summary>Product-scoped fixture license UUID, never a production identity.</summary>
        internal Guid LicenseId { get; } = licenseId;
        /// <summary>Original fixture type UUID used by classification mutation tests.</summary>
        internal Guid TypeId { get; } = typeId;
        /// <summary>Fixture product boundary used by ledger and replacement-type mutations.</summary>
        internal Guid ProductId { get; } = productId;
        /// <summary>Administrator connection to this scenario's isolated database, used only by test observers.</summary>
        internal string AdminConnection { get; } = adminConnection;
        /// <summary>Original proof nonce retained to test byte-for-byte receipt replay.</summary>
        private readonly RuntimeProofHeaders _proof = Proof(key, "capability", Guid.Parse(request.EnrollmentId!), request.Audience!, "-", Sha256("compat991-capability"));
        /// <summary>Exact lowercase SPKI digest expected by the real consumer validator.</summary>
        internal string Spki => Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

        /// <summary>Uses the original proof unless a genuinely new nonce is requested; never alters a stored receipt.</summary>
        internal Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>> IssueAsync(bool newNonce = false) =>
            Service.CreateCapabilityAsync(Guid.Parse(Request.EnrollmentId!), Sha256("compat991-capability"), Request,
                newNonce ? Proof(key, "capability", Guid.Parse(Request.EnrollmentId!), Request.Audience!, "-", Sha256("compat991-capability")) : _proof, IPAddress.Loopback);

        /// <summary>Changes only the fixture commercial expiration; real authority triggers remain active.</summary>
        internal async Task SetExpiryAsync(DateTime? expiry)
        {
            await using var db = await Factory.CreateDbContextAsync();
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\"={expiry} WHERE \"Id\"={LicenseId}");
        }

        /// <summary>Reads the same PostgreSQL clock as the service, avoiding host/container clock-offset assumptions.</summary>
        internal async Task<DateTime> DatabaseNowAsync()
        {
            await using var db = await Factory.CreateDbContextAsync();
            await db.Database.OpenConnectionAsync();
            return (await RuntimeEnrollmentService.DatabaseNowAsync(db, CancellationToken.None)).UtcDateTime;
        }

        /// <summary>
        /// Replaces only the fixture's encrypted receipt with a genuinely signed historical token and
        /// matching JSON expiry. Uses the production envelope/AAD contract and leaves nonce identity intact.
        /// </summary>
        internal async Task ReplaceReceiptWithHistoricalAsync()
        {
            var id = Guid.Parse(Request.EnrollmentId!);
            var nonce = Guid.Parse(_proof.Jti);
            var issuedAt = DateTimeOffset.UtcNow.AddMinutes(-3);
            var token = Request.SessionId is null
                ? Crypto.SignLegacyCapability(id, 1, 1, Request.Audience!, Request.Scope!, Spki, issuedAt, Guid.NewGuid().ToString("D"))
                : Crypto.SignCapability(id, 1, 1, Request.InstallationId!, Request.ReleaseVersion!, Request.SessionId,
                    Request.Binaries!, Request.Audience!, Request.Scope!, Spki, issuedAt, Guid.NewGuid().ToString("D"));
            var response = new RuntimeEnrollmentCapabilityResponse(RuntimeEnrollmentService.CapabilityResponseSchema,
                RuntimeEnrollmentService.ProtocolVersion, token, FormatUtc(issuedAt.AddSeconds(120)));
            var bytes = JsonSerializer.SerializeToUtf8Bytes(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            await using var db = await Factory.CreateDbContextAsync();
            await using var transaction = await db.Database.BeginTransactionAsync();
            var envelope = await Crypto.SealAsync(db, "capability-response", nonce, 1, bytes,
                $"RuntimeEnrollmentProofNonces:{id:D}:{nonce:D}:capability:ResponseCiphertext");
            var row = await db.RuntimeEnrollmentProofNonces.SingleAsync(value => value.EnrollmentId == id && value.Jti == _proof.Jti && value.Operation == "capability");
            row.ResponseCiphertext = envelope.Ciphertext;
            row.ResponseKeyId = envelope.KeyId;
            await db.SaveChangesAsync();
            await transaction.CommitAsync();
        }

        /// <summary>Creates a synthetic existing paid identity in the actual ledger, optionally omitting it to test denial.</summary>
        internal async Task MakePassAsync(DateTime expiry, bool ledger)
        {
            await using var db = await Factory.CreateDbContextAsync();
            await using var transaction = await db.Database.BeginTransactionAsync();
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"Slug\"={PersonalDayPassPolicy.TypeSlug}, \"IsRecurring\"=true WHERE \"Id\"={TypeId}");
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\"={expiry} WHERE \"Id\"={LicenseId}");
            if (ledger)
            {
                var subject = Guid.NewGuid();
                db.Add(new RuntimeRecoveryCommercialSubject { Id = subject, ProductId = ProductId, CreatedAtUtc = DateTime.UtcNow });
                await db.SaveChangesAsync();
                db.Add(new PersonalDayPass { LicenseId = LicenseId, ProductId = ProductId, CommercialSubjectId = subject, PaidThroughUtc = expiry });
                await db.SaveChangesAsync();
            }
            await transaction.CommitAsync();
        }

        /// <summary>Atomically changes both paid and license horizons under the existing exclusive authority lock.</summary>
        internal async Task SetPassExpiryAsync(DateTime expiry)
        {
            await using var db = await Factory.CreateDbContextAsync();
            await using var transaction = await db.Database.BeginTransactionAsync();
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\"={expiry} WHERE \"Id\"={LicenseId}");
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"PersonalDayPasses\" SET \"PaidThroughUtc\"={expiry} WHERE \"ProductId\"={ProductId} AND \"LicenseId\"={LicenseId}");
            await transaction.CommitAsync();
        }

        /// <summary>Disposes only this scenario's ephemeral cryptographic material; the campaign owns database cleanup.</summary>
        public void Dispose() { Crypto.Dispose(); Signing.Dispose(); key.Dispose(); }
    }
}

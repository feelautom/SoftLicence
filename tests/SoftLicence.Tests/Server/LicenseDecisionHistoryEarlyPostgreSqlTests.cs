using System.Data.Common;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves early authenticated-entitlement refusals have no business SQL and persist only identity-level history.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Early terminal persistence fails closed on prior SQL/pending writes, transaction abort, shutdown and storage faults, preserving retry identity after unknown commit.</summary>
    /// <remarks>Injected resolver faults run inside the real private transaction after production reads. Whole-table fingerprints and a fresh observer prove disposal restores business state. Only acknowledged or acknowledgement-lost commits may leave an event. No other connection is mutated.</remarks>
    [Theory]
    [InlineData("write-sql")]
    [InlineData("assign-xid")]
    [InlineData("tx-aborted")]
    [InlineData("pending-business")]
    [InlineData("cancel-before")]
    [InlineData("cancel-after")]
    [InlineData("host-stop")]
    [InlineData("insert")]
    [InlineData("commit-before")]
    [InlineData("commit-ack")]
    [InlineData("timeout")]
    public async Task Tkt976_EarlyRefusal_FaultsNeverCommitBusinessOrClaimFalseDurability(string mode)
    {
        var connections = await ProvisionAsync();
        var clean = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        var sql = new Tkt976EarlySqlObserver();
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown);
        var factory = new Tkt976EarlyFactory(connections.App, sql, fault);
        var protection = new EphemeralDataProtectionProvider();
        var now = DateTimeOffset.UtcNow;
        var resolver = new Tkt976EarlyAliasResolver(mode, requestCancellation, shutdown);
        var service = new DistributionInstallationBindingService(factory, protection, new FixedTimeProvider(now), resolver,
            applicationLifetime: new Tkt976HostLifetime(shutdown));
        var request = await Tkt976_CreateRequestAsync(service, fixture, now, "1234567890ABCDEF");
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        fault.Armed = true;
        sql.Armed = true;
        if (mode == "cancel-before") requestCancellation.Cancel();
        var timer = System.Diagnostics.Stopwatch.StartNew();
        if (mode == "cancel-before")
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("976-early-fault"), request, requestCancellation.Token));
        else if (mode == "cancel-after")
        {
            var refused = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("976-early-fault"), request, requestCancellation.Token));
            Assert.Equal("hardware_authority_refused", refused.ErrorCode);
            Assert.True(requestCancellation.IsCancellationRequested);
        }
        else
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => service.FinalizeAsync(
                "tkt976-synthetic-client", Sha256("976-early-fault"), request, requestCancellation.Token));
            Assert.StartsWith("Licence decision ", error.Message);
            Assert.DoesNotContain("SELECT", error.Message);
            if (mode is "commit-before" or "commit-ack") Assert.Contains("indeterminate", error.Message);
        }
        timer.Stop();
        if (mode == "timeout") Assert.InRange(timer.Elapsed.TotalSeconds, 4.5, 15);
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using (var observed = await clean.CreateDbContextAsync())
        {
            Assert.Equal(mode is "cancel-after" or "commit-ack" ? 1 : 0,
                await observed.LicenseHistories.CountAsync(row => row.LicenseId == fixture.LicenseId));
            await using var lockCheck = await observed.Database.BeginTransactionAsync();
            Assert.True(await observed.Database.SqlQueryRaw<bool>(
                "SELECT pg_try_advisory_xact_lock(999831, 1) AS \"Value\"").SingleAsync());
            await lockCheck.RollbackAsync();
        }
        if (mode is "write-sql" or "assign-xid" or "tx-aborted" or "pending-business")
            Assert.DoesNotContain("LicenseHistories", sql.BusinessWriteTables);
        if (mode == "write-sql") Assert.Contains("Licenses", sql.BusinessWriteTables);
        var retry = new DistributionInstallationBindingService(clean, protection, new FixedTimeProvider(now), new Tkt976EarlyAliasResolver());
        var finalRefusal = await Assert.ThrowsAsync<DistributionOperationException>(() => retry.FinalizeAsync(
            "tkt976-synthetic-client", Sha256("976-early-fault"), request));
        Assert.Equal("hardware_authority_refused", finalRefusal.ErrorCode);
        await using var final = await clean.CreateDbContextAsync();
        Assert.Equal(1, await final.LicenseHistories.CountAsync(row => row.LicenseId == fixture.LicenseId));
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
    }

    /// <summary>Each early refusal belongs only to the protected entitlement licence, preserves unknown facts, and deduplicates an unchanged retry.</summary>
    /// <remarks>The interceptor records SQL text without parameter values after setup. Full-table fingerprints include ownership, receipts and trigger-maintained authority epochs. No raw request or cryptographic content is retained in the proof.</remarks>
    [Theory]
    [InlineData("legacy-target")]
    [InlineData("grant-owner")]
    [InlineData("generation")]
    [InlineData("alias")]
    public async Task Tkt976_EarlyRefusal_OnlyAuthoritativeIdentityAndHistoryCommit(string mode)
    {
        var connections = await ProvisionAsync();
        var clean = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        var other = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        var sql = new Tkt976EarlySqlObserver();
        var factory = new Tkt976EarlyFactory(connections.App, sql);
        var now = DateTimeOffset.UtcNow;
        var protection = new EphemeralDataProtectionProvider();
        var resolver = mode == "alias" ? new Tkt976EarlyAliasResolver() : (IHardwareAuthorityAliasResolver)TestHardwareAuthorityAliasResolver.Instance;
        var service = new DistributionInstallationBindingService(factory, protection, new FixedTimeProvider(now), resolver);
        var clientId = "tkt976-synthetic-client";
        var request = await Tkt976_CreateRequestAsync(service, fixture, now, "1234567890ABCDEF");
        if (mode == "alias")
        {
            // finalize-v4 is only well formed with explicit same-authority recovery; without it the
            // request stops at input validation (invalid_request) before the alias refusal under test.
            request.Schema = DistributionInstallationBindingService.FinalizeV4Schema;
            request.AllowSameAuthorityRecovery = true;
            request.LicenseReplacementCandidates = new DistributionLicenseReplacementCandidateSet
            {
                Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
                Sources =
                [
                    new()
                    {
                        Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
                        SourceBindingId = Guid.NewGuid().ToString("D"),
                        SourceLicenseId = Guid.NewGuid().ToString("D"),
                        SourceSubjectRef = Convert.ToBase64String(SHA256.HashData("early-v4-candidate"u8.ToArray()))
                            .TrimEnd('=').Replace('+', '-').Replace('/', '_')
                    }
                ]
            };
        }
        string code;
        if (mode == "legacy-target")
        {
            request.Schema = DistributionInstallationBindingService.FinalizeV5Schema;
            request.AllowSameAuthorityRecovery = true;
            request.LegacyLicenseReplacement = new DistributionLegacyLicenseReplacementProof
            {
                Schema = DistributionInstallationBindingService.LegacyLicenseReplacementSchema,
                SourceLicenseId = fixture.LicenseId.ToString("D"), TargetLicenseId = other.LicenseId.ToString("D")
            };
            code = "binding_conflict";
        }
        else if (mode == "grant-owner")
        {
            await using var setup = await clean.CreateDbContextAsync();
            setup.DistributionGrantOwnerships.Add(new DistributionGrantOwnership
            {
                ProductId = fixture.ProductId, GrantRefDigestSha256 = Sha256(request.GrantRef!),
                ClientId = "synthetic-other-client", Source = "finalize_v1", CreatedAtUtc = now.UtcDateTime
            });
            await setup.SaveChangesAsync();
            code = "grant_ownership_mismatch";
        }
        else if (mode == "generation")
        {
            var authority = await SeedTkt000686AuthorityAsync(clean, fixture.ProductId, fixture.Version, fixture.GrantRef);
            clientId = "website-step1";
            var issued = await service.IssueEntitlementAsync(clientId, Sha256("976-early-generation-issue"),
                Tkt000686IssueRequest(fixture, authority.GenerationId, Guid.NewGuid().ToString("D")));
            request = Tkt000686FinalizeRequest(fixture, issued.Response.EntitlementRef, now);
            request.Binaries![0].Sha256 = new string('f', 64);
            code = "binary_mismatch";
        }
        else code = "hardware_authority_refused";

        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        sql.Armed = true;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var refused = await Assert.ThrowsAsync<DistributionOperationException>(() => service.FinalizeAsync(
                clientId, Sha256("976-early-" + mode), request));
            Assert.Equal(code, refused.ErrorCode);
        }
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        Assert.NotEmpty(sql.Commands);
        Assert.All(sql.BusinessWriteTables, table => Assert.Equal("LicenseHistories", table));
        await using var observed = await clean.CreateDbContextAsync();
        var row = Assert.Single(await observed.LicenseHistories.Where(item => item.Action == "ACTIVATION_DECISION_V1"
            && item.LicenseId == fixture.LicenseId).ToListAsync());
        Assert.False(await observed.LicenseHistories.AnyAsync(item => item.LicenseId == other.LicenseId
            && item.Action == "ACTIVATION_DECISION_V1"));
        var decision = JsonSerializer.Deserialize<LicenseDecisionHistory>(row.Details!, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.Equal(fixture.ProductId, decision.Snapshot.ProductId);
        Assert.Equal(fixture.LicenseId, decision.Snapshot.LicenseId);
        Assert.Equal(request.HardwareId, decision.SubmittedHardwareId);
        Assert.Null(decision.ResolvedHardwareId);
        Assert.Null(decision.CorrelatedHardwareId);
        Assert.Null(decision.Snapshot.ActiveSeats);
        Assert.Null(decision.Snapshot.SeatLimit);
        Assert.Null(decision.Snapshot.ActiveSeatDetails);
        Assert.Equal("authenticated_entitlement_identity_only", decision.Snapshot.ObservationGuarantee);
        Assert.NotNull(decision.ReplacementCandidates);
        Assert.Equal(mode == "alias" ? 1 : 0, decision.ReplacementCandidates.Count);
        Assert.Equal(mode == "alias" ? "not_evaluated" : "none", decision.SelectionOutcome);
        if (mode == "alias")
        {
            var candidate = Assert.Single(decision.ReplacementCandidates);
            Assert.Equal("not_evaluated", candidate.Outcome);
            Assert.Equal(new[] { "selection_not_reached" }, candidate.ReasonCodes);
        }
        Assert.Equal("refusal_observed", LicenseDecisionHistoryProjection.FromHistory(row).Classification);
        Assert.DoesNotContain(other.LicenseId.ToString("D"), row.Details!);
        Assert.DoesNotContain(request.EntitlementRef!, row.Details!);
    }

    /// <summary>Creates private Npgsql contexts with a command observer; setup is excluded until explicitly armed.</summary>
    private sealed class Tkt976EarlyFactory(string connection, Tkt976EarlySqlObserver observer,
        Tkt976FaultState? fault = null) : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Caller owns disposal; only synthetic connection and test interceptor are configured.</summary>
        public LicenseDbContext CreateDbContext()
        {
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).AddInterceptors(observer);
            if (fault != null) options.AddInterceptors(new Tkt976TransactionFault(fault), new Tkt976InsertFault(fault));
            return new(options.Options);
        }
        /// <summary>Honors cancellation before creating the private test context.</summary>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(CreateDbContext());
        }
    }

    /// <summary>Records bounded SQL shapes, never parameter values, to expose hidden business writes before terminal history commit.</summary>
    private sealed class Tkt976EarlySqlObserver : DbCommandInterceptor
    {
        /// <summary>True only during Finalize, after all synthetic fixture setup committed.</summary>
        internal bool Armed { get; set; }
        /// <summary>SQL text bounded to 256 commands of 16 KiB, used only in assertions.</summary>
        internal List<string> Commands { get; } = [];
        /// <summary>Exact quoted tables targeted by INSERT/UPDATE/DELETE, including DML inside a batch.</summary>
        internal IEnumerable<string> BusinessWriteTables => Commands.SelectMany(command =>
            Regex.Matches(command, "(?:INSERT INTO|UPDATE|DELETE FROM)\\s+\"([^\"]+)\"", RegexOptions.CultureInvariant)
                .Select(match => match.Groups[1].Value));
        /// <summary>Fails the fixture on oversized capture instead of silently dropping SQL evidence.</summary>
        private void Record(DbCommand command)
        {
            if (!Armed) return;
            Assert.True(Commands.Count < 256 && command.CommandText.Length <= 16384);
            Commands.Add(command.CommandText);
        }
        /// <summary>Captures read and RETURNING-command shapes before execution, preserving provider behavior.</summary>
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        { Record(command); return ValueTask.FromResult(result); }
        /// <summary>Captures nonquery write/lock shapes without suppressing execution.</summary>
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        { Record(command); return ValueTask.FromResult(result); }
        /// <summary>Captures scalar shapes without changing their result or cancellation.</summary>
        public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
        { Record(command); return ValueTask.FromResult(result); }
    }

    /// <summary>Exercises the real resolver reads, then injects one deterministic alias refusal without writing business state.</summary>
    private sealed class Tkt976EarlyAliasResolver(string mode = "none", CancellationTokenSource? request = null,
        CancellationTokenSource? shutdown = null) : IHardwareAuthorityAliasResolver
    {
        /// <summary>Rejects context-free resolution so the fixture cannot escape the caller's transaction.</summary>
        public Task<HardwareAuthorityResolution> ResolveAsync(Guid productId, Guid licenseId, string submittedHardwareId,
            HardwareAuthorityResolutionIntent intent, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Context required.");
        /// <summary>Runs production alias queries before returning a synthetic refused observation; effective identity must not become authority in history.</summary>
        public async Task<HardwareAuthorityResolution> ResolveAsync(LicenseDbContext authorityDb, Guid productId, Guid licenseId,
            string submittedHardwareId, HardwareAuthorityResolutionIntent intent, CancellationToken cancellationToken = default)
        {
            await TestHardwareAuthorityAliasResolver.Instance.ResolveAsync(authorityDb, productId, licenseId, submittedHardwareId, intent, cancellationToken);
            // These synthetic faults deliberately precede the refusal. The production terminal
            // guard must reject prior writes/aborted state instead of committing them with history.
            if (mode == "write-sql")
                await authorityDb.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE \"Licenses\" SET \"CustomerName\" = \"CustomerName\" WHERE \"Id\" = {licenseId}", cancellationToken);
            if (mode == "assign-xid")
                await authorityDb.Database.ExecuteSqlRawAsync("SELECT pg_current_xact_id()", cancellationToken);
            if (mode == "tx-aborted")
            {
                var aborted = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                    authorityDb.Database.ExecuteSqlRawAsync("SELECT 1 / 0", cancellationToken));
                Assert.Equal("22012", aborted.SqlState);
            }
            if (mode == "pending-business")
                (await authorityDb.Licenses.SingleAsync(row => row.Id == licenseId, cancellationToken)).CustomerName = "synthetic pending change";
            if (mode == "cancel-after") request!.Cancel();
            if (mode == "host-stop") shutdown!.Cancel();
            return new(submittedHardwareId, "UNTRUSTED-RESOLVER-OUTPUT", null, HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.AliasUnavailable);
        }
    }
}

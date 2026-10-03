using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>PostgreSQL proofs for pending-seat recovery using unique synthetic authority graphs.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Both a new seat and an existing inactive seat must yield exactly one committed successor and replay.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tkt981_PendingSeat_RecoversAndReplays(bool existingTarget)
    {
        var fixture = await PreparePendingSeatRecoveryAsync(existingTarget);
        var result = await fixture.Service.FinalizeAsync("website-step1", Sha256("pending-target"), fixture.Request);
        var replay = await fixture.Service.FinalizeAsync("website-step1", Sha256("pending-target"), fixture.Request);
        Assert.False(result.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(result.Response, replay.Response);
        await AssertPendingSeatSuccessAsync(fixture, result.Response.BindingId);
    }

    /// <summary>Parallel identical requests serialize and produce one successor, one seat and a frozen replay.</summary>
    [Fact]
    public async Task Tkt981_PendingSeat_ConcurrentIdenticalRequestsCommitOnce()
    {
        var fixture = await PreparePendingSeatRecoveryAsync();
        var calls = Enumerable.Range(0, 2).Select(_ => fixture.Service.FinalizeAsync(
            "website-step1", Sha256("pending-concurrent"), fixture.Request)).ToArray();
        var results = await Task.WhenAll(calls).WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Single(results, result => !result.Idempotent);
        Assert.Single(results, result => result.Idempotent);
        Assert.Equal(results[0].Response, results[1].Response);
        await AssertPendingSeatSuccessAsync(fixture, results[0].Response.BindingId);
    }

    /// <summary>Distinct machines racing for the released slot must still share the licence lock and respect one seat.</summary>
    [Fact]
    public async Task Tkt981_PendingSeat_ConcurrentDifferentTargetsCannotExceedQuota()
    {
        var fixture = await PreparePendingSeatRecoveryAsync(withCapacityWitness: true);
        var other = JsonSerializer.Deserialize<DistributionInstallationFinalizeRequest>(JsonSerializer.Serialize(fixture.Request))!;
        var grant = Guid.NewGuid().ToString("D");
        var subject = Convert.ToBase64String(SHA256.HashData("pending-seat-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var entitlement = await fixture.Service.IssueEntitlementAsync("website-step1", Sha256(grant + "-issue"),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"), ProductId = other.ProductId,
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D"), GrantRefDigestSha256 = Sha256(grant), SubjectRef = subject
            });
        other.RequestId = Guid.NewGuid().ToString("D");
        other.GrantRef = grant;
        other.HandoffDigestSha256 = Sha256(grant + "-handoff");
        other.EntitlementRef = entitlement.Response.EntitlementRef;
        other.InstallationId = Guid.NewGuid().ToString("D");
        other.HardwareId = "E1A2B3C4D5E6A7B8";
        var attempts = await Task.WhenAll(
            CaptureAsync(() => fixture.Service.FinalizeAsync("website-step1", Sha256("pending-race-first"), fixture.Request)),
            CaptureAsync(() => fixture.Service.FinalizeAsync("website-step1", Sha256("pending-race-other"), other)))
            .WaitAsync(TimeSpan.FromSeconds(30));
        var success = Assert.Single(attempts, attempt => attempt.Error == null).Result!;
        var refused = Assert.IsType<DistributionOperationException>(Assert.Single(attempts, attempt => attempt.Error != null).Error);
        Assert.Equal("seat_limit_reached", refused.ErrorCode);
        var winner = success.Response.HardwareIdHash == Sha256(fixture.Request.HardwareId!) ? fixture.Request : other;
        await AssertPendingSeatSuccessAsync(fixture with { Request = winner }, success.Response.BindingId);
    }

    /// <summary>A valid pending seat must not bypass the original quota, owner or late enrollment checks.</summary>
    [Theory]
    [InlineData("quota", "seat_limit_reached")]
    [InlineData("owner", "binding_conflict")]
    [InlineData("enrollment", "binding_conflict")]
    public async Task Tkt981_PendingSeat_RefusalsPreserveOriginalState(string scenario, string error)
    {
        var fixture = await PreparePendingSeatRecoveryAsync(withCapacityWitness: scenario == "quota");
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            if (scenario == "quota")
                (await db.LicenseSeats.SingleAsync(seat => seat.Id == fixture.SourceSeatId)).IsActive = true;
            else if (scenario == "owner")
            {
                var source = await db.DistributionInstallationBindings.SingleAsync(binding => binding.Id == fixture.SourceBindingId);
                var owner = await db.DistributionGrantOwnerships.SingleAsync(grant =>
                    grant.ProductId == source.ProductId && grant.GrantRefDigestSha256 == source.GrantRefDigestSha256);
                owner.ClientId = "WEBSITE-STEP1";
            }
            else
                db.RuntimeEnrollments.Remove(await db.RuntimeEnrollments.SingleAsync(enrollment => enrollment.BindingId == fixture.SourceBindingId));
            await db.SaveChangesAsync();
        }
        var refused = await Assert.ThrowsAsync<DistributionOperationException>(() => fixture.Service.FinalizeAsync(
            "website-step1", Sha256("pending-refusal-" + scenario), fixture.Request));
        Assert.Equal(error, refused.ErrorCode);
        if (scenario == "owner")
            Assert.Equal("same_authority_mismatch", refused.ReasonCode);
        if (scenario == "enrollment")
            Assert.NotEqual("same_authority_mismatch", refused.ReasonCode);
        await AssertPendingSeatRollbackAsync(fixture);
    }

    /// <summary>A failure after the pending seat is saved must roll back the seat, source invalidation and successor together.</summary>
    [Fact]
    public async Task Tkt981_PendingSeat_LateSqlFailureRollsBackAllEffectsAndRetrySucceeds()
    {
        var fixture = await PreparePendingSeatRecoveryAsync();
        await using (var admin = new NpgsqlConnection(fixture.Admin))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, """
                CREATE FUNCTION public.test_fail_pending_seat_receipt()
                RETURNS trigger LANGUAGE plpgsql AS $failure$
                BEGIN
                    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'synthetic pending seat receipt failure';
                END
                $failure$;
                """);
            // The interpolation is a generated canonical UUID, never a caller-supplied SQL fragment.
            await ExecuteAsync(admin, $"""
                CREATE TRIGGER test_fail_pending_seat_receipt
                BEFORE INSERT ON public."DistributionBindingRequests"
                FOR EACH ROW
                WHEN (NEW."RequestId" = '{fixture.Request.RequestId}')
                EXECUTE FUNCTION public.test_fail_pending_seat_receipt();
                """);
        }
        try
        {
            var failure = await Assert.ThrowsAsync<DbUpdateException>(() => fixture.Service.FinalizeAsync(
                "website-step1", Sha256("pending-sql-failure"), fixture.Request));
            Assert.Equal("P0001", Assert.IsType<PostgresException>(failure.InnerException).SqlState);
        }
        finally
        {
            await using var admin = new NpgsqlConnection(fixture.Admin);
            await admin.OpenAsync();
            await ExecuteAsync(admin, """
                DROP TRIGGER test_fail_pending_seat_receipt ON public."DistributionBindingRequests";
                DROP FUNCTION public.test_fail_pending_seat_receipt();
                """);
        }
        await AssertPendingSeatRollbackAsync(fixture);
        var retry = await fixture.Service.FinalizeAsync("website-step1", Sha256("pending-sql-failure"), fixture.Request);
        await AssertPendingSeatSuccessAsync(fixture, retry.Response.BindingId);
    }

    /// <summary>
    /// Seeds a modern binding and active enrollment, releases its seat, and issues a fresh request
    /// for different hardware. Each fixture owns a unique product/licence in the bounded test database.
    /// </summary>
    /// <param name="existingTarget">Adds an inactive target row to cover the pre-existing relational lookup path.</param>
    /// <param name="withCapacityWitness">Keeps one unrelated seat active in a two-seat licence, leaving exactly one recoverable slot.</param>
    /// <returns>Only synthetic fixture identities and services; the admin connection must never be logged.</returns>
    private static async Task<PendingSeatFixture> PreparePendingSeatRecoveryAsync(bool existingTarget = false, bool withCapacityWitness = false)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var authority = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(authority.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);
        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(factory, new EphemeralDataProtectionProvider(),
            new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var subject = Convert.ToBase64String(SHA256.HashData("pending-seat-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        // Issues independently owned grants for the same synthetic subject and licence. Hardware
        // is an exact synthetic identifier; minutesAgo is the positive age of the frozen handoff.
        async Task<DistributionInstallationFinalizeRequest> RequestAsync(string hardware, int minutesAgo)
        {
            var grant = Guid.NewGuid().ToString("D");
            var entitlement = await service.IssueEntitlementAsync("website-step1", Sha256(grant + "-issue"),
                new DistributionEntitlementIssueRequest
                {
                    Schema = DistributionInstallationBindingService.IssueV3Schema,
                    RequestId = Guid.NewGuid().ToString("D"), ProductId = authority.ProductId.ToString("D"),
                    SoftLicenceLicenseId = authority.LicenseId.ToString("D"), GrantRefDigestSha256 = Sha256(grant),
                    SubjectRef = subject
                });
            return new DistributionInstallationFinalizeRequest
            {
                Schema = DistributionInstallationBindingService.FinalizeV2Schema,
                RequestId = Guid.NewGuid().ToString("D"), GrantRef = grant, HandoffDigestSha256 = Sha256(grant + "-handoff"),
                HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-minutesAgo)), HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
                DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-minutesAgo + 1)), ProductId = authority.ProductId.ToString("D"),
                EntitlementRef = entitlement.Response.EntitlementRef, InstallationId = Guid.NewGuid().ToString("D"),
                HardwareId = hardware, AllowSameAuthorityRecovery = true,
                Release = new DistributionReleaseEvidence
                {
                    Version = authority.Version, InstallerFilename = "TiaConnect-Setup_v2.2.844.exe", InstallerSha256 = Sha256(grant + "-installer")
                },
                Binaries = [new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                    new() { Key = "FP_DLL", Sha256 = new string('b', 64) }, new() { Key = "FP_CORE", Sha256 = new string('c', 64) }]
            };
        }

        var originalRequest = await RequestAsync(authority.HardwareId, 15);
        var original = await service.FinalizeAsync("website-step1", Sha256("pending-original"), originalRequest);
        var originalId = Guid.Parse(original.Response.BindingId);
        const string targetHardware = "F1A2B3C4D5E6A7B8";
        Guid sourceSeatId;
        Guid? witnessId = withCapacityWitness ? Guid.NewGuid() : null;
        // Seed exactly representable PostgreSQL microseconds so immutable timestamps compare exactly.
        var witnessTicks = now.AddDays(-2).UtcDateTime.Ticks;
        var witnessAt = new DateTime(witnessTicks - witnessTicks % 10, DateTimeKind.Utc);
        await using (var db = await factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(item => item.Id == originalId);
            sourceSeatId = binding.LicenseSeatId;
            var seat = await db.LicenseSeats.SingleAsync(item => item.Id == sourceSeatId);
            seat.IsActive = false;
            seat.UnlinkedAt = now.AddMinutes(-10).UtcDateTime;
            if (witnessId.HasValue)
            {
                (await db.Licenses.SingleAsync(row => row.Id == authority.LicenseId)).MaxSeats = 2;
                db.LicenseSeats.Add(new LicenseSeat { Id = witnessId.Value, LicenseId = authority.LicenseId,
                    HardwareId = "AAAABBBBCCCCDDDD", IsActive = true,
                    FirstActivatedAt = witnessAt, LastCheckInAt = witnessAt });
            }
            if (existingTarget)
                db.LicenseSeats.Add(new LicenseSeat { Id = Guid.NewGuid(), LicenseId = authority.LicenseId,
                    HardwareId = targetHardware, IsActive = false, FirstActivatedAt = now.AddHours(-1).UtcDateTime });
            var epoch = await db.RuntimeEnrollmentAuthorityStates.Where(item => item.Id == 1).Select(item => item.Epoch).SingleAsync();
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = Guid.NewGuid(), ClientId = "website-step1", BindingId = binding.Id,
                ProductId = binding.ProductId, LicenseId = binding.LicenseId, LicenseSeatId = binding.LicenseSeatId,
                InstallationId = binding.InstallationId, HardwareIdHash = binding.HardwareIdHash,
                ReleaseVersion = binding.Version, HandoffDigestSha256 = binding.HandoffDigestSha256,
                SubjectRefDigestSha256 = binding.SubjectRefDigestSha256, ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256", KeyBackend = "software-cng-unattested", AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test", PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('d', 64), KeyThumbprint = Guid.NewGuid().ToString("N"),
                ChallengeCiphertext = "test", ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('e', 64), State = "ACTIVE", Epoch = 1, SecurityEpoch = 4,
                AuthorityEpoch = epoch, ChallengeExpiresAtUtc = now.AddHours(1).UtcDateTime,
                CreatedAtUtc = now.AddHours(-1).UtcDateTime, ActivatedAtUtc = now.AddMinutes(-20).UtcDateTime
            });
            await db.SaveChangesAsync();
        }
        return new PendingSeatFixture(factory, service, connections.Admin, authority.LicenseId, originalId,
            sourceSeatId, await RequestAsync(targetHardware, 5), witnessId, witnessAt);
    }

    /// <summary>Checks committed relational state rather than treating an HTTP success as proof of a valid transition.</summary>
    /// <param name="fixture">The isolated authority graph and the winning request, including its exact hardware ID.</param>
    /// <param name="newBindingId">Canonical UUID returned by the successful finalize operation.</param>
    private static async Task AssertPendingSeatSuccessAsync(PendingSeatFixture fixture, string newBindingId)
    {
        await using var db = await fixture.Factory.CreateDbContextAsync();
        var successor = await db.DistributionInstallationBindings.SingleAsync(item => item.Id == Guid.Parse(newBindingId));
        Assert.Equal(fixture.SourceBindingId, successor.SupersededBindingId);
        Assert.NotEqual(fixture.SourceSeatId, successor.LicenseSeatId);
        Assert.Equal("active", successor.State);
        Assert.Equal("invalidated", (await db.DistributionInstallationBindings.SingleAsync(item => item.Id == fixture.SourceBindingId)).State);
        Assert.Equal("INVALIDATED", (await db.RuntimeEnrollments.SingleAsync(item => item.BindingId == fixture.SourceBindingId)).State);
        await AssertPendingCapacityWitnessAsync(db, fixture);
        var activeSeat = Assert.Single(await db.LicenseSeats.Where(item => item.LicenseId == fixture.LicenseId
            && item.IsActive && (fixture.CapacityWitnessId == null || item.Id != fixture.CapacityWitnessId)).ToListAsync());
        Assert.Equal(successor.LicenseSeatId, activeSeat.Id);
        Assert.Equal(fixture.Request.HardwareId, activeSeat.HardwareId);
        Assert.Equal(fixture.CapacityWitnessId.HasValue ? 3 : 2, await db.LicenseSeats.CountAsync(item => item.LicenseId == fixture.LicenseId));
    }

    /// <summary>Checks that a rejected request leaves no pending seat, successor, receipt or success history behind.</summary>
    /// <param name="fixture">A graph originally containing one active binding and one seat, without a preseeded target.</param>
    private static async Task AssertPendingSeatRollbackAsync(PendingSeatFixture fixture)
    {
        await using var db = await fixture.Factory.CreateDbContextAsync();
        await AssertPendingCapacityWitnessAsync(db, fixture);
        Assert.Equal(fixture.CapacityWitnessId.HasValue ? 2 : 1,
            await db.LicenseSeats.CountAsync(item => item.LicenseId == fixture.LicenseId));
        Assert.Single(await db.LicenseSeats.Where(item => item.LicenseId == fixture.LicenseId
            && (fixture.CapacityWitnessId == null || item.Id != fixture.CapacityWitnessId)).ToListAsync());
        Assert.Single(await db.DistributionInstallationBindings.Where(item => item.LicenseId == fixture.LicenseId).ToListAsync());
        Assert.Equal("active", (await db.DistributionInstallationBindings.SingleAsync(item => item.Id == fixture.SourceBindingId)).State);
        Assert.False(await db.DistributionBindingRequests.AnyAsync(item => item.RequestId == fixture.Request.RequestId));
        Assert.Empty(await db.LicenseHistories.Where(item => item.LicenseId == fixture.LicenseId
            && (item.Action == "RUNTIME_INITIAL_SEAT_CREATED" || item.Action == "RUNTIME_INITIAL_SEAT_REACTIVATED")).ToListAsync());
    }

    /// <summary>Verifies that capacity competition neither releases nor rewrites the unrelated original seat.</summary>
    private static async Task AssertPendingCapacityWitnessAsync(LicenseDbContext db, PendingSeatFixture fixture)
    {
        if (!fixture.CapacityWitnessId.HasValue) return;
        var witness = await db.LicenseSeats.SingleAsync(row => row.Id == fixture.CapacityWitnessId);
        Assert.True(witness.IsActive);
        Assert.Equal("AAAABBBBCCCCDDDD", witness.HardwareId);
        Assert.Equal(fixture.CapacityWitnessAt, witness.FirstActivatedAt);
        Assert.Equal(fixture.CapacityWitnessAt, witness.LastCheckInAt);
        Assert.Null(witness.UnlinkedAt);
    }

    /// <summary>Synthetic test ownership bundle, including optional immutable capacity-witness facts; Admin must never be rendered or logged.</summary>
    private sealed record PendingSeatFixture(TestDbFactory Factory, DistributionInstallationBindingService Service,
        string Admin, Guid LicenseId, Guid SourceBindingId, Guid SourceSeatId, DistributionInstallationFinalizeRequest Request,
        Guid? CapacityWitnessId, DateTime CapacityWitnessAt);
}

using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// The identity validator can prove an enrolled key and approved release without commercial
    /// rows. This unit boundary prevents an accidental assignment lookup in the cryptographic path.
    /// </summary>
    [Fact]
    public async Task EnrollmentIdentity_NoCommercialRows_ValidatesIndependentRelease()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase("enrollment-identity-" + Guid.NewGuid().ToString("N")).Options;
        await using var db = new LicenseDbContext(options);
        var productId = Guid.NewGuid();
        const string version = "2.2.916";
        foreach (var key in new[] { "FP_CORE", "FP_DLL", "FP_EXE" })
            db.ApprovedBinaries.Add(new ApprovedBinary
            {
                ProductId = productId, Version = version, Key = key,
                Hash = new string('a', 64), Source = ApprovedBinaryService.ReleaseSource
            });
        await db.SaveChangesAsync();

        var enrollment = new RuntimeEnrollment
        {
            ProductId = productId, State = "PENDING", Epoch = 1, SecurityEpoch = 1,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion, Algorithm = "PS256",
            InstallationId = Guid.NewGuid().ToString("D"), ReleaseVersion = version,
            PublicKeySpkiCiphertext = "encrypted", PublicKeySpkiKeyId = "key-id",
            PublicKeySpkiSha256 = new string('b', 64), KeyThumbprint = "thumbprint"
        };
        var result = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
            db, enrollment, "PENDING", false, null, CancellationToken.None);
        Assert.Equal(3, result.Binaries.Count);
        Assert.Empty(db.EnrollmentLicenseAssignments);
        Assert.Empty(db.Licenses);
        Assert.Empty(db.LicenseSeats);
    }

    /// <summary>
    /// A copied historical hardware hash is neither key identity nor a commercial assignment.
    /// Changing it alone cannot revise the assignment or refuse a valid capability.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_CopiedHardwareChangeDoesNotChangeGrantOrCredential()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        EnrollmentLicenseAssignment before;
        await using (var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            before = await admin.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            await admin.RuntimeEnrollments.Where(row => row.Id == scenario.EnrollmentId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    row => row.HardwareIdHash, new string('f', 64)));
        }

        var request = AssignmentCapabilityRequest(scenario);
        var digest = Sha256("copied-hardware-independent-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId,
            request.Audience!, "-", digest);
        var issued = await scenario.Runtime.CreateCapabilityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.False(issued.Idempotent);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var after = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(before.Id, after.Id);
        Assert.Equal(before.Revision, after.Revision);
        Assert.Equal(before.LicenseId, after.LicenseId);
        Assert.Equal(before.LicenseSeatId, after.LicenseSeatId);
    }

    /// <summary>
    /// Component-ban keys retain their historical case-insensitive lookup so the new commercial
    /// validator cannot grant a capability from a differently cased provider row.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_MixedCaseComponentBanDeniesWithoutCryptoMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        RuntimeEnrollment original;
        await using (var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            original = await admin.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var hash = await admin.ApprovedBinaries.AsNoTracking()
                .Where(row => row.ProductId == scenario.Fixture.ProductId
                    && row.Version == scenario.Fixture.Version && row.Key == "FP_EXE")
                .Select(row => row.Hash).SingleAsync();
            admin.BannedComponents.Add(new BannedComponent
            {
                ProductId = scenario.Fixture.ProductId,
                ComponentType = "fp_exe",
                ComponentHash = hash,
                IsActive = true,
                Reason = "item3a-test"
            });
            await admin.SaveChangesAsync();
        }

        var request = AssignmentCapabilityRequest(scenario);
        var digest = Sha256("assignment-component-ban-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId,
            request.Audience!, "-", digest);
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.CreateCapabilityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal("authority_ineligible", denied.ErrorCode);
        Assert.Equal("component_banned", denied.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var current = await check.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", current.State);
        Assert.Equal(original.SecurityEpoch, current.SecurityEpoch);
        Assert.Equal(original.AuthorityEpoch, current.AuthorityEpoch);
        Assert.Null(current.InvalidationReason);
    }

    /// <summary>
    /// A valid challenge and enrolled key cannot activate a pending enrollment after its commercial
    /// assignment ends. Refusal leaves the challenge and cryptographic epochs available for diagnosis.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_ConfirmCommercialDenialPreservesPendingCredential()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        RuntimeEnrollment original;
        await using (var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            original = await admin.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var assignment = await admin.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var license = await admin.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.IsActive = false;
            await admin.SaveChangesAsync();
        }

        var request = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = original.Epoch
        };
        var digest = Sha256("assignment-confirm-denial-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "confirm", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.ConfirmAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal("authority_ineligible", denied.ErrorCode);
        Assert.Equal("assignment_missing", denied.DiagnosticCode);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var current = await check.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("PENDING", current.State);
        Assert.Equal(original.Epoch, current.Epoch);
        Assert.Equal(original.SecurityEpoch, current.SecurityEpoch);
        Assert.Equal(original.AuthorityEpoch, current.AuthorityEpoch);
        Assert.Null(current.ChallengeConsumedAtUtc);
        Assert.Null(current.InvalidationReason);
    }

    /// <summary>
    /// A frozen Confirm response cannot reactivate an enrollment whose right ended after the first
    /// response. The proof nonce remains historical evidence and the credential stays intact.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_ConfirmReplayRechecksCurrentCommercialRight()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        var request = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"), Epoch = 1
        };
        var digest = Sha256("assignment-confirm-replay-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "confirm", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        var issued = await scenario.Runtime.ConfirmAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.False(issued.Idempotent);

        RuntimeEnrollment original;
        await using (var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            original = await admin.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var assignment = await admin.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var license = await admin.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.IsActive = false;
            await admin.SaveChangesAsync();
        }

        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.ConfirmAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal("authority_ineligible", denied.ErrorCode);
        Assert.Equal("assignment_missing", denied.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var current = await check.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", current.State);
        Assert.Equal(original.KeyThumbprint, current.KeyThumbprint);
        Assert.Equal(original.SecurityEpoch, current.SecurityEpoch);
        Assert.Equal(original.AuthorityEpoch, current.AuthorityEpoch);
        Assert.Null(current.InvalidationReason);
    }

    /// <summary>
    /// An ended commercial right refuses a frozen capability replay without altering the enrolled
    /// key, security epoch or terminal evidence. The initial issue also proves both validators pass.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_RevokedLicenseDeniesCapabilityReplayWithoutCryptoMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = AssignmentCapabilityRequest(scenario);
        var digest = Sha256("assignment-capability-replay-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId,
            request.Audience!, "-", digest);
        var issued = await scenario.Runtime.CreateCapabilityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.False(issued.Idempotent);

        RuntimeEnrollment original;
        await using (var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            original = await admin.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var assignment = await admin.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var license = await admin.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.IsActive = false;
            await admin.SaveChangesAsync();
        }

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.CreateCapabilityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refused.StatusCode);
        Assert.Equal("authority_ineligible", refused.ErrorCode);
        Assert.Equal("assignment_missing", refused.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var current = await check.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", current.State);
        Assert.Equal(original.Epoch, current.Epoch);
        Assert.Equal(original.SecurityEpoch, current.SecurityEpoch);
        Assert.Equal(original.AuthorityEpoch, current.AuthorityEpoch);
        Assert.Equal(original.KeyThumbprint, current.KeyThumbprint);
        Assert.Null(current.InvalidationReason);
        Assert.Empty(await check.EnrollmentLicenseAssignments.Where(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>
    /// A quarantined enrollment has no grant even when its credential and approved release remain
    /// valid. The two validators expose distinct bounded diagnostics and do not change the row.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_QuarantineRefusesCommerciallyWithoutInvalidatingIdentity()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext();
        var enrollment = await admin.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        var identity = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
            admin, enrollment, "PENDING", false, null, CancellationToken.None);
        Assert.Equal(3, identity.Binaries.Count);

        var invalidState = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            RuntimeEnrollmentIdentityValidator.ValidateAsync(
                admin, enrollment, "ACTIVE", false, null, CancellationToken.None));
        Assert.Equal("enrollment_state_invalid", invalidState.DiagnosticCode);

        await admin.EnrollmentLicenseAssignments.Where(row => row.EnrollmentId == scenario.EnrollmentId)
            .ExecuteDeleteAsync();
        var assignment = await admin.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleOrDefaultAsync(row => row.EnrollmentId == scenario.EnrollmentId);
        admin.EnrollmentLicenseAssignmentQuarantines.Add(new EnrollmentLicenseAssignmentQuarantine
        {
            EnrollmentId = scenario.EnrollmentId,
            BindingId = scenario.Fixture.BindingId,
            LicenseId = assignment?.LicenseId,
            LicenseSeatId = assignment?.LicenseSeatId,
            Reason = "binding_mismatch",
            ObservedAtUtc = DateTime.UtcNow
        });
        await admin.SaveChangesAsync();

        var assessment = await RuntimeCommercialEligibilityValidator.AssessAsync(
            admin, enrollment, identity.Binaries, DateTimeOffset.UtcNow, null, CancellationToken.None);
        Assert.Equal(RuntimeCommercialEligibilityValidator.AssessmentOutcome.Denied, assessment.Outcome);
        Assert.False(assessment.IsEligible);
        Assert.Equal("assignment_quarantined", assessment.DenialReason);
        Assert.Null(assessment.Assignment);
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            RuntimeCommercialEligibilityValidator.ValidateAsync(
                admin, enrollment, identity.Binaries, DateTimeOffset.UtcNow, CancellationToken.None));
        Assert.Equal("authority_ineligible", denied.ErrorCode);
        Assert.Equal("assignment_quarantined", denied.DiagnosticCode);
        var unchanged = await admin.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("PENDING", unchanged.State);
        Assert.Equal(enrollment.Epoch, unchanged.Epoch);
        Assert.Equal(enrollment.SecurityEpoch, unchanged.SecurityEpoch);
        Assert.Equal(enrollment.AuthorityEpoch, unchanged.AuthorityEpoch);
    }

    private static RuntimeEnrollmentCapabilityRequest AssignmentCapabilityRequest(
        PreparedBootstrapScenario scenario) => new()
    {
        Schema = RuntimeEnrollmentService.CapabilitySchema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        EnrollmentId = scenario.EnrollmentId.ToString("D"),
        Epoch = 1,
        SecurityEpoch = 1,
        InstallationId = scenario.Fixture.InstallationId,
        ReleaseVersion = scenario.Fixture.Version,
        SessionId = Guid.NewGuid().ToString("D"),
        Audience = "https://broker.example.test",
        Scope = ["runtime.execute"],
        Binaries = CapabilityBinaries()
    };

    /// <summary>
    /// Milestones grant a client-declared ACK only while current assignment policy allows it.
    /// A revoked licence blocks both an old ACK and a new sequence without invalidating the key.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_MilestoneNewAndReplayDeniedWithoutIdentityMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = new RuntimeMilestoneRequest
        {
            Schema = RuntimeEnrollmentService.MilestoneSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            SessionId = Guid.NewGuid().ToString("D"),
            Sequence = 1,
            EventId = Guid.NewGuid().ToString("D"),
            Code = "bootstrap_entered",
            OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow)
        };
        var digest = Sha256(System.Text.Json.JsonSerializer.Serialize(request));
        var proof = Proof(scenario.EnrollmentKey, "milestone", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var issued = await scenario.Runtime.RecordMilestoneAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.False(issued.Idempotent);

        scenario.Options.ProofClockSkewSeconds = 0;
        await Task.Delay(20);
        var oldProofReplay = await scenario.Runtime.RecordMilestoneAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.True(oldProofReplay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, oldProofReplay.ExactResponseBody);

        RuntimeEnrollment original;
        await using (var admin = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            original = await admin.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var assignment = await admin.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            var license = await admin.Licenses.SingleAsync(row => row.Id == assignment.LicenseId);
            license.IsActive = false;
            await admin.SaveChangesAsync();
        }

        var replayDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RecordMilestoneAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));
        Assert.Equal("authority_ineligible", replayDenied.ErrorCode);
        Assert.Equal("assignment_missing", replayDenied.DiagnosticCode);
        request.Sequence = 2;
        request.EventId = Guid.NewGuid().ToString("D");
        var nextDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(request));
        var nextDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RecordMilestoneAsync(scenario.EnrollmentId, nextDigest, request,
                Proof(scenario.EnrollmentKey, "milestone", scenario.EnrollmentId,
                    scenario.Options.ConfirmAudience, "-", nextDigest), IPAddress.Loopback));
        Assert.Equal("authority_ineligible", nextDenied.ErrorCode);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var current = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", current.State);
        Assert.Equal(original.KeyThumbprint, current.KeyThumbprint);
        Assert.Equal(original.SecurityEpoch, current.SecurityEpoch);
        Assert.Equal(original.AuthorityEpoch, current.AuthorityEpoch);
        Assert.Null(current.InvalidationReason);
        Assert.Equal(1, await check.RuntimeMilestones.CountAsync(row => row.EnrollmentId == scenario.EnrollmentId));
    }

    /// <summary>
    /// A milestone replay that waits behind the commercial barrier uses PostgreSQL time sampled
    /// after the wait. A licence expiring while blocked therefore refuses the frozen ACK without
    /// charging quota or changing the enrolled credential and historical milestone evidence.
    /// </summary>
    [Fact]
    public async Task AssignmentValidation_MilestoneReplayExpiryDuringBarrierWaitRefusesWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = new RuntimeMilestoneRequest
        {
            Schema = RuntimeEnrollmentService.MilestoneSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            SessionId = Guid.NewGuid().ToString("D"),
            Sequence = 1,
            EventId = Guid.NewGuid().ToString("D"),
            Code = "bootstrap_entered",
            OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow)
        };
        var digest = Sha256(System.Text.Json.JsonSerializer.Serialize(request));
        var proof = Proof(scenario.EnrollmentKey, "milestone", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var issued = await scenario.Runtime.RecordMilestoneAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        Assert.False(issued.Idempotent);

        RuntimeEnrollment before;
        int quotaCount;
        DateTimeOffset expiresAt;
        await using (var arrange = new TestDbFactory(scenario.AdminConnectionString).CreateDbContext())
        {
            await arrange.Database.OpenConnectionAsync();
            var now = await RuntimeEnrollmentService.DatabaseNowAsync(arrange, CancellationToken.None);
            expiresAt = now.AddSeconds(1);
            var licenseId = await arrange.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE")
                .Select(row => row.LicenseId)
                .SingleAsync();
            var license = await arrange.Licenses.SingleAsync(row => row.Id == licenseId);
            license.ExpirationDate = expiresAt.UtcDateTime;
            await arrange.SaveChangesAsync();
            before = await arrange.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            quotaCount = await arrange.RuntimeEnrollmentQuotas.CountAsync();
        }

        await using var blocker = new NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync();
        await using var blockerTransaction = await blocker.BeginTransactionAsync();
        await using (var takeBarrier = new NpgsqlCommand(
                         "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", blocker, blockerTransaction))
            await takeBarrier.ExecuteNonQueryAsync();
        var pending = scenario.Runtime.RecordMilestoneAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
        await observer.OpenAsync();
        await WaitForSharedCommercialBarrierWaiterAsync(observer, blocker.ProcessID);
        while (await ScalarAsync<DateTime>(observer,
                   "SELECT pg_catalog.clock_timestamp() AT TIME ZONE 'UTC' AS \"Value\";")
               <= expiresAt.UtcDateTime)
        {
            await Task.Delay(20);
        }
        Assert.False(pending.IsCompleted);
        await blockerTransaction.CommitAsync();

        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => pending);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
        Assert.Equal("authority_ineligible", denied.ErrorCode);
        Assert.Equal("commercial_authority_ineligible", denied.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var current = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal(before.Epoch, current.Epoch);
        Assert.Equal(before.SecurityEpoch, current.SecurityEpoch);
        Assert.Equal(before.AuthorityEpoch, current.AuthorityEpoch);
        Assert.Equal(quotaCount, await check.RuntimeEnrollmentQuotas.CountAsync());
        Assert.Single(await check.RuntimeMilestones.Where(row => row.EnrollmentId == scenario.EnrollmentId).ToListAsync());
        Assert.Single(await check.RuntimeEnrollmentProofNonces.Where(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.Operation == "milestone").ToListAsync());
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{
    protected const string Tkt1617KnownSystemUuid = "d1e3ecf4-8d7a-4e64-9f91-8a62bcf65410";
    protected const string Tkt1617NewSystemUuid = "4054867e-6f10-4b72-9df8-d9ae0b3a37ec";
    protected const string Tkt1617PreviousMigration = "20261004120000_AddRuntimeMachineClassification";
    protected const string Tkt1617Migration = "20261006110000_PreserveRelinkedEnrollmentAssignments";

    /// <summary>
    /// Exercises the complete known-enrollment distribution journey against current PostgreSQL authority. Since
    /// TKT-003751 the daily quota after the journey equals the count before plus one, unless the requested identifier
    /// was already activated today on the target licence or its seat was already active (no activation then).
    /// </summary>
    /// <param name="newHardware">Whether the proved machine identifier changes.</param>
    /// <param name="maximumSeats">Current licence capacity.</param>
    /// <param name="reuseHistoricalLicense">Whether the released historical licence is reused.</param>
    /// <param name="liveStateMismatch">Seeds the exact quarantined historical state and already active new seat.</param>
    /// <param name="invalidQuarantineEvidence">Optional historical or current authority defect that must be refused.</param>
    protected static async Task AssertTkt1617CommercialReattachmentAsync(
        bool newHardware,
        int maximumSeats,
        bool reuseHistoricalLicense,
        bool liveStateMismatch,
        string? invalidQuarantineEvidence = null)
    {
        var subjectRef = Base64Url(SHA256.HashData("tkt-001617-subject"u8.ToArray()));
        var knownHardware = Assert.IsType<string>(MachineIdentity.FromUuid(Tkt1617KnownSystemUuid).HardwareId);
        var requestedSystemUuid = newHardware ? Tkt1617NewSystemUuid : Tkt1617KnownSystemUuid;
        var requestedHardware = Assert.IsType<string>(MachineIdentity.FromUuid(requestedSystemUuid).HardwareId);
        using var scenario = await CreatePreparedBootstrapScenarioAsync(
            initialHardwareId: knownHardware,
            initialSubjectRef: subjectRef);
        await scenario.ConsumeAsync();
        await SetScenarioHardwareAuthorityAsync(scenario, knownHardware);
        var confirmRequest = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("tkt-001617-confirm-" + Guid.NewGuid().ToString("D"));
        var confirmProof = Proof(
            scenario.EnrollmentKey,
            "confirm",
            scenario.EnrollmentId,
            scenario.Options.ConfirmAudience,
            scenario.Prepared.Challenge,
            confirmDigest);
        var initialConfirm = await scenario.Runtime.ConfirmAsync(
            scenario.EnrollmentId,
            confirmDigest,
            confirmRequest,
            confirmProof,
            IPAddress.Loopback);
        Assert.False(initialConfirm.Idempotent);

        await using (var enforcement = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString))
            await SetAssignmentSwitchAsync(enforcement, AssignmentEnforcementSetting.Closed);

        RuntimeCommercialReattachmentSnapshot historical;
        Guid historicalLicenseId;
        Guid historicalSeatId;
        await using (var beforeRelease = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await beforeRelease.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            var binding = await beforeRelease.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            var assignment = await beforeRelease.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
            historicalLicenseId = assignment.LicenseId;
            historicalSeatId = assignment.LicenseSeatId;
            historical = RuntimeCommercialReattachmentSnapshot.Capture(enrollment, binding);
        }

        var portal = new PortalDeactivationService(
            scenario.Factory,
            TimeProvider.System,
            NullLogger<PortalDeactivationService>.Instance);
        var released = await portal.DeactivateAsync(
            "website-step1",
            Sha256("tkt-001617-release-" + Guid.NewGuid().ToString("D")),
            new PortalDeactivationRequest(
                PortalDeactivationService.RequestSchema,
                Guid.NewGuid().ToString("D"),
                scenario.Fixture.ProductId.ToString("D"),
                historicalLicenseId.ToString("D"),
                knownHardware,
                "settings_button"));
        Assert.Equal("deactivated", released.Response.Outcome);

        if (liveStateMismatch)
        {
            // Represent the populated migration state before any successor exists. Replication mode
            // is confined to fixture construction; the actual journey uses the production app role.
            await using var seed = new NpgsqlConnection(scenario.AdminConnectionString);
            await seed.OpenAsync();
            await using var transaction = await seed.BeginTransactionAsync();
            await using var command = new NpgsqlCommand("""
                SET LOCAL session_replication_role = replica;
                DELETE FROM public."EnrollmentLicenseAssignments" WHERE "EnrollmentId" = @enrollment;
                UPDATE public."Licenses" SET "ExpirationDate" = pg_catalog.clock_timestamp() - interval '1 day'
                WHERE "Id" = @license;
                INSERT INTO public."EnrollmentLicenseAssignmentQuarantines" (
                    "EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId", "Reason", "ObservedAtUtc")
                VALUES (@enrollment, @binding, @license, @seat, @reason,
                    pg_catalog.clock_timestamp() + @observationOffset);
                """, seed, transaction);
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            command.Parameters.AddWithValue("binding", scenario.Fixture.BindingId);
            command.Parameters.AddWithValue("license", historicalLicenseId);
            command.Parameters.AddWithValue("seat", historicalSeatId);
            command.Parameters.AddWithValue("reason", invalidQuarantineEvidence == "binding_mismatch"
                ? "binding_mismatch" : "live_state_mismatch");
            command.Parameters.AddWithValue("observationOffset", invalidQuarantineEvidence == "future_observation"
                ? TimeSpan.FromDays(1) : TimeSpan.Zero);
            await command.ExecuteNonQueryAsync();
            await transaction.CommitAsync();
        }

        var target = await CreateTkt1617TargetDistributionAsync(
            scenario,
            subjectRef,
            knownHardware,
            requestedHardware,
            maximumSeats,
            reuseHistoricalLicense,
            alreadyActivatedKnownSeat: liveStateMismatch);
        int usedChangesBefore;
        bool requestedAlreadyCountedOrActive;
        Guid? alreadyActivatedSeatId = null;
        string? quarantineBefore = null;
        await using (var releasedState = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.Equal("ACTIVE", (await releasedState.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
            if (liveStateMismatch)
            {
                Assert.Empty(await releasedState.EnrollmentLicenseAssignments.AsNoTracking()
                    .Where(row => row.EnrollmentId == scenario.EnrollmentId).ToListAsync());
                var quarantine = Assert.Single(await releasedState.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                    .Where(row => row.EnrollmentId == scenario.EnrollmentId).ToListAsync());
                Assert.Equal(invalidQuarantineEvidence == "binding_mismatch"
                    ? "binding_mismatch" : "live_state_mismatch", quarantine.Reason);
                Assert.Equal(historicalLicenseId, quarantine.LicenseId);
                Assert.Equal(historicalSeatId, quarantine.LicenseSeatId);
                quarantineBefore = JsonSerializer.Serialize(quarantine);
                Assert.False((await releasedState.LicenseSeats.AsNoTracking()
                    .SingleAsync(row => row.Id == historicalSeatId)).IsActive);
                Assert.True((await releasedState.Licenses.AsNoTracking()
                    .SingleAsync(row => row.Id == historicalLicenseId)).ExpirationDate < DateTime.UtcNow);
                var activeSeat = Assert.Single(await releasedState.LicenseSeats.AsNoTracking()
                    .Where(row => row.LicenseId == target.LicenseId).ToListAsync());
                Assert.True(activeSeat.IsActive);
                Assert.Equal(knownHardware, activeSeat.HardwareId);
                alreadyActivatedSeatId = activeSeat.Id;
            }
            else
                Assert.Equal("ENDED", (await releasedState.EnrollmentLicenseAssignments.AsNoTracking()
                    .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId)).State);
            Assert.Empty(await releasedState.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE")
                .ToListAsync());
            var targetLicense = await releasedState.Licenses.Include(row => row.Type)
                .SingleAsync(row => row.Id == target.LicenseId);
            usedChangesBefore = (await SeatChangeQuota.GetStatusAsync(
                releasedState,
                targetLicense,
                DateTime.UtcNow)).UsedToday;
            // TKT-003751: the reattachment adds the requested identifier to the day's count unless it was
            // already activated today on the target or its seat is already active (no activation then).
            var dayStart = DateTime.UtcNow.Date;
            requestedAlreadyCountedOrActive = await releasedState.LicenseSeats.AsNoTracking().AnyAsync(row =>
                row.LicenseId == target.LicenseId && row.HardwareId == requestedHardware
                && (row.IsActive || row.LastActivatedAt >= dayStart));
            // TKT-003751: the quota counts distinct identifiers activated today; the scenario activated its own
            // machine today, so a fresh target licence has counted that identifier at most once.
            if (!reuseHistoricalLicense)
                Assert.InRange(usedChangesBefore, 0, 1);
        }

        var preflightRequest = new RuntimeDistributionPreflightRequest
        {
            Schema = RuntimeDistributionPreflightService.RequestSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = target.LicenseId.ToString("D"),
            GrantRefDigestSha256 = target.GrantRefDigestSha256,
            InstallationId = scenario.Fixture.InstallationId,
            KeyThumbprint = scenario.PrepareRequest.Key!.KeyThumbprint,
            HardwareEvidence = new RuntimeDistributionHardwareEvidence
            {
                SystemUuid = requestedSystemUuid,
                MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence(
                    "Dell Inc.",
                    "Precision 7680")
            }
        };
        var preflight = new RuntimeDistributionPreflightService(
            new TestDbFactory(new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
            {
                Username = "softlicence_app",
                Password = "runtime-production-role-test-only",
                Pooling = false
            }.ConnectionString),
            NullLogger<RuntimeDistributionPreflightService>.Instance);
        RuntimeDistributionPreflightResponse? preflightResponse = null;
        var preflightFailure = await Record.ExceptionAsync(async () =>
            preflightResponse = await preflight.EvaluateAsync(
                target.ClientId,
                Sha256(JsonSerializer.Serialize(preflightRequest)),
                preflightRequest,
                CancellationToken.None));
        Assert.True(preflightFailure is null, preflightFailure is DistributionOperationException refusal
            ? $"Preflight refused with {refusal.ErrorCode}/{refusal.ReasonCode}."
            : preflightFailure?.ToString());
        Assert.NotNull(preflightResponse);
        Assert.Equal("accepted", preflightResponse.Decision);
        Assert.Equal(Sha256(requestedHardware), preflightResponse.HardwareIdHash);

        await using (var eligibility = await scenario.Factory.CreateDbContextAsync())
        await using (var transaction = await eligibility.Database.BeginTransactionAsync())
        {
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(
                eligibility,
                CancellationToken.None);
            var enrollment = await eligibility.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            var approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
                eligibility,
                enrollment,
                CancellationToken.None);
            var now = await RuntimeEnrollmentService.DatabaseNowAsync(eligibility, CancellationToken.None);
            var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                eligibility,
                enrollment,
                approved.Binaries,
                now,
                CancellationToken.None);
            Assert.Equal(target.LicenseId, assignment.LicenseId);
            Assert.Equal(requestedHardware, assignment.HardwareId);
            await transaction.RollbackAsync();
        }

        var finalizeDigest = Sha256("tkt-001617-finalize-" + Guid.NewGuid().ToString("D"));
        if (invalidQuarantineEvidence is not null)
        {
            if (invalidQuarantineEvidence == "current_assignment_scope_mismatch")
            {
                // A valid historical quarantine must not repair or bless a corrupt current relation.
                // Bypass triggers only to construct that durable corruption, never for the request.
                await using var corrupt = new NpgsqlConnection(scenario.AdminConnectionString);
                await corrupt.OpenAsync();
                await using var corruptionTransaction = await corrupt.BeginTransactionAsync();
                await using var corruptCommand = new NpgsqlCommand("""
                    SET LOCAL session_replication_role = replica;
                    UPDATE public."EnrollmentLicenseAssignments" SET "LicenseSeatId" = @historicalSeat
                    WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                    """, corrupt, corruptionTransaction);
                corruptCommand.Parameters.AddWithValue("historicalSeat", historicalSeatId);
                corruptCommand.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
                Assert.Equal(1, await corruptCommand.ExecuteNonQueryAsync());
                await corruptionTransaction.CommitAsync();
            }
            await using var beforeRefusal = await scenario.Factory.CreateDbContextAsync();
            var requestCount = await beforeRefusal.DistributionBindingRequests.CountAsync();
            var businessBeforeRefusal = await ReadTkt1617CommercialStateAsync(beforeRefusal);
            var finalizeRefusal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                target.Service.FinalizeAsync(target.ClientId, finalizeDigest, target.FinalizeRequest));
            Assert.Equal("binding_conflict", finalizeRefusal.ErrorCode);
            Assert.Equal("replacement_existing_installation_conflict", finalizeRefusal.ReasonCode);
            await using var afterRefusal = await scenario.Factory.CreateDbContextAsync();
            Assert.Equal(requestCount, await afterRefusal.DistributionBindingRequests.CountAsync());
            Assert.Equal(businessBeforeRefusal, await ReadTkt1617CommercialStateAsync(afterRefusal));
            Assert.Equal(quarantineBefore, JsonSerializer.Serialize(
                await afterRefusal.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                    .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId)));
            Assert.Equal(historical, RuntimeCommercialReattachmentSnapshot.Capture(
                await afterRefusal.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId),
                await afterRefusal.DistributionInstallationBindings.AsNoTracking()
                    .SingleAsync(row => row.Id == scenario.Fixture.BindingId)));
            return;
        }
        var finalized = await target.Service.FinalizeAsync(
            target.ClientId,
            finalizeDigest,
            target.FinalizeRequest);
        string commercialStateAfterFinalize;
        await using (var afterFinalize = await scenario.Factory.CreateDbContextAsync())
            commercialStateAfterFinalize = await ReadTkt1617CommercialStateAsync(afterFinalize);
        var replay = await target.Service.FinalizeAsync(
            target.ClientId,
            finalizeDigest,
            target.FinalizeRequest);
        Assert.False(finalized.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(finalized.Response, replay.Response);

        await using (var afterExactReplay = await scenario.Factory.CreateDbContextAsync())
            Assert.Equal(commercialStateAfterFinalize, await ReadTkt1617CommercialStateAsync(afterExactReplay));
        var originalRequestId = target.FinalizeRequest.RequestId;
        // A finalized entitlement permits its exact request replay only. A fresh request using the
        // same grant must hit that consumed-grant guard instead of returning the cache or charging again.
        target.FinalizeRequest.RequestId = Guid.NewGuid().ToString("D");
        var freshDigest = Sha256(JsonSerializer.Serialize(target.FinalizeRequest));
        var consumedGrantRefusal = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            target.Service.FinalizeAsync(target.ClientId, freshDigest, target.FinalizeRequest));
        Assert.Equal("entitlement_ineligible", consumedGrantRefusal.ErrorCode);
        await using (var afterConsumedGrant = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.False(await afterConsumedGrant.DistributionBindingRequests.AsNoTracking().AnyAsync(row =>
                row.ClientId == target.ClientId && row.RequestId == target.FinalizeRequest.RequestId));
            Assert.Equal(commercialStateAfterFinalize, await ReadTkt1617CommercialStateAsync(afterConsumedGrant));
        }

        // A genuinely new grant goes through known-enrollment preflight and uncached finalization,
        // retaining the same identity and current seat without another customer hardware change.
        var freshGrant = Guid.NewGuid().ToString("D");
        var freshEntitlement = await target.Service.IssueEntitlementAsync(target.ClientId,
            Sha256("tkt-001617-fresh-entitlement-" + Guid.NewGuid().ToString("D")),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = scenario.Fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = target.LicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(freshGrant),
                SubjectRef = subjectRef
            });
        preflightRequest.RequestId = Guid.NewGuid().ToString("D");
        preflightRequest.GrantRefDigestSha256 = Sha256(freshGrant);
        var freshPreflight = await preflight.EvaluateAsync(target.ClientId,
            Sha256(JsonSerializer.Serialize(preflightRequest)), preflightRequest, CancellationToken.None);
        Assert.Equal("accepted", freshPreflight.Decision);
        target.FinalizeRequest.RequestId = Guid.NewGuid().ToString("D");
        target.FinalizeRequest.GrantRef = freshGrant;
        target.FinalizeRequest.EntitlementRef = freshEntitlement.Response.EntitlementRef;
        freshDigest = Sha256(JsonSerializer.Serialize(target.FinalizeRequest));
        var freshFinalize = await target.Service.FinalizeAsync(
            target.ClientId, freshDigest, target.FinalizeRequest);
        Assert.NotEqual(originalRequestId, target.FinalizeRequest.RequestId);
        Assert.False(freshFinalize.Idempotent);
        Assert.Equal(finalized.Response, freshFinalize.Response);
        await using (var afterFreshFinalize = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.True(await afterFreshFinalize.DistributionBindingRequests.AsNoTracking().AnyAsync(row =>
                row.ClientId == target.ClientId && row.RequestId == target.FinalizeRequest.RequestId));
            Assert.Equal(commercialStateAfterFinalize, await ReadTkt1617CommercialStateAsync(afterFreshFinalize));
        }

        // An ACTIVE known enrollment cannot legitimately be prepared again. Replaying Prepare must
        // reach the normal lifecycle refusal after validating the repaired assignment, while the exact
        // signed Confirm replay must still return its original terminal response without rewriting identity.
        var prepareReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.PrepareAsync(
                "website-step1", scenario.PrepareDigest, scenario.PrepareRequest));
        Assert.Equal(StatusCodes.Status409Conflict, prepareReplay.StatusCode);
        Assert.Equal("prepare_superseded", prepareReplay.ErrorCode);
        var confirmReplay = await scenario.Runtime.ConfirmAsync(
            scenario.EnrollmentId,
            confirmDigest,
            confirmRequest,
            confirmProof,
            IPAddress.Loopback);
        Assert.True(confirmReplay.Idempotent);
        Assert.Equal(initialConfirm.Response, confirmReplay.Response);

        if (target.LicenseId != historicalLicenseId)
        {
            await using var historicalMutation = new LicenseDbContext(
                new DbContextOptionsBuilder<LicenseDbContext>()
                    .UseNpgsql(scenario.AdminConnectionString).Options);
            var historicalLicense = await historicalMutation.Licenses
                .SingleAsync(row => row.Id == historicalLicenseId);
            historicalLicense.IsActive = false;
            await historicalMutation.SaveChangesAsync();
        }

        await using var verification = await scenario.Factory.CreateDbContextAsync();
        var active = Assert.Single(await verification.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE")
            .ToListAsync());
        Assert.Equal(target.LicenseId, active.LicenseId);
        if (liveStateMismatch)
        {
            Assert.Equal(1, active.Revision);
            Assert.Equal(alreadyActivatedSeatId, active.LicenseSeatId);
            Assert.Single(await verification.LicenseSeats.AsNoTracking()
                .Where(row => row.LicenseId == target.LicenseId).ToListAsync());
            Assert.Equal(quarantineBefore, JsonSerializer.Serialize(
                await verification.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                    .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId)));
            Assert.False((await verification.LicenseSeats.AsNoTracking()
                .SingleAsync(row => row.Id == historicalSeatId)).IsActive);
        }
        else
        {
            var ended = Assert.Single(await verification.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ENDED").ToListAsync());
            Assert.Equal(2, active.Revision);
            Assert.Equal(1, ended.Revision);
            Assert.Equal("seat_released", ended.EndReason);
        }
        Assert.Equal(historical, RuntimeCommercialReattachmentSnapshot.Capture(
            await verification.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId),
            await verification.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.Fixture.BindingId)));
        var finalTargetLicense = await verification.Licenses.Include(row => row.Type)
            .SingleAsync(row => row.Id == target.LicenseId);
        var finalTargetSeat = Assert.Single(await verification.LicenseSeats.AsNoTracking()
            .Where(row => row.LicenseId == target.LicenseId && row.IsActive
                && row.HardwareId == requestedHardware)
            .ToListAsync());
        Assert.Equal(requestedHardware, finalTargetSeat.HardwareId);
        Assert.Equal(
            usedChangesBefore + (requestedAlreadyCountedOrActive ? 0 : 1),
            (await SeatChangeQuota.GetStatusAsync(
                verification,
                finalTargetLicense,
                DateTime.UtcNow)).UsedToday);
        Assert.True(await verification.AssignmentEnforcementSettings.AsNoTracking()
            .AnyAsync(row => row.Id == 1 && row.Mode == AssignmentEnforcementSetting.Closed));
        Assert.InRange(
            await verification.LicenseSeats.CountAsync(row => row.LicenseId == target.LicenseId && row.IsActive),
            0,
            finalTargetLicense.MaxSeats);
    }

    /// <summary>Captures the resolver's supplied mutable commercial inputs without navigation cycles.</summary>
    /// <param name="enrollment">The source cryptographic identity whose subject must remain exact.</param>
    /// <param name="license">The supplied licence and loaded seats that a refusal must leave untouched.</param>
    /// <returns>A deterministic scalar snapshot of caller-visible identity, licence and seat state.</returns>
    protected static string Tkt1617ResolverInputSnapshot(RuntimeEnrollment enrollment, License license) =>
        JsonSerializer.Serialize(new
        {
            Enrollment = new { enrollment.Id, enrollment.SubjectRefDigestSha256, enrollment.State,
                enrollment.LicenseId, enrollment.LicenseSeatId, enrollment.BindingId },
            License = new { license.Id, license.ProductId, license.LicenseTypeId, license.IsActive,
                license.MaxSeats, license.HardwareId, license.ActivationDate, license.ExpirationDate,
                license.RevokedAt, license.AllowedVersions },
            Seats = license.Seats.OrderBy(row => row.Id).Select(row => new
                { row.Id, row.LicenseId, row.HardwareId, row.IsActive, row.UnlinkedAt,
                    row.FirstActivatedAt, row.LastCheckInAt }).ToArray()
        });

    /// <summary>
    /// Reads business rows and counted quota history, excluding expected request/refusal audit entries.
    /// Refusals and an uncached successful replay must leave these identity, capacity and quota rows unchanged.
    /// </summary>
    /// <param name="db">Context for the exact isolated PostgreSQL or in-memory test database.</param>
    /// <returns>A deterministic persisted business-state snapshot, without navigation properties.</returns>
    protected static async Task<string> ReadTkt1617CommercialStateAsync(LicenseDbContext db)
    {
        var licenses = await db.Licenses.AsNoTracking().Include(row => row.Type)
            .OrderBy(row => row.Id).ToListAsync();
        var quotas = new List<object>();
        foreach (var license in licenses)
            quotas.Add(new { license.Id, Quota = await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow) });
        return JsonSerializer.Serialize(new
        {
            Quotas = quotas,
            Licenses = licenses.Select(row => new
                { row.Id, row.ProductId, row.LicenseTypeId, row.IsActive, row.MaxSeats, row.HardwareId,
                    row.ActivationDate, row.ExpirationDate, row.RevokedAt, row.AllowedVersions }).ToArray(),
            Seats = await db.LicenseSeats.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
            History = await db.LicenseHistories.AsNoTracking().Where(row =>
                    row.Action == HistoryActions.UnlinkedApi
                    || row.Action == HistoryActions.RuntimeCommercialNewIdentifier
                    || row.Action == HistoryActions.HardwareIdMigrated)
                .OrderBy(row => row.Id).ToListAsync(),
            Assignments = await db.EnrollmentLicenseAssignments.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
            Quarantines = await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                .OrderBy(row => row.EnrollmentId).ToListAsync(),
            Enrollments = await db.RuntimeEnrollments.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
            Bindings = await db.DistributionInstallationBindings.AsNoTracking().OrderBy(row => row.Id).ToListAsync()
        });
    }

    /// <summary>Creates one server-authorized successor without rewriting historical identity.</summary>
    protected static async Task<Tkt1617SuccessorAssignment> CreateTkt1617SuccessorAssignmentAsync(
        PreparedBootstrapScenario scenario,
        string subjectRef,
        string knownHardware,
        bool quarantineHistoricalBinding)
    {
        Guid historicalLicenseId;
        Guid historicalSeatId;
        await using (var release = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await release.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            historicalLicenseId = enrollment.LicenseId;
            historicalSeatId = enrollment.LicenseSeatId;
            var seat = await release.LicenseSeats.SingleAsync(row => row.Id == historicalSeatId);
            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow;
            await release.SaveChangesAsync();
        }

        var target = await CreateTkt1617TargetDistributionAsync(
            scenario,
            subjectRef,
            knownHardware,
            Assert.IsType<string>(MachineIdentity.FromUuid(Tkt1617NewSystemUuid).HardwareId),
            maximumSeats: 2,
            reuseHistoricalLicense: false);
        Guid targetSeatId;
        Guid entitlementId;
        string subjectDigest;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
        {
            targetSeatId = await read.LicenseSeats.AsNoTracking()
                .Where(row => row.LicenseId == target.LicenseId && row.IsActive)
                .Select(row => row.Id)
                .SingleAsync();
            entitlementId = await read.DistributionEntitlements.AsNoTracking()
                .Where(row => row.LicenseId == target.LicenseId && row.ClientId == target.ClientId)
                .Select(row => row.Id)
                .SingleAsync();
            subjectDigest = Assert.IsType<string>((await read.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId)).SubjectRefDigestSha256);
        }

        Guid assignmentId;
        var production = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only",
            Pooling = false
        }.ConnectionString;
        await using (var relink = new NpgsqlConnection(production))
        {
            await relink.OpenAsync();
            await using var command = new NpgsqlCommand("""
                SELECT public.relink_runtime_commercial_assignment(
                    @enrollment, @license, @seat, @subject, @client, @entitlement, NULL, NULL);
                """, relink);
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            command.Parameters.AddWithValue("license", target.LicenseId);
            command.Parameters.AddWithValue("seat", targetSeatId);
            command.Parameters.AddWithValue("subject", subjectDigest);
            command.Parameters.AddWithValue("client", target.ClientId);
            command.Parameters.AddWithValue("entitlement", entitlementId);
            assignmentId = Assert.IsType<Guid>(await command.ExecuteScalarAsync());
        }

        if (quarantineHistoricalBinding)
        {
            await using var corrupt = new NpgsqlConnection(scenario.AdminConnectionString);
            await corrupt.OpenAsync();
            await using var transaction = await corrupt.BeginTransactionAsync();
            await using var command = new NpgsqlCommand("""
                SET LOCAL session_replication_role = replica;
                UPDATE public."DistributionInstallationBindings"
                SET "LicenseId" = @successorLicense
                WHERE "Id" = @binding;
                INSERT INTO public."EnrollmentLicenseAssignmentQuarantines" (
                    "EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId", "Reason", "ObservedAtUtc")
                VALUES (@enrollment, @binding, @historicalLicense, @historicalSeat,
                    'binding_mismatch', pg_catalog.clock_timestamp());
                """, corrupt, transaction);
            command.Parameters.AddWithValue("successorLicense", target.LicenseId);
            command.Parameters.AddWithValue("binding", scenario.Fixture.BindingId);
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            command.Parameters.AddWithValue("historicalLicense", historicalLicenseId);
            command.Parameters.AddWithValue("historicalSeat", historicalSeatId);
            await command.ExecuteNonQueryAsync();
            await transaction.CommitAsync();
        }

        return new Tkt1617SuccessorAssignment(assignmentId, targetSeatId);
    }

    /// <summary>Reads only PostgreSQL's function catalogue for the migration lifecycle assertion.</summary>
    protected static async Task<bool> Tkt1617RelinkHelperExistsAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT pg_catalog.to_regprocedure('public.sync_current_enrollment_license_assignment(uuid)') IS NOT NULL;",
            connection);
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>Reads PostgreSQL's catalogue for the narrowly granted relink writer.</summary>
    protected static async Task<bool> Tkt1617RelinkWriterExistsAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT pg_catalog.to_regprocedure('public.relink_runtime_commercial_assignment(uuid,uuid,uuid,text,text,uuid,text,uuid)') IS NOT NULL;",
            connection);
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>Proves the production role has the bounded writer but no direct assignment INSERT.</summary>
    protected static async Task<bool> Tkt1617ProductionRoleUsesOnlyRelinkWriterAsync(string connectionString)
    {
        var production = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only",
            Pooling = false
        }.ConnectionString;
        await using var connection = new NpgsqlConnection(production);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT NOT pg_catalog.has_table_privilege(
                       CURRENT_USER, 'public."EnrollmentLicenseAssignments"', 'INSERT')
                   AND pg_catalog.has_function_privilege(
                       CURRENT_USER,
                       'public.relink_runtime_commercial_assignment(uuid,uuid,uuid,text,text,uuid,text,uuid)',
                       'EXECUTE');
            """, connection);
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>Proves forged grant, subject, and seat inputs cannot use the privileged relink writer.</summary>
    protected static async Task Tkt1617ProductionRelinkWriterRejectsForgedAuthorityAsync(
        PreparedBootstrapScenario scenario)
    {
        Guid licenseId;
        Guid seatId;
        Guid entitlementId;
        string subjectDigest;
        int assignmentsBefore;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await read.RuntimeEnrollments.AsNoTracking().SingleAsync();
            licenseId = enrollment.LicenseId;
            seatId = enrollment.LicenseSeatId;
            subjectDigest = Assert.IsType<string>(enrollment.SubjectRefDigestSha256);
            entitlementId = await read.DistributionEntitlements.AsNoTracking()
                .Where(row => row.LicenseId == licenseId)
                .Select(row => row.Id)
                .SingleAsync();
            assignmentsBefore = await read.EnrollmentLicenseAssignments.CountAsync();
        }

        var production = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only",
            Pooling = false
        }.ConnectionString;
        await using var connection = new NpgsqlConnection(production);
        await connection.OpenAsync();

        await AssertRejectedAsync(Guid.NewGuid(), subjectDigest, seatId);
        await AssertRejectedAsync(entitlementId, Sha256("forged-subject"), seatId);
        await AssertRejectedAsync(entitlementId, subjectDigest, Guid.NewGuid());

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(assignmentsBefore, await verify.EnrollmentLicenseAssignments.CountAsync());
        return;

        async Task AssertRejectedAsync(Guid submittedEntitlementId, string submittedSubjectDigest, Guid submittedSeatId)
        {
            await using var command = new NpgsqlCommand("""
                SELECT public.relink_runtime_commercial_assignment(
                    @enrollment, @license, @seat, @subject, @client, @entitlement, NULL, NULL);
                """, connection);
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            command.Parameters.AddWithValue("license", licenseId);
            command.Parameters.AddWithValue("seat", submittedSeatId);
            command.Parameters.AddWithValue("subject", submittedSubjectDigest);
            command.Parameters.AddWithValue("client", "website-step1");
            command.Parameters.AddWithValue("entitlement", submittedEntitlementId);
            var refusal = await Assert.ThrowsAsync<PostgresException>(async () =>
                await command.ExecuteScalarAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, refusal.SqlState);
            Assert.StartsWith("runtime_commercial_relink_", refusal.MessageText, StringComparison.Ordinal);
        }
    }

    /// <summary>Creates the target same-subject commercial licence and a genuine V4 Finalize request.</summary>
    /// <param name="scenario">The historical proved enrollment fixture.</param>
    /// <param name="subjectRef">The exact server-proved opaque owner reference.</param>
    /// <param name="initialHardwareId">Hardware from the historical seat.</param>
    /// <param name="requestedHardwareId">Hardware proved by the new distribution request.</param>
    /// <param name="maximumSeats">Target licence capacity.</param>
    /// <param name="reuseHistoricalLicense">Reuses the existing licence instead of creating a new one.</param>
    /// <param name="alreadyActivatedKnownSeat">Creates the current seat as already active at full mono capacity.</param>
    /// <returns>The issued entitlement and exact finalization scope for the target licence.</returns>
    protected static async Task<Tkt1617TargetDistribution> CreateTkt1617TargetDistributionAsync(
        PreparedBootstrapScenario scenario,
        string subjectRef,
        string initialHardwareId,
        string requestedHardwareId,
        int maximumSeats,
        bool reuseHistoricalLicense,
        bool alreadyActivatedKnownSeat = false)
    {
        Guid licenseId;
        List<DistributionBinaryEvidence> binaries;
        string installationId;
        Guid sourceBindingId;
        Guid sourceLicenseId;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var source = await db.Licenses.SingleAsync();
            var identifierIsNew = !string.Equals(
                initialHardwareId, requestedHardwareId, StringComparison.Ordinal);
            License target;
            if (reuseHistoricalLicense)
            {
                Assert.False(identifierIsNew);
                target = source;
                target.MaxSeats = maximumSeats;
            }
            else
            {
                target = new License
                {
                    ProductId = source.ProductId,
                    LicenseTypeId = source.LicenseTypeId,
                    LicenseKey = "TKT1617-" + Guid.NewGuid().ToString("N"),
                    CustomerName = source.CustomerName,
                    CustomerEmail = source.CustomerEmail,
                    CreationDate = DateTime.UtcNow,
                    ExpirationDate = DateTime.UtcNow.AddYears(1),
                    CommercialNature = source.CommercialNature,
                    IsActive = true,
                    AllowedVersions = source.AllowedVersions,
                    MaxSeats = maximumSeats,
                    HardwareId = identifierIsNew || alreadyActivatedKnownSeat ? initialHardwareId : "TKT1617-OTHER-HARDWARE",
                    ActivationDate = DateTime.UtcNow
                };
                var seat = new LicenseSeat
                {
                    LicenseId = target.Id,
                    HardwareId = initialHardwareId,
                    IsActive = identifierIsNew || alreadyActivatedKnownSeat,
                    FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
                    LastCheckInAt = DateTime.UtcNow.AddDays(-1),
                    // TKT-003751: activated two days ago, set explicitly so the context does not stamp today.
                    LastActivatedAt = DateTime.UtcNow.AddDays(-2),
                    UnlinkedAt = identifierIsNew || alreadyActivatedKnownSeat ? null : DateTime.UtcNow.AddDays(-1)
                };
                db.Licenses.Add(target);
                db.LicenseSeats.Add(seat);
                if (!identifierIsNew && !alreadyActivatedKnownSeat)
                {
                    db.LicenseSeats.Add(new LicenseSeat
                    {
                        LicenseId = target.Id,
                        HardwareId = "TKT1617-OTHER-HARDWARE",
                        IsActive = true,
                        FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
                        LastCheckInAt = DateTime.UtcNow.AddDays(-1),
                        LastActivatedAt = DateTime.UtcNow.AddDays(-2)
                    });
                }
            }
            await db.SaveChangesAsync();
            licenseId = target.Id;
            var enrollment = await db.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.EnrollmentId);
            installationId = enrollment.InstallationId;
            sourceBindingId = enrollment.BindingId;
            sourceLicenseId = enrollment.LicenseId;
            binaries = await db.ApprovedBinaries.AsNoTracking()
                .Where(row => row.ProductId == scenario.Fixture.ProductId
                    && row.Version == scenario.Fixture.Version
                    && row.Source == ApprovedBinaryService.ReleaseSource)
                .OrderBy(row => row.Key)
                .Select(row => new DistributionBinaryEvidence { Key = row.Key, Sha256 = row.Hash })
                .ToListAsync();
        }
        Assert.Equal(3, binaries.Count);

        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            scenario.Factory,
            new EphemeralDataProtectionProvider(),
            new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grantRef = Guid.NewGuid().ToString("D");
        var issued = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("tkt-001617-entitlement-" + Guid.NewGuid().ToString("D")),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = scenario.Fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = licenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef),
                SubjectRef = subjectRef
            });
        var request = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeV4Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("tkt-001617-handoff-" + Guid.NewGuid().ToString("D")),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-2)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-1)),
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            EntitlementRef = issued.Response.EntitlementRef,
            InstallationId = installationId,
            HardwareId = requestedHardwareId,
            AllowSameAuthorityRecovery = true,
            LicenseReplacementCandidates = new DistributionLicenseReplacementCandidateSet
            {
                Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
                Sources =
                [
                    new DistributionLicenseReplacementProof
                    {
                        Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
                        SourceBindingId = sourceBindingId.ToString("D"),
                        SourceLicenseId = sourceLicenseId.ToString("D"),
                        SourceSubjectRef = subjectRef
                    }
                ]
            },
            Release = new DistributionReleaseEvidence
            {
                Version = scenario.Fixture.Version,
                InstallerFilename = $"TiaConnect-Setup_v{scenario.Fixture.Version}.msi",
                InstallerSha256 = new string('f', 64)
            },
            Binaries = binaries
        };
        return new Tkt1617TargetDistribution(
            service,
            request,
            "website-step1",
            licenseId,
            Sha256(grantRef));
    }

    /// <summary>Target licence and authenticated distribution request used by the TKT-001617 regression.</summary>
    protected sealed record Tkt1617TargetDistribution(
        DistributionInstallationBindingService Service,
        DistributionInstallationFinalizeRequest FinalizeRequest,
        string ClientId,
        Guid LicenseId,
        string GrantRefDigestSha256);

    /// <summary>Identifiers needed to verify one server-authorized successor assignment.</summary>
    protected sealed record Tkt1617SuccessorAssignment(Guid AssignmentId, Guid SeatId);

    /// <summary>Immutable fields that commercial repair must never rewrite.</summary>
    protected sealed record RuntimeCommercialReattachmentSnapshot(
        Guid EnrollmentId,
        string EnrollmentClientId,
        Guid EnrollmentBindingId,
        Guid EnrollmentProductId,
        Guid EnrollmentLicenseId,
        Guid EnrollmentSeatId,
        string EnrollmentInstallationId,
        string EnrollmentHardwareIdHash,
        string EnrollmentReleaseVersion,
        string EnrollmentHandoffDigest,
        string? EnrollmentSubjectDigest,
        string EnrollmentProtocolVersion,
        string EnrollmentAlgorithm,
        string EnrollmentKeyBackend,
        string EnrollmentAttestationLevel,
        string EnrollmentPublicKeyCiphertext,
        string EnrollmentPublicKeyKeyId,
        string EnrollmentPublicKeyKeyPurpose,
        string EnrollmentPublicKeySha256,
        string EnrollmentKeyThumbprint,
        string EnrollmentChallengeCiphertext,
        string EnrollmentChallengeKeyId,
        string EnrollmentChallengeKeyPurpose,
        string EnrollmentChallengeDigestSha256,
        string EnrollmentState,
        int EnrollmentEpoch,
        int EnrollmentSecurityEpoch,
        long EnrollmentAuthorityEpoch,
        DateTime EnrollmentChallengeExpiresAtUtc,
        DateTime EnrollmentCreatedAtUtc,
        DateTime? EnrollmentActivatedAtUtc,
        DateTime? EnrollmentChallengeConsumedAtUtc,
        DateTime? EnrollmentInvalidatedAtUtc,
        string? EnrollmentInvalidationReason,
        Guid BindingId,
        Guid BindingProductId,
        Guid BindingLicenseId,
        Guid BindingSeatId,
        Guid BindingEntitlementId,
        string? BindingSubjectDigest,
        string BindingGrantRef,
        string BindingInstallationId,
        string BindingGrantDigest,
        string BindingHandoffDigest,
        DateTime? BindingHandoffIssuedAtUtc,
        DateTime? BindingHandoffExpiresAtUtc,
        DateTime? BindingDownloadCompletedAtUtc,
        string BindingHardwareIdHash,
        string BindingVersion,
        string BindingInstallerFilename,
        string BindingInstallerSha256,
        string BindingExecutableSha256,
        string BindingNativeDllSha256,
        string BindingCoreSha256,
        string BindingApprovedBinariesSource,
        string BindingState,
        DateTime BindingBoundAtUtc,
        Guid? BindingSupersededBindingId,
        int BindingInitialSecurityEpoch,
        DateTime? BindingInvalidatedAtUtc,
        string? BindingInvalidationReason)
    {
        /// <summary>Captures Runtime identity and historical binding fields before commercial release.</summary>
        internal static RuntimeCommercialReattachmentSnapshot Capture(
            RuntimeEnrollment enrollment,
            DistributionInstallationBinding binding) => new(
                enrollment.Id,
                enrollment.ClientId,
                enrollment.BindingId,
                enrollment.ProductId,
                enrollment.LicenseId,
                enrollment.LicenseSeatId,
                enrollment.InstallationId,
                enrollment.HardwareIdHash,
                enrollment.ReleaseVersion,
                enrollment.HandoffDigestSha256,
                enrollment.SubjectRefDigestSha256,
                enrollment.ProtocolVersion,
                enrollment.Algorithm,
                enrollment.KeyBackend,
                enrollment.AttestationLevel,
                enrollment.PublicKeySpkiCiphertext,
                enrollment.PublicKeySpkiKeyId,
                enrollment.PublicKeySpkiKeyPurpose,
                enrollment.PublicKeySpkiSha256,
                enrollment.KeyThumbprint,
                enrollment.ChallengeCiphertext,
                enrollment.ChallengeKeyId,
                enrollment.ChallengeKeyPurpose,
                enrollment.ChallengeDigestSha256,
                enrollment.State,
                enrollment.Epoch,
                enrollment.SecurityEpoch,
                enrollment.AuthorityEpoch,
                enrollment.ChallengeExpiresAtUtc,
                enrollment.CreatedAtUtc,
                enrollment.ActivatedAtUtc,
                enrollment.ChallengeConsumedAtUtc,
                enrollment.InvalidatedAtUtc,
                enrollment.InvalidationReason,
                binding.Id,
                binding.ProductId,
                binding.LicenseId,
                binding.LicenseSeatId,
                binding.EntitlementId,
                binding.SubjectRefDigestSha256,
                binding.GrantRef,
                binding.InstallationId,
                binding.GrantRefDigestSha256,
                binding.HandoffDigestSha256,
                binding.HandoffIssuedAtUtc,
                binding.HandoffExpiresAtUtc,
                binding.DownloadCompletedAtUtc,
                binding.HardwareIdHash,
                binding.Version,
                binding.InstallerFilename,
                binding.InstallerSha256,
                binding.ExecutableSha256,
                binding.NativeDllSha256,
                binding.CoreSha256,
                binding.ApprovedBinariesSource,
                binding.State,
                binding.BoundAtUtc,
                binding.SupersededBindingId,
                binding.InitialSecurityEpoch,
                binding.InvalidatedAtUtc,
                binding.InvalidationReason);
    }
}

/// <summary>Runs the tests from RuntimeCommercialReattachmentPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeCommercialReattachmentPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// Proves a cryptographically known Runtime installation can acquire the current commercial seat of the
    /// same provider subject after its historical seat was released. A known identifier is free; a new identifier
    /// uses the existing automatic seat-change counter exactly once. Strict assignment enforcement remains closed.
    /// </summary>
    /// <param name = "newHardware">Whether the request presents a new server-derived hardware identifier.</param>
    /// <param name = "maximumSeats">Target capacity chosen to cover both a full known seat and spare capacity.</param>
    /// <param name = "reuseHistoricalLicense">Whether the successor returns to the exact historical licence and seat.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617_KnownEnrollmentWithoutActiveAssignment_RelinksAndFinalizes")]
    [InlineData(false, 1, false)]
    [InlineData(true, 2, false)]
    [InlineData(false, 1, true)]
    public async Task Tkt1617_KnownEnrollmentWithoutActiveAssignment_RelinksAndFinalizes(bool newHardware, int maximumSeats, bool reuseHistoricalLicense)
    {
        await AssertTkt1617CommercialReattachmentAsync(newHardware, maximumSeats, reuseHistoricalLicense, liveStateMismatch: false);
    }

    /// <summary>
    /// Reproduces TKT-001603 before preflight: an ACTIVE historical enrollment quarantined for
    /// live_state_mismatch, an expired old licence and released seat, and a new licence already
    /// activated on the same hardware at full single-seat capacity. Only commercial authority changes.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1603_LiveStateMismatchBeforePreflight_AlreadyActivatedNewLicense_ReusesSeatAndIdentity")]
    public async Task Tkt1603_LiveStateMismatchBeforePreflight_AlreadyActivatedNewLicense_ReusesSeatAndIdentity()
    {
        await AssertTkt1617CommercialReattachmentAsync(newHardware: false, maximumSeats: 1, reuseHistoricalLicense: false, liveStateMismatch: true);
    }

    /// <summary>Proves quarantine history cannot authorize unrelated, future, or corrupt current authority.</summary>
    /// <param name = "invalidEvidence">The historical quarantine defect that must remain fail-closed.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1603_QuarantineAloneDoesNotAuthorizeFinalization")]
    [InlineData("binding_mismatch")]
    [InlineData("future_observation")]
    [InlineData("current_assignment_scope_mismatch")]
    public async Task Tkt1603_QuarantineAloneDoesNotAuthorizeFinalization(string invalidEvidence)
    {
        await AssertTkt1617CommercialReattachmentAsync(newHardware: false, maximumSeats: 1, reuseHistoricalLicense: false, liveStateMismatch: true, invalidQuarantineEvidence: invalidEvidence);
    }

    /// <summary>Proves a server-owned subject mismatch cannot create or alter commercial authority.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617_DifferentProviderSubject_DoesNotRelink")]
    public async Task Tkt1617_DifferentProviderSubject_DoesNotRelink()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseInMemoryDatabase("tkt-001617-subject-" + Guid.NewGuid().ToString("N")).Options;
        await using var db = new LicenseDbContext(options);
        var productId = Guid.NewGuid();
        var enrollment = new RuntimeEnrollment
        {
            ProductId = productId,
            SubjectRefDigestSha256 = Sha256("subject-a")
        };
        var license = new License
        {
            ProductId = productId,
            IsActive = true,
            MaxSeats = 1
        };
        var before = Tkt1617ResolverInputSnapshot(enrollment, license);
        var durableBefore = await ReadTkt1617CommercialStateAsync(db);
        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => RuntimeCommercialAssignmentResolver.ResolveOrRelinkAsync(db, enrollment, license, Sha256("subject-b"), "TKT1617-HARDWARE", "2.4.801", "website-step1", RuntimeCommercialAssignmentResolver.AuthorityProof.Distribution("website-step1", Guid.NewGuid()), DateTimeOffset.UtcNow, CancellationToken.None));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
        Assert.Equal("commercial_authority_ineligible", refusal.DiagnosticCode);
        Assert.Equal(before, Tkt1617ResolverInputSnapshot(enrollment, license));
        Assert.Equal(durableBefore, await ReadTkt1617CommercialStateAsync(db));
        Assert.DoesNotContain(db.ChangeTracker.Entries(), entry => entry.State is EntityState.Added or EntityState.Modified or EntityState.Deleted);
    }

    /// <summary>
    /// Proves a new identifier remains subject to the daily quota of different identifiers (TKT-003751: two other
    /// identifiers already activated today with N = 1 x 2 seats) and a full multi-seat licence remains subject to
    /// MaxSeats (identifiers activated yesterday, so the quota leaves room), without creating a seat or assignment on
    /// refusal.
    /// </summary>
    /// <param name = "refusal">Commercial guard exercised before any relink write.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617_NewIdentifier_EnforcesExistingQuotaAndSeatCapacity")]
    [InlineData("quota")]
    [InlineData("capacity")]
    public async Task Tkt1617_NewIdentifier_EnforcesExistingQuotaAndSeatCapacity(string refusal)
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseInMemoryDatabase("tkt-001617-guard-" + refusal + Guid.NewGuid().ToString("N")).Options;
        await using var db = new LicenseDbContext(options);
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var subjectDigest = Sha256("tkt-001617-guard-subject");
        var type = new LicenseType
        {
            ProductId = productId,
            Name = "TKT-001617 guarded type",
            Slug = "TKT1617-GUARD",
            MaxActivationsPerDay = 1
        };
        var license = new License
        {
            ProductId = productId,
            LicenseTypeId = type.Id,
            Type = type,
            LicenseKey = "TKT1617-GUARD-" + Guid.NewGuid().ToString("N"),
            IsActive = true,
            ExpirationDate = now.AddDays(1),
            AllowedVersions = "*",
            MaxSeats = 2
        };
        license.Seats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "TKT1617-ACTIVE-ONE", IsActive = true, FirstActivatedAt = now.AddDays(-1), LastCheckInAt = now.AddMinutes(-1), LastActivatedAt = now.AddDays(-1) });
        if (refusal == "capacity")
        {
            license.Seats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "TKT1617-ACTIVE-TWO", IsActive = true, FirstActivatedAt = now.AddDays(-1), LastCheckInAt = now.AddMinutes(-1), LastActivatedAt = now.AddDays(-1) });
        }
        else
        {
            // The limit applies per seat (TKT-002030): two seats at one per day allow two different identifiers.
            // TKT-003751: two other identifiers activated today, then released, exhaust it. TKT-004196: anchored in the
            // current UTC day, because now.AddMinutes(-3) fell on the previous day between 00:00 and 00:03 UTC.
            var first = SoftLicence.Tests.Harness.UtcDayTimestamps.Today(now, 0.25);
            var second = SoftLicence.Tests.Harness.UtcDayTimestamps.Today(now, 0.5);
            var third = SoftLicence.Tests.Harness.UtcDayTimestamps.Today(now, 0.75);
            license.Seats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "TKT1617-TODAY-ONE", IsActive = false, FirstActivatedAt = first, LastCheckInAt = first, LastActivatedAt = first, UnlinkedAt = second });
            license.Seats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "TKT1617-TODAY-TWO", IsActive = false, FirstActivatedAt = second, LastCheckInAt = second, LastActivatedAt = second, UnlinkedAt = third });
        }

        db.AddRange(type, license);
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        license = await db.Licenses.Include(row => row.Type).Include(row => row.Seats).SingleAsync(row => row.Id == license.Id);
        var enrollment = new RuntimeEnrollment
        {
            ProductId = productId,
            SubjectRefDigestSha256 = subjectDigest
        };
        var before = Tkt1617ResolverInputSnapshot(enrollment, license);
        var durableBefore = await ReadTkt1617CommercialStateAsync(db);
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => RuntimeCommercialAssignmentResolver.ResolveOrRelinkAsync(db, enrollment, license, subjectDigest, "TKT1617-NEW-HARDWARE", "2.4.801", "website-step1", RuntimeCommercialAssignmentResolver.AuthorityProof.Distribution("website-step1", Guid.NewGuid()), new DateTimeOffset(now, TimeSpan.Zero), CancellationToken.None));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
        Assert.Equal(refusal == "quota" ? "activation_rate_limited" : "authority_ineligible", denied.ErrorCode);
        Assert.Equal(refusal == "quota" ? "seat_change_quota_exhausted" : "seat_capacity_exceeded", denied.DiagnosticCode);
        Assert.Equal(before, Tkt1617ResolverInputSnapshot(enrollment, license));
        Assert.Equal(durableBefore, await ReadTkt1617CommercialStateAsync(db));
        Assert.DoesNotContain(license.Seats, seat => seat.HardwareId == "TKT1617-NEW-HARDWARE");
        Assert.Empty(await db.EnrollmentLicenseAssignments.ToListAsync());
        Assert.DoesNotContain(db.ChangeTracker.Entries(), entry => entry.State is EntityState.Added or EntityState.Modified or EntityState.Deleted);
    }

    /// <summary>Proves a licence-excluded machine is refused before any reattachment write.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt2041_ExcludedHardware_CannotReattachCommercialAssignment")]
    public async Task Tkt2041_ExcludedHardware_CannotReattachCommercialAssignment()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseInMemoryDatabase("tkt-002041-exclusion-" + Guid.NewGuid().ToString("N")).Options;
        await using var db = new LicenseDbContext(options);
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var subjectDigest = Sha256("tkt-002041-exclusion-subject");
        var type = new LicenseType
        {
            ProductId = productId,
            Name = "TKT-002041 exclusion type",
            Slug = "TKT2041-EXCL"
        };
        var license = new License
        {
            ProductId = productId,
            LicenseTypeId = type.Id,
            Type = type,
            LicenseKey = "TKT2041-EXCL-" + Guid.NewGuid().ToString("N"),
            IsActive = true,
            ExpirationDate = now.AddDays(1),
            AllowedVersions = "*",
            MaxSeats = 1
        };
        license.Seats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "TKT2041-ACTIVE-ONE", IsActive = true, FirstActivatedAt = now.AddDays(-1), LastCheckInAt = now.AddMinutes(-1) });
        db.LicenseHardwareExclusions.Add(new LicenseHardwareExclusion
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseId = license.Id,
            HardwareId = "TKT2041EXCLNEW01",
            CreatedAtUtc = now.AddMinutes(-5),
            CreatedByRequestId = Guid.NewGuid(),
            CreatedByClientId = "tia-connect-website-exclusions",
            CreatedByRequestFingerprintSha256 = new string('a', 64),
            Actor = "s2s",
            ReleaseActiveSeat = false,
            ReleaseOutcome = "none"
        });
        db.AddRange(type, license);
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        license = await db.Licenses.Include(row => row.Type).Include(row => row.Seats).SingleAsync(row => row.Id == license.Id);
        var enrollment = new RuntimeEnrollment
        {
            ProductId = productId,
            SubjectRefDigestSha256 = subjectDigest
        };

        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => RuntimeCommercialAssignmentResolver.ResolveOrRelinkAsync(
            db, enrollment, license, subjectDigest, "TKT2041EXCLNEW01", "2.4.801", "website-step1",
            RuntimeCommercialAssignmentResolver.AuthorityProof.Distribution("website-step1", Guid.NewGuid()),
            new DateTimeOffset(now, TimeSpan.Zero), CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, denied.StatusCode);
        Assert.Equal("license_hardware_excluded", denied.ErrorCode);
        Assert.DoesNotContain(license.Seats, seat => seat.HardwareId == "TKT2041EXCLNEW01");
        Assert.Empty(await db.EnrollmentLicenseAssignments.ToListAsync());
    }

    /// <summary>Proves the trigger migration removes and restores only its own helper across Down and Up.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617_AssignmentTriggerMigration_DownThenUp_IsReversible")]
    public async Task Tkt1617_AssignmentTriggerMigration_DownThenUp_IsReversible()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var migrator = migration.GetService<IMigrator>();
        await migrator.MigrateAsync(Tkt1617PreviousMigration);
        Assert.False(await Tkt1617RelinkHelperExistsAsync(scenario.AdminConnectionString));
        Assert.False(await Tkt1617RelinkWriterExistsAsync(scenario.AdminConnectionString));
        await migrator.MigrateAsync(Tkt1617Migration);
        Assert.True(await Tkt1617RelinkHelperExistsAsync(scenario.AdminConnectionString));
        Assert.True(await Tkt1617RelinkWriterExistsAsync(scenario.AdminConnectionString));
        Assert.True(await Tkt1617ProductionRoleUsesOnlyRelinkWriterAsync(scenario.AdminConnectionString));
        await Tkt1617ProductionRelinkWriterRejectsForgedAuthorityAsync(scenario);
    }

    /// <summary>
    /// Proves a migration-era binding quarantine remains historical evidence after a valid
    /// successor assignment and cannot veto either synchronization or a later seat release.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617_QuarantinedHistoricalBinding_DoesNotVetoSuccessorAssignment")]
    public async Task Tkt1617_QuarantinedHistoricalBinding_DoesNotVetoSuccessorAssignment()
    {
        var subjectRef = Base64Url(SHA256.HashData("tkt-001617-quarantine-subject"u8.ToArray()));
        var knownHardware = Assert.IsType<string>(MachineIdentity.FromUuid(Tkt1617KnownSystemUuid).HardwareId);
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: knownHardware, initialSubjectRef: subjectRef);
        var successor = await CreateTkt1617SuccessorAssignmentAsync(scenario, subjectRef, knownHardware, quarantineHistoricalBinding: true);
        await using (var synchronize = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await synchronize.OpenAsync();
            await using var command = new NpgsqlCommand("SELECT public.sync_current_enrollment_license_assignment(@enrollment);", synchronize);
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            await command.ExecuteNonQueryAsync();
        }

        await using (var release = await scenario.Factory.CreateDbContextAsync())
        {
            var seat = await release.LicenseSeats.SingleAsync(row => row.Id == successor.SeatId);
            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow;
            await release.SaveChangesAsync();
        }

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var assignment = await verify.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(row => row.Id == successor.AssignmentId);
        Assert.Equal("ENDED", assignment.State);
        Assert.Equal("seat_released", assignment.EndReason);
        Assert.True(await verify.EnrollmentLicenseAssignmentQuarantines.AsNoTracking().AnyAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.Reason == "binding_mismatch"));
    }

    /// <summary>
    /// Proves rollback fails before changing the schema when successor assignments would be
    /// interpreted through the obsolete historical-binding router.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617_AssignmentTriggerMigration_DownWithSuccessorAssignment_IsRejectedWithoutDataLoss")]
    public async Task Tkt1617_AssignmentTriggerMigration_DownWithSuccessorAssignment_IsRejectedWithoutDataLoss()
    {
        var subjectRef = Base64Url(SHA256.HashData("tkt-001617-down-guard-subject"u8.ToArray()));
        var knownHardware = Assert.IsType<string>(MachineIdentity.FromUuid(Tkt1617KnownSystemUuid).HardwareId);
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: knownHardware, initialSubjectRef: subjectRef);
        await CreateTkt1617SuccessorAssignmentAsync(scenario, subjectRef, knownHardware, quarantineHistoricalBinding: false);
        string assignmentsBefore;
        await using (var snapshot = await scenario.Factory.CreateDbContextAsync())
        {
            assignmentsBefore = JsonSerializer.Serialize(await snapshot.EnrollmentLicenseAssignments.AsNoTracking().OrderBy(row => row.Revision).ToListAsync());
        }

        await using var migration = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var migrator = migration.GetService<IMigrator>();
        var failure = await Record.ExceptionAsync(() => migrator.MigrateAsync(Tkt1617PreviousMigration));
        Assert.NotNull(failure);
        var refusal = Assert.IsType<PostgresException>(failure.GetBaseException());
        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, refusal.SqlState);
        Assert.Equal("tkt001617_down_blocked_successor_assignments", refusal.MessageText);
        Assert.Contains(Tkt1617Migration, await migration.Database.GetAppliedMigrationsAsync());
        Assert.True(await Tkt1617RelinkHelperExistsAsync(scenario.AdminConnectionString));
        Assert.True(await Tkt1617RelinkWriterExistsAsync(scenario.AdminConnectionString));
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(assignmentsBefore, JsonSerializer.Serialize(await verify.EnrollmentLicenseAssignments.AsNoTracking().OrderBy(row => row.Revision).ToListAsync()));
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Data.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// A persisted pre-B1 portal unlink must allow a fresh, server-owned Finalize generation while
    /// keeping the released credential terminal, including when legacy activation occupied another seat.
    /// The <c>stale-runtime-call</c> variants replay the TKT-001198 incident: the still installed
    /// client calls Runtime after the unlink, which must refuse it without rewriting the
    /// <c>seat_released</c> evidence. The <c>late-binding-ineligible</c> variants reproduce the
    /// historical graph that call wrote before the fix, which must still allow reinstallation through
    /// the provider-direct hardware path used in production; like the prior authority_ineligible
    /// variants, the signed alias path deliberately keeps requiring the exact seat_released proof.
    /// </summary>
    [Theory]
    [InlineData(false, "stale-runtime-call")]
    [InlineData(false, "stale-runtime-call-direct-v4")]
    [InlineData(false, "late-binding-ineligible-direct")]
    [InlineData(false, "late-binding-ineligible-direct-v4")]
    [InlineData(false, "valid")]
    [InlineData(true, "valid")]
    [InlineData(false, "v4")]
    [InlineData(true, "v4")]
    [InlineData(false, "direct")]
    [InlineData(false, "direct-v4")]
    [InlineData(false, "security")]
    [InlineData(false, "timestamp")]
    [InlineData(false, "subject")]
    [InlineData(false, "epoch")]
    [InlineData(false, "revoked")]
    [InlineData(false, "prior-authority-ineligible-direct-v4")]
    [InlineData(false, "prior-version-ineligible-direct-v4")]
    [InlineData(false, "prior-authority-ineligible-concurrent-direct-v4")]
    [InlineData(false, "prior-security-direct-v4")]
    [InlineData(false, "future-authority-ineligible-direct-v4")]
    public async Task SeatRelease_NewFinalizeAfterPortalUnlink_PreservesTerminalAuthority(bool legacySeat, string variant)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var subject = Base64Url(System.Security.Cryptography.SHA256.HashData("tkt998-new-finalize"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subject);
        await MigrateScenarioAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var source = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var oldEnrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var oldEpoch = oldEnrollment.SecurityEpoch;
        DateTime? priorTerminalAt = null;
        var hasHistoricalTerminal = variant.Contains("prior-authority-ineligible", StringComparison.Ordinal)
            || variant.Contains("prior-version-ineligible", StringComparison.Ordinal)
            || variant.Contains("prior-security", StringComparison.Ordinal)
            || variant.Contains("future-authority-ineligible", StringComparison.Ordinal);
        if (hasHistoricalTerminal)
        {
            var terminalNow = DateTime.UtcNow;
            priorTerminalAt = new DateTime(
                terminalNow.Ticks - terminalNow.Ticks % 10,
                DateTimeKind.Utc);
            oldEnrollment.State = "INVALIDATED";
            oldEnrollment.InvalidatedAtUtc = priorTerminalAt;
            oldEnrollment.InvalidationReason = variant.Contains("prior-security", StringComparison.Ordinal)
                ? "security_lockdown"
                : variant.Contains("prior-version-ineligible", StringComparison.Ordinal)
                    ? "version_ineligible"
                    : "authority_ineligible";
            await db.SaveChangesAsync();
            // These variants model a complete pre-B1 release graph. Materialize that graph before
            // invoking the new release service so it observes an already-inactive commercial seat
            // instead of attempting to release an enrollment that item2 already terminalized.
            await PersistHistoricalSeatReleaseAsync(db, source, oldEnrollment, releaseSeat: true);
        }
        var portal = new PortalDeactivationService(scenario.Factory, TimeProvider.System,
            NullLogger<PortalDeactivationService>.Instance);
        var unlink = await portal.DeactivateAsync("website-step1", Sha256("new-finalize-unlink"),
            new PortalDeactivationRequest(PortalDeactivationService.RequestSchema, Guid.NewGuid().ToString("D"),
                source.ProductId.ToString("D"), source.LicenseId.ToString("D"), StableHardwareId, "settings_button"));
        Assert.Equal(hasHistoricalTerminal ? "already_inactive" : "deactivated", unlink.Response.Outcome);
        // This test protects compatibility with terminal evidence written before B1. New releases
        // intentionally leave these Runtime rows untouched and are covered by the B1 endpoint tests.
        if (!hasHistoricalTerminal)
            await PersistHistoricalSeatReleaseAsync(db, source, oldEnrollment);
        if (variant.StartsWith("stale-runtime-call", StringComparison.Ordinal))
        {
            // The client installed on the released machine keeps calling Runtime. Its binding check
            // must refuse the call while leaving the release's own terminal reason and instant intact.
            await db.Entry(oldEnrollment).ReloadAsync();
            var releaseTerminalAt = oldEnrollment.InvalidatedAtUtc;
            Assert.Equal("seat_released", oldEnrollment.InvalidationReason);
            var milestone = new RuntimeMilestoneRequest
            {
                Schema = RuntimeEnrollmentService.MilestoneSchema,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                EnrollmentId = scenario.EnrollmentId.ToString("D"),
                Epoch = 1,
                SecurityEpoch = oldEpoch,
                SessionId = Guid.NewGuid().ToString("D"),
                Sequence = 1,
                EventId = Guid.NewGuid().ToString("D"),
                Code = "bootstrap_entered",
                OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow)
            };
            var milestoneDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(milestone));
            var stale = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                scenario.Runtime.RecordMilestoneAsync(scenario.EnrollmentId, milestoneDigest, milestone,
                    Proof(scenario.EnrollmentKey, "milestone", scenario.EnrollmentId,
                        scenario.Options.ConfirmAudience, "-", milestoneDigest),
                    IPAddress.Loopback));
            Assert.Equal("enrollment_inactive", stale.ErrorCode);
            await db.Entry(oldEnrollment).ReloadAsync();
            Assert.Equal("INVALIDATED", oldEnrollment.State);
            Assert.Equal("seat_released", oldEnrollment.InvalidationReason);
            Assert.Equal(releaseTerminalAt, oldEnrollment.InvalidatedAtUtc);
        }
        if (legacySeat)
        {
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = source.LicenseId, HardwareId = LegacyHardwareId, IsActive = true,
                FirstActivatedAt = DateTime.UtcNow.AddMinutes(-10), LastCheckInAt = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }
        var prepared = await PrepareDistributionFinalizeAsync(scenario, subject, LegacyHardwareId);
        if (variant.Contains("v4", StringComparison.Ordinal))
            ConfigureFinalizeV4WithUnrelatedCandidates(prepared.Request);
        if (variant.Contains("direct", StringComparison.Ordinal))
            prepared.Request.HardwareId = StableHardwareId;
        await db.Entry(source).ReloadAsync();
        await db.Entry(oldEnrollment).ReloadAsync();
        switch (variant)
        {
            case "security": source.InvalidationReason = "security_lockdown"; break;
            case "timestamp": oldEnrollment.InvalidatedAtUtc = oldEnrollment.InvalidatedAtUtc!.Value.AddSeconds(-1); break;
            case "subject": oldEnrollment.SubjectRefDigestSha256 = Sha256("different-subject"); break;
            case "epoch":
            {
                var alias = await db.HardwareAuthorityAliases.SingleAsync();
                alias.SecurityEpoch = checked(oldEnrollment.SecurityEpoch + 1);
                break;
            }
            case "revoked":
                var revoked = await db.Licenses.SingleAsync(row => row.Id == source.LicenseId);
                revoked.IsActive = false;
                revoked.RevokedAt = DateTime.UtcNow;
                break;
        }
        if (variant.Contains("future-authority-ineligible", StringComparison.Ordinal))
            oldEnrollment.InvalidatedAtUtc = source.InvalidatedAtUtc!.Value.AddSeconds(1);
        if (variant.StartsWith("late-binding-ineligible", StringComparison.Ordinal))
        {
            // Historical production graph written before TKT-001198: a stale Runtime call rewrote
            // the released enrollment one microsecond after the release, still before Finalize runs.
            oldEnrollment.InvalidationReason = "binding_ineligible";
            oldEnrollment.InvalidatedAtUtc = source.InvalidatedAtUtc!.Value.AddTicks(10);
        }
        await db.SaveChangesAsync();
        var digest = Sha256("new-finalize-" + Guid.NewGuid());
        if (variant is "security" or "timestamp" or "subject" or "epoch" or "revoked"
            || variant.Contains("prior-security", StringComparison.Ordinal)
            || variant.Contains("future-authority-ineligible", StringComparison.Ordinal))
        {
            var error = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                prepared.Service.FinalizeAsync("website-step1", digest, prepared.Request));
            if (variant.Contains("prior-security", StringComparison.Ordinal)
                || variant.Contains("future-authority-ineligible", StringComparison.Ordinal))
            {
                Assert.Equal("binding_conflict", error.ErrorCode);
                Assert.Equal("replacement_candidate_none", error.ReasonCode);
            }
            Assert.Empty(await db.DistributionInstallationBindings.AsNoTracking()
                .Where(row => row.ProductId == source.ProductId && row.State == "active").ToListAsync());
            Assert.Empty(await db.LicenseSeats.AsNoTracking()
                .Where(row => row.LicenseId == source.LicenseId && row.IsActive).ToListAsync());
            await db.Entry(oldEnrollment).ReloadAsync();
            Assert.Equal("INVALIDATED", oldEnrollment.State);
            return;
        }
        DistributionOperationResult<DistributionInstallationBindingResponse> result;
        DistributionOperationResult<DistributionInstallationBindingResponse> replay;
        if (variant.Contains("concurrent", StringComparison.Ordinal))
        {
            var outcomes = await Task.WhenAll(
                prepared.Service.FinalizeAsync("website-step1", digest, prepared.Request),
                prepared.Service.FinalizeAsync("website-step1", digest, prepared.Request));
            Assert.Single(outcomes, outcome => !outcome.Idempotent);
            Assert.Single(outcomes, outcome => outcome.Idempotent);
            result = outcomes.Single(outcome => !outcome.Idempotent);
            replay = outcomes.Single(outcome => outcome.Idempotent);
        }
        else
        {
            result = await prepared.Service.FinalizeAsync("website-step1", digest, prepared.Request);
            replay = await prepared.Service.FinalizeAsync("website-step1", digest, prepared.Request);
        }
        Assert.False(result.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(result.Response, replay.Response);
        await db.Entry(source).ReloadAsync();
        await db.Entry(oldEnrollment).ReloadAsync();
        Assert.Equal("invalidated", source.State);
        Assert.Equal("seat_released", source.InvalidationReason);
        Assert.Equal("INVALIDATED", oldEnrollment.State);
        Assert.Equal(oldEpoch, oldEnrollment.SecurityEpoch);
        Assert.Equal(
            variant.Contains("prior-authority-ineligible", StringComparison.Ordinal)
                ? "authority_ineligible"
                : variant.Contains("prior-version-ineligible", StringComparison.Ordinal)
                    ? "version_ineligible"
                : variant.StartsWith("late-binding-ineligible", StringComparison.Ordinal)
                    ? "binding_ineligible"
                    : "seat_released",
            oldEnrollment.InvalidationReason);
        if (variant.Contains("prior-authority-ineligible", StringComparison.Ordinal)
            || variant.Contains("prior-version-ineligible", StringComparison.Ordinal))
            Assert.Equal(priorTerminalAt, oldEnrollment.InvalidatedAtUtc);
        var successor = await db.DistributionInstallationBindings.SingleAsync(row =>
            row.ProductId == source.ProductId && row.State == "active");
        Assert.Equal(source.Id, successor.SupersededBindingId);
        Assert.Equal(oldEpoch + 1, successor.InitialSecurityEpoch);
        Assert.Equal(source.SubjectRefDigestSha256, successor.SubjectRefDigestSha256);
        Assert.Single(await db.LicenseSeats.Where(row => row.LicenseId == source.LicenseId && row.IsActive).ToListAsync());
    }

    /// <summary>
    /// The composed 798/998 contract refuses interactive quota exhaustion without touching any
    /// Runtime or receipt row, yet authenticated subscription termination still releases a revoked
    /// licence's exact live graph. This executes the real service against PostgreSQL.
    /// </summary>
    [Theory]
    [InlineData("settings_button")]
    [InlineData("uninstall")]
    public async Task SeatRelease_QuotaRefusalHasNoRuntimeEffect_AndTerminationStillReleases(string reason)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var license = await db.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == binding.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
        seat.FirstActivatedAt = DateTime.UtcNow.AddHours(-1);
        license.Type!.MaxActivationsPerDay = 1;
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = license.Id, HardwareId = "QUOTA-HISTORY", IsActive = false,
            UnlinkedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        var historyCount = await db.LicenseHistories.CountAsync();
        var request = new PortalDeactivationRequest(PortalDeactivationService.RequestSchema,
            Guid.NewGuid().ToString("D"), binding.ProductId.ToString("D"), binding.LicenseId.ToString("D"),
            LegacyHardwareId, reason);
        var service = new PortalDeactivationService(scenario.Factory, TimeProvider.System,
            NullLogger<PortalDeactivationService>.Instance);

        await Assert.ThrowsAsync<PortalDeactivationQuotaException>(() =>
            service.DeactivateAsync("website-step1", Sha256("quota-refused"), request));

        await db.Entry(seat).ReloadAsync();
        Assert.True(seat.IsActive);
        Assert.Equal("active", (await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == binding.Id)).State);
        Assert.Equal("ACTIVE", (await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.Equal(historyCount, await db.LicenseHistories.CountAsync());
        Assert.Empty(await db.PortalDeactivationOperations.ToListAsync());
        license.IsActive = false;
        await db.SaveChangesAsync();
        var revokedAssignment = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId);
        Assert.Equal("ENDED", revokedAssignment.State);
        Assert.Equal("license_revoked", revokedAssignment.EndReason);
        var runtimeBeforeTermination = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);

        var terminal = await service.DeactivateAsync("website-step1", Sha256("termination"),
            request with { Reason = "subscription_termination" });

        Assert.Equal("deactivated", terminal.Response.Outcome);
        Assert.Equal("active", (await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == binding.Id)).State);
        var runtimeAfterTermination = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal(runtimeBeforeTermination.State, runtimeAfterTermination.State);
        Assert.Equal(runtimeBeforeTermination.SecurityEpoch, runtimeAfterTermination.SecurityEpoch);
        Assert.Equal(runtimeBeforeTermination.AuthorityEpoch, runtimeAfterTermination.AuthorityEpoch);
        Assert.Equal(runtimeBeforeTermination.InvalidatedAtUtc, runtimeAfterTermination.InvalidatedAtUtc);
        Assert.Equal(runtimeBeforeTermination.InvalidationReason, runtimeAfterTermination.InvalidationReason);
        var preservedAssignment = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.Id == revokedAssignment.Id);
        Assert.Equal(revokedAssignment.State, preservedAssignment.State);
        Assert.Equal(revokedAssignment.EndReason, preservedAssignment.EndReason);
        Assert.Equal(revokedAssignment.EndedAtUtc, preservedAssignment.EndedAtUtc);
        Assert.Equal(revokedAssignment.Revision, preservedAssignment.Revision);
        Assert.Single(await db.PortalDeactivationOperations.ToListAsync());
        await db.Entry(license).ReloadAsync();
        Assert.False(license.IsActive);
    }

    /// <summary>
    /// A subscription cleanup may preserve the immutable item2 licence-revocation terminal, but no
    /// other terminal reason can substitute for that exact commercial relation.
    /// </summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("divergent-seat")]
    [InlineData("unexpected-terminal")]
    public async Task SeatRelease_SubscriptionTerminationRejectsInvalidTerminalRelation(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var license = await db.Licenses.Include(row => row.Type)
            .SingleAsync(row => row.Id == binding.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
        var unrelatedSeat = new LicenseSeat
        {
            LicenseId = license.Id,
            HardwareId = "TERMINAL-RELATION-DIVERGENCE",
            IsActive = false,
            FirstActivatedAt = DateTime.UtcNow.AddHours(-2),
            LastCheckInAt = DateTime.UtcNow.AddHours(-1),
            UnlinkedAt = DateTime.UtcNow.AddHours(-1)
        };
        db.LicenseSeats.Add(unrelatedSeat);
        seat.FirstActivatedAt = DateTime.UtcNow.AddHours(-1);
        license.IsActive = false;
        await db.SaveChangesAsync();
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.CommandText = mutation switch
            {
                "missing" => """
                    DELETE FROM public."EnrollmentLicenseAssignments"
                    WHERE "EnrollmentId" = @enrollmentId;
                    """,
                "duplicate" => """
                    INSERT INTO public."EnrollmentLicenseAssignments"
                        ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                         "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
                    SELECT @duplicateId, "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                           "ActivatedAtUtc", "EndedAtUtc", "Revision" + 1, "EndReason"
                    FROM public."EnrollmentLicenseAssignments"
                    WHERE "EnrollmentId" = @enrollmentId;
                    """,
                "divergent-seat" => """
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "LicenseSeatId" = @otherSeatId
                    WHERE "EnrollmentId" = @enrollmentId;
                    """,
                _ => """
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "EndReason" = 'unexpected_terminal'
                    WHERE "EnrollmentId" = @enrollmentId;
                    """
            };
            command.Parameters.AddWithValue("enrollmentId", scenario.EnrollmentId);
            if (mutation == "duplicate")
                command.Parameters.AddWithValue("duplicateId", Guid.NewGuid());
            if (mutation == "divergent-seat")
                command.Parameters.AddWithValue("otherSeatId", unrelatedSeat.Id);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        var runtimeBefore = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        var service = new PortalDeactivationService(
            scenario.Factory, TimeProvider.System, NullLogger<PortalDeactivationService>.Instance);
        var request = new PortalDeactivationRequest(
            PortalDeactivationService.RequestSchema,
            Guid.NewGuid().ToString("D"),
            binding.ProductId.ToString("D"),
            binding.LicenseId.ToString("D"),
            LegacyHardwareId,
            "subscription_termination");

        var failure = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.DeactivateAsync("website-step1", Sha256("unexpected-terminal"), request));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
        Assert.Equal("authority_unavailable", failure.ErrorCode);
        await db.Entry(seat).ReloadAsync();
        Assert.True(seat.IsActive);
        Assert.Empty(await db.PortalDeactivationOperations.ToListAsync());
        var runtimeAfter = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal(runtimeBefore.State, runtimeAfter.State);
        Assert.Equal(runtimeBefore.SecurityEpoch, runtimeAfter.SecurityEpoch);
        Assert.Equal(runtimeBefore.AuthorityEpoch, runtimeAfter.AuthorityEpoch);
    }

    /// <summary>
    /// A new already-inactive receipt and its exact replay certify only the seat state. They must
    /// not silently repair a historical Runtime graph or manufacture a second unlink event.
    /// </summary>
    [Fact]
    public async Task SeatRelease_AlreadyInactiveReceipt_DoesNotSilentlyRepairHistoricalRuntime()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
        seat.IsActive = false;
        seat.UnlinkedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        var request = new PortalDeactivationRequest(PortalDeactivationService.RequestSchema,
            Guid.NewGuid().ToString("D"), binding.ProductId.ToString("D"), binding.LicenseId.ToString("D"),
            LegacyHardwareId, "settings_button");
        var service = new PortalDeactivationService(scenario.Factory, TimeProvider.System,
            NullLogger<PortalDeactivationService>.Instance);

        var result = await service.DeactivateAsync("website-step1", Sha256("inactive-receipt"), request);
        var replay = await service.DeactivateAsync("website-step1", Sha256("inactive-receipt"), request);

        Assert.Equal("already_inactive", result.Response.Outcome);
        Assert.True(replay.Idempotent);
        Assert.Equal("active", (await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == binding.Id)).State);
        Assert.Equal("ACTIVE", (await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.Single(await db.PortalDeactivationOperations.ToListAsync());
        Assert.Empty(await db.LicenseHistories.Where(row => row.Action == "RUNTIME_RELEASE_RECONCILED").ToListAsync());
    }

    /// <summary>
    /// Exercises each real legacy HTTP release entry point against the application database role.
    /// Successful release ends only the commercial assignment and preserves Runtime identity.
    /// </summary>
    [Theory]
    [InlineData("admin")]
    [InlineData("client")]
    [InlineData("reset")]
    public async Task SeatRelease_HttpEndpoints_EndAssignmentAndPreserveRuntimeGraph(string route)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var enrollmentBefore = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        var assignmentBefore = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var proofNonceCountBefore = await db.RuntimeEnrollmentProofNonces.AsNoTracking()
            .CountAsync(row => row.EnrollmentId == scenario.EnrollmentId);
        var license = await db.Licenses.Include(row => row.Product).SingleAsync(row => row.Id == binding.LicenseId);
        license.LicenseKey = license.LicenseKey.ToUpperInvariant();
        license.ResetCode = "123456";
        license.ResetCodeExpiry = DateTime.UtcNow.AddMinutes(10);
        await db.SaveChangesAsync();
        using var baseFactory = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var web = baseFactory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AdminSettings:ApiSecret", "seat-release-http-test-only");
            builder.UseSetting("AdminSettings:AllowedIps", "");
        });
        using var client = web.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "seat-release-http-test-only");
        using var response = route switch
        {
            "admin" => await client.DeleteAsync($"/api/admin/licenses/{license.LicenseKey}/seats/{LegacyHardwareId}"),
            "reset" => await client.PostAsJsonAsync("/api/activation/reset-confirm", new
            {
                license.LicenseKey, AppName = license.Product!.Name, ResetCode = "123456"
            }),
            _ => await client.PostAsJsonAsync("/api/activation/deactivate", new
            {
                license.LicenseKey, AppName = license.Product!.Name,
                HardwareId = LegacyHardwareId, Source = "settings_button"
            })
        };
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False((await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == binding.LicenseSeatId)).IsActive);
        var bindingAfter = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == binding.Id);
        Assert.Equal("active", bindingAfter.State);
        Assert.Null(bindingAfter.InvalidatedAtUtc);
        Assert.Null(bindingAfter.InvalidationReason);
        var enrollmentAfter = await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal(enrollmentBefore.State, enrollmentAfter.State);
        Assert.Equal(enrollmentBefore.SecurityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollmentAfter.AuthorityEpoch);
        Assert.Null(enrollmentAfter.InvalidatedAtUtc);
        Assert.Null(enrollmentAfter.InvalidationReason);
        var assignmentAfter = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.Id == assignmentBefore.Id);
        Assert.Equal("ENDED", assignmentAfter.State);
        Assert.Equal("seat_released", assignmentAfter.EndReason);
        Assert.Equal(assignmentBefore.Revision, assignmentAfter.Revision);
        Assert.Empty(await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE")
            .ToListAsync());
        Assert.Equal(proofNonceCountBefore, await db.RuntimeEnrollmentProofNonces.AsNoTracking()
            .CountAsync(row => row.EnrollmentId == scenario.EnrollmentId));
    }

    /// <summary>
    /// Reproduces the old inactive stable seat plus active binding incident, then proves a signed
    /// licensing-only migration leaves the historical Runtime graph untouched and replays exactly.
    /// </summary>
    [Fact]
    public async Task SeatRelease_HistoricalOrphan_MigratesAndReplaysWithoutRevivingOldRights()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var orphan = await SeedReleasedRuntimeAsync(scenario, "eligible");
        await using (var historical = await scenario.Factory.CreateDbContextAsync())
        {
            var historicalBinding = await historical.DistributionInstallationBindings
                .SingleAsync(row => row.Id == orphan.BindingId);
            var historicalEnrollment = await historical.RuntimeEnrollments
                .SingleAsync(row => row.Id == orphan.EnrollmentId);
            await PersistHistoricalSeatReleaseAsync(
                historical, historicalBinding, historicalEnrollment, releaseSeat: true);
        }
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("seat-release-migration-" + Guid.NewGuid());
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        var result = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var replay = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.Equal("migrated", result.Response.Decision);
        Assert.True(replay.Idempotent);
        Assert.Equal(result.ExactResponseBody, replay.ExactResponseBody);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.False((await db.LicenseSeats.SingleAsync(row => row.Id == orphan.SeatId)).IsActive);
        var oldBinding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == orphan.BindingId);
        Assert.Equal("invalidated", oldBinding.State);
        Assert.Equal("seat_released", oldBinding.InvalidationReason);
        Assert.Equal("INVALIDATED", (await db.RuntimeEnrollments.SingleAsync(row => row.Id == orphan.EnrollmentId)).State);
        Assert.Equal("ACTIVE", (await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.Empty(await db.LicenseHistories.Where(row => row.Action == "RUNTIME_RELEASE_RECONCILED").ToListAsync());
        Assert.Single(await db.LicenseHistories.Where(row => row.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>
    /// A coherent business release preserves only the signed hardware correspondence. Security
    /// terminals, disabled aliases and inconsistent terminal timestamps or subjects remain refused.
    /// No resolver outcome may reactivate either the seat or its old Runtime credential.
    /// </summary>
    [Theory]
    [InlineData("coherent", true)]
    [InlineData("security-revoked", false)]
    [InlineData("disabled-alias", false)]
    [InlineData("terminal-time", false)]
    [InlineData("terminal-subject", false)]
    [InlineData("prior-authority-ineligible", false)]
    public async Task SeatRelease_AliasRetainsOnlyCoherentHardwareProof(string mutation, bool resolves)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var service = new PortalDeactivationService(scenario.Factory, TimeProvider.System,
            NullLogger<PortalDeactivationService>.Instance);
        await service.DeactivateAsync("website-step1", Sha256("alias-release"),
            new PortalDeactivationRequest(PortalDeactivationService.RequestSchema, Guid.NewGuid().ToString("D"),
                binding.ProductId.ToString("D"), binding.LicenseId.ToString("D"), StableHardwareId, "settings_button"));
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        // Alias resolution must continue to understand immutable release evidence persisted by
        // earlier server versions even though B1 no longer writes that Runtime terminal shape.
        await PersistHistoricalSeatReleaseAsync(db, binding, enrollment);
        await db.Entry(binding).ReloadAsync();
        var alias = await db.HardwareAuthorityAliases.SingleAsync();
        switch (mutation)
        {
            case "security-revoked": binding.InvalidationReason = "security_lockdown"; break;
            case "disabled-alias":
                alias.IsActive = false;
                alias.DisabledAtUtc = DateTime.UtcNow;
                alias.DisabledReason = "test-explicit-disable";
                break;
            case "terminal-time": enrollment.InvalidatedAtUtc = enrollment.InvalidatedAtUtc!.Value.AddSeconds(-1); break;
            case "terminal-subject": enrollment.SubjectRefDigestSha256 = Sha256("other-terminal-subject"); break;
            case "prior-authority-ineligible":
                enrollment.InvalidationReason = "authority_ineligible";
                enrollment.InvalidatedAtUtc = binding.InvalidatedAtUtc!.Value.AddSeconds(-1);
                break;
        }
        await db.SaveChangesAsync();

        var resolution = await CreateAliasResolver(db).ResolveAsync(binding.ProductId, binding.LicenseId,
            LegacyHardwareId, HardwareAuthorityResolutionIntent.Activation);

        Assert.Equal(resolves, resolution.UsedAlias);
        Assert.Equal(!resolves, resolution.Refused);
        Assert.Equal("INVALIDATED", enrollment.State);
        Assert.Equal("invalidated", binding.State);
        Assert.False((await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId)).IsActive);
    }

    /// <summary>
    /// Historical recovery cannot retire a live, unproven, mismatched or differently owned binding.
    /// PostgreSQL evaluates the exact persisted subject and hash comparisons, including mixed case.
    /// </summary>
    [Theory]
    [InlineData("active-seat")]
    [InlineData("no-unlink")]
    [InlineData("different-subject")]
    [InlineData("different-license")]
    [InlineData("case-subject")]
    [InlineData("seat-hash-mismatch")]
    [InlineData("binding-after-unlink")]
    public async Task SeatRelease_UnprovenHistoricalBinding_RemainsConflict(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var orphan = await SeedReleasedRuntimeAsync(scenario, mutation);

        var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => MigrateScenarioAsync(scenario));

        Assert.Equal(mutation == "active-seat" ? "authority_ineligible" : "hardware_authority_migration_conflict", error.ErrorCode);
        await AssertLegacyAuthorityUnchangedAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("active", (await db.DistributionInstallationBindings.SingleAsync(row => row.Id == orphan.BindingId)).State);
        Assert.Equal("ACTIVE", (await db.RuntimeEnrollments.SingleAsync(row => row.Id == orphan.EnrollmentId)).State);
        Assert.Empty(await db.LicenseHistories.Where(row => row.Action == "RUNTIME_RELEASE_RECONCILED").ToListAsync());
    }

    /// <summary>
    /// A later ban refusal rolls historical cleanup back together with the attempted migration.
    /// This prevents a failed request from partially repairing or revoking another graph.
    /// </summary>
    [Fact]
    public async Task SeatRelease_MigrationRefusedAfterCleanup_RollsBackHistoricalInvalidation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var orphan = await SeedReleasedRuntimeAsync(scenario, "eligible");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = StableHardwareId, IsActive = true, Reason = "test-only"
            });
            await db.SaveChangesAsync();
        }

        await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => MigrateScenarioAsync(scenario));

        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("active", (await check.DistributionInstallationBindings.SingleAsync(row => row.Id == orphan.BindingId)).State);
        Assert.Empty(await check.LicenseHistories.Where(row => row.Action == "RUNTIME_RELEASE_RECONCILED").ToListAsync());
    }

    /// <summary>
    /// Real portal requests end the exact commercial assignment and serialize different request
    /// IDs on the same seat. An exact replay cannot end a later seat reactivation assignment.
    /// </summary>
    [Fact]
    public async Task SeatRelease_PortalConcurrentRequests_EndOnceAndReplayDoesNotEndReactivation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var request = new PortalDeactivationRequest(PortalDeactivationService.RequestSchema,
            Guid.NewGuid().ToString("D"), binding.ProductId.ToString("D"), binding.LicenseId.ToString("D"),
            LegacyHardwareId, "settings_button");
        var service = new PortalDeactivationService(scenario.Factory, TimeProvider.System,
            NullLogger<PortalDeactivationService>.Instance);
        var responses = await Task.WhenAll(
            service.DeactivateAsync("website-step1", Sha256("release-a"), request),
            service.DeactivateAsync("website-step1", Sha256("release-b"), request with { RequestId = Guid.NewGuid().ToString("D") }));
        Assert.Single(responses, row => row.Response.Outcome == "deactivated");
        Assert.Single(responses, row => row.Response.Outcome == "already_inactive");
        Assert.Equal("active", (await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == binding.Id)).State);
        Assert.Equal("ACTIVE", (await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        var ended = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId);
        Assert.Equal("ENDED", ended.State);
        Assert.Equal("seat_released", ended.EndReason);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
        seat.IsActive = true;
        seat.UnlinkedAt = null;
        await db.SaveChangesAsync();
        var replacement = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");

        var replay = await service.DeactivateAsync("website-step1", Sha256("release-a"), request);

        Assert.True(replay.Idempotent);
        await db.Entry(seat).ReloadAsync();
        Assert.True(seat.IsActive);
        Assert.Equal(replacement.Id, (await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE")).Id);
        // Slice A legitimately migrates the reactivated assignment. The exact portal replay above
        // must leave that assignment active so the signed migration can use current authority.
        await MigrateScenarioAsync(scenario);
        Assert.Equal("active", (await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == binding.Id)).State);
    }

    /// <summary>
    /// Proves both commit orders between the production portal release and a separate commercial
    /// grant transaction. PostgreSQL blocking evidence identifies the exact owning backend; each
    /// order leaves a complete assignment history without changing Runtime identity.
    /// </summary>
    /// <param name="releaseFirst">True pauses the release after both barriers; false holds the grant first.</param>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SeatRelease_TwoConnectionReleaseAndGrantSerializeWithoutPartialAuthority(bool releaseFirst)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var snapshot = await scenario.Factory.CreateDbContextAsync();
        var binding = await snapshot.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var enrollmentBefore = await snapshot.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        var originalAssignment = await snapshot.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var request = new PortalDeactivationRequest(
            PortalDeactivationService.RequestSchema,
            Guid.NewGuid().ToString("D"),
            binding.ProductId.ToString("D"),
            binding.LicenseId.ToString("D"),
            LegacyHardwareId,
            "settings_button");
        var digest = Sha256("two-connection-release-grant-" + releaseFirst + Guid.NewGuid().ToString("N"));
        var portalApplication = "tkt001312-b1-release-" + Guid.NewGuid().ToString("N");
        var writerApplication = "tkt001312-b1-grant-" + Guid.NewGuid().ToString("N");
        var portalConnectionString = new NpgsqlConnectionStringBuilder(scenario.AppConnectionString)
        {
            ApplicationName = portalApplication,
            Pooling = false
        }.ConnectionString;
        var writerConnectionString = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            ApplicationName = writerApplication,
            Pooling = false
        }.ConnectionString;
        var pause = releaseFirst ? new SeatReleaseBarrierPauseInterceptor() : null;
        var portalFactory = new SeatReleaseTestDbFactory(portalConnectionString, pause);
        var portal = new PortalDeactivationService(
            portalFactory, TimeProvider.System, NullLogger<PortalDeactivationService>.Instance);
        await using var writer = new NpgsqlConnection(writerConnectionString);
        await writer.OpenAsync();
        await using var writerTransaction = await writer.BeginTransactionAsync();
        Task<PortalDeactivationResult>? pendingRelease = null;
        Task<int>? pendingGrant = null;
        var writerCommitted = false;
        try
        {
            if (releaseFirst)
            {
                pendingRelease = portal.DeactivateAsync("website-step1", digest, request);
                var releaseBackendPid = await pause!.BarrierHeld.WaitAsync(TimeSpan.FromSeconds(15));
                pendingGrant = ExecuteCommercialGrantAsync(writer, writerTransaction, binding.LicenseSeatId);
                await WaitForBlockedBackendAsync(
                    scenario.AdminConnectionString, writer.ProcessID, releaseBackendPid, writerApplication);
                Assert.False(pendingGrant.IsCompleted);
                pause.Release();
                var released = await pendingRelease;
                Assert.Equal("deactivated", released.Response.Outcome);
                Assert.False(released.Idempotent);
                await pendingGrant;
                await writerTransaction.CommitAsync();
                writerCommitted = true;
            }
            else
            {
                await ExecuteCommercialGrantAsync(writer, writerTransaction, binding.LicenseSeatId);
                pendingRelease = portal.DeactivateAsync("website-step1", digest, request);
                await WaitForApplicationBlockedAsync(
                    scenario.AdminConnectionString, portalApplication, writer.ProcessID);
                Assert.False(pendingRelease.IsCompleted);
                await writerTransaction.CommitAsync();
                writerCommitted = true;
                var released = await pendingRelease;
                Assert.Equal("deactivated", released.Response.Outcome);
                Assert.False(released.Idempotent);
            }
        }
        finally
        {
            pause?.Release();
            if (pendingRelease != null)
                await pendingRelease;
            if (pendingGrant != null)
                await pendingGrant;
            if (!writerCommitted)
                await writerTransaction.RollbackAsync();
        }

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var bindingAfter = await check.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == binding.Id);
        var enrollmentAfter = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId);
        Assert.Equal("active", bindingAfter.State);
        Assert.Equal(enrollmentBefore.State, enrollmentAfter.State);
        Assert.Equal(enrollmentBefore.SecurityEpoch, enrollmentAfter.SecurityEpoch);
        Assert.Equal(enrollmentBefore.AuthorityEpoch, enrollmentAfter.AuthorityEpoch);
        Assert.Equal(enrollmentBefore.InvalidatedAtUtc, enrollmentAfter.InvalidatedAtUtc);
        Assert.Equal(enrollmentBefore.InvalidationReason, enrollmentAfter.InvalidationReason);
        var assignments = await check.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId)
            .OrderBy(row => row.Revision).ToListAsync();
        Assert.Equal(originalAssignment.Id, assignments[0].Id);
        if (releaseFirst)
        {
            Assert.Equal(2, assignments.Count);
            Assert.Equal("ENDED", assignments[0].State);
            Assert.Equal("seat_released", assignments[0].EndReason);
            Assert.Equal("ACTIVE", assignments[1].State);
            Assert.Null(assignments[1].EndReason);
            var replay = await portal.DeactivateAsync("website-step1", digest, request);
            Assert.True(replay.Idempotent);
            Assert.Equal(assignments[1].Id, (await check.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE")).Id);
        }
        else
        {
            Assert.Equal(2, assignments.Count);
            Assert.All(assignments, row => Assert.Equal("ENDED", row.State));
            Assert.All(assignments, row => Assert.Equal("seat_released", row.EndReason));
            Assert.DoesNotContain(assignments, row => row.State == "ACTIVE");
        }
    }

    /// <summary>Runs the real item2 deactivation/reactivation trigger sequence in one writer transaction.</summary>
    /// <param name="connection">The separate tagged PostgreSQL writer connection.</param>
    /// <param name="transaction">The writer transaction that owns all commercial locks.</param>
    /// <param name="seatId">The exact seat whose commercial grant is regenerated.</param>
    /// <returns>The number of rows affected by the final activation update.</returns>
    private static async Task<int> ExecuteCommercialGrantAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid seatId)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandTimeout = 20;
        command.CommandText = """
            SET LOCAL lock_timeout = '15000ms';
            SET LOCAL statement_timeout = '20000ms';
            SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);
            SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);
            UPDATE public."LicenseSeats"
            SET "IsActive" = FALSE, "UnlinkedAt" = pg_catalog.clock_timestamp()
            WHERE "Id" = @seatId;
            SET CONSTRAINTS "TR_LicenseSeats_AssignmentDualWrite" IMMEDIATE;
            SET CONSTRAINTS "TR_LicenseSeats_AssignmentDualWrite" DEFERRED;
            UPDATE public."LicenseSeats"
            SET "IsActive" = TRUE, "UnlinkedAt" = NULL,
                "LastCheckInAt" = pg_catalog.clock_timestamp()
            WHERE "Id" = @seatId;
            SET CONSTRAINTS "TR_LicenseSeats_AssignmentDualWrite" IMMEDIATE;
            SET CONSTRAINTS "TR_LicenseSeats_AssignmentDualWrite" DEFERRED;
            """;
        command.Parameters.AddWithValue("seatId", seatId);
        return await command.ExecuteNonQueryAsync();
    }

    /// <summary>Waits for one exact backend to be blocked by another exact backend.</summary>
    /// <param name="adminConnectionString">The isolated database administrator connection.</param>
    /// <param name="waitingBackendPid">The backend expected to wait.</param>
    /// <param name="blockingBackendPid">The backend expected to own the blocking lock.</param>
    /// <param name="applicationName">The exact waiting application tag.</param>
    private static async Task WaitForBlockedBackendAsync(
        string adminConnectionString,
        int waitingBackendPid,
        int blockingBackendPid,
        string applicationName)
    {
        await using var observer = new NpgsqlConnection(adminConnectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 150; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity
                    WHERE pid = @waitingPid
                      AND application_name = @applicationName
                      AND wait_event_type = 'Lock'
                      AND @blockingPid = ANY(pg_catalog.pg_blocking_pids(pid)));
                """;
            command.Parameters.AddWithValue("waitingPid", waitingBackendPid);
            command.Parameters.AddWithValue("blockingPid", blockingBackendPid);
            command.Parameters.AddWithValue("applicationName", applicationName);
            if ((bool)(await command.ExecuteScalarAsync())!)
                return;
            await Task.Delay(20);
        }
        throw new TimeoutException("The commercial writer was not observed behind the release backend.");
    }

    /// <summary>Waits for one tagged application backend to be blocked by the exact writer.</summary>
    /// <param name="adminConnectionString">The isolated database administrator connection.</param>
    /// <param name="applicationName">The exact waiting application tag.</param>
    /// <param name="blockingBackendPid">The writer backend expected to own the blocking lock.</param>
    private static async Task WaitForApplicationBlockedAsync(
        string adminConnectionString,
        string applicationName,
        int blockingBackendPid)
    {
        await using var observer = new NpgsqlConnection(adminConnectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 150; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity
                    WHERE application_name = @applicationName
                      AND wait_event_type = 'Lock'
                      AND @blockingPid = ANY(pg_catalog.pg_blocking_pids(pid)));
                """;
            command.Parameters.AddWithValue("applicationName", applicationName);
            command.Parameters.AddWithValue("blockingPid", blockingBackendPid);
            if ((bool)(await command.ExecuteScalarAsync())!)
                return;
            await Task.Delay(20);
        }
        throw new TimeoutException("The portal release was not observed behind the commercial writer.");
    }

    /// <summary>Creates isolated contexts with an optional command interceptor.</summary>
    private sealed class SeatReleaseTestDbFactory(
        string connectionString,
        DbCommandInterceptor? interceptor) : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Creates one caller-owned context using the production model.</summary>
        /// <returns>A new context for the isolated scenario database.</returns>
        public LicenseDbContext CreateDbContext()
        {
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString);
            if (interceptor != null)
                options.AddInterceptors(interceptor);
            return new LicenseDbContext(options.Options);
        }

        /// <summary>Creates one caller-owned context asynchronously.</summary>
        /// <param name="cancellationToken">Unused because context construction performs no I/O.</param>
        /// <returns>The newly created context.</returns>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>Pauses a portal release immediately after it acquires global and item2 barriers.</summary>
    private sealed class SeatReleaseBarrierPauseInterceptor : DbCommandInterceptor
    {
        private readonly TaskCompletionSource<int> _barrierHeld =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _captured;

        /// <summary>Completes with the release backend PID while both barriers are held.</summary>
        internal Task<int> BarrierHeld => _barrierHeld.Task;

        /// <summary>Allows the paused production command to return to its caller.</summary>
        internal void Release() => _release.TrySetResult();

        /// <inheritdoc />
        public override async ValueTask<int> NonQueryExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("pg_advisory_xact_lock(999831, 1)", StringComparison.Ordinal)
                && command.CommandText.Contains("pg_advisory_xact_lock(1312, 1)", StringComparison.Ordinal)
                && Interlocked.Exchange(ref _captured, 1) == 0)
            {
                _barrierHeld.TrySetResult(((NpgsqlConnection)command.Connection!).ProcessID);
                await _release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }

    /// <summary>
    /// Materializes the immutable Runtime terminal shape produced by server versions before B1.
    /// Already-terminal enrollment evidence remains unchanged, matching the historical writer.
    /// </summary>
    /// <param name="db">The isolated PostgreSQL scenario context.</param>
    /// <param name="binding">The historical binding to terminalize.</param>
    /// <param name="enrollment">The historical enrollment to terminalize when it is live.</param>
    /// <param name="releaseSeat">Whether to materialize the historical inactive-seat projection too.</param>
    private static async Task PersistHistoricalSeatReleaseAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        RuntimeEnrollment enrollment,
        bool releaseSeat = false)
    {
        var connectionWasClosed = db.Database.GetDbConnection().State != System.Data.ConnectionState.Open;
        if (connectionWasClosed)
            await db.Database.OpenConnectionAsync();
        try
        {
            var terminalAtUtc = (await RuntimeEnrollmentService.DatabaseNowAsync(db, CancellationToken.None)).UtcDateTime;
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = terminalAtUtc;
            binding.InvalidationReason = "seat_released";
            if (enrollment.State is "PENDING" or "ACTIVE")
            {
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = terminalAtUtc;
                enrollment.InvalidationReason = "seat_released";
            }
            if (releaseSeat)
            {
                var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
                seat.IsActive = false;
                seat.UnlinkedAt = terminalAtUtc;
            }
            await db.SaveChangesAsync();
        }
        finally
        {
            if (connectionWasClosed)
                await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>
    /// Seeds the precise legacy incident under a real authority lease. Cloned scalar records use
    /// new identifiers and grant digests; only the selected negative dimension is made divergent.
    /// </summary>
    private static async Task<(Guid SeatId, Guid BindingId, Guid EnrollmentId)> SeedReleasedRuntimeAsync(
        PreparedBootstrapScenario scenario, string mutation)
    {
        await SetScenarioSubjectAuthorityAsync(scenario, Base64Url(System.Security.Cryptography.SHA256.HashData("release-subject"u8.ToArray())));
        var authority = new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(db, scenario.Fixture.BindingId);
        var current = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var seat = new LicenseSeat
        {
            LicenseId = current.LicenseId,
            HardwareId = mutation == "seat-hash-mismatch" ? "BBBBBBBBBBBBBBBB" : StableHardwareId,
            IsActive = mutation == "active-seat",
            UnlinkedAt = mutation == "no-unlink" ? null : DateTime.UtcNow.AddMinutes(-10)
        };
        if (mutation == "different-license")
        {
            var license = await db.Licenses.SingleAsync(row => row.Id == current.LicenseId);
            var other = (License)db.Entry(license).CurrentValues.ToObject();
            other.Id = Guid.NewGuid();
            other.LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant();
            db.Licenses.Add(other);
            seat.LicenseId = other.Id;
        }
        var binding = (DistributionInstallationBinding)db.Entry(current).CurrentValues.ToObject();
        binding.Id = Guid.NewGuid();
        binding.LicenseSeatId = seat.Id;
        binding.LicenseId = seat.LicenseId;
        binding.InstallationId = Guid.NewGuid().ToString("D");
        binding.GrantRef = Guid.NewGuid().ToString("D");
        binding.GrantRefDigestSha256 = Sha256(binding.GrantRef);
        binding.HandoffDigestSha256 = Sha256("historical-handoff-" + binding.Id);
        binding.HardwareIdHash = Sha256(StableHardwareId);
        binding.BoundAtUtc = DateTime.UtcNow.AddMinutes(mutation == "binding-after-unlink" ? -5 : -20);
        if (mutation == "different-subject") binding.SubjectRefDigestSha256 = Sha256("other-subject");
        if (mutation == "case-subject") binding.SubjectRefDigestSha256 = binding.SubjectRefDigestSha256!.ToUpperInvariant();
        var oldEnrollment = (RuntimeEnrollment)db.Entry(enrollment).CurrentValues.ToObject();
        oldEnrollment.Id = Guid.NewGuid();
        oldEnrollment.KeyThumbprint = Base64Url(System.Security.Cryptography.SHA256.HashData(oldEnrollment.Id.ToByteArray()));
        oldEnrollment.BindingId = binding.Id;
        oldEnrollment.LicenseId = seat.LicenseId;
        oldEnrollment.LicenseSeatId = seat.Id;
        oldEnrollment.InstallationId = binding.InstallationId;
        oldEnrollment.HardwareIdHash = binding.HardwareIdHash;
        oldEnrollment.HandoffDigestSha256 = binding.HandoffDigestSha256;
        oldEnrollment.SubjectRefDigestSha256 = binding.SubjectRefDigestSha256;
        db.LicenseSeats.Add(seat);
        db.DistributionInstallationBindings.Add(binding);
        db.RuntimeEnrollments.Add(oldEnrollment);
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(row => row.Id == 1).Select(row => row.Epoch).SingleAsync();
        await db.SaveChangesAsync();
        await lease.CommitAsync();
        return (seat.Id, binding.Id, oldEnrollment.Id);
    }
}

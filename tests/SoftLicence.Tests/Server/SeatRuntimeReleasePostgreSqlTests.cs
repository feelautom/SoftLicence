using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// A real portal unlink must allow a fresh, server-owned Finalize generation while keeping
    /// the released credential terminal, including when legacy activation occupied another seat.
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
        if (variant.Contains("prior-authority-ineligible", StringComparison.Ordinal)
            || variant.Contains("prior-version-ineligible", StringComparison.Ordinal)
            || variant.Contains("prior-security", StringComparison.Ordinal)
            || variant.Contains("future-authority-ineligible", StringComparison.Ordinal))
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
        }
        var portal = new PortalDeactivationService(scenario.Factory, TimeProvider.System,
            NullLogger<PortalDeactivationService>.Instance);
        var unlink = await portal.DeactivateAsync("website-step1", Sha256("new-finalize-unlink"),
            new PortalDeactivationRequest(PortalDeactivationService.RequestSchema, Guid.NewGuid().ToString("D"),
                source.ProductId.ToString("D"), source.LicenseId.ToString("D"), StableHardwareId, "settings_button"));
        Assert.Equal("deactivated", unlink.Response.Outcome);
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
            Assert.Equal("binding_ineligible", stale.ErrorCode);
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
            case "epoch": oldEnrollment.SecurityEpoch = 1; break;
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

        var terminal = await service.DeactivateAsync("website-step1", Sha256("termination"),
            request with { Reason = "subscription_termination" });

        Assert.Equal("deactivated", terminal.Response.Outcome);
        Assert.Equal("invalidated", (await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == binding.Id)).State);
        Assert.Equal("INVALIDATED", (await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        Assert.Single(await db.PortalDeactivationOperations.ToListAsync());
        await db.Entry(license).ReloadAsync();
        Assert.False(license.IsActive);
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
    /// Successful release must terminalize both Runtime records before the response is returned.
    /// </summary>
    [Theory]
    [InlineData("admin")]
    [InlineData("client")]
    [InlineData("reset")]
    public async Task SeatRelease_HttpEndpoints_InvalidateExactRuntimeGraph(string route)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
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
        Assert.Equal("invalidated", (await db.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == binding.Id)).State);
        Assert.Equal("INVALIDATED", (await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
    }

    /// <summary>
    /// Reproduces the old inactive stable seat plus active binding incident, then proves a signed
    /// migration terminalizes that historical graph and exact replay preserves the new authority.
    /// </summary>
    [Fact]
    public async Task SeatRelease_HistoricalOrphan_MigratesAndReplaysWithoutRevivingOldRights()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var orphan = await SeedReleasedRuntimeAsync(scenario, "eligible");
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
        Assert.Single(await db.LicenseHistories.Where(row => row.Action == "RUNTIME_RELEASE_RECONCILED").ToListAsync());
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
        await db.Entry(binding).ReloadAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
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
    /// Real portal requests terminalize the exact live Runtime graph and serialize different
    /// request IDs on the same seat. An exact replay cannot revoke a later seat reactivation.
    /// </summary>
    [Fact]
    public async Task SeatRelease_PortalConcurrentRequests_TerminalizeOnceAndReplayDoesNotUnlinkAgain()
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
        Assert.Equal("invalidated", (await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == binding.Id)).State);
        Assert.Equal("INVALIDATED", (await db.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.EnrollmentId)).State);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
        seat.IsActive = true;
        seat.UnlinkedAt = null;
        await db.SaveChangesAsync();

        var replay = await service.DeactivateAsync("website-step1", Sha256("release-a"), request);

        Assert.True(replay.Idempotent);
        await db.Entry(seat).ReloadAsync();
        Assert.True(seat.IsActive);
        await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => MigrateScenarioAsync(scenario));
        Assert.Equal("invalidated", (await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == binding.Id)).State);
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

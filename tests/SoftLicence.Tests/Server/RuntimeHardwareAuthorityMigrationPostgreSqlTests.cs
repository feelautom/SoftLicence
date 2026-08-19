using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    private const string LegacyHardwareId = "A00272B768FFD6AF";
    private const string StableHardwareId = "A6D3EED115BC84AD";

    /// <summary>
    /// Proves the signed Runtime transition updates one existing seat and every linked authority
    /// row atomically, issues a V2 license, preserves quota, and replays exact response bytes.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_AtomicallyMovesExistingSeatAndReplays()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-atomic-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var migrated = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        var replay = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.False(migrated.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(migrated.ExactResponseBody, replay.ExactResponseBody);
        Assert.Equal("migrated", migrated.Response.Decision);
        Assert.Equal(1, migrated.Response.OldSecurityEpoch);
        Assert.Equal(2, migrated.Response.NewSecurityEpoch);
        Assert.Equal(StableHardwareId, migrated.Response.HardwareIdV2);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var binding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await check.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await check.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        var license = await check.Licenses.Include(candidate => candidate.Product)
            .SingleAsync(candidate => candidate.Id == binding.LicenseId);
        var alias = await check.HardwareAuthorityAliases.SingleAsync();
        Assert.Equal(StableHardwareId, seat.HardwareId);
        Assert.Equal(Sha256(StableHardwareId), binding.HardwareIdHash);
        Assert.Equal(binding.HardwareIdHash, enrollment.HardwareIdHash);
        Assert.Equal(2, enrollment.SecurityEpoch);
        Assert.Equal(license.ProductId, alias.ProductId);
        Assert.Equal(license.Id, alias.LicenseId);
        Assert.Equal(seat.Id, alias.LicenseSeatId);
        Assert.Equal(enrollment.Id, alias.RuntimeEnrollmentId);
        Assert.Equal(binding.Id, alias.BindingId);
        Assert.Equal(Sha256(LegacyHardwareId), alias.LegacyHardwareIdSha256);
        Assert.Equal(Sha256(StableHardwareId), alias.CanonicalHardwareIdSha256);
        Assert.Equal(enrollment.SecurityEpoch, alias.SecurityEpoch);
        Assert.Equal(enrollment.AuthorityEpoch, alias.AuthorityEpoch);
        Assert.Single(await check.LicenseSeats.Where(candidate => candidate.LicenseId == license.Id).ToListAsync());
        Assert.Single(await check.LicenseHistories.Where(candidate =>
            candidate.LicenseId == license.Id && candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
        var targetConflictSql = check.LicenseSeats.Where(candidate => candidate.Id != seat.Id
            && candidate.IsActive && candidate.License!.ProductId == license.ProductId
            && candidate.HardwareId.ToUpper() == StableHardwareId).ToQueryString();
        Assert.Contains("upper(", targetConflictSql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ProductId", targetConflictSql, StringComparison.Ordinal);
        var validation = LicenseService.ValidateLicense(
            migrated.Response.LicenseFile, license.Product!.PublicKeyXml, StableHardwareId);
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.False(LicenseService.ValidateLicense(
            migrated.Response.LicenseFile, license.Product.PublicKeyXml, LegacyHardwareId).IsValid);
    }

    /// <summary>
    /// Proves the authenticated alias resolves the same V2 seat and never grants a second seat.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_ValidGraphResolvesCanonicalSeat()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolution = await CreateAliasResolver(db).ResolveAsync(
            binding.ProductId,
            binding.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);

        Assert.True(resolution.UsedAlias);
        Assert.Equal(StableHardwareId, resolution.EffectiveHardwareId);
        Assert.Single(await db.LicenseSeats.Where(candidate => candidate.LicenseId == binding.LicenseId).ToListAsync());
    }

    /// <summary>
    /// Proves an inactive V2 seat remains locatable for activation and status but cannot be targeted by deactivation.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_InactiveSeatPreservesReactivationIdentityOnly()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await MutateAliasGraphAsync(scenario, "seat-inactive");

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolver = CreateAliasResolver(db);
        var activation = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);
        var status = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, LegacyHardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck);
        var deactivation = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Deactivation);

        Assert.True(activation.UsedAlias);
        Assert.True(status.UsedAlias);
        Assert.Equal(StableHardwareId, activation.EffectiveHardwareId);
        Assert.True(deactivation.Refused);
    }

    /// <summary>
    /// Proves legitimate monotonic Runtime generations preserve a matching alias while rollback and identity divergence fail closed.
    /// </summary>
    [Theory]
    [InlineData("generation-forward", true)]
    [InlineData("security-rollback", false)]
    [InlineData("authority-rollback", false)]
    [InlineData("enrollment-hash", false)]
    [InlineData("binding-hash", false)]
    [InlineData("canonical-hash", false)]
    [InlineData("enrollment-inactive", false)]
    [InlineData("binding-inactive", false)]
    [InlineData("alias-disabled", false)]
    public async Task HardwareAuthorityAlias_RevalidatesLiveAuthorityGraph(string mutation, bool shouldResolve)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await MutateAliasGraphAsync(scenario, mutation);

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolution = await CreateAliasResolver(db).ResolveAsync(
            binding.ProductId,
            binding.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);

        Assert.Equal(shouldResolve, resolution.UsedAlias);
        Assert.Equal(!shouldResolve, resolution.Refused);
        Assert.Single(await db.LicenseSeats.Where(candidate => candidate.LicenseId == binding.LicenseId).ToListAsync());
    }

    /// <summary>
    /// Proves the one-time migration backfill materializes a divergent historical migration as disabled so legacy input is refused instead of becoming a new seat.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_BackfillDivergenceCreatesDisabledRefusalMarker()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);

        var adminFactory = new TestDbFactory(scenario.AdminConnectionString);
        await using (var downgrade = await adminFactory.CreateDbContextAsync())
        {
            await downgrade.GetService<IMigrator>().MigrateAsync(
                "20260816131533_AllowRuntimeHardwareAuthorityMigrationProofs");
        }
        await using (var diverge = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await diverge.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            binding.HardwareIdHash = Sha256("backfill-divergence");
            await diverge.SaveChangesAsync();
        }
        await using (var upgrade = await adminFactory.CreateDbContextAsync())
        {
            await upgrade.GetService<IMigrator>().MigrateAsync();
        }
        await using (var admin = new Npgsql.NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            Assert.True(await ScalarAsync<bool>(admin, """
                SELECT has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'SELECT')
                   AND has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'INSERT')
                   AND has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'UPDATE')
                   AND has_table_privilege('softlicence_app', 'public."HardwareAuthorityAliases"', 'DELETE');
                """));
            await GrantApplicationRuntimePrivilegesAsync(admin);
        }

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var alias = await db.HardwareAuthorityAliases.SingleAsync();
        var bindingAfter = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var seatCount = await db.LicenseSeats.CountAsync(candidate =>
            candidate.LicenseId == bindingAfter.LicenseId);
        var resolution = await CreateAliasResolver(db).ResolveAsync(
            bindingAfter.ProductId,
            bindingAfter.LicenseId,
            LegacyHardwareId,
            HardwareAuthorityResolutionIntent.Activation);

        Assert.False(alias.IsActive);
        Assert.NotNull(alias.DisabledAtUtc);
        Assert.True(resolution.Refused);
        Assert.Equal(1, seatCount);
    }

    /// <summary>
    /// Proves the complete legacy compatibility cycle uses one V2 seat through real HTTP serialization, rejects non-canonical primary identities before reactivation, checks both ban identities, and fails closed on later alias divergence.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_HttpCyclePreservesOneCanonicalSeatAndFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await PrepareLegacyHttpActivationAsync(scenario);
        var aliasLogs = new RecordingLogger<HardwareAuthorityAliasResolver>();
        using var webFactory = CreateAliasWebFactory(scenario, aliasLogs);
        using var client = webFactory.CreateClient();

        Guid licenseId;
        Guid seatId;
        DateTime firstActivatedAt;
        string licenseKey;
        string appName;
        string publicKey;
        await using (var initial = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await initial.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var license = await initial.Licenses.Include(candidate => candidate.Product)
                .SingleAsync(candidate => candidate.Id == binding.LicenseId);
            var seat = await initial.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
            licenseId = license.Id;
            seatId = seat.Id;
            firstActivatedAt = seat.FirstActivatedAt;
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
            publicKey = license.Product.PublicKeyXml;
        }

        var initialActivation = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        Assert.True(
            initialActivation.IsSuccessStatusCode,
            $"Legacy HTTP activation failed with {(int)initialActivation.StatusCode}: {await initialActivation.Content.ReadAsStringAsync()}");
        await MigrateScenarioAsync(scenario);

        var legacyCheck = await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId);
        Assert.Equal(HttpStatusCode.OK, legacyCheck.StatusCode);
        using (var checkJson = JsonDocument.Parse(await legacyCheck.Content.ReadAsStringAsync()))
        {
            Assert.Equal("VALID", checkJson.RootElement.GetProperty("status").GetString());
            var signed = checkJson.RootElement.GetProperty("licenseFile").GetString();
            Assert.NotNull(signed);
            Assert.True(LicenseService.ValidateLicense(signed!, publicKey, StableHardwareId).IsValid);
            Assert.False(LicenseService.ValidateLicense(signed!, publicKey, LegacyHardwareId).IsValid);
        }

        var deactivation = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = LegacyHardwareId,
            AppName = appName,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, deactivation.StatusCode);

        var reactivation = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        Assert.True(
            reactivation.IsSuccessStatusCode,
            $"Canonical legacy reactivation failed with {(int)reactivation.StatusCode}: {await reactivation.Content.ReadAsStringAsync()}");

        var directV2Check = await PostCheckAsync(client, licenseKey, appName, StableHardwareId);
        var directV2Body = await directV2Check.Content.ReadAsStringAsync();
        Assert.True(
            directV2Check.IsSuccessStatusCode,
            $"Direct V2 check failed with {(int)directV2Check.StatusCode}: {directV2Body}");
        using (var directJson = JsonDocument.Parse(directV2Body))
            Assert.Equal("VALID", directJson.RootElement.GetProperty("status").GetString());

        await SetHardwareBanAsync(scenario, StableHardwareId, active: true);
        using (var canonicalBanJson = JsonDocument.Parse(
            await (await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId)).Content.ReadAsStringAsync()))
            Assert.Equal("REVOKED", canonicalBanJson.RootElement.GetProperty("status").GetString());

        await SetHardwareBanAsync(scenario, StableHardwareId, active: false);
        await SetHardwareBanAsync(scenario, LegacyHardwareId, active: true);
        using (var legacyBanJson = JsonDocument.Parse(
            await (await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId)).Content.ReadAsStringAsync()))
            Assert.Equal("REVOKED", legacyBanJson.RootElement.GetProperty("status").GetString());

        await SetHardwareBanAsync(scenario, LegacyHardwareId, active: false);
        await using (var diverge = await scenario.Factory.CreateDbContextAsync())
        {
            var alias = await diverge.HardwareAuthorityAliases.SingleAsync();
            alias.CanonicalHardwareIdSha256 = Sha256("endpoint-divergence");
            await diverge.SaveChangesAsync();
        }
        var refused = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        Assert.Equal(HttpStatusCode.OK, refused.StatusCode);
        Assert.Equal("HARDWARE_AUTHORITY_REFUSED", refused.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        await using var final = await scenario.Factory.CreateDbContextAsync();
        var seats = await final.LicenseSeats.Where(candidate => candidate.LicenseId == licenseId).ToListAsync();
        Assert.Single(seats);
        Assert.Equal(seatId, seats[0].Id);
        Assert.Equal(firstActivatedAt, seats[0].FirstActivatedAt);
        Assert.Equal(StableHardwareId, seats[0].HardwareId);
        Assert.True(seats[0].IsActive);
        Assert.DoesNotContain(aliasLogs.Messages, message =>
            message.Contains(LegacyHardwareId, StringComparison.Ordinal)
            || message.Contains(StableHardwareId, StringComparison.Ordinal)
            || message.Contains(Sha256(LegacyHardwareId), StringComparison.Ordinal)
            || message.Contains(Sha256(StableHardwareId), StringComparison.Ordinal));
    }

    /// <summary>
    /// Proves a lowercase spelling of a known migrated legacy identity is rejected by all public seat endpoints
    /// before it can create, reactivate, check, or deactivate the single canonical V2 seat.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_LowercaseKnownLegacyIsRejectedWithoutSeatMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        var aliasLogs = new RecordingLogger<HardwareAuthorityAliasResolver>();
        using var webFactory = CreateAliasWebFactory(scenario, aliasLogs);
        using var client = webFactory.CreateClient();

        Guid licenseId;
        string licenseKey;
        string appName;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var license = await db.Licenses.Include(candidate => candidate.Product)
                .SingleAsync(candidate => candidate.Id == binding.LicenseId);
            licenseId = license.Id;
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
        }

        var canonicalDeactivation = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = LegacyHardwareId,
            AppName = appName,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, canonicalDeactivation.StatusCode);

        var lowercaseLegacy = LegacyHardwareId.ToLowerInvariant();
        var invalidActivation = await PostActivationAsync(client, licenseKey, appName, lowercaseLegacy);
        Assert.Equal(HttpStatusCode.BadRequest, invalidActivation.StatusCode);
        Assert.Equal("INVALID_HARDWARE_ID", invalidActivation.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        var invalidCheck = await PostCheckAsync(client, licenseKey, appName, lowercaseLegacy);
        Assert.Equal(HttpStatusCode.BadRequest, invalidCheck.StatusCode);
        Assert.Equal("INVALID_HARDWARE_ID", invalidCheck.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        var invalidDeactivation = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = lowercaseLegacy,
            AppName = appName,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.BadRequest, invalidDeactivation.StatusCode);
        Assert.Equal("INVALID_HARDWARE_ID", invalidDeactivation.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var seats = await verify.LicenseSeats
            .Where(candidate => candidate.LicenseId == licenseId)
            .ToListAsync();
        Assert.Single(seats);
        Assert.False(seats[0].IsActive);
        Assert.Equal(StableHardwareId, seats[0].HardwareId);
    }

    /// <summary>
    /// Proves through resolver and HTTP paths that direct canonical V2 remains operational while legacy alias compatibility is disabled.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityAlias_DisabledPolicyDoesNotBlockDirectV2OrAuthorizeArbitraryLegacy()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, StableHardwareId);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var resolver = new HardwareAuthorityAliasResolver(
            db,
            Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "off" }),
            NullLogger<HardwareAuthorityAliasResolver>.Instance);

        var direct = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, StableHardwareId,
            HardwareAuthorityResolutionIntent.StatusCheck);
        var arbitrary = await resolver.ResolveAsync(
            binding.ProductId, binding.LicenseId, "B00272B768FFD6AF",
            HardwareAuthorityResolutionIntent.Activation);

        Assert.Equal(HardwareAuthorityResolutionStatus.NoAlias, direct.Status);
        Assert.Equal(HardwareAuthorityResolutionStatus.NoAlias, arbitrary.Status);
        Assert.Empty(await db.HardwareAuthorityAliases.ToListAsync());

        var aliasLogs = new RecordingLogger<HardwareAuthorityAliasResolver>();
        using var webFactory = CreateAliasWebFactory(scenario, aliasLogs, aliasMode: "off");
        using var client = webFactory.CreateClient();
        var license = await db.Licenses.Include(candidate => candidate.Product)
            .SingleAsync(candidate => candidate.Id == binding.LicenseId);
        var directV2Check = await PostCheckAsync(
            client,
            license.LicenseKey,
            license.Product!.Name,
            StableHardwareId);
        Assert.Equal(HttpStatusCode.OK, directV2Check.StatusCode);
        using var directV2Json = JsonDocument.Parse(await directV2Check.Content.ReadAsStringAsync());
        Assert.Equal("VALID", directV2Json.RootElement.GetProperty("status").GetString());
        Assert.False(string.IsNullOrWhiteSpace(directV2Json.RootElement.GetProperty("licenseFile").GetString()));
    }

    /// <summary>
    /// Proves identical legacy and V2 identities return a signed current license without
    /// changing the seat, security generation, or audit history.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_IdenticalAuthorityIsNoOp()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, StableHardwareId);
        var request = MigrationRequest(scenario, StableHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-current-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var result = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.Equal("already_current", result.Response.Decision);
        Assert.Equal(result.Response.OldSecurityEpoch, result.Response.NewSecurityEpoch);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
        Assert.Empty(await check.HardwareAuthorityAliases.ToListAsync());
    }

    /// <summary>
    /// Proves a fluctuating legacy disk observation can converge locally when the requested V2
    /// identity already owns the exact seat, binding, and enrollment without mutating authority.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_TargetAlreadyAuthoritativeIsNoOp()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, StableHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-target-current-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var result = await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);

        Assert.False(result.Idempotent);
        Assert.Equal("already_current", result.Response.Decision);
        Assert.Equal(1, result.Response.OldSecurityEpoch);
        Assert.Equal(1, result.Response.NewSecurityEpoch);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(StableHardwareId, (await check.LicenseSeats.SingleAsync()).HardwareId);
        Assert.Empty(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>
    /// Proves a different WMI enumeration result cannot claim the current installation even
    /// when it proposes the same deterministic V2 target.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_DifferentLegacyDiskFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, "B00272B768FFD6AF", StableHardwareId);
        var digest = Sha256("hardware-migration-wmi-order-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, rejected.StatusCode);
        Assert.Equal("hardware_authority_migration_ineligible", rejected.ErrorCode);
        await AssertLegacyAuthorityUnchangedAsync(scenario);
    }

    /// <summary>
    /// Proves a V2 identity already owned by another active seat in the same product cannot be
    /// merged, transferred, or consumed by the current Runtime installation.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_CompetingTargetSeatFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await AddCompetingTargetSeatAsync(scenario);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-conflict-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status409Conflict, rejected.StatusCode);
        Assert.Equal("hardware_authority_migration_conflict", rejected.ErrorCode);
        await AssertLegacyAuthorityUnchangedAsync(scenario);
    }

    /// <summary>
    /// Proves concurrent migration attempts serialize on authority and only one can transition
    /// the existing seat generation.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_ConcurrentRequestsHaveSingleWinner()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var firstRequest = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var secondRequest = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var firstDigest = Sha256("hardware-migration-race-a-" + Guid.NewGuid().ToString("D"));
        var secondDigest = Sha256("hardware-migration-race-b-" + Guid.NewGuid().ToString("D"));
        var firstProof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", firstDigest);
        var secondProof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", secondDigest);

        var outcomes = await Task.WhenAll(
            CaptureHardwareMigrationAsync(scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, firstDigest, firstRequest, firstProof, IPAddress.Loopback)),
            CaptureHardwareMigrationAsync(scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, secondDigest, secondRequest, secondProof, IPAddress.Loopback)));

        Assert.Single(outcomes, outcome => outcome.Result?.Response.Decision == "migrated");
        Assert.Single(outcomes, outcome => outcome.Error != null);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>
    /// Proves an exact encrypted replay cannot bypass a licence revocation committed after the
    /// original V2 transition.
    /// </summary>
    [Fact]
    public async Task HardwareAuthorityMigration_ReplayRevalidatesCurrentAuthority()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-replay-revocation-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        await MutateScenarioAuthorityAsync(scenario, "license-revoked");

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, rejected.StatusCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>
    /// Proves an unresolved critical Runtime incident blocks both a first migration and any
    /// otherwise exact replay, so identity repair cannot bypass the incident authority.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HardwareAuthorityMigration_OpenCriticalIncidentFailsClosed(bool migrateBeforeIncident)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-critical-incident-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        if (migrateBeforeIncident)
        {
            await scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
        }

        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await seed.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            seed.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident
            {
                EnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                ProductId = enrollment.ProductId,
                InstallationId = enrollment.InstallationId,
                EventId = Guid.NewGuid().ToString("D"),
                Trigger = "RuntimeCheck_NativeDllSwapped",
                State = "OPEN",
                OpenedSecurityEpoch = enrollment.SecurityEpoch,
                OpenedAuthorityEpoch = enrollment.AuthorityEpoch,
                OpenedAtUtc = DateTime.UtcNow
            });
            await seed.SaveChangesAsync();
        }

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status423Locked, rejected.StatusCode);
        Assert.Equal("critical_incident_unresolved", rejected.ErrorCode);
    }

    /// <summary>
    /// Proves revocation, expiry, seat removal, and identity authority divergence always win
    /// over a correctly signed migration request.
    /// </summary>
    [Theory]
    [InlineData("license-revoked")]
    [InlineData("license-expired")]
    [InlineData("seat-inactive")]
    [InlineData("binding-subject")]
    [InlineData("binding-installation")]
    [InlineData("enrollment-client")]
    [InlineData("binding-product")]
    public async Task HardwareAuthorityMigration_IneligibleAuthorityFailsClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MutateScenarioAuthorityAsync(scenario, mutation);
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-migration-ineligible-" + mutation + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);

        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.MigrateHardwareAuthorityAsync(
                scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, rejected.StatusCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Empty(await check.LicenseHistories.Where(candidate =>
            candidate.Action == "HWID_V2_MIGRATED").ToListAsync());
    }

    /// <summary>Creates an application-role HTTP server with an exact product alias compatibility mode and the scenario signing authority.</summary>
    /// <param name="scenario">Isolated PostgreSQL authority graph and signing fixture.</param>
    /// <param name="aliasLogger">Logger used to assert that alias telemetry contains no hardware identifiers or digests.</param>
    /// <param name="aliasMode">Exact default compatibility mode, either enabled or off.</param>
    /// <returns>A disposable HTTP factory connected to the isolated application-role database.</returns>
    private static WebApplicationFactory<Program> CreateAliasWebFactory(
        PreparedBootstrapScenario scenario,
        RecordingLogger<HardwareAuthorityAliasResolver> aliasLogger,
        string aliasMode = "enabled")
    {
        var notification = new Mock<NotificationService>(
            scenario.Factory,
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        notification.Setup(service => service.Notify(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<object?>()));

        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("HardwareAuthorityAliases:DefaultMode", aliasMode);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseNpgsql(scenario.AppConnectionString));
                services.RemoveAll<ISignedLicenseFileService>();
                services.AddSingleton(scenario.SignedLicenseFiles);
                services.RemoveAll<NotificationService>();
                services.AddSingleton(notification.Object);
                services.RemoveAll<ILogger<HardwareAuthorityAliasResolver>>();
                services.AddSingleton<ILogger<HardwareAuthorityAliasResolver>>(aliasLogger);
            });
        });
    }

    /// <summary>Sends the canonical JSON activation shape used by transition clients.</summary>
    private static Task<HttpResponseMessage> PostActivationAsync(
        HttpClient client,
        string licenseKey,
        string appName,
        string hardwareId) =>
        client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = "2.3.393"
        });

    /// <summary>Sends the canonical JSON status shape used by transition clients.</summary>
    private static Task<HttpResponseMessage> PostCheckAsync(
        HttpClient client,
        string licenseKey,
        string appName,
        string hardwareId) =>
        client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName = appName,
            AppVersion = "2.3.393"
        });

    /// <summary>
    /// Makes the already confirmed Runtime fixture require one real legacy HTTP reactivation while preserving its binding authority.
    /// </summary>
    private static async Task PrepareLegacyHttpActivationAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        license.CustomerEmail = "hwid-alias-regression@example.com";
        license.AllowedVersions = "2.*";
        seat.IsActive = false;
        await db.SaveChangesAsync();
    }

    /// <summary>Creates or toggles one exact product-scoped hardware ban for endpoint tests.</summary>
    private static async Task SetHardwareBanAsync(
        PreparedBootstrapScenario scenario,
        string hardwareId,
        bool active)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var ban = await db.BannedHardwareIds.SingleOrDefaultAsync(candidate =>
            candidate.HardwareId == hardwareId && candidate.ProductId == scenario.Fixture.ProductId);
        if (ban == null)
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = scenario.Fixture.ProductId,
                BanCategory = BannedHardwareId.Categories.Piracy,
                Reason = "hardware-authority-alias-test",
                IsActive = active
            });
        }
        else
        {
            ban.IsActive = active;
        }
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Captures rendered structured log messages for redaction assertions without changing production logging.
    /// </summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly ConcurrentQueue<string> _messages = new();

        /// <summary>Gets a stable snapshot of rendered messages.</summary>
        public IReadOnlyList<string> Messages => _messages.ToArray();

        /// <inheritdoc />
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        /// <inheritdoc />
        public bool IsEnabled(LogLevel logLevel) => true;

        /// <inheritdoc />
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            _messages.Enqueue(formatter(state, exception));
    }

    /// <summary>Creates the exact versioned migration request for an activated test scenario.</summary>
    private static RuntimeHardwareAuthorityMigrationRequest MigrationRequest(
        PreparedBootstrapScenario scenario,
        string legacyHardwareId,
        string hardwareIdV2) => new()
        {
            Schema = RuntimeEnrollmentService.HardwareAuthorityMigrationSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            LegacyHardwareId = legacyHardwareId,
            HardwareIdV2 = hardwareIdV2,
            LegacyAlgorithm = "legacy-wmi-first-disk",
            HardwareIdV2Algorithm = "v2-wmi-disk-index-0",
            SdkVersion = "1.1.13"
        };

    /// <summary>Executes one fresh signed legacy-to-V2 migration for alias tests.</summary>
    private static async Task MigrateScenarioAsync(PreparedBootstrapScenario scenario)
    {
        var request = MigrationRequest(scenario, LegacyHardwareId, StableHardwareId);
        var digest = Sha256("hardware-alias-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
    }

    /// <summary>Creates the production resolver with explicit enabled compatibility policy.</summary>
    private static HardwareAuthorityAliasResolver CreateAliasResolver(LicenseDbContext db) =>
        new(
            db,
            Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "enabled" }),
            NullLogger<HardwareAuthorityAliasResolver>.Instance);

    /// <summary>Mutates one post-migration graph dimension without creating a replacement seat.</summary>
    private static async Task MutateAliasGraphAsync(PreparedBootstrapScenario scenario, string mutation)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var alias = await db.HardwareAuthorityAliases.SingleAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == alias.RuntimeEnrollmentId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate => candidate.Id == alias.BindingId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == alias.LicenseSeatId);
        switch (mutation)
        {
            case "seat-inactive":
                seat.IsActive = false;
                break;
            case "generation-forward":
                enrollment.SecurityEpoch++;
                enrollment.AuthorityEpoch++;
                break;
            case "security-rollback":
                alias.SecurityEpoch = enrollment.SecurityEpoch + 1;
                break;
            case "authority-rollback":
                alias.AuthorityEpoch = enrollment.AuthorityEpoch + 1;
                break;
            case "enrollment-hash":
                enrollment.HardwareIdHash = Sha256("enrollment-divergence");
                break;
            case "binding-hash":
                binding.HardwareIdHash = Sha256("binding-divergence");
                break;
            case "canonical-hash":
                alias.CanonicalHardwareIdSha256 = Sha256("canonical-divergence");
                break;
            case "enrollment-inactive":
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = DateTime.UtcNow;
                enrollment.InvalidationReason = "test";
                break;
            case "binding-inactive":
                binding.State = "invalidated";
                binding.InvalidatedAtUtc = DateTime.UtcNow;
                binding.InvalidationReason = "test";
                break;
            case "alias-disabled":
                alias.IsActive = false;
                alias.DisabledAtUtc = DateTime.UtcNow;
                break;
            default:
                throw new InvalidOperationException("Unknown alias mutation: " + mutation);
        }

        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Delivers the initial license, rewrites fixture identity under the production authority
    /// lease, and activates the Runtime enrollment with its original signed challenge.
    /// </summary>
    private static async Task ActivateCanonicalScenarioAsync(
        PreparedBootstrapScenario scenario,
        string hardwareId)
    {
        await scenario.ConsumeAsync();
        await SetScenarioHardwareAuthorityAsync(scenario, hardwareId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1
        };
        var digest = Sha256("hardware-migration-confirm-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "confirm", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, scenario.Prepared.Challenge, digest);
        await scenario.Runtime.ConfirmAsync(
            scenario.EnrollmentId, digest, confirm, proof, IPAddress.Loopback);
    }

    /// <summary>Rebinds the seeded fixture to a canonical 16-character hardware authority.</summary>
    private static async Task SetScenarioHardwareAuthorityAsync(
        PreparedBootstrapScenario scenario,
        string hardwareId)
    {
        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(
            db, scenario.Fixture.BindingId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        seat.HardwareId = hardwareId;
        binding.HardwareIdHash = Sha256(hardwareId);
        enrollment.HardwareIdHash = binding.HardwareIdHash;
        license.HardwareId = hardwareId;
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1).Select(candidate => candidate.Epoch).SingleAsync();
        await db.SaveChangesAsync();
        await lease.CommitAsync();
    }

    /// <summary>Adds a competing active seat under the same product and authority lease.</summary>
    private static async Task AddCompetingTargetSeatAsync(PreparedBootstrapScenario scenario)
    {
        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(db, scenario.Fixture.BindingId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        license.MaxSeats = 2;
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = license.Id,
            HardwareId = StableHardwareId,
            IsActive = true
        });
        await db.SaveChangesAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        enrollment.AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1).Select(candidate => candidate.Epoch).SingleAsync();
        await db.SaveChangesAsync();
        await lease.CommitAsync();
    }

    /// <summary>Mutates one authoritative dimension under the production mutation lease.</summary>
    private static async Task MutateScenarioAuthorityAsync(
        PreparedBootstrapScenario scenario,
        string mutation)
    {
        var authority = new RuntimeEnrollmentAuthorityService(
            scenario.Factory, Options.Create(scenario.Options));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(db, scenario.Fixture.BindingId);
        var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        var license = await db.Licenses.SingleAsync(candidate => candidate.Id == binding.LicenseId);
        switch (mutation)
        {
            case "license-revoked":
                license.RevokedAt = DateTime.UtcNow;
                break;
            case "license-expired":
                license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
                break;
            case "seat-inactive":
                seat.IsActive = false;
                break;
            case "binding-subject":
                binding.SubjectRefDigestSha256 = Sha256("different-subject");
                break;
            case "binding-installation":
                binding.InstallationId = Guid.NewGuid().ToString("D");
                break;
            case "enrollment-client":
                enrollment.ClientId = "different-client";
                break;
            case "binding-product":
                var differentProduct = new Product
                {
                    Id = Guid.NewGuid(),
                    Name = "Different migration product " + Guid.NewGuid().ToString("N"),
                    PrivateKeyXml = "test",
                    PublicKeyXml = "test",
                    ApiSecret = Guid.NewGuid().ToString("N")
                };
                db.Products.Add(differentProduct);
                binding.ProductId = differentProduct.Id;
                break;
            default:
                throw new InvalidOperationException("Unknown migration authority mutation: " + mutation);
        }
        await db.SaveChangesAsync();
        enrollment.AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1).Select(candidate => candidate.Epoch).SingleAsync();
        await db.SaveChangesAsync();
        await lease.CommitAsync();
    }

    /// <summary>Captures one concurrent migration outcome without obscuring its exception.</summary>
    private static async Task<(
        RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>? Result,
        Exception? Error)> CaptureHardwareMigrationAsync(
        Task<RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>> task)
    {
        try
        {
            return (await task, null);
        }
        catch (Exception exception)
        {
            return (null, exception);
        }
    }

    /// <summary>Asserts a refused transition left all linked legacy authority rows untouched.</summary>
    private static async Task AssertLegacyAuthorityUnchangedAsync(PreparedBootstrapScenario scenario)
    {
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var binding = await check.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.Id == scenario.Fixture.BindingId);
        var enrollment = await check.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        var seat = await check.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        Assert.Equal(LegacyHardwareId, seat.HardwareId);
        Assert.Equal(Sha256(LegacyHardwareId), binding.HardwareIdHash);
        Assert.Equal(binding.HardwareIdHash, enrollment.HardwareIdHash);
        Assert.DoesNotContain(await check.LicenseHistories.ToListAsync(), candidate =>
            candidate.Action == "HWID_V2_MIGRATED");
    }
}

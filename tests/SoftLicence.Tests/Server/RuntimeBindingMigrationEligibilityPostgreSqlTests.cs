using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Exercises both private-reset callers with real receipt crypto and the existing explicit licence allowlist.</summary>
    [Theory]
    [InlineData("current")]
    [InlineData("obsolete")]
    [InlineData("corrupt-receipt")]
    public async Task MigratedBindingEligibility_PrivateResetAuthenticatesMigration(string scenarioKind)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        if (scenarioKind == "obsolete")
        {
            (await db.Products.SingleAsync(row => row.Id == binding.ProductId)).MinimumAllowedVersion = "99.0.0";
            await db.SaveChangesAsync();
        }
        if (scenarioKind == "corrupt-receipt")
        {
            var original = await db.HardwareAuthorityMigrationReceipts.AsNoTracking().SingleAsync();
            var counterfeit = new HardwareAuthorityMigrationReceipt
            {
                Id = Guid.NewGuid(), EnrollmentId = original.EnrollmentId, EnrollmentEpoch = original.EnrollmentEpoch,
                RequestId = Guid.NewGuid(), Jti = Guid.NewGuid(), KeyId = original.KeyId, Ciphertext = original.Ciphertext
            };
            db.HardwareAuthorityMigrationReceipts.Add(counterfeit);
            (await db.HardwareAuthorityAliases.SingleAsync()).MigrationReceiptId = counterfeit.Id;
            await db.SaveChangesAsync();
        }
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["PrivateValidationTestReset:AllowedLicenseIds"] = binding.LicenseId.ToString("D")
        }).Build();
        var authority = new RuntimeEnrollmentAuthorityService(scenario.Factory, Options.Create(scenario.Options));
        var service = new PrivateValidationTestResetService(scenario.Factory, authority, TimeProvider.System,
            configuration, crypto);
        var request = new PrivateValidationTestResetRequest(binding.ProductId, enrollment.Id, binding.Id,
            binding.InstallationId, binding.Version, enrollment.SecurityEpoch, "TKT-001501");
        if (scenarioKind == "corrupt-receipt")
        {
            foreach (var execute in new[] { false, true })
            {
                var failure = await Assert.ThrowsAsync<PrivateValidationTestResetException>(() =>
                    execute ? service.ExecuteAsync(request) : service.ValidateAsync(request));
                Assert.Equal("authority_unavailable", failure.ErrorCode);
                Assert.Equal(503, failure.StatusCode);
                Assert.Equal("migration_receipt_unavailable",
                    Assert.IsType<RuntimeEnrollmentException>(failure.InnerException).DiagnosticCode);
            }
            await db.Entry(binding).ReloadAsync();
            await db.Entry(enrollment).ReloadAsync();
            Assert.Equal("active", binding.State);
            Assert.Equal("ACTIVE", enrollment.State);
        }
        else if (scenarioKind == "obsolete")
        {
            Assert.Equal("authority_ineligible", (await Assert.ThrowsAsync<PrivateValidationTestResetException>(
                () => service.ValidateAsync(request))).ErrorCode);
            Assert.Equal("authority_ineligible", (await Assert.ThrowsAsync<PrivateValidationTestResetException>(
                () => service.ExecuteAsync(request))).ErrorCode);
        }
        else
        {
            var preview = await service.ValidateAsync(request);
            Assert.False(preview.Executed);
            Assert.Equal("ACTIVE", preview.EnrollmentState);
            var reset = await service.ExecuteAsync(request);
            Assert.True(reset.Executed);
            Assert.Equal("INVALIDATED", reset.EnrollmentState);
            Assert.Equal("invalidated", reset.BindingState);
        }
    }

    /// <summary>
    /// Updates the exact TKT-001500 two-alias graph without treating its unproved historical
    /// companion as evidence. Both historical producers retain byte-identical alias data.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MigratedBindingEligibility_HistoricalCompanionAllowsOnlyCurrentVersionUpdate(bool backfill)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var subjectRef = Base64Url(SHA256.HashData("tkt1501-historical-update"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await SeedPreUuidStableSeatAsync(scenario, bindingCarriesLegacy: false);
        Guid historicalId;
        string historicalBefore;
        await using (var seed = await scenario.Factory.CreateDbContextAsync())
        {
            var historical = await seed.HardwareAuthorityAliases.SingleAsync();
            if (backfill) historical.MigrationRequestId = null;
            await seed.SaveChangesAsync();
            historicalId = historical.Id;
            historicalBefore = JsonSerializer.Serialize(historical);
        }
        var request = MigrationRequest(scenario, PreUuidStableHardwareId, StableHardwareId);
        var digest = Sha256("tkt1501-historical-migration");
        var proof = Proof(scenario.EnrollmentKey, "hardware-authority-migration", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, "-", digest);
        Assert.Equal("migrated", (await scenario.Runtime.MigrateHardwareAuthorityAsync(
            scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback)).Response.Decision);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        var product = await db.Products.SingleAsync(row => row.Id == binding.ProductId);
        // The synthetic entitlement explicitly permits the new release; minimum version alone
        // makes the old execution ineligible, exactly as in the original forced-update fixture.
        (await db.Licenses.SingleAsync(row => row.Id == binding.LicenseId)).AllowedVersions = "*";
        var baselines = await db.ApprovedBinaries.AsNoTracking()
            .Where(row => row.ProductId == binding.ProductId && row.Version == binding.Version).ToListAsync();
        product.MinimumAllowedVersion = "99.0.0";
        enrollment.State = "INVALIDATED";
        enrollment.InvalidationReason = "version_ineligible";
        enrollment.InvalidatedAtUtc = DateTime.UtcNow;
        foreach (var row in baselines)
            db.ApprovedBinaries.Add(new ApprovedBinary
            {
                ProductId = row.ProductId, Version = "100.0.0", Key = row.Key, Hash = row.Hash, Source = row.Source
            });
        await db.SaveChangesAsync();
        Assert.Equal(2, await db.HardwareAuthorityAliases.CountAsync(row => row.IsActive));
        Assert.Equal(RuntimeBindingEligibility.VersionIneligible,
            await RuntimeBindingEligibilityEvaluator.EvaluateAsync(db, binding, DateTimeOffset.UtcNow,
                false, CancellationToken.None, crypto));
        var prepared = await PrepareDistributionFinalizeAsync(scenario, subjectRef, StableHardwareId,
            hardwareAuthorityAliases: CreateAliasResolver(db, crypto));
        Assert.NotNull(prepared.Request.Release);
        prepared.Request.Release.Version = "100.0.0";
        var finalized = await prepared.Service.FinalizeAsync("website-step1",
            Sha256("tkt1501-historical-finalize"), prepared.Request);
        Assert.False(finalized.Idempotent);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(historicalBefore, JsonSerializer.Serialize(await check.HardwareAuthorityAliases.AsNoTracking()
            .SingleAsync(row => row.Id == historicalId)));
        var seat = Assert.Single(await check.LicenseSeats.Where(row => row.LicenseId == binding.LicenseId).ToListAsync());
        Assert.True(seat.IsActive);
        Assert.Equal(StableHardwareId, seat.HardwareId);
        var successor = await check.DistributionInstallationBindings.SingleAsync(row =>
            row.Id == Guid.Parse(finalized.Response.BindingId));
        Assert.Equal("100.0.0", successor.Version);
        Assert.Equal(binding.Id, successor.SupersededBindingId);
    }

    /// <summary>
    /// Exercises the shared evaluator after a real signed migration. Authenticated parentage
    /// must preserve every current commercial/security refusal, including obsolete execution.
    /// </summary>
    [Theory]
    [InlineData("current", "Eligible")]
    [InlineData("obsolete", "VersionIneligible")]
    [InlineData("missing-receipt", "AuthorityIneligible")]
    [InlineData("disabled-alias", "AuthorityIneligible")]
    [InlineData("foreign-source", "AuthorityIneligible")]
    [InlineData("foreign-installation", "AuthorityIneligible")]
    [InlineData("expired-license", "AuthorityIneligible")]
    [InlineData("revoked-license", "AuthorityIneligible")]
    [InlineData("zero-quota", "AuthorityIneligible")]
    [InlineData("hardware-ban", "AuthorityIneligible")]
    [InlineData("binary-mismatch", "AuthorityIneligible")]
    [InlineData("missing-crypto", "AuthorityIneligible")]
    public async Task MigratedBindingEligibility_PreservesCurrentRightsAndVersionRefusal(
        string mutation, string expected)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
        var license = await db.Licenses.Include(row => row.Product).SingleAsync(row => row.Id == binding.LicenseId);
        var product = license.Product ?? throw new InvalidOperationException("Synthetic product was not loaded.");
        var alias = await db.HardwareAuthorityAliases.SingleAsync(row => row.BindingId == binding.Id);
        Assert.NotNull(alias.MigrationReceiptId);
        Assert.NotEqual(binding.HardwareIdHash, Sha256(seat.HardwareId));
        Assert.True(await RuntimeEnrollmentService.HasAcceptedBindingHardwareAsync(
            db, binding, Sha256(seat.HardwareId), crypto, CancellationToken.None));

        switch (mutation)
        {
            case "obsolete": product.MinimumAllowedVersion = "99.0.0"; break;
            case "missing-receipt": alias.MigrationReceiptId = null; break;
            case "disabled-alias":
                alias.IsActive = false;
                alias.DisabledAtUtc = DateTime.UtcNow;
                alias.DisabledReason = "test_disabled";
                break;
            // Detached inputs exercise the exact source scope without bypassing a database constraint.
            case "foreign-source": binding.HardwareIdHash = new string('f', 64); break;
            case "foreign-installation": binding.InstallationId = "foreign-installation"; break;
            case "expired-license": license.ExpirationDate = DateTime.UtcNow.AddDays(-1); break;
            case "revoked-license": license.IsActive = false; break;
            case "zero-quota": license.MaxSeats = 0; break;
            case "hardware-ban": await SetHardwareBanAsync(scenario, seat.HardwareId, active: true); break;
            case "binary-mismatch": binding.ExecutableSha256 = new string('f', 64); break;
        }
        await db.SaveChangesAsync();
        Assert.Equal(expected, (await RuntimeBindingEligibilityEvaluator.EvaluateAsync(
            db, binding, DateTimeOffset.UtcNow, false, CancellationToken.None,
            mutation == "missing-crypto" ? null : crypto)).ToString());
        // Evaluation is read-only: migration never reverts the canonical seat or resurrects identity.
        await db.Entry(seat).ReloadAsync();
        Assert.Equal(StableHardwareId, seat.HardwareId);
        Assert.True(seat.IsActive);
    }
}

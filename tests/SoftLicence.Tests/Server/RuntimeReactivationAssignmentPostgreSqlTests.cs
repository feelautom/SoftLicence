using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Reactivates a genuine released signed alias through HTTP without consuming another daily
    /// activation or seat-change event, changing MaxSeats, touching another seat, or reviving Runtime.
    /// The exhausted case proves the existing live licence-type activation limit still refuses.
    /// </summary>
    /// <param name="maxSeats">Existing key capacity, never reduced by reactivation.</param>
    /// <param name="dailyLimit">Live type quota applied after release, not a product constant.</param>
    /// <param name="quotaExhausted">Whether the original activation already reaches that limit.</param>
    /// <param name="unlinkTimestampMissing">Whether the seat lacks optional legacy release metadata; the exact ENDED row remains authoritative.</param>
    [Theory]
    [InlineData(1, 3, false, false)]
    [InlineData(1, 3, false, true)]
    [InlineData(3, 5, false, false)]
    [InlineData(3, 1, true, false)]
    public async Task HardwareAuthorityAlias_ReleasedAssignmentReactivationPreservesQuotaAndMultiSeats(
        int maxSeats, int dailyLimit, bool quotaExhausted, bool unlinkTimestampMissing)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        Guid licenseId;
        Guid seatId;
        Guid? otherSeatId = null;
        string licenseKey;
        string appName;
        string publicKey;
        DateTime firstActivatedAt;
        await using (var setup = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Product).Include(row => row.Type).SingleAsync();
            var seat = await setup.LicenseSeats.SingleAsync(row => row.IsActive);
            licenseId = license.Id;
            seatId = seat.Id;
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
            publicKey = license.Product.PublicKeyXml;
            firstActivatedAt = seat.FirstActivatedAt;
            license.MaxSeats = maxSeats;
            license.CustomerEmail = "reactivation-fixture@example.com";
            license.AllowedVersions = "2.*";
            license.Type!.MaxActivationsPerDay = 10;
            if (maxSeats > 1)
            {
                var other = new LicenseSeat
                {
                    LicenseId = license.Id, HardwareId = "REACTION-OTHER-SEAT",
                    IsActive = true, FirstActivatedAt = DateTime.UtcNow.AddDays(-2)
                };
                otherSeatId = other.Id;
                setup.LicenseSeats.Add(other);
            }
            await setup.SaveChangesAsync();
        }
        using var web = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var client = web.CreateClient();
        using var deactivation = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey, HardwareId = LegacyHardwareId, AppName = appName, Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, deactivation.StatusCode);
        string runtimeBefore;
        string bindingBefore;
        string? otherBefore = null;
        string endedBefore;
        int activationsBefore;
        int changesBefore;
        await using (var released = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await released.Licenses.Include(row => row.Type).SingleAsync();
            license.Type!.MaxActivationsPerDay = dailyLimit;
            await released.SaveChangesAsync();
            var seat = await released.LicenseSeats.SingleAsync(row => row.Id == seatId);
            Assert.False(seat.IsActive);
            Assert.NotNull(seat.UnlinkedAt);
            if (unlinkTimestampMissing)
            {
                seat.UnlinkedAt = null;
                await released.SaveChangesAsync();
            }
            var assignment = Assert.Single(await released.EnrollmentLicenseAssignments.AsNoTracking().ToListAsync());
            Assert.Equal("ENDED", assignment.State);
            Assert.Equal("seat_released", assignment.EndReason);
            Assert.Equal(scenario.EnrollmentId, assignment.EnrollmentId);
            endedBefore = JsonSerializer.Serialize(assignment);
            runtimeBefore = JsonSerializer.Serialize(await released.RuntimeEnrollments.AsNoTracking().SingleAsync());
            bindingBefore = JsonSerializer.Serialize(await released.DistributionInstallationBindings.AsNoTracking().SingleAsync());
            if (otherSeatId.HasValue)
                otherBefore = JsonSerializer.Serialize(await released.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == otherSeatId));
            activationsBefore = await released.LicenseSeats.CountAsync(row => row.LicenseId == licenseId && row.FirstActivatedAt >= DateTime.UtcNow.Date);
            changesBefore = (await SeatChangeQuota.GetStatusAsync(released, license, DateTime.UtcNow)).UsedToday;
            Assert.Equal(1, activationsBefore);
        }
        // Resolving an inactive identity for status must not return a signed right or restore authority.
        using (var inactiveStatus = await PostCheckAsync(client, licenseKey, appName, LegacyHardwareId))
        using (var inactiveBody = JsonDocument.Parse(await inactiveStatus.Content.ReadAsStringAsync()))
        {
            Assert.Equal("HARDWARE_NOT_ACTIVATED", inactiveBody.RootElement.GetProperty("status").GetString());
            Assert.False(inactiveBody.RootElement.TryGetProperty("licenseFile", out var inactiveFile)
                && inactiveFile.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(inactiveFile.GetString()));
        }
        await using (var stillReleased = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.False((await stillReleased.LicenseSeats.SingleAsync(row => row.Id == seatId)).IsActive);
            Assert.Equal(runtimeBefore, JsonSerializer.Serialize(await stillReleased.RuntimeEnrollments.AsNoTracking().SingleAsync()));
            Assert.Equal(bindingBefore, JsonSerializer.Serialize(await stillReleased.DistributionInstallationBindings.AsNoTracking().SingleAsync()));
            Assert.Equal(endedBefore, JsonSerializer.Serialize(await stillReleased.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync()));
        }
        using var response = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        if (quotaExhausted)
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("MAX_DAILY_ACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        }
        else
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(body.RootElement.TryGetProperty("isSuccess", out var success) && !success.GetBoolean());
            var signed = body.RootElement.GetProperty("licenseFile").GetString();
            Assert.NotNull(signed);
            Assert.True(LicenseService.ValidateLicense(signed!, publicKey, LegacyHardwareId).IsValid);
            using var status = await PostCheckAsync(client, licenseKey, appName, StableHardwareId);
            using var statusBody = JsonDocument.Parse(await status.Content.ReadAsStringAsync());
            Assert.Equal("VALID", statusBody.RootElement.GetProperty("status").GetString());
        }
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(runtimeBefore, JsonSerializer.Serialize(await check.RuntimeEnrollments.AsNoTracking().SingleAsync()));
        Assert.Equal(bindingBefore, JsonSerializer.Serialize(await check.DistributionInstallationBindings.AsNoTracking().SingleAsync()));
        var original = await check.LicenseSeats.SingleAsync(row => row.Id == seatId);
        Assert.Equal(!quotaExhausted, original.IsActive);
        Assert.Equal(firstActivatedAt, original.FirstActivatedAt);
        Assert.Equal(StableHardwareId, original.HardwareId);
        Assert.Equal(maxSeats > 1 ? 2 : 1, await check.LicenseSeats.CountAsync());
        Assert.Equal((maxSeats > 1 ? 1 : 0) + (quotaExhausted ? 0 : 1), await check.LicenseSeats.CountAsync(row => row.IsActive));
        if (otherSeatId.HasValue)
            Assert.Equal(otherBefore, JsonSerializer.Serialize(await check.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == otherSeatId)));
        var finalLicense = await check.Licenses.Include(row => row.Type).SingleAsync();
        Assert.Equal(maxSeats, finalLicense.MaxSeats);
        Assert.Equal(dailyLimit, finalLicense.Type!.MaxActivationsPerDay);
        Assert.Equal(activationsBefore, await check.LicenseSeats.CountAsync(row => row.LicenseId == licenseId && row.FirstActivatedAt >= DateTime.UtcNow.Date));
        Assert.Equal(changesBefore, (await SeatChangeQuota.GetStatusAsync(check, finalLicense, DateTime.UtcNow)).UsedToday);
        var ended = await check.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync(row => row.State == "ENDED");
        Assert.Equal(endedBefore, JsonSerializer.Serialize(ended));
        Assert.Equal(quotaExhausted ? 0 : 1, await check.EnrollmentLicenseAssignments.CountAsync(row => row.State == "ACTIVE"));
    }

    /// <summary>
    /// Rejects incomplete or foreign ended-assignment evidence and security/commercial refusals.
    /// Each case starts with a genuine signed migration and HTTP release; no constraint or trigger
    /// is disabled, and the rejected activation must leave Runtime, bindings, aliases and rights intact.
    /// </summary>
    /// <param name="mutation">One bounded adversarial mutation in the task-owned synthetic database.</param>
    [Theory]
    [InlineData("missing-assignment")]
    [InlineData("wrong-end-reason")]
    [InlineData("later-ended-revision")]
    [InlineData("foreign-assignment")]
    [InlineData("assignment-future")]
    [InlineData("quarantine")]
    [InlineData("alias-disabled")]
    [InlineData("alias-generation")]
    [InlineData("seat-unlink-future")]
    [InlineData("license-revoked")]
    [InlineData("license-expired")]
    [InlineData("canonical-ban")]
    [InlineData("legacy-ban")]
    public async Task HardwareAuthorityAlias_ReleasedAssignmentReactivationFailsClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        string licenseKey;
        string appName;
        Guid licenseId;
        Guid seatId;
        await using (var setup = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Product).Include(row => row.Type).SingleAsync();
            licenseId = license.Id;
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
            seatId = (await setup.LicenseSeats.SingleAsync(row => row.IsActive)).Id;
            license.CustomerEmail = "reactivation-negative@example.com";
            license.AllowedVersions = "2.*";
            license.Type!.MaxActivationsPerDay = 10;
            await setup.SaveChangesAsync();
        }
        using var web = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var client = web.CreateClient();
        using var release = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey, HardwareId = LegacyHardwareId, AppName = appName, Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, release.StatusCode);
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var assignment = await mutate.EnrollmentLicenseAssignments.SingleAsync();
            Assert.Equal("ENDED", assignment.State);
            Assert.Equal("seat_released", assignment.EndReason);
            var seat = await mutate.LicenseSeats.SingleAsync(row => row.Id == seatId);
            Assert.False(seat.IsActive);
            var alias = await mutate.HardwareAuthorityAliases.SingleAsync();
            var license = await mutate.Licenses.SingleAsync();
            switch (mutation)
            {
                case "missing-assignment": mutate.EnrollmentLicenseAssignments.Remove(assignment); break;
                case "wrong-end-reason": assignment.EndReason = "license_revoked"; break;
                case "later-ended-revision":
                    mutate.EnrollmentLicenseAssignments.Add(new EnrollmentLicenseAssignment
                    {
                        EnrollmentId = assignment.EnrollmentId, LicenseId = assignment.LicenseId,
                        LicenseSeatId = assignment.LicenseSeatId, Revision = assignment.Revision + 1,
                        State = "ENDED", EndReason = "commercial_transfer",
                        ActivatedAtUtc = assignment.ActivatedAtUtc, EndedAtUtc = assignment.EndedAtUtc
                    });
                    break;
                case "foreign-assignment":
                    var foreign = await SeedAuthorityAsync(scenario.Factory, "2.2.944");
                    var foreignBinding = await mutate.DistributionInstallationBindings.AsNoTracking()
                        .SingleAsync(row => row.Id == foreign.BindingId);
                    assignment.LicenseId = foreignBinding.LicenseId;
                    assignment.LicenseSeatId = foreignBinding.LicenseSeatId;
                    break;
                case "assignment-future": assignment.EndedAtUtc = DateTime.UtcNow.AddDays(1); break;
                case "quarantine":
                    mutate.EnrollmentLicenseAssignmentQuarantines.Add(new EnrollmentLicenseAssignmentQuarantine
                    {
                        EnrollmentId = scenario.EnrollmentId, BindingId = scenario.Fixture.BindingId,
                        LicenseId = licenseId, LicenseSeatId = seatId,
                        Reason = "binding_mismatch", ObservedAtUtc = DateTime.UtcNow
                    });
                    break;
                case "alias-disabled":
                    alias.IsActive = false; alias.DisabledAtUtc = DateTime.UtcNow;
                    alias.DisabledReason = HardwareAuthorityAlias.OperatorDisabledReason; break;
                case "alias-generation": alias.SecurityEpoch = int.MaxValue; break;
                case "seat-unlink-future": seat.UnlinkedAt = DateTime.UtcNow.AddDays(1); break;
                case "license-revoked": license.RevokedAt = DateTime.UtcNow; break;
                case "license-expired": license.ExpirationDate = DateTime.UtcNow.AddDays(-1); break;
                case "canonical-ban":
                case "legacy-ban":
                    mutate.BannedHardwareIds.Add(new BannedHardwareId
                    {
                        ProductId = scenario.Fixture.ProductId,
                        HardwareId = mutation == "canonical-ban" ? StableHardwareId : LegacyHardwareId,
                        BanCategory = BannedHardwareId.Categories.Piracy, IsActive = true,
                        Reason = "reactivation-negative-fixture"
                    });
                    break;
                default: throw new InvalidOperationException("Unknown reactivation evidence mutation.");
            }
            await mutate.SaveChangesAsync();
        }
        string runtimeBefore;
        string bindingBefore;
        string assignmentsBefore;
        string aliasesBefore;
        await using (var before = await scenario.Factory.CreateDbContextAsync())
        {
            runtimeBefore = JsonSerializer.Serialize(await before.RuntimeEnrollments.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
            bindingBefore = JsonSerializer.Serialize(await before.DistributionInstallationBindings.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
            assignmentsBefore = JsonSerializer.Serialize(await before.EnrollmentLicenseAssignments.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
            aliasesBefore = JsonSerializer.Serialize(await before.HardwareAuthorityAliases.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
        }
        using var response = await PostActivationAsync(client, licenseKey, appName, LegacyHardwareId);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(body.RootElement.GetProperty("isSuccess").GetBoolean());
        Assert.Equal(mutation is "canonical-ban" or "legacy-ban" ? "BANNED" : "HARDWARE_AUTHORITY_REFUSED",
            body.RootElement.GetProperty("errorCode").GetString());
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.False((await check.LicenseSeats.SingleAsync(row => row.Id == seatId)).IsActive);
        Assert.Equal(runtimeBefore, JsonSerializer.Serialize(await check.RuntimeEnrollments.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
        Assert.Equal(bindingBefore, JsonSerializer.Serialize(await check.DistributionInstallationBindings.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
        Assert.Equal(assignmentsBefore, JsonSerializer.Serialize(await check.EnrollmentLicenseAssignments.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
        Assert.Equal(aliasesBefore, JsonSerializer.Serialize(await check.HardwareAuthorityAliases.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
    }
}

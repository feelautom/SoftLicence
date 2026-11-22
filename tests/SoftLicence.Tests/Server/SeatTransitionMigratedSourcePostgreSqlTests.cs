using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{
}

/// <summary>Runs the tests from SeatTransitionMigratedSourcePostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class SeatTransitionMigratedSourcePostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// TKT-001719: a seat whose identity was moved by a signed migration is unlinked from the portal,
    /// then the same account installs on a different machine. The released binding stays active and
    /// keeps its immutable pre-migration digest, so the seat transition must accept the binding's own
    /// authenticated migration receipt, and must keep refusing when that receipt cannot be authenticated.
    /// </summary>
    /// <param name = "receiptAuthenticatorAvailable">False models a service without the server receipt authenticator.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1719_SeatTransitionAfterPortalUnlink_MigratedSourceSeat_RequiresAuthenticatedReceipt")]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Tkt1719_SeatTransitionAfterPortalUnlink_MigratedSourceSeat_RequiresAuthenticatedReceipt(bool receiptAuthenticatorAvailable)
    {
        const string otherMachineHardwareId = "C3D4E5F6A7B80912";
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var migrationCrypto = new RuntimeEnrollmentCryptoService(Options.Create(scenario.Options));
        var subject = Base64Url(SHA256.HashData("tkt1719-migrated-seat-transition"u8.ToArray()));
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await SetScenarioSubjectAuthorityAsync(scenario, subject);
        await MigrateScenarioAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var source = await db.DistributionInstallationBindings.SingleAsync(row => row.Id == scenario.Fixture.BindingId);
        var portal = new PortalDeactivationService(scenario.Factory, TimeProvider.System, NullLogger<PortalDeactivationService>.Instance);
        var unlink = await portal.DeactivateAsync("website-step1", Sha256("tkt1719-portal-unlink"), new PortalDeactivationRequest(PortalDeactivationService.RequestSchema, Guid.NewGuid().ToString("D"), source.ProductId.ToString("D"), source.LicenseId.ToString("D"), StableHardwareId, "settings_button"));
        Assert.Equal("deactivated", unlink.Response.Outcome);
        // Exact production graph: the portal release leaves the Runtime rows untouched, the binding
        // keeps the legacy digest and the released seat carries the migrated identity.
        await db.Entry(source).ReloadAsync();
        Assert.Equal("active", source.State);
        Assert.Equal(Sha256(LegacyHardwareId), source.HardwareIdHash);
        var sourceSeat = await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == source.LicenseSeatId);
        Assert.Equal(StableHardwareId, sourceSeat.HardwareId);
        Assert.False(sourceSeat.IsActive);
        Assert.NotNull(sourceSeat.UnlinkedAt);
        var prepared = await PrepareDistributionFinalizeAsync(scenario, subject, otherMachineHardwareId, migrationCrypto: receiptAuthenticatorAvailable ? migrationCrypto : null);
        var digest = Sha256("tkt1719-finalize-" + Guid.NewGuid().ToString("D"));
        if (!receiptAuthenticatorAvailable)
        {
            var refused = await Assert.ThrowsAsync<DistributionOperationException>(() => prepared.Service.FinalizeAsync("website-step1", digest, prepared.Request));
            Assert.Equal("binding_conflict", refused.ErrorCode);
            Assert.Equal("same_authority_mismatch", refused.ReasonCode);
            await using var unchanged = await scenario.Factory.CreateDbContextAsync();
            Assert.Equal("active", (await unchanged.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == source.Id)).State);
            Assert.Empty(await unchanged.LicenseSeats.AsNoTracking().Where(row => row.LicenseId == source.LicenseId && row.IsActive).ToListAsync());
            return;
        }

        var result = await prepared.Service.FinalizeAsync("website-step1", digest, prepared.Request);
        Assert.False(result.Idempotent);
        Assert.Equal(Sha256(otherMachineHardwareId), result.Response.HardwareIdHash);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var activeSeat = Assert.Single(await check.LicenseSeats.AsNoTracking().Where(row => row.LicenseId == source.LicenseId && row.IsActive).ToListAsync());
        Assert.Equal(otherMachineHardwareId, activeSeat.HardwareId);
        Assert.NotEqual(source.LicenseSeatId, activeSeat.Id);
        var successor = Assert.Single(await check.DistributionInstallationBindings.AsNoTracking().Where(row => row.LicenseId == source.LicenseId && row.State == "active").ToListAsync());
        Assert.Equal(source.Id, successor.SupersededBindingId);
        Assert.Equal(activeSeat.Id, successor.LicenseSeatId);
        Assert.Equal(Sha256(otherMachineHardwareId), successor.HardwareIdHash);
        var released = await check.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == source.LicenseSeatId);
        Assert.False(released.IsActive);
        Assert.Equal(StableHardwareId, released.HardwareId);
        // Production follow-up of the same incident: the Desktop then prepares and confirms the
        // successor enrollment. The released seat's alias names the old machine, so Confirm must not
        // try to advance it onto a successor that lives on another seat and another machine.
        var releasedAlias = await check.HardwareAuthorityAliases.AsNoTracking().SingleAsync();
        Assert.Equal(source.Id, releasedAlias.BindingId);
        using var successorKey = RSA.Create(3072);
        var prepareRequest = PrepareRequest((successor.ProductId, successor.Id, successor.HandoffDigestSha256, successor.InstallationId, successor.Version), Guid.NewGuid().ToString("D"), successorKey);
        prepareRequest.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var successorPrepared = await scenario.Runtime.PrepareAsync("website-step1", Sha256("tkt1719-prepare-" + Guid.NewGuid().ToString("D")), prepareRequest);
        var successorEnrollmentId = Guid.Parse(successorPrepared.Response.EnrollmentId);
        var confirmRequest = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = successorEnrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("tkt1719-confirm-" + Guid.NewGuid().ToString("D"));
        var confirmed = await scenario.Runtime.ConfirmAsync(successorEnrollmentId, confirmDigest, confirmRequest, Proof(successorKey, "confirm", successorEnrollmentId, scenario.Options.ConfirmAudience, successorPrepared.Response.Challenge, confirmDigest), System.Net.IPAddress.Loopback);
        Assert.False(confirmed.Idempotent);
        await using var afterConfirm = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("ACTIVE", (await afterConfirm.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == successorEnrollmentId)).State);
        // The alias keeps describing the released machine on the superseded binding, untouched.
        var aliasAfterConfirm = await afterConfirm.HardwareAuthorityAliases.AsNoTracking().SingleAsync();
        Assert.Equal(releasedAlias.Id, aliasAfterConfirm.Id);
        Assert.Equal(source.Id, aliasAfterConfirm.BindingId);
        Assert.Equal(releasedAlias.RuntimeEnrollmentId, aliasAfterConfirm.RuntimeEnrollmentId);
        Assert.Equal(source.LicenseSeatId, aliasAfterConfirm.LicenseSeatId);
        Assert.True(aliasAfterConfirm.IsActive);
    }
}

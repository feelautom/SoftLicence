using System.Reflection;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class DistributionInstallationBindingServiceTests
{
    /// <summary>
    /// Executes the production relational selector against a three-link alternating-hardware
    /// history. Successors outside the candidate hardware/seat subset must still retire ancestors.
    /// No recovery authority is granted by the final released row in this cross-seat selector.
    /// </summary>
    [Fact]
    public async Task SameLicenseTopology_ThreeReplacedAncestorsOnOtherHardware_ReturnsNoSource()
    {
        await using var db = new LicenseDbContext(_options);
        DistributionInstallationBinding? previous = null;
        for (var i = 0; i < 3; i++)
        {
            var ancestor = AddTopologyBinding(db, "old-" + i, previous?.Id);
            previous = AddTopologyBinding(db, HardwareId, ancestor.Id);
        }
        previous!.InvalidationReason = "seat_released";
        await db.SaveChangesAsync();

        Assert.Null(await ResolveTopologySourceAsync(db));
        Assert.Equal(6, await db.DistributionInstallationBindings.CountAsync());
        Assert.All(await db.DistributionInstallationBindings.ToListAsync(), b => Assert.Equal("invalidated", b.State));
    }

    /// <summary>Unrelated terminal branches remain ambiguous; topology preservation must not pick the newest.</summary>
    [Fact]
    public async Task SameLicenseTopology_TwoRealLeaves_StillRejectsAmbiguity()
    {
        await using var db = new LicenseDbContext(_options);
        AddTopologyBinding(db, "old-a");
        AddTopologyBinding(db, "old-b");
        await db.SaveChangesAsync();
        var error = await Assert.ThrowsAsync<DistributionOperationException>(() => ResolveTopologySourceAsync(db));
        Assert.Equal("same_license_seat_transition_ambiguous", error.ReasonCode);
    }

    /// <summary>A unique eligible terminal remains selectable; security and released rows grant no generic authority.</summary>
    [Theory]
    [InlineData("installation_superseded", true)]
    [InlineData("security_lockdown", false)]
    [InlineData("seat_released", false)]
    public async Task SameLicenseTopology_UniqueLeaf_PreservesReasonPolicy(string reason, bool expected)
    {
        await using var db = new LicenseDbContext(_options);
        var source = AddTopologyBinding(db, "old-hardware");
        source.InvalidationReason = reason;
        await db.SaveChangesAsync();
        Assert.Equal(expected ? source.Id : (Guid?)null, (await ResolveTopologySourceAsync(db))?.Id);
    }

    /// <summary>
    /// Creates synthetic terminal history with distinct relational identities and preserved predecessor links.
    /// Each source seat is explicitly unlinked; test data contains no customer identifiers or credentials.
    /// </summary>
    private static DistributionInstallationBinding AddTopologyBinding(
        LicenseDbContext db, string hardwareId, Guid? predecessor = null)
    {
        var seat = new LicenseSeat
        {
            Id = Guid.NewGuid(), LicenseId = LicenseId, HardwareId = hardwareId,
            IsActive = false, UnlinkedAt = Now.AddMinutes(-1).UtcDateTime
        };
        var binding = new DistributionInstallationBinding
        {
            Id = Guid.NewGuid(), ProductId = ProductId, LicenseId = LicenseId,
            LicenseSeatId = seat.Id, SubjectRefDigestSha256 = Hash("topology-subject"),
            HardwareIdHash = Hash(hardwareId), State = "invalidated",
            InvalidationReason = "installation_superseded", SupersededBindingId = predecessor,
            BoundAtUtc = Now.AddDays(-1).UtcDateTime, InvalidatedAtUtc = Now.AddMinutes(-1).UtcDateTime,
            HandoffDigestSha256 = Hash(NewUuid()), GrantRefDigestSha256 = Hash(NewUuid()),
            InstallationId = NewUuid()
        };
        db.AddRange(seat, binding);
        return binding;
    }

    /// <summary>
    /// Invokes the real private EF query without exposing a new production API solely for testing.
    /// Async domain refusals propagate from the returned task; no selection logic is reproduced here.
    /// </summary>
    private static Task<DistributionInstallationBinding?> ResolveTopologySourceAsync(LicenseDbContext db)
    {
        var method = typeof(DistributionInstallationBindingService).GetMethod(
            "ResolveSameLicenseSeatTransitionSourceAsync", BindingFlags.Static | BindingFlags.NonPublic)!;
        return (Task<DistributionInstallationBinding?>)method.Invoke(null,
            [db, ProductId, LicenseId, SeatId, Hash("topology-subject"), Hash(HardwareId), CancellationToken.None])!;
    }
}

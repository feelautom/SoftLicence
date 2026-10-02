using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Reproduces the SUP-000027 production graph (TKT-001221): a renewed licence whose history is
    /// closed and released, v4 candidates coming only from the revoked predecessor licence, and a
    /// brand-new machine. Under Franck's policy (2026-09-21) every history divergence, including a
    /// historical security terminal, is logged under <c>TEMP-FAIL-OPEN(TKT-001221)</c> and still
    /// creates one initial binding. An orphan superseded node is claimed first by the same-license
    /// transition; its same-authority refusal is now logged the same way and falls back to the
    /// initial binding.
    /// </summary>
    /// A fork is not exercised: the unique index on <c>SupersededBindingId</c> makes it unrepresentable.
    /// <param name="mutation">The single history defect applied before Finalize, or <c>none</c>.</param>
    [Theory]
    [InlineData("none")]
    [InlineData("orphan_superseded")]
    [InlineData("successor_other_license")]
    [InlineData("successor_other_subject")]
    [InlineData("successor_bound_before_end")]
    [InlineData("live_enrollment")]
    [InlineData("security_enrollment")]
    [InlineData("release_seat_not_unlinked")]
    [InlineData("incoherent_release")]
    [InlineData("active_binding_inactive_seat")]
    [InlineData("unknown_reason")]
    [InlineData("divergent_entitlement_subject")]
    public async Task DistributionFinalize_V4CandidatesOnReleasedTargetHistory_OnlyClosedGraphCreatesInitialBinding(
        string mutation)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory, includeSeat: false);
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);

        var now = new DateTimeOffset(2026, 9, 21, 6, 17, 42, TimeSpan.Zero);
        var logger = new RecordingLogger<DistributionInstallationBindingService>();
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance, logger);
        // The shared test database outlives one run: every digest is made unique per execution.
        var run = mutation + "-" + Guid.NewGuid().ToString("N");
        var subjectRef = Base64UrlSubject("released-target-history-" + run);
        var subjectDigest = Sha256(subjectRef);
        var historicalLicenseId = Guid.NewGuid();
        var historicalRootId = Guid.NewGuid();
        var interiorId = Guid.NewGuid();
        var leafAId = Guid.NewGuid();
        var leafBId = Guid.NewGuid();
        var seatAId = Guid.NewGuid();
        var seatBId = Guid.NewGuid();
        var t0 = now.AddDays(-20).UtcDateTime;

        await using (var seed = await factory.CreateDbContextAsync())
        {
            var licenseTypeId = await seed.Licenses.AsNoTracking()
                .Where(candidate => candidate.Id == fixture.LicenseId)
                .Select(candidate => candidate.LicenseTypeId)
                .SingleAsync();
            seed.Licenses.Add(new License
            {
                Id = historicalLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = licenseTypeId,
                LicenseKey = "HIST-" + Guid.NewGuid().ToString("N"),
                IsActive = false,
                RevokedAt = now.AddDays(-25).UtcDateTime,
                MaxSeats = 1,
                ExpirationDate = now.AddDays(-25).UtcDateTime
            });
            var historicalSeatId = Guid.NewGuid();
            seed.LicenseSeats.Add(new LicenseSeat
            {
                Id = historicalSeatId,
                LicenseId = historicalLicenseId,
                HardwareId = "RELHISTHWIDA0001",
                IsActive = false,
                UnlinkedAt = t0
            });
            seed.LicenseSeats.Add(new LicenseSeat
            {
                Id = seatAId,
                LicenseId = fixture.LicenseId,
                HardwareId = "RELHISTHWIDA0001",
                IsActive = false,
                FirstActivatedAt = t0,
                UnlinkedAt = mutation == "release_seat_not_unlinked" ? null : now.AddDays(-10).UtcDateTime
            });
            // An active binding kept on a seat that was deactivated but never explicitly unlinked
            // is the e7019ca shape: it stays outside the same-license transition and must refuse here.
            seed.LicenseSeats.Add(new LicenseSeat
            {
                Id = seatBId,
                LicenseId = fixture.LicenseId,
                HardwareId = "RELHISTHWIDB0002",
                IsActive = false,
                FirstActivatedAt = t0,
                UnlinkedAt = mutation == "active_binding_inactive_seat" ? null : now.AddDays(-11).UtcDateTime
            });

            // Revoked predecessor licence root, superseded across licences into the renewed target.
            seed.DistributionInstallationBindings.Add(HistoryBinding(
                historicalRootId, fixture.ProductId, fixture.Version, historicalLicenseId, historicalSeatId,
                subjectDigest, "RELHISTHWIDA0001", t0, t0.AddDays(1), "installation_superseded", supersedes: null));
            var interior = HistoryBinding(
                interiorId, fixture.ProductId, fixture.Version, fixture.LicenseId, seatAId,
                mutation == "successor_other_subject" ? Sha256("other-subject") : subjectDigest,
                "RELHISTHWIDA0001", t0.AddDays(1), t0.AddDays(2),
                mutation == "unknown_reason" ? "operator_mystery_reason" : "installation_superseded",
                supersedes: historicalRootId);
            seed.DistributionInstallationBindings.Add(interior);
            seed.RuntimeEnrollments.Add(HistoryEnrollment(
                interior, runtimeOptions.Encryption.ActiveKeyId, t0.AddDays(1), t0.AddDays(1).AddHours(1),
                "INVALIDATED", "authority_ineligible"));

            // Leaf A: coherent release terminalized by the release itself. Its bound instant equals
            // the predecessor's terminal instant exactly, as observed in production.
            var leafAEnd = now.AddDays(-10).UtcDateTime;
            if (mutation != "orphan_superseded")
            {
                var leafABound = mutation == "successor_bound_before_end"
                    ? t0.AddDays(2).AddSeconds(-1) : t0.AddDays(2);
                var otherLicense = mutation == "successor_other_license";
                var leafA = HistoryBinding(
                    leafAId, fixture.ProductId, fixture.Version,
                    otherLicense ? historicalLicenseId : fixture.LicenseId,
                    otherLicense ? historicalSeatId : seatAId,
                    subjectDigest, "RELHISTHWIDA0001", leafABound, leafAEnd,
                    SeatRuntimeReleaseAuthority.Reason, supersedes: interiorId);
                seed.DistributionInstallationBindings.Add(leafA);
                seed.RuntimeEnrollments.Add(HistoryEnrollment(
                    leafA, runtimeOptions.Encryption.ActiveKeyId, leafABound,
                    mutation == "incoherent_release" ? leafAEnd.AddSeconds(-30) : leafAEnd,
                    mutation == "live_enrollment" ? "ACTIVE" : "INVALIDATED",
                    mutation == "security_enrollment" ? "security_revoked" : SeatRuntimeReleaseAuthority.Reason));
            }
            // Leaf B: a second released root of the same licence on another machine.
            var leafBEnd = now.AddDays(-11).UtcDateTime;
            var activeLeafB = mutation == "active_binding_inactive_seat";
            var leafB = HistoryBinding(
                leafBId, fixture.ProductId, fixture.Version, fixture.LicenseId, seatBId, subjectDigest,
                "RELHISTHWIDB0002", t0.AddDays(5), activeLeafB ? null : leafBEnd,
                activeLeafB ? null : SeatRuntimeReleaseAuthority.Reason, supersedes: null);
            if (activeLeafB) leafB.State = "active";
            seed.DistributionInstallationBindings.Add(leafB);
            seed.RuntimeEnrollments.Add(HistoryEnrollment(
                leafB, runtimeOptions.Encryption.ActiveKeyId, t0.AddDays(5), leafBEnd,
                activeLeafB ? "ACTIVE" : "INVALIDATED", SeatRuntimeReleaseAuthority.Reason));
            await seed.SaveChangesAsync();
        }

        var grantRef = Guid.NewGuid().ToString("D");
        // A divergent entitlement subject still names a legitimate Website owner of this licence.
        var entitlementSubjectRef = mutation == "divergent_entitlement_subject"
            ? Base64UrlSubject("other-owner-" + run) : subjectRef;
        var entitlement = await service.IssueEntitlementAsync(
            "website-step1",
            Sha256("released-target-history-issue-" + run),
            new DistributionEntitlementIssueRequest
            {
                Schema = DistributionInstallationBindingService.IssueV3Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grantRef),
                SubjectRef = entitlementSubjectRef
            });
        const string freshHardwareId = "0BDE9EAEEB20E778";
        var request = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeV4Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantRef,
            HandoffDigestSha256 = Sha256("released-target-history-handoff-" + run),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-5)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-4)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = entitlement.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = freshHardwareId,
            AllowSameAuthorityRecovery = true,
            LicenseReplacementCandidates = new DistributionLicenseReplacementCandidateSet
            {
                Schema = DistributionInstallationBindingService.LicenseReplacementCandidatesSchema,
                Sources =
                [
                    new DistributionLicenseReplacementProof
                    {
                        Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
                        SourceBindingId = historicalRootId.ToString("D"),
                        SourceLicenseId = historicalLicenseId.ToString("D"),
                        SourceSubjectRef = subjectRef
                    }
                ]
            },
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "TiaConnect-Setup_v2.4.402.exe",
                InstallerSha256 = Sha256("released-target-history-installer")
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        var result = await service.FinalizeAsync(
            "website-step1", Sha256("released-target-history-finalize-" + run), request);

        Assert.False(result.Idempotent);
        Assert.Equal("active", result.Response.State);
        await using var after = await factory.CreateDbContextAsync();
        var created = await after.DistributionInstallationBindings.SingleAsync(candidate =>
            candidate.ProductId == fixture.ProductId && candidate.HardwareIdHash == Sha256(freshHardwareId));
        Assert.Equal(fixture.LicenseId, created.LicenseId);
        Assert.Null(created.SupersededBindingId);
        Assert.Equal(1, await after.LicenseSeats.CountAsync(candidate =>
            candidate.LicenseId == fixture.LicenseId && candidate.IsActive));
        if (mutation == "none")
        {
            var leaves = await after.DistributionInstallationBindings.AsNoTracking()
                .Where(candidate => candidate.Id == leafAId || candidate.Id == leafBId)
                .ToListAsync();
            Assert.All(leaves, leaf => Assert.Equal(SeatRuntimeReleaseAuthority.Reason, leaf.InvalidationReason));
        }
        Assert.False(await after.DistributionInstallationBindings.AnyAsync(candidate =>
            candidate.SupersededBindingId == leafAId || candidate.SupersededBindingId == leafBId));

        // TEMP-FAIL-OPEN(TKT-001221): every tolerated divergence must be observable in the logs with
        // internal graph facts and never a hardware identifier; a released history logs nothing.
        var failOpenLogs = logger.Messages.Where(message =>
            message.Contains("TEMP-FAIL-OPEN(TKT-001221)", StringComparison.Ordinal)).ToList();
        // A divergent entitlement subject leaves the persisted history released: nothing is tolerated.
        if (mutation is "none" or "divergent_entitlement_subject")
        {
            Assert.Empty(failOpenLogs);
            return;
        }
        // An orphan is logged twice: the same-license fallback, then the unreleased history node.
        Assert.Equal(mutation == "orphan_superseded" ? 2 : 1, failOpenLogs.Count);
        Assert.All(failOpenLogs, failOpen =>
        {
            Assert.Contains(request.RequestId, failOpen, StringComparison.Ordinal);
            Assert.Contains(fixture.LicenseId.ToString(), failOpen, StringComparison.Ordinal);
            Assert.DoesNotContain(freshHardwareId, failOpen, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("RELHISTHWID", failOpen, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Sha256(freshHardwareId), failOpen, StringComparison.OrdinalIgnoreCase);
        });
        Assert.Contains(failOpenLogs, failOpen => failOpen.Contains("history divergence", StringComparison.Ordinal)
            && failOpen.Contains("enrollments 1,", StringComparison.Ordinal));
        if (mutation == "orphan_superseded")
        {
            Assert.Contains(failOpenLogs, failOpen =>
                failOpen.Contains("same_authority_mismatch", StringComparison.Ordinal)
                && failOpen.Contains(interiorId.ToString(), StringComparison.Ordinal));
        }
    }

    /// <summary>Builds a URL-safe base64 subject reference from a stable test label.</summary>
    private static string Base64UrlSubject(string label) =>
        Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(label)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Creates one persisted historical binding with production-shaped release evidence.</summary>
    private static DistributionInstallationBinding HistoryBinding(
        Guid id,
        Guid productId,
        string version,
        Guid licenseId,
        Guid seatId,
        string subjectDigest,
        string hardwareId,
        DateTime boundAt,
        DateTime? invalidatedAt,
        string? reason,
        Guid? supersedes)
    {
        var grantRef = Guid.NewGuid().ToString("D");
        return new DistributionInstallationBinding
        {
            Id = id,
            ProductId = productId,
            LicenseId = licenseId,
            LicenseSeatId = seatId,
            EntitlementId = Guid.NewGuid(),
            SubjectRefDigestSha256 = subjectDigest,
            GrantRef = grantRef,
            GrantRefDigestSha256 = Sha256(grantRef),
            HandoffDigestSha256 = Sha256("history-handoff-" + id.ToString("N")),
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareIdHash = Sha256(hardwareId),
            Version = version,
            InstallerFilename = "TiaConnect-Setup_v2.3.876.exe",
            InstallerSha256 = Sha256("history-installer"),
            ExecutableSha256 = new string('a', 64),
            NativeDllSha256 = new string('b', 64),
            CoreSha256 = new string('c', 64),
            ApprovedBinariesSource = "release",
            State = "invalidated",
            BoundAtUtc = boundAt,
            InitialSecurityEpoch = 1,
            InvalidatedAtUtc = invalidatedAt,
            InvalidationReason = reason,
            SupersededBindingId = supersedes
        };
    }

    /// <summary>Creates the single Runtime enrollment persisted for one historical binding.</summary>
    private static RuntimeEnrollment HistoryEnrollment(
        DistributionInstallationBinding binding,
        string activeKeyId,
        DateTime createdAt,
        DateTime invalidatedAt,
        string state,
        string reason) => new()
        {
            Id = Guid.NewGuid(),
            ClientId = "website-step1",
            BindingId = binding.Id,
            ProductId = binding.ProductId,
            LicenseId = binding.LicenseId,
            LicenseSeatId = binding.LicenseSeatId,
            InstallationId = binding.InstallationId,
            HardwareIdHash = binding.HardwareIdHash,
            ReleaseVersion = binding.Version,
            HandoffDigestSha256 = binding.HandoffDigestSha256,
            SubjectRefDigestSha256 = binding.SubjectRefDigestSha256,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            Algorithm = "PS256",
            KeyBackend = "software-cng-unattested",
            AttestationLevel = "none",
            PublicKeySpkiCiphertext = "test",
            PublicKeySpkiKeyId = activeKeyId,
            PublicKeySpkiSha256 = new string('d', 64),
            KeyThumbprint = "sl-" + Guid.NewGuid().ToString("N"),
            ChallengeCiphertext = "test",
            ChallengeKeyId = activeKeyId,
            ChallengeDigestSha256 = new string('e', 64),
            State = state,
            Epoch = 1,
            SecurityEpoch = 1,
            AuthorityEpoch = 1,
            ChallengeExpiresAtUtc = createdAt.AddHours(1),
            CreatedAtUtc = createdAt,
            ActivatedAtUtc = createdAt.AddSeconds(3),
            ChallengeConsumedAtUtc = createdAt.AddSeconds(3),
            InvalidatedAtUtc = state == "ACTIVE" ? null : invalidatedAt,
            InvalidationReason = state == "ACTIVE" ? null : reason
        };
}

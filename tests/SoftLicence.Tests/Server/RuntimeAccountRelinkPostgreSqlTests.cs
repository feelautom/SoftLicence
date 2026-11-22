using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002919 anti-regression suite on a real PostgreSQL 17 database. An installation whose seat was released is
/// relinked for the account signed in inside the application, through the dedicated relink identity, under every
/// existing seat rule; every refusal writes nothing and consumes no installation proof. TKT-003350 adds the optional
/// owner for the installation's own licence and the daily seat-change quota (ACT/J) of a seat taken back from
/// another machine. TKT-003647 adds the read-only current-assignment answer in the CurrentAssignment part, which
/// reuses these relink and release scenarios.
/// </summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeAccountRelinkPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    private const string RelinkClientId = "website-account-relink";
    private const string OtherCanonicalHardwareId = "C0FFEE00C0FFEE00";

    /// <summary>
    /// Team member unlinked by the administrator (key activation disabled, so no key path exists): the account
    /// relink restores the seat and the next capability is issued.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_TeamMemberSeatReleased_Returns200_ThenCapability200")]
    public async Task AccountRelink_TeamMemberSeatReleased_Returns200_ThenCapability200()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await DisableKeyActivationAsync(scenario, licenseId);
        await ReleaseAsync(scenario, "admin");

        var result = await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, owner));

        Assert.False(result.Replayed);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(licenseId, active.LicenseId);
        Assert.Equal(
            $"{{\"schema\":\"softlicence.runtime-account-relink.response.v1\",\"enrollmentId\":\"{scenario.EnrollmentId:D}\",\"licenseId\":\"{licenseId:D}\",\"assignmentRevision\":{active.Revision},\"relinked\":true}}",
            Encoding.UTF8.GetString(result.ExactBody));
        Assert.Single(await db.LicenseHistories.AsNoTracking()
            .Where(row => row.LicenseId == licenseId && row.Action == RuntimeEnrollmentService.AccountRelinkHistoryAction)
            .ToListAsync());
        var ledger = await db.RuntimeAccountRelinkRequests.AsNoTracking().SingleAsync();
        Assert.Equal("COMPLETED", ledger.State);
        Assert.Equal(RelinkClientId, ledger.AuthenticatedClientId);
        Assert.Equal(await EnrollmentClientIdAsync(scenario), ledger.EnrollmentClientId);

        var capability = await CapabilityAsync(scenario);
        Assert.False(capability.Idempotent);
    }

    /// <summary>The account chooses another licence of the same registry owner: a seat is taken on that licence.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_OwnerOtherLicense_Returns200")]
    public async Task AccountRelink_OwnerOtherLicense_Returns200()
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, await InstallationLicenseIdAsync(scenario), owner);
        await ReleaseAsync(scenario, "client");
        var (otherLicenseId, _) = await AddLicenseWithSeatAsync(scenario, owner, OtherCanonicalHardwareId, seatActive: false);

        await RelinkAsync(scenario, await BuildAsync(scenario, otherLicenseId, owner));

        await using var db = await scenario.Factory.CreateDbContextAsync();
        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(otherLicenseId, active.LicenseId);
        var seat = await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == active.LicenseSeatId);
        Assert.Equal(LegacyHardwareId, seat.HardwareId);
        Assert.True(seat.IsActive);
    }

    /// <summary>The account digest of another account, or an owner that does not own both licences: 409, no write.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_OtherAccount_Returns409_NoWrite")]
    [InlineData("digest")]
    [InlineData("owner-target")]
    [InlineData("owner-installation")]
    public async Task AccountRelink_OtherAccount_Returns409_NoWrite(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        var installationLicenseId = await InstallationLicenseIdAsync(scenario);
        await SetOwnerAsync(scenario, installationLicenseId, mutation == "owner-installation" ? Guid.NewGuid() : owner);
        await ReleaseAsync(scenario, "client");
        var (targetId, _) = await AddLicenseWithSeatAsync(scenario,
            mutation == "owner-target" ? Guid.NewGuid() : owner, OtherCanonicalHardwareId, seatActive: false);
        var request = await BuildAsync(scenario, targetId, owner,
            digest: mutation == "digest" ? new string('b', 64) : null);

        await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status409Conflict, "installation_other_account");
    }

    /// <summary>Every installation proof failure is 403 and writes nothing.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_InstallationProofInvalid_Returns403")]
    [InlineData("missing")]
    [InlineData("bad-signature")]
    [InlineData("replayed-jti")]
    [InlineData("expired")]
    [InlineData("statement-mismatch")]
    [InlineData("other-key")]
    public async Task AccountRelink_InstallationProofInvalid_Returns403(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        Guid? jti = null;
        if (mutation == "replayed-jti")
        {
            // A jti already recorded by this enrollment for another operation is spent for every operation.
            var (capability, digest, proof) = CapabilityRequest(scenario);
            await scenario.Runtime.CreateCapabilityAsync(scenario.EnrollmentId, digest, capability, proof, IPAddress.Loopback);
            jti = Guid.Parse(proof.Jti);
        }
        await ReleaseAsync(scenario, "client");
        using var otherKey = RSA.Create(3072);
        var request = await BuildAsync(scenario, licenseId, owner,
            jti: jti,
            sentAt: mutation == "expired" ? DateTimeOffset.UtcNow.AddMinutes(-30) : null,
            omitProof: mutation == "missing",
            signingKey: mutation == "other-key" ? otherKey : null,
            corruptSignature: mutation == "bad-signature",
            signedLicenseId: mutation == "statement-mismatch" ? Guid.NewGuid() : null);

        await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status403Forbidden, "installation_proof_invalid");
    }

    /// <summary>A website-relayed machine that is not the installation's machine is refused even when signed.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_HardwareIdMismatch_Returns403")]
    public async Task AccountRelink_HardwareIdMismatch_Returns403()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "client");

        var request = await BuildAsync(scenario, licenseId, owner, hardwareId: OtherCanonicalHardwareId);

        await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status403Forbidden, "installation_proof_invalid");
    }

    /// <summary>An installation identifier different from the enrollment's is an invalid request.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_InstallationIdMismatch_Returns400")]
    public async Task AccountRelink_InstallationIdMismatch_Returns400()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "client");

        var request = await BuildAsync(scenario, licenseId, owner, installationId: Guid.NewGuid().ToString("D"));

        await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status400BadRequest, "invalid_request");
    }

    /// <summary>A stale security epoch is the non-terminal 409 the application answers by reading its state again.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_SecurityEpochMismatch_Returns409")]
    public async Task AccountRelink_SecurityEpochMismatch_Returns409()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "client");

        var request = await BuildAsync(scenario, licenseId, owner, securityEpoch: 7);

        await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status409Conflict, "security_epoch_mismatch");
    }

    /// <summary>Revocation, ban, quarantine, version and an invalidated binding stay terminal 422, without write.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_InstallationNotRepairable_Returns422")]
    [InlineData("revoked")]
    [InlineData("hardware-ban")]
    [InlineData("quarantine")]
    [InlineData("version")]
    [InlineData("binding-invalidated")]
    public async Task AccountRelink_InstallationNotRepairable_Returns422(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, mutation == "binding-invalidated" ? "provider" : "client");
        await using (var admin = AdminContext(scenario))
        {
            switch (mutation)
            {
                case "revoked":
                    await admin.Database.ExecuteSqlInterpolatedAsync(
                        $"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevokedAt\" = now(), \"RevocationReason\" = 'tkt002919-synthetic' WHERE \"Id\" = {licenseId}");
                    break;
                case "hardware-ban":
                    admin.BannedHardwareIds.Add(new BannedHardwareId
                    {
                        HardwareId = LegacyHardwareId, ProductId = scenario.Fixture.ProductId,
                        Reason = "tkt002919-synthetic-ban", IsActive = true
                    });
                    break;
                case "quarantine":
                    admin.EnrollmentLicenseAssignmentQuarantines.Add(new EnrollmentLicenseAssignmentQuarantine
                    {
                        EnrollmentId = scenario.EnrollmentId, BindingId = scenario.Fixture.BindingId,
                        Reason = "live_state_mismatch", ObservedAtUtc = DateTime.UtcNow
                    });
                    break;
                case "version":
                    await admin.Database.ExecuteSqlInterpolatedAsync(
                        $"UPDATE \"Licenses\" SET \"AllowedVersions\" = '9.*' WHERE \"Id\" = {licenseId}");
                    break;
            }
            await admin.SaveChangesAsync();
        }

        var request = await BuildAsync(scenario, licenseId, owner);

        await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status422UnprocessableEntity, "authority_ineligible");
    }

    /// <summary>
    /// An excluded machine is terminal in both repair paths, decided by the same shared predicate, before any write;
    /// each path keeps its own exact public code (decision of TEAM-IRIS, 03/11/2026).
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.HardwareExcluded_SameRefusalInCapabilityAndAccountRelink")]
    public async Task HardwareExcluded_SameRefusalInCapabilityAndAccountRelink()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "exclusion");
        var before = await SnapshotAsync(scenario);

        var capability = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => CapabilityAsync(scenario));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, capability.StatusCode);
        Assert.Equal("authority_ineligible", capability.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));

        await AssertRefusedWithoutWriteAsync(scenario, await BuildAsync(scenario, licenseId, owner),
            StatusCodes.Status422UnprocessableEntity, "license_hardware_excluded");
    }

    /// <summary>
    /// The target key already reached its daily limit of different identifiers (TKT-003751) and this machine is neither
    /// one of them nor its last PC: 422 activation_rate_limited, no write.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_SeatQuotaExhausted_Returns422")]
    public async Task AccountRelink_SeatQuotaExhausted_Returns422()
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, await InstallationLicenseIdAsync(scenario), owner);
        await ReleaseAsync(scenario, "client");
        var (targetId, _) = await AddLicenseWithSeatAsync(scenario, owner, OtherCanonicalHardwareId, seatActive: false);
        await using (var admin = AdminContext(scenario))
        {
            await admin.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"LicenseTypes\" SET \"MaxActivationsPerDay\" = 1 WHERE \"Id\" = (SELECT \"LicenseTypeId\" FROM \"Licenses\" WHERE \"Id\" = {targetId})");
            // TKT-003751: the target key was already activated today on another identifier (N = 1), which is its
            // last PC; this machine is new to it today.
            admin.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = targetId, HardwareId = "C0FFEE00C0FFEE77", IsActive = false,
                FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow,
                LastActivatedAt = DateTime.UtcNow, UnlinkedAt = DateTime.UtcNow
            });
            await admin.SaveChangesAsync();
        }

        await AssertRefusedWithoutWriteAsync(scenario, await BuildAsync(scenario, targetId, owner),
            StatusCodes.Status422UnprocessableEntity, "activation_rate_limited");
    }

    /// <summary>Every seat of the target licence is taken by other machines: 422 seat_capacity_exceeded, no write.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_SeatCapacityFull_Returns422")]
    public async Task AccountRelink_SeatCapacityFull_Returns422()
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, await InstallationLicenseIdAsync(scenario), owner);
        await ReleaseAsync(scenario, "client");
        var (targetId, _) = await AddLicenseWithSeatAsync(scenario, owner, OtherCanonicalHardwareId);
        await using (var admin = AdminContext(scenario))
        {
            await admin.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"Licenses\" SET \"MaxSeats\" = 2 WHERE \"Id\" = {targetId}");
            admin.LicenseSeats.Add(new LicenseSeat { LicenseId = targetId, HardwareId = "D00DFEEDD00DFEED", IsActive = true });
            await admin.SaveChangesAsync();
        }

        await AssertRefusedWithoutWriteAsync(scenario, await BuildAsync(scenario, targetId, owner),
            StatusCodes.Status422UnprocessableEntity, "seat_capacity_exceeded");
    }

    /// <summary>
    /// A retry with the same request and the same bytes returns the frozen bytes, without evaluating the proof again
    /// and without consuming quota; the same request with other bytes is a conflict.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_SameRequestReplay_ReturnsFrozenBytes_WithoutQuota")]
    public async Task AccountRelink_SameRequestReplay_ReturnsFrozenBytes_WithoutQuota()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "client");
        var request = await BuildAsync(scenario, licenseId, owner);
        var first = await RelinkAsync(scenario, request);
        var quota = await QuotaCountAsync(scenario);

        var replay = await RelinkAsync(scenario, request);

        Assert.True(replay.Replayed);
        Assert.Equal(first.ExactBody, replay.ExactBody);
        Assert.Equal(quota, await QuotaCountAsync(scenario));

        var other = await BuildAsync(scenario, licenseId, owner, requestId: request.Command.RequestId);
        var conflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => RelinkAsync(scenario, other));
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
        Assert.Equal("request_conflict", conflict.ErrorCode);
    }

    /// <summary>
    /// Two concurrent calls of the same request (the website retries after its own timeout while the first call still
    /// holds the enrollment lock): both pass the frozen lookup before the lock, wait behind it, and both must return
    /// the same 200 bytes. Without the lookup under lock, the second sees the consumed jti and answers 403.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_ConcurrentSameRequest_BothReturnFrozenBytes")]
    public async Task AccountRelink_ConcurrentSameRequest_BothReturnFrozenBytes()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "client");
        var request = await BuildAsync(scenario, licenseId, owner);

        // Hold the enrollment row lock so both calls are admitted past the first frozen lookup and queue behind it.
        await using var holder = new NpgsqlConnection(scenario.AppConnectionString);
        await holder.OpenAsync();
        await using var holding = await holder.BeginTransactionAsync();
        await using (var lockCommand = new NpgsqlCommand(
                         "SELECT 1 FROM public.\"RuntimeEnrollments\" WHERE \"Id\" = @id FOR UPDATE", holder, holding))
        {
            lockCommand.Parameters.AddWithValue("id", scenario.EnrollmentId);
            await lockCommand.ExecuteScalarAsync();
        }
        var first = Task.Run(() => RelinkAsync(scenario, request));
        var second = Task.Run(() => RelinkAsync(scenario, request));
        await WaitForLockWaitersAsync(scenario, 2);
        await holding.CommitAsync();

        var results = await Task.WhenAll(first, second);

        Assert.Equal(results[0].ExactBody, results[1].ExactBody);
        Assert.Single(results, result => result.Replayed);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await db.RuntimeAccountRelinkRequests.AsNoTracking().ToListAsync());
        Assert.Single(await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>An ACTIVE assignment on another licence is a conflict; on the same licence it is 200 not relinked.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_ActiveAssignment_OtherLicense409_SameLicense200NotRelinked")]
    public async Task AccountRelink_ActiveAssignment_OtherLicense409_SameLicense200NotRelinked()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        var (otherId, _) = await AddLicenseWithSeatAsync(scenario, owner, OtherCanonicalHardwareId, seatActive: false);

        await AssertRefusedWithoutWriteAsync(scenario, await BuildAsync(scenario, otherId, owner),
            StatusCodes.Status409Conflict, "assignment_conflict");

        var same = await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, owner));
        using var json = JsonDocument.Parse(same.ExactBody);
        Assert.False(json.RootElement.GetProperty("relinked").GetBoolean());
        Assert.Equal(licenseId, json.RootElement.GetProperty("licenseId").GetGuid());
    }

    /// <summary>
    /// The dedicated identity acts only for the distribution clients it is linked to: an enrollment of another client
    /// is answered as not found, without write.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_DedicatedClientNotLinkedToEnrollmentClient_Returns404_NoWrite")]
    public async Task AccountRelink_DedicatedClientNotLinkedToEnrollmentClient_Returns404_NoWrite()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "client");
        var request = await BuildAsync(scenario, licenseId, owner);
        var before = await SnapshotAsync(scenario);

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.RelinkAccountAsync(
            Principal("another-distribution-client"), request.Command));

        Assert.Equal(StatusCodes.Status404NotFound, refused.StatusCode);
        Assert.Equal("enrollment_not_found", refused.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>Eleven authenticated attempts in the same hour: the eleventh is 429 rate_limited.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_HourlyQuotaExceeded_Returns429")]
    public async Task AccountRelink_HourlyQuotaExceeded_Returns429()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await ReleaseAsync(scenario, "client");
        for (var attempt = 0; attempt < RuntimeEnrollmentService.AccountRelinkHourlyLimit; attempt++)
        {
            var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(async () =>
                await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, Guid.NewGuid())));
            Assert.Equal("installation_other_account", refused.ErrorCode);
        }

        var limited = await Assert.ThrowsAsync<RuntimeEnrollmentException>(async () =>
            await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, Guid.NewGuid())));

        Assert.Equal(StatusCodes.Status429TooManyRequests, limited.StatusCode);
        Assert.Equal("rate_limited", limited.ErrorCode);
    }

    /// <summary>
    /// The relink writer revalidates the account relink proof itself: no PENDING row, a row of another client, a row
    /// naming another enrollment client, or an owner no longer ACTIVE is refused even when the application is bypassed.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.RelinkWriter_AccountRelinkProof_IsRevalidatedInDatabase")]
    [InlineData("valid")]
    [InlineData("no-row")]
    [InlineData("other-authenticated-client")]
    [InlineData("other-enrollment-client")]
    [InlineData("owner-not-active")]
    public async Task RelinkWriter_AccountRelinkProof_IsRevalidatedInDatabase(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var owner = Guid.NewGuid();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await SetOwnerAsync(scenario, licenseId, owner);
        await ReleaseAsync(scenario, "client");
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var seatId = await db.LicenseSeats.AsNoTracking()
            .Where(row => row.LicenseId == licenseId && row.HardwareId == LegacyHardwareId).Select(row => row.Id).SingleAsync();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE \"LicenseSeats\" SET \"IsActive\" = true, \"UnlinkedAt\" = NULL WHERE \"Id\" = {seatId}");
        if (mutation == "owner-not-active")
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"RuntimeRecoveryCommercialOwnerships\" SET \"State\" = 'REVOKED', \"EndedAtUtc\" = now() WHERE \"LicenseId\" = {licenseId} AND \"State\" = 'ACTIVE'");
        if (mutation != "no-row")
        {
            db.RuntimeAccountRelinkRequests.Add(new RuntimeAccountRelinkRequest
            {
                Id = Guid.NewGuid(),
                AuthenticatedClientId = mutation == "other-authenticated-client" ? "another-relink-client" : RelinkClientId,
                EnrollmentClientId = mutation == "other-enrollment-client" ? "another-distribution-client" : enrollment.ClientId,
                RequestId = Guid.NewGuid(),
                BodyDigestSha256 = new string('a', 64),
                ProductId = enrollment.ProductId,
                EnrollmentId = enrollment.Id,
                LicenseId = licenseId,
                OwnerSubjectId = owner,
                SubjectRefDigestSha256 = enrollment.SubjectRefDigestSha256!,
                State = "PENDING",
                CreatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }

        var call = () => db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT public.relink_runtime_commercial_assignment(
                {enrollment.Id}, {licenseId}, {seatId}, {enrollment.SubjectRefDigestSha256},
                {RelinkClientId}, {(Guid?)null}, {(string?)null}, {(Guid?)owner});
            """);
        if (mutation == "valid")
        {
            await call();
            return;
        }
        var failure = await Assert.ThrowsAsync<PostgresException>(call);
        Assert.Equal("runtime_commercial_relink_authority_ineligible", failure.MessageText);
    }

    /// <summary>
    /// TKT-003350, the VM 101 case: the installation licence has no ACTIVE owner in the registry and the website sends
    /// a null owner. The account digest and the installation proof suffice: 200, a ledger row without owner, then the
    /// next capability is issued.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_InstallationLicenseWithoutOwner_NullOwner_Returns200_ThenCapability200")]
    public async Task AccountRelink_InstallationLicenseWithoutOwner_NullOwner_Returns200_ThenCapability200()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await ReleaseAsync(scenario, "client");
        await using (var check = await scenario.Factory.CreateDbContextAsync())
            Assert.False(await check.RuntimeRecoveryCommercialOwnerships.AnyAsync(row => row.LicenseId == licenseId));

        var result = await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, owner: null));

        Assert.False(result.Replayed);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        Assert.Equal(licenseId, active.LicenseId);
        var ledger = await db.RuntimeAccountRelinkRequests.AsNoTracking().SingleAsync();
        Assert.Equal("COMPLETED", ledger.State);
        Assert.Null(ledger.OwnerSubjectId);
        var capability = await CapabilityAsync(scenario);
        Assert.False(capability.Idempotent);
    }

    /// <summary>
    /// TKT-003350: a null owner never opens another licence, and never replaces the account digest. Both stay 409
    /// <c>installation_other_account</c>, without any write.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_NullOwner_OtherLicenseOrOtherAccount_Returns409_NoWrite")]
    [InlineData("other-licence")]
    [InlineData("digest")]
    public async Task AccountRelink_NullOwner_OtherLicenseOrOtherAccount_Returns409_NoWrite(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var installationLicenseId = await InstallationLicenseIdAsync(scenario);
        await ReleaseAsync(scenario, "client");
        var targetId = installationLicenseId;
        if (mutation == "other-licence")
            (targetId, _) = await AddLicenseWithSeatAsync(scenario, Guid.NewGuid(), OtherCanonicalHardwareId, seatActive: false);
        var request = await BuildAsync(scenario, targetId, owner: null,
            digest: mutation == "digest" ? new string('b', 64) : null);

        await AssertRefusedWithoutWriteAsync(scenario, request, StatusCodes.Status409Conflict, "installation_other_account");
    }

    /// <summary>
    /// TKT-003350: after a dashboard unlink (« Délier ») the same machine takes its own seat back even when the daily
    /// seat-change quota of the licence type (ACT/J) is already exhausted, and the relink consumes nothing.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_SameMachineAfterUnlink_QuotaExhausted_Returns200_ConsumesNothing")]
    public async Task AccountRelink_SameMachineAfterUnlink_QuotaExhausted_Returns200_ConsumesNothing()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await SetActivationsPerDayAsync(scenario, licenseId, 1);
        await ReleaseAsync(scenario, "admin");
        var before = await SeatChangeQuotaAsync(scenario, licenseId);
        Assert.True(before.IsExhausted, $"used {before.UsedToday} of {before.Limit}");

        await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, owner: null));

        // Nothing is consumed: the counter never grows. It may even drop here, because the administrator unlink
        // writes no counted event and was visible only through the legacy floor (inactive seat unlinked today),
        // which disappears once the machine takes its own seat back; a portal unlink stays counted by its operation.
        var after = await SeatChangeQuotaAsync(scenario, licenseId);
        Assert.True(after.UsedToday <= before.UsedToday, $"used {before.UsedToday} then {after.UsedToday}");
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        var seat = await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == active.LicenseSeatId);
        Assert.Equal(LegacyHardwareId, seat.HardwareId);
        Assert.False(await db.LicenseHistories.AsNoTracking().AnyAsync(row =>
            row.LicenseId == licenseId && (row.Action == HistoryActions.RuntimeAccountRelinkSeatTakeover
                || row.Action == HistoryActions.RuntimeCommercialNewIdentifier)));
    }

    /// <summary>
    /// TKT-003350 revised by TKT-003751 (owner rule): another machine took the only seat after this installation
    /// signed out. This machine was already activated today, so taking its seat back is never refused, whatever N is
    /// (1 or 3, read from the type), and adds nothing to the day's count of different identifiers (2: this machine and
    /// the other one). The takeover history row is kept as audit.
    /// </summary>
    /// <param name="perDay">Value of <c>LicenseTypes.MaxActivationsPerDay</c> (single-seat licence, so N = perDay).</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_TakeBackSingleSeat_MachineOfTheDay_NeverRefused")]
    [InlineData(1)]
    [InlineData(3)]
    public async Task AccountRelink_TakeBackSingleSeat_MachineOfTheDay_NeverRefused(int perDay)
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, licenseId, owner);
        await SetActivationsPerDayAsync(scenario, licenseId, perDay);
        await ReleaseAsync(scenario, "client");
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            // The other machine took the only seat after this installation signed out.
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = licenseId, HardwareId = OtherCanonicalHardwareId, IsActive = true,
                FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }
        Assert.Equal(2, (await SeatChangeQuotaAsync(scenario, licenseId)).UsedToday);

        await RelinkAsync(scenario, await BuildAsync(scenario, licenseId, owner));

        Assert.Equal(2, (await SeatChangeQuotaAsync(scenario, licenseId)).UsedToday);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var seats = await check.LicenseSeats.AsNoTracking().Where(row => row.LicenseId == licenseId).ToListAsync();
        Assert.True(seats.Single(row => row.HardwareId == LegacyHardwareId).IsActive);
        Assert.False(seats.Single(row => row.HardwareId == OtherCanonicalHardwareId).IsActive);
        Assert.Single(await check.LicenseHistories.AsNoTracking()
            .Where(row => row.LicenseId == licenseId && row.Action == HistoryActions.RuntimeAccountRelinkSeatTakeover)
            .ToListAsync());
    }

    /// <summary>
    /// TKT-003350: the relink writer revalidates the optional owner itself. A null owner is accepted only for the
    /// installation's own licence with a ledger row that carries no owner either; another licence, or a ledger row
    /// naming an owner, is refused in the database whatever the application layer decided. TKT-003753: another
    /// licence is accepted only when the PENDING ledger row carries the website attestation.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.RelinkWriter_AccountRelinkNullOwner_IsRevalidatedInDatabase")]
    [InlineData("valid")]
    [InlineData("other-licence")]
    [InlineData("other-licence-attested")]
    [InlineData("ledger-names-owner")]
    public async Task RelinkWriter_AccountRelinkNullOwner_IsRevalidatedInDatabase(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var installationLicenseId = await InstallationLicenseIdAsync(scenario);
        await ReleaseAsync(scenario, "client");
        var targetId = installationLicenseId;
        if (mutation.StartsWith("other-licence", StringComparison.Ordinal))
            (targetId, _) = await AddLicenseWithSeatAsync(scenario, Guid.NewGuid(), LegacyHardwareId, seatActive: false);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var seatId = await db.LicenseSeats.AsNoTracking()
            .Where(row => row.LicenseId == targetId && row.HardwareId == LegacyHardwareId).Select(row => row.Id).SingleAsync();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE \"LicenseSeats\" SET \"IsActive\" = true, \"UnlinkedAt\" = NULL WHERE \"Id\" = {seatId}");
        db.RuntimeAccountRelinkRequests.Add(new RuntimeAccountRelinkRequest
        {
            Id = Guid.NewGuid(),
            AuthenticatedClientId = RelinkClientId,
            EnrollmentClientId = enrollment.ClientId,
            RequestId = Guid.NewGuid(),
            BodyDigestSha256 = new string('a', 64),
            ProductId = enrollment.ProductId,
            EnrollmentId = enrollment.Id,
            LicenseId = targetId,
            OwnerSubjectId = mutation == "ledger-names-owner" ? Guid.NewGuid() : null,
            OwnerAttestation = mutation == "other-licence-attested"
                ? RuntimeAccountRelinkContract.WebsiteSameAccountAttestation : null,
            SubjectRefDigestSha256 = enrollment.SubjectRefDigestSha256!,
            State = "PENDING",
            CreatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        var call = () => db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT public.relink_runtime_commercial_assignment(
                {enrollment.Id}, {targetId}, {seatId}, {enrollment.SubjectRefDigestSha256},
                {RelinkClientId}, {(Guid?)null}, {(string?)null}, {(Guid?)null});
            """);
        if (mutation is "valid" or "other-licence-attested")
        {
            await call();
            return;
        }
        var failure = await Assert.ThrowsAsync<PostgresException>(call);
        Assert.Equal("runtime_commercial_relink_authority_ineligible", failure.MessageText);
    }

    /// <summary>Completed relinks stay replayable for 30 days, then the cleanup routine removes them.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.AccountRelink_CompletedRows_PurgedAfter30Days")]
    public async Task AccountRelink_CompletedRows_PurgedAfter30Days()
    {
        using var scenario = await ActivatedScenarioAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
            foreach (var ageDays in new[] { 31, 29 })
                db.RuntimeAccountRelinkRequests.Add(new RuntimeAccountRelinkRequest
                {
                    Id = Guid.NewGuid(), AuthenticatedClientId = RelinkClientId, EnrollmentClientId = enrollment.ClientId,
                    RequestId = Guid.NewGuid(), BodyDigestSha256 = new string('a', 64), ProductId = enrollment.ProductId,
                    EnrollmentId = enrollment.Id, LicenseId = enrollment.LicenseId, OwnerSubjectId = Guid.NewGuid(),
                    SubjectRefDigestSha256 = enrollment.SubjectRefDigestSha256!, State = "COMPLETED", ResponseBody = "{}",
                    CreatedAtUtc = DateTime.UtcNow.AddDays(-ageDays), CompletedAtUtc = DateTime.UtcNow.AddDays(-ageDays)
                });
            await db.SaveChangesAsync();
        }

        await new RuntimeEnrollmentCleanupService(scenario.Factory, Options.Create(scenario.Options), TimeProvider.System,
            NullLogger<RuntimeEnrollmentCleanupService>.Instance).CleanupAsync(CancellationToken.None);

        await using var check = await scenario.Factory.CreateDbContextAsync();
        var remaining = await check.RuntimeAccountRelinkRequests.AsNoTracking().ToListAsync();
        var kept = Assert.Single(remaining);
        Assert.True(kept.CompletedAtUtc > DateTime.UtcNow.AddDays(-30));
    }

    /// <summary>One signed request, its exact bytes and the parsed command.</summary>
    /// <param name="Body">Exact JSON bytes as the website sends them.</param>
    /// <param name="Command">The same request parsed by the production contract parser.</param>
    private sealed record SignedRequest(byte[] Body, RuntimeAccountRelinkCommand Command);

    /// <summary>
    /// Builds and signs one request with the scenario installation key. Each optional argument breaks exactly one
    /// element of the contract so a test names the refusal it proves. A null <paramref name="owner"/> is sent as an
    /// explicit JSON null, as the website does when it knows no commercial owner (TKT-003350). A non-null
    /// <paramref name="ownerAttestation"/> adds the TKT-003753 field <c>ownerAttestation</c>.
    /// </summary>
    private static async Task<SignedRequest> BuildAsync(
        PreparedBootstrapScenario scenario,
        Guid licenseId,
        Guid? owner,
        string? digest = null,
        Guid? jti = null,
        DateTimeOffset? sentAt = null,
        bool omitProof = false,
        RSA? signingKey = null,
        bool corruptSignature = false,
        Guid? signedLicenseId = null,
        string? hardwareId = null,
        string? installationId = null,
        int? securityEpoch = null,
        Guid? requestId = null,
        string? ownerAttestation = null)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var unsigned = new RuntimeAccountRelinkCommand(
            requestId ?? Guid.NewGuid(), enrollment.ProductId, enrollment.Id, installationId ?? enrollment.InstallationId,
            signedLicenseId ?? licenseId, hardwareId ?? LegacyHardwareId, enrollment.ReleaseVersion,
            securityEpoch ?? enrollment.SecurityEpoch, digest ?? enrollment.SubjectRefDigestSha256!, owner, null, string.Empty,
            ownerAttestation);
        var timestamp = FormatUtc(sentAt ?? DateTimeOffset.UtcNow);
        var proofJti = (jti ?? Guid.NewGuid()).ToString("D");
        var signature = (signingKey ?? scenario.EnrollmentKey).SignData(
            Encoding.UTF8.GetBytes(RuntimeAccountRelinkContract.BuildProofPayload(unsigned, timestamp, proofJti)),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if (corruptSignature)
            signature[10] ^= 0x5a;
        var body = new JsonObject
        {
            ["schema"] = RuntimeAccountRelinkContract.RequestSchema,
            ["requestId"] = unsigned.RequestId.ToString("D"),
            ["productId"] = unsigned.ProductId.ToString("D"),
            ["enrollmentId"] = unsigned.EnrollmentId.ToString("D"),
            ["installationId"] = unsigned.InstallationId,
            ["licenseId"] = licenseId.ToString("D"),
            ["hardwareId"] = unsigned.HardwareId,
            ["releaseVersion"] = unsigned.ReleaseVersion,
            ["securityEpoch"] = unsigned.SecurityEpoch,
            ["installationSubjectRefDigestSha256"] = unsigned.InstallationSubjectRefDigestSha256,
            ["ownerSubjectId"] = owner?.ToString("D")
        };
        // TKT-003753: the optional attestation is sent only when the test names one, as the website does.
        if (ownerAttestation is not null)
            body["ownerAttestation"] = ownerAttestation;
        if (!omitProof)
            body["installationProof"] = new JsonObject
            {
                ["timestamp"] = timestamp, ["jti"] = proofJti, ["signature"] = Base64Url(signature)
            };
        var bytes = Encoding.UTF8.GetBytes(body.ToJsonString());
        var command = RuntimeAccountRelinkContract.Parse(bytes);
        Assert.NotNull(command);
        return new SignedRequest(bytes, command);
    }

    /// <summary>Calls the production service with the dedicated identity linked to the scenario's distribution client.</summary>
    private static async Task<RuntimeAccountRelinkResult> RelinkAsync(PreparedBootstrapScenario scenario, SignedRequest request) =>
        await scenario.Runtime.RelinkAccountAsync(Principal(await EnrollmentClientIdAsync(scenario)), request.Command);

    /// <summary>Dedicated relink principal linked to exactly one distribution client.</summary>
    private static DistributionS2SPrincipal Principal(string linkedClientId) =>
        new(RelinkClientId, "account-relink-2026-10", AllowRuntimeAccountRelink: true,
            AccountRelinkForClientIds: [linkedClientId]);

    /// <summary>Asserts the exact refusal and that no business row changed (quota counters are not business rows).</summary>
    private static async Task AssertRefusedWithoutWriteAsync(
        PreparedBootstrapScenario scenario, SignedRequest request, int status, string error)
    {
        var before = await SnapshotAsync(scenario);
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => RelinkAsync(scenario, request));
        Assert.Equal(status, refused.StatusCode);
        Assert.Equal(error, refused.ErrorCode);
        Assert.Equal(before, await SnapshotAsync(scenario));
    }

    /// <summary>Captures every business row a refused relink must leave unchanged, ledger and proof registry included.</summary>
    private static async Task<string> SnapshotAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        var assignments = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == scenario.EnrollmentId)
            .OrderBy(row => row.Revision).Select(row => row.Id + ":" + row.State + ":" + row.EndReason).ToListAsync();
        var seats = await db.LicenseSeats.AsNoTracking().OrderBy(row => row.Id)
            .Select(row => row.Id + ":" + row.IsActive + ":" + row.HardwareId).ToListAsync();
        var nonces = await db.RuntimeEnrollmentProofNonces.AsNoTracking().CountAsync(row => row.EnrollmentId == scenario.EnrollmentId);
        var histories = await db.LicenseHistories.AsNoTracking().CountAsync();
        var ledger = await db.RuntimeAccountRelinkRequests.AsNoTracking().CountAsync();
        return string.Join("|", enrollment.State, enrollment.Epoch, enrollment.SecurityEpoch, enrollment.AuthorityEpoch,
            enrollment.InvalidationReason, string.Join(",", assignments), string.Join(",", seats), nonces, histories, ledger);
    }

    /// <summary>
    /// Waits (at most 30 s) until <paramref name="count"/> sessions of the scenario database wait on a row lock, so the
    /// concurrent test releases its lock only once both calls are queued behind it.
    /// </summary>
    private static async Task WaitForLockWaitersAsync(PreparedBootstrapScenario scenario, int count)
    {
        await using var admin = new NpgsqlConnection(scenario.AdminConnectionString);
        await admin.OpenAsync();
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            await using var command = new NpgsqlCommand(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'", admin);
            if (Convert.ToInt32(await command.ExecuteScalarAsync()) >= count)
                return;
            Assert.True(DateTime.UtcNow < deadline, "The concurrent relink calls never queued behind the enrollment lock.");
            await Task.Delay(50);
        }
    }

    /// <summary>Sum of account relink quota counters of the scenario enrollment.</summary>
    private static async Task<int> QuotaCountAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var subject = scenario.EnrollmentId.ToString("D");
        return await db.RuntimeEnrollmentQuotas.AsNoTracking()
            .Where(row => row.Scope == RuntimeEnrollmentService.AccountRelinkQuotaScope && row.SubjectPseudonym == subject)
            .SumAsync(row => row.Count);
    }

    /// <summary>Distribution client that created the scenario enrollment.</summary>
    private static async Task<string> EnrollmentClientIdAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        return await db.RuntimeEnrollments.AsNoTracking()
            .Where(row => row.Id == scenario.EnrollmentId).Select(row => row.ClientId).SingleAsync();
    }

    /// <summary>Administrator context for fixture rows the application role may not write directly.</summary>
    private static LicenseDbContext AdminContext(PreparedBootstrapScenario scenario) =>
        new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(scenario.AdminConnectionString).Options);

    /// <summary>
    /// Sets ACT/J (<c>LicenseTypes.MaxActivationsPerDay</c>) on the type of one licence, as an administrator does in
    /// the SoftLicence admin; the licences of these tests have one seat, so the daily limit equals the value.
    /// </summary>
    private static async Task SetActivationsPerDayAsync(PreparedBootstrapScenario scenario, Guid licenseId, int perDay)
    {
        await using var admin = AdminContext(scenario);
        await admin.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE \"LicenseTypes\" SET \"MaxActivationsPerDay\" = {perDay} WHERE \"Id\" = (SELECT \"LicenseTypeId\" FROM \"Licenses\" WHERE \"Id\" = {licenseId})");
    }

    /// <summary>Reads the production seat-change quota of one licence (the counter the dashboard shows), now, in UTC.</summary>
    private static async Task<SeatChangeQuotaStatus> SeatChangeQuotaAsync(PreparedBootstrapScenario scenario, Guid licenseId)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.AsNoTracking().Include(row => row.Type).SingleAsync(row => row.Id == licenseId);
        return await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow);
    }

    /// <summary>Creates the prepared scenario, activates it on the legacy machine with one seat, and returns it.</summary>
    private static async Task<PreparedBootstrapScenario> ActivatedScenarioAsync()
    {
        var scenario = await CreatePreparedBootstrapScenarioAsync();
        try
        {
            await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var licenseId = await InstallationLicenseIdAsync(db, scenario);
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"Licenses\" SET \"MaxSeats\" = 1, \"LicenseKey\" = upper(\"LicenseKey\") WHERE \"Id\" = {licenseId}");
            return scenario;
        }
        catch
        {
            scenario.Dispose();
            throw;
        }
    }

    /// <summary>Builds one fresh signed capability request of the scenario installation.</summary>
    private static (RuntimeEnrollmentCapabilityRequest Request, string Digest, RuntimeProofHeaders Proof) CapabilityRequest(
        PreparedBootstrapScenario scenario)
    {
        var request = new RuntimeEnrollmentCapabilityRequest
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
        var digest = Sha256("tkt002919-capability-" + Guid.NewGuid().ToString("D"));
        var proof = Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId, request.Audience, "-", digest);
        return (request, digest, proof);
    }

    /// <summary>Issues one fresh capability through the production service.</summary>
    private static Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>> CapabilityAsync(
        PreparedBootstrapScenario scenario)
    {
        var (request, digest, proof) = CapabilityRequest(scenario);
        return scenario.Runtime.CreateCapabilityAsync(scenario.EnrollmentId, digest, request, proof, IPAddress.Loopback);
    }

    /// <summary>
    /// Releases the scenario seat through one real path: client sign out, administrator unlink, licence exclusion,
    /// or provider seat release (which invalidates binding and enrollment).
    /// </summary>
    private static async Task ReleaseAsync(PreparedBootstrapScenario scenario, string route)
    {
        if (route == "exclusion")
        {
            var licenseId = await InstallationLicenseIdAsync(scenario);
            var service = new LicenseHardwareExclusionService(scenario.Factory, new FixedTimeProvider(DateTimeOffset.UtcNow),
                TestHardwareAuthorityAliasResolver.Instance, NullLogger<LicenseHardwareExclusionService>.Instance);
            await service.AddAsync("tia-connect-website-exclusions", new string('a', 64),
                new LicenseHardwareExclusionRequest(LicenseHardwareExclusionService.RequestSchema,
                    Guid.NewGuid().ToString("D"), scenario.Fixture.ProductId.ToString("D"),
                    licenseId.ToString("D"), LegacyHardwareId, true));
            return;
        }
        if (route == "provider")
        {
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var binding = await db.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == scenario.Fixture.BindingId);
            var now = DateTimeOffset.UtcNow;
            var distribution = new DistributionInstallationBindingService(scenario.Factory,
                new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
                TestHardwareAuthorityAliasResolver.Instance);
            await distribution.InvalidateAsync(await EnrollmentClientIdAsync(scenario),
                Sha256("tkt002919-provider-release-" + Guid.NewGuid()),
                new DistributionInstallationInvalidationRequest
                {
                    Schema = DistributionInstallationBindingService.InvalidationSchema,
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = scenario.Fixture.ProductId.ToString("D"),
                    BindingId = scenario.Fixture.BindingId.ToString("D"),
                    GrantRefDigestSha256 = binding.GrantRefDigestSha256,
                    Reason = "seat_released",
                    OccurredAtUtc = FormatUtc(now),
                    Epoch = 1
                });
            return;
        }

        string licenseKey, appName;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var licenseId = await InstallationLicenseIdAsync(db, scenario);
            var license = await db.Licenses.AsNoTracking().Include(row => row.Product).SingleAsync(row => row.Id == licenseId);
            licenseKey = license.LicenseKey;
            appName = license.Product!.Name;
        }
        using var baseFactory = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var web = baseFactory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AdminSettings:ApiSecret", "tkt002919-test-only");
            builder.UseSetting("AdminSettings:AllowedIps", "");
        });
        using var client = web.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt002919-test-only");
        using var response = route == "admin"
            ? await client.DeleteAsync($"/api/admin/licenses/{licenseKey}/seats/{LegacyHardwareId}")
            : await client.PostAsJsonAsync("/api/activation/deactivate",
                new { LicenseKey = licenseKey, AppName = appName, HardwareId = LegacyHardwareId, Source = "settings_button" });
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    /// <summary>Returns the licence of the scenario binding.</summary>
    private static async Task<Guid> InstallationLicenseIdAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        return await InstallationLicenseIdAsync(db, scenario);
    }

    /// <summary>Returns the licence of the scenario binding with a caller-owned context.</summary>
    private static Task<Guid> InstallationLicenseIdAsync(LicenseDbContext db, PreparedBootstrapScenario scenario) =>
        db.DistributionInstallationBindings.AsNoTracking()
            .Where(row => row.Id == scenario.Fixture.BindingId).Select(row => row.LicenseId).SingleAsync();

    /// <summary>Records one account owner as the ACTIVE registry owner of a licence, as licence creation does.</summary>
    private static async Task SetOwnerAsync(PreparedBootstrapScenario scenario, Guid licenseId, Guid owner)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        if (!await db.RuntimeRecoveryCommercialSubjects.AnyAsync(row => row.Id == owner))
            db.RuntimeRecoveryCommercialSubjects.Add(new RuntimeRecoveryCommercialSubject
            {
                Id = owner, ProductId = scenario.Fixture.ProductId, CreatedAtUtc = DateTime.UtcNow
            });
        foreach (var current in await db.RuntimeRecoveryCommercialOwnerships
                     .Where(row => row.LicenseId == licenseId && row.State == "ACTIVE").ToListAsync())
            db.RuntimeRecoveryCommercialOwnerships.Remove(current);
        await db.SaveChangesAsync();
        db.RuntimeRecoveryCommercialOwnerships.Add(new RuntimeRecoveryCommercialOwnership
        {
            Id = Guid.NewGuid(), ProductId = scenario.Fixture.ProductId, LicenseId = licenseId,
            OwnerSubjectId = owner, State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Disables key activation on a licence, as a Team licence is configured (TKT-002475).</summary>
    private static async Task DisableKeyActivationAsync(PreparedBootstrapScenario scenario, Guid licenseId)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        db.LicenseKeyActivationSettings.Add(new LicenseKeyActivationSetting
        {
            Id = Guid.NewGuid(), ProductId = scenario.Fixture.ProductId, LicenseId = licenseId, Disabled = true,
            DisabledAtUtc = DateTime.UtcNow, DisabledByRequestId = Guid.NewGuid(), DisabledByActor = LicenseKeyActivationSettingService.S2SActor,
            DisabledByClientId = "tkt002919-test", CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Adds another licence of the scenario product owned by one owner, with one seat on the given machine.</summary>
    private static async Task<(Guid LicenseId, Guid SeatId)> AddLicenseWithSeatAsync(
        PreparedBootstrapScenario scenario, Guid owner, string hardwareId, bool seatActive = true)
    {
        Guid licenseId;
        Guid seatId;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var source = await db.Licenses.AsNoTracking()
                .SingleAsync(row => row.Id == db.DistributionInstallationBindings
                    .Where(binding => binding.Id == scenario.Fixture.BindingId).Select(binding => binding.LicenseId).Single());
            var license = (License)db.Entry(source).CurrentValues.ToObject();
            license.Id = Guid.NewGuid();
            license.LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant();
            license.HardwareId = seatActive ? hardwareId : null;
            license.MaxSeats = 1;
            db.Licenses.Add(license);
            var seat = new LicenseSeat
            {
                LicenseId = license.Id, HardwareId = hardwareId, IsActive = seatActive,
                UnlinkedAt = seatActive ? null : DateTime.UtcNow.AddDays(-1)
            };
            db.LicenseSeats.Add(seat);
            await db.SaveChangesAsync();
            licenseId = license.Id;
            seatId = seat.Id;
        }
        await SetOwnerAsync(scenario, licenseId, owner);
        return (licenseId, seatId);
    }
}

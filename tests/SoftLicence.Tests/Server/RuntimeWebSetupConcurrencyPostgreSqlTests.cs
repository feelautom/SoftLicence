using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Exercises two real installations against PostgreSQL authority triggers. Finishing either
    /// installation must not expire the other's reservation or reject its signed upgrade.
    /// </summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task WebSetupConcurrency_IndependentUpgradePreservesPendingTransition(
        bool reverseOrder, bool replayIssue)
    {
        await ExerciseWebSetupConcurrencyAsync(reverseOrder, replayIssue, null);
    }

    /// <summary>
    /// Authority changes belonging to the pending installation remain terminal even when
    /// an unrelated installation has advanced the global authority epoch first.
    /// </summary>
    [Theory]
    [InlineData("license", false)]
    [InlineData("license_wait", false)]
    [InlineData("expiry_wait", false)]
    [InlineData("seat", false)]
    [InlineData("source", false)]
    [InlineData("security_epoch", false)]
    [InlineData("target_baseline", false)]
    [InlineData("installation", false)]
    [InlineData("future_epoch", false)]
    [InlineData("future_epoch", true)]
    [InlineData("expired", true)]
    [InlineData("license", true)]
    [InlineData("seat", true)]
    public async Task WebSetupConcurrency_RevalidatesRelevantAuthority(string mutation, bool replayIssue)
    {
        await ExerciseWebSetupConcurrencyAsync(false, replayIssue, mutation);
    }

    /// <summary>
    /// Seeds two licenses and installations for one product, issues both reservations before
    /// either is consumed, then optionally changes the remaining installation's authority.
    /// Uses the application database role and actual signed requests, never a mocked epoch.
    /// </summary>
    private static async Task ExerciseWebSetupConcurrencyAsync(
        bool reverseOrder, bool replayIssue, string? mutation)
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var first = await SeedAuthorityAsync(factory, "2.3.647", "*");
        var secondBindingId = Guid.NewGuid();
        var secondInstallationId = Guid.NewGuid().ToString("D");
        var secondHandoff = Sha256(Guid.NewGuid().ToString("D"));
        // Clone detached seed rows before insertion so immutable product keys never change.
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var binding = await seed.DistributionInstallationBindings.AsNoTracking().SingleAsync(row => row.Id == first.BindingId);
            var license = await seed.Licenses.AsNoTracking().SingleAsync(row => row.Id == binding.LicenseId);
            var seat = await seed.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == binding.LicenseSeatId);
            license.Id = Guid.NewGuid();
            license.LicenseKey = "RUNTIME-" + Guid.NewGuid().ToString("N");
            seat.Id = Guid.NewGuid();
            seat.LicenseId = license.Id;
            seat.HardwareId = "runtime-hwid-" + Guid.NewGuid().ToString("N");
            binding.Id = secondBindingId;
            binding.LicenseId = license.Id;
            binding.LicenseSeatId = seat.Id;
            binding.EntitlementId = Guid.NewGuid();
            binding.InstallationId = secondInstallationId;
            binding.HardwareIdHash = Sha256(seat.HardwareId);
            binding.HandoffDigestSha256 = secondHandoff;
            binding.GrantRef = Guid.NewGuid().ToString("D");
            binding.GrantRefDigestSha256 = Sha256(binding.GrantRef);
            seed.Licenses.Add(license);
            seed.LicenseSeats.Add(seat);
            seed.DistributionInstallationBindings.Add(binding);
            seed.DistributionGrantOwnerships.Add(new DistributionGrantOwnership
            {
                ProductId = first.ProductId, GrantRefDigestSha256 = binding.GrantRefDigestSha256,
                ClientId = "website-step1", Source = "finalize_v1", CreatedAtUtc = DateTime.UtcNow
            });
            seed.DistributionBindingRequests.Add(new DistributionBindingRequest
            {
                ClientId = "website-step1", RequestId = Guid.NewGuid().ToString("D"),
                Operation = "finalize_binding", PayloadDigest = new string('b', 64),
                BindingId = binding.Id, ResponseJson = "{}", CreatedAtUtc = DateTime.UtcNow
            });
            await seed.SaveChangesAsync();
        }
        var second = (first.ProductId, BindingId: secondBindingId, HandoffDigest: secondHandoff,
            InstallationId: secondInstallationId, first.Version);
        using var signing = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var firstKey = RSA.Create(3072);
        using var secondKey = RSA.Create(3072);
        var options = RuntimeOptions(first.ProductId, signing, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory,
            new RuntimeEnrollmentAuthorityService(factory, Options.Create(options)),
            new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options)),
            crypto, Options.Create(options));

        var fixtures = new[] { first, second };
        var keys = new[] { firstKey, secondKey };
        var enrollmentIds = new Guid[2];
        for (var index = 0; index < fixtures.Length; index++)
        {
            var prepared = await service.PrepareAsync("website-step1", Sha256(Guid.NewGuid().ToString("D")),
                PrepareRequest(fixtures[index], Guid.NewGuid().ToString("D"), keys[index]));
            var id = Guid.Parse(prepared.Response.EnrollmentId);
            enrollmentIds[index] = id;
            var digest = Sha256(Guid.NewGuid().ToString("D"));
            await service.ConfirmAsync(id, digest, new RuntimeEnrollmentConfirmRequest
            {
                Schema = RuntimeEnrollmentService.ConfirmSchema,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                EnrollmentId = id.ToString("D"), Epoch = 1
            }, Proof(keys[index], "confirm", id, options.ConfirmAudience,
                prepared.Response.Challenge, digest), IPAddress.Loopback);
        }

        const string target = "2.3.924";
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FP_CORE"] = new string('1', 64), ["FP_DLL"] = new string('2', 64),
            ["FP_EXE"] = new string('3', 64)
        };
        await using (var seed = await factory.CreateDbContextAsync())
        {
            foreach (var hash in hashes)
                seed.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = first.ProductId, Version = target, Key = hash.Key,
                    Hash = hash.Value, Source = ApprovedBinaryService.ReleaseSource
                });
            await seed.SaveChangesAsync();
        }

        var issues = new RuntimeWebSetupTransitionIssueRequest[2];
        var issueDigests = new string[2];
        var issued = new RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>[2];
        for (var index = 0; index < fixtures.Length; index++)
        {
            issues[index] = new RuntimeWebSetupTransitionIssueRequest
            {
                Schema = RuntimeEnrollmentService.WebSetupTransitionIssueSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                ProductId = first.ProductId.ToString("D"),
                BindingId = fixtures[index].BindingId.ToString("D"),
                EnrollmentId = enrollmentIds[index].ToString("D"),
                SourceVersion = fixtures[index].Version, TargetVersion = target,
                TargetInstallerFilename = "TiaConnect-Setup_v2.3.924.msi",
                TargetInstallerSha256 = new string('4', 64)
            };
            issueDigests[index] = Sha256(JsonSerializer.Serialize(issues[index]));
            issued[index] = await service.IssueWebSetupTransitionAsync("website-step1", issueDigests[index], issues[index]);
        }

        /// <summary>Builds a fresh proof over the exact authorization bytes for one installation.</summary>
        (RuntimeWebSetupUpgradeRelayRequest Request, string Digest) Relay(int index)
        {
            var authorization = new RuntimeWebSetupUpgradeAuthorization
            {
                Schema = RuntimeEnrollmentService.WebSetupUpgradeAuthorizationSchema,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                ProductId = first.ProductId.ToString("D"), EnrollmentId = enrollmentIds[index].ToString("D"),
                TransitionId = issued[index].Response.TransitionId, Capability = issued[index].Response.Capability,
                SourceVersion = fixtures[index].Version, TargetVersion = target,
                Binaries = hashes.Select(hash => new RuntimeEnrollmentBinaryEvidenceRequest
                    { Key = hash.Key, Sha256 = hash.Value }).ToList()
            };
            var bytes = JsonSerializer.SerializeToUtf8Bytes(authorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var proof = Proof(keys[index], "websetup-upgrade", enrollmentIds[index],
                RuntimeEnrollmentService.WebSetupUpgradeAudience, "-", Convert.ToHexStringLower(SHA256.HashData(bytes)));
            var request = new RuntimeWebSetupUpgradeRelayRequest
            {
                Schema = RuntimeEnrollmentService.WebSetupUpgradeSchema,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                AuthorizationBodyBase64Url = Base64Url(bytes), ProofTimestamp = proof.Timestamp,
                ProofJti = proof.Jti, ProofSignature = proof.Signature
            };
            return (request, Sha256(JsonSerializer.Serialize(request)));
        }

        var completed = reverseOrder ? 0 : 1;
        var pending = 1 - completed;
        var firstRelay = Relay(completed);
        var completedResult = await service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", firstRelay.Digest, firstRelay.Request);
        Assert.False(completedResult.Idempotent);
        if (mutation is "license_wait" or "expiry_wait")
        {
            var raceRelay = Relay(pending);
            await using var writer = new Npgsql.NpgsqlConnection(connections.App);
            await writer.OpenAsync();
            await using var lookup = await factory.CreateDbContextAsync();
            var pendingLicenseId = (await lookup.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == fixtures[pending].BindingId)).LicenseId;
            if (mutation == "expiry_wait")
            {
                await using var setExpiry = writer.CreateCommand();
                setExpiry.CommandText = "UPDATE public.\"Licenses\" SET \"ExpirationDate\" = pg_catalog.clock_timestamp() + interval '2 seconds' WHERE \"Id\" = @licenseId";
                setExpiry.Parameters.AddWithValue("licenseId", pendingLicenseId);
                Assert.Equal(1, await setExpiry.ExecuteNonQueryAsync());
            }
            await using var writerTransaction = await writer.BeginTransactionAsync();
            Task<RuntimeEnrollmentOperationResult<RuntimeWebSetupUpgradeResponse>>? waitingConsume = null;
            var writerCommitted = false;
            try
            {
                await using (var hold = writer.CreateCommand())
                {
                    hold.Transaction = writerTransaction;
                    hold.CommandText = mutation == "license_wait"
                        ? "UPDATE public.\"Licenses\" SET \"RevokedAt\" = pg_catalog.clock_timestamp() WHERE \"Id\" = @licenseId"
                        : "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)";
                    if (mutation == "license_wait")
                        hold.Parameters.AddWithValue("licenseId", pendingLicenseId);
                    await hold.ExecuteNonQueryAsync();
                }
                waitingConsume = service.UpgradeFromWebSetupAsync(
                    "website-step1", "s2s-test", raceRelay.Digest, raceRelay.Request);
                await using var observer = new Npgsql.NpgsqlConnection(connections.Admin);
                await observer.OpenAsync();
                var blocked = false;
                for (var attempt = 0; attempt < 30; attempt++)
                {
                    await using var query = observer.CreateCommand();
                    query.CommandText = "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE @writerPid = ANY(pg_catalog.pg_blocking_pids(pid))";
                    query.Parameters.AddWithValue("writerPid", writer.ProcessID);
                    if ((long)(await query.ExecuteScalarAsync())! > 0) { blocked = true; break; }
                    await Task.Delay(100);
                }
                Assert.True(blocked);
                Assert.False(waitingConsume.IsCompleted);
                if (mutation == "expiry_wait")
                {
                    var expired = false;
                    for (var attempt = 0; attempt < 35; attempt++)
                    {
                        await using var query = observer.CreateCommand();
                        query.CommandText = "SELECT \"ExpirationDate\" <= pg_catalog.clock_timestamp() FROM public.\"Licenses\" WHERE \"Id\" = @licenseId";
                        query.Parameters.AddWithValue("licenseId", pendingLicenseId);
                        if ((bool)(await query.ExecuteScalarAsync())!) { expired = true; break; }
                        await Task.Delay(100);
                    }
                    Assert.True(expired);
                    Assert.False(waitingConsume.IsCompleted);
                }
                await writerTransaction.CommitAsync();
                writerCommitted = true;
                var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => waitingConsume!);
                Assert.Equal(422, denied.StatusCode);
                Assert.Equal("authority_ineligible", denied.ErrorCode);
                await using var verify = await factory.CreateDbContextAsync();
                var enrollment = await verify.RuntimeEnrollments.AsNoTracking()
                    .SingleAsync(row => row.Id == enrollmentIds[pending]);
                Assert.Equal("ACTIVE", enrollment.State);
                Assert.Equal(fixtures[pending].Version, enrollment.ReleaseVersion);
                Assert.Equal(1, enrollment.SecurityEpoch);
                Assert.Equal("ISSUED", (await verify.RuntimeEnrollmentWebSetupTransitions.AsNoTracking()
                    .SingleAsync(row => row.Id == Guid.Parse(issued[pending].Response.TransitionId))).State);
                Assert.Empty(await verify.RuntimeEnrollmentProofNonces.Where(row =>
                    row.EnrollmentId == enrollmentIds[pending] && row.Operation == "websetup-upgrade").ToListAsync());
                Assert.Equal(mutation == "expiry_wait", await verify.EnrollmentLicenseAssignments.AnyAsync(row =>
                    row.EnrollmentId == enrollmentIds[pending] && row.State == "ACTIVE"));
            }
            finally
            {
                if (!writerCommitted)
                    await writerTransaction.RollbackAsync();
                if (waitingConsume is not null)
                    try { await waitingConsume; } catch (RuntimeEnrollmentException) { }
            }
            return;
        }
        await using (var check = await factory.CreateDbContextAsync())
        {
            var transitionId = Guid.Parse(issued[pending].Response.TransitionId);
            var transition = await check.RuntimeEnrollmentWebSetupTransitions.SingleAsync(row => row.Id == transitionId);
            var epoch = await check.RuntimeEnrollmentAuthorityStates.SingleAsync();
            Assert.True(epoch.Epoch > transition.AuthorityEpoch);
            Assert.Equal("ISSUED", transition.State);
            if (mutation != null)
            {
                var binding = await check.DistributionInstallationBindings.SingleAsync(row => row.Id == fixtures[pending].BindingId);
                var originalBindingVersion = binding.Version;
                var originalInstallationId = binding.InstallationId;
                var originalLicenseId = binding.LicenseId;
                var originalSeatId = binding.LicenseSeatId;
                var originalTransitionEpoch = transition.AuthorityEpoch;
                if (mutation == "license")
                    (await check.Licenses.SingleAsync(row => row.Id == binding.LicenseId)).RevokedAt = DateTime.UtcNow;
                else if (mutation == "seat")
                    (await check.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId)).IsActive = false;
                else if (mutation == "source")
                    binding.Version = "2.3.876";
                else if (mutation == "security_epoch")
                    (await check.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentIds[pending])).SecurityEpoch++;
                else if (mutation == "installation")
                    binding.InstallationId = Guid.NewGuid().ToString("D");
                else if (mutation == "future_epoch")
                    transition.AuthorityEpoch = epoch.Epoch + 100;
                else if (mutation == "expired")
                {
                    transition.IssuedAtUtc = DateTime.UtcNow.AddMinutes(-31);
                    transition.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
                }
                else if (mutation == "target_baseline")
                    (await check.ApprovedBinaries.SingleAsync(row => row.ProductId == first.ProductId
                        && row.Version == target && row.Key == "FP_EXE")).Hash = new string('9', 64);
                else
                    throw new InvalidOperationException("Unknown authority mutation.");
                if (mutation is "source" or "installation")
                {
                    // Item 2 rejects a live binding that diverges from its ACTIVE enrollment at
                    // commit. These historical fixtures can no longer reach the WebSetup call.
                    var rejected = await Assert.ThrowsAsync<DbUpdateException>(() => check.SaveChangesAsync());
                    var postgres = Assert.IsType<Npgsql.PostgresException>(rejected.InnerException);
                    Assert.Equal(Npgsql.PostgresErrorCodes.CheckViolation, postgres.SqlState);
                    Assert.Contains("binding_mismatch", postgres.MessageText);
                    await using var unchanged = await factory.CreateDbContextAsync();
                    var persistedBinding = await unchanged.DistributionInstallationBindings.AsNoTracking()
                        .SingleAsync(row => row.Id == fixtures[pending].BindingId);
                    var persistedTransition = await unchanged.RuntimeEnrollmentWebSetupTransitions.AsNoTracking()
                        .SingleAsync(row => row.Id == transitionId);
                    Assert.Equal(originalBindingVersion, persistedBinding.Version);
                    Assert.Equal(originalInstallationId, persistedBinding.InstallationId);
                    Assert.Equal(originalLicenseId, persistedBinding.LicenseId);
                    Assert.Equal(originalSeatId, persistedBinding.LicenseSeatId);
                    Assert.Equal("ISSUED", persistedTransition.State);
                    Assert.Equal(originalTransitionEpoch, persistedTransition.AuthorityEpoch);
                    Assert.Equal(transition.SourceVersion, persistedTransition.SourceVersion);
                    Assert.Equal(transition.TargetVersion, persistedTransition.TargetVersion);
                    return;
                }
                await check.SaveChangesAsync();
            }
        }

        if (replayIssue)
        {
            if (mutation != null)
            {
                var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                    service.IssueWebSetupTransitionAsync("website-step1", issueDigests[pending], issues[pending]));
                Assert.Equal(mutation is "future_epoch" or "expired"
                    ? "websetup_transition_expired" : "authority_ineligible", error.ErrorCode);
                return;
            }
            var replay = await service.IssueWebSetupTransitionAsync("website-step1", issueDigests[pending], issues[pending]);
            Assert.True(replay.Idempotent);
            Assert.Equal(issued[pending].ExactResponseBody, replay.ExactResponseBody);
        }
        var pendingRelay = Relay(pending);
        if (mutation != null)
        {
            var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", pendingRelay.Digest, pendingRelay.Request));
            Assert.Equal(mutation switch
            {
                "source" or "installation" => "binding_ineligible",
                "security_epoch" or "future_epoch" => "websetup_transition_binding_changed",
                "target_baseline" => "release_unapproved", _ => "authority_ineligible"
            }, error.ErrorCode);
            if (mutation is "license" or "seat")
            {
                await using var denied = await factory.CreateDbContextAsync();
                var deniedEnrollment = await denied.RuntimeEnrollments.AsNoTracking()
                    .SingleAsync(row => row.Id == enrollmentIds[pending]);
                var deniedTransition = await denied.RuntimeEnrollmentWebSetupTransitions.AsNoTracking()
                    .SingleAsync(row => row.Id == Guid.Parse(issued[pending].Response.TransitionId));
                Assert.Equal("ACTIVE", deniedEnrollment.State);
                Assert.Equal(fixtures[pending].Version, deniedEnrollment.ReleaseVersion);
                Assert.Equal(1, deniedEnrollment.SecurityEpoch);
                Assert.Equal("ISSUED", deniedTransition.State);
                Assert.Null(deniedTransition.ConsumedAtUtc);
                Assert.Empty(await denied.RuntimeEnrollmentRequests.Where(row =>
                    row.EnrollmentId == enrollmentIds[pending] && row.Operation == "websetup-upgrade").ToListAsync());
                Assert.Empty(await denied.RuntimeEnrollmentProofNonces.Where(row =>
                    row.EnrollmentId == enrollmentIds[pending] && row.Operation == "websetup-upgrade").ToListAsync());
            }
            return;
        }
        var result = await service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", pendingRelay.Digest, pendingRelay.Request);
        Assert.False(result.Idempotent);
        var retry = await service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", firstRelay.Digest, firstRelay.Request);
        Assert.True(retry.Idempotent);
        Assert.Equal(completedResult.ExactResponseBody, retry.ExactResponseBody);
        await using var final = await factory.CreateDbContextAsync();
        foreach (var id in enrollmentIds)
        {
            var enrollment = await final.RuntimeEnrollments.SingleAsync(row => row.Id == id);
            Assert.Equal(target, enrollment.ReleaseVersion);
            Assert.Equal(2, enrollment.SecurityEpoch);
        }
    }
}

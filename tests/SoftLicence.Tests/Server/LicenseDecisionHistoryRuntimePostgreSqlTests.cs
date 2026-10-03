using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Validates Runtime licence-transfer decisions using synthetic provider authority and a caller-owned bounded PostgreSQL harness.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Proves a rejected source release still records the authenticated v2 source refusal without issuing a transition or changing the commercial graph.</summary>
    [Fact]
    public Task WebSetupTransitionV2_SourceReleaseRefusal_PersistsHistoryWithoutGraphMutation() =>
        Tkt976_Runtime_TransferFaults_RetainOnlyDecisionAfterLeaseDisposal("source-ap-release");

    /// <summary>Exercises target quota refusal and persistence failures while source seats, target seats, ownership, bindings, receipts and encryption nonces remain unchanged.</summary>
    /// <param name="mode">Synthetic quota/post-save refusal, insertion/commit fault, client/host cancellation or bounded timeout.</param>
    /// <remarks>The real transfer prepares and confirms an enrolled source before attempting an authenticated target entitlement. The fixture contains no production secrets; exact operation retries must not duplicate its unchanged decision.</remarks>
    [Theory]
    [InlineData("quota")]
    [InlineData("runtime-business-after-save")]
    [InlineData("insert")]
    [InlineData("commit-before")]
    [InlineData("commit-ack")]
    [InlineData("cancel-before")]
    [InlineData("cancel-after")]
    [InlineData("host-stop")]
    [InlineData("timeout")]
    [InlineData("source-release")]
    [InlineData("source-token")]
    [InlineData("source-target-untrusted")]
    [InlineData("source-unowned")]
    [InlineData("source-insert")]
    [InlineData("source-commit-before")]
    [InlineData("source-commit-ack")]
    [InlineData("source-cancel-after")]
    [InlineData("source-host-stop")]
    [InlineData("source-timeout")]
    [InlineData("source-aborted-before-rollback")]
    [InlineData("source-cancel-before")]
    public async Task Tkt976_Runtime_TransferFaults_RetainOnlyDecisionAfterLeaseDisposal(string mode)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.985");
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var dataProtection = new EphemeralDataProtectionProvider();
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(
            factory, authority, registry, crypto, Options.Create(options), dataProtectionProvider: dataProtection);

        var sourceSubjectRef = Base64Url(SHA256.HashData("websetup-source-subject"u8.ToArray()));
        var targetSubjectRef = Base64Url(SHA256.HashData("websetup-target-subject"u8.ToArray()));
        Guid sourceLicenseId;
        Guid sourceSeatId;
        Guid licenseTypeId;
        await using (var sourceSeed = await factory.CreateDbContextAsync())
        {
            var binding = await sourceSeed.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            sourceLicenseId = binding.LicenseId;
            sourceSeatId = binding.LicenseSeatId;
            binding.SubjectRefDigestSha256 = Sha256(sourceSubjectRef);
            licenseTypeId = (await sourceSeed.Licenses.SingleAsync(row => row.Id == sourceLicenseId)).LicenseTypeId;
            await sourceSeed.SaveChangesAsync();
        }

        var prepared = await service.PrepareAsync("website-step1", Sha256("websetup-v2-transfer-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("websetup-v2-transfer-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, confirm,
            Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
                prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        const string targetVersion = "2.2.987";
        var targetLicenseId = Guid.NewGuid();
        await using (var targetSeed = await factory.CreateDbContextAsync())
        {
            targetSeed.Licenses.Add(new License
            {
                Id = targetLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = licenseTypeId,
                LicenseKey = "RUNTIME-TRANSFER-" + Guid.NewGuid().ToString("N"),
                IsActive = true,
                MaxSeats = mode == "runtime-business-after-save" || mode.StartsWith("source-", StringComparison.Ordinal) ? 1 : 2,
                AllowedVersions = "2.2.*",
                ExpirationDate = DateTime.UtcNow.AddDays(30)
            });
            foreach (var binary in new[] { ("FP_CORE", '1'), ("FP_DLL", '2'), ("FP_EXE", '3') })
                targetSeed.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = fixture.ProductId,
                    Version = targetVersion,
                    Key = binary.Item1,
                    Hash = new string(binary.Item2, 64),
                    Source = ApprovedBinaryService.ReleaseSource
                });
            var sourceLicense = await targetSeed.Licenses.SingleAsync(row => row.Id == sourceLicenseId);
            sourceLicense.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
            sourceLicense.AllowedVersions = "9.*";
            await targetSeed.SaveChangesAsync();
        }

        var targetGrantRef = Guid.NewGuid().ToString("D");
        var distribution = new DistributionInstallationBindingService(
            factory, dataProtection, TimeProvider.System,
            TestHardwareAuthorityAliasResolver.Instance);
        var entitlementRequest = new DistributionEntitlementIssueRequest
        {
            Schema = DistributionInstallationBindingService.IssueV3Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = targetLicenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(targetGrantRef),
            SubjectRef = targetSubjectRef
        };
        var entitlement = await distribution.IssueEntitlementAsync(
            "website-step1", Sha256(JsonSerializer.Serialize(entitlementRequest)), entitlementRequest);
        var issue = new RuntimeWebSetupTransitionIssueRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupTransitionIssueV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            SourceLicenseId = sourceLicenseId.ToString("D"),
            SourceSubjectRef = sourceSubjectRef,
            TargetGrantRef = targetGrantRef,
            TargetLicenseId = targetLicenseId.ToString("D"),
            TargetSubjectRef = targetSubjectRef,
            TargetEntitlementRef = entitlement.Response.EntitlementRef,
            SourceVersion = fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = $"TiaConnect-Setup_v{targetVersion}.msi",
            TargetInstallerSha256 = new string('4', 64)
        };
        if (mode.StartsWith("source-", StringComparison.Ordinal))
        {
            var sourceMode = mode[7..];
            var sourceFaulted = sourceMode is "insert" or "commit-before" or "commit-ack" or "host-stop" or "timeout";
            if (sourceMode == "ap-release")
            {
                await using var change = await factory.CreateDbContextAsync();
                Assert.Equal(1, await change.ApprovedBinaries.Where(row => row.ProductId == fixture.ProductId
                    && row.Version == fixture.Version && row.Key == "FP_EXE").ExecuteDeleteAsync());
            }
            if (mode == "source-release" || sourceFaulted || sourceMode is "cancel-after" or "aborted-before-rollback")
            {
                await using var change = await factory.CreateDbContextAsync();
                await change.ApprovedBinaries.Where(row => row.ProductId == fixture.ProductId && row.Version == targetVersion).ExecuteDeleteAsync();
            }
            if (mode == "source-token") issue.TargetEntitlementRef = new string('X', 80);
            if (mode == "source-target-untrusted") issue.TargetLicenseId = Guid.NewGuid().ToString("D");
            var sourceBefore = await Tkt976_BusinessFingerprintAsync(connections.App);
            var sourceObserver = new Tkt976EarlySqlObserver { Armed = true };
            using var sourceRequestCancellation = new CancellationTokenSource();
            using var sourceShutdown = new CancellationTokenSource();
            var sourceFault = new Tkt976FaultState(sourceMode, sourceRequestCancellation, sourceShutdown) { Armed = true };
            var sourceService = new RuntimeEnrollmentService(new Tkt976EarlyFactory(connections.App, sourceObserver, sourceFault),
                authority, registry, crypto, Options.Create(options), dataProtectionProvider: dataProtection,
                applicationLifetime: new Tkt976HostLifetime(sourceShutdown));
            var client = mode == "source-unowned" ? "synthetic-other-client" : "website-step1";
            if (sourceMode == "cancel-before")
            {
                sourceRequestCancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sourceService.IssueWebSetupTransitionAsync(
                    client, Sha256(JsonSerializer.Serialize(issue)), issue, sourceRequestCancellation.Token));
                Assert.Equal(sourceBefore, await Tkt976_BusinessFingerprintAsync(connections.App));
                await using var canceledObserved = await factory.CreateDbContextAsync();
                Assert.Empty(await canceledObserved.LicenseHistories.Where(row => row.LicenseId == sourceLicenseId
                    && row.Action == "ACTIVATION_DECISION_V1").ToListAsync());
                return;
            }
            var sourceClock = System.Diagnostics.Stopwatch.StartNew();
            var sourceResult = await Tkt976_RuntimeIssueControllerAsync(sourceService, options, issue, client, sourceRequestCancellation.Token);
            Assert.Equal(sourceFaulted ? 503 : mode == "source-token" ? 500 : 422, sourceResult.StatusCode);
            if (sourceMode == "cancel-after") Assert.True(sourceRequestCancellation.IsCancellationRequested);
            if (sourceMode == "timeout") Assert.InRange(sourceClock.Elapsed.TotalSeconds, 4.5, 15);
            Assert.Equal(sourceBefore, await Tkt976_BusinessFingerprintAsync(connections.App));
            if (sourceMode == "aborted-before-rollback")
            {
                Assert.True(sourceFault.Triggered);
                Assert.All(sourceObserver.BusinessWriteTables, table => Assert.Contains(table, new[] { "Licenses", "LicenseHistories" }));
            }
            else Assert.All(sourceObserver.BusinessWriteTables, table => Assert.Equal("LicenseHistories", table));
            Assert.Contains(sourceObserver.Commands, command => command.Contains("FOR UPDATE", StringComparison.Ordinal));
            await using var sourceObserved = await factory.CreateDbContextAsync();
            var sourceRows = await sourceObserved.LicenseHistories.Where(row => row.Action == "ACTIVATION_DECISION_V1"
                && (row.LicenseId == sourceLicenseId || row.LicenseId == targetLicenseId)).ToListAsync();
            if (mode == "source-unowned" || sourceFaulted && sourceMode != "commit-ack") Assert.Empty(sourceRows);
            else
            {
                var sourceRow = Assert.Single(sourceRows);
                Assert.Equal(sourceLicenseId, sourceRow.LicenseId);
                var decision = JsonSerializer.Deserialize<LicenseDecisionHistory>(sourceRow.Details!,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
                Assert.Equal("runtime_transfer_from_source_target_unestablished", decision.Phase);
                Assert.Equal(mode == "source-token" ? 500 : 422, decision.HttpStatus);
                if (sourceMode == "ap-release")
                {
                    Assert.Equal("authority_ineligible", decision.Code);
                    Assert.Null(decision.ReasonCode);
                    Assert.Empty(await sourceObserved.RuntimeEnrollmentWebSetupTransitions
                        .Where(row => row.EnrollmentId == enrollmentId).ToListAsync());
                    Assert.Empty(await sourceObserved.RuntimeEnrollmentWebSetupTransitionRequests
                        .Where(row => row.ClientId == client && row.Operation == "issue"
                            && row.RequestId == issue.RequestId).ToListAsync());
                    Assert.Equal("ACTIVE", (await sourceObserved.EnrollmentLicenseAssignments
                        .SingleAsync(row => row.EnrollmentId == enrollmentId)).State);
                }
                Assert.Null(decision.Snapshot.ActiveSeats);
                Assert.Null(decision.Snapshot.SeatLimit);
                Assert.Null(decision.ResolvedHardwareId);
                Assert.Null(decision.SubmittedHardwareId);
                Assert.DoesNotContain(issue.TargetLicenseId!, sourceRow.Details!);
                Assert.DoesNotContain(issue.TargetSubjectRef!, sourceRow.Details!);
                Assert.DoesNotContain(issue.TargetEntitlementRef!, sourceRow.Details!);
            }
            if (mode != "source-unowned")
            {
                var retry = await Tkt976_RuntimeIssueControllerAsync(service, options, issue, client);
                Assert.Equal(mode == "source-token" ? 500 : 422, retry.StatusCode);
                Assert.Equal(1, await sourceObserved.LicenseHistories.CountAsync(row =>
                    row.LicenseId == sourceLicenseId && row.Action == "ACTIVATION_DECISION_V1"));
                Assert.Equal(sourceBefore, await Tkt976_BusinessFingerprintAsync(connections.App));
            }
            await using var releasedLease = await authority.AcquireMutationAsync(sourceObserved, fixture.BindingId);
            return;
        }
        if (mode != "runtime-business-after-save")
        {
            await using var quota = await factory.CreateDbContextAsync();
            // A full multi-seat target preserves the capacity refusal; mono-seat replacement is now intentional.
            for (var index = 0; index < 2; index++)
            {
                quota.LicenseSeats.Add(new LicenseSeat
                {
                    LicenseId = targetLicenseId, HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant(),
                    IsActive = true, FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow
                });
            }
            await quota.SaveChangesAsync();
        }
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        var issueDigest = Sha256(JsonSerializer.Serialize(issue));
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown) { Armed = true };
        var faultService = new RuntimeEnrollmentService(new Tkt976FaultFactory(connections.App, fault),
            authority, registry, crypto, Options.Create(options), dataProtectionProvider: dataProtection,
            applicationLifetime: new Tkt976HostLifetime(shutdown));
        if (mode == "cancel-before")
        {
            requestCancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => faultService.IssueWebSetupTransitionAsync(
                "website-step1", issueDigest, issue, requestCancellation.Token));
        }
        else
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                faultService.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue, requestCancellation.Token));
            var businessRefusal = mode is "quota" or "runtime-business-after-save" or "cancel-after";
            Assert.Equal(businessRefusal ? 422 : 503, refusal.StatusCode);
            Assert.Equal(businessRefusal
                ? mode == "runtime-business-after-save" ? "synthetic_transfer_refusal" : "seat_limit_reached"
                : "authority_unavailable", refusal.ErrorCode);
            if (mode == "commit-ack") Assert.Equal("decision_history_commit_indeterminate", refusal.DiagnosticCode);
            if (mode == "runtime-business-after-save") Assert.True(fault.Triggered);
            if (mode == "cancel-after") Assert.True(requestCancellation.IsCancellationRequested);
            if (mode == "timeout") Assert.InRange(clock.Elapsed.TotalSeconds, 4.5, 15);
        }
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using (var observed = await factory.CreateDbContextAsync())
        {
            var rows = await observed.LicenseHistories.Where(item =>
                item.LicenseId == targetLicenseId && item.Action == "ACTIVATION_DECISION_V1").ToListAsync();
            var durable = mode is "quota" or "runtime-business-after-save" or "cancel-after" or "commit-ack";
            Assert.Equal(durable ? 1 : 0, rows.Count);
            if (durable)
            {
                var decision = JsonSerializer.Deserialize<LicenseDecisionHistory>(rows[0].Details!,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
                Assert.Equal(mode == "runtime-business-after-save" ? "synthetic_transfer_refusal" : "seat_limit_reached", decision.Code);
                Assert.Equal(422, decision.HttpStatus);
                Assert.Equal(mode == "runtime-business-after-save" ? 0 : 2, decision.Snapshot.ActiveSeats);
                Assert.Equal(mode == "runtime-business-after-save" ? 1 : 2, decision.Snapshot.SeatLimit);
                Assert.Null(decision.SubmittedHardwareId);
                Assert.Null(decision.CorrelatedHardwareId);
                Assert.Equal((await observed.LicenseSeats.SingleAsync(item => item.Id == sourceSeatId)).HardwareId,
                    decision.ResolvedHardwareId);
            }
            await using var lockCheck = await observed.Database.BeginTransactionAsync();
            Assert.True(await observed.Database.SqlQueryRaw<bool>(
                "SELECT pg_try_advisory_xact_lock(999831, 1) AS \"Value\"").SingleAsync());
            await lockCheck.RollbackAsync();
        }
        // Retry with the original fault-free service and exact operation bytes. An unknown
        // acknowledgement must not create another refusal; a rolled-back post-save transfer
        // remains eligible for one accepted event and its existing business replay.
        if (mode == "runtime-business-after-save")
        {
            Assert.False((await service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue)).Idempotent);
            Assert.True((await service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue)).Idempotent);
        }
        else
        {
            var retry = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue));
            Assert.Equal("seat_limit_reached", retry.ErrorCode);
            Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        }
        await using var final = await factory.CreateDbContextAsync();
        Assert.Equal(mode == "runtime-business-after-save" ? 2 : 1,
            await final.LicenseHistories.CountAsync(item => item.LicenseId == targetLicenseId && item.Action == "ACTIVATION_DECISION_V1"));
    }

    /// <summary>Invokes the unchanged Runtime HTTP wrapper with actual service behavior and synthetic S2S authority to prove its public error mapping.</summary>
    /// <remarks>No middleware nonce or production authentication is exercised. The mocked principal owns only the requested fixture product; the real service still checks binding/client ownership. In particular DistributionOperationException remains generic500.</remarks>
    private static async Task<Microsoft.AspNetCore.Mvc.ObjectResult> Tkt976_RuntimeIssueControllerAsync(
        IRuntimeEnrollmentService service, RuntimeEnrollmentOptions options, RuntimeWebSetupTransitionIssueRequest request, string client,
        CancellationToken cancellationToken = default)
    {
        var s2s = new Moq.Mock<IDistributionS2SAuthenticationService>(Moq.MockBehavior.Strict);
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                Moq.It.IsAny<Microsoft.AspNetCore.Http.HttpContext>(), Moq.It.IsAny<ReadOnlyMemory<byte>>(),
                request.ProductId!, Moq.It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(client, "synthetic-key", false, true));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(request, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.RequestAborted = cancellationToken;
        context.Request.Method = "POST";
        context.Request.Path = "/api/internal/v1/runtime-enrollments/websetup-transitions";
        context.Request.ContentType = "application/json";
        context.Request.ContentLength = bytes.Length;
        context.Request.Body = new MemoryStream(bytes);
        var controller = new SoftLicence.Server.Controllers.RuntimeEnrollmentsController(s2s.Object, service, Options.Create(options))
        { ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext { HttpContext = context } };
        return Assert.IsAssignableFrom<Microsoft.AspNetCore.Mvc.ObjectResult>(await controller.IssueWebSetupTransition(cancellationToken));
    }
}

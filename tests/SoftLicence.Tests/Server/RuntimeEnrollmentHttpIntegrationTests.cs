using System.Net;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentHttpIntegrationTests
{
    private const string PreparePath = "/api/internal/v1/runtime-enrollments/prepare";
    private const string RefreshPath = "/api/internal/v1/runtime-enrollments/refresh";
    private const string EnrollmentId = "55555555-5555-4555-8555-555555555555";
    private const string ConfirmPath = "/api/v1/runtime-enrollments/" + EnrollmentId + "/confirm";
    private const string CapabilityPath = "/api/v1/runtime-enrollments/" + EnrollmentId + "/capabilities";
    private const string ClientCriticalRecoveryRefetchPath = "/api/v1/runtime-enrollments/" + EnrollmentId + "/critical-recoveries/refetch";
    private const string CriticalRecoveryPath = "/api/internal/v1/runtime-enrollments/critical-recoveries";
    private const string CriticalRecoveryRefetchPath = CriticalRecoveryPath + "/refetch";
    private const string UpgradePath = "/api/internal/v1/runtime-enrollments/upgrades";
    private const string RollbackPath = "/api/internal/v1/runtime-enrollments/recovery-rollbacks";
    private const string ConfirmBody = "{\"schema\":\"runtime-enrollment-confirm-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"enrollmentId\":\"" + EnrollmentId + "\",\"epoch\":1}";
    private const string CapabilityBody = "{\"schema\":\"runtime-enrollment-capability-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"enrollmentId\":\"" + EnrollmentId + "\",\"epoch\":1,\"securityEpoch\":1,\"audience\":\"https://broker.example.test\",\"scope\":[\"runtime.execute\"]}";
    private const string ClientCriticalRecoveryRefetchBody = "{\"schema\":\"runtime-critical-recovery-client-refetch-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"requestId\":\"77777777-7777-4777-8777-777777777777\",\"enrollmentId\":\"" + EnrollmentId + "\",\"epoch\":1,\"securityEpoch\":1}";
    private const string PrepareBody = "{\"schema\":\"runtime-enrollment-prepare-v1\",\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"protocolVersion\":\"runtime-enrollment-v1\",\"productId\":\"22222222-2222-4222-8222-222222222222\",\"bindingId\":\"33333333-3333-4333-8333-333333333333\",\"handoffDigestSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"installationId\":\"44444444-4444-4444-8444-444444444444\",\"releaseVersion\":\"2.2.844+security.1\",\"epoch\":1,\"key\":{\"alg\":\"PS256\",\"publicKeySpkiBase64\":\"AA==\",\"publicKeySpkiSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"keyThumbprint\":\"thumbprint\",\"backend\":\"software-cng-unattested\",\"attestation\":\"none\"}}";
    private const string PrepareV2Body = "{\"schema\":\"runtime-enrollment-prepare-v2\",\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"protocolVersion\":\"runtime-enrollment-v1\",\"productId\":\"22222222-2222-4222-8222-222222222222\",\"bindingId\":\"33333333-3333-4333-8333-333333333333\",\"handoffDigestSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"installationId\":\"44444444-4444-4444-8444-444444444444\",\"releaseVersion\":\"2.2.844+security.1\",\"epoch\":1,\"key\":{\"alg\":\"PS256\",\"publicKeySpkiBase64\":\"AA==\",\"publicKeySpkiSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"keyThumbprint\":\"thumbprint\",\"backend\":\"software-cng-unattested\",\"attestation\":\"none\"}}";
    private const string RefreshBody = "{\"schema\":\"runtime-enrollment-refresh-v1\",\"requestId\":\"77777777-7777-4777-8777-777777777777\",\"protocolVersion\":\"runtime-enrollment-v1\",\"productId\":\"22222222-2222-4222-8222-222222222222\",\"bindingId\":\"33333333-3333-4333-8333-333333333333\",\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"expectedChallengeDigestSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}";
    private const string RefreshV2Body = "{\"schema\":\"runtime-enrollment-refresh-v2\",\"requestId\":\"77777777-7777-4777-8777-777777777777\",\"protocolVersion\":\"runtime-enrollment-v1\",\"productId\":\"22222222-2222-4222-8222-222222222222\",\"bindingId\":\"33333333-3333-4333-8333-333333333333\",\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"expectedChallengeDigestSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"expectedSecurityEpoch\":5}";
    private const string CriticalRecoveryBody = "{\"schema\":\"runtime-critical-recovery-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"22222222-2222-4222-8222-222222222222\",\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"bindingId\":\"33333333-3333-4333-8333-333333333333\",\"installationId\":\"44444444-4444-4444-8444-444444444444\",\"eventId\":\"66666666-6666-4666-8666-666666666666\",\"oldSecurityEpoch\":1,\"newSecurityEpoch\":2}";
    private const string CriticalRecoveryRefetchBody = "{\"schema\":\"runtime-critical-recovery-refetch-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"requestId\":\"77777777-7777-4777-8777-777777777777\",\"productId\":\"22222222-2222-4222-8222-222222222222\",\"recoveryId\":\"88888888-8888-4888-8888-888888888888\",\"bindingId\":\"33333333-3333-4333-8333-333333333333\",\"installationId\":\"44444444-4444-4444-8444-444444444444\",\"eventId\":\"66666666-6666-4666-8666-666666666666\",\"newSecurityEpoch\":2}";
    private const string UpgradeBody = "{\"schema\":\"runtime-enrollment-upgrade-relay-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"authorizationBodyBase64Url\":\"eyJwcm9kdWN0SWQiOiIyMjIyMjIyMi0yMjIyLTQyMjItODIyMi0yMjIyMjIyMjIyMjIifQ\",\"proofTimestamp\":\"2026-07-24T12:00:00.0000000Z\",\"proofJti\":\"99999999-9999-4999-8999-999999999999\",\"proofSignature\":\"AA\"}";
    private const string RollbackBody = "{\"schema\":\"runtime-enrollment-recovery-rollback-relay-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"authorizationBodyBase64Url\":\"eyJwcm9kdWN0SWQiOiIyMjIyMjIyMi0yMjIyLTQyMjItODIyMi0yMjIyMjIyMjIyMjIifQ\",\"proofTimestamp\":\"2026-07-24T12:00:00.0000000Z\",\"proofJti\":\"99999999-9999-4999-8999-999999999999\",\"proofSignature\":\"AA\"}";

    [Fact]
    public async Task Upgrade_RequiresDedicatedPermission_IndependentFromCriticalRecovery()
    {
        var exact = "{\"schema\":\"runtime-enrollment-upgrade-response-v1\"}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.UpgradeAsync(
                "website-updater", "runtime-test-key", It.IsAny<string>(),
                It.IsAny<RuntimeEnrollmentUpgradeRelayRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>(
                new()
                {
                    Schema = "runtime-enrollment-upgrade-response-v1",
                    ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                    Alg = "PS256",
                    KeyId = "signing-key",
                    Audience = RuntimeEnrollmentService.UpgradeAudience,
                    Use = RuntimeEnrollmentService.UpgradeUse,
                    RequestId = "99999999-9999-4999-8999-999999999999",
                    ProductId = "22222222-2222-4222-8222-222222222222",
                    EnrollmentId = EnrollmentId,
                    BindingId = "33333333-3333-4333-8333-333333333333",
                    InstallationId = "44444444-4444-4444-8444-444444444444",
                    SourceVersion = "2.2.916",
                    TargetVersion = "2.2.924",
                    OldSecurityEpoch = 1,
                    NewSecurityEpoch = 2,
                    RecoveryReceiptId = "77777777-7777-4777-8777-777777777777",
                    RecoveryReceiptDigestSha256 = new string('a', 64),
                    Decision = "upgraded",
                    IssuedAtUtc = "2026-07-24T12:00:00.0000000Z",
                    ExpiresAtUtc = "2026-07-24T12:05:00.0000000Z",
                    Signature = new string('A', 512)
                }, false, exact));

        using (var deniedFactory = CreateFactory(enrollment.Object, allowRuntimeRecovery: true))
        using (var deniedClient = deniedFactory.CreateClient())
        using (var denied = await deniedClient.PostAsync(
                   UpgradePath,
                   new StringContent(UpgradeBody, Encoding.UTF8, "application/json")))
        {
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            AssertNoStore(denied);
        }

        using var factory = CreateFactory(enrollment.Object, allowRuntimeUpgrade: true);
        using var client = factory.CreateClient();
        using var response = await client.PostAsync(
            UpgradePath,
            new StringContent(UpgradeBody, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(exact, await response.Content.ReadAsByteArrayAsync());
        AssertNoStore(response);
        enrollment.Verify(service => service.UpgradeAsync(
            "website-updater", "runtime-test-key", It.IsAny<string>(),
            It.IsAny<RuntimeEnrollmentUpgradeRelayRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Rollback_RequiresRecoveryPermission_IndependentFromUpgrade()
    {
        var exact = "{\"schema\":\"runtime-enrollment-recovery-rollback-response-v1\"}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.RollbackAsync(
                "security-operator", "runtime-test-key", It.IsAny<string>(),
                It.IsAny<RuntimeEnrollmentUpgradeRelayRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>(
                new()
                {
                    Schema = RuntimeEnrollmentService.RollbackResponseSchema,
                    ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                    Alg = "PS256",
                    KeyId = "signing-key",
                    Audience = RuntimeEnrollmentService.RollbackAudience,
                    Use = RuntimeEnrollmentService.RollbackUse,
                    RequestId = "99999999-9999-4999-8999-999999999999",
                    ProductId = "22222222-2222-4222-8222-222222222222",
                    EnrollmentId = EnrollmentId,
                    BindingId = "33333333-3333-4333-8333-333333333333",
                    InstallationId = "44444444-4444-4444-8444-444444444444",
                    SourceVersion = "2.2.935",
                    TargetVersion = "2.2.924",
                    OldSecurityEpoch = 2,
                    NewSecurityEpoch = 3,
                    RecoveryReceiptId = "77777777-7777-4777-8777-777777777777",
                    RecoveryReceiptDigestSha256 = new string('a', 64),
                    Decision = "rolled_back",
                    IssuedAtUtc = "2026-07-24T12:00:00.0000000Z",
                    ExpiresAtUtc = "2026-07-24T12:05:00.0000000Z",
                    Signature = new string('A', 512)
                }, false, exact));

        using (var deniedFactory = CreateFactory(enrollment.Object, allowRuntimeUpgrade: true))
        using (var deniedClient = deniedFactory.CreateClient())
        using (var denied = await deniedClient.PostAsync(
                   RollbackPath,
                   new StringContent(RollbackBody, Encoding.UTF8, "application/json")))
        {
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            AssertNoStore(denied);
        }

        using var factory = CreateFactory(enrollment.Object, allowRuntimeRecovery: true);
        using var client = factory.CreateClient();
        using var response = await client.PostAsync(
            RollbackPath,
            new StringContent(RollbackBody, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(exact, await response.Content.ReadAsByteArrayAsync());
        AssertNoStore(response);
        enrollment.Verify(service => service.RollbackAsync(
            "security-operator", "runtime-test-key", It.IsAny<string>(),
            It.IsAny<RuntimeEnrollmentUpgradeRelayRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CriticalRecovery_RealHttpRoute_IsS2sGatedFrozenAndNoStore()
    {
        var exact = "{\"schema\":\"runtime-critical-recovery-receipt-v1\"}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.RecoverCriticalAsync(
                "security-operator", "runtime-test-key", It.IsAny<string>(),
                It.IsAny<RuntimeCriticalRecoveryRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                new()
                {
                    Schema = RuntimeEnrollmentService.CriticalRecoveryResponseSchema,
                    ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                    Alg = "PS256",
                    KeyId = "signing-key",
                    Audience = RuntimeEnrollmentService.CriticalRecoveryAudience,
                    Use = RuntimeEnrollmentService.CriticalRecoveryUse,
                    RecoveryId = Guid.NewGuid().ToString("D"),
                    RequestId = Guid.NewGuid().ToString("D"),
                    ProductId = "22222222-2222-4222-8222-222222222222",
                    EnrollmentId = EnrollmentId,
                    BindingId = "33333333-3333-4333-8333-333333333333",
                    InstallationId = "44444444-4444-4444-8444-444444444444",
                    EventId = "66666666-6666-4666-8666-666666666666",
                    OldSecurityEpoch = 1,
                    NewSecurityEpoch = 2,
                    Decision = "recovered",
                    IssuedAtUtc = "2026-07-19T18:00:00.0000000Z",
                    ExpiresAtUtc = "2026-07-20T18:00:00.0000000Z",
                    Signature = new string('A', 512)
                }, false, exact));
        using var factory = CreateFactory(enrollment.Object, allowRuntimeRecovery: true);
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(
            CriticalRecoveryPath,
            new StringContent(CriticalRecoveryBody, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(exact, await response.Content.ReadAsByteArrayAsync());
        AssertNoStore(response);
    }

    [Fact]
    public async Task CriticalRecoveryRefetch_RealHttpRoute_IsStrictPermissionGatedFrozenAndNoStore()
    {
        var exact = "{\"schema\":\"runtime-critical-recovery-receipt-v1\",\"refetch\":true}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.RefetchCriticalRecoveryAsync(
                "security-operator", "runtime-test-key", It.IsAny<string>(),
                It.IsAny<RuntimeCriticalRecoveryRefetchRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                new()
                {
                    Schema = RuntimeEnrollmentService.CriticalRecoveryResponseSchema,
                    ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                    Alg = "PS256",
                    KeyId = "signing-key",
                    Audience = RuntimeEnrollmentService.CriticalRecoveryAudience,
                    Use = RuntimeEnrollmentService.CriticalRecoveryUse,
                    RecoveryId = "88888888-8888-4888-8888-888888888888",
                    RequestId = "77777777-7777-4777-8777-777777777777",
                    ProductId = "22222222-2222-4222-8222-222222222222",
                    EnrollmentId = EnrollmentId,
                    BindingId = "33333333-3333-4333-8333-333333333333",
                    InstallationId = "44444444-4444-4444-8444-444444444444",
                    EventId = "66666666-6666-4666-8666-666666666666",
                    OldSecurityEpoch = 1,
                    NewSecurityEpoch = 2,
                    Decision = "recovered",
                    IssuedAtUtc = "2026-07-19T18:00:00.0000000Z",
                    ExpiresAtUtc = "2026-07-20T18:00:00.0000000Z",
                    Signature = new string('A', 512)
                }, false, exact));

        using (var deniedFactory = CreateFactory(enrollment.Object))
        using (var deniedClient = deniedFactory.CreateClient())
        using (var denied = await deniedClient.PostAsync(
                   CriticalRecoveryRefetchPath,
                   new StringContent(CriticalRecoveryRefetchBody, Encoding.UTF8, "application/json")))
        {
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            AssertNoStore(denied);
        }

        using var factory = CreateFactory(enrollment.Object, allowRuntimeRecovery: true);
        using var client = factory.CreateClient();
        using var strict = await client.PostAsync(
            CriticalRecoveryRefetchPath + "?unexpected=1",
            new StringContent(CriticalRecoveryRefetchBody, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, strict.StatusCode);
        AssertNoStore(strict);

        using var response = await client.PostAsync(
            CriticalRecoveryRefetchPath,
            new StringContent(CriticalRecoveryRefetchBody, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(exact, await response.Content.ReadAsByteArrayAsync());
        AssertNoStore(response);
        enrollment.Verify(service => service.RefetchCriticalRecoveryAsync(
            "security-operator", "runtime-test-key", It.IsAny<string>(),
            It.IsAny<RuntimeCriticalRecoveryRefetchRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ClientCriticalRecoveryRefetch_RealHttpRoute_IsDpopBoundFrozenAndNoStore()
    {
        var exact = "{\"schema\":\"runtime-critical-recovery-receipt-v1\"}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.RefetchCriticalRecoveryForClientAsync(
                Guid.Parse(EnrollmentId), It.IsAny<string>(),
                It.IsAny<RuntimeCriticalRecoveryClientRefetchRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<IPAddress>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                new()
                {
                    Schema = RuntimeEnrollmentService.CriticalRecoveryResponseSchema,
                    ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                    Alg = "PS256",
                    KeyId = "signing-key",
                    Audience = RuntimeEnrollmentService.CriticalRecoveryAudience,
                    Use = RuntimeEnrollmentService.CriticalRecoveryUse,
                    RecoveryId = "88888888-8888-4888-8888-888888888888",
                    RequestId = "77777777-7777-4777-8777-777777777777",
                    ProductId = "22222222-2222-4222-8222-222222222222",
                    EnrollmentId = EnrollmentId,
                    BindingId = "33333333-3333-4333-8333-333333333333",
                    InstallationId = "44444444-4444-4444-8444-444444444444",
                    EventId = "66666666-6666-4666-8666-666666666666",
                    OldSecurityEpoch = 1,
                    NewSecurityEpoch = 2,
                    Decision = "recovered",
                    IssuedAtUtc = "2026-07-19T18:00:00.0000000Z",
                    ExpiresAtUtc = "2026-07-20T18:00:00.0000000Z",
                    Signature = new string('A', 512)
                }, false, exact));
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        using var response = await PostPublicAsync(
            client, ClientCriticalRecoveryRefetchPath, ClientCriticalRecoveryRefetchBody);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(exact, await response.Content.ReadAsByteArrayAsync());
        AssertNoStore(response);
        enrollment.Verify(service => service.RefetchCriticalRecoveryForClientAsync(
            Guid.Parse(EnrollmentId), It.IsAny<string>(),
            It.Is<RuntimeCriticalRecoveryClientRefetchRequest>(request => request.SecurityEpoch == 1),
            It.IsAny<RuntimeProofHeaders>(), It.IsAny<IPAddress>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Prepare_ReturnsFrozenExactBytes_StatusAndNoStoreAcrossReplay()
    {
        var exact = Encoding.UTF8.GetBytes("{\"schema\":\"runtime-enrollment-prepare-response-v1\",\"status\":\"pending\"}");
        var calls = 0;
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.PrepareAsync(
                "website-step1", It.IsAny<string>(), It.IsAny<RuntimeEnrollmentPrepareRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                new("runtime-enrollment-prepare-response-v1", "runtime-enrollment-v1", "pending",
                    "55555555-5555-4555-8555-555555555555", 1, "challenge", "2026-07-19T04:00:00.0000000Z",
                    "https://runtime.example.test"),
                Interlocked.Increment(ref calls) > 1,
                exact));
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        using var first = await PostPrepareAsync(client);
        using var replay = await PostPrepareAsync(client);

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(exact, await first.Content.ReadAsByteArrayAsync());
        Assert.Equal(exact, await replay.Content.ReadAsByteArrayAsync());
        Assert.Contains("no-store", first.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
        Assert.Contains("no-store", replay.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrepareV2_PreservesNegotiatedSchemaAndAuthoritativeSecurityEpoch()
    {
        var exact = Encoding.UTF8.GetBytes("{\"schema\":\"runtime-enrollment-prepare-response-v2\",\"securityEpoch\":5}");
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.PrepareAsync(
                "website-step1", It.IsAny<string>(),
                It.Is<RuntimeEnrollmentPrepareRequest>(request =>
                    request.Schema == RuntimeEnrollmentService.PrepareV2Schema),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                new(RuntimeEnrollmentService.PrepareV2ResponseSchema, RuntimeEnrollmentService.ProtocolVersion,
                    "pending", EnrollmentId, 1, "challenge", "2026-07-19T04:00:00.0000000Z",
                    "https://runtime.example.test") { SecurityEpoch = 5 },
                false,
                exact));
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(
            PreparePath, new StringContent(PrepareV2Body, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(exact, await response.Content.ReadAsByteArrayAsync());
        AssertNoStore(response);
    }

    [Fact]
    public async Task Refresh_WithoutLicenseBootstrapPermission_IsForbiddenBeforeServiceCall()
    {
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(
            RefreshPath, new StringContent(RefreshBody, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("{\"error\":\"license_bootstrap_forbidden\"}", await response.Content.ReadAsStringAsync());
        AssertNoStore(response);
        enrollment.Verify(service => service.RefreshPendingAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<RuntimeEnrollmentRefreshRequest>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Refresh_ReturnsFrozenExactBytes_StatusAndNoStoreAcrossReplay()
    {
        var exact = Encoding.UTF8.GetBytes("{\"schema\":\"runtime-enrollment-refresh-response-v1\",\"status\":\"pending\"}");
        var calls = 0;
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.RefreshPendingAsync(
                "website-step1", It.IsAny<string>(),
                It.Is<RuntimeEnrollmentRefreshRequest>(request =>
                    request.ProductId == "22222222-2222-4222-8222-222222222222"
                    && request.BindingId == "33333333-3333-4333-8333-333333333333"
                    && request.EnrollmentId == EnrollmentId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                new(RuntimeEnrollmentService.RefreshResponseSchema, RuntimeEnrollmentService.ProtocolVersion,
                    "pending", EnrollmentId, 1, "challenge", "2026-07-19T04:05:00.0000000Z",
                    "https://runtime.example.test"),
                Interlocked.Increment(ref calls) > 1,
                exact));
        using var factory = CreateFactory(enrollment.Object, allowLicenseBootstrap: true);
        using var client = factory.CreateClient();

        using var first = await client.PostAsync(
            RefreshPath, new StringContent(RefreshBody, Encoding.UTF8, "application/json"));
        using var replay = await client.PostAsync(
            RefreshPath, new StringContent(RefreshBody, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(exact, await first.Content.ReadAsByteArrayAsync());
        Assert.Equal(exact, await replay.Content.ReadAsByteArrayAsync());
        AssertNoStore(first);
        AssertNoStore(replay);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        IReadOnlyList<AccessLog> logs = [];
        for (var attempt = 0; attempt < 50; attempt++)
        {
            await using var db = await dbFactory.CreateDbContextAsync();
            logs = await db.AccessLogs.AsNoTracking()
                .Where(log => log.Path == RefreshPath).ToListAsync();
            if (logs.Count == 2)
                break;
            await Task.Delay(20);
        }
        Assert.Equal(2, logs.Count);
        Assert.All(logs, log =>
        {
            Assert.Equal("[REDACTED]", log.RequestBody);
            Assert.Null(log.ErrorDetails);
            Assert.Empty(log.LicenseKey);
            Assert.Empty(log.HardwareId);
            Assert.DoesNotContain("challenge", log.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task RefreshV2_PreservesExpectedAndAuthoritativeSecurityEpoch()
    {
        var exact = Encoding.UTF8.GetBytes("{\"schema\":\"runtime-enrollment-refresh-response-v2\",\"securityEpoch\":5}");
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.RefreshPendingAsync(
                "website-step1", It.IsAny<string>(),
                It.Is<RuntimeEnrollmentRefreshRequest>(request =>
                    request.Schema == RuntimeEnrollmentService.RefreshV2Schema
                    && request.ExpectedSecurityEpoch == 5),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                new(RuntimeEnrollmentService.RefreshV2ResponseSchema, RuntimeEnrollmentService.ProtocolVersion,
                    "pending", EnrollmentId, 1, "challenge", "2026-07-19T04:05:00.0000000Z",
                    "https://runtime.example.test") { SecurityEpoch = 5 },
                false,
                exact));
        using var factory = CreateFactory(enrollment.Object, allowLicenseBootstrap: true);
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(
            RefreshPath, new StringContent(RefreshV2Body, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(exact, await response.Content.ReadAsByteArrayAsync());
        AssertNoStore(response);
    }

    [Theory]
    [InlineData("uppercase-product")]
    [InlineData("uppercase-digest")]
    [InlineData("whitespace-enrollment")]
    [InlineData("unknown-member")]
    public async Task Refresh_NonCanonicalOrExtendedStrings_AreRejectedBeforeAuthority(string mutation)
    {
        var authority = new Mock<IRuntimeEnrollmentAuthorityService>();
        var registry = new Mock<IRuntimeEnrollmentKeyRegistryService>();
        var crypto = new Mock<IRuntimeEnrollmentCryptoService>();
        using var factory = CreateRealServiceFactory(authority.Object, registry.Object, crypto.Object);
        using var client = factory.CreateClient();
        var body = mutation switch
        {
            "uppercase-product" => RefreshBody.Replace(
                "22222222-2222-4222-8222-222222222222",
                "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", StringComparison.Ordinal),
            "uppercase-digest" => RefreshBody.Replace(new string('a', 64), new string('A', 64),
                StringComparison.Ordinal),
            "whitespace-enrollment" => RefreshBody.Replace(EnrollmentId, " " + EnrollmentId,
                StringComparison.Ordinal),
            _ => RefreshBody[..^1] + ",\"unexpected\":true}"
        };

        using var response = await client.PostAsync(
            RefreshPath, new StringContent(body, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertNoStore(response);
        authority.VerifyNoOtherCalls();
        registry.VerifyNoOtherCalls();
        crypto.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Prepare_RateLimit429_IsNoStore()
    {
        var exact = "{}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.PrepareAsync(
                "website-step1", It.IsAny<string>(), It.IsAny<RuntimeEnrollmentPrepareRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                new("runtime-enrollment-prepare-response-v1", "runtime-enrollment-v1", "pending",
                    "55555555-5555-4555-8555-555555555555", 1, "challenge", "2026-07-19T04:00:00.0000000Z",
                    "https://runtime.example.test"), false, exact));
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        HttpResponseMessage? rejected = null;
        for (var index = 0; index < 121; index++)
        {
            var response = await PostPrepareAsync(client);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                rejected = response;
                break;
            }
            response.Dispose();
        }

        Assert.NotNull(rejected);
        using (rejected)
        {
            Assert.Contains("no-store", rejected.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
            Assert.Contains("no-cache", rejected.Headers.Pragma.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Prepare_NonCanonicalSemVer_IsRejectedByRealServiceBeforeAuthorityAccess()
    {
        var authority = new Mock<IRuntimeEnrollmentAuthorityService>();
        var registry = new Mock<IRuntimeEnrollmentKeyRegistryService>();
        var crypto = new Mock<IRuntimeEnrollmentCryptoService>();
        using var factory = CreateRealServiceFactory(authority.Object, registry.Object, crypto.Object);
        using var client = factory.CreateClient();
        var body = PrepareBody.Replace("2.2.844+security.1", "2.2.0-01", StringComparison.Ordinal);

        using var response = await client.PostAsync(
            PreparePath, new StringContent(body, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertNoStore(response);
        authority.VerifyNoOtherCalls();
        registry.VerifyNoOtherCalls();
        crypto.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ConfirmAndCapability_ReturnFrozenBytes_AndAuditPayloadsAreRedacted()
    {
        var confirmBytes = "{\"status\":\"active\"}"u8.ToArray();
        var capabilityBytes = "{\"capabilityToken\":\"secret-token\"}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.ConfirmAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<RuntimeEnrollmentConfirmRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<IPAddress>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>(
                new("runtime-enrollment-confirm-response-v1", "runtime-enrollment-v1", "active", EnrollmentId, 1,
                    "2026-07-19T04:00:00.0000000Z"), false, confirmBytes));
        enrollment.Setup(service => service.CreateCapabilityAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<RuntimeEnrollmentCapabilityRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<IPAddress>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>(
                new("runtime-enrollment-capability-response-v1", "runtime-enrollment-v1", "secret-token",
                    "2026-07-19T04:02:00.0000000Z"), false, capabilityBytes));
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        using var confirm = await PostPublicAsync(client, ConfirmPath, ConfirmBody);
        using var capability = await PostPublicAsync(client, CapabilityPath, CapabilityBody);

        Assert.Equal(confirmBytes, await confirm.Content.ReadAsByteArrayAsync());
        Assert.Equal(capabilityBytes, await capability.Content.ReadAsByteArrayAsync());
        AssertNoStore(confirm);
        AssertNoStore(capability);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        IReadOnlyList<AccessLog> logs = [];
        for (var attempt = 0; attempt < 50; attempt++)
        {
            await using var db = await dbFactory.CreateDbContextAsync();
            logs = await db.AccessLogs.AsNoTracking()
                .Where(log => log.Path == ConfirmPath || log.Path == CapabilityPath)
                .ToListAsync();
            if (logs.Count == 2)
                break;
            await Task.Delay(20);
        }
        Assert.Equal(2, logs.Count);
        Assert.All(logs, log =>
        {
            Assert.Equal("[REDACTED]", log.RequestBody);
            Assert.Null(log.ErrorDetails);
            Assert.Empty(log.LicenseKey);
            Assert.Empty(log.HardwareId);
            Assert.DoesNotContain("secret-token", log.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
        });
    }

    [Theory]
    [InlineData("GET", ConfirmPath, ConfirmBody, null, 405)]
    [InlineData("POST", ConfirmPath + "/extra", ConfirmBody, null, 404)]
    [InlineData("POST", ConfirmPath + "?x=1", ConfirmBody, null, 400)]
    [InlineData("POST", ConfirmPath, "{\"schema\":\"x\",\"schema\":\"y\"}", null, 400)]
    [InlineData("POST", ConfirmPath, ConfirmBody, "text/plain", 415)]
    public async Task RuntimePrefix_RoutingAndTransportFailures_AreNoStore(
        string method, string path, string body, string? contentType, int expectedStatus)
    {
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(new HttpMethod(method), path)
        {
            Content = new StringContent(body, Encoding.UTF8, contentType ?? "application/json")
        };
        AddProofHeaders(request);

        using var response = await client.SendAsync(request);

        Assert.Equal(expectedStatus, (int)response.StatusCode);
        AssertNoStore(response);
    }

    [Fact]
    public async Task RuntimePrefix_409_413_422_And500_AreNoStore()
    {
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.SetupSequence(service => service.ConfirmAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<RuntimeEnrollmentConfirmRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<IPAddress>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RuntimeEnrollmentException("idempotency_conflict", 409))
            .ThrowsAsync(new RuntimeEnrollmentException("authority_ineligible", 422))
            .ThrowsAsync(new InvalidOperationException("test-only failure"));
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        foreach (var status in new[] { 409, 422, 500 })
        {
            using var response = await PostPublicAsync(client, ConfirmPath, ConfirmBody);
            Assert.Equal(status, (int)response.StatusCode);
            AssertNoStore(response);
        }
        using var oversized = await PostPublicAsync(client, ConfirmPath, new string('x', 4097));
        Assert.Equal(413, (int)oversized.StatusCode);
        AssertNoStore(oversized);
    }

    [Fact]
    public async Task Confirm_MissingProofHeaders_Returns401NoStore()
    {
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(
            ConfirmPath, new StringContent(ConfirmBody, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        AssertNoStore(response);
    }

    [Fact]
    public async Task ForwardedHeaders_StopsAtFirstUntrustedProxy_ForProofQuotaAddress()
    {
        IPAddress? observed = null;
        var exact = "{}"u8.ToArray();
        var enrollment = new Mock<IRuntimeEnrollmentService>();
        enrollment.Setup(service => service.ConfirmAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<RuntimeEnrollmentConfirmRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<IPAddress>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, string, RuntimeEnrollmentConfirmRequest, RuntimeProofHeaders, IPAddress?, CancellationToken>(
                (_, _, _, _, address, _) => observed = address)
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>(
                new("runtime-enrollment-confirm-response-v1", "runtime-enrollment-v1", "active", EnrollmentId, 1,
                    "2026-07-19T04:00:00.0000000Z"), false, exact));
        using var factory = CreateFactory(enrollment.Object);
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, ConfirmPath)
        {
            Content = new StringContent(ConfirmBody, Encoding.UTF8, "application/json")
        };
        AddProofHeaders(request);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.10, 198.51.100.20");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(IPAddress.Parse("198.51.100.20"), observed);
        Assert.NotEqual(IPAddress.Parse("203.0.113.10"), observed);
        AssertNoStore(response);
    }

    private static WebApplicationFactory<Program> CreateFactory(
        IRuntimeEnrollmentService enrollment,
        bool allowRuntimeRecovery = false,
        bool allowRuntimeUpgrade = false,
        bool allowLicenseBootstrap = false)
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<Microsoft.AspNetCore.Http.HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                allowRuntimeRecovery
                    ? "security-operator"
                    : allowRuntimeUpgrade ? "website-updater" : "website-step1",
                "runtime-test-key",
                allowRuntimeRecovery,
                allowRuntimeUpgrade,
                allowLicenseBootstrap));
        var databaseName = $"runtime-http-{Guid.NewGuid():N}";
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<IDistributionS2SAuthenticationService>();
                services.RemoveAll<IRuntimeEnrollmentService>();
                services.RemoveAll<IOptions<RuntimeEnrollmentOptions>>();
                services.RemoveAll<IHostedService>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(databaseName));
                services.AddSingleton(authentication.Object);
                services.AddSingleton(enrollment);
                services.AddSingleton<IOptions<RuntimeEnrollmentOptions>>(
                    Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));
            });
        });
    }

    private static WebApplicationFactory<Program> CreateRealServiceFactory(
        IRuntimeEnrollmentAuthorityService authority,
        IRuntimeEnrollmentKeyRegistryService registry,
        IRuntimeEnrollmentCryptoService crypto)
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<Microsoft.AspNetCore.Http.HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "website-step1", "runtime-test-key", AllowLicenseBootstrap: true));
        var databaseName = $"runtime-http-semver-{Guid.NewGuid():N}";
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<IDistributionS2SAuthenticationService>();
                services.RemoveAll<IRuntimeEnrollmentService>();
                services.RemoveAll<IRuntimeEnrollmentAuthorityService>();
                services.RemoveAll<IRuntimeEnrollmentKeyRegistryService>();
                services.RemoveAll<IRuntimeEnrollmentCryptoService>();
                services.RemoveAll<IOptions<RuntimeEnrollmentOptions>>();
                services.RemoveAll<IHostedService>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(databaseName));
                services.AddSingleton(authentication.Object);
                services.AddSingleton(authority);
                services.AddSingleton(registry);
                services.AddSingleton(crypto);
                services.AddScoped<IRuntimeEnrollmentService, RuntimeEnrollmentService>();
                services.AddSingleton<IOptions<RuntimeEnrollmentOptions>>(
                    Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));
            });
        });
    }

    private static Task<HttpResponseMessage> PostPrepareAsync(HttpClient client) =>
        client.PostAsync(PreparePath, new StringContent(PrepareBody, Encoding.UTF8, "application/json"));

    private static Task<HttpResponseMessage> PostPublicAsync(HttpClient client, string path, string body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        AddProofHeaders(request);
        return client.SendAsync(request);
    }

    private static void AddProofHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("X-Runtime-Enrollment-Timestamp", "2026-07-19T04:00:00.0000000Z");
        request.Headers.TryAddWithoutValidation("X-Runtime-Enrollment-Jti", "66666666-6666-4666-8666-666666666666");
        request.Headers.TryAddWithoutValidation("X-Runtime-Enrollment-Signature", new string('A', 512));
    }

    private static void AssertNoStore(HttpResponseMessage response)
    {
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);
    }
}

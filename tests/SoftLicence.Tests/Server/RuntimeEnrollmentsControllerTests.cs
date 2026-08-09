using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentsControllerTests
{
    [Fact]
    public async Task Prepare_WhenModeIsOff_ReturnsUnavailableBeforeAuthentication()
    {
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        var service = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var controller = CreateController(s2s, service, "off", "/api/internal/v1/runtime-enrollments/prepare", "{}");

        var result = Assert.IsType<ObjectResult>(await controller.Prepare(CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        Assert.Equal("runtime_enrollment_unavailable", Assert.IsType<SoftLicence.Server.Models.RuntimeEnrollmentApiError>(result.Value).Error);
        s2s.VerifyNoOtherCalls();
        service.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Confirm_WhenQueryIsPresent_RejectsBeforeProofService()
    {
        var service = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var id = Guid.NewGuid().ToString("D");
        var controller = CreateController(new(MockBehavior.Strict), service, "enabled",
            $"/api/v1/runtime-enrollments/{id}/confirm", "{}", "?unexpected=1");

        var result = Assert.IsType<ObjectResult>(await controller.Confirm(id, CancellationToken.None));

        Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
        service.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Capability_WhenTransferEncodingIsPresent_RejectsBeforeBodyRead()
    {
        var service = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var id = Guid.NewGuid().ToString("D");
        var controller = CreateController(new(MockBehavior.Strict), service, "enabled",
            $"/api/v1/runtime-enrollments/{id}/capabilities", "{}");
        controller.Request.Headers.TransferEncoding = "chunked";

        var result = Assert.IsType<ObjectResult>(await controller.Capability(id, CancellationToken.None));

        Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
        service.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Milestone_WithStrictBodyAndProof_ReturnsFrozenExactAck()
    {
        var enrollmentId = "11111111-1111-4111-8111-111111111111";
        var body = "{\"schema\":\"runtime-milestone-v1\",\"protocolVersion\":\"runtime-enrollment-v1\","+
            "\"enrollmentId\":\"" + enrollmentId + "\",\"epoch\":1,\"securityEpoch\":1,"+
            "\"sessionId\":\"22222222-2222-4222-8222-222222222222\",\"sequence\":1,"+
            "\"eventId\":\"33333333-3333-4333-8333-333333333333\",\"code\":\"bootstrap_entered\","+
            "\"occurredAtUtc\":\"2026-07-20T10:00:00.0000000Z\"}";
        var service = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var exact = Encoding.UTF8.GetBytes("{\"accepted\":true}");
        service.Setup(runtime => runtime.RecordMilestoneAsync(
                Guid.Parse(enrollmentId), It.IsAny<string>(), It.IsAny<RuntimeMilestoneRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<System.Net.IPAddress?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeMilestoneAckResponse>(
                new(RuntimeEnrollmentService.MilestoneAckSchema, RuntimeEnrollmentService.ProtocolVersion,
                    enrollmentId, "22222222-2222-4222-8222-222222222222", 1,
                    "33333333-3333-4333-8333-333333333333", "client_declared",
                    "2026-07-20T10:00:01.0000000Z"), false, exact));
        var controller = CreateController(new(MockBehavior.Strict), service, "enabled",
            $"/api/v1/runtime-enrollments/{enrollmentId}/milestones", body);
        controller.Request.Headers["X-Runtime-Enrollment-Timestamp"] = "2026-07-20T10:00:00.0000000Z";
        controller.Request.Headers["X-Runtime-Enrollment-Jti"] = "44444444-4444-4444-8444-444444444444";
        controller.Request.Headers["X-Runtime-Enrollment-Signature"] = new string('A', 512);

        var result = Assert.IsType<FileContentResult>(
            await controller.Milestone(enrollmentId, CancellationToken.None));

        Assert.Equal(exact, result.FileContents);
        service.VerifyAll();
    }

    [Fact]
    public async Task Confirm_WhenBodyExceedsLimit_ReturnsPayloadTooLarge()
    {
        var service = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var id = Guid.NewGuid().ToString("D");
        var controller = CreateController(new(MockBehavior.Strict), service, "enabled",
            $"/api/v1/runtime-enrollments/{id}/confirm", new string('x', 4097));

        var result = Assert.IsType<ObjectResult>(await controller.Confirm(id, CancellationToken.None));

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, result.StatusCode);
        service.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task CriticalRecovery_RequiresExplicitS2sRecoveryPermission()
    {
        var productId = Guid.NewGuid().ToString("D");
        var body = RecoveryBody(productId);
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("website-step1", "key-1"));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v1/runtime-enrollments/critical-recoveries", body);

        var result = Assert.IsType<ObjectResult>(await controller.RecoverCritical(CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        Assert.Equal("recovery_forbidden", Assert.IsType<RuntimeEnrollmentApiError>(result.Value).Error);
        runtime.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task CriticalRecovery_WhenAuthorized_ReturnsFrozenExactBody()
    {
        var productId = Guid.NewGuid().ToString("D");
        var body = RecoveryBody(productId);
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("security-operator", "key-1", true));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var response = new RuntimeCriticalRecoveryResponse
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryResponseSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            Alg = "PS256",
            KeyId = "signing-key",
            Audience = RuntimeEnrollmentService.CriticalRecoveryAudience,
            Use = RuntimeEnrollmentService.CriticalRecoveryUse,
            RecoveryId = Guid.NewGuid().ToString("D"),
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = productId,
            EnrollmentId = Guid.NewGuid().ToString("D"),
            BindingId = Guid.NewGuid().ToString("D"),
            InstallationId = Guid.NewGuid().ToString("D"),
            EventId = Guid.NewGuid().ToString("D"),
            OldSecurityEpoch = 1,
            NewSecurityEpoch = 2,
            Decision = "recovered",
            IssuedAtUtc = "2026-07-19T18:00:00.0000000Z",
            ExpiresAtUtc = "2026-07-20T18:00:00.0000000Z",
            Signature = new string('A', 512)
        };
        var exact = Encoding.UTF8.GetBytes("{\"frozen\":true}");
        runtime.Setup(service => service.RecoverCriticalAsync(
                "security-operator", "key-1", It.IsAny<string>(),
                It.IsAny<RuntimeCriticalRecoveryRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(response, false, exact));
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v1/runtime-enrollments/critical-recoveries", body);

        var result = Assert.IsType<FileContentResult>(await controller.RecoverCritical(CancellationToken.None));

        Assert.Equal(exact, result.FileContents);
        Assert.Equal(StatusCodes.Status201Created, controller.Response.StatusCode);
    }

    [Fact]
    public async Task WebSetupTransition_WhenAuthorized_ReturnsFrozenExactCapabilityBody()
    {
        var productId = Guid.NewGuid().ToString("D");
        var body = "{\"schema\":\"runtime-websetup-transition-issue-v1\"," +
            "\"requestId\":\"11111111-1111-4111-8111-111111111111\"," +
            "\"protocolVersion\":\"runtime-enrollment-v1\",\"productId\":\"" + productId + "\"," +
            "\"bindingId\":\"22222222-2222-4222-8222-222222222222\"," +
            "\"enrollmentId\":\"33333333-3333-4333-8333-333333333333\"," +
            "\"sourceVersion\":\"2.2.985\",\"targetVersion\":\"2.2.987\"," +
            "\"targetInstallerFilename\":\"TiaConnect-2.2.987.msi\"," +
            "\"targetInstallerSha256\":\"" + new string('a', 64) + "\"}";
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("website-step1", "key-1", false, true));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var response = new RuntimeWebSetupTransitionIssuedResponse(
            RuntimeEnrollmentService.WebSetupTransitionCapabilitySchema,
            RuntimeEnrollmentService.ProtocolVersion,
            "44444444-4444-4444-8444-444444444444", new string('A', 43),
            "2026-07-29T18:02:00.0000000Z");
        var exact = Encoding.UTF8.GetBytes("{\"frozen\":true}");
        runtime.Setup(service => service.IssueWebSetupTransitionAsync(
                "website-step1", It.IsAny<string>(), It.IsAny<RuntimeWebSetupTransitionIssueRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>(
                response, false, exact));
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v1/runtime-enrollments/websetup-transitions", body);

        var result = Assert.IsType<FileContentResult>(
            await controller.IssueWebSetupTransition(CancellationToken.None));

        Assert.Equal(exact, result.FileContents);
        Assert.Equal(StatusCodes.Status201Created, controller.Response.StatusCode);
        s2s.VerifyAll();
        runtime.VerifyAll();
    }

    [Fact]
    public async Task ReinstallAuthority_WhenS2sAuthenticated_ReturnsCurrentMinimalAssertion()
    {
        var productId = "11111111-1111-4111-8111-111111111111";
        var bootstrapId = "22222222-2222-4222-8222-222222222222";
        var body = "{\"schema\":\"runtime-enrollment-reinstall-authority-v1\","+
            "\"protocolVersion\":\"runtime-enrollment-v1\",\"requestId\":\"33333333-3333-4333-8333-333333333333\","+
            "\"productId\":\"" + productId + "\",\"bootstrapId\":\"" + bootstrapId + "\","+
            "\"installationId\":\"44444444-4444-4444-8444-444444444444\","+
            "\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"releaseVersion\":\"2.3.7\","+
            "\"keyThumbprint\":\"" + new string('A', 43) + "\",\"securityEpoch\":3,"+
            "\"challenge\":\"" + new string('B', 86) + "\",\"signature\":\"" + new string('C', 512) + "\"}";
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("website-step1", "key-1"));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var response = new RuntimeReinstallAuthorityResponse(
            RuntimeEnrollmentService.ReinstallAuthorityResponseSchema,
            RuntimeEnrollmentService.ProtocolVersion, "authorized",
            "33333333-3333-4333-8333-333333333333", bootstrapId, productId,
            "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777",
            "44444444-4444-4444-8444-444444444444", "2.3.7", new string('D', 43), 4,
            "88888888-8888-4888-8888-888888888888", new string('a', 64),
            "99999999-9999-4999-8999-999999999999", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        runtime.Setup(service => service.AuthorizeReinstallAsync(
                "website-step1", It.IsAny<RuntimeReinstallAuthorityRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v1/runtime-enrollments/reinstall-authorizations", body);

        var result = Assert.IsType<OkObjectResult>(await controller.AuthorizeReinstall(CancellationToken.None));

        Assert.Same(response, result.Value);
        s2s.VerifyAll();
        runtime.VerifyAll();
    }

    [Fact]
    public async Task ReinstallAuthority_LegacyV2_PreservesExactGrantAndSubjectReferences()
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        const string grantRef = "88888888-8888-4888-8888-888888888888";
        var subjectRef = new string('A', 43);
        var body = "{\"schema\":\"runtime-enrollment-reinstall-authority-v2\"," +
            "\"protocolVersion\":\"runtime-enrollment-v1\",\"requestId\":\"33333333-3333-4333-8333-333333333333\"," +
            "\"productId\":\"" + productId + "\",\"bootstrapId\":\"22222222-2222-4222-8222-222222222222\"," +
            "\"installationId\":\"44444444-4444-4444-8444-444444444444\"," +
            "\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"releaseVersion\":\"2.3.7\"," +
            "\"keyThumbprint\":\"" + new string('B', 43) + "\",\"securityEpoch\":3," +
            "\"grantRef\":\"" + grantRef + "\",\"subjectRef\":\"" + subjectRef + "\"," +
            "\"challenge\":\"" + new string('C', 86) + "\",\"signature\":\"" + new string('D', 512) + "\"}";
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("website-step1", "key-1"));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        runtime.Setup(service => service.AuthorizeReinstallAsync(
                "website-step1",
                It.Is<RuntimeReinstallAuthorityRequest>(request =>
                    request.Schema == RuntimeEnrollmentService.ReinstallAuthorityLegacyV2Schema
                    && request.GrantRef == grantRef
                    && request.SubjectRef == subjectRef),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeReinstallAuthorityResponse(
                RuntimeEnrollmentService.ReinstallAuthorityResponseSchema,
                RuntimeEnrollmentService.ProtocolVersion, "authorized",
                "33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222", productId,
                "55555555-5555-4555-8555-555555555555", "77777777-7777-4777-8777-777777777777",
                "44444444-4444-4444-8444-444444444444", "2.3.7", new string('B', 43), 3,
                grantRef, new string('a', 64), "99999999-9999-4999-8999-999999999999",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v1/runtime-enrollments/reinstall-authorizations", body);

        Assert.IsType<OkObjectResult>(await controller.AuthorizeReinstall(CancellationToken.None));
        s2s.VerifyAll();
        runtime.VerifyAll();
    }

    private static string RecoveryBody(string productId) =>
        "{\"schema\":\"runtime-critical-recovery-v1\",\"protocolVersion\":\"runtime-enrollment-v1\","
        + "\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"" + productId + "\","
        + "\"enrollmentId\":\"22222222-2222-4222-8222-222222222222\","
        + "\"bindingId\":\"33333333-3333-4333-8333-333333333333\","
        + "\"installationId\":\"44444444-4444-4444-8444-444444444444\","
        + "\"eventId\":\"55555555-5555-4555-8555-555555555555\","
        + "\"oldSecurityEpoch\":1,\"newSecurityEpoch\":2}";

    private static RuntimeEnrollmentsController CreateController(
        Mock<IDistributionS2SAuthenticationService> s2s,
        Mock<IRuntimeEnrollmentService> service,
        string mode,
        string path,
        string body,
        string query = "")
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = path;
        context.Request.QueryString = new QueryString(query);
        context.Request.ContentType = "application/json; charset=utf-8";
        context.Request.ContentLength = bytes.Length;
        context.Request.Body = new MemoryStream(bytes);
        return new RuntimeEnrollmentsController(
            s2s.Object, service.Object, Options.Create(new RuntimeEnrollmentOptions { Mode = mode }))
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }
}

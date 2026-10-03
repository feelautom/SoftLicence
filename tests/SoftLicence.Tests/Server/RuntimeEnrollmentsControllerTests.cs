using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentsControllerTests
{
    /// <summary>Proves recovery preparation authenticates the exact path/body and forwards only the bound principal.</summary>
    [Fact]
    public async Task AuthorityRecoveryPreparation_WithUpgradePrincipal_ForwardsExactAuthenticatedBody()
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        const string attemptId = "22222222-2222-4222-8222-222222222222";
        var body = "{\"productId\":\"" + productId + "\"}";
        var bytes = Encoding.UTF8.GetBytes(body);
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                It.Is<HttpContext>(context => context.Request.Path ==
                    "/api/internal/v2/runtime-enrollment-authority/recovery-preparations"),
                It.Is<ReadOnlyMemory<byte>>(actual => ExactBytes(actual, bytes)), productId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("authority-client", "transport-key", false, true, false));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        runtime.Setup(value => value.PrepareAuthorityRecoveryV2Async(
                "authority-client", "transport-key", Guid.Parse(attemptId),
                It.Is<ReadOnlyMemory<byte>>(actual => ExactBytes(actual, bytes)),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentAuthorityRecoveryPreparationResult("{}"u8.ToArray()));
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v2/runtime-enrollment-authority/recovery-preparations", body, authorityV2: true);
        controller.Request.Headers["X-Runtime-Enrollment-Attempt-Id"] = attemptId;

        var result = Assert.IsType<FileContentResult>(
            await controller.PrepareAuthorityRecoveryV2(CancellationToken.None));

        Assert.Equal("{}"u8.ToArray(), result.FileContents);
        Assert.Equal(controller.HttpContext.TraceIdentifier, controller.Response.Headers["X-Correlation-Id"]);
        Assert.Equal("REA-V2-RECOVERY-PREPARED", controller.Response.Headers["X-Support-Code"]);
        s2s.VerifyAll();
        runtime.VerifyAll();
    }

    /// <summary>Proves finalization reauthenticates exact bytes and forwards the three exact detached recovery values.</summary>
    [Fact]
    public async Task AuthorityRecoveryFinalization_WithUpgradePrincipal_ForwardsExactBindings()
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        const string attemptId = "22222222-2222-4222-8222-222222222222";
        var body = "{\"productId\":\"" + productId + "\"}";
        var bytes = Encoding.UTF8.GetBytes(body);
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                It.Is<HttpContext>(context => context.Request.Path ==
                    "/api/internal/v2/runtime-enrollment-authority/recovery-finalizations"),
                It.Is<ReadOnlyMemory<byte>>(actual => ExactBytes(actual, bytes)), productId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("authority-client", "transport-key", false, true, false));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        runtime.Setup(value => value.FinalizeAuthorityRecoveryV2Async(
                "authority-client", "transport-key", Guid.Parse(attemptId),
                It.Is<ReadOnlyMemory<byte>>(actual => ExactBytes(actual, bytes)),
                "preparation-token", "recovery-key", new string('A', 342),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentAuthorityV2OperationResult(201, "{}"u8, false));
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v2/runtime-enrollment-authority/recovery-finalizations", body, authorityV2: true);
        controller.Request.Headers["X-Runtime-Enrollment-Attempt-Id"] = attemptId;
        controller.Request.Headers["X-Runtime-Enrollment-Recovery-Preparation"] = "preparation-token";
        controller.Request.Headers["X-Runtime-Enrollment-Recovery-Key-Id"] = "recovery-key";
        controller.Request.Headers["X-Runtime-Enrollment-Recovery-Signature"] = new string('A', 342);

        var result = Assert.IsType<FileContentResult>(
            await controller.FinalizeAuthorityRecoveryV2(CancellationToken.None));

        Assert.Equal("{}"u8.ToArray(), result.FileContents);
        Assert.Equal(201, controller.Response.StatusCode);
        s2s.VerifyAll();
        runtime.VerifyAll();
    }

    /// <summary>Proves authenticated exact bytes reach v2 and an accepted result emits closed correlation diagnostics.</summary>
    [Fact]
    public async Task AuthorityGenerationV2_WithUpgradePrincipal_ForwardsExactAuthenticatedBody()
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        const string attemptId = "22222222-2222-4222-8222-222222222222";
        var body = "{\"productId\":\"" + productId + "\"}";
        var bytes = Encoding.UTF8.GetBytes(body);
        var authenticated = false;
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.Is<ReadOnlyMemory<byte>>(actual => ExactBytes(actual, bytes)),
                productId, It.IsAny<CancellationToken>()))
            .Callback<HttpContext, ReadOnlyMemory<byte>, string, CancellationToken>(
                (context, signedBody, signedProductId, _) =>
                {
                    Assert.Equal(HttpMethods.Post, context.Request.Method);
                    Assert.Equal("/api/internal/v2/runtime-enrollment-authority/generations",
                        context.Request.Path.Value);
                    Assert.True(ExactBytes(signedBody, bytes));
                    Assert.Equal(productId, signedProductId);
                    authenticated = true;
                })
            .ReturnsAsync(new DistributionS2SPrincipal("authority-client", "transport-key", false, true, false));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        runtime.Setup(value => value.IssueAuthorityGenerationV2Async(
                "authority-client", "transport-key", Guid.Parse(attemptId),
                It.Is<ReadOnlyMemory<byte>>(actual => ExactBytes(actual, bytes)), "recovery-key",
                new string('A', 342),
                It.IsAny<CancellationToken>()))
            .Callback(() => Assert.True(authenticated))
            .ReturnsAsync(new RuntimeEnrollmentAuthorityV2OperationResult(201, "{}"u8, false));
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v2/runtime-enrollment-authority/generations", body, authorityV2: true);
        controller.Request.Headers["X-Runtime-Enrollment-Attempt-Id"] = attemptId;
        controller.Request.Headers["X-Runtime-Enrollment-Recovery-Key-Id"] = "recovery-key";
        controller.Request.Headers["X-Runtime-Enrollment-Recovery-Signature"] = new string('A', 342);

        var result = Assert.IsType<FileContentResult>(
            await controller.IssueAuthorityGenerationV2(CancellationToken.None));

        Assert.Equal("{}"u8.ToArray(), result.FileContents);
        s2s.VerifyAll();
        runtime.VerifyAll();
    }

    /// <summary>Proves a denied authenticated principal receives redacted terminal diagnostics before v2 service use.</summary>
    [Fact]
    public async Task AuthorityGenerationV2_WithoutUpgradePermission_FailsBeforeService()
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "authority-client", "transport-key", true, false, false));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var logger = new Mock<ILogger<RuntimeEnrollmentsController>>();
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v2/runtime-enrollment-authority/generations",
            "{\"productId\":\"" + productId + "\"}", logger: logger.Object, authorityV2: true);
        controller.HttpContext.TraceIdentifier = "correlation-item4";

        var result = Assert.IsType<ObjectResult>(
            await controller.IssueAuthorityGenerationV2(CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        Assert.Equal("correlation-item4", controller.Response.Headers["X-Correlation-Id"]);
        Assert.Equal("REA-V2-AUTHORIZATION", controller.Response.Headers["X-Support-Code"]);
        logger.Verify(entry => entry.Log(
            LogLevel.Warning,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((value, _) =>
                value.ToString()!.Contains("REFUSED", StringComparison.Ordinal)
                && value.ToString()!.Contains("REA-V2-AUTHORIZATION", StringComparison.Ordinal)
                && value.ToString()!.Contains("correlation-item4", StringComparison.Ordinal)
                && value.ToString()!.Contains("AUTHORITY_AUTHORIZATION", StringComparison.Ordinal)
                && !value.ToString()!.Contains(productId, StringComparison.Ordinal)
                && !value.ToString()!.Contains("authority-client", StringComparison.Ordinal)
                && !value.ToString()!.Contains("transport-key", StringComparison.Ordinal)),
            null,
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
        runtime.VerifyNoOtherCalls();
    }

    /// <summary>Proves v2 cannot activate while global Runtime Enrollment remains disabled.</summary>
    [Fact]
    public async Task AuthorityGenerationV2_GlobalModeOff_FailsBeforeAuthentication()
    {
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var controller = CreateController(s2s, runtime, "off",
            "/api/internal/v2/runtime-enrollment-authority/generations",
            "{\"productId\":\"11111111-1111-4111-8111-111111111111\"}", authorityV2: true);

        var result = Assert.IsType<ObjectResult>(
            await controller.IssueAuthorityGenerationV2(CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        s2s.VerifyNoOtherCalls();
        runtime.VerifyNoOtherCalls();
    }

    /// <summary>Proves authentication refusal emits redacted terminal diagnostics without invoking v2 persistence.</summary>
    [Fact]
    public async Task AuthorityGenerationV2_AuthenticationFailure_DoesNotInvokeService()
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId,
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionS2SAuthenticationException(
                "invalid_signature", StatusCodes.Status401Unauthorized));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var logger = new Mock<ILogger<RuntimeEnrollmentsController>>();
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v2/runtime-enrollment-authority/generations",
            "{\"productId\":\"" + productId + "\"}", logger: logger.Object, authorityV2: true);
        controller.HttpContext.TraceIdentifier = "correlation-item4";

        var result = Assert.IsType<ObjectResult>(
            await controller.IssueAuthorityGenerationV2(CancellationToken.None));

        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Equal("correlation-item4", controller.Response.Headers["X-Correlation-Id"]);
        Assert.Equal("REA-V2-AUTHENTICATION", controller.Response.Headers["X-Support-Code"]);
        logger.Verify(entry => entry.Log(
            LogLevel.Warning,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((value, _) =>
                value.ToString()!.Contains("REFUSED", StringComparison.Ordinal)
                && value.ToString()!.Contains("REA-V2-AUTHENTICATION", StringComparison.Ordinal)
                && value.ToString()!.Contains("correlation-item4", StringComparison.Ordinal)
                && value.ToString()!.Contains("TRANSPORT_AUTHENTICATION", StringComparison.Ordinal)
                && !value.ToString()!.Contains(productId, StringComparison.Ordinal)
                && !value.ToString()!.Contains("invalid_signature", StringComparison.Ordinal)),
            null,
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
        s2s.VerifyAll();
        runtime.VerifyNoOtherCalls();
    }

    /// <summary>Proves altered signed bytes, path, or ordinal product fail before semantic v2 execution.</summary>
    [Theory]
    [InlineData("body")]
    [InlineData("path")]
    [InlineData("product")]
    public async Task AuthorityGenerationV2_AlteredTransportBinding_DoesNotInvokeService(string mutation)
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        var body = "{\"productId\":\"" + (mutation == "product"
            ? "22222222-2222-4222-8222-222222222222" : productId) + "\"}";
        var path = mutation == "path" ? "/api/internal/v2/runtime-enrollment-authority/other"
            : "/api/internal/v2/runtime-enrollment-authority/generations";
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionS2SAuthenticationException(
                mutation == "body" ? "invalid_signature" : "invalid_transport_binding",
                StatusCodes.Status401Unauthorized));
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var controller = CreateController(s2s, runtime, "enabled", path,
            mutation == "body" ? body + " " : body, authorityV2: true);

        var result = Assert.IsType<ObjectResult>(
            await controller.IssueAuthorityGenerationV2(CancellationToken.None));

        Assert.Equal(mutation == "path" ? StatusCodes.Status400BadRequest
            : StatusCodes.Status401Unauthorized, result.StatusCode);
        if (mutation == "path") s2s.VerifyNoOtherCalls();
        else s2s.VerifyAll();
        runtime.VerifyNoOtherCalls();
    }
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

    /// <summary>Verifies the public migration route preserves strict body bytes and proof headers.</summary>
    [Fact]
    public async Task HardwareAuthorityMigration_WithStrictProofReturnsFrozenExactBody()
    {
        const string enrollmentId = "11111111-1111-4111-8111-111111111111";
        var body = "{\"schema\":\"runtime-hardware-authority-migration-v1\"," +
            "\"protocolVersion\":\"runtime-enrollment-v1\",\"requestId\":\"22222222-2222-4222-8222-222222222222\"," +
            "\"enrollmentId\":\"" + enrollmentId + "\",\"epoch\":1,\"securityEpoch\":1," +
            "\"legacyHardwareId\":\"A00272B768FFD6AF\",\"hardwareIdV2\":\"6B775195D2F86F36\"," +
            "\"legacyAlgorithm\":\"licensed-hardware-id\",\"hardwareIdV2Algorithm\":\"smbios-uuid-v1\"," +
            "\"sdkVersion\":\"2.0.0\",\"systemUuid\":\"4C4C4544-0051-3610-8052-B7C04F4A4E32\"}";
        var service = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var exact = Encoding.UTF8.GetBytes("{\"migrated\":true}");
        service.Setup(runtime => runtime.MigrateHardwareAuthorityAsync(
                Guid.Parse(enrollmentId), It.IsAny<string>(),
                It.IsAny<RuntimeHardwareAuthorityMigrationRequest>(), It.IsAny<RuntimeProofHeaders>(),
                It.IsAny<System.Net.IPAddress?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>(
                new(RuntimeEnrollmentService.HardwareAuthorityMigrationResponseSchema,
                    RuntimeEnrollmentService.ProtocolVersion, "migrated",
                    "22222222-2222-4222-8222-222222222222", enrollmentId,
                    "33333333-3333-4333-8333-333333333333",
                    "44444444-4444-4444-8444-444444444444", 1, 2,
                    "6B775195D2F86F36", "signed-license", "2026-08-16T13:00:00.0000000Z"),
                false, exact));
        var controller = CreateController(new(MockBehavior.Strict), service, "enabled",
            $"/api/v1/runtime-enrollments/{enrollmentId}/hardware-authority-migrations", body);
        controller.Request.Headers["X-Runtime-Enrollment-Timestamp"] = "2026-08-16T13:00:00.0000000Z";
        controller.Request.Headers["X-Runtime-Enrollment-Jti"] = "55555555-5555-4555-8555-555555555555";
        controller.Request.Headers["X-Runtime-Enrollment-Signature"] = new string('A', 512);

        var result = Assert.IsType<FileContentResult>(
            await controller.MigrateHardwareAuthority(enrollmentId, CancellationToken.None));

        Assert.Equal(exact, result.FileContents);
        service.VerifyAll();
    }

    [Theory]
    [InlineData(RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, true)]
    [InlineData(null, false)]
    [InlineData("invalid_signature", false)]
    public async Task HardwareAuthorityMigration_QualifiesOnlyProofClockSkewForAudit(
        string? diagnosticCode,
        bool expectedClassification)
    {
        const string enrollmentId = "11111111-1111-4111-8111-111111111111";
        var body = "{\"schema\":\"runtime-hardware-authority-migration-v1\"," +
            "\"protocolVersion\":\"runtime-enrollment-v1\",\"requestId\":\"22222222-2222-4222-8222-222222222222\"," +
            "\"enrollmentId\":\"" + enrollmentId + "\",\"epoch\":1,\"securityEpoch\":1," +
            "\"legacyHardwareId\":\"A00272B768FFD6AF\",\"hardwareIdV2\":\"6B775195D2F86F36\"," +
            "\"legacyAlgorithm\":\"licensed-hardware-id\",\"hardwareIdV2Algorithm\":\"smbios-uuid-v1\"," +
            "\"sdkVersion\":\"2.0.0\",\"systemUuid\":\"4C4C4544-0051-3610-8052-B7C04F4A4E32\"}";
        var service = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        service.Setup(runtime => runtime.MigrateHardwareAuthorityAsync(
                Guid.Parse(enrollmentId), It.IsAny<string>(),
                It.IsAny<RuntimeHardwareAuthorityMigrationRequest>(), It.IsAny<RuntimeProofHeaders>(),
                It.IsAny<System.Net.IPAddress?>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RuntimeEnrollmentException(
                "authentication_failed",
                StatusCodes.Status401Unauthorized,
                diagnosticCode));
        var controller = CreateController(new(MockBehavior.Strict), service, "enabled",
            $"/api/v1/runtime-enrollments/{enrollmentId}/hardware-authority-migrations", body);
        controller.Request.Headers["X-Runtime-Enrollment-Timestamp"] = "2026-08-16T13:00:00.0000000Z";
        controller.Request.Headers["X-Runtime-Enrollment-Jti"] = "55555555-5555-4555-8555-555555555555";
        controller.Request.Headers["X-Runtime-Enrollment-Signature"] = new string('A', 512);

        var result = Assert.IsType<ObjectResult>(
            await controller.MigrateHardwareAuthority(enrollmentId, CancellationToken.None));

        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Equal("authentication_failed", Assert.IsType<RuntimeEnrollmentApiError>(result.Value).Error);
        Assert.Equal(
            expectedClassification,
            controller.HttpContext.Items.ContainsKey(SoftLicence.Server.LogKeys.RuntimeAuthenticationDisposition));
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
    public async Task ReinstallAuthority_WhenS2sAuthenticated_ReturnsAndLogsExactDecision()
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
            RuntimeEnrollmentService.ProtocolVersion, "identity_confirmed",
            "33333333-3333-4333-8333-333333333333", bootstrapId, productId,
            "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777",
            "44444444-4444-4444-8444-444444444444", "2.3.7", new string('D', 43), 4,
            "88888888-8888-4888-8888-888888888888", new string('a', 64),
            "99999999-9999-4999-8999-999999999999", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        runtime.Setup(service => service.AuthorizeReinstallAsync(
                "website-step1", It.IsAny<RuntimeReinstallAuthorityRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
        var logger = new Mock<ILogger<RuntimeEnrollmentsController>>();
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v1/runtime-enrollments/reinstall-authorizations", body, logger: logger.Object);

        var result = Assert.IsType<OkObjectResult>(await controller.AuthorizeReinstall(CancellationToken.None));

        Assert.Same(response, result.Value);
        logger.Verify(entry => entry.Log(
            LogLevel.Information,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((value, _) =>
                value.ToString()!.Contains("identity_confirmed", StringComparison.Ordinal)
                && !value.ToString()!.Contains("authority authorized", StringComparison.Ordinal)),
            null,
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
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

    [Fact]
    public async Task ReinstallAuthority_WhenRefused_LogsInternalDiagnosticWithoutExposingIt()
    {
        const string productId = "11111111-1111-4111-8111-111111111111";
        const string bootstrapId = "22222222-2222-4222-8222-222222222222";
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
        runtime.Setup(service => service.AuthorizeReinstallAsync(
                "website-step1", It.IsAny<RuntimeReinstallAuthorityRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RuntimeEnrollmentException(
                "reinstall_authority_ineligible",
                StatusCodes.Status403Forbidden,
                "v2_finalize_owner_mismatch"));
        var logger = new Mock<ILogger<RuntimeEnrollmentsController>>();
        var controller = CreateController(s2s, runtime, "enabled",
            "/api/internal/v1/runtime-enrollments/reinstall-authorizations", body, logger: logger.Object);

        var result = Assert.IsType<ObjectResult>(
            await controller.AuthorizeReinstall(CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        Assert.Equal(
            "reinstall_authority_ineligible",
            Assert.IsType<RuntimeEnrollmentApiError>(result.Value).Error);
        logger.Verify(entry => entry.Log(
            LogLevel.Warning,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((value, _) =>
                value.ToString()!.Contains("v2_finalize_owner_mismatch", StringComparison.Ordinal)),
            null,
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
    }

    private static string RecoveryBody(string productId) =>
        "{\"schema\":\"runtime-critical-recovery-v1\",\"protocolVersion\":\"runtime-enrollment-v1\","
        + "\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"" + productId + "\","
        + "\"enrollmentId\":\"22222222-2222-4222-8222-222222222222\","
        + "\"bindingId\":\"33333333-3333-4333-8333-333333333333\","
        + "\"installationId\":\"44444444-4444-4444-8444-444444444444\","
        + "\"eventId\":\"55555555-5555-4555-8555-555555555555\","
        + "\"oldSecurityEpoch\":1,\"newSecurityEpoch\":2}";

    /// <summary>Compares exact request bytes outside Moq expression-tree span restrictions.</summary>
    private static bool ExactBytes(ReadOnlyMemory<byte> actual, byte[] expected) =>
        actual.ToArray().SequenceEqual(expected);

    /// <summary>Creates a controller with one owned exact request body and explicit feature modes.</summary>
    private static RuntimeEnrollmentsController CreateController(
        Mock<IDistributionS2SAuthenticationService> s2s,
        Mock<IRuntimeEnrollmentService> service,
        string mode,
        string path,
        string body,
        string query = "",
        ILogger<RuntimeEnrollmentsController>? logger = null,
        bool authorityV2 = false)
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
            s2s.Object, service.Object, Options.Create(new RuntimeEnrollmentOptions
            {
                Mode = mode,
                AuthorityGenerationV2 = new RuntimeAuthorityGenerationV2Options
                    { Mode = authorityV2 ? "enabled" : "off" }
            }), logger)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }
}

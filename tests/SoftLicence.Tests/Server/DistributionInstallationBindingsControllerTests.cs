using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class DistributionInstallationBindingsControllerTests
{
    [Fact]
    public async Task IssueEntitlement_PassesExactBodyToAuthenticationAndReturnsCreated()
    {
        const string body = "{\"schema\":\"distribution-entitlement-issue-v1\",\"requestId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"softLicenceLicenseId\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                "12345678-1234-4234-9234-1234567890ab",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.IssueEntitlementAsync(
                "tia-connect-website",
                It.Is<string>(digest => digest.Length == 64),
                It.IsAny<DistributionEntitlementIssueRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionEntitlementIssueResponse>(
                new("distribution-entitlement-v1", "opaque-reference", "2026-07-18T20:30:00.0000000Z"),
                false));
        var controller = CreateController(authentication.Object, bindings.Object, body);
        controller.Request.ContentType = "application/json; charset=utf-8";

        var result = await controller.IssueEntitlement(CancellationToken.None);

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status201Created, objectResult.StatusCode);
    }

    [Fact]
    public async Task Finalize_ReplayFailure_ReturnsOnlyStablePseudonymousError()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionS2SAuthenticationException("replay_rejected", StatusCodes.Status409Conflict));
        var controller = CreateController(authentication.Object, Mock.Of<IDistributionInstallationBindingService>(), body);

        var result = await controller.FinalizeInstallation(CancellationToken.None);

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, objectResult.StatusCode);
        Assert.Equal(new DistributionApiError("replay_rejected"), objectResult.Value);
    }

    [Fact]
    public async Task Finalize_AuthorityConflict_ReturnsAllowlistedInternalReasonWithoutSensitiveContext()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.FinalizeAsync(
                "tia-connect-website", It.IsAny<string>(), It.IsAny<DistributionInstallationFinalizeRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionOperationException(
                "binding_conflict", StatusCodes.Status409Conflict, "cross_generation_grant_owner_mismatch"));
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = Assert.IsType<ObjectResult>(
            await controller.FinalizeInstallation(CancellationToken.None));

        Assert.Equal(StatusCodes.Status409Conflict, result.StatusCode);
        Assert.Equal(new DistributionApiError("binding_conflict", "cross_generation_grant_owner_mismatch"), result.Value);
    }

    [Fact]
    public async Task Finalize_DuplicateProductId_IsRejectedBeforeAuthentication()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"productId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        var controller = CreateController(authentication.Object, Mock.Of<IDistributionInstallationBindingService>(), body);

        var result = await controller.FinalizeInstallation(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        authentication.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("application/jsonp")]
    [InlineData("application/jsonmalformed")]
    [InlineData("application/json; charset=")]
    public async Task IssueEntitlement_JsonLikeButInvalidMediaType_IsRejectedBeforeAuthentication(string contentType)
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        var controller = CreateController(authentication.Object, Mock.Of<IDistributionInstallationBindingService>(), body);
        controller.Request.ContentType = contentType;

        var result = await controller.IssueEntitlement(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        authentication.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Finalize_NestedDuplicateProperty_ConsumesAuthenticationNonceBeforeBadRequest()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"release\":{\"version\":\"2.2.844\",\"version\":\"2.2.845\"}}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = await controller.FinalizeInstallation(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        authentication.Verify(service => service.AuthenticateAndReserveNonceAsync(
            It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(),
            "12345678-1234-4234-9234-1234567890ab", It.IsAny<CancellationToken>()), Times.Once);
        bindings.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Invalidate_PassesExactBodyAfterAuthenticationAndReturnsCreated()
    {
        var grantDigest = new string('a', 64);
        var body = $$"""{"schema":"distribution-installation-invalidation-v1","requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","productId":"12345678-1234-4234-9234-1234567890ab","bindingId":null,"grantRefDigestSha256":"{{grantDigest}}","reason":"grant_revoked","occurredAtUtc":"2026-07-18T18:20:00.0000000Z","epoch":1}""";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                "12345678-1234-4234-9234-1234567890ab",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.InvalidateAsync(
                "tia-connect-website", It.Is<string>(digest => digest.Length == 64),
                It.IsAny<DistributionInstallationInvalidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionInstallationInvalidationResponse>(
                new("distribution-installation-invalidation-result-v1", null, "invalidated", grantDigest,
                    "grant_revoked", "2026-07-18T18:20:00.0000000Z", 1, "2026-07-18T18:30:00.0000000Z"), false));
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = await controller.InvalidateInstallation(CancellationToken.None);

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status201Created, objectResult.StatusCode);
    }

    [Fact]
    public async Task Invalidate_ExactReplayReturnsOk_AndChangedPayloadConflictRemainsStable()
    {
        var grantDigest = new string('a', 64);
        var body = $$"""{"schema":"distribution-installation-invalidation-v1","requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","productId":"12345678-1234-4234-9234-1234567890ab","bindingId":null,"grantRefDigestSha256":"{{grantDigest}}","reason":"grant_revoked","occurredAtUtc":"2026-07-18T18:20:00.0000000Z","epoch":1}""";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(),
                "12345678-1234-4234-9234-1234567890ab", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var response = new DistributionInstallationInvalidationResponse(
            "distribution-installation-invalidation-result-v1", null, "invalidated", grantDigest,
            "grant_revoked", "2026-07-18T18:20:00.0000000Z", 1, "2026-07-18T18:30:00.0000000Z");
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.SetupSequence(service => service.InvalidateAsync(
                "tia-connect-website", It.IsAny<string>(), It.IsAny<DistributionInstallationInvalidationRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionInstallationInvalidationResponse>(response, true))
            .ThrowsAsync(new DistributionOperationException("idempotency_conflict", StatusCodes.Status409Conflict));

        var replayController = CreateController(authentication.Object, bindings.Object, body);
        var replay = Assert.IsType<ObjectResult>(await replayController.InvalidateInstallation(CancellationToken.None));
        Assert.Equal(StatusCodes.Status200OK, replay.StatusCode);
        Assert.Equal(response, replay.Value);

        var changedController = CreateController(authentication.Object, bindings.Object, body.Replace("grant_revoked", "fraud_flagged", StringComparison.Ordinal));
        var changed = Assert.IsType<ObjectResult>(await changedController.InvalidateInstallation(CancellationToken.None));
        Assert.Equal(StatusCodes.Status409Conflict, changed.StatusCode);
        Assert.Equal(new DistributionApiError("idempotency_conflict"), changed.Value);
    }

    private static DistributionInstallationBindingsController CreateController(
        IDistributionS2SAuthenticationService authentication,
        IDistributionInstallationBindingService bindings,
        string body)
    {
        var controller = new DistributionInstallationBindingsController(authentication, bindings);
        var context = new DefaultHttpContext();
        var bytes = Encoding.UTF8.GetBytes(body);
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;
        context.Request.ContentType = "application/json";
        controller.ControllerContext = new ControllerContext { HttpContext = context };
        return controller;
    }
}

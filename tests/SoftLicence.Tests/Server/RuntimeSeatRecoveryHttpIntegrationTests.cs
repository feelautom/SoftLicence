using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies the closed S2S transport boundary independently from PostgreSQL business state.</summary>
public sealed class RuntimeSeatRecoveryHttpIntegrationTests
{
    private const string AuthorizationBody = "{\"schema\":\"runtime-seat-recovery-authorization-v1\",\"contractVersion\":1,\"requestId\":\"018f6fd4-fe06-75d7-ae93-b15d36ca5501\",\"recoveryOperationRef\":\"018f6fd4-7a01-7b01-8c01-0123456789ab\",\"recoveryDigestSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"provider\":\"softlicence\",\"providerGrantRef\":\"grant:tenant-a:café:🚀\",\"productId\":\"018f6fd4-94b2-7f7e-8f47-13eb8aab8b11\",\"licenseId\":\"018f6fd4-1111-7111-8111-111111111111\",\"seatClaim\":null,\"installation\":{\"installationId\":\"018f6fd4-dce4-7b2a-8202-5846e80d1301\",\"hardwareIdDigestSha256\":\"2222222222222222222222222222222222222222222222222222222222222222\"},\"release\":{\"version\":\"2.3.445\",\"artifactSetDigestSha256\":\"1111111111111111111111111111111111111111111111111111111111111111\"},\"newKeyCommitment\":{\"algorithm\":\"PS256\",\"publicKeySpkiSha256\":\"c61e282a88aa590621c577f7ffb08a92a2e057eb73813d73c1759c21c1f31b69\",\"keyThumbprint\":\"xh4oKoiqWQYhxXf3_7CKkqLgV-tzgT1zwXWcIcHzG2k\"},\"expiresAtUtc\":\"2026-08-29T06:00:00.000000Z\"}";

    /// <summary>Proves exact request bytes and authenticated client identity reach the atomic service unchanged.</summary>
    [Fact]
    public async Task Authorize_RecoveryCapableS2SClient_ForwardsExactCanonicalIdentity()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(body => body.ToArray().SequenceEqual(Encoding.UTF8.GetBytes(AuthorizationBody))),
                "018f6fd4-94b2-7f7e-8f47-13eb8aab8b11", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("website-recovery", "key", AllowRuntimeRecovery: true));
        var authorizations = new Mock<IRuntimeSeatRecoveryAuthorizationService>();
        var exact = Encoding.UTF8.GetBytes("{\"decision\":\"authorized\"}");
        authorizations.Setup(service => service.AuthorizeAsync("website-recovery",
                It.Is<RuntimeSeatRecoveryContractCodec.AuthorizationParseResult>(parsed =>
                    parsed.RequestDigestSha256 == "8fd3ff4e488e651ba3945e7e5d10fa3cdaf57cf3647159acd7cd439828ca673f"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeSeatRecoveryHttpResult(200, "application/json; charset=utf-8", exact));
        var controller = Controller(authentication.Object, authorizations.Object, AuthorizationBody,
            "/api/internal/v1/runtime-seat-recovery-authorizations");

        var file = Assert.IsType<FileContentResult>(await controller.Authorize(CancellationToken.None));

        Assert.Equal(exact, file.FileContents);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
        authentication.VerifyAll();
        authorizations.VerifyAll();
    }

    /// <summary>Proves an authenticated client without the dedicated recovery capability never reaches business state.</summary>
    [Fact]
    public async Task Authorize_MissingRecoveryCapability_ReturnsClosed403BeforeBusinessService()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("website", "key"));
        var authorizations = new Mock<IRuntimeSeatRecoveryAuthorizationService>(MockBehavior.Strict);
        var controller = Controller(authentication.Object, authorizations.Object, AuthorizationBody,
            "/api/internal/v1/runtime-seat-recovery-authorizations");

        var file = Assert.IsType<FileContentResult>(await controller.Authorize(CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, controller.Response.StatusCode);
        Assert.Equal("{\"schema\":\"runtime-seat-recovery-transport-error-v1\",\"contractVersion\":1,\"errorCode\":\"recovery_not_authorized\"}",
            Encoding.UTF8.GetString(file.FileContents));
        authorizations.VerifyNoOtherCalls();
    }

    /// <summary>Proves an invented JTI is rejected before authentication and every response is non-cacheable.</summary>
    [Fact]
    public async Task ConfirmKey_UnknownJti_IsClosedInvalidRequestAndNoStore()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        var authorizations = new Mock<IRuntimeSeatRecoveryAuthorizationService>(MockBehavior.Strict);
        const string body = "{\"jti\":\"018f6fd4-4444-7444-8444-444444444444\"}";
        const string requestId = "018f6fd4-fe06-75d7-ae93-b15d36ca5501";
        var controller = Controller(authentication.Object, authorizations.Object, body,
            $"/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/key-confirmations");

        var file = Assert.IsType<FileContentResult>(await controller.ConfirmKey(requestId, CancellationToken.None));

        Assert.Equal(StatusCodes.Status400BadRequest, controller.Response.StatusCode);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
        Assert.Contains("\"errorCode\":\"invalid_request\"", Encoding.UTF8.GetString(file.FileContents), StringComparison.Ordinal);
        authentication.VerifyNoOtherCalls();
        authorizations.VerifyNoOtherCalls();
    }

    /// <summary>Proves the key-preparation route closes non-exact media type before reading business state.</summary>
    [Fact]
    public async Task PrepareKey_NonExactContentType_Returns415AndNoStore()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        var authorizations = new Mock<IRuntimeSeatRecoveryAuthorizationService>(MockBehavior.Strict);
        const string requestId = "018f6fd4-fe06-75d7-ae93-b15d36ca5501";
        var controller = Controller(authentication.Object, authorizations.Object, "{}",
            $"/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/key-preparations");
        controller.Request.ContentType = "application/json";

        var file = Assert.IsType<FileContentResult>(await controller.PrepareKey(requestId, CancellationToken.None));

        Assert.Equal(StatusCodes.Status415UnsupportedMediaType, controller.Response.StatusCode);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
        Assert.Contains("\"errorCode\":\"unsupported_media_type\"", Encoding.UTF8.GetString(file.FileContents), StringComparison.Ordinal);
        authentication.VerifyNoOtherCalls();
        authorizations.VerifyNoOtherCalls();
    }

    /// <summary>Proves the confirmation route rejects the declared upper bound before parsing or authentication.</summary>
    [Fact]
    public async Task ConfirmKey_DeclaredBodyAbove4096_Returns413AndNoStore()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        var authorizations = new Mock<IRuntimeSeatRecoveryAuthorizationService>(MockBehavior.Strict);
        const string requestId = "018f6fd4-fe06-75d7-ae93-b15d36ca5501";
        var controller = Controller(authentication.Object, authorizations.Object, "{}",
            $"/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/key-confirmations");
        controller.Request.ContentLength = 4097;

        var file = Assert.IsType<FileContentResult>(await controller.ConfirmKey(requestId, CancellationToken.None));

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, controller.Response.StatusCode);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
        Assert.Contains("\"errorCode\":\"payload_too_large\"", Encoding.UTF8.GetString(file.FileContents), StringComparison.Ordinal);
        authentication.VerifyNoOtherCalls();
        authorizations.VerifyNoOtherCalls();
    }

    /// <summary>Creates one enabled controller with the exact request target and UTF-8 JSON framing.</summary>
    private static RuntimeSeatRecoveryAuthorizationsController Controller(
        IDistributionS2SAuthenticationService authentication,
        IRuntimeSeatRecoveryAuthorizationService authorizations,
        string body,
        string path)
    {
        var controller = new RuntimeSeatRecoveryAuthorizationsController(authentication, authorizations,
            Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.ContentType = "application/json; charset=utf-8";
        context.Request.ContentLength = Encoding.UTF8.GetByteCount(body);
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        controller.ControllerContext = new ControllerContext { HttpContext = context };
        return controller;
    }
}

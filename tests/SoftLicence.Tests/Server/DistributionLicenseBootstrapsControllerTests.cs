using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class DistributionLicenseBootstrapsControllerTests
{
    private const string ProductId = "12345678-1234-4234-9234-1234567890ab";
    private const string BindingId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    private const string EnrollmentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private const string RequestId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    [Theory]
    [InlineData(false, 201)]
    [InlineData(true, 200)]
    public async Task Recover_AuthenticatesExactBodyAndReturnsFrozenResponse(bool replay, int expectedStatus)
    {
        var body = $$"""{"schema":"distribution-license-bootstrap-recover-v1","requestId":"{{RequestId}}","productId":"{{ProductId}}","bindingId":"{{BindingId}}","enrollmentId":"{{EnrollmentId}}"}""";
        var responseBytes = Encoding.UTF8.GetBytes("{\"schema\":\"distribution-license-bootstrap-capability-v1\"}");
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                ProductId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "website-step1", "key-id", AllowLicenseBootstrap: true));
        var bootstraps = new Mock<IDistributionLicenseBootstrapService>();
        bootstraps.Setup(service => service.RecoverAsync(
                "website-step1",
                It.Is<string>(digest => digest.Length == 64),
                It.Is<DistributionLicenseBootstrapRecoverRequest>(request =>
                    request.Schema == DistributionLicenseBootstrapService.RecoverSchema
                    && request.RequestId == RequestId
                    && request.ProductId == ProductId
                    && request.BindingId == BindingId
                    && request.EnrollmentId == EnrollmentId
                    && request.ExtensionData == null),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>(
                new(DistributionLicenseBootstrapService.ResponseSchema, BindingId, "capability",
                    "2026-07-28T16:02:00.0000000Z", "2026-07-28T18:00:00.0000000Z"),
                replay,
                responseBytes));
        var controller = CreateController(authentication.Object, bootstraps.Object, body);

        var result = await controller.Recover(CancellationToken.None);

        var file = Assert.IsType<FileContentResult>(result);
        Assert.Equal(expectedStatus, controller.Response.StatusCode);
        Assert.Equal("application/json", file.ContentType);
        Assert.Equal(responseBytes, file.FileContents);
        Assert.Equal("no-store", controller.Response.Headers.CacheControl);
    }

    [Fact]
    public async Task Recover_WithoutBootstrapPermission_FailsBeforeService()
    {
        var body = $$"""{"schema":"distribution-license-bootstrap-recover-v1","requestId":"{{RequestId}}","productId":"{{ProductId}}","bindingId":"{{BindingId}}","enrollmentId":"{{EnrollmentId}}"}""";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("website-step1", "key-id"));
        var bootstraps = new Mock<IDistributionLicenseBootstrapService>();
        var controller = CreateController(authentication.Object, bootstraps.Object, body);

        var result = await controller.Recover(CancellationToken.None);

        var forbidden = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, forbidden.StatusCode);
        Assert.Equal(new DistributionApiError("license_bootstrap_forbidden"), forbidden.Value);
        bootstraps.VerifyNoOtherCalls();
    }

    private static DistributionLicenseBootstrapsController CreateController(
        IDistributionS2SAuthenticationService authentication,
        IDistributionLicenseBootstrapService bootstraps,
        string body)
    {
        var controller = new DistributionLicenseBootstrapsController(authentication, bootstraps);
        var context = new DefaultHttpContext();
        var bytes = Encoding.UTF8.GetBytes(body);
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/internal/v1/distribution-license-bootstraps/recover";
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;
        context.Request.ContentType = "application/json";
        controller.ControllerContext = new ControllerContext { HttpContext = context };
        return controller;
    }
}

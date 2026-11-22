using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Protects the provider-owned key-activation-setting authority boundary: dedicated S2S capability,
/// strict request shape, stable correlation and fail-closed controller errors, without a database.
/// </summary>
public sealed class LicenseKeyActivationContractTests
{
    private const string RequestId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    private const string ProductId = "12345678-1234-4234-9234-1234567890ab";
    private const string LicenseId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 14, 0, 0, TimeSpan.Zero);

    /// <summary>Requires the dedicated S2S capability on the configured options and the principal.</summary>
    [Fact]
    public void DistributionS2SAuthority_ExposesDedicatedKeyActivationCapability()
    {
        Assert.NotNull(typeof(DistributionS2SClientOptions).GetProperty("AllowLicenseKeyActivationSettings"));
        Assert.NotNull(typeof(DistributionS2SPrincipal).GetProperty("AllowLicenseKeyActivationSettings"));
        Assert.False(new DistributionS2SClientOptions().AllowLicenseKeyActivationSettings);
        Assert.False(new DistributionS2SPrincipal("client", "key").AllowLicenseKeyActivationSettings);
    }

    /// <summary>Preserves the existing positional hardware-exclusion capability when appending new S2S rights.</summary>
    [Fact]
    public void DistributionS2SPrincipal_PreservesHardwareExclusionArgumentPosition()
    {
        var principal = new DistributionS2SPrincipal("client", "key", false, false, false, false, true);

        Assert.True(principal.AllowLicenseHardwareExclusions);
        Assert.False(principal.AllowLicenseKeyActivationSettings);
    }

    /// <summary>Proves the key-activation capability cannot share a client identity with another capability.</summary>
    [Fact]
    public void DistributionS2SOptions_RejectMixedKeyActivationIdentity()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfoPem();

        var mixed = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            Clients =
            [
                new DistributionS2SClientOptions
                {
                    ClientId = "provider-settings-client",
                    KeyId = "settings-key-2026-01",
                    PublicKeyPem = publicKey,
                    AllowLicenseKeyActivationSettings = true,
                    AllowRuntimeRecovery = true,
                    ProductIds = [ProductId],
                    AllowedCidrs = ["127.0.0.1/32"]
                }
            ]
        });

        Assert.True(mixed.Failed);
        Assert.Contains(mixed.Failures, failure =>
            failure.Contains("License key activation settings require one dedicated client identity"));

        var dedicated = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            Clients =
            [
                new DistributionS2SClientOptions
                {
                    ClientId = "provider-settings-client",
                    KeyId = "settings-key-2026-01",
                    PublicKeyPem = publicKey,
                    AllowLicenseKeyActivationSettings = true,
                    ProductIds = [ProductId],
                    AllowedCidrs = ["127.0.0.1/32"]
                }
            ]
        });

        Assert.False(dedicated.Failed);
    }

    /// <summary>Proves an unsigned request is rejected before any authentication state is consumed.</summary>
    [Fact]
    public async Task Disable_WithoutSignature_IsFailClosedUnauthorized()
    {
        using var rsa = RSA.Create(2048);
        var (controller, context) = CreateController(
            CreateAuthenticationService(rsa.ExportSubjectPublicKeyInfoPem()),
            Mock.Of<ILicenseKeyActivationSettingService>());
        WriteBody(context.Request, ValidBody(LicenseKeyActivationSettingService.RequestSchema));

        var result = await controller.Disable(CancellationToken.None);

        AssertApiError(result, StatusCodes.Status401Unauthorized, "authentication_failed");
    }

    /// <summary>Proves a principal without the dedicated capability is refused before deserialization.</summary>
    [Fact]
    public async Task Disable_WithoutCapability_IsCapabilityDenied()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication
            .Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("other-client", "other-key"));
        var (controller, context) = CreateController(
            authentication.Object, Mock.Of<ILicenseKeyActivationSettingService>());
        WriteBody(context.Request, ValidBody(LicenseKeyActivationSettingService.RequestSchema));

        var result = await controller.Disable(CancellationToken.None);

        AssertApiError(result, StatusCodes.Status403Forbidden, "capability_denied");
    }

    /// <summary>Proves a mismatched correlation header is refused before any mutation.</summary>
    [Fact]
    public async Task Disable_WithUnstableCorrelation_IsBadRequest()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication
            .Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DedicatedPrincipal());
        var (controller, context) = CreateController(authentication.Object, Mock.Of<ILicenseKeyActivationSettingService>());
        WriteBody(context.Request, ValidBody(LicenseKeyActivationSettingService.RequestSchema));
        context.Request.Headers["X-Correlation-Id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

        var result = await controller.Disable(CancellationToken.None);

        AssertApiError(result, StatusCodes.Status400BadRequest, "invalid_request");
    }

    /// <summary>Proves a request body with the wrong closed schema variant is refused before any mutation.</summary>
    [Fact]
    public async Task Disable_WithLiftSchemaVariant_IsBadRequest()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication
            .Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DedicatedPrincipal());
        var (controller, context) = CreateController(authentication.Object, Mock.Of<ILicenseKeyActivationSettingService>());
        WriteBody(context.Request, ValidBody(LicenseKeyActivationSettingService.RequestLiftSchema));

        var result = await controller.Disable(CancellationToken.None);

        AssertApiError(result, StatusCodes.Status400BadRequest, "invalid_request");
    }

    /// <summary>Proves an authenticated pose forwards the exact validated command and returns the terminal.</summary>
    [Fact]
    public async Task Disable_WithCapability_AppliesValidatedCommand()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication
            .Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DedicatedPrincipal());
        LicenseKeyActivationCommand? applied = null;
        var settings = new Mock<ILicenseKeyActivationSettingService>();
        settings
            .Setup(service => service.DisableAsync(It.IsAny<LicenseKeyActivationCommand>(), It.IsAny<CancellationToken>()))
            .Callback<LicenseKeyActivationCommand, CancellationToken>((command, _) => applied = command)
            .ReturnsAsync(new LicenseKeyActivationResult(
                new LicenseKeyActivationResponse(
                    LicenseKeyActivationSettingService.ResponseSchema,
                    RequestId,
                    LicenseKeyActivationSettingService.DisabledOutcome),
                false));
        var (controller, context) = CreateController(authentication.Object, settings.Object);
        WriteBody(context.Request, ValidBody(LicenseKeyActivationSettingService.RequestSchema));

        var result = await controller.Disable(CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(StatusCodes.Status200OK, ok.StatusCode);
        var response = Assert.IsType<LicenseKeyActivationResponse>(ok.Value);
        Assert.Equal(LicenseKeyActivationSettingService.DisabledOutcome, response.Outcome);
        Assert.NotNull(applied);
        Assert.Equal(Guid.ParseExact(RequestId, "D"), applied!.RequestId);
        Assert.Equal(Guid.ParseExact(ProductId, "D"), applied.ProductId);
        Assert.Equal(Guid.ParseExact(LicenseId, "D"), applied.LicenseId);
        Assert.Equal(LicenseKeyActivationSettingService.S2SActor, applied.Actor);
        Assert.Equal("provider-settings-client", applied.ClientId);
    }

    /// <summary>Proves a service idempotency conflict keeps its 409 status and closed code.</summary>
    [Fact]
    public async Task Lift_ServiceConflict_IsConflictWithClosedCode()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication
            .Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DedicatedPrincipal());
        var settings = new Mock<ILicenseKeyActivationSettingService>();
        settings
            .Setup(service => service.LiftAsync(It.IsAny<LicenseKeyActivationCommand>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionOperationException("idempotency_conflict", StatusCodes.Status409Conflict));
        var (controller, context) = CreateController(authentication.Object, settings.Object);
        WriteBody(context.Request, ValidBody(LicenseKeyActivationSettingService.RequestLiftSchema));

        var result = await controller.Lift(CancellationToken.None);

        AssertApiError(result, StatusCodes.Status409Conflict, "idempotency_conflict");
    }

    /// <summary>
    /// PR #422 point 6: the historical portal-deactivation rule is unchanged, so a client combining portal
    /// deactivation and hardware exclusions stays accepted, while the new capability alone is strict.
    /// </summary>
    [Fact]
    public void DistributionS2SOptions_KeepPortalRuleAndStrictKeyActivationRule()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfoPem();
        DistributionS2SClientOptions Client(bool portal, bool exclusions, bool keyActivation) => new()
        {
            ClientId = "website-portal-client",
            KeyId = "portal-key-2026-01",
            PublicKeyPem = publicKey,
            AllowPortalDeactivation = portal,
            AllowLicenseHardwareExclusions = exclusions,
            AllowLicenseKeyActivationSettings = keyActivation,
            ProductIds = [ProductId],
            AllowedCidrs = ["127.0.0.1/32"]
        };

        var historical = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            Clients = [Client(portal: true, exclusions: true, keyActivation: false)]
        });
        var mixedNew = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            Clients = [Client(portal: true, exclusions: false, keyActivation: true)]
        });

        Assert.False(historical.Failed, string.Join(" | ", historical.Failures ?? []));
        Assert.True(mixedNew.Failed);
        Assert.Contains(mixedNew.Failures, failure =>
            failure.Contains("License key activation settings require one dedicated client identity"));
    }

    /// <summary>Asserts the controller returned the exact status and closed error code in its result object.</summary>
    private static void AssertApiError(IActionResult result, int statusCode, string errorCode)
    {
        var objectResult = Assert.IsAssignableFrom<ObjectResult>(result);
        Assert.Equal(statusCode, objectResult.StatusCode);
        var error = Assert.IsType<DistributionApiError>(objectResult.Value);
        Assert.Equal(errorCode, error.Error);
    }

    private static DistributionS2SPrincipal DedicatedPrincipal() =>
        new("provider-settings-client", "settings-key-2026-01",
            AllowLicenseKeyActivationSettings: true);

    private static IDistributionS2SAuthenticationService CreateAuthenticationService(string publicKeyPem) =>
        new DistributionS2SAuthenticationService(
            new PortalDeactivationPostgreSqlFixture.TestDbContextFactory("contract-" + Guid.NewGuid().ToString("N")),
            Options.Create(new DistributionS2SOptions
            {
                Clients =
                [
                    new DistributionS2SClientOptions
                    {
                        ClientId = "provider-settings-client",
                        KeyId = "settings-key-2026-01",
                        PublicKeyPem = publicKeyPem,
                        AllowLicenseKeyActivationSettings = true,
                        ProductIds = [ProductId],
                        AllowedCidrs = ["127.0.0.1/32"]
                    }
                ]
            }),
            new FixedTimeProvider(Now));

    private static (LicenseKeyActivationSettingsController Controller, DefaultHttpContext Context) CreateController(
        IDistributionS2SAuthenticationService authentication,
        ILicenseKeyActivationSettingService settings)
    {
        var controller = new LicenseKeyActivationSettingsController(authentication, settings);
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/internal/v1/license-key-activation-settings";
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Headers[DistributionS2SAuthenticationService.ClientHeader] = "provider-settings-client";
        context.Request.Headers[DistributionS2SAuthenticationService.KeyIdHeader] = "settings-key-2026-01";
        context.Request.Headers[DistributionS2SAuthenticationService.TimestampHeader] =
            "2026-10-23T14:00:00.0000000Z";
        context.Request.Headers[DistributionS2SAuthenticationService.NonceHeader] =
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        context.Request.Headers["X-Correlation-Id"] = RequestId;
        controller.ControllerContext = new ControllerContext { HttpContext = context };
        return (controller, context);
    }

    private static void WriteBody(HttpRequest request, string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        request.ContentType = "application/json";
        request.Body = new MemoryStream(bytes);
        request.ContentLength = bytes.Length;
    }

    private static string ValidBody(string schema) => JsonSerializer.Serialize(new
    {
        schema,
        requestId = RequestId,
        productId = ProductId,
        licenseId = LicenseId
    }, new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    });

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

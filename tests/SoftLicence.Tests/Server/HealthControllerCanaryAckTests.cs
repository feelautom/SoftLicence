using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class HealthControllerCanaryAckTests
{
    private const string EnrollmentId = "12345678-1234-4234-9234-1234567890ac";
    private const string Timestamp = "2026-07-18T17:30:00.0000000Z";
    private const string Jti = "12345678-1234-4234-9234-1234567890ad";
    private const string Signature = "proof";

    [Fact]
    public async Task Ping_WithAuthenticatedCriticalContract_DelegatesExactBodyAndReturnsExactReceipt()
    {
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var response = CreateResponse();
        var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        string? observedDigest = null;
        runtime.Setup(service => service.ProcessCanaryAsync(
                Guid.Parse(EnrollmentId), It.IsAny<string>(), It.IsAny<CanaryPingRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<System.Net.IPAddress>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, string, CanaryPingRequest, RuntimeProofHeaders, System.Net.IPAddress?, CancellationToken>(
                (_, digest, _, proof, _, _) =>
                {
                    observedDigest = digest;
                    Assert.Equal(Timestamp, proof.Timestamp);
                    Assert.Equal(Jti, proof.Jti);
                    Assert.Equal(Signature, proof.Signature);
                })
            .ReturnsAsync(new RuntimeEnrollmentOperationResult<CanaryAckResponse>(response, false, responseBytes));
        var controller = BuildController(runtime.Object);
        AddProofHeaders(controller);
        const string json = "{\"schema\":\"canary-ack-v1\",\"eventId\":\"12345678-1234-4234-9234-1234567890ab\",\"sentAtUtc\":\"2026-07-18T17:30:00.0000000Z\",\"hardwareId\":\"72A4BC9E3A72C063\",\"appVersion\":\"2.2.843\",\"trigger\":\"RuntimeCheck_NativeDllSwapped\",\"severity\":3}";
        SetExactRequest(controller, Encoding.UTF8.GetBytes(json));

        var result = await controller.Ping(CancellationToken.None);

        var file = Assert.IsType<FileContentResult>(result);
        Assert.Equal(responseBytes, file.FileContents);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json))), observedDigest);
        runtime.VerifyAll();
    }

    [Theory]
    [InlineData("empty", StatusCodes.Status400BadRequest)]
    [InlineData("oversized", StatusCodes.Status413PayloadTooLarge)]
    [InlineData("chunked", StatusCodes.Status400BadRequest)]
    [InlineData("content-encoding", StatusCodes.Status400BadRequest)]
    [InlineData("missing-content-type", StatusCodes.Status415UnsupportedMediaType)]
    [InlineData("wrong-content-type", StatusCodes.Status415UnsupportedMediaType)]
    [InlineData("wrong-charset", StatusCodes.Status415UnsupportedMediaType)]
    [InlineData("extra-content-type-parameter", StatusCodes.Status415UnsupportedMediaType)]
    [InlineData("bom", StatusCodes.Status400BadRequest)]
    [InlineData("invalid-utf8", StatusCodes.Status400BadRequest)]
    [InlineData("extra-bytes", StatusCodes.Status400BadRequest)]
    [InlineData("query", StatusCodes.Status400BadRequest)]
    [InlineData("trailing-slash", StatusCodes.Status400BadRequest)]
    [InlineData("path-case", StatusCodes.Status400BadRequest)]
    public async Task Ping_ActionRejectsNonExactTransportWithoutAuthority(string scenario, int expectedStatus)
    {
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var controller = BuildController(runtime.Object);
        var body = Encoding.UTF8.GetBytes(CriticalJson());
        SetExactRequest(controller, body);

        switch (scenario)
        {
            case "empty":
                controller.Request.Body = new MemoryStream();
                controller.Request.ContentLength = 0;
                break;
            case "oversized":
                controller.Request.Body = new MemoryStream(new byte[4097]);
                controller.Request.ContentLength = 4097;
                break;
            case "chunked":
                controller.Request.Headers.TransferEncoding = "chunked";
                controller.Request.ContentLength = null;
                break;
            case "content-encoding":
                controller.Request.Headers.ContentEncoding = "gzip";
                break;
            case "missing-content-type":
                controller.Request.ContentType = null;
                break;
            case "wrong-content-type":
                controller.Request.ContentType = "text/plain";
                break;
            case "wrong-charset":
                controller.Request.ContentType = "application/json; charset=utf-16";
                break;
            case "extra-content-type-parameter":
                controller.Request.ContentType = "application/json; charset=utf-8; profile=test";
                break;
            case "bom":
                body = [.. Encoding.UTF8.Preamble, .. body];
                SetExactRequest(controller, body);
                break;
            case "invalid-utf8":
                SetExactRequest(controller, [0xC3, 0x28]);
                break;
            case "extra-bytes":
                controller.Request.Body = new MemoryStream([.. body, 0x20]);
                controller.Request.ContentLength = body.Length;
                break;
            case "query":
                controller.Request.QueryString = new QueryString("?x=1");
                break;
            case "trailing-slash":
                controller.Request.Path = "/api/health/ping/";
                break;
            case "path-case":
                controller.Request.Path = "/api/Health/ping";
                break;
        }

        var result = await controller.Ping(CancellationToken.None);

        var error = Assert.IsAssignableFrom<ObjectResult>(result);
        Assert.Equal(expectedStatus, error.StatusCode);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
        runtime.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("{\"hardwareId\":\"HW-LEGACY\",\"trigger\":\"RuntimeCheck_Debugger\",\"severity\":3}")]
    [InlineData("{\"schema\":\"canary-ack-v1\",\"eventId\":\"12345678-1234-4234-9234-1234567890ab\",\"sentAtUtc\":\"2026-07-18T17:30:00.0000000Z\",\"hardwareId\":\"72A4BC9E3A72C063\",\"appVersion\":\"2.2.843\",\"trigger\":\"RuntimeCheck_NativeDllSwapped\",\"severity\":3,\"extra\":true}")]
    [InlineData("{\"Schema\":\"canary-ack-v1\",\"eventId\":\"12345678-1234-4234-9234-1234567890ab\",\"sentAtUtc\":\"2026-07-18T17:30:00.0000000Z\",\"hardwareId\":\"72A4BC9E3A72C063\",\"appVersion\":\"2.2.843\",\"trigger\":\"RuntimeCheck_NativeDllSwapped\",\"severity\":3}")]
    public async Task Ping_WithLegacyOrNonExactPayload_IsIgnoredWithoutCallingAuthority(string json)
    {
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var controller = BuildController(runtime.Object);
        using var document = JsonDocument.Parse(json);

        var result = await controller.Ping(document.RootElement);

        Assert.IsType<AcceptedResult>(result);
        runtime.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Ping_WithMissingProofHeaders_IsUnauthorizedBeforeAuthority()
    {
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var controller = BuildController(runtime.Object);
        using var document = JsonDocument.Parse(CriticalJson());

        var result = await controller.Ping(document.RootElement);

        var unauthorized = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, unauthorized.StatusCode);
        runtime.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Ping_WhenAuthorityRejects_DoesNotReturnAck()
    {
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        runtime.Setup(service => service.ProcessCanaryAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CanaryPingRequest>(),
                It.IsAny<RuntimeProofHeaders>(), It.IsAny<System.Net.IPAddress>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized));
        var controller = BuildController(runtime.Object);
        AddProofHeaders(controller);
        using var document = JsonDocument.Parse(CriticalJson());

        var result = await controller.Ping(document.RootElement);

        var unauthorized = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, unauthorized.StatusCode);
        runtime.VerifyAll();
    }

    [Fact]
    public void CanaryPublicKey_WithExistingExactKeyId_RemainsCompatible()
    {
        var controller = BuildController(Mock.Of<IRuntimeEnrollmentService>());

        var result = controller.GetCanaryPublicKey(CanaryAckOptions.InitialKeyId);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<CanaryAckPublicKeyResponse>(ok.Value);
        Assert.Equal(CanaryAckOptions.InitialKeyId, response.KeyId);
    }

    [Theory]
    [InlineData("CANARY-RS256-2026-01")]
    [InlineData("canary-rs256-2026-01 ")]
    [InlineData("canary-rs256-2026-٠١")]
    [InlineData("unknown")]
    public void CanaryPublicKey_WithNonExactOrUnknownKeyId_ReturnsNotFound(string keyId)
    {
        var controller = BuildController(Mock.Of<IRuntimeEnrollmentService>());

        var result = controller.GetCanaryPublicKey(keyId);

        Assert.IsType<NotFoundResult>(result);
    }

    private static HealthController BuildController(IRuntimeEnrollmentService runtime)
    {
        using var rsa = RSA.Create(2048);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = rsa.ExportPkcs8PrivateKeyPem()
        }).Build();
        var dbFactory = new TestDbContextFactory();
        var ack = new CanaryAckService(dbFactory, configuration, TimeProvider.System);
        var controller = new HealthController(Mock.Of<ILogger<HealthController>>(), ack, runtime)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
        controller.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
        return controller;
    }

    private static void AddProofHeaders(HealthController controller)
    {
        controller.Request.Headers["X-Runtime-Enrollment-Id"] = EnrollmentId;
        controller.Request.Headers["X-Runtime-Enrollment-Timestamp"] = Timestamp;
        controller.Request.Headers["X-Runtime-Enrollment-Jti"] = Jti;
        controller.Request.Headers["X-Runtime-Enrollment-Signature"] = Signature;
    }

    private static void SetExactRequest(HealthController controller, byte[] body)
    {
        controller.Request.Method = HttpMethods.Post;
        controller.Request.Path = "/api/health/ping";
        controller.Request.QueryString = QueryString.Empty;
        controller.Request.ContentType = "application/json; charset=utf-8";
        controller.Request.ContentLength = body.Length;
        controller.Request.Body = new MemoryStream(body, writable: false);
    }

    private static string CriticalJson() =>
        "{\"schema\":\"canary-ack-v1\",\"eventId\":\"12345678-1234-4234-9234-1234567890ab\",\"sentAtUtc\":\"2026-07-18T17:30:00.0000000Z\",\"hardwareId\":\"72A4BC9E3A72C063\",\"appVersion\":\"2.2.843\",\"trigger\":\"RuntimeCheck_NativeDllSwapped\",\"severity\":3}";

    private static CanaryAckResponse CreateResponse() => new()
    {
        Schema = CanaryAckService.Schema,
        Alg = CanaryAckService.Algorithm,
        KeyId = CanaryAckService.KeyId,
        EventId = "12345678-1234-4234-9234-1234567890ab",
        HardwareId = "72A4BC9E3A72C063",
        AppVersion = "2.2.843",
        Decision = "ack",
        IssuedAtUtc = Timestamp,
        ExpiresAtUtc = "2026-07-18T17:33:00.0000000Z",
        ReceiptId = "12345678-1234-4234-9234-1234567890ae",
        Signature = "signed"
    };

    private sealed class TestDbContextFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options;
        public LicenseDbContext CreateDbContext() => new(_options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

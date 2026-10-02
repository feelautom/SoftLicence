using System.Reflection;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Protects the provider-owned portal-deactivation authority boundary independently of deployment configuration.
/// </summary>
public sealed class PortalDeactivationContractTests
{
    private const string RequestId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    private const string ProductId = "12345678-1234-4234-9234-1234567890ab";
    private const string LicenseId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private const string HardwareId = "ABCDEF0123456789";
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 18, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Requires a dedicated S2S capability on both configured clients and authenticated principals.
    /// </summary>
    [Fact]
    public void DistributionS2SAuthority_ExposesDedicatedPortalDeactivationCapability()
    {
        Assert.NotNull(typeof(DistributionS2SClientOptions).GetProperty("AllowPortalDeactivation"));
        Assert.NotNull(typeof(DistributionS2SPrincipal).GetProperty("AllowPortalDeactivation"));
    }

    /// <summary>Proves a real PS256 authentication propagates only the explicitly configured portal capability.</summary>
    [Fact]
    public async Task DistributionS2SAuthentication_PropagatesExplicitPortalCapability()
    {
        Assert.False(new DistributionS2SClientOptions().AllowPortalDeactivation);
        using var rsa = RSA.Create(2048);
        var factory = new TestDbContextFactory("portal-auth-" + Guid.NewGuid().ToString("N"));
        var service = new DistributionS2SAuthenticationService(
            factory,
            Options.Create(new DistributionS2SOptions
            {
                Clients =
                [
                    new DistributionS2SClientOptions
                    {
                        ClientId = "tia-connect-website-portal",
                        KeyId = "portal-key-2026-01",
                        PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
                        AllowPortalDeactivation = true,
                        ProductIds = [ProductId],
                        AllowedCidrs = ["127.0.0.1/32"]
                    }
                ]
            }),
            new FixedTimeProvider(Now));
        var body = Encoding.UTF8.GetBytes(ValidBody("settings_button"));
        const string nonce = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        const string timestamp = "2026-08-30T18:00:00.0000000Z";
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/internal/v1/portal-deactivations";
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Headers[DistributionS2SAuthenticationService.ClientHeader] = "tia-connect-website-portal";
        context.Request.Headers[DistributionS2SAuthenticationService.KeyIdHeader] = "portal-key-2026-01";
        context.Request.Headers[DistributionS2SAuthenticationService.TimestampHeader] = timestamp;
        context.Request.Headers[DistributionS2SAuthenticationService.NonceHeader] = nonce;
        var payload = DistributionS2SAuthenticationService.BuildSignaturePayload(
            "tia-connect-website-portal",
            "portal-key-2026-01",
            HttpMethods.Post,
            "/api/internal/v1/portal-deactivations",
            timestamp,
            nonce,
            body);
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        context.Request.Headers[DistributionS2SAuthenticationService.SignatureHeader] =
            Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        context.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.1");
        var denied = await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            service.AuthenticateAndReserveNonceAsync(context, body, ProductId));
        Assert.Equal("authentication_failed", denied.ErrorCode);
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        var principal = await service.AuthenticateAndReserveNonceAsync(context, body, ProductId);

        Assert.True(principal.AllowPortalDeactivation);
        Assert.False(principal.AllowRuntimeRecovery);
        Assert.False(principal.AllowRuntimeUpgrade);
        Assert.False(principal.AllowLicenseBootstrap);
    }

    /// <summary>Proves portal capability cannot be combined with other privileges or diverge across key rotation.</summary>
    [Fact]
    public void DistributionS2SOptions_RejectMixedPortalIdentityCapabilities()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfoPem();
        var result = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            Clients =
            [
                new DistributionS2SClientOptions
                {
                    ClientId = "tia-connect-website-portal",
                    KeyId = "portal-key-2026-01",
                    PublicKeyPem = publicKey,
                    AllowPortalDeactivation = true,
                    ProductIds = [ProductId],
                    AllowedCidrs = ["127.0.0.1/32"]
                },
                new DistributionS2SClientOptions
                {
                    ClientId = "tia-connect-website-portal",
                    KeyId = "portal-key-2026-02",
                    PublicKeyPem = publicKey,
                    AllowRuntimeRecovery = true,
                    ProductIds = [ProductId],
                    AllowedCidrs = ["127.0.0.1/32"]
                }
            ]
        });

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, failure => failure.Contains("dedicated client identity", StringComparison.Ordinal));
    }

    /// <summary>
    /// Proves the anonymous public endpoint never treats the literal portal source as trusted authority.
    /// </summary>
    [Fact]
    public void PublicActivationApi_PortalSourceCannotBypassAnonymousGuard()
    {
        var normalize = typeof(ActivationController).GetMethod(
            "NormalizeDeactivationSource",
            BindingFlags.NonPublic | BindingFlags.Static);
        var isTrusted = typeof(ActivationController).GetMethod(
            "IsTrustedImmediateDeactivationSource",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(normalize);
        Assert.NotNull(isTrusted);
        var normalized = Assert.IsType<string>(normalize.Invoke(null, ["portal", null]));
        Assert.Equal("unknown", normalized);
        Assert.False(Assert.IsType<bool>(isTrusted.Invoke(null, [normalized])));
    }

    /// <summary>
    /// Requires full request and response redaction for the internal provider route.
    /// </summary>
    [Fact]
    public void ProviderRoute_IsClassifiedAsSensitiveAuditTraffic()
    {
        var classifier = typeof(AuditMiddleware).GetMethod(
            "IsDistributionS2SPath",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(classifier);
        Assert.True(Assert.IsType<bool>(classifier.Invoke(
            null,
            ["/api/internal/v1/portal-deactivations"])));
        Assert.True(Assert.IsType<bool>(classifier.Invoke(
            null,
            ["/api/internal/v1/portal-deactivations/"])));
    }

    /// <summary>
    /// Proves exact bytes are authenticated before the dedicated capability permits provider mutation.
    /// </summary>
    [Fact]
    public async Task Controller_AuthenticatesExactBodyAndReturnsBoundedTerminalResult()
    {
        var body = ValidBody("settings_button");
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                ProductId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "tia-connect-website-portal",
                "portal-key",
                AllowPortalDeactivation: true));
        var deactivations = new Mock<IPortalDeactivationService>();
        deactivations.Setup(service => service.DeactivateAsync(
                "tia-connect-website-portal",
                It.Is<string>(digest => IsLowerSha256(digest)),
                It.Is<PortalDeactivationRequest>(request => request.Reason == "settings_button"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PortalDeactivationResult(
                new PortalDeactivationResponse(PortalDeactivationService.ResponseSchema, RequestId, PortalDeactivationService.DeactivatedOutcome),
                false));
        var controller = CreateController(authentication.Object, deactivations.Object, body);

        var result = Assert.IsType<OkObjectResult>(await controller.Deactivate(CancellationToken.None));

        Assert.Equal(
            new PortalDeactivationResponse(PortalDeactivationService.ResponseSchema, RequestId, PortalDeactivationService.DeactivatedOutcome),
            result.Value);
        deactivations.VerifyAll();
    }

    /// <summary>
    /// Proves an authenticated client without the dedicated capability cannot reach the mutation service.
    /// </summary>
    [Fact]
    public async Task Controller_MissingCapabilityFailsBeforeProviderMutation()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("distribution-client", "key"));
        var deactivations = new Mock<IPortalDeactivationService>();
        var controller = CreateController(authentication.Object, deactivations.Object, ValidBody("settings_button"));

        var result = Assert.IsType<ObjectResult>(await controller.Deactivate(CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        Assert.Equal(new DistributionApiError("capability_denied"), result.Value);
        deactivations.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Proves duplicate JSON members consume authentication nonce authority but never reach mutation.
    /// </summary>
    [Fact]
    public async Task Controller_DuplicateMemberFailsClosedAfterAuthentication()
    {
        var body = ValidBody("settings_button").Replace(
            $"\"productId\":\"{ProductId}\"",
            $"\"productId\":\"{ProductId}\",\"licenseId\":\"{LicenseId}\"");
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "tia-connect-website-portal", "portal-key", AllowPortalDeactivation: true));
        var deactivations = new Mock<IPortalDeactivationService>();
        var controller = CreateController(authentication.Object, deactivations.Object, body);

        Assert.IsType<BadRequestObjectResult>(await controller.Deactivate(CancellationToken.None));

        authentication.VerifyAll();
        deactivations.VerifyNoOtherCalls();
    }

    /// <summary>Proves unknown DTO members remain closed after exact-body authentication.</summary>
    [Fact]
    public async Task Controller_UnknownMemberFailsClosedAfterAuthentication()
    {
        var body = ValidBody("settings_button").Replace("}", ",\"unexpected\":true}");
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "tia-connect-website-portal", "portal-key", AllowPortalDeactivation: true));
        var deactivations = new Mock<IPortalDeactivationService>();
        var controller = CreateController(authentication.Object, deactivations.Object, body);

        Assert.IsType<BadRequestObjectResult>(await controller.Deactivate(CancellationToken.None));

        authentication.VerifyAll();
        deactivations.VerifyNoOtherCalls();
    }

    /// <summary>Proves the 4,096-byte transport limit is enforced before authentication.</summary>
    [Fact]
    public async Task Controller_OversizedBodyFailsBeforeAuthentication()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        var deactivations = new Mock<IPortalDeactivationService>();
        var controller = CreateController(authentication.Object, deactivations.Object, new string('x', 4097));

        Assert.IsType<BadRequestObjectResult>(await controller.Deactivate(CancellationToken.None));

        authentication.VerifyNoOtherCalls();
        deactivations.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Proves the TKT-733 correlation header is mandatory and must equal the signed body request UUID ordinally.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")]
    [InlineData("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")]
    public async Task Controller_MissingOrDivergentCorrelationFailsClosedAfterAuthentication(string? correlationId)
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "tia-connect-website-portal", "portal-key", AllowPortalDeactivation: true));
        var deactivations = new Mock<IPortalDeactivationService>();
        var controller = CreateController(
            authentication.Object,
            deactivations.Object,
            ValidBody("settings_button"),
            correlationId);

        Assert.IsType<BadRequestObjectResult>(await controller.Deactivate(CancellationToken.None));

        authentication.VerifyAll();
        deactivations.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Proves the real HTTP pipeline routes the endpoint and persists no portal payload identifiers.
    /// </summary>
    [Fact]
    public async Task HttpPipeline_SuccessPersistsOnlyRedactedAuditPayload()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(
                "tia-connect-website-portal", "portal-key", AllowPortalDeactivation: true));
        var deactivations = new Mock<IPortalDeactivationService>();
        deactivations.Setup(service => service.DeactivateAsync(
                "tia-connect-website-portal", It.IsAny<string>(), It.IsAny<PortalDeactivationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PortalDeactivationResult(
                new PortalDeactivationResponse(PortalDeactivationService.ResponseSchema, RequestId, PortalDeactivationService.DeactivatedOutcome),
                false));
        using var factory = CreateAuditFactory(authentication.Object, deactivations.Object);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/internal/v1/portal-deactivations")
        {
            Content = new StringContent(ValidBody("settings_button"), Encoding.UTF8, "application/json")
        };
        request.Headers.Add("X-Correlation-Id", RequestId);

        using var response = await factory.CreateClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var log = await WaitForAuditLogAsync(factory.Services);
        Assert.Equal("[REDACTED]", log.RequestBody);
        Assert.Null(log.ErrorDetails);
        var persisted = string.Join('|', log.RequestBody, log.ErrorDetails, log.LicenseKey, log.HardwareId);
        foreach (var sensitive in new[] { RequestId, ProductId, LicenseId, HardwareId })
            Assert.DoesNotContain(sensitive, persisted, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Proves exact replay is terminal while a changed digest for the same request identifier conflicts.
    /// </summary>
    [Fact]
    public async Task Service_ExactReplayIsStableAndChangedPayloadConflicts()
    {
        var fixture = CreateServiceFixture(active: true, seatAge: TimeSpan.FromMinutes(10));
        var request = ValidRequest("subscription_termination");

        var first = await fixture.Service.DeactivateAsync("tia-connect-website-portal", new string('a', 64), request);
        var replay = await fixture.Service.DeactivateAsync("tia-connect-website-portal", new string('a', 64), request);
        var conflict = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            fixture.Service.DeactivateAsync("tia-connect-website-portal", new string('b', 64), request));

        Assert.False(first.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(first.Response, replay.Response);
        Assert.Equal("idempotency_conflict", conflict.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Single(await verify.PortalDeactivationOperations.ToListAsync());
        Assert.Single(await verify.LicenseHistories.ToListAsync());
        Assert.False((await verify.LicenseSeats.SingleAsync()).IsActive);
    }

    /// <summary>
    /// Proves only settings and uninstall can bypass the five-minute anonymous guard.
    /// </summary>
    [Theory]
    [InlineData("settings_button", true)]
    [InlineData("uninstall", true)]
    [InlineData("subscription_termination", false)]
    public async Task Service_RecentSeatBypassIsClosedByReason(string reason, bool permitted)
    {
        var fixture = CreateServiceFixture(active: true, seatAge: TimeSpan.FromMinutes(1));
        if (permitted)
        {
            var result = await fixture.Service.DeactivateAsync(
                "tia-connect-website-portal", new string('a', 64), ValidRequest(reason));
            Assert.Equal(PortalDeactivationService.DeactivatedOutcome, result.Response.Outcome);
            return;
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            fixture.Service.DeactivateAsync(
                "tia-connect-website-portal", new string('a', 64), ValidRequest(reason)));
        Assert.Equal("deactivation_guard_active", exception.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, exception.StatusCode);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.True((await verify.LicenseSeats.SingleAsync()).IsActive);
        Assert.Empty(await verify.PortalDeactivationOperations.ToListAsync());
    }

    /// <summary>Proves a future-dated seat never enters an interactive bypass path.</summary>
    [Fact]
    public async Task Service_FutureSeatFailsClosedForInteractiveReason()
    {
        var fixture = CreateServiceFixture(active: true, seatAge: TimeSpan.FromMinutes(-1));

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            fixture.Service.DeactivateAsync(
                "tia-connect-website-portal", new string('a', 64), ValidRequest("settings_button")));

        Assert.Equal("authority_inconsistent", exception.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, exception.StatusCode);
    }

    /// <summary>
    /// Proves an exact inactive seat returns the bounded terminal success without creating duplicate history.
    /// </summary>
    [Fact]
    public async Task Service_ExactInactiveSeatReturnsAlreadyInactive()
    {
        var fixture = CreateServiceFixture(active: false, seatAge: TimeSpan.FromHours(1));

        var result = await fixture.Service.DeactivateAsync(
            "tia-connect-website-portal", new string('a', 64), ValidRequest("uninstall"));

        Assert.Equal(PortalDeactivationService.AlreadyInactiveOutcome, result.Response.Outcome);
        await using var verify = fixture.Factory.CreateDbContext();
        Assert.Empty(await verify.LicenseHistories.ToListAsync());
        Assert.Single(await verify.PortalDeactivationOperations.ToListAsync());
    }

    /// <summary>
    /// Proves malformed, normalized, or non-canonical string variants remain fail-closed.
    /// </summary>
    [Theory]
    [InlineData("PORTAL-DEACTIVATION-V1", RequestId, ProductId, LicenseId, HardwareId, "settings_button")]
    [InlineData("portal-deactivation-v1", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", ProductId, LicenseId, HardwareId, "settings_button")]
    [InlineData("portal-deactivation-v1", RequestId, ProductId, LicenseId, "abcdef0123456789", "settings_button")]
    [InlineData("portal-deactivation-v1", RequestId, ProductId, LicenseId, HardwareId, "Settings_Button")]
    [InlineData("portal-deactivation-v1", RequestId, ProductId, LicenseId, HardwareId, "revocation_cleanup")]
    [InlineData("portal-deactivation-v1 ", RequestId, ProductId, LicenseId, HardwareId, "settings_button")]
    [InlineData("portal-deactivation-v1", RequestId, ProductId, LicenseId, "ABCDEF0123456789 ", "settings_button")]
    [InlineData("portal-deactivation-v1", RequestId, ProductId, LicenseId, HardwareId, "")]
    public async Task Service_StringVariantsRemainFailClosed(
        string schema,
        string requestId,
        string productId,
        string licenseId,
        string hardwareId,
        string reason)
    {
        var fixture = CreateServiceFixture(active: true, seatAge: TimeSpan.FromHours(1));
        var request = new PortalDeactivationRequest(schema, requestId, productId, licenseId, hardwareId, reason);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            fixture.Service.DeactivateAsync("tia-connect-website-portal", new string('a', 64), request));

        Assert.Equal("invalid_request", exception.ErrorCode);
        Assert.Equal(StatusCodes.Status400BadRequest, exception.StatusCode);
    }

    private static PortalDeactivationsController CreateController(
        IDistributionS2SAuthenticationService authentication,
        IPortalDeactivationService deactivations,
        string body,
        string? correlationId = RequestId)
    {
        var context = new DefaultHttpContext();
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        context.Request.ContentLength = Encoding.UTF8.GetByteCount(body);
        context.Request.ContentType = "application/json; charset=utf-8";
        if (correlationId != null)
            context.Request.Headers["X-Correlation-Id"] = correlationId;
        return new PortalDeactivationsController(authentication, deactivations)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }

    private static WebApplicationFactory<Program> CreateAuditFactory(
        IDistributionS2SAuthenticationService authentication,
        IPortalDeactivationService deactivations)
    {
        var databaseName = "audit-portal-" + Guid.NewGuid().ToString("N");
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<IDistributionS2SAuthenticationService>();
                services.RemoveAll<IPortalDeactivationService>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(databaseName));
                services.AddSingleton(authentication);
                services.AddSingleton(deactivations);
            });
        });
    }

    private static async Task<AccessLog> WaitForAuditLogAsync(IServiceProvider services)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            await using var scope = services.CreateAsyncScope();
            var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
            await using var db = await factory.CreateDbContextAsync();
            var log = await db.AccessLogs.AsNoTracking()
                .OrderByDescending(candidate => candidate.Timestamp)
                .FirstOrDefaultAsync(candidate => candidate.Path == "/api/internal/v1/portal-deactivations");
            if (log != null)
                return log;
            await Task.Delay(100);
        }
        throw new TimeoutException("Expected redacted portal-deactivation audit log was not written.");
    }

    private static string ValidBody(string reason) =>
        $$"""{"schema":"portal-deactivation-v1","requestId":"{{RequestId}}","productId":"{{ProductId}}","licenseId":"{{LicenseId}}","hardwareId":"{{HardwareId}}","reason":"{{reason}}"}""";

    private static PortalDeactivationRequest ValidRequest(string reason) =>
        new(PortalDeactivationService.RequestSchema, RequestId, ProductId, LicenseId, HardwareId, reason);

    private static bool IsLowerSha256(string value) =>
        value.Length == 64
        && value.All(character =>
            (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f'));

    /// <summary>Proves a type-defined quota refuses without a seat, history, or receipt mutation.</summary>
    [Fact]
    public async Task Service_QuotaRefusalHasZeroEffectAndCanRetryNextUtcDay()
    {
        var fixture = CreateServiceFixture(active: true, seatAge: TimeSpan.FromHours(1));
        await using (var seed = fixture.Factory.CreateDbContext())
        {
            var license = await seed.Licenses.Include(row => row.Type).SingleAsync();
            license.Type!.MaxActivationsPerDay = 2;
            for (var index = 0; index < 2; index++)
                seed.LicenseSeats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = $"OTHER-{index}", IsActive = false, UnlinkedAt = Now.UtcDateTime });
            await seed.SaveChangesAsync();
        }
        var request = ValidRequest("settings_button");
        var refusal = await Record.ExceptionAsync(() => fixture.Service.DeactivateAsync("tia-connect-website-portal", new string('a', 64), request));
        var quota = Assert.IsType<PortalDeactivationQuotaException>(refusal);
        Assert.Equal(2, quota.Refusal.Limit);
        Assert.Equal(RequestId, quota.Refusal.RequestId);
        Assert.Equal(Now.UtcDateTime.Date.AddDays(1), quota.Refusal.ResetAtUtc);
        await using (var verify = fixture.Factory.CreateDbContext())
        {
            Assert.True((await verify.LicenseSeats.SingleAsync(row => row.HardwareId == HardwareId)).IsActive);
            Assert.Empty(await verify.PortalDeactivationOperations.ToListAsync());
            Assert.Empty(await verify.LicenseHistories.ToListAsync());
        }
        var tomorrow = new PortalDeactivationService(fixture.Factory, new FixedTimeProvider(Now.AddDays(1)), NullLogger<PortalDeactivationService>.Instance);
        var result = await tomorrow.DeactivateAsync("tia-connect-website-portal", new string('a', 64), request);
        Assert.Equal("deactivated", result.Response.Outcome);
    }

    /// <summary>Preserves unlimited policy for every non-positive type limit.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task NonPositiveQuota_IsUnlimited(int limit)
    {
        var fixture = CreateServiceFixture(true, TimeSpan.FromHours(1));
        await using (var db = fixture.Factory.CreateDbContext())
        {
            (await db.LicenseTypes.SingleAsync()).MaxActivationsPerDay = limit;
            db.LicenseSeats.Add(new LicenseSeat { LicenseId = Guid.Parse(LicenseId), HardwareId = "OTHER-QUOTA", IsActive = false, UnlinkedAt = Now.UtcDateTime });
            await db.SaveChangesAsync();
        }
        Assert.Equal("deactivated", (await fixture.Service.DeactivateAsync("tia-connect-website-portal", new string('a', 64), ValidRequest("settings_button"))).Response.Outcome);
    }

    /// <summary>Verifies HTTP status and the exact dynamic refusal contract after authentication.</summary>
    [Fact]
    public async Task Controller_QuotaRefusalHasClosedDynamicContract()
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
            It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website-portal", "key", AllowPortalDeactivation: true));
        var refusal = new PortalDeactivationQuotaRefusal("portal-deactivation-refusal-v1", RequestId,
            "deactivation_quota_exceeded", 7, Now.UtcDateTime.Date.AddDays(1));
        var service = new Mock<IPortalDeactivationService>();
        service.Setup(provider => provider.DeactivateAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<PortalDeactivationRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new PortalDeactivationQuotaException(refusal));
        var controller = CreateController(authentication.Object, service.Object, ValidBody("settings_button"));
        var result = Assert.IsType<ObjectResult>(await controller.Deactivate(CancellationToken.None));
        Assert.Equal(429, result.StatusCode);
        Assert.Equal(refusal, result.Value);
    }

    private static ServiceFixture CreateServiceFixture(bool active, TimeSpan seatAge)
    {
        var factory = new TestDbContextFactory(Guid.NewGuid().ToString("N"));
        using (var db = factory.CreateDbContext())
        {
            var license = new License
            {
                Id = Guid.Parse(LicenseId),
                ProductId = Guid.Parse(ProductId),
                LicenseTypeId = Guid.Parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
                Type = new LicenseType { Id = Guid.Parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), Name = "Portal", Slug = "PORTAL" },
                LicenseKey = "PORTAL-TEST-LICENSE",
                HardwareId = active ? HardwareId : null,
                ActivationDate = active ? Now.UtcDateTime - seatAge : null
            };
            license.Seats.Add(new LicenseSeat
            {
                Id = Guid.Parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
                LicenseId = license.Id,
                HardwareId = HardwareId,
                FirstActivatedAt = Now.UtcDateTime - seatAge,
                LastCheckInAt = Now.UtcDateTime - TimeSpan.FromSeconds(30),
                IsActive = active,
                UnlinkedAt = active ? null : Now.UtcDateTime - TimeSpan.FromMinutes(1)
            });
            db.Licenses.Add(license);
            db.SaveChanges();
        }
        var service = new PortalDeactivationService(
            factory,
            new FixedTimeProvider(Now),
            NullLogger<PortalDeactivationService>.Instance);
        return new ServiceFixture(factory, service);
    }

    private sealed record ServiceFixture(TestDbContextFactory Factory, PortalDeactivationService Service);

    private sealed class TestDbContextFactory(string databaseName) : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>().UseInMemoryDatabase(databaseName).Options;

        public LicenseDbContext CreateDbContext() => new(_options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

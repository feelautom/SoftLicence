using System.Reflection;
using System.Net;
using System.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class AuditMiddlewareRuntimeEnrollmentRedactionTests
{
    [Theory]
    [InlineData("/api/internal/v1/runtime-enrollments/prepare")]
    [InlineData("/api/internal/v1/runtime-enrollments/prepare/")]
    [InlineData("/api/internal/v1/runtime-enrollments/other")]
    [InlineData("/api/internal/v2/runtime-enrollment-authority/generations")]
    [InlineData("/api/internal/v2/runtime-enrollment-authority/recovery-preparations")]
    [InlineData("/api/internal/v2/runtime-enrollment-authority/recovery-finalizations")]
    [InlineData("/api/internal/test/v1/runtime-enrollment-source-c-authority")]
    [InlineData("/api/internal/test/v1/runtime-enrollment-source-c-authority/")]
    [InlineData("/api/v1/runtime-enrollments")]
    [InlineData("/api/v1/runtime-enrollments/id/status")]
    [InlineData("/api/v1/runtime-enrollments/not-even-a-uuid/confirm")]
    [InlineData("/api/v1/runtime-enrollments/11111111-1111-4111-8111-111111111111/capabilities/")]
    public void RuntimeEnrollmentRoutes_AreAlwaysClassifiedSensitive(string path)
    {
        var method = typeof(AuditMiddleware).GetMethod(
            "IsRuntimeEnrollmentPath", BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        Assert.True((bool)method.Invoke(null, [path])!);
    }

    [Theory]
    [InlineData("/api/v1/licenses")]
    [InlineData("/api/internal/v1/distribution-bindings")]
    public void UnrelatedRoutes_AreNotClassifiedAsRuntimeSensitive(string path)
    {
        var method = typeof(AuditMiddleware).GetMethod(
            "IsRuntimeEnrollmentPath", BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        Assert.False((bool)method.Invoke(null, [path])!);
    }

    [Theory]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 150, false, true)]
    [InlineData("/API/V1/RUNTIME-ENROLLMENTS/id/capabilities", 199, false, true)]
    [InlineData("/api/internal/v1/runtime-enrollments/prepare", 150, false, false)]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 99, false, false)]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 200, false, false)]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 150, true, false)]
    public void RuntimeThreatDelayBypass_IsLimitedToPublicQuarantinedRequests(
        string path,
        int score,
        bool whitelisted,
        bool expected)
    {
        var method = typeof(AuditMiddleware).GetMethod(
            "ShouldBypassThreatScoreDelay", BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        Assert.Equal(expected, (bool)method.Invoke(null, [path, score, whitelisted])!);
    }

    [Theory]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 401, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, true)]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 401, null, false)]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 401, "invalid_signature", false)]
    [InlineData("/api/v1/runtime-enrollments/id/capabilities", 403, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, false)]
    [InlineData("/api/internal/v1/runtime-enrollments/prepare", 401, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, false)]
    [InlineData("/api/activation/check", 401, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, false)]
    public void AuthenticationThreatScoreSuppression_RequiresExactServerClassification(
        string path,
        int statusCode,
        string? disposition,
        bool expected)
    {
        var method = typeof(AuditMiddleware).GetMethod(
            "ShouldSuppressAuthenticationThreatScore", BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        Assert.Equal(expected, (bool)method.Invoke(null, [path, statusCode, disposition])!);
    }

    [Theory]
    [InlineData("/api/health/ping", true)]
    [InlineData("/api/health/ping/", false)]
    [InlineData("/api/health/ping/extra", false)]
    [InlineData("/api/health", false)]
    public void CanaryEvidenceRoute_IsExactAndExcludedFromGenericAudit(string path, bool expected)
    {
        var method = typeof(AuditMiddleware).GetMethod(
            "IsCanaryEvidencePath", BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        Assert.Equal(expected, (bool)method.Invoke(null, [path])!);
    }

    [Fact]
    public async Task CanaryEvidenceRoute_FromBannedIp_IsRejectedBeforeConfidentialAuditBypass()
    {
        const string bannedIp = "203.0.113.77";
        var factory = new TestDbContextFactory();
        await using (var db = await factory.CreateDbContextAsync())
        {
            db.BannedIps.Add(new BannedIp
            {
                IpAddress = bannedIp,
                BannedAt = DateTime.UtcNow,
                Reason = "test",
                IsActive = true
            });
            await db.SaveChangesAsync();
        }
        var configuration = new ConfigurationBuilder().Build();
        var notifications = new NotificationService(
            factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        var security = new SecurityService(
            factory, Mock.Of<ILogger<SecurityService>>(), notifications, configuration);
        var nextCalled = false;
        var middleware = new AuditMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            Mock.Of<ILogger<AuditMiddleware>>(), Mock.Of<IServiceScopeFactory>());
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(bannedIp);
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/health/ping";
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context, factory, security, null!, configuration, null!);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        Assert.Equal("Access Denied (Banned)", await new StreamReader(context.Response.Body).ReadToEndAsync());
    }

    [Fact]
    public async Task PublicRuntimeRoute_FromBannedIp_IsRejectedBeforeThreatDelayBypass()
    {
        const string bannedIp = "203.0.113.78";
        var factory = new TestDbContextFactory();
        await using (var db = await factory.CreateDbContextAsync())
        {
            db.BannedIps.Add(new BannedIp
            {
                IpAddress = bannedIp,
                BannedAt = DateTime.UtcNow,
                Reason = "test",
                IsActive = true
            });
            await db.SaveChangesAsync();
        }
        var configuration = new ConfigurationBuilder().Build();
        var notifications = new NotificationService(
            factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        var security = new SecurityService(
            factory, Mock.Of<ILogger<SecurityService>>(), notifications, configuration);
        var nextCalled = false;
        var middleware = new AuditMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            Mock.Of<ILogger<AuditMiddleware>>(), Mock.Of<IServiceScopeFactory>());
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(bannedIp);
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/v1/runtime-enrollments/11111111-1111-4111-8111-111111111111/capabilities";
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context, factory, security, null!, configuration, null!);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task ExpectedRuntimeClockRecovery_BypassesDelayAndKeepsThreatScore()
    {
        const string clientIp = "203.0.113.79";
        var factory = new TestDbContextFactory();
        var configuration = new ConfigurationBuilder().Build();
        var notifications = new NotificationService(
            factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        var security = new SecurityService(
            factory, Mock.Of<ILogger<SecurityService>>(), notifications, configuration);
        await security.ReportThreatAsync(clientIp, 50, "test-runtime-auth-1");
        await security.ReportThreatAsync(clientIp, 50, "test-runtime-auth-2");
        await security.ReportThreatAsync(clientIp, 50, "test-runtime-auth-3");
        Assert.Equal(150, security.GetThreatScore(clientIp));

        var auditNotifier = new AuditNotifier();
        using var provider = new ServiceCollection()
            .AddSingleton<IDbContextFactory<LicenseDbContext>>(factory)
            .AddSingleton(security)
            .AddSingleton(auditNotifier)
            .BuildServiceProvider();
        var logger = new Mock<ILogger<AuditMiddleware>>();
        var environment = new Mock<IWebHostEnvironment>();
        environment.SetupGet(value => value.ContentRootPath).Returns(Path.GetTempPath());
        var geoIp = new Mock<GeoIpService>(
            MockBehavior.Strict,
            environment.Object,
            new MemoryCache(new MemoryCacheOptions()),
            Mock.Of<ILogger<GeoIpService>>());
        geoIp.Setup(service => service.GetGeoInfoAsync(clientIp))
            .ReturnsAsync(new SoftLicence.Server.Models.GeoInfo());
        var middleware = new AuditMiddleware(
            async context =>
            {
                context.Items[SoftLicence.Server.LogKeys.RuntimeAuthenticationDisposition] =
                    RuntimeEnrollmentService.ProofClockSkewDiagnosticCode;
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("{\"error\":\"authentication_failed\"}");
            },
            logger.Object,
            provider.GetRequiredService<IServiceScopeFactory>());
        var httpContext = new DefaultHttpContext
        {
            RequestServices = provider,
            Response = { Body = new MemoryStream() }
        };
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse(clientIp);
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Path =
            "/api/v1/runtime-enrollments/11111111-1111-4111-8111-111111111111/capabilities";

        var stopwatch = Stopwatch.StartNew();
        await middleware.InvokeAsync(
            httpContext,
            factory,
            security,
            geoIp.Object,
            configuration,
            auditNotifier);
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2),
            $"Expected Runtime bypass to avoid the 10-second tarpit; elapsed {stopwatch.Elapsed}.");
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline && !HasExpectedRecoveryLog(logger))
            await Task.Delay(50);
        Assert.True(HasExpectedRecoveryLog(logger));
        Assert.Equal(150, security.GetThreatScore(clientIp));
        Assert.Contains(logger.Invocations, invocation =>
            invocation.Arguments.Count > 2
            && invocation.Arguments[2]?.ToString()?.Contains(
                "TEMP-FAIL-OPEN(TKT-001268) Public Runtime threat-score delay bypassed",
                StringComparison.Ordinal) == true);
    }

    private static bool HasExpectedRecoveryLog(Mock<ILogger<AuditMiddleware>> logger) =>
        logger.Invocations.Any(invocation =>
            invocation.Arguments.Count > 2
            && invocation.Arguments[2]?.ToString()?.Contains(
                "TEMP-FAIL-OPEN(TKT-001268) Expected Runtime authentication recovery was not threat-scored",
                StringComparison.Ordinal) == true);

    private sealed class TestDbContextFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>()
                .UseInMemoryDatabase("canary-audit-" + Guid.NewGuid().ToString("N"))
                .Options;

        public LicenseDbContext CreateDbContext() => new(_options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

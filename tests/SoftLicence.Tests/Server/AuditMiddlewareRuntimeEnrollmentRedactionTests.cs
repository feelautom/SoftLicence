using System.Reflection;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
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

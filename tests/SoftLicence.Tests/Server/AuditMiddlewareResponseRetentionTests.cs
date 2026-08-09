using System.Net;
using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SoftLicence.Server.Data;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class AuditMiddlewareResponseRetentionTests
{
    [Fact]
    public async Task LargeSuccessfulResponse_IsDeliveredButBodyIsNotPersisted()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/docs");
        var responseBytes = await response.Content.ReadAsByteArrayAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(responseBytes.Length > 16 * 1024);
        var log = await WaitForLogAsync(factory.Services, "/api/docs", StatusCodes.Status200OK);
        Assert.Null(log.ErrorDetails);
        Assert.Equal(responseBytes.LongLength, log.ResponseSizeBytes);
    }

    [Fact]
    public void ErrorDetails_AreBoundedAndSensitiveValuesAreRedacted()
    {
        var method = typeof(SoftLicence.Server.Middlewares.AuditMiddleware).GetMethod(
            "SanitizeErrorDetails", BindingFlags.NonPublic | BindingFlags.Static,
            null, [typeof(string), typeof(bool)], null);
        Assert.NotNull(method);
        var body = "{\"email\":\"person@example.test\",\"licenseKey\":\"SECRET-LICENSE-KEY\",\"token\":\"secret-token\",\"message\":\""
            + new string('x', 32 * 1024) + "\"}";

        var sanitized = Assert.IsType<string>(method.Invoke(null, [body, false]));

        Assert.True(Encoding.UTF8.GetByteCount(sanitized) <= 8 * 1024 + 128);
        Assert.Contains("[TRUNCATED]", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("person@example.test", sanitized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SECRET-LICENSE-KEY", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-token", sanitized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ErrorBoundaryAndMalformedPayloads_AreFailClosedThroughRealMiddleware()
    {
        using var factory = CreateFactory();
        var cases = new[]
        {
            new string('x', 8 * 1024 - 24) + "{\"password\":\"SECRET-PREFIX-WITHOUT-END",
            "{\"message\":\"Bearer VERY-SECRET-BEARER " + new string('y', 9 * 1024) + "\"}",
            "{\"email\":\"private@example.test\"",
            "{\"token\":\"MULTIBYTE-SECRET\",\"message\":\"" + string.Concat(Enumerable.Repeat("é🙂", 3000)) + "\"}"
        };

        for (var index = 0; index < cases.Length; index++)
        {
            var path = $"/api/test-error-boundary-{index}";
            await InvokeAuditMiddlewareAsync(factory.Services, path, cases[index]);
            var log = await WaitForLogAsync(factory.Services, path, StatusCodes.Status500InternalServerError);
            Assert.Equal("[REDACTED]", log.ErrorDetails);
            Assert.DoesNotContain("SECRET", log.ErrorDetails, StringComparison.Ordinal);
            Assert.DoesNotContain("private@example.test", log.ErrorDetails, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("VERY-SECRET-BEARER", log.ErrorDetails, StringComparison.Ordinal);
        }
    }

    private static async Task InvokeAuditMiddlewareAsync(IServiceProvider services, string path, string responseBody)
    {
        await using var scope = services.CreateAsyncScope();
        var provider = scope.ServiceProvider;
        var context = new DefaultHttpContext
        {
            RequestServices = provider,
            Response = { Body = new MemoryStream() }
        };
        context.Request.Path = path;
        context.Request.Method = HttpMethods.Get;
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
        var middleware = new AuditMiddleware(
            async httpContext =>
            {
                httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await httpContext.Response.WriteAsync(responseBody);
            },
            provider.GetRequiredService<ILogger<AuditMiddleware>>(),
            provider.GetRequiredService<IServiceScopeFactory>());
        await middleware.InvokeAsync(
            context,
            provider.GetRequiredService<IDbContextFactory<LicenseDbContext>>(),
            provider.GetRequiredService<SecurityService>(),
            provider.GetRequiredService<GeoIpService>(),
            provider.GetRequiredService<IConfiguration>(),
            provider.GetRequiredService<AuditNotifier>());
    }

    private static WebApplicationFactory<Program> CreateFactory()
    {
        var databaseName = $"audit-response-retention-{Guid.NewGuid():N}";
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(databaseName));
            });
        });
    }

    private static async Task<AccessLog> WaitForLogAsync(IServiceProvider services, string path, int statusCode)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            await using var scope = services.CreateAsyncScope();
            var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
            await using var db = await factory.CreateDbContextAsync();
            var log = await db.AccessLogs.AsNoTracking()
                .OrderByDescending(candidate => candidate.Timestamp)
                .FirstOrDefaultAsync(candidate => candidate.Path == path && candidate.StatusCode == statusCode);
            if (log != null)
                return log;
            await Task.Delay(100);
        }

        throw new TimeoutException("Expected audit log was not written.");
    }
}

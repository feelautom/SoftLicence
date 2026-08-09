using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class AuditMiddlewareTelemetryRedactionTests
{
    [Theory]
    [InlineData("/api/telemetry", true)]
    [InlineData("/api/telemetry/event", true)]
    [InlineData("/API/TELEMETRY/event/", true)]
    [InlineData("/api/telemetryevil/event", false)]
    [InlineData("/api/telemetry-event", false)]
    public void TelemetryRouteClassification_UsesSegmentBoundary(string path, bool expected)
    {
        var method = typeof(SoftLicence.Server.Middlewares.AuditMiddleware).GetMethod(
            "IsTelemetryApiPath",
            BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        Assert.Equal(expected, (bool)method.Invoke(null, [path])!);
    }

    [Fact]
    public async Task TelemetryEvent_AccessLogRedactsRequestAndResponseBodies()
    {
        const string path = "/api/telemetry/event";
        const string hardwareId = "DECLARED-HWID-FOR-TELEMETRY";
        const string malformedHash = "raw-malformed-approved-binary";
        var databaseName = $"audit-telemetry-{Guid.NewGuid():N}";
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(databaseName));
            });
        });
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
            await using var db = await dbFactory.CreateDbContextAsync();
            db.Products.Add(new Product
            {
                Name = "YOUR_APP_NAME",
                PrivateKeyXml = "key",
                PublicKeyXml = "key",
                ApiSecret = "synthetic-test-secret"
            });
            await db.SaveChangesAsync();
        }
        var body = JsonSerializer.Serialize(new
        {
            hardwareId,
            appName = "YOUR_APP_NAME",
            version = "1.2.3",
            eventName = "Startup_AppStarted",
            properties = new Dictionary<string, string> { ["FP_EXE"] = malformedHash }
        });

        using var response = await factory.CreateClient().PostAsync(
            path,
            new StringContent(body, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var log = await WaitForLogAsync(factory.Services, path);
        Assert.Equal("[REDACTED]", log.RequestBody);
        Assert.Null(log.ErrorDetails);
        Assert.True(string.IsNullOrEmpty(log.HardwareId));
        Assert.True(string.IsNullOrEmpty(log.LicenseKey));
        var bodies = string.Join('|', log.RequestBody, log.ErrorDetails);
        Assert.DoesNotContain(malformedHash, bodies, StringComparison.Ordinal);
        Assert.DoesNotContain(hardwareId, bodies, StringComparison.Ordinal);
    }

    private static async Task<AccessLog> WaitForLogAsync(IServiceProvider services, string path)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            await using var scope = services.CreateAsyncScope();
            var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
            await using var db = await factory.CreateDbContextAsync();
            var log = await db.AccessLogs.AsNoTracking().OrderByDescending(row => row.Timestamp)
                .FirstOrDefaultAsync(row => row.Path == path);
            if (log != null)
                return log;
            await Task.Delay(100);
        }

        throw new TimeoutException("Expected telemetry audit log was not written.");
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Protects the exact audit-redaction boundary for automatic and manual BugTrace report ingestion.
/// </summary>
public sealed class AuditMiddlewareBugTraceAutoReportRedactionTests
{
    [Theory]
    [InlineData("/api/bugtrace/auto-report", true)]
    [InlineData("/API/BUGTRACE/AUTO-REPORT", true)]
    [InlineData("/api/bugtrace/submit", true)]
    [InlineData("/API/BUGTRACE/SUBMIT", true)]
    [InlineData("/api/bugtrace/submit/", true)]
    [InlineData("/api/bugtrace/auto-report/extra", false)]
    [InlineData("/api/bugtrace/submit//", false)]
    [InlineData("/api/bugtrace/submit/extra", false)]
    [InlineData("/api/bugtrace/auto-reporting", false)]
    public void SensitiveReportRouteClassification_IsExactAndCaseInsensitive(string path, bool expected)
    {
        var classifier = typeof(AuditMiddleware).GetMethod(
            "IsBugTraceSensitiveReportPath",
            BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(classifier);
        Assert.Equal(expected, (bool)classifier.Invoke(null, [path])!);
    }

    /// <summary>
    /// Proves that the routable trailing-slash variant persists neither the request body nor
    /// structured licence and hardware authority after a successful keyed submission.
    /// </summary>
    [Fact]
    public async Task ManualSubmitTrailingSlash_AccessLogRedactsBodyLicenseAndHardware()
    {
        const string path = "/api/bugtrace/submit/";
        const string licenseKey = "TKT893-AUDIT-KEY";
        const string hardwareId = "89ABCDEF01234567";
        var databaseName = $"audit-bugtrace-submit-{Guid.NewGuid():N}";
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "CHANGE_ME_RANDOM_SECRET");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<IBugTraceProxyService>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase(databaseName));
                services.AddSingleton<IBugTraceProxyService>(new FakeBugTraceProxyService());
            });
        });
        await SeedLicenseAsync(factory.Services, licenseKey, hardwareId);

        using var response = await factory.CreateClient().PostAsJsonAsync(path, new
        {
            licenseKey,
            hardwareId,
            projectId = "9f3c8fea-8740-42af-be83-6f527c6d102a",
            ticket = new { title = "Audit proof", description = "Synthetic" }
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var log = await WaitForLogAsync(factory.Services, path);
        Assert.Equal("[REDACTED]", log.RequestBody);
        Assert.True(string.IsNullOrEmpty(log.LicenseKey));
        Assert.True(string.IsNullOrEmpty(log.HardwareId));
        var persisted = string.Join('|', log.RequestBody, log.LicenseKey, log.HardwareId);
        Assert.DoesNotContain(licenseKey, persisted, StringComparison.Ordinal);
        Assert.DoesNotContain(hardwareId, persisted, StringComparison.Ordinal);
    }

    /// <summary>Seeds the minimum active direct hardware history required by keyed submission.</summary>
    /// <param name="services">Application services bound to the isolated audit database.</param>
    /// <param name="licenseKey">Synthetic keyed authority.</param>
    /// <param name="hardwareId">Synthetic direct hardware history.</param>
    private static async Task SeedLicenseAsync(
        IServiceProvider services,
        string licenseKey,
        string hardwareId)
    {
        await using var scope = services.CreateAsyncScope();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await factory.CreateDbContextAsync();
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = "TKT-000893 audit proof",
            PrivateKeyXml = "test-private-placeholder",
            PublicKeyXml = "test-public-placeholder"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(),
            Product = product,
            Name = "TKT-000893 audit type",
            Slug = "TKT893-AUDIT"
        };
        db.AddRange(product, type, new License
        {
            Product = product,
            Type = type,
            LicenseTypeId = type.Id,
            LicenseKey = licenseKey,
            CustomerName = "Synthetic audit",
            CustomerEmail = "tkt893-audit@example.invalid",
            HardwareId = hardwareId,
            IsActive = true
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Waits for the middleware's asynchronous audit persistence for one exact request path.</summary>
    /// <param name="services">Application services that own the isolated audit database.</param>
    /// <param name="path">Exact request path, including its trailing slash.</param>
    /// <returns>The persisted audit record.</returns>
    private static async Task<AccessLog> WaitForLogAsync(IServiceProvider services, string path)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            await using var scope = services.CreateAsyncScope();
            var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
            await using var db = await factory.CreateDbContextAsync();
            var log = await db.AccessLogs.AsNoTracking()
                .OrderByDescending(candidate => candidate.Timestamp)
                .FirstOrDefaultAsync(candidate => candidate.Path == path);
            if (log != null)
                return log;
            await Task.Delay(100);
        }

        throw new TimeoutException("Expected redacted BugTrace audit log was not written.");
    }
}

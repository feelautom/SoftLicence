using System.Net;
using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class AuditMiddlewareDistributionRedactionTests
{
    private const string ClientId = "tia-connect-website";

    [Fact]
    public void GenericAuditSanitizer_RedactsHistoricalReplacementSubjectRef()
    {
        const string sourceSubjectRef = "sensitive-historical-subject-reference";
        var method = typeof(SoftLicence.Server.Middlewares.AuditMiddleware).GetMethod(
            "SanitizeErrorDetails",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: [typeof(string), typeof(bool)],
            modifiers: null);

        Assert.NotNull(method);
        var sanitized = Assert.IsType<string>(method.Invoke(
            null,
            [$"{{\"sourceSubjectRef\":\"{sourceSubjectRef}\",\"error\":\"binding_conflict\"}}", false]));
        Assert.DoesNotContain(sourceSubjectRef, sanitized, StringComparison.Ordinal);
        Assert.Contains("\"sourceSubjectRef\":\"[REDACTED]\"", sanitized, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/api/internal/v1/distribution-license-bootstraps/issue")]
    [InlineData("/api/internal/v1/distribution-license-bootstraps/remint")]
    [InlineData("/api/internal/v1/distribution-license-bootstraps/recover")]
    public void LicenseBootstrapRoutes_AreClassifiedAsSensitive(string path)
    {
        var method = typeof(SoftLicence.Server.Middlewares.AuditMiddleware).GetMethod(
            "IsDistributionS2SPath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        Assert.True((bool)method.Invoke(null, [path])!);
    }

    [Theory]
    [InlineData("/api/internal/v1/distribution-entitlements/issue")]
    [InlineData("/api/internal/v1/distribution-entitlements/issue/")]
    public async Task DistributionIssue_Success_DoesNotPersistLicenseIdOrEntitlementResponse(string path)
    {
        const string licenseId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const string entitlementRef = "CfDJ8-sensitive-bearer-entitlement-reference";
        const string body = "{\"schema\":\"distribution-entitlement-issue-v1\",\"requestId\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\",\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"softLicenceLicenseId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"}";
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.IssueEntitlementAsync(
                ClientId, It.IsAny<string>(), It.IsAny<DistributionEntitlementIssueRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionEntitlementIssueResponse>(
                new("distribution-entitlement-v1", entitlementRef, "2026-07-18T22:00:00.0000000Z"), false));
        using var factory = CreateFactory(bindings.Object);

        using var response = await PostJsonAsync(factory.CreateClient(), path, body);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Contains(entitlementRef, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        var log = await WaitForLogAsync(factory.Services, path, StatusCodes.Status201Created);
        AssertRedacted(log, licenseId, entitlementRef);
    }

    [Theory]
    [InlineData("/api/internal/v1/distribution-installation-bindings/finalize")]
    [InlineData("/api/internal/v1/distribution-installation-bindings/finalize/")]
    public async Task DistributionFinalize_Error_DoesNotPersistEntitlementHwidOrHashes(string path)
    {
        const string licenseId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
        const string entitlementRef = "CfDJ8-sensitive-bearer-entitlement-reference";
        const string hardwareId = "TEST-HWID-ABCDEF012345";
        var executableHash = new string('a', 64);
        var nativeHash = new string('b', 64);
        var coreHash = new string('c', 64);
        var installerHash = new string('d', 64);
        var body = $$"""
            {"schema":"distribution-installation-finalize-v1","requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","grantRef":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","handoffDigestSha256":"{{new string('e', 64)}}","handoffIssuedAtUtc":"2026-07-18T18:00:00.0000000Z","handoffExpiresAtUtc":"2026-07-18T20:00:00.0000000Z","downloadCompletedAtUtc":"2026-07-18T18:10:00.0000000Z","productId":"12345678-1234-4234-9234-1234567890ab","softLicenceLicenseId":"{{licenseId}}","entitlementRef":"{{entitlementRef}}","installationId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","hardwareId":"{{hardwareId}}","release":{"version":"2.2.844","installerFilename":"TiaConnect-Setup.exe","installerSha256":"{{installerHash}}"},"binaries":[{"key":"FP_EXE","sha256":"{{executableHash}}"},{"key":"FP_DLL","sha256":"{{nativeHash}}"},{"key":"FP_CORE","sha256":"{{coreHash}}"}]}
            """;
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.FinalizeAsync(
                ClientId, It.IsAny<string>(), It.IsAny<DistributionInstallationFinalizeRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionOperationException("binary_mismatch", StatusCodes.Status422UnprocessableEntity));
        using var factory = CreateFactory(bindings.Object);

        using var response = await PostJsonAsync(factory.CreateClient(), path, body);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var log = await WaitForLogAsync(factory.Services, path, StatusCodes.Status422UnprocessableEntity);
        AssertRedacted(log, licenseId, entitlementRef, hardwareId, executableHash, nativeHash, coreHash, installerHash);
    }

    [Theory]
    [InlineData("/api/internal/v1/distribution-installation-bindings/invalidate")]
    [InlineData("/api/internal/v1/distribution-installation-bindings/invalidate/")]
    public async Task DistributionInvalidate_DoesNotPersistSignedBodyOrPseudonymousEvidence(string path)
    {
        var grantDigest = new string('e', 64);
        var body = $$"""{"schema":"distribution-installation-invalidation-v1","requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","productId":"12345678-1234-4234-9234-1234567890ab","bindingId":null,"grantRefDigestSha256":"{{grantDigest}}","reason":"fraud_flagged","occurredAtUtc":"2026-07-18T18:20:00.0000000Z","epoch":1}""";
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.InvalidateAsync(
                ClientId, It.IsAny<string>(), It.IsAny<DistributionInstallationInvalidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionInstallationInvalidationResponse>(
                new("distribution-installation-invalidation-result-v1", null, "invalidated", grantDigest,
                    "fraud_flagged", "2026-07-18T18:20:00.0000000Z", 1, "2026-07-18T18:30:00.0000000Z"), false));
        using var factory = CreateFactory(bindings.Object);

        using var response = await PostJsonAsync(factory.CreateClient(), path, body);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var log = await WaitForLogAsync(factory.Services, path, StatusCodes.Status201Created);
        AssertRedacted(log, grantDigest, "fraud_flagged", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    }

    private static WebApplicationFactory<Program> CreateFactory(IDistributionInstallationBindingService bindings)
    {
        var databaseName = $"audit-distribution-{Guid.NewGuid():N}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(ClientId, "test-key"));

        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<IDistributionS2SAuthenticationService>();
                services.RemoveAll<IDistributionInstallationBindingService>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(databaseName));
                services.AddSingleton(authentication.Object);
                services.AddSingleton(bindings);
            });
        });
    }

    private static Task<HttpResponseMessage> PostJsonAsync(HttpClient client, string path, string body) =>
        client.PostAsync(path, new StringContent(body, Encoding.UTF8, "application/json"));

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
        throw new TimeoutException("Expected redacted Distribution S2S audit log was not written.");
    }

    private static void AssertRedacted(AccessLog log, params string[] sensitiveValues)
    {
        Assert.Equal("[REDACTED]", log.RequestBody);
        if (log.IsSuccess)
            Assert.Null(log.ErrorDetails);
        else
            Assert.Equal("[REDACTED]", log.ErrorDetails);
        Assert.True(string.IsNullOrEmpty(log.LicenseKey));
        Assert.True(string.IsNullOrEmpty(log.HardwareId));
        var persisted = string.Join('|', log.RequestBody, log.ErrorDetails, log.LicenseKey, log.HardwareId);
        foreach (var sensitiveValue in sensitiveValues)
            Assert.DoesNotContain(sensitiveValue, persisted, StringComparison.OrdinalIgnoreCase);
    }
}

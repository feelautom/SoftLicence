using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class AnalyticsControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string ValidAnalyticsKey = "sla_test_valid_analytics_key_001";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public AnalyticsControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "admin-secret");
            builder.UseSetting("AdminSettings:AllowedIps", "");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase(_dbName));
            });
        });
    }

    [Fact]
    public async Task TelemetryOverview_WhenProductKeyHeaderIsMissing_ReturnsUnauthorized()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/analytics/telemetry/overview");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TelemetryOverview_WhenProductKeyIsInvalid_ReturnsUnauthorized()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", "wrong-secret");

        var response = await client.GetAsync("/api/analytics/telemetry/overview");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TelemetryOverview_WhenProductKeyIsValid_ReturnsScopedSummary()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/overview?days=7&top=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal(4, GetInt(json, "recordsAnalyzed"));
        Assert.Equal(2, GetInt(json, "uniqueDevices"));

        var topEvents = GetArray(json, "topEvents");
        Assert.Contains(topEvents, e =>
            GetString(e, "name") == "Startup_AppStarted" && GetInt(e, "count") == 1);
        Assert.DoesNotContain(topEvents, e => GetString(e, "name") == "OtherProduct_Event");
    }

    [Fact]
    public async Task TelemetryOverview_WhenDateIsProvided_UsesCalendarDayPeriod()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);
        var date = DateTime.UtcNow.ToString("yyyy-MM-dd");

        var response = await client.GetAsync($"/api/analytics/telemetry/overview?date={date}&top=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal("date", GetString(json, "periodMode"));
        Assert.Equal(4, GetInt(json, "recordsAnalyzed"));
    }

    [Fact]
    public async Task TelemetryRawSample_ReturnsRedactedBoundedRecords()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/raw-sample?hardwareId=HW-A&take=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SECRET-LICENSE-001", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret-token-value", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private-secret-value", body, StringComparison.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(body);
        Assert.True(GetInt(doc.RootElement, "recordsReturned") <= 10);
        var records = GetArray(doc.RootElement, "records");
        Assert.Contains(records, r => GetString(r, "eventName") == "Startup_AppStarted");
        var startup = Assert.Single(records, r => GetString(r, "eventName") == "Startup_AppStarted");
        var properties = GetProperty(startup, "properties");
        Assert.Equal("Pass", GetString(properties, "OverallStatus"));
        Assert.Throws<KeyNotFoundException>(() => GetProperty(properties, "LicenseKey"));
    }

    [Fact]
    public async Task TelemetryDevices_ReturnsProductScopedDevices()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/devices?days=7&take=10&topEvents=5");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal(4, GetInt(json, "recordsAnalyzed"));
        Assert.Equal(2, GetInt(json, "totalDevices"));
        Assert.Equal(2, GetInt(json, "devicesReturned"));

        var devices = GetArray(json, "devices");
        Assert.Contains(devices, d => GetString(d, "hardwareId") == "HW-A");
        Assert.Contains(devices, d => GetString(d, "hardwareId") == "HW-B");
        Assert.DoesNotContain(devices, d => GetString(d, "hardwareId") == "HW-C");
    }

    [Fact]
    public async Task TelemetryInsights_ReturnsAuthFailureInsight()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/insights?days=7&top=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        var insights = GetArray(json, "insights");
        Assert.Contains(insights, i =>
            GetString(i, "category") == "auth"
            && GetString(i, "severity") == "warning"
            && GetInt(i, "count") == 1);
        Assert.Contains(insights, i =>
            GetString(i, "category") == "quota"
            && GetString(i, "severity") == "opportunity"
            && GetString(i, "summary")!.Contains("potential upgrade/conversion signal", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(insights, i =>
            GetString(i, "category") == "quota"
            && GetString(i, "severity") == "critical");
    }

    [Fact]
    public async Task TelemetryActivationFailures_ReturnsDetailsWithoutSensitiveActivationPayload()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/activation-failures?days=7&hardwareId=HW-A&take=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SECRET-LICENSE-001", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CUSTOMER-LICENSE-001", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ACTIVATION-REQUEST-BODY", body, StringComparison.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(body);
        Assert.Equal(1, GetInt(doc.RootElement, "recordsMatched"));
        Assert.Equal(1, GetInt(doc.RootElement, "recordsReturned"));

        var failures = GetArray(doc.RootElement, "failures");
        var failure = Assert.Single(failures);
        Assert.Equal("HW-A", GetString(failure, "hardwareId"));
        Assert.Equal("activation.failure@example.test", GetString(failure, "customerEmail"));
        Assert.Equal("BAD_REQUEST", GetString(failure, "status"));
        Assert.Equal("Invalid license key format", GetString(failure, "failureReason"));
        Assert.Equal("2.1.900", GetString(failure, "clientVersion"));
    }

    [Fact]
    public async Task SupportProfile_WhenHardwareIdPartialMatchesMultipleMachines_ReturnsAmbiguousBoundedCandidates()
    {
        await SeedTelemetryAsync();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var productId = await db.Products
                .Where(p => p.Name == "T-IA Connect")
                .Select(p => p.Id)
                .SingleAsync();

            AddEvent(db, productId, "CTRL01AAAABBBB", "Startup_AppStarted", "2.1.900", "{}", DateTime.UtcNow.AddMinutes(-10));
            AddEvent(db, productId, "CTRL01CCCCDDDD", "Mcp_ToolCall", "2.1.900", "{}", DateTime.UtcNow.AddMinutes(-5));
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/support/profile?hardwareId=HW-&days=7&take=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.False(GetBool(GetProperty(json, "query"), "hardwareIdPartialLookupEnabled"));
        Assert.Equal(0, GetInt(json, "candidateCount"));

        response = await client.GetAsync("/api/analytics/support/profile?hardwareId=CTRL01&days=7&take=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        json = await ReadJsonAsync(response);
        var query = GetProperty(json, "query");
        Assert.True(GetBool(query, "hasHardwareId"));
        Assert.True(GetBool(query, "hardwareIdPartialLookupEnabled"));
        Assert.Equal(6, GetInt(query, "hardwareIdLength"));
        Assert.True(GetBool(json, "isAmbiguous"));
        Assert.Equal(2, GetInt(json, "candidateCount"));
        Assert.Equal(JsonValueKind.Null, GetProperty(json, "selectedCandidate").ValueKind);
    }

    [Fact]
    public async Task SupportProfile_WhenSixCharHexHardwareIdFragmentMatchesTelemetryOnly_ReturnsCandidate()
    {
        await SeedTelemetryAsync();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var productId = await db.Products
                .Where(p => p.Name == "T-IA Connect")
                .Select(p => p.Id)
                .SingleAsync();

            AddEvent(db, productId, "D803580B5152BF70", "Startup_AppStarted", "2.1.997", "{}", DateTime.UtcNow.AddMinutes(-5));
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/support/profile?hardwareId=d803-58&days=30&take=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        var query = GetProperty(json, "query");
        Assert.True(GetBool(query, "hardwareIdPartialLookupEnabled"));
        Assert.Equal(6, GetInt(query, "hardwareIdLength"));
        Assert.Equal(1, GetInt(json, "candidateCount"));

        var selected = GetProperty(json, "selectedCandidate");
        Assert.Equal("D803580B5152BF70", GetString(selected, "hardwareId"));
        Assert.Equal("telemetry_hardware_fragment", GetString(selected, "matchType"));
    }

    [Fact]
    public async Task SecurityBans_WhenHardwareIdHasBannedFingerprint_ReturnsHardwareAndComponentBans()
    {
        await SeedTelemetryAsync();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var productId = await db.Products
                .Where(p => p.Name == "T-IA Connect")
                .Select(p => p.Id)
                .SingleAsync();

            db.HardwareFingerprints.Add(new HardwareFingerprint
            {
                HardwareId = "HW-SEC",
                MotherboardHash = "shared-mb-hash"
            });
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                ProductId = productId,
                HardwareId = "HW-SEC",
                Reason = "Manual review",
                BanCategory = BannedHardwareId.Categories.Manual
            });
            db.BannedComponents.Add(new BannedComponent
            {
                ProductId = productId,
                ComponentType = "MB",
                ComponentHash = "shared-mb-hash",
                Reason = "BinaryPatched: hash mismatch for v2.1.839 (FP_EXE: expected=aaa got=bbb)"
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/security/bans?hardwareId=HW-SEC&take=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal(2, GetInt(json, "recordsMatched"));
        var bans = GetArray(json, "bans");
        Assert.Contains(bans, b => GetString(b, "targetType") == "hardware_id" && GetString(b, "hardwareId") == "HW-SEC");
        var componentBan = bans.Single(b => GetString(b, "targetType") == "component");
        Assert.Equal("MB", GetString(componentBan, "componentType"));
        Assert.Equal("shared-mb-hash", GetString(componentBan, "componentHash"));
        Assert.Equal("MB", GetString(componentBan, "componentMatchType"));
        Assert.Equal("weak", GetString(componentBan, "componentMatchStrength"));
        Assert.True(GetBool(componentBan, "isWeakComponentCorrelation"));
        Assert.Contains("weak", GetString(componentBan, "componentMatchSummary"), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("FP_EXE", GetString(componentBan, "reason"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SecurityBanDetails_WhenComponentHashExistsInTelemetry_ReturnsSourceEvent()
    {
        await SeedTelemetryAsync();
        Guid banId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var productId = await db.Products
                .Where(p => p.Name == "T-IA Connect")
                .Select(p => p.Id)
                .SingleAsync();

            var patchedHash = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222";
            var ban = new BannedComponent
            {
                ProductId = productId,
                ComponentType = "FP_EXE",
                ComponentHash = patchedHash,
                Reason = "BinaryPatched: hash mismatch for v2.1.839 (FP_EXE: expected=aaa got=bbb)"
            };
            db.BannedComponents.Add(ban);
            AddEvent(db, productId, "HW-BINARY-PATCHED", "Startup_AppStarted", "2.1.839",
                $$"""{"FP_EXE":"{{patchedHash}}","OverallStatus":"Fail"}""",
                DateTime.UtcNow.AddMinutes(-5));
            await db.SaveChangesAsync();
            banId = ban.Id;
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync($"/api/analytics/security/bans/{banId:D}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        var banJson = GetProperty(json, "ban");
        Assert.True(GetBool(banJson, "sourceEventAvailable"));
        Assert.Equal("source_event_found", GetString(banJson, "sourceEventStatus"));
        Assert.Equal("strong", GetString(banJson, "componentMatchStrength"));
        Assert.False(GetBool(banJson, "isWeakComponentCorrelation"));

        var source = GetProperty(json, "sourceEvent");
        Assert.True(GetBool(source, "found"));
        Assert.Equal("HW-BINARY-PATCHED", GetString(source, "hardwareId"));
        Assert.Equal("Startup_AppStarted", GetString(source, "eventName"));
        Assert.Contains(GetArray(source, "propertyKeys"), k => k.GetString() == "FP_EXE");
    }

    [Fact]
    public async Task SecurityBanDetails_WhenHardwareBanHasLaterTelemetry_ReturnsEventNearBannedAt()
    {
        await SeedTelemetryAsync();
        Guid banId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var productId = await db.Products
                .Where(p => p.Name == "T-IA Connect")
                .Select(p => p.Id)
                .SingleAsync();

            var bannedAt = DateTime.UtcNow.AddHours(-4);
            var ban = new BannedHardwareId
            {
                ProductId = productId,
                HardwareId = "HW-OLD-VERSION",
                Reason = "Auto-ban: feature usage (Wizard_McpToolSelected) with version 2.1.679 below minimum 2.1.781",
                BanCategory = BannedHardwareId.Categories.OutdatedVersion,
                BannedAt = bannedAt
            };
            db.BannedHardwareIds.Add(ban);
            AddEvent(db, productId, "HW-OLD-VERSION", "Wizard_McpToolSelected", "2.1.679",
                """{"McpTool":"create_program_block"}""",
                bannedAt.AddSeconds(-2));
            AddEvent(db, productId, "HW-OLD-VERSION", "Copilot_Chat", "2.1.679",
                """{"Provider":"OpenAI"}""",
                bannedAt.AddHours(3));
            await db.SaveChangesAsync();
            banId = ban.Id;
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync($"/api/analytics/security/bans/{banId:D}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        var source = GetProperty(json, "sourceEvent");
        Assert.True(GetBool(source, "found"));
        Assert.Equal("source_event_found", GetString(source, "status"));
        Assert.Equal("exact", GetString(source, "correlationConfidence"));
        Assert.Equal("Wizard_McpToolSelected", GetString(source, "eventName"));
        Assert.Equal("HW-OLD-VERSION", GetString(source, "hardwareId"));
    }

    [Fact]
    public async Task TelemetryMachineProfile_WhenHardwareIdIsMissing_ReturnsBadRequest()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/machine-profile");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task TelemetryMachineProfile_RedactsSensitivePropertyKeysAndValues()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/machine-profile?hardwareId=HW-A&days=7&take=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SECRET-LICENSE-001", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret-token-value", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private-secret-value", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hidden stack", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hidden message", body, StringComparison.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(body);
        var records = GetArray(doc.RootElement, "recentRecords");
        var startup = Assert.Single(records, r => GetString(r, "eventName") == "Startup_AppStarted");
        var keys = GetArray(startup, "propertyKeys").Select(k => k.GetString()).ToList();

        Assert.Contains("OverallStatus", keys);
        Assert.DoesNotContain("LicenseKey", keys);
        Assert.DoesNotContain("Token", keys);
        Assert.DoesNotContain("ApiSecret", keys);
    }

    [Fact]
    public async Task TelemetryVersionHealth_ReturnsCompactErrorSummaryWithoutRawErrorDetails()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/version-health?days=7&top=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("hidden message", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hidden stack", body, StringComparison.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(body);
        Assert.Equal(4, GetInt(doc.RootElement, "recordsAnalyzed"));
        Assert.Equal(1, GetInt(doc.RootElement, "errorRecords"));

        var errors = GetArray(doc.RootElement, "topErrorTypes");
        Assert.Contains(errors, e => GetString(e, "name") == "FatalUnhandled" && GetInt(e, "count") == 1);
    }

    [Fact]
    public async Task TelemetryOverview_WhenAnalyticsKeyIsValid_UpdatesLastUsedAuditFields()
    {
        await SeedTelemetryAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/telemetry/overview");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var key = await db.AnalyticsApiKeys.SingleAsync(k => k.Prefix == AnalyticsApiKeyAuthService.BuildPrefix(ValidAnalyticsKey));

        Assert.NotNull(key.LastUsedAtUtc);
    }

    [Fact]
    public async Task CreateAnalyticsApiKey_WhenAdminSecretIsValid_ReturnsRawKeyOnceAndStoresOnlyHash()
    {
        var productId = await SeedProductOnlyAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "admin-secret");

        var response = await client.PostAsJsonAsync(
            $"/api/admin/products/{productId}/analytics-keys",
            new { name = "MCP test key" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        var rawKey = GetString(json, "apiKey");
        Assert.False(string.IsNullOrWhiteSpace(rawKey));
        Assert.StartsWith("sla_", rawKey, StringComparison.Ordinal);
        Assert.Equal(AnalyticsApiKeyScopes.TelemetryRead, GetString(json, "scopes"));

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var storedKey = await db.AnalyticsApiKeys.SingleAsync(k => k.ProductId == productId);

        Assert.Equal("MCP test key", storedKey.Name);
        Assert.Equal(AnalyticsApiKeyAuthService.BuildPrefix(rawKey!), storedKey.Prefix);
        Assert.Equal(AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey!), storedKey.KeyHash);
        Assert.DoesNotContain(rawKey!, storedKey.KeyHash, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLicenseHardwareId_WhenSeatHasActiveLicense_ReturnsActiveFromServerLicenseTables()
    {
        await SeedLicenseVerifierScenarioAsync("HW-ACTIVE");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/licenses/verify-hwid?hardwareId=HW-ACTIVE");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal("HW-ACTIVE", GetString(json, "hardwareId"));
        Assert.Equal("Active", GetString(json, "status"));
        Assert.Equal("active_license_found", GetString(json, "reasonCode"));
        Assert.Equal("TIA-CONNECT-PRO", GetString(json, "licenseType"));
        Assert.Equal("Pro", GetString(json, "licenseTypeLabel"));
        Assert.Equal("Active Customer", GetString(json, "company"));
        Assert.Equal("active@example.test", GetString(json, "customerEmail"));
        Assert.Equal("ac***@example.test", GetString(json, "customerEmailRedacted"));
        Assert.True(GetBool(json, "sourceAuthoritative"));
        Assert.Equal("SoftLicence.Licenses", GetString(json, "source"));
        Assert.Throws<KeyNotFoundException>(() => GetProperty(json, "licenseKey"));
    }

    [Fact]
    public async Task VerifyLicenseHardwareId_WhenHwidAliasIsUsed_ReturnsActive()
    {
        await SeedLicenseVerifierScenarioAsync("HW-ACTIVE");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/licenses/verify-hwid?hwid=hw-active");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal("Active", GetString(json, "status"));
        Assert.Equal("HW-ACTIVE", GetString(json, "hardwareId"));
    }

    [Fact]
    public async Task VerifyLicenseHardwareId_WhenHardwareIdIsUnknown_ReturnsUnknown()
    {
        await SeedLicenseVerifierScenarioAsync("HW-ACTIVE");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/licenses/verify-hwid?hardwareId=HW-MISSING");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal("Unknown", GetString(json, "status"));
        Assert.Equal("hardware_id_not_found", GetString(json, "reasonCode"));
        Assert.Equal("HW-MISSING", GetString(json, "hardwareId"));
    }

    [Theory]
    [InlineData("HW-EXPIRED", "license_expired")]
    [InlineData("HW-REVOKED", "license_revoked")]
    [InlineData("HW-SEAT-INACTIVE", "seat_inactive")]
    public async Task VerifyLicenseHardwareId_WhenKnownButNotActive_ReturnsInactive(string hardwareId, string reasonCode)
    {
        await SeedLicenseVerifierScenarioAsync("HW-ACTIVE");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync($"/api/analytics/licenses/verify-hwid?hardwareId={hardwareId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal("Inactive", GetString(json, "status"));
        Assert.Equal(reasonCode, GetString(json, "reasonCode"));
        Assert.Equal(hardwareId, GetString(json, "hardwareId"));
        Assert.Equal("TIA-CONNECT-PRO", GetString(json, "licenseType"));
    }

    [Fact]
    public async Task VerifyLicenseHardwareId_WhenOnlyTelemetryContainsHardwareId_ReturnsUnknown()
    {
        await SeedLicenseVerifierScenarioAsync("HW-ACTIVE");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/licenses/verify-hwid?hardwareId=HW-TELEMETRY-ONLY");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal("Unknown", GetString(json, "status"));
        Assert.Equal("hardware_id_not_found", GetString(json, "reasonCode"));
    }

    [Fact]
    public async Task RecentOnboardingMetrics_ReturnsRedactedReadOnlyTimeline()
    {
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();

            var productId = Guid.NewGuid();
            var typeId = Guid.NewGuid();
            var activationDate = DateTime.UtcNow.AddMinutes(-20);

            db.Products.Add(new Product
            {
                Id = productId,
                Name = "T-IA Connect",
                PrivateKeyXml = "k",
                PublicKeyXml = "k",
                ApiSecret = "legacy-product-secret"
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = typeId,
                ProductId = productId,
                Name = "TIA Connect Pro",
                Slug = "TIA-CONNECT-PRO",
                IsFree = false
            });
            db.AnalyticsApiKeys.Add(new AnalyticsApiKey
            {
                ProductId = productId,
                Name = "MCP analytics test key",
                Prefix = AnalyticsApiKeyAuthService.BuildPrefix(ValidAnalyticsKey),
                KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(ValidAnalyticsKey),
                Scopes = AnalyticsApiKeyScopes.TelemetryRead,
                IsActive = true
            });
            db.Licenses.Add(new License
            {
                ProductId = productId,
                LicenseTypeId = typeId,
                LicenseKey = "SECRET-ONBOARDING-KEY",
                CustomerName = "Onboarding Customer",
                CustomerEmail = "onboarding@example.test",
                HardwareId = "HW-ONBOARDING-123456",
                ActivationDate = activationDate,
                CreationDate = activationDate.AddMinutes(-5),
                ExpirationDate = DateTime.UtcNow.AddDays(30),
                IsActive = true
            });
            AddEvent(db, productId, "HW-ONBOARDING-123456", "Wizard_Completed", "2.2.501", "{}", activationDate.AddMinutes(4));
            AddEvent(db, productId, "HW-ONBOARDING-123456", "Mcp_ToolCall", "2.2.501", "{}", activationDate.AddMinutes(8));
            AddEvent(db, productId, "HW-ONBOARDING-123456", "Block_Export", "2.2.501", "{}", activationDate.AddMinutes(11));

            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", ValidAnalyticsKey);

        var response = await client.GetAsync("/api/analytics/licenses/recent-onboarding-metrics?take=10&licenseType=paid&status=active");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SECRET-ONBOARDING-KEY", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HW-ONBOARDING-123456", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("onboarding@example.test", body, StringComparison.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(body);
        Assert.Equal(1, GetInt(doc.RootElement, "licensesReturned"));
        var license = Assert.Single(GetArray(doc.RootElement, "licenses"));
        Assert.Equal("on***@example.test", GetString(license, "customerEmailRedacted"));
        Assert.Equal("fast", GetString(license, "onboardingSegment"));
        Assert.Equal("mcp_direct", GetString(license, "detectedPath"));
        Assert.Equal(11, GetProperty(license, "minutesActivationToProductiveEvent").GetDouble());
    }

    private async Task SeedTelemetryAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var productA = new Product
        {
            Id = Guid.NewGuid(),
            Name = "T-IA Connect",
            PrivateKeyXml = "k",
            PublicKeyXml = "k",
            ApiSecret = "analytics-secret-a"
        };

        var productB = new Product
        {
            Id = Guid.NewGuid(),
            Name = "Other Product",
            PrivateKeyXml = "k",
            PublicKeyXml = "k",
            ApiSecret = "analytics-secret-b"
        };

        db.Products.AddRange(productA, productB);
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productA.Id,
            LicenseKey = "CUSTOMER-LICENSE-001",
            CustomerName = "Activation Failure Customer",
            CustomerEmail = "activation.failure@example.test",
            HardwareId = "HW-A",
            ActivationDate = DateTime.UtcNow.AddDays(-1),
            CreationDate = DateTime.UtcNow.AddDays(-1),
            IsActive = true
        });
        db.AnalyticsApiKeys.Add(new AnalyticsApiKey
        {
            ProductId = productA.Id,
            Name = "MCP analytics test key",
            Prefix = AnalyticsApiKeyAuthService.BuildPrefix(ValidAnalyticsKey),
            KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(ValidAnalyticsKey),
            Scopes = AnalyticsApiKeyScopes.TelemetryRead,
            IsActive = true
        });

        AddEvent(db, productA.Id, "HW-A", "Startup_AppStarted", "2.1.900",
            """{"OverallStatus":"Pass","LicenseKey":"SECRET-LICENSE-001","Token":"secret-token-value","ApiSecret":"private-secret-value"}""",
            DateTime.UtcNow.AddHours(-3));
        AddEvent(db, productA.Id, "HW-B", "Mcp_ToolCall", "2.1.900",
            """{"Tool":"list_blocks","RequestSource":"MCP_Agent","Quota_Mcp_Daily":"10/10"}""",
            DateTime.UtcNow.AddHours(-2));
        AddEvent(db, productA.Id, "HW-B", "API_AuthFailed", "2.1.900",
            """{"Reason":"InvalidKey"}""",
            DateTime.UtcNow.AddMinutes(-90));
        AddError(db, productA.Id, "HW-A", "UnhandledException", "2.1.900", "FatalUnhandled", DateTime.UtcNow.AddHours(-1));
        AddEvent(db, productB.Id, "HW-C", "OtherProduct_Event", "1.0",
            """{"Safe":"Value"}""",
            DateTime.UtcNow);
        AddAccessLog(db, "T-IA Connect", "ACTIVATE", false, 400, "BAD_REQUEST", "HW-A", "10.0.0.1", "Invalid license key format", DateTime.UtcNow.AddMinutes(-40));
        AddAccessLog(db, "T-IA Connect", "ACTIVATE", false, 403, "REVOKED", "HW-B", "10.0.0.2", "License revoked", DateTime.UtcNow.AddMinutes(-30));
        AddAccessLog(db, "Other Product", "ACTIVATE", false, 400, "BAD_REQUEST", "HW-C", "10.0.0.3", "Other product failure", DateTime.UtcNow.AddMinutes(-20));

        await db.SaveChangesAsync();
    }

    private async Task<Guid> SeedProductOnlyAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = "T-IA Connect",
            PrivateKeyXml = "k",
            PublicKeyXml = "k",
            ApiSecret = "legacy-product-secret"
        };

        db.Products.Add(product);
        await db.SaveChangesAsync();
        return product.Id;
    }

    private async Task SeedLicenseVerifierScenarioAsync(string activeHardwareId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = "T-IA Connect",
            PrivateKeyXml = "k",
            PublicKeyXml = "k",
            ApiSecret = "legacy-product-secret"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            Name = "AI Pro Edition",
            Slug = "TIA-CONNECT-PRO",
            DefaultDurationDays = 30
        };

        db.Products.Add(product);
        db.LicenseTypes.Add(type);
        db.AnalyticsApiKeys.Add(new AnalyticsApiKey
        {
            ProductId = product.Id,
            Name = "MCP analytics test key",
            Prefix = AnalyticsApiKeyAuthService.BuildPrefix(ValidAnalyticsKey),
            KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(ValidAnalyticsKey),
            Scopes = AnalyticsApiKeyScopes.TelemetryRead,
            IsActive = true
        });

        AddLicenseWithSeat(db, product.Id, type.Id, activeHardwareId, "Active Customer", "active@example.test", true, DateTime.UtcNow.AddDays(20), true);
        AddLicenseWithSeat(db, product.Id, type.Id, "HW-EXPIRED", "Expired Customer", "expired@example.test", true, DateTime.UtcNow.AddDays(-1), true);
        AddLicenseWithSeat(db, product.Id, type.Id, "HW-REVOKED", "Revoked Customer", "revoked@example.test", false, DateTime.UtcNow.AddDays(20), true);
        AddLicenseWithSeat(db, product.Id, type.Id, "HW-SEAT-INACTIVE", "Inactive Seat Customer", "seat@example.test", true, DateTime.UtcNow.AddDays(20), false, setLegacyHardwareId: false);
        AddEvent(db, product.Id, "HW-TELEMETRY-ONLY", "Startup_AppStarted", "2.1.997", """{"LicenseStatus":"Active"}""", DateTime.UtcNow);

        await db.SaveChangesAsync();
    }

    private static void AddLicenseWithSeat(
        LicenseDbContext db,
        Guid productId,
        Guid licenseTypeId,
        string hardwareId,
        string customerName,
        string customerEmail,
        bool isActive,
        DateTime? expirationDate,
        bool isSeatActive,
        bool setLegacyHardwareId = true)
    {
        var license = new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = licenseTypeId,
            LicenseKey = $"SECRET-{hardwareId}",
            CustomerName = customerName,
            CustomerEmail = customerEmail,
            HardwareId = setLegacyHardwareId ? hardwareId : null,
            ActivationDate = DateTime.UtcNow.AddDays(-2),
            CreationDate = DateTime.UtcNow.AddDays(-3),
            ExpirationDate = expirationDate,
            IsActive = isActive,
            RevokedAt = isActive ? null : DateTime.UtcNow.AddDays(-1),
            RevocationReason = isActive ? null : "test revoke"
        };

        license.Seats.Add(new LicenseSeat
        {
            LicenseId = license.Id,
            HardwareId = hardwareId,
            FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
            LastCheckInAt = DateTime.UtcNow.AddHours(-1),
            IsActive = isSeatActive
        });

        db.Licenses.Add(license);
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        string version,
        string propertiesJson,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Event,
            EventData = new TelemetryEvent { PropertiesJson = propertiesJson }
        });
    }

    private static void AddError(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        string version,
        string errorType,
        DateTime timestamp)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            ProductId = productId,
            Timestamp = timestamp,
            HardwareId = hardwareId,
            AppName = "TIAConnect",
            Version = version,
            EventName = eventName,
            Type = TelemetryType.Error,
            ErrorData = new TelemetryError
            {
                ErrorType = errorType,
                Message = "hidden message",
                StackTrace = "hidden stack"
            }
        });
    }

    private static void AddAccessLog(
        LicenseDbContext db,
        string appName,
        string endpoint,
        bool isSuccess,
        int statusCode,
        string resultStatus,
        string hardwareId,
        string clientIp,
        string? errorDetails,
        DateTime timestamp)
    {
        db.AccessLogs.Add(new AccessLog
        {
            Timestamp = timestamp,
            ClientIp = clientIp,
            Method = "POST",
            Path = "/api/activation",
            Endpoint = endpoint,
            LicenseKey = "SECRET-LICENSE-001",
            HardwareId = hardwareId,
            AppName = appName,
            StatusCode = statusCode,
            ResultStatus = resultStatus,
            RequestBody = "ACTIVATION-REQUEST-BODY",
            ErrorDetails = errorDetails,
            IsSuccess = isSuccess,
            DurationMs = 42
        });
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        await using var stream = await response.Content.ReadAsStreamAsync();
        using var doc = await JsonDocument.ParseAsync(stream);
        return doc.RootElement.Clone();
    }

    private static JsonElement[] GetArray(JsonElement element, string propertyName)
    {
        return GetProperty(element, propertyName).EnumerateArray().ToArray();
    }

    private static int GetInt(JsonElement element, string propertyName)
    {
        return GetProperty(element, propertyName).GetInt32();
    }

    private static bool GetBool(JsonElement element, string propertyName)
    {
        return GetProperty(element, propertyName).GetBoolean();
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        return GetProperty(element, propertyName).GetString();
    }

    private static JsonElement GetProperty(JsonElement element, string propertyName)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                return property.Value;
        }

        throw new KeyNotFoundException($"Property '{propertyName}' was not found.");
    }
}

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

public sealed class LlmTipFeedbackIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();
    private readonly FakeBugTraceProxyService _fakeBugTrace = new();

    public LlmTipFeedbackIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<IBugTraceProxyService>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
                services.AddSingleton<IBugTraceProxyService>(_fakeBugTrace);
            });
        });
    }

    [Fact]
    public async Task UsageAndTipsEndpoints_WithFakePayloads_StoreOnlyDedicatedRowsAndDeduplicateTips()
    {
        await SeedProductAndAnalyticsKeyAsync("TIAConnect", "llm-feedback-read-key");
        var client = _factory.CreateClient();

        var usageResponse = await client.PostAsJsonAsync("/api/llm-tips-feedback/usage", new
        {
            timestamp = DateTime.UtcNow,
            appName = "TIAConnect",
            version = "2.2.0",
            schemaVersion = "1",
            eventName = "llm_tip_created",
            properties = new Dictionary<string, string>
            {
                ["Category"] = "lad",
                ["Severity"] = "warning",
                ["Approved"] = "False"
            },
            context = new Dictionary<string, string>
            {
                ["requestSource"] = "MCP",
                ["runtimeMode"] = "Desktop",
                ["uiMode"] = "Gui",
                ["licenseEdition"] = "Enterprise"
            }
        });

        var tipPayload = new
        {
            timestamp = DateTime.UtcNow,
            appName = "TIAConnect",
            version = "2.2.0",
            schemaVersion = "1",
            anonymized = true,
            contentHash = "fake-local-smoke-content-hash",
            category = "lad",
            title = "LAD network empty after import",
            description = "Use symbol instead of signal in LAD JSON.",
            severity = "warning",
            confidence = "confirmed",
            approved = true,
            upvotes = 3,
            submittedAt = DateTime.UtcNow.AddMinutes(-1),
            context = new Dictionary<string, string>
            {
                ["requestSource"] = "MCP",
                ["runtimeMode"] = "Desktop",
                ["uiMode"] = "Gui",
                ["licenseEdition"] = "Enterprise"
            }
        };

        var tipResponse = await client.PostAsJsonAsync("/api/llm-tips-feedback/tips", tipPayload);
        var duplicateTipResponse = await client.PostAsJsonAsync("/api/llm-tips-feedback/tips", tipPayload);

        Assert.Equal(HttpStatusCode.OK, usageResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, tipResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, duplicateTipResponse.StatusCode);

        var duplicateJson = await duplicateTipResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("deduplicated", duplicateJson.GetProperty("status").GetString());
        Assert.Equal(2, duplicateJson.GetProperty("occurrenceCount").GetInt32());

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.Single(await db.LlmTipFeedbackEvents.ToListAsync());
        var tip = Assert.Single(await db.LlmTipFeedbackTips.ToListAsync());
        Assert.Equal(2, tip.OccurrenceCount);
        Assert.False(await db.TelemetryRecords.AnyAsync());
        Assert.False(await db.TelemetryEvents.AnyAsync());

        client.DefaultRequestHeaders.Add("X-Analytics-Key", "llm-feedback-read-key");
        var listResponse = await client.GetAsync("/api/llm-tips-feedback/tips?category=lad&sortBy=occurrences");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var list = await listResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("fake-local-smoke-content-hash", list[0].GetProperty("contentHash").GetString());

        db.LlmTipFeedbackEvents.RemoveRange(db.LlmTipFeedbackEvents);
        db.LlmTipFeedbackTips.RemoveRange(db.LlmTipFeedbackTips);
        await db.SaveChangesAsync();

        Assert.False(await db.LlmTipFeedbackEvents.AnyAsync());
        Assert.False(await db.LlmTipFeedbackTips.AnyAsync());
        Assert.False(await db.TelemetryRecords.AnyAsync());
        Assert.False(await db.TelemetryEvents.AnyAsync());
    }

    [Fact]
    public async Task AdminConvertToBugTraceEndpoint_CreatesTicketAndMarksTipConverted()
    {
        _fakeBugTrace.SubmittedTickets.Clear();
        await SeedProductAndAnalyticsKeyAsync("TIAConnect", "llm-feedback-convert-key");
        var client = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/llm-tips-feedback/tips", new
        {
            appName = "TIAConnect",
            version = "2.2.600",
            schemaVersion = "1",
            anonymized = true,
            contentHash = "admin-convert-bugtrace-hash",
            category = "lad",
            title = "Convert this LLM tip",
            description = "Anonymized product workflow issue.",
            severity = "warning",
            confidence = "confirmed",
            approved = true,
            upvotes = 4,
            submittedAt = DateTime.UtcNow.AddMinutes(-1),
            context = new Dictionary<string, string>
            {
                ["requestSource"] = "MCP",
                ["runtimeMode"] = "Desktop",
                ["uiMode"] = "Gui",
                ["licenseEdition"] = "Pro"
            }
        })).StatusCode);

        client.DefaultRequestHeaders.Add("X-Analytics-Key", "llm-feedback-convert-key");
        var convertResponse = await client.PostAsJsonAsync("/api/llm-tips-feedback/admin/tips/convert-to-bugtrace", new
        {
            contentHash = "admin-convert-bugtrace-hash"
        });

        Assert.Equal(HttpStatusCode.OK, convertResponse.StatusCode);
        var converted = await convertResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("converted-to-bugtrace", converted.GetProperty("reviewStatus").GetString());
        Assert.Equal("BT-00042", converted.GetProperty("bugTraceTicketRef").GetString());
        Assert.True(converted.GetProperty("created").GetBoolean());
        Assert.Single(_fakeBugTrace.SubmittedTickets);

        var detailResponse = await client.GetAsync("/api/llm-tips-feedback/admin/tips/admin-convert-bugtrace-hash");
        Assert.Equal(HttpStatusCode.OK, detailResponse.StatusCode);
        var detail = await detailResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("converted-to-bugtrace", detail.GetProperty("reviewStatus").GetString());
        Assert.Equal("BT-00042", detail.GetProperty("bugTraceTicketRef").GetString());

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.False(await db.TelemetryRecords.AnyAsync());
        Assert.False(await db.TelemetryEvents.AnyAsync());
    }

    [Fact]
    public async Task TipsEndpoint_WhenPayloadIsSensitive_ReturnsBadRequestAndDoesNotPersist()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/llm-tips-feedback/tips", new
        {
            appName = "TIAConnect",
            schemaVersion = "1",
            anonymized = true,
            contentHash = "hash-sensitive-http",
            category = "lad",
            title = "Sensitive payload",
            description = "Local path C:\\Users\\Customer\\Project\\secret.scl",
            approved = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.False(await db.LlmTipFeedbackTips.AnyAsync());
        Assert.False(await db.TelemetryRecords.AnyAsync());
    }

    [Fact]
    public async Task AdminEndpoints_WithAnalyticsKey_ListDetailStatsAndUpdateReviewStatus()
    {
        await SeedProductAndAnalyticsKeyAsync("TIAConnect", "llm-feedback-admin-key");
        var client = _factory.CreateClient();

        var localProbePayload = new
        {
            timestamp = DateTime.UtcNow,
            appName = "TIAConnect",
            version = "2.2.501",
            schemaVersion = "1",
            anonymized = true,
            contentHash = "admin-mcp-probe-hash",
            category = "general",
            title = "TKT-999041 AUTO FEEDBACK LOCAL PROBE 20260628-1552",
            description = "Centralized anonymized MCP probe.",
            severity = "info",
            confidence = "confirmed",
            approved = true,
            upvotes = 7,
            submittedAt = DateTime.UtcNow.AddMinutes(-1),
            context = new Dictionary<string, string>
            {
                ["requestSource"] = "MCP",
                ["runtimeMode"] = "Desktop",
                ["uiMode"] = "Gui",
                ["licenseEdition"] = "Pro"
            }
        };
        var vmProbePayload = new
        {
            timestamp = DateTime.UtcNow,
            appName = "TIAConnect",
            version = "2.2.501",
            schemaVersion = "1",
            anonymized = true,
            contentHash = "admin-mcp-vm-probe-hash",
            category = "general",
            title = "TKT-999041 AUTO FEEDBACK VM PROBE 20260628-1552",
            description = "Centralized anonymized MCP VM probe.",
            severity = "info",
            confidence = "confirmed",
            approved = true,
            upvotes = 3,
            submittedAt = DateTime.UtcNow.AddMinutes(-1),
            context = new Dictionary<string, string>
            {
                ["requestSource"] = "MCP",
                ["runtimeMode"] = "Desktop",
                ["uiMode"] = "Gui",
                ["licenseEdition"] = "Pro"
            }
        };
        var usagePayload = new
        {
            timestamp = DateTime.UtcNow,
            appName = "TIAConnect",
            version = "2.2.501",
            schemaVersion = "1",
            eventName = "llm_tip_upvoted",
            properties = new Dictionary<string, string> { ["Category"] = "general" }
        };

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/llm-tips-feedback/tips", localProbePayload)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/llm-tips-feedback/tips", vmProbePayload)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/llm-tips-feedback/usage", usagePayload)).StatusCode);

        client.DefaultRequestHeaders.Add("X-Analytics-Key", "llm-feedback-admin-key");

        var listResponse = await client.GetAsync("/api/llm-tips-feedback/admin/tips?appVersion=2.2.501&category=general&severity=info&search=AUTO%20FEEDBACK&limit=10&sortBy=upvotes&sortDir=desc");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var list = await listResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, list.GetProperty("total").GetInt32());
        var item = list.GetProperty("items")[0];
        Assert.Equal("admin-mcp-probe-hash", item.GetProperty("contentHash").GetString());
        Assert.True(item.GetProperty("approved").GetBoolean());
        Assert.Equal(7, item.GetProperty("upvotes").GetInt32());
        var listedTitles = list.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("title").GetString()).ToList();
        Assert.Contains("TKT-999041 AUTO FEEDBACK LOCAL PROBE 20260628-1552", listedTitles);
        Assert.Contains("TKT-999041 AUTO FEEDBACK VM PROBE 20260628-1552", listedTitles);

        var detailResponse = await client.GetAsync("/api/llm-tips-feedback/admin/tips/admin-mcp-probe-hash");
        Assert.Equal(HttpStatusCode.OK, detailResponse.StatusCode);
        var detail = await detailResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("TKT-999041 AUTO FEEDBACK LOCAL PROBE 20260628-1552", detail.GetProperty("title").GetString());
        Assert.Equal(7, detail.GetProperty("upvotes").GetInt32());

        var statsResponse = await client.GetAsync("/api/llm-tips-feedback/admin/stats?days=30&appVersion=2.2.501");
        Assert.Equal(HttpStatusCode.OK, statsResponse.StatusCode);
        var stats = await statsResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, stats.GetProperty("totalTips").GetInt32());
        Assert.Equal(2, stats.GetProperty("approvedTips").GetInt32());
        Assert.Equal(10, stats.GetProperty("totalUpvotes").GetInt32());
        Assert.Equal(1, stats.GetProperty("upvotedUsageEvents").GetInt32());

        var updateResponse = await client.PatchAsJsonAsync("/api/llm-tips-feedback/admin/tips/review-status", new
        {
            contentHash = "admin-mcp-probe-hash",
            reviewStatus = "needs-regression-test"
        });
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);

        detailResponse = await client.GetAsync("/api/llm-tips-feedback/admin/tips/admin-mcp-probe-hash");
        detail = await detailResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("needs-regression-test", detail.GetProperty("reviewStatus").GetString());

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.False(await db.TelemetryRecords.AnyAsync());
        Assert.False(await db.TelemetryEvents.AnyAsync());
    }

    [Fact]
    public async Task AdminReviewStatusEndpoint_WhenStatusIsInvalid_ReturnsBadRequest()
    {
        await SeedProductAndAnalyticsKeyAsync("TIAConnect", "llm-feedback-admin-invalid-key");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Analytics-Key", "llm-feedback-admin-invalid-key");

        var response = await client.PatchAsJsonAsync("/api/llm-tips-feedback/admin/tips/review-status", new
        {
            contentHash = "missing",
            reviewStatus = "raw-user-email"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AdminDetailAndReviewStatus_WithGlobalKey_RequireAndEnforceExplicitProduct()
    {
        var tiaProductId = await SeedProductAndAnalyticsKeyAsync("TIAConnect", "llm-feedback-tia-key");
        var otherProductId = await SeedProductAndAnalyticsKeyAsync("OtherProduct", "llm-feedback-other-key");
        await SeedGlobalAnalyticsKeyAsync("llm-feedback-global-key");

        var ingestionClient = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await ingestionClient.PostAsJsonAsync("/api/llm-tips-feedback/tips", new
        {
            appName = "TIAConnect",
            version = "2.2.798",
            schemaVersion = "1",
            anonymized = true,
            contentHash = "global-product-selector-tip",
            category = "hmi",
            title = "Global selector regression tip",
            description = "Anonymized product-scoped feedback.",
            severity = "warning",
            approved = false,
            upvotes = 1
        })).StatusCode);

        var globalClient = _factory.CreateClient();
        globalClient.DefaultRequestHeaders.Add("X-Analytics-Key", "llm-feedback-global-key");

        var missingSelector = await globalClient.GetAsync(
            "/api/llm-tips-feedback/admin/tips/global-product-selector-tip");
        Assert.Equal(HttpStatusCode.BadRequest, missingSelector.StatusCode);
        var missingBody = await missingSelector.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("PRODUCT_SELECTOR_REQUIRED", missingBody.GetProperty("errorCode").GetString());

        var missingUpdateSelector = await globalClient.PatchAsJsonAsync(
            "/api/llm-tips-feedback/admin/tips/review-status",
            new { contentHash = "global-product-selector-tip", reviewStatus = "ignored" });
        Assert.Equal(HttpStatusCode.BadRequest, missingUpdateSelector.StatusCode);

        var detailById = await globalClient.GetAsync(
            $"/api/llm-tips-feedback/admin/tips/global-product-selector-tip?productId={tiaProductId:D}");
        Assert.Equal(HttpStatusCode.OK, detailById.StatusCode);

        var detailByName = await globalClient.GetAsync(
            "/api/llm-tips-feedback/admin/tips/global-product-selector-tip?productName=TIAConnect");
        Assert.Equal(HttpStatusCode.OK, detailByName.StatusCode);

        var wrongProduct = await globalClient.GetAsync(
            $"/api/llm-tips-feedback/admin/tips/global-product-selector-tip?productId={otherProductId:D}");
        Assert.Equal(HttpStatusCode.NotFound, wrongProduct.StatusCode);

        var missingProduct = await globalClient.GetAsync(
            $"/api/llm-tips-feedback/admin/tips/global-product-selector-tip?productId={Guid.NewGuid():D}");
        Assert.Equal(HttpStatusCode.NotFound, missingProduct.StatusCode);
        var missingProductBody = await missingProduct.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("PRODUCT_NOT_FOUND", missingProductBody.GetProperty("errorCode").GetString());

        var update = await globalClient.PatchAsJsonAsync(
            $"/api/llm-tips-feedback/admin/tips/review-status?productId={tiaProductId:D}",
            new { contentHash = "global-product-selector-tip", reviewStatus = "needs-product-fix" });
        Assert.Equal(HttpStatusCode.OK, update.StatusCode);

        var updateWrongProduct = await globalClient.PatchAsJsonAsync(
            $"/api/llm-tips-feedback/admin/tips/review-status?productId={otherProductId:D}",
            new { contentHash = "global-product-selector-tip", reviewStatus = "ignored" });
        Assert.Equal(HttpStatusCode.NotFound, updateWrongProduct.StatusCode);

        var productClient = _factory.CreateClient();
        productClient.DefaultRequestHeaders.Add("X-Analytics-Key", "llm-feedback-tia-key");
        var productKeyWrongScope = await productClient.GetAsync(
            $"/api/llm-tips-feedback/admin/tips/global-product-selector-tip?productId={otherProductId:D}");
        Assert.Equal(HttpStatusCode.Forbidden, productKeyWrongScope.StatusCode);

        var productKeyWrongUpdateScope = await productClient.PatchAsJsonAsync(
            $"/api/llm-tips-feedback/admin/tips/review-status?productId={otherProductId:D}",
            new { contentHash = "global-product-selector-tip", reviewStatus = "ignored" });
        Assert.Equal(HttpStatusCode.Forbidden, productKeyWrongUpdateScope.StatusCode);

        var finalDetail = await productClient.GetAsync(
            "/api/llm-tips-feedback/admin/tips/global-product-selector-tip");
        Assert.Equal(HttpStatusCode.OK, finalDetail.StatusCode);
        var finalBody = await finalDetail.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("needs-product-fix", finalBody.GetProperty("reviewStatus").GetString());
    }

    private async Task<Guid> SeedProductAndAnalyticsKeyAsync(string productName, string rawAnalyticsKey)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var existingProductId = await db.Products
            .Where(p => p.Name == productName)
            .Select(p => (Guid?)p.Id)
            .SingleOrDefaultAsync();
        if (existingProductId.HasValue)
            return existingProductId.Value;

        var productId = Guid.NewGuid();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = productName,
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret-" + productName
        });
        db.AnalyticsApiKeys.Add(new AnalyticsApiKey
        {
            ProductId = productId,
            Name = "LLM feedback read key",
            Prefix = AnalyticsApiKeyAuthService.BuildPrefix(rawAnalyticsKey),
            KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(rawAnalyticsKey),
            Scopes = AnalyticsApiKeyScopes.TelemetryRead
        });
        await db.SaveChangesAsync();
        return productId;
    }

    private async Task SeedGlobalAnalyticsKeyAsync(string rawAnalyticsKey)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        db.AnalyticsApiKeys.Add(new AnalyticsApiKey
        {
            ProductId = null,
            Name = "Global LLM feedback key",
            Prefix = AnalyticsApiKeyAuthService.BuildPrefix(rawAnalyticsKey),
            KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(rawAnalyticsKey),
            Scopes = $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.MultiProductRead}",
            ScopeKind = AnalyticsApiKeyScopeKinds.Global,
            IsActive = true
        });
        await db.SaveChangesAsync();
    }
}

using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class LlmTipFeedbackServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;

    public LlmTipFeedbackServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task SaveUsageAsync_WhenPayloadIsValid_PersistsOnlyLlmTipFeedbackEvent()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        var result = await service.SaveUsageAsync(new LlmTipFeedbackUsageRequest
        {
            AppName = "TIAConnect",
            Version = "2.2.0",
            SchemaVersion = "1",
            EventName = "llm_tip_created",
            Properties = new Dictionary<string, string>
            {
                ["Category"] = "lad",
                ["Severity"] = "warning"
            },
            Context = new Dictionary<string, string>
            {
                ["requestSource"] = "MCP",
                ["runtimeMode"] = "Desktop",
                ["uiMode"] = "Gui",
                ["licenseEdition"] = "Enterprise"
            }
        });

        await using var db = new LicenseDbContext(_dbOptions);
        var stored = await db.LlmTipFeedbackEvents.SingleAsync();

        Assert.Equal("accepted", result.Status);
        Assert.Equal("llm_tip_created", stored.EventName);
        Assert.Equal("lad", stored.Category);
        Assert.Equal("Enterprise", stored.LicenseEdition);
        Assert.False(await db.TelemetryRecords.AnyAsync());
        Assert.False(await db.TelemetryEvents.AnyAsync());
    }

    [Fact]
    public async Task SaveTipAsync_WhenPayloadIsValid_PersistsOnlyLlmTipFeedbackTip()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        var result = await service.SaveTipAsync(BuildTip("hash-tip-ok"));

        await using var db = new LicenseDbContext(_dbOptions);
        var stored = await db.LlmTipFeedbackTips.SingleAsync();

        Assert.Equal("accepted", result.Status);
        Assert.Equal("hash-tip-ok", stored.ContentHash);
        Assert.Equal(1, stored.OccurrenceCount);
        Assert.Equal("new", stored.ReviewStatus);
        Assert.False(await db.TelemetryRecords.AnyAsync());
        Assert.False(await db.TelemetryEvents.AnyAsync());
    }

    [Fact]
    public async Task SaveTipAsync_WhenContentHashAlreadyExists_DeduplicatesAndUpdatesOccurrenceCount()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await service.SaveTipAsync(BuildTip("hash-duplicate", upvotes: 1));
        var result = await service.SaveTipAsync(BuildTip("hash-duplicate", upvotes: 4));

        await using var db = new LicenseDbContext(_dbOptions);
        var stored = await db.LlmTipFeedbackTips.SingleAsync();

        Assert.Equal("deduplicated", result.Status);
        Assert.Equal(2, stored.OccurrenceCount);
        Assert.Equal(4, stored.Upvotes);
    }

    [Fact]
    public async Task SaveTipAsync_WhenPayloadContainsSensitiveData_RejectsAndDoesNotPersist()
    {
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var request = BuildTip("hash-sensitive");
        request.Description = "Contact raw.user@example.test for details.";

        await Assert.ThrowsAsync<ArgumentException>(() => service.SaveTipAsync(request));

        await using var db = new LicenseDbContext(_dbOptions);
        Assert.False(await db.LlmTipFeedbackTips.AnyAsync());
        Assert.False(await db.TelemetryRecords.AnyAsync());
    }

    [Fact]
    public async Task SaveTipAsync_WhenAnonymizedIsFalse_RejectsAndDoesNotPersist()
    {
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var request = BuildTip("hash-not-anonymized");
        request.Anonymized = false;

        await Assert.ThrowsAsync<ArgumentException>(() => service.SaveTipAsync(request));

        await using var db = new LicenseDbContext(_dbOptions);
        Assert.False(await db.LlmTipFeedbackTips.AnyAsync());
    }

    [Fact]
    public async Task Schema_WhenCreatedWithRelationalProvider_ContainsDedicatedLlmTipFeedbackTables()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        SqliteFullModelHarness.RegisterConnection(connection);

        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(connection)
            .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
            .Options;

        await using (var db = new LicenseDbContext(options, Mock.Of<ILogger<LicenseDbContext>>()))
        {
            await db.Database.EnsureCreatedAsync();
        }

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('LlmTipFeedbackEvents', 'LlmTipFeedbackTips') ORDER BY name;";
        var names = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            names.Add(reader.GetString(0));
        }

        Assert.Equal(["LlmTipFeedbackEvents", "LlmTipFeedbackTips"], names);
    }

    [Fact]
    public async Task GetAdminOverviewAsync_ReturnsStatsAndSortsByOccurrencesByDefault()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await service.SaveUsageAsync(new LlmTipFeedbackUsageRequest
        {
            AppName = "TIAConnect",
            SchemaVersion = "1",
            EventName = "llm_tip_created",
            Properties = new Dictionary<string, string> { ["Category"] = "lad" }
        });
        await service.SaveTipAsync(BuildTip("hash-low", upvotes: 1));
        await service.SaveTipAsync(BuildTip("hash-high", upvotes: 2));
        await service.SaveTipAsync(BuildTip("hash-high", upvotes: 5));

        var overview = await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery
        {
            Days = 30
        });

        Assert.Equal(2, overview.TotalTips);
        Assert.Equal(1, overview.TotalEvents);
        Assert.Equal(3, overview.TotalOccurrences);
        Assert.Equal(2, overview.NewTips);
        Assert.Equal("hash-high", overview.Tips[0].ContentHash);
        Assert.Equal(2, overview.Tips[0].OccurrenceCount);
        Assert.Contains(overview.TopCategories, c => c.Name == "lad" && c.Count == 3);
        Assert.Equal(0, await CountTelemetryRowsAsync());
    }

    [Fact]
    public async Task GetAdminOverviewAsync_AppliesCategoryVersionStatusAndSearchFilters()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await service.SaveTipAsync(BuildTip("hash-lad", version: "2.2.495", category: "lad", title: "LAD import fix"));
        await service.SaveTipAsync(BuildTip("hash-scl", version: "2.2.12", category: "scl", title: "SCL timeout"));
        await service.UpdateReviewStatusAsync((await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery
        {
            Search = "hash-lad",
            Days = 0
        })).Tips.Single().Id, "needs-doc");

        var overview = await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery
        {
            Category = "lad",
            AppVersion = "2.2.495",
            ReviewStatus = "needs-doc",
            Search = "import",
            Days = 0
        });

        var tip = Assert.Single(overview.Tips);
        Assert.Equal("hash-lad", tip.ContentHash);
        Assert.Equal("needs-doc", tip.ReviewStatus);
    }

    [Fact]
    public async Task ListAdminTipsAsync_AppliesSeveritySortAndPagination()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await service.SaveTipAsync(BuildTip("hash-warning-a", upvotes: 1, category: "lad", title: "A"));
        await service.SaveTipAsync(BuildTip("hash-info-b", upvotes: 2, category: "scl", title: "B", severity: "info"));
        await service.SaveTipAsync(BuildTip("hash-warning-c", upvotes: 3, category: "lad", title: "C"));
        await service.SaveTipAsync(BuildTip("hash-warning-c", upvotes: 4, category: "lad", title: "C"));

        var page = await service.ListAdminTipsAsync(new LlmTipFeedbackAdminQuery
        {
            Severity = "warning",
            Limit = 1,
            Offset = 1,
            SortBy = "occurrenceCount",
            SortDir = "desc",
            Days = 0
        });

        Assert.Equal(2, page.Total);
        Assert.Equal(1, page.Limit);
        Assert.Equal(1, page.Offset);
        var tip = Assert.Single(page.Items);
        Assert.Equal("hash-warning-a", tip.ContentHash);
        Assert.True(tip.Approved);
        Assert.Equal(1, tip.Upvotes);
    }

    [Fact]
    public async Task GetAdminOverviewAsync_IncludesApprovedUpvotesAndUpvotedUsageEvents()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await service.SaveTipAsync(BuildTip("hash-upvote", upvotes: 5, category: "lad"));
        await service.SaveUsageAsync(new LlmTipFeedbackUsageRequest
        {
            AppName = "TIAConnect",
            SchemaVersion = "1",
            EventName = "llm_tip_upvoted",
            Properties = new Dictionary<string, string> { ["Category"] = "lad" }
        });

        var overview = await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 });

        Assert.Equal(1, overview.ApprovedTips);
        Assert.Equal(5, overview.TotalUpvotes);
        Assert.Equal(1, overview.UpvotedUsageEvents);
        Assert.Contains(overview.TopSeverities, s => s.Name == "warning" && s.Count == 1);
        Assert.Equal("hash-upvote", Assert.Single(overview.TopTipsByUpvotes).ContentHash);
    }

    [Fact]
    public async Task GetTipDetailAsync_ReturnsAnonymizedPayloadFromDedicatedTip()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        await service.SaveTipAsync(BuildTip("hash-detail", description: "Use symbol instead of signal."));

        var id = (await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 }))
            .Tips.Single().Id;
        var detail = await service.GetTipDetailAsync(id);

        Assert.NotNull(detail);
        Assert.Equal("hash-detail", detail.ContentHash);
        Assert.Contains("Use symbol", detail.Description);
        Assert.Contains("\"contentHash\"", detail.PayloadJson);
    }

    [Fact]
    public async Task UpdateReviewStatusAsync_RejectsUnsupportedStatus()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        await service.SaveTipAsync(BuildTip("hash-review"));
        var id = (await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 }))
            .Tips.Single().Id;

        await Assert.ThrowsAsync<ArgumentException>(() => service.UpdateReviewStatusAsync(id, "raw-user-email"));
    }

    [Fact]
    public async Task UpdateReviewStatusAsync_ByContentHash_UpdatesMatchingProductTip()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        await service.SaveTipAsync(BuildTip("hash-content-review"));

        await using var db = new LicenseDbContext(_dbOptions);
        var productId = await db.Products.Where(p => p.Name == "TIAConnect").Select(p => p.Id).SingleAsync();

        var updated = await service.UpdateReviewStatusAsync(
            id: null,
            contentHash: "hash-content-review",
            productId,
            reviewStatus: "needs-mcp-guide");

        Assert.True(updated);
        var detail = await service.GetTipDetailAsync("hash-content-review", productId);
        Assert.NotNull(detail);
        Assert.Equal("needs-mcp-guide", detail.ReviewStatus);
    }

    [Fact]
    public async Task ConvertToBugTraceAsync_CreatesAnonymizedTicketAndMarksTipConverted()
    {
        var productId = await SeedProductAsync("TIAConnect");
        var bugTrace = new FakeBugTraceProxyService();
        var service = BuildRoutedService(bugTrace, productId.ToString("D"));
        await service.SaveTipAsync(BuildTip("hash-convert-bugtrace", upvotes: 8, severity: "critical"));
        var tip = (await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 })).Tips.Single();

        var result = await service.ConvertToBugTraceAsync(tip.Id, null, tip.ProductId);

        Assert.NotNull(result);
        Assert.True(result.Created);
        Assert.Equal("converted-to-bugtrace", result.ReviewStatus);
        Assert.Equal("BT-00042", result.BugTraceTicketRef);
        var submitted = Assert.Single(bugTrace.SubmittedTickets);
        var submittedJson = JsonSerializer.Serialize(submitted);
        Assert.Contains("LLM tip review:", submittedJson);
        Assert.Contains("hash-convert-bugtrace", submittedJson);
        Assert.Contains("CRITICAL", submittedJson);

        var detail = await service.GetTipDetailAsync(tip.Id);
        Assert.NotNull(detail);
        Assert.Equal("converted-to-bugtrace", detail.ReviewStatus);
        Assert.Equal("BT-00042", detail.BugTraceTicketRef);

        var second = await service.ConvertToBugTraceAsync(tip.Id, null, tip.ProductId);
        Assert.NotNull(second);
        Assert.False(second.Created);
        Assert.Single(bugTrace.SubmittedTickets);
    }

    /// <summary>
    /// TKT-003093 regression: a tip reported by the T-IA Connect product must be converted through the
    /// dedicated, provider-verified T-IA authority, whose token selects the T-IA-Connect BugTrace project.
    /// The legacy SoftLicence technical-report authority must never receive it, because BugTrace chooses
    /// the destination project from the token alone and that token files tickets in the SoftLicence project.
    /// </summary>
    [Fact]
    public async Task ConvertToBugTraceAsync_WhenTipComesFromTiaConnect_UsesTiaProjectAuthorityNotSoftLicence()
    {
        var productId = await SeedProductAsync("TIAConnect");
        var bugTrace = new FakeBugTraceProxyService();
        var service = BuildRoutedService(bugTrace, productId.ToString("D"));
        await service.SaveTipAsync(BuildTip("hash-tia-project-routing"));
        var tip = (await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 })).Tips.Single();

        var result = await service.ConvertToBugTraceAsync(tip.Id, null, tip.ProductId);

        Assert.NotNull(result);
        Assert.True(result.Created);
        Assert.Empty(bugTrace.LegacySubmittedTickets);
        Assert.Single(bugTrace.SubmittedTiaTickets);
        // The tip identifier is the provider idempotency key, so a concurrent double click replays one ticket.
        Assert.Equal(tip.Id.ToString("D"), Assert.Single(bugTrace.TiaIdempotencyKeys));
    }

    /// <summary>
    /// TKT-003093: a product without a configured BugTrace project is refused before any provider call, with no
    /// fallback to the legacy SoftLicence project, and the tip stays unconverted.
    /// </summary>
    [Fact]
    public async Task ConvertToBugTraceAsync_WhenProductHasNoProject_RefusesWithoutAnyProviderCall()
    {
        var productId = await SeedProductAsync("TIAConnect");
        var bugTrace = new FakeBugTraceProxyService();
        var service = BuildRoutedService(bugTrace, Guid.NewGuid().ToString("D"));
        await service.SaveTipAsync(BuildTip("hash-unrouted-product"));
        var tip = (await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 })).Tips.Single();

        var refusal = await Assert.ThrowsAsync<LlmTipBugTraceProjectNotConfiguredException>(
            () => service.ConvertToBugTraceAsync(tip.Id, null, tip.ProductId));

        Assert.Equal(productId, refusal.ProductId);
        Assert.False(refusal.MappingInvalid);
        Assert.Empty(bugTrace.SubmittedTickets);
        var detail = await service.GetTipDetailAsync(tip.Id);
        Assert.NotNull(detail);
        Assert.Null(detail.BugTraceTicketRef);
        Assert.NotEqual("converted-to-bugtrace", detail.ReviewStatus);
    }

    /// <summary>
    /// TKT-003093: a malformed mapping setting refuses every conversion (flagged as such) instead of routing part
    /// of the products, and no provider call is made.
    /// </summary>
    [Fact]
    public async Task ConvertToBugTraceAsync_WhenMappingIsMalformed_RefusesEveryProduct()
    {
        var productId = await SeedProductAsync("TIAConnect");
        var bugTrace = new FakeBugTraceProxyService();
        var service = BuildRoutedService(bugTrace, productId.ToString("D") + ",not-a-guid");
        await service.SaveTipAsync(BuildTip("hash-malformed-mapping"));
        var tip = (await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 })).Tips.Single();

        var refusal = await Assert.ThrowsAsync<LlmTipBugTraceProjectNotConfiguredException>(
            () => service.ConvertToBugTraceAsync(tip.Id, null, tip.ProductId));

        Assert.True(refusal.MappingInvalid);
        Assert.Empty(bugTrace.SubmittedTickets);
    }

    /// <summary>
    /// TKT-003093: a mapped product whose T-IA authority is not configured fails as "unavailable" without ever
    /// falling back to the legacy SoftLicence token.
    /// </summary>
    [Fact]
    public async Task ConvertToBugTraceAsync_WhenTiaAuthorityIsNotConfigured_FailsWithoutLegacyFallback()
    {
        var productId = await SeedProductAsync("TIAConnect");
        var bugTrace = new FakeBugTraceProxyService { IsTiaConfigured = false };
        var service = BuildRoutedService(bugTrace, productId.ToString("D"));
        await service.SaveTipAsync(BuildTip("hash-tia-unconfigured"));
        var tip = (await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 })).Tips.Single();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.ConvertToBugTraceAsync(tip.Id, null, tip.ProductId));

        Assert.Empty(bugTrace.SubmittedTickets);
    }

    /// <summary>
    /// TKT-003093 anti-duplicate: an already converted tip returns its existing ticket without contacting BugTrace,
    /// even after its product mapping was removed and with no proxy at all.
    /// </summary>
    [Fact]
    public async Task ConvertToBugTraceAsync_WhenTipAlreadyConverted_ReturnsExistingTicketWithoutProvider()
    {
        var productId = await SeedProductAsync("TIAConnect");
        var bugTrace = new FakeBugTraceProxyService();
        var routed = BuildRoutedService(bugTrace, productId.ToString("D"));
        await routed.SaveTipAsync(BuildTip("hash-already-converted"));
        var tip = (await routed.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 })).Tips.Single();
        await routed.ConvertToBugTraceAsync(tip.Id, null, tip.ProductId);
        var unrouted = new LlmTipFeedbackService(_dbFactoryMock.Object);

        var replay = await unrouted.ConvertToBugTraceAsync(null, "hash-already-converted", tip.ProductId);

        Assert.NotNull(replay);
        Assert.False(replay.Created);
        Assert.Equal("BT-00042", replay.BugTraceTicketRef);
        Assert.Single(bugTrace.SubmittedTickets);
    }

    [Fact]
    public async Task PostTip_WhenPersistenceFails_ReturnsServiceUnavailableInsteadOfAccepted()
    {
        var controller = BuildControllerWithFailingPersistence();

        var result = await controller.PostTip(BuildTip("hash-persistence-failure"));

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(503, objectResult.StatusCode);
        Assert.Contains("llm_tip_feedback_persistence_failed", JsonSerializer.Serialize(objectResult.Value));
    }

    [Fact]
    public async Task PostUsage_WhenPersistenceFails_ReturnsServiceUnavailableInsteadOfAccepted()
    {
        var controller = BuildControllerWithFailingPersistence();

        var result = await controller.PostUsage(new LlmTipFeedbackUsageRequest
        {
            AppName = "TIAConnect",
            SchemaVersion = "1",
            EventName = "llm_tip_created"
        });

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(503, objectResult.StatusCode);
        Assert.Contains("llm_tip_feedback_persistence_failed", JsonSerializer.Serialize(objectResult.Value));
    }

    /// <summary>Seeds one product and returns its identifier, so routing tests can map it explicitly.</summary>
    private async Task<Guid> SeedProductAsync(string name)
    {
        var productId = Guid.NewGuid();
        await using var db = new LicenseDbContext(_dbOptions);
        db.Products.Add(new Product
        {
            Id = productId,
            Name = name,
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret-" + name
        });
        await db.SaveChangesAsync();
        return productId;
    }

    /// <summary>
    /// Builds a service whose LLM tip routing is parsed from <paramref name="tiaProductIds"/>, exactly as the
    /// BUGTRACE_LLM_TIP_TIA_PRODUCT_IDS setting would be (TKT-003093).
    /// </summary>
    private LlmTipFeedbackService BuildRoutedService(FakeBugTraceProxyService bugTrace, string tiaProductIds) =>
        new(_dbFactoryMock.Object, bugTrace, bugTraceRouting: new LlmTipBugTraceRouting(tiaProductIds));

    private async Task<int> CountTelemetryRowsAsync()
    {
        await using var db = new LicenseDbContext(_dbOptions);
        return await db.TelemetryRecords.CountAsync() + await db.TelemetryEvents.CountAsync();
    }

    private static LlmTipFeedbackController BuildControllerWithFailingPersistence()
    {
        var dbFactory = new Mock<IDbContextFactory<LicenseDbContext>>();
        dbFactory.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Simulated persistence failure."));

        var service = new LlmTipFeedbackService(dbFactory.Object);
        return new LlmTipFeedbackController(
            service,
            apiKeyAuth: null!,
            dbFactory.Object,
            NullLogger<LlmTipFeedbackController>.Instance);
    }

    private static LlmTipFeedbackTipRequest BuildTip(
        string contentHash,
        int upvotes = 3,
        string version = "2.2.0",
        string category = "lad",
        string title = "LAD network empty after import",
        string severity = "warning",
        string description = "Use symbol instead of signal in LAD JSON.")
    {
        return new LlmTipFeedbackTipRequest
        {
            AppName = "TIAConnect",
            Version = version,
            SchemaVersion = "1",
            Anonymized = true,
            ContentHash = contentHash,
            Category = category,
            Title = title,
            Description = description,
            Severity = severity,
            Confidence = "confirmed",
            Approved = true,
            Upvotes = upvotes,
            SubmittedAt = DateTime.UtcNow.AddMinutes(-1),
            Context = new Dictionary<string, string>
            {
                ["requestSource"] = "MCP",
                ["runtimeMode"] = "Desktop",
                ["uiMode"] = "Gui",
                ["licenseEdition"] = "Enterprise"
            }
        };
    }
}

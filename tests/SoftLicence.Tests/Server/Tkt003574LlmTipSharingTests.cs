using System.Reflection;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.EntityFrameworkCore;
using Moq;
using SoftLicence.Mcp;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003574 service rules for sharing an LLM tip with every client: only an administrator decision publishes a tip,
/// ingestion never changes that decision, a retraction needs a reason, every change is journaled once, and the public
/// snapshot exposes only shared tips of the requested product.
/// </summary>
/// <remarks>
/// The first three cases were red on <c>develop</c> 8a07bd8 (no sharing operation on the service, the admin API or the
/// MCP), and the two ingestion cases were red on the only field that existed (<c>Approved</c>, driven by clients).
/// EF InMemory covers the C# rules here; the relational predicates (product name and category case, CHECK
/// constraints) are proven on PostgreSQL by <see cref="Tkt003574LlmTipSharingPostgreSqlTests"/>.
/// </remarks>
public sealed class Tkt003574LlmTipSharingTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;

    /// <summary>
    /// Builds an isolated in-memory database per test instance so that no state leaks between cases.
    /// </summary>
    public Tkt003574LlmTipSharingTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public void Service_ExposesAnAdminOperationToShareOrRetractATip()
    {
        Assert.NotNull(typeof(LlmTipFeedbackService).GetMethod(nameof(LlmTipFeedbackService.SetSharingAsync)));
    }

    [Fact]
    public void AdminApi_ExposesARouteToShareOrRetractATip()
    {
        var templates = typeof(LlmTipFeedbackController)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .SelectMany(m => m.GetCustomAttributes<HttpMethodAttribute>())
            .Select(a => a.Template ?? string.Empty)
            .ToList();

        Assert.Contains("admin/tips/sharing", templates);
        Assert.Contains("shared", templates);
    }

    [Fact]
    public void AnalyticsMcp_ExposesAToolToShareOrRetractATip()
    {
        var method = typeof(SoftLicenceAnalyticsTools).GetMethod(nameof(SoftLicenceAnalyticsTools.SetLlmTipFeedbackSharing));

        Assert.NotNull(method);
        Assert.NotNull(method.GetCustomAttribute<ModelContextProtocol.Server.McpServerToolAttribute>());
    }

    /// <summary>
    /// A client marks a tip approved locally after three upvotes. That local flag is kept as information but must
    /// not publish the tip: only an administrator decision may share it.
    /// </summary>
    [Fact]
    public async Task SaveTipAsync_ClientApprovedFlag_DoesNotShareTheTipWithEveryClient()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await service.SaveTipAsync(BuildClientTip("hash-3574-client-approved", clientApproved: true));

        await using var db = new LicenseDbContext(_dbOptions);
        var stored = await db.LlmTipFeedbackTips.SingleAsync();
        Assert.True(stored.Approved);
        Assert.False(stored.SharedWithClients, "A client-side approval must not share the tip with every client.");
        Assert.Empty(await service.ListSharedTipsAsync("TIAConnect", null));
    }

    /// <summary>
    /// The administrator shares then retracts a tip; a client then sends the same tip again with its local approval.
    /// The retraction must survive the deduplicated ingestion, and a later share must survive it too.
    /// </summary>
    [Fact]
    public async Task SaveTipAsync_DeduplicatedIngestion_DoesNotUndoAnAdministratorDecision()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var created = await service.SaveTipAsync(BuildClientTip("hash-3574-retracted", clientApproved: false));
        await service.SetSharingAsync(created.Id, null, null, true, null, "admin-ui:alice", "admin-ui", null);
        await service.SetSharingAsync(created.Id, null, null, false, "Bug report, not a tip", "admin-ui:alice", "admin-ui", null);

        var result = await service.SaveTipAsync(BuildClientTip("hash-3574-retracted", clientApproved: true));

        await using (var verify = new LicenseDbContext(_dbOptions))
        {
            var stored = await verify.LlmTipFeedbackTips.SingleAsync();
            Assert.Equal("deduplicated", result.Status);
            Assert.False(stored.SharedWithClients, "The next client ingestion must not undo the administrator's retraction.");
        }

        await service.SetSharingAsync(created.Id, null, null, true, null, "admin-ui:alice", "admin-ui", null);
        await service.SaveTipAsync(BuildClientTip("hash-3574-retracted", clientApproved: false));

        await using var final = new LicenseDbContext(_dbOptions);
        Assert.True((await final.LlmTipFeedbackTips.SingleAsync()).SharedWithClients);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task SetSharingAsync_RetractionWithoutReason_IsRefusedAndWritesNothing(string? reason)
    {
        var (service, tipId) = await SeedSharedTipAsync();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.SetSharingAsync(tipId, null, null, false, reason, "admin-ui:alice", "admin-ui", null));

        await using var db = new LicenseDbContext(_dbOptions);
        Assert.True((await db.LlmTipFeedbackTips.SingleAsync()).SharedWithClients);
        Assert.Equal(1, await db.LlmTipFeedbackSharingDecisions.CountAsync());
    }

    [Fact]
    public async Task SetSharingAsync_ReasonLongerThanTheJournalColumn_IsRefused()
    {
        var (service, tipId) = await SeedSharedTipAsync();

        await Assert.ThrowsAsync<ArgumentException>(() => service.SetSharingAsync(
            tipId, null, null, false, new string('x', LlmTipFeedbackService.MaxSharingReasonLength + 1),
            "admin-ui:alice", "admin-ui", null));
    }

    [Theory]
    [InlineData("website")]
    [InlineData("")]
    public async Task SetSharingAsync_UnknownChannel_IsRefused(string channel)
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var created = await service.SaveTipAsync(BuildClientTip("hash-3574-channel", clientApproved: false));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.SetSharingAsync(created.Id, null, null, true, null, "analytics-key:x", channel, null));
    }

    /// <summary>
    /// Sharing twice writes one journal row; the repeat answers Changed=false with the first decision's instant and
    /// actor. The journal row keeps the trimmed reason, the actor, the lower-cased channel and the caller address.
    /// </summary>
    [Fact]
    public async Task SetSharingAsync_RepeatedShare_IsIdempotentAndJournaledOnce()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var created = await service.SaveTipAsync(BuildClientTip("hash-3574-idempotent", clientApproved: false));

        var first = await service.SetSharingAsync(created.Id, null, null, true, "  Useful TIA tip  ", "analytics-key:k1", "MCP", "192.0.2.2");
        var second = await service.SetSharingAsync(null, "hash-3574-idempotent", null, true, null, "analytics-key:k2", "api", "192.0.2.3");

        Assert.NotNull(first);
        Assert.True(first.Changed);
        Assert.NotNull(second);
        Assert.False(second.Changed);
        Assert.True(second.SharedWithClients);
        Assert.Equal("analytics-key:k1", second.SharingChangedBy);

        await using var db = new LicenseDbContext(_dbOptions);
        var decision = await db.LlmTipFeedbackSharingDecisions.SingleAsync();
        Assert.Equal(LlmTipFeedbackSharingDecision.SharedAction, decision.Action);
        Assert.Equal("Useful TIA tip", decision.Reason);
        Assert.Equal("analytics-key:k1", decision.DecidedBy);
        Assert.Equal("mcp", decision.Channel);
        Assert.Equal("192.0.2.2", decision.CallerIp);
    }

    [Fact]
    public async Task SetSharingAsync_TipOfAnotherProduct_IsNotFoundAndUnchanged()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var created = await service.SaveTipAsync(BuildClientTip("hash-3574-scope", clientApproved: false));

        var result = await service.SetSharingAsync(created.Id, null, Guid.NewGuid(), true, null, "analytics-key:k", "api", null);

        Assert.Null(result);
        await using var db = new LicenseDbContext(_dbOptions);
        Assert.False((await db.LlmTipFeedbackTips.SingleAsync()).SharedWithClients);
        Assert.Empty(await db.LlmTipFeedbackSharingDecisions.ToListAsync());
    }

    /// <summary>
    /// The public snapshot lists shared tips of the named product only, drops a retracted tip, and returns nothing
    /// for an unknown product; the detail shows the journal newest first.
    /// </summary>
    [Fact]
    public async Task ListSharedTipsAsync_ReturnsOnlyCurrentlySharedTipsOfTheProduct()
    {
        await SeedProductAsync("TIAConnect");
        await SeedProductAsync("OtherApp");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var kept = await service.SaveTipAsync(BuildClientTip("hash-3574-kept", clientApproved: false));
        var retracted = await service.SaveTipAsync(BuildClientTip("hash-3574-gone", clientApproved: true));
        await service.SaveTipAsync(BuildClientTip("hash-3574-never", clientApproved: true));
        var other = await service.SaveTipAsync(BuildClientTip("hash-3574-other", clientApproved: false, appName: "OtherApp"));
        foreach (var id in new[] { kept.Id, retracted.Id, other.Id })
            await service.SetSharingAsync(id, null, null, true, null, "admin-ui:alice", "admin-ui", null);
        await service.SetSharingAsync(retracted.Id, null, null, false, "Product bug report", "admin-ui:alice", "admin-ui", null);

        var snapshot = await service.ListSharedTipsAsync("TIAConnect", null);
        var unknown = await service.ListSharedTipsAsync("NoSuchProduct", null);
        var detail = await service.GetTipDetailAsync(retracted.Id);

        var item = Assert.Single(snapshot);
        Assert.Equal("hash-3574-kept", item.ContentHash);
        Assert.Equal("Convert to Real before Div/Mul in LAD", item.Title);
        Assert.Empty(unknown);
        Assert.NotNull(detail);
        Assert.False(detail.SharedWithClients);
        Assert.Equal(
            new[] { LlmTipFeedbackSharingDecision.RetractedAction, LlmTipFeedbackSharingDecision.SharedAction },
            detail.SharingDecisions!.Select(d => d.Action).ToArray());
        Assert.Equal("Product bug report", detail.SharingDecisions![0].Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("  ")]
    public async Task ListSharedTipsAsync_WithoutAppName_IsRefused(string? appName)
    {
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await Assert.ThrowsAsync<ArgumentException>(() => service.ListSharedTipsAsync(appName, null));
    }

    [Fact]
    public async Task ListSharedTipsAsync_AppNameLongerThan120Characters_IsRefused()
    {
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);

        await Assert.ThrowsAsync<ArgumentException>(() => service.ListSharedTipsAsync(new string('a', 121), null));
    }

    /// <summary>
    /// The admin list filters on the sharing state and the overview counts shared tips, so an operator sees which
    /// tips every client receives.
    /// </summary>
    [Fact]
    public async Task AdminQueries_FilterAndCountSharedTips()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var shared = await service.SaveTipAsync(BuildClientTip("hash-3574-admin-shared", clientApproved: false));
        await service.SaveTipAsync(BuildClientTip("hash-3574-admin-unshared", clientApproved: true));
        await service.SetSharingAsync(shared.Id, null, null, true, null, "admin-ui:alice", "admin-ui", null);

        var onlyShared = await service.ListAdminTipsAsync(new LlmTipFeedbackAdminQuery { Shared = true, Days = 0 });
        var onlyUnshared = await service.ListAdminTipsAsync(new LlmTipFeedbackAdminQuery { Shared = false, Days = 0 });
        var overview = await service.GetAdminOverviewAsync(new LlmTipFeedbackAdminQuery { Days = 0 });

        Assert.Equal("hash-3574-admin-shared", Assert.Single(onlyShared.Items).ContentHash);
        Assert.True(onlyShared.Items[0].SharedWithClients);
        Assert.Equal("hash-3574-admin-unshared", Assert.Single(onlyUnshared.Items).ContentHash);
        Assert.Equal(1, overview.SharedTips);
        Assert.Equal(1, overview.ApprovedTips);
    }

    /// <summary>The public item exposes only reviewed content: no identifier, counter, vote, version or context.</summary>
    [Fact]
    public void SharedTipContract_ExposesOnlyAnonymizedReviewedContent()
    {
        var names = typeof(LlmTipSharedTip).GetProperties().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();

        Assert.Equal(
            new[] { "Category", "Confidence", "ContentHash", "Description", "Severity", "SharedAtUtc", "Title" },
            names);
    }

    /// <summary>Stores one tip for TIAConnect and shares it once, returning the service and the tip id.</summary>
    /// <returns>The service bound to this test's database and the shared tip identifier.</returns>
    private async Task<(LlmTipFeedbackService Service, Guid TipId)> SeedSharedTipAsync()
    {
        await SeedProductAsync("TIAConnect");
        var service = new LlmTipFeedbackService(_dbFactoryMock.Object);
        var created = await service.SaveTipAsync(BuildClientTip("hash-3574-seed-shared", clientApproved: false));
        await service.SetSharingAsync(created.Id, null, null, true, null, "admin-ui:alice", "admin-ui", null);
        return (service, created.Id);
    }

    /// <summary>
    /// Inserts the product the ingestion links tips to by application name.
    /// </summary>
    /// <param name="name">Product name matched case-insensitively against the tip's <c>appName</c>.</param>
    private async Task SeedProductAsync(string name)
    {
        await using var db = new LicenseDbContext(_dbOptions);
        db.Products.Add(new Product
        {
            Id = Guid.NewGuid(),
            Name = name,
            PrivateKeyXml = "key",
            PublicKeyXml = "key",
            ApiSecret = "secret-" + name
        });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Builds an anonymized tip exactly as T-IA Connect sends it, without any sensitive field so the
    /// ingestion privacy filter accepts it.
    /// </summary>
    /// <param name="contentHash">Deduplication key; two calls with the same value hit the same row.</param>
    /// <param name="clientApproved">The client's local approval flag (set after three local upvotes).</param>
    /// <param name="appName">Product name the tip is linked to.</param>
    /// <returns>A request accepted by <see cref="LlmTipFeedbackService.SaveTipAsync"/>.</returns>
    internal static LlmTipFeedbackTipRequest BuildClientTip(string contentHash, bool clientApproved, string appName = "TIAConnect")
    {
        return new LlmTipFeedbackTipRequest
        {
            AppName = appName,
            Version = "2.6.292",
            SchemaVersion = "1",
            Anonymized = true,
            ContentHash = contentHash,
            Category = "lad",
            Title = "Convert to Real before Div/Mul in LAD",
            Description = "Constants must be converted to Real before a LAD Div or Mul box.",
            Severity = "info",
            Confidence = "confirmed",
            Approved = clientApproved,
            Upvotes = clientApproved ? 3 : 0,
            SubmittedAt = DateTime.UtcNow.AddMinutes(-1)
        };
    }
}

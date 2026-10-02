using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies deterministic projections and mono-product/global authorization isolation for Recovery analytics.</summary>
public sealed class RecoveryTelemetryAnalyticsTests
{
    /// <summary>Proves mono-product keys default to their product and cannot select a different product.</summary>
    [Fact]
    public async Task MonoProductKey_DefaultsToOwnProduct_AndForbidsCrossProduct()
    {
        await using var fixture = await AnalyticsFixture.CreateAsync();
        var controller = fixture.CreateController();

        var own = await controller.Timeline(fixture.RunId, fixture.ProductKey, null, null, CancellationToken.None);
        Assert.IsType<OkObjectResult>(own);
        var forbidden = await controller.Timeline(fixture.RunId, fixture.ProductKey, fixture.OtherProductId, null, CancellationToken.None);
        Assert.IsType<ForbidResult>(forbidden);
    }

    /// <summary>Proves a global key must select exactly one product and exact names remain case-sensitive in SQL.</summary>
    [Fact]
    public async Task GlobalKey_RequiresOneExactProductSelector()
    {
        await using var fixture = await AnalyticsFixture.CreateAsync();
        var controller = fixture.CreateController();

        var missing = await controller.Timeline(fixture.RunId, fixture.GlobalKey, null, null, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(missing);
        var wrongCase = await controller.Timeline(fixture.RunId, fixture.GlobalKey, null, "tiaconnect", CancellationToken.None);
        Assert.IsType<NotFoundObjectResult>(wrongCase);
        var exact = await controller.Timeline(fixture.RunId, fixture.GlobalKey, null, "TIAConnect", CancellationToken.None);
        Assert.IsType<OkObjectResult>(exact);
    }

    /// <summary>Proves rejections are bounded to the authorized product and contain no raw payload columns.</summary>
    [Fact]
    public async Task Rejections_AreProductScopedAndBounded()
    {
        await using var fixture = await AnalyticsFixture.CreateAsync();
        var rows = await fixture.Analytics.GetRejectionsAsync(fixture.ProductId, null, 500, CancellationToken.None);
        Assert.Single(rows);
        Assert.Equal("unknown_field", rows[0].Code);
        Assert.Equal(fixture.RunId, rows[0].RecoveryRunId);
    }

    /// <summary>Owns a relational authorization fixture with two products and both analytics key kinds.</summary>
    private sealed class AnalyticsFixture : IAsyncDisposable
    {
        private readonly SqliteConnection connection;
        private readonly TestDbContextFactory factory;

        private AnalyticsFixture(SqliteConnection connection, TestDbContextFactory factory)
        {
            this.connection = connection;
            this.factory = factory;
            Analytics = new RecoveryTelemetryAnalyticsService(factory);
        }

        public Guid ProductId { get; private init; }
        public Guid OtherProductId { get; private init; }
        public Guid RunId { get; private init; }
        public string ProductKey { get; private init; } = string.Empty;
        public string GlobalKey { get; private init; } = string.Empty;
        public RecoveryTelemetryAnalyticsService Analytics { get; }

        /// <summary>Creates the API controller with a request context that carries no persisted client identity.</summary>
        public RecoveryTelemetryAnalyticsController CreateController()
        {
            var controller = new RecoveryTelemetryAnalyticsController(new AnalyticsApiKeyAuthService(factory), Analytics, factory)
            {
                ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
            };
            return controller;
        }

        /// <summary>Creates products, keys, one run, and isolated rejection rows in a relational SQLite database.</summary>
        public static async Task<AnalyticsFixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            SqliteFullModelHarness.RegisterConnection(connection);
            var options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseSqlite(connection)
                .AddInterceptors(SqliteFullModelHarness.ConnectionInterceptor, SqliteFullModelHarness.CommandInterceptor)
                .Options;
            var factory = new TestDbContextFactory(options);
            await using var db = new LicenseDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var product = new Product { Name = "TIAConnect", PrivateKeyXml = "test", PublicKeyXml = "test", ApiSecret = "test" };
            var other = new Product { Name = "Other", PrivateKeyXml = "test", PublicKeyXml = "test", ApiSecret = "test" };
            db.Products.AddRange(product, other);
            const string productKey = "sl_product_recovery_test";
            const string globalKey = "sl_global_recovery_test";
            db.AnalyticsApiKeys.AddRange(
                new AnalyticsApiKey { Product = product, Name = "product", Prefix = "product", KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(productKey), ScopeKind = AnalyticsApiKeyScopeKinds.Product, Scopes = AnalyticsApiKeyScopes.TelemetryRead, IsActive = true },
                new AnalyticsApiKey { Name = "global", Prefix = "global", KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(globalKey), ScopeKind = AnalyticsApiKeyScopeKinds.Global, Scopes = $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.MultiProductRead}", IsActive = true });
            var runId = Guid.Parse("10000000-0000-4000-8000-000000000021");
            db.RecoveryTelemetryRuns.Add(new RecoveryTelemetryRun { Product = product, RecoveryRunId = runId, LastSequence = 1, LastStage = "run", LastOutcome = "started", Status = RecoveryTelemetryStatuses.Incomplete, CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow });
            db.RecoveryTelemetryRejections.AddRange(
                new RecoveryTelemetryRejection { Product = product, RecoveryRunId = runId, Code = "unknown_field", CorrelationId = Guid.NewGuid(), ReceivedAtUtc = DateTime.UtcNow },
                new RecoveryTelemetryRejection { Product = other, RecoveryRunId = runId, Code = "unknown_field", CorrelationId = Guid.NewGuid(), ReceivedAtUtc = DateTime.UtcNow });
            await db.SaveChangesAsync();
            return new AnalyticsFixture(connection, factory) { ProductId = product.Id, OtherProductId = other.Id, RunId = runId, ProductKey = productKey, GlobalKey = globalKey };
        }

        /// <summary>Closes the relational connection after all factory-created contexts have completed.</summary>
        public async ValueTask DisposeAsync() => await connection.DisposeAsync();
    }

    /// <summary>Creates independent EF contexts over the fixture's shared relational connection.</summary>
    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options) : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);
    }
}

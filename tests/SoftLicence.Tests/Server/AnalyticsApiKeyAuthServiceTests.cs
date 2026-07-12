using Microsoft.EntityFrameworkCore;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class AnalyticsApiKeyAuthServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;

    public AnalyticsApiKeyAuthServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task ValidateAsync_WhenKeyIsValid_ReturnsProductAndUpdatesAudit()
    {
        var productId = Guid.NewGuid();
        const string rawKey = "sla_test_valid_key";
        await SeedKeyAsync(productId, rawKey, AnalyticsApiKeyScopes.TelemetryRead);
        var service = new AnalyticsApiKeyAuthService(_dbFactoryMock.Object);

        var result = await service.ValidateAsync(rawKey, AnalyticsApiKeyScopes.TelemetryRead, "127.0.0.1");

        Assert.NotNull(result);
        Assert.Equal(productId, result.ProductId);
        Assert.False(result.IsGlobal);
        Assert.Equal(AnalyticsApiKeyScopeKinds.Product, result.ScopeKind);

        await using var db = new LicenseDbContext(_dbOptions);
        var storedKey = await db.AnalyticsApiKeys.SingleAsync();
        Assert.NotEqual(rawKey, storedKey.KeyHash);
        Assert.Equal(AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey), storedKey.KeyHash);
        Assert.NotNull(storedKey.LastUsedAtUtc);
        Assert.Equal("127.0.0.1", storedKey.LastUsedIp);
    }

    [Fact]
    public async Task ValidateAsync_WhenKeyIsInactive_ReturnsNull()
    {
        const string rawKey = "sla_test_inactive_key";
        await SeedKeyAsync(Guid.NewGuid(), rawKey, AnalyticsApiKeyScopes.TelemetryRead, isActive: false);
        var service = new AnalyticsApiKeyAuthService(_dbFactoryMock.Object);

        var result = await service.ValidateAsync(rawKey, AnalyticsApiKeyScopes.TelemetryRead, "127.0.0.1");

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WhenKeyIsExpired_ReturnsNull()
    {
        const string rawKey = "sla_test_expired_key";
        await SeedKeyAsync(
            Guid.NewGuid(),
            rawKey,
            AnalyticsApiKeyScopes.TelemetryRead,
            expiresAtUtc: DateTime.UtcNow.AddMinutes(-1));
        var service = new AnalyticsApiKeyAuthService(_dbFactoryMock.Object);

        var result = await service.ValidateAsync(rawKey, AnalyticsApiKeyScopes.TelemetryRead, "127.0.0.1");

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WhenScopeIsMissing_ReturnsNull()
    {
        const string rawKey = "sla_test_wrong_scope_key";
        await SeedKeyAsync(Guid.NewGuid(), rawKey, "admin:read");
        var service = new AnalyticsApiKeyAuthService(_dbFactoryMock.Object);

        var result = await service.ValidateAsync(rawKey, AnalyticsApiKeyScopes.TelemetryRead, "127.0.0.1");

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WhenGlobalKeyIsValid_ReturnsGlobalScope()
    {
        const string rawKey = "sla_test_global_valid_key";
        await using (var db = new LicenseDbContext(_dbOptions))
        {
            db.AnalyticsApiKeys.Add(new AnalyticsApiKey
            {
                ProductId = null,
                Name = "Global test analytics key",
                Prefix = AnalyticsApiKeyAuthService.BuildPrefix(rawKey),
                KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey),
                Scopes = $"{AnalyticsApiKeyScopes.TelemetryRead} {AnalyticsApiKeyScopes.MultiProductRead}",
                ScopeKind = AnalyticsApiKeyScopeKinds.Global,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var service = new AnalyticsApiKeyAuthService(_dbFactoryMock.Object);

        var result = await service.ValidateAsync(rawKey, AnalyticsApiKeyScopes.TelemetryRead, "127.0.0.1");

        Assert.NotNull(result);
        Assert.Null(result.ProductId);
        Assert.True(result.IsGlobal);
        Assert.Equal(AnalyticsApiKeyScopeKinds.Global, result.ScopeKind);
    }

    private async Task SeedKeyAsync(
        Guid productId,
        string rawKey,
        string scopes,
        bool isActive = true,
        DateTime? expiresAtUtc = null)
    {
        await using var db = new LicenseDbContext(_dbOptions);
        db.Products.Add(new Product
        {
            Id = productId,
            Name = $"Product-{Guid.NewGuid():N}",
            PrivateKeyXml = "k",
            PublicKeyXml = "k",
            ApiSecret = Guid.NewGuid().ToString("N")
        });
        db.AnalyticsApiKeys.Add(new AnalyticsApiKey
        {
            ProductId = productId,
            Name = "Test analytics key",
            Prefix = AnalyticsApiKeyAuthService.BuildPrefix(rawKey),
            KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(rawKey),
            Scopes = scopes,
            ScopeKind = AnalyticsApiKeyScopeKinds.Product,
            IsActive = isActive,
            ExpiresAtUtc = expiresAtUtc
        });
        await db.SaveChangesAsync();
    }
}

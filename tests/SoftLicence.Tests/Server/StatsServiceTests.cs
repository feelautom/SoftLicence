using Microsoft.EntityFrameworkCore;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public class StatsServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;

    public StatsServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(default))
            .Returns(() => Task.FromResult(new LicenseDbContext(_dbOptions)));
    }

    [Fact]
    public async Task GetDashboardStatsAsync_ShouldCalculateCorrectKPIs()
    {
        // Arrange
        using (var db = new LicenseDbContext(_dbOptions))
        {
            db.Products.Add(new Product { Id = Guid.NewGuid(), Name = "P1", PrivateKeyXml = "k", PublicKeyXml = "k" });
            db.Products.Add(new Product { Id = Guid.NewGuid(), Name = "P2", PrivateKeyXml = "k", PublicKeyXml = "k" });
            
            db.Licenses.Add(new License { Id = Guid.NewGuid(), LicenseKey = "L1", IsActive = true, ProductId = Guid.NewGuid(), LicenseTypeId = Guid.NewGuid(), CustomerName="C1", CustomerEmail="e" });
            db.Licenses.Add(new License { Id = Guid.NewGuid(), LicenseKey = "L2", IsActive = true, ProductId = Guid.NewGuid(), LicenseTypeId = Guid.NewGuid(), CustomerName="C2", CustomerEmail="e" });
            db.Licenses.Add(new License { Id = Guid.NewGuid(), LicenseKey = "L3", IsActive = false, ProductId = Guid.NewGuid(), LicenseTypeId = Guid.NewGuid(), CustomerName="C3", CustomerEmail="e" });
            
            await db.SaveChangesAsync();
        }

        var service = new StatsService(_dbFactoryMock.Object);

        // Act
        var stats = await service.GetDashboardStatsAsync();

        // Assert
        Assert.Equal(2, stats.TotalProducts);
        Assert.Equal(3, stats.TotalLicenses);
        Assert.Equal(2, stats.ActiveLicenses);
        Assert.Equal(1, stats.RevokedLicenses);
    }

    [Fact]
    public async Task GetDashboardStatsAsync_ShouldCalculateRequestMetrics()
    {
        // Arrange
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var now = DateTime.UtcNow;
            
            // Successes
            db.AccessLogs.Add(new AccessLog { Timestamp = now, ResultStatus = "VALID", Endpoint = "ACTIVATE", IsSuccess = true, ClientIp="1", Path="/", Method="P", AppName="A" });
            db.AccessLogs.Add(new AccessLog { Timestamp = now, ResultStatus = "SUCCESS", Endpoint = "CHECK", IsSuccess = true, ClientIp="1", Path="/", Method="P", AppName="A" });
            
            // Fails
            db.AccessLogs.Add(new AccessLog { Timestamp = now, ResultStatus = "INVALID_KEY", Endpoint = "ACTIVATE", IsSuccess = false, ClientIp="1", Path="/", Method="P", AppName="A" });
            db.AccessLogs.Add(new AccessLog { Timestamp = now, ResultStatus = "NOT_FOUND", Endpoint = "OTHER", IsSuccess = false, ClientIp="1", Path="/", Method="P", AppName="A" });

            await db.SaveChangesAsync();
        }

        var service = new StatsService(_dbFactoryMock.Object);

        // Act
        var stats = await service.GetDashboardStatsAsync();

        // Assert
        Assert.Equal(4, stats.TotalRequests);
        Assert.Equal(2, stats.FailedRequests); // INVALID_KEY and NOT_FOUND
        Assert.Equal(1, stats.ActivationCount); // Only the VALID one
        Assert.Equal(1, stats.CheckInCount); // Only the SUCCESS one
    }

    [Fact]
    public async Task GetDashboardStatsAsync_ShouldGenerateActivityChart()
    {
        // Arrange
        using (var db = new LicenseDbContext(_dbOptions))
        {
            var today = DateTime.UtcNow.Date;
            var yesterday = today.AddDays(-1);

            // Today: 2 total, 1 error
            db.AccessLogs.Add(new AccessLog { Timestamp = today.AddHours(1), ResultStatus = "VALID", IsSuccess = true, ClientIp="1", Path="/", Method="P", AppName="A", Endpoint="E" });
            db.AccessLogs.Add(new AccessLog { Timestamp = today.AddHours(2), ResultStatus = "ERROR", IsSuccess = false, ClientIp="1", Path="/", Method="P", AppName="A", Endpoint="E" });

            // Yesterday: 1 total, 0 error
            db.AccessLogs.Add(new AccessLog { Timestamp = yesterday.AddHours(5), ResultStatus = "SUCCESS", IsSuccess = true, ClientIp="1", Path="/", Method="P", AppName="A", Endpoint="E" });

            await db.SaveChangesAsync();
        }

        var service = new StatsService(_dbFactoryMock.Object);

        // Act
        var stats = await service.GetDashboardStatsAsync();

        // Assert
        Assert.Equal(7, stats.ActivityChart.Count);
        
        var todayData = stats.ActivityChart.First(c => c.Date == DateTime.UtcNow.Date);
        Assert.Equal(2, todayData.Total);
        Assert.Equal(1, todayData.Errors);

        var yesterdayData = stats.ActivityChart.First(c => c.Date == DateTime.UtcNow.Date.AddDays(-1));
        Assert.Equal(1, yesterdayData.Total);
        Assert.Equal(0, yesterdayData.Errors);
    }
}

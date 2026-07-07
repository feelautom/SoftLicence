using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class FreemiumAbuseBugTraceAlertServiceTests
{
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly Mock<IDbContextFactory<LicenseDbContext>> _dbFactoryMock;
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public FreemiumAbuseBugTraceAlertServiceTests()
    {
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbFactoryMock = new Mock<IDbContextFactory<LicenseDbContext>>();
        _dbFactoryMock.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_dbOptions));
    }

    [Fact]
    public async Task HandleTelemetryAsync_WhenFreemiumRiskIsHigh_CreatesInternalBugTraceTicket()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var domain = $"risk-{Guid.NewGuid():N}.example";

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndFreemiumType(db, productId, typeId);
            AddLicense(db, productId, typeId, $"user1@{domain}", "HW-RISK-1", now.AddDays(-5), now.AddDays(2));
            AddLicense(db, productId, typeId, $"user2@{domain}", "HW-RISK-2", now.AddDays(-4), now.AddDays(3));
            AddLicense(db, productId, typeId, $"user3@{domain}", "HW-RISK-3", now.AddDays(-3), now.AddDays(4));
            AddEvent(db, productId, "HW-RISK-1", "Mcp_ToolCall", now.AddHours(-1), """{"Quota_Mcp_Daily":"20/20"}""");
            AddEvent(db, productId, "HW-RISK-2", "Compile_Success", now.AddHours(-2), "{}");
            AddEvent(db, productId, "HW-RISK-3", "Tag_Export", now.AddHours(-3), "{}");
            await db.SaveChangesAsync();
        }

        var bugTrace = new FakeBugTraceProxy();
        var service = BuildService(bugTrace);

        await service.HandleTelemetryAsync(productId, BuildTrigger("HW-RISK-1"));

        var submitted = Assert.Single(bugTrace.SubmittedTickets);
        var json = JsonSerializer.Serialize(submitted);

        Assert.Contains("\"isInternal\":true", json);
        Assert.Contains("\"priority\":\"HIGH\"", json);
        Assert.Contains("Freemium abuse risk", json);
        Assert.Contains("No automatic revocation was performed", json);
        Assert.Contains("business_domain", json);
        Assert.Contains("dedupe:", json);
        Assert.DoesNotContain("HW-RISK-1\"", json);
    }

    [Fact]
    public async Task HandleTelemetryAsync_WhenSameRiskGroupIsSeenTwice_CreatesSingleTicket()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var domain = $"dedupe-{Guid.NewGuid():N}.example";

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndFreemiumType(db, productId, typeId);
            AddLicense(db, productId, typeId, $"user1@{domain}", "HW-DEDUP-1", now.AddDays(-5), now.AddDays(2));
            AddLicense(db, productId, typeId, $"user2@{domain}", "HW-DEDUP-2", now.AddDays(-4), now.AddDays(3));
            AddLicense(db, productId, typeId, $"user3@{domain}", "HW-DEDUP-3", now.AddDays(-3), now.AddDays(4));
            AddEvent(db, productId, "HW-DEDUP-1", "Mcp_ToolCall", now.AddHours(-1), """{"Quota_Mcp_Daily":"20/20"}""");
            AddEvent(db, productId, "HW-DEDUP-2", "Compile_Success", now.AddHours(-2), "{}");
            await db.SaveChangesAsync();
        }

        var bugTrace = new FakeBugTraceProxy();
        var service = BuildService(bugTrace);

        await service.HandleTelemetryAsync(productId, BuildTrigger("HW-DEDUP-1"));
        await service.HandleTelemetryAsync(productId, BuildTrigger("HW-DEDUP-1"));

        Assert.Single(bugTrace.SubmittedTickets);
    }

    [Fact]
    public async Task HandleTelemetryAsync_WhenSameCustomerNameUsesDifferentEmailsAndHardware_CreatesReviewTicket()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndFreemiumType(db, productId, typeId);
            AddLicense(db, productId, typeId, "first@gmail.com", "HW-NAME-ALERT-1", now.AddDays(-2), now.AddDays(5), "Oussama Essalih");
            AddLicense(db, productId, typeId, "second@outlook.com", "HW-NAME-ALERT-2", now.AddDays(-1), now.AddDays(6), "Oussama Essalih");
            AddEvent(db, productId, "HW-NAME-ALERT-1", "Mcp_ToolCall", now.AddHours(-1), """{"Quota_Mcp_Daily":"20/20"}""");
            AddEvent(db, productId, "HW-NAME-ALERT-2", "Compile_Success", now.AddHours(-2), "{}");
            await db.SaveChangesAsync();
        }

        var bugTrace = new FakeBugTraceProxy();
        var service = BuildService(bugTrace);

        await service.HandleTelemetryAsync(productId, BuildTrigger("HW-NAME-ALERT-1"));

        var submitted = Assert.Single(bugTrace.SubmittedTickets);
        var json = JsonSerializer.Serialize(submitted);

        Assert.Contains("\"priority\":\"NORMAL\"", json);
        Assert.Contains("probable_multi_account_abuse", json);
        Assert.Contains("shared_customer_name", json);
        Assert.Contains("CustomerNameHashes", json);
        Assert.DoesNotContain("Oussama", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleTelemetryAsync_WhenFreemiumRiskIsLow_DoesNotCreateTicket()
    {
        var now = DateTime.UtcNow;
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();

        await using (var db = new LicenseDbContext(_dbOptions))
        {
            SeedProductAndFreemiumType(db, productId, typeId);
            AddLicense(db, productId, typeId, "solo@gmail.com", "HW-SOLO-LOW", now.AddDays(-1), now.AddDays(6));
            AddEvent(db, productId, "HW-SOLO-LOW", "Copilot_ToolCall", now.AddHours(-1), """{"Quota_Copilot_Daily":"10/100"}""");
            await db.SaveChangesAsync();
        }

        var bugTrace = new FakeBugTraceProxy();
        var service = BuildService(bugTrace);

        await service.HandleTelemetryAsync(productId, BuildTrigger("HW-SOLO-LOW"));

        Assert.Empty(bugTrace.SubmittedTickets);
    }

    private FreemiumAbuseBugTraceAlertService BuildService(FakeBugTraceProxy bugTrace)
    {
        var risk = new FreemiumAbuseRiskAnalyticsService(_dbFactoryMock.Object, _cache);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SOFTLICENCE_FREEMIUM_ABUSE_AUTO_TICKETS"] = "true"
            })
            .Build();

        return new FreemiumAbuseBugTraceAlertService(
            risk,
            bugTrace,
            Mock.Of<ILogger<FreemiumAbuseBugTraceAlertService>>(),
            config);
    }

    private static void SeedProductAndFreemiumType(LicenseDbContext db, Guid productId, Guid typeId)
    {
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "TIAConnect",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = "secret"
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "TIA Connect Freemium",
            Slug = "TIA-CONNECT-FREEMIUM",
            IsFree = true
        });
    }

    private static void AddLicense(
        LicenseDbContext db,
        Guid productId,
        Guid typeId,
        string email,
        string hardwareId,
        DateTime activationDate,
        DateTime expirationDate,
        string? customerName = null)
    {
        db.Licenses.Add(new License
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = Guid.NewGuid().ToString("N"),
            CustomerEmail = email,
            CustomerName = customerName ?? email,
            HardwareId = hardwareId,
            ActivationDate = activationDate,
            CreationDate = activationDate,
            ExpirationDate = expirationDate,
            IsActive = true
        });
    }

    private static void AddEvent(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        string eventName,
        DateTime timestamp,
        string propertiesJson)
    {
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            HardwareId = hardwareId,
            ClientIp = "203.0.113.10",
            AppName = "TIAConnect",
            Version = "2.1.997",
            Type = TelemetryType.Event,
            EventName = eventName,
            Timestamp = timestamp,
            EventData = new TelemetryEvent
            {
                PropertiesJson = propertiesJson
            }
        });
    }

    private static TelemetryEventRequest BuildTrigger(string hardwareId)
    {
        return new TelemetryEventRequest
        {
            AppName = "TIAConnect",
            HardwareId = hardwareId,
            Version = "2.1.997",
            EventName = "Mcp_ToolCall",
            Properties = new Dictionary<string, string>
            {
                ["Quota_Mcp_Daily"] = "20/20"
            }
        };
    }

    private sealed class FakeBugTraceProxy : IBugTraceProxyService
    {
        public string ExpectedProjectId => "test-project";
        public bool IsConfigured { get; set; } = true;
        public List<object> SubmittedTickets { get; } = new();

        public Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default)
        {
            SubmittedTickets.Add(ticketBody);
            var json = JsonSerializer.Serialize(new { ticketNumber = "TKT-TEST-001", id = "ticket-id" });
            return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
        }

        public Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default) =>
            throw new NotImplementedException();

        public Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default) =>
            throw new NotImplementedException();

        public Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default) =>
            throw new NotImplementedException();
    }
}

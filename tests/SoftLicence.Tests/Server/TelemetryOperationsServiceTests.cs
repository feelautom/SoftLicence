using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class TelemetryOperationsServiceTests
{
    [Fact]
    public void Parse_MalformedJson_ReportsOnlySanitizedValidationCode()
    {
        var result = TelemetryRejectionCaptureMiddleware.Parse("{\"hardwareId\":", oversized: false);
        Assert.Equal("MalformedJson", result.ValidationCode);
        Assert.Equal(["body"], result.InvalidFields);
        Assert.Null(result.HardwareId);
    }

    [Fact]
    public void Parse_MissingAndWrongType_IdentifiesFieldsWithoutRawPayload()
    {
        var result = TelemetryRejectionCaptureMiddleware.Parse(
            "{\"hardwareId\":123,\"appName\":\"TIAConnect\",\"eventName\":\"\"}", oversized: false);
        Assert.Equal("InvalidFields", result.ValidationCode);
        Assert.Contains("hardwareId:type", result.InvalidFields);
        Assert.Contains("eventName:empty", result.InvalidFields);
    }

    [Fact]
    public void Parse_Oversized_DoesNotInspectBody()
    {
        var result = TelemetryRejectionCaptureMiddleware.Parse("secret", oversized: true);
        Assert.Equal("PayloadTooLarge", result.ValidationCode);
        Assert.Null(result.AppName);
        Assert.Null(result.HardwareId);
    }

    [Fact]
    public void IdentifierNormalization_IsStableAndMasked()
    {
        Assert.Equal(
            TelemetryRejectionService.HashIdentifier(" hw-abcd-1234 "),
            TelemetryRejectionService.HashIdentifier("HW-ABCD-1234"));
        Assert.Equal("HW-A…1234", TelemetryRejectionService.MaskIdentifier("hw-abcd-1234"));
        Assert.Equal("219.140.62.0/24", TelemetryRejectionService.MaskIp("219.140.62.45"));
    }

    [Fact]
    public async Task Rejection_RecordAsync_PersistsOnlyBoundedSanitizedMetadata()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        var factory = new TestDbFactory(options);
        var notifications = new Mock<NotificationService>(factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        var service = new TelemetryRejectionService(factory, notifications.Object);

        await service.RecordAsync(new TelemetryRejectionCandidate(
            "/api/telemetry/event", "InvalidFields", ["hardwareId:type"],
            "TIAConnect", "2.2.798", "Startup", "secret-hwid-1234",
            "219.140.62.45", "WebSetup\r\nInjected", "corr-1"));

        await using var db = await factory.CreateDbContextAsync();
        var row = await db.TelemetryIngestionRejections.SingleAsync();
        Assert.Equal("SECR…1234", row.HardwareIdMasked);
        Assert.DoesNotContain("secret-hwid-1234", row.HardwareIdHash, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("219.140.62.0/24", row.ClientIpMasked);
        Assert.Equal("WebSetupInjected", row.ClientName);
        Assert.Equal("corr-1", row.CorrelationId);
    }

    [Fact]
    public async Task ActivationIncident_ThresholdDeduplicatesAndSuccessRecovers()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        var factory = new TestDbFactory(options);
        var notifications = new Mock<NotificationService>(factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        var service = new ActivationIncidentService(factory, notifications.Object);
        var request = new TelemetryEventRequest
        {
            HardwareId = "hw-activation-0001",
            AppName = "TIAConnect",
            Version = "2.2.798",
            EventName = "LicenseActivation_NetworkError"
        };

        await service.ProcessAsync(null, request, "219.140.62.45", new GeoInfo { CountryCode = "CN", Isp = "Test" });
        await service.ProcessAsync(null, request, "219.140.62.45", new GeoInfo { CountryCode = "CN", Isp = "Test" });
        await service.ProcessAsync(null, request, "219.140.62.45", new GeoInfo { CountryCode = "CN", Isp = "Test" });

        await using (var db = await factory.CreateDbContextAsync())
        {
            var incident = await db.ActivationIncidents.SingleAsync();
            Assert.Equal("WARNING", incident.Severity);
            Assert.Equal(3, incident.RepeatCount);
            Assert.Equal("WARNING", incident.LastNotifiedSeverity);
            Assert.DoesNotContain("hw-activation-0001", incident.HardwareIdMasked, StringComparison.OrdinalIgnoreCase);
        }

        request.EventName = "LicenseActivation_Success";
        await service.ProcessAsync(null, request, "219.140.62.45", new GeoInfo { CountryCode = "CN" });
        await using (var db = await factory.CreateDbContextAsync())
            Assert.Equal("RECOVERED", (await db.ActivationIncidents.SingleAsync()).Status);

        notifications.Verify(x => x.Notify(NotificationService.Triggers.ActivationIncident, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()), Times.Once);
        notifications.Verify(x => x.Notify(NotificationService.Triggers.ActivationRecovered, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()), Times.Once);
    }

    private sealed class TestDbFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options;
        public TestDbFactory(DbContextOptions<LicenseDbContext> options) => _options = options;
        public LicenseDbContext CreateDbContext() => new(_options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) => Task.FromResult(CreateDbContext());
    }
}

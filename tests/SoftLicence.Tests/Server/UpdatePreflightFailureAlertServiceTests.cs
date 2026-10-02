using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class UpdatePreflightFailureAlertServiceTests : IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private DbContextOptions<LicenseDbContext> _options = null!;
    private Guid _productId;

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        SqliteFullModelHarness.RegisterConnection(_connection);
        _options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(
                SqliteFullModelHarness.ConnectionInterceptor,
                SqliteFullModelHarness.CommandInterceptor)
            .Options;
        await using var db = new LicenseDbContext(_options);
        await db.Database.EnsureCreatedAsync();
        _productId = Guid.NewGuid();
        db.Products.Add(new Product
        {
            Id = _productId,
            Name = "TIAConnect",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = "secret"
        });
        await db.SaveChangesAsync();
    }

    public async Task DisposeAsync() => await _connection.DisposeAsync();

    [Fact]
    public void TryParse_RejectsFreeFormOrUnknownProtocolValues()
    {
        var valid = BuildRequest();
        Assert.True(UpdatePreflightFailureAlertService.TryParse(valid, out var observation));
        Assert.Equal(64, observation.SignatureSha256.Length);

        valid.Properties!["DecisionReason"] = "server said: secret payload";
        Assert.False(UpdatePreflightFailureAlertService.TryParse(valid, out _));
        valid.Properties["DecisionReason"] = "distribution_downloads_paused";
        valid.Properties["SupportCode"] = "UPD-9999";
        Assert.False(UpdatePreflightFailureAlertService.TryParse(valid, out _));
    }

    [Fact]
    public async Task RecordAndClaimAsync_GroupsThirtyMinuteSignatureWithoutLosingOccurrences()
    {
        var service = BuildService();
        Assert.True(UpdatePreflightFailureAlertService.TryParse(BuildRequest(), out var observation));
        var firstAt = new DateTime(2026, 9, 20, 7, 5, 0, DateTimeKind.Utc);

        var first = await service.RecordAndClaimAsync(_productId, observation, firstAt);
        var repeated = await service.RecordAndClaimAsync(_productId, observation, firstAt.AddMinutes(2));
        var nextWindow = await service.RecordAndClaimAsync(_productId, observation, firstAt.AddMinutes(30));

        Assert.True(first.ShouldNotify);
        Assert.NotNull(first.ClaimId);
        Assert.False(repeated.ShouldNotify);
        Assert.Equal(2, repeated.OccurrenceCount);
        Assert.True(nextWindow.ShouldNotify);
        Assert.NotEqual(first.AggregateId, nextWindow.AggregateId);

        await using var db = new LicenseDbContext(_options);
        var aggregates = await db.TelemetryUpdatePreflightAlerts
            .OrderBy(item => item.WindowStartUtc)
            .ToListAsync();
        Assert.Equal(2, aggregates.Count);
        Assert.Equal(2, aggregates[0].OccurrenceCount);
        Assert.Equal(1, aggregates[1].OccurrenceCount);
    }

    [Fact]
    public async Task RecordAndClaimAsync_UntrustedDiagnosticVariantsCannotMultiplyAlerts()
    {
        var service = BuildService();
        var firstRequest = BuildRequest();
        var variantRequest = BuildRequest();
        variantRequest.Properties!["DecisionReason"] = "different_bounded_reason";
        variantRequest.Properties["CurrentVersion"] = "9.9.9";
        Assert.True(UpdatePreflightFailureAlertService.TryParse(firstRequest, out var firstObservation));
        Assert.True(UpdatePreflightFailureAlertService.TryParse(variantRequest, out var variantObservation));
        var observedAt = new DateTime(2026, 9, 20, 7, 5, 0, DateTimeKind.Utc);

        var first = await service.RecordAndClaimAsync(_productId, firstObservation, observedAt);
        var variant = await service.RecordAndClaimAsync(
            _productId,
            variantObservation,
            observedAt.AddMinutes(1));

        Assert.True(first.ShouldNotify);
        Assert.False(variant.ShouldNotify);
        Assert.Equal(first.AggregateId, variant.AggregateId);
        Assert.Equal(2, variant.OccurrenceCount);
    }

    [Fact]
    public async Task MarkNotificationSentAsync_PreventsAnotherClaimInSameWindow()
    {
        var service = BuildService();
        Assert.True(UpdatePreflightFailureAlertService.TryParse(BuildRequest(), out var observation));
        var observedAt = new DateTime(2026, 9, 20, 7, 5, 0, DateTimeKind.Utc);
        var first = await service.RecordAndClaimAsync(_productId, observation, observedAt);

        await service.MarkNotificationSentAsync(
            first.AggregateId,
            first.ClaimId!.Value,
            observedAt.AddSeconds(1));
        var repeated = await service.RecordAndClaimAsync(
            _productId,
            observation,
            observedAt.AddMinutes(5));

        Assert.False(repeated.ShouldNotify);
        Assert.Equal(2, repeated.OccurrenceCount);
    }

    [Fact]
    public async Task RecordAndClaimAsync_WhenPreviousClaimExpired_AllowsNotificationRecovery()
    {
        var service = BuildService();
        Assert.True(UpdatePreflightFailureAlertService.TryParse(BuildRequest(), out var observation));
        var observedAt = new DateTime(2026, 9, 20, 7, 5, 0, DateTimeKind.Utc);
        var abandoned = await service.RecordAndClaimAsync(_productId, observation, observedAt);

        var recovered = await service.RecordAndClaimAsync(
            _productId,
            observation,
            observedAt.AddMinutes(6));

        Assert.True(recovered.ShouldNotify);
        Assert.NotNull(recovered.ClaimId);
        Assert.NotEqual(abandoned.ClaimId, recovered.ClaimId);
        Assert.Equal(abandoned.AggregateId, recovered.AggregateId);
        Assert.Equal(2, recovered.OccurrenceCount);
    }

    private UpdatePreflightFailureAlertService BuildService()
    {
        var factory = new Mock<IDbContextFactory<LicenseDbContext>>();
        factory.Setup(item => item.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(_options));
        return new UpdatePreflightFailureAlertService(
            factory.Object,
            NullLogger<UpdatePreflightFailureAlertService>.Instance);
    }

    private static TelemetryEventRequest BuildRequest() => new()
    {
        AppName = "TIAConnect",
        HardwareId = "HW-UPD",
        Version = "2.4.380",
        EventName = UpdatePreflightFailureAlertService.EventName,
        Properties = new Dictionary<string, string>
        {
            ["SupportCode"] = "UPD-1002",
            ["CurrentVersion"] = "2.4.380",
            ["LatestVersion"] = "2.4.309",
            ["PresentationStage"] = "initial",
            ["DecisionReason"] = "distribution_downloads_paused",
            ["SelectedChannel"] = "paid",
            ["ReconciliationOutcome"] = "unknown",
            ["UpdateAvailable"] = "False",
            ["Mandatory"] = "False",
            ["UpToDate"] = "False"
        }
    };
}

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Verifies the relational contract that activation failures sent through the event endpoint retain
/// their event payload while being classified as errors for support and analytics consumers.
/// </summary>
/// <remarks>
/// Event names are exact ordinal protocol identifiers. Legacy fallback is intentionally limited to
/// two historical names; current producers must use the explicit direct or nested error type.
/// </remarks>
/// <param name="fixture">The fixture that owns the isolated PostgreSQL database and test server.</param>
public sealed class TelemetryActivationFailureClassificationPostgreSqlTests(
    TelemetryActivationFailureClassificationPostgreSqlFixture fixture)
    : IClassFixture<TelemetryActivationFailureClassificationPostgreSqlFixture>
{
    /// <summary>
    /// Proves that the two exact legacy names remain error-classified without losing their event-backed
    /// support metadata when an older producer omits the explicit type.
    /// </summary>
    /// <param name="eventName">The exact legacy activation-failure protocol identifier.</param>
    [Theory]
    [InlineData("LicenseActivation_Failed")]
    [InlineData("LicenseActivation_ApiError")]
    public async Task PostEvent_LegacyActivationFailureName_ShouldPersistErrorWithCompleteEventProperties(
        string eventName)
    {
        var product = await fixture.CreateProductAsync("legacy");
        var hardwareId = NewHardwareId();
        var properties = CreateSupportProperties();

        var record = await PostEventAndReadAsync(product, hardwareId, new
        {
            timestamp = DateTime.UtcNow,
            hardwareId,
            appName = product.Name,
            version = "2.4.0",
            eventName,
            properties
        });

        Assert.Equal(TelemetryType.Error, record.Type);
        Assert.Equal(eventName, record.EventName);
        Assert.Null(record.ErrorData);
        AssertPropertiesEqual(properties, record.EventData?.PropertiesJson);
    }

    /// <summary>
    /// Proves that a current producer can explicitly classify a reason-specific activation failure as
    /// an error at the event endpoint without renaming it or converting its properties to error data.
    /// </summary>
    [Fact]
    public async Task PostEvent_DirectExplicitErrorType_ShouldPersistErrorWithoutRenamingOrPropertyLoss()
    {
        const string eventName = "LicenseActivation_InvalidKey";
        var product = await fixture.CreateProductAsync("direct");
        var hardwareId = NewHardwareId();
        var properties = CreateSupportProperties();

        var record = await PostEventAndReadAsync(product, hardwareId, new
        {
            timestamp = DateTime.UtcNow,
            hardwareId,
            appName = product.Name,
            version = "2.4.0",
            eventName,
            type = "Error",
            properties
        });

        Assert.Equal(TelemetryType.Error, record.Type);
        Assert.Equal(eventName, record.EventName);
        Assert.Null(record.ErrorData);
        AssertPropertiesEqual(properties, record.EventData?.PropertiesJson);
    }

    /// <summary>
    /// Proves that the compatibility <c>req</c> envelope can carry the explicit error classification and
    /// property bag while the endpoint retains the top-level routing identity used by deployed clients.
    /// </summary>
    [Fact]
    public async Task PostEvent_NestedRequestExplicitErrorType_ShouldPersistErrorAndNestedProperties()
    {
        const string eventName = "LicenseActivation_NetworkError";
        var product = await fixture.CreateProductAsync("nested");
        var hardwareId = NewHardwareId();
        var properties = CreateSupportProperties();
        var timestamp = DateTime.UtcNow;

        var record = await PostEventAndReadAsync(product, hardwareId, new
        {
            timestamp,
            hardwareId,
            appName = product.Name,
            version = "2.4.0",
            eventName,
            req = new
            {
                timestamp,
                hardwareId,
                appName = product.Name,
                version = "2.4.0",
                eventName,
                type = "Error",
                properties
            }
        });

        Assert.Equal(TelemetryType.Error, record.Type);
        Assert.Equal(eventName, record.EventName);
        Assert.Null(record.ErrorData);
        AssertPropertiesEqual(properties, record.EventData?.PropertiesJson);
    }

    /// <summary>
    /// Locks the exact ordinal fallback boundary so lookalikes, success telemetry, and ordinary usage
    /// telemetry cannot inflate operational error counters.
    /// </summary>
    /// <param name="eventName">A protocol identifier that must remain an ordinary event.</param>
    [Theory]
    [InlineData("licenseactivation_failed")]
    [InlineData("LicenseActivation_Failed ")]
    [InlineData("LicenseActivation_Success")]
    [InlineData("Usage_ProjectOpened")]
    public async Task PostEvent_NonAllowlistedNameWithoutExplicitType_ShouldRemainEvent(string eventName)
    {
        var product = await fixture.CreateProductAsync("negative");
        var hardwareId = NewHardwareId();

        var record = await PostEventAndReadAsync(product, hardwareId, new
        {
            timestamp = DateTime.UtcNow,
            hardwareId,
            appName = product.Name,
            version = "2.4.0",
            eventName,
            properties = CreateSupportProperties()
        });

        Assert.Equal(TelemetryType.Event, record.Type);
    }

    /// <summary>
    /// Proves that the product telemetry read model exposes event-backed properties for an error-typed
    /// row instead of returning a null data payload.
    /// </summary>
    [Fact]
    public async Task GetTelemetry_ErrorTypedEventData_ShouldReturnWebsiteContract()
    {
        var product = await fixture.CreateProductAsync("read-model");
        var hardwareId = NewHardwareId();
        var properties = CreateSupportProperties();
        await fixture.SeedHybridErrorEventAsync(product.Id, product.Name, hardwareId, properties);

        using var client = fixture.CreateClient();
        client.DefaultRequestHeaders.Add("X-Product-Key", product.ApiSecret);
        using var response = await client.GetAsync("/api/telemetry?page=1&pageSize=10&type=Error");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var row = Assert.Single(payload.RootElement.EnumerateArray());
        Assert.Equal("Error", row.GetProperty("type").GetString());
        Assert.Equal("LicenseActivation_Failed", row.GetProperty("eventName").GetString());
        var data = row.GetProperty("data");
        Assert.Equal(JsonValueKind.Object, data.ValueKind);
        Assert.Equal(properties["CorrelationId"], data.GetProperty("CorrelationId").GetString());
        Assert.Equal(properties["FailureReason"], data.GetProperty("FailureReason").GetString());
    }

    /// <summary>
    /// Proves that event-backed errors retain the ordinary event flood policy while classic error-data
    /// submissions remain exempt, preserving complete crash evidence sent through the error endpoint.
    /// </summary>
    [Fact]
    public async Task RepeatedErrors_ShouldSuppressHybridEventsButRetainClassicErrorData()
    {
        var product = await fixture.CreateProductAsync("flood-policy");
        var hardwareId = NewHardwareId();
        await fixture.ConfigureFloodSuppressionAsync(threshold: 1, windowMinutes: 10);
        using var client = fixture.CreateClient();

        var classicPayload = new
        {
            timestamp = DateTime.UtcNow,
            hardwareId,
            appName = product.Name,
            version = "2.4.0",
            eventName = "LicenseActivation_Failed",
            errorType = "System.InvalidOperationException",
            message = "bounded test message",
            stackTrace = "bounded test stack"
        };
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var response = await client.PostAsJsonAsync("/api/telemetry/error", classicPayload);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        var hybridPayload = new
        {
            timestamp = DateTime.UtcNow,
            hardwareId,
            appName = product.Name,
            version = "2.4.0",
            eventName = "LicenseActivation_Failed",
            properties = CreateSupportProperties()
        };
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var response = await client.PostAsJsonAsync("/api/telemetry/event", hybridPayload);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        await using var db = fixture.CreateDb();
        Assert.Equal(1, await db.TelemetryRecords.CountAsync(record =>
            record.HardwareId == hardwareId
            && record.EventName == "LicenseActivation_Failed"
            && record.Type == TelemetryType.Error
            && record.EventData != null));
        Assert.Equal(2, await db.TelemetryRecords.CountAsync(record =>
            record.HardwareId == hardwareId
            && record.EventName == "LicenseActivation_Failed"
            && record.Type == TelemetryType.Error
            && record.ErrorData != null));
        var counter = await db.TelemetryFloodSuppressionCounters.SingleAsync(item =>
            item.HardwareId == hardwareId
            && item.EventName == "LicenseActivation_Failed");
        Assert.Equal(1, counter.RawStoredCount);
        Assert.Equal(1, counter.SuppressedCount);
        Assert.Single(await db.TelemetryFloodSuppressionCounters.ToListAsync());
    }

    /// <summary>
    /// Proves that support timeline severity and telemetry error counters consume the relational type
    /// while the timeline continues to read the event-backed correlation and reason properties.
    /// </summary>
    [Fact]
    public async Task TimelineAndAnalytics_ErrorTypedEventData_ShouldRetainSupportContextAndErrorCount()
    {
        var product = await fixture.CreateProductAsync("consumers");
        var hardwareId = NewHardwareId();
        var properties = CreateSupportProperties();
        await fixture.SeedHybridErrorEventAsync(product.Id, product.Name, hardwareId, properties);
        var dbFactory = fixture.CreateDbContextFactory();

        using var cache = new MemoryCache(new MemoryCacheOptions());
        var timelineService = new CustomerLicenseTimelineAnalyticsService(dbFactory, cache);
        var period = TelemetryAnalyticsPeriod.Resolve(days: 7, date: null, fromUtc: null, toUtc: null);
        var timeline = await timelineService.GetTimelineForProductIdAsync(
            product.Id,
            email: null,
            emailFragment: null,
            hardwareId,
            licenseId: null,
            licenseFragment: null,
            period,
            includeAccessLogs: false,
            includeNoise: false,
            importantOnly: true,
            includeProperties: true);

        var item = Assert.Single(
            timeline.Timeline,
            entry => entry.EventName == "LicenseActivation_Failed");
        Assert.Equal("error", item.Severity);
        Assert.Equal(properties["CorrelationId"], item.CorrelationId);
        Assert.Equal(properties["FailureReason"], item.ShortProperties["FailureReason"]);

        var analytics = await new TelemetryAnalyticsService(dbFactory).GetAnalyticsAsync(product.Id, days: 7);
        Assert.Equal(1, analytics.ErrorCount);
        Assert.Equal(0, analytics.EventCount);
        var topError = Assert.Single(
            analytics.TopErrors,
            error => error.ErrorType == "LicenseActivation_Failed");
        Assert.Equal(string.Empty, topError.Message);
        Assert.Equal(1, topError.Count);
    }

    /// <summary>
    /// Locks the four administrative detail views to render event-backed properties for hybrid errors
    /// before falling back to classic error data, without changing either persistence representation.
    /// </summary>
    [Fact]
    public void AdminViews_ErrorTypedEventData_ShouldRenderPropertiesWithoutMaskingClassicErrors()
    {
        var telemetry = ReadRepositoryFile("src/SoftLicence.Server/Components/Pages/Telemetry.razor");
        var products = ReadRepositoryFile("src/SoftLicence.Server/Components/Pages/Products.razor");
        var telemetryDeep = ReadRepositoryFile("src/SoftLicence.Server/Components/Pages/TelemetryDeep.razor");
        var userTelemetry = ReadRepositoryFile("src/SoftLicence.Server/Components/Pages/UserTelemetry.razor");

        AssertHybridErrorPropertiesBranch(telemetry, "SelectedRecord");
        AssertHybridErrorPropertiesBranch(products, "SelectedRecord");
        AssertHybridErrorPropertiesBranch(telemetryDeep, "selectedRecord");
        AssertHybridErrorPropertiesBranch(userTelemetry, "rec");
        Assert.Contains(".Include(r => r.EventData)", telemetryDeep, StringComparison.Ordinal);
        Assert.Contains("rec.ErrorData?.ErrorType ?? rec.EventName", telemetryDeep, StringComparison.Ordinal);
    }

    /// <summary>
    /// Posts one telemetry payload through the public event endpoint and reloads its exact relational
    /// row, including both specialized-data navigation properties.
    /// </summary>
    /// <param name="product">The unique product that authorizes the app name used by the endpoint.</param>
    /// <param name="hardwareId">The unique hardware identifier used to select the inserted row.</param>
    /// <param name="payload">The direct or compatibility request shape under test.</param>
    /// <returns>The single row persisted for the supplied product and hardware identity.</returns>
    private async Task<TelemetryRecord> PostEventAndReadAsync(Product product, string hardwareId, object payload)
    {
        using var client = fixture.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/telemetry/event", payload);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var db = fixture.CreateDb();
        return await db.TelemetryRecords
            .AsNoTracking()
            .Include(record => record.EventData)
            .Include(record => record.ErrorData)
            .SingleAsync(record => record.ProductId == product.Id && record.HardwareId == hardwareId);
    }

    /// <summary>
    /// Asserts exact key/value preservation for the bounded, non-secret activation support metadata.
    /// </summary>
    /// <param name="expected">The metadata submitted by the test producer.</param>
    /// <param name="actualJson">The serialized relational event payload.</param>
    private static void AssertPropertiesEqual(
        IReadOnlyDictionary<string, string> expected,
        string? actualJson)
    {
        Assert.False(string.IsNullOrWhiteSpace(actualJson));
        var actual = JsonSerializer.Deserialize<Dictionary<string, string>>(actualJson!);
        Assert.NotNull(actual);
        Assert.Equal(expected.Count, actual.Count);
        foreach (var property in expected)
            Assert.Equal(property.Value, actual[property.Key]);
    }

    /// <summary>
    /// Creates a non-secret property bag that represents the support fields expected from the desktop
    /// activation flow and deliberately excludes messages, stack traces, keys, and personal data.
    /// </summary>
    /// <returns>A new exact-key dictionary safe to persist in the test database.</returns>
    private static Dictionary<string, string> CreateSupportProperties() => new(StringComparer.Ordinal)
    {
        ["CorrelationId"] = "corr-tkt-001758",
        ["FailureReason"] = "InvalidKey",
        ["ExceptionType"] = "System.ComponentModel.Win32Exception",
        ["NativeErrorCode"] = "5"
    };

    /// <summary>
    /// Creates a canonical uppercase hexadecimal hardware identifier that is unique to one test row.
    /// </summary>
    /// <returns>A 16-character identifier accepted by the telemetry endpoint.</returns>
    private static string NewHardwareId() => Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();

    /// <summary>
    /// Asserts that one Razor source handles hybrid event data first and retains the classic error-data
    /// branch as an explicit fallback.
    /// </summary>
    /// <param name="source">The complete Razor source.</param>
    /// <param name="recordExpression">The component-local telemetry-record expression.</param>
    private static void AssertHybridErrorPropertiesBranch(string source, string recordExpression)
    {
        var eventDataGuard = $"{recordExpression}.EventData != null";
        var errorTypeGuard = $"{recordExpression}.Type == TelemetryType.Error";
        var classicErrorGuard =
            $"else if ({recordExpression}.Type == TelemetryType.Error && {recordExpression}.ErrorData != null)";

        var eventDataIndex = source.IndexOf(eventDataGuard, StringComparison.Ordinal);
        var classicErrorIndex = source.IndexOf(classicErrorGuard, StringComparison.Ordinal);
        Assert.True(eventDataIndex >= 0, $"Missing hybrid EventData guard for {recordExpression}.");
        Assert.Contains(errorTypeGuard, source[eventDataIndex..], StringComparison.Ordinal);
        Assert.True(
            classicErrorIndex > eventDataIndex,
            $"Classic ErrorData fallback must follow hybrid EventData for {recordExpression}.");
    }

    /// <summary>
    /// Reads one repository-owned source file from the test output directory without relying on the
    /// caller's current working directory.
    /// </summary>
    /// <param name="relativePath">A slash-delimited path beneath the repository root.</param>
    /// <returns>The complete source text.</returns>
    private static string ReadRepositoryFile(string relativePath)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (!Directory.Exists(Path.Combine(directory.FullName, "src"))
                || !Directory.Exists(Path.Combine(directory.FullName, "tests")))
            {
                continue;
            }

            return File.ReadAllText(Path.Combine(directory.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        }

        throw new DirectoryNotFoundException("The SoftLicence repository root could not be located.");
    }
}

/// <summary>
/// Owns one migrated PostgreSQL database and one in-process server for the TKT-001758 relational
/// classification tests; the database name is unique and is forcibly dropped during fixture cleanup.
/// </summary>
public sealed class TelemetryActivationFailureClassificationPostgreSqlFixture : IAsyncLifetime
{
    /// <summary>
    /// Holds the container-local maintenance connection used only to create and drop the fixture database.
    /// </summary>
    private string? maintenanceConnectionString;

    /// <summary>
    /// Identifies the unique database owned by this fixture so cleanup cannot target another test run.
    /// </summary>
    private string? databaseName;

    /// <summary>
    /// Hosts the API with every EF registration redirected to the isolated PostgreSQL database.
    /// </summary>
    private WebApplicationFactory<Program>? application;

    /// <summary>
    /// Clones and binds the isolated current-schema PostgreSQL database before any test is allowed to run.
    /// If host creation fails, the partially created database is dropped before the error is propagated.
    /// </summary>
    public async Task InitializeAsync()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("telemetry");
        databaseName = clone.DatabaseName;
        maintenanceConnectionString = clone.MaintenanceConnectionString;
        ConnectionString = clone.ConnectionString;
        try
        {
            application = CreateApplication(ConnectionString);
        }
        catch
        {
            await DropDatabaseAsync(maintenanceConnectionString, databaseName);
            databaseName = null;
            throw;
        }
    }

    /// <summary>
    /// Disposes the in-process server, clears Npgsql pools, and removes only the uniquely named database
    /// created by this fixture, even when a behavioral assertion failed.
    /// </summary>
    public async Task DisposeAsync()
    {
        application?.Dispose();
        if (maintenanceConnectionString is not null && databaseName is not null)
            await DropDatabaseAsync(maintenanceConnectionString, databaseName);
    }

    /// <summary>
    /// Gets the isolated connection string populated before migrations and server creation begin.
    /// </summary>
    public string ConnectionString { get; private set; } = string.Empty;

    /// <summary>
    /// Creates an HTTP client bound to the in-process server and its isolated relational database.
    /// </summary>
    /// <returns>A disposable client whose lifetime is owned by the caller.</returns>
    public HttpClient CreateClient() =>
        (application ?? throw new InvalidOperationException("The PostgreSQL fixture is not initialized."))
        .CreateClient();

    /// <summary>
    /// Creates a direct context over the isolated PostgreSQL database for fixture setup and assertions.
    /// </summary>
    /// <returns>A context whose lifetime is owned by the caller.</returns>
    public LicenseDbContext CreateDb() => new(
        new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(ConnectionString).Options);

    /// <summary>
    /// Creates the provider-backed context factory required by analytics services under test.
    /// </summary>
    /// <returns>A factory that creates independent Npgsql contexts.</returns>
    public IDbContextFactory<LicenseDbContext> CreateDbContextFactory() =>
        new NpgsqlTestDbContextFactory(ConnectionString);

    /// <summary>
    /// Persists one unique product that authorizes a telemetry app name and supplies a private read key.
    /// </summary>
    /// <param name="purpose">A readable test-purpose fragment; it is not used for equality decisions.</param>
    /// <returns>The detached product identity used by the HTTP and consumer assertions.</returns>
    public async Task<Product> CreateProductAsync(string purpose)
    {
        var suffix = Guid.NewGuid().ToString("N");
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = $"Tkt1758-{purpose}-{suffix}",
            PrivateKeyXml = "test-private-key",
            PublicKeyXml = "test-public-key",
            ApiSecret = $"tkt1758-read-{suffix}"
        };

        await using var db = CreateDb();
        db.Products.Add(product);
        await db.SaveChangesAsync();
        db.Entry(product).State = EntityState.Detached;
        return product;
    }

    /// <summary>
    /// Configures a bounded flood-suppression window in the fixture-owned database so repetition
    /// behavior can be proven without depending on machine or deployment configuration.
    /// </summary>
    /// <param name="threshold">The number of matching raw records retained per window.</param>
    /// <param name="windowMinutes">The duration of the suppression window in minutes.</param>
    public async Task ConfigureFloodSuppressionAsync(int threshold, int windowMinutes)
    {
        await using var db = CreateDb();
        var now = DateTime.UtcNow;
        db.SystemSettings.AddRange(
            new SystemSetting
            {
                Key = "TelemetryFloodSuppressionEnabled",
                Value = "true",
                LastUpdated = now
            },
            new SystemSetting
            {
                Key = "TelemetryFloodSuppressionThreshold",
                Value = threshold.ToString(System.Globalization.CultureInfo.InvariantCulture),
                LastUpdated = now
            },
            new SystemSetting
            {
                Key = "TelemetryFloodSuppressionWindowMinutes",
                Value = windowMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture),
                LastUpdated = now
            });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Seeds the durable hybrid shape expected after classification: an error-typed record whose complete
    /// support metadata remains owned by <see cref="TelemetryEvent"/>, not <see cref="TelemetryError"/>.
    /// </summary>
    /// <param name="productId">The owning product identifier.</param>
    /// <param name="appName">The canonical product name.</param>
    /// <param name="hardwareId">The test hardware identifier used by timeline selection.</param>
    /// <param name="properties">The exact safe support metadata to serialize.</param>
    public async Task SeedHybridErrorEventAsync(
        Guid productId,
        string appName,
        string hardwareId,
        IReadOnlyDictionary<string, string> properties)
    {
        await using var db = CreateDb();
        db.TelemetryRecords.Add(new TelemetryRecord
        {
            Id = Guid.NewGuid(),
            ProductId = productId,
            Timestamp = DateTime.UtcNow.AddSeconds(-1),
            HardwareId = hardwareId,
            AppName = appName,
            Version = "2.4.0",
            EventName = "LicenseActivation_Failed",
            Type = TelemetryType.Error,
            EventData = new TelemetryEvent
            {
                PropertiesJson = JsonSerializer.Serialize(properties)
            }
        });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Drops the exact generated database after terminating its remaining test connections.
    /// </summary>
    /// <param name="maintenanceConnection">A connection to the container-local maintenance database.</param>
    /// <param name="name">The generated database identifier, never external input.</param>
    private static async Task DropDatabaseAsync(string maintenanceConnection, string name)
        => await PostgreSqlModelDatabase.DropAsync(maintenanceConnection, name);

    /// <summary>
    /// Builds an integration-test host whose complete EF surface uses the isolated Npgsql database.
    /// </summary>
    /// <param name="connectionString">The fixture-owned database connection string.</param>
    /// <returns>A disposable in-process application factory.</returns>
    private static WebApplicationFactory<Program> CreateApplication(string connectionString) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "tkt1758-admin");
            builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connectionString));
            });
        });

    /// <summary>
    /// Creates independent provider-backed contexts for analytics services without sharing tracked state.
    /// </summary>
    private sealed class NpgsqlTestDbContextFactory(string connectionString)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>
        /// Reuses immutable provider options while returning an independent context for every consumer call.
        /// </summary>
        private readonly DbContextOptions<LicenseDbContext> options =
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options;

        /// <inheritdoc/>
        public LicenseDbContext CreateDbContext() => new(options);

        /// <inheritdoc/>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

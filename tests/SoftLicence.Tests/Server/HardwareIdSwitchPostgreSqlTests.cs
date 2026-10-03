using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001277 lot 2b on PostgreSQL: activation with <c>PreviousHardwareId</c> detaches the held seat and attaches the
/// new identifier in one transaction, consumes the daily seat-change quota, refuses when it is exhausted, and rolls
/// the detachment back when the same activation is refused afterwards.
/// </summary>
public sealed partial class HardwareIdSwitchPostgreSqlTests
{
    private const string AppName = "SwitchApp";
    private const string OldHardwareId = "0123456789ABCDEF";
    private const string Uuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";
    private static readonly string NewHardwareId = MachineIdentity.FromUuid(Uuid).HardwareId!;

    [Fact]
    public async Task Switch_DetachesPrevious_AttachesNew_AndCountsOneSeatChange()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay: 3, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10));

        var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, OldHardwareId));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var seats = await SeatsAsync(provision.ConnectionString);
        Assert.False(seats.Single(seat => seat.HardwareId == OldHardwareId).IsActive);
        Assert.True(seats.Single(seat => seat.HardwareId == NewHardwareId).IsActive);
        await using var db = CreateDb(provision.ConnectionString);
        var license = await db.Licenses.Include(row => row.Type).SingleAsync();
        Assert.Contains(await db.LicenseHistories.Where(row => row.LicenseId == license.Id).ToListAsync(),
            row => row.Action == HistoryActions.UnlinkedApi && row.Details != null && row.Details.Contains("hardware_id_switch", StringComparison.Ordinal));
        Assert.Equal(1, (await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow, default)).UsedToday);
    }

    [Fact]
    public async Task Switch_QuotaExhausted_IsRefused_AndPreviousSeatStaysAttached()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay: 1, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10), releasesToday: 1);

        var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, OldHardwareId));

        Assert.Equal("MAX_DAILY_DEACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        var seats = await SeatsAsync(provision.ConnectionString);
        Assert.True(seats.Single(seat => seat.HardwareId == OldHardwareId).IsActive);
        Assert.DoesNotContain(seats, seat => seat.HardwareId == NewHardwareId);
    }

    [Fact]
    public async Task Switch_RefusedLaterInSameActivation_RollsTheDetachmentBack()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        // Quota allows one change, but the daily activation limit (seats first activated today) is already reached,
        // so the activation is refused after the detachment ran inside the transaction.
        var licenseKey = await SeedAsync(host, maxPerDay: 1, oldSeatActivatedAt: DateTime.UtcNow);

        var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, OldHardwareId));

        Assert.Equal("MAX_DAILY_ACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        var seats = await SeatsAsync(provision.ConnectionString);
        Assert.True(seats.Single(seat => seat.HardwareId == OldHardwareId).IsActive);
        Assert.Null(seats.Single(seat => seat.HardwareId == OldHardwareId).UnlinkedAt);
        Assert.DoesNotContain(seats, seat => seat.HardwareId == NewHardwareId);
        await using var db = CreateDb(provision.ConnectionString);
        Assert.DoesNotContain(await db.LicenseHistories.ToListAsync(), row => row.Action == HistoryActions.UnlinkedApi);
    }

    [Fact]
    public async Task Switch_PreviousNotAnActiveSeat_IsIgnored_AndSeatLimitStillApplies()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay: 3, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10));

        var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, "FEDCBA9876543210"));

        Assert.Equal("SEAT_LIMIT", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        Assert.True((await SeatsAsync(provision.ConnectionString)).Single(seat => seat.HardwareId == OldHardwareId).IsActive);
    }

    [Fact]
    public async Task Switch_NonCanonicalPreviousIdentifier_IsRejectedBeforeAnyChange()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay: 3, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10));

        var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, OldHardwareId.ToLowerInvariant()));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("INVALID_PREVIOUS_HARDWARE_ID", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        Assert.True((await SeatsAsync(provision.ConnectionString)).Single(seat => seat.HardwareId == OldHardwareId).IsActive);
    }

    /// <summary>Version refusals precede UUID seat replacement; a conforming caller still obeys the existing quota.</summary>
    [Theory]
    [InlineData(null, false, "UPDATE_REQUIRED")]
    [InlineData("2.1.357", false, "UPDATE_REQUIRED")]
    [InlineData("99.0-preview", false, "UPDATE_REQUIRED")]
    [InlineData("2.4.300", false, null)]
    [InlineData("2.4.300", true, "MAX_DAILY_DEACTIVATIONS_REACHED")]
    public async Task Tkt1469_UuidSwitch_PreservesSeatAndQuotaUntilVersionEligible(string? version, bool exhausted, string? error)
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay: 1, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10), releasesToday: exhausted ? 1 : 0);
        await using (var db = CreateDb(provision.ConnectionString))
        {
            var product = await db.Products.SingleAsync();
            product.Name = "TIAConnect";
            product.MinimumAllowedVersion = "2.4.300";
            await db.SaveChangesAsync();
        }
        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", new {
            LicenseKey = licenseKey, HardwareId = NewHardwareId, AppName = "TIAConnect",
            SystemUuid = Uuid, PreviousHardwareId = OldHardwareId, AppVersion = version, SdkVersion = "2.0.0"
        });
        var seats = await SeatsAsync(provision.ConnectionString);
        await using var observed = CreateDb(provision.ConnectionString);
        var releases = await observed.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi);
        if (error != null)
        {
            Assert.Equal(error, response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
            Assert.True(seats.Single(seat => seat.HardwareId == OldHardwareId).IsActive);
            Assert.DoesNotContain(seats, seat => seat.HardwareId == NewHardwareId);
            Assert.Equal(exhausted ? 1 : 0, releases);
            Assert.DoesNotContain("licenseFile", await response.Content.ReadAsStringAsync());
        }
        else
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.False(seats.Single(seat => seat.HardwareId == OldHardwareId).IsActive);
            Assert.True(seats.Single(seat => seat.HardwareId == NewHardwareId).IsActive);
            Assert.Equal(1, releases);
            Assert.Contains("licenseFile", await response.Content.ReadAsStringAsync());
        }
    }

    private static object Request(string licenseKey, string previousHardwareId) => new
    {
        LicenseKey = licenseKey,
        HardwareId = NewHardwareId,
        AppName,
        SystemUuid = Uuid,
        PreviousHardwareId = previousHardwareId
    };

    private static async Task<string> SeedAsync(WebApplicationFactory<Program> host, int maxPerDay, DateTime oldSeatActivatedAt, int releasesToday = 0)
    {
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
        var keys = LicenseService.GenerateKeys();
        var product = new Product
        {
            Id = Guid.NewGuid(), Name = AppName, PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
            PublicKeyXml = keys.PublicKey, ApiSecret = "secret"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(), ProductId = product.Id, Name = "Pro", Slug = "PRO", IsFree = false,
            DefaultDurationDays = 365, MaxActivationsPerDay = maxPerDay
        };
        var license = new License
        {
            Id = Guid.NewGuid(), ProductId = product.Id, LicenseTypeId = type.Id,
            LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant(), CustomerName = "Switch User",
            CustomerEmail = "switch@example.com", IsActive = true, MaxSeats = 1, AllowedVersions = "*",
            HardwareId = OldHardwareId, ActivationDate = oldSeatActivatedAt
        };
        db.Products.Add(product);
        db.LicenseTypes.Add(type);
        db.Licenses.Add(license);
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = license.Id, HardwareId = OldHardwareId, IsActive = true,
            FirstActivatedAt = oldSeatActivatedAt, LastCheckInAt = oldSeatActivatedAt
        });
        for (var index = 0; index < releasesToday; index++)
        {
            db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id, Action = HistoryActions.UnlinkedApi,
                Details = "earlier customer release", PerformedBy = "127.0.0.1", Timestamp = DateTime.UtcNow
            });
        }
        await db.SaveChangesAsync();
        return license.LicenseKey;
    }

    private static async Task<List<LicenseSeat>> SeatsAsync(string connectionString)
    {
        await using var db = CreateDb(connectionString);
        return await db.LicenseSeats.AsNoTracking().ToListAsync();
    }

    private static LicenseDbContext CreateDb(string connectionString) =>
        new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

    private static WebApplicationFactory<Program> CreateHost(string connectionString)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !Directory.Exists(Path.Combine(root.FullName, "src", "SoftLicence.Server")))
            root = root.Parent;
        var contentRoot = Path.Combine(root!.FullName, "artifacts", "tkt001277-switch", "web-host");
        Directory.CreateDirectory(contentRoot);
        var factory = new Factory(connectionString);
        var notifier = new Mock<NotificationService>(factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseContentRoot(contentRoot);
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddSingleton<IDbContextFactory<LicenseDbContext>>(factory);
                services.AddScoped(provider => provider.GetRequiredService<IDbContextFactory<LicenseDbContext>>().CreateDbContext());
                services.RemoveAll<NotificationService>();
                services.AddSingleton(notifier.Object);
                services.RemoveAll<IDataProtectionProvider>();
                services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                foreach (var worker in services.Where(descriptor => descriptor.ServiceType == typeof(IHostedService)
                    && descriptor.ImplementationType?.Namespace?.StartsWith("SoftLicence.", StringComparison.Ordinal) == true).ToArray())
                    services.Remove(worker);
            });
        });
    }

    private sealed class Factory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => CreateDb(connectionString);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class Provision(string maintenance, string database) : IAsyncDisposable
    {
        public string ConnectionString { get; private init; } = string.Empty;

        public static async Task<Provision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for PostgreSQL contract tests.");

            var database = "hardware_switch_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            var provision = new Provision(maintenance, database)
            {
                ConnectionString = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString
            };
            try
            {
                await using var db = CreateDb(provision.ConnectionString);
                await db.Database.MigrateAsync();
                return provision;
            }
            catch
            {
                await provision.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenance);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)";
            await command.ExecuteNonQueryAsync();
        }
    }
}

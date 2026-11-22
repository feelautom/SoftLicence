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
/// new identifier in one transaction, and rolls the detachment back when the same activation is refused afterwards.
/// Since TKT-003751 the daily quota counts the distinct hardware identifiers the key was activated on during the UTC
/// day (<see cref="LicenseSeat.LastActivatedAt"/>), never the releases: the switch is refused with
/// <c>MAX_DAILY_ACTIVATIONS_REACHED</c> before anything is detached when N different identifiers were already
/// activated today, N being <see cref="LicenseType.MaxActivationsPerDay"/> x <see cref="License.MaxSeats"/>.
/// </summary>
public sealed partial class HardwareIdSwitchPostgreSqlTests
{
    private const string AppName = "SwitchApp";
    private const string OldHardwareId = "0123456789ABCDEF";
    private const string Uuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";
    private static readonly string NewHardwareId = MachineIdentity.FromUuid(Uuid).HardwareId!;

    /// <summary>
    /// TKT-003751: an accepted switch from A to B the same UTC day releases A and activates B; the day then counts two
    /// distinct identifiers (A, activated today by the seeding, and B), and the release of A adds nothing.
    /// </summary>
    [Fact]
    public async Task Switch_DetachesPrevious_AttachesNew_AndCountsBothIdentifiersActivatedToday()
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
        Assert.Equal(2, (await SeatChangeQuota.GetStatusAsync(db, license, DateTime.UtcNow, default)).UsedToday);
    }

    /// <summary>
    /// TKT-003751: once the key was activated today on N different identifiers (N read from the type, single seat),
    /// a switch to a further identifier is refused with 400 <c>MAX_DAILY_ACTIVATIONS_REACHED</c> before any write:
    /// the previous seat stays attached, no seat is created for the new identifier and no release is journaled.
    /// The previous identifier counts as one of the N (seeded active today), so N - 1 other identifiers are added.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Switch_DailyIdentifierLimitReached_IsRefused_AndPreviousSeatStaysAttached(int maxPerDay)
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10),
            otherIdentifiersActivatedToday: maxPerDay - 1);

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", Request(licenseKey, OldHardwareId));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("MAX_DAILY_ACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        var seats = await SeatsAsync(provision.ConnectionString);
        var previous = seats.Single(seat => seat.HardwareId == OldHardwareId);
        Assert.True(previous.IsActive);
        Assert.Null(previous.UnlinkedAt);
        Assert.DoesNotContain(seats, seat => seat.HardwareId == NewHardwareId);
        await using var db = CreateDb(provision.ConnectionString);
        Assert.DoesNotContain(await db.LicenseHistories.ToListAsync(), row => row.Action == HistoryActions.UnlinkedApi);
    }

    [Fact]
    public async Task Switch_RefusedLaterInSameActivation_RollsTheDetachmentBack()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        // N = 1 and the old seat was itself activated today, so the new identifier would be a second one: since
        // TKT-003751 the switch is refused before detaching, and the previous seat must be left exactly as it was.
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

    /// <summary>
    /// Version refusals precede UUID seat replacement and leave the seat and the quota untouched; a conforming caller
    /// still obeys the daily quota of TKT-003751. With N = 2 and the old identifier counting as one activated today,
    /// the switch fits (accepted, one release journaled), while one other identifier already activated today exhausts
    /// the quota (400 <c>MAX_DAILY_ACTIVATIONS_REACHED</c>, nothing released).
    /// </summary>
    [Theory]
    [InlineData(null, false, "UPDATE_REQUIRED")]
    [InlineData("2.1.357", false, "UPDATE_REQUIRED")]
    [InlineData("99.0-preview", false, "UPDATE_REQUIRED")]
    [InlineData("2.4.300", false, null)]
    [InlineData("2.4.300", true, "MAX_DAILY_ACTIVATIONS_REACHED")]
    public async Task Tkt1469_UuidSwitch_PreservesSeatAndQuotaUntilVersionEligible(string? version, bool exhausted, string? error)
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var licenseKey = await SeedAsync(host, maxPerDay: 2, oldSeatActivatedAt: DateTime.UtcNow.AddDays(-10),
            otherIdentifiersActivatedToday: exhausted ? 1 : 0);
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
            // A refusal (version or quota) writes nothing: no release is journaled.
            Assert.Equal(0, releases);
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

    /// <summary>
    /// Seeds one product, one paid licence type at <paramref name="maxPerDay"/> activations per seat and day, and one
    /// single-seat licence whose active seat is on <see cref="OldHardwareId"/>, first activated at
    /// <paramref name="oldSeatActivatedAt"/>.
    /// </summary>
    /// <remarks>
    /// The old seat is added active without <see cref="LicenseSeat.LastActivatedAt"/>, so the context stamps the
    /// seeding instant (TKT-003751): <see cref="OldHardwareId"/> always counts as one identifier activated today,
    /// whatever <paramref name="oldSeatActivatedAt"/> says. Callers (including the automatic seat switch partial)
    /// rely on that count. <paramref name="otherIdentifiersActivatedToday"/> released seats on distinct synthetic
    /// identifiers, activated today, add to it; the quota counts only seat activations, so history rows cannot.
    /// </remarks>
    /// <param name="host">Test host whose scoped context and encryption service write the rows.</param>
    /// <param name="maxPerDay">Value of <see cref="LicenseType.MaxActivationsPerDay"/>; zero means unlimited.</param>
    /// <param name="oldSeatActivatedAt">UTC instant of the old seat's first activation and last check-in.</param>
    /// <param name="otherIdentifiersActivatedToday">Number of released seats activated today on other identifiers.</param>
    /// <returns>The licence key to activate.</returns>
    private static async Task<string> SeedAsync(WebApplicationFactory<Program> host, int maxPerDay, DateTime oldSeatActivatedAt, int otherIdentifiersActivatedToday = 0)
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
        AddSeatsActivatedToday(db, license.Id, otherIdentifiersActivatedToday);
        await db.SaveChangesAsync();
        return license.LicenseKey;
    }

    /// <summary>
    /// Adds <paramref name="count"/> released seats of the licence, each on a distinct synthetic canonical identifier
    /// (<c>D</c> followed by 15 digits, never equal to <see cref="OldHardwareId"/> or a UUID-derived identifier),
    /// activated and released today, so the TKT-003751 quota counts exactly <paramref name="count"/> identifiers.
    /// </summary>
    /// <remarks>
    /// The seats are inactive, so they take no seat capacity; their explicit <see cref="LicenseSeat.LastActivatedAt"/>
    /// is kept by the context. Whichever seat ends up as the licence's last activated PC (an active seat stamped at
    /// save time, or one of these), it is never an identifier requested by these tests, so the last-PC exception of
    /// <see cref="SeatChangeQuota.IsActivationRefusedAsync"/> never hides a refusal. Nothing is saved here; the caller saves.
    /// </remarks>
    /// <param name="db">Context tracking the new rows.</param>
    /// <param name="licenseId">Licence owning the seats.</param>
    /// <param name="count">Number of distinct identifiers to seed; zero adds nothing.</param>
    private static void AddSeatsActivatedToday(LicenseDbContext db, Guid licenseId, int count)
    {
        var today = DateTime.UtcNow;
        for (var index = 0; index < count; index++)
        {
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = licenseId, HardwareId = $"D{index:D15}", IsActive = false,
                FirstActivatedAt = today, LastActivatedAt = today, LastCheckInAt = today, UnlinkedAt = today
            });
        }
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
            var clone = await PostgreSqlModelDatabase.CloneAsync("hardware_switch");
            return new Provision(clone.MaintenanceConnectionString, clone.DatabaseName)
            {
                ConnectionString = clone.ConnectionString
            };
        }

        public async ValueTask DisposeAsync()
            => await PostgreSqlModelDatabase.DropAsync(maintenance, database);
    }
}

using System.Net;
using Microsoft.AspNetCore.Builder;
using System.Net.Http.Json;
using System.Text.Json;
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
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class CloneGuardPostgreSqlTests
{
    /// <summary>Admin secret of the test host only; never a real credential.</summary>
    internal const string AdminSecret = "tkt003615-test-only";

    /// <summary>Parsed answer of a check or reactivation.</summary>
    /// <param name="HttpStatus">HTTP status code.</param>
    /// <param name="Root">Raw JSON root, for asserting the absence of members.</param>
    internal sealed record Answer(HttpStatusCode HttpStatus, JsonElement Root)
    {
        /// <summary>Gets the logical status.</summary>
        public string? Status => Text(Root, "status");
        /// <summary>Gets the licence file, or <see langword="null"/>.</summary>
        public string? LicenseFile => Text(Root, "licenseFile");
        /// <summary>Gets the error message, or <see langword="null"/>.</summary>
        public string? ErrorMessage => Text(Root, "errorMessage");
        /// <summary>Gets the clone guard outcome, or <see langword="null"/> when the member is absent.</summary>
        public string? Outcome => Guard is { } guard ? Text(guard, "outcome") : null;
        /// <summary>Gets the clone guard reason, or <see langword="null"/>.</summary>
        public string? Reason => Guard is { } guard ? Text(guard, "reason") : null;
        /// <summary>Gets whether the server reported a changed VM Generation ID.</summary>
        public bool EnvironmentChanged => Guard is { } guard && guard.GetProperty("environmentChanged").GetBoolean();
        /// <summary>Gets the <c>cloneGuard</c> object of the answer, or <see langword="null"/> when absent or not an object.</summary>
        private JsonElement? Guard => Root.TryGetProperty("cloneGuard", out var guard) && guard.ValueKind == JsonValueKind.Object ? guard : null;
        /// <summary>Reads a string member, or <see langword="null"/> when the member is absent or not a string (JSON null included).</summary>
        private static string? Text(JsonElement element, string name) =>
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    /// <summary>
    /// Per-test bench: one cloned PostgreSQL database, one in-process server host on it with background workers removed,
    /// a mocked notifier counting <c>Security.CloneSuspected</c> calls, and helpers to seed and observe rows. Disposal
    /// stops the host and drops the database.
    /// </summary>
    internal sealed class Bench : IAsyncDisposable
    {
        /// <summary>Cloned database owned by this bench; dropped by <see cref="DisposeAsync"/>.</summary>
        private readonly PostgreSqlDatabaseClone _clone;

        /// <summary>In-process server bound to <see cref="_clone"/>; disposed before the database is dropped.</summary>
        private readonly WebApplicationFactory<Program> _host;

        /// <summary>Notifier mock registered in the host; its callback updates the two alert counters.</summary>
        private readonly Mock<NotificationService> _notifier;

        /// <summary>Repetition and other-network alerts; written with <see cref="Interlocked"/> from request threads, read with <see cref="Volatile"/>.</summary>
        private int _cloneAlerts;

        /// <summary>Quota-limit alerts; same synchronisation as <see cref="_cloneAlerts"/>.</summary>
        private int _limitAlerts;

        /// <summary>Gets the number of quota-limit <c>Security.CloneSuspected</c> notifications sent so far (thread-safe).</summary>
        public int LimitAlerts() => Volatile.Read(ref _limitAlerts);

        /// <summary>Captures the owned clone, host, notifier mock and client; only <see cref="CreateAsync"/> builds a bench.</summary>
        private Bench(PostgreSqlDatabaseClone clone, WebApplicationFactory<Program> host, Mock<NotificationService> notifier, HttpClient client)
        {
            _clone = clone;
            _host = host;
            _notifier = notifier;
            Client = client;
        }

        /// <summary>Gets the HTTP client of the in-process server.</summary>
        public HttpClient Client { get; }

        /// <summary>
        /// Gets the key of the licence created by <see cref="SeedAsync"/>. Helpers select that licence by key because
        /// some scenarios add other licences of the same product (single-use history), which a bare SingleAsync would
        /// reject.
        /// </summary>
        public string SeededLicenseKey { get; private set; } = string.Empty;

        /// <summary>Gets the connection string of the cloned database.</summary>
        public string ConnectionString => _clone.ConnectionString;

        /// <summary>Gets the number of repetition or other-network <c>Security.CloneSuspected</c> notifications sent so far (thread-safe).</summary>
        public int CloneAlerts => Volatile.Read(ref _cloneAlerts);

        /// <summary>Creates the database clone and the host; the caller disposes the bench.</summary>
        public static async Task<Bench> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("clone_guard");
            Bench? bench = null;
            var factory = new ContextFactory(clone.ConnectionString);
            var notifier = new Mock<NotificationService>(factory, Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
            notifier.Setup(service => service.Notify(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()))
                .Callback<string, string, string, object?>((trigger, _, message, _) =>
                {
                    if (trigger != NotificationService.Triggers.SecurityCloneSuspected)
                        return;
                    // The limit alert and the repetition alert share the trigger; the cause line tells them apart.
                    if (message.Contains("quota journalier", StringComparison.Ordinal))
                        Interlocked.Increment(ref bench!._limitAlerts);
                    else
                        Interlocked.Increment(ref bench!._cloneAlerts);
                });
            var root = new DirectoryInfo(AppContext.BaseDirectory);
            while (root != null && !Directory.Exists(Path.Combine(root.FullName, "src", "SoftLicence.Server")))
                root = root.Parent;
            var contentRoot = Path.Combine(root!.FullName, "artifacts", "tkt003615-clone-guard", "web-host");
            Directory.CreateDirectory(contentRoot);
            var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseContentRoot(contentRoot);
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", AdminSecret);
                builder.UseSetting("AdminSettings:AllowedIps", "");
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
                    services.AddSingleton<IStartupFilter>(new RemoteAddressStartupFilter());
                    foreach (var worker in services.Where(descriptor => descriptor.ServiceType == typeof(IHostedService)
                        && descriptor.ImplementationType?.Namespace?.StartsWith("SoftLicence.", StringComparison.Ordinal) == true).ToArray())
                        services.Remove(worker);
                });
            });
            bench = new Bench(clone, host, notifier, host.CreateClient());
            return bench;
        }

        /// <summary>Opens a fresh context on the cloned database (caller disposes).</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(ConnectionString).Options);

        /// <summary>
        /// Seeds one product, one paid type at <paramref name="perSeat"/> changes per seat and day, and one licence of
        /// <paramref name="seats"/> seats with an active seat on each identifier. Seats are stamped as activated
        /// <b>yesterday</b>, so they use no unit of today's quota: each test sets today's usage explicitly.
        /// </summary>
        /// <returns>The licence key.</returns>
        public async Task<string> SeedAsync(int perSeat, int seats, params string[] hardwareIds)
        {
            using var scope = _host.Services.CreateScope();
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
                DefaultDurationDays = 365, MaxActivationsPerDay = perSeat
            };
            var license = new License
            {
                Id = Guid.NewGuid(), ProductId = product.Id, LicenseTypeId = type.Id,
                LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant(), CustomerName = "Clone Guard",
                CustomerEmail = "clone-guard@example.com", IsActive = true, MaxSeats = seats, AllowedVersions = "*",
                ActivationDate = DateTime.UtcNow.AddDays(-30)
            };
            db.Products.Add(product);
            db.LicenseTypes.Add(type);
            db.Licenses.Add(license);
            var yesterday = DateTime.UtcNow.AddDays(-1);
            foreach (var hardwareId in hardwareIds)
                db.LicenseSeats.Add(new LicenseSeat
                {
                    LicenseId = license.Id, HardwareId = hardwareId, IsActive = true,
                    FirstActivatedAt = yesterday, LastCheckInAt = yesterday, LastActivatedAt = yesterday
                });
            await db.SaveChangesAsync();
            SeededLicenseKey = license.LicenseKey;
            return license.LicenseKey;
        }

        /// <summary>
        /// Adds <paramref name="count"/> released seats on distinct synthetic identifiers activated today, consuming that
        /// many units of today's quota through the existing machine-change term.
        /// </summary>
        public async Task UseMachineChangesTodayAsync(int count)
        {
            await using var db = Db();
            var license = await db.Licenses.SingleAsync(row => row.LicenseKey == SeededLicenseKey);
            var now = DateTime.UtcNow;
            for (var index = 0; index < count; index++)
                db.LicenseSeats.Add(new LicenseSeat
                {
                    LicenseId = license.Id, HardwareId = $"D{index:D15}", IsActive = false,
                    FirstActivatedAt = now, LastActivatedAt = now, LastCheckInAt = now, UnlinkedAt = now
                });
            await db.SaveChangesAsync();
        }

        /// <summary>
        /// Posts a check, with or without a <c>cloneGuard</c> member, and parses the answer.
        /// </summary>
        /// <param name="from">Transport address to simulate, or <see langword="null"/> for the default private address.</param>
        public async Task<Answer> CheckAsync(string key, string hardwareId, object? guard, string? from = null)
        {
            object body = guard == null
                ? new { LicenseKey = key, HardwareId = hardwareId, AppName }
                : new { LicenseKey = key, HardwareId = hardwareId, AppName, CloneGuard = guard };
            return await PostAsync("/api/activation/check", body, from);
        }

        /// <summary>Posts a guided reactivation and parses the answer.</summary>
        public Task<Answer> ReactivateAsync(string key, string hardwareId, string nextToken, string? vmGenerationId = null) =>
            PostAsync("/api/activation/clone-guard/reactivate",
                new { LicenseKey = key, HardwareId = hardwareId, AppName, NextToken = nextToken, VmGenerationId = vmGenerationId });

        /// <summary>Posts JSON, optionally from a simulated address, and parses the body; a non-JSON body fails the test with its text.</summary>
        private async Task<Answer> PostAsync(string path, object body, string? from = null)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
            if (from != null)
                request.Headers.Add(RemoteAddressHeader, from);
            using var response = await Client.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            try
            {
                using var document = JsonDocument.Parse(text);
                return new Answer(response.StatusCode, document.RootElement.Clone());
            }
            catch (JsonException)
            {
                throw new Xunit.Sdk.XunitException($"{path} answered {(int)response.StatusCode} with a non-JSON body: {text}");
            }
        }

        /// <summary>Counts the rows of one table.</summary>
        public async Task<int> CountAsync<T>() where T : class
        {
            await using var db = Db();
            return await db.Set<T>().CountAsync();
        }

        /// <summary>Reads the single guard row.</summary>
        public async Task<SeatCloneGuard> SingleGuardAsync()
        {
            await using var db = Db();
            return await db.SeatCloneGuards.AsNoTracking().SingleAsync();
        }

        /// <summary>Lists journal kinds in insertion order of their instant.</summary>
        public async Task<List<string>> EventKindsAsync()
        {
            await using var db = Db();
            return await db.SeatCloneGuardEvents.AsNoTracking().OrderBy(row => row.OccurredAt).Select(row => row.Kind).ToListAsync();
        }

        /// <summary>Lists the journal rows of one kind.</summary>
        public async Task<List<SeatCloneGuardEvent>> EventsAsync(string kind)
        {
            await using var db = Db();
            return await db.SeatCloneGuardEvents.AsNoTracking().Where(row => row.Kind == kind).ToListAsync();
        }

        /// <summary>Sets the licence active flag (false answers REVOKED).</summary>
        public async Task SetLicenseActiveAsync(bool active)
        {
            await using var db = Db();
            var license = await db.Licenses.SingleAsync(row => row.LicenseKey == SeededLicenseKey);
            license.IsActive = active;
            await db.SaveChangesAsync();
        }

        /// <summary>
        /// Moves the last accepted check of the single guard into the past, as if the copy holding the current token had
        /// stopped beating <paramref name="ago"/> ago.
        /// </summary>
        public async Task AgeHolderAsync(TimeSpan ago)
        {
            await using var db = Db();
            var guard = await db.SeatCloneGuards.SingleAsync();
            guard.LastAcceptedAt = DateTime.UtcNow - ago;
            await db.SaveChangesAsync();
        }

        /// <summary>Changes the licence seat count in the middle of the day (administrator change).</summary>
        public async Task SetMaxSeatsAsync(int seats)
        {
            await using var db = Db();
            var license = await db.Licenses.SingleAsync(row => row.LicenseKey == SeededLicenseKey);
            license.MaxSeats = seats;
            await db.SaveChangesAsync();
        }

        /// <summary>Releases then re-activates the seat of an identifier in two saves, like a sign-out then sign-in.</summary>
        public async Task ReleaseAndReactivateSeatAsync(string hardwareId)
        {
            await using (var db = Db())
            {
                var seat = await db.LicenseSeats.SingleAsync(row => row.HardwareId == hardwareId);
                seat.IsActive = false;
                seat.UnlinkedAt = DateTime.UtcNow;
                await db.SaveChangesAsync();
            }
            await using (var db = Db())
            {
                var seat = await db.LicenseSeats.SingleAsync(row => row.HardwareId == hardwareId);
                seat.IsActive = true;
                seat.UnlinkedAt = null;
                await db.SaveChangesAsync();
            }
        }

        /// <summary>Moves a seat in place to another identifier, as the hardware-authority migration does (TKT-003614).</summary>
        public async Task MoveSeatAsync(string from, string to)
        {
            await using var db = Db();
            var seat = await db.LicenseSeats.SingleAsync(row => row.HardwareId == from);
            seat.HardwareId = to;
            await db.SaveChangesAsync();
        }

        /// <summary>Asserts that no ban, no threat score and no seat release resulted from the clone guard.</summary>
        public async Task AssertNoSanctionAsync()
        {
            await using var db = Db();
            Assert.Equal(0, await db.BannedHardwareIds.CountAsync());
            Assert.Equal(0, await db.BannedIps.CountAsync());
            Assert.Equal(0, await db.IpThreatScores.CountAsync(row => row.Score > 0));
            Assert.True(await db.Licenses.AllAsync(row => row.IsActive && row.RevokedAt == null));
            Assert.Equal(0, await db.LicenseSeats.CountAsync(row => !row.IsActive && !row.HardwareId.StartsWith("D")));
        }

        /// <summary>Stops the host and drops the cloned database.</summary>
        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _host.DisposeAsync();
            await PostgreSqlModelDatabase.DropAsync(_clone.MaintenanceConnectionString, _clone.DatabaseName);
        }
    }

    /// <summary>Test-only header naming the transport address the next request comes from.</summary>
    internal const string RemoteAddressHeader = "X-Test-Remote-Address";

    /// <summary>
    /// Gives every in-process request a transport address, which TestServer leaves null: the value of
    /// <see cref="RemoteAddressHeader"/> when present, otherwise a private address. A private address keeps the
    /// production rule that exempts private networks from the <c>PublicAPI</c> limiter (10 requests per minute),
    /// which the quota tests exceed on purpose; the header lets the alert tests simulate another network. Runs first in
    /// the pipeline, before forwarded headers, rate limiting and the controllers.
    /// </summary>
    private sealed class RemoteAddressStartupFilter : IStartupFilter
    {
        /// <summary>Prepends the address-setting middleware to the application pipeline.</summary>
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, following) =>
            {
                context.Connection.RemoteIpAddress =
                    context.Request.Headers.TryGetValue(RemoteAddressHeader, out var value) && IPAddress.TryParse(value.ToString(), out var address)
                        ? address
                        : IPAddress.Parse("10.36.15.1");
                await following();
            });
            next(app);
        };
    }

    /// <summary>Context factory bound to the cloned database, used by the host and the mocked notifier.</summary>
    private sealed class ContextFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Creates a context on the clone.</summary>
        public LicenseDbContext CreateDbContext() =>
            new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);
    }
}

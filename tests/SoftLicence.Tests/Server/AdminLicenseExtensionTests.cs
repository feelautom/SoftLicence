using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.JSInterop;
using Moq;
using Npgsql;
using SoftLicence.Server.Components.Shared;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises real PostgreSQL transactions and the actual Razor confirmation handlers using synthetic identities only.</summary>
[Trait("Category", "RequiresPostgreSql")]
public sealed class AdminLicenseExtensionTests(AdminExtensionDatabase database) : IClassFixture<AdminExtensionDatabase>
{
    /// <summary>UTC anchor crossing the autumn Paris DST transition when one day is added.</summary>
    private static readonly DateTime Now = new(2026, 10, 24, 12, 34, 56, DateTimeKind.Utc);
    /// <summary>Synthetic permission and exact opaque identity shared only by these local tests.</summary>
    private static readonly ClaimsPrincipal Admin = new(new ClaimsIdentity([
        new Claim(ClaimTypes.NameIdentifier, "admin-1480"), new Claim(ClaimTypes.Name, "Synthetic operator"),
        new Claim("Permissions", "licenses.view")], "test"));

    /// <summary>Only bounded ASCII integers are admitted; culture-specific digits, signs and separators are rejected.</summary>
    [Theory]
    [InlineData(null, false)] [InlineData("", false)] [InlineData("0", false)] [InlineData("-1", false)]
    [InlineData("1.5", false)] [InlineData("1,5", false)] [InlineData("+1", false)] [InlineData(" 1", false)]
    [InlineData("1 ", false)] [InlineData("１", false)] [InlineData("١", false)] [InlineData("3651", false)]
    [InlineData("999999999999", false)] [InlineData("1", true)] [InlineData("30", true)] [InlineData("3650", true)]
    public void DaysInput_HasExplicitAsciiContract(string? input, bool accepted) =>
        Assert.Equal(accepted, AdminLicenseExtensionService.TryParseDays(input, out _));

    /// <summary>Valid licences retain every remaining second; expired licences restart at confirmation, independent of DST.</summary>
    [Theory]
    [InlineData(false, -10, 1)] [InlineData(true, -10, 30)] [InlineData(true, 0, 1)]
    [InlineData(false, 180, 2)] [InlineData(true, 180, 1)] [InlineData(true, 1, 30)]
    [InlineData(false, -1, 3650)]
    public async Task Confirm_PreservesRemainingTimeAndSynchronizesPass(bool pass, int oldOffset, int days)
    {
        var license = await SeedAsync(Now.AddDays(oldOffset), pass);
        var command = new AdminLicenseExtensionService.Command(Guid.NewGuid(), license.Id, license.AuthorityVersion, days);
        var service = new AdminLicenseExtensionService(database, new FrozenClock(Now));
        var result = await service.ConfirmAsync(command, Admin);
        Assert.Equal("Applied", result.Code);
        var expectedBase = oldOffset > 0 ? license.ExpirationDate!.Value : Now;
        Assert.Equal(expectedBase.AddSeconds(days * 86400), result.ExpirationUtc);
        await using var db = database.CreateDbContext();
        var persisted = await db.Licenses.SingleAsync(l => l.Id == license.Id);
        Assert.Equal(result.ExpirationUtc, persisted.ExpirationDate);
        Assert.NotEqual(license.AuthorityVersion, persisted.AuthorityVersion);
        var audit = Assert.Single(await db.LicenseHistories.Where(h => h.LicenseId == license.Id).ToListAsync());
        var receipt = JsonSerializer.Deserialize<AdminLicenseExtensionService.Receipt>(audit.Details!)!;
        Assert.Equal(Now, receipt.ConfirmedAtUtc);
        Assert.Equal(license.ExpirationDate, receipt.OldExpirationUtc);
        Assert.Equal("admin-1480", receipt.ActorId);
        Assert.Equal("Synthetic operator", audit.PerformedBy);
        if (pass) Assert.Equal(result.ExpirationUtc, (await db.PersonalDayPasses.SingleAsync(p => p.LicenseId == license.Id)).PaidThroughUtc);
    }

    /// <summary>Concurrent exact replays create one audit and one 24-hour grant, even after the clock changes.</summary>
    [Theory]
    [InlineData(-1)] [InlineData(180)]
    public async Task ConcurrentReplay_IsOneGrantAndDivergentReplayIsRejected(int oldOffset)
    {
        var license = await SeedAsync(Now.AddDays(oldOffset), true);
        var expected = Now.AddDays(Math.Max(oldOffset, 0) + 1);
        var command = new AdminLicenseExtensionService.Command(Guid.NewGuid(), license.Id, license.AuthorityVersion, 1);
        var service = new AdminLicenseExtensionService(database, new FrozenClock(Now));
        var results = await Task.WhenAll(service.ConfirmAsync(command, Admin), service.ConfirmAsync(command, Admin));
        Assert.All(results, r => Assert.Equal(expected, r.ExpirationUtc));
        Assert.Single(results, r => !r.Replayed);
        Assert.Single(results, r => r.Replayed);
        var later = new AdminLicenseExtensionService(database, new FrozenClock(Now.AddHours(3)));
        Assert.Equal(expected, (await later.ConfirmAsync(command, Admin)).ExpirationUtc);
        Assert.Equal("Conflict", (await later.ConfirmAsync(command with { Days = 2 }, Admin)).Code);
        Assert.Equal("Conflict", (await later.ConfirmAsync(command with { LicenseId = Guid.NewGuid() }, Admin)).Code);
        var other = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "ADMIN-1480"),
            new Claim("Permissions", "licenses.view")], "test"));
        Assert.Equal("Conflict", (await later.ConfirmAsync(command, other)).Code);
        await using var db = database.CreateDbContext();
        Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == license.Id));
    }

    /// <summary>The reported March expiry gains two exact days, independent of the earlier confirmation date.</summary>
    [Fact]
    public async Task ActiveMarchExpiry_AddsTwoDaysIntoApril()
    {
        var expiry = new DateTime(2027, 3, 30, 5, 58, 5, DateTimeKind.Utc);
        var license = await SeedAsync(expiry, false);
        var command = new AdminLicenseExtensionService.Command(Guid.NewGuid(), license.Id, license.AuthorityVersion, 2);
        var result = await new AdminLicenseExtensionService(database, new FrozenClock(Now)).ConfirmAsync(command, Admin);
        Assert.Equal("Applied", result.Code);
        Assert.Equal(new DateTime(2027, 4, 1, 5, 58, 5, DateTimeKind.Utc), result.ExpirationUtc);
    }

    /// <summary>Previously persisted receipts remain authoritative after the calculation rule changes.</summary>
    [Fact]
    public async Task PreviousReceipt_ReplaysStoredResultWithoutAddingTime()
    {
        var license = await SeedAsync(Now.AddDays(30), true);
        var command = new AdminLicenseExtensionService.Command(Guid.NewGuid(), license.Id, Guid.NewGuid(), 30);
        await using var db = database.CreateDbContext();
        db.LicenseHistories.Add(new LicenseHistory
        {
            Id = command.OperationId, LicenseId = license.Id, Timestamp = Now,
            Action = AdminLicenseExtensionService.HistoryAction, PerformedBy = "Synthetic operator",
            Details = JsonSerializer.Serialize(new AdminLicenseExtensionService.Receipt(1,
                command.ExpectedAuthorityVersion, 30, "admin-1480", Now, Now.AddDays(1), Now.AddDays(30)))
        });
        await db.SaveChangesAsync();
        var result = await new AdminLicenseExtensionService(database, new FrozenClock(Now.AddHours(2))).ConfirmAsync(command, Admin);
        Assert.True(result.Replayed);
        Assert.Equal(Now.AddDays(30), result.ExpirationUtc);
        Assert.Equal(license.ExpirationDate, (await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == license.Id)).ExpirationDate);
        Assert.Single(await db.LicenseHistories.Where(h => h.LicenseId == license.Id).ToListAsync());
    }

    /// <summary>Two independent confirmations of one version cannot overwrite each other.</summary>
    [Fact]
    public async Task ConcurrentDifferentOperations_RejectStalePreview()
    {
        var license = await SeedAsync(Now.AddDays(-1), true);
        var service = new AdminLicenseExtensionService(database, new FrozenClock(Now));
        var command = new AdminLicenseExtensionService.Command(Guid.NewGuid(), license.Id, license.AuthorityVersion, 1);
        var results = await Task.WhenAll(service.ConfirmAsync(command, Admin),
            service.ConfirmAsync(command with { OperationId = Guid.NewGuid(), Days = 2 }, Admin));
        Assert.Single(results, r => r.Code == "Applied");
        Assert.Single(results, r => r.Code == "Conflict");
    }

    /// <summary>A failed audit insert must roll back both rights surfaces, not leave an unaudited grant.</summary>
    [Fact]
    public async Task AuditFailure_RollsBackLicenseAndPass()
    {
        var license = await SeedAsync(Now.AddDays(-1), true);
        var operation = Guid.NewGuid();
        await using var db = database.CreateDbContext();
        // NOT VALID preserves earlier fixture evidence. This isolated, serial test class owns the constraint.
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"LicenseHistories\" ADD CONSTRAINT tkt1480_fault CHECK (\"Action\" <> 'ADMIN_EXTENSION_V1') NOT VALID");
        try
        {
            var command = new AdminLicenseExtensionService.Command(operation, license.Id, license.AuthorityVersion, 1);
            await Assert.ThrowsAsync<DbUpdateException>(() => new AdminLicenseExtensionService(database, new FrozenClock(Now)).ConfirmAsync(command, Admin));
            Assert.Equal(license.ExpirationDate, (await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == license.Id)).ExpirationDate);
            Assert.Equal(license.ExpirationDate, (await db.PersonalDayPasses.AsNoTracking().SingleAsync(p => p.LicenseId == license.Id)).PaidThroughUtc);
            Assert.Empty(await db.LicenseHistories.Where(h => h.LicenseId == license.Id).ToListAsync());
        }
        finally { await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"LicenseHistories\" DROP CONSTRAINT tkt1480_fault"); }
    }

    /// <summary>Every business refusal preserves expiry, pass horizon and history.</summary>
    [Theory]
    [InlineData("overflow", "ExpirationOutOfRange")] [InlineData("revoked", "Ineligible")]
    [InlineData("deferred", "Ineligible")] [InlineData("mismatch", "InconsistentPass")]
    [InlineData("stale", "Conflict")] [InlineData("anonymous", "Unauthorized")]
    [InlineData("zero", "InvalidDays")] [InlineData("negative", "InvalidDays")] [InlineData("over", "InvalidDays")]
    public async Task Refusal_DoesNotWrite(string scenario, string expected)
    {
        var license = await SeedAsync(scenario == "overflow" ? DateTime.SpecifyKind(DateTime.MaxValue.AddHours(-1), DateTimeKind.Utc) : Now.AddDays(-1), true);
        await using (var setup = database.CreateDbContext())
        {
            var row = await setup.Licenses.SingleAsync(l => l.Id == license.Id);
            if (scenario == "revoked") row.RevokedAt = Now;
            if (scenario == "deferred") row.ExpirationDate = null;
            if (scenario == "mismatch") (await setup.PersonalDayPasses.SingleAsync(p => p.LicenseId == license.Id)).PaidThroughUtc = Now;
            await setup.SaveChangesAsync();
            await setup.Entry(row).ReloadAsync();
            license = row;
        }
        var days = scenario switch { "zero" => 0, "negative" => -1, "over" => 3651, _ => 1 };
        var command = new AdminLicenseExtensionService.Command(Guid.NewGuid(), license.Id,
            scenario == "stale" ? Guid.NewGuid() : license.AuthorityVersion, days);
        var result = await new AdminLicenseExtensionService(database, new FrozenClock(Now))
            .ConfirmAsync(command, scenario == "anonymous" ? new ClaimsPrincipal() : Admin);
        Assert.Equal(expected, result.Code);
        await using var verify = database.CreateDbContext();
        Assert.Equal(license.ExpirationDate, (await verify.Licenses.SingleAsync(l => l.Id == license.Id)).ExpirationDate);
        Assert.Empty(await verify.LicenseHistories.Where(h => h.LicenseId == license.Id).ToListAsync());
    }

    /// <summary>Actual Razor handlers cannot persist before review and confirmation; cancellation is read-only.</summary>
    [Theory]
    [InlineData(-2)] [InlineData(180)]
    public async Task Dialog_RequiresReviewThenConfirmation_AndCancelDoesNotWrite(int oldOffset)
    {
        var license = await SeedAsync(DateTime.UtcNow.AddDays(oldOffset), true);
        var activator = new CaptureActivator();
        var services = new ServiceCollection();
        services.AddLogging(); services.AddLocalization(); services.AddSingleton<TimeZoneService>();
        services.AddSingleton<IDbContextFactory<LicenseDbContext>>(database);
        services.AddSingleton(new AuthService(new TestAuthentication()));
        services.AddSingleton<IComponentActivator>(activator);
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        var canceled = 0; var applied = 0;
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var root = await renderer.RenderComponentAsync<LicenseExtensionDialog>(ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                ["License"] = license,
                ["Canceled"] = EventCallback.Factory.Create(this, () => canceled++),
                ["Applied"] = EventCallback.Factory.Create(this, () => applied++)
            }));
            var component = activator.Instance!;
            Assert.DoesNotContain("type=\"date\"", root.ToHtmlString());
            await InvokeAsync(component, "ConfirmAsync");
            Assert.Equal(0, applied);
            Set(component, "daysText", "-1"); await InvokeAsync(component, "Prepare");
            await InvokeAsync(component, "ConfirmAsync"); Assert.Equal(0, applied);
            Set(component, "daysText", "1"); await InvokeAsync(component, "Prepare");
            if (oldOffset > 0)
                Assert.Equal(license.ExpirationDate!.Value.AddDays(1),
                    component.GetType().GetField("previewUtc", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(component));
            typeof(ComponentBase).GetMethod("StateHasChanged", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(component, null);
            Assert.Contains("<div class=\"alert alert-info\">", root.ToHtmlString());
            await using (var check = database.CreateDbContext())
                Assert.Empty(await check.LicenseHistories.Where(h => h.LicenseId == license.Id).ToListAsync());
            await InvokeAsync(component, "CancelAsync"); Assert.Equal(1, canceled);
            await InvokeAsync(component, "ConfirmAsync"); Assert.Equal(0, applied);
            // Cancellation removes this component in the real parent. Render a fresh instance to confirm.
            var next = await renderer.RenderComponentAsync<LicenseExtensionDialog>(ParameterView.FromDictionary(new Dictionary<string, object?>
            { ["License"] = license, ["Applied"] = EventCallback.Factory.Create(this, () => applied++) }));
            component = activator.Instance!;
            Set(component, "daysText", "1"); await InvokeAsync(component, "Prepare");
            var before = DateTime.UtcNow;
            await InvokeAsync(component, "ConfirmAsync"); await InvokeAsync(component, "ConfirmAsync");
            Assert.True(applied == 1, "Dialog outcome: " + component.GetType().GetField("errorKey", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(component));
            await using var checkFinal = database.CreateDbContext();
            var audit = Assert.Single(await checkFinal.LicenseHistories.Where(h => h.LicenseId == license.Id).ToListAsync());
            var receipt = JsonSerializer.Deserialize<AdminLicenseExtensionService.Receipt>(audit.Details!)!;
            Assert.InRange(receipt.ConfirmedAtUtc, before.AddMilliseconds(-1), DateTime.UtcNow);
            Assert.Equal(TimeSpan.FromHours(24), receipt.NewExpirationUtc -
                (oldOffset > 0 ? license.ExpirationDate!.Value : receipt.ConfirmedAtUtc));
        });
    }

    /// <summary>Renders the full page, proving expired rows have one action and opening one row yields one dialog.</summary>
    [Fact]
    public async Task Page_ExpiredRowsHaveOneExtensionAction_AndOneDialog()
    {
        await SeedAsync(DateTime.UtcNow.AddDays(-1), true);
        var activator = new CaptureActivator();
        var services = new ServiceCollection();
        services.AddLogging(); services.AddLocalization(); services.AddOptions(); services.AddHttpClient();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.AddSingleton<TimeZoneService>(); services.AddSingleton<ToastService>(); services.AddSingleton<EmailService>();
        services.AddSingleton<NotificationService>(); services.AddSingleton<SecurityService>();
        services.AddSingleton<NavigationManager, TestNavigation>();
        services.AddSingleton<IJSRuntime>(Mock.Of<IJSRuntime>());
        services.AddSingleton<IDbContextFactory<LicenseDbContext>>(database);
        services.AddSingleton(new AuthService(new TestAuthentication()));
        services.AddSingleton<IComponentActivator>(activator);
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var root = await renderer.RenderComponentAsync<SoftLicence.Server.Components.Pages.Licenses>();
            var page = activator.Page!;
            var rows = (List<License>)page.GetType().GetField("LicensesList", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(page)!;
            Assert.NotEmpty(rows);
            var expected = rows.Count(l => l.ExpirationDate.HasValue && l.IsActive && !l.RevokedAt.HasValue);
            var html = root.ToHtmlString();
            Assert.Equal(expected, System.Text.RegularExpressions.Regex.Matches(html, ">Licenses_Extend</button>").Count);
            Assert.DoesNotContain("+30j", html); Assert.DoesNotContain("+90j", html); Assert.DoesNotContain("+1an", html);
            Set(page, "licenseToExtend", rows.First(l => l.ExpirationDate < DateTime.UtcNow && l.IsActive && !l.RevokedAt.HasValue));
            typeof(ComponentBase).GetMethod("StateHasChanged", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(page, null);
            Assert.Single(System.Text.RegularExpressions.Regex.Matches(root.ToHtmlString(), "id=\"extension-days\""));
        });
    }

    /// <summary>Seeds only task-owned synthetic product, type, licence and optional pass rows.</summary>
    private async Task<License> SeedAsync(DateTime expiry, bool pass)
    {
        // Day Pass timestamps are timestamp(3); fixtures must share that exact precision with the licence.
        expiry = new DateTime(expiry.Ticks - expiry.Ticks % TimeSpan.TicksPerMillisecond, DateTimeKind.Utc);
        await using var db = database.CreateDbContext();
        var product = new Product { Id = Guid.NewGuid(), Name = "tkt1480-" + Guid.NewGuid().ToString("N"), ApiSecret = "synthetic-only" };
        var type = new LicenseType { Id = Guid.NewGuid(), Product = product, Name = "Synthetic type", Slug = "TEST-1480", DefaultDurationDays = 1 };
        var license = new License { Product = product, Type = type, LicenseTypeId = type.Id,
            LicenseKey = Guid.NewGuid().ToString("D"), CustomerName = "Synthetic customer", CustomerEmail = "extension@example.test",
            ExpirationDate = expiry, ActivationDate = expiry.AddDays(-1), IsActive = true };
        db.AddRange(product, type, license);
        await db.SaveChangesAsync();
        if (pass)
        {
            var subject = new RuntimeRecoveryCommercialSubject { Id = Guid.NewGuid(), ProductId = product.Id, CreatedAtUtc = Now };
            db.Add(subject);
            db.PersonalDayPasses.Add(new PersonalDayPass { ProductId = product.Id, CommercialSubjectId = subject.Id,
                LicenseId = license.Id, PaidThroughUtc = expiry, InitialPaidThroughUtc = expiry.AddDays(-1) });
            await db.SaveChangesAsync();
        }
        await db.Entry(license).ReloadAsync();
        return license;
    }

    /// <summary>Invokes the real private callback on the renderer dispatcher, without browser or JS claims.</summary>
    private static async Task InvokeAsync(object component, string name)
    {
        var result = component.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(component, null);
        if (result is Task task) await task;
    }
    /// <summary>Supplies synthetic field input as the renderer's input event would.</summary>
    private static void Set(object component, string name, object value) =>
        component.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(component, value);
    /// <summary>Freezes UTC independently of wall-clock time for exact duration assertions.</summary>
    private sealed class FrozenClock(DateTime instant) : TimeProvider
    {
        /// <summary>Returns the same authoritative UTC instant on every read.</summary>
        public override DateTimeOffset GetUtcNow() => new(instant);
    }
    /// <summary>Captures the real component while preserving framework injection and lifecycle.</summary>
    private sealed class CaptureActivator : IComponentActivator
    {
        /// <summary>Last dialog created by the renderer, for dispatching its actual event handlers.</summary>
        public LicenseExtensionDialog? Instance { get; private set; }
        /// <summary>Full page instance for verifying row rendering through the real parent.</summary>
        public IComponent? Page { get; private set; }
        /// <summary>Constructs a fresh framework-owned component without replacing its behavior.</summary>
        public IComponent CreateInstance(Type type)
        {
            var component = (IComponent)Activator.CreateInstance(type)!;
            if (component is LicenseExtensionDialog dialog) Instance = dialog;
            if (component is SoftLicence.Server.Components.Pages.Licenses) Page = component;
            return component;
        }
    }
    /// <summary>Provides a synthetic identity without cookies, secrets or external services.</summary>
    private sealed class TestAuthentication : AuthenticationStateProvider
    {
        /// <summary>Returns only the test principal; no external authentication is performed.</summary>
        public override Task<AuthenticationState> GetAuthenticationStateAsync() => Task.FromResult(new AuthenticationState(Admin));
    }
    /// <summary>Provides local synthetic navigation without opening a browser or contacting a site.</summary>
    private sealed class TestNavigation : NavigationManager
    {
        /// <summary>Initializes the page route without query parameters or external state.</summary>
        public TestNavigation() => Initialize("https://synthetic.invalid/", "https://synthetic.invalid/licenses");
        /// <summary>Fails the test if an unexpected navigation is attempted.</summary>
        protected override void NavigateToCore(string uri, bool forceLoad) => throw new InvalidOperationException("Unexpected test navigation.");
    }
}

/// <summary>Owns a unique disposable PostgreSQL database on an explicitly local test server; applies production migrations.</summary>
public sealed class AdminExtensionDatabase : IDbContextFactory<LicenseDbContext>, IAsyncLifetime
{
    /// <summary>Generated identifier is never derived from external input or a shared database name.</summary>
    private readonly string name = "tkt1480_" + Guid.NewGuid().ToString("N");
    /// <summary>Verified loopback connection used only to create/drop the owned database.</summary>
    private string maintenance = "";
    /// <summary>Connection to this fixture's database, never production.</summary>
    private string connectionString = "";
    /// <summary>Cleanup authority exists only after successful creation by this fixture.</summary>
    private bool created;
    /// <summary>Builds a private production-provider context for each operation and assertion.</summary>
    public LicenseDbContext CreateDbContext() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);
    /// <summary>Refuses non-local database targets and provisions a bounded, generated database name.</summary>
    public async Task InitializeAsync()
    {
        var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES")
            ?? throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required.");
        var builder = new NpgsqlConnectionStringBuilder(configured);
        if (builder.Host is not ("127.0.0.1" or "localhost" or "::1")) throw new InvalidOperationException("Local test PostgreSQL required.");
        builder.Database = "postgres"; maintenance = builder.ConnectionString;
        builder.Database = name; connectionString = builder.ConnectionString;
        await ExecuteMaintenanceAsync($"CREATE DATABASE \"{name}\""); created = true;
        try { await using var db = CreateDbContext(); await db.Database.MigrateAsync(); }
        catch { await DisposeAsync(); throw; }
    }
    /// <summary>Drops only this fixture's generated database; no shared database or global pool is changed.</summary>
    public async Task DisposeAsync()
    {
        if (!created) return;
        using (var poolConnection = new NpgsqlConnection(connectionString)) NpgsqlConnection.ClearPool(poolConnection);
        await ExecuteMaintenanceAsync($"DROP DATABASE \"{name}\" WITH (FORCE)"); created = false;
    }
    /// <summary>Executes only fixture-owned database lifecycle statements against the verified local maintenance database.</summary>
    private async Task ExecuteMaintenanceAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(maintenance); await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection); await command.ExecuteNonQueryAsync();
    }
}

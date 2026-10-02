using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;
using LicensesPage = SoftLicence.Server.Components.Pages.Licenses;

namespace SoftLicence.Tests.Server;

/// <summary>Renders the real administrator licence page against synthetic PostgreSQL without browser installation or outbound services.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Deep-linked mixed history requires licenses.view and a second consultation reloads events committed by another private context.</summary>
    /// <remarks>HtmlRenderer exercises real page lifecycle and Razor output. Reflection invokes the existing history button callback on the captured component; this is not a physical browser/click or JavaScript test. All identities, permissions and stored facts are synthetic.</remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Tkt976_Ui_MixedHistoryDeepLinkAndRefresh_RequirePermission(bool authorized)
    {
        var connections = await ProvisionAsync();
        var database = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(database);
        Guid oldEventId;
        await using (var seed = await database.CreateDbContextAsync())
        {
            var license = await seed.Licenses.Include(row => row.Type).Include(row => row.Seats)
                .SingleAsync(row => row.Id == fixture.LicenseId);
            var old = new LicenseHistory { LicenseId = license.Id, Action = "CREATED",
                Details = "tkt976-historical-original", Timestamp = DateTime.UtcNow.AddMinutes(-2) };
            oldEventId = old.Id;
            seed.LicenseHistories.Add(old);
            await LicenseDecisionHistoryWriter.AddAsync(seed,
                new LicenseDecisionHistory(1, "legacy_activation", "tkt976-ui-operation", "refused", "SEAT_LIMIT", null,
                    400, "SUBMITTED-UI-HWID", null, null, null,
                    LicenseDecisionHistoryWriter.CaptureObserved(license, DateTimeOffset.UtcNow, null), null),
                "synthetic-ui", "synthetic-ui", DateTimeOffset.UtcNow, CancellationToken.None);
            await seed.SaveChangesAsync();
        }
        var activator = new Tkt976UiActivator();
        using var host = Tkt976_CreateLegacyHost(database, configureTestServices: services =>
        {
            // Only the synthetic renderer's identity and navigation are replaced. The page
            // still runs its real licenses.view check and private database reads.
            var authentication = new Tkt976UiAuthentication(authorized);
            services.RemoveAll<AuthService>();
            services.AddSingleton(new AuthService(authentication));
            services.RemoveAll<AuthenticationStateProvider>();
            services.AddSingleton<AuthenticationStateProvider>(authentication);
            services.RemoveAll<NavigationManager>();
            services.AddSingleton<NavigationManager>(new Tkt976UiNavigation(fixture.LicenseId));
            services.RemoveAll<IComponentActivator>();
            services.AddSingleton<IComponentActivator>(activator);
        });
        using var scope = host.Services.CreateScope();
        await using var renderer = new HtmlRenderer(scope.ServiceProvider, scope.ServiceProvider.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var rendered = await renderer.RenderComponentAsync<LicensesPage>();
            var html = rendered.ToHtmlString();
            if (!authorized)
            {
                Assert.DoesNotContain("SUBMITTED-UI-HWID", html);
                Assert.DoesNotContain("tkt976-historical-original", html);
                Assert.DoesNotContain($"history-{oldEventId:D}", html);
                return;
            }
            Assert.Contains($"history-{oldEventId:D}", html);
            Assert.Contains("tkt976-historical-original", html);
            Assert.Contains("SEAT_LIMIT", html);
            Assert.Contains("SUBMITTED-UI-HWID", html);
            var lateEvent = new LicenseHistory { LicenseId = fixture.LicenseId, Action = "CREATED", Details = "tkt976-later-event" };
            await using (var writer = await database.CreateDbContextAsync())
            {
                writer.LicenseHistories.Add(lateEvent);
                await writer.SaveChangesAsync();
            }
            var page = Assert.IsType<LicensesPage>(activator.Page);
            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var licenses = Assert.IsType<List<License>>(typeof(LicensesPage).GetField("LicensesList", flags)!.GetValue(page));
            var selected = Assert.Single(licenses, item => item.Id == fixture.LicenseId);
            await (Task)typeof(LicensesPage).GetMethod("SwitchToHistoryTab", flags)!.Invoke(page, [selected])!;
            typeof(ComponentBase).GetMethod("StateHasChanged", flags)!.Invoke(page, null);
            html = rendered.ToHtmlString();
            Assert.Contains($"history-{lateEvent.Id:D}", html);
            Assert.Contains("tkt976-later-event", html);
            Assert.Contains("tkt976-historical-original", html);
            Assert.Single(selected.History, item => item.Id == oldEventId);
        });
    }

    /// <summary>Creates framework component instances and captures only the licence page for invoking its existing UI callback.</summary>
    private sealed class Tkt976UiActivator : IComponentActivator
    {
        /// <summary>Renderer-owned page instance; the test never disposes or shares it outside its renderer dispatcher.</summary>
        internal IComponent? Page { get; private set; }
        /// <summary>Creates a fresh component; normal renderer property injection and lifecycle remain active.</summary>
        public IComponent CreateInstance(Type componentType)
        {
            var component = (IComponent)Activator.CreateInstance(componentType)!;
            if (componentType == typeof(LicensesPage)) Page = component;
            return component;
        }
    }

    /// <summary>Supplies only a synthetic authenticated licenses.view principal or an anonymous principal.</summary>
    private sealed class Tkt976UiAuthentication(bool authorized) : AuthenticationStateProvider
    {
        /// <summary>No cookies, users or external identity service are consulted.</summary>
        public override Task<AuthenticationState> GetAuthenticationStateAsync() => Task.FromResult(new AuthenticationState(
            new ClaimsPrincipal(authorized ? new ClaimsIdentity([new Claim("Permissions", "licenses.view")], "synthetic") : new ClaimsIdentity())));
    }

    /// <summary>Provides a synthetic exact licence deep link without opening a network connection.</summary>
    private sealed class Tkt976UiNavigation : NavigationManager
    {
        /// <summary>Initializes the renderer's query context to the task-owned licence UUID.</summary>
        internal Tkt976UiNavigation(Guid licenseId) => Initialize("https://synthetic.invalid/", $"https://synthetic.invalid/licenses?licenseId={licenseId:D}");
        /// <summary>Rejects unexpected navigation; this test only renders and refreshes an existing page.</summary>
        protected override void NavigateToCore(string uri, bool forceLoad) => throw new InvalidOperationException("Unexpected navigation in synthetic UI test.");
    }
}

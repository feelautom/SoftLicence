using System.Reflection;
using System.Net;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SoftLicence.Server.Components.Shared;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;
using SecurityLocksPage = SoftLicence.Server.Components.Pages.SecurityLocks;

namespace SoftLicence.Tests.Server;

/// <summary>Runs the PostgreSQL-backed security-lock page tests as one independently schedulable class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed class SecurityLocksPagePostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>TKT-001837 keeps RELEASED rows with an open incident in the default review set and opens one modal.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001837_DefaultReview_IncludesReleasedIncidentAndOpensReleaseModal")]
    public async Task Tkt001837_DefaultReview_IncludesReleasedIncidentAndOpensReleaseModal()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('f');
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Release, "reviewed", "tkt1837-root",
            scenario.Fixture.ProductId)).Outcome);
        await OpenPreparedCriticalIncidentAsync(scenario);

        var activator = new Tkt1782SecurityLocksActivator();
        var services = CreateSecurityLocksRenderServices(scenario.Factory, prepared.Admin, activator);
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var rendered = await renderer.RenderComponentAsync<SecurityLocksPage>();
            var html = rendered.ToHtmlString();
            Assert.Contains("(1 à examiner)", html, StringComparison.Ordinal);
            Assert.Contains("1 incident(s) critique(s) ouvert(s)", html, StringComparison.Ordinal);
            Assert.DoesNotContain("<th>Verrou</th>", html, StringComparison.Ordinal);
            Assert.Contains(">Relâcher</button>", html, StringComparison.Ordinal);

            var page = Assert.IsType<SecurityLocksPage>(activator.Page);
            Invoke(page, "RequestLockDecision", prepared.ReportId, SecurityLockDecisionDialog.ReleaseAction);
            StateHasChanged(page);
            html = rendered.ToHtmlString();
            var dialog = Assert.IsType<SecurityLockDecisionDialog>(activator.Dialog);
            Assert.Contains("data-testid=\"security-lock-dialog\"", html, StringComparison.Ordinal);
            Assert.Equal(SecurityLockDecisionDialog.ReleaseAction, dialog.Request.Action);
            Assert.Equal(1, dialog.Request.OpenIncidentCount);
            await using var check = await scenario.Factory.CreateDbContextAsync();
            var report = await check.SecurityLockReports.AsNoTracking().SingleAsync(row => row.Id == prepared.ReportId);
            Assert.Equal(report.LockId, dialog.Request.Identifier);
            Assert.Equal(report.EvidenceDigestSha256, dialog.Request.EvidenceDigest);
        });
    }

    /// <summary>TKT-001837 renders a BANNED row with only the explicit UNBAN action and its audit modal.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001837_BannedRow_OffersOnlyUnbanAndOpensAuditModal")]
    public async Task Tkt001837_BannedRow_OffersOnlyUnbanAndOpensAuditModal()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('d');
        using var scenario = prepared.Scenario;
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Ban, "confirmed", "tkt1837-root",
            scenario.Fixture.ProductId)).Outcome);

        var activator = new Tkt1782SecurityLocksActivator();
        var services = CreateSecurityLocksRenderServices(scenario.Factory, prepared.Admin, activator);
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var rendered = await renderer.RenderComponentAsync<SecurityLocksPage>();
            var page = Assert.IsType<SecurityLocksPage>(activator.Page);
            Set(page, "stateFilter", SecurityLockReportStates.Banned);
            await InvokeAsync(page, "LoadData");
            StateHasChanged(page);
            var html = rendered.ToHtmlString();
            Assert.Contains(">Débannir</button>", html, StringComparison.Ordinal);
            Assert.DoesNotContain(">Relâcher</button>", html, StringComparison.Ordinal);

            Invoke(page, "RequestLockDecision", prepared.ReportId, SecurityLockDecisionDialog.UnbanAction);
            StateHasChanged(page);
            html = rendered.ToHtmlString();
            var dialog = Assert.IsType<SecurityLockDecisionDialog>(activator.Dialog);
            Assert.Equal(SecurityLockDecisionDialog.UnbanAction, dialog.Request.Action);
            Assert.Equal(prepared.ReportId, dialog.Request.TargetId);
            Assert.True(dialog.Request.HasActiveEnrollment);
            Assert.Contains("Un enrôlement actif existe", WebUtility.HtmlDecode(html), StringComparison.Ordinal);
            Assert.Contains("data-testid=\"security-lock-dialog\"", html, StringComparison.Ordinal);
        });
    }

    /// <summary>TKT-001838 warns before UNBAN and preserves the reinstall-required success diagnostic.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt001838_UnbanWithoutActiveEnrollment_ShowsReinstallBeforeAndAfterConfirmation")]
    public async Task Tkt001838_UnbanWithoutActiveEnrollment_ShowsReinstallBeforeAndAfterConfirmation()
    {
        var prepared = await PrepareAdminReleaseFixtureAsync('8');
        using var scenario = prepared.Scenario;
        await OpenPreparedCriticalIncidentAsync(scenario);
        Assert.Equal(SecurityLockAdminOutcomes.Ok, (await prepared.Admin.DecideAsync(
            prepared.ReportId, SecurityLockAdminDecisions.Ban, "confirmed", "tkt1838-root",
            scenario.Fixture.ProductId)).Outcome);
        await using (var invalidate = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await invalidate.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "TKT-001838 production-shaped inactive enrollment";
            var assignment = await invalidate.EnrollmentLicenseAssignments
                .SingleAsync(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE");
            assignment.State = "ENDED";
            assignment.EndedAtUtc = enrollment.InvalidatedAtUtc;
            assignment.EndReason = "tkt001838_reinstall_required";
            await invalidate.SaveChangesAsync();
        }

        var activator = new Tkt1782SecurityLocksActivator();
        using var toast = new ToastService();
        string? successMessage = null;
        // Capture only the successful terminal message; any error toast must leave the expected value absent.
        toast.OnShow += (message, _, level) =>
        {
            if (level == ToastLevel.Success) successMessage = message;
        };
        var services = CreateSecurityLocksRenderServices(scenario.Factory, prepared.Admin, activator, toast);
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var rendered = await renderer.RenderComponentAsync<SecurityLocksPage>();
            var page = Assert.IsType<SecurityLocksPage>(activator.Page);
            Set(page, "stateFilter", SecurityLockReportStates.Banned);
            await InvokeAsync(page, "LoadData");
            StateHasChanged(page);
            Invoke(page, "RequestLockDecision", prepared.ReportId, SecurityLockDecisionDialog.UnbanAction);
            StateHasChanged(page);
            var dialog = Assert.IsType<SecurityLockDecisionDialog>(activator.Dialog);
            Assert.False(dialog.Request.HasActiveEnrollment);
            Assert.Contains("Aucun enrôlement actif n’existe", WebUtility.HtmlDecode(rendered.ToHtmlString()),
                StringComparison.Ordinal);

            await InvokeAsync(page, "ConfirmDecision", new SecurityLockDecisionDialog.Confirmation(
                dialog.Request, "False positive reviewed", "TKT-001838"));
            Assert.Equal(
                "Débanni et incidents clos. Aucun enrôlement actif : le client doit réinstaller T-IA Connect pour repartir.",
                successMessage);
        });
    }

    /// <summary>
    /// Builds only the services required by the real security-lock Razor page and modal. A supplied toast instance is
    /// retained so a test can observe the exact user-facing completion diagnostic.
    /// </summary>
    private static ServiceCollection CreateSecurityLocksRenderServices(
        IDbContextFactory<LicenseDbContext> factory,
        SecurityLockAdminService admin,
        IComponentActivator activator,
        ToastService? toast = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization();
        services.AddSingleton<TimeZoneService>();
        services.AddSingleton(toast ?? new ToastService());
        services.AddSingleton(factory);
        services.AddSingleton(new AuthService(new Tkt1782RootAuthentication()));
        services.AddSingleton(admin);
        services.AddSingleton(activator);
        return services;
    }

    /// <summary>Invokes one private synchronous Razor handler with its exact captured arguments.</summary>
    private static void Invoke(object component, string method, params object[] arguments) =>
        component.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(component, arguments);

    /// <summary>Invokes one private asynchronous Razor handler.</summary>
    private static async Task InvokeAsync(object component, string method)
    {
        var task = (Task)component.GetType().GetMethod(method,
            BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(component, null)!;
        await task;
    }

    /// <summary>
    /// Invokes one private asynchronous Razor handler with one captured argument and propagates reflection or handler
    /// failures to the owning UI integration test.
    /// </summary>
    private static async Task InvokeAsync(object component, string method, object argument)
    {
        var task = (Task)component.GetType().GetMethod(method,
            BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(component, [argument])!;
        await task;
    }

    /// <summary>Updates the captured private field as a rendered input or select would.</summary>
    private static void Set(object component, string field, object value) =>
        component.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(component, value);

    /// <summary>Requests one renderer-owned rerender on the active dispatcher.</summary>
    private static void StateHasChanged(ComponentBase component) =>
        typeof(ComponentBase).GetMethod("StateHasChanged", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(component, null);
}

/// <summary>Exercises the TKT-001480-derived modal shell without database or browser side effects.</summary>
public sealed class SecurityLockDecisionDialogTests
{
    /// <summary>TKT-001837 proves cancellation is inert and a rapid double confirmation invokes the action once.</summary>
    [Fact]
    public async Task Tkt001837_Dialog_CancelIsInertAndDoubleConfirmExecutesOnce()
    {
        var activator = new DialogActivator();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IComponentActivator>(activator);
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var canceled = 0;
            var confirmed = 0;
            var release = new SecurityLockDecisionDialog.DialogRequest(
                Guid.NewGuid(), SecurityLockDecisionDialog.ReleaseAction, "lock-1837", "HWID-1837",
                "DEBUGGER", "digest-1837", 2, true, true);
            var rendered = await renderer.RenderComponentAsync<SecurityLockDecisionDialog>(
                ParameterView.FromDictionary(new Dictionary<string, object?>
                {
                    ["Request"] = release,
                    ["Canceled"] = EventCallback.Factory.Create(this, () => canceled++),
                    ["Confirmed"] = EventCallback.Factory.Create<SecurityLockDecisionDialog.Confirmation>(
                        this, _ => confirmed++)
                }));
            Assert.Contains("La décision sera mémorisée", rendered.ToHtmlString(), StringComparison.Ordinal);
            await InvokeDialogAsync(activator.Instance!, "CancelAsync");
            await InvokeDialogAsync(activator.Instance!, "ConfirmAsync");
            Assert.Equal(1, canceled);
            Assert.Equal(0, confirmed);

            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var unban = release with
            {
                Action = SecurityLockDecisionDialog.UnbanAction,
                OpenIncidentCount = 1,
                RememberRelease = false
            };
            rendered = await renderer.RenderComponentAsync<SecurityLockDecisionDialog>(
                ParameterView.FromDictionary(new Dictionary<string, object?>
                {
                    ["Request"] = unban,
                    ["Confirmed"] = EventCallback.Factory.Create<SecurityLockDecisionDialog.Confirmation>(this,
                        async _ =>
                        {
                            confirmed++;
                            await gate.Task;
                        })
                }));
            Assert.Contains("Confirmer le débannissement", WebUtility.HtmlDecode(rendered.ToHtmlString()),
                StringComparison.Ordinal);
            Assert.Contains("id=\"security-lock-unban-reason\"", rendered.ToHtmlString(), StringComparison.Ordinal);
            Assert.Contains("id=\"security-lock-unban-audit\"", rendered.ToHtmlString(), StringComparison.Ordinal);
            var dialog = activator.Instance!;
            SetDialog(dialog, "reason", "False positive reviewed");
            SetDialog(dialog, "auditReference", "TKT-001837");
            var first = StartDialogCall(dialog, "ConfirmAsync");
            var second = StartDialogCall(dialog, "ConfirmAsync");
            Assert.Equal(1, confirmed);
            gate.SetResult();
            await Task.WhenAll(first, second);
            Assert.Equal(1, confirmed);
            Assert.Contains("Un nouveau ban matériel restera prioritaire", rendered.ToHtmlString(),
                StringComparison.Ordinal);
            Assert.Contains("Un enrôlement actif existe", WebUtility.HtmlDecode(rendered.ToHtmlString()),
                StringComparison.Ordinal);
        });
    }

    /// <summary>Starts one private dialog task without awaiting it, reproducing overlapping click delivery.</summary>
    private static Task StartDialogCall(SecurityLockDecisionDialog dialog, string method) =>
        (Task)dialog.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(dialog, null)!;

    /// <summary>Invokes and awaits one private dialog handler.</summary>
    private static Task InvokeDialogAsync(SecurityLockDecisionDialog dialog, string method) =>
        StartDialogCall(dialog, method);

    /// <summary>Supplies controlled test input as the renderer's bound fields would.</summary>
    private static void SetDialog(SecurityLockDecisionDialog dialog, string field, string value) =>
        dialog.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(dialog, value);

    /// <summary>Captures the most recently rendered real modal instance.</summary>
    private sealed class DialogActivator : IComponentActivator
    {
        internal SecurityLockDecisionDialog? Instance { get; private set; }

        /// <summary>Constructs the requested component and retains only the modal under test.</summary>
        public IComponent CreateInstance(Type componentType)
        {
            var component = (IComponent)Activator.CreateInstance(componentType)!;
            if (component is SecurityLockDecisionDialog dialog) Instance = dialog;
            return component;
        }
    }
}

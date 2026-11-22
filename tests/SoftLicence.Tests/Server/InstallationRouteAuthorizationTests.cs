using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003162: the installation and enrollment S2S routes (nine, plus the TKT-003647 current-assignment read) require
/// <see cref="DistributionS2SPrincipal.MayDriveInstallation"/>. Every dedicated identity configured in production
/// (portal, key activation, account relink) gets 403 <c>installation_not_authorized</c> before any service call,
/// and the main distribution client, with its production rights, reaches the service.
/// </summary>
/// <remarks>
/// The check reads the authenticated principal only, with no database query, so controller-level tests with strict
/// mocks are the relevant proof: a strict service mock without setup fails the call, which the controllers turn into
/// 500 or 503, never 403. Acceptance is proven by a probe exception thrown by the service and mapped by the route.
/// </remarks>
public sealed class InstallationRouteAuthorizationTests
{
    /// <summary>Product scope carried by every request body; authentication is mocked, so any canonical UUID works.</summary>
    private const string ProductId = "12345678-1234-4234-9234-1234567890ab";

    /// <summary>Minimal JSON body: the right is checked before deserialization of the route-specific request.</summary>
    private const string Body = "{\"productId\":\"" + ProductId + "\"}";

    /// <summary>Error code thrown by the service probes to prove that a route reached its service.</summary>
    private const string ProbeErrorCode = "probe_reached";

    /// <summary>Status of the probe exception, chosen so it cannot be confused with a real route answer.</summary>
    private const int ProbeStatus = StatusCodes.Status418ImATeapot;

    /// <summary>The nine routes protected by TKT-003162 plus the TKT-003647 current-assignment read, one name per controller action.</summary>
    public static readonly TheoryData<string> Routes = new()
    {
        "finalize-authority", "hardware-authority", "source-authority", "entitlement-issue", "finalize",
        "invalidate", "enrollment-prepare", "reinstall-source-authority", "reinstall-authorizations",
        "current-assignment",
    };

    /// <summary>
    /// Every (route, refused identity) pair. Rights mirror production as read by TEAM-LUC on 06/11/2026, plus a
    /// distribution client holding recovery and upgrade but not bootstrap, to lock the exact right chosen.
    /// </summary>
    public static TheoryData<string, string> RefusedCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var route in Routes)
            foreach (var identity in new[] { "portal", "key-activation", "account-relink", "recovery-upgrade-only" })
                data.Add(route, identity);
        return data;
    }

    /// <summary>
    /// A dedicated identity gets 403 <c>installation_not_authorized</c>, and no service method is invoked (strict
    /// mocks record no invocation).
    /// </summary>
    [Theory]
    [MemberData(nameof(RefusedCases))]
    public async Task DedicatedIdentity_IsRefusedBeforeAnyServiceCall(string route, string identity)
    {
        var services = new ServiceMocks(MockBehavior.Strict);

        var result = await InvokeAsync(route, Principal(identity), services);

        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        Assert.Equal(DistributionS2SPrincipal.InstallationNotAuthorizedErrorCode, ErrorCode(result.Value));
        Assert.Empty(services.Bindings.Invocations);
        Assert.Empty(services.Preflight.Invocations);
        Assert.Empty(services.FinalizeAuthority.Invocations);
        Assert.Empty(services.Enrollments.Invocations);
    }

    /// <summary>The main distribution client, with its production rights, reaches the service of every route.</summary>
    [Theory]
    [MemberData(nameof(Routes))]
    public async Task MainDistributionClient_ReachesTheService(string route)
    {
        var services = new ServiceMocks(MockBehavior.Strict);
        services.ThrowProbeEverywhere();

        var result = await InvokeAsync(route, Principal("main"), services);

        Assert.Equal(ProbeStatus, result.StatusCode);
        Assert.Equal(ProbeErrorCode, ErrorCode(result.Value));
    }

    /// <summary>
    /// Builds the principal of one identity. Client identifiers and rights are those of the production
    /// configuration (clients 0 to 3); <c>recovery-upgrade-only</c> is synthetic.
    /// </summary>
    /// <param name="identity">One of <c>main</c>, <c>portal</c>, <c>key-activation</c>, <c>account-relink</c>,
    /// <c>recovery-upgrade-only</c>.</param>
    /// <returns>The principal the mocked authentication returns.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Unknown identity name.</exception>
    private static DistributionS2SPrincipal Principal(string identity) => identity switch
    {
        "main" => new("tia-connect-website", "key-0",
            AllowRuntimeRecovery: true, AllowRuntimeUpgrade: true, AllowLicenseBootstrap: true),
        "portal" => new("tia-website-portal", "key-1",
            AllowPortalDeactivation: true, AllowLicenseHardwareExclusions: true),
        "key-activation" => new("tia-website-key-activation", "key-2", AllowLicenseKeyActivationSettings: true),
        "account-relink" => new("website-account-relink", "key-3",
            AllowRuntimeAccountRelink: true, AccountRelinkForClientIds: ["tia-connect-website"]),
        "recovery-upgrade-only" => new("distribution-without-bootstrap", "key-4",
            AllowRuntimeRecovery: true, AllowRuntimeUpgrade: true),
        _ => throw new ArgumentOutOfRangeException(nameof(identity), identity, null),
    };

    /// <summary>
    /// Calls one route on a fresh controller whose authentication returns <paramref name="principal"/>.
    /// </summary>
    /// <param name="route">One name of <see cref="Routes"/>.</param>
    /// <param name="principal">Principal returned by the mocked authentication.</param>
    /// <param name="services">Service mocks injected in the controller.</param>
    /// <returns>The route answer; every answer of these routes in this setup is an <see cref="ObjectResult"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Unknown route name.</exception>
    private static async Task<ObjectResult> InvokeAsync(
        string route, DistributionS2SPrincipal principal, ServiceMocks services)
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(principal);
        var token = CancellationToken.None;
        IActionResult result = route switch
        {
            "finalize-authority" => await Bindings(authentication, services).FinalizeAuthorityPair(token),
            "hardware-authority" => await Bindings(authentication, services).RuntimePreflight(token),
            "source-authority" => await Bindings(authentication, services).ResolveRuntimeSource(token),
            "entitlement-issue" => await Bindings(authentication, services).IssueEntitlement(token),
            "finalize" => await Bindings(authentication, services).FinalizeInstallation(token),
            "invalidate" => await Bindings(authentication, services).InvalidateInstallation(token),
            "enrollment-prepare" => await Enrollments(authentication, services,
                "/api/internal/v1/runtime-enrollments/prepare").Prepare(token),
            "reinstall-source-authority" => await Enrollments(authentication, services,
                "/api/internal/v1/runtime-enrollments/reinstall-source-authority/resolve")
                .ResolveReinstallSourceAuthority(token),
            "reinstall-authorizations" => await Enrollments(authentication, services,
                "/api/internal/v1/runtime-enrollments/reinstall-authorizations").AuthorizeReinstall(token),
            "current-assignment" => await Enrollments(authentication, services,
                "/api/internal/v1/runtime-enrollments/current-assignment/resolve").ResolveCurrentAssignment(token),
            _ => throw new ArgumentOutOfRangeException(nameof(route), route, null),
        };
        return Assert.IsAssignableFrom<ObjectResult>(result);
    }

    /// <summary>Creates the binding controller with the shared JSON body and every optional collaborator set.</summary>
    private static DistributionInstallationBindingsController Bindings(
        Mock<IDistributionS2SAuthenticationService> authentication, ServiceMocks services) =>
        new(authentication.Object, services.Bindings.Object, services.Preflight.Object,
            NullLogger<DistributionInstallationBindingsController>.Instance, services.FinalizeAuthority.Object)
        {
            ControllerContext = new ControllerContext { HttpContext = Context("/unused") }
        };

    /// <summary>
    /// Creates the enrollment controller in enabled mode; <paramref name="path"/> must be the exact route path,
    /// which the controller checks before authentication.
    /// </summary>
    private static RuntimeEnrollmentsController Enrollments(
        Mock<IDistributionS2SAuthenticationService> authentication, ServiceMocks services, string path) =>
        new(authentication.Object, services.Enrollments.Object,
            Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }))
        {
            ControllerContext = new ControllerContext { HttpContext = Context(path) }
        };

    /// <summary>Builds a POST JSON request context carrying <see cref="Body"/> on <paramref name="path"/>.</summary>
    private static DefaultHttpContext Context(string path)
    {
        var bytes = Encoding.UTF8.GetBytes(Body);
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = path;
        context.Request.ContentType = "application/json";
        context.Request.ContentLength = bytes.Length;
        context.Request.Body = new MemoryStream(bytes);
        return context;
    }

    /// <summary>Reads the error code of either error record used by the two controllers.</summary>
    /// <exception cref="Xunit.Sdk.XunitException">The answer body is not an API error record.</exception>
    private static string ErrorCode(object? value) => value switch
    {
        DistributionApiError error => error.Error,
        RuntimeEnrollmentApiError error => error.Error,
        _ => throw new Xunit.Sdk.XunitException($"Unexpected answer body {value?.GetType().Name ?? "null"}."),
    };

    /// <summary>Service mocks of the two controllers, sharing one behavior.</summary>
    private sealed class ServiceMocks(MockBehavior behavior)
    {
        /// <summary>Binding service of entitlement, finalize, invalidate and source routes.</summary>
        public Mock<IDistributionInstallationBindingService> Bindings { get; } = new(behavior);

        /// <summary>Hardware authority service of the preflight route.</summary>
        public Mock<IRuntimeDistributionPreflightService> Preflight { get; } = new(behavior);

        /// <summary>Alias pair resolver of the finalize-authority route.</summary>
        public Mock<IFinalizeAuthorityPairResolver> FinalizeAuthority { get; } = new(behavior);

        /// <summary>Enrollment service of the prepare and reinstall routes.</summary>
        public Mock<IRuntimeEnrollmentService> Enrollments { get; } = new(behavior);

        /// <summary>
        /// Makes every service method used by the ten routes throw the probe exception, which each route maps to
        /// its status and code: an answer 418 <c>probe_reached</c> proves the service was called.
        /// </summary>
        public void ThrowProbeEverywhere()
        {
            var distribution = new DistributionOperationException(ProbeErrorCode, ProbeStatus);
            var enrollment = new RuntimeEnrollmentException(ProbeErrorCode, ProbeStatus);
            FinalizeAuthority.Setup(service => service.ResolveAsync(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<FinalizeAuthorityPairRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(distribution);
            Preflight.Setup(service => service.EvaluateAsync(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<RuntimeDistributionPreflightRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(distribution);
            Bindings.Setup(service => service.ResolveRuntimeSourceAsync(
                    It.IsAny<string>(), It.IsAny<DistributionRuntimeSourceResolutionRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(distribution);
            Bindings.Setup(service => service.IssueEntitlementAsync(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DistributionEntitlementIssueRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(distribution);
            Bindings.Setup(service => service.FinalizeAsync(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DistributionInstallationFinalizeRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(distribution);
            Bindings.Setup(service => service.InvalidateAsync(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DistributionInstallationInvalidationRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(distribution);
            Enrollments.Setup(service => service.PrepareAsync(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<RuntimeEnrollmentPrepareRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(enrollment);
            Enrollments.Setup(service => service.ResolveReinstallSourceAuthorityAsync(
                    It.IsAny<string>(), It.IsAny<RuntimeReinstallSourceResolutionRequest>(),
                    It.IsAny<CancellationToken>()))
                .ThrowsAsync(enrollment);
            Enrollments.Setup(service => service.AuthorizeReinstallAsync(
                    It.IsAny<string>(), It.IsAny<RuntimeReinstallAuthorityRequest>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(enrollment);
            Enrollments.Setup(service => service.ResolveCurrentAssignmentAsync(
                    It.IsAny<string>(), It.IsAny<RuntimeCurrentAssignmentRequest>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(enrollment);
        }
    }
}

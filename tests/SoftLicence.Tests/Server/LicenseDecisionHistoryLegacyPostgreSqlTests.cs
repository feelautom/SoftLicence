using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises the legacy producer against synthetic PostgreSQL with request-scoped dependencies and no external notification transport.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Proves the history-only offline helper preserves response correlation and all business tables across bounded persistence faults.</summary>
    /// <remarks>The refusal is already established on a disabled unique licence. Cancellation is injected exactly before history insertion; client abort remains independent while host stop is respected. An independent observer distinguishes committed acknowledgement loss from absent history.</remarks>
    [Theory]
    [InlineData("insert")]
    [InlineData("commit-before")]
    [InlineData("commit-ack")]
    [InlineData("timeout")]
    [InlineData("cancel-at-insert")]
    [InlineData("host-at-insert")]
    public async Task Tkt976_Offline_PrecheckFaults_PreserveBusinessAndCorrelation(string mode)
    {
        var connections = await ProvisionAsync();
        var clean = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        var secret = "tkt976-precheck-fault-" + fixture.ProductId.ToString("N");
        string licenseKey;
        await using (var setup = await clean.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Product).SingleAsync(row => row.Id == fixture.LicenseId);
            licenseKey = license.LicenseKey;
            license.IsActive = false;
            license.Product!.ApiSecret = secret;
            await setup.SaveChangesAsync();
        }
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown);
        using var host = Tkt976_CreateLegacyHost(new Tkt976FaultFactory(connections.App, fault));
        _ = host.Services;
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        using (var scope = host.Services.CreateScope())
        {
            var controller = ActivatorUtilities.CreateInstance<ActivationController>(scope.ServiceProvider, new Tkt976HostLifetime(shutdown));
            controller.ControllerContext = new ControllerContext
            { HttpContext = new DefaultHttpContext { RequestServices = scope.ServiceProvider,
                RequestAborted = requestCancellation.Token, TraceIdentifier = "precheck-correlation" } };
            controller.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
            controller.Request.Headers["X-Admin-Secret"] = secret;
            controller.Response.Headers["X-Request-Id"] = "precheck-request";
            controller.Response.Headers["X-Content-Type-Options"] = "nosniff";
            fault.Armed = true;
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var response = Assert.IsAssignableFrom<ObjectResult>(await controller.ActivateOffline(
                new ActivationController.OfflineActivationRequest
                { LicenseKey = licenseKey, HardwareId = fixture.HardwareId, OfflineRequestCode = "ABCD-EF01-2345-6789" }));
            Assert.Equal(mode == "cancel-at-insert" ? 403 : 500, response.StatusCode);
            Assert.Equal("precheck-request", controller.Response.Headers["X-Request-Id"].ToString());
            Assert.Equal("nosniff", controller.Response.Headers["X-Content-Type-Options"].ToString());
            Assert.Equal("precheck-correlation", controller.HttpContext.TraceIdentifier);
            var body = System.Text.Json.JsonSerializer.Serialize(response.Value);
            Assert.DoesNotContain(licenseKey, body);
            Assert.DoesNotContain("INSERT", body);
            if (mode != "cancel-at-insert") Assert.Contains("offline_activation_failed", body);
            if (mode == "timeout") Assert.InRange(clock.Elapsed.TotalSeconds, 4.5, 15);
        }
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var observed = await clean.CreateDbContextAsync();
        Assert.Equal(mode is "cancel-at-insert" or "commit-ack" ? 1 : 0,
            await observed.LicenseHistories.CountAsync(row => row.LicenseId == fixture.LicenseId && row.Action == "ACTIVATION_DECISION_V1"));
    }

    /// <summary>Records only uniquely product-authorized offline precheck refusals, preserving generic403 and independent request identity.</summary>
    /// <remarks>The loaded graph is captured before the compound predicate; unknown resolver and quota authority are not inferred. Synthetic authentication and every business table remain unchanged.</remarks>
    [Theory]
    [InlineData("disabled")]
    [InlineData("revoked")]
    [InlineData("free")]
    [InlineData("expired")]
    [InlineData("features")]
    [InlineData("unauthorized")]
    public async Task Tkt976_Offline_Prechecks_RecordOnlyAuthorizedLicence(string mode)
    {
        var connections = await ProvisionAsync();
        var database = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(database);
        string licenseKey;
        var syntheticSecret = "tkt976-offline-precheck-" + fixture.ProductId.ToString("N");
        await using (var seed = await database.CreateDbContextAsync())
        {
            var license = await seed.Licenses.Include(row => row.Product).Include(row => row.Type)
                .SingleAsync(row => row.Id == fixture.LicenseId);
            licenseKey = license.LicenseKey;
            license.Product!.ApiSecret = syntheticSecret;
            license.IsActive = mode != "disabled";
            license.RevokedAt = mode == "revoked" ? DateTime.UtcNow : null;
            license.ExpirationDate = DateTime.UtcNow.AddDays(mode == "expired" ? -1 : 30);
            license.Type!.IsFree = mode == "free";
            if (mode != "features") seed.LicenseTypeCustomParams.Add(new LicenseTypeCustomParam
            { LicenseTypeId = license.LicenseTypeId, Key = "allowOffline", Name = "Synthetic", Value = "true" });
            await seed.SaveChangesAsync();
        }
        using var host = Tkt976_CreateLegacyHost(database);
        _ = host.Services;
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var scope = host.Services.CreateScope();
            var controller = Tkt976_CreateDirectLegacyController(scope.ServiceProvider);
            controller.Request.Headers["X-Admin-Secret"] = mode == "unauthorized" ? "synthetic-invalid" : syntheticSecret;
            var result = Assert.IsAssignableFrom<ObjectResult>(await controller.ActivateOffline(
                new ActivationController.OfflineActivationRequest
                { LicenseKey = licenseKey, HardwareId = fixture.HardwareId, OfflineRequestCode = "ABCD-EF01-2345-6789" }));
            Assert.Equal(mode == "unauthorized" ? 401 : 403, result.StatusCode);
        }
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var observed = await database.CreateDbContextAsync();
        var rows = await observed.LicenseHistories.Where(row => row.LicenseId == fixture.LicenseId
            && row.Action == "ACTIVATION_DECISION_V1").ToListAsync();
        Assert.Equal(mode == "unauthorized" ? 0 : 2, rows.Count);
        foreach (var row in rows)
        {
            var decision = System.Text.Json.JsonSerializer.Deserialize<LicenseDecisionHistory>(row.Details!,
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!;
            Assert.Equal("offline_activation_denied", decision.Code);
            Assert.Equal(403, decision.HttpStatus);
            Assert.Null(decision.ReasonCode);
            Assert.Null(decision.ResolvedHardwareId);
            Assert.Null(decision.CorrelatedHardwareId);
            Assert.Equal("authorized_offline_precheck_observation", decision.Snapshot.ObservationGuarantee);
            Assert.DoesNotContain(licenseKey, row.Details!);
        }
    }

    /// <summary>Freezes the first HWID quota observation, proves the concurrent quota writer waits, then admits another HWID after the quota change; history retains the original facts.</summary>
    /// <remarks>The barrier runs after PostgreSQL has executed the exact active-seat statement. Both HTTP calls are awaited, every context is fixture-owned, and the barrier is released in finally. Existing authorization and hardware lock behavior remain unchanged.</remarks>
    [Fact]
    public async Task Tkt976_Legacy_InterHardwareConcurrency_PreservesOriginalPredicateFacts()
    {
        var connections = await ProvisionAsync();
        var clean = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        await Tkt976_FillMultiSeatCapacityAsync(clean, fixture.LicenseId);
        var firstApplication = "history-first-" + Guid.NewGuid().ToString("N");
        var writerApplication = "history-quota-" + Guid.NewGuid().ToString("N");
        var firstConnection = new Npgsql.NpgsqlConnectionStringBuilder(connections.App)
            { ApplicationName = firstApplication, Pooling = false }.ConnectionString;
        var writerConnection = new Npgsql.NpgsqlConnectionStringBuilder(connections.App)
            { ApplicationName = writerApplication, Pooling = false }.ConnectionString;
        var writerFactory = new TestDbFactory(writerConnection);
        var barrier = new Tkt976LegacyQuotaBarrier(fixture.LicenseId);
        using var firstHost = Tkt976_CreateLegacyHost(new Tkt976LegacyBarrierFactory(firstConnection, barrier));
        using var secondHost = Tkt976_CreateLegacyHost(clean);
        ActivationController.ActivationRequest firstRequest;
        ActivationController.ActivationRequest secondRequest;
        await using (var setup = await clean.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Product).SingleAsync(row => row.Id == fixture.LicenseId);
            firstRequest = new ActivationController.ActivationRequest
            {
                LicenseKey = license.LicenseKey, AppName = license.Product!.Name,
                HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant(),
                AppVersion = fixture.Version, CustomerEmail = license.CustomerEmail
            };
            secondRequest = new ActivationController.ActivationRequest
            {
                LicenseKey = license.LicenseKey, AppName = license.Product.Name,
                HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant(),
                AppVersion = fixture.Version, CustomerEmail = license.CustomerEmail
            };
        }
        using var firstScope = firstHost.Services.CreateScope();
        using var secondScope = secondHost.Services.CreateScope();
        var first = Tkt976_CreateDirectLegacyController(firstScope.ServiceProvider);
        var second = Tkt976_CreateDirectLegacyController(secondScope.ServiceProvider);
        var pending = first.Activate(firstRequest);
        await using var change = await writerFactory.CreateDbContextAsync();
        Task? quotaChange = null;
        try
        {
            await barrier.Reached.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var license = await change.Licenses.SingleAsync(row => row.Id == fixture.LicenseId);
            license.MaxSeats = 3;
            quotaChange = change.SaveChangesAsync();
            await WaitForBlockedBackendAsync(connections.Admin, writerApplication, firstApplication);
            Assert.False(quotaChange.IsCompleted);
            Assert.False(pending.IsCompleted);
            barrier.Resume.TrySetResult();
            Assert.IsType<BadRequestObjectResult>(await pending.WaitAsync(TimeSpan.FromSeconds(15)));
            await quotaChange.WaitAsync(TimeSpan.FromSeconds(15));
            Assert.IsType<OkObjectResult>(await second.Activate(secondRequest));
        }
        finally
        {
            barrier.Resume.TrySetResult();
            await pending.WaitAsync(TimeSpan.FromSeconds(15));
            if (quotaChange != null)
                await quotaChange.WaitAsync(TimeSpan.FromSeconds(15));
        }
        Assert.Equal(1, barrier.MatchingQueryCount);
        Assert.IsType<BadRequestObjectResult>(await pending);
        await using var observed = await clean.CreateDbContextAsync();
        Assert.Equal(3, await observed.LicenseSeats.CountAsync(row => row.LicenseId == fixture.LicenseId && row.IsActive));
        var rows = await observed.LicenseHistories.Where(row => row.LicenseId == fixture.LicenseId
            && row.Action == "ACTIVATION_DECISION_V1").ToListAsync();
        Assert.Equal(2, rows.Count);
        var decisions = rows.Select(row => System.Text.Json.JsonSerializer.Deserialize<LicenseDecisionHistory>(row.Details!,
            new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!).ToArray();
        var refusal = Assert.Single(decisions, row => row.Outcome == "refused");
        Assert.Equal(firstRequest.HardwareId, refusal.SubmittedHardwareId);
        Assert.Equal(2, refusal.Snapshot.ActiveSeats);
        Assert.Equal(2, refusal.Snapshot.SeatLimit);
        Assert.Equal("hardware_lock_observation", refusal.Snapshot.ObservationGuarantee);
        Assert.DoesNotContain(refusal.Snapshot.ActiveSeatDetails!, seat => seat.HardwareId == secondRequest.HardwareId);
        Assert.Equal(secondRequest.HardwareId, Assert.Single(decisions, row => row.Outcome == "accepted").SubmittedHardwareId);
    }

    /// <summary>Creates a controller for one caller-owned scope, with loopback synthetic HTTP context and no middleware/background side effects.</summary>
    private static ActivationController Tkt976_CreateDirectLegacyController(IServiceProvider services)
    {
        var controller = ActivatorUtilities.CreateInstance<ActivationController>(services);
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { RequestServices = services }
        };
        controller.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
        return controller;
    }

    /// <summary>Creates isolated contexts that share only this test's single quota barrier; callers dispose all contexts.</summary>
    private sealed class Tkt976LegacyBarrierFactory(string connection, Tkt976LegacyQuotaBarrier barrier) : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Allocates one synthetic PostgreSQL context with the task-owned interceptor.</summary>
        public LicenseDbContext CreateDbContext() => new(new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connection).AddInterceptors(barrier).Options);
        /// <summary>Honors pre-allocation cancellation and returns a new caller-owned context.</summary>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(CreateDbContext());
        }
    }

    /// <summary>Pauses exactly one already-executed active-seat query for one synthetic licence; never alters SQL, rows or locks.</summary>
    private sealed class Tkt976LegacyQuotaBarrier(Guid licenseId) : DbCommandInterceptor
    {
        /// <summary>Signals the first matching statement has obtained its PostgreSQL snapshot.</summary>
        internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>Caller must release in finally; no unrelated request uses this barrier.</summary>
        internal TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>Atomic one-shot flag prevents startup or later history queries from blocking again.</summary>
        private int _entered;
        /// <summary>Counts matching predicate reads so history cannot silently reread the quota.</summary>
        internal int MatchingQueryCount => Volatile.Read(ref _entered);
        /// <summary>Waits at most fifteen seconds after the target predicate executes, retaining its original result reader unchanged.</summary>
        public override async ValueTask<System.Data.Common.DbDataReader> ReaderExecutedAsync(
            System.Data.Common.DbCommand command, CommandExecutedEventData eventData,
            System.Data.Common.DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("WHERE l.\"LicenseId\" =", StringComparison.Ordinal)
                && command.CommandText.Contains("AND l.\"IsActive\"", StringComparison.Ordinal)
                // The earlier existing-seat lookup has the same licence/active predicates
                // plus an HWID predicate and LIMIT. Only pause the complete quota result.
                && !command.CommandText.Contains("AND l.\"HardwareId\" =", StringComparison.Ordinal)
                && !command.CommandText.Contains("LIMIT", StringComparison.Ordinal)
                && command.Parameters.Cast<System.Data.Common.DbParameter>().Any(parameter => Equals(parameter.Value, licenseId))
                && Interlocked.Increment(ref _entered) == 1)
            {
                Reached.TrySetResult();
                await Resume.Task.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            }
            return result;
        }
    }

    /// <summary>Proves direct and offline refusal persistence faults retain correlation/security headers and never advertise a business refusal as a confirmed HTTP500 result.</summary>
    /// <param name="offline">Selects the real administrator offline wrapper, which maps a core quota refusal to HTTP403.</param>
    /// <param name="mode">One bounded synthetic persistence fault, post-decision client cancellation, or normal refusal.</param>
    /// <remarks>Every fixture has its own product secret and licence. No real configuration is read. All business tables must remain unchanged; commit acknowledgement loss is distinguished from rollback by an independent observer.</remarks>
    [Theory]
    [InlineData(false, "none")]
    [InlineData(true, "none")]
    [InlineData(false, "insert")]
    [InlineData(true, "insert")]
    [InlineData(false, "cancel-after")]
    [InlineData(true, "cancel-after")]
    [InlineData(false, "host-stop")]
    [InlineData(true, "host-stop")]
    [InlineData(false, "timeout")]
    [InlineData(true, "timeout")]
    [InlineData(false, "commit-before")]
    [InlineData(true, "commit-before")]
    [InlineData(false, "commit-ack")]
    [InlineData(true, "commit-ack")]
    public async Task Tkt976_Legacy_FaultsPreserveHeadersAndActualOfflineStatus(bool offline, string mode)
    {
        var connections = await ProvisionAsync();
        var clean = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        await Tkt976_FillMultiSeatCapacityAsync(clean, fixture.LicenseId);
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown);
        var database = new Tkt976FaultFactory(connections.App, fault);
        var syntheticSecret = "tkt976-offline-" + fixture.ProductId.ToString("N");
        ActivationController.ActivationRequest request;
        await using (var setup = await clean.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Product).Include(row => row.Type)
                .SingleAsync(row => row.Id == fixture.LicenseId);
            license.Product!.ApiSecret = syntheticSecret;
            license.AllowedVersions = "*";
            license.Type!.IsFree = false;
            setup.LicenseTypeCustomParams.Add(new LicenseTypeCustomParam
            {
                LicenseTypeId = license.LicenseTypeId, Key = "allowOffline", Name = "Synthetic offline", Value = "true"
            });
            await setup.SaveChangesAsync();
            request = new ActivationController.ActivationRequest
            {
                LicenseKey = license.LicenseKey, AppName = license.Product.Name,
                HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant(),
                AppVersion = fixture.Version, CustomerEmail = license.CustomerEmail
            };
        }
        using var host = Tkt976_CreateLegacyHost(database);
        _ = host.Services;
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        var confirmed = mode is "none" or "cancel-after";
        using (var scope = host.Services.CreateScope())
        {
            var controller = ActivatorUtilities.CreateInstance<ActivationController>(scope.ServiceProvider,
                new Tkt976HostLifetime(shutdown));
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    RequestServices = scope.ServiceProvider, RequestAborted = requestCancellation.Token,
                    TraceIdentifier = "tkt976-correlation"
                }
            };
            controller.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
            controller.Request.Headers["X-Admin-Secret"] = syntheticSecret;
            controller.Response.Headers["X-Request-Id"] = "tkt976-request";
            controller.Response.Headers["X-Content-Type-Options"] = "nosniff";
            fault.Armed = true;
            var response = offline
                ? await controller.ActivateOffline(new ActivationController.OfflineActivationRequest
                {
                    LicenseKey = request.LicenseKey, HardwareId = request.HardwareId,
                    OfflineRequestCode = "ABCD-EF01-2345-6789"
                })
                : await controller.Activate(request);
            var result = Assert.IsAssignableFrom<ObjectResult>(response);
            Assert.Equal(confirmed ? (offline ? 403 : 400) : 500, result.StatusCode);
            Assert.Equal("tkt976-correlation", controller.Response.Headers["X-SoftLicence-Correlation-Id"].ToString());
            Assert.Equal("tkt976-request", controller.Response.Headers["X-Request-Id"].ToString());
            Assert.Equal("nosniff", controller.Response.Headers["X-Content-Type-Options"].ToString());
            if (!confirmed)
            {
                Assert.False(controller.Response.Headers.ContainsKey("X-SoftLicence-Error-Code"));
                Assert.False(controller.Response.Headers.ContainsKey("X-SoftLicence-Error-Contract"));
                Assert.False(controller.HttpContext.Items.ContainsKey(LogKeys.ResultStatusOverride));
                var body = System.Text.Json.JsonSerializer.Serialize(result.Value);
                Assert.DoesNotContain("SEAT_LIMIT", body);
                Assert.DoesNotContain(request.LicenseKey, body);
                Assert.DoesNotContain("INSERT", body);
                if (offline) Assert.Contains("offline_activation_failed", body);
            }
            if (mode == "cancel-after") Assert.True(requestCancellation.IsCancellationRequested);
        }
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var observed = await clean.CreateDbContextAsync();
        var rows = await observed.LicenseHistories.Where(row => row.LicenseId == fixture.LicenseId).ToListAsync();
        Assert.Equal(confirmed || mode == "commit-ack" ? 1 : 0, rows.Count);
        if (rows.Count == 1)
        {
            var decision = System.Text.Json.JsonSerializer.Deserialize<LicenseDecisionHistory>(rows[0].Details!,
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!;
            Assert.Equal("SEAT_LIMIT", decision.Code);
            Assert.Equal(offline ? 403 : 400, decision.HttpStatus);
            Assert.Equal("hardware_lock_observation", decision.Snapshot.ObservationGuarantee);
        }
    }

    /// <summary>Proves independent legacy quota refusals retain separate observations and preserve the existing business response and database.</summary>
    /// <remarks>The controller is invoked directly to exclude access-log middleware from business fingerprints. The real dependency graph uses synthetic database data, an ephemeral protector and a fixed signer; application background jobs are disabled in this fixture only.</remarks>
    [Fact]
    public async Task Tkt976_Legacy_IndependentQuotaRefusals_PersistObservedFactsWithoutBusinessChanges()
    {
        var connections = await ProvisionAsync();
        var database = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(database);
        await Tkt976_FillMultiSeatCapacityAsync(database, fixture.LicenseId);
        using var host = Tkt976_CreateLegacyHost(database);
        ActivationController.ActivationRequest request;
        await using (var setup = await database.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Product).SingleAsync(row => row.Id == fixture.LicenseId);
            request = new ActivationController.ActivationRequest
            {
                LicenseKey = license.LicenseKey, AppName = license.Product!.Name,
                HardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant(),
                AppVersion = fixture.Version, CustomerEmail = license.CustomerEmail
            };
        }
        // Build the host before fingerprinting; no startup artifact is attributed to a refusal.
        _ = host.Services;
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var scope = host.Services.CreateScope();
            var controller = ActivatorUtilities.CreateInstance<ActivationController>(scope.ServiceProvider);
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { RequestServices = scope.ServiceProvider }
            };
            controller.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
            var response = await controller.Activate(request);
            Assert.IsType<BadRequestObjectResult>(response);
            Assert.Equal("SEAT_LIMIT", controller.Response.Headers["X-SoftLicence-Error-Code"].ToString());
        }
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var observed = await database.CreateDbContextAsync();
        var decisions = await observed.LicenseHistories.AsNoTracking()
            .Where(row => row.LicenseId == fixture.LicenseId && row.Action == "ACTIVATION_DECISION_V1").ToListAsync();
        Assert.Equal(2, decisions.Count);
        Assert.Equal(2, decisions.Select(row => row.DecisionOperationId).Distinct(StringComparer.Ordinal).Count());
        foreach (var row in decisions)
        {
            var decision = System.Text.Json.JsonSerializer.Deserialize<LicenseDecisionHistory>(row.Details!,
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!;
            Assert.Equal("SEAT_LIMIT", decision.Code);
            Assert.Equal(400, decision.HttpStatus);
            Assert.Equal("hardware_lock_observation", decision.Snapshot.ObservationGuarantee);
            Assert.Equal(request.HardwareId, decision.SubmittedHardwareId);
            Assert.Null(decision.CorrelatedHardwareId);
            Assert.Equal(2, decision.Snapshot.ActiveSeats);
            Assert.Equal(2, decision.Snapshot.SeatLimit);
        }
    }

    /// <summary>Builds the real controller dependency graph with all persistence and generated files confined to this task's synthetic harness.</summary>
    /// <param name="database">Application-role factory for the current task-owned PostgreSQL container.</param>
    /// <returns>Caller-owned test host. No real HTTP listener or notification transport is used. Framework key-manager startup may create synthetic protection files only inside the task artifact root; never copy them into a candidate commit.</returns>
    private static WebApplicationFactory<Program> Tkt976_CreateLegacyHost(IDbContextFactory<LicenseDbContext> database,
        Action<string, string>? notificationObserver = null, Action<IServiceCollection>? configureTestServices = null)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !Directory.Exists(Path.Combine(root.FullName, "src", "SoftLicence.Server")))
            root = root.Parent;
        if (root == null)
            throw new InvalidOperationException("The synthetic host requires a resolved SoftLicence repository artifact root.");
        var contentRoot = Path.Combine(root.FullName, "artifacts", "tkt976-validation", "legacy-web-host");
        Directory.CreateDirectory(contentRoot);
        var notifier = new Mock<NotificationService>(database,
            Mock.Of<ILogger<NotificationService>>(), Mock.Of<IHttpClientFactory>());
        notifier.Setup(service => service.Notify(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()))
            .Callback<string, string, string, object?>((trigger, _, message, _) => notificationObserver?.Invoke(trigger, message));
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            // Content-root isolation prevents appsettings/keys from another checkout becoming
            // this fixture's configuration or output; all licensing data comes from PostgreSQL.
            builder.UseContentRoot(contentRoot);
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "tkt976-unused-synthetic-global");
            builder.UseSetting("AdminSettings:AllowedIps", "127.0.0.1");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddSingleton<IDbContextFactory<LicenseDbContext>>(database);
                services.AddScoped(provider => provider.GetRequiredService<IDbContextFactory<LicenseDbContext>>().CreateDbContext());
                services.RemoveAll<NotificationService>();
                services.AddSingleton(notifier.Object);
                services.RemoveAll<ISignedLicenseFileService>();
                services.AddSingleton<ISignedLicenseFileService>(new FixedSignedLicenseFileService());
                services.RemoveAll<IDataProtectionProvider>();
                services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                // Preserve the framework's test server lifecycle; only application workers
                // that could perform unrelated cleanup or outbound delivery are removed.
                foreach (var worker in services.Where(descriptor => descriptor.ServiceType == typeof(IHostedService)
                    && descriptor.ImplementationType?.Namespace?.StartsWith("SoftLicence.", StringComparison.Ordinal) == true).ToArray())
                    services.Remove(worker);
                configureTestServices?.Invoke(services);
            });
        });
    }
}

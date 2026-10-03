using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises targeted administrator decision reads through the real local HTTP/authentication stack and synthetic PostgreSQL.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>The existing success notification references an already committed event; refusal creates no new notification channel.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Tkt976_Notification_OnlyAcceptedCommittedDecisionIsEnriched(bool allowSeat)
    {
        var connections = await ProvisionAsync();
        var database = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(database);
        if (!allowSeat)
            await Tkt976_FillMultiSeatCapacityAsync(database, fixture.LicenseId);
        SoftLicence.Server.Controllers.ActivationController.ActivationRequest request;
        await using (var setup = await database.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Product).SingleAsync(row => row.Id == fixture.LicenseId);
            license.MaxSeats = 2;
            request = new() { LicenseKey = license.LicenseKey, AppName = license.Product!.Name,
                HardwareId = "1234567890ABCDEF", AppVersion = fixture.Version, CustomerEmail = license.CustomerEmail };
            await setup.SaveChangesAsync();
        }
        var messages = new List<string>();
        using var host = Tkt976_CreateLegacyHost(database, (trigger, message) =>
        {
            if (trigger != NotificationService.Triggers.LicenseActivated) return;
            using var committed = database.CreateDbContext();
            Assert.True(committed.LicenseHistories.Any(row => row.LicenseId == fixture.LicenseId
                && row.Action == "ACTIVATION_DECISION_V1"));
            messages.Add(message);
        });
        using var scope = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.CreateScope(host.Services);
        var controller = Tkt976_CreateDirectLegacyController(scope.ServiceProvider);
        var response = await controller.Activate(request);
        if (!allowSeat)
        {
            Assert.IsType<Microsoft.AspNetCore.Mvc.BadRequestObjectResult>(response);
            Assert.Empty(messages);
            return;
        }
        Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(response);
        var notification = Assert.Single(messages);
        await using var observed = await database.CreateDbContextAsync();
        var entry = await observed.LicenseHistories.SingleAsync(row => row.LicenseId == fixture.LicenseId
            && row.Action == "ACTIVATION_DECISION_V1");
        Assert.Contains($"/licenses?licenseId={fixture.LicenseId:D}#history-{entry.Id:D}", notification);
        Assert.Contains("HWID soumis: " + request.HardwareId, notification);
        Assert.Contains("HWID résolu: " + request.HardwareId, notification);
        Assert.DoesNotContain(request.LicenseKey, notification);
    }

    /// <summary>Requires authentication, exact targeting and product ownership while returning decision facts without licence keys or invented correlations.</summary>
    /// <remarks>Keys and history are synthetic. The API may update its existing key-usage audit, but must never mutate licensing state. The task-owned test host disables external notification delivery and application background jobs.</remarks>
    [Fact]
    public async Task Tkt976_DecisionRead_HttpScopeAndExactTargets_DoNotLeakOtherProduct()
    {
        var connections = await ProvisionAsync();
        var database = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(database);
        var other = await SeedDistributionAuthorityWithoutBindingAsync(database);
        var syntheticKey = "tkt976-analytics-" + Guid.NewGuid().ToString("N");
        const string hardwareId = "ABCDEF0123456789";
        const string operationId = "tkt976.request:CaseSensitive";
        await using (var seed = await database.CreateDbContextAsync())
        {
            seed.AnalyticsApiKeys.Add(new AnalyticsApiKey
            {
                ProductId = fixture.ProductId, Name = "Synthetic decision read",
                Prefix = AnalyticsApiKeyAuthService.BuildPrefix(syntheticKey),
                KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(syntheticKey),
                Scopes = AnalyticsApiKeyScopes.TelemetryRead, ScopeKind = AnalyticsApiKeyScopeKinds.Product
            });
            foreach (var identity in new[] { fixture, other })
            {
                var license = await seed.Licenses.Include(row => row.Type).Include(row => row.Seats)
                    .SingleAsync(row => row.Id == identity.LicenseId);
                var decision = new LicenseDecisionHistory(1, "legacy_activation", operationId,
                    "refused", "SEAT_LIMIT", null, 400, hardwareId, hardwareId, null, "provider_direct",
                    LicenseDecisionHistoryWriter.CaptureObserved(license, DateTimeOffset.UtcNow, hardwareId), identity.Version);
                await LicenseDecisionHistoryWriter.AddAsync(seed, decision, "synthetic_admin_read",
                    identity.ProductId.ToString("D"), DateTimeOffset.UtcNow, CancellationToken.None);
            }
            await seed.SaveChangesAsync();
        }
        using var host = Tkt976_CreateLegacyHost(database);
        using var client = host.CreateClient();
        const string route = "/api/analytics/support/license-decisions";
        using (var anonymous = await client.GetAsync(route + "?licenseId=" + fixture.LicenseId.ToString("D")))
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        client.DefaultRequestHeaders.Add("X-Analytics-Key", syntheticKey);
        using (var untargeted = await client.GetAsync(route))
            Assert.Equal(HttpStatusCode.BadRequest, untargeted.StatusCode);
        using (var forbidden = await client.GetAsync(route + "?productId=" + other.ProductId.ToString("D")
            + "&licenseId=" + other.LicenseId.ToString("D")))
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        foreach (var selector in new[]
        {
            "licenseId=" + fixture.LicenseId.ToString("D"),
            "hardwareId=" + hardwareId,
            "requestId=" + Uri.EscapeDataString(operationId)
        })
        {
            using var response = await client.GetAsync(route + "?" + selector);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync();
            using var json = JsonDocument.Parse(body);
            var entry = Assert.Single(json.RootElement.GetProperty("items").EnumerateArray());
            Assert.Equal(fixture.LicenseId.ToString("D"), entry.GetProperty("licenseId").GetString());
            Assert.Equal("SEAT_LIMIT", entry.GetProperty("decision").GetProperty("code").GetString());
            Assert.Equal(JsonValueKind.Null, entry.GetProperty("decision").GetProperty("correlatedHardwareId").ValueKind);
            Assert.DoesNotContain("licenseKey", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(other.LicenseId.ToString("D"), body);
        }
        using var wrongCase = await client.GetAsync(route + "?requestId=" + Uri.EscapeDataString(operationId.ToLowerInvariant()));
        Assert.Equal(HttpStatusCode.OK, wrongCase.StatusCode);
        using var wrongJson = JsonDocument.Parse(await wrongCase.Content.ReadAsStringAsync());
        Assert.Empty(wrongJson.RootElement.GetProperty("items").EnumerateArray());
        foreach (var invalid in new[] { "take=0", "take=201", "offset=-1", "offset=10001", "hardwareId=%20HWID", "requestId=" + new string('x', 201) })
        {
            using var rejected = await client.GetAsync(route + "?licenseId=" + fixture.LicenseId.ToString("D") + "&" + invalid);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        }
        using var intersected = await client.GetAsync(route + "?licenseId=" + other.LicenseId.ToString("D") + "&requestId=" + Uri.EscapeDataString(operationId));
        Assert.Equal(HttpStatusCode.OK, intersected.StatusCode);
        using var intersectedJson = JsonDocument.Parse(await intersected.Content.ReadAsStringAsync());
        Assert.Empty(intersectedJson.RootElement.GetProperty("items").EnumerateArray());
    }
}

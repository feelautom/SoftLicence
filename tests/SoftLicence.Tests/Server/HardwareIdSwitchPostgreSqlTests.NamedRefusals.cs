using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-004085 on PostgreSQL through the real HTTP pipeline: a legitimate refusal reaches the desktop client as a named
/// code with an English message and a correlation reference, never as an empty HTTP 500 or a fake server outage.
/// </summary>
/// <remarks>
/// The trigger cases install a test-only <c>BEFORE UPDATE</c> trigger on <c>LicenseSeats</c> that raises the exact
/// SQLSTATE and message of the production assignment trigger when a seat is released. Reproducing a real quarantine
/// through the product would need a migration-era graph; the exact production raises are proven separately by
/// <c>NamedAssignmentRefusalPostgreSqlTests</c>. Each test owns its cloned database (see <c>Provision</c>), so the
/// trigger never leaks into another class.
/// </remarks>
public sealed partial class HardwareIdSwitchPostgreSqlTests
{
    /// <summary>A quarantine refusal of the trigger at deactivation is a named 409, and the seat stays active.</summary>
    [Fact]
    public async Task NamedRefusal_DeactivateRefusedByQuarantineTrigger_IsReconciliationRequired()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        await InstallSeatReleaseRaiseAsync(provision.ConnectionString, "23514", "commercial assignment remains quarantined");

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = key, HardwareId = OldHardwareId, AppName, Source = "settings_button"
        });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(AssignmentRefusals.ReconciliationRequiredCode, body.RootElement.GetProperty("error").GetString());
        Assert.Equal("enrollment_quarantined", body.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal(AssignmentRefusals.ReconciliationRequiredMessage, body.RootElement.GetProperty("message").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("correlationId").GetString()));
        Assert.True((await SeatsAsync(provision.ConnectionString)).Single().IsActive);
    }

    /// <summary>A concurrent-claimant refusal at deactivation is a named 409 with <c>Retry-After</c>.</summary>
    [Fact]
    public async Task NamedRefusal_DeactivateRefusedByConcurrentClaimant_IsBusyWithRetryAfter()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        await InstallSeatReleaseRaiseAsync(provision.ConnectionString, "40001", "concurrent commercial seat claimant");

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = key, HardwareId = OldHardwareId, AppName, Source = "settings_button"
        });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("5", response.Headers.RetryAfter?.ToString());
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(AssignmentRefusals.BusyCode, body.RootElement.GetProperty("error").GetString());
        Assert.Equal("concurrent_seat_claimant", body.RootElement.GetProperty("reasonCode").GetString());
        Assert.True((await SeatsAsync(provision.ConnectionString)).Single().IsActive);
    }

    /// <summary>
    /// An unexpected database error that escapes the action is answered by the API safety net with a JSON body and a
    /// correlation reference instead of an empty HTTP 500; the database error text is never returned.
    /// </summary>
    [Fact]
    public async Task NamedRefusal_DeactivateUnexpectedDatabaseError_ReturnsJsonInternalError()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        await InstallSeatReleaseRaiseAsync(provision.ConnectionString, "P0001", "tkt004085 simulated failure");

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = key, HardwareId = OldHardwareId, AppName, Source = "settings_button"
        });

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var text = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("tkt004085", text, StringComparison.Ordinal);
        using var body = JsonDocument.Parse(text);
        Assert.Equal("internal_error", body.RootElement.GetProperty("error").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("correlationId").GetString()));
        Assert.True((await SeatsAsync(provision.ConnectionString)).Single().IsActive);
    }

    /// <summary>
    /// A key activation on a machine excluded from the licence returns the named 403 <c>license_hardware_excluded</c>
    /// already used by the Runtime routes, instead of the empty HTTP 500 that lost the code.
    /// </summary>
    [Fact]
    public async Task NamedRefusal_KeyActivationOnExcludedMachine_IsLicenseHardwareExcluded()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        await using (var setup = CreateDb(provision.ConnectionString))
        {
            var license = await setup.Licenses.SingleAsync();
            setup.LicenseHardwareExclusions.Add(new LicenseHardwareExclusion
            {
                Id = Guid.NewGuid(), ProductId = license.ProductId, LicenseId = license.Id,
                HardwareId = OldHardwareId, CreatedAtUtc = DateTime.UtcNow, CreatedByRequestId = Guid.NewGuid(),
                CreatedByClientId = "tkt004085-admin", CreatedByRequestFingerprintSha256 = new string('a', 64),
                Actor = "admin", ReleaseOutcome = "none"
            });
            await setup.SaveChangesAsync();
        }

        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = key, HardwareId = OldHardwareId, AppName
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(body.RootElement.GetProperty("isSuccess").GetBoolean());
        Assert.Equal(LicenseHardwareExclusionChecker.PublicErrorCode, body.RootElement.GetProperty("errorCode").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("message").GetString()));
        Assert.Equal(LicenseHardwareExclusionChecker.PublicErrorCode,
            Assert.Single(response.Headers.GetValues("X-SoftLicence-Error-Code")));
    }

    /// <summary>
    /// Installs, in the test's own cloned database, a trigger that raises <paramref name="message"/> with
    /// <paramref name="sqlState"/> whenever an active seat is released, like the production assignment trigger does
    /// when it refuses the release. It fires inside <c>SeatRuntimeReleaseAuthority.CompleteAsync</c>.
    /// </summary>
    /// <param name="connectionString">Administrator connection of the cloned database.</param>
    /// <param name="sqlState">Five-character SQLSTATE to raise.</param>
    /// <param name="message">Exact primary message to raise.</param>
    private static async Task InstallSeatReleaseRaiseAsync(string connectionString, string sqlState, string message)
    {
        // A function body cannot take bind parameters; both values are fixed test literals without quotes.
        Assert.DoesNotContain('\'', sqlState + message);
        var sql = """
            CREATE FUNCTION public.tkt004085_raise_on_release() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION USING ERRCODE = '@state', MESSAGE = '@message';
            END $$;
            CREATE TRIGGER tkt004085_raise_on_release
            BEFORE UPDATE ON public."LicenseSeats"
            FOR EACH ROW WHEN (OLD."IsActive" AND NOT NEW."IsActive")
            EXECUTE FUNCTION public.tkt004085_raise_on_release();
            """.Replace("@state", sqlState, StringComparison.Ordinal).Replace("@message", message, StringComparison.Ordinal);
        await using var db = CreateDb(connectionString);
        await db.Database.ExecuteSqlRawAsync(sql);
    }
}

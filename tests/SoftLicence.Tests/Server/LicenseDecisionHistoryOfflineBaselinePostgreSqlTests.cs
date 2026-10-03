using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Compares the exact3742 controller against976 using identical synthetic database clones and unchanged ban maintenance dependencies.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Proves expired/live ban maintenance is unchanged for refusal, success and failed history persistence.</summary>
    /// <remarks>The generated controller and its cleanup dependency both come from 3742d1d9; only type names and required test-project imports differ. Mixing the old controller transaction protocol with the current cleanup lease would invalidate the baseline. Each baseline database clones the fully seeded candidate database before either call; UUIDs and business values are identical. Clones remain until the owning ephemeral container is removed, with no database deletion during tests. Fingerprints omit history and explicitly named occurrence timestamps only, never identities, state or counters.</remarks>
    [Theory]
    [InlineData(true, "refusal")]
    [InlineData(false, "refusal")]
    [InlineData(true, "success")]
    [InlineData(false, "success")]
    [InlineData(true, "insert")]
    [InlineData(false, "insert")]
    public async Task Tkt976_Offline_Baseline3742_PreservesAutonomousBanMaintenance(bool expired, string mode)
    {
        var connections = await ProvisionAsync();
        var clean = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(clean);
        var secret = "tkt976-baseline-" + fixture.ProductId.ToString("N");
        string licenseKey;
        Guid initialAuthorityVersion;
        var banId = Guid.NewGuid();
        await using (var seed = await clean.CreateDbContextAsync())
        {
            var license = await seed.Licenses.Include(row => row.Product).Include(row => row.Type)
                .SingleAsync(row => row.Id == fixture.LicenseId);
            licenseKey = license.LicenseKey;
            license.Product!.ApiSecret = secret;
            license.Type!.IsFree = false;
            license.AllowedVersions = "*";
            if (mode == "success") seed.LicenseTypeCustomParams.Add(new LicenseTypeCustomParam
            { LicenseTypeId = license.LicenseTypeId, Key = "allowOffline", Name = "Synthetic", Value = "true" });
            seed.BannedHardwareIds.Add(new BannedHardwareId
            {
                Id = banId, ProductId = fixture.ProductId, HardwareId = fixture.HardwareId,
                IsActive = true, ExpiresAt = DateTime.UtcNow.AddDays(expired ? -1 : 1), Reason = "Synthetic baseline"
            });
            await seed.SaveChangesAsync();
            await seed.Entry(license).ReloadAsync();
            initialAuthorityVersion = license.AuthorityVersion;
        }
        var clone = await Tkt976_CloneBaselineDatabaseAsync(connections);
        var baselineObserver = new Tkt976EarlySqlObserver();
        using var baselineHost = Tkt976_CreateLegacyHost(new Tkt976EarlyFactory(clone, baselineObserver),
            configureTestServices: services => services.AddScoped<SoftLicence.Server.Services.Tkt976BaselineSeatCleanupService>());
        using var requestCancellation = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        var fault = new Tkt976FaultState(mode, requestCancellation, shutdown);
        var observer = new Tkt976EarlySqlObserver();
        using var candidateHost = Tkt976_CreateLegacyHost(new Tkt976EarlyFactory(connections.App, observer, fault));
        int? baselineStatus;
        using (var scope = baselineHost.Services.CreateScope())
        {
            var baseline = ActivatorUtilities.CreateInstance<Tkt976BaselineActivationController>(scope.ServiceProvider);
            baseline.ControllerContext = new ControllerContext
            { HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = scope.ServiceProvider } };
            baseline.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
            baseline.Request.Headers["X-Admin-Secret"] = secret;
            baselineObserver.Armed = true;
            baselineStatus = Assert.IsAssignableFrom<ObjectResult>(await baseline.ActivateOffline(
                new Tkt976BaselineActivationController.OfflineActivationRequest
                { LicenseKey = licenseKey, HardwareId = fixture.HardwareId, OfflineRequestCode = "ABCD-EF01-2345-6789" })).StatusCode;
        }
        using (var scope = candidateHost.Services.CreateScope())
        {
            var candidate = Tkt976_CreateDirectLegacyController(scope.ServiceProvider);
            candidate.Request.Headers["X-Admin-Secret"] = secret;
            fault.Armed = true;
            observer.Armed = true;
            var result = Assert.IsAssignableFrom<ObjectResult>(await candidate.ActivateOffline(
                new ActivationController.OfflineActivationRequest
                { LicenseKey = licenseKey, HardwareId = fixture.HardwareId, OfflineRequestCode = "ABCD-EF01-2345-6789" }));
            Assert.Equal(mode == "insert" ? 500 : baselineStatus, result.StatusCode);
            Assert.Equal(expired && mode == "success" ? 200 : 403, baselineStatus);
        }
        Assert.Equal(await Tkt976_ComparableBusinessFingerprintAsync(clone),
            await Tkt976_ComparableBusinessFingerprintAsync(connections.App));
        await using var observed = await clean.CreateDbContextAsync();
        await using var baselineObserved = await new TestDbFactory(clone).CreateDbContextAsync();
        var baselineVersion = (await baselineObserved.Licenses.SingleAsync(row => row.Id == fixture.LicenseId)).AuthorityVersion;
        var candidateVersion = (await observed.Licenses.SingleAsync(row => row.Id == fixture.LicenseId)).AuthorityVersion;
        Assert.NotEqual(Guid.Empty, candidateVersion);
        Assert.Equal(baselineVersion != initialAuthorityVersion, candidateVersion != initialAuthorityVersion);
        Assert.Equal(baselineObserver.BusinessWriteTables.Where(table => table != "LicenseHistories").ToArray(),
            observer.BusinessWriteTables.Where(table => table != "LicenseHistories").ToArray());
        Assert.Equal(!expired, (await observed.BannedHardwareIds.SingleAsync(row => row.Id == banId)).IsActive);
        Assert.Equal(mode == "insert" ? 0 : 1, await observed.LicenseHistories.CountAsync(row =>
            row.LicenseId == fixture.LicenseId && row.Action == "ACTIVATION_DECISION_V1"));
        if (mode != "success")
            Assert.All(observer.BusinessWriteTables, table => Assert.Contains(table, new[] { "BannedHardwareIds", "LicenseHistories" }));
    }

    /// <summary>Clones a closed synthetic harness database through its task-owned administrator, preserving exact fixture IDs and values.</summary>
    /// <remarks>Only pools for the two exact fixture connection strings are closed. Database names are generated ASCII and identifier-quoted. No existing database, volume or other service is removed; the caller's authorized container finally owns cleanup. Six clones fit the768MiB monitored harness budget.</remarks>
    private static async Task<string> Tkt976_CloneBaselineDatabaseAsync((string Admin, string App) connections)
    {
        using (var appPool = new NpgsqlConnection(connections.App)) NpgsqlConnection.ClearPool(appPool);
        using (var adminPool = new NpgsqlConnection(connections.Admin)) NpgsqlConnection.ClearPool(adminPool);
        var source = new NpgsqlConnectionStringBuilder(connections.Admin);
        var databaseName = "tkt976_baseline_" + Guid.NewGuid().ToString("N");
        var control = new NpgsqlConnectionStringBuilder(connections.Admin) { Database = "postgres", Pooling = false };
        await using var connection = new NpgsqlConnection(control.ConnectionString);
        await connection.OpenAsync();
        var quotedSource = "\"" + (source.Database ?? throw new InvalidOperationException("Synthetic database required."))
            .Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        await using var command = new NpgsqlCommand("CREATE DATABASE \"" + databaseName + "\" TEMPLATE " + quotedSource, connection);
        await command.ExecuteNonQueryAsync();
        return new NpgsqlConnectionStringBuilder(connections.App) { Database = databaseName }.ConnectionString;
    }

    /// <summary>Hashes all business values except history and three occurrence timestamps that naturally differ between sequential baseline and candidate calls.</summary>
    /// <remarks>The timestamp exclusions are Licenses.ActivationDate, LicenseSeats.LastCheckInAt and RuntimeEnrollmentAuthorityStates.UpdatedAtUtc. The939 trigger generates a random Licenses.AuthorityVersion on every update: its changed-versus-initial state and exact business DML sequence are asserted separately. All business IDs, state, ownership, seat counts and epochs remain compared. No rows or parameter values are printed or changed.</remarks>
    private static async Task<string[]> Tkt976_ComparableBusinessFingerprintAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        var tables = new List<string>();
        await using (var catalog = new NpgsqlCommand("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'LicenseHistories' ORDER BY table_name", connection))
        await using (var reader = await catalog.ExecuteReaderAsync())
            while (await reader.ReadAsync()) tables.Add(reader.GetString(0));
        var result = new List<string>();
        foreach (var table in tables)
        {
            var projection = "to_jsonb(t)" + (table switch
            {
                "Licenses" => " - 'ActivationDate' - 'AuthorityVersion'",
                "LicenseSeats" => " - 'LastCheckInAt'",
                "RuntimeEnrollmentAuthorityStates" => " - 'UpdatedAtUtc'",
                _ => string.Empty
            });
            var quoted = "\"" + table.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
            await using var command = new NpgsqlCommand("SELECT md5(COALESCE(jsonb_agg(" + projection
                + " ORDER BY (" + projection + ")::text)::text,'[]')) FROM public." + quoted + " t", connection);
            result.Add(table + ":" + (string)(await command.ExecuteScalarAsync())!);
        }
        return result.ToArray();
    }
}

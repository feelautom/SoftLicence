using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class HardwareIdSwitchPostgreSqlTests
{
    private const string AutoUuidA = "11111111-2222-4333-8444-555555555555";
    private const string AutoUuidB = "22222222-3333-4444-8555-666666666666";

    /// <summary>The authority reload must not discard the customer identity already validated by reseller activation.</summary>
    [Fact]
    public async Task AutoSeatSwitch_Classic_PreservesValidatedPendingResellerIdentity()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        await using (var setup = CreateDb(provision.ConnectionString))
        {
            setup.ResellerPartners.Add(new ResellerPartner { Code = "AUTO-SYNTHETIC", Name = "Synthetic reseller", IsActive = true });
            var license = await setup.Licenses.SingleAsync();
            license.PartnerCode = "AUTO-SYNTHETIC";
            license.CustomerEmail = string.Empty;
            license.CustomerName = string.Empty;
            await setup.SaveChangesAsync();
        }
        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = key, HardwareId = MachineIdentity.FromUuid(AutoUuidB).HardwareId,
            AppName, SystemUuid = AutoUuidB, SdkVersion = "2.0.0",
            CustomerEmail = "synthetic@example.invalid", CustomerName = "Synthetic receiver"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using var db = CreateDb(provision.ConnectionString);
        var retained = await db.Licenses.SingleAsync();
        Assert.Equal("synthetic@example.invalid", retained.CustomerEmail);
        Assert.Equal("Synthetic receiver", retained.CustomerName);
        Assert.Single(await db.LicenseHistories.Where(row => row.Action == HistoryActions.UnlinkedApi).ToListAsync());
    }

    /// <summary>Reactivating the same historical seat does not charge a second change after its public deactivation exhausted quota.</summary>
    [Fact]
    public async Task AutoSeatSwitch_Classic_SameMachineReactivationAtExhaustedQuotaCostsZero()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 1, DateTime.UtcNow.AddDays(-10));
        var original = Assert.Single(await SeatsAsync(provision.ConnectionString));
        using var client = host.CreateClient();
        using var released = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = key, HardwareId = OldHardwareId, AppName
        });
        Assert.Equal(HttpStatusCode.OK, released.StatusCode);
        await using (var check = CreateDb(provision.ConnectionString))
            Assert.False((await check.LicenseSeats.SingleAsync()).IsActive);
        using var activated = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = key, HardwareId = OldHardwareId, AppName
        });
        Assert.Equal(HttpStatusCode.OK, activated.StatusCode);
        using var body = JsonDocument.Parse(await activated.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("licenseFile").GetString()));
        await using var db = CreateDb(provision.ConnectionString);
        await db.Database.OpenConnectionAsync();
        var seat = await db.LicenseSeats.SingleAsync();
        Assert.Equal(original.Id, seat.Id);
        Assert.Equal(original.FirstActivatedAt, seat.FirstActivatedAt);
        Assert.True(seat.IsActive);
        var license = await db.Licenses.Include(row => row.Type).SingleAsync();
        var quota = await SeatChangeQuota.GetStatusAsync(db, license,
            (await RuntimeEnrollmentService.DatabaseNowAsync(db, default)).UtcDateTime);
        Assert.Equal(1, quota.UsedToday);
        Assert.True(quota.IsExhausted);
        Assert.Equal(1, await db.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi));
    }

    /// <summary>Two HTTP activations actually wait together on the common barrier; only one can spend the final change.</summary>
    [Fact]
    public async Task AutoSeatSwitch_ClassicConcurrent_LastQuotaSlotHasOneWinner()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 1, DateTime.UtcNow.AddDays(-10));
        using var client = host.CreateClient();
        HttpResponseMessage? first = null;
        HttpResponseMessage? second = null;
        var errors = await AutomaticSeatSwitchConcurrencyProof.RunAsync(provision.ConnectionString,
            async () => first = await client.PostAsJsonAsync("/api/activation", AutoRequest(key, AutoUuidA)),
            async () => second = await client.PostAsJsonAsync("/api/activation", AutoRequest(key, AutoUuidB)));
        Assert.All(errors, Assert.Null);
        Assert.NotNull(first);
        Assert.NotNull(second);
        using (first)
        using (second)
        {
            Assert.Single(new[] { first, second }, response => response.StatusCode == HttpStatusCode.OK);
            var refused = Assert.Single(new[] { first, second }, response => response.StatusCode == HttpStatusCode.BadRequest);
            Assert.Equal("MAX_DAILY_DEACTIVATIONS_REACHED", refused.Headers.GetValues("X-SoftLicence-Error-Code").Single());
            await using var db = CreateDb(provision.ConnectionString);
            var active = await db.LicenseSeats.SingleAsync(row => row.IsActive);
            Assert.Equal(MachineIdentity.FromUuid(first.StatusCode == HttpStatusCode.OK ? AutoUuidA : AutoUuidB).HardwareId, active.HardwareId);
            Assert.Equal(1, await db.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi));
        }
    }

    /// <summary>A signer failure after release and persistence must roll back both seats and the counted event.</summary>
    [Fact]
    public async Task AutoSeatSwitch_Classic_SigningFailureRollsBackReleaseAndQuota()
    {
        await using var provision = await Provision.CreateAsync();
        using var sourceHost = CreateHost(provision.ConnectionString);
        var signer = new FailingAutoSigner();
        using var host = sourceHost.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<ISignedLicenseFileService>();
            services.AddSingleton<ISignedLicenseFileService>(signer);
        }));
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        var original = Assert.Single(await SeatsAsync(provision.ConnectionString));
        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", AutoRequest(key, AutoUuidB));
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(1, signer.Calls);
        await using var db = CreateDb(provision.ConnectionString);
        var retained = await db.LicenseSeats.SingleAsync();
        Assert.Equal(original.Id, retained.Id);
        Assert.Equal(original.FirstActivatedAt, retained.FirstActivatedAt);
        Assert.True(retained.IsActive);
        Assert.Null(retained.UnlinkedAt);
        Assert.False(await db.LicenseHistories.AnyAsync(row => row.Action == HistoryActions.UnlinkedApi));
    }

    /// <summary>Injects one deterministic signing failure after the activation transaction has written its candidate.</summary>
    private sealed class FailingAutoSigner : ISignedLicenseFileService
    {
        public int Calls { get; private set; }
        public string Generate(License license, string hardwareId, IReadOnlyDictionary<string, string>? featureOverride = null)
        {
            Calls++;
            throw new CryptographicException("Synthetic TKT-001510 signer failure.");
        }
    }

    /// <summary>Exercises the real HTTP signer and event quota across A-B-A-B and the refused fourth switch.</summary>
    [Fact]
    public async Task AutoSeatSwitch_Classic_ABAB_QuotaAndHistoryAreAtomic()
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        // Remove only synthetic setup before the first request: this licence starts unused.
        await using (var setup = CreateDb(provision.ConnectionString))
        {
            setup.LicenseSeats.RemoveRange(await setup.LicenseSeats.ToListAsync());
            var license = await setup.Licenses.SingleAsync();
            license.HardwareId = null;
            license.ActivationDate = null;
            await setup.SaveChangesAsync();
        }
        using var client = host.CreateClient();
        var sequence = new[] { AutoUuidA, AutoUuidA, AutoUuidB, AutoUuidA, AutoUuidB };
        var expectedChanges = new[] { 0, 0, 1, 2, 3 };
        var originalTimes = new Dictionary<Guid, DateTime>();
        for (var index = 0; index < sequence.Length; index++)
        {
            using var response = await client.PostAsJsonAsync("/api/activation", AutoRequest(key, sequence[index]));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("licenseFile").GetString()));
            await using var db = CreateDb(provision.ConnectionString);
            await db.Database.OpenConnectionAsync();
            var license = await db.Licenses.Include(row => row.Type).SingleAsync();
            var seats = await db.LicenseSeats.AsNoTracking().ToListAsync();
            Assert.Equal(MachineIdentity.FromUuid(sequence[index]).HardwareId, Assert.Single(seats, row => row.IsActive).HardwareId);
            Assert.Equal(expectedChanges[index], (await SeatChangeQuota.GetStatusAsync(db, license,
                (await RuntimeEnrollmentService.DatabaseNowAsync(db, default)).UtcDateTime)).UsedToday);
            Assert.Equal(expectedChanges[index], await db.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi));
            if (index >= 2)
            {
                var previousHardware = MachineIdentity.FromUuid(sequence[index - 1]).HardwareId;
                var released = Assert.Single(seats, row => row.HardwareId == previousHardware);
                var lastChange = await db.LicenseHistories.Where(row => row.Action == HistoryActions.UnlinkedApi)
                    .OrderByDescending(row => row.Timestamp).FirstAsync();
                Assert.Equal(released.UnlinkedAt, lastChange.Timestamp);
                Assert.Equal(AutomaticSeatSwitch.Source, lastChange.PerformedBy);
                Assert.Equal($"{AutomaticSeatSwitch.Source}: {previousHardware} -> {MachineIdentity.FromUuid(sequence[index]).HardwareId}; actor=Unknown",
                    lastChange.Details);
            }
            foreach (var seat in seats)
            {
                if (originalTimes.TryGetValue(seat.Id, out var first)) Assert.Equal(first, seat.FirstActivatedAt);
                else originalTimes.Add(seat.Id, seat.FirstActivatedAt);
                if (!seat.IsActive) Assert.NotNull(seat.UnlinkedAt);
            }
        }
        using var refused = await client.PostAsJsonAsync("/api/activation", AutoRequest(key, AutoUuidA));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal("MAX_DAILY_DEACTIVATIONS_REACHED", refused.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        await using var observed = CreateDb(provision.ConnectionString);
        Assert.Equal(MachineIdentity.FromUuid(AutoUuidB).HardwareId,
            (await observed.LicenseSeats.SingleAsync(row => row.IsActive)).HardwareId);
        Assert.Equal(2, await observed.LicenseSeats.CountAsync());
        var history = await observed.LicenseHistories.Where(row => row.Action == HistoryActions.UnlinkedApi).ToListAsync();
        Assert.Equal(3, history.Count);
        Assert.All(history, row => Assert.Contains(AutomaticSeatSwitch.Source, row.Details));
    }

    /// <summary>Proves licence/type/ban refusals and multi-seat limits leave the old seat and counter untouched.</summary>
    [Theory]
    [InlineData("revoked")]
    [InlineData("inactive")]
    [InlineData("expired")]
    [InlineData("type-disabled")]
    [InlineData("permanent-ban")]
    [InlineData("multi-full")]
    [InlineData("single-use")]
    public async Task AutoSeatSwitch_Classic_RefusalPreservesOldSeat(string refusal)
    {
        await using var provision = await Provision.CreateAsync();
        using var host = CreateHost(provision.ConnectionString);
        var key = await SeedAsync(host, 3, DateTime.UtcNow.AddDays(-10));
        await using (var db = CreateDb(provision.ConnectionString))
        {
            var license = await db.Licenses.Include(row => row.Type).SingleAsync();
            if (refusal == "revoked") license.RevokedAt = DateTime.UtcNow.AddMinutes(-1);
            if (refusal == "inactive") license.IsActive = false;
            if (refusal == "expired") license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
            if (refusal == "type-disabled") license.Type!.DisableNewActivations = true;
            if (refusal == "single-use")
            {
                license.Type!.EnforceSingleUsePerHardwareId = true;
                db.Licenses.Add(new License
                {
                    ProductId = license.ProductId, LicenseTypeId = license.LicenseTypeId,
                    LicenseKey = "CONSUMED-" + Guid.NewGuid().ToString("N"), IsActive = false,
                    HardwareId = MachineIdentity.FromUuid(AutoUuidB).HardwareId
                });
            }
            if (refusal == "permanent-ban")
                db.BannedHardwareIds.Add(new BannedHardwareId { HardwareId = MachineIdentity.FromUuid(AutoUuidB).HardwareId!, IsActive = true, ProductId = license.ProductId, Reason = "synthetic permanent ban", BanCategory = BannedHardwareId.Categories.Debugger });
            if (refusal == "multi-full")
            {
                license.MaxSeats = 2;
                db.LicenseSeats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "FEDCBA9876543210", IsActive = true });
            }
            await db.SaveChangesAsync();
        }
        using var response = await host.CreateClient().PostAsJsonAsync("/api/activation", AutoRequest(key, AutoUuidB));
        if (refusal == "permanent-ban")
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(body.RootElement.GetProperty("isSuccess").GetBoolean());
            Assert.Equal("BANNED", body.RootElement.GetProperty("errorCode").GetString());
        }
        else Assert.False(response.IsSuccessStatusCode);
        await using var observed = CreateDb(provision.ConnectionString);
        Assert.True((await observed.LicenseSeats.SingleAsync(row => row.HardwareId == OldHardwareId)).IsActive);
        Assert.Null((await observed.LicenseSeats.SingleAsync(row => row.HardwareId == OldHardwareId)).UnlinkedAt);
        Assert.False(await observed.LicenseHistories.AnyAsync(row => row.Action == HistoryActions.UnlinkedApi));
        Assert.False(await observed.LicenseSeats.AnyAsync(row => row.HardwareId == MachineIdentity.FromUuid(AutoUuidB).HardwareId));
    }

    /// <summary>Builds a synthetic SDK2 activation without the explicit legacy migration parameter.</summary>
    private static object AutoRequest(string licenseKey, string systemUuid) => new
    {
        LicenseKey = licenseKey, HardwareId = MachineIdentity.FromUuid(systemUuid).HardwareId,
        AppName, SystemUuid = systemUuid, SdkVersion = "2.0.0"
    };
}

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Real application DI records only the observed S2S transport; headers cannot supply address or correlation.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AutoSeatSwitch_RuntimeInitial_RecordsObservedTransportThroughApplicationDi(bool withHttpContext)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        using var host = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var scope = host.Services.CreateScope();
        var accessor = scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>();
        var context = new DefaultHttpContext { TraceIdentifier = "synthetic-runtime-initial-trace" };
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.41");
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.99";
        context.Request.Headers["X-Correlation-ID"] = "forged-client-correlation";
        accessor.HttpContext = withHttpContext ? context : null;
        try
        {
            var service = Assert.IsType<DistributionInstallationBindingService>(
                scope.ServiceProvider.GetRequiredService<IDistributionInstallationBindingService>());
            await using var db = await scenario.Factory.CreateDbContextAsync();
            var licenseId = await db.Licenses.Select(row => row.Id).SingleAsync();
            var prepared = await PrepareAutoFinalizeForLicenseAsync(scenario, licenseId, "ABCDEF0123456789", service);
            await service.FinalizeAsync("website-step1", Sha256("transport-initial"), prepared.Request);
            var change = await db.LicenseHistories.SingleAsync(row => row.LicenseId == licenseId
                && row.Action == HistoryActions.UnlinkedApi);
            Assert.EndsWith("; transport=s2s; remote_address=" + (withHttpContext ? "192.0.2.41" : "unavailable"), change.Details);
            Assert.Equal(withHttpContext ? context.TraceIdentifier : null, change.DecisionCorrelationId);
            Assert.DoesNotContain("198.51.100.99", change.Details);
            Assert.DoesNotContain("forged-client-correlation", change.Details);
        }
        finally
        {
            accessor.HttpContext = null;
        }
    }

    /// <summary>A virgin licence costs zero; public release then same-machine reactivation adds no change even at its limit.</summary>
    [Fact]
    public async Task AutoSeatSwitch_RuntimeInitial_NewAndSameMachineAtExhaustedQuotaCostZero()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var licenseId = Guid.NewGuid();
        var licenseKey = "AUTO-NEW-" + Guid.NewGuid().ToString("N");
        string productName;
        await using (var setup = await scenario.Factory.CreateDbContextAsync())
        {
            var original = await setup.Licenses.Include(row => row.Type).Include(row => row.Product).SingleAsync();
            original.Type!.MaxActivationsPerDay = 1;
            productName = original.Product!.Name;
            setup.Licenses.Add(new License
            {
                Id = licenseId, ProductId = original.ProductId, LicenseTypeId = original.LicenseTypeId,
                LicenseKey = licenseKey, IsActive = true, MaxSeats = 1, AllowedVersions = "2.2.*",
                ExpirationDate = DateTime.UtcNow.AddDays(1)
            });
            await setup.SaveChangesAsync();
        }
        var first = await PrepareAutoFinalizeForLicenseAsync(scenario, licenseId, "ABCDEF0123456789");
        var firstResult = await first.Service.FinalizeAsync("website-step1", Sha256("auto-new-first"), first.Request);
        await ActivateAutoRuntimeAsync(scenario, first.Request, firstResult.Response.BindingId);
        Guid originalSeatId;
        DateTime originalFirstAt;
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            await check.Database.OpenConnectionAsync();
            var license = await check.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == licenseId);
            Assert.Equal(0, (await SeatChangeQuota.GetStatusAsync(check, license,
                (await RuntimeEnrollmentService.DatabaseNowAsync(check, default)).UtcDateTime)).UsedToday);
            var seat = await check.LicenseSeats.SingleAsync(row => row.LicenseId == licenseId);
            originalSeatId = seat.Id;
            originalFirstAt = seat.FirstActivatedAt;
        }
        using var host = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var client = host.CreateClient();
        using var release = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey, HardwareId = "ABCDEF0123456789", AppName = productName,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, release.StatusCode);
        await using (var check = await scenario.Factory.CreateDbContextAsync())
            Assert.False((await check.LicenseSeats.SingleAsync(row => row.Id == originalSeatId)).IsActive);
        var again = await PrepareAutoFinalizeForLicenseAsync(scenario, licenseId, "ABCDEF0123456789");
        var restored = await again.Service.FinalizeAsync("website-step1", Sha256("auto-new-again"), again.Request);
        await ActivateAutoRuntimeAsync(scenario, again.Request, restored.Response.BindingId);
        await using var final = await scenario.Factory.CreateDbContextAsync();
        await final.Database.OpenConnectionAsync();
        var retained = await final.LicenseSeats.SingleAsync(row => row.LicenseId == licenseId);
        Assert.Equal(originalSeatId, retained.Id);
        Assert.Equal(originalFirstAt, retained.FirstActivatedAt);
        Assert.True(retained.IsActive);
        var finalLicense = await final.Licenses.Include(row => row.Type).SingleAsync(row => row.Id == licenseId);
        var quota = await SeatChangeQuota.GetStatusAsync(final, finalLicense,
            (await RuntimeEnrollmentService.DatabaseNowAsync(final, default)).UtcDateTime);
        Assert.Equal(1, quota.UsedToday);
        Assert.True(quota.IsExhausted);
        Assert.Equal(1, await final.LicenseHistories.CountAsync(row => row.LicenseId == licenseId && row.Action == HistoryActions.UnlinkedApi));
    }

    /// <summary>Issues a fresh modern grant for one explicitly selected synthetic licence without rewriting previous authority.</summary>
    private static async Task<(DistributionInstallationBindingService Service, DistributionInstallationFinalizeRequest Request)>
        PrepareAutoFinalizeForLicenseAsync(PreparedBootstrapScenario scenario, Guid licenseId, string hardwareId,
            DistributionInstallationBindingService? serviceOverride = null)
    {
        var service = serviceOverride ?? new DistributionInstallationBindingService(scenario.Factory,
            new EphemeralDataProtectionProvider(), TimeProvider.System, TestHardwareAuthorityAliasResolver.Instance);
        var grant = Guid.NewGuid().ToString("D");
        var issue = new DistributionEntitlementIssueRequest
        {
            Schema = DistributionInstallationBindingService.IssueV3Schema, RequestId = Guid.NewGuid().ToString("D"),
            ProductId = scenario.Fixture.ProductId.ToString("D"), SoftLicenceLicenseId = licenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(grant), SubjectRef = Base64Url(SHA256.HashData("auto-new-subject"u8.ToArray()))
        };
        var entitlement = await service.IssueEntitlementAsync("website-step1", Sha256(JsonSerializer.Serialize(issue)), issue);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binaries = await db.ApprovedBinaries.Where(row => row.ProductId == scenario.Fixture.ProductId
            && row.Version == scenario.Fixture.Version && row.Source == ApprovedBinaryService.ReleaseSource)
            .Select(row => new DistributionBinaryEvidence { Key = row.Key, Sha256 = row.Hash }).ToListAsync();
        Assert.Equal(3, binaries.Count);
        var now = DateTimeOffset.UtcNow;
        return (service, new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeV2Schema, RequestId = Guid.NewGuid().ToString("D"),
            ProductId = scenario.Fixture.ProductId.ToString("D"), GrantRef = grant,
            EntitlementRef = entitlement.Response.EntitlementRef, InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = hardwareId, HandoffDigestSha256 = Sha256(Guid.NewGuid().ToString("D")),
            HandoffIssuedAtUtc = FormatUtc(now), DownloadCompletedAtUtc = FormatUtc(now),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)), AllowSameAuthorityRecovery = true,
            Release = new DistributionReleaseEvidence
            {
                Version = scenario.Fixture.Version, InstallerFilename = "Synthetic.msi", InstallerSha256 = new string('f', 64)
            }, Binaries = binaries
        });
    }

    /// <summary>HTTP activation and Runtime Finalize compete under the same PostgreSQL barrier and daily quota.</summary>
    [Fact]
    public async Task AutoSeatSwitch_MixedConcurrent_LastQuotaSlotHasOneWinner()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        string licenseKey;
        string productName;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.Include(row => row.Type).Include(row => row.Product).SingleAsync();
            license.Type!.MaxActivationsPerDay = 1;
            licenseKey = license.LicenseKey;
            productName = license.Product!.Name;
            await db.SaveChangesAsync();
        }
        var runtime = await PrepareDistributionFinalizeAsync(scenario,
            Base64Url(SHA256.HashData("auto-seat-subject"u8.ToArray())), "AUTO-RUNTIME-MACHINE");
        using var host = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>());
        using var client = host.CreateClient();
        const string uuid = "33333333-4444-4555-8666-777777777777";
        var classicHardware = MachineIdentity.FromUuid(uuid).HardwareId;
        HttpResponseMessage? response = null;
        var errors = await AutomaticSeatSwitchConcurrencyProof.RunAsync(scenario.AppConnectionString,
            async () => response = await client.PostAsJsonAsync("/api/activation", new
            {
                LicenseKey = licenseKey, HardwareId = classicHardware, SystemUuid = uuid,
                AppName = productName, AppVersion = scenario.Fixture.Version, SdkVersion = "2.0.0"
            }),
            async () => await runtime.Service.FinalizeAsync("website-step1", Sha256("mixed-runtime-finalize"), runtime.Request));
        Assert.Null(errors[0]);
        Assert.NotNull(response);
        using (response)
        {
            if (response.StatusCode == HttpStatusCode.OK)
            {
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("licenseFile").GetString()));
                Assert.Equal("seat_change_quota_exhausted", Assert.IsType<DistributionOperationException>(errors[1]).ReasonCode);
            }
            else
            {
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                Assert.Equal("MAX_DAILY_DEACTIVATIONS_REACHED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
                Assert.Null(errors[1]);
            }
            await using var observed = await scenario.Factory.CreateDbContextAsync();
            Assert.Equal(response.StatusCode == HttpStatusCode.OK ? classicHardware : "AUTO-RUNTIME-MACHINE",
                (await observed.LicenseSeats.SingleAsync(row => row.IsActive)).HardwareId);
            Assert.Equal(1, await observed.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi));
        }
    }

    /// <summary>Finalization refuses each live policy before releasing the previous machine or charging its change quota.</summary>
    [Theory]
    [InlineData("revoked")]
    [InlineData("inactive")]
    [InlineData("expired")]
    [InlineData("type-disabled")]
    [InlineData("permanent-ban")]
    [InlineData("multi-full")]
    [InlineData("single-use")]
    public async Task AutoSeatSwitch_RuntimeInitial_RefusalPreservesOldSeat(string refusal)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var attempt = await PrepareDistributionFinalizeAsync(scenario,
            Base64Url(SHA256.HashData("auto-seat-subject"u8.ToArray())), "AUTO-MACHINE-B");
        Guid originalSeat;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.Include(row => row.Type).SingleAsync();
            originalSeat = (await db.LicenseSeats.SingleAsync(row => row.IsActive)).Id;
            if (refusal == "revoked") license.RevokedAt = DateTime.UtcNow.AddMinutes(-1);
            if (refusal == "inactive") license.IsActive = false;
            if (refusal == "expired") license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
            if (refusal == "type-disabled") license.Type!.DisableNewActivations = true;
            if (refusal == "single-use")
            {
                license.Type!.EnforceSingleUsePerHardwareId = true;
                db.Licenses.Add(new License
                {
                    ProductId = license.ProductId, LicenseTypeId = license.LicenseTypeId,
                    LicenseKey = "CONSUMED-" + Guid.NewGuid().ToString("N"), IsActive = false,
                    HardwareId = "AUTO-MACHINE-B"
                });
            }
            if (refusal == "permanent-ban") db.BannedHardwareIds.Add(new BannedHardwareId
            {
                ProductId = license.ProductId, HardwareId = "AUTO-MACHINE-B", IsActive = true,
                Reason = "synthetic permanent ban", BanCategory = BannedHardwareId.Categories.Debugger
            });
            if (refusal == "multi-full")
            {
                license.MaxSeats = 2;
                db.LicenseSeats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "AUTO-MULTI-OTHER", IsActive = true });
            }
            await db.SaveChangesAsync();
        }
        var error = await Assert.ThrowsAsync<DistributionOperationException>(() => attempt.Service.FinalizeAsync(
            "website-step1", Sha256(Guid.NewGuid().ToString("D")), attempt.Request));
        Assert.Equal(refusal switch
        {
            "type-disabled" => "new_activations_disabled",
            "multi-full" => "seat_limit_reached",
            "single-use" => "hardware_already_consumed",
            _ => "entitlement_ineligible"
        }, error.ErrorCode);
        await using var observed = await scenario.Factory.CreateDbContextAsync();
        var retained = await observed.LicenseSeats.SingleAsync(row => row.Id == originalSeat);
        Assert.True(retained.IsActive);
        Assert.Null(retained.UnlinkedAt);
        Assert.False(await observed.LicenseHistories.AnyAsync(row => row.Action == HistoryActions.UnlinkedApi));
        Assert.False(await observed.LicenseSeats.AnyAsync(row => row.HardwareId == "AUTO-MACHINE-B"));
    }

    /// <summary>Two distinct grants serialize at the same server barrier and cannot both spend one remaining change.</summary>
    [Fact]
    public async Task AutoSeatSwitch_RuntimeConcurrent_LastQuotaSlotHasOneWinner()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.Include(row => row.Type).SingleAsync();
            license.Type!.MaxActivationsPerDay = 1;
            await db.SaveChangesAsync();
        }
        var subject = Base64Url(SHA256.HashData("auto-seat-subject"u8.ToArray()));
        var first = await PrepareDistributionFinalizeAsync(scenario, subject, "AUTO-MACHINE-B");
        var second = await PrepareDistributionFinalizeAsync(scenario, subject, "AUTO-MACHINE-C");
        var errors = await AutomaticSeatSwitchConcurrencyProof.RunAsync(scenario.AppConnectionString,
            async () => await first.Service.FinalizeAsync("website-step1", Sha256("auto-race-b"), first.Request),
            async () => await second.Service.FinalizeAsync("website-step1", Sha256("auto-race-c"), second.Request));
        Assert.Single(errors, error => error == null);
        var refusal = Assert.IsType<DistributionOperationException>(Assert.Single(errors, error => error != null));
        Assert.Equal("activation_rate_limited", refusal.ErrorCode);
        Assert.Equal("seat_change_quota_exhausted", refusal.ReasonCode);
        await using var observed = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(errors[0] == null ? "AUTO-MACHINE-B" : "AUTO-MACHINE-C",
            (await observed.LicenseSeats.SingleAsync(row => row.IsActive)).HardwareId);
        Assert.Equal(1, await observed.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi));
    }
    /// <summary>Returns to retained machines through fresh grants and real possession proofs, counting changes only.</summary>
    [Fact]
    public async Task AutoSeatSwitch_RuntimeInitial_ABAB_RefusesFourthChangeWithoutLosingWinner()
    {
        var subject = Base64Url(SHA256.HashData("auto-seat-subject"u8.ToArray()));
        using var scenario = await CreatePreparedBootstrapScenarioAsync(
            initialHardwareId: "AUTO-MACHINE-A", initialSubjectRef: subject);
        var initialConfirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"), Epoch = 1
        };
        var initialDigest = Sha256(JsonSerializer.Serialize(initialConfirm));
        await scenario.Runtime.ConfirmAsync(scenario.EnrollmentId, initialDigest, initialConfirm,
            Proof(scenario.EnrollmentKey, "confirm", scenario.EnrollmentId, scenario.Options.ConfirmAudience,
                scenario.Prepared.Challenge, initialDigest), IPAddress.Loopback);
        string hardwareA;
        await using (var setup = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Type).SingleAsync();
            license.Type!.MaxActivationsPerDay = 3;
            hardwareA = (await setup.LicenseSeats.SingleAsync(row => row.IsActive)).HardwareId;
            await setup.SaveChangesAsync();
        }
        var firstActivation = new Dictionary<Guid, DateTime>();
        var sequence = new[] { "AUTO-MACHINE-B", hardwareA, "AUTO-MACHINE-B" };
        for (var index = 0; index < sequence.Length; index++)
        {
            var attempt = await PrepareDistributionFinalizeAsync(scenario,
                subject, sequence[index]);
            // The next download occurs after the previous handoff, without altering its history.
            var downloadedAt = DateTimeOffset.UtcNow;
            attempt.Request.HandoffIssuedAtUtc = FormatUtc(downloadedAt);
            attempt.Request.DownloadCompletedAtUtc = FormatUtc(downloadedAt);
            var result = await attempt.Service.FinalizeAsync("website-step1",
                Sha256(Guid.NewGuid().ToString("D")), attempt.Request);
            await ActivateAutoRuntimeAsync(scenario, attempt.Request, result.Response.BindingId);
            await using var observed = await scenario.Factory.CreateDbContextAsync();
            await observed.Database.OpenConnectionAsync();
            var license = await observed.Licenses.Include(row => row.Type).SingleAsync();
            var seats = await observed.LicenseSeats.AsNoTracking().ToListAsync();
            Assert.Equal(sequence[index], Assert.Single(seats, row => row.IsActive).HardwareId);
            Assert.Equal(index + 1, (await SeatChangeQuota.GetStatusAsync(observed, license,
                (await RuntimeEnrollmentService.DatabaseNowAsync(observed, default)).UtcDateTime)).UsedToday);
            var previousHardware = index == 0 ? hardwareA : sequence[index - 1];
            var released = Assert.Single(seats, row => row.HardwareId == previousHardware);
            var lastChange = await observed.LicenseHistories.Where(row => row.Action == HistoryActions.UnlinkedApi)
                .OrderByDescending(row => row.Timestamp).FirstAsync();
            Assert.Equal(released.UnlinkedAt, lastChange.Timestamp);
            Assert.Equal(AutomaticSeatSwitch.Source, lastChange.PerformedBy);
            Assert.Equal($"{AutomaticSeatSwitch.Source}: {previousHardware} -> {sequence[index]}; actor=website-step1; transport=s2s; remote_address=unavailable", lastChange.Details);
            Assert.Null(lastChange.DecisionCorrelationId);
            foreach (var seat in seats)
            {
                if (firstActivation.TryGetValue(seat.Id, out var first)) Assert.Equal(first, seat.FirstActivatedAt);
                else firstActivation.Add(seat.Id, seat.FirstActivatedAt);
            }
        }
        var fourth = await PrepareDistributionFinalizeAsync(scenario,
            Base64Url(SHA256.HashData("auto-seat-subject"u8.ToArray())), hardwareA);
        var refused = await Assert.ThrowsAsync<DistributionOperationException>(() => fourth.Service.FinalizeAsync(
            "website-step1", Sha256(Guid.NewGuid().ToString("D")), fourth.Request));
        Assert.Equal("activation_rate_limited", refused.ErrorCode);
        Assert.Equal("seat_change_quota_exhausted", refused.ReasonCode);
        await using var final = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("AUTO-MACHINE-B", (await final.LicenseSeats.SingleAsync(row => row.IsActive)).HardwareId);
        Assert.Equal(3, await final.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi));
        Assert.Equal(2, await final.LicenseSeats.CountAsync());
    }

    /// <summary>Runs initial Runtime Finalize through a new entitlement, then proves exact replay cannot evict its later winner.</summary>
    [Fact]
    public async Task AutoSeatSwitch_RuntimeInitial_ChangesOnceAndReplayPreservesLaterWinner()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using (var setup = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await setup.Licenses.Include(row => row.Type).SingleAsync();
            license.Type!.MaxActivationsPerDay = 3;
            await setup.SaveChangesAsync();
        }
        var first = await PrepareDistributionFinalizeAsync(scenario, Base64Url(SHA256.HashData("auto-seat-subject"u8.ToArray())), "AUTO-MACHINE-B");
        var digest = Sha256("auto-seat-switch-first");
        var result = await first.Service.FinalizeAsync("website-step1", digest, first.Request);
        Assert.False(result.Idempotent);
        await ActivateAutoRuntimeAsync(scenario, first.Request, result.Response.BindingId);
        var second = await PrepareDistributionFinalizeAsync(scenario, Base64Url(SHA256.HashData("auto-seat-subject"u8.ToArray())), "AUTO-MACHINE-C");
        Assert.False((await second.Service.FinalizeAsync("website-step1", Sha256("auto-seat-switch-second"), second.Request)).Idempotent);
        Assert.True((await first.Service.FinalizeAsync("website-step1", digest, first.Request)).Idempotent);
        // A new request identifier cannot turn the consumed entitlement into a new switch.
        first.Request.RequestId = Guid.NewGuid().ToString("D");
        var consumed = await Assert.ThrowsAsync<DistributionOperationException>(() => first.Service.FinalizeAsync(
            "website-step1", Sha256("consumed-entitlement-new-request"), first.Request));
        Assert.Equal("entitlement_ineligible", consumed.ErrorCode);
        await using var observed = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal("AUTO-MACHINE-C", (await observed.LicenseSeats.SingleAsync(row => row.IsActive)).HardwareId);
        Assert.Equal(2, await observed.LicenseHistories.CountAsync(row => row.Action == HistoryActions.UnlinkedApi));
        await observed.Database.OpenConnectionAsync();
        var licence = await observed.Licenses.Include(row => row.Type).SingleAsync();
        Assert.Equal(2, (await SeatChangeQuota.GetStatusAsync(observed, licence,
            (await RuntimeEnrollmentService.DatabaseNowAsync(observed, default)).UtcDateTime)).UsedToday);
    }

    /// <summary>Completes real Runtime possession proof after Finalize, preserving its binding and enrollment history.</summary>
    private static async Task ActivateAutoRuntimeAsync(
        PreparedBootstrapScenario scenario, DistributionInstallationFinalizeRequest finalized, string bindingId)
    {
        using var key = RSA.Create(3072);
        var fixture = (scenario.Fixture.ProductId, Guid.Parse(bindingId), finalized.HandoffDigestSha256!,
            finalized.InstallationId!, scenario.Fixture.Version);
        var prepareRequest = PrepareRequest(fixture, Guid.NewGuid().ToString("D"), key);
        prepareRequest.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var prepared = await scenario.Runtime.PrepareAsync("website-step1", Sha256(Guid.NewGuid().ToString("D")), prepareRequest);
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var request = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema, ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = prepared.Response.EnrollmentId, Epoch = 1
        };
        var digest = Sha256(JsonSerializer.Serialize(request));
        await scenario.Runtime.ConfirmAsync(enrollmentId, digest, request,
            Proof(key, "confirm", enrollmentId, scenario.Options.ConfirmAudience,
                prepared.Response.Challenge, digest), IPAddress.Loopback);
    }
}

/// <summary>Proves real overlapping requests using PostgreSQL's own blocking graph, then releases only its own barrier.</summary>
internal static class AutomaticSeatSwitchConcurrencyProof
{
    internal static async Task<Exception?[]> RunAsync(string connectionString, Func<Task> first, Func<Task> second)
    {
        await using var barrier = new NpgsqlConnection(connectionString);
        await barrier.OpenAsync();
        await using (var hold = new NpgsqlCommand("SELECT pg_advisory_lock(999831, 1)", barrier))
            await hold.ExecuteNonQueryAsync();
        var firstTask = Record.ExceptionAsync(first);
        var secondTask = Record.ExceptionAsync(second);
        var count = 0L;
        try
        {
            await using var observer = new NpgsqlConnection(connectionString);
            await observer.OpenAsync();
            var deadline = DateTime.UtcNow.AddSeconds(3);
            do
            {
                await using var query = new NpgsqlCommand(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND @blocker = ANY(pg_blocking_pids(pid))", observer);
                query.Parameters.AddWithValue("blocker", barrier.ProcessID);
                count = (long)(await query.ExecuteScalarAsync() ?? throw new InvalidOperationException("Missing blocker count."));
                if (count == 2) break;
                await Task.Delay(20);
            } while (DateTime.UtcNow < deadline);
        }
        finally
        {
            await using var release = new NpgsqlCommand("SELECT pg_advisory_unlock(999831, 1)", barrier);
            await release.ExecuteNonQueryAsync();
        }
        var errors = await Task.WhenAll(firstTask, secondTask);
        Assert.Equal(2, count);
        return errors;
    }
}

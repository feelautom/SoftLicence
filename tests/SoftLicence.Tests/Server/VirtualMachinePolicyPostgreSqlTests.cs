using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Npgsql;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises commercial VM restrictions through real HTTP against isolated PostgreSQL databases.</summary>
public sealed partial class PersonalDayPassPostgreSqlTests
{
    /// <summary>A first-order VM refusal precedes the separate 1424 rule, preserving both licenses and the prior product seat.</summary>
    [Fact]
    public async Task Tkt1550_VmRefusalNeverTriggersFirstOrderRevocationOrProductUnlink()
    {
        await using var f = await Fixture.CreateAsync();
        var prior = await f.ReadResponseAsync(f.Request());
        await ActivatePhysicalCommercialAsync(f, prior.LicenseKey, VmPolicyHardware);
        var next = await f.ReadResponseAsync(Qualified(f.Request() with { CommercialSubjectId = Guid.NewGuid() }));
        await using var db = f.Db();
        var beforeLicenses = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
        var beforeSeats = JsonSerializer.Serialize(await db.LicenseSeats.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
        using var response = await f.Client.PostAsJsonAsync("/api/activation", new {
            AppName = f.ProductName, LicenseKey = next.LicenseKey, HardwareId = VmPolicyHardware, SystemUuid = VmPolicyUuid,
            AppVersion = "2.3.924", MachineEvidence = VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform") });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("VIRTUAL_MACHINE_NOT_ALLOWED", await response.Content.ReadAsStringAsync());
        Assert.Equal(beforeLicenses, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
        Assert.Equal(beforeSeats, JsonSerializer.Serialize(await db.LicenseSeats.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
        Assert.False(await db.LicenseHistories.AnyAsync(row => row.Action == "FIRST_ORDER_FREE_REVOKED"));
    }

    /// <summary>Both public trial creation routes classify newly issued free rights and refuse before creating seats or licenses.</summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(true, false)]
    public async Task Tkt1550_PublicTrialCreationHonorsMachinePolicy(bool automatic, bool virtualMachine)
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        var product = await db.Products.SingleAsync();
        db.LicenseTypes.Add(new LicenseType { ProductId = product.Id, Name = "Synthetic Trial", Slug = "TRIAL",
            IsFree = true, AllowPublicTrial = true, DefaultDurationDays = 7, DefaultMaxSeats = 1 });
        await db.SaveChangesAsync();
        using var response = await f.Client.PostAsJsonAsync(automatic ? "/api/activation" : "/api/activation/trial", new {
            AppName = product.Name, LicenseKey = "FREE-TRIAL", TypeSlug = "TRIAL", HardwareId = VmPolicyHardware,
            SystemUuid = VmPolicyUuid, AppVersion = "2.3.924", CustomerEmail = "trial@example.test",
            MachineEvidence = virtualMachine ? VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform")
                : VmPolicyEvidence("Dell Inc.", "Precision 7680") });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        if (virtualMachine)
        {
            Assert.Contains("VIRTUAL_MACHINE_NOT_ALLOWED", await response.Content.ReadAsStringAsync());
            Assert.False(await db.Licenses.AnyAsync());
            Assert.False(await db.LicenseSeats.AnyAsync());
        }
        else
        {
            Assert.Contains("licenseFile", await response.Content.ReadAsStringAsync());
            Assert.Equal("FREE", (await db.Licenses.AsNoTracking().SingleAsync()).CommercialNature);
        }
    }

    /// <summary>Valid synthetic identity shared by isolated commercial tests that must reach the inter-subject rule.</summary>
    internal const string VmPolicyUuid = "E42A9458-12C9-4759-B0E2-345AB6451290";
    /// <summary>Derives the matching HWID instead of bypassing UUID consistency checks in 1424 compatibility fixtures.</summary>
    internal static string VmPolicyHardware => MachineIdentity.FromUuid(VmPolicyUuid).HardwareId!;
    /// <summary>Supplies a physical machine to existing commercial-rule tests without changing their business assertions.</summary>
    private static async Task ActivatePhysicalCommercialAsync(Fixture fixture, string key, string hardware)
    {
        using var response = await fixture.Client.PostAsJsonAsync("/api/activation", new {
            AppName = fixture.ProductName, LicenseKey = key, HardwareId = hardware, SystemUuid = VmPolicyUuid,
            MachineEvidence = VmPolicyEvidence("Dell Inc.", "Precision 7680"), AppVersion = "2.3.924",
            CustomerEmail = "buyer@example.test", CustomerName = "Synthetic buyer" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("licenseFile", await response.Content.ReadAsStringAsync());
    }
    /// <summary>Uses the existing SDK wire shape without introducing any prospective server API.</summary>
    internal static JsonElement VmPolicyEvidence(string manufacturer, string model) => JsonSerializer.SerializeToElement(new {
        SystemManufacturer = new { Status = "Present", Values = new[] { manufacturer }, Error = (string?)null },
        SystemModel = new { Status = "Present", Values = new[] { model }, Error = (string?)null },
        HypervisorPresent = new { Status = "Present", Values = new[] { "True" }, Error = (string?)null }
    });

    /// <summary>Restricted offers refuse VM or missing evidence without revocation; physical Hyper-V and paid authority remain valid.</summary>
    [Theory]
    [InlineData("FIRST_ORDER_FREE", "VMware, Inc.", "VMware Virtual Platform", "VIRTUAL_MACHINE_NOT_ALLOWED")]
    [InlineData("FREE", "innotek GmbH", "VirtualBox", "VIRTUAL_MACHINE_NOT_ALLOWED")]
    [InlineData("PAID_TRIAL", "Microsoft Corporation", "Virtual Machine", "VIRTUAL_MACHINE_NOT_ALLOWED")]
    [InlineData("FREE", "QEMU", "Standard PC (Q35 + ICH9, 2009)", "VIRTUAL_MACHINE_NOT_ALLOWED")]
    [InlineData("FREE", "Xen", "HVM domU", "VIRTUAL_MACHINE_NOT_ALLOWED")]
    [InlineData("FREE", "Parallels Software International Inc.", "Parallels Virtual Platform", "VIRTUAL_MACHINE_NOT_ALLOWED")]
    [InlineData("FIRST_ORDER_FREE", null, null, "MACHINE_EVIDENCE_REQUIRED")]
    [InlineData("FREE", "Dell Inc.", "Precision 7680", null)]
    [InlineData("PAID_TRIAL", "LENOVO", "ThinkPad P16", null)]
    [InlineData("PAID", "VMware, Inc.", "VMware Virtual Platform", null)]
    [InlineData("UNKNOWN", "Microsoft Corporation", "Virtual Machine", null)]
    [InlineData("PAID", null, null, null)]
    [InlineData("UNKNOWN", null, null, null)]
    public async Task Tkt1550_ClassicActivationAppliesCommercialVmPolicy(string nature, string? manufacturer, string? model, string? refusal)
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request();
        var issued = await f.ReadResponseAsync(nature == "UNKNOWN" ? request
            : Qualified(request, nature, nature == "PAID_TRIAL" ? 10000 : nature == "PAID" ? 14900 : 0));
        const string uuid = "E42A9458-12C9-4759-B0E2-345AB6451290";
        var identity = MachineIdentity.FromUuid(uuid);
        Assert.True(identity.IsAccepted);
        await using var db = f.Db();
        var before = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync());
        using var response = await f.Client.PostAsJsonAsync("/api/activation", new {
            AppName = f.ProductName, LicenseKey = issued.LicenseKey, HardwareId = identity.HardwareId,
            SystemUuid = uuid, AppVersion = "2.3.924",
            MachineEvidence = manufacturer is null ? (JsonElement?)null : VmPolicyEvidence(manufacturer, model!)
        });
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        if (refusal is null)
        {
            Assert.Contains("licenseFile", body);
            Assert.True((await db.Licenses.AsNoTracking().SingleAsync()).IsActive);
        }
        else
        {
            Assert.DoesNotContain("licenseFile", body);
            Assert.Equal(refusal, Assert.Single(response.Headers.GetValues("X-SoftLicence-Error-Code")));
            using var error = JsonDocument.Parse(body);
            Assert.False(error.RootElement.GetProperty("isSuccess").GetBoolean());
            Assert.Equal(refusal, error.RootElement.GetProperty("errorCode").GetString());
            var expectedMessage = refusal == "VIRTUAL_MACHINE_NOT_ALLOWED"
                ? "Free and trial licenses cannot be activated on a virtual machine."
                : "Update your installer or application to provide the machine information required for free and trial licenses.";
            Assert.Equal(expectedMessage, error.RootElement.GetProperty("message").GetString());
            Assert.Equal(expectedMessage, error.RootElement.GetProperty("errorMessage").GetString());
            Assert.Equal(1, error.RootElement.GetProperty("contractVersion").GetInt32());
            Assert.False(string.IsNullOrWhiteSpace(error.RootElement.GetProperty("correlationId").GetString()));
            Assert.Equal(before, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync()));
            Assert.False(await db.LicenseSeats.AnyAsync());
            Assert.Null((await db.PersonalDayPasses.SingleAsync()).InitialPaidThroughUtc);
        }
        Assert.True(await db.MachineEvidenceObservations.AnyAsync(x => x.HardwareId == identity.HardwareId));
    }
}

/// <summary>Verifies that authenticated preflight uses its own machine evidence before issuing a hardware decision.</summary>
public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>Builds the real closed preflight DTO from an issued finalize request; all rights remain server-owned.</summary>
    protected static RuntimeDistributionPreflightRequest VmPreflight(DistributionInstallationFinalizeRequest request,
        Guid licenseId, JsonElement? evidence, string? key = null) => new()
    {
        Schema = "runtime-distribution-hardware-authority", RequestId = Guid.NewGuid().ToString("D"),
        ProductId = request.ProductId, SoftLicenceLicenseId = licenseId.ToString("D"),
        GrantRefDigestSha256 = Sha256(request.GrantRef!), InstallationId = request.InstallationId,
        KeyThumbprint = key ?? new string('A', 43), HardwareEvidence = new() {
            SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid, MachineEvidence = evidence }
    };
}

/// <summary>Runs the tests from VirtualMachinePolicyPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class VirtualMachinePolicyPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>Expiry during the new evidence lock wait cannot authorize a classification or a download.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_PreflightRechecksEntitlementExpiryAfterProofWait")]
    public async Task Tkt1550_PreflightRechecksEntitlementExpiryAfterProofWait()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.Admin);
        var scenario = await SeedRuntimeDistributionScenarioAsync(factory);
        var request = scenario.Request;
        request.HardwareIdHash = null;
        request.InstallationId = Guid.NewGuid().ToString("D");
        request.KeyThumbprint = new string ('A', 43);
        request.HardwareEvidence = new()
        {
            SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680")
        };
        await using var db = await factory.CreateDbContextAsync();
        var entitlement = await db.DistributionEntitlements.SingleAsync();
        entitlement.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(3);
        await db.SaveChangesAsync();
        await using var blocker = await factory.CreateDbContextAsync();
        await using var transaction = await blocker.Database.BeginTransactionAsync();
        await RuntimeMachineEvidenceAuthority.LockAsync(blocker, "tia-connect-website", scenario.ProductId, scenario.LicenseId, Sha256(PersonalDayPassPostgreSqlTests.VmPolicyHardware), CancellationToken.None);
        const string application = "tkt1550-proof-expiry";
        var service = new RuntimeDistributionPreflightService(NamedFactory(database.App, application), Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var evaluation = service.EvaluateAsync("tia-connect-website", Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None);
        try
        {
            await WaitForAdvisoryLockWaiterAsync(database.Admin, application);
            var remaining = entitlement.ExpiresAtUtc.AddMilliseconds(100) - DateTime.UtcNow;
            if (remaining > TimeSpan.Zero)
                await Task.Delay(remaining);
        }
        finally
        {
            await transaction.CommitAsync();
        }

        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(async () => await evaluation);
        Assert.Equal("not_eligible", refusal.ErrorCode);
        var decision = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal("commercial_authority_invalid", decision.ReasonCode);
        Assert.Null(decision.MachineEvidenceSourceDecisionId);
        Assert.False(await db.LicenseSeats.AnyAsync());
    }

    /// <summary>The additive migration does not infer physical evidence from old accepted decisions or change paid compatibility.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_HistoricalAcceptedDecisionWithoutClassificationRequiresFreshEvidence")]
    public async Task Tkt1550_HistoricalAcceptedDecisionWithoutClassificationRequiresFreshEvidence()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.Admin);
        var scenario = await SeedRuntimeDistributionScenarioAsync(factory);
        await using var db = await factory.CreateDbContextAsync();
        Assert.False(db.Database.HasPendingModelChanges());
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = "FREE";
        var historical = new RuntimeDistributionHardwareDecision
        {
            Id = Guid.NewGuid(),
            ClientId = "tia-connect-website",
            ProductId = scenario.ProductId,
            LicenseId = scenario.LicenseId,
            RequestId = Guid.NewGuid().ToString("D"),
            PayloadDigestSha256 = new string ('e', 64),
            GrantRefDigestSha256 = scenario.Request.GrantRefDigestSha256!,
            HardwareIdHash = scenario.Request.HardwareIdHash,
            InstallationIdHash = new string ('b', 64),
            KeyThumbprint = new string ('A', 43),
            AuthorityMode = "server-derived",
            Outcome = "accepted",
            ReasonCode = "eligible",
            LicenseActive = true,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-1),
            LastSeenAtUtc = DateTime.UtcNow.AddDays(-1)
        };
        db.Add(historical);
        await db.SaveChangesAsync();
        var service = new RuntimeDistributionPreflightService(factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        Assert.Equal("machine_evidence_required", (await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync("tia-connect-website", Sha256("historical-proof"), scenario.Request, CancellationToken.None))).ErrorCode);
        var old = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync(row => row.Id == historical.Id);
        Assert.Null(old.MachineClassifierVersion);
        Assert.Null(old.MachineEvidenceSourceDecisionId);
        Assert.Equal("accepted", old.Outcome);
    }

    /// <summary>A VM source queued before finalize commits first; finalize cannot authorize from an obsolete physical source.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_ConcurrentVmSourceWinsBeforeNewFinalizeWithoutSideEffects")]
    public async Task Tkt1550_ConcurrentVmSourceWinsBeforeNewFinalizeWithoutSideEffects()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = "FREE";
        await db.SaveChangesAsync();
        const string preflightName = "tkt1550-vm-preflight";
        const string finalizeName = "tkt1550-vm-finalize";
        var finalize = new DistributionInstallationBindingService(NamedFactory(scenario.AppConnectionString, finalizeName), new EphemeralDataProtectionProvider(), TimeProvider.System, TestHardwareAuthorityAliasResolver.Instance);
        var earlierGrant = await PrepareAutoFinalizeForLicenseAsync(scenario, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyHardware, finalize);
        var attempt = await PrepareAutoFinalizeForLicenseAsync(scenario, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyHardware, finalize);
        earlierGrant.Request.InstallationId = attempt.Request.InstallationId;
        var preflight = new RuntimeDistributionPreflightService(NamedFactory(scenario.AppConnectionString, preflightName), Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var physical = VmPreflight(attempt.Request, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680"));
        await preflight.EvaluateAsync("website-step1", Sha256(JsonSerializer.Serialize(physical)), physical, CancellationToken.None);
        var before = await RuntimeGraphAsync(db, license.Id);
        await using var blocker = await new TestDbFactory(scenario.AdminConnectionString).CreateDbContextAsync();
        await using var transaction = await blocker.Database.BeginTransactionAsync();
        await RuntimeMachineEvidenceAuthority.LockAsync(blocker, "website-step1", license.ProductId, license.Id, Sha256(PersonalDayPassPostgreSqlTests.VmPolicyHardware), CancellationToken.None);
        // Different grant, same machine authority: the proof lock must still serialize this source against finalize.
        var vm = VmPreflight(earlierGrant.Request, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform"));
        var sourceTask = preflight.EvaluateAsync("website-step1", Sha256(JsonSerializer.Serialize(vm)), vm, CancellationToken.None);
        await WaitForAdvisoryLockWaiterAsync(scenario.AdminConnectionString, preflightName);
        var finalizeTask = finalize.FinalizeAsync("website-step1", Sha256("vm-finalize-race"), attempt.Request);
        try
        {
            await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
            await observer.OpenAsync();
            var waiting = false;
            for (var retry = 0; retry < 100 && !waiting; retry++)
            {
                await using var command = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=@name AND wait_event_type='Lock')", observer);
                command.Parameters.AddWithValue("name", finalizeName);
                waiting = (bool)(await command.ExecuteScalarAsync())!;
                if (!waiting)
                    await Task.Delay(50);
            }

            Assert.True(waiting, "Finalize did not reach the locked authority boundary.");
        }
        finally
        {
            await transaction.CommitAsync();
        }

        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(async () => await sourceTask)).ErrorCode);
        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(async () => await finalizeTask)).ErrorCode);
        Assert.Equal(before, await RuntimeGraphAsync(db, license.Id));
    }

    /// <summary>A failed proof write is a technical failure and rolls back the whole decision, without revoking paid or free rights.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_PreflightPersistenceFailureIsAtomicAndTechnical")]
    public async Task Tkt1550_PreflightPersistenceFailureIsAtomicAndTechnical()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.Admin);
        var scenario = await SeedRuntimeDistributionScenarioAsync(factory);
        await using var db = await factory.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = "FREE";
        await db.SaveChangesAsync();
        var before = JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync());
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION tkt1550_fail_decision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
              RAISE EXCEPTION 'synthetic persistence failure'; END $$;
            CREATE TRIGGER tkt1550_fail_decision BEFORE INSERT ON "RuntimeDistributionHardwareDecisions"
              FOR EACH ROW EXECUTE FUNCTION tkt1550_fail_decision();
            """);
        var request = scenario.Request;
        request.HardwareIdHash = null;
        request.InstallationId = Guid.NewGuid().ToString("D");
        request.KeyThumbprint = new string ('A', 43);
        request.HardwareEvidence = new()
        {
            SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform")
        };
        var service = new RuntimeDistributionPreflightService(factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var error = await Assert.ThrowsAsync<DbUpdateException>(() => service.EvaluateAsync("tia-connect-website", Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None));
        Assert.IsType<PostgresException>(error.InnerException);
        Assert.False(await db.RuntimeDistributionHardwareDecisions.AnyAsync());
        Assert.Equal(before, JsonSerializer.Serialize(await db.Licenses.AsNoTracking().SingleAsync()));
        Assert.False(await db.LicenseSeats.AnyAsync());
    }

    /// <summary>Concurrent exact full requests create one source; read-only digest revalidation never creates a newer source.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_ConcurrentReplayAndDigestReuseDoNotPromoteSource")]
    public async Task Tkt1550_ConcurrentReplayAndDigestReuseDoNotPromoteSource()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.Admin);
        var scenario = await SeedRuntimeDistributionScenarioAsync(factory);
        await using var db = await factory.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = "FREE";
        await db.SaveChangesAsync();
        var request = scenario.Request;
        request.HardwareIdHash = null;
        request.InstallationId = Guid.NewGuid().ToString("D");
        request.KeyThumbprint = new string ('A', 43);
        request.HardwareEvidence = new()
        {
            SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680")
        };
        var service = new RuntimeDistributionPreflightService(factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var digest = Sha256(JsonSerializer.Serialize(request));
        var results = await Task.WhenAll(service.EvaluateAsync("tia-connect-website", digest, request, CancellationToken.None), service.EvaluateAsync("tia-connect-website", digest, request, CancellationToken.None));
        Assert.Equal(results[0], results[1]);
        var source = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        Assert.Equal(2, source.AttemptCount);
        Assert.Equal(source.Id, source.MachineEvidenceSourceDecisionId);
        request.RequestId = Guid.NewGuid().ToString("D");
        request.HardwareIdHash = results[0].HardwareIdHash;
        request.HardwareEvidence = null;
        request.InstallationId = null;
        request.KeyThumbprint = null;
        await service.EvaluateAsync("tia-connect-website", Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None);
        var linked = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync(row => row.Id != source.Id);
        Assert.Equal(source.Id, linked.MachineEvidenceSourceDecisionId);
        Assert.NotEqual(linked.Id, linked.MachineEvidenceSourceDecisionId);
        var mutation = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"RuntimeDistributionHardwareDecisions\" SET \"MachineClassification\" = 'virtual' WHERE \"Id\" = {source.Id}"));
        Assert.Equal("23514", mutation.SqlState);
    }

    /// <summary>A public physical observation cannot replace the exact authenticated VM evidence or cross any authority scope.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_PublicObservationAndCrossScopeProofCannotAuthorizeFinalize")]
    public async Task Tkt1550_PublicObservationAndCrossScopeProofCannotAuthorizeFinalize()
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(database.Admin);
        var scenario = await SeedRuntimeDistributionScenarioAsync(factory);
        var request = scenario.Request;
        request.HardwareIdHash = null;
        request.InstallationId = Guid.NewGuid().ToString("D");
        request.KeyThumbprint = new string ('A', 43);
        request.HardwareEvidence = new()
        {
            SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform")
        };
        var service = new RuntimeDistributionPreflightService(factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        // UNKNOWN accepts the request but still captures the declarative VM classification for later restricted rights.
        await service.EvaluateAsync("tia-connect-website", Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None);
        await new MachineIdentityObservationService(factory, Mock.Of<ILogger<MachineIdentityObservationService>>()).ObserveDerivedAsync(scenario.ProductId, PersonalDayPassPostgreSqlTests.VmPolicyUuid, PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680"), "CHECK", CancellationToken.None);
        await using var db = await factory.CreateDbContextAsync();
        var hardware = Sha256(PersonalDayPassPostgreSqlTests.VmPolicyHardware);
        var install = Sha256(request.InstallationId);
        var exact = await RuntimeMachineEvidenceAuthority.FindAsync(db, "tia-connect-website", scenario.ProductId, scenario.LicenseId, request.GrantRefDigestSha256!, hardware, install, request.KeyThumbprint, false, CancellationToken.None);
        Assert.Equal("virtual", exact.Kind);
        foreach (var dimension in new[]
        {
            "client",
            "product",
            "license",
            "grant",
            "hardware",
            "installation",
            "key"
        }

        )
        {
            var proof = await RuntimeMachineEvidenceAuthority.FindAsync(db, dimension == "client" ? "other" : "tia-connect-website", dimension == "product" ? Guid.NewGuid() : scenario.ProductId, dimension == "license" ? Guid.NewGuid() : scenario.LicenseId, dimension == "grant" ? new string ('e', 64) : request.GrantRefDigestSha256!, dimension == "hardware" ? new string ('e', 64) : hardware, dimension == "installation" ? new string ('e', 64) : install, dimension == "key" ? new string ('B', 43) : request.KeyThumbprint, false, CancellationToken.None);
            Assert.Equal("unknown", proof.Kind);
        }

        var source = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync();
        var crossedLicense = Guid.NewGuid();
        var crossed = new RuntimeDistributionHardwareDecision
        {
            Id = Guid.NewGuid(),
            ClientId = source.ClientId,
            ProductId = source.ProductId,
            LicenseId = crossedLicense,
            RequestId = Guid.NewGuid().ToString("D"),
            PayloadDigestSha256 = new string ('f', 64),
            GrantRefDigestSha256 = source.GrantRefDigestSha256,
            HardwareIdHash = source.HardwareIdHash,
            InstallationIdHash = source.InstallationIdHash,
            KeyThumbprint = source.KeyThumbprint,
            AuthorityMode = "known-enrollment",
            Outcome = "accepted",
            ReasonCode = "eligible",
            MachineClassifierVersion = 1,
            MachineClassification = source.MachineClassification,
            MachineEvidenceDigestSha256 = source.MachineEvidenceDigestSha256,
            MachineEvidenceSourceDecisionId = source.Id,
            CreatedAtUtc = DateTime.UtcNow,
            LastSeenAtUtc = DateTime.UtcNow
        };
        db.Add(crossed);
        await db.SaveChangesAsync();
        Assert.Equal("unknown", (await RuntimeMachineEvidenceAuthority.FindAsync(db, "tia-connect-website", scenario.ProductId, crossedLicense, request.GrantRefDigestSha256!, hardware, install, request.KeyThumbprint, false, CancellationToken.None)).Kind);
        var tiedInstall = Sha256("tkt1550-tied-installation");
        // Three equal-time sources must not be reduced to a potentially agreeable first pair.
        foreach (var kind in new[]
        {
            "physical",
            "physical",
            "virtual"
        }

        )
        {
            var tied = JsonSerializer.Deserialize<RuntimeDistributionHardwareDecision>(JsonSerializer.Serialize(source))!;
            tied.Id = Guid.NewGuid();
            tied.RequestId = Guid.NewGuid().ToString("D");
            tied.InstallationIdHash = tiedInstall;
            tied.MachineClassification = kind;
            tied.MachineEvidenceSourceDecisionId = tied.Id;
            tied.MachineEvidenceDigestSha256 = Sha256(tied.Id.ToString("D"));
            db.Add(tied);
        }

        await db.SaveChangesAsync();
        Assert.Equal("unknown", (await RuntimeMachineEvidenceAuthority.FindAsync(db, "tia-connect-website", scenario.ProductId, scenario.LicenseId, request.GrantRefDigestSha256!, hardware, tiedInstall, request.KeyThumbprint, false, CancellationToken.None)).Kind);
    }

    /// <summary>Known installations recover missing proof without changing keys; a new grant reuses its linked immutable source.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_KnownEnrollmentFreshEvidenceAndNewGrantFinalize")]
    public async Task Tkt1550_KnownEnrollmentFreshEvidenceAndNewGrantFinalize()
    {
        var hardware = PersonalDayPassPostgreSqlTests.VmPolicyHardware;
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: hardware, initialSubjectRef: Base64Url(System.Security.Cryptography.SHA256.HashData("auto-new-subject"u8.ToArray())));
        await ActivateCanonicalScenarioAsync(scenario, hardware);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = "FREE";
        await db.SaveChangesAsync();
        var(client, first) = await BuildKnownDistributionPreflightRequestAsync(scenario);
        var preflight = new RuntimeDistributionPreflightService(scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var oldDigest = Sha256(JsonSerializer.Serialize(first));
        Assert.Equal("machine_evidence_required", (await Assert.ThrowsAsync<DistributionOperationException>(() => preflight.EvaluateAsync(client, oldDigest, first, CancellationToken.None))).ErrorCode);
        var before = await RuntimeGraphAsync(db, license.Id);
        first.RequestId = Guid.NewGuid().ToString("D");
        first.HardwareEvidence = new()
        {
            SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680")
        };
        await preflight.EvaluateAsync(client, Sha256(JsonSerializer.Serialize(first)), first, CancellationToken.None);
        Assert.Equal(before, await RuntimeGraphAsync(db, license.Id));
        var source = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync(row => row.Outcome == "accepted");
        var attempt = await PrepareAutoFinalizeForLicenseAsync(scenario, license.Id, hardware);
        attempt.Request.InstallationId = first.InstallationId;
        var next = VmPreflight(attempt.Request, license.Id, null, first.KeyThumbprint);
        next.HardwareEvidence = null;
        await preflight.EvaluateAsync(client, Sha256(JsonSerializer.Serialize(next)), next, CancellationToken.None);
        var linked = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync(row => row.RequestId == next.RequestId);
        Assert.Equal(source.Id, linked.MachineEvidenceSourceDecisionId);
        Assert.NotEqual(linked.Id, linked.MachineEvidenceSourceDecisionId);
        // A newer source on the preceding grant cannot leave this new grant linked to stale physical evidence.
        first.RequestId = Guid.NewGuid().ToString("D");
        first.HardwareEvidence = new()
        {
            SystemUuid = PersonalDayPassPostgreSqlTests.VmPolicyUuid,
            MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform")
        };
        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(() => preflight.EvaluateAsync(client, Sha256(JsonSerializer.Serialize(first)), first, CancellationToken.None))).ErrorCode);
        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(() => attempt.Service.FinalizeAsync(client, Sha256("known-stale-source"), attempt.Request))).ErrorCode);
        first.RequestId = Guid.NewGuid().ToString("D");
        first.HardwareEvidence.MachineEvidence = PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680");
        await preflight.EvaluateAsync(client, Sha256(JsonSerializer.Serialize(first)), first, CancellationToken.None);
        // Fresh physical evidence on another grant cannot itself grant rights: current grant must explicitly link it.
        var sourceCount = await db.RuntimeDistributionHardwareDecisions.CountAsync(row => row.MachineEvidenceSourceDecisionId == row.Id);
        Assert.Equal("machine_evidence_required", (await Assert.ThrowsAsync<DistributionOperationException>(() => preflight.EvaluateAsync(client, Sha256(JsonSerializer.Serialize(next)), next, CancellationToken.None))).ErrorCode);
        var replayed = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync(row => row.RequestId == next.RequestId);
        Assert.Equal(linked.MachineEvidenceSourceDecisionId, replayed.MachineEvidenceSourceDecisionId);
        Assert.Equal(linked.CreatedAtUtc, replayed.CreatedAtUtc);
        Assert.Equal(sourceCount, await db.RuntimeDistributionHardwareDecisions.CountAsync(row => row.MachineEvidenceSourceDecisionId == row.Id));
        Assert.Equal("machine_evidence_required", (await Assert.ThrowsAsync<DistributionOperationException>(() => attempt.Service.FinalizeAsync(client, Sha256("known-stale-positive"), attempt.Request))).ErrorCode);
        next.RequestId = Guid.NewGuid().ToString("D");
        await preflight.EvaluateAsync(client, Sha256(JsonSerializer.Serialize(next)), next, CancellationToken.None);
        var refreshed = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync(row => row.RequestId == next.RequestId);
        Assert.NotEqual(linked.MachineEvidenceSourceDecisionId, refreshed.MachineEvidenceSourceDecisionId);
        Assert.NotEqual(refreshed.Id, refreshed.MachineEvidenceSourceDecisionId);
        var finalized = await attempt.Service.FinalizeAsync(client, Sha256("known-new-grant"), attempt.Request);
        Assert.False(finalized.Idempotent);
        Assert.True((await db.Licenses.AsNoTracking().SingleAsync()).IsActive);
    }

    /// <summary>Missing proof recovers through a new full request; later VM proof wins over old physical replay without revocation.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_NewFinalizeUsesCurrentSourceAndHistoricalReplayStaysInert")]
    public async Task Tkt1550_NewFinalizeUsesCurrentSourceAndHistoricalReplayStaysInert()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = "FREE";
        await db.SaveChangesAsync();
        var attempt = await PrepareAutoFinalizeForLicenseAsync(scenario, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyHardware);
        var preflight = new RuntimeDistributionPreflightService(scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var missing = await Assert.ThrowsAsync<DistributionOperationException>(() => attempt.Service.FinalizeAsync("website-step1", Sha256("vm-missing-finalize"), attempt.Request));
        Assert.Equal("machine_evidence_required", missing.ErrorCode);
        var empty = VmPreflight(attempt.Request, license.Id, null);
        Assert.Equal("machine_evidence_required", (await Assert.ThrowsAsync<DistributionOperationException>(() => preflight.EvaluateAsync("website-step1", Sha256(JsonSerializer.Serialize(empty)), empty, CancellationToken.None))).ErrorCode);
        var physical = VmPreflight(attempt.Request, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680"));
        var physicalDigest = Sha256(JsonSerializer.Serialize(physical));
        await preflight.EvaluateAsync("website-step1", physicalDigest, physical, CancellationToken.None);
        var finalDigest = Sha256("vm-physical-finalize");
        var finalized = await attempt.Service.FinalizeAsync("website-step1", finalDigest, attempt.Request);
        Assert.False(finalized.Idempotent);
        var before = await RuntimeGraphAsync(db, license.Id);
        var vm = VmPreflight(attempt.Request, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform"));
        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(() => preflight.EvaluateAsync("website-step1", Sha256(JsonSerializer.Serialize(vm)), vm, CancellationToken.None))).ErrorCode);
        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(() => preflight.EvaluateAsync("website-step1", physicalDigest, physical, CancellationToken.None))).ErrorCode);
        var replay = await attempt.Service.FinalizeAsync("website-step1", finalDigest, attempt.Request);
        Assert.True(replay.Idempotent);
        Assert.Equal(finalized.Response, replay.Response);
        // A consumed entitlement cannot mint new rights. Issue a real fresh grant before testing a new finalize refusal.
        var nextAttempt = await PrepareAutoFinalizeForLicenseAsync(scenario, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyHardware);
        nextAttempt.Request.InstallationId = attempt.Request.InstallationId;
        var nextVm = VmPreflight(nextAttempt.Request, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyEvidence("VMware, Inc.", "VMware Virtual Platform"));
        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(() => preflight.EvaluateAsync("website-step1", Sha256(JsonSerializer.Serialize(nextVm)), nextVm, CancellationToken.None))).ErrorCode);
        Assert.Equal("virtual_machine_not_allowed", (await Assert.ThrowsAsync<DistributionOperationException>(() => nextAttempt.Service.FinalizeAsync("website-step1", Sha256("vm-new-finalize"), nextAttempt.Request))).ErrorCode);
        Assert.Equal(before, await RuntimeGraphAsync(db, license.Id));
        Assert.Null((await db.Licenses.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.True((await db.Licenses.AsNoTracking().SingleAsync()).IsActive);
        var decisions = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().OrderBy(row => row.CreatedAtUtc).ToListAsync();
        Assert.Equal(4, decisions.Count);
        Assert.All(decisions, row => Assert.Equal(row.Id, row.MachineEvidenceSourceDecisionId));
        Assert.Equal("physical", decisions[1].MachineClassification);
        Assert.Equal(1, decisions[1].AttemptCount);
    }

    /// <summary>Two authenticated keys for a new installation cannot be resolved by selecting the latest physical report.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_NewFinalizeRejectsAmbiguousKeysWithoutChangingRights")]
    public async Task Tkt1550_NewFinalizeRejectsAmbiguousKeysWithoutChangingRights()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = "PAID_TRIAL";
        await db.SaveChangesAsync();
        var attempt = await PrepareAutoFinalizeForLicenseAsync(scenario, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyHardware);
        var preflight = new RuntimeDistributionPreflightService(scenario.Factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        foreach (var key in new[]
        {
            new string ('A', 43),
            new string ('B', 43)
        }

        )
        {
            var request = VmPreflight(attempt.Request, license.Id, PersonalDayPassPostgreSqlTests.VmPolicyEvidence("Dell Inc.", "Precision 7680"), key);
            await preflight.EvaluateAsync("website-step1", Sha256(JsonSerializer.Serialize(request)), request, CancellationToken.None);
        }

        var before = await RuntimeGraphAsync(db, license.Id);
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => attempt.Service.FinalizeAsync("website-step1", Sha256("vm-key-conflict"), attempt.Request));
        Assert.Equal("machine_evidence_required", refusal.ErrorCode);
        Assert.Equal(before, await RuntimeGraphAsync(db, license.Id));
    }

    /// <summary>Preflight must reject a declared VM for a restricted license before an accepted decision can authorize finalize.</summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1550_PreflightRejectsRestrictedVm")]
    [InlineData("FREE")]
    [InlineData("PAID_TRIAL")]
    public async Task Tkt1550_PreflightRejectsRestrictedVm(string nature)
    {
        await using var database = await ProvisionCleanedIsolatedAsync();
        var admin = new TestDbFactory(database.Admin);
        var scenario = await SeedRuntimeDistributionScenarioAsync(admin);
        await using var db = await admin.CreateDbContextAsync();
        var license = await db.Licenses.SingleAsync();
        license.CommercialNature = nature;
        await db.SaveChangesAsync();
        scenario.Request.HardwareIdHash = null;
        scenario.Request.InstallationId = Guid.NewGuid().ToString("D");
        scenario.Request.KeyThumbprint = new string ('A', 43);
        scenario.Request.HardwareEvidence = new RuntimeDistributionHardwareEvidence
        {
            SystemUuid = "E42A9458-12C9-4759-B0E2-345AB6451290",
            // Exact WebSetup status/value shape verified in ticket note1884a52c; distinct from the SDK arrays.
            MachineEvidence = JsonSerializer.SerializeToElement(new { systemManufacturer = new { status = "present", value = "VMware, Inc." }, systemModel = new { status = "present", value = "VMware Virtual Platform" }, hypervisorPresent = new { status = "present", value = "True" } })
        };
        var service = new RuntimeDistributionPreflightService(new TestDbFactory(database.App), Mock.Of<ILogger<RuntimeDistributionPreflightService>>());
        var refusal = await Assert.ThrowsAsync<DistributionOperationException>(() => service.EvaluateAsync("tia-connect-website", new string ('d', 64), scenario.Request, CancellationToken.None));
        Assert.Equal("virtual_machine_not_allowed", refusal.ErrorCode);
        Assert.True((await db.Licenses.AsNoTracking().SingleAsync()).IsActive);
        Assert.Null((await db.Licenses.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.Equal("refused", (await db.RuntimeDistributionHardwareDecisions.AsNoTracking().SingleAsync()).Outcome);
    }
}

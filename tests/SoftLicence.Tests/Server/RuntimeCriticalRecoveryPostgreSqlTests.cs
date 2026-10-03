using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// A commercial-only global epoch bump cannot rewrite the enrolled credential during
    /// security recovery or either receipt path. Frozen replies remain gated by current B.
    /// </summary>
    [Fact]
    public async Task CriticalRecovery_CommercialBump_PreservesHistoricalAuthorityAndGatesReplays()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var eventId = await OpenPreparedCriticalIncidentAsync(scenario);
        long historicalEpoch;
        long globalBefore;
        await using (var change = await scenario.Factory.CreateDbContextAsync())
        {
            historicalEpoch = (await change.RuntimeEnrollments.SingleAsync()).AuthorityEpoch;
            globalBefore = await change.RuntimeEnrollmentAuthorityStates.Select(row => row.Epoch).SingleAsync();
            (await change.Licenses.SingleAsync()).MaxSeats += 1;
            await change.SaveChangesAsync();
        }
        await using (var check = await scenario.Factory.CreateDbContextAsync())
            Assert.True(await check.RuntimeEnrollmentAuthorityStates.Select(row => row.Epoch).SingleAsync()
                > globalBefore);

        var request = BuildPreparedCriticalRecoveryRequest(scenario, eventId);
        var bodyDigest = Sha256("critical-recovery-commercial-bump");
        var issued = await scenario.Runtime.RecoverCriticalAsync(
            "security-operator", "operator-key", bodyDigest, request);
        var replay = await scenario.Runtime.RecoverCriticalAsync(
            "security-operator", "rotated-operator-key", bodyDigest, request);
        Assert.False(issued.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, replay.ExactResponseBody);

        var refetch = new RuntimeCriticalRecoveryRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            RecoveryId = issued.Response.RecoveryId,
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            InstallationId = scenario.Fixture.InstallationId,
            EventId = eventId,
            NewSecurityEpoch = 2
        };
        var refetchDigest = Sha256("critical-recovery-s2s-refetch");
        var s2s = await scenario.Runtime.RefetchCriticalRecoveryAsync(
            "security-operator", "operator-key", refetchDigest, refetch);
        var s2sReplay = await scenario.Runtime.RefetchCriticalRecoveryAsync(
            "security-operator", "rotated-operator-key", refetchDigest, refetch);
        Assert.False(s2s.Idempotent);
        Assert.True(s2sReplay.Idempotent);
        Assert.Equal(s2s.ExactResponseBody, s2sReplay.ExactResponseBody);

        var clientRequest = new RuntimeCriticalRecoveryClientRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryClientRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1
        };
        var clientDigest = Sha256("critical-recovery-client-refetch");
        var clientProof = Proof(scenario.EnrollmentKey, "critical-recovery-refetch",
            scenario.EnrollmentId, scenario.Options.ConfirmAudience, "-", clientDigest);
        var client = await scenario.Runtime.RefetchCriticalRecoveryForClientAsync(
            scenario.EnrollmentId, clientDigest, clientRequest, clientProof, IPAddress.Loopback);
        var clientReplay = await scenario.Runtime.RefetchCriticalRecoveryForClientAsync(
            scenario.EnrollmentId, clientDigest, clientRequest, clientProof, IPAddress.Loopback);
        Assert.False(client.Idempotent);
        Assert.True(clientReplay.Idempotent);
        Assert.Equal(client.ExactResponseBody, clientReplay.ExactResponseBody);
        int quotaBefore;
        await using (var check = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await check.RuntimeEnrollments.SingleAsync();
            Assert.Equal(2, enrollment.SecurityEpoch);
            Assert.Equal(historicalEpoch, enrollment.AuthorityEpoch);
            Assert.Single(await check.RuntimeCriticalRecoveries.ToListAsync());
            Assert.Equal(2, await check.RuntimeCriticalRecoveryReceipts.CountAsync());
            quotaBefore = await check.RuntimeEnrollmentQuotas.SumAsync(row => row.Count);
        }

        await using (var revoke = await scenario.Factory.CreateDbContextAsync())
        {
            (await revoke.Licenses.SingleAsync()).IsActive = false;
            await revoke.SaveChangesAsync();
        }
        var recoveredDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RecoverCriticalAsync(
                "security-operator", "operator-key", bodyDigest, request));
        var s2sDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RefetchCriticalRecoveryAsync(
                "security-operator", "operator-key", refetchDigest, refetch));
        var clientDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RefetchCriticalRecoveryForClientAsync(
                scenario.EnrollmentId, clientDigest, clientRequest, clientProof, IPAddress.Loopback));
        Assert.All([recoveredDenied, s2sDenied, clientDenied], denial =>
        {
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, denial.StatusCode);
            Assert.Equal("authority_ineligible", denial.ErrorCode);
            Assert.Equal("assignment_missing", denial.DiagnosticCode);
        });
        await using var final = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(historicalEpoch, (await final.RuntimeEnrollments.SingleAsync()).AuthorityEpoch);
        Assert.Equal(2, (await final.RuntimeEnrollments.SingleAsync()).SecurityEpoch);
        Assert.Equal(2, await final.RuntimeCriticalRecoveryReceipts.CountAsync());
        Assert.Equal(1, await final.RuntimeEnrollmentProofNonces.CountAsync(row =>
            row.Operation == "critical-recovery-refetch"));
        Assert.Equal(quotaBefore, await final.RuntimeEnrollmentQuotas.SumAsync(row => row.Count));
    }

    /// <summary>
    /// A concurrent commercial revocation commits before recovery can cross the shared
    /// barrier. It leaves the incident open and cannot mint a signed recovery receipt.
    /// </summary>
    [Fact]
    public async Task CriticalRecovery_CommercialWriterWins_NoPartialSecurityTransition()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var eventId = await OpenPreparedCriticalIncidentAsync(scenario);
        var request = BuildPreparedCriticalRecoveryRequest(scenario, eventId);
        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var holdEnrollment = new NpgsqlCommand(
                         "SELECT 1 FROM public.\"RuntimeEnrollments\" WHERE \"Id\" = @enrollment FOR UPDATE;",
                         writer, transaction))
        {
            holdEnrollment.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, Convert.ToInt32(await holdEnrollment.ExecuteScalarAsync()));
        }
        await using (var revoke = new NpgsqlCommand(
                         "UPDATE public.\"Licenses\" SET \"IsActive\" = false WHERE \"ProductId\" = @product;",
                         writer, transaction))
        {
            revoke.Parameters.AddWithValue("product", scenario.Fixture.ProductId);
            Assert.Equal(1, await revoke.ExecuteNonQueryAsync());
        }
        var pending = scenario.Runtime.RecoverCriticalAsync(
            "security-operator", "operator-key", Sha256("critical-recovery-race"), request);
        var committed = false;
        try
        {
            await AssertRecoveryWaitsBehindWriterAsync(scenario, pending);
            await transaction.CommitAsync();
            committed = true;
            var denial = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => pending);
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, denial.StatusCode);
            Assert.Equal("authority_ineligible", denial.ErrorCode);
        }
        finally
        {
            if (!committed)
                await transaction.RollbackAsync();
            // Drain the service attempt after releasing the writer so fixture cleanup never
            // hides the original assertion with an unrelated active-session exception.
            try { await pending.WaitAsync(TimeSpan.FromSeconds(20)); }
            catch (Exception) { }
        }
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(1, (await check.RuntimeEnrollments.SingleAsync()).SecurityEpoch);
        Assert.Single(await check.RuntimeCriticalIncidents.Where(row => row.State == "OPEN").ToListAsync());
        Assert.Empty(await check.RuntimeCriticalRecoveries.ToListAsync());
        Assert.Empty(await check.RuntimeCriticalRecoveryReceipts.ToListAsync());
    }

    /// <summary>
    /// Commercial expiry is judged at database time after waiting for the assignment barrier.
    /// A time sampled before the wait must not authorize a new security transition.
    /// </summary>
    [Fact]
    public async Task CriticalRecovery_BarrierWaitPastLicenseExpiry_DeniesWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var eventId = await OpenPreparedCriticalIncidentAsync(scenario);
        var request = BuildPreparedCriticalRecoveryRequest(scenario, eventId);
        scenario.Options.LockTimeoutMilliseconds = 5000;
        scenario.Options.StatementTimeoutMilliseconds = 15000;
        var expiry = DateTime.UtcNow.AddSeconds(4);
        await using (var setExpiry = await scenario.Factory.CreateDbContextAsync())
        {
            (await setExpiry.Licenses.SingleAsync()).ExpirationDate = expiry;
            await setExpiry.SaveChangesAsync();
        }
        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand(
                         "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", writer, transaction))
            await hold.ExecuteNonQueryAsync();
        var pending = scenario.Runtime.RecoverCriticalAsync(
            "security-operator", "operator-key", Sha256("critical-recovery-expiry"), request);
        var committed = false;
        try
        {
            await AssertRecoveryWaitsOnCommercialBarrierAsync(scenario, pending);
            Assert.True(DateTime.UtcNow < expiry);
            await Task.Delay(expiry - DateTime.UtcNow + TimeSpan.FromMilliseconds(300));
            Assert.False(pending.IsCompleted);
            await transaction.CommitAsync();
            committed = true;
            var denial = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => pending);
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, denial.StatusCode);
            Assert.Equal("authority_ineligible", denial.ErrorCode);
            Assert.Equal("commercial_authority_ineligible", denial.DiagnosticCode);
        }
        finally
        {
            if (!committed)
                await transaction.RollbackAsync();
            try { await pending.WaitAsync(TimeSpan.FromSeconds(20)); }
            catch (Exception) { }
        }
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(1, (await check.RuntimeEnrollments.SingleAsync()).SecurityEpoch);
        Assert.Single(await check.RuntimeCriticalIncidents.Where(row => row.State == "OPEN").ToListAsync());
        Assert.Empty(await check.RuntimeCriticalRecoveries.ToListAsync());
        Assert.Empty(await check.RuntimeCriticalRecoveryReceipts.ToListAsync());
    }

    /// <summary>
    /// A broken assignment relation is unavailable provider state, never a commercial 422 or
    /// permission to resolve the security incident with invented seat authority.
    /// </summary>
    [Fact]
    public async Task CriticalRecovery_MissingAssignmentSeat_503LeavesIncidentOpen()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivatePreparedEnrollmentAsync(scenario);
        var eventId = await OpenPreparedCriticalIncidentAsync(scenario);
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var dropConstraint = new NpgsqlCommand("""
                DO $broken_relation$
                DECLARE constraint_name name;
                BEGIN
                    SELECT conname INTO constraint_name FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public."EnrollmentLicenseAssignments"'::pg_catalog.regclass
                      AND conname LIKE 'FK_EnrollmentLicenseAssignments_LicenseSeats%';
                    EXECUTE pg_catalog.format(
                        'ALTER TABLE public."EnrollmentLicenseAssignments" DROP CONSTRAINT %I',
                        constraint_name);
                END;
                $broken_relation$;
                """, admin);
            await dropConstraint.ExecuteNonQueryAsync();
            await using var breakRelation = new NpgsqlCommand("""
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @missing
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            breakRelation.Parameters.AddWithValue("missing", Guid.NewGuid());
            breakRelation.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, await breakRelation.ExecuteNonQueryAsync());
        }
        var unavailable = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RecoverCriticalAsync(
                "security-operator", "operator-key", Sha256("critical-recovery-broken-seat"),
                BuildPreparedCriticalRecoveryRequest(scenario, eventId)));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("authority_unavailable", unavailable.ErrorCode);
        Assert.Equal("assignment_relation_missing", unavailable.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(1, (await check.RuntimeEnrollments.SingleAsync()).SecurityEpoch);
        Assert.Single(await check.RuntimeCriticalIncidents.Where(row => row.State == "OPEN").ToListAsync());
        Assert.Empty(await check.RuntimeCriticalRecoveries.ToListAsync());
        Assert.Empty(await check.RuntimeCriticalRecoveryReceipts.ToListAsync());
    }

    /// <summary>Observes a live second connection blocked on the shared commercial barrier.</summary>
    private static async Task AssertRecoveryWaitsOnCommercialBarrierAsync(
        PreparedBootstrapScenario scenario, Task pending)
    {
        await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
        await observer.OpenAsync();
        var observedWait = false;
        for (var poll = 0; poll < 200 && !observedWait; poll++)
        {
            await using var activity = new NpgsqlCommand("""
                SELECT count(*) FROM pg_catalog.pg_stat_activity
                WHERE datname = pg_catalog.current_database()
                  AND pid <> pg_catalog.pg_backend_pid()
                  AND query LIKE '%pg_advisory_xact_lock_shared(1312, 1)%'
                  AND wait_event_type = 'Lock'
                  AND pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0;
                """, observer);
            observedWait = Convert.ToInt64(await activity.ExecuteScalarAsync()) > 0;
            if (!observedWait)
                await Task.Delay(10);
        }
        Assert.True(observedWait);
        Assert.False(pending.IsCompleted);
    }

    /// <summary>Observes the runtime reader blocked behind a real row/deferred writer.</summary>
    private static async Task AssertRecoveryWaitsBehindWriterAsync(
        PreparedBootstrapScenario scenario, Task pending)
    {
        await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
        await observer.OpenAsync();
        var observedWait = false;
        for (var poll = 0; poll < 200 && !observedWait; poll++)
        {
            await using var activity = new NpgsqlCommand("""
                SELECT count(*) FROM pg_catalog.pg_stat_activity
                WHERE datname = pg_catalog.current_database()
                  AND pid <> pg_catalog.pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0;
                """, observer);
            observedWait = Convert.ToInt64(await activity.ExecuteScalarAsync()) > 0;
            if (!observedWait)
                await Task.Delay(10);
        }
        Assert.True(observedWait);
        Assert.False(pending.IsCompleted);
    }

    /// <summary>Seeds a provider-owned OPEN incident for the exact prepared enrollment scope.</summary>
    private static async Task<string> OpenPreparedCriticalIncidentAsync(PreparedBootstrapScenario scenario)
    {
        var eventId = Guid.NewGuid().ToString("D");
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
        db.RuntimeCriticalIncidents.Add(new SoftLicence.Server.Data.RuntimeCriticalIncident
        {
            EnrollmentId = enrollment.Id,
            BindingId = enrollment.BindingId,
            ProductId = enrollment.ProductId,
            InstallationId = enrollment.InstallationId,
            EventId = eventId,
            Trigger = "RuntimeCheck_NativeDllSwapped",
            State = "OPEN",
            OpenedSecurityEpoch = enrollment.SecurityEpoch,
            OpenedAuthorityEpoch = enrollment.AuthorityEpoch,
            OpenedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        return eventId;
    }

    /// <summary>Builds one strict S2S security transition for the seeded OPEN incident.</summary>
    private static RuntimeCriticalRecoveryRequest BuildPreparedCriticalRecoveryRequest(
        PreparedBootstrapScenario scenario, string eventId) => new()
    {
        Schema = RuntimeEnrollmentService.CriticalRecoverySchema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        RequestId = Guid.NewGuid().ToString("D"),
        ProductId = scenario.Fixture.ProductId.ToString("D"),
        EnrollmentId = scenario.EnrollmentId.ToString("D"),
        BindingId = scenario.Fixture.BindingId.ToString("D"),
        InstallationId = scenario.Fixture.InstallationId,
        EventId = eventId,
        OldSecurityEpoch = 1,
        NewSecurityEpoch = 2
    };

    /// <summary>
    /// Exercises the full critical-recovery generation, receipt and capability replay contract.
    /// The terminal non-resurrection check runs last because item-2 assignment history forbids
    /// restoring an invalidated enrollment to ACTIVE; its isolated database is task-owned and
    /// disposed with the fixture after all assertions.
    /// </summary>
    [Fact]
    public async Task CriticalRecovery_BlocksBeforeCapabilityReplay_ResolvesGenerationAndRefetches()
    {
        var connections = await ProvisionIsolatedAsync();
        using var cleanup = new BootstrapIsolatedDatabaseCleanup(connections.Admin, connections.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        var otherFixture = await SeedAuthorityAsync(factory);
        string hardwareId;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var binding = await seed.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            var seat = await seed.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
            hardwareId = seat.HardwareId.ToUpperInvariant();
            seat.HardwareId = hardwareId;
            binding.HardwareIdHash = Sha256(hardwareId);
            await seed.SaveChangesAsync();
        }

        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        using var ackKey = RSA.Create(2048);
        var options = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(
            factory,
            authority,
            registry,
            crypto,
            Options.Create(options),
            new CanaryAckService(factory, configuration, TimeProvider.System));

        var prepared = await service.PrepareAsync(
            "website-step1",
            Sha256("critical-recovery-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirmDigest = Sha256("critical-recovery-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        }, Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
            prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        await using (var mismatchedScope = await factory.CreateDbContextAsync())
        {
            mismatchedScope.RuntimeCriticalIncidents.Add(new SoftLicence.Server.Data.RuntimeCriticalIncident
            {
                EnrollmentId = enrollmentId,
                BindingId = otherFixture.BindingId,
                ProductId = otherFixture.ProductId,
                InstallationId = otherFixture.InstallationId,
                EventId = Guid.NewGuid().ToString("D"),
                Trigger = "RuntimeCheck_NativeDllSwapped",
                State = "OPEN",
                OpenedSecurityEpoch = 1,
                OpenedAuthorityEpoch = 0,
                OpenedAtUtc = DateTime.UtcNow
            });
            var mismatch = await Assert.ThrowsAsync<DbUpdateException>(() =>
                mismatchedScope.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
                Assert.IsType<PostgresException>(mismatch.InnerException).SqlState);
        }
        await using (var mismatchedInstallation = await factory.CreateDbContextAsync())
        {
            mismatchedInstallation.RuntimeCriticalIncidents.Add(
                new SoftLicence.Server.Data.RuntimeCriticalIncident
                {
                    EnrollmentId = enrollmentId,
                    BindingId = fixture.BindingId,
                    ProductId = fixture.ProductId,
                    InstallationId = otherFixture.InstallationId,
                    EventId = Guid.NewGuid().ToString("D"),
                    Trigger = "RuntimeCheck_NativeDllSwapped",
                    State = "OPEN",
                    OpenedSecurityEpoch = 1,
                    OpenedAuthorityEpoch = 0,
                    OpenedAtUtc = DateTime.UtcNow
                });
            var mismatch = await Assert.ThrowsAsync<DbUpdateException>(() =>
                mismatchedInstallation.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
                Assert.IsType<PostgresException>(mismatch.InnerException).SqlState);
        }
        await using (var mismatchedRecovery = await factory.CreateDbContextAsync())
        {
            mismatchedRecovery.RuntimeCriticalRecoveries.Add(
                new SoftLicence.Server.Data.RuntimeCriticalRecovery
                {
                    EnrollmentId = enrollmentId,
                    BindingId = fixture.BindingId,
                    ProductId = fixture.ProductId,
                    InstallationId = otherFixture.InstallationId,
                    RequestedEventId = Guid.NewGuid().ToString("D"),
                    OldSecurityEpoch = 1,
                    NewSecurityEpoch = 2,
                    ResolvedIncidentCount = 1,
                    AuthorityEpoch = 0,
                    RecoveredByClientId = "security-operator",
                    RecoveredByKeyId = "operator-key",
                    RecoveredAtUtc = DateTime.UtcNow
                });
            var mismatch = await Assert.ThrowsAsync<DbUpdateException>(() =>
                mismatchedRecovery.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
                Assert.IsType<PostgresException>(mismatch.InnerException).SqlState);
        }

        var capabilityRequest = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            InstallationId = fixture.InstallationId,
            ReleaseVersion = fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var capabilityDigest = Sha256("critical-recovery-capability");
        var frozenCapabilityProof = Proof(enrollmentKey, "capability", enrollmentId,
            capabilityRequest.Audience, "-", capabilityDigest);
        var issuedBeforeIncident = await service.CreateCapabilityAsync(
            enrollmentId, capabilityDigest, capabilityRequest, frozenCapabilityProof, IPAddress.Loopback);
        Assert.False(issuedBeforeIncident.Idempotent);

        var firstEvent = await OpenCriticalAsync("first");
        var secondEvent = await OpenCriticalAsync("second");

        var blockedReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.CreateCapabilityAsync(
                enrollmentId, capabilityDigest, capabilityRequest, frozenCapabilityProof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status423Locked, blockedReplay.StatusCode);
        Assert.Equal("critical_incident_unresolved", blockedReplay.ErrorCode);

        var recoveryRequest = new RuntimeCriticalRecoveryRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoverySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            InstallationId = fixture.InstallationId,
            EventId = firstEvent,
            OldSecurityEpoch = 1,
            NewSecurityEpoch = 2
        };
        var recoveryDigest = Sha256("critical-recovery-exact-body");
        var recovered = await Task.WhenAll(
            service.RecoverCriticalAsync("security-operator", "operator-key", recoveryDigest, recoveryRequest),
            service.RecoverCriticalAsync("security-operator", "operator-key", recoveryDigest, recoveryRequest));
        Assert.Single(recovered, result => !result.Idempotent);
        Assert.Single(recovered, result => result.Idempotent);
        Assert.Single(recovered.Select(result => Convert.ToBase64String(result.ExactResponseBody)).Distinct());
        Assert.All(recovered, result => Assert.Equal(2, result.Response.NewSecurityEpoch));
        AssertRecoverySignature(recovered[0].Response, activeSigning);
        var previousTrustEntry = new RuntimeCapabilitySigningKeyOptions
        {
            KeyId = recovered[0].Response.KeyId,
            Role = "previous",
            PublicKeyPem = activeSigning.ExportSubjectPublicKeyInfoPem(),
            RetainUntilUtc = DateTimeOffset.UtcNow.AddHours(25)
        };
        Assert.Null(previousTrustEntry.PrivateKeyPem);
        using (var previousVerifier = RSA.Create())
        {
            previousVerifier.ImportFromPem(previousTrustEntry.PublicKeyPem);
            AssertRecoverySignature(recovered[0].Response, previousVerifier);
        }

        await using (var check = await factory.CreateDbContextAsync())
        {
            Assert.Equal(2, (await check.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
            Assert.Equal(2, await check.RuntimeCriticalIncidents.CountAsync(row =>
                row.BindingId == fixture.BindingId && row.State == "RESOLVED"));
            Assert.False(await check.RuntimeCriticalIncidents.AnyAsync(row =>
                row.BindingId == fixture.BindingId && row.InstallationId == fixture.InstallationId && row.State == "OPEN"));
            var recovery = await check.RuntimeCriticalRecoveries.SingleAsync();
            Assert.Equal(2, recovery.ResolvedIncidentCount);
            Assert.Single(await check.RuntimeCriticalRecoveryReceipts.ToListAsync());
        }

        var stalePostRecoveryProof = Proof(enrollmentKey, "capability", enrollmentId,
            capabilityRequest.Audience, "-", capabilityDigest);
        var staleEpoch = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.CreateCapabilityAsync(
                enrollmentId, capabilityDigest, capabilityRequest,
                stalePostRecoveryProof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status409Conflict, staleEpoch.StatusCode);
        Assert.Equal("security_epoch_mismatch", staleEpoch.ErrorCode);

        var clientRefetch = new RuntimeCriticalRecoveryClientRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryClientRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1
        };
        var clientRefetchDigest = Sha256("critical-recovery-client-refetch-body");
        var clientRefetchProof = Proof(
            enrollmentKey, "critical-recovery-refetch", enrollmentId,
            options.ConfirmAudience, "-", clientRefetchDigest);
        var clientReceipt = await service.RefetchCriticalRecoveryForClientAsync(
            enrollmentId, clientRefetchDigest, clientRefetch,
            clientRefetchProof, IPAddress.Loopback);
        Assert.Equal(1, clientReceipt.Response.OldSecurityEpoch);
        Assert.Equal(2, clientReceipt.Response.NewSecurityEpoch);
        Assert.Equal(firstEvent, clientReceipt.Response.EventId);
        AssertRecoverySignature(clientReceipt.Response, activeSigning);

        capabilityRequest.SecurityEpoch = 2;
        var postRecoveryProof = Proof(enrollmentKey, "capability", enrollmentId,
            capabilityRequest.Audience, "-", capabilityDigest);
        Assert.False((await service.CreateCapabilityAsync(
            enrollmentId, capabilityDigest, capabilityRequest, postRecoveryProof, IPAddress.Loopback)).Idempotent);

        var refetch = new RuntimeCriticalRecoveryRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            RecoveryId = recovered[0].Response.RecoveryId,
            BindingId = fixture.BindingId.ToString("D"),
            InstallationId = fixture.InstallationId,
            EventId = firstEvent,
            NewSecurityEpoch = 2
        };
        var refetchDigest = Sha256("critical-recovery-refetch-body");
        var refreshed = await service.RefetchCriticalRecoveryAsync(
            "security-operator", "operator-key", refetchDigest, refetch);
        var refreshedReplay = await service.RefetchCriticalRecoveryAsync(
            "security-operator", "rotated-operator-key", refetchDigest, refetch);
        Assert.False(refreshed.Idempotent);
        Assert.True(refreshedReplay.Idempotent);
        Assert.Equal(refreshed.ExactResponseBody, refreshedReplay.ExactResponseBody);
        AssertRecoverySignature(refreshed.Response, activeSigning);

        await using (var mutation = await factory.CreateDbContextAsync())
        {
            var binding = await mutation.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            var license = await mutation.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
            license.IsActive = false;
            license.RevokedAt = DateTime.UtcNow;
            await mutation.SaveChangesAsync();
        }
        await AssertStoredReceiptsRejectedAsync("authority_ineligible");
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var binding = await restore.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            var license = await restore.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
            license.IsActive = true;
            license.RevokedAt = null;
            await restore.SaveChangesAsync();
        }

        await using (var mutation = await factory.CreateDbContextAsync())
        {
            var binding = await mutation.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = DateTime.UtcNow;
            binding.InvalidationReason = "recovery replay regression";
            await mutation.SaveChangesAsync();
        }
        await AssertStoredReceiptsRejectedAsync("binding_ineligible");
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var binding = await restore.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            binding.State = "active";
            binding.InvalidatedAtUtc = null;
            binding.InvalidationReason = null;
            await restore.SaveChangesAsync();
        }

        await using (var expire = await factory.CreateDbContextAsync())
        {
            var receipts = await expire.RuntimeCriticalRecoveryReceipts.ToListAsync();
            foreach (var receipt in receipts)
            {
                receipt.IssuedAtUtc = DateTime.UtcNow.AddHours(-26);
                receipt.ExpiresAtUtc = DateTime.UtcNow.AddHours(-2);
            }
            await expire.SaveChangesAsync();
            await expire.Database.ExecuteSqlRawAsync("""
                UPDATE public."RuntimeCriticalRecoveryReceipts"
                SET "ExactResponseBody" = NULL,
                    "DeliveryPurgedAtUtc" = clock_timestamp()
                WHERE "ExactResponseBody" IS NOT NULL
                  AND "ExpiresAtUtc" <= clock_timestamp();
                """);
        }
        await AssertStoredReceiptsRejectedAsync("recovery_receipt_expired");
        await using (var tombstones = await factory.CreateDbContextAsync())
        {
            Assert.Equal(2, await tombstones.RuntimeCriticalRecoveryReceipts.CountAsync());
            Assert.False(await tombstones.RuntimeCriticalRecoveryReceipts
                .AnyAsync(receipt => receipt.ExactResponseBody != null));
            Assert.Single(await tombstones.RuntimeCriticalRecoveries.ToListAsync());
            Assert.Equal(2, (await tombstones.RuntimeEnrollments
                .SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
        }

        var postExpiryRefetch = new RuntimeCriticalRecoveryRefetchRequest
        {
            Schema = refetch.Schema,
            ProtocolVersion = refetch.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = refetch.ProductId,
            RecoveryId = refetch.RecoveryId,
            BindingId = refetch.BindingId,
            InstallationId = refetch.InstallationId,
            EventId = refetch.EventId,
            NewSecurityEpoch = refetch.NewSecurityEpoch
        };
        var postExpiryDelivery = await service.RefetchCriticalRecoveryAsync(
            "security-operator", "operator-key", Sha256("post-expiry-refetch"), postExpiryRefetch);
        Assert.False(postExpiryDelivery.Idempotent);
        Assert.NotEmpty(postExpiryDelivery.ExactResponseBody);
        AssertRecoverySignature(postExpiryDelivery.Response, activeSigning);

        var thirdEvent = await OpenCriticalAsync("third");
        var staleRefetchRequest = new RuntimeCriticalRecoveryRefetchRequest
        {
            Schema = refetch.Schema,
            ProtocolVersion = refetch.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = refetch.ProductId,
            RecoveryId = refetch.RecoveryId,
            BindingId = refetch.BindingId,
            InstallationId = refetch.InstallationId,
            EventId = refetch.EventId,
            NewSecurityEpoch = refetch.NewSecurityEpoch
        };
        var staleRefetch = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RefetchCriticalRecoveryAsync(
                "security-operator", "operator-key", Sha256("new-refetch"), staleRefetchRequest));
        Assert.Equal("recovery_generation_conflict", staleRefetch.ErrorCode);

        var wrongGeneration = recoveryRequest;
        wrongGeneration.RequestId = Guid.NewGuid().ToString("D");
        wrongGeneration.EventId = thirdEvent;
        var generationConflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RecoverCriticalAsync(
                "security-operator", "operator-key", Sha256("wrong-generation"), wrongGeneration));
        Assert.Equal("recovery_binding_conflict", generationConflict.ErrorCode);

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await using (var appRole = new NpgsqlConnection(connections.App))
        {
            await appRole.OpenAsync();
            Assert.True(await ScalarAsync<bool>(appRole, """
                SELECT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalIncidents"', 'SELECT,INSERT,UPDATE')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalIncidents"', 'DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveries"', 'SELECT,INSERT,UPDATE')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveries"', 'DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveryReceipts"', 'SELECT,INSERT,UPDATE')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveryReceipts"', 'DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentAuthorityStates"', 'SELECT')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentAuthorityStates"', 'INSERT,UPDATE,DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentKeyRegistries"', 'SELECT')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentKeyRegistries"', 'INSERT,UPDATE,DELETE,TRUNCATE');
                """));
        }
        await ExecuteAsync(admin, "SET enable_seqscan = off;");
        await using var explain = admin.CreateCommand();
        explain.CommandText = "EXPLAIN SELECT 1 FROM public.\"RuntimeCriticalIncidents\" WHERE \"BindingId\"=@binding AND \"InstallationId\"=@installation AND \"State\"='OPEN';";
        explain.Parameters.AddWithValue("binding", fixture.BindingId);
        explain.Parameters.AddWithValue("installation", fixture.InstallationId);
        var plan = string.Join('\n', await ReadRowsAsync(explain));
        Assert.Contains("IX_RuntimeCriticalIncidents_BindingId_InstallationId_State", plan, StringComparison.Ordinal);

        await ExecuteAsync(admin, "DELETE FROM public.\"RuntimeCanaryProofNonces\";");
        await using var durable = await factory.CreateDbContextAsync();
        Assert.Equal(3, await durable.RuntimeCriticalIncidents.CountAsync());

        // A terminal enrollment cannot be restored after item-2 ledger revocation. Prove
        // the stored receipts cannot resurrect it only after the active-state cases finish.
        await using (var mutation = await factory.CreateDbContextAsync())
        {
            var enrollment = await mutation.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "recovery replay regression";
            await mutation.SaveChangesAsync();
        }
        await AssertStoredReceiptsRejectedAsync();

        async Task AssertStoredReceiptsRejectedAsync(string? expectedErrorCode = null)
        {
            var recoveryReplay = await CaptureAsync(() => service.RecoverCriticalAsync(
                "security-operator", "operator-key", recoveryDigest, recoveryRequest));
            var refetchReplay = await CaptureAsync(() => service.RefetchCriticalRecoveryAsync(
                "security-operator", "rotated-operator-key", refetchDigest, refetch));

            Assert.Null(recoveryReplay.Result);
            Assert.Null(refetchReplay.Result);
            var recoveryError = Assert.IsType<RuntimeEnrollmentException>(recoveryReplay.Error);
            var refetchError = Assert.IsType<RuntimeEnrollmentException>(refetchReplay.Error);
            Assert.False(recoveryError.StatusCode is >= 200 and < 300);
            Assert.False(refetchError.StatusCode is >= 200 and < 300);
            if (expectedErrorCode != null)
            {
                Assert.Equal(expectedErrorCode, recoveryError.ErrorCode);
                Assert.Equal(expectedErrorCode, refetchError.ErrorCode);
            }
        }

        async Task<string> OpenCriticalAsync(string suffix)
        {
            var canary = new CanaryPingRequest
            {
                Schema = CanaryAckService.Schema,
                EventId = Guid.NewGuid().ToString("D"),
                SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
                HardwareId = hardwareId,
                AppVersion = fixture.Version,
                Trigger = "RuntimeCheck_NativeDllSwapped",
                Severity = 3
            };
            var digest = Sha256("critical-canary-" + suffix);
            await service.ProcessCanaryAsync(enrollmentId, digest, canary,
                CanaryProof(enrollmentKey, enrollmentId, canary.EventId!, digest, options),
                IPAddress.Loopback);
            return canary.EventId!;
        }
    }

    private static void AssertRecoverySignature(RuntimeCriticalRecoveryResponse response, RSA key)
    {
        var signature = DecodeBase64Url(response.Signature);
        var payload = RuntimeEnrollmentCryptoService.BuildRecoverySignaturePayload(
            response with { Signature = string.Empty });
        Assert.True(key.VerifyData(
            Encoding.UTF8.GetBytes(payload),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
        Assert.False(key.VerifyData(
            Encoding.UTF8.GetBytes(RuntimeEnrollmentCryptoService.BuildRecoverySignaturePayload(
                response with { BindingId = Guid.NewGuid().ToString("D"), Signature = string.Empty })),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
        Assert.False(key.VerifyData(
            Encoding.UTF8.GetBytes(payload.Replace(
                RuntimeEnrollmentService.CriticalRecoveryResponseSchema,
                "runtime-enrollment-capability-v1",
                StringComparison.Ordinal)),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
    }

    private static async Task<IReadOnlyList<string>> ReadRowsAsync(NpgsqlCommand command)
    {
        var rows = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            rows.Add(reader.GetString(0));
        return rows;
    }
}

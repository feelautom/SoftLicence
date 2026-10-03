using System.Globalization;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises the Source C producer over a script-owned isolated PostgreSQL 17 database.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Produces all four scenarios through the production v2 service, proves bounded metadata collection,
    /// semantic replay, cancellation retry, PS256 output, and absence of raw provider values.
    /// </summary>
    [Fact]
    public async Task Tkt000672SourceCAuthority_RealV2FlowsAreBoundedReplayableAndMetadataOnly()
    {
        var connectionString = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
        var bootstrapConnectionString = Environment.GetEnvironmentVariable(
            "SOFTLICENCE_RUNTIME_TEST_POSTGRES_BOOTSTRAP");
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new InvalidOperationException(
                "Use scripts/Invoke-Tkt000672SourceCAuthority.ps1 to provision the isolated PostgreSQL 17 resource.");
        var builder = new NpgsqlConnectionStringBuilder(connectionString);
        var database = builder.Database ?? throw new InvalidOperationException("The isolated database name is required.");
        Assert.StartsWith("sl_tkt672_sc_", database, StringComparison.Ordinal);
        if (string.IsNullOrWhiteSpace(bootstrapConnectionString))
            bootstrapConnectionString = connectionString;
        await AssertOwnedDatabaseAsync(bootstrapConnectionString, database);
        var bootstrapOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(bootstrapConnectionString).Options;
        await using (var migration = new LicenseDbContext(bootstrapOptions))
            await migration.Database.MigrateAsync();
        await GrantAndAssertApplicationPrivilegesAsync(
            bootstrapConnectionString, connectionString, builder.Username!, database);
        await ProvisionEnrollmentEncryptionKeyAsync(bootstrapConnectionString, "test");
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options;
        var factory = new Tkt000672PostgreSqlFactory(options);

        DateTimeOffset observed;
        await using (var clock = await factory.CreateDbContextAsync())
        {
            await clock.Database.OpenConnectionAsync();
            var databaseNow = await RuntimeEnrollmentService.DatabaseNowAsync(clock, CancellationToken.None);
            // One millisecond-precision anchor keeps request timestamps and current licence policy coherent.
            observed = DateTimeOffset.FromUnixTimeMilliseconds(databaseNow.ToUnixTimeMilliseconds());
        }
        await using var executor = new PostgreSqlRealScenarioExecutor(factory, observed);
        using var signers = new StableSignerFactory();
        var harness = new Tkt000672SourceCAuthorityHarness(
            new Tkt000672PostgreSqlEvidenceReader(factory), executor, signers);
        var request = Tkt000672SourceCAuthorityContract.ParseRequest(PostgreSqlRequest(observed)).Request!;
        executor.InterruptAfterFirstPersistedGeneration = true;
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            harness.RunAsync(request, CancellationToken.None));
        await using (var interrupted = await factory.CreateDbContextAsync())
            Assert.Equal(1, await interrupted.RuntimeEnrollmentAuthorityGenerations.AsNoTracking().CountAsync(
                item => executor.RequestIds.Contains(item.RequestId)));
        using var start = new Barrier(2);
        // Releases both complete harness calls together so the executor's per-scenario atomicity is observable.
        async Task<Tkt000672HarnessResult> CompleteAsync()
        {
            start.SignalAndWait();
            return await harness.RunAsync(request, CancellationToken.None);
        }
        var completions = await Task.WhenAll(Task.Run(CompleteAsync), Task.Run(CompleteAsync));
        Assert.All(completions, result => Assert.True(result.Ok));
        var first = completions[0];
        Assert.True(first.Ok);
        Assert.Equal(9, executor.RealServiceCalls);
        Assert.Equal(5, first.Response!.Manifest["payload"]!["history"]!["generationCount"]!.GetValue<int>());
        Assert.Equal(
            [
                ("PROVEN", "PROVEN_EXACT_ATTESTED_TUPLE", 1, 1),
                ("PARTIAL", "PARTIAL_REQUIRED_EVIDENCE_MISSING", 1, 1),
                ("AMBIGUOUS", "AMBIGUOUS_MULTIPLE_ATTESTED_TUPLES", 2, 2),
                ("INCONSISTENT", "INCONSISTENT_ATTESTED_TUPLE_CONFLICT", 1, 1)
            ],
            first.Response.ClassificationEvidence.Select(item =>
                (item.Classification, item.Reason, item.RequestCount, item.GenerationCount)).ToArray());
        var firstDigest = first.Response.Manifest["authorityDigest"]!.GetValue<string>();
        var second = await harness.RunAsync(request, CancellationToken.None);
        Assert.True(second.Ok);
        Assert.Equal(9, executor.RealServiceCalls);
        Assert.Equal(firstDigest, second.Response!.Manifest["authorityDigest"]!.GetValue<string>());
        Assert.DoesNotContain(executor.RawGrantRefs, grant =>
            second.Response.Manifest.ToJsonString().Contains(grant, StringComparison.Ordinal));
        await using var check = await factory.CreateDbContextAsync();
        Assert.Equal(5, await check.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .CountAsync(item => executor.RequestIds.Contains(item.RequestId)));
        Assert.Equal(5, await check.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
            .CountAsync(item => executor.RequestIds.Contains(item.RequestId)));
        Assert.Equal(executor.RequestIds.Count, await check.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
            .Where(item => executor.RequestIds.Contains(item.RequestId))
            .Select(item => item.RequestId).Distinct().CountAsync());

        var priorRuntimeConnection = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
        try
        {
            Environment.SetEnvironmentVariable(
                "SOFTLICENCE_RUNTIME_TEST_POSTGRES", bootstrapConnectionString, EnvironmentVariableTarget.Process);
            await AuthorityRecovery_TwoStageProductionFlowCommitsAndReplaysExactly(-90);
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "SOFTLICENCE_RUNTIME_TEST_POSTGRES", priorRuntimeConnection, EnvironmentVariableTarget.Process);
        }
    }

    /// <summary>Grants and proves the exact non-superuser application privileges after bootstrap migrations.</summary>
    private static async Task GrantAndAssertApplicationPrivilegesAsync(
        string bootstrapConnectionString, string applicationConnectionString,
        string applicationRole, string database)
    {
        if (!applicationRole.StartsWith("sl_tkt672_app_", StringComparison.Ordinal)
            && applicationConnectionString != bootstrapConnectionString)
            throw new InvalidOperationException("The application role is outside the ticket-owned namespace.");
        await using var bootstrap = new NpgsqlConnection(bootstrapConnectionString);
        await bootstrap.OpenAsync();
        if (applicationConnectionString != bootstrapConnectionString)
        {
            var quotedRole = '"' + applicationRole.Replace("\"", "\"\"") + '"';
            await using var grant = bootstrap.CreateCommand();
            grant.CommandText = $"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {quotedRole}; "
                + $"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {quotedRole};";
            await grant.ExecuteNonQueryAsync();
        }
        await using var application = new NpgsqlConnection(applicationConnectionString);
        await application.OpenAsync();
        await using var proof = application.CreateCommand();
        proof.CommandText = """
            SELECT current_database() = @database,
                   current_user = @role,
                   NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
                   NOT (SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user),
                   NOT (SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user),
                   NOT (SELECT rolreplication FROM pg_roles WHERE rolname = current_user),
                   NOT (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user),
                   has_database_privilege(current_user, current_database(), 'CONNECT'),
                   has_schema_privilege(current_user, 'public', 'USAGE'),
                   NOT has_schema_privilege(current_user, 'public', 'CREATE'),
                   COALESCE(bool_and(has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'SELECT')), true),
                   COALESCE(bool_and(has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'INSERT')), true),
                   COALESCE(bool_and(has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'UPDATE')), true),
                   COALESCE(bool_and(has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'DELETE')), true),
                   COALESCE(bool_and(NOT has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'TRUNCATE')), true),
                   COALESCE(bool_and(NOT has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'REFERENCES')), true),
                   COALESCE(bool_and(NOT has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'TRIGGER')), true),
                   COALESCE(bool_and(NOT has_table_privilege(current_user,
                       format('%I.%I', schemaname, tablename), 'MAINTAIN')), true),
                   (SELECT COALESCE(bool_and(has_sequence_privilege(current_user,
                       format('%I.%I', sequence_schema, sequence_name), 'USAGE')), true)
                    FROM information_schema.sequences WHERE sequence_schema = 'public'),
                   (SELECT COALESCE(bool_and(has_sequence_privilege(current_user,
                       format('%I.%I', sequence_schema, sequence_name), 'SELECT')), true)
                    FROM information_schema.sequences WHERE sequence_schema = 'public'),
                   (SELECT COALESCE(bool_and(has_sequence_privilege(current_user,
                       format('%I.%I', sequence_schema, sequence_name), 'UPDATE')), true)
                    FROM information_schema.sequences WHERE sequence_schema = 'public'),
                   NOT EXISTS (
                       SELECT 1 FROM pg_namespace n,
                           LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
                       WHERE n.nspname = 'public' AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                           AND a.is_grantable),
                   NOT EXISTS (
                       SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,
                           LATERAL aclexplode(COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, c.relowner))) a
                       WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S')
                           AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                           AND a.is_grantable)
            FROM pg_tables WHERE schemaname = 'public'
            """;
        proof.Parameters.AddWithValue("database", database);
        proof.Parameters.AddWithValue("role", applicationRole);
        await using var reader = await proof.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        for (var index = 0; index < 23; index++) Assert.True(reader.GetBoolean(index));
        Assert.False(await reader.ReadAsync());
    }

    /// <summary>Proves the current database name and ticket-purpose comment before any fixture mutation.</summary>
    /// <param name="connectionString">Bootstrap connection kept out of output.</param>
    /// <param name="database">Expected ticket-owned database name.</param>
    /// <returns>A task completing only after the exact ownership row is proven.</returns>
    private static async Task AssertOwnedDatabaseAsync(string connectionString, string database)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT d.datname, pg_catalog.shobj_description(d.oid, 'pg_database')
            FROM pg_catalog.pg_database d WHERE d.datname = current_database()
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(database, reader.GetString(0));
        Assert.Equal("ticket=TKT-000672;purpose=source-c-authority", reader.GetString(1));
        Assert.False(await reader.ReadAsync());
    }

    /// <summary>Serializes one closed metadata-only request for the isolated PostgreSQL execution.</summary>
    /// <param name="observed">Shared database-clock anchor for this synthetic scenario.</param>
    /// <returns>Owned compact UTF-8 JSON bytes.</returns>
    private static byte[] PostgreSqlRequest(DateTimeOffset observed) => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
    {
        schema = Tkt000672SourceCAuthorityContract.RequestSchema,
        runId = "run_00000000000000000000000000000003",
        environment = Tkt000672SourceCAuthorityContract.Environment,
        sourceId = "source_c_postgresql_01",
        observedAtUtc = observed.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
        snapshotHash = new string('1', 64), catalogHash = new string('2', 64),
        migrationsHash = new string('3', 64), oracleHash = new string('4', 64),
        generationSpecHash = new string('5', 64), providerScope = "provider_scope_pg",
        productScope = "product_scope_pg", grantScope = "grant_scope_pg"
    });

    /// <summary>
    /// Atomically provisions each closed scenario once, traverses authenticated production v2 HTTP routes,
    /// and exposes only owned request IDs for bounded PostgreSQL evidence collection. Lazy initialization plus
    /// a per-scenario gate makes concurrent complete harness calls share one persisted state; interrupted genesis
    /// remains resumable and recovery preparation/finalization never bypasses the controller.
    /// </summary>
    private sealed class PostgreSqlRealScenarioExecutor : ITkt000672AuthorityScenarioExecutor, IAsyncDisposable
    {
        private readonly Tkt000672PostgreSqlFactory factory;
        private readonly DateTimeOffset observed;
        private readonly ConcurrentDictionary<string, Lazy<Task<ScenarioState>>> states =
            new(StringComparer.Ordinal);

        /// <summary>Creates the executor over the isolated application-role factory and exact observed instant.</summary>
        /// <param name="factory">Application-role PostgreSQL factory; bootstrap authority is not accepted.</param>
        /// <param name="observed">Exact UTC instant shared by signing, S2S, trust, and evidence fixtures.</param>
        internal PostgreSqlRealScenarioExecutor(Tkt000672PostgreSqlFactory factory, DateTimeOffset observed)
        {
            this.factory = factory;
            this.observed = observed;
        }

        private int realServiceCalls;
        /// <summary>Gets the exact count of real authority-v2 service invocations, excluding cached dispatcher replay.</summary>
        internal int RealServiceCalls => realServiceCalls;
        /// <summary>Gets all request IDs owned by completed state, including the recovered successor.</summary>
        internal IReadOnlyCollection<Guid> RequestIds => states.Values.Where(item => item.IsValueCreated)
            .Select(item => item.Value).Where(task => task.IsCompletedSuccessfully).Select(task => task.Result)
            .SelectMany(item => item.RecoveryRequestId is { } recovery
                ? new[] { item.RequestId, recovery } : new[] { item.RequestId })
            .ToArray();
        /// <summary>Gets raw synthetic grant references only for negative no-leak assertions.</summary>
        internal IReadOnlyCollection<string> RawGrantRefs => states.Values.Where(item => item.IsValueCreated)
            .Select(item => item.Value).Where(task => task.IsCompletedSuccessfully)
            .Select(item => item.Result.RawGrantRef).ToArray();

        /// <summary>Gets or sets a one-shot interruption injected after the first persisted genesis.</summary>
        internal bool InterruptAfterFirstPersistedGeneration { get; set; }

        /// <inheritdoc />
        public async Task<Tkt000672ScenarioExecution> ExecuteAsync(
            Tkt000672Scenario scenario, Tkt000672SourceCRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var state = await states.GetOrAdd(scenario.ScenarioId, _ => new Lazy<Task<ScenarioState>>(
                () => CreateStateAsync(scenario, CancellationToken.None),
                LazyThreadSafetyMode.ExecutionAndPublication)).Value.WaitAsync(cancellationToken);
            await state.Gate.WaitAsync(cancellationToken);
            try
            {
                if (!state.GenesisIssued)
                {
                    await IssueAsync(state, state.Body, 201, cancellationToken);
                    state.GenesisIssued = true;
                    if (InterruptAfterFirstPersistedGeneration)
                    {
                        InterruptAfterFirstPersistedGeneration = false;
                        throw new OperationCanceledException("tkt672_interrupted_after_persisted_generation");
                    }
                }
                if (!state.Completed)
                {
                    if (scenario.ScenarioId == "scenario_ambiguous")
                        await ExecuteRecoveryAsync(state, cancellationToken);
                    else if (scenario.ScenarioId is "scenario_partial" or "scenario_inconsistent")
                        await IssueAsync(state, state.Body, 200, cancellationToken);
                    state.Completed = true;
                }
                return new(scenario.ScenarioId, state.RecoveryRequestId is { } recovery
                    ? new[] { state.RequestId, recovery }
                    : new[] { state.RequestId });
            }
            finally
            {
                state.Gate.Release();
            }
        }

        /// <summary>Invokes one real v2 operation and asserts the exact terminal status.</summary>
        /// <param name="state">Atomic scenario state owning the authenticated client.</param>
        /// <param name="body">Exact closed authority request bytes.</param>
        /// <param name="expectedStatus">Expected HTTP status code.</param>
        /// <param name="cancellationToken">Cancellation propagated to TestServer and the real service.</param>
        /// <returns>A task completing after persistence and exact status verification.</returns>
        private async Task IssueAsync(
            ScenarioState state, byte[] body, int expectedStatus, CancellationToken cancellationToken)
        {
            using var response = await SendAsync(state.Client,
                "/api/internal/v2/runtime-enrollment-authority/generations", body,
                state.Authentication, Guid.NewGuid(), null, null, null, cancellationToken);
            Interlocked.Increment(ref realServiceCalls);
            Assert.Equal(expectedStatus, (int)response.StatusCode);
        }

        /// <summary>Traverses authenticated preparation and finalization endpoints to append one real successor.</summary>
        /// <param name="state">Ambiguous scenario state whose genesis is already persisted.</param>
        /// <param name="cancellationToken">Cancellation propagated across database and HTTP operations.</param>
        /// <returns>A task completing after prepare, finalize, and exact replay succeed.</returns>
        private async Task ExecuteRecoveryAsync(ScenarioState state, CancellationToken cancellationToken)
        {
            RuntimeEnrollmentAuthorityGenerationPayloadV2 predecessor;
            await using (var db = await factory.CreateDbContextAsync(cancellationToken))
            {
                var row = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                    .SingleAsync(item => item.RequestId == state.RequestId, cancellationToken);
                predecessor = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
                    row.CanonicalPayloadUtf8, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions())!;
                db.RuntimeCriticalRecoveries.Add(new RuntimeCriticalRecovery
                {
                    EnrollmentId = Guid.Parse(predecessor.Enrollment.EnrollmentId),
                    BindingId = Guid.Parse(predecessor.Binding.BindingId),
                    ProductId = Guid.Parse(predecessor.ProductId),
                    InstallationId = predecessor.Installation.InstallationId,
                    RequestedEventId = Guid.NewGuid().ToString("D"), OldSecurityEpoch = predecessor.Key.SecurityEpoch,
                    NewSecurityEpoch = predecessor.Key.SecurityEpoch + 1, ResolvedIncidentCount = 1,
                    AuthorityEpoch = 1, RecoveredByClientId = "website-step1",
                    RecoveredByKeyId = "s2s-runtime-test", RecoveredAtUtc = observed.UtcDateTime
                });
                await db.SaveChangesAsync(cancellationToken);
            }
            var recoveryOptions = AuthorityRecoverySigningOptions(observed, state.Operational,
                state.Successor, state.Recovery);
            var runtime = AuthorityRuntime(factory, Guid.Parse(predecessor.ProductId), observed,
                recoveryOptions, state.Registry, state.CapabilityActive, state.CapabilityNext);
            state.Own(runtime.RuntimeCrypto);
            var recoveryFactory = CreateAuthorityHttpFactory(runtime.Service, state.Authentication);
            state.Own(recoveryFactory);
            var client = recoveryFactory.CreateClient(new WebApplicationFactoryClientOptions
                { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
            state.Own(client);
            var requestId = Guid.NewGuid();
            var body = AuthorityRecoveryRequest(requestId, predecessor, "operational-2026-02",
                predecessor.Key.SecurityEpoch + 1, observed.AddMinutes(1).UtcDateTime);
            var attempt = Guid.NewGuid();
            using var preparation = await SendAsync(client,
                "/api/internal/v2/runtime-enrollment-authority/recovery-preparations", body,
                state.Authentication, attempt, null, null, null, cancellationToken);
            Assert.Equal(HttpStatusCode.OK, preparation.StatusCode);
            var preparationBody = await preparation.Content.ReadAsByteArrayAsync(cancellationToken);
            using var preparationJson = JsonDocument.Parse(preparationBody);
            var payload = DecodeBase64Url(preparationJson.RootElement.GetProperty("payloadUtf8Base64Url").GetString()!);
            var token = preparationJson.RootElement.GetProperty("preparationToken").GetString()!;
            var signature = Base64Url(state.Recovery.SignData(Encoding.UTF8.GetBytes(
                "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n" + Encoding.UTF8.GetString(payload)),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            using var finalized = await SendAsync(client,
                "/api/internal/v2/runtime-enrollment-authority/recovery-finalizations", body,
                state.Authentication, attempt, token, "recovery-2026-01", signature, cancellationToken);
            Assert.Equal(HttpStatusCode.Created, finalized.StatusCode);
            using var replay = await SendAsync(client,
                "/api/internal/v2/runtime-enrollment-authority/recovery-finalizations", body,
                state.Authentication, attempt, token, "recovery-2026-01", signature, cancellationToken);
            Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
            state.RecoveryRequestId = requestId;
            Interlocked.Add(ref realServiceCalls, 3);
        }

        /// <summary>Disposes every scenario's in-memory cryptographic owners after all database work completes.</summary>
        /// <returns>A completed value task after every initialized state is disposed.</returns>
        public ValueTask DisposeAsync()
        {
            foreach (var lazy in states.Values)
                if (lazy.IsValueCreated && lazy.Value.IsCompletedSuccessfully) lazy.Value.Result.Dispose();
            return ValueTask.CompletedTask;
        }

        /// <summary>
        /// Creates prerequisite synthetic provider fixtures, ephemeral distinct keys, a real authority service,
        /// and an authenticated TestServer client without persisting any authority generation itself.
        /// </summary>
        /// <param name="scenario">Closed scenario selecting only metadata-safe fixture identities.</param>
        /// <param name="cancellationToken">Cancellation applied to bounded prerequisite database operations.</param>
        /// <returns>An incomplete atomic state whose genesis is issued later through HTTP.</returns>
        private async Task<ScenarioState> CreateStateAsync(
            Tkt000672Scenario scenario, CancellationToken cancellationToken)
        {
            var fixture = await SeedAuthorityAsync(factory, $"2.3.{600 + scenario.Order}", "*");
            DistributionInstallationBinding binding;
            RuntimeEnrollment enrollment;
            License license;
            const string artifactDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            await using (var seed = await factory.CreateDbContextAsync(cancellationToken))
            {
                binding = await seed.DistributionInstallationBindings.SingleAsync(
                    item => item.Id == fixture.BindingId, cancellationToken);
                license = await seed.Licenses.SingleAsync(item => item.Id == binding.LicenseId, cancellationToken);
                license.CreationDate = observed.UtcDateTime.AddDays(-1);
                license.ActivationDate = license.CreationDate;
                license.ExpirationDate = observed.UtcDateTime.AddDays(1);
                var enrollmentId = Guid.NewGuid();
                enrollment = new RuntimeEnrollment
                {
                    Id = enrollmentId, ClientId = "website-step1", BindingId = binding.Id,
                    ProductId = fixture.ProductId, LicenseId = binding.LicenseId,
                    LicenseSeatId = binding.LicenseSeatId, InstallationId = binding.InstallationId,
                    HardwareIdHash = binding.HardwareIdHash, ReleaseVersion = binding.Version,
                    HandoffDigestSha256 = binding.HandoffDigestSha256,
                    ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                    Algorithm = "PS256", KeyBackend = "test", AttestationLevel = "none",
                    PublicKeySpkiCiphertext = "test", PublicKeySpkiKeyId = "test",
                    PublicKeySpkiKeyPurpose = "encryption", PublicKeySpkiSha256 = new string('1', 64),
                    KeyThumbprint = Base64Url(SHA256.HashData(enrollmentId.ToByteArray())),
                    ChallengeCiphertext = "test", ChallengeKeyId = "test",
                    ChallengeKeyPurpose = "encryption", ChallengeDigestSha256 = new string('2', 64),
                    State = "ACTIVE", Epoch = 1, SecurityEpoch = 7,
                    ChallengeExpiresAtUtc = observed.UtcDateTime.AddMinutes(5),
                    CreatedAtUtc = license.CreationDate, ActivatedAtUtc = license.CreationDate
                };
                seed.RuntimeEnrollments.Add(enrollment);
                seed.ApprovedBinaryRegistrations.Add(new ApprovedBinaryRegistration
                {
                    ProductId = fixture.ProductId, Version = binding.Version,
                    RegistrationKey = $"tkt672-source-c-{scenario.Order}-{fixture.ProductId:D}",
                    ManifestDigestSha256 = new string('b', 64), BaselineDigestSha256 = artifactDigest,
                    Source = "release", RegisteredAtUtc = observed.UtcDateTime
                });
                await seed.SaveChangesAsync(cancellationToken);
                try
                {
                    // Diagnose synthetic credential prerequisites before exercising the HTTP authority flow.
                    var approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(seed, enrollment, cancellationToken);
                    await using var transaction = await seed.Database.BeginTransactionAsync(cancellationToken);
                    await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(seed, cancellationToken);
                    var databaseNow = await RuntimeEnrollmentService.DatabaseNowAsync(seed, cancellationToken);
                    var assessment = await RuntimeCommercialEligibilityValidator.AssessAsync(
                        seed, enrollment, approved.Binaries, databaseNow, null, cancellationToken);
                    Assert.True(assessment.IsEligible,
                        $"Source C seed commercial refusal: {assessment.DenialReason}; "
                        + $"license_expired={license.ExpirationDate <= databaseNow.UtcDateTime}.");
                    await transaction.CommitAsync(cancellationToken);
                }
                catch (RuntimeEnrollmentException exception)
                {
                    throw new InvalidOperationException(
                        $"Source C seed credential refused: status={exception.StatusCode}; "
                        + $"code={exception.ErrorCode}; diagnostic={exception.DiagnosticCode}.", exception);
                }
            }
            var operational = RSA.Create(2048);
            var successor = RSA.Create(2048);
            var recovery = RSA.Create(2048);
            var registry = RSA.Create(2048);
            var capabilityActive = RSA.Create(3072);
            var capabilityNext = RSA.Create(3072);
            var runtime = AuthorityRuntime(factory, fixture.ProductId, observed,
                operational, recovery, registry, capabilityActive, capabilityNext);
            var requestId = Guid.NewGuid();
            var body = AuthorityGenesisRequest(requestId, fixture.ProductId, binding, enrollment,
                license, artifactDigest, observed.UtcDateTime.AddSeconds(scenario.Order));
            var authentication = new StrictS2SAuthentication(observed);
            var webFactory = CreateAuthorityHttpFactory(runtime.Service, authentication);
            var client = webFactory.CreateClient(new WebApplicationFactoryClientOptions
                { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
            return new(requestId, binding.GrantRef, body, client, webFactory, authentication,
                operational, successor, recovery, registry, capabilityActive, capabilityNext,
                runtime.RuntimeCrypto);
        }

        /// <summary>Creates a production-controller TestServer whose real service persists through the app-role factory.</summary>
        /// <param name="service">Real Runtime Enrollment service already bound to PostgreSQL.</param>
        /// <param name="authentication">Run-local strict S2S authenticator.</param>
        /// <returns>A caller-owned factory with v2 enabled only in the test host.</returns>
        private static WebApplicationFactory<Program> CreateAuthorityHttpFactory(
            IRuntimeEnrollmentService service, IDistributionS2SAuthenticationService authentication) =>
            new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("IsIntegrationTest", "true");
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<IDistributionS2SAuthenticationService>();
                    services.RemoveAll<IRuntimeEnrollmentService>();
                    services.RemoveAll<IOptions<RuntimeEnrollmentOptions>>();
                    services.RemoveAll<IHostedService>();
                    services.AddSingleton(authentication);
                    services.AddSingleton(service);
                    services.AddSingleton<IOptions<RuntimeEnrollmentOptions>>(Options.Create(
                        new RuntimeEnrollmentOptions
                        {
                            Mode = "enabled",
                            AuthorityGenerationV2 = new RuntimeAuthorityGenerationV2Options { Mode = "enabled" }
                        }));
                });
            });

        /// <summary>Sends exact bytes with all required v2 attempt, S2S, nonce, permission, and recovery headers.</summary>
        /// <param name="client">Authenticated TestServer client.</param>
        /// <param name="path">Exact production v2 route.</param>
        /// <param name="body">Exact signed request bytes.</param>
        /// <param name="authentication">Run-local S2S signer.</param>
        /// <param name="attemptId">Canonical attempt UUID.</param>
        /// <param name="preparation">Optional server recovery preparation token.</param>
        /// <param name="recoveryKey">Optional exact recovery key ID.</param>
        /// <param name="recoverySignature">Optional detached PS256 recovery signature.</param>
        /// <param name="cancellationToken">Cancellation propagated to HTTP.</param>
        /// <returns>The caller-owned response.</returns>
        private static Task<HttpResponseMessage> SendAsync(
            HttpClient client, string path, byte[] body, StrictS2SAuthentication authentication,
            Guid attemptId, string? preparation, string? recoveryKey, string? recoverySignature,
            CancellationToken cancellationToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, path)
            {
                Content = new ByteArrayContent(body)
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Headers.TryAddWithoutValidation("X-Runtime-Enrollment-Attempt-Id", attemptId.ToString("D"));
            if (preparation is not null)
                request.Headers.TryAddWithoutValidation("X-Runtime-Enrollment-Recovery-Preparation", preparation);
            if (recoveryKey is not null)
                request.Headers.TryAddWithoutValidation("X-Runtime-Enrollment-Recovery-Key-Id", recoveryKey);
            if (recoverySignature is not null)
                request.Headers.TryAddWithoutValidation("X-Runtime-Enrollment-Recovery-Signature", recoverySignature);
            authentication.Authorize(request, body);
            return client.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>Owns one atomic scenario fixture and all ephemeral HTTP/cryptographic resources.</summary>
    private sealed class ScenarioState : IDisposable
    {
        private readonly List<IDisposable> owned;

        /// <summary>Creates an incomplete state that becomes visible only through one lazy atomic initializer.</summary>
        /// <param name="requestId">Primary genesis request identity.</param>
        /// <param name="rawGrantRef">Synthetic raw grant retained only for negative leak assertions.</param>
        /// <param name="body">Exact genesis bytes.</param>
        /// <param name="client">Authenticated production-controller client.</param>
        /// <param name="webFactory">Owner of the production controller TestServer.</param>
        /// <param name="authentication">Run-local strict S2S authority.</param>
        /// <param name="operational">Predecessor signing key.</param>
        /// <param name="successor">Successor signing key.</param>
        /// <param name="recovery">Distinct recovery key.</param>
        /// <param name="registry">Registry authority key.</param>
        /// <param name="capabilityActive">Active capability key.</param>
        /// <param name="capabilityNext">Next capability key.</param>
        /// <param name="runtimeCrypto">Disposable real runtime encryption service.</param>
        internal ScenarioState(Guid requestId, string rawGrantRef, byte[] body, HttpClient client,
            WebApplicationFactory<Program> webFactory, StrictS2SAuthentication authentication,
            RSA operational, RSA successor, RSA recovery, RSA registry, RSA capabilityActive,
            RSA capabilityNext, RuntimeEnrollmentCryptoService runtimeCrypto)
        {
            RequestId = requestId;
            RawGrantRef = rawGrantRef;
            Body = body;
            Client = client;
            Authentication = authentication;
            Operational = operational;
            Successor = successor;
            Recovery = recovery;
            Registry = registry;
            CapabilityActive = capabilityActive;
            CapabilityNext = capabilityNext;
            owned = [client, webFactory, authentication, runtimeCrypto, operational, successor,
                recovery, registry, capabilityActive, capabilityNext];
        }

        /// <summary>Gets the primary real v2 request identity.</summary>
        internal Guid RequestId { get; }
        /// <summary>Gets or sets the real recovery successor request identity after finalization.</summary>
        internal Guid? RecoveryRequestId { get; set; }
        /// <summary>Gets the synthetic raw grant reference retained solely for no-leak assertions.</summary>
        internal string RawGrantRef { get; }
        /// <summary>Gets the exact signed primary genesis body.</summary>
        internal byte[] Body { get; }
        /// <summary>Gets the authenticated production-controller client.</summary>
        internal HttpClient Client { get; }
        /// <summary>Gets the run-local strict S2S authenticator.</summary>
        internal StrictS2SAuthentication Authentication { get; }
        /// <summary>Gets the predecessor operational signing key.</summary>
        internal RSA Operational { get; }
        /// <summary>Gets the successor operational signing key.</summary>
        internal RSA Successor { get; }
        /// <summary>Gets the distinct recovery signing key.</summary>
        internal RSA Recovery { get; }
        /// <summary>Gets the registry authority key.</summary>
        internal RSA Registry { get; }
        /// <summary>Gets the active capability authority key.</summary>
        internal RSA CapabilityActive { get; }
        /// <summary>Gets the next capability authority key.</summary>
        internal RSA CapabilityNext { get; }
        /// <summary>Serializes initialization, interruption/resume, and replay for this scenario.</summary>
        internal SemaphoreSlim Gate { get; } = new(1, 1);
        /// <summary>Gets or sets whether genesis has been persisted through HTTP.</summary>
        internal bool GenesisIssued { get; set; }
        /// <summary>Gets or sets whether the real service state has reached its terminal idempotent fixture.</summary>
        internal bool Completed { get; set; }

        /// <summary>Adds one late-created disposable recovery resource to the owned state.</summary>
        /// <param name="resource">Resource disposed in reverse creation order.</param>
        internal void Own(IDisposable resource) => owned.Add(resource);

        /// <summary>Disposes the runtime cryptography service and every scenario-local RSA owner exactly once.</summary>
        public void Dispose()
        {
            Gate.Dispose();
            for (var index = owned.Count - 1; index >= 0; index--) owned[index].Dispose();
        }
    }

    /// <summary>Authenticates exact test-host S2S headers with a run-local PS256 key and one-use nonce set.</summary>
    private sealed class StrictS2SAuthentication : IDistributionS2SAuthenticationService, IDisposable
    {
        private readonly RSA key = RSA.Create(2048);
        private readonly ConcurrentDictionary<string, byte> nonces = new(StringComparer.Ordinal);
        private readonly string timestamp;

        /// <summary>Creates a run-local authenticator fixed to the scenario observation instant.</summary>
        /// <param name="observed">Exact UTC time serialized into every S2S request.</param>
        internal StrictS2SAuthentication(DateTimeOffset observed) =>
            timestamp = observed.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

        /// <summary>Adds exact client/key/timestamp/nonce/signature headers to one request.</summary>
        /// <param name="request">Owned request whose relative path is signed exactly.</param>
        /// <param name="body">Exact body bytes bound into the signature.</param>
        internal void Authorize(HttpRequestMessage request, byte[] body)
        {
            var nonce = Guid.NewGuid().ToString("D");
            request.Headers.TryAddWithoutValidation(DistributionS2SAuthenticationService.ClientHeader, "website-step1");
            request.Headers.TryAddWithoutValidation(DistributionS2SAuthenticationService.KeyIdHeader, "s2s-runtime-test");
            request.Headers.TryAddWithoutValidation(DistributionS2SAuthenticationService.TimestampHeader, timestamp);
            request.Headers.TryAddWithoutValidation(DistributionS2SAuthenticationService.NonceHeader, nonce);
            request.Headers.TryAddWithoutValidation(DistributionS2SAuthenticationService.SignatureHeader,
                Base64Url(key.SignData(AuthenticationBytes(request.Method.Method,
                    request.RequestUri!.IsAbsoluteUri ? request.RequestUri.AbsolutePath : request.RequestUri.OriginalString,
                    timestamp, nonce, body), HashAlgorithmName.SHA256, RSASignaturePadding.Pss)));
        }

        /// <inheritdoc />
        public Task<DistributionS2SPrincipal> AuthenticateAndReserveNonceAsync(
            Microsoft.AspNetCore.Http.HttpContext context, ReadOnlyMemory<byte> exactBody,
            string productId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var headers = context.Request.Headers;
            string One(string name) => headers.TryGetValue(name, out var values) && values.Count == 1
                ? values[0]!
                : throw new DistributionS2SAuthenticationException("s2s_header_invalid", 401);
            var client = One(DistributionS2SAuthenticationService.ClientHeader);
            var keyId = One(DistributionS2SAuthenticationService.KeyIdHeader);
            var sentAt = One(DistributionS2SAuthenticationService.TimestampHeader);
            var nonce = One(DistributionS2SAuthenticationService.NonceHeader);
            var signature = One(DistributionS2SAuthenticationService.SignatureHeader);
            if (client != "website-step1" || keyId != "s2s-runtime-test" || sentAt != timestamp
                || !Guid.TryParseExact(nonce, "D", out _) || !nonces.TryAdd(nonce, 0)
                || !key.VerifyData(AuthenticationBytes(context.Request.Method, context.Request.Path,
                    sentAt, nonce, exactBody.Span), DecodeBase64Url(signature),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw new DistributionS2SAuthenticationException("s2s_authentication_invalid", 401);
            return Task.FromResult(new DistributionS2SPrincipal(client, keyId,
                AllowRuntimeRecovery: true, AllowRuntimeUpgrade: true));
        }

        /// <summary>Disposes the run-local private test credential.</summary>
        public void Dispose() => key.Dispose();

        /// <summary>Frames exact method/path/timestamp/nonce/body digest bytes for PS256 authentication.</summary>
        /// <param name="method">Exact uppercase HTTP method.</param>
        /// <param name="path">Exact ordinal route path.</param>
        /// <param name="sentAt">Exact strict UTC timestamp.</param>
        /// <param name="nonce">One-use canonical UUID.</param>
        /// <param name="body">Exact request body bytes.</param>
        /// <returns>Domain-separated UTF-8 authentication bytes.</returns>
        private static byte[] AuthenticationBytes(
            string method, string path, string sentAt, string nonce, ReadOnlySpan<byte> body) =>
            Encoding.UTF8.GetBytes(string.Join('\n', "TKT-000672-S2S-V1", method, path, sentAt, nonce,
                Convert.ToHexStringLower(SHA256.HashData(body))));
    }

    /// <summary>
    /// Retains two distinct run-local PKCS#8 encodings so replayed harness calls use one stable public trust
    /// identity while each returned RSA owner remains independently disposable. Encodings are zeroed on disposal.
    /// </summary>
    private sealed class StableSignerFactory : ITkt000672ManifestSignerFactory, IDisposable
    {
        private readonly byte[] manifest = CreatePrivateKey();
        private readonly byte[] trust = CreatePrivateKey();

        /// <inheritdoc />
        public Tkt000672ManifestSigner Create()
        {
            var manifestKey = RSA.Create();
            manifestKey.ImportPkcs8PrivateKey(manifest, out _);
            var trustKey = RSA.Create();
            trustKey.ImportPkcs8PrivateKey(trust, out _);
            return new(manifestKey, trustKey, "tkt672-pg-manifest-key");
        }

        /// <summary>Zeros both stable run-local private-key encodings after deterministic replay assertions.</summary>
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(manifest);
            CryptographicOperations.ZeroMemory(trust);
        }

        /// <summary>Creates one in-memory 2048-bit PKCS#8 test key encoding.</summary>
        /// <returns>A caller-owned private-key encoding that must be zeroed.</returns>
        private static byte[] CreatePrivateKey()
        {
            using var key = RSA.Create(2048);
            return key.ExportPkcs8PrivateKey();
        }
    }

    /// <summary>Creates contexts bound only to the isolated non-superuser application-role options.</summary>
    /// <param name="options">Prevalidated Npgsql options for the ticket-owned database.</param>
    private sealed class Tkt000672PostgreSqlFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);
        /// <inheritdoc />
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

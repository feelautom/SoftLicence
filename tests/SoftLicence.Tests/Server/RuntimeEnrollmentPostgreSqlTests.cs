using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Npgsql;
using System.Data.Common;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Proves minimum-version enforcement preserves the public refusal and precise diagnostic
    /// without terminating an otherwise valid cryptographic enrollment.
    /// </summary>
    [Fact]
    public async Task VersionIneligible_PublicCodeAndDiagnosticRemainPrecise_WithoutCryptoInvalidation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await using (var policy = await scenario.Factory.CreateDbContextAsync())
        {
            var product = await policy.Products.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.ProductId);
            product.MinimumAllowedVersion = "9.9.9";
            await policy.SaveChangesAsync();
        }

        var request = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            InstallationId = scenario.Fixture.InstallationId,
            ReleaseVersion = scenario.Fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var digest = Sha256("version-ineligible-public-contract-" + Guid.NewGuid().ToString("D"));
        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.CreateCapabilityAsync(
                scenario.EnrollmentId,
                digest,
                request,
                Proof(
                    scenario.EnrollmentKey,
                    "capability",
                    scenario.EnrollmentId,
                    request.Audience,
                    "-",
                    digest),
                IPAddress.Loopback));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
        Assert.Equal("authority_ineligible", refusal.ErrorCode);
        Assert.Equal("version_ineligible", refusal.DiagnosticCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await check.RuntimeEnrollments.SingleAsync(candidate =>
            candidate.Id == scenario.EnrollmentId);
        Assert.Equal("ACTIVE", enrollment.State);
        Assert.Null(enrollment.InvalidationReason);
    }

    private static readonly SemaphoreSlim ProvisioningLock = new(1, 1);
    private static bool _provisioned;
    private static readonly byte[] ActiveSigningPrivateKey = CreateSigningPrivateKey();
    private static readonly byte[] NextSigningPrivateKey = CreateSigningPrivateKey();
    private static readonly string[] ProtectedTables =
    [
        "ApprovedBinaries", "BannedComponents", "BannedHardwareIds",
        "DistributionBindingRequests", "DistributionGrantOwnerships", "DistributionInstallationBindings",
        "LicenseSeats", "Licenses", "Products"
    ];

    [Fact]
    public void WebSetupTransition_Contract_IsExplicitAndVersioned()
    {
        Assert.Equal("runtime-websetup-transition-issue-v1", RuntimeEnrollmentService.WebSetupTransitionIssueSchema);
        Assert.Equal("runtime-websetup-transition-capability-v1", RuntimeEnrollmentService.WebSetupTransitionCapabilitySchema);
        Assert.Equal("runtime-enrollment-websetup-upgrade-v1", RuntimeEnrollmentService.WebSetupUpgradeSchema);
    }

    [Fact]
    public async Task PrivateValidationTestReset_AtomicallyInvalidatesBindingAndEnrollment_AndReplays()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.944");
        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);
        var enrollmentId = Guid.NewGuid();
        const int securityEpoch = 3;
        await using (var db = await factory.CreateDbContextAsync())
        {
            var binding = await db.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == fixture.BindingId);
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = enrollmentId,
                ClientId = "website-step1",
                BindingId = binding.Id,
                ProductId = binding.ProductId,
                LicenseId = binding.LicenseId,
                LicenseSeatId = binding.LicenseSeatId,
                InstallationId = binding.InstallationId,
                HardwareIdHash = binding.HardwareIdHash,
                ReleaseVersion = binding.Version,
                HandoffDigestSha256 = binding.HandoffDigestSha256,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = runtimeOptions.Encryption.ActiveKeyId,
                PublicKeySpkiSha256 = new string('a', 64),
                KeyThumbprint = "test",
                ChallengeCiphertext = "test",
                ChallengeKeyId = runtimeOptions.Encryption.ActiveKeyId,
                ChallengeDigestSha256 = new string('b', 64),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = securityEpoch,
                AuthorityEpoch = 1,
                ChallengeExpiresAtUtc = DateTime.UtcNow.AddHours(1),
                CreatedAtUtc = DateTime.UtcNow,
                ActivatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }

        Guid allowedLicenseId;
        await using (var allowlistDb = await factory.CreateDbContextAsync())
        {
            allowedLicenseId = await allowlistDb.DistributionInstallationBindings.AsNoTracking()
                .Where(candidate => candidate.Id == fixture.BindingId)
                .Select(candidate => candidate.LicenseId)
                .SingleAsync();
        }
        var resetConfiguration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["PrivateValidationTestReset:AllowedLicenseIds"] = allowedLicenseId.ToString("D")
            }).Build();
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(runtimeOptions));
        var service = new PrivateValidationTestResetService(
            factory, authority, TimeProvider.System, resetConfiguration);
        var request = new PrivateValidationTestResetRequest(
            fixture.ProductId,
            enrollmentId,
            fixture.BindingId,
            fixture.InstallationId,
            fixture.Version,
            securityEpoch,
            "TKT-999962");

        Task<PrivateValidationTestResetResult> racingExecute;
        await using (var revoke = await factory.CreateDbContextAsync())
        {
            await using var revokeTransaction = await revoke.Database.BeginTransactionAsync();
            var license = await revoke.Licenses.SingleAsync(candidate => candidate.Id == allowedLicenseId);
            license.IsActive = false;
            license.RevokedAt = DateTime.UtcNow;
            await revoke.SaveChangesAsync();
            racingExecute = service.ExecuteAsync(request);
            await using var observer = new NpgsqlConnection(connections.Admin);
            await observer.OpenAsync();
            var observedAuthorityWait = false;
            for (var attempt = 0; attempt < 50 && !observedAuthorityWait; attempt++)
            {
                observedAuthorityWait = await ScalarAsync<bool>(observer, """
                    SELECT EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_stat_activity
                        WHERE usename = 'softlicence_runtime_test_app'
                          AND wait_event_type = 'Lock'
                          AND wait_event = 'advisory'
                          AND query LIKE '%pg_advisory_xact_lock(999831, 1)%'
                    );
                    """);
                if (!observedAuthorityWait)
                    await Task.Delay(20);
            }
            Assert.True(observedAuthorityWait);
            Assert.False(racingExecute.IsCompleted);
            await revokeTransaction.CommitAsync();
        }
        var executeIneligible = await Assert.ThrowsAsync<PrivateValidationTestResetException>(
            () => racingExecute);
        Assert.Equal("authority_ineligible", executeIneligible.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, executeIneligible.StatusCode);
        var ineligible = await Assert.ThrowsAsync<PrivateValidationTestResetException>(
            () => service.ValidateAsync(request));
        Assert.Equal("authority_ineligible", ineligible.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, ineligible.StatusCode);
        await using (var unchanged = await factory.CreateDbContextAsync())
        {
            Assert.Equal("ACTIVE", (await unchanged.RuntimeEnrollments
                .SingleAsync(candidate => candidate.Id == enrollmentId)).State);
            Assert.Equal("active", (await unchanged.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == fixture.BindingId)).State);
        }
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var license = await restore.Licenses.SingleAsync(candidate => candidate.Id == allowedLicenseId);
            license.IsActive = true;
            license.RevokedAt = null;
            await restore.SaveChangesAsync();
        }

        var first = await service.ExecuteAsync(request);
        var replay = await service.ExecuteAsync(request);

        Assert.True(first.Executed);
        Assert.False(first.AlreadyApplied);
        Assert.True(replay.Executed);
        Assert.True(replay.AlreadyApplied);
        Assert.Equal("INVALIDATED", replay.EnrollmentState);
        Assert.Equal("invalidated", replay.BindingState);
        Assert.True(replay.AuthorityEpoch > 1);
        await using var check = await factory.CreateDbContextAsync();
        Assert.Equal("test_identity_reset_tkt_999962", (await check.RuntimeEnrollments
            .SingleAsync(candidate => candidate.Id == enrollmentId)).InvalidationReason);
        Assert.Equal("test_identity_reset_tkt_999962", (await check.DistributionInstallationBindings
            .SingleAsync(candidate => candidate.Id == fixture.BindingId)).InvalidationReason);
    }

    [Fact]
    public async Task AuthorityInfrastructure_UsesHardenedFunctionAndAllFourStatementTriggers()
    {
        var connections = await ProvisionAsync();
        var authority = new RuntimeEnrollmentAuthorityService(
            new TestDbFactory(connections.App),
            Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));

        await authority.ValidateInfrastructureAsync();

        await using var connection = new NpgsqlConnection(connections.App);
        await connection.OpenAsync();
        foreach (var table in ProtectedTables)
        {
            var before = await EpochAsync(connection);
            await ExecuteAsync(connection, $"INSERT INTO public.\"{table}\" SELECT * FROM public.\"{table}\" WHERE false;");
            Assert.Equal(before + 1, await EpochAsync(connection));

            before = await EpochAsync(connection);
            await ExecuteAsync(connection, $"DELETE FROM public.\"{table}\" WHERE false;");
            Assert.Equal(before + 1, await EpochAsync(connection));
        }


        foreach (var statement in new[]
        {
            "UPDATE public.\"RuntimeEnrollmentAuthorityStates\" SET \"Epoch\"=\"Epoch\" WHERE \"Id\"=1;",
            "DELETE FROM public.\"RuntimeEnrollmentKeyRegistries\" WHERE false;",
            "SELECT public.runtime_enrollment_bump_authority_epoch();",
            "SELECT public.runtime_enrollment_guard_key_registry();"
        })
        {
            var denied = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, statement));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
        }
    }

    [Fact]
    public async Task AuthorityInfrastructure_IgnoresUnrelatedBusinessTriggerOnProtectedTable()
    {
        var connections = await ProvisionAsync();
        var authority = new RuntimeEnrollmentAuthorityService(
            new TestDbFactory(connections.App),
            Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));
        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await ExecuteAsync(admin, """
            CREATE OR REPLACE FUNCTION public.test_auto_revoke_on_ban()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $body$
            BEGIN
                RETURN NEW;
            END;
            $body$;

            CREATE TRIGGER trg_auto_revoke_on_ban
            AFTER INSERT OR UPDATE ON public."BannedHardwareIds"
            FOR EACH ROW
            EXECUTE FUNCTION public.test_auto_revoke_on_ban();
            """);
        try
        {
            await authority.ValidateInfrastructureAsync();
        }
        finally
        {
            await ExecuteAsync(admin, """
                DROP TRIGGER trg_auto_revoke_on_ban ON public."BannedHardwareIds";
                DROP FUNCTION public.test_auto_revoke_on_ban();
                """);
        }
    }

    [Fact]
    public async Task ProtectedUpdateAndTruncate_BumpEpoch_WhileUnprotectedUpdateDoesNot()
    {
        var connections = await ProvisionAsync();
        await using var connection = new NpgsqlConnection(connections.App);
        await connection.OpenAsync();

        var before = await EpochAsync(connection);
        await ExecuteAsync(connection, "UPDATE public.\"Products\" SET \"MinimumAllowedVersion\" = \"MinimumAllowedVersion\" WHERE false;");
        Assert.Equal(before + 1, await EpochAsync(connection));

        before = await EpochAsync(connection);
        await ExecuteAsync(connection, "UPDATE public.\"Products\" SET \"Name\" = \"Name\" WHERE false;");
        Assert.Equal(before, await EpochAsync(connection));

        await using var transaction = await connection.BeginTransactionAsync();
        before = await EpochAsync(connection, transaction);
        await ExecuteAsync(connection, "TRUNCATE public.\"ApprovedBinaries\";", transaction);
        Assert.Equal(before + 1, await EpochAsync(connection, transaction));
        await transaction.RollbackAsync();
    }

    [Fact]
    public async Task FailedProtectedStatement_RollsBackItsEpochChange()
    {
        var connections = await ProvisionAsync();
        await using var connection = new NpgsqlConnection(connections.App);
        await connection.OpenAsync();
        var productId = Guid.NewGuid();
        var name = "runtime-trigger-" + productId.ToString("N");
        await using (var insert = connection.CreateCommand())
        {
            insert.CommandText = """
                INSERT INTO public."Products"
                    ("Id", "Name", "PrivateKeyXml", "PublicKeyXml", "ApiSecret")
                VALUES (@id, @name, '', '', @secret);
                """;
            insert.Parameters.AddWithValue("id", productId);
            insert.Parameters.AddWithValue("name", name);
            insert.Parameters.AddWithValue("secret", Guid.NewGuid().ToString("N"));
            await insert.ExecuteNonQueryAsync();
        }
        var beforeFailure = await EpochAsync(connection);

        await using var duplicate = connection.CreateCommand();
        duplicate.CommandText = """
            INSERT INTO public."Products"
                ("Id", "Name", "PrivateKeyXml", "PublicKeyXml", "ApiSecret")
            VALUES (@id, @name, '', '', @secret);
            """;
        duplicate.Parameters.AddWithValue("id", Guid.NewGuid());
        duplicate.Parameters.AddWithValue("name", name);
        duplicate.Parameters.AddWithValue("secret", Guid.NewGuid().ToString("N"));
        await Assert.ThrowsAsync<PostgresException>(() => duplicate.ExecuteNonQueryAsync());
        Assert.Equal(beforeFailure, await EpochAsync(connection));
    }

    [Fact]
    public async Task GlobalSharedLocks_RunInParallel_AndBindingExclusiveLockConverges()
    {
        var connections = await ProvisionAsync();
        await using var first = new NpgsqlConnection(connections.App);
        await using var second = new NpgsqlConnection(connections.App);
        await first.OpenAsync();
        await second.OpenAsync();
        await using var firstTransaction = await first.BeginTransactionAsync();
        await using var secondTransaction = await second.BeginTransactionAsync();

        Assert.True(await BooleanAsync(first,
            "SELECT pg_catalog.pg_try_advisory_xact_lock_shared(999831, 1);", firstTransaction));
        Assert.True(await BooleanAsync(second,
            "SELECT pg_catalog.pg_try_advisory_xact_lock_shared(999831, 1);", secondTransaction));
        const string bindingLock = "SELECT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('11111111-1111-4111-8111-111111111111', 999831));";
        Assert.True(await BooleanAsync(first, bindingLock, firstTransaction));
        Assert.False(await BooleanAsync(second, bindingLock, secondTransaction));
    }

    [Fact]
    public async Task DisabledAuthorityTrigger_IsDetectedByEnabledReadiness()
    {
        var connections = await ProvisionAsync();
        var authority = new RuntimeEnrollmentAuthorityService(
            new TestDbFactory(connections.App),
            Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));
        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await ExecuteAsync(admin,
            "ALTER TABLE public.\"Products\" DISABLE TRIGGER trg_runtime_authority_products_update;");
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => authority.ValidateInfrastructureAsync());
        }
        finally
        {
            await ExecuteAsync(admin,
                "ALTER TABLE public.\"Products\" ENABLE TRIGGER trg_runtime_authority_products_update;");
        }
        await authority.ValidateInfrastructureAsync();
    }

    [Fact]
    public async Task KeyRegistry_TwoReplicasMatch_AndMaterialDriftFailsClosed()
    {
        var connections = await ProvisionAsync();
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var options = RuntimeOptions(Guid.Parse("11111111-1111-4111-8111-111111111111"), active, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);

        var firstReplica = new RuntimeEnrollmentKeyRegistryService(
            new TestDbFactory(connections.App), Options.Create(options));
        var secondReplica = new RuntimeEnrollmentKeyRegistryService(
            new TestDbFactory(connections.App), Options.Create(options));
        await firstReplica.ValidateAsync();
        await secondReplica.ValidateAsync();

        options.Encryption.Keys[0].KeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var driftedReplica = new RuntimeEnrollmentKeyRegistryService(
            new TestDbFactory(connections.App), Options.Create(options));
        await Assert.ThrowsAsync<InvalidOperationException>(() => driftedReplica.ValidateAsync());
    }

    [Fact]
    public async Task CanaryKeyRegistryInfrastructure_TriggerFunctionAndAclTamperingFailsClosed()
    {
        var connections = await ProvisionAsync();
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var options = RuntimeOptions(Guid.Parse("11111111-1111-4111-8111-111111111111"), active, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var registry = new RuntimeEnrollmentKeyRegistryService(
            new TestDbFactory(connections.App), Options.Create(options));
        await registry.ValidateAsync();

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();

        await ExecuteAsync(admin, "ALTER TABLE public.\"RuntimeEnrollmentKeyRegistries\" DISABLE TRIGGER trg_runtime_canary_key_retirement_guard;");
        await Assert.ThrowsAsync<InvalidOperationException>(() => registry.ValidateAsync());
        await ExecuteAsync(admin, "ALTER TABLE public.\"RuntimeEnrollmentKeyRegistries\" ENABLE TRIGGER trg_runtime_canary_key_retirement_guard;");
        await registry.ValidateAsync();

        await ExecuteAsync(admin, """
            CREATE OR REPLACE FUNCTION public.runtime_canary_guard_key_retirement()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $tampered$ BEGIN RETURN NEW; END; $tampered$;
            """);
        await Assert.ThrowsAsync<InvalidOperationException>(() => registry.ValidateAsync());
        await ExecuteAsync(admin, """
            CREATE OR REPLACE FUNCTION public.runtime_canary_guard_key_retirement()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $restored$
            BEGIN
                IF OLD."Purpose" = 'encryption'
                   AND NEW."State" = 'retired'
                   AND OLD."State" <> 'retired'
                   AND EXISTS (
                       SELECT 1 FROM public."RuntimeCanaryProofNonces" proof
                       WHERE proof."ResponseKeyId" = OLD."KeyId"
                   ) THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment key is still referenced by canary proof';
                END IF;
                RETURN NEW;
            END;
            $restored$;
            REVOKE ALL ON FUNCTION public.runtime_canary_guard_key_retirement() FROM PUBLIC;
            """);
        await registry.ValidateAsync();

        await ExecuteAsync(admin,
            "GRANT EXECUTE ON FUNCTION public.runtime_canary_guard_key_retirement() TO softlicence_runtime_test_app;");
        await Assert.ThrowsAsync<InvalidOperationException>(() => registry.ValidateAsync());
        await ExecuteAsync(admin,
            "REVOKE EXECUTE ON FUNCTION public.runtime_canary_guard_key_retirement() FROM softlicence_runtime_test_app;");
        await registry.ValidateAsync();

        await ExecuteAsync(admin,
            "REVOKE SELECT ON public.\"RuntimeCanaryProofNonces\" FROM softlicence_runtime_authority_owner;");
        await Assert.ThrowsAsync<InvalidOperationException>(() => registry.ValidateAsync());
        await ExecuteAsync(admin,
            "GRANT SELECT ON public.\"RuntimeCanaryProofNonces\" TO softlicence_runtime_authority_owner;");
        await registry.ValidateAsync();
    }

    [Fact]
    public async Task KeyRegistry_RealMultiRotation_OneToTwoToThree_PreservesOldDecryptAndVerify()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        using var signing1 = RSA.Create(3072);
        using var signing2 = RSA.Create(3072);
        using var signing3 = RSA.Create(3072);
        using var signing4 = RSA.Create(3072);
        using var clientKey = RSA.Create(3072);
        var aes1 = SHA256.HashData("runtime-rotation-aes-1"u8.ToArray());
        var aes2 = SHA256.HashData("runtime-rotation-aes-2"u8.ToArray());
        var aes3 = SHA256.HashData("runtime-rotation-aes-3"u8.ToArray());
        var v1 = RotationOptions(fixture.ProductId, 1, "enc-rotation-1",
            [("enc-rotation-1", aes1)],
            [(signing1, "active"), (signing2, "next")]);
        await UpsertKeyRegistryAsync(connections.Admin, v1);

        var authority1 = new RuntimeEnrollmentAuthorityService(factory, Options.Create(v1));
        var registry1 = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(v1));
        using var crypto1 = new RuntimeEnrollmentCryptoService(Options.Create(v1));
        var service1 = new RuntimeEnrollmentService(factory, authority1, registry1, crypto1, Options.Create(v1));
        await registry1.ValidateAsync();
        var prepared = await service1.PrepareAsync(
            "website-step1", Sha256("rotation-prepare"), PrepareRequest(fixture, Guid.NewGuid().ToString("D"), clientKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var oldToken = crypto1.SignCapability(enrollmentId, 1, 1,
            fixture.InstallationId, fixture.Version, Guid.NewGuid().ToString("D"), CapabilityBinaries(),
            "https://broker.example.test",
            ["runtime.execute"], new string('a', 64), DateTimeOffset.UtcNow, Guid.NewGuid().ToString("D"));
        RuntimeEnrollment enrollment;
        await using (var db = await factory.CreateDbContextAsync())
        {
            enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == enrollmentId);
            Assert.Equal("enc-rotation-1", enrollment.PublicKeySpkiKeyId);
            Assert.True(await db.RuntimeEnrollmentEncryptionNonces.AsNoTracking()
                .AnyAsync(row => row.KeyId == "enc-rotation-1"));
        }

        var v2 = RotationOptions(fixture.ProductId, 2, "enc-rotation-2",
            [("enc-rotation-1", aes1), ("enc-rotation-2", aes2)],
            [(signing1, "previous"), (signing2, "active"), (signing3, "next")]);
        await RotateKeyRegistryAsync(connections.Admin, v1, v2);
        var registry2a = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(v2));
        var registry2b = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(v2));
        await registry2a.ValidateAsync();
        await registry2b.ValidateAsync();
        using var crypto2 = new RuntimeEnrollmentCryptoService(Options.Create(v2));
        Assert.Equal(clientKey.ExportSubjectPublicKeyInfo(), crypto2.Open(
            "enrollment-spki", enrollment.Id, enrollment.Epoch, enrollment.PublicKeySpkiKeyId,
            enrollment.PublicKeySpkiCiphertext, $"RuntimeEnrollments:{enrollment.Id:D}:PublicKeySpkiCiphertext"));
        AssertTokenVerified(oldToken, signing1);
        var secondToken = crypto2.SignCapability(enrollmentId, 1, 1,
            fixture.InstallationId, fixture.Version, Guid.NewGuid().ToString("D"), CapabilityBinaries(),
            "https://broker.example.test",
            ["runtime.execute"], new string('b', 64), DateTimeOffset.UtcNow, Guid.NewGuid().ToString("D"));

        var v3 = RotationOptions(fixture.ProductId, 3, "enc-rotation-3",
            [("enc-rotation-1", aes1), ("enc-rotation-2", aes2), ("enc-rotation-3", aes3)],
            [(signing1, "previous"), (signing2, "previous"), (signing3, "active"), (signing4, "next")]);
        v3.CapabilitySigning.Keys.Single(key => key.KeyId == SigningKeyId(signing1)).RetainUntilUtc =
            v2.CapabilitySigning.Keys.Single(key => key.KeyId == SigningKeyId(signing1)).RetainUntilUtc;
        await RotateKeyRegistryAsync(connections.Admin, v2, v3);
        var registry3a = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(v3));
        var registry3b = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(v3));
        await registry3a.ValidateAsync();
        await registry3b.ValidateAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => registry2a.ValidateAsync());
        using var crypto3 = new RuntimeEnrollmentCryptoService(Options.Create(v3));
        Assert.Equal(clientKey.ExportSubjectPublicKeyInfo(), crypto3.Open(
            "enrollment-spki", enrollment.Id, enrollment.Epoch, enrollment.PublicKeySpkiKeyId,
            enrollment.PublicKeySpkiCiphertext, $"RuntimeEnrollments:{enrollment.Id:D}:PublicKeySpkiCiphertext"));
        AssertTokenVerified(oldToken, signing1);
        AssertTokenVerified(secondToken, signing2);
        var thirdToken = crypto3.SignCapability(enrollmentId, 1, 1,
            fixture.InstallationId, fixture.Version, Guid.NewGuid().ToString("D"), CapabilityBinaries(),
            "https://broker.example.test",
            ["runtime.execute"], new string('c', 64), DateTimeOffset.UtcNow, Guid.NewGuid().ToString("D"));
        AssertTokenVerified(thirdToken, signing3);

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        Assert.Equal(3, await ScalarAsync<int>(admin, "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentKeyRegistries\" WHERE \"Purpose\"='registry-version' AND \"KeyId\"='global';"));
        Assert.Equal("active", await ScalarAsync<string>(admin, "SELECT \"State\" FROM public.\"RuntimeEnrollmentKeyRegistries\" WHERE \"Purpose\"='encryption' AND \"KeyId\"='enc-rotation-3';"));
        foreach (var statement in new[]
        {
            "UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"State\"='active',\"Epoch\"=\"Epoch\"+1 WHERE \"Purpose\"='encryption' AND \"KeyId\"='enc-rotation-1';",
            $"UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"State\"='active',\"Epoch\"=\"Epoch\"+1 WHERE \"Purpose\"='capability-signing' AND \"KeyId\"='{SigningKeyId(signing1)}';",
            "UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"Epoch\"=\"Epoch\"+1 WHERE \"Purpose\"='encryption' AND \"KeyId\"='enc-rotation-1';",
            "UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"State\"='retired',\"RetiredAtUtc\"=clock_timestamp(),\"Epoch\"=\"Epoch\"+1 WHERE \"Purpose\"='registry-version' AND \"KeyId\"='global';",
            "UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"MaterialDigestSha256\"=repeat('f',64),\"Epoch\"=\"Epoch\"+1 WHERE \"Purpose\"='registry-version' AND \"KeyId\"='global';",
            "DELETE FROM public.\"RuntimeEnrollmentKeyRegistries\" WHERE \"Purpose\"='registry-version' AND \"KeyId\"='global';",
            "INSERT INTO public.\"RuntimeEnrollmentKeyRegistries\" (\"Purpose\",\"KeyId\",\"MaterialDigestSha256\",\"State\",\"Epoch\",\"CreatedAtUtc\") VALUES ('registry-version','other',repeat('0',64),'active',1,clock_timestamp());",
            "INSERT INTO public.\"RuntimeEnrollmentKeyRegistries\" (\"Purpose\",\"KeyId\",\"MaterialDigestSha256\",\"State\",\"Epoch\",\"CreatedAtUtc\") VALUES ('encryption','enc-invalid-epoch',repeat('1',64),'active',2,clock_timestamp());"
        })
        {
            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(admin, statement));
            Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, blocked.SqlState);
        }
    }

    [Fact]
    public async Task KeyRegistryOperator_DryRunRollbackConcurrencyAndIdempotence_AreAtomic()
    {
        var connections = await ProvisionIsolatedAsync();
        using var signing1 = RSA.Create(3072);
        using var signing2 = RSA.Create(3072);
        using var signing3 = RSA.Create(3072);
        using var signing4 = RSA.Create(3072);
        var productId = Guid.NewGuid();
        var aes = SHA256.HashData("runtime-operator-aes"u8.ToArray());
        var v1 = RotationOptions(productId, 1, "enc-operator-1",
            [("enc-operator-1", aes)],
            [(signing1, "active"), (signing2, "next")]);
        var v2 = RotationOptions(productId, 2, "enc-operator-1",
            [("enc-operator-1", aes)],
            [(signing1, "previous"), (signing2, "active"), (signing3, "next")]);
        await UpsertKeyRegistryAsync(connections.Admin, v1);
        var before = await SnapshotRuntimeKeyRegistryAsync(connections.Admin);

        var dryRun = await RuntimeEnrollmentKeyRegistryOperator.RunAsync(
            connections.Admin, v2, 1, false);
        Assert.Equal("dry-run", dryRun.Mode);
        Assert.Equal("rotation", dryRun.Classification);
        Assert.Equal(1, dryRun.InsertedKeys);
        Assert.Equal(2, dryRun.TransitionedKeys);
        Assert.Equal(before, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                connections.Admin, v2, 7, false));
        Assert.Equal(before, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));

        var partial = RotationOptions(productId, 2, "enc-operator-1",
            [("enc-operator-1", aes)],
            [(signing1, "active"), (signing3, "next")]);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                connections.Admin, partial, 1, false));
        Assert.Equal(before, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));

        var duplicateMaterial = RotationOptions(productId, 2, "enc-operator-1",
            [("enc-operator-1", aes)],
            [(signing1, "previous"), (signing2, "active"), (signing3, "next")]);
        duplicateMaterial.CapabilitySigning.Keys.Single(key => key.Role == "next").PublicKeyPem =
            signing1.ExportSubjectPublicKeyInfoPem();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                connections.Admin, duplicateMaterial, 1, false));
        Assert.Equal(before, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        var divergentKeyId = SigningKeyId(signing2).Replace("'", "''", StringComparison.Ordinal);
        await ExecuteAsync(admin, $"""
            SET session_replication_role = replica;
            UPDATE public."RuntimeEnrollmentKeyRegistries"
            SET "State" = 'previous', "RetainUntilUtc" = clock_timestamp() + interval '1 day'
            WHERE "Purpose" = 'capability-signing' AND "KeyId" = '{divergentKeyId}';
            SET session_replication_role = origin;
            """);
        try
        {
            var divergent = await SnapshotRuntimeKeyRegistryAsync(connections.Admin);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                    connections.Admin, v2, 1, false));
            Assert.Equal(divergent, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));
        }
        finally
        {
            await ExecuteAsync(admin, $"""
                SET session_replication_role = replica;
                UPDATE public."RuntimeEnrollmentKeyRegistries"
                SET "State" = 'next', "RetainUntilUtc" = NULL
                WHERE "Purpose" = 'capability-signing' AND "KeyId" = '{divergentKeyId}';
                SET session_replication_role = origin;
                """);
        }

        var beforeRollback = await SnapshotRuntimeKeyRegistryAsync(connections.Admin);
        await ExecuteAsync(admin, """
            CREATE OR REPLACE FUNCTION public.runtime_test_reject_registry_version()
            RETURNS trigger LANGUAGE plpgsql AS $test$
            BEGIN
                IF OLD."Purpose" = 'registry-version' THEN
                    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'test rollback';
                END IF;
                RETURN NEW;
            END;
            $test$;
            CREATE TRIGGER trg_runtime_test_reject_registry_version
            BEFORE UPDATE ON public."RuntimeEnrollmentKeyRegistries"
            FOR EACH ROW EXECUTE FUNCTION public.runtime_test_reject_registry_version();
            """);
        try
        {
            var failure = await Assert.ThrowsAsync<PostgresException>(() =>
                RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                    connections.Admin,
                    v2,
                    1,
                    true,
                    RuntimeEnrollmentKeyRegistryOperator.ExecuteConfirmation));
            Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, failure.SqlState);
            Assert.Equal(beforeRollback, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));
        }
        finally
        {
            await ExecuteAsync(admin, """
                DROP TRIGGER IF EXISTS trg_runtime_test_reject_registry_version
                    ON public."RuntimeEnrollmentKeyRegistries";
                DROP FUNCTION IF EXISTS public.runtime_test_reject_registry_version();
                """);
        }

        var results = await Task.WhenAll(
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                connections.Admin,
                v2,
                1,
                true,
                RuntimeEnrollmentKeyRegistryOperator.ExecuteConfirmation),
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                connections.Admin,
                v2,
                1,
                true,
                RuntimeEnrollmentKeyRegistryOperator.ExecuteConfirmation));
        Assert.Single(results, result => !result.AlreadyApplied);
        Assert.Single(results, result => result.AlreadyApplied);
        var registry = new RuntimeEnrollmentKeyRegistryService(
            new TestDbFactory(connections.App),
            Options.Create(v2));
        await registry.ValidateAsync();

        var replay = await RuntimeEnrollmentKeyRegistryOperator.RunAsync(
            connections.Admin,
            v2,
            1,
            true,
            RuntimeEnrollmentKeyRegistryOperator.ExecuteConfirmation);
        Assert.True(replay.AlreadyApplied);

        var after = await SnapshotRuntimeKeyRegistryAsync(connections.Admin);
        var prematureRetirement = RotationOptions(productId, 3, "enc-operator-1",
            [("enc-operator-1", aes)],
            [(signing2, "active"), (signing3, "next")]);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                connections.Admin, prematureRetirement, 2, false));
        Assert.Equal(after, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));

        var retiredCandidateId = SigningKeyId(signing1).Replace("'", "''", StringComparison.Ordinal);
        await ExecuteAsync(admin, $"""
            SET session_replication_role = replica;
            UPDATE public."RuntimeEnrollmentKeyRegistries"
            SET "RetainUntilUtc" = clock_timestamp() - interval '1 second'
            WHERE "Purpose" = 'capability-signing' AND "KeyId" = '{retiredCandidateId}';
            SET session_replication_role = origin;
            """);
        var beforeMixed = await SnapshotRuntimeKeyRegistryAsync(connections.Admin);
        var mixed = RotationOptions(productId, 3, "enc-operator-1",
            [("enc-operator-1", aes)],
            [(signing2, "previous"), (signing3, "active"), (signing4, "next")]);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                connections.Admin, mixed, 2, false));
        Assert.Equal(beforeMixed, await SnapshotRuntimeKeyRegistryAsync(connections.Admin));
    }

    [Fact]
    public async Task Prepare_NonCanonicalSemVer_IsRejectedWithOpenPoliciesBeforeDatabaseAuthority()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.0-01", "*");
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        using var clientKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, active, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));

        var invalid = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.PrepareAsync(
            "website-step1", Sha256("invalid-semver-open-policy"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), clientKey)));

        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
        await using var db = await factory.CreateDbContextAsync();
        Assert.False(await db.RuntimeEnrollments.AnyAsync(row => row.BindingId == fixture.BindingId));
        Assert.Null(await db.Products.AsNoTracking().Where(row => row.Id == fixture.ProductId)
            .Select(row => row.MinimumAllowedVersion).SingleAsync());
        Assert.Equal("*", await db.Licenses.AsNoTracking().Where(row => row.ProductId == fixture.ProductId)
            .Select(row => row.AllowedVersions).SingleAsync());
    }

    [Fact]
    public async Task EncryptionEnvelope_BindsFullOwnerReference_AndRequiresTransaction()
    {
        var connections = await ProvisionAsync();
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var options = RuntimeOptions(Guid.Parse("11111111-1111-4111-8111-111111111111"), active, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var ownerId = Guid.NewGuid();
        const string ownerReference = "RuntimeEnrollmentProofNonces:enrollment-a:jti-a:confirm:ResponseCiphertext";
        await using var db = await new TestDbFactory(connections.App).CreateDbContextAsync();

        await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => crypto.SealAsync(
            db, "confirm-response", ownerId, 1, "payload"u8.ToArray(), ownerReference));

        await using var transaction = await db.Database.BeginTransactionAsync();
        var sealedValue = await crypto.SealAsync(
            db, "confirm-response", ownerId, 1, "payload"u8.ToArray(), ownerReference);
        var opened = crypto.Open(
            "confirm-response", ownerId, 1, sealedValue.KeyId, sealedValue.Ciphertext, ownerReference);
        Assert.Equal("payload"u8.ToArray(), opened);
        Assert.ThrowsAny<CryptographicException>(() => crypto.Open(
            "confirm-response", ownerId, 1, sealedValue.KeyId, sealedValue.Ciphertext,
            "RuntimeEnrollmentProofNonces:enrollment-b:jti-a:confirm:ResponseCiphertext"));
        Assert.ThrowsAny<CryptographicException>(() => crypto.Open(
            "capability-response", ownerId, 1, sealedValue.KeyId, sealedValue.Ciphertext, ownerReference));
        await transaction.RollbackAsync();
    }

    /// <summary>
    /// Exercises Prepare, confirmation, current and historical capability issuance, exact replay, and
    /// proves a divergent distribution-binding version cannot replace current enrollment/commercial authority.
    /// </summary>
    [Fact]
    public async Task PrepareConfirmCapability_EndToEnd_UsesFrozenReplayAndValidPs256Token()
    {
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (isolated.Admin, isolated.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, RuntimeEnrollmentService.LegacyCapabilityReleaseVersion);
        string grantRefDigest;
        await using (var fixtureDb = await factory.CreateDbContextAsync())
        {
            grantRefDigest = await fixtureDb.DistributionInstallationBindings
                .Where(candidate => candidate.Id == fixture.BindingId)
                .Select(candidate => candidate.GrantRefDigestSha256)
                .SingleAsync();
        }
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));
        var spki = enrollmentKey.ExportSubjectPublicKeyInfo();
        var spkiDigest = SHA256.HashData(spki);
        var prepareId = Guid.NewGuid().ToString("D");
        var prepare = new RuntimeEnrollmentPrepareRequest
        {
            Schema = RuntimeEnrollmentService.PrepareV2Schema,
            RequestId = prepareId,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            HandoffDigestSha256 = fixture.HandoffDigest,
            InstallationId = fixture.InstallationId,
            ReleaseVersion = fixture.Version,
            Epoch = 1,
            Key = new RuntimeEnrollmentKeyRequest
            {
                Alg = "PS256",
                PublicKeySpkiBase64 = Convert.ToBase64String(spki),
                PublicKeySpkiSha256 = Convert.ToHexStringLower(spkiDigest),
                KeyThumbprint = Base64Url(spkiDigest),
                Backend = "software-cng-unattested",
                Attestation = "none"
            }
        };
        var prepareDigest = Sha256("prepare-exact-body");

        var prepared = await service.PrepareAsync("website-step1", prepareDigest, prepare);
        var replayedPrepare = await service.PrepareAsync("website-step1", prepareDigest, prepare);

        Assert.False(prepared.Idempotent);
        Assert.True(replayedPrepare.Idempotent);
        Assert.Equal(prepared.Response, replayedPrepare.Response);
        Assert.Equal(RuntimeEnrollmentService.PrepareV2ResponseSchema, prepared.Response.Schema);
        Assert.Equal(1, prepared.Response.SecurityEpoch);
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("confirm-exact-body");
        var confirmProof = Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
            prepared.Response.Challenge, confirmDigest);
        await InstallProofFailureTriggerAsync(connections.Admin, failOnce: true);
        RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse> confirmed;
        try
        {
            confirmed = await service.ConfirmAsync(
                enrollmentId, confirmDigest, confirm, confirmProof, IPAddress.Loopback);
        }
        finally
        {
            await RemoveProofFailureTriggerAsync(connections.Admin);
        }
        Assert.Equal("active", confirmed.Response.Status);

        var capability = new RuntimeEnrollmentCapabilityRequest
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
        var capabilityDigest = Sha256("capability-exact-body");
        var capabilityProof = Proof(enrollmentKey, "capability", enrollmentId,
            capability.Audience, "-", capabilityDigest);
        await InstallProofFailureTriggerAsync(connections.Admin, failOnce: false);
        try
        {
            var unavailable = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.CreateCapabilityAsync(
                enrollmentId, capabilityDigest, capability, capabilityProof, IPAddress.Loopback));
            Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
            Assert.Equal("authority_unavailable", unavailable.ErrorCode);
        }
        finally
        {
            await RemoveProofFailureTriggerAsync(connections.Admin);
        }
        capabilityProof = Proof(enrollmentKey, "capability", enrollmentId,
            capability.Audience, "-", capabilityDigest);
        var issued = await service.CreateCapabilityAsync(
            enrollmentId, capabilityDigest, capability, capabilityProof, IPAddress.Loopback);
        var segments = issued.Response.CapabilityToken.Split('.');
        Assert.Equal(3, segments.Length);
        Assert.True(capabilitySigning.VerifyData(
            Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), DecodeBase64Url(segments[2]),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        using (var payload = JsonDocument.Parse(DecodeBase64Url(segments[1])))
        {
            Assert.Equal(fixture.InstallationId,
                payload.RootElement.GetProperty("installation_id").GetString());
            Assert.Equal(fixture.Version,
                payload.RootElement.GetProperty("release_version").GetString());
            Assert.Equal(capability.SessionId,
                payload.RootElement.GetProperty("session_id").GetString());
            Assert.Equal(new string('d', 64),
                payload.RootElement.GetProperty("binaries").GetProperty("FP_DLL").GetString());
        }

        foreach (var mismatch in new[] { "installation", "release", "binary" })
        {
            var mismatchedRequest = JsonSerializer.Deserialize<RuntimeEnrollmentCapabilityRequest>(
                JsonSerializer.Serialize(capability))!;
            mismatchedRequest.SessionId = Guid.NewGuid().ToString("D");
            if (mismatch == "installation")
                mismatchedRequest.InstallationId = Guid.NewGuid().ToString("D");
            else if (mismatch == "release")
                mismatchedRequest.ReleaseVersion = "2.2.998";
            else
                mismatchedRequest.Binaries!.Single(binary => binary.Key == "FP_DLL").Sha256 = new string('f', 64);
            var rejectedDigest = Sha256("capability-binding-mismatch-" + mismatch);
            var error = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.CreateCapabilityAsync(
                enrollmentId, rejectedDigest, mismatchedRequest,
                Proof(enrollmentKey, "capability", enrollmentId, mismatchedRequest.Audience!, "-", rejectedDigest),
                IPAddress.Loopback));
            Assert.Equal(StatusCodes.Status409Conflict, error.StatusCode);
            Assert.Equal(mismatch == "binary" ? "capability_binary_mismatch" : "capability_binding_mismatch",
                error.ErrorCode);
        }

        Guid assignmentId;
        Guid assignmentLicenseId;
        Guid assignmentSeatId;
        await using (var authorityDb = await factory.CreateDbContextAsync())
        {
            var assignment = await authorityDb.EnrollmentLicenseAssignments.SingleAsync(row =>
                row.EnrollmentId == enrollmentId && row.State == "ACTIVE");
            assignmentId = assignment.Id;
            assignmentLicenseId = assignment.LicenseId;
            assignmentSeatId = assignment.LicenseSeatId;
            Assert.True(await authorityDb.Licenses.AnyAsync(row => row.Id == assignmentLicenseId
                && row.ProductId == fixture.ProductId && row.IsActive));
            Assert.True(await authorityDb.LicenseSeats.AnyAsync(row => row.Id == assignmentSeatId
                && row.LicenseId == assignmentLicenseId && row.IsActive));
        }
        // The dual-write trigger correctly rejects creating new divergence. Disable only its exact
        // isolated-fixture trigger to represent pre-existing history, then re-enable it before Runtime acts.
        await using (var admin = new NpgsqlConnection(connections.Admin))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, """
                ALTER TABLE public."DistributionInstallationBindings"
                DISABLE TRIGGER "TR_DistributionBindings_AssignmentDualWrite";
                """);
            try
            {
                await using var command = admin.CreateCommand();
                command.CommandText = """
                    UPDATE public."DistributionInstallationBindings"
                    SET "Version" = '2.2.915'
                    WHERE "Id" = @bindingId;
                    """;
                command.Parameters.AddWithValue("bindingId", fixture.BindingId);
                Assert.Equal(1, await command.ExecuteNonQueryAsync());
            }
            finally
            {
                await ExecuteAsync(admin, """
                    ALTER TABLE public."DistributionInstallationBindings"
                    ENABLE TRIGGER "TR_DistributionBindings_AssignmentDualWrite";
                    """);
            }
        }

        var legacyCapability = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"]
        };
        var legacyDigest = Sha256("capability-2.2.916-exact-body");
        var legacyProof = Proof(enrollmentKey, "capability", enrollmentId,
            legacyCapability.Audience, "-", legacyDigest);
        var legacyIssued = await service.CreateCapabilityAsync(
            enrollmentId, legacyDigest, legacyCapability, legacyProof, IPAddress.Loopback);
        var legacyReplay = await service.CreateCapabilityAsync(
            enrollmentId, legacyDigest, legacyCapability, legacyProof, IPAddress.Loopback);
        Assert.False(legacyIssued.Idempotent);
        Assert.True(legacyReplay.Idempotent);
        Assert.Equal(legacyIssued.ExactResponseBody, legacyReplay.ExactResponseBody);
        await using (var authorityDb = await factory.CreateDbContextAsync())
        {
            var enrollment = await authorityDb.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId);
            var binding = await authorityDb.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == fixture.BindingId);
            var assignment = await authorityDb.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == enrollmentId && row.State == "ACTIVE");
            Assert.Equal(RuntimeEnrollmentService.LegacyCapabilityReleaseVersion, enrollment.ReleaseVersion);
            Assert.Equal("2.2.915", binding.Version);
            Assert.Equal(assignmentId, assignment.Id);
            Assert.Equal(assignmentLicenseId, assignment.LicenseId);
            Assert.Equal(assignmentSeatId, assignment.LicenseSeatId);
            Assert.True(await authorityDb.Licenses.AsNoTracking().AnyAsync(row =>
                row.Id == assignment.LicenseId && row.ProductId == enrollment.ProductId && row.IsActive));
            Assert.True(await authorityDb.LicenseSeats.AsNoTracking().AnyAsync(row =>
                row.Id == assignment.LicenseSeatId && row.LicenseId == assignment.LicenseId && row.IsActive));
        }
        await using (var restoreDb = await factory.CreateDbContextAsync())
        {
            var binding = await restoreDb.DistributionInstallationBindings.SingleAsync(row =>
                row.Id == fixture.BindingId);
            binding.Version = RuntimeEnrollmentService.LegacyCapabilityReleaseVersion;
            await restoreDb.SaveChangesAsync();
        }
        var legacySegments = legacyIssued.Response.CapabilityToken.Split('.');
        using (var legacyPayload = JsonDocument.Parse(DecodeBase64Url(legacySegments[1])))
        {
            Assert.Equal(
                new[] { "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "epoch", "security_epoch", "scope", "cnf" },
                legacyPayload.RootElement.EnumerateObject().Select(property => property.Name).ToArray());
        }

        var milestoneSessionId = Guid.NewGuid().ToString("D");
        var firstMilestone = new RuntimeMilestoneRequest
        {
            Schema = RuntimeEnrollmentService.MilestoneSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            SessionId = milestoneSessionId,
            Sequence = 1,
            EventId = Guid.NewGuid().ToString("D"),
            Code = "bootstrap_entered",
            OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow)
        };
        var firstMilestoneDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(firstMilestone));
        var firstMilestoneProof = Proof(enrollmentKey, "milestone", enrollmentId,
            options.ConfirmAudience, "-", firstMilestoneDigest);
        var milestoneResults = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => service.RecordMilestoneAsync(
            enrollmentId, firstMilestoneDigest, firstMilestone, firstMilestoneProof, IPAddress.Loopback)));
        Assert.Single(milestoneResults, result => !result.Idempotent);
        Assert.Equal(11, milestoneResults.Count(result => result.Idempotent));
        Assert.Single(milestoneResults.Select(result => Convert.ToBase64String(result.ExactResponseBody)).Distinct());
        Assert.All(milestoneResults, result => Assert.Equal("client_declared", result.Response.EvidenceClass));

        var duplicateCode = new RuntimeMilestoneRequest
        {
            Schema = firstMilestone.Schema,
            ProtocolVersion = firstMilestone.ProtocolVersion,
            EnrollmentId = firstMilestone.EnrollmentId,
            Epoch = firstMilestone.Epoch,
            SecurityEpoch = firstMilestone.SecurityEpoch,
            SessionId = firstMilestone.SessionId,
            Sequence = 2,
            EventId = Guid.NewGuid().ToString("D"),
            Code = firstMilestone.Code,
            OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow)
        };
        var duplicateCodeDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(duplicateCode));
        var duplicateCodeError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.RecordMilestoneAsync(
            enrollmentId, duplicateCodeDigest, duplicateCode,
            Proof(enrollmentKey, "milestone", enrollmentId, options.ConfirmAudience, "-", duplicateCodeDigest),
            IPAddress.Loopback));
        Assert.Equal("milestone_conflict", duplicateCodeError.ErrorCode);

        duplicateCode.Sequence = 3;
        duplicateCode.Code = "integrity_allowed";
        var skippedDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(duplicateCode));
        var skippedError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.RecordMilestoneAsync(
            enrollmentId, skippedDigest, duplicateCode,
            Proof(enrollmentKey, "milestone", enrollmentId, options.ConfirmAudience, "-", skippedDigest),
            IPAddress.Loopback));
        Assert.Equal("sequence_out_of_order", skippedError.ErrorCode);

        duplicateCode.Sequence = 2;
        var secondDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(duplicateCode));
        await service.RecordMilestoneAsync(enrollmentId, secondDigest, duplicateCode,
            Proof(enrollmentKey, "milestone", enrollmentId, options.ConfirmAudience, "-", secondDigest),
            IPAddress.Loopback);

        await using (var milestoneCheck = await factory.CreateDbContextAsync())
        {
            Assert.Equal(2, await milestoneCheck.RuntimeMilestones.CountAsync(row => row.EnrollmentId == enrollmentId));
            Assert.All(await milestoneCheck.RuntimeMilestones.Where(row => row.EnrollmentId == enrollmentId).ToListAsync(),
                row => Assert.Equal("client_declared", row.EvidenceClass));
            Assert.Equal(2, (await milestoneCheck.RuntimeMilestoneSessions.SingleAsync(row =>
                row.EnrollmentId == enrollmentId && row.SessionId == milestoneSessionId)).LastSequence);
        }

        await using (var openIncident = await factory.CreateDbContextAsync())
        {
            var enrollment = await openIncident.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            openIncident.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident
            {
                EnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                ProductId = enrollment.ProductId,
                InstallationId = enrollment.InstallationId,
                EventId = Guid.NewGuid().ToString("D"),
                Trigger = "RuntimeCheck_NativeDllSwapped",
                State = "OPEN",
                OpenedSecurityEpoch = enrollment.SecurityEpoch,
                OpenedAuthorityEpoch = enrollment.AuthorityEpoch,
                OpenedAtUtc = DateTime.UtcNow
            });
            await openIncident.SaveChangesAsync();
        }
        duplicateCode.Sequence = 3;
        duplicateCode.EventId = Guid.NewGuid().ToString("D");
        duplicateCode.Code = "license_allowed";
        duplicateCode.OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow);
        var incidentMilestoneDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(duplicateCode));
        var incidentMilestone = await service.RecordMilestoneAsync(
            enrollmentId, incidentMilestoneDigest, duplicateCode,
            Proof(enrollmentKey, "milestone", enrollmentId, options.ConfirmAudience, "-", incidentMilestoneDigest),
            IPAddress.Loopback);
        Assert.Equal("client_declared", incidentMilestone.Response.EvidenceClass);
        await using (var removeIncident = await new TestDbFactory(connections.Admin).CreateDbContextAsync())
        {
            removeIncident.RuntimeCriticalIncidents.RemoveRange(
                removeIncident.RuntimeCriticalIncidents.Where(row => row.EnrollmentId == enrollmentId));
            await removeIncident.SaveChangesAsync();
        }

        var expiredAt = DateTime.UtcNow.AddMinutes(-1);
        await using (var expireSession = await factory.CreateDbContextAsync())
        {
            await expireSession.RuntimeMilestones.Where(row =>
                    row.EnrollmentId == enrollmentId && row.SessionId == milestoneSessionId)
                .ExecuteUpdateAsync(update => update
                    .SetProperty(row => row.AcceptedAtUtc, expiredAt.AddMinutes(-1))
                    .SetProperty(row => row.ExpiresAtUtc, expiredAt));
            await expireSession.RuntimeMilestoneSessions.Where(row =>
                    row.EnrollmentId == enrollmentId && row.SessionId == milestoneSessionId)
                .ExecuteUpdateAsync(update => update
                    .SetProperty(row => row.CreatedAtUtc, expiredAt.AddMinutes(-2))
                    .SetProperty(row => row.LastAcceptedAtUtc, expiredAt.AddMinutes(-1))
                    .SetProperty(row => row.ExpiresAtUtc, expiredAt));
        }
        duplicateCode.Sequence = 4;
        duplicateCode.EventId = Guid.NewGuid().ToString("D");
        duplicateCode.Code = "tia_connected";
        duplicateCode.OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow);
        var expiredSessionDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(duplicateCode));
        var expiredSessionError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.RecordMilestoneAsync(
            enrollmentId, expiredSessionDigest, duplicateCode,
            Proof(enrollmentKey, "milestone", enrollmentId, options.ConfirmAudience, "-", expiredSessionDigest),
            IPAddress.Loopback));
        Assert.Equal("session_expired", expiredSessionError.ErrorCode);

        var cleanup = new RuntimeEnrollmentCleanupService(
            factory, Options.Create(options), TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<RuntimeEnrollmentCleanupService>.Instance);
        var cleanupMethod = typeof(RuntimeEnrollmentCleanupService).GetMethod(
            "CleanupAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        await Assert.IsAssignableFrom<Task>(cleanupMethod.Invoke(cleanup, [CancellationToken.None]));
        await using (var cleanupCheck = await factory.CreateDbContextAsync())
        {
            Assert.False(await cleanupCheck.RuntimeMilestoneSessions.AnyAsync(row =>
                row.EnrollmentId == enrollmentId && row.SessionId == milestoneSessionId));
            Assert.False(await cleanupCheck.RuntimeMilestones.AnyAsync(row =>
                row.EnrollmentId == enrollmentId && row.SessionId == milestoneSessionId));
            Assert.False(await cleanupCheck.RuntimeEnrollmentProofNonces.AnyAsync(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "milestone"));
        }

        var invalidationNow = DateTimeOffset.UtcNow;
        var distribution = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(invalidationNow),
            TestHardwareAuthorityAliasResolver.Instance);
        var invalidation = new DistributionInstallationInvalidationRequest
        {
            Schema = DistributionInstallationBindingService.InvalidationSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            GrantRefDigestSha256 = grantRefDigest,
            Reason = "grant_revoked",
            OccurredAtUtc = FormatUtc(invalidationNow),
            Epoch = 1
        };
        await distribution.InvalidateAsync(
            "website-step1", Sha256("runtime-e2e-invalidation-exact-body"), invalidation);

        capabilityProof = Proof(enrollmentKey, "capability", enrollmentId,
            capability.Audience, "-", capabilityDigest);
        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.CreateCapabilityAsync(
            enrollmentId, capabilityDigest, capability, capabilityProof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, rejected.StatusCode);
        Assert.Equal("authority_ineligible", rejected.ErrorCode);
        Assert.Equal("assignment_missing", rejected.DiagnosticCode);

        await using var check = await factory.CreateDbContextAsync();
        Assert.Equal("invalidated", (await check.DistributionInstallationBindings.SingleAsync(
            candidate => candidate.Id == fixture.BindingId)).State);
        Assert.Equal("ACTIVE", (await check.RuntimeEnrollments.SingleAsync(
            candidate => candidate.Id == enrollmentId)).State);
        Assert.Single(await check.DistributionBindingInvalidations.Where(candidate =>
            candidate.BindingId == fixture.BindingId).ToListAsync());
    }

    /// <summary>
    /// Proves a new Prepare publishes the enrollment and its sole ACTIVE commercial assignment
    /// together, then returns the byte-identical response only while that authority remains live.
    /// A second connection cannot observe either row while the transaction is paused after the
    /// assignment trigger and before the final quota write commits.
    /// </summary>
    [Fact]
    public async Task Prepare_NewAndExactReplay_PublishAssignmentAtomicallyAndReturnFrozenBytes()
    {
        using var scenario = await CreatePrepareOnlyScenarioAsync();
        const long pauseKey = 131200031;
        await using var blocker = new NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync();
        await ExecuteAsync(blocker, $"SELECT pg_catalog.pg_advisory_lock({pauseKey});");
        var blockerPid = await ScalarAsync<int>(blocker, "SELECT pg_catalog.pg_backend_pid() AS \"Value\";");
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, $"""
                CREATE OR REPLACE FUNCTION public.test_item3hc1_pause_prepare_quota()
                RETURNS trigger
                LANGUAGE plpgsql
                SECURITY DEFINER
                SET search_path = pg_catalog, pg_temp
                AS $function$
                BEGIN
                    IF NEW."Scope" = 'prepare-binding' THEN
                        PERFORM pg_catalog.pg_advisory_xact_lock({pauseKey});
                    END IF;
                    RETURN NEW;
                END;
                $function$;
                CREATE TRIGGER test_item3hc1_pause_prepare_quota
                BEFORE INSERT ON public."RuntimeEnrollmentQuotas"
                FOR EACH ROW EXECUTE FUNCTION public.test_item3hc1_pause_prepare_quota();
                """);
        }

        try
        {
            var pending = scenario.Runtime.PrepareAsync(
                "website-step1", scenario.PrepareDigest, scenario.PrepareRequest);
            await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
            await observer.OpenAsync();
            _ = await WaitForAdvisoryWaitAsync(observer, blockerPid);
            Assert.False(pending.IsCompleted);
            Assert.Equal(0L, await ScalarAsync<long>(observer, """
                SELECT count(*)::bigint AS "Value" FROM public."RuntimeEnrollments";
                """));
            Assert.Equal(0L, await ScalarAsync<long>(observer, """
                SELECT count(*)::bigint AS "Value" FROM public."EnrollmentLicenseAssignments";
                """));

            await ExecuteAsync(blocker, $"SELECT pg_catalog.pg_advisory_unlock({pauseKey});");
            var created = await pending;
            var replay = await scenario.Runtime.PrepareAsync(
                "website-step1", scenario.PrepareDigest, scenario.PrepareRequest);

            Assert.False(created.Idempotent);
            Assert.True(replay.Idempotent);
            Assert.Equal(created.ExactResponseBody, replay.ExactResponseBody);
            var enrollmentId = Guid.Parse(created.Response.EnrollmentId);
            await using var verify = await scenario.Factory.CreateDbContextAsync();
            var assignment = await verify.EnrollmentLicenseAssignments.SingleAsync(row =>
                row.EnrollmentId == enrollmentId && row.State == "ACTIVE");
            Assert.Equal(1, assignment.Revision);
            Assert.Equal(scenario.Fixture.LicenseId, assignment.LicenseId);
            Assert.Equal(scenario.Fixture.SeatId, assignment.LicenseSeatId);
            Assert.Single(await verify.RuntimeEnrollmentRequests.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "prepare").ToListAsync());
        }
        finally
        {
            if (blocker.State == System.Data.ConnectionState.Open)
            {
                await ExecuteAsync(blocker, $"SELECT pg_catalog.pg_advisory_unlock({pauseKey});");
                await blocker.CloseAsync();
            }
        }
    }

    /// <summary>
    /// Exact Prepare replay is a live challenge read, not a historical receipt. ACTIVE, consumed
    /// or expired challenges remain closed after A and B are re-evaluated and return no frozen bytes.
    /// </summary>
    [Theory]
    [InlineData("active")]
    [InlineData("consumed")]
    [InlineData("expired")]
    public async Task Prepare_ExactReplay_ClosesTerminalConsumedAndExpiredChallenges(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            if (mutation == "active")
            {
                enrollment.State = "ACTIVE";
                enrollment.ChallengeConsumedAtUtc = DateTime.UtcNow;
            }
            else if (mutation == "consumed")
            {
                enrollment.ChallengeConsumedAtUtc = DateTime.UtcNow;
            }
            else
            {
                enrollment.ChallengeExpiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
            }
            await mutate.SaveChangesAsync();
        }

        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.PrepareAsync("website-step1", scenario.PrepareDigest, scenario.PrepareRequest));

        Assert.Equal(StatusCodes.Status409Conflict, refusal.StatusCode);
        Assert.Equal("prepare_superseded", refusal.ErrorCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Single(await verify.RuntimeEnrollmentRequests.Where(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.Operation == "prepare").ToListAsync());
    }

    /// <summary>
    /// A current hardware ban is decided by B after the item-2 assignment trigger. The refusal
    /// rolls back every enrollment, assignment, request, quota and encrypted response fragment.
    /// </summary>
    [Fact]
    public async Task Prepare_CommercialDenial_RollsBackEveryAuthorityFragment()
    {
        using var scenario = await CreatePrepareOnlyScenarioAsync();
        await using (var ban = await scenario.Factory.CreateDbContextAsync())
        {
            ban.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = scenario.Fixture.HardwareId,
                ProductId = scenario.Fixture.ProductId,
                Reason = "Item 3H-C1 Prepare commercial denial",
                BanCategory = BannedHardwareId.Categories.Piracy,
                IsActive = true
            });
            await ban.SaveChangesAsync();
        }

        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.PrepareAsync("website-step1", scenario.PrepareDigest, scenario.PrepareRequest));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
        Assert.Equal("authority_ineligible", refusal.ErrorCode);
        Assert.Equal("hardware_banned", refusal.DiagnosticCode);
        await AssertNoPrepareFragmentsAsync(scenario);
    }

    /// <summary>
    /// A finalized binding whose signed executable digest differs from the approved release fails
    /// provenance after the assignment trigger and rolls back every first-Prepare authority fragment.
    /// </summary>
    [Fact]
    public async Task Prepare_BinaryProvenanceMismatch_RollsBackEveryAuthorityFragment()
    {
        using var scenario = await CreatePrepareOnlyScenarioAsync();
        await using (var corrupt = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await corrupt.DistributionInstallationBindings.SingleAsync(row =>
                row.Id == scenario.Fixture.BindingId);
            binding.ExecutableSha256 = new string('0', 64);
            await corrupt.SaveChangesAsync();
        }

        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.PrepareAsync("website-step1", scenario.PrepareDigest, scenario.PrepareRequest));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
        Assert.Equal("binding_ineligible", refusal.ErrorCode);
        await AssertNoPrepareFragmentsAsync(scenario);
    }

    /// <summary>
    /// The named assignment trigger's 23514 remains a bounded Runtime refusal. PostgreSQL text and
    /// the trigger's temporary quarantine never escape the rolled-back Prepare transaction.
    /// </summary>
    [Fact]
    public async Task Prepare_AssignmentTriggerCheckViolation_IsBoundedAndLeavesNoFragments()
    {
        using var scenario = await CreatePrepareOnlyScenarioAsync();
        await using (var corrupt = await scenario.Factory.CreateDbContextAsync())
        {
            var currentLicense = await corrupt.Licenses.SingleAsync(row => row.Id == scenario.Fixture.LicenseId);
            var otherLicense = new License
            {
                ProductId = scenario.Fixture.ProductId,
                LicenseTypeId = currentLicense.LicenseTypeId,
                LicenseKey = "ITEM3HC1-" + Guid.NewGuid().ToString("N"),
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*"
            };
            var otherSeat = new LicenseSeat
            {
                License = otherLicense,
                HardwareId = "ITEM3HC1-OTHER-" + Guid.NewGuid().ToString("N"),
                IsActive = true,
                FirstActivatedAt = DateTime.UtcNow,
                LastCheckInAt = DateTime.UtcNow
            };
            corrupt.Licenses.Add(otherLicense);
            corrupt.LicenseSeats.Add(otherSeat);
            await corrupt.SaveChangesAsync();
            var binding = await corrupt.DistributionInstallationBindings.SingleAsync(row =>
                row.Id == scenario.Fixture.BindingId);
            binding.LicenseSeatId = otherSeat.Id;
            await corrupt.SaveChangesAsync();
        }

        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.PrepareAsync("website-step1", scenario.PrepareDigest, scenario.PrepareRequest));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
        Assert.Equal("binding_ineligible", refusal.ErrorCode);
        Assert.Equal("assignment_trigger_refused", refusal.DiagnosticCode);
        Assert.DoesNotContain("commercial assignment", refusal.Message, StringComparison.OrdinalIgnoreCase);
        await AssertNoPrepareFragmentsAsync(scenario);
    }

    /// <summary>
    /// Retryable PostgreSQL transaction states exhaust only the configured bounded retry loop and
    /// surface the stable 503 without retaining any failed Prepare attempt.
    /// </summary>
    [Theory]
    [InlineData("40001")]
    [InlineData("40P01")]
    [InlineData("55P03")]
    public async Task Prepare_RetryableDatabaseFailure_ExhaustsTo503WithoutFragments(string sqlState)
    {
        using var scenario = await CreatePrepareOnlyScenarioAsync();
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, $"""
                CREATE OR REPLACE FUNCTION public.test_item3hc1_retryable_prepare_failure()
                RETURNS trigger
                LANGUAGE plpgsql
                SECURITY DEFINER
                SET search_path = pg_catalog, pg_temp
                AS $function$
                BEGIN
                    RAISE EXCEPTION 'bounded prepare retry injection' USING ERRCODE = '{sqlState}';
                END;
                $function$;
                CREATE TRIGGER test_item3hc1_retryable_prepare_failure
                BEFORE INSERT ON public."RuntimeEnrollmentRequests"
                FOR EACH ROW EXECUTE FUNCTION public.test_item3hc1_retryable_prepare_failure();
                """);
        }

        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.PrepareAsync("website-step1", scenario.PrepareDigest, scenario.PrepareRequest));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refusal.StatusCode);
        Assert.Equal("authority_unavailable", refusal.ErrorCode);
        await AssertNoPrepareFragmentsAsync(scenario);
    }

    /// <summary>
    /// A real commercial writer that owns the item-2 barrier commits before Prepare's decisive
    /// snapshot. Prepare then sees the revocation, refuses atomically and cannot deadlock or grant.
    /// </summary>
    [Fact]
    public async Task Prepare_ConcurrentItem2RevocationBeforeBarrier_RefusesWithoutFragments()
    {
        using var scenario = await CreatePrepareOnlyScenarioAsync();
        await using var writer = await scenario.Factory.CreateDbContextAsync();
        await using var writerTransaction = await writer.Database.BeginTransactionAsync();
        var license = await writer.Licenses.SingleAsync(row => row.Id == scenario.Fixture.LicenseId);
        license.IsActive = false;
        await writer.SaveChangesAsync();
        await writer.Database.ExecuteSqlRawAsync(
            "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);");

        var pending = scenario.Runtime.PrepareAsync(
            "website-step1", scenario.PrepareDigest, scenario.PrepareRequest);
        await Task.Delay(200);
        Assert.False(pending.IsCompleted);
        await writerTransaction.CommitAsync();

        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => pending);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
        Assert.Equal("authority_ineligible", refusal.ErrorCode);
        Assert.Equal("assignment_missing", refusal.DiagnosticCode);
        await AssertNoPrepareFragmentsAsync(scenario);
    }

    /// <summary>
    /// Prepare locks an existing live enrollment before taking the commercial barrier, then reads
    /// database time after that barrier. A challenge expiring during the intercepted barrier is
    /// invalidated before the successor is created, while a competing row locker remains blocked.
    /// </summary>
    [Fact]
    public async Task Prepare_ExpiredPending_LocksEnrollmentBeforeBarrierAndUsesFreshDatabaseTime()
    {
        var barrierInterceptor = new PrepareWriteBarrierInterceptor(initiallyArmed: false);
        using var scenario = await CreatePrepareOnlyScenarioAsync(barrierInterceptor);
        var original = await scenario.Runtime.PrepareAsync(
            "website-step1", scenario.PrepareDigest, scenario.PrepareRequest);
        var originalEnrollmentId = Guid.Parse(original.Response.EnrollmentId);
        DateTime expiresAtUtc;
        await using (var expire = await scenario.Factory.CreateDbContextAsync())
        {
            await expire.Database.OpenConnectionAsync();
            expiresAtUtc = (await RuntimeEnrollmentService.DatabaseNowAsync(
                expire, CancellationToken.None)).AddMilliseconds(750).UtcDateTime;
            var enrollment = await expire.RuntimeEnrollments.SingleAsync(row =>
                row.Id == originalEnrollmentId);
            enrollment.ChallengeExpiresAtUtc = expiresAtUtc;
            await expire.SaveChangesAsync();
        }

        using var successorKey = RSA.Create(3072);
        var successorRequest = PrepareRequest(
            (scenario.Fixture.ProductId, scenario.Fixture.BindingId, scenario.Fixture.HandoffDigest,
                scenario.Fixture.InstallationId, scenario.Fixture.Version),
            Guid.NewGuid().ToString("D"), successorKey);
        var successorDigest = Sha256("item3hc1-expired-successor-" + successorRequest.RequestId);
        var lockerConnectionString = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Pooling = false
        }.ConnectionString;
        await using var locker = new NpgsqlConnection(lockerConnectionString);
        await locker.OpenAsync();
        await using var lockerTransaction = await locker.BeginTransactionAsync();
        barrierInterceptor.Arm();
        var pendingPrepare = scenario.Runtime.PrepareAsync(
            "website-step1", successorDigest, successorRequest);
        var prepareBackendPid = await barrierInterceptor.BarrierHeld.WaitAsync(TimeSpan.FromSeconds(15));
        await using var lockEnrollment = new NpgsqlCommand("""
            SELECT "Id" FROM public."RuntimeEnrollments" WHERE "Id" = @enrollment_id FOR UPDATE;
            """, locker, lockerTransaction);
        lockEnrollment.Parameters.AddWithValue("enrollment_id", originalEnrollmentId);
        var pendingEnrollmentLock = lockEnrollment.ExecuteScalarAsync();
        await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
        await observer.OpenAsync();
        try
        {
            await WaitForBackendBlockedByAsync(observer, locker.ProcessID, prepareBackendPid);
            Assert.False(pendingEnrollmentLock.IsCompleted);
            while (await ScalarAsync<DateTime>(observer,
                       "SELECT pg_catalog.clock_timestamp() AT TIME ZONE 'UTC' AS \"Value\";")
                   <= expiresAtUtc)
            {
                await Task.Delay(25);
            }
        }
        finally
        {
            barrierInterceptor.Release();
        }

        var successor = await pendingPrepare;
        Assert.False(successor.Idempotent);
        Assert.Equal(originalEnrollmentId, Assert.IsType<Guid>(await pendingEnrollmentLock));
        await lockerTransaction.RollbackAsync();

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var originalEnrollment = await verify.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == originalEnrollmentId);
        Assert.Equal("INVALIDATED", originalEnrollment.State);
        Assert.Equal("challenge_expired", originalEnrollment.InvalidationReason);
        Assert.Equal("PENDING", (await verify.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == Guid.Parse(successor.Response.EnrollmentId))).State);
        Assert.Equal("ENDED", (await verify.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == originalEnrollmentId)).State);
        Assert.Single(await verify.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.State == "ACTIVE").ToListAsync());
    }

    /// <summary>
    /// Proves the opposite serialization order: Prepare may commit while it owns the global shared
    /// authority lease and commercial barrier, then a licence writer waiting on global authority
    /// commits through the real item-2 trigger and closes exact replay. The replay returns no frozen
    /// bytes and cannot mutate the original challenge, request or quota.
    /// </summary>
    [Fact]
    public async Task Prepare_ConcurrentItem2RevocationAfterBarrier_CommitsThenClosesReplay()
    {
        var barrierInterceptor = new PrepareWriteBarrierInterceptor();
        using var scenario = await CreatePrepareOnlyScenarioAsync(barrierInterceptor);
        var writerConnectionString = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Pooling = false
        }.ConnectionString;
        await using var writer = new NpgsqlConnection(writerConnectionString);
        await writer.OpenAsync();
        await using var writerTransaction = await writer.BeginTransactionAsync();

        Task<int>? pendingWriterUpdate = null;
        try
        {
            var pendingPrepare = scenario.Runtime.PrepareAsync(
                "website-step1", scenario.PrepareDigest, scenario.PrepareRequest);
            var prepareBackendPid = await barrierInterceptor.BarrierHeld.WaitAsync(TimeSpan.FromSeconds(15));
            Assert.False(pendingPrepare.IsCompleted);

            await using var revoke = new NpgsqlCommand("""
                UPDATE public."Licenses" SET "IsActive" = FALSE WHERE "Id" = @license_id;
                """, writer, writerTransaction);
            revoke.Parameters.AddWithValue("license_id", scenario.Fixture.LicenseId);
            var writerBackendPid = writer.ProcessID;
            pendingWriterUpdate = revoke.ExecuteNonQueryAsync();
            await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
            await observer.OpenAsync();
            try
            {
                await WaitForWriterBlockedOnPrepareGlobalAuthorityAsync(
                    observer, writerBackendPid, prepareBackendPid);
                Assert.False(pendingPrepare.IsCompleted);
                Assert.False(pendingWriterUpdate.IsCompleted);
            }
            finally
            {
                barrierInterceptor.Release();
            }

            var created = await pendingPrepare;
            Assert.False(created.Idempotent);
            Assert.Equal(1, await pendingWriterUpdate);
            await writerTransaction.CommitAsync();

            var enrollmentId = Guid.Parse(created.Response.EnrollmentId);
            string challengeDigestBeforeReplay;
            int requestCountBeforeReplay;
            int quotaCountBeforeReplay;
            await using (var beforeReplay = await scenario.Factory.CreateDbContextAsync())
            {
                var enrollmentBeforeReplay = await beforeReplay.RuntimeEnrollments.AsNoTracking()
                    .SingleAsync(row => row.Id == enrollmentId);
                challengeDigestBeforeReplay = enrollmentBeforeReplay.ChallengeDigestSha256;
                requestCountBeforeReplay = await beforeReplay.RuntimeEnrollmentRequests.CountAsync(row =>
                    row.EnrollmentId == enrollmentId && row.Operation == "prepare");
                quotaCountBeforeReplay = await beforeReplay.RuntimeEnrollmentQuotas.CountAsync(row =>
                    row.Scope == "prepare-binding" || row.Scope == "prepare-global");
            }

            var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                scenario.Runtime.PrepareAsync("website-step1", scenario.PrepareDigest, scenario.PrepareRequest));
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, refusal.StatusCode);
            Assert.Equal("authority_ineligible", refusal.ErrorCode);
            Assert.Equal("assignment_missing", refusal.DiagnosticCode);

            await using var verify = await scenario.Factory.CreateDbContextAsync();
            var enrollment = await verify.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId);
            Assert.Equal("PENDING", enrollment.State);
            Assert.Null(enrollment.ChallengeConsumedAtUtc);
            Assert.Equal(Sha256(created.Response.Challenge), enrollment.ChallengeDigestSha256);
            Assert.Equal(challengeDigestBeforeReplay, enrollment.ChallengeDigestSha256);
            Assert.Equal(requestCountBeforeReplay, await verify.RuntimeEnrollmentRequests.CountAsync(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "prepare"));
            Assert.Equal(quotaCountBeforeReplay, await verify.RuntimeEnrollmentQuotas.CountAsync(row =>
                row.Scope == "prepare-binding" || row.Scope == "prepare-global"));
            Assert.Equal(1, requestCountBeforeReplay);
            Assert.Equal(2, quotaCountBeforeReplay);
            var assignment = await verify.EnrollmentLicenseAssignments.SingleAsync(row =>
                row.EnrollmentId == enrollmentId);
            Assert.Equal("ENDED", assignment.State);
            Assert.False(await verify.EnrollmentLicenseAssignments.AnyAsync(row =>
                row.EnrollmentId == enrollmentId && row.State == "ACTIVE"));
        }
        finally
        {
            barrierInterceptor.Release();
        }
    }

    [Fact]
    public async Task WebSetupTransitionV2_ExpiredSource_TransfersToSelectedEligibleLicenseAtomically()
        => await ExerciseWebSetupTransferAsync(automaticReplacement: false);

    /// <summary>Transfers an authenticated Runtime source to a full single-seat target without losing history or charging twice.</summary>
    [Fact]
    public async Task AutoSeatSwitch_RuntimeTransfer_FullTargetReplacesOneMachineAtomically()
        => await ExerciseWebSetupTransferAsync(automaticReplacement: true);

    /// <summary>The transfer path observes transport metadata without trusting forwarded or correlation headers.</summary>
    [Fact]
    public async Task AutoSeatSwitch_RuntimeTransfer_RecordsObservedTransport()
    {
        var context = new DefaultHttpContext { TraceIdentifier = "synthetic-runtime-transfer-trace" };
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.42");
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.99";
        context.Request.Headers["X-Correlation-ID"] = "forged-client-correlation";
        var accessor = new HttpContextAccessor { HttpContext = context };
        try
        {
            await ExerciseWebSetupTransferAsync(automaticReplacement: true, transportAccessor: accessor);
        }
        finally
        {
            accessor.HttpContext = null;
        }
    }

    /// <summary>Retains the original transfer guards and adds a distinct full-single-seat success contract.</summary>
    private static async Task ExerciseWebSetupTransferAsync(bool automaticReplacement, IHttpContextAccessor? transportAccessor = null)
    {
        var connections = automaticReplacement ? await ProvisionIsolatedAsync() : await ProvisionAsync();
        using var cleanup = automaticReplacement
            ? new BootstrapIsolatedDatabaseCleanup(connections.Admin, connections.App) : null;
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.985");
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var dataProtection = new EphemeralDataProtectionProvider();
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(
            factory, authority, registry, crypto, Options.Create(options), dataProtectionProvider: dataProtection,
            httpContextAccessor: transportAccessor);

        var sourceSubjectRef = Base64Url(SHA256.HashData("websetup-source-subject"u8.ToArray()));
        var targetSubjectRef = Base64Url(SHA256.HashData("websetup-target-subject"u8.ToArray()));
        Guid sourceLicenseId;
        Guid sourceSeatId;
        Guid licenseTypeId;
        await using (var sourceSeed = await factory.CreateDbContextAsync())
        {
            var binding = await sourceSeed.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            sourceLicenseId = binding.LicenseId;
            sourceSeatId = binding.LicenseSeatId;
            binding.SubjectRefDigestSha256 = Sha256(sourceSubjectRef);
            licenseTypeId = (await sourceSeed.Licenses.SingleAsync(row => row.Id == sourceLicenseId)).LicenseTypeId;
            await sourceSeed.SaveChangesAsync();
        }

        var prepared = await service.PrepareAsync("website-step1", Sha256("websetup-v2-transfer-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("websetup-v2-transfer-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, confirm,
            Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
                prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);
        long historicalAuthorityEpoch;
        await using (var authoritySnapshot = await factory.CreateDbContextAsync())
        {
            historicalAuthorityEpoch = (await authoritySnapshot.RuntimeEnrollments.SingleAsync(
                row => row.Id == enrollmentId)).AuthorityEpoch;
        }

        const string targetVersion = "2.2.987";
        var targetLicenseId = Guid.NewGuid();
        await using (var targetSeed = await factory.CreateDbContextAsync())
        {
            targetSeed.Licenses.Add(new License
            {
                Id = targetLicenseId,
                ProductId = fixture.ProductId,
                LicenseTypeId = licenseTypeId,
                LicenseKey = "RUNTIME-TRANSFER-" + Guid.NewGuid().ToString("N"),
                IsActive = true,
                MaxSeats = automaticReplacement ? 1 : 2,
                AllowedVersions = "2.2.*",
                ExpirationDate = DateTime.UtcNow.AddDays(30)
            });
            foreach (var binary in new[] { ("FP_CORE", '1'), ("FP_DLL", '2'), ("FP_EXE", '3') })
                targetSeed.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = fixture.ProductId,
                    Version = targetVersion,
                    Key = binary.Item1,
                    Hash = new string(binary.Item2, 64),
                    Source = ApprovedBinaryService.ReleaseSource
                });
            var sourceLicense = await targetSeed.Licenses.SingleAsync(row => row.Id == sourceLicenseId);
            sourceLicense.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
            sourceLicense.AllowedVersions = "9.*";
            await targetSeed.SaveChangesAsync();
        }

        var targetGrantRef = Guid.NewGuid().ToString("D");
        var distribution = new DistributionInstallationBindingService(
            factory, dataProtection, TimeProvider.System,
            TestHardwareAuthorityAliasResolver.Instance);
        var entitlementRequest = new DistributionEntitlementIssueRequest
        {
            Schema = DistributionInstallationBindingService.IssueV3Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = targetLicenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(targetGrantRef),
            SubjectRef = targetSubjectRef
        };
        var entitlement = await distribution.IssueEntitlementAsync(
            "website-step1", Sha256(JsonSerializer.Serialize(entitlementRequest)), entitlementRequest);
        var issue = new RuntimeWebSetupTransitionIssueRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupTransitionIssueV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            SourceLicenseId = sourceLicenseId.ToString("D"),
            SourceSubjectRef = sourceSubjectRef,
            TargetGrantRef = targetGrantRef,
            TargetLicenseId = targetLicenseId.ToString("D"),
            TargetSubjectRef = targetSubjectRef,
            TargetEntitlementRef = entitlement.Response.EntitlementRef,
            SourceVersion = fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = $"TiaConnect-Setup_v{targetVersion}.msi",
            TargetInstallerSha256 = new string('4', 64)
        };
        var validRequestId = issue.RequestId;
        issue.RequestId = Guid.NewGuid().ToString("D");
        issue.TargetSubjectRef = Base64Url(SHA256.HashData("wrong-target-subject"u8.ToArray()));
        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.IssueWebSetupTransitionAsync(
                "website-step1", Sha256(JsonSerializer.Serialize(issue)), issue));
        Assert.Equal("websetup_transition_ineligible", rejected.ErrorCode);
        await using (var unchanged = await factory.CreateDbContextAsync())
        {
            Assert.Equal(sourceLicenseId, (await unchanged.DistributionInstallationBindings.SingleAsync(
                row => row.Id == fixture.BindingId)).LicenseId);
            Assert.True((await unchanged.LicenseSeats.SingleAsync(row => row.Id == sourceSeatId)).IsActive);
        }

        issue.RequestId = validRequestId;
        issue.TargetSubjectRef = targetSubjectRef;
        var occupiedTargetSeatId = Guid.NewGuid();
        await using (var occupyTarget = await factory.CreateDbContextAsync())
        {
            if (automaticReplacement)
                (await occupyTarget.LicenseTypes.SingleAsync(row => row.Id == licenseTypeId)).MaxActivationsPerDay = 3;
            occupyTarget.LicenseSeats.Add(new LicenseSeat
            {
                Id = occupiedTargetSeatId,
                LicenseId = targetLicenseId,
                HardwareId = "WEBS-" + Guid.NewGuid().ToString("N")[..11].ToUpperInvariant(),
                IsActive = true,
                FirstActivatedAt = DateTime.UtcNow,
                LastCheckInAt = DateTime.UtcNow
            });
            if (!automaticReplacement)
                occupyTarget.LicenseSeats.Add(new LicenseSeat
                {
                    LicenseId = targetLicenseId, HardwareId = "WEBS-SECOND-CAPACITY", IsActive = true,
                    FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow
                });
            await occupyTarget.SaveChangesAsync();
        }
        if (!automaticReplacement)
        {
        var targetCapacityDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.IssueWebSetupTransitionAsync("website-step1", Sha256(JsonSerializer.Serialize(issue)), issue));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, targetCapacityDenied.StatusCode);
        Assert.Equal("seat_limit_reached", targetCapacityDenied.ErrorCode);
        await using (var targetDeniedCheck = await factory.CreateDbContextAsync())
        {
            Assert.Equal(sourceLicenseId, (await targetDeniedCheck.DistributionInstallationBindings.SingleAsync(
                row => row.Id == fixture.BindingId)).LicenseId);
            Assert.True((await targetDeniedCheck.LicenseSeats.SingleAsync(row => row.Id == sourceSeatId)).IsActive);
            Assert.False(await targetDeniedCheck.RuntimeEnrollmentWebSetupTransitions.AnyAsync(row =>
                row.EnrollmentId == enrollmentId));
        }
        var matchingTargetSeatId = Guid.NewGuid();
        await using (var overCapacityTarget = await factory.CreateDbContextAsync())
        {
            var sourceHardware = (await overCapacityTarget.LicenseSeats.SingleAsync(row =>
                row.Id == sourceSeatId)).HardwareId;
            overCapacityTarget.LicenseSeats.Add(new LicenseSeat
            {
                Id = matchingTargetSeatId,
                LicenseId = targetLicenseId,
                HardwareId = sourceHardware,
                IsActive = true,
                FirstActivatedAt = DateTime.UtcNow,
                LastCheckInAt = DateTime.UtcNow
            });
            await overCapacityTarget.SaveChangesAsync();
        }
        var existingTargetSeatDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.IssueWebSetupTransitionAsync("website-step1", Sha256(JsonSerializer.Serialize(issue)), issue));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, existingTargetSeatDenied.StatusCode);
        Assert.Equal("seat_limit_reached", existingTargetSeatDenied.ErrorCode);
        await using (var overCapacityCheck = await factory.CreateDbContextAsync())
        {
            Assert.Equal(sourceLicenseId, (await overCapacityCheck.DistributionInstallationBindings.SingleAsync(
                row => row.Id == fixture.BindingId)).LicenseId);
            Assert.True((await overCapacityCheck.LicenseSeats.SingleAsync(row => row.Id == sourceSeatId)).IsActive);
            Assert.False(await overCapacityCheck.RuntimeEnrollmentWebSetupTransitions.AnyAsync(row =>
                row.EnrollmentId == enrollmentId));
        }
        await using (var releaseTarget = await factory.CreateDbContextAsync())
        {
            (await releaseTarget.LicenseSeats.SingleAsync(row => row.LicenseId == targetLicenseId
                && row.HardwareId == "WEBS-SECOND-CAPACITY")).IsActive = false;
            (await releaseTarget.LicenseSeats.SingleAsync(row => row.Id == occupiedTargetSeatId)).IsActive = false;
            (await releaseTarget.LicenseSeats.SingleAsync(row => row.Id == matchingTargetSeatId)).IsActive = false;
            await releaseTarget.SaveChangesAsync();
        }
        }
        var issueDigest = Sha256(JsonSerializer.Serialize(issue));
        var issued = await service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue);
        var replay = await service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue);
        Assert.False(issued.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, replay.ExactResponseBody);

        await using var check = await factory.CreateDbContextAsync();
        var rebound = await check.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
        var enrollment = await check.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
        Assert.Equal(targetLicenseId, rebound.LicenseId);
        Assert.Equal(targetGrantRef, rebound.GrantRef);
        Assert.Equal(Sha256(targetSubjectRef), rebound.SubjectRefDigestSha256);
        Assert.Equal(targetLicenseId, enrollment.LicenseId);
        Assert.Equal(historicalAuthorityEpoch, enrollment.AuthorityEpoch);
        Assert.False((await check.LicenseSeats.SingleAsync(row => row.Id == sourceSeatId)).IsActive);
        Assert.True((await check.LicenseSeats.SingleAsync(row => row.Id == rebound.LicenseSeatId)).IsActive);
        if (automaticReplacement)
        {
            var replaced = await check.LicenseSeats.SingleAsync(row => row.Id == occupiedTargetSeatId);
            Assert.False(replaced.IsActive);
            Assert.NotNull(replaced.UnlinkedAt);
            Assert.Single(await check.LicenseSeats.Where(row => row.LicenseId == targetLicenseId && row.IsActive).ToListAsync());
            var change = Assert.Single(await check.LicenseHistories.Where(row => row.LicenseId == targetLicenseId
                && row.Action == HistoryActions.UnlinkedApi).ToListAsync());
            Assert.Equal(replaced.UnlinkedAt, change.Timestamp);
            Assert.Equal(AutomaticSeatSwitch.Source, change.PerformedBy);
            Assert.EndsWith("; transport=s2s; remote_address="
                + (transportAccessor?.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unavailable"), change.Details);
            Assert.Equal(transportAccessor?.HttpContext?.TraceIdentifier, change.DecisionCorrelationId);
            Assert.DoesNotContain("198.51.100.99", change.Details);
            Assert.DoesNotContain("forged-client-correlation", change.Details);
        }
        Assert.Equal("finalized", (await check.DistributionEntitlements.SingleAsync(
            row => row.Id == rebound.EntitlementId)).State);

        // Storage corruption behind the new authoritative assignment remains unavailable rather
        // than becoming a business denial or returning the frozen issue bytes.
        var targetSeatId = rebound.LicenseSeatId;
        await using (var admin = new NpgsqlConnection(connections.Admin))
        {
            await admin.OpenAsync();
            await using var dropSeatForeignKey = new NpgsqlCommand("""
                DO $broken_relation$
                DECLARE constraint_name name;
                BEGIN
                    SELECT conname INTO constraint_name FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public."EnrollmentLicenseAssignments"'::pg_catalog.regclass
                      AND confrelid = 'public."LicenseSeats"'::pg_catalog.regclass;
                    IF constraint_name IS NOT NULL THEN
                        EXECUTE pg_catalog.format(
                            'ALTER TABLE public."EnrollmentLicenseAssignments" DROP CONSTRAINT %I',
                            constraint_name);
                    END IF;
                END;
                $broken_relation$;
                """, admin);
            await dropSeatForeignKey.ExecuteNonQueryAsync();
            await using var breakAssignment = new NpgsqlCommand("""
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @missing
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            breakAssignment.Parameters.AddWithValue("missing", Guid.NewGuid());
            breakAssignment.Parameters.AddWithValue("enrollment", enrollmentId);
            Assert.Equal(1, await breakAssignment.ExecuteNonQueryAsync());
            var unavailableReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue));
            Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailableReplay.StatusCode);
            Assert.Equal("authority_unavailable", unavailableReplay.ErrorCode);
            Assert.Equal("assignment_relation_missing", unavailableReplay.DiagnosticCode);
            await using var repairAssignment = new NpgsqlCommand("""
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @seat
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            repairAssignment.Parameters.AddWithValue("seat", targetSeatId);
            repairAssignment.Parameters.AddWithValue("enrollment", enrollmentId);
            Assert.Equal(1, await repairAssignment.ExecuteNonQueryAsync());
        }

        // The target assignment is the only commercial grant after the atomic transfer. A later
        // target revocation closes it through the deferred item-2 writer, so exact issue replay
        // must recheck B rather than return a reservation that was issued under the old target right.
        (await check.Licenses.SingleAsync(row => row.Id == targetLicenseId)).IsActive = false;
        await check.SaveChangesAsync();
        var replayDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, replayDenied.StatusCode);
        Assert.Equal("authority_ineligible", replayDenied.ErrorCode);
        Assert.Equal("assignment_missing", replayDenied.DiagnosticCode);
        await using var deniedCheck = await factory.CreateDbContextAsync();
        Assert.Equal("ISSUED", (await deniedCheck.RuntimeEnrollmentWebSetupTransitions.SingleAsync(row =>
            row.EnrollmentId == enrollmentId)).State);
        var deniedEnrollment = await deniedCheck.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
        Assert.Equal("ACTIVE", deniedEnrollment.State);
        Assert.Equal(historicalAuthorityEpoch, deniedEnrollment.AuthorityEpoch);
    }

    /// <summary>Preserves the exact-body replay conflict before a later release A/P denial, without changing the issued transition or commercial graph.</summary>
    [Fact]
    public async Task WebSetupTransitionIssue_DivergentReplayDigest_PrecedesCurrentReleaseDenial()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.985");
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));

        var prepared = await service.PrepareAsync("website-step1", Sha256("websetup-replay-conflict-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("websetup-replay-conflict-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, confirm,
            Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
                prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        const string targetVersion = "2.2.987";
        await using (var release = await factory.CreateDbContextAsync())
        {
            foreach (var binary in new[] { ("FP_CORE", '1'), ("FP_DLL", '2'), ("FP_EXE", '3') })
                release.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = fixture.ProductId,
                    Version = targetVersion,
                    Key = binary.Item1,
                    Hash = new string(binary.Item2, 64),
                    Source = ApprovedBinaryService.ReleaseSource
                });
            await release.SaveChangesAsync();
        }
        var issue = new RuntimeWebSetupTransitionIssueRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupTransitionIssueSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            SourceVersion = fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = "TiaConnect-2.2.987.msi",
            TargetInstallerSha256 = new string('4', 64)
        };
        var issued = await service.IssueWebSetupTransitionAsync("website-step1",
            Sha256(JsonSerializer.Serialize(issue)), issue);
        Assert.False(issued.Idempotent);

        await using (var revokeRelease = await factory.CreateDbContextAsync())
            Assert.Equal(1, await revokeRelease.ApprovedBinaries.Where(row => row.ProductId == fixture.ProductId
                && row.Version == fixture.Version && row.Key == "FP_EXE").ExecuteDeleteAsync());
        var before = await Tkt976_BusinessFingerprintAsync(connections.App);
        issue.TargetInstallerSha256 = new string('5', 64);
        var refusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.IssueWebSetupTransitionAsync("website-step1", Sha256(JsonSerializer.Serialize(issue)), issue));
        Assert.Equal(409, refusal.StatusCode);
        Assert.Equal("idempotency_conflict", refusal.ErrorCode);
        Assert.Equal(before, await Tkt976_BusinessFingerprintAsync(connections.App));
        await using var verify = await factory.CreateDbContextAsync();
        Assert.Equal("ISSUED", (await verify.RuntimeEnrollmentWebSetupTransitions.SingleAsync(row =>
            row.EnrollmentId == enrollmentId)).State);
        Assert.Equal(1, await verify.RuntimeEnrollmentWebSetupTransitionRequests.CountAsync(row =>
            row.ClientId == "website-step1" && row.RequestId == issue.RequestId && row.Operation == "issue"));
        Assert.Equal("ACTIVE", (await verify.EnrollmentLicenseAssignments.SingleAsync(row =>
            row.EnrollmentId == enrollmentId)).State);
    }

    [Fact]
    public async Task WebSetupTransition_EndToEnd_IsOneShotAtomic_ReplaysFrozenResponse_AndAllowsHistoricalCriticalRecovery()
    {
        // Global transition assertions require an owned database, not rows left by other fixtures.
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (Admin: isolated.Admin, App: isolated.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.985");
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));

        var prepared = await service.PrepareAsync("website-step1", Sha256("websetup-transition-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("websetup-transition-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, confirm,
            Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
                prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        var historicalEventId = Guid.NewGuid().ToString("D");
        await using (var criticalSeed = await factory.CreateDbContextAsync())
        {
            var seededEnrollment = await criticalSeed.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            criticalSeed.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident
            {
                EnrollmentId = enrollmentId,
                BindingId = fixture.BindingId,
                ProductId = fixture.ProductId,
                InstallationId = fixture.InstallationId,
                EventId = historicalEventId,
                Trigger = "RuntimeCheck_Debugger",
                State = "OPEN",
                OpenedSecurityEpoch = 1,
                OpenedAuthorityEpoch = seededEnrollment.AuthorityEpoch,
                OpenedAtUtc = DateTime.UtcNow
            });
            await criticalSeed.SaveChangesAsync();
        }

        const string targetVersion = "2.2.987";
        const string targetInstaller = "TiaConnect-2.2.987.msi";
        var targetInstallerSha256 = new string('4', 64);
        var targetHashes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FP_CORE"] = new string('1', 64),
            ["FP_DLL"] = new string('2', 64),
            ["FP_EXE"] = new string('3', 64)
        };
        await using (var seed = await factory.CreateDbContextAsync())
        {
            foreach (var binary in targetHashes)
                seed.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = fixture.ProductId,
                    Version = targetVersion,
                    Key = binary.Key,
                    Hash = binary.Value,
                    Source = ApprovedBinaryService.ReleaseSource
                });
            await seed.SaveChangesAsync();
        }

        var issue = new RuntimeWebSetupTransitionIssueRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupTransitionIssueSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            SourceVersion = fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = targetInstaller,
            TargetInstallerSha256 = targetInstallerSha256
        };
        var issueDigest = Sha256(JsonSerializer.Serialize(issue));
        var issued = await service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue);
        var issueReplay = await service.IssueWebSetupTransitionAsync("website-step1", issueDigest, issue);
        Assert.False(issued.Idempotent);
        Assert.True(issueReplay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, issueReplay.ExactResponseBody);
        Assert.Equal(43, issued.Response.Capability.Length);
        var issuedExpiry = DateTime.Parse(
            issued.Response.ExpiresAtUtc,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        Assert.InRange(issuedExpiry, DateTime.UtcNow.AddMinutes(29), DateTime.UtcNow.AddMinutes(31));

        var authorization = new RuntimeWebSetupUpgradeAuthorization
        {
            Schema = RuntimeEnrollmentService.WebSetupUpgradeAuthorizationSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            TransitionId = issued.Response.TransitionId,
            Capability = issued.Response.Capability,
            SourceVersion = fixture.Version,
            TargetVersion = targetVersion,
            Binaries = targetHashes.Select(binary => new RuntimeEnrollmentBinaryEvidenceRequest
            {
                Key = binary.Key,
                Sha256 = binary.Value
            }).ToList()
        };
        (RuntimeWebSetupUpgradeRelayRequest Relay, string RelayDigest, string AuthorizationDigest) RelayFor(
            RuntimeWebSetupUpgradeAuthorization exactAuthorization)
        {
            var exactBytes = JsonSerializer.SerializeToUtf8Bytes(
                exactAuthorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var exactDigest = Convert.ToHexStringLower(SHA256.HashData(exactBytes));
            var exactProof = Proof(enrollmentKey, "websetup-upgrade", enrollmentId,
                RuntimeEnrollmentService.WebSetupUpgradeAudience, "-", exactDigest);
            var exactRelay = new RuntimeWebSetupUpgradeRelayRequest
            {
                Schema = RuntimeEnrollmentService.WebSetupUpgradeSchema,
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                AuthorizationBodyBase64Url = Base64Url(exactBytes),
                ProofTimestamp = exactProof.Timestamp,
                ProofJti = exactProof.Jti,
                ProofSignature = exactProof.Signature
            };
            return (exactRelay, Sha256(JsonSerializer.Serialize(exactRelay)), exactDigest);
        }

        var substitutedCapability = new RuntimeWebSetupUpgradeAuthorization
        {
            Schema = authorization.Schema,
            ProtocolVersion = authorization.ProtocolVersion,
            ProductId = authorization.ProductId,
            EnrollmentId = authorization.EnrollmentId,
            TransitionId = authorization.TransitionId,
            Capability = Base64Url(RandomNumberGenerator.GetBytes(32)),
            SourceVersion = authorization.SourceVersion,
            TargetVersion = authorization.TargetVersion,
            Binaries = authorization.Binaries
        };
        var substituted = RelayFor(substitutedCapability);
        var substitutedFailure = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", substituted.RelayDigest, substituted.Relay));
        Assert.Equal("websetup_transition_invalid", substitutedFailure.ErrorCode);

        var substitutedTarget = new RuntimeWebSetupUpgradeAuthorization
        {
            Schema = authorization.Schema,
            ProtocolVersion = authorization.ProtocolVersion,
            ProductId = authorization.ProductId,
            EnrollmentId = authorization.EnrollmentId,
            TransitionId = authorization.TransitionId,
            Capability = authorization.Capability,
            SourceVersion = authorization.SourceVersion,
            TargetVersion = "2.2.988",
            Binaries = authorization.Binaries
        };
        var substitutedVersion = RelayFor(substitutedTarget);
        var versionFailure = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", substitutedVersion.RelayDigest, substitutedVersion.Relay));
        Assert.Equal("websetup_transition_invalid", versionFailure.ErrorCode);

        var valid = RelayFor(authorization);
        var unknownTransition = new RuntimeWebSetupUpgradeAuthorization
        {
            Schema = authorization.Schema,
            ProtocolVersion = authorization.ProtocolVersion,
            ProductId = authorization.ProductId,
            EnrollmentId = authorization.EnrollmentId,
            TransitionId = Guid.NewGuid().ToString("D"),
            Capability = authorization.Capability,
            SourceVersion = authorization.SourceVersion,
            TargetVersion = authorization.TargetVersion,
            Binaries = authorization.Binaries
        };
        var unknownTransitionRelay = RelayFor(unknownTransition);
        // A valid proof for another body must fail before lookup reveals whether this tuple exists.
        unknownTransitionRelay.Relay.ProofSignature = valid.Relay.ProofSignature;
        var unauthenticatedUnknown = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test",
                Sha256(JsonSerializer.Serialize(unknownTransitionRelay.Relay)), unknownTransitionRelay.Relay));
        Assert.Equal(401, unauthenticatedUnknown.StatusCode);
        Assert.Equal("authentication_failed", unauthenticatedUnknown.ErrorCode);
        await using (var expire = await factory.CreateDbContextAsync())
        {
            var expiringTransition = await expire.RuntimeEnrollmentWebSetupTransitions.SingleAsync();
            expiringTransition.IssuedAtUtc = DateTime.UtcNow.AddMinutes(-2);
            expiringTransition.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
            await expire.SaveChangesAsync();
        }
        var expiredFailure = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", valid.RelayDigest, valid.Relay));
        Assert.Equal("websetup_transition_expired", expiredFailure.ErrorCode);
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var expiringTransition = await restore.RuntimeEnrollmentWebSetupTransitions.SingleAsync();
            expiringTransition.IssuedAtUtc = DateTime.UtcNow;
            expiringTransition.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(1);
            await restore.SaveChangesAsync();
        }

        var relay = valid.Relay;
        var relayDigest = valid.RelayDigest;
        var authorizationDigest = valid.AuthorizationDigest;
        long historicalAuthorityEpoch;
        await using (var commercialBump = await factory.CreateDbContextAsync())
        {
            var sourceEnrollment = await commercialBump.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            historicalAuthorityEpoch = sourceEnrollment.AuthorityEpoch;
            var sourceBinding = await commercialBump.DistributionInstallationBindings.SingleAsync(row =>
                row.Id == fixture.BindingId);
            var sourceLicense = await commercialBump.Licenses.SingleAsync(row => row.Id == sourceBinding.LicenseId);
            sourceLicense.AllowedVersions = "*";
            await commercialBump.SaveChangesAsync();
            Assert.True((await commercialBump.RuntimeEnrollmentAuthorityStates.SingleAsync()).Epoch
                > historicalAuthorityEpoch);
            Assert.Equal(historicalAuthorityEpoch, (await commercialBump.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId)).AuthorityEpoch);
            Assert.Equal(1, (await commercialBump.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
        }
        var attempts = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", relayDigest, relay)));

        Assert.Single(attempts, result => !result.Idempotent);
        Assert.Equal(19, attempts.Count(result => result.Idempotent));
        Assert.All(attempts, result => Assert.Equal(attempts[0].ExactResponseBody, result.ExactResponseBody));
        var freshProofRetry = RelayFor(authorization);
        var recoveredAfterLostResponse = await service.UpgradeFromWebSetupAsync(
            "website-step1", "s2s-test", freshProofRetry.RelayDigest, freshProofRetry.Relay);
        Assert.True(recoveredAfterLostResponse.Idempotent);
        Assert.Equal(attempts[0].ExactResponseBody, recoveredAfterLostResponse.ExactResponseBody);
        var response = attempts[0].Response;
        Assert.Equal(RuntimeEnrollmentService.WebSetupUpgradeResponseSchema, response.Schema);
        Assert.Equal(issued.Response.TransitionId, response.TransitionId);
        Assert.Equal(1, response.OldSecurityEpoch);
        Assert.Equal(2, response.NewSecurityEpoch);
        Assert.True(capabilitySigning.VerifyData(
            Encoding.UTF8.GetBytes(RuntimeEnrollmentCryptoService.BuildWebSetupUpgradeSignaturePayload(response)),
            DecodeBase64Url(response.Signature),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        await using var check = await factory.CreateDbContextAsync();
        var binding = await check.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
        var enrollment = await check.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
        var transition = await check.RuntimeEnrollmentWebSetupTransitions.SingleAsync();
        Assert.Equal(targetVersion, binding.Version);
        Assert.Equal(targetInstallerSha256, binding.InstallerSha256);
        Assert.Equal(targetHashes["FP_EXE"], binding.ExecutableSha256);
        Assert.Equal(targetVersion, enrollment.ReleaseVersion);
        Assert.Equal(2, enrollment.SecurityEpoch);
        Assert.Equal(historicalAuthorityEpoch, enrollment.AuthorityEpoch);
        Assert.Equal("CONSUMED", transition.State);
        Assert.Equal(authorizationDigest, transition.ConsumedPayloadDigestSha256);
        Assert.Single(await check.RuntimeEnrollmentRequests.Where(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade").ToListAsync());
        Assert.Equal(2, await check.RuntimeEnrollmentProofNonces.CountAsync(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade"));
        Assert.All(await check.RuntimeEnrollmentProofNonces.Where(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade").ToListAsync(), nonce =>
            Assert.True(nonce.AuthorityEpoch > historicalAuthorityEpoch));

        var license = await check.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
        license.RevokedAt = DateTime.UtcNow;
        await check.SaveChangesAsync();
        var revokedReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", relayDigest, relay));
        Assert.Equal("authority_ineligible", revokedReplay.ErrorCode);
        await using (var deniedReplay = await factory.CreateDbContextAsync())
        {
            var unchangedEnrollment = await deniedReplay.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId);
            Assert.Equal("ACTIVE", unchangedEnrollment.State);
            Assert.Equal(2, unchangedEnrollment.SecurityEpoch);
            Assert.Equal(historicalAuthorityEpoch, unchangedEnrollment.AuthorityEpoch);
            Assert.Equal(2, await deniedReplay.RuntimeEnrollmentProofNonces.CountAsync(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade"));
            Assert.Equal("CONSUMED", (await deniedReplay.RuntimeEnrollmentWebSetupTransitions.AsNoTracking()
                .SingleAsync(row => row.Id == Guid.Parse(issued.Response.TransitionId))).State);
        }

        license.RevokedAt = null;
        await check.SaveChangesAsync();

        var currentEventId = Guid.NewGuid().ToString("D");
        var futureEventId = Guid.NewGuid().ToString("D");
        await using (var incidentSeed = await factory.CreateDbContextAsync())
        {
            var currentEnrollment = await incidentSeed.RuntimeEnrollments
                .SingleAsync(row => row.Id == enrollmentId);
            incidentSeed.RuntimeCriticalIncidents.AddRange(
                new RuntimeCriticalIncident
                {
                    EnrollmentId = enrollmentId,
                    BindingId = fixture.BindingId,
                    ProductId = fixture.ProductId,
                    InstallationId = fixture.InstallationId,
                    EventId = currentEventId,
                    Trigger = "RuntimeCheck_NativeDllSwapped",
                    State = "OPEN",
                    OpenedSecurityEpoch = 2,
                    OpenedAuthorityEpoch = currentEnrollment.AuthorityEpoch,
                    OpenedAtUtc = DateTime.UtcNow
                },
                new RuntimeCriticalIncident
                {
                    EnrollmentId = enrollmentId,
                    BindingId = fixture.BindingId,
                    ProductId = fixture.ProductId,
                    InstallationId = fixture.InstallationId,
                    EventId = futureEventId,
                    Trigger = "RuntimeCheck_FutureGenerationRegression",
                    State = "OPEN",
                    OpenedSecurityEpoch = 3,
                    OpenedAuthorityEpoch = currentEnrollment.AuthorityEpoch,
                    OpenedAtUtc = DateTime.UtcNow
                });
            await incidentSeed.SaveChangesAsync();
        }

        var recoveryRequest = new RuntimeCriticalRecoveryRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoverySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            InstallationId = fixture.InstallationId,
            EventId = historicalEventId,
            OldSecurityEpoch = 2,
            NewSecurityEpoch = 3
        };
        var recoveryDigest = Sha256(JsonSerializer.Serialize(recoveryRequest));
        var futureConflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RecoverCriticalAsync(
                "security-operator", "operator-key", recoveryDigest, recoveryRequest));
        Assert.Equal("recovery_generation_conflict", futureConflict.ErrorCode);
        await using (var unchanged = await factory.CreateDbContextAsync())
        {
            Assert.Equal(2, (await unchanged.RuntimeEnrollments
                .SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
            Assert.Equal(3, await unchanged.RuntimeCriticalIncidents.CountAsync(row =>
                row.BindingId == fixture.BindingId && row.InstallationId == fixture.InstallationId
                && row.State == "OPEN"));
            Assert.Empty(await unchanged.RuntimeCriticalRecoveries.ToListAsync());
        }

        await using (var admin = new NpgsqlConnection(connections.Admin))
        {
            await admin.OpenAsync();
            await using var deleteFuture = admin.CreateCommand();
            deleteFuture.CommandText = """
                DELETE FROM public."RuntimeCriticalIncidents"
                WHERE "EnrollmentId" = @enrollmentId AND "EventId" = @eventId;
                """;
            deleteFuture.Parameters.AddWithValue("enrollmentId", enrollmentId);
            deleteFuture.Parameters.AddWithValue("eventId", futureEventId);
            Assert.Equal(1, await deleteFuture.ExecuteNonQueryAsync());
        }

        var recovered = await service.RecoverCriticalAsync(
            "security-operator", "operator-key", recoveryDigest, recoveryRequest);
        Assert.False(recovered.Idempotent);
        Assert.Equal(2, recovered.Response.OldSecurityEpoch);
        Assert.Equal(3, recovered.Response.NewSecurityEpoch);
        Assert.Equal(historicalEventId, recovered.Response.EventId);
        var recoveryReplay = await service.RecoverCriticalAsync(
            "security-operator", "operator-key", recoveryDigest, recoveryRequest);
        Assert.True(recoveryReplay.Idempotent);
        Assert.Equal(recovered.ExactResponseBody, recoveryReplay.ExactResponseBody);
        await using (var recoveredState = await factory.CreateDbContextAsync())
        {
            Assert.Equal(3, (await recoveredState.RuntimeEnrollments
                .SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
            Assert.Equal(2, await recoveredState.RuntimeCriticalIncidents.CountAsync(row =>
                row.BindingId == fixture.BindingId && row.InstallationId == fixture.InstallationId
                && row.State == "RESOLVED"));
            Assert.False(await recoveredState.RuntimeCriticalIncidents.AnyAsync(row =>
                row.BindingId == fixture.BindingId && row.InstallationId == fixture.InstallationId
                && row.State == "OPEN"));
            var recovery = await recoveredState.RuntimeCriticalRecoveries.SingleAsync();
            Assert.Equal(2, recovery.ResolvedIncidentCount);
            Assert.All(await recoveredState.RuntimeCriticalIncidents.Where(row =>
                row.BindingId == fixture.BindingId && row.InstallationId == fixture.InstallationId).ToListAsync(),
                incident =>
                {
                    Assert.Equal(recovery.Id, incident.RecoveryId);
                    Assert.Equal(3, incident.RecoveredSecurityEpoch);
                });
        }

        const string laterVersion = "2.2.988";
        var laterHashes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FP_CORE"] = new string('5', 64),
            ["FP_DLL"] = new string('6', 64),
            ["FP_EXE"] = new string('7', 64)
        };
        await using (var laterRelease = await factory.CreateDbContextAsync())
        {
            foreach (var binary in laterHashes)
                laterRelease.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = fixture.ProductId,
                    Version = laterVersion,
                    Key = binary.Key,
                    Hash = binary.Value,
                    Source = ApprovedBinaryService.ReleaseSource
                });
            await laterRelease.SaveChangesAsync();
        }
        var laterIssue = new RuntimeWebSetupTransitionIssueRequest
        {
            Schema = RuntimeEnrollmentService.WebSetupTransitionIssueSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            SourceVersion = targetVersion,
            TargetVersion = laterVersion,
            TargetInstallerFilename = "TiaConnect-2.2.988.msi",
            TargetInstallerSha256 = new string('8', 64)
        };
        var laterIssued = await service.IssueWebSetupTransitionAsync("website-step1",
            Sha256(JsonSerializer.Serialize(laterIssue)), laterIssue);
        var laterAuthorization = new RuntimeWebSetupUpgradeAuthorization
        {
            Schema = RuntimeEnrollmentService.WebSetupUpgradeAuthorizationSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            TransitionId = laterIssued.Response.TransitionId,
            Capability = laterIssued.Response.Capability,
            SourceVersion = targetVersion,
            TargetVersion = laterVersion,
            Binaries = laterHashes.Select(binary => new RuntimeEnrollmentBinaryEvidenceRequest
            {
                Key = binary.Key,
                Sha256 = binary.Value
            }).ToList()
        };
        var laterRelay = RelayFor(laterAuthorization);
        var laterConsumed = await service.UpgradeFromWebSetupAsync(
            "website-step1", "s2s-test", laterRelay.RelayDigest, laterRelay.Relay);
        Assert.False(laterConsumed.Idempotent);
        Assert.Equal(3, laterConsumed.Response.OldSecurityEpoch);
        Assert.Equal(4, laterConsumed.Response.NewSecurityEpoch);
        var oldReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", relayDigest, relay));
        Assert.Equal(409, oldReplay.StatusCode);
        Assert.Equal("websetup_transition_replay_rejected", oldReplay.ErrorCode);
        await using var laterState = await factory.CreateDbContextAsync();
        Assert.Equal(4, (await laterState.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
        Assert.Equal(historicalAuthorityEpoch,
            (await laterState.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).AuthorityEpoch);
        var proofCountBeforeMissing = await laterState.RuntimeEnrollmentProofNonces.CountAsync(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade");
        var currentSeatId = (await laterState.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == enrollmentId && row.State == "ACTIVE")).LicenseSeatId;
        await using (var admin = new NpgsqlConnection(connections.Admin))
        {
            await admin.OpenAsync();
            await using (var dropSeatForeignKey = admin.CreateCommand())
            {
                dropSeatForeignKey.CommandText = """
                    DO $broken_relation$
                    DECLARE constraint_name name;
                    BEGIN
                        SELECT conname INTO constraint_name FROM pg_catalog.pg_constraint
                        WHERE conrelid = 'public."EnrollmentLicenseAssignments"'::pg_catalog.regclass
                          AND confrelid = 'public."LicenseSeats"'::pg_catalog.regclass;
                        IF constraint_name IS NOT NULL THEN
                            EXECUTE pg_catalog.format(
                                'ALTER TABLE public."EnrollmentLicenseAssignments" DROP CONSTRAINT %I',
                                constraint_name);
                        END IF;
                    END;
                    $broken_relation$;
                    """;
                await dropSeatForeignKey.ExecuteNonQueryAsync();
            }
            await using (var breakRelation = admin.CreateCommand())
            {
                breakRelation.CommandText = "UPDATE public.\"EnrollmentLicenseAssignments\" SET \"LicenseSeatId\" = @missing WHERE \"EnrollmentId\" = @enrollmentId AND \"State\" = 'ACTIVE'";
                breakRelation.Parameters.AddWithValue("missing", Guid.NewGuid());
                breakRelation.Parameters.AddWithValue("enrollmentId", enrollmentId);
                Assert.Equal(1, await breakRelation.ExecuteNonQueryAsync());
            }
            var missingRelationReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                service.UpgradeFromWebSetupAsync(
                    "website-step1", "s2s-test", laterRelay.RelayDigest, laterRelay.Relay));
            Assert.Equal(503, missingRelationReplay.StatusCode);
            Assert.Equal("assignment_relation_missing", missingRelationReplay.DiagnosticCode);
            await using (var repairRelation = admin.CreateCommand())
            {
                repairRelation.CommandText = "UPDATE public.\"EnrollmentLicenseAssignments\" SET \"LicenseSeatId\" = @seat WHERE \"EnrollmentId\" = @enrollmentId AND \"State\" = 'ACTIVE'";
                repairRelation.Parameters.AddWithValue("seat", currentSeatId);
                repairRelation.Parameters.AddWithValue("enrollmentId", enrollmentId);
                Assert.Equal(1, await repairRelation.ExecuteNonQueryAsync());
            }
            await using (var allowSyntheticDuplicate = admin.CreateCommand())
            {
                // This isolated database deliberately removes the production uniqueness guards
                // so the validator's unavailable branch is exercised without weakening migration DDL.
                allowSyntheticDuplicate.CommandText = """
                    DROP INDEX public."IX_EnrollmentLicenseAssignments_EnrollmentId";
                    DROP INDEX public."IX_EnrollmentLicenseAssignments_LicenseSeatId";
                    INSERT INTO public."EnrollmentLicenseAssignments"
                        ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                         "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
                    SELECT pg_catalog.gen_random_uuid(), "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                           "ActivatedAtUtc", "EndedAtUtc", "Revision" + 1, "EndReason"
                    FROM public."EnrollmentLicenseAssignments"
                    WHERE "EnrollmentId" = @enrollmentId AND "State" = 'ACTIVE';
                    """;
                allowSyntheticDuplicate.Parameters.AddWithValue("enrollmentId", enrollmentId);
                await allowSyntheticDuplicate.ExecuteNonQueryAsync();
            }
            var duplicateAssignmentReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                service.UpgradeFromWebSetupAsync(
                    "website-step1", "s2s-test", laterRelay.RelayDigest, laterRelay.Relay));
            Assert.Equal(503, duplicateAssignmentReplay.StatusCode);
            Assert.Equal("assignment_duplicate_active", duplicateAssignmentReplay.DiagnosticCode);
            await using var removeAssignment = admin.CreateCommand();
            removeAssignment.CommandText = "DELETE FROM public.\"EnrollmentLicenseAssignments\" WHERE \"EnrollmentId\" = @enrollmentId AND \"State\" = 'ACTIVE'";
            removeAssignment.Parameters.AddWithValue("enrollmentId", enrollmentId);
            Assert.Equal(2, await removeAssignment.ExecuteNonQueryAsync());
        }
        var missingAssignmentReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync(
                "website-step1", "s2s-test", laterRelay.RelayDigest, laterRelay.Relay));
        Assert.Equal(422, missingAssignmentReplay.StatusCode);
        Assert.Equal("authority_ineligible", missingAssignmentReplay.ErrorCode);
        Assert.Equal("assignment_missing", missingAssignmentReplay.DiagnosticCode);
        await using var missingState = await factory.CreateDbContextAsync();
        Assert.Equal(proofCountBeforeMissing, await missingState.RuntimeEnrollmentProofNonces.CountAsync(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade"));
        Assert.Equal("ACTIVE", (await missingState.RuntimeEnrollments.SingleAsync(row =>
            row.Id == enrollmentId)).State);
        Assert.Equal(4, (await missingState.RuntimeEnrollments.SingleAsync(row =>
            row.Id == enrollmentId)).SecurityEpoch);
    }

    /// <summary>
    /// Exercises the exact upgrade/rollback lifecycle both normally and with a second
    /// PostgreSQL connection holding the decisive global lease past licence expiry.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UpgradeAndRollback_EndToEnd_RebindAtomicallyAndReplayFrozenResponses(
        bool includePostWaitExpiryRace)
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.2.916");
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));

        var prepared = await service.PrepareAsync("website-step1", Sha256("upgrade-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("upgrade-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, confirm,
            Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
                prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        const string targetVersion = "2.2.923";
        var targetHashes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FP_CORE"] = new string('1', 64),
            ["FP_DLL"] = new string('2', 64),
            ["FP_EXE"] = new string('3', 64)
        };
        await using (var seed = await factory.CreateDbContextAsync())
        {
            foreach (var binary in targetHashes)
                seed.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = fixture.ProductId,
                    Version = targetVersion,
                    Key = binary.Key,
                    Hash = binary.Value,
                    Source = ApprovedBinaryService.ReleaseSource
                });
            await seed.SaveChangesAsync();
        }

        string hardwareIdHash;
        string sourceInstallerFilename;
        string sourceInstallerSha256;
        Dictionary<string, string> sourceHashes;
        await using (var bindingRead = await factory.CreateDbContextAsync())
        {
            var sourceBinding = await bindingRead.DistributionInstallationBindings
                .Where(row => row.Id == fixture.BindingId)
                .Select(row => new
                {
                    row.HardwareIdHash,
                    row.InstallerFilename,
                    row.InstallerSha256,
                    row.ExecutableSha256,
                    row.NativeDllSha256,
                    row.CoreSha256
                })
                .SingleAsync();
            hardwareIdHash = sourceBinding.HardwareIdHash;
            sourceInstallerFilename = sourceBinding.InstallerFilename;
            sourceInstallerSha256 = sourceBinding.InstallerSha256;
            sourceHashes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["FP_CORE"] = sourceBinding.CoreSha256,
                ["FP_DLL"] = sourceBinding.NativeDllSha256,
                ["FP_EXE"] = sourceBinding.ExecutableSha256
            };
        }
        var receiptId = Guid.NewGuid().ToString("D");
        var historicalRecoveryHardwareIdHash = new string('9', 64);
        Assert.NotEqual(hardwareIdHash, historicalRecoveryHardwareIdHash);
        var authorization = new RuntimeEnrollmentUpgradeAuthorization
        {
            Schema = RuntimeEnrollmentService.UpgradeAuthorizationSchema,
            RequestId = receiptId,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            InstallationId = fixture.InstallationId,
            Epoch = 1,
            SecurityEpoch = 1,
            SourceVersion = fixture.Version,
            TargetVersion = targetVersion,
            TargetInstallerFilename = "TiaConnect-2.2.923.msi",
            TargetInstallerSha256 = new string('4', 64),
            RecoveryReceiptId = receiptId,
            RecoveryReceiptDigestSha256 = new string('5', 64),
            RecoveryHardwareIdHash = historicalRecoveryHardwareIdHash,
            Binaries = targetHashes.Select(binary => new RuntimeEnrollmentBinaryEvidenceRequest
            {
                Key = binary.Key,
                Sha256 = binary.Value
            }).ToList()
        };
        var authorizationBytes = JsonSerializer.SerializeToUtf8Bytes(
            authorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var authorizationDigest = Convert.ToHexStringLower(SHA256.HashData(authorizationBytes));
        var proof = Proof(enrollmentKey, "upgrade", enrollmentId,
            RuntimeEnrollmentService.UpgradeAudience, "-", authorizationDigest);
        var relay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = RuntimeEnrollmentService.UpgradeRelaySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            AuthorizationBodyBase64Url = Base64Url(authorizationBytes),
            ProofTimestamp = proof.Timestamp,
            ProofJti = proof.Jti,
            ProofSignature = proof.Signature
        };
        var relayDigest = Sha256(JsonSerializer.Serialize(relay));
        var invalidProofRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = relay.Schema,
            ProtocolVersion = relay.ProtocolVersion,
            AuthorizationBodyBase64Url = relay.AuthorizationBodyBase64Url,
            ProofTimestamp = relay.ProofTimestamp,
            ProofJti = relay.ProofJti,
            ProofSignature = "AA"
        };
        var unauthenticatedUnknownReceipt = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeAsync("website-step1", "s2s-test",
                Sha256(JsonSerializer.Serialize(invalidProofRelay)), invalidProofRelay));
        Assert.Equal(401, unauthenticatedUnknownReceipt.StatusCode);
        await using (var proofCheck = await factory.CreateDbContextAsync())
        {
            Assert.Empty(await proofCheck.RuntimeEnrollmentRequests.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
            Assert.Empty(await proofCheck.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
        }

        // Re-seal one signed, expired operation response in this isolated database to exercise
        // fresh-JTI expiry without waiting ten real minutes or altering the production clock.
        async Task AssertExpiredFreshReplayAsync(
            string operationName,
            RuntimeEnrollmentUpgradeResponse signedResponse,
            RuntimeEnrollmentUpgradeRelayRequest freshRelay,
            string expectedCode)
        {
            await using var alter = await factory.CreateDbContextAsync();
            var stored = await alter.RuntimeEnrollmentRequests.SingleAsync(row =>
                row.EnrollmentId == enrollmentId && row.Operation == operationName);
            var originalCiphertext = stored.ResponseCiphertext;
            var originalKeyId = stored.ResponseKeyId;
            var expiredResponse = signedResponse with
            {
                IssuedAtUtc = DateTime.UtcNow.AddMinutes(-2).ToString(
                    "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture),
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1).ToString(
                    "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture),
                Signature = string.Empty
            };
            expiredResponse = expiredResponse with { Signature = crypto.SignUpgrade(expiredResponse) };
            var expiredBytes = JsonSerializer.SerializeToUtf8Bytes(
                expiredResponse, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var reference = $"RuntimeEnrollmentRequests:{stored.Id:D}:{enrollmentId:D}:{operationName}:website-step1:{stored.RequestId}";
            await using (var transaction = await alter.Database.BeginTransactionAsync())
            {
                var envelope = await crypto.SealAsync(alter, operationName + "-response", stored.Id,
                    1, expiredBytes, reference);
                stored.ResponseCiphertext = envelope.Ciphertext;
                stored.ResponseKeyId = envelope.KeyId;
                await alter.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            try
            {
                var failure = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                    operationName == "upgrade"
                        ? service.UpgradeAsync("website-step1", "s2s-test",
                            Sha256(JsonSerializer.Serialize(freshRelay)), freshRelay)
                        : service.RollbackAsync("website-step1", "s2s-test",
                            Sha256(JsonSerializer.Serialize(freshRelay)), freshRelay));
                Assert.Equal(410, failure.StatusCode);
                Assert.Equal(expectedCode, failure.ErrorCode);
            }
            finally
            {
                stored.ResponseCiphertext = originalCiphertext;
                stored.ResponseKeyId = originalKeyId;
                await alter.SaveChangesAsync();
            }
        }

        long historicalAuthorityEpoch;
        await using (var commercialBump = await factory.CreateDbContextAsync())
        {
            var enrolled = await commercialBump.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            historicalAuthorityEpoch = enrolled.AuthorityEpoch;
            var sourceLicenseId = (await commercialBump.DistributionInstallationBindings.SingleAsync(row =>
                row.Id == fixture.BindingId)).LicenseId;
            var sourceLicense = await commercialBump.Licenses.SingleAsync(row => row.Id == sourceLicenseId);
            sourceLicense.AllowedVersions = "*";
            await commercialBump.SaveChangesAsync();
            Assert.True((await commercialBump.RuntimeEnrollmentAuthorityStates.SingleAsync()).Epoch
                > historicalAuthorityEpoch);
            Assert.Equal(historicalAuthorityEpoch, (await commercialBump.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId)).AuthorityEpoch);
        }
        await using (var denyNew = await factory.CreateDbContextAsync())
        {
            // Version policy comes from the current commercial assignment, not the
            // copied licence fields on the binding or historical receipt.
            var sourceLicenseId = (await denyNew.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == enrollmentId && row.State == "ACTIVE")).LicenseId;
            (await denyNew.Licenses.SingleAsync(row => row.Id == sourceLicenseId)).AllowedVersions = "9.*";
            await denyNew.SaveChangesAsync();
            var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay));
            Assert.Equal(422, denied.StatusCode);
            Assert.Equal("authority_ineligible", denied.ErrorCode);
            Assert.Equal("version_ineligible", denied.DiagnosticCode);
            var unchangedEnrollment = await denyNew.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId);
            Assert.Equal("ACTIVE", unchangedEnrollment.State);
            Assert.Equal(1, unchangedEnrollment.SecurityEpoch);
            Assert.Equal(historicalAuthorityEpoch, unchangedEnrollment.AuthorityEpoch);
            Assert.Empty(await denyNew.RuntimeEnrollmentRequests.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
            Assert.Empty(await denyNew.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
            (await denyNew.Licenses.SingleAsync(row => row.Id == sourceLicenseId)).AllowedVersions = "*";
            await denyNew.SaveChangesAsync();
        }

        // The second connection holds the exact global mutation lease while the source
        // licence expires. Release must use database time after that decisive wait and
        // refuse without persisting a request, proof nonce, or crypto state change.
        if (includePostWaitExpiryRace)
        {
            await using (var writer = new NpgsqlConnection(connections.App))
            {
                await writer.OpenAsync();
                Guid sourceLicenseId;
                await using (var source = await factory.CreateDbContextAsync())
                    sourceLicenseId = (await source.DistributionInstallationBindings.AsNoTracking()
                        .SingleAsync(row => row.Id == fixture.BindingId)).LicenseId;
                await using (var expire = writer.CreateCommand())
                {
                    expire.CommandText = """
                        UPDATE public."Licenses"
                        SET "ExpirationDate" = pg_catalog.clock_timestamp() + interval '1500 milliseconds'
                        WHERE "Id" = @licenseId;
                        """;
                    expire.Parameters.AddWithValue("licenseId", sourceLicenseId);
                    Assert.Equal(1, await expire.ExecuteNonQueryAsync());
                }
                await using var writerTransaction = await writer.BeginTransactionAsync();
                Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>>? waitingUpgrade = null;
                var writerCommitted = false;
                try
                {
                    await using (var hold = writer.CreateCommand())
                    {
                        hold.Transaction = writerTransaction;
                        hold.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
                        await hold.ExecuteNonQueryAsync();
                    }
                    waitingUpgrade = service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay);
                    await using var observer = new NpgsqlConnection(connections.Admin);
                    await observer.OpenAsync();
                    var blocked = false;
                    for (var poll = 0; poll < 100; poll++)
                    {
                        await using var query = observer.CreateCommand();
                        query.CommandText = """
                            SELECT count(*) FROM pg_catalog.pg_stat_activity
                            WHERE @writerPid = ANY(pg_catalog.pg_blocking_pids(pid));
                            """;
                        query.Parameters.AddWithValue("writerPid", writer.ProcessID);
                        if ((long)(await query.ExecuteScalarAsync())! > 0)
                        {
                            blocked = true;
                            break;
                        }
                        await Task.Delay(20);
                    }
                    Assert.True(blocked);
                    Assert.False(waitingUpgrade.IsCompleted);
                    var expired = false;
                    for (var poll = 0; poll < 150; poll++)
                    {
                        await using var query = observer.CreateCommand();
                        query.CommandText = """
                            SELECT "ExpirationDate" <= pg_catalog.clock_timestamp()
                            FROM public."Licenses" WHERE "Id" = @licenseId;
                            """;
                        query.Parameters.AddWithValue("licenseId", sourceLicenseId);
                        if ((bool)(await query.ExecuteScalarAsync())!)
                        {
                            expired = true;
                            break;
                        }
                        await Task.Delay(20);
                    }
                    Assert.True(expired);
                    Assert.False(waitingUpgrade.IsCompleted);
                    await writerTransaction.CommitAsync();
                    writerCommitted = true;
                    var expiredRefusal = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => waitingUpgrade);
                    Assert.Equal(422, expiredRefusal.StatusCode);
                    Assert.Equal("authority_ineligible", expiredRefusal.ErrorCode);
                    Assert.Equal("commercial_authority_ineligible", expiredRefusal.DiagnosticCode);
                    await using var check = await factory.CreateDbContextAsync();
                    var unchangedEnrollment = await check.RuntimeEnrollments.AsNoTracking()
                        .SingleAsync(row => row.Id == enrollmentId);
                    Assert.Equal("ACTIVE", unchangedEnrollment.State);
                    Assert.Equal(1, unchangedEnrollment.SecurityEpoch);
                    Assert.Equal(historicalAuthorityEpoch, unchangedEnrollment.AuthorityEpoch);
                    Assert.Empty(await check.RuntimeEnrollmentRequests.Where(row =>
                        row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
                    Assert.Empty(await check.RuntimeEnrollmentProofNonces.Where(row =>
                        row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
                }
                finally
                {
                    if (!writerCommitted)
                        await writerTransaction.RollbackAsync();
                    if (waitingUpgrade is not null)
                        try { await waitingUpgrade; } catch (RuntimeEnrollmentException) { }
                }
            }
            await using (var restoreExpiry = await factory.CreateDbContextAsync())
            {
                var sourceLicenseId = (await restoreExpiry.DistributionInstallationBindings.AsNoTracking()
                    .SingleAsync(row => row.Id == fixture.BindingId)).LicenseId;
                var sourceLicense = await restoreExpiry.Licenses.SingleAsync(row => row.Id == sourceLicenseId);
                sourceLicense.ExpirationDate = DateTime.UtcNow.AddDays(1);
                await restoreExpiry.SaveChangesAsync();
            }
        }

        var upgraded = await service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay);
        var replayed = await service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay);
        var freshUpgradeProof = Proof(enrollmentKey, "upgrade", enrollmentId,
            RuntimeEnrollmentService.UpgradeAudience, "-", authorizationDigest);
        var freshUpgradeRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = relay.Schema,
            ProtocolVersion = relay.ProtocolVersion,
            AuthorizationBodyBase64Url = relay.AuthorizationBodyBase64Url,
            ProofTimestamp = freshUpgradeProof.Timestamp,
            ProofJti = freshUpgradeProof.Jti,
            ProofSignature = freshUpgradeProof.Signature
        };
        await AssertExpiredFreshReplayAsync(
            "upgrade", upgraded.Response, freshUpgradeRelay, "upgrade_replay_expired");
        var freshUpgradeReplay = await service.UpgradeAsync("website-step1", "s2s-test",
            Sha256(JsonSerializer.Serialize(freshUpgradeRelay)), freshUpgradeRelay);

        Assert.False(upgraded.Idempotent);
        Assert.True(replayed.Idempotent);
        Assert.Equal(upgraded.ExactResponseBody, replayed.ExactResponseBody);
        Assert.True(freshUpgradeReplay.Idempotent);
        Assert.Equal(upgraded.ExactResponseBody, freshUpgradeReplay.ExactResponseBody);
        Guid assignedLicenseId;
        await using (var denyPolicy = await factory.CreateDbContextAsync())
        {
            assignedLicenseId = (await denyPolicy.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == enrollmentId && row.State == "ACTIVE")).LicenseId;
            (await denyPolicy.Licenses.SingleAsync(row => row.Id == assignedLicenseId)).AllowedVersions = "9.*";
            await denyPolicy.SaveChangesAsync();
        }
        var deniedUpgradeReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay));
        Assert.Equal(422, deniedUpgradeReplay.StatusCode);
        Assert.Equal("authority_ineligible", deniedUpgradeReplay.ErrorCode);
        Assert.Equal("version_ineligible", deniedUpgradeReplay.DiagnosticCode);
        var originalUpgradeFilename = authorization.TargetInstallerFilename;
        authorization.TargetInstallerFilename = "TiaConnect-2.2.923-divergent.msi";
        var divergentUpgradeBytes = JsonSerializer.SerializeToUtf8Bytes(
            authorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        authorization.TargetInstallerFilename = originalUpgradeFilename;
        var divergentUpgradeProof = Proof(enrollmentKey, "upgrade", enrollmentId,
            RuntimeEnrollmentService.UpgradeAudience, "-",
            Convert.ToHexStringLower(SHA256.HashData(divergentUpgradeBytes)));
        var divergentUpgradeRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = relay.Schema,
            ProtocolVersion = relay.ProtocolVersion,
            AuthorizationBodyBase64Url = Base64Url(divergentUpgradeBytes),
            ProofTimestamp = divergentUpgradeProof.Timestamp,
            ProofJti = divergentUpgradeProof.Jti,
            ProofSignature = divergentUpgradeProof.Signature
        };
        var divergentUpgrade = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeAsync("website-step1", "s2s-test",
                Sha256(JsonSerializer.Serialize(divergentUpgradeRelay)), divergentUpgradeRelay));
        Assert.Equal(409, divergentUpgrade.StatusCode);
        Assert.Equal("upgrade_receipt_reused", divergentUpgrade.ErrorCode);
        await using (var deniedState = await factory.CreateDbContextAsync())
        {
            var unchangedEnrollment = await deniedState.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId);
            Assert.Equal("ACTIVE", unchangedEnrollment.State);
            Assert.Equal(targetVersion, unchangedEnrollment.ReleaseVersion);
            Assert.Equal(2, unchangedEnrollment.SecurityEpoch);
            Assert.Equal(historicalAuthorityEpoch, unchangedEnrollment.AuthorityEpoch);
            Assert.Equal(2, await deniedState.RuntimeEnrollmentProofNonces.CountAsync(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade"));
            (await deniedState.Licenses.SingleAsync(row => row.Id == assignedLicenseId)).AllowedVersions = "*";
            await deniedState.SaveChangesAsync();
        }
        Assert.Equal(1, upgraded.Response.OldSecurityEpoch);
        Assert.Equal(2, upgraded.Response.NewSecurityEpoch);
        Assert.True(capabilitySigning.VerifyData(
            Encoding.UTF8.GetBytes(RuntimeEnrollmentCryptoService.BuildUpgradeSignaturePayload(upgraded.Response)),
            DecodeBase64Url(upgraded.Response.Signature),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        await using (var check = await factory.CreateDbContextAsync())
        {
            var binding = await check.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            var enrollment = await check.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            Assert.Equal(targetVersion, binding.Version);
            Assert.Equal(new string('4', 64), binding.InstallerSha256);
            Assert.Equal(targetHashes["FP_EXE"], binding.ExecutableSha256);
            Assert.Equal(targetVersion, enrollment.ReleaseVersion);
            Assert.Equal(2, enrollment.SecurityEpoch);
            Assert.Equal(historicalAuthorityEpoch, enrollment.AuthorityEpoch);
            Assert.Single(await check.RuntimeEnrollmentRequests.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
            Assert.Equal(2, await check.RuntimeEnrollmentProofNonces.CountAsync(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade"));
            Assert.All(await check.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync(), nonce =>
                Assert.True(nonce.AuthorityEpoch > historicalAuthorityEpoch));
        }

        authorization.RequestId = authorization.RecoveryReceiptId = Guid.NewGuid().ToString("D");
        authorization.SourceVersion = targetVersion;
        authorization.TargetVersion = "2.2.924";
        authorization.SecurityEpoch = 2;
        authorizationBytes = JsonSerializer.SerializeToUtf8Bytes(
            authorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        authorizationDigest = Convert.ToHexStringLower(SHA256.HashData(authorizationBytes));
        proof = Proof(enrollmentKey, "upgrade", enrollmentId,
            RuntimeEnrollmentService.UpgradeAudience, "-", authorizationDigest);
        relay.AuthorizationBodyBase64Url = Base64Url(authorizationBytes);
        relay.ProofTimestamp = proof.Timestamp;
        relay.ProofJti = proof.Jti;
        relay.ProofSignature = proof.Signature;
        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.UpgradeAsync(
            "website-step1", "s2s-test", Sha256(JsonSerializer.Serialize(relay)), relay));
        Assert.Equal("release_unapproved", rejected.ErrorCode);

        await using var unchanged = await factory.CreateDbContextAsync();
        Assert.Equal(targetVersion, (await unchanged.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).ReleaseVersion);
        Assert.Equal(2, (await unchanged.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);

        var rollbackReceiptId = Guid.NewGuid().ToString("D");
        var rollbackAuthorization = new RuntimeEnrollmentUpgradeAuthorization
        {
            Schema = RuntimeEnrollmentService.RollbackAuthorizationSchema,
            RequestId = rollbackReceiptId,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            InstallationId = fixture.InstallationId,
            Epoch = 1,
            SecurityEpoch = 2,
            SourceVersion = targetVersion,
            TargetVersion = fixture.Version,
            TargetInstallerFilename = sourceInstallerFilename,
            TargetInstallerSha256 = sourceInstallerSha256,
            RecoveryReceiptId = rollbackReceiptId,
            RecoveryReceiptDigestSha256 = new string('6', 64),
            RecoveryHardwareIdHash = historicalRecoveryHardwareIdHash,
            Binaries = sourceHashes.Select(binary => new RuntimeEnrollmentBinaryEvidenceRequest
            {
                Key = binary.Key,
                Sha256 = binary.Value
            }).ToList()
        };
        rollbackAuthorization.TargetVersion = "2.2.924";
        var invalidRollbackAuthorizationBytes = JsonSerializer.SerializeToUtf8Bytes(
            rollbackAuthorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var invalidRollbackAuthorizationDigest = Convert.ToHexStringLower(
            SHA256.HashData(invalidRollbackAuthorizationBytes));
        var invalidRollbackProof = Proof(enrollmentKey, "rollback", enrollmentId,
            RuntimeEnrollmentService.RollbackAudience, "-", invalidRollbackAuthorizationDigest);
        var invalidRollbackRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = RuntimeEnrollmentService.RollbackRelaySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            AuthorizationBodyBase64Url = Base64Url(invalidRollbackAuthorizationBytes),
            ProofTimestamp = invalidRollbackProof.Timestamp,
            ProofJti = invalidRollbackProof.Jti,
            ProofSignature = invalidRollbackProof.Signature
        };
        var invalidRollback = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.RollbackAsync(
            "website-step1", "s2s-test", Sha256(JsonSerializer.Serialize(invalidRollbackRelay)), invalidRollbackRelay));
        Assert.Equal("invalid_request", invalidRollback.ErrorCode);

        rollbackAuthorization.TargetVersion = fixture.Version;
        var rollbackAuthorizationBytes = JsonSerializer.SerializeToUtf8Bytes(
            rollbackAuthorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var rollbackAuthorizationDigest = Convert.ToHexStringLower(SHA256.HashData(rollbackAuthorizationBytes));
        var rollbackProof = Proof(enrollmentKey, "rollback", enrollmentId,
            RuntimeEnrollmentService.RollbackAudience, "-", rollbackAuthorizationDigest);
        var rollbackRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = RuntimeEnrollmentService.RollbackRelaySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            AuthorizationBodyBase64Url = Base64Url(rollbackAuthorizationBytes),
            ProofTimestamp = rollbackProof.Timestamp,
            ProofJti = rollbackProof.Jti,
            ProofSignature = rollbackProof.Signature
        };
        var rollbackRelayDigest = Sha256(JsonSerializer.Serialize(rollbackRelay));
        var invalidRollbackProofRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = rollbackRelay.Schema,
            ProtocolVersion = rollbackRelay.ProtocolVersion,
            AuthorizationBodyBase64Url = rollbackRelay.AuthorizationBodyBase64Url,
            ProofTimestamp = rollbackRelay.ProofTimestamp,
            ProofJti = rollbackRelay.ProofJti,
            ProofSignature = "AA"
        };
        var unauthenticatedRollbackReceipt = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RollbackAsync("website-step1", "s2s-test",
                Sha256(JsonSerializer.Serialize(invalidRollbackProofRelay)), invalidRollbackProofRelay));
        Assert.Equal(401, unauthenticatedRollbackReceipt.StatusCode);
        await using (var proofCheck = await factory.CreateDbContextAsync())
        {
            Assert.Empty(await proofCheck.RuntimeEnrollmentRequests.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "rollback").ToListAsync());
            Assert.Empty(await proofCheck.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "rollback").ToListAsync());
        }

        await using (var commercialBump = await factory.CreateDbContextAsync())
        {
            var sourceLicenseId = (await commercialBump.DistributionInstallationBindings.SingleAsync(row =>
                row.Id == fixture.BindingId)).LicenseId;
            var sourceLicense = await commercialBump.Licenses.SingleAsync(row => row.Id == sourceLicenseId);
            sourceLicense.AllowedVersions = "2.2.*";
            await commercialBump.SaveChangesAsync();
            Assert.True((await commercialBump.RuntimeEnrollmentAuthorityStates.SingleAsync()).Epoch
                > historicalAuthorityEpoch);
        }

        var rolledBack = await service.RollbackAsync(
            "website-step1", "s2s-test", rollbackRelayDigest, rollbackRelay);
        var rollbackReplay = await service.RollbackAsync(
            "website-step1", "s2s-test", rollbackRelayDigest, rollbackRelay);
        var freshRollbackProof = Proof(enrollmentKey, "rollback", enrollmentId,
            RuntimeEnrollmentService.RollbackAudience, "-", rollbackAuthorizationDigest);
        var freshRollbackRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = rollbackRelay.Schema,
            ProtocolVersion = rollbackRelay.ProtocolVersion,
            AuthorizationBodyBase64Url = rollbackRelay.AuthorizationBodyBase64Url,
            ProofTimestamp = freshRollbackProof.Timestamp,
            ProofJti = freshRollbackProof.Jti,
            ProofSignature = freshRollbackProof.Signature
        };
        await AssertExpiredFreshReplayAsync(
            "rollback", rolledBack.Response, freshRollbackRelay, "rollback_replay_expired");
        var freshRollbackReplay = await service.RollbackAsync("website-step1", "s2s-test",
            Sha256(JsonSerializer.Serialize(freshRollbackRelay)), freshRollbackRelay);
        Guid rollbackAssignedLicenseId;
        await using (var denyDivergent = await factory.CreateDbContextAsync())
        {
            rollbackAssignedLicenseId = (await denyDivergent.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleAsync(row => row.EnrollmentId == enrollmentId && row.State == "ACTIVE")).LicenseId;
            (await denyDivergent.Licenses.SingleAsync(row => row.Id == rollbackAssignedLicenseId))
                .AllowedVersions = "9.*";
            await denyDivergent.SaveChangesAsync();
        }
        var originalRollbackFilename = rollbackAuthorization.TargetInstallerFilename;
        rollbackAuthorization.TargetInstallerFilename = "TiaConnect-rollback-divergent.msi";
        var divergentRollbackBytes = JsonSerializer.SerializeToUtf8Bytes(
            rollbackAuthorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        rollbackAuthorization.TargetInstallerFilename = originalRollbackFilename;
        var divergentRollbackProof = Proof(enrollmentKey, "rollback", enrollmentId,
            RuntimeEnrollmentService.RollbackAudience, "-",
            Convert.ToHexStringLower(SHA256.HashData(divergentRollbackBytes)));
        var divergentRollbackRelay = new RuntimeEnrollmentUpgradeRelayRequest
        {
            Schema = rollbackRelay.Schema,
            ProtocolVersion = rollbackRelay.ProtocolVersion,
            AuthorizationBodyBase64Url = Base64Url(divergentRollbackBytes),
            ProofTimestamp = divergentRollbackProof.Timestamp,
            ProofJti = divergentRollbackProof.Jti,
            ProofSignature = divergentRollbackProof.Signature
        };
        var divergentRollback = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RollbackAsync("website-step1", "s2s-test",
                Sha256(JsonSerializer.Serialize(divergentRollbackRelay)), divergentRollbackRelay));
        Assert.Equal(409, divergentRollback.StatusCode);
        Assert.Equal("rollback_receipt_reused", divergentRollback.ErrorCode);
        await using (var restoreDivergent = await factory.CreateDbContextAsync())
        {
            var enrollmentBefore = await restoreDivergent.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(row => row.Id == enrollmentId);
            Assert.Equal("ACTIVE", enrollmentBefore.State);
            Assert.Equal(3, enrollmentBefore.SecurityEpoch);
            Assert.Equal(historicalAuthorityEpoch, enrollmentBefore.AuthorityEpoch);
            Assert.Equal(2, await restoreDivergent.RuntimeEnrollmentProofNonces.CountAsync(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "rollback"));
            Assert.Single(await restoreDivergent.RuntimeEnrollmentRequests.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "rollback").ToListAsync());
            (await restoreDivergent.Licenses.SingleAsync(row => row.Id == rollbackAssignedLicenseId))
                .AllowedVersions = "*";
            await restoreDivergent.SaveChangesAsync();
        }
        var obsoleteUpgrade = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay));
        Assert.Equal(409, obsoleteUpgrade.StatusCode);
        Assert.Equal("upgrade_binding_conflict", obsoleteUpgrade.ErrorCode);

        Assert.False(rolledBack.Idempotent);
        Assert.True(rollbackReplay.Idempotent);
        Assert.Equal(rolledBack.ExactResponseBody, rollbackReplay.ExactResponseBody);
        Assert.True(freshRollbackReplay.Idempotent);
        Assert.Equal(rolledBack.ExactResponseBody, freshRollbackReplay.ExactResponseBody);
        Assert.Equal(RuntimeEnrollmentService.RollbackResponseSchema, rolledBack.Response.Schema);
        Assert.Equal(RuntimeEnrollmentService.RollbackUse, rolledBack.Response.Use);
        Assert.Equal("rolled_back", rolledBack.Response.Decision);
        Assert.Equal(2, rolledBack.Response.OldSecurityEpoch);
        Assert.Equal(3, rolledBack.Response.NewSecurityEpoch);
        Assert.True(capabilitySigning.VerifyData(
            Encoding.UTF8.GetBytes(RuntimeEnrollmentCryptoService.BuildUpgradeSignaturePayload(rolledBack.Response)),
            DecodeBase64Url(rolledBack.Response.Signature),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        await using var rollbackCheck = await factory.CreateDbContextAsync();
        var rollbackBinding = await rollbackCheck.DistributionInstallationBindings
            .SingleAsync(row => row.Id == fixture.BindingId);
        var rollbackEnrollment = await rollbackCheck.RuntimeEnrollments
            .SingleAsync(row => row.Id == enrollmentId);
        Assert.Equal(fixture.Version, rollbackBinding.Version);
        Assert.Equal(sourceInstallerSha256, rollbackBinding.InstallerSha256);
        Assert.Equal(sourceHashes["FP_EXE"], rollbackBinding.ExecutableSha256);
        Assert.Equal(fixture.Version, rollbackEnrollment.ReleaseVersion);
        Assert.Equal(3, rollbackEnrollment.SecurityEpoch);
        Assert.Equal(historicalAuthorityEpoch, rollbackEnrollment.AuthorityEpoch);
        Assert.Single(await rollbackCheck.RuntimeEnrollmentRequests.Where(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "rollback").ToListAsync());
        Assert.Equal(2, await rollbackCheck.RuntimeEnrollmentProofNonces.CountAsync(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "rollback"));
        await using (var admin = new NpgsqlConnection(connections.Admin))
        {
            await admin.OpenAsync();
            await using var duplicate = admin.CreateCommand();
            // This disposable fixture removes both production uniqueness indexes solely to
            // prove that an ambiguous commercial graph remains infrastructure unavailable.
            duplicate.CommandText = """
                DROP INDEX public."IX_EnrollmentLicenseAssignments_EnrollmentId";
                DROP INDEX public."IX_EnrollmentLicenseAssignments_LicenseSeatId";
                INSERT INTO public."EnrollmentLicenseAssignments"
                    ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                     "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
                SELECT pg_catalog.gen_random_uuid(), "EnrollmentId", "LicenseId", "LicenseSeatId",
                       "State", "ActivatedAtUtc", "EndedAtUtc", "Revision" + 1, "EndReason"
                FROM public."EnrollmentLicenseAssignments"
                WHERE "EnrollmentId" = @enrollmentId AND "State" = 'ACTIVE';
                """;
            duplicate.Parameters.AddWithValue("enrollmentId", enrollmentId);
            await duplicate.ExecuteNonQueryAsync();
        }
        var ambiguousReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RollbackAsync("website-step1", "s2s-test", rollbackRelayDigest, rollbackRelay));
        Assert.Equal(503, ambiguousReplay.StatusCode);
        Assert.Equal("assignment_duplicate_active", ambiguousReplay.DiagnosticCode);
        await using var ambiguousState = await factory.CreateDbContextAsync();
        Assert.Equal(3, (await ambiguousState.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
        Assert.Equal(2, await ambiguousState.RuntimeEnrollmentProofNonces.CountAsync(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "rollback"));
    }

    private static List<RuntimeEnrollmentBinaryEvidenceRequest> CapabilityBinaries() =>
    [
        new() { Key = "FP_CORE", Sha256 = new string('c', 64) },
        new() { Key = "FP_DLL", Sha256 = new string('d', 64) },
        new() { Key = "FP_EXE", Sha256 = new string('e', 64) }
    ];

    [Fact]
    public async Task CanaryProof_ConcurrentExactRetryAndNegativeMatrix_AreAtomic()
    {
        // Keep the exact nonce/alert counts and no-ban assertion meaningful across the full suite.
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (Admin: isolated.Admin, App: isolated.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        Guid licenseId;
        string hardwareId;
        string grantRefDigest;
        await using (var seedCheck = await factory.CreateDbContextAsync())
        {
            var binding = await seedCheck.DistributionInstallationBindings.SingleAsync(
                candidate => candidate.Id == fixture.BindingId);
            licenseId = binding.LicenseId;
            grantRefDigest = binding.GrantRefDigestSha256;
            var seat = await seedCheck.LicenseSeats.SingleAsync(
                candidate => candidate.Id == binding.LicenseSeatId);
            hardwareId = seat.HardwareId.ToUpperInvariant();
            seat.HardwareId = hardwareId;
            binding.HardwareIdHash = Sha256(hardwareId);
            await seedCheck.SaveChangesAsync();
        }
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        using var ackKey = RSA.Create(2048);
        var options = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        var ack = new CanaryAckService(factory, configuration, TimeProvider.System);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(
            factory, authority, registry, crypto, Options.Create(options), ack);

        var prepared = await service.PrepareAsync(
            "website-step1", Sha256("canary-prepare-body"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("canary-confirm-body");
        await service.ConfirmAsync(
            enrollmentId, confirmDigest, confirm,
            Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
                prepared.Response.Challenge, confirmDigest),
            IPAddress.Loopback);

        long historicalEnrollmentAuthorityEpoch;
        await using (var historicalEpoch = await factory.CreateDbContextAsync())
            historicalEnrollmentAuthorityEpoch = await historicalEpoch.RuntimeEnrollments.AsNoTracking()
                .Where(candidate => candidate.Id == enrollmentId)
                .Select(candidate => candidate.AuthorityEpoch)
                .SingleAsync();
        long commercialAuditEpoch;
        await using (var commercialBump = new NpgsqlConnection(connections.Admin))
        {
            await commercialBump.OpenAsync();
            var beforeCommercialBump = await EpochAsync(commercialBump);
            await using var command = commercialBump.CreateCommand();
            command.CommandText = "UPDATE public.\"Licenses\" SET \"MaxSeats\"=\"MaxSeats\"+1 WHERE \"Id\"=@license;";
            command.Parameters.AddWithValue("license", licenseId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
            commercialAuditEpoch = await EpochAsync(commercialBump);
            Assert.True(commercialAuditEpoch > beforeCommercialBump);
        }

        var milestone = new RuntimeMilestoneRequest
        {
            Schema = RuntimeEnrollmentService.MilestoneSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            SessionId = Guid.NewGuid().ToString("D"),
            Sequence = 1,
            EventId = Guid.NewGuid().ToString("D"),
            Code = "bootstrap_entered",
            OccurredAtUtc = FormatUtc(DateTimeOffset.UtcNow)
        };
        var milestoneDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(milestone));
        var milestoneProof = Proof(enrollmentKey, "milestone", enrollmentId,
            options.ConfirmAudience, "-", milestoneDigest);
        var milestoneIssued = await service.RecordMilestoneAsync(
            enrollmentId, milestoneDigest, milestone, milestoneProof, IPAddress.Loopback);
        Assert.False(milestoneIssued.Idempotent);

        var request = new CanaryPingRequest
        {
            Schema = CanaryAckService.Schema,
            EventId = Guid.NewGuid().ToString("D"),
            SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
            HardwareId = hardwareId,
            AppVersion = fixture.Version,
            Trigger = "RuntimeCheck_NativeDllSwapped",
            Severity = 3
        };
        var bodyDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(request));
        var proof = CanaryProof(enrollmentKey, enrollmentId, request.EventId!, bodyDigest, options);

        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, proof, IPAddress.Loopback)));

        Assert.Single(results, result => !result.Idempotent);
        Assert.Equal(19, results.Count(result => result.Idempotent));
        Assert.Single(results.Select(result => Convert.ToBase64String(result.ExactResponseBody)).Distinct());
        Assert.All(results, result => Assert.Equal("ack", result.Response.Decision));

        await using (var epochCheck = await factory.CreateDbContextAsync())
        {
            Assert.Equal(historicalEnrollmentAuthorityEpoch,
                await epochCheck.RuntimeEnrollments.AsNoTracking()
                    .Where(candidate => candidate.Id == enrollmentId)
                    .Select(candidate => candidate.AuthorityEpoch)
                    .SingleAsync());
            Assert.Equal(commercialAuditEpoch,
                await epochCheck.RuntimeMilestones.AsNoTracking()
                    .Where(candidate => candidate.EnrollmentId == enrollmentId
                        && candidate.EventId == milestone.EventId)
                    .Select(candidate => candidate.AuthorityEpoch)
                    .SingleAsync());
            Assert.Equal(commercialAuditEpoch,
                await epochCheck.RuntimeEnrollmentProofNonces.AsNoTracking()
                    .Where(candidate => candidate.EnrollmentId == enrollmentId
                        && candidate.Operation == "milestone" && candidate.Jti == milestoneProof.Jti)
                    .Select(candidate => candidate.AuthorityEpoch)
                    .SingleAsync());
            Assert.Equal(commercialAuditEpoch,
                await epochCheck.RuntimeCanaryProofNonces.AsNoTracking()
                    .Where(candidate => candidate.EnrollmentId == enrollmentId && candidate.Jti == proof.Jti)
                    .Select(candidate => candidate.AuthorityEpoch)
                    .SingleAsync());
            Assert.Equal(commercialAuditEpoch,
                await epochCheck.RuntimeCriticalIncidents.AsNoTracking()
                    .Where(candidate => candidate.EnrollmentId == enrollmentId
                        && candidate.EventId == request.EventId)
                    .Select(candidate => candidate.OpenedAuthorityEpoch)
                    .SingleAsync());
        }

        await using (var authorityBump = new NpgsqlConnection(connections.Admin))
        {
            await authorityBump.OpenAsync();
            await using var command = authorityBump.CreateCommand();
            command.CommandText = "UPDATE public.\"Products\" SET \"Name\"=\"Name\" WHERE \"Id\"=@product;";
            command.Parameters.AddWithValue("product", fixture.ProductId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        var replayAfterIndependentAuthorityBump = await service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, proof, IPAddress.Loopback);
        Assert.True(replayAfterIndependentAuthorityBump.Idempotent);
        Assert.Equal(results[0].ExactResponseBody, replayAfterIndependentAuthorityBump.ExactResponseBody);

        var forged = proof with { Signature = new string('A', 512) };
        var forgedError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, forged, IPAddress.Loopback));
        Assert.Equal("authentication_failed", forgedError.ErrorCode);
        Assert.Null(forgedError.DiagnosticCode);

        var mismatched = new CanaryPingRequest
        {
            Schema = request.Schema,
            EventId = Guid.NewGuid().ToString("D"),
            SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
            HardwareId = "FFFFFFFFFFFFFFFF",
            AppVersion = request.AppVersion,
            Trigger = request.Trigger,
            Severity = 3
        };
        var mismatchDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(mismatched));
        var mismatchProof = CanaryProof(
            enrollmentKey, enrollmentId, mismatched.EventId!, mismatchDigest, options);
        var mismatchAccepted = await service.ProcessCanaryAsync(
            enrollmentId, mismatchDigest, mismatched, mismatchProof, IPAddress.Loopback);
        Assert.Equal("ack", mismatchAccepted.Response.Decision);
        await using (var mismatchCheck = await factory.CreateDbContextAsync())
            Assert.Equal("report_hardware_unlinked", (await mismatchCheck.CanaryAlerts
                .SingleAsync(alert => alert.HardwareId == mismatched.HardwareId)).Details);

        RuntimeEnrollment beforeBarrierWait;
        DateTimeOffset expiresDuringBarrierWait;
        await using (var arrangeExpiry = await new TestDbFactory(connections.Admin).CreateDbContextAsync())
        {
            await arrangeExpiry.Database.OpenConnectionAsync();
            var databaseNow = await RuntimeEnrollmentService.DatabaseNowAsync(
                arrangeExpiry, CancellationToken.None);
            expiresDuringBarrierWait = databaseNow.AddSeconds(1);
            var license = await arrangeExpiry.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.ExpirationDate = expiresDuringBarrierWait.UtcDateTime;
            await arrangeExpiry.SaveChangesAsync();
            beforeBarrierWait = await arrangeExpiry.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentId);
        }
        await using (var barrierBlocker = new NpgsqlConnection(connections.Admin))
        {
            await barrierBlocker.OpenAsync();
            await using var barrierTransaction = await barrierBlocker.BeginTransactionAsync();
            await using (var takeBarrier = new NpgsqlCommand(
                             "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);",
                             barrierBlocker, barrierTransaction))
                await takeBarrier.ExecuteNonQueryAsync();

            var postWaitRequest = new CanaryPingRequest
            {
                Schema = request.Schema,
                EventId = Guid.NewGuid().ToString("D"),
                SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
                HardwareId = request.HardwareId,
                AppVersion = request.AppVersion,
                Trigger = request.Trigger,
                Severity = request.Severity
            };
            var postWaitDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(postWaitRequest));
            var postWaitProof = CanaryProof(
                enrollmentKey, enrollmentId, postWaitRequest.EventId!, postWaitDigest, options);
            var pendingPostWait = service.ProcessCanaryAsync(
                enrollmentId, postWaitDigest, postWaitRequest, postWaitProof, IPAddress.Loopback);
            await using var observer = new NpgsqlConnection(connections.Admin);
            await observer.OpenAsync();
            await WaitForSharedCommercialBarrierWaiterAsync(observer, barrierBlocker.ProcessID);
            while (await ScalarAsync<DateTime>(observer,
                       "SELECT pg_catalog.clock_timestamp() AT TIME ZONE 'UTC' AS \"Value\";")
                   <= expiresDuringBarrierWait.UtcDateTime)
            {
                await Task.Delay(20);
            }
            Assert.False(pendingPostWait.IsCompleted);
            await barrierTransaction.CommitAsync();

            var postWaitAccepted = await pendingPostWait;
            Assert.False(postWaitAccepted.Idempotent);
            Assert.Equal("ack", postWaitAccepted.Response.Decision);
            await using var postWaitCheck = await factory.CreateDbContextAsync();
            var postWaitAlert = await postWaitCheck.CanaryAlerts.SingleAsync(
                alert => alert.HardwareId == postWaitRequest.HardwareId
                    && alert.Details == "commercial_denial:commercial_authority_ineligible");
            Assert.Equal("authenticated_evidence", postWaitAlert.ServerAction);
            Assert.True(await postWaitCheck.RuntimeCriticalIncidents.AnyAsync(
                incident => incident.EventId == postWaitRequest.EventId && incident.State == "OPEN"));
            var unchanged = await postWaitCheck.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(candidate => candidate.Id == enrollmentId);
            Assert.Equal(beforeBarrierWait.Epoch, unchanged.Epoch);
            Assert.Equal(beforeBarrierWait.SecurityEpoch, unchanged.SecurityEpoch);
            Assert.Equal(beforeBarrierWait.AuthorityEpoch, unchanged.AuthorityEpoch);
        }
        await using (var restoreExpiry = await new TestDbFactory(connections.Admin).CreateDbContextAsync())
        {
            var license = await restoreExpiry.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.ExpirationDate = DateTime.UtcNow.AddDays(30);
            await restoreExpiry.SaveChangesAsync();
        }

        var versionMismatch = new CanaryPingRequest
        {
            Schema = request.Schema,
            EventId = Guid.NewGuid().ToString("D"),
            SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
            HardwareId = request.HardwareId,
            AppVersion = "2.2.998",
            Trigger = request.Trigger,
            Severity = 3
        };
        var versionMismatchDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(versionMismatch));
        var versionMismatchProof = CanaryProof(
            enrollmentKey, enrollmentId, versionMismatch.EventId!, versionMismatchDigest, options);
        var versionMismatchError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, versionMismatchDigest, versionMismatch, versionMismatchProof, IPAddress.Loopback));
        Assert.Equal("canary_binding_mismatch", versionMismatchError.ErrorCode);

        var malformedProofs = new[]
        {
            CanaryProof(enrollmentKey, Guid.NewGuid(), request.EventId!, bodyDigest, options),
            CanaryProof(enrollmentKey, enrollmentId, request.EventId!, bodyDigest, options, epoch: 2),
            CanaryProof(enrollmentKey, enrollmentId, request.EventId!, bodyDigest, options,
                audience: "https://runtime.example.test/api/health/other"),
            CanaryProof(enrollmentKey, enrollmentId, request.EventId!, bodyDigest, options,
                payloadTransform: payload => payload.Replace("\nPOST\n", "\nGET\n", StringComparison.Ordinal)),
            CanaryProof(enrollmentKey, enrollmentId, request.EventId!, bodyDigest, options,
                payloadTransform: payload => payload.Replace(
                    "\n/api/health/ping\n", "\n/api/health/ping/other\n", StringComparison.Ordinal))
        };
        foreach (var malformedProof in malformedProofs)
        {
            var malformedError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
                enrollmentId, bodyDigest, request, malformedProof, IPAddress.Loopback));
            Assert.Equal("authentication_failed", malformedError.ErrorCode);
        }

        var duplicateEventProof = CanaryProof(
            enrollmentKey, enrollmentId, request.EventId!, bodyDigest, options, jti: Guid.NewGuid());
        var eventConflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, duplicateEventProof, IPAddress.Loopback));
        Assert.Equal("event_conflict", eventConflict.ErrorCode);

        var expiredRequest = new CanaryPingRequest
        {
            Schema = request.Schema,
            EventId = Guid.NewGuid().ToString("D"),
            SentAtUtc = FormatUtc(DateTimeOffset.UtcNow.AddMinutes(-2)),
            HardwareId = request.HardwareId,
            AppVersion = request.AppVersion,
            Trigger = request.Trigger,
            Severity = 3
        };
        var expiredDigest = Sha256(System.Text.Json.JsonSerializer.Serialize(expiredRequest));
        var expiredProof = CanaryProof(enrollmentKey, enrollmentId, expiredRequest.EventId!, expiredDigest,
            options, DateTimeOffset.UtcNow.AddMinutes(-2));
        var expiredError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, expiredDigest, expiredRequest, expiredProof, IPAddress.Loopback));
        Assert.Equal("authentication_failed", expiredError.ErrorCode);
        Assert.Equal(RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, expiredError.DiagnosticCode);

        await using (var revoke = await factory.CreateDbContextAsync())
        {
            var license = await revoke.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.IsActive = false;
            license.RevokedAt = DateTime.UtcNow;
            await revoke.SaveChangesAsync();
        }
        var revokedReplay = await service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, proof, IPAddress.Loopback);
        Assert.True(revokedReplay.Idempotent);
        Assert.Equal(results[0].ExactResponseBody, revokedReplay.ExactResponseBody);
        await using (var restoreAuthorityForNextIndependentCase = await factory.CreateDbContextAsync())
        {
            var license = await restoreAuthorityForNextIndependentCase.Licenses.SingleAsync(
                candidate => candidate.Id == licenseId);
            license.IsActive = true;
            license.RevokedAt = null;
            await restoreAuthorityForNextIndependentCase.SaveChangesAsync();
        }

        var invalidations = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), TimeProvider.System,
            TestHardwareAuthorityAliasResolver.Instance);
        var invalidatedAt = DateTimeOffset.UtcNow;
        await invalidations.InvalidateAsync("website-step1", Sha256("canary-binding-invalidation"), new()
        {
            Schema = DistributionInstallationBindingService.InvalidationSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            GrantRefDigestSha256 = grantRefDigest,
            Reason = "security_lockdown",
            OccurredAtUtc = FormatUtc(invalidatedAt),
            Epoch = 1
        });
        var invalidatedReplay = await service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, proof, IPAddress.Loopback);
        Assert.True(invalidatedReplay.Idempotent);
        Assert.Equal(results[0].ExactResponseBody, invalidatedReplay.ExactResponseBody);

        await using var check = await factory.CreateDbContextAsync();
        Assert.Equal(3, await check.RuntimeCanaryProofNonces.CountAsync());
        Assert.Single(await check.RuntimeCriticalIncidents.Where(incident =>
            incident.State == "OPEN" && incident.EventId == request.EventId).ToListAsync());
        Assert.Equal(3, await check.CanaryAlerts.CountAsync(alert => alert.ServerAction == "authenticated_evidence"));
        Assert.False(await check.BannedHardwareIds.AnyAsync());
        Assert.True((await check.Licenses.SingleAsync(license => license.Id == licenseId)).IsActive);
        Assert.True((await check.LicenseSeats.SingleAsync(seat => seat.LicenseId == licenseId)).IsActive);
        Assert.Equal("ACTIVE", (await check.RuntimeEnrollments.SingleAsync(
            candidate => candidate.Id == enrollmentId)).State);
    }

    [Fact]
    public async Task Prepare_SameClientRequestIdAcrossBindings_ConvergesTo409()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var first = await SeedAuthorityAsync(factory);
        var second = await SeedAuthorityAsync(factory);
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var options = RuntimeOptions(first.ProductId, active, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));
        using var firstKey = RSA.Create(3072);
        using var secondKey = RSA.Create(3072);
        var requestId = Guid.NewGuid().ToString("D");
        var firstRequest = PrepareRequest(first, requestId, firstKey);
        var secondRequest = PrepareRequest(second, requestId, secondKey);

        var firstTask = service.PrepareAsync("website-step1", Sha256("cross-binding-a"), firstRequest);
        var secondTask = service.PrepareAsync("website-step1", Sha256("cross-binding-b"), secondRequest);
        var outcomes = await Task.WhenAll(CaptureAsync(firstTask), CaptureAsync(secondTask));

        Assert.Single(outcomes, outcome => outcome.Result != null);
        var conflict = Assert.IsType<RuntimeEnrollmentException>(
            Assert.Single(outcomes, outcome => outcome.Error != null).Error);
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
        Assert.Equal("idempotency_conflict", conflict.ErrorCode);
    }

    [Fact]
    public async Task KeyRegistryForeignKeys_RejectMissingOrWrongPurpose_AndReferencedKeysCannotMutateOrRetire()
    {
        var connections = await ProvisionAsync();
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var options = RuntimeOptions(Guid.Parse("11111111-1111-4111-8111-111111111111"), active, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        var missing = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(admin, """
            INSERT INTO public."RuntimeEnrollmentEncryptionNonces"
                ("Purpose", "KeyId", "Nonce", "OwnerType", "OwnerId", "CreatedAtUtc")
            VALUES ('encryption', 'missing-key', decode('000000000000000000000000', 'hex'),
                'test', gen_random_uuid(), clock_timestamp());
            """));
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, missing.SqlState);

        var wrongPurpose = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(admin, """
            INSERT INTO public."RuntimeEnrollmentEncryptionNonces"
                ("Purpose", "KeyId", "Nonce", "OwnerType", "OwnerId", "CreatedAtUtc")
            VALUES ('capability-signing', 'runtime-2026-01', decode('010000000000000000000000', 'hex'),
                'test', gen_random_uuid(), clock_timestamp());
            """));
        Assert.Equal(PostgresErrorCodes.CheckViolation, wrongPurpose.SqlState);

        var registryVersionPurpose = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(admin, """
            INSERT INTO public."RuntimeEnrollmentEncryptionNonces"
                ("Purpose", "KeyId", "Nonce", "OwnerType", "OwnerId", "CreatedAtUtc")
            VALUES ('registry-version', 'global', decode('011000000000000000000000', 'hex'),
                'test', gen_random_uuid(), clock_timestamp());
            """));
        Assert.Equal(PostgresErrorCodes.CheckViolation, registryVersionPurpose.SqlState);

        await ExecuteAsync(admin, """
            INSERT INTO public."RuntimeEnrollmentEncryptionNonces"
                ("Purpose", "KeyId", "Nonce", "OwnerType", "OwnerId", "CreatedAtUtc")
            VALUES ('encryption', 'enc-2026-01', decode('020000000000000000000000', 'hex'),
                'test', gen_random_uuid(), clock_timestamp());
            """);

        foreach (var statement in new[]
        {
            "DELETE FROM public.\"RuntimeEnrollmentKeyRegistries\" WHERE \"Purpose\" = 'encryption' AND \"KeyId\" = 'enc-2026-01';",
            "UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"State\" = 'retired', \"RetiredAtUtc\" = clock_timestamp() WHERE \"Purpose\" = 'encryption' AND \"KeyId\" = 'enc-2026-01';",
            "UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"MaterialDigestSha256\" = repeat('f', 64) WHERE \"Purpose\" = 'encryption' AND \"KeyId\" = 'enc-2026-01';",
            "UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"KeyId\" = 'enc-mutated' WHERE \"Purpose\" = 'encryption' AND \"KeyId\" = 'enc-2026-01';"
        })
        {
            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(admin, statement));
            Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, blocked.SqlState);
        }

        var signingKeyId = options.CapabilitySigning.ActiveKeyId.Replace("'", "''", StringComparison.Ordinal);
        foreach (var statement in new[]
        {
            $"INSERT INTO public.\"RuntimeEnrollmentKeyRegistries\" (\"Purpose\",\"KeyId\",\"MaterialDigestSha256\",\"State\",\"Epoch\",\"CreatedAtUtc\") VALUES ('capability-signing','{signingKeyId}',repeat('f',64),'active',1,clock_timestamp());",
            $"DELETE FROM public.\"RuntimeEnrollmentKeyRegistries\" WHERE \"Purpose\"='capability-signing' AND \"KeyId\"='{signingKeyId}';",
            $"UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"State\"='retired',\"RetiredAtUtc\"=clock_timestamp(),\"Epoch\"=\"Epoch\"+1 WHERE \"Purpose\"='capability-signing' AND \"KeyId\"='{signingKeyId}';",
            $"UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"MaterialDigestSha256\"=repeat('e',64),\"Epoch\"=\"Epoch\"+1 WHERE \"Purpose\"='capability-signing' AND \"KeyId\"='{signingKeyId}';",
            $"UPDATE public.\"RuntimeEnrollmentKeyRegistries\" SET \"Epoch\"=\"Epoch\"+2 WHERE \"Purpose\"='capability-signing' AND \"KeyId\"='{signingKeyId}';"
        })
        {
            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(admin, statement));
            Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, blocked.SqlState);
        }
    }

    [Fact]
    public async Task RuntimeEnrollmentMigration_RealUpDownUp_PreservesDependencyOrder()
    {
        var connections = await ProvisionIsolatedAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connections.Admin).Options;
        await using var db = new LicenseDbContext(dbOptions);
        var migrator = db.GetService<IMigrator>();

        await migrator.MigrateAsync("20260718183759_AddDistributionInstallationBindings");
        await using (var connection = new NpgsqlConnection(connections.Admin))
        {
            await connection.OpenAsync();
            Assert.Equal(0L, await ScalarAsync<long>(connection, """
                SELECT count(*) FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relname LIKE 'RuntimeEnrollment%';
                """));
        }

        await migrator.MigrateAsync();
        await using (var connection = new NpgsqlConnection(connections.Admin))
        {
            await connection.OpenAsync();
            await GrantApplicationRuntimePrivilegesAsync(connection);
        }
        Assert.False((await db.Database.GetPendingMigrationsAsync()).Any());
    }

    [Fact]
    public async Task DistributionInvalidationMigration_BackfillsHistoricalUtf8DigestAndEnforcesV1Checks()
    {
        var shared = await ProvisionAsync();
        var database = $"softlicence_distribution_invalidation_{Guid.NewGuid():N}";
        await using (var connection = new NpgsqlConnection(shared.Admin))
        {
            await connection.OpenAsync();
            await ExecuteAsync(connection, $"CREATE DATABASE \"{database}\";");
        }
        var isolated = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(isolated).Options;
        await using var db = new LicenseDbContext(dbOptions);
        var migrator = db.GetService<IMigrator>();
        await migrator.MigrateAsync("20260719024400_AddRuntimeEnrollments");

        var firstGrant = "café-历史-" + Guid.NewGuid().ToString("N")[..20];
        var secondGrant = "grant-" + Guid.NewGuid().ToString("N")[..24];
        var productId = Guid.NewGuid();
        var firstBindingId = Guid.NewGuid();
        await using (var seedDb = new LicenseDbContext(dbOptions))
        {
            seedDb.Products.Add(new Product
            {
                Id = productId,
                Name = "Historical distribution " + productId.ToString("N"),
                PrivateKeyXml = string.Empty,
                PublicKeyXml = string.Empty,
                ApiSecret = Guid.NewGuid().ToString("N")
            });
            await seedDb.SaveChangesAsync();
        }
        await using (var connection = new NpgsqlConnection(isolated))
        {
            await connection.OpenAsync();
            await ExecuteAsync(connection, "SET session_replication_role = replica;");
            foreach (var grant in new[] { firstGrant, secondGrant })
            {
                var bindingId = grant == firstGrant ? firstBindingId : Guid.NewGuid();
                await using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO public."DistributionInstallationBindings"
                        ("Id", "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId", "GrantRef",
                         "HandoffDigestSha256", "InstallationId", "HardwareIdHash", "Version",
                         "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256",
                         "CoreSha256", "ApprovedBinariesSource", "State", "BoundAtUtc")
                    VALUES
                        (@id, @product, @license, @seat, @entitlement, @grant, @handoff, @installation,
                         @hardware, '2.2.844', 'test.exe', @installer, @exe, @dll, @core, 'release', 'active', clock_timestamp());
                    """;
                insert.Parameters.AddWithValue("id", bindingId);
                insert.Parameters.AddWithValue("product", productId);
                insert.Parameters.AddWithValue("license", Guid.NewGuid());
                insert.Parameters.AddWithValue("seat", Guid.NewGuid());
                insert.Parameters.AddWithValue("entitlement", Guid.NewGuid());
                insert.Parameters.AddWithValue("grant", grant);
                insert.Parameters.AddWithValue("handoff", Sha256(Guid.NewGuid().ToString("D")));
                insert.Parameters.AddWithValue("installation", Guid.NewGuid().ToString("D"));
                insert.Parameters.AddWithValue(
                    "hardware",
                    grant == firstGrant ? new string('a', 64) : new string('f', 64));
                insert.Parameters.AddWithValue("installer", new string('b', 64));
                insert.Parameters.AddWithValue("exe", new string('c', 64));
                insert.Parameters.AddWithValue("dll", new string('d', 64));
                insert.Parameters.AddWithValue("core", new string('e', 64));
                Assert.Equal(1, await insert.ExecuteNonQueryAsync());

                await using var request = connection.CreateCommand();
                request.CommandText = """
                    INSERT INTO public."DistributionBindingRequests"
                        ("Id", "ClientId", "RequestId", "Operation", "PayloadDigest", "BindingId", "ResponseJson", "CreatedAtUtc")
                    VALUES
                        (@id, 'website-step1', @request, 'finalize_binding', @digest, @binding, '{}', clock_timestamp());
                    """;
                request.Parameters.AddWithValue("id", Guid.NewGuid());
                request.Parameters.AddWithValue("request", Guid.NewGuid().ToString("D"));
                request.Parameters.AddWithValue("digest", Sha256("finalize-" + grant));
                request.Parameters.AddWithValue("binding", bindingId);
                Assert.Equal(1, await request.ExecuteNonQueryAsync());
            }
            await ExecuteAsync(connection, "SET session_replication_role = origin;");
        }

        await migrator.MigrateAsync();

        await using (var connection = new NpgsqlConnection(isolated))
        {
            await connection.OpenAsync();
            await using var digest = connection.CreateCommand();
            digest.CommandText = """
                SELECT "GrantRefDigestSha256"
                FROM public."DistributionInstallationBindings"
                WHERE "GrantRef" = @grant;
                """;
            digest.Parameters.AddWithValue("grant", firstGrant);
            Assert.Equal(Sha256(firstGrant), (string)(await digest.ExecuteScalarAsync())!);
            Assert.Equal(0L, await ScalarAsync<long>(connection,
                "SELECT count(*) FROM public.\"DistributionInstallationBindings\" WHERE \"GrantRefDigestSha256\" IS NULL OR \"GrantRefDigestSha256\" = '';"));
            Assert.Equal(2L, await ScalarAsync<long>(connection,
                "SELECT count(*) FROM public.\"DistributionGrantOwnerships\" WHERE \"ClientId\" = 'website-step1' AND \"Source\" = 'finalize_v1';"));

            var invalidEpoch = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, $$"""
                INSERT INTO public."DistributionBindingInvalidations"
                    ("Id", "ProductId", "GrantRefDigestSha256", "ClientId", "RequestId", "Reason",
                     "OccurredAtUtc", "Epoch", "ReceivedAtUtc")
                VALUES ('{{Guid.NewGuid():D}}', '{{productId:D}}', '{{Sha256(firstGrant)}}', 'website-step1',
                        '{{Guid.NewGuid():D}}', 'grant_revoked', clock_timestamp(), 2, clock_timestamp());
                """));
            Assert.Equal(PostgresErrorCodes.CheckViolation, invalidEpoch.SqlState);

            var triggerColumns = await QueryStringsAsync(connection, """
                SELECT a.attname
                FROM pg_trigger t
                JOIN pg_attribute a ON a.attrelid = t.tgrelid
                WHERE t.tgname = 'trg_runtime_authority_distributioninstallationbindings_update'
                  AND (t.tgattr::int2[] @> ARRAY[a.attnum]::int2[])
                ORDER BY a.attname;
                """);
            Assert.Contains("GrantRefDigestSha256", triggerColumns);
        }

        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            new TestDbFactory(isolated), new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        await service.InvalidateAsync("website-step1", Sha256("historical-invalidation"), new()
        {
            Schema = DistributionInstallationBindingService.InvalidationSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = productId.ToString("D"),
            BindingId = firstBindingId.ToString("D"),
            GrantRefDigestSha256 = Sha256(firstGrant),
            Reason = "grant_revoked",
            OccurredAtUtc = FormatUtc(now),
            Epoch = 1
        });
        Assert.Equal("invalidated", (await service.RevalidateForCapabilityAsync(firstBindingId)).State);
    }

    [Fact]
    public async Task SameAuthorityRecoveryMigration_RejectsActiveHardwareDuplicatesThenSucceedsWhenUnambiguous()
    {
        var shared = await ProvisionAsync();
        var database = $"softlicence_same_authority_migration_{Guid.NewGuid():N}";
        await using (var admin = new NpgsqlConnection(shared.Admin))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, $"CREATE DATABASE \"{database}\";");
        }
        var isolated = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
        try
        {
            var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(isolated).Options;
            await using var db = new LicenseDbContext(dbOptions);
            var migrator = db.GetService<IMigrator>();
            await migrator.MigrateAsync("20260802185000_PartitionAccessLogs");

            var productId = Guid.NewGuid();
            var duplicateHardwareHash = new string('a', 64);
            await using (var connection = new NpgsqlConnection(isolated))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, "SET session_replication_role = replica;");
                for (var index = 0; index < 2; index++)
                {
                    var grant = Guid.NewGuid().ToString("D");
                    await using var insert = connection.CreateCommand();
                    insert.CommandText = """
                        INSERT INTO public."DistributionInstallationBindings"
                            ("Id", "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId",
                             "SubjectRefDigestSha256", "GrantRef", "GrantRefDigestSha256",
                             "HandoffDigestSha256", "HandoffIssuedAtUtc", "HandoffExpiresAtUtc",
                             "DownloadCompletedAtUtc", "InstallationId", "HardwareIdHash", "Version",
                             "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256",
                             "CoreSha256", "ApprovedBinariesSource", "State", "BoundAtUtc")
                        VALUES
                            (@id, @product, @license, @seat, @entitlement, @subject, @grant, @grantDigest,
                             @handoff, clock_timestamp() - interval '5 minutes', clock_timestamp() + interval '20 minutes',
                             clock_timestamp() - interval '4 minutes', @installation, @hardware, '2.2.844',
                             'test.exe', @installer, @exe, @dll, @core, 'release', 'active', clock_timestamp());
                        """;
                    insert.Parameters.AddWithValue("id", Guid.NewGuid());
                    insert.Parameters.AddWithValue("product", productId);
                    insert.Parameters.AddWithValue("license", Guid.NewGuid());
                    insert.Parameters.AddWithValue("seat", Guid.NewGuid());
                    insert.Parameters.AddWithValue("entitlement", Guid.NewGuid());
                    insert.Parameters.AddWithValue("subject", new string((char)('b' + index), 64));
                    insert.Parameters.AddWithValue("grant", grant);
                    insert.Parameters.AddWithValue("grantDigest", Sha256(grant));
                    insert.Parameters.AddWithValue("handoff", Sha256("migration-handoff-" + index));
                    insert.Parameters.AddWithValue("installation", Guid.NewGuid().ToString("D"));
                    insert.Parameters.AddWithValue("hardware", duplicateHardwareHash);
                    insert.Parameters.AddWithValue("installer", new string('d', 64));
                    insert.Parameters.AddWithValue("exe", new string('e', 64));
                    insert.Parameters.AddWithValue("dll", new string('f', 64));
                    insert.Parameters.AddWithValue("core", new string('1', 64));
                    Assert.Equal(1, await insert.ExecuteNonQueryAsync());
                }
                await ExecuteAsync(connection, "SET session_replication_role = origin;");
            }

            var duplicate = await Assert.ThrowsAsync<PostgresException>(() => migrator.MigrateAsync());
            Assert.Equal(PostgresErrorCodes.UniqueViolation, duplicate.SqlState);
            Assert.Contains("duplicate product/hardware authority", duplicate.MessageText, StringComparison.Ordinal);

            await using (var repair = new NpgsqlConnection(isolated))
            {
                await repair.OpenAsync();
                await ExecuteAsync(repair, "SET session_replication_role = replica;");
                await ExecuteAsync(repair, """
                    DELETE FROM public."DistributionInstallationBindings"
                    WHERE "Id" = (
                        SELECT "Id" FROM public."DistributionInstallationBindings"
                        WHERE "State" = 'active'
                        ORDER BY "Id" DESC
                        LIMIT 1
                    );
                    """);
                await ExecuteAsync(repair, "SET session_replication_role = origin;");
            }

            await migrator.MigrateAsync();
            await using var check = new NpgsqlConnection(isolated);
            await check.OpenAsync();
            Assert.Equal(1L, await ScalarAsync<long>(check, """
                SELECT count(*) FROM public."DistributionInstallationBindings"
                WHERE "State" = 'active';
                """));
        }
        finally
        {
            await using var admin = new NpgsqlConnection(shared.Admin);
            await admin.OpenAsync();
            await using var drop = admin.CreateCommand();
            // The complete Runtime matrix creates many distinct Npgsql pools before this cleanup.
            // Keep the drop bounded while allowing PostgreSQL to terminate those test-only sessions.
            drop.CommandTimeout = 120;
            drop.CommandText = $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE);";
            await drop.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// Proves the provider release is one atomic terminal transition for PC A and that PC B can
    /// acquire only fresh seat, installation, binding, grant, enrollment, key, and lineage identities afterward.
    /// </summary>
    [Fact]
    public async Task ProviderSeatRelease_ConcurrentRetryTerminalizesA_AndBUsesFreshAuthority()
    {
        var shared = await ProvisionAsync();
        var database = "softlicence_tkt734_transfer_" + Guid.NewGuid().ToString("N");
        var cleanupAdmin = new NpgsqlConnectionStringBuilder(shared.Admin)
        {
            Pooling = false,
            CommandTimeout = 120
        }.ConnectionString;
        await CreateDatabaseAsync(shared.Admin, database);
        try
        {
        var admin = new NpgsqlConnectionStringBuilder(shared.Admin)
        {
            Database = database,
            Pooling = false
        }.ConnectionString;
        var app = new NpgsqlConnectionStringBuilder(admin)
        {
            Username = "softlicence_runtime_test_app",
            Password = "runtime-test-only",
            Pooling = false
        }.ConnectionString;
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
        await using (var migration = new LicenseDbContext(options))
            await migration.Database.MigrateAsync();
        await using (var grants = new NpgsqlConnection(admin))
        {
            await grants.OpenAsync();
            await GrantApplicationRuntimePrivilegesAsync(grants);
        }
        var connections = (Admin: admin, App: app);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        var now = DateTimeOffset.UtcNow;
        const string artifactDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        using var capabilitySigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentAKey = RSA.Create(3072);
        using var enrollmentBKey = RSA.Create(3072);
        var runtimeOptions = RuntimeOptions(fixture.ProductId, capabilitySigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, runtimeOptions);
        var dataProtection = new EphemeralDataProtectionProvider();
        var enrollmentAuthority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(runtimeOptions));
        var keyRegistry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(runtimeOptions));
        using var enrollmentCrypto = new RuntimeEnrollmentCryptoService(Options.Create(runtimeOptions));
        var enrollmentService = new RuntimeEnrollmentService(
            factory, enrollmentAuthority, keyRegistry, enrollmentCrypto, Options.Create(runtimeOptions),
            dataProtectionProvider: dataProtection);
        var preparedA = await enrollmentService.PrepareAsync(
            "website-step1", Sha256("tkt734-prepare-a"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentAKey));
        var enrollmentAId = Guid.Parse(preparedA.Response.EnrollmentId);
        var confirmA = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentAId.ToString("D"),
            Epoch = 1
        };
        var confirmADigest = Sha256("tkt734-confirm-a");
        await enrollmentService.ConfirmAsync(
            enrollmentAId, confirmADigest, confirmA,
            Proof(enrollmentAKey, "confirm", enrollmentAId, runtimeOptions.ConfirmAudience,
                preparedA.Response.Challenge, confirmADigest),
            IPAddress.Loopback);
        Guid licenseId;
        Guid seatAId;
        string grantA;
        string hardwareA;
        DistributionInstallationBinding bindingAForAuthority;
        RuntimeEnrollment enrollmentAForAuthority;
        License licenseForAuthority;
        await using (var setup = await factory.CreateDbContextAsync())
        {
            var bindingA = await setup.DistributionInstallationBindings
                .SingleAsync(item => item.Id == fixture.BindingId);
            bindingAForAuthority = bindingA;
            licenseId = bindingA.LicenseId;
            seatAId = bindingA.LicenseSeatId;
            grantA = bindingA.GrantRef;
            hardwareA = (await setup.LicenseSeats.SingleAsync(item => item.Id == seatAId)).HardwareId;
            enrollmentAForAuthority = await setup.RuntimeEnrollments
                .SingleAsync(item => item.Id == enrollmentAId);
            licenseForAuthority = await setup.Licenses.SingleAsync(item => item.Id == licenseId);
            setup.ApprovedBinaryRegistrations.Add(new ApprovedBinaryRegistration
            {
                ProductId = fixture.ProductId,
                Version = bindingA.Version,
                RegistrationKey = $"tkt734-authority-{fixture.ProductId:D}",
                ManifestDigestSha256 = new string('b', 64),
                BaselineDigestSha256 = artifactDigest,
                Source = "release",
                RegisteredAtUtc = now.UtcDateTime
            });
            await setup.SaveChangesAsync();
        }

        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        using var registryAuthority = RSA.Create(2048);
        var authorityRuntime = AuthorityRuntime(
            factory, fixture.ProductId, now, operational, recovery, registryAuthority,
            capabilitySigning, nextSigning);
        using var authorityRuntimeCrypto = authorityRuntime.RuntimeCrypto;
        var authorityARequestId = Guid.NewGuid();
        var authorityABody = AuthorityGenesisRequest(
            authorityARequestId, fixture.ProductId, bindingAForAuthority,
            enrollmentAForAuthority, licenseForAuthority, artifactDigest, now.UtcDateTime);
        var authorityA = await authorityRuntime.Service.IssueAuthorityGenerationV2Async(
            "website-step1", "s2s-runtime-test", Guid.NewGuid(), authorityABody, null, null);
        Assert.True(
            authorityA.StatusCode is >= 200 and < 300,
            Encoding.UTF8.GetString(authorityA.ExactResponseBody));

        var service = new DistributionInstallationBindingService(
            factory, dataProtection, new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var release = new DistributionInstallationInvalidationRequest
        {
            Schema = DistributionInstallationBindingService.InvalidationSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            GrantRefDigestSha256 = Sha256(grantA),
            Reason = "seat_released",
            OccurredAtUtc = FormatUtc(now),
            Epoch = 1
        };
        var releaseDigest = Sha256("tkt734-release-" + release.RequestId);
        var divergentSeatId = Guid.NewGuid();
        await using (var divergentSetup = await factory.CreateDbContextAsync())
        {
            divergentSetup.LicenseSeats.Add(new LicenseSeat
            {
                Id = divergentSeatId,
                LicenseId = licenseId,
                HardwareId = "DIVERGENT-" + Guid.NewGuid().ToString("N").ToUpperInvariant(),
                IsActive = true
            });
            var enrollment = await divergentSetup.RuntimeEnrollments
                .SingleAsync(item => item.Id == enrollmentAId);
            enrollment.LicenseSeatId = divergentSeatId;
            var forbidden = await Assert.ThrowsAsync<PostgresException>(() => divergentSetup.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, forbidden.SqlState);
            Assert.Contains("binding_mismatch", forbidden.MessageText, StringComparison.Ordinal);
        }
        await using (var unchanged = await factory.CreateDbContextAsync())
        {
            Assert.Equal("active", (await unchanged.DistributionInstallationBindings
                .SingleAsync(item => item.Id == fixture.BindingId)).State);
            Assert.True((await unchanged.LicenseSeats.SingleAsync(item => item.Id == seatAId)).IsActive);
            Assert.Equal("ACTIVE", (await unchanged.RuntimeEnrollments
                .SingleAsync(item => item.Id == enrollmentAId)).State);
            Assert.False(await unchanged.DistributionBindingInvalidations.AnyAsync(item =>
                item.BindingId == fixture.BindingId));
            Assert.Equal(seatAId, (await unchanged.RuntimeEnrollments
                .SingleAsync(item => item.Id == enrollmentAId)).LicenseSeatId);
            Assert.False(await unchanged.LicenseSeats.AnyAsync(item => item.Id == divergentSeatId));
        }
        var concurrent = await Task.WhenAll(
            service.InvalidateAsync("website-step1", releaseDigest, release),
            service.InvalidateAsync("website-step1", releaseDigest, release));
        Assert.Contains(concurrent, result => !result.Idempotent);
        Assert.Contains(concurrent, result => result.Idempotent);
        Assert.Equal(concurrent[0].Response, concurrent[1].Response);

        var grantB = Guid.NewGuid().ToString("D");
        var hardwareB = "B-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        var issueB = await service.IssueEntitlementAsync(
            "website-step1", Sha256("tkt734-issue-b-" + grantB), new()
        {
            Schema = DistributionInstallationBindingService.IssueV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = licenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(grantB)
        });
        var installationB = Guid.NewGuid().ToString("D");
        var finalizeB = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = grantB,
            HandoffDigestSha256 = Sha256("tkt734-handoff-b-" + grantB),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-1)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = issueB.Response.EntitlementRef,
            InstallationId = installationB,
            HardwareId = hardwareB,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "tkt734-b.exe",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('e', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('d', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };
        var failedB = JsonSerializer.Deserialize<DistributionInstallationFinalizeRequest>(
            JsonSerializer.Serialize(finalizeB))!;
        failedB.Binaries![0].Sha256 = new string('0', 64);
        var failed = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync("website-step1", Sha256("tkt734-failed-b-" + grantB), failedB));
        Assert.Equal("binary_mismatch", failed.ErrorCode);
        await using (var afterFailedB = await factory.CreateDbContextAsync())
        {
            Assert.Equal("invalidated", (await afterFailedB.DistributionInstallationBindings
                .SingleAsync(item => item.Id == fixture.BindingId)).State);
            Assert.False((await afterFailedB.LicenseSeats.SingleAsync(item => item.Id == seatAId)).IsActive);
            Assert.Equal("INVALIDATED", (await afterFailedB.RuntimeEnrollments
                .SingleAsync(item => item.Id == enrollmentAId)).State);
            Assert.False(await afterFailedB.DistributionInstallationBindings.AnyAsync(item =>
                item.ProductId == fixture.ProductId
                && item.InstallationId == installationB
                && item.State == "active"));
        }
        var bindingB = await service.FinalizeAsync(
            "website-step1", Sha256("tkt734-finalize-b-" + grantB), finalizeB);
        var bindingBId = Guid.Parse(bindingB.Response.BindingId);
        var fixtureB = (
            fixture.ProductId,
            BindingId: bindingBId,
            HandoffDigest: finalizeB.HandoffDigestSha256,
            InstallationId: installationB,
            Version: fixture.Version);
        var preparedB = await enrollmentService.PrepareAsync(
            "website-step1", Sha256("tkt734-prepare-b"),
            PrepareRequest(fixtureB, Guid.NewGuid().ToString("D"), enrollmentBKey));
        var enrollmentBId = Guid.Parse(preparedB.Response.EnrollmentId);
        var confirmB = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentBId.ToString("D"),
            Epoch = 1
        };
        var confirmBDigest = Sha256("tkt734-confirm-b");
        await enrollmentService.ConfirmAsync(
            enrollmentBId, confirmBDigest, confirmB,
            Proof(enrollmentBKey, "confirm", enrollmentBId, runtimeOptions.ConfirmAudience,
                preparedB.Response.Challenge, confirmBDigest),
            IPAddress.Loopback);

        DistributionInstallationBinding bindingBForAuthority;
        RuntimeEnrollment enrollmentBForAuthority;
        License licenseBForAuthority;
        await using (var authorityBSetup = await factory.CreateDbContextAsync())
        {
            bindingBForAuthority = await authorityBSetup.DistributionInstallationBindings
                .SingleAsync(item => item.Id == bindingBId);
            enrollmentBForAuthority = await authorityBSetup.RuntimeEnrollments
                .SingleAsync(item => item.Id == enrollmentBId);
            licenseBForAuthority = await authorityBSetup.Licenses
                .SingleAsync(item => item.Id == licenseId);
        }
        var authorityBRequestId = Guid.NewGuid();
        var authorityBBody = AuthorityGenesisRequest(
            authorityBRequestId, fixture.ProductId, bindingBForAuthority,
            enrollmentBForAuthority, licenseBForAuthority, artifactDigest, now.UtcDateTime);
        var authorityB = await authorityRuntime.Service.IssueAuthorityGenerationV2Async(
            "website-step1", "s2s-runtime-test", Guid.NewGuid(), authorityBBody, null, null);
        Assert.True(
            authorityB.StatusCode is >= 200 and < 300,
            Encoding.UTF8.GetString(authorityB.ExactResponseBody));

        await using var check = await factory.CreateDbContextAsync();
        var persistedA = await check.DistributionInstallationBindings
            .SingleAsync(item => item.Id == fixture.BindingId);
        var seatA = await check.LicenseSeats.SingleAsync(item => item.Id == seatAId);
        var enrollmentA = await check.RuntimeEnrollments.SingleAsync(item => item.Id == enrollmentAId);
        var persistedB = await check.DistributionInstallationBindings
            .SingleAsync(item => item.Id == bindingBId);
        var seatB = await check.LicenseSeats.SingleAsync(item => item.Id == persistedB.LicenseSeatId);
        var enrollmentB = await check.RuntimeEnrollments.SingleAsync(item => item.Id == enrollmentBId);
        var generationA = await check.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleAsync(item => item.RequestId == authorityARequestId);
        var generationB = await check.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleAsync(item => item.RequestId == authorityBRequestId);
        var lineageA = await check.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
            .SingleAsync(item => item.AuthorityLineageId == generationA.AuthorityLineageId);
        var lineageB = await check.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
            .SingleAsync(item => item.AuthorityLineageId == generationB.AuthorityLineageId);
        Assert.Equal("invalidated", persistedA.State);
        Assert.Equal("seat_released", persistedA.InvalidationReason);
        Assert.False(seatA.IsActive);
        Assert.Equal("INVALIDATED", enrollmentA.State);
        Assert.Equal("seat_released", enrollmentA.InvalidationReason);
        Assert.Equal("active", persistedB.State);
        Assert.True(seatB.IsActive);
        Assert.Equal("ACTIVE", enrollmentB.State);
        Assert.NotEqual(seatAId, seatB.Id);
        Assert.NotEqual(fixture.BindingId, persistedB.Id);
        Assert.NotEqual(fixture.InstallationId, persistedB.InstallationId);
        Assert.NotEqual(enrollmentAId, enrollmentB.Id);
        Assert.NotEqual(enrollmentA.PublicKeySpkiSha256, enrollmentB.PublicKeySpkiSha256);
        Assert.NotEqual(enrollmentA.KeyThumbprint, enrollmentB.KeyThumbprint);
        Assert.NotEqual(hardwareA, seatB.HardwareId);
        Assert.NotEqual(grantA, persistedB.GrantRef);
        Assert.Equal(grantB, persistedB.GrantRef);
        Assert.NotEqual(lineageA.AuthorityLineageId, lineageB.AuthorityLineageId);
        Assert.Equal(seatAId, lineageA.LicenseSeatId);
        Assert.Equal(seatB.Id, lineageB.LicenseSeatId);
        Assert.Equal(grantA, lineageA.ProviderGrantRef);
        Assert.Equal(grantB, lineageB.ProviderGrantRef);
        Assert.Single(await check.DistributionBindingInvalidations.Where(item =>
            item.BindingId == fixture.BindingId && item.Reason == "seat_released").ToListAsync());
        Assert.True(await check.LicenseHistories.AnyAsync(item =>
            item.LicenseId == licenseId && item.Action == "RUNTIME_SEAT_RELEASED"));

        }
        finally
        {
            await DropDatabaseAsync(cleanupAdmin, database);
        }
    }

    /// <summary>Proves the vocabulary migration upgrades cleanly and refuses a lossy downgrade.</summary>
    [Fact]
    public async Task SeatReleaseReasonMigration_DownFailsClosedWhenHistoryExists()
    {
        var shared = await ProvisionAsync();
        const string previousMigration = "20260828095000_AddTkt000732SeatScopedAuthorityLineages";
        var database = "softlicence_tkt734_migration_" + Guid.NewGuid().ToString("N");
        var productId = Guid.NewGuid();
        var cleanupAdmin = new NpgsqlConnectionStringBuilder(shared.Admin)
        {
            Pooling = false,
            CommandTimeout = 120
        }.ConnectionString;
        await CreateDatabaseAsync(shared.Admin, database);
        try
        {
            var isolated = new NpgsqlConnectionStringBuilder(shared.Admin)
            {
                Database = database,
                Pooling = false
            }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(isolated).Options;
            await using (var db = new LicenseDbContext(options))
            {
                var migrator = db.GetService<IMigrator>();
                await migrator.MigrateAsync(previousMigration);
                await migrator.MigrateAsync();
                await migrator.MigrateAsync(previousMigration);
                await migrator.MigrateAsync();
                db.Products.Add(new Product
                {
                    Id = productId,
                    Name = "TKT-734 migration fixture",
                    PrivateKeyXml = string.Empty,
                    PublicKeyXml = string.Empty,
                    ApiSecret = Guid.NewGuid().ToString("N")
                });
                await db.SaveChangesAsync();
            }
            await using (var connection = new NpgsqlConnection(isolated))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $$"""
                    INSERT INTO public."DistributionBindingInvalidations"
                        ("Id","ProductId","GrantRefDigestSha256","ClientId","RequestId","Reason",
                         "OccurredAtUtc","Epoch","ReceivedAtUtc")
                    VALUES ('{{Guid.NewGuid():D}}','{{productId:D}}','{{new string('a', 64)}}',
                            'website-step1','{{Guid.NewGuid():D}}','seat_released',clock_timestamp(),1,clock_timestamp());
                    """);
            }
            await using (var downgrade = new LicenseDbContext(options))
            {
                var failure = await Assert.ThrowsAnyAsync<Exception>(() =>
                    downgrade.GetService<IMigrator>().MigrateAsync(previousMigration));
                var exception = Assert.IsType<PostgresException>(failure.GetBaseException());
                Assert.Equal("55000", exception.SqlState);
            }
            await using var verify = new NpgsqlConnection(isolated);
            await verify.OpenAsync();
            Assert.Equal(1L, await ScalarAsync<long>(verify, """
                SELECT count(*)::bigint AS "Value"
                FROM public."DistributionBindingInvalidations"
                WHERE "Reason" = 'seat_released';
                """));
        }
        finally
        {
            await DropDatabaseAsync(cleanupAdmin, database);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DistributionInvalidationMigration_OrphanOrAmbiguousActiveBindingFailsClosed(bool ambiguous)
    {
        var shared = await ProvisionAsync();
        var database = $"softlicence_distribution_owner_failure_{Guid.NewGuid():N}";
        await using (var connection = new NpgsqlConnection(shared.Admin))
        {
            await connection.OpenAsync();
            await ExecuteAsync(connection, $"CREATE DATABASE \"{database}\";");
        }
        var isolated = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(isolated).Options;
        await using var db = new LicenseDbContext(dbOptions);
        var migrator = db.GetService<IMigrator>();
        await migrator.MigrateAsync("20260719024400_AddRuntimeEnrollments");

        var productId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        await using (var seedDb = new LicenseDbContext(dbOptions))
        {
            seedDb.Products.Add(new Product
            {
                Id = productId,
                Name = "Historical invalid owner " + productId.ToString("N"),
                PrivateKeyXml = string.Empty,
                PublicKeyXml = string.Empty,
                ApiSecret = Guid.NewGuid().ToString("N")
            });
            await seedDb.SaveChangesAsync();
        }
        await using (var connection = new NpgsqlConnection(isolated))
        {
            await connection.OpenAsync();
            await ExecuteAsync(connection, "SET session_replication_role = replica;");
            await ExecuteAsync(connection, $$"""
                INSERT INTO public."DistributionInstallationBindings"
                    ("Id", "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId", "GrantRef",
                     "HandoffDigestSha256", "InstallationId", "HardwareIdHash", "Version",
                     "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256",
                     "CoreSha256", "ApprovedBinariesSource", "State", "BoundAtUtc")
                VALUES
                    ('{{bindingId:D}}', '{{productId:D}}', '{{Guid.NewGuid():D}}', '{{Guid.NewGuid():D}}',
                     '{{Guid.NewGuid():D}}', '{{Guid.NewGuid():D}}', '{{new string('a', 64)}}',
                     '{{Guid.NewGuid():D}}', '{{new string('b', 64)}}', '2.2.844', 'test.exe',
                     '{{new string('c', 64)}}', '{{new string('d', 64)}}', '{{new string('e', 64)}}',
                     '{{new string('f', 64)}}', 'release', 'active', clock_timestamp());
                """);
            if (ambiguous)
            {
                foreach (var clientId in new[] { "website-step1", "other-authorized-client" })
                {
                    await using var request = connection.CreateCommand();
                    request.CommandText = """
                        INSERT INTO public."DistributionBindingRequests"
                            ("Id", "ClientId", "RequestId", "Operation", "PayloadDigest", "BindingId", "ResponseJson", "CreatedAtUtc")
                        VALUES (@id, @client, @request, 'finalize_binding', @digest, @binding, '{}', clock_timestamp());
                        """;
                    request.Parameters.AddWithValue("id", Guid.NewGuid());
                    request.Parameters.AddWithValue("client", clientId);
                    request.Parameters.AddWithValue("request", Guid.NewGuid().ToString("D"));
                    request.Parameters.AddWithValue("digest", Sha256(clientId));
                    request.Parameters.AddWithValue("binding", bindingId);
                    Assert.Equal(1, await request.ExecuteNonQueryAsync());
                }
            }
            await ExecuteAsync(connection, "SET session_replication_role = origin;");
        }

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => migrator.MigrateAsync());
        var postgres = Assert.IsType<PostgresException>(exception.InnerException);
        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, postgres.SqlState);
        Assert.Contains("exactly one finalize_binding client", postgres.MessageText, StringComparison.Ordinal);
        await using var verify = new NpgsqlConnection(isolated);
        await verify.OpenAsync();
        Assert.Equal(0L, await ScalarAsync<long>(verify,
            "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'DistributionGrantOwnerships';"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task DistributionInvalidation_ConcurrentWithFinalize_NeverLeavesActiveBinding(int iteration)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var now = new DateTimeOffset(2026, 7, 19, 8, 30, 0, TimeSpan.Zero);
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var issue = await service.IssueEntitlementAsync("website-step1", Sha256("issue-" + fixture.GrantRef), new()
        {
            Schema = DistributionInstallationBindingService.IssueV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(fixture.GrantRef)
        });
        var finalize = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = fixture.GrantRef,
            HandoffDigestSha256 = Sha256("handoff-" + fixture.GrantRef),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = issue.Response.EntitlementRef,
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = fixture.HardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "distribution-race.exe",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };
        var invalidate = new DistributionInstallationInvalidationRequest
        {
            Schema = DistributionInstallationBindingService.InvalidationSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            GrantRefDigestSha256 = Sha256(fixture.GrantRef),
            Reason = "grant_revoked",
            OccurredAtUtc = FormatUtc(now.AddMinutes(-1)),
            Epoch = 1
        };

        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finalizeTask = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256($"finalize-{iteration}-{fixture.GrantRef}"), finalize));
        });
        var invalidateTask = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.InvalidateAsync(
                "website-step1", Sha256($"invalidate-{iteration}-{fixture.GrantRef}"), invalidate));
        });
        start.SetResult();
        await Task.WhenAll(finalizeTask, invalidateTask);
        var finalizeOutcome = await finalizeTask;
        var invalidateOutcome = await invalidateTask;

        await using var check = await factory.CreateDbContextAsync();
        Assert.False(await check.DistributionInstallationBindings.AnyAsync(candidate =>
            candidate.ProductId == fixture.ProductId && candidate.State == "active"));
        Assert.Single(await check.DistributionBindingInvalidations.Where(candidate =>
            candidate.ProductId == fixture.ProductId).ToListAsync());
        Assert.Null(invalidateOutcome.Error);
        if (finalizeOutcome.Error is DistributionOperationException operation)
            Assert.Equal("binding_invalidated", operation.ErrorCode);
    }

    [Fact]
    public async Task DistributionEntitlementV3_SubMicrosecondClock_FinalizesAfterPostgreSqlRoundTrip()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var now = new DateTimeOffset(2026, 7, 30, 13, 13, 43, TimeSpan.Zero)
            .AddTicks(9_958_927);
        var dataProtectionProvider = new EphemeralDataProtectionProvider();
        var service = new DistributionInstallationBindingService(
            factory, dataProtectionProvider, new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var subjectRef = Convert.ToBase64String(SHA256.HashData("postgres-v3-subject"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var issue = await service.IssueEntitlementAsync("website-step1", Sha256("postgres-v3-issue"), new()
        {
            Schema = DistributionInstallationBindingService.IssueV3Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(fixture.GrantRef),
            SubjectRef = subjectRef
        });
        var protector = dataProtectionProvider.CreateProtector("SoftLicence.DistributionEntitlement.v1");
        var issuedPayload = protector.Unprotect(issue.Response.EntitlementRef);
        Assert.Contains("2026-07-30T13:13:43.9958920Z", issuedPayload, StringComparison.Ordinal);
        Assert.Contains(issue.Response.ExpiresAtUtc, issuedPayload, StringComparison.Ordinal);
        var historicalPayload = issuedPayload
            .Replace("2026-07-30T13:13:43.9958920Z", FormatUtc(now), StringComparison.Ordinal)
            .Replace(issue.Response.ExpiresAtUtc, FormatUtc(now.AddHours(2)), StringComparison.Ordinal);
        Assert.Contains(FormatUtc(now), historicalPayload, StringComparison.Ordinal);
        Assert.Contains(FormatUtc(now.AddHours(2)), historicalPayload, StringComparison.Ordinal);
        var nextMicrosecond = now.AddTicks(3);
        var nextMicrosecondPayload = issuedPayload
            .Replace("2026-07-30T13:13:43.9958920Z", FormatUtc(nextMicrosecond), StringComparison.Ordinal)
            .Replace(issue.Response.ExpiresAtUtc, FormatUtc(nextMicrosecond.AddHours(2)), StringComparison.Ordinal);
        var finalize = new DistributionInstallationFinalizeRequest
        {
            Schema = DistributionInstallationBindingService.FinalizeSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            GrantRef = fixture.GrantRef,
            HandoffDigestSha256 = Sha256("postgres-v3-handoff-" + fixture.GrantRef),
            HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
            HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
            DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
            ProductId = fixture.ProductId.ToString("D"),
            EntitlementRef = protector.Protect(nextMicrosecondPayload),
            InstallationId = Guid.NewGuid().ToString("D"),
            HardwareId = fixture.HardwareId,
            Release = new DistributionReleaseEvidence
            {
                Version = fixture.Version,
                InstallerFilename = "distribution-v3-postgresql.exe",
                InstallerSha256 = new string('f', 64)
            },
            Binaries =
            [
                new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
            ]
        };

        var nextMicrosecondRejection = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync("website-step1", Sha256("postgres-v3-next-microsecond"), finalize));
        Assert.Equal("entitlement_ineligible", nextMicrosecondRejection.ErrorCode);
        finalize.RequestId = Guid.NewGuid().ToString("D");
        finalize.EntitlementRef = protector.Protect(historicalPayload);
        var finalized = await service.FinalizeAsync(
            "website-step1", Sha256("postgres-v3-finalize"), finalize);

        Assert.Equal("2026-07-30T15:13:43.9958920Z", issue.Response.ExpiresAtUtc);
        Assert.Equal("active", finalized.Response.State);
        await using var verify = await factory.CreateDbContextAsync();
        Assert.Equal("finalized", (await verify.DistributionEntitlements.SingleAsync(candidate =>
            candidate.LicenseId == fixture.LicenseId)).State);
    }

    /// <summary>Two initial claims compete for the last multi-seat slot without replacing the untouched capacity witness.</summary>
    [Fact]
    public async Task DistributionFinalize_ConcurrentInitialSeatClaims_RespectLicenseCapacity()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory, includeSeat: false);
        var now = new DateTimeOffset(2026, 7, 26, 9, 30, 0, TimeSpan.Zero);
        var witnessId = Guid.NewGuid();
        await using (var seed = await factory.CreateDbContextAsync())
        {
            (await seed.Licenses.SingleAsync(row => row.Id == fixture.LicenseId)).MaxSeats = 2;
            seed.LicenseSeats.Add(new LicenseSeat { Id = witnessId, LicenseId = fixture.LicenseId,
                HardwareId = "CAPACITY-WITNESS", IsActive = true, FirstActivatedAt = now.AddDays(-1).UtcDateTime });
            await seed.SaveChangesAsync();
        }
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grants = new[] { fixture.GrantRef, Guid.NewGuid().ToString("D") };
        var hardwares = new[] { fixture.HardwareId, fixture.HardwareId + "-OTHER" };
        var finalizes = new List<DistributionInstallationFinalizeRequest>();
        for (var index = 0; index < grants.Length; index++)
        {
            var grant = grants[index];
            var issue = await service.IssueEntitlementAsync("website-step1", Sha256("issue-" + grant), new()
            {
                Schema = DistributionInstallationBindingService.IssueV2Schema,
                RequestId = Guid.NewGuid().ToString("D"),
                ProductId = fixture.ProductId.ToString("D"),
                SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
                GrantRefDigestSha256 = Sha256(grant)
            });
            finalizes.Add(new DistributionInstallationFinalizeRequest
            {
                Schema = DistributionInstallationBindingService.FinalizeSchema,
                RequestId = Guid.NewGuid().ToString("D"),
                GrantRef = grant,
                HandoffDigestSha256 = Sha256("handoff-" + grant),
                HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-10)),
                HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(30)),
                DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-5)),
                ProductId = fixture.ProductId.ToString("D"),
                EntitlementRef = issue.Response.EntitlementRef,
                InstallationId = Guid.NewGuid().ToString("D"),
                HardwareId = hardwares[index],
                Release = new DistributionReleaseEvidence
                {
                    Version = fixture.Version,
                    InstallerFilename = "distribution-seat-race.exe",
                    InstallerSha256 = new string('f', 64)
                },
                Binaries =
                [
                    new() { Key = "FP_EXE", Sha256 = new string('a', 64) },
                    new() { Key = "FP_DLL", Sha256 = new string('b', 64) },
                    new() { Key = "FP_CORE", Sha256 = new string('c', 64) }
                ]
            });
        }

        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = finalizes.Select((request, index) => Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.FinalizeAsync(
                "website-step1", Sha256("finalize-seat-race-" + index), request));
        })).ToArray();
        start.SetResult();
        var outcomes = await Task.WhenAll(tasks);

        Assert.Single(outcomes, outcome => outcome.Error == null);
        var rejection = Assert.IsType<DistributionOperationException>(
            Assert.Single(outcomes, outcome => outcome.Error != null).Error);
        Assert.Equal("seat_limit_reached", rejection.ErrorCode);
        await using var check = await factory.CreateDbContextAsync();
        var active = await check.LicenseSeats.Where(candidate =>
            candidate.LicenseId == fixture.LicenseId && candidate.IsActive).ToListAsync();
        Assert.Equal(2, active.Count);
        var witness = Assert.Single(active, row => row.Id == witnessId);
        Assert.Equal("CAPACITY-WITNESS", witness.HardwareId);
        Assert.Equal(now.AddDays(-1).UtcDateTime, witness.FirstActivatedAt);
        Assert.Null(witness.UnlinkedAt);
        Assert.Single(active, row => hardwares.Contains(row.HardwareId));
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.LicenseId == fixture.LicenseId && candidate.State == "active").ToListAsync());
    }

    [Fact]
    public async Task DistributionIssueV2_ConcurrentInvalidationConvergesAfterBoundedRetry()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var now = new DateTimeOffset(2026, 7, 19, 8, 30, 0, TimeSpan.Zero);
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var grantDigest = Sha256(fixture.GrantRef);
        var issueRequest = new DistributionEntitlementIssueRequest
        {
            Schema = DistributionInstallationBindingService.IssueV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
            GrantRefDigestSha256 = grantDigest
        };
        var invalidationRequest = new DistributionInstallationInvalidationRequest
        {
            Schema = DistributionInstallationBindingService.InvalidationSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            GrantRefDigestSha256 = grantDigest,
            Reason = "grant_revoked",
            OccurredAtUtc = FormatUtc(now.AddMinutes(-1)),
            Epoch = 1
        };
        var issueDigest = Sha256("issue-race-" + fixture.GrantRef);
        var invalidationDigest = Sha256("invalidate-race-" + fixture.GrantRef);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var issueTask = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.IssueEntitlementAsync(
                "website-step1", issueDigest, issueRequest));
        });
        var invalidateTask = Task.Run(async () =>
        {
            await start.Task;
            return await CaptureAsync(() => service.InvalidateAsync(
                "website-step1", invalidationDigest, invalidationRequest));
        });
        start.SetResult();
        await Task.WhenAll(issueTask, invalidateTask);
        var issueOutcome = await issueTask;
        var invalidationOutcome = await invalidateTask;

        Assert.Null(issueOutcome.Error);
        if (invalidationOutcome.Error != null)
        {
            var operation = Assert.IsType<DistributionOperationException>(invalidationOutcome.Error);
            Assert.Equal("grant_ownership_mismatch", operation.ErrorCode);
            var retry = await service.InvalidateAsync(
                "website-step1", invalidationDigest, invalidationRequest);
            Assert.False(retry.Idempotent);
        }

        await using var check = await factory.CreateDbContextAsync();
        var owner = await check.DistributionGrantOwnerships.SingleAsync(candidate =>
            candidate.ProductId == fixture.ProductId);
        Assert.Equal("website-step1", owner.ClientId);
        Assert.Equal("issue_v2", owner.Source);
        Assert.Single(await check.DistributionBindingInvalidations.Where(candidate =>
            candidate.ProductId == fixture.ProductId).ToListAsync());
        Assert.Empty(await check.DistributionInstallationBindings.Where(candidate =>
            candidate.ProductId == fixture.ProductId).ToListAsync());
    }

    [Fact]
    public async Task DistributionIssueV2_SecondClientCannotClaimOwnedGrant()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var now = new DateTimeOffset(2026, 7, 19, 8, 30, 0, TimeSpan.Zero);
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now),
            TestHardwareAuthorityAliasResolver.Instance);
        var request = new DistributionEntitlementIssueRequest
        {
            Schema = DistributionInstallationBindingService.IssueV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
            GrantRefDigestSha256 = Sha256(fixture.GrantRef)
        };
        await service.IssueEntitlementAsync("website-step1", Sha256("owner-" + fixture.GrantRef), request);
        request.RequestId = Guid.NewGuid().ToString("D");

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.IssueEntitlementAsync("other-website", Sha256("other-" + fixture.GrantRef), request));

        Assert.Equal("grant_ownership_conflict", exception.ErrorCode);
        await using var check = await factory.CreateDbContextAsync();
        Assert.Equal("website-step1", (await check.DistributionGrantOwnerships.SingleAsync(candidate =>
            candidate.ProductId == fixture.ProductId)).ClientId);
    }

    [Fact]
    public async Task HardwareBan_MixedCaseLookup_UsesFunctionalIndex()
    {
        var connections = await ProvisionAsync();
        await using var connection = new NpgsqlConnection(connections.App);
        await connection.OpenAsync();
        await using (var insert = connection.CreateCommand())
        {
            insert.CommandText = """
                INSERT INTO public."BannedHardwareIds"
                    ("Id", "HardwareId", "BannedAt", "Reason", "IsActive")
                VALUES (gen_random_uuid(), 'mixed-case-hwid', clock_timestamp(), 'runtime test', true);
                """;
            await insert.ExecuteNonQueryAsync();
        }
        Assert.True(await ScalarAsync<bool>(connection, """
            SELECT EXISTS (SELECT 1 FROM public."BannedHardwareIds"
                WHERE upper("HardwareId") = 'MIXED-CASE-HWID' AND "ProductId" IS NULL);
            """));

        await ExecuteAsync(connection, "SET enable_seqscan = off;");
        var plan = string.Join('\n', await QueryStringsAsync(connection, """
            EXPLAIN (COSTS OFF)
            SELECT 1 FROM public."BannedHardwareIds"
            WHERE upper("HardwareId") = 'MIXED-CASE-HWID' AND "ProductId" IS NULL;
            """));
        Assert.Contains("IX_BannedHardwareIds_UpperHardwareId_ProductId", plan, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProductionApplicationRole_HasRuntimeAclWithMigrationReadWithoutAuthorityDml()
    {
        var connections = await ProvisionAsync();
        var app = new NpgsqlConnectionStringBuilder(connections.Admin)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only"
        }.ConnectionString;
        await using var connection = new NpgsqlConnection(app);
        await connection.OpenAsync();

        Assert.Equal("softlicence_app", await ScalarAsync<string>(connection, "SELECT current_user;"));
        Assert.True(await ScalarAsync<bool>(connection, """
            SELECT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb
                AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
            FROM pg_catalog.pg_roles WHERE rolname = current_user;
            """));
        Assert.True(await ScalarAsync<bool>(connection,
            "SELECT pg_catalog.has_table_privilege(current_user, 'public.\"Products\"', 'SELECT,INSERT,UPDATE,DELETE');"));
        Assert.True(await ScalarAsync<bool>(connection,
            "SELECT pg_catalog.has_table_privilege(current_user, 'public.\"__EFMigrationsHistory\"', 'SELECT');"));
        Assert.False(await ScalarAsync<bool>(connection,
            "SELECT pg_catalog.has_table_privilege(current_user, 'public.\"RuntimeEnrollmentAuthorityStates\"', 'INSERT,UPDATE,DELETE,TRUNCATE');"));
        Assert.False(await ScalarAsync<bool>(connection,
            "SELECT pg_catalog.has_table_privilege(current_user, 'public.\"RuntimeEnrollmentKeyRegistries\"', 'INSERT,UPDATE,DELETE,TRUNCATE');"));
        Assert.False(await ScalarAsync<bool>(connection,
            "SELECT pg_catalog.pg_has_role(current_user, 'softlicence_runtime_authority_owner', 'MEMBER');"));

        var authority = new RuntimeEnrollmentAuthorityService(
            new TestDbFactory(app),
            Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));
        await authority.ValidateInfrastructureAsync();
    }

    [Fact]
    public async Task FreshRegistryProvisioner_InitializesOnceAndThenOnlyValidates()
    {
        var connections = await ProvisionIsolatedAsync();
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var options = RuntimeOptions(
            Guid.Parse("11111111-1111-4111-8111-111111111111"),
            active,
            next);

        await RuntimeEnrollmentKeyRegistryProvisioner.InitializeOrValidateAsync(connections.Admin, options);
        await RuntimeEnrollmentKeyRegistryProvisioner.InitializeOrValidateAsync(connections.Admin, options);

        var registry = new RuntimeEnrollmentKeyRegistryService(
            new TestDbFactory(connections.App),
            Options.Create(options));
        await registry.ValidateAsync();
    }

    [Fact]
    public async Task ExistingMismatchedRegistry_ProvisionerFailsWithoutMutation()
    {
        var connections = await ProvisionIsolatedAsync();
        using var active = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        var options = RuntimeOptions(
            Guid.Parse("22222222-2222-4222-8222-222222222222"),
            active,
            next);

        await RuntimeEnrollmentKeyRegistryProvisioner.InitializeOrValidateAsync(connections.Admin, options);
        await using var verify = new NpgsqlConnection(connections.Admin);
        await verify.OpenAsync();
        var originalDigest = await ScalarAsync<string>(verify, """
            SELECT "MaterialDigestSha256"
            FROM public."RuntimeEnrollmentKeyRegistries"
            WHERE "Purpose" = 'encryption' AND "State" = 'active';
            """);
        options.Encryption.Keys[0].KeyBase64 = Convert.ToBase64String(
            SHA256.HashData("unexpected-runtime-test-aes-key"u8.ToArray()));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RuntimeEnrollmentKeyRegistryProvisioner.InitializeOrValidateAsync(connections.Admin, options));

        Assert.Equal(originalDigest, await ScalarAsync<string>(verify, """
            SELECT "MaterialDigestSha256"
            FROM public."RuntimeEnrollmentKeyRegistries"
            WHERE "Purpose" = 'encryption' AND "State" = 'active';
            """));
    }

    [Fact]
    public async Task RefreshPendingChallenge_AfterCrashAndExpiry_RotatesOnceAndConfirmsOnlyNewChallenge()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        var enrollmentId = scenario.EnrollmentId;
        var oldChallenge = scenario.Prepared.Challenge;

        await using (var expire = await scenario.Factory.CreateDbContextAsync())
        {
            var row = await expire.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == enrollmentId);
            row.ChallengeExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
            await expire.SaveChangesAsync();
        }

        var refresh = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(oldChallenge),
            ExpectedSecurityEpoch = 1
        };
        var refreshDigest = Sha256("refresh-expired-request");
        var refreshed = await scenario.Runtime.RefreshPendingAsync(
            "website-step1", refreshDigest, refresh);
        var replay = await scenario.Runtime.RefreshPendingAsync(
            "website-step1", refreshDigest, refresh);

        Assert.False(refreshed.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(refreshed.ExactResponseBody, replay.ExactResponseBody);
        Assert.NotEqual(oldChallenge, refreshed.Response.Challenge);
        Assert.Equal(enrollmentId.ToString("D"), refreshed.Response.EnrollmentId);
        Assert.Equal(RuntimeEnrollmentService.RefreshV2ResponseSchema, refreshed.Response.Schema);
        Assert.Equal(1, refreshed.Response.SecurityEpoch);

        var oldPrepare = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.PrepareAsync("website-step1", scenario.PrepareDigest, scenario.PrepareRequest));
        Assert.Equal(StatusCodes.Status409Conflict, oldPrepare.StatusCode);
        Assert.Equal("prepare_superseded", oldPrepare.ErrorCode);

        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("refresh-expired-confirm");
        var oldProof = Proof(scenario.EnrollmentKey, "confirm", enrollmentId, scenario.Options.ConfirmAudience,
            oldChallenge, confirmDigest);
        var oldRejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => scenario.Runtime.ConfirmAsync(
            enrollmentId, confirmDigest, confirm, oldProof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status401Unauthorized, oldRejected.StatusCode);

        var newProof = Proof(scenario.EnrollmentKey, "confirm", enrollmentId, scenario.Options.ConfirmAudience,
            refreshed.Response.Challenge, confirmDigest);
        var confirmed = await scenario.Runtime.ConfirmAsync(
            enrollmentId, confirmDigest, confirm, newProof, IPAddress.Loopback);
        Assert.Equal("active", confirmed.Response.Status);
    }

    /// <summary>
    /// A licence policy and same-seat hardware update advance the global lease epoch
    /// without minting a new bootstrap credential. Refresh and Confirm preserve the
    /// authorization lineage through a successful Capability and its exact replay. A later
    /// commercial denial rejects that replay without changing the credential or proof history.
    /// </summary>
    [Fact]
    public async Task RefreshPendingChallenge_CommercialEpochBump_PreservesBootstrapLineageThroughConfirm()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        long historicalEpoch;
        long globalEpoch;
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            historicalEpoch = (await db.RuntimeEnrollments.SingleAsync()).AuthorityEpoch;
            globalEpoch = await db.RuntimeEnrollmentAuthorityStates.Select(row => row.Epoch).SingleAsync();
            var license = await db.Licenses.SingleAsync();
            license.MaxSeats += 1;
            var seat = await db.LicenseSeats.SingleAsync();
            seat.HardwareId = "refresh-current-seat-" + Guid.NewGuid().ToString("N");
            await db.SaveChangesAsync();
        }
        var refresh = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshV2Schema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge),
            ExpectedSecurityEpoch = 1
        };
        var digest = Sha256("refresh-commercial-epoch");
        var refreshed = await scenario.Runtime.RefreshPendingAsync("website-step1", digest, refresh);
        var replay = await scenario.Runtime.RefreshPendingAsync("website-step1", digest, refresh);
        Assert.False(refreshed.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(refreshed.ExactResponseBody, replay.ExactResponseBody);

        var confirm = new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1
        };
        var confirmDigest = Sha256("confirm-after-commercial-epoch");
        var proof = Proof(scenario.EnrollmentKey, "confirm", scenario.EnrollmentId,
            scenario.Options.ConfirmAudience, refreshed.Response.Challenge, confirmDigest);
        var activated = await scenario.Runtime.ConfirmAsync(
            scenario.EnrollmentId, confirmDigest, confirm, proof, IPAddress.Loopback);
        Assert.Equal("active", activated.Response.Status);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verify.RuntimeEnrollments.SingleAsync();
        var authorization = await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        Assert.True(await verify.RuntimeEnrollmentAuthorityStates.Select(row => row.Epoch).SingleAsync() > globalEpoch);
        Assert.Equal(historicalEpoch, enrollment.AuthorityEpoch);
        Assert.Equal(historicalEpoch, authorization.AuthorityEpoch);
        Assert.Equal("CONSUMED", authorization.State);
        Assert.Equal(1, enrollment.Epoch);
        Assert.Equal(1, enrollment.SecurityEpoch);

        var capabilityRequest = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            InstallationId = scenario.Fixture.InstallationId,
            ReleaseVersion = scenario.Fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var capabilityDigest = Sha256("capability-after-commercial-epoch");
        var capabilityProof = Proof(scenario.EnrollmentKey, "capability", scenario.EnrollmentId,
            capabilityRequest.Audience, "-", capabilityDigest);
        var capability = await scenario.Runtime.CreateCapabilityAsync(
            scenario.EnrollmentId, capabilityDigest, capabilityRequest, capabilityProof, IPAddress.Loopback);
        Assert.NotNull(capability.Response);
        var capabilityReplay = await scenario.Runtime.CreateCapabilityAsync(
            scenario.EnrollmentId, capabilityDigest, capabilityRequest, capabilityProof, IPAddress.Loopback);
        Assert.True(capabilityReplay.Idempotent);
        Assert.Equal(capability.ExactResponseBody, capabilityReplay.ExactResponseBody);
        await using (var afterCapability = await scenario.Factory.CreateDbContextAsync())
        {
            Assert.Equal(historicalEpoch, (await afterCapability.RuntimeEnrollments.SingleAsync()).AuthorityEpoch);
            Assert.Equal(historicalEpoch,
                (await afterCapability.DistributionLicenseBootstrapAuthorizations.SingleAsync()).AuthorityEpoch);
            var license = await afterCapability.Licenses.SingleAsync();
            license.IsActive = false;
            await afterCapability.SaveChangesAsync();
        }
        var deniedReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.CreateCapabilityAsync(
                scenario.EnrollmentId, capabilityDigest, capabilityRequest, capabilityProof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, deniedReplay.StatusCode);
        Assert.Equal("authority_ineligible", deniedReplay.ErrorCode);
        Assert.Equal("assignment_missing", deniedReplay.DiagnosticCode);
        await using var afterDenial = await scenario.Factory.CreateDbContextAsync();
        var finalEnrollment = await afterDenial.RuntimeEnrollments.SingleAsync();
        Assert.Equal("ACTIVE", finalEnrollment.State);
        Assert.Equal(historicalEpoch, finalEnrollment.AuthorityEpoch);
        Assert.Equal(1, finalEnrollment.Epoch);
        Assert.Equal(1, finalEnrollment.SecurityEpoch);
        Assert.Equal(historicalEpoch,
            (await afterDenial.DistributionLicenseBootstrapAuthorizations.SingleAsync()).AuthorityEpoch);
        Assert.Single(await afterDenial.RuntimeEnrollmentProofNonces.Where(row =>
            row.EnrollmentId == scenario.EnrollmentId && row.Operation == "capability").ToListAsync());
    }

    /// <summary>
    /// Commercial denial after one valid refresh rejects both its exact replay and a new
    /// request without rotating that challenge or changing credential epochs.
    /// </summary>
    [Fact]
    public async Task RefreshPendingChallenge_CommercialDenial_PreservesCredentialAndChallenge()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        var refresh = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge)
        };
        var digest = Sha256("refresh-commercial-denial");
        var refreshed = await scenario.Runtime.RefreshPendingAsync("website-step1", digest, refresh);
        var next = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(refreshed.Response.Challenge)
        };
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.SingleAsync();
            license.IsActive = false;
            await db.SaveChangesAsync();
        }
        foreach (var (deniedRequest, deniedDigest) in new[]
                 {
                     (refresh, digest), (next, Sha256("refresh-commercial-denial-new"))
                 })
        {
            var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                scenario.Runtime.RefreshPendingAsync("website-step1", deniedDigest, deniedRequest));
            Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
            Assert.Equal("refresh_ineligible", denied.ErrorCode);
            Assert.Equal("assignment_missing", denied.DiagnosticCode);
        }
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verify.RuntimeEnrollments.SingleAsync();
        var authorization = await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        Assert.Equal("PENDING", enrollment.State);
        Assert.Equal(Sha256(refreshed.Response.Challenge), enrollment.ChallengeDigestSha256);
        Assert.Equal(1, enrollment.Epoch);
        Assert.Equal(1, enrollment.SecurityEpoch);
        Assert.Equal(authorization.AuthorityEpoch, enrollment.AuthorityEpoch);
        Assert.Equal("CONSUMED", authorization.State);
        Assert.Equal(2, await verify.RuntimeEnrollmentRequests.CountAsync(row =>
            row.EnrollmentId == enrollment.Id && row.Operation == "prepare"));
    }

    /// <summary>
    /// A concurrent policy transaction commits before Refresh can decide. The new challenge
    /// must not be created from the old eligible graph after that transaction commits.
    /// </summary>
    [Fact]
    public async Task RefreshPendingChallenge_ConcurrentLicenseRevocation_RejectsAtomically()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        var refresh = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge)
        };
        await using var mutation = await scenario.Factory.CreateDbContextAsync();
        await using var transaction = await mutation.Database.BeginTransactionAsync();
        var license = await mutation.Licenses.SingleAsync();
        license.IsActive = false;
        await mutation.SaveChangesAsync();

        var pending = scenario.Runtime.RefreshPendingAsync(
            "website-step1", Sha256("refresh-racing-revocation"), refresh);
        await Task.Delay(200);
        Assert.False(pending.IsCompleted);
        await transaction.CommitAsync();
        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => pending);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
        Assert.Equal("refresh_ineligible", denied.ErrorCode);

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verify.RuntimeEnrollments.SingleAsync();
        Assert.Equal("PENDING", enrollment.State);
        Assert.Equal(Sha256(scenario.Prepared.Challenge), enrollment.ChallengeDigestSha256);
        Assert.Single(await verify.RuntimeEnrollmentRequests.Where(row =>
            row.EnrollmentId == enrollment.Id && row.Operation == "prepare").ToListAsync());
    }

    /// <summary>
    /// A commercial read barrier held past the licence's database-time expiry cannot let
    /// Refresh use a timestamp captured before the wait. The refused attempt leaves the
    /// original challenge, request, quota and credential epoch state unchanged.
    /// </summary>
    [Fact]
    public async Task RefreshPendingChallenge_LicenseExpiresWhileCommercialBarrierWaits_RejectsWithoutMutation()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        DateTime expiresAtUtc;
        await using (var setup = await scenario.Factory.CreateDbContextAsync())
        {
            await setup.Database.OpenConnectionAsync();
            expiresAtUtc = (await RuntimeEnrollmentService.DatabaseNowAsync(
                setup, CancellationToken.None)).AddSeconds(5).UtcDateTime;
            var license = await setup.Licenses.SingleAsync();
            license.ExpirationDate = expiresAtUtc;
            await setup.SaveChangesAsync();
        }

        var request = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge)
        };
        await using var writer = new NpgsqlConnection(scenario.AdminConnectionString);
        await writer.OpenAsync();
        await using var transaction = await writer.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand(
                         "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", writer, transaction))
            await hold.ExecuteNonQueryAsync();
        var pending = scenario.Runtime.RefreshPendingAsync(
            "website-step1", Sha256("refresh-after-commercial-barrier-expiry"), request);
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
        var expiredBeforeRelease = false;
        for (var poll = 0; poll < 400 && !expiredBeforeRelease; poll++)
        {
            await using var clock = new NpgsqlCommand("SELECT pg_catalog.clock_timestamp();", observer);
            expiredBeforeRelease = (DateTime)(await clock.ExecuteScalarAsync())! >= expiresAtUtc.AddMilliseconds(100);
            if (!expiredBeforeRelease)
                await Task.Delay(20);
        }
        Assert.True(expiredBeforeRelease);
        Assert.False(pending.IsCompleted);
        await transaction.CommitAsync();

        var denied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => pending);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, denied.StatusCode);
        Assert.Equal("refresh_ineligible", denied.ErrorCode);
        Assert.Equal("commercial_authority_ineligible", denied.DiagnosticCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await verify.RuntimeEnrollments.SingleAsync();
        var authorization = await verify.DistributionLicenseBootstrapAuthorizations.SingleAsync();
        Assert.Equal("PENDING", enrollment.State);
        Assert.Equal(Sha256(scenario.Prepared.Challenge), enrollment.ChallengeDigestSha256);
        Assert.Null(enrollment.ChallengeConsumedAtUtc);
        Assert.Equal(1, enrollment.Epoch);
        Assert.Equal(1, enrollment.SecurityEpoch);
        Assert.Equal(authorization.AuthorityEpoch, enrollment.AuthorityEpoch);
        Assert.Equal("CONSUMED", authorization.State);
        Assert.Single(await verify.RuntimeEnrollmentRequests.Where(row =>
            row.EnrollmentId == enrollment.Id && row.Operation == "prepare").ToListAsync());
        Assert.Equal(0, await verify.RuntimeEnrollmentQuotas.CountAsync(row =>
            row.Scope == "refresh-binding" || row.Scope == "refresh-global"));
    }

    /// <summary>
    /// A missing seat behind the active assignment is storage corruption, not a commercial
    /// denial. Refresh must surface unavailable and keep the original challenge unchanged.
    /// </summary>
    [Fact]
    public async Task RefreshPendingChallenge_MissingAssignmentSeat_PreservesUnavailable()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var drop = new NpgsqlCommand("""
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
            await drop.ExecuteNonQueryAsync();
            await using var breakSeat = new NpgsqlCommand("""
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @missing
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            breakSeat.Parameters.AddWithValue("missing", Guid.NewGuid());
            breakSeat.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            Assert.Equal(1, await breakSeat.ExecuteNonQueryAsync());
        }
        var refresh = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge)
        };
        var unavailable = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RefreshPendingAsync(
                "website-step1", Sha256("refresh-missing-assignment-seat"), refresh));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("authority_unavailable", unavailable.ErrorCode);
        Assert.Equal("assignment_relation_missing", unavailable.DiagnosticCode);
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(Sha256(scenario.Prepared.Challenge),
            (await verify.RuntimeEnrollments.SingleAsync()).ChallengeDigestSha256);
    }

    [Fact]
    public async Task RefreshPendingChallenge_ConcurrentRequests_CreateOneAuthoritativeLineage()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        var enrollmentId = scenario.EnrollmentId;
        RuntimeEnrollmentRefreshRequest Request() => new()
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge)
        };
        var firstRequest = Request();
        var secondRequest = Request();

        var outcomes = await Task.WhenAll(
            CaptureAsync(scenario.Runtime.RefreshPendingAsync("website-step1", Sha256("refresh-concurrent-a"), firstRequest)),
            CaptureAsync(scenario.Runtime.RefreshPendingAsync("website-step1", Sha256("refresh-concurrent-b"), secondRequest)));

        Assert.Single(outcomes, outcome => outcome.Result != null);
        var rejected = Assert.IsType<RuntimeEnrollmentException>(
            Assert.Single(outcomes, outcome => outcome.Error != null).Error);
        Assert.Equal(StatusCodes.Status409Conflict, rejected.StatusCode);
        Assert.Equal("refresh_conflict", rejected.ErrorCode);
        await using var check = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await check.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == enrollmentId);
        Assert.Equal(Sha256(Assert.Single(outcomes, outcome => outcome.Result != null).Result!.Response.Challenge),
            enrollment.ChallengeDigestSha256);
        Assert.Equal(2, await check.RuntimeEnrollmentRequests.CountAsync(candidate =>
            candidate.EnrollmentId == enrollmentId && candidate.Operation == "prepare"));
    }

    [Fact]
    public async Task RefreshPendingChallenge_AfterConsumedBootstrap_PreservesAuthorityAndRejectsLegacy()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        var refresh = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge)
        };

        var refreshed = await scenario.Runtime.RefreshPendingAsync(
            "website-step1", Sha256("refresh-after-bootstrap-consumed"), refresh);
        Assert.False(refreshed.Idempotent);

        await using (var mutate = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await mutate.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
            var binding = await mutate.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            enrollment.SubjectRefDigestSha256 = null;
            binding.SubjectRefDigestSha256 = null;
            await mutate.SaveChangesAsync();
        }
        var legacy = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(refreshed.Response.Challenge)
        };
        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RefreshPendingAsync("website-step1", Sha256("refresh-legacy"), legacy));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refused.StatusCode);
        Assert.Equal("refresh_ineligible", refused.ErrorCode);
    }

    /// <summary>
    /// A consumed generation cannot refresh when its binding is revoked, its key or frozen
    /// authority epoch diverges, or its approved release evidence changes. The item-2 trigger
    /// already rejects impossible direct binding-version corruption before service validation.
    /// </summary>
    /// <param name="mutation">One persisted, structurally admissible authority divergence.</param>
    [Theory]
    [InlineData("binding-revoked")]
    [InlineData("runtime-key")]
    [InlineData("approved-binary")]
    [InlineData("authority-lineage")]
    public async Task RefreshPendingChallenge_ChangedAuthority_IsFailClosed(string mutation)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await scenario.ConsumeAsync();
        await using (var db = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await db.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            var binding = await db.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            if (mutation == "binding-revoked")
            {
                binding.State = "invalidated";
                binding.InvalidatedAtUtc = DateTime.UtcNow;
                binding.InvalidationReason = "test_revocation";
            }
            else if (mutation == "runtime-key")
            {
                enrollment.PublicKeySpkiSha256 = new string('f', 64);
            }
            else if (mutation == "authority-lineage")
            {
                enrollment.AuthorityEpoch += 1;
            }
            else
            {
                var binary = await db.ApprovedBinaries.FirstAsync(candidate =>
                    candidate.ProductId == scenario.Fixture.ProductId
                    && candidate.Version == scenario.Fixture.Version);
                binary.Hash = new string('f', 64);
            }
            await db.SaveChangesAsync();
        }
        var request = new RuntimeEnrollmentRefreshRequest
        {
            Schema = RuntimeEnrollmentService.RefreshSchema,
            RequestId = Guid.NewGuid().ToString("D"),
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = scenario.Fixture.ProductId.ToString("D"),
            BindingId = scenario.Fixture.BindingId.ToString("D"),
            EnrollmentId = scenario.EnrollmentId.ToString("D"),
            ExpectedChallengeDigestSha256 = Sha256(scenario.Prepared.Challenge)
        };

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            scenario.Runtime.RefreshPendingAsync("website-step1", Sha256("refresh-authority-" + mutation), request));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, refused.StatusCode);
        Assert.Equal("refresh_ineligible", refused.ErrorCode);
    }

    private static async Task<(string Admin, string App)> ProvisionAsync()
    {
        var admin = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(admin))
            throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES must target a fresh PostgreSQL 17 test database.");
        var builder = new NpgsqlConnectionStringBuilder(admin);
        var app = new NpgsqlConnectionStringBuilder(admin)
        {
            Username = "softlicence_runtime_test_app",
            Password = "runtime-test-only"
        }.ConnectionString;

        await ProvisioningLock.WaitAsync();
        try
        {
            if (!_provisioned)
            {
                await using var connection = new NpgsqlConnection(admin);
                await connection.OpenAsync();
                await ExecuteAsync(connection, """
                    DO $roles$
                    BEGIN
                        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_runtime_authority_owner') THEN
                            CREATE ROLE softlicence_runtime_authority_owner NOLOGIN;
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_runtime_test_app') THEN
                            CREATE ROLE softlicence_runtime_test_app LOGIN PASSWORD 'runtime-test-only';
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                            CREATE ROLE softlicence_app LOGIN PASSWORD 'runtime-production-role-test-only';
                        END IF;
                    END;
                    $roles$;
                    ALTER ROLE softlicence_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                        NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'runtime-production-role-test-only';
                    """);
                var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
                await using (var db = new LicenseDbContext(dbOptions))
                    await db.Database.MigrateAsync();
                await GrantApplicationRuntimePrivilegesAsync(connection);
                _provisioned = true;
            }
        }
        finally
        {
            ProvisioningLock.Release();
        }
        return (admin, app);
    }

    /// <summary>
    /// Proves a failure after isolated database creation but before lease ownership force-drops the exact
    /// generated database instead of leaving persistent PostgreSQL harness state.
    /// </summary>
    private static async Task AssertProvisioningFailureBeforeLeaseDropsDatabaseAsync()
    {
        var shared = await ProvisionAsync();
        string? generatedDatabase = null;
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ProvisionIsolatedAsync(database =>
            {
                generatedDatabase = database;
                throw new InvalidOperationException("Injected failure before lease ownership.");
            }));

        Assert.Equal("Injected failure before lease ownership.", failure.Message);
        Assert.NotNull(generatedDatabase);
        await using var connection = new NpgsqlConnection(shared.Admin);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = @database);",
            connection);
        command.Parameters.AddWithValue("database", generatedDatabase);
        Assert.False((bool)(await command.ExecuteScalarAsync())!);
    }

    /// <summary>
    /// Creates and migrates one uniquely named Runtime Enrollment database while reusing only the shared
    /// PostgreSQL server and roles. This method owns the generated name until provisioning returns: every
    /// creation, migration, or grant failure triggers a force-drop before the original failure is rethrown.
    /// After a successful return, the caller owns and must drop the returned database.
    /// </summary>
    /// <param name="afterDatabaseCreated">
    /// Optional test-only fault injection invoked after database creation and before migration.
    /// </param>
    /// <param name="targetMigration">Optional exact historical schema boundary; null migrates to the current schema. The returned database is always newly created.</param>
    /// <returns>Administrator and application-role connections targeting the generated database.</returns>
    /// <exception cref="AggregateException">
    /// Thrown when provisioning and the mandatory failure cleanup both fail, preserving both causes.
    /// </exception>
    private static async Task<(string Admin, string App)> ProvisionIsolatedAsync(
        Func<string, Task>? afterDatabaseCreated = null, string? targetMigration = null)
    {
        var shared = await ProvisionAsync();
        var database = $"softlicence_runtime_rotation_{Guid.NewGuid():N}";
        try
        {
            await using (var connection = new NpgsqlConnection(shared.Admin))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"CREATE DATABASE \"{database}\";");
            }
            if (afterDatabaseCreated is not null)
                await afterDatabaseCreated(database);
            var admin = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
            var app = new NpgsqlConnectionStringBuilder(admin)
            {
                Username = "softlicence_runtime_test_app",
                Password = "runtime-test-only"
            }.ConnectionString;
            var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
            await using (var db = new LicenseDbContext(dbOptions))
                await db.GetService<IMigrator>().MigrateAsync(targetMigration);
            await using (var connection = new NpgsqlConnection(admin))
            {
                await connection.OpenAsync();
                await GrantApplicationRuntimePrivilegesAsync(connection);
            }
            return (admin, app);
        }
        catch (Exception provisioningFailure)
        {
            try
            {
                await DropDatabaseAsync(shared.Admin, database);
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException(
                    "Isolated Runtime Enrollment provisioning and mandatory cleanup both failed.",
                    provisioningFailure,
                    cleanupFailure);
            }
            throw;
        }
    }

    /// <summary>
    /// Provisions one migrated database through the existing isolated harness and returns a lease that
    /// force-drops only that generated database when the owning test exits, including exceptional exits.
    /// The provisioning helper owns cleanup until it returns successfully; the lease owns cleanup after
    /// that handoff, so no created database exists without exactly one cleanup owner.
    /// </summary>
    /// <returns>An owned lease exposing administrator and application connections for the isolated database.</returns>
    private static async Task<IsolatedDatabaseLease> ProvisionCleanedIsolatedAsync()
    {
        var shared = await ProvisionAsync();
        var isolated = await ProvisionIsolatedAsync();
        return new IsolatedDatabaseLease(shared.Admin, isolated.Admin, isolated.App);
    }

    /// <summary>Owns one generated Runtime Enrollment test database and its guaranteed cleanup.</summary>
    private sealed class IsolatedDatabaseLease : IAsyncDisposable
    {
        /// <summary>Exact ASCII prefix used by <see cref="ProvisionIsolatedAsync"/> for generated databases.</summary>
        private const string DatabasePrefix = "softlicence_runtime_rotation_";

        /// <summary>Administrator connection outside the generated database; never logged or exposed.</summary>
        private readonly string _cleanupAdmin;

        /// <summary>Validated generated database identifier that is safe for the bounded quoted DROP statement.</summary>
        private readonly string _databaseName;

        /// <summary>
        /// Initializes ownership of one isolated database after validating that its identifier is exactly
        /// the harness prefix followed by one lowercase GUID in N format.
        /// </summary>
        /// <param name="cleanupAdmin">Administrator connection used only to drop the generated database.</param>
        /// <param name="admin">Administrator connection targeting the generated database.</param>
        /// <param name="app">Application-role connection targeting the generated database.</param>
        /// <exception cref="InvalidOperationException">Thrown when the isolated connection does not name a harness-generated database.</exception>
        internal IsolatedDatabaseLease(string cleanupAdmin, string admin, string app)
        {
            var databaseName = new NpgsqlConnectionStringBuilder(admin).Database;
            if (databaseName is null
                || !databaseName.StartsWith(DatabasePrefix, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Isolated Runtime Enrollment database identity is invalid.");
            }

            var suffix = databaseName[DatabasePrefix.Length..];
            if (!Guid.TryParseExact(suffix, "N", out var parsed)
                || !string.Equals(suffix, parsed.ToString("N"), StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Isolated Runtime Enrollment database identity is invalid.");
            }

            _cleanupAdmin = cleanupAdmin;
            _databaseName = databaseName;
            Admin = admin;
            App = app;
        }

        /// <summary>Gets the administrator connection targeting the owned isolated database.</summary>
        internal string Admin { get; }

        /// <summary>Gets the application-role connection targeting the owned isolated database.</summary>
        internal string App { get; }

        /// <summary>Force-drops the exact owned database and completes only after PostgreSQL confirms its absence.</summary>
        /// <returns>A value task representing the asynchronous cleanup.</returns>
        public ValueTask DisposeAsync() => new(DropDatabaseAsync(_cleanupAdmin, _databaseName));
    }

    private static async Task<(Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version)>
        SeedAuthorityAsync(
            IDbContextFactory<LicenseDbContext> factory,
            string version = "2.2.999",
            string allowedVersions = "2.2.*",
            string? initialHardwareId = null)
    {
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var seatId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        var hardwareId = initialHardwareId ?? "runtime-hwid-" + Guid.NewGuid().ToString("N");
        var hashes = new Dictionary<string, string>
        {
            ["FP_CORE"] = new string('c', 64),
            ["FP_DLL"] = new string('d', 64),
            ["FP_EXE"] = new string('e', 64)
        };
        var handoff = Sha256(Guid.NewGuid().ToString("D"));
        var installationId = Guid.NewGuid().ToString("D");
        await using var db = await factory.CreateDbContextAsync();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "Runtime product " + productId.ToString("N"),
            PrivateKeyXml = string.Empty,
            PublicKeyXml = string.Empty,
            ApiSecret = Guid.NewGuid().ToString("N")
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "Runtime",
            Slug = "runtime-" + productId.ToString("N")
        });
        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = "RUNTIME-" + Guid.NewGuid().ToString("N"),
            IsActive = true,
            MaxSeats = 1,
            AllowedVersions = allowedVersions,
            ExpirationDate = DateTime.UtcNow.AddDays(1)
        });
        db.LicenseSeats.Add(new LicenseSeat
        {
            Id = seatId,
            LicenseId = licenseId,
            HardwareId = hardwareId,
            IsActive = true
        });
        foreach (var item in hashes)
            db.ApprovedBinaries.Add(new ApprovedBinary
            {
                ProductId = productId,
                Version = version,
                Key = item.Key,
                Hash = item.Value,
                Source = ApprovedBinaryService.ReleaseSource
            });
        var grantRef = Guid.NewGuid().ToString("D");
        db.DistributionInstallationBindings.Add(new DistributionInstallationBinding
        {
            Id = bindingId,
            ProductId = productId,
            LicenseId = licenseId,
            LicenseSeatId = seatId,
            EntitlementId = Guid.NewGuid(),
            GrantRef = grantRef,
            GrantRefDigestSha256 = Sha256(grantRef),
            HandoffDigestSha256 = handoff,
            InstallationId = installationId,
            HardwareIdHash = Sha256(hardwareId),
            Version = version,
            InstallerFilename = $"TiaConnect-Setup_v{version}.msi",
            InstallerSha256 = new string('f', 64),
            ExecutableSha256 = hashes["FP_EXE"],
            NativeDllSha256 = hashes["FP_DLL"],
            CoreSha256 = hashes["FP_CORE"],
            ApprovedBinariesSource = "release",
            State = "active",
            BoundAtUtc = DateTime.UtcNow
        });
        db.DistributionBindingRequests.Add(new DistributionBindingRequest
        {
            ClientId = "website-step1",
            RequestId = Guid.NewGuid().ToString("D"),
            Operation = "finalize_binding",
            PayloadDigest = new string('b', 64),
            BindingId = bindingId,
            ResponseJson = "{}",
            CreatedAtUtc = DateTime.UtcNow
        });
        db.DistributionGrantOwnerships.Add(new DistributionGrantOwnership
        {
            ProductId = productId,
            GrantRefDigestSha256 = Sha256(grantRef),
            ClientId = "website-step1",
            Source = "finalize_v1",
            CreatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        return (productId, bindingId, handoff, installationId, version);
    }

    private static async Task<(Guid ProductId, Guid LicenseId, string HardwareId, string Version, string GrantRef)>
        SeedDistributionAuthorityWithoutBindingAsync(
            IDbContextFactory<LicenseDbContext> factory,
            bool includeSeat = true)
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var hardwareId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
        const string version = "2.2.844";
        await using var db = await factory.CreateDbContextAsync();
        db.Products.Add(new Product
        {
            Id = productId,
            Name = "Distribution race " + productId.ToString("N"),
            PrivateKeyXml = string.Empty,
            PublicKeyXml = string.Empty,
            ApiSecret = Guid.NewGuid().ToString("N")
        });
        db.LicenseTypes.Add(new LicenseType
        {
            Id = typeId,
            ProductId = productId,
            Name = "Distribution",
            Slug = "distribution-" + productId.ToString("N")
        });
        db.Licenses.Add(new License
        {
            Id = licenseId,
            ProductId = productId,
            LicenseTypeId = typeId,
            LicenseKey = "DIST-" + Guid.NewGuid().ToString("N"),
            IsActive = true,
            MaxSeats = 1,
            AllowedVersions = "2.2.*",
            ExpirationDate = DateTime.UtcNow.AddDays(1)
        });
        if (includeSeat)
        {
            db.LicenseSeats.Add(new LicenseSeat
            {
                Id = Guid.NewGuid(),
                LicenseId = licenseId,
                HardwareId = hardwareId,
                IsActive = true
            });
        }
        db.ApprovedBinaries.AddRange(
            new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_EXE", Hash = new string('a', 64), Source = "release" },
            new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_DLL", Hash = new string('b', 64), Source = "release" },
            new ApprovedBinary { ProductId = productId, Version = version, Key = "FP_CORE", Hash = new string('c', 64), Source = "release" });
        await db.SaveChangesAsync();
        return (productId, licenseId, hardwareId, version, Guid.NewGuid().ToString("D"));
    }

    private static async Task<(T? Result, Exception? Error)> CaptureAsync<T>(Func<Task<T>> action)
    {
        try
        {
            return (await action(), null);
        }
        catch (Exception exception)
        {
            return (default, exception);
        }
    }

    private static string FormatUtc(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);

    private static RuntimeEnrollmentOptions RuntimeOptions(Guid productId, RSA active, RSA next)
    {
        var activeId = "signing-" + Convert.ToHexStringLower(
            SHA256.HashData(active.ExportSubjectPublicKeyInfo()))[..16];
        var nextId = "signing-" + Convert.ToHexStringLower(
            SHA256.HashData(next.ExportSubjectPublicKeyInfo()))[..16];
        var signingKeys = new List<RuntimeCapabilitySigningKeyOptions>
        {
            new() { KeyId = activeId, Role = "active", PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(), PrivateKeyPem = active.ExportPkcs8PrivateKeyPem() },
            new() { KeyId = nextId, Role = "next", PublicKeyPem = next.ExportSubjectPublicKeyInfoPem() }
        };
        signingKeys.Sort((left, right) => string.CompareOrdinal(left.KeyId, right.KeyId));
        return new RuntimeEnrollmentOptions
        {
            Mode = "enabled",
            Issuer = "https://runtime.example.test",
            ConfirmAudience = "https://runtime.example.test",
            CanaryAudience = "https://runtime.example.test/api/health/ping",
            CanaryTriggers = ["RuntimeCheck_NativeDllSwapped"],
            IpPseudonymKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            CapabilitySigning = new RuntimeCapabilitySigningOptions
            {
                ActiveKeyId = activeId,
                Keys = signingKeys
            },
            Encryption = new RuntimeEncryptionOptions
            {
                ActiveKeyId = "enc-2026-01",
                Keys = [new() { KeyId = "enc-2026-01", KeyBase64 = Convert.ToBase64String(SHA256.HashData("runtime-test-aes-key"u8.ToArray())) }]
            },
            Products =
            [
                new()
                {
                    ProductId = productId.ToString("D"),
                    Capabilities =
                    [
                        new() { Audience = "https://broker.example.test", Scopes = ["runtime.execute"] },
                        new() { Audience = "https://runtime.example.test", Scopes = ["milestone:write"] }
                    ]
                }
            ]
        };
    }

    private static RuntimeEnrollmentOptions RotationOptions(
        Guid productId,
        int registryVersion,
        string activeEncryptionKeyId,
        IReadOnlyList<(string KeyId, byte[] Material)> encryptionKeys,
        IReadOnlyList<(RSA Key, string Role)> signingKeys)
    {
        var configuredSigning = signingKeys.Select(item => new RuntimeCapabilitySigningKeyOptions
        {
            KeyId = SigningKeyId(item.Key),
            Role = item.Role,
            PublicKeyPem = item.Key.ExportSubjectPublicKeyInfoPem(),
            PrivateKeyPem = item.Role == "active" ? item.Key.ExportPkcs8PrivateKeyPem() : null,
            RetainUntilUtc = item.Role == "previous" ? DateTimeOffset.UtcNow.AddDays(1) : null
        }).OrderBy(item => item.KeyId, StringComparer.Ordinal).ToList();
        return new RuntimeEnrollmentOptions
        {
            Mode = "enabled",
            Issuer = "https://runtime.example.test",
            ConfirmAudience = "https://runtime.example.test",
            CanaryAudience = "https://runtime.example.test/api/health/ping",
            CanaryTriggers = ["RuntimeCheck_NativeDllSwapped"],
            KeyRegistryVersion = registryVersion,
            IpPseudonymKeyBase64 = Convert.ToBase64String(SHA256.HashData("runtime-rotation-ip-key"u8.ToArray())),
            CapabilitySigning = new RuntimeCapabilitySigningOptions
            {
                ActiveKeyId = configuredSigning.Single(item => item.Role == "active").KeyId,
                Keys = configuredSigning
            },
            Encryption = new RuntimeEncryptionOptions
            {
                ActiveKeyId = activeEncryptionKeyId,
                Keys = encryptionKeys.Select(item => new RuntimeEncryptionKeyOptions
                {
                    KeyId = item.KeyId,
                    KeyBase64 = Convert.ToBase64String(item.Material)
                }).OrderBy(item => item.KeyId, StringComparer.Ordinal).ToList()
            },
            Products =
            [
                new RuntimeProductCapabilityOptions
                {
                    ProductId = productId.ToString("D"),
                    Capabilities =
                    [
                        new() { Audience = "https://broker.example.test", Scopes = ["runtime.execute"] },
                        new() { Audience = "https://runtime.example.test", Scopes = ["milestone:write"] }
                    ]
                }
            ]
        };
    }

    private static async Task RotateKeyRegistryAsync(
        string adminConnectionString,
        RuntimeEnrollmentOptions before,
        RuntimeEnrollmentOptions after)
    {
        Assert.Equal(before.KeyRegistryVersion + 1, after.KeyRegistryVersion);
        var previous = RuntimeEnrollmentKeyRegistryService.BuildExpected(before);
        var next = RuntimeEnrollmentKeyRegistryService.BuildExpected(after);
        Assert.All(previous.Keys, key => Assert.True(next.ContainsKey(key)));
        await using var admin = new NpgsqlConnection(adminConnectionString);
        await admin.OpenAsync();
        await using var transaction = await admin.BeginTransactionAsync();
        foreach (var key in next)
        {
            if (!previous.TryGetValue(key.Key, out var old))
            {
                await using var insert = admin.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO public."RuntimeEnrollmentKeyRegistries"
                        ("Purpose", "KeyId", "MaterialDigestSha256", "State", "Epoch", "CreatedAtUtc",
                         "RetainUntilUtc")
                    VALUES (@purpose, @keyId, @digest, @state, 1, clock_timestamp(), @retainUntilUtc);
                    """;
                insert.Parameters.AddWithValue("purpose", key.Key.Purpose);
                insert.Parameters.AddWithValue("keyId", key.Key.KeyId);
                insert.Parameters.AddWithValue("digest", key.Value.Digest);
                insert.Parameters.AddWithValue("state", key.Value.State);
                insert.Parameters.AddWithValue(
                    "retainUntilUtc",
                    key.Value.RetainUntilUtc ?? (object)DBNull.Value);
                Assert.Equal(1, await insert.ExecuteNonQueryAsync());
                continue;
            }
            Assert.Equal(old.Digest, key.Value.Digest);
            if (old.State == key.Value.State)
                continue;
            await using var update = admin.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE public."RuntimeEnrollmentKeyRegistries"
                SET "State"=@newState, "Epoch"="Epoch"+1, "RetainUntilUtc"=@retainUntilUtc
                WHERE "Purpose"=@purpose AND "KeyId"=@keyId
                  AND "MaterialDigestSha256"=@digest AND "State"=@oldState;
                """;
            update.Parameters.AddWithValue("newState", key.Value.State);
            update.Parameters.AddWithValue("purpose", key.Key.Purpose);
            update.Parameters.AddWithValue("keyId", key.Key.KeyId);
            update.Parameters.AddWithValue("digest", key.Value.Digest);
            update.Parameters.AddWithValue("oldState", old.State);
            update.Parameters.AddWithValue(
                "retainUntilUtc",
                key.Value.RetainUntilUtc ?? (object)DBNull.Value);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }
        await using (var version = admin.CreateCommand())
        {
            version.Transaction = transaction;
            version.CommandText = """
                UPDATE public."RuntimeEnrollmentKeyRegistries"
                SET "Epoch"="Epoch"+1
                WHERE "Purpose"='registry-version' AND "KeyId"='global' AND "Epoch"=@expected;
                """;
            version.Parameters.AddWithValue("expected", before.KeyRegistryVersion);
            Assert.Equal(1, await version.ExecuteNonQueryAsync());
        }
        await transaction.CommitAsync();
    }

    private static string SigningKeyId(RSA key) => "signing-" + Convert.ToHexStringLower(
        SHA256.HashData(key.ExportSubjectPublicKeyInfo()))[..16];

    private static void AssertTokenVerified(string token, RSA key)
    {
        var segments = token.Split('.');
        Assert.Equal(3, segments.Length);
        Assert.True(key.VerifyData(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]),
            DecodeBase64Url(segments[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    private static async Task UpsertKeyRegistryAsync(string adminConnectionString, RuntimeEnrollmentOptions options)
    {
        var expected = RuntimeEnrollmentKeyRegistryService.BuildExpected(options);
        await using var admin = new NpgsqlConnection(adminConnectionString);
        await admin.OpenAsync();
        foreach (var key in expected)
        {
            await using var command = admin.CreateCommand();
            command.CommandText = """
                INSERT INTO public."RuntimeEnrollmentKeyRegistries"
                    ("Purpose", "KeyId", "MaterialDigestSha256", "State", "Epoch", "CreatedAtUtc",
                     "RetainUntilUtc")
                VALUES (@purpose, @keyId, @digest, @state, 1, clock_timestamp(), @retainUntilUtc)
                ON CONFLICT ("Purpose", "KeyId") DO NOTHING;
                """;
            command.Parameters.AddWithValue("purpose", key.Key.Purpose);
            command.Parameters.AddWithValue("keyId", key.Key.KeyId);
            command.Parameters.AddWithValue("digest", key.Value.Digest);
            command.Parameters.AddWithValue("state", key.Value.State);
            command.Parameters.AddWithValue(
                "retainUntilUtc",
                key.Value.RetainUntilUtc ?? (object)DBNull.Value);
            await command.ExecuteNonQueryAsync();
        }
    }

    /// <summary>Provisions one exact encryption registry identity before a fixture references it through both enrollment foreign keys.</summary>
    /// <param name="adminConnectionString">Administrator connection used only by the existing isolated PostgreSQL harness.</param>
    /// <param name="keyId">Opaque key identifier persisted and compared without normalization.</param>
    /// <returns>A task completing after the exact registry identity exists.</returns>
    private static async Task ProvisionEnrollmentEncryptionKeyAsync(
        string adminConnectionString,
        string keyId)
    {
        await using var admin = new NpgsqlConnection(adminConnectionString);
        await admin.OpenAsync();
        await using var command = admin.CreateCommand();
        command.CommandText = """
            INSERT INTO public."RuntimeEnrollmentKeyRegistries"
                ("Purpose", "KeyId", "MaterialDigestSha256", "State", "Epoch", "CreatedAtUtc", "RetainUntilUtc")
            VALUES ('encryption', @keyId, repeat('a', 64), 'active', 1, clock_timestamp(), NULL)
            ON CONFLICT ("Purpose", "KeyId") DO NOTHING;
            """;
        command.Parameters.AddWithValue("keyId", keyId);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<string> SnapshotRuntimeKeyRegistryAsync(string adminConnectionString)
    {
        await using var connection = new NpgsqlConnection(adminConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT string_agg(
                "Purpose" || ':' || "KeyId" || ':' || "State" || ':' || "Epoch"::text || ':'
                || COALESCE("RetainUntilUtc"::text, '-') || ':' || COALESCE("RetiredAtUtc"::text, '-')
                || ':' || xmin::text,
                ',' ORDER BY "Purpose" COLLATE "C", "KeyId" COLLATE "C")
            FROM public."RuntimeEnrollmentKeyRegistries";
            """;
        return Assert.IsType<string>(await command.ExecuteScalarAsync());
    }

    private static RuntimeProofHeaders Proof(
        RSA rsa, string operation, Guid enrollmentId, string audience, string challenge, string digest)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        var jti = Guid.NewGuid().ToString("D");
        var path = RuntimeEnrollmentService.BuildProofPath(enrollmentId, operation);
        var payload = RuntimeEnrollmentService.BuildProofPayload(
            operation, enrollmentId, 1, path, audience, timestamp, jti, challenge, digest);
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return new RuntimeProofHeaders(timestamp, jti, Base64Url(signature));
    }

    private static RuntimeProofHeaders CanaryProof(
        RSA rsa,
        Guid enrollmentId,
        string eventId,
        string digest,
        RuntimeEnrollmentOptions options,
        DateTimeOffset? sentAt = null,
        Guid? jti = null,
        int epoch = 1,
        string? audience = null,
        Func<string, string>? payloadTransform = null)
    {
        var timestamp = FormatUtc(sentAt ?? DateTimeOffset.UtcNow);
        var canonicalJti = (jti ?? Guid.NewGuid()).ToString("D");
        var payload = RuntimeEnrollmentService.BuildCanaryProofPayload(
            enrollmentId, epoch, audience ?? options.CanaryAudience, timestamp, canonicalJti, eventId, digest);
        if (payloadTransform != null)
            payload = payloadTransform(payload);
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return new RuntimeProofHeaders(timestamp, canonicalJti, Base64Url(signature));
    }

    private static RuntimeEnrollmentPrepareRequest PrepareRequest(
        (Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version) fixture,
        string requestId,
        RSA key)
    {
        var spki = key.ExportSubjectPublicKeyInfo();
        var digest = SHA256.HashData(spki);
        return new RuntimeEnrollmentPrepareRequest
        {
            Schema = RuntimeEnrollmentService.PrepareSchema,
            RequestId = requestId,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = fixture.ProductId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            HandoffDigestSha256 = fixture.HandoffDigest,
            InstallationId = fixture.InstallationId,
            ReleaseVersion = fixture.Version,
            Epoch = 1,
            Key = new RuntimeEnrollmentKeyRequest
            {
                Alg = "PS256",
                PublicKeySpkiBase64 = Convert.ToBase64String(spki),
                PublicKeySpkiSha256 = Convert.ToHexStringLower(digest),
                KeyThumbprint = Base64Url(digest),
                Backend = "software-cng-unattested",
                Attestation = "none"
            }
        };
    }

    /// <summary>
    /// Creates an isolated authority graph without calling Prepare so failure and pre-commit tests
    /// can inspect every possible fragment of the first enrollment transaction.
    /// </summary>
    /// <param name="interceptor">Optional test-only command observer attached only to Runtime contexts.</param>
    /// <returns>A task-owned database, Runtime service, request and cryptographic key fixture.</returns>
    private static async Task<PrepareOnlyScenario> CreatePrepareOnlyScenarioAsync(
        DbCommandInterceptor? interceptor = null)
    {
        var connections = await ProvisionIsolatedAsync();
        using var cleanupOnPreparationFailure = new BootstrapIsolatedDatabaseCleanup(
            connections.Admin, connections.App);
        var factory = new TestDbFactory(connections.App);
        var seeded = await SeedAuthorityAsync(factory, "2.2.978");
        PrepareOnlyFixture fixture;
        await using (var read = await factory.CreateDbContextAsync())
        {
            var binding = await read.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(row => row.Id == seeded.BindingId);
            var hardwareId = await read.LicenseSeats.AsNoTracking()
                .Where(row => row.Id == binding.LicenseSeatId)
                .Select(row => row.HardwareId)
                .SingleAsync();
            fixture = new PrepareOnlyFixture(
                seeded.ProductId, seeded.BindingId, seeded.HandoffDigest, seeded.InstallationId,
                seeded.Version, binding.LicenseId, binding.LicenseSeatId, hardwareId);
        }

        var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        IDbContextFactory<LicenseDbContext> runtimeFactory = interceptor is null
            ? factory
            : new InterceptedDbFactory(connections.App, interceptor);
        var authority = new RuntimeEnrollmentAuthorityService(runtimeFactory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(runtimeFactory, Options.Create(options));
        var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var runtime = new RuntimeEnrollmentService(
            runtimeFactory, authority, registry, crypto, Options.Create(options));
        var request = PrepareRequest(
            (fixture.ProductId, fixture.BindingId, fixture.HandoffDigest, fixture.InstallationId, fixture.Version),
            Guid.NewGuid().ToString("D"), enrollmentKey);
        var scenario = new PrepareOnlyScenario(
            runtimeFactory, connections.Admin, connections.App, fixture, activeSigning, nextSigning,
            enrollmentKey, crypto, runtime, request, Sha256("item3hc1-prepare-" + request.RequestId));
        cleanupOnPreparationFailure.Disarm();
        return scenario;
    }

    /// <summary>Asserts that a refused first Prepare retained no database-owned authority fragment.</summary>
    /// <param name="scenario">Isolated Prepare fixture whose request was refused.</param>
    private static async Task AssertNoPrepareFragmentsAsync(PrepareOnlyScenario scenario)
    {
        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.False(await verify.RuntimeEnrollments.AnyAsync(row =>
            row.BindingId == scenario.Fixture.BindingId));
        Assert.False(await verify.RuntimeEnrollmentRequests.AnyAsync(row =>
            row.ClientId == "website-step1" && row.RequestId == scenario.PrepareRequest.RequestId));
        Assert.False(await verify.EnrollmentLicenseAssignments.AnyAsync());
        Assert.False(await verify.EnrollmentLicenseAssignmentQuarantines.AnyAsync());
        Assert.False(await verify.RuntimeEnrollmentQuotas.AnyAsync(row =>
            row.Scope == "prepare-binding" || row.Scope == "prepare-global"));
        Assert.False(await verify.RuntimeEnrollmentEncryptionNonces.AnyAsync());
    }

    /// <summary>
    /// Waits a bounded interval until another backend is observably blocked on an advisory lock.
    /// The caller supplies a separate autocommit observer so PostgreSQL activity snapshots refresh
    /// between polls; timeout fails the concurrency proof rather than weakening its assertions.
    /// </summary>
    /// <param name="observer">Open administrator connection used only for activity observation.</param>
    /// <param name="blockingBackendPid">Exact task-owned backend that must block the observed waiter.</param>
    /// <returns>The exact backend PID blocked by the task-owned session.</returns>
    private static async Task<int> WaitForAdvisoryWaitAsync(
        NpgsqlConnection observer,
        int blockingBackendPid)
    {
        for (var poll = 0; poll < 300; poll++)
        {
            await using var activity = new NpgsqlCommand("""
                SELECT pid FROM pg_catalog.pg_stat_activity
                WHERE datname = pg_catalog.current_database()
                  AND pid <> pg_catalog.pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND wait_event = 'advisory'
                  AND @blocking_backend_pid = ANY(pg_catalog.pg_blocking_pids(pid))
                ORDER BY pid
                LIMIT 1;
                """, observer);
            activity.Parameters.AddWithValue("blocking_backend_pid", blockingBackendPid);
            if (await activity.ExecuteScalarAsync() is int waiterPid)
                return waiterPid;
            await Task.Delay(10);
        }

        Assert.Fail("Expected a backend to wait on the task-owned advisory lock.");
        throw new InvalidOperationException("Advisory wait assertion did not terminate execution.");
    }

    /// <summary>
    /// Waits until PostgreSQL proves that the licence writer is blocked by the exact Prepare backend,
    /// with a non-granted exclusive global-authority request opposite Prepare's granted shared lease.
    /// The real deferred item-2 trigger acquires the commercial barrier after the update proceeds.
    /// </summary>
    /// <param name="observer">Open autocommit connection used only for refreshed lock snapshots.</param>
    /// <param name="writerBackendPid">Exact backend attempting the conflicting licence update.</param>
    /// <param name="prepareBackendPid">Exact Prepare backend holding the shared global authority lease.</param>
    private static async Task WaitForWriterBlockedOnPrepareGlobalAuthorityAsync(
        NpgsqlConnection observer,
        int writerBackendPid,
        int prepareBackendPid)
    {
        for (var poll = 0; poll < 300; poll++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT
                    @prepare_backend_pid = ANY(pg_catalog.pg_blocking_pids(@writer_backend_pid))
                    AND EXISTS (
                        SELECT 1 FROM pg_catalog.pg_locks
                        WHERE pid = @writer_backend_pid
                          AND locktype = 'advisory'
                          AND classid = 999831
                          AND objid = 1
                          AND objsubid = 2
                          AND mode = 'ExclusiveLock'
                          AND NOT granted)
                    AND EXISTS (
                        SELECT 1 FROM pg_catalog.pg_locks
                        WHERE pid = @prepare_backend_pid
                          AND locktype = 'advisory'
                          AND classid = 999831
                          AND objid = 1
                          AND objsubid = 2
                          AND mode = 'ShareLock'
                          AND granted);
                """, observer);
            command.Parameters.AddWithValue("writer_backend_pid", writerBackendPid);
            command.Parameters.AddWithValue("prepare_backend_pid", prepareBackendPid);
            if ((bool)(await command.ExecuteScalarAsync())!)
                return;
            await Task.Delay(10);
        }

        Assert.Fail("The licence writer did not wait on Prepare's shared global authority lease.");
    }

    /// <summary>
    /// Waits a bounded interval until PostgreSQL reports the exact task-owned backend dependency.
    /// This generic row-lock proof uses refreshed autocommit snapshots and never inspects SQL text.
    /// </summary>
    /// <param name="observer">Open autocommit connection used only for lock observation.</param>
    /// <param name="waitingBackendPid">Exact backend expected to wait.</param>
    /// <param name="blockingBackendPid">Exact backend expected to block the waiter.</param>
    private static async Task WaitForBackendBlockedByAsync(
        NpgsqlConnection observer,
        int waitingBackendPid,
        int blockingBackendPid)
    {
        for (var poll = 0; poll < 300; poll++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT @blocking_backend_pid = ANY(
                    pg_catalog.pg_blocking_pids(@waiting_backend_pid));
                """, observer);
            command.Parameters.AddWithValue("waiting_backend_pid", waitingBackendPid);
            command.Parameters.AddWithValue("blocking_backend_pid", blockingBackendPid);
            if ((bool)(await command.ExecuteScalarAsync())!)
                return;
            await Task.Delay(10);
        }

        Assert.Fail("The expected PostgreSQL backend dependency was not observed.");
    }

    /// <summary>
    /// Pauses only the test's Prepare continuation after PostgreSQL has completed the exact exclusive
    /// barrier command. The transaction keeps the lock while no SQL statement remains active, which
    /// permits a second transaction's licence update to wait observably on Prepare's global lease.
    /// </summary>
    private sealed class PrepareWriteBarrierInterceptor : DbCommandInterceptor
    {
        private const string WriteBarrierCommand = "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);";
        private readonly TaskCompletionSource<int> _barrierHeld =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _armed;
        private int _matched;

        /// <summary>Creates the interceptor armed by default, or dormant for an explicit later race.</summary>
        /// <param name="initiallyArmed">Whether the first exact barrier command should be intercepted.</param>
        internal PrepareWriteBarrierInterceptor(bool initiallyArmed = true) =>
            _armed = initiallyArmed ? 1 : 0;

        /// <summary>Completes once the intercepted connection owns the commercial write barrier.</summary>
        internal Task<int> BarrierHeld => _barrierHeld.Task;

        /// <summary>Releases the bounded test-only continuation pause; repeated calls are harmless.</summary>
        internal void Release() => _release.TrySetResult();

        /// <summary>Arms a dormant interceptor before any exact barrier command has been captured.</summary>
        /// <exception cref="InvalidOperationException">Thrown if a barrier was already captured.</exception>
        internal void Arm()
        {
            if (Volatile.Read(ref _matched) != 0)
                throw new InvalidOperationException("The Prepare barrier interceptor already captured a command.");
            Volatile.Write(ref _armed, 1);
        }

        /// <summary>
        /// Captures the exact PostgreSQL backend after the write-barrier statement completes, then
        /// pauses only its .NET continuation for at most fifteen seconds. Other commands and retries
        /// pass through unchanged, and cancellation propagates without converting infrastructure state.
        /// </summary>
        /// <param name="command">Completed database command.</param>
        /// <param name="eventData">EF command event metadata for the owning connection.</param>
        /// <param name="result">Affected-row result returned by PostgreSQL.</param>
        /// <param name="cancellationToken">Cancellation for the intercepted operation.</param>
        /// <returns>The unchanged affected-row result after the test releases the continuation.</returns>
        public override async ValueTask<int> NonQueryExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (Volatile.Read(ref _armed) != 0
                && string.Equals(command.CommandText, WriteBarrierCommand, StringComparison.Ordinal)
                && Interlocked.CompareExchange(ref _matched, 1, 0) == 0)
            {
                var connection = Assert.IsType<NpgsqlConnection>(command.Connection);
                _barrierHeld.TrySetResult(connection.ProcessID);
                await _release.Task.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            }

            return result;
        }
    }

    /// <summary>
    /// Creates application contexts with one test-owned interceptor while retaining the production
    /// model and connection string. Every returned context is caller-owned and performs no I/O at creation.
    /// </summary>
    private sealed class InterceptedDbFactory(
        string connectionString,
        DbCommandInterceptor interceptor) : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Creates a caller-owned production context with the exact test interceptor attached.</summary>
        /// <returns>A new context that has not opened a database connection.</returns>
        public LicenseDbContext CreateDbContext() => new(
            new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(connectionString)
                .AddInterceptors(interceptor)
                .Options);

        /// <summary>Creates a context synchronously after honoring pre-cancelled requests.</summary>
        /// <param name="cancellationToken">Cancels creation before a context is returned.</param>
        /// <returns>A completed task containing a new caller-owned context.</returns>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(CreateDbContext());
        }
    }

    /// <summary>Immutable provider-owned identifiers used by a first-Prepare test.</summary>
    /// <param name="ProductId">Seeded product identifier.</param>
    /// <param name="BindingId">Finalized distribution binding identifier.</param>
    /// <param name="HandoffDigest">Authenticated handoff digest.</param>
    /// <param name="InstallationId">Canonical installation identifier.</param>
    /// <param name="Version">Approved source release.</param>
    /// <param name="LicenseId">Current commercial licence identifier.</param>
    /// <param name="SeatId">Current commercial seat identifier.</param>
    /// <param name="HardwareId">Exact current seat hardware value.</param>
    private sealed record PrepareOnlyFixture(
        Guid ProductId,
        Guid BindingId,
        string HandoffDigest,
        string InstallationId,
        string Version,
        Guid LicenseId,
        Guid SeatId,
        string HardwareId);

    /// <summary>
    /// Owns an isolated first-Prepare database and every disposable cryptographic object used by it.
    /// Disposal releases the objects and drops only the exact generated database through the shared guard.
    /// </summary>
    private sealed class PrepareOnlyScenario : IDisposable
    {
        /// <summary>Current Runtime signing key.</summary>
        private readonly RSA _activeSigning;
        /// <summary>Next Runtime signing key.</summary>
        private readonly RSA _nextSigning;
        /// <summary>Installation possession key.</summary>
        private readonly RSA _enrollmentKey;
        /// <summary>Encrypted-field service retaining task-local key material.</summary>
        private readonly RuntimeEnrollmentCryptoService _crypto;
        /// <summary>Exact generated-database cleanup owner.</summary>
        private readonly BootstrapIsolatedDatabaseCleanup _databaseCleanup;

        /// <summary>Application-role context factory.</summary>
        internal IDbContextFactory<LicenseDbContext> Factory { get; }
        /// <summary>Administrator connection for bounded test instrumentation.</summary>
        internal string AdminConnectionString { get; }
        /// <summary>Application-role connection used to prove production ACL boundaries.</summary>
        internal string AppConnectionString { get; }
        /// <summary>Seeded provider and commercial identifiers.</summary>
        internal PrepareOnlyFixture Fixture { get; }
        /// <summary>Runtime service under test.</summary>
        internal RuntimeEnrollmentService Runtime { get; }
        /// <summary>Exact first-Prepare request.</summary>
        internal RuntimeEnrollmentPrepareRequest PrepareRequest { get; }
        /// <summary>Digest of the exact request body.</summary>
        internal string PrepareDigest { get; }

        /// <summary>Transfers ownership of an isolated Prepare fixture to this disposable scenario.</summary>
        internal PrepareOnlyScenario(
            IDbContextFactory<LicenseDbContext> factory,
            string adminConnectionString,
            string appConnectionString,
            PrepareOnlyFixture fixture,
            RSA activeSigning,
            RSA nextSigning,
            RSA enrollmentKey,
            RuntimeEnrollmentCryptoService crypto,
            RuntimeEnrollmentService runtime,
            RuntimeEnrollmentPrepareRequest prepareRequest,
            string prepareDigest)
        {
            Factory = factory;
            AdminConnectionString = adminConnectionString;
            AppConnectionString = appConnectionString;
            Fixture = fixture;
            _activeSigning = activeSigning;
            _nextSigning = nextSigning;
            _enrollmentKey = enrollmentKey;
            _crypto = crypto;
            Runtime = runtime;
            PrepareRequest = prepareRequest;
            PrepareDigest = prepareDigest;
            _databaseCleanup = new BootstrapIsolatedDatabaseCleanup(
                adminConnectionString, appConnectionString);
        }

        /// <summary>Releases cryptographic resources and the exact generated test database.</summary>
        public void Dispose()
        {
            _crypto.Dispose();
            _enrollmentKey.Dispose();
            _nextSigning.Dispose();
            _activeSigning.Dispose();
            _databaseCleanup.Dispose();
        }
    }

    private static async Task<(RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>? Result, Exception? Error)>
        CaptureAsync(Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>> task)
    {
        try
        {
            return (await task, null);
        }
        catch (Exception exception)
        {
            return (null, exception);
        }
    }

    private static byte[] CreateSigningPrivateKey()
    {
        using var rsa = RSA.Create(3072);
        return rsa.ExportPkcs8PrivateKey();
    }

    private static RSA CreateSigningKey(byte[] privateKey)
    {
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);
        return rsa;
    }

    private static async Task InstallProofFailureTriggerAsync(string connectionString, bool failOnce)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        var predicate = failOnce
            ? "IF nextval('public.runtime_test_proof_failure_sequence') = 1 THEN"
            : "IF true THEN";
        await ExecuteAsync(connection, $"""
            CREATE SEQUENCE IF NOT EXISTS public.runtime_test_proof_failure_sequence START 1;
            CREATE OR REPLACE FUNCTION public.runtime_test_proof_failure()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
            BEGIN
                {predicate}
                    RAISE EXCEPTION USING ERRCODE='40P01', MESSAGE='injected post-proof deadlock';
                END IF;
                RETURN NEW;
            END;
            $body$;
            CREATE TRIGGER runtime_test_proof_failure
            BEFORE INSERT ON public."RuntimeEnrollmentProofNonces"
            FOR EACH ROW EXECUTE FUNCTION public.runtime_test_proof_failure();
            """);
    }

    private static async Task RemoveProofFailureTriggerAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, """
            DROP TRIGGER IF EXISTS runtime_test_proof_failure ON public."RuntimeEnrollmentProofNonces";
            DROP FUNCTION IF EXISTS public.runtime_test_proof_failure();
            DROP SEQUENCE IF EXISTS public.runtime_test_proof_failure_sequence;
            """);
    }

    private static string Sha256(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        return Convert.FromBase64String(base64);
    }

    private static async Task<long> EpochAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction = null)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentAuthorityStates\" WHERE \"Id\" = 1;";
        return (long)(await command.ExecuteScalarAsync())!;
    }

    private static async Task ExecuteAsync(
        NpgsqlConnection connection,
        string sql,
        NpgsqlTransaction? transaction = null)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private static Task GrantApplicationRuntimePrivilegesAsync(NpgsqlConnection connection) =>
        ExecuteAsync(connection, """
            DO $grant$
            BEGIN
                EXECUTE format(
                    'GRANT CONNECT ON DATABASE %I TO softlicence_runtime_test_app',
                    current_database());
            END;
            $grant$;
            GRANT USAGE ON SCHEMA public TO softlicence_runtime_test_app;
            GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO softlicence_runtime_test_app;
            GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO softlicence_runtime_test_app;
            REVOKE ALL ON public."RuntimeEnrollmentAuthorityStates" FROM softlicence_runtime_test_app;
            REVOKE ALL ON public."RuntimeEnrollmentKeyRegistries" FROM softlicence_runtime_test_app;
            GRANT SELECT ON public."RuntimeEnrollmentAuthorityStates" TO softlicence_runtime_test_app;
            GRANT SELECT ON public."RuntimeEnrollmentKeyRegistries" TO softlicence_runtime_test_app;
            REVOKE ALL ON public."RuntimeCriticalIncidents" FROM softlicence_runtime_test_app;
            REVOKE ALL ON public."RuntimeCriticalRecoveries" FROM softlicence_runtime_test_app;
            REVOKE ALL ON public."RuntimeCriticalRecoveryReceipts" FROM softlicence_runtime_test_app;
            GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalIncidents" TO softlicence_runtime_test_app;
            GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalRecoveries" TO softlicence_runtime_test_app;
            GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalRecoveryReceipts" TO softlicence_runtime_test_app;
            -- TKT-001277 lot 2d: this suite specifies the blocking behaviour, so it runs with the assignment
            -- switch closed. The open behaviour is covered by AssignmentEnforcementSwitchPostgreSqlTests.
            DO $switch$
            BEGIN
                IF pg_catalog.to_regclass('public."AssignmentEnforcementSettings"') IS NOT NULL THEN
                    UPDATE public."AssignmentEnforcementSettings"
                    SET "Mode" = 'closed', "UpdatedBy" = 'test:blocking-suite'
                    WHERE "Id" = 1;
                END IF;
            END;
            $switch$;
            """);

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (T)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>
    /// Waits until a Runtime transaction is observably blocked on the shared item-2 commercial
    /// barrier owned exclusively by the supplied PostgreSQL backend.
    /// </summary>
    /// <param name="observer">Independent autocommit connection used only for lock inspection.</param>
    /// <param name="blockingBackendPid">Backend holding the exclusive <c>(1312, 1)</c> lock.</param>
    private static async Task WaitForSharedCommercialBarrierWaiterAsync(
        NpgsqlConnection observer,
        int blockingBackendPid)
    {
        for (var poll = 0; poll < 300; poll++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT pg_catalog.count(*)
                FROM pg_catalog.pg_stat_activity AS activity
                WHERE activity.datname = pg_catalog.current_database()
                  AND @blocking_backend_pid = ANY(pg_catalog.pg_blocking_pids(activity.pid))
                  AND EXISTS (
                      SELECT 1
                      FROM pg_catalog.pg_locks AS held
                      WHERE held.pid = activity.pid
                        AND held.locktype = 'advisory'
                        AND held.classid = 1312
                        AND held.objid = 1
                        AND held.objsubid = 2
                        AND held.mode = 'ShareLock'
                        AND NOT held.granted);
                """;
            command.Parameters.AddWithValue("blocking_backend_pid", blockingBackendPid);
            if (Convert.ToInt64(await command.ExecuteScalarAsync()) > 0)
                return;
            await Task.Delay(10);
        }

        Assert.Fail("The Runtime transaction did not wait on the expected shared commercial barrier.");
    }

    private static async Task<IReadOnlyList<string>> QueryStringsAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync();
        var values = new List<string>();
        while (await reader.ReadAsync())
            values.Add(reader.GetString(0));
        return values;
    }

    private static async Task<bool> BooleanAsync(
        NpgsqlConnection connection,
        string sql,
        NpgsqlTransaction transaction)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>
    /// Creates production <see cref="LicenseDbContext"/> instances for one PostgreSQL connection.
    /// When <paramref name="historicalSchemaIgnoredProperties"/> is non-empty, contexts instead use a
    /// model without those scalar properties so fixtures can seed a database deliberately migrated to
    /// an older migration (see <see cref="ForExistingSchemaAsync"/> and <see cref="HistoricalSchemaModel"/>).
    /// </summary>
    /// <param name="connectionString">The connection used by every created context.</param>
    /// <param name="historicalSchemaIgnoredProperties">Scalar properties absent from the target schema.</param>
    private sealed class TestDbFactory(
        string connectionString,
        IReadOnlyList<(Type ClrType, string Property)>? historicalSchemaIgnoredProperties = null)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <summary>Creates a context on the current model, or on the historical-schema model when configured.</summary>
        /// <returns>A new context owned and disposed by the caller.</returns>
        public LicenseDbContext CreateDbContext() =>
            HistoricalSchemaModel.CreateContext(connectionString, historicalSchemaIgnoredProperties ?? []);

        /// <summary>Creates a context synchronously; see <see cref="CreateDbContext"/>.</summary>
        /// <param name="cancellationToken">Unused; creation performs no I/O.</param>
        /// <returns>A completed task carrying a new caller-owned context.</returns>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());

        /// <summary>
        /// Builds a factory matching the schema actually present in the target database; a database at
        /// the current schema yields the unchanged production model. Detection rules are documented on
        /// <see cref="HistoricalSchemaModel.DetectMissingScalarPropertiesAsync"/>.
        /// </summary>
        /// <param name="adminConnection">Connection allowed to read <c>information_schema</c>.</param>
        /// <param name="appConnection">Connection used by the created contexts.</param>
        /// <returns>A factory whose model matches the target schema.</returns>
        public static async Task<TestDbFactory> ForExistingSchemaAsync(string adminConnection, string appConnection) =>
            new(appConnection, await HistoricalSchemaModel.DetectMissingScalarPropertiesAsync(adminConnection));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

/// <summary>Provides owned fixtures for the Runtime Enrollment v2 PostgreSQL proof scenarios.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>Creates the production persistence component with enabled bounded transaction settings.</summary>
    /// <param name="factory">Factory for the existing PostgreSQL harness application role.</param>
    /// <returns>A production authority persistence component.</returns>
    private static RuntimeEnrollmentAuthorityService AuthorityPersistence(
        IDbContextFactory<LicenseDbContext> factory) => new(factory, Options.Create(new RuntimeEnrollmentOptions
        {
            Mode = "enabled",
            LockTimeoutMilliseconds = 5000,
            StatementTimeoutMilliseconds = 15000
        }));

    /// <summary>
    /// Creates one already-validated opaque persistence candidate. Returned byte arrays and identifiers are
    /// independently owned; opaque text is not trimmed, folded, or normalized.
    /// </summary>
    /// <param name="lineageId">Optional exact lineage identity.</param>
    /// <param name="generationId">Optional exact generation identity.</param>
    /// <param name="requestId">Optional exact request identity.</param>
    /// <param name="productId">Optional exact product identity.</param>
    /// <param name="providerGrantRef">Optional opaque grant reference.</param>
    /// <param name="sequence">Zero-based generation sequence.</param>
    /// <param name="previousGenerationId">Null only for genesis.</param>
    /// <param name="lineageCreatedAtUtc">Optional exact immutable lineage instant.</param>
    /// <param name="bindingIds">Binding locks expected before persistence.</param>
    /// <returns>An independently owned candidate within item-1 byte and digest bounds.</returns>
    private static RuntimeEnrollmentAuthorityPersistenceCandidate AuthorityCandidate(
        Guid? lineageId = null,
        Guid? generationId = null,
        Guid? requestId = null,
        Guid? productId = null,
        Guid? licenseSeatId = null,
        string? providerGrantRef = null,
        long sequence = 0,
        Guid? previousGenerationId = null,
        DateTime? lineageCreatedAtUtc = null,
        IReadOnlyCollection<Guid>? bindingIds = null)
    {
        var generation = generationId ?? Guid.NewGuid();
        var request = requestId ?? Guid.NewGuid();
        var grant = providerGrantRef ?? "grant:" + Guid.NewGuid().ToString("N");
        var created = lineageCreatedAtUtc ?? ExactUtcNow();
        var payload = new[] { generation.ToByteArray()[0] };
        var statement = new[] { request.ToByteArray()[0], generation.ToByteArray()[1] };
        return new RuntimeEnrollmentAuthorityPersistenceCandidate
        {
            AuthorityLineageId = lineageId ?? Guid.NewGuid(),
            AuthorityGenerationId = generation,
            RequestId = request,
            RequestDigest = DigestFor(request.ToByteArray()),
            Provider = "softlicence",
            ProductId = productId ?? Guid.NewGuid(),
            LicenseSeatId = licenseSeatId ?? Guid.NewGuid(),
            ProviderGrantRef = grant,
            ProviderGrantRefScalarCount = grant.EnumerateRunes().Count(),
            LineageCreatedAtUtc = created,
            Sequence = sequence,
            PreviousGenerationId = previousGenerationId,
            CanonicalPayloadUtf8 = payload,
            SignedStatementUtf8 = statement,
            AuthorityDigest = DigestFor(payload),
            SignatureAlgorithm = "PS256",
            SignatureKeyId = "runtime-authority-test-key",
            SignatureValue = new string('A', 342),
            OccurredAtUtc = created.AddSeconds(sequence),
            CreatedAtUtc = created.AddSeconds(sequence),
            BindingIds = bindingIds ?? []
        };
    }

    /// <summary>Counts granted transaction-level advisory locks owned by the current production connection.</summary>
    /// <param name="db">Context with the caller-owned active transaction.</param>
    /// <returns>The exact number of granted advisory lock rows for the current backend.</returns>
    private static Task<long> CurrentAdvisoryLockCountAsync(LicenseDbContext db) =>
        db.Database.SqlQueryRaw<long>("""
            SELECT count(*)::bigint AS "Value" FROM pg_catalog.pg_locks
            WHERE locktype='advisory' AND granted AND pid=pg_catalog.pg_backend_pid()
            """).SingleAsync();

    /// <summary>Reads exact advisory lock identities and modes held by the current production transaction.</summary>
    /// <param name="db">Context whose backend owns the authority transaction.</param>
    /// <returns>Ordered class/object/sub-id/mode rows copied from <c>pg_locks</c>.</returns>
    private static Task<List<string>> CurrentAdvisoryLocksAsync(LicenseDbContext db) =>
        db.Database.SqlQueryRaw<string>("""
            SELECT (classid::bigint || ':' || objid::bigint || ':' || objsubid::bigint || ':' || mode)::text AS "Value"
            FROM pg_catalog.pg_locks
            WHERE locktype = 'advisory' AND granted AND pid = pg_catalog.pg_backend_pid()
            ORDER BY classid, objid, objsubid, mode
            """).ToListAsync();

    /// <summary>Computes the exact <c>pg_locks</c> identity for one production hash advisory key.</summary>
    /// <param name="db">Context used only to invoke PostgreSQL's authoritative hash function.</param>
    /// <param name="value">Exact non-normalized lock input.</param>
    /// <param name="seed">Production hash seed.</param>
    /// <returns>The class/object/sub-id identity with exclusive mode.</returns>
    private static Task<string> AdvisoryHashLockIdentityAsync(
        LicenseDbContext db, string value, long seed) =>
        db.Database.SqlQueryRaw<string>("""
            SELECT (((pg_catalog.hashtextextended({0}, {1}) >> 32) & 4294967295)::text
                || ':' || ((pg_catalog.hashtextextended({0}, {1}) & 4294967295)::text)
                || ':1:ExclusiveLock') AS "Value"
            """, value, seed).SingleAsync();

    /// <summary>
    /// Creates a complete item-2 registry, production coordinator, and runtime service rooted in distinct
    /// ephemeral operational, recovery, registry, and capability keys.
    /// </summary>
    /// <param name="factory">Application-role context factory.</param>
    /// <param name="productId">Exact scoped product UUID.</param>
    /// <param name="now">Trusted fixed authority time.</param>
    /// <param name="operational">Active operational key owner.</param>
    /// <param name="recovery">Active recovery key owner.</param>
    /// <param name="registryAuthority">Independent registry pin owner.</param>
    /// <param name="capabilityActive">Legacy runtime capability signer required only by the service constructor.</param>
    /// <param name="capabilityNext">Legacy runtime next signer required only by the service constructor.</param>
    /// <returns>The production service, coordinator, persistence owner, and disposable runtime crypto owner.</returns>
    private static (RuntimeEnrollmentService Service, RuntimeEnrollmentAuthorityV2Coordinator Coordinator,
        RuntimeEnrollmentAuthorityService Authority, RuntimeEnrollmentCryptoService RuntimeCrypto) AuthorityRuntime(
        IDbContextFactory<LicenseDbContext> factory, Guid productId, DateTimeOffset now,
        RSA operational, RSA recovery, RSA registryAuthority, RSA capabilityActive, RSA capabilityNext)
    {
        var options = RuntimeOptions(productId, capabilityActive, capabilityNext);
        var signing = AuthoritySigningOptions(now, operational, recovery);
        return AuthorityRuntime(factory, productId, now, signing, registryAuthority,
            capabilityActive, capabilityNext);
    }

    /// <summary>Creates the production runtime from an exact caller-owned authority registry fixture.</summary>
    private static (RuntimeEnrollmentService Service, RuntimeEnrollmentAuthorityV2Coordinator Coordinator,
        RuntimeEnrollmentAuthorityService Authority, RuntimeEnrollmentCryptoService RuntimeCrypto) AuthorityRuntime(
        IDbContextFactory<LicenseDbContext> factory, Guid productId, DateTimeOffset now,
        RuntimeAuthorityGenerationSigningOptions signing, RSA registryAuthority,
        RSA capabilityActive, RSA capabilityNext)
    {
        var options = RuntimeOptions(productId, capabilityActive, capabilityNext);
        var registryCrypto = new RuntimeEnrollmentAuthorityCryptography(
            new FixedTimeProvider(now), registryAuthority.ExportSubjectPublicKeyInfo());
        var authenticationInput = registryCrypto.GetRegistrySnapshotAuthenticationInput(signing, now).Value!;
        options.AuthorityGenerationSigning = signing;
        options.AuthorityGenerationV2 = new RuntimeAuthorityGenerationV2Options
        {
            Mode = "enabled",
            RegistryAuthoritySpkiBase64 = Convert.ToBase64String(registryAuthority.ExportSubjectPublicKeyInfo()),
            RegistryObservedAtUtc = now.ToString("O", CultureInfo.InvariantCulture),
            RegistrySnapshotSignatureBase64Url = Base64Url(registryAuthority.SignData(
                authenticationInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        };
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var coordinator = new RuntimeEnrollmentAuthorityV2Coordinator(
            authority, Options.Create(options), new FixedTimeProvider(now));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        var runtimeCrypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        return (new RuntimeEnrollmentService(factory, authority, registry, runtimeCrypto,
            Options.Create(options), authorityV2: coordinator), coordinator, authority, runtimeCrypto);
    }

    /// <summary>Creates a registry where the old signer is compromised/revoked and a distinct successor is active.</summary>
    private static RuntimeAuthorityGenerationSigningOptions AuthorityRecoverySigningOptions(
        DateTimeOffset now, RSA predecessor, RSA successor, RSA recovery) => new()
    {
        ActiveSigningKeyId = "operational-2026-02",
        RegistrySnapshotId = "registry-recovery",
        RegistrySnapshotVersion = 2,
        Keys =
        [
            new RuntimeAuthorityGenerationKeyOptions
            {
                KeyId = "operational-2026-01", Purpose = "operational", Domain = "generation",
                ContractVersion = 2, Status = "revoked", ActivatedAtUtc = now.AddDays(-2),
                CompromiseFromUtc = now.AddHours(-2), RevokedAtUtc = now.AddHours(-1),
                RevocationReason = "COMPROMISED", PublicKeyPem = predecessor.ExportSubjectPublicKeyInfoPem()
            },
            new RuntimeAuthorityGenerationKeyOptions
            {
                KeyId = "operational-2026-02", Purpose = "operational", Domain = "generation",
                ContractVersion = 2, Status = "active", ActivatedAtUtc = now.AddHours(-3),
                PublicKeyPem = successor.ExportSubjectPublicKeyInfoPem(),
                PrivateKeyPem = successor.ExportPkcs8PrivateKeyPem()
            },
            new RuntimeAuthorityGenerationKeyOptions
            {
                KeyId = "recovery-2026-01", Purpose = "recovery", Domain = "recovery",
                ContractVersion = 2, Status = "active", ActivatedAtUtc = now.AddDays(-1),
                PublicKeyPem = recovery.ExportSubjectPublicKeyInfoPem()
            }
        ]
    };

    /// <summary>Creates exact successor recovery request bytes from the committed locked head.</summary>
    private static byte[] AuthorityRecoveryRequest(
        Guid requestId, RuntimeEnrollmentAuthorityGenerationPayloadV2 predecessor,
        string successorKeyId, int successorEpoch, DateTime occurredAtUtc,
        Guid? substitutedHead = null) => JsonSerializer.SerializeToUtf8Bytes(
        new RuntimeEnrollmentAuthorityRequestV2
        {
            Schema = "runtime-enrollment-authority-request-v2", ContractVersion = 2,
            RequestId = requestId.ToString("D"),
            ExpectedAuthorityLineageId = predecessor.AuthorityLineageId,
            ExpectedCurrentGenerationId = (substitutedHead ?? Guid.Parse(predecessor.AuthorityGenerationId)).ToString("D"),
            ExpectedPredecessorGenerationId = (substitutedHead ?? Guid.Parse(predecessor.AuthorityGenerationId)).ToString("D"),
            Provider = predecessor.Provider, ProductId = predecessor.ProductId,
            ProviderGrantRef = predecessor.ProviderGrantRef,
            RequestedAuthority = new RuntimeEnrollmentAuthorityRequestedRequestV2
            {
                Release = predecessor.Release, Binding = predecessor.Binding,
                Enrollment = predecessor.Enrollment,
                Key = new RuntimeEnrollmentAuthorityKeyV2
                    { AuthorityKeyId = successorKeyId, SecurityEpoch = successorEpoch },
                Installation = predecessor.Installation
            },
            Transition = new RuntimeEnrollmentAuthorityRequestTransitionV2
            {
                Kind = "recovery", ReasonCode = "RECOVERY_AUTHORIZED",
                RequestedAtUtc = occurredAtUtc.ToString(
                    "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture)
            }
        }, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());

    /// <summary>Creates exact canonical genesis request bytes from one fully scoped authoritative fixture.</summary>
    /// <param name="requestId">Semantic request UUID.</param>
    /// <param name="productId">Scoped product UUID.</param>
    /// <param name="binding">Authoritative binding row.</param>
    /// <param name="enrollment">Authoritative enrollment row.</param>
    /// <param name="license">Authoritative license row whose activation instant, or creation fallback, becomes the exact issuance instant.</param>
    /// <param name="artifactDigest">Exact approved registration baseline digest.</param>
    /// <param name="occurredAtUtc">Exact six-fraction transition instant.</param>
    /// <returns>Newly allocated UTF-8 bytes serialized by the production closed contract.</returns>
    private static byte[] AuthorityGenesisRequest(
        Guid requestId, Guid productId, DistributionInstallationBinding binding,
        RuntimeEnrollment enrollment, License license, string artifactDigest, DateTime occurredAtUtc) =>
        JsonSerializer.SerializeToUtf8Bytes(new RuntimeEnrollmentAuthorityRequestV2
        {
            Schema = "runtime-enrollment-authority-request-v2",
            ContractVersion = 2,
            RequestId = requestId.ToString("D"),
            ExpectedAuthorityLineageId = null,
            ExpectedCurrentGenerationId = null,
            ExpectedPredecessorGenerationId = null,
            Provider = "softlicence",
            ProductId = productId.ToString("D"),
            ProviderGrantRef = binding.GrantRef,
            RequestedAuthority = new RuntimeEnrollmentAuthorityRequestedRequestV2
            {
                Release = new() { Version = binding.Version, ArtifactSetDigest = artifactDigest },
                Binding = new() { BindingId = binding.Id.ToString("D"), HardwareIdDigest = binding.HardwareIdHash },
                Enrollment = new()
                {
                    EnrollmentId = enrollment.Id.ToString("D"), State = "active",
                    IssuedAtUtc = (license.ActivationDate ?? license.CreationDate)
                        .ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture),
                    ExpiresAtUtc = license.ExpirationDate?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture)
                },
                Key = new() { AuthorityKeyId = "operational-2026-01", SecurityEpoch = enrollment.SecurityEpoch },
                Installation = new() { InstallationId = binding.InstallationId, SeatId = binding.LicenseSeatId.ToString("D") }
            },
            Transition = new RuntimeEnrollmentAuthorityRequestTransitionV2
            {
                Kind = "genesis", ReasonCode = "INITIAL_ENROLLMENT",
                RequestedAtUtc = occurredAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture)
            }
        }, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());

    /// <summary>Removes only the test-owned head-suppression trigger and function.</summary>
    /// <param name="connection">Open administrator connection.</param>
    /// <returns>A task completing after both test-owned objects are absent.</returns>
    private static Task RemoveAuthorityHeadSuppressionAsync(NpgsqlConnection connection) =>
        ExecuteAsync(connection, """
            DROP TRIGGER IF EXISTS zzz_runtime_test_re_authority_suppress_head
                ON public."RuntimeEnrollmentAuthorityLineages";
            DROP FUNCTION IF EXISTS public.runtime_test_re_authority_suppress_head();
            """);

    /// <summary>Attempts one adversarial terminal attempt insert and returns its PostgreSQL SQLSTATE.</summary>
    /// <param name="factory">Application-role context factory.</param>
    /// <param name="attempt">Caller-owned malformed immutable attempt.</param>
    /// <returns>The exact PostgreSQL failure raised by relational enforcement.</returns>
    private static async Task<PostgresException> RejectAttemptInsertAsync(
        IDbContextFactory<LicenseDbContext> factory, RuntimeEnrollmentAuthorityAttempt attempt)
    {
        await using var db = await factory.CreateDbContextAsync();
        db.RuntimeEnrollmentAuthorityAttempts.Add(attempt);
        var failure = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        return Assert.IsType<PostgresException>(failure.InnerException);
    }

    /// <summary>Attempts one adversarial terminal request insert and returns its PostgreSQL SQLSTATE.</summary>
    /// <param name="factory">Application-role context factory.</param>
    /// <param name="request">Caller-owned malformed immutable request.</param>
    /// <returns>The exact PostgreSQL failure raised by relational enforcement.</returns>
    private static async Task<PostgresException> RejectRequestInsertAsync(
        IDbContextFactory<LicenseDbContext> factory, RuntimeEnrollmentAuthorityRequest request)
    {
        await using var db = await factory.CreateDbContextAsync();
        db.RuntimeEnrollmentAuthorityRequests.Add(request);
        var failure = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        return Assert.IsType<PostgresException>(failure.InnerException);
    }

    /// <summary>Computes one exact lowercase SHA-256 digest for opaque test bytes.</summary>
    /// <param name="value">Bytes to hash without transformation.</param>
    /// <returns>Exactly 64 lowercase hexadecimal ASCII characters.</returns>
    private static string DigestFor(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    /// <summary>Returns a microsecond-exact UTC instant that round-trips through PostgreSQL unchanged.</summary>
    private static DateTime ExactUtcNow() =>
        new(2026, 8, 24, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>Creates a canonical production-serialized generation payload for recovery proof tests.</summary>
    /// <returns>Newly allocated UTF-8 bytes owned by the caller.</returns>
    private static byte[] AuthorityPayloadBytes() => JsonSerializer.SerializeToUtf8Bytes(
        new RuntimeEnrollmentAuthorityGenerationPayloadV2
        {
            Schema = "runtime-enrollment-authority-generation-v2",
            ContractVersion = 2,
            AuthorityLineageId = "018f6fd4-8f31-7cc2-8d19-9e79c8b87a01",
            AuthorityGenerationId = "018f6fd4-aad1-7a27-91fe-fec30a9ff201",
            PreviousGenerationId = null,
            Sequence = 0,
            Provider = "softlicence",
            ProductId = "018f6fd4-94b2-7f7e-8f47-13eb8aab8b11",
            ProviderGrantRef = "grant:exact",
            Release = new RuntimeEnrollmentAuthorityReleaseV2
                { Version = "2.3.445", ArtifactSetDigest = new string('1', 64) },
            Binding = new RuntimeEnrollmentAuthorityBindingV2
                { BindingId = "018f6fd4-bbc2-7467-a238-0bf114bb3101", HardwareIdDigest = new string('2', 64) },
            Enrollment = new RuntimeEnrollmentAuthorityEnrollmentV2
                { EnrollmentId = "018f6fd4-cbd3-7d7d-b8db-a905a7786201", State = "active", IssuedAtUtc = "2026-08-22T16:00:02.000000Z", ExpiresAtUtc = null },
            Key = new RuntimeEnrollmentAuthorityKeyV2
                { AuthorityKeyId = "operational-2026-01", SecurityEpoch = 7 },
            Installation = new RuntimeEnrollmentAuthorityInstallationV2
                { InstallationId = "018f6fd4-dce4-7b2a-8202-5846e80d1301", SeatId = null },
            Transition = new RuntimeEnrollmentAuthorityGenerationTransitionV2
            {
                Kind = "genesis",
                ReasonCode = "INITIAL_ENROLLMENT",
                RequestId = "018f6fd4-fe06-75d7-ae93-b15d36ca5501",
                OccurredAtUtc = "2026-08-22T16:00:02.000000Z"
            }
        }, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());

    /// <summary>Creates an exact sorted operational/recovery registry with optional compromise metadata.</summary>
    /// <param name="now">Trusted UTC instant used for lifecycle metadata.</param>
    /// <param name="operational">Distinct operational RSA-2048 key owner.</param>
    /// <param name="recovery">Distinct recovery RSA-2048 key owner.</param>
    /// <param name="revokedRecovery">Whether recovery metadata represents compromise then revocation.</param>
    /// <returns>New mutable options whose PEM strings contain only ephemeral test material.</returns>
    private static RuntimeAuthorityGenerationSigningOptions AuthoritySigningOptions(
        DateTimeOffset now, RSA operational, RSA recovery, bool revokedRecovery = false) => new()
    {
        ActiveSigningKeyId = "operational-2026-01",
        RegistrySnapshotId = revokedRecovery ? "registry-revoked" : "registry-active",
        RegistrySnapshotVersion = revokedRecovery ? 2 : 1,
        Keys =
        [
            new RuntimeAuthorityGenerationKeyOptions
            {
                KeyId = "operational-2026-01", Purpose = "operational", Domain = "generation",
                ContractVersion = 2, Status = "active", ActivatedAtUtc = now.AddDays(-1),
                PublicKeyPem = operational.ExportSubjectPublicKeyInfoPem(),
                PrivateKeyPem = operational.ExportPkcs8PrivateKeyPem()
            },
            new RuntimeAuthorityGenerationKeyOptions
            {
                KeyId = "recovery-2026-01", Purpose = "recovery", Domain = "recovery",
                ContractVersion = 2, Status = revokedRecovery ? "revoked" : "active",
                ActivatedAtUtc = now.AddDays(-1),
                CompromiseFromUtc = revokedRecovery ? now.AddHours(-2) : null,
                RevokedAtUtc = revokedRecovery ? now.AddHours(-1) : null,
                RevocationReason = revokedRecovery ? "COMPROMISED" : null,
                PublicKeyPem = recovery.ExportSubjectPublicKeyInfoPem()
            }
        ]
    };

    /// <summary>Authenticates one registry snapshot exclusively with the independent registry authority.</summary>
    /// <param name="crypto">Item-2-owned cryptographic boundary.</param>
    /// <param name="options">Complete untrusted registry metadata.</param>
    /// <param name="registry">Independent pinned registry authority.</param>
    /// <param name="observedAtUtc">Authenticated observation instant.</param>
    /// <returns>A sealed immutable snapshot proof.</returns>
    private static RuntimeEnrollmentAuthorityCryptography.TrustedKeyRegistrySnapshotProof
        AuthenticateAuthoritySnapshot(RuntimeEnrollmentAuthorityCryptography crypto,
            RuntimeAuthorityGenerationSigningOptions options, RSA registry,
            DateTimeOffset observedAtUtc)
    {
        var input = crypto.GetRegistrySnapshotAuthenticationInput(options, observedAtUtc);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, input.Error);
        var evidence = crypto.AuthenticateRegistrySnapshot(options, observedAtUtc,
            registry.SignData(input.Value!, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None, evidence.Error);
        return crypto.CreateTrustedSnapshotProof(evidence.Value!);
    }

    /// <summary>Creates one isolated database through the existing administrator connection.</summary>
    /// <param name="adminConnectionString">Administrator connection to the harness database.</param>
    /// <param name="databaseName">Generated ASCII database identifier.</param>
    /// <returns>A task completing after PostgreSQL creates the isolated database.</returns>
    private static async Task CreateDatabaseAsync(string adminConnectionString, string databaseName)
    {
        await using var connection = new NpgsqlConnection(adminConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"CREATE DATABASE \"{databaseName}\";");
    }

    /// <summary>Force-drops only the generated isolated migration database during test cleanup.</summary>
    /// <param name="adminConnectionString">Administrator connection outside the generated database.</param>
    /// <param name="databaseName">Generated ASCII database identifier previously created by this test.</param>
    /// <returns>A task completing after the isolated database is absent.</returns>
    private static async Task DropDatabaseAsync(string adminConnectionString, string databaseName)
    {
        await using var connection = new NpgsqlConnection(adminConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"DROP DATABASE IF EXISTS \"{databaseName}\" WITH (FORCE);");
    }
}

/// <summary>Exercises the historical item-1 to item-3 migration with the existing isolated database harness.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Proves historical accepted rows backfill exact item-3 terminal data while the request guard is
    /// temporarily removed then restored before effective NOT NULL/check constraints; local Down and Up
    /// remain bounded. The seeded historical generation uses the production generation-v2 scalar grammar
    /// because the item-3 migration parses its canonical payload to derive lineage and seat authority.
    /// It also proves the production signature constraint accepts exactly 342 canonical
    /// Base64Url characters and rejects wrong lengths or forbidden characters with a check violation.
    /// This test is executed only by the separately supervised PostgreSQL recipe.
    /// </summary>
    [Fact]
    public async Task AuthorityAttemptResultMigration_RealItem1UpItem3DownUpIsExactAndGuarded()
    {
        var shared = await ProvisionAsync();
        var databaseName = "softlicence_re_authority_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, databaseName);
        var isolated = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = databaseName }.ConnectionString;
        var lineageId = Guid.NewGuid();
        var generationId = Guid.NewGuid();
        var requestId = Guid.NewGuid();
        var productId = Guid.NewGuid();
        var seatId = Guid.NewGuid();
        var createdAt = ExactUtcNow();
        var canonicalCreatedAt = createdAt.ToString(
            "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",
            CultureInfo.InvariantCulture);
        // Keep this fixture on the production scalar grammar: the TKT-000732 migration parses
        // CanonicalPayloadUtf8 and requires canonical lineage and installation seat identities.
        var canonicalPayload = JsonSerializer.SerializeToUtf8Bytes(
            new RuntimeEnrollmentAuthorityGenerationPayloadV2
            {
                Schema = "runtime-enrollment-authority-generation-v2",
                ContractVersion = 2,
                AuthorityLineageId = lineageId.ToString("D"),
                AuthorityGenerationId = generationId.ToString("D"),
                PreviousGenerationId = null,
                Sequence = 0,
                Provider = "softlicence",
                ProductId = productId.ToString("D"),
                ProviderGrantRef = "historical-grant",
                Release = new RuntimeEnrollmentAuthorityReleaseV2
                {
                    Version = "1.0.0",
                    ArtifactSetDigest = new string('a', 64)
                },
                Binding = new RuntimeEnrollmentAuthorityBindingV2
                {
                    BindingId = Guid.NewGuid().ToString("D"),
                    HardwareIdDigest = new string('b', 64)
                },
                Enrollment = new RuntimeEnrollmentAuthorityEnrollmentV2
                {
                    EnrollmentId = Guid.NewGuid().ToString("D"),
                    State = "active",
                    IssuedAtUtc = canonicalCreatedAt,
                    ExpiresAtUtc = null
                },
                Key = new RuntimeEnrollmentAuthorityKeyV2
                {
                    AuthorityKeyId = "historical-key",
                    SecurityEpoch = 1
                },
                Installation = new RuntimeEnrollmentAuthorityInstallationV2
                {
                    InstallationId = Guid.NewGuid().ToString("D"),
                    SeatId = seatId.ToString("D")
                },
                Transition = new RuntimeEnrollmentAuthorityGenerationTransitionV2
                {
                    Kind = "genesis",
                    ReasonCode = "INITIAL_ENROLLMENT",
                    RequestId = requestId.ToString("D"),
                    OccurredAtUtc = canonicalCreatedAt
                }
            },
            RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());
        var statement = new byte[] { 0x11, 0x22, 0x33 };
        try
        {
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(isolated).Options;
            await using var db = new LicenseDbContext(options);
            var migrator = db.GetService<IMigrator>();
            const string item1Migration = "20260823131005_AddRuntimeEnrollmentGenerationAuthority";
            await migrator.MigrateAsync(item1Migration);

            await using (var connection = new NpgsqlConnection(isolated))
            {
                await connection.OpenAsync();
                await using var transaction = await connection.BeginTransactionAsync();
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    INSERT INTO public."RuntimeEnrollmentAuthorityLineages"
                        ("AuthorityLineageId","Provider","ProductId","ProviderGrantRef",
                         "ProviderGrantRefScalarCount","CreatedAtUtc","HeadGenerationId","HeadSequence")
                    VALUES (@lineage,'softlicence',@product,'historical-grant',16,@created,@generation,0);
                    INSERT INTO public."RuntimeEnrollmentAuthorityGenerations"
                        ("AuthorityGenerationId","AuthorityLineageId","Sequence","PreviousGenerationId",
                         "RequestId","CanonicalPayloadUtf8","SignedStatementUtf8","AuthorityDigest",
                         "SignatureAlgorithm","SignatureKeyId","SignatureValue","OccurredAtUtc","CreatedAtUtc")
                    VALUES (@generation,@lineage,0,NULL,@request,@payload,@statement,
                            repeat('a',64),'PS256','historical-key',repeat('A',342),@created,@created);
                    INSERT INTO public."RuntimeEnrollmentAuthorityRequests"
                        ("RequestId","RequestDigest","AuthorityGenerationId","ResultCode","CreatedAtUtc")
                    VALUES (@request,repeat('b',64),@generation,'ACCEPTED',@created);
                    """;
                command.Parameters.AddWithValue("lineage", lineageId);
                command.Parameters.AddWithValue("product", productId);
                command.Parameters.AddWithValue("generation", generationId);
                command.Parameters.AddWithValue("request", requestId);
                command.Parameters.AddWithValue("created", createdAt);
                command.Parameters.AddWithValue("payload", canonicalPayload);
                command.Parameters.AddWithValue("statement", statement);
                Assert.Equal(3, await command.ExecuteNonQueryAsync());
                await transaction.CommitAsync();
            }

            (string Label, string Value, string SqlState, string? ConstraintName)[] invalidSignatures =
            [
                ("length-341", new string('A', 341), PostgresErrorCodes.CheckViolation, "CK_REAuthorityGenerations_Signature"),
                ("length-343", new string('A', 343), PostgresErrorCodes.StringDataRightTruncation, null),
                ("plus", "+" + new string('A', 341), PostgresErrorCodes.CheckViolation, "CK_REAuthorityGenerations_Signature"),
                ("slash", new string('A', 171) + "/" + new string('A', 170), PostgresErrorCodes.CheckViolation, "CK_REAuthorityGenerations_Signature"),
                ("padding", new string('A', 341) + "=", PostgresErrorCodes.CheckViolation, "CK_REAuthorityGenerations_Signature")
            ];
            for (var invalidSignatureIndex = 0; invalidSignatureIndex < invalidSignatures.Length; invalidSignatureIndex++)
            {
                var invalidSignature = invalidSignatures[invalidSignatureIndex];
                await using var rejected = new NpgsqlConnection(isolated);
                await rejected.OpenAsync();
                await using var rejectedTransaction = await rejected.BeginTransactionAsync();
                await using var rejectedCommand = rejected.CreateCommand();
                rejectedCommand.Transaction = rejectedTransaction;
                rejectedCommand.CommandText = """
                    INSERT INTO public."RuntimeEnrollmentAuthorityLineages"
                        ("AuthorityLineageId","Provider","ProductId","ProviderGrantRef",
                         "ProviderGrantRefScalarCount","CreatedAtUtc","HeadGenerationId","HeadSequence")
                    VALUES (@lineage,'softlicence',@product,@grant,36,@created,@generation,0);
                    INSERT INTO public."RuntimeEnrollmentAuthorityGenerations"
                        ("AuthorityGenerationId","AuthorityLineageId","Sequence","PreviousGenerationId",
                         "RequestId","CanonicalPayloadUtf8","SignedStatementUtf8","AuthorityDigest",
                         "SignatureAlgorithm","SignatureKeyId","SignatureValue","OccurredAtUtc","CreatedAtUtc")
                    VALUES (@generation,@lineage,0,NULL,@request,decode('01','hex'),@statement,
                            repeat('a',64),'PS256','historical-key',@signature,@created,@created);
                    """;
                rejectedCommand.Parameters.AddWithValue("lineage", Guid.NewGuid());
                rejectedCommand.Parameters.AddWithValue("product", productId);
                rejectedCommand.Parameters.AddWithValue("grant", Guid.NewGuid().ToString("D"));
                rejectedCommand.Parameters.AddWithValue("generation", Guid.NewGuid());
                rejectedCommand.Parameters.AddWithValue("request", Guid.NewGuid());
                rejectedCommand.Parameters.AddWithValue("created", createdAt);
                rejectedCommand.Parameters.AddWithValue("statement", statement);
                rejectedCommand.Parameters.AddWithValue("signature", invalidSignature.Value);
                var failure = await Assert.ThrowsAsync<PostgresException>(() =>
                    rejectedCommand.ExecuteNonQueryAsync());
                var diagnostic = string.Create(
                    CultureInfo.InvariantCulture,
                    $"test={nameof(AuthorityAttemptResultMigration_RealItem1UpItem3DownUpIsExactAndGuarded)}; index={invalidSignatureIndex}; label={invalidSignature.Label}; line=signature-insert; exception={failure.GetType().Name}; sqlState={failure.SqlState}; constraint={failure.ConstraintName ?? "<none>"}");
                Assert.True(
                    string.Equals(invalidSignature.SqlState, failure.SqlState, StringComparison.Ordinal),
                    diagnostic);
                Assert.True(
                    string.Equals(invalidSignature.ConstraintName, failure.ConstraintName, StringComparison.Ordinal),
                    diagnostic);
                await rejectedTransaction.RollbackAsync();
            }

            await migrator.MigrateAsync();
            await using (var connection = new NpgsqlConnection(isolated))
            {
                await connection.OpenAsync();
                await using var terminal = connection.CreateCommand();
                terminal.CommandText = """
                    SELECT "AuthorityLineageId","AuthorityGenerationId","CompletedAtUtc",
                           "HttpStatusCode","ExactResponseUtf8"
                    FROM public."RuntimeEnrollmentAuthorityRequests"
                    WHERE "RequestId"=@request;
                    """;
                terminal.Parameters.AddWithValue("request", requestId);
                await using var reader = await terminal.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal(lineageId, reader.GetGuid(0));
                Assert.Equal(generationId, reader.GetGuid(1));
                Assert.Equal(createdAt, reader.GetDateTime(2));
                Assert.Equal(StatusCodes.Status200OK, reader.GetInt32(3));
                Assert.Equal(statement, (byte[])reader[4]);
                await reader.DisposeAsync();

                Assert.Equal(3L, await ScalarAsync<long>(connection, """
                    SELECT count(*) FROM pg_catalog.pg_attribute
                    WHERE attrelid='public."RuntimeEnrollmentAuthorityRequests"'::regclass
                      AND attname IN ('CompletedAtUtc','HttpStatusCode','ExactResponseUtf8')
                      AND attnotnull AND NOT attisdropped;
                    """));
                Assert.Equal(6L, await ScalarAsync<long>(connection, """
                    SELECT count(*) FROM pg_catalog.pg_constraint
                    WHERE conrelid='public."RuntimeEnrollmentAuthorityRequests"'::regclass
                      AND conname IN ('CK_REAuthorityRequests_ResultCode','CK_REAuthorityRequests_TerminalShape',
                                      'CK_REAuthorityRequests_Chronology','CK_REAuthorityRequests_ErrorCode',
                                      'CK_REAuthorityRequests_HttpStatus','CK_REAuthorityRequests_ResponseBytes');
                    """));
                Assert.True(await ScalarAsync<bool>(connection, """
                    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                    WHERE tgrelid='public."RuntimeEnrollmentAuthorityRequests"'::regclass
                      AND tgname='trg_runtime_enrollment_authority_requests_immutable'
                      AND tgenabled='O');
                    """));
                var immutable = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection,
                    $"UPDATE public.\"RuntimeEnrollmentAuthorityRequests\" SET \"HttpStatusCode\"=201 WHERE \"RequestId\"='{requestId:D}'::uuid;"));
                Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, immutable.SqlState);
            }

            await migrator.MigrateAsync(item1Migration);
            await using (var down = new NpgsqlConnection(isolated))
            {
                await down.OpenAsync();
                Assert.Equal(0L, await ScalarAsync<long>(down, """
                    SELECT count(*) FROM pg_catalog.pg_attribute
                    WHERE attrelid='public."RuntimeEnrollmentAuthorityRequests"'::regclass
                      AND attname IN ('AuthorityLineageId','CompletedAtUtc','ErrorCode','HttpStatusCode','ExactResponseUtf8')
                      AND NOT attisdropped;
                    """));
                Assert.False(await ScalarAsync<bool>(down,
                    "SELECT to_regclass('public.\"RuntimeEnrollmentAuthorityAttempts\"') IS NOT NULL;"));
            }

            await migrator.MigrateAsync();
            await using var final = new NpgsqlConnection(isolated);
            await final.OpenAsync();
            Assert.Equal(lineageId, await ScalarAsync<Guid>(final, $"""
                SELECT "AuthorityLineageId" FROM public."RuntimeEnrollmentAuthorityRequests"
                WHERE "RequestId"='{requestId:D}'::uuid;
                """));
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, databaseName);
        }
    }
}

/// <summary>Exercises terminal replay, immutable tombstones, and recovery retry ownership.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Proves accepted and refused request/attempt terminals retain exact bytes, winning identifiers, and
    /// frozen HTTP status while digest divergence remains closed and tombstone mutations are rejected.
    /// </summary>
    [Fact]
    public async Task AuthorityGenerationPersistence_TerminalReplayAndTombstonesAreExactAndImmutable()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var authority = AuthorityPersistence(factory);
        var accepted = AuthorityCandidate();
        await using (var acceptedDb = await factory.CreateDbContextAsync())
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
                (await authority.PersistValidatedGenerationAsync(acceptedDb, accepted)).Status);
        var acceptedAttemptId = Guid.NewGuid();
        await using (var db = await factory.CreateDbContextAsync())
        await using (var lease = await authority.AcquireMutationAsync(db, Guid.NewGuid()))
        {
            await authority.PersistAttemptInAmbientTransactionAsync(db, new RuntimeEnrollmentAuthorityAttempt
            {
                AttemptId = acceptedAttemptId,
                RequestId = accepted.RequestId,
                RequestDigest = accepted.RequestDigest,
                AuthorityLineageId = accepted.AuthorityLineageId,
                AuthorityGenerationId = accepted.AuthorityGenerationId,
                Status = "ACCEPTED",
                ErrorCode = null,
                HttpStatusCode = StatusCodes.Status200OK,
                CreatedAtUtc = accepted.CreatedAtUtc,
                CompletedAtUtc = accepted.CreatedAtUtc,
                ExactResponseUtf8 = [.. accepted.SignedStatementUtf8]
            }, CancellationToken.None);
            await lease.CommitAsync();
        }

        var refusedRequestId = Guid.NewGuid();
        var refusedAttemptId = Guid.NewGuid();
        var refusedDigest = DigestFor(refusedRequestId.ToByteArray());
        var refusedBytes = "{\"error\":\"RUNTIME_ENROLLMENT_DENIED\"}"u8.ToArray();
        var refusedAt = ExactUtcNow();
        await using (var db = await factory.CreateDbContextAsync())
        await using (var lease = await authority.AcquireMutationAsync(db, Guid.NewGuid()))
        {
            var request = new RuntimeEnrollmentAuthorityRequest
            {
                RequestId = refusedRequestId,
                RequestDigest = refusedDigest,
                AuthorityLineageId = null,
                AuthorityGenerationId = null,
                ResultCode = "REFUSED",
                ErrorCode = "RECOVERY_NOT_AUTHORIZED",
                HttpStatusCode = StatusCodes.Status403Forbidden,
                CreatedAtUtc = refusedAt,
                CompletedAtUtc = refusedAt,
                ExactResponseUtf8 = [.. refusedBytes]
            };
            var attempt = new RuntimeEnrollmentAuthorityAttempt
            {
                AttemptId = refusedAttemptId,
                RequestId = refusedRequestId,
                RequestDigest = refusedDigest,
                AuthorityLineageId = null,
                AuthorityGenerationId = null,
                Status = "REFUSED",
                ErrorCode = "RECOVERY_NOT_AUTHORIZED",
                HttpStatusCode = StatusCodes.Status403Forbidden,
                CreatedAtUtc = refusedAt,
                CompletedAtUtc = refusedAt,
                ExactResponseUtf8 = [.. refusedBytes]
            };
            await authority.PersistRefusedResultInAmbientTransactionAsync(
                db, request, attempt, CancellationToken.None);
            await lease.CommitAsync();
        }

        await using (var check = await factory.CreateDbContextAsync())
        {
            var acceptedRequest = await check.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                .SingleAsync(row => row.RequestId == accepted.RequestId);
            var acceptedAttempt = await check.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
                .SingleAsync(row => row.AttemptId == acceptedAttemptId);
            Assert.Equal(accepted.SignedStatementUtf8, acceptedRequest.ExactResponseUtf8);
            Assert.Equal(accepted.SignedStatementUtf8, acceptedAttempt.ExactResponseUtf8);
            Assert.Equal(accepted.AuthorityLineageId, acceptedAttempt.AuthorityLineageId);
            Assert.Equal(accepted.AuthorityGenerationId, acceptedAttempt.AuthorityGenerationId);
            Assert.Equal(StatusCodes.Status200OK,
                RuntimeEnrollmentAuthorityV2Coordinator.ReplayStatus(
                    acceptedAttempt.Status, acceptedAttempt.HttpStatusCode));

            var refusedRequest = await check.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                .SingleAsync(row => row.RequestId == refusedRequestId);
            var refusedAttempt = await check.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
                .SingleAsync(row => row.AttemptId == refusedAttemptId);
            Assert.Equal(refusedBytes, refusedRequest.ExactResponseUtf8);
            Assert.Equal(refusedBytes, refusedAttempt.ExactResponseUtf8);
            Assert.Null(refusedAttempt.AuthorityLineageId);
            Assert.Null(refusedAttempt.AuthorityGenerationId);
            Assert.Equal(StatusCodes.Status403Forbidden,
                RuntimeEnrollmentAuthorityV2Coordinator.ReplayStatus(
                    refusedAttempt.Status, refusedAttempt.HttpStatusCode));
            Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.ExactAttempt,
                RuntimeEnrollmentAuthorityReplayRules.Classify(
                    refusedAttempt, refusedRequest, refusedRequestId, refusedDigest));
            Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.AttemptIdReuse,
                RuntimeEnrollmentAuthorityReplayRules.Classify(
                    refusedAttempt, refusedRequest, refusedRequestId, new string('f', 64)));
            Assert.Equal(RuntimeEnrollmentAuthorityReplayDecision.RequestReplayDivergence,
                RuntimeEnrollmentAuthorityReplayRules.Classify(
                    null, refusedRequest, refusedRequestId, new string('f', 64)));
        }

        await using var app = new NpgsqlConnection(connections.App);
        await app.OpenAsync();
        foreach (var statement in new[]
        {
            $"UPDATE public.\"RuntimeEnrollmentAuthorityAttempts\" SET \"HttpStatusCode\"=400 WHERE \"AttemptId\"='{refusedAttemptId:D}'::uuid;",
            $"DELETE FROM public.\"RuntimeEnrollmentAuthorityAttempts\" WHERE \"AttemptId\"='{refusedAttemptId:D}'::uuid;",
            "TRUNCATE public.\"RuntimeEnrollmentAuthorityAttempts\";",
            $"UPDATE public.\"RuntimeEnrollmentAuthorityRequests\" SET \"HttpStatusCode\"=400 WHERE \"RequestId\"='{refusedRequestId:D}'::uuid;",
            $"DELETE FROM public.\"RuntimeEnrollmentAuthorityRequests\" WHERE \"RequestId\"='{refusedRequestId:D}'::uuid;"
        })
        {
            var immutable = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(app, statement));
            Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, immutable.SqlState);
        }
    }

    /// <summary>
    /// Rejects lineage or generation substitution and every invalid accepted/refused HTTP terminal shape
    /// through the production model and PostgreSQL constraints.
    /// </summary>
    [Fact]
    public async Task AuthorityTerminalRelations_RejectSubstitutedIdsAndInvalidHttpShapes()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var authority = AuthorityPersistence(factory);
        var accepted = AuthorityCandidate();
        await using (var db = await factory.CreateDbContextAsync())
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
                (await authority.PersistValidatedGenerationAsync(db, accepted)).Status);
        var at = ExactUtcNow();
        var body = "{\"error\":\"RUNTIME_ENROLLMENT_DENIED\"}"u8.ToArray();

        RuntimeEnrollmentAuthorityAttempt Attempt(
            string status, int http, Guid? lineage, Guid? generation, string? error) => new()
        {
            AttemptId = Guid.NewGuid(), RequestId = accepted.RequestId,
            RequestDigest = accepted.RequestDigest, AuthorityLineageId = lineage,
            AuthorityGenerationId = generation, Status = status, ErrorCode = error,
            HttpStatusCode = http, CreatedAtUtc = at, CompletedAtUtc = at,
            ExactResponseUtf8 = [.. body]
        };
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
            (await RejectAttemptInsertAsync(factory, Attempt("ACCEPTED", 200,
                Guid.NewGuid(), accepted.AuthorityGenerationId, null))).SqlState);
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
            (await RejectAttemptInsertAsync(factory, Attempt("ACCEPTED", 200,
                accepted.AuthorityLineageId, Guid.NewGuid(), null))).SqlState);
        Assert.Equal(PostgresErrorCodes.CheckViolation,
            (await RejectAttemptInsertAsync(factory, Attempt("REFUSED", 403,
                accepted.AuthorityLineageId, null, "DENIED"))).SqlState);
        Assert.Equal(PostgresErrorCodes.CheckViolation,
            (await RejectAttemptInsertAsync(factory, Attempt("ACCEPTED", 403,
                accepted.AuthorityLineageId, accepted.AuthorityGenerationId, null))).SqlState);
        Assert.Equal(PostgresErrorCodes.CheckViolation,
            (await RejectAttemptInsertAsync(factory, Attempt("REFUSED", 200,
                null, null, "DENIED"))).SqlState);

        RuntimeEnrollmentAuthorityRequest Request(
            string result, int http, Guid? lineage, Guid? generation, string? error) => new()
        {
            RequestId = Guid.NewGuid(), RequestDigest = DigestFor(Guid.NewGuid().ToByteArray()),
            AuthorityLineageId = lineage, AuthorityGenerationId = generation,
            ResultCode = result, ErrorCode = error, HttpStatusCode = http,
            CreatedAtUtc = at, CompletedAtUtc = at, ExactResponseUtf8 = [.. body]
        };
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
            (await RejectRequestInsertAsync(factory, Request("ACCEPTED", 200,
                Guid.NewGuid(), accepted.AuthorityGenerationId, null))).SqlState);
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
            (await RejectRequestInsertAsync(factory, Request("ACCEPTED", 200,
                accepted.AuthorityLineageId, Guid.NewGuid(), null))).SqlState);
        Assert.Equal(PostgresErrorCodes.CheckViolation,
            (await RejectRequestInsertAsync(factory, Request("REFUSED", 403,
                accepted.AuthorityLineageId, null, "DENIED"))).SqlState);
        Assert.Equal(PostgresErrorCodes.CheckViolation,
            (await RejectRequestInsertAsync(factory, Request("ACCEPTED", 403,
                accepted.AuthorityLineageId, accepted.AuthorityGenerationId, null))).SqlState);
        Assert.Equal(PostgresErrorCodes.CheckViolation,
            (await RejectRequestInsertAsync(factory, Request("REFUSED", 200,
                null, null, "DENIED"))).SqlState);
    }

    /// <summary>
    /// Proves recovery proof consumption rolls back with its transaction, retries exactly, and observes
    /// compromise/revocation lifecycle boundaries without executing outside the PostgreSQL harness.
    /// </summary>
    [Fact]
    public async Task AuthorityRecoveryProof_RollbackRetryIsIdempotentAndLifecycleIsExact()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var now = new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero);
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var activeOptions = AuthoritySigningOptions(now, operational, recovery);
        var crypto = new RuntimeEnrollmentAuthorityCryptography(
            new FixedTimeProvider(now), registry.ExportSubjectPublicKeyInfo());
        var activeSnapshot = AuthenticateAuthoritySnapshot(crypto, activeOptions, registry, now);
        var payload = AuthorityPayloadBytes();
        var canonical = crypto.CanonicalizeGenerationPayload(payload).Value!.CanonicalUtf8;
        var recoveryInput = Encoding.UTF8.GetBytes(
            "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n"
            + Encoding.UTF8.GetString(canonical));
        var signature = Base64Url(recovery.SignData(
            recoveryInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var proof = crypto.VerifyRecoverySignature(
            payload, "recovery-2026-01", signature, activeSnapshot).Value!;

        var authority = AuthorityPersistence(factory);
        var rolledBackRequestId = Guid.NewGuid();
        var rolledBackAttemptId = Guid.NewGuid();
        var rolledBackDigest = DigestFor(rolledBackRequestId.ToByteArray());
        var rolledBackAt = ExactUtcNow();
        var rolledBackBody = "{\"error\":\"RUNTIME_ENROLLMENT_DENIED\"}"u8.ToArray();
        await using (var db = await factory.CreateDbContextAsync())
        await using (await authority.AcquireMutationAsync(db, Guid.NewGuid()))
        {
            Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None,
                crypto.ConsumeRecoveryProof(proof, payload, "recovery-2026-01", activeSnapshot));
            await authority.PersistRefusedResultInAmbientTransactionAsync(db,
                new RuntimeEnrollmentAuthorityRequest
                {
                    RequestId = rolledBackRequestId,
                    RequestDigest = rolledBackDigest,
                    ResultCode = "REFUSED",
                    ErrorCode = "RECOVERY_NOT_AUTHORIZED",
                    HttpStatusCode = StatusCodes.Status403Forbidden,
                    CreatedAtUtc = rolledBackAt,
                    CompletedAtUtc = rolledBackAt,
                    ExactResponseUtf8 = [.. rolledBackBody]
                },
                new RuntimeEnrollmentAuthorityAttempt
                {
                    AttemptId = rolledBackAttemptId,
                    RequestId = rolledBackRequestId,
                    RequestDigest = rolledBackDigest,
                    Status = "REFUSED",
                    ErrorCode = "RECOVERY_NOT_AUTHORIZED",
                    HttpStatusCode = StatusCodes.Status403Forbidden,
                    CreatedAtUtc = rolledBackAt,
                    CompletedAtUtc = rolledBackAt,
                    ExactResponseUtf8 = [.. rolledBackBody]
                }, CancellationToken.None);
        }
        await using (var rollbackCheck = await factory.CreateDbContextAsync())
        {
            Assert.False(await rollbackCheck.RuntimeEnrollmentAuthorityRequests.AnyAsync(row =>
                row.RequestId == rolledBackRequestId));
            Assert.False(await rollbackCheck.RuntimeEnrollmentAuthorityAttempts.AnyAsync(row =>
                row.AttemptId == rolledBackAttemptId));
        }
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.Failure.None,
            crypto.ConsumeRecoveryProof(proof, payload, "recovery-2026-01", activeSnapshot));

        var revokedOptions = AuthoritySigningOptions(now, operational, recovery, revokedRecovery: true);
        var revokedSnapshot = AuthenticateAuthoritySnapshot(crypto, revokedOptions, registry, now);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Valid,
            revokedSnapshot.ClassifyRecovery("recovery-2026-01", now.AddHours(-3), now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Compromised,
            revokedSnapshot.ClassifyRecovery("recovery-2026-01", now.AddMinutes(-90), now).Outcome);
        Assert.Equal(RuntimeEnrollmentAuthorityCryptography.KeyLifecycleOutcome.Revoked,
            revokedSnapshot.ClassifyRecovery("recovery-2026-01", now.AddHours(-1), now).Outcome);
    }
}

/// <summary>Exercises Runtime Enrollment v2 authority persistence against the existing PostgreSQL harness.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Traverses the production coordinator under its ambient transaction, proves exact advisory lock
    /// identities/modes, proves both enrollment key references use one provisioned registry identity and
    /// reject an unknown substitution, then traverses the runtime service with two independent contexts and attempts.
    /// PostgreSQL execution remains owned by the separately supervised recipe.
    /// </summary>
    [Fact]
    public async Task AuthorityGenerationCoordinator_RealServiceConvergesAndUsesExactLocks()
    {
        await AssertProvisioningFailureBeforeLeaseDropsDatabaseAsync();
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (isolated.Admin, isolated.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.3.445", "*");
        await ProvisionEnrollmentEncryptionKeyAsync(connections.Admin, "test");
        DateTimeOffset now;
        await using (var clock = await factory.CreateDbContextAsync())
        {
            await clock.Database.OpenConnectionAsync();
            now = await RuntimeEnrollmentService.DatabaseNowAsync(clock, CancellationToken.None);
        }
        const string artifactDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        DistributionInstallationBinding binding;
        RuntimeEnrollment enrollment;
        License license;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            binding = await seed.DistributionInstallationBindings.SingleAsync(item => item.Id == fixture.BindingId);
            license = await seed.Licenses.SingleAsync(item => item.Id == binding.LicenseId);
            license.CreationDate = now.UtcDateTime.AddDays(-1);
            license.ActivationDate = license.CreationDate;
            license.ExpirationDate = now.UtcDateTime.AddDays(1);
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
                KeyThumbprint = Base64Url(SHA256.HashData(enrollmentId.ToByteArray())), ChallengeCiphertext = "test",
                ChallengeKeyId = "test", ChallengeKeyPurpose = "encryption",
                ChallengeDigestSha256 = new string('2', 64), State = "ACTIVE", Epoch = 1,
                SecurityEpoch = 7, ChallengeExpiresAtUtc = now.UtcDateTime.AddMinutes(5),
                CreatedAtUtc = license.CreationDate, ActivatedAtUtc = license.CreationDate
            };
            seed.RuntimeEnrollments.Add(enrollment);
            seed.ApprovedBinaryRegistrations.Add(new ApprovedBinaryRegistration
            {
                ProductId = fixture.ProductId, Version = binding.Version,
                RegistrationKey = $"runtime-authority-proof-{fixture.ProductId:D}", ManifestDigestSha256 = new string('b', 64),
                BaselineDigestSha256 = artifactDigest, Source = "release", RegisteredAtUtc = now.UtcDateTime
            });
            await seed.SaveChangesAsync();
            enrollment.HardwareIdHash = new string('9', 64);
            await seed.SaveChangesAsync();
            await seed.Entry(binding).ReloadAsync();
            await seed.Entry(license).ReloadAsync();
            await seed.Entry(enrollment).ReloadAsync();
        }

        await using (var rejected = new NpgsqlConnection(connections.App))
        {
            await rejected.OpenAsync();
            await using var command = rejected.CreateCommand();
            command.CommandText = """
                UPDATE public."RuntimeEnrollments"
                SET "PublicKeySpkiKeyId" = 'unknown-encryption-key'
                WHERE "Id" = @enrollmentId;
                """;
            command.Parameters.AddWithValue("enrollmentId", enrollment.Id);
            var failure = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, failure.SqlState);
            Assert.Equal("FK_RuntimeEnrollments_PublicKey_KeyRegistry", failure.ConstraintName);
        }

        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        using var registryAuthority = RSA.Create(2048);
        using var capabilityActive = RSA.Create(3072);
        using var capabilityNext = RSA.Create(3072);
        var runtime = AuthorityRuntime(factory, fixture.ProductId, now,
            operational, recovery, registryAuthority, capabilityActive, capabilityNext);
        using var runtimeCrypto = runtime.RuntimeCrypto;
        var requestId = Guid.NewGuid();
        var body = AuthorityGenesisRequest(
            requestId, fixture.ProductId, binding, enrollment, license, artifactDigest, now.UtcDateTime);
        var prepared = runtime.Coordinator.Prepare(
            "website-step1", "s2s-runtime-test", Guid.NewGuid(), body, null, null);

        var mismatchedLicense = new License
        {
            LicenseKey = "ITEM3HB-LICENSE-MISMATCH-" + Guid.NewGuid().ToString("N"),
            LicenseTypeId = license.LicenseTypeId,
            ProductId = fixture.ProductId,
            CreationDate = now.UtcDateTime.AddDays(-1),
            ActivationDate = now.UtcDateTime.AddDays(-1),
            ExpirationDate = now.UtcDateTime.AddDays(1),
            AllowedVersions = "*",
            MaxSeats = 1,
            IsActive = true
        };
        await using (var mismatchSeed = await factory.CreateDbContextAsync())
        {
            mismatchSeed.Licenses.Add(mismatchedLicense);
            await mismatchSeed.SaveChangesAsync();
        }

        // The item-2 trigger is deferred, so this transaction exposes the exact inconsistent live graph
        // to the authority resolver without committing or bypassing database guards. The ACTIVE assignment
        // must not authorize a binding that points at another licence.
        var mismatchRequestId = Guid.NewGuid();
        var mismatchBody = AuthorityGenesisRequest(
            mismatchRequestId, fixture.ProductId, binding, enrollment, license,
            artifactDigest, now.UtcDateTime);
        var mismatchPrepared = runtime.Coordinator.Prepare(
            "website-step1", "s2s-runtime-test", Guid.NewGuid(), mismatchBody, null, null);
        await using (var mismatchDb = await factory.CreateDbContextAsync())
        await using (await runtime.Authority.AcquireMutationAsync(mismatchDb, binding.Id))
        {
            var mutableBinding = await mismatchDb.DistributionInstallationBindings
                .SingleAsync(item => item.Id == binding.Id);
            mutableBinding.LicenseId = mismatchedLicense.Id;
            await mismatchDb.SaveChangesAsync();

            var deniedMismatch = await runtime.Coordinator.ExecuteAmbientAsync(
                mismatchDb, mismatchPrepared, CancellationToken.None);
            Assert.Equal(StatusCodes.Status403Forbidden, deniedMismatch.StatusCode);
            Assert.False(await mismatchDb.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                .AnyAsync(item => item.RequestId == mismatchRequestId));
        }

        await using (var eligibility = await factory.CreateDbContextAsync())
        {
            var persisted = await eligibility.RuntimeEnrollments.AsNoTracking()
                .SingleAsync(item => item.Id == enrollment.Id);
            var persistedBinding = await eligibility.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(item => item.Id == binding.Id);
            var persistedLicense = await eligibility.Licenses.AsNoTracking()
                .SingleAsync(item => item.Id == license.Id);
            var requestAuthority = prepared.Request.RequestedAuthority;
            var provenanceChecks = new Dictionary<string, bool>
            {
                ["owner"] = await eligibility.DistributionBindingRequests.AsNoTracking().AnyAsync(item =>
                    item.BindingId == binding.Id && item.ClientId == "website-step1"
                        && item.Operation == "finalize_binding"),
                ["binding"] = persistedBinding.ProductId == fixture.ProductId
                    && persistedBinding.GrantRef == prepared.GrantRef
                    && persistedBinding.HardwareIdHash == requestAuthority.Binding.HardwareIdDigest
                    && persistedBinding.Version == requestAuthority.Release.Version
                    && persistedBinding.InstallationId == requestAuthority.Installation.InstallationId
                    && persistedBinding.LicenseSeatId == prepared.LicenseSeatId
                    && persistedBinding.LicenseSeatId.ToString("D") == requestAuthority.Installation.SeatId
                    && persistedBinding.State == "active",
                ["enrollment"] = persisted.ClientId == "website-step1"
                    && persisted.ProductId == fixture.ProductId && persisted.BindingId == binding.Id
                    && persisted.InstallationId == requestAuthority.Installation.InstallationId
                    && persisted.ReleaseVersion == requestAuthority.Release.Version
                    && persisted.SecurityEpoch == requestAuthority.Key.SecurityEpoch,
                ["issued"] = (persistedLicense.ActivationDate ?? persistedLicense.CreationDate)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture)
                    == requestAuthority.Enrollment.IssuedAtUtc,
                ["expiry"] = persistedLicense.ExpirationDate?.ToString(
                    "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture)
                    == requestAuthority.Enrollment.ExpiresAtUtc
            };
            Assert.True(provenanceChecks.All(item => item.Value),
                string.Join(",", provenanceChecks.Select(item => $"{item.Key}={item.Value}")));
            var approvedRelease = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
                eligibility, persisted, CancellationToken.None);
            await eligibility.Database.OpenConnectionAsync();
            var currentDatabaseTime = await RuntimeEnrollmentService.DatabaseNowAsync(
                eligibility, CancellationToken.None);
            var assessment = await RuntimeCommercialEligibilityValidator.AssessAsync(
                eligibility, persisted, approvedRelease.Binaries,
                currentDatabaseTime, null, CancellationToken.None);
            Assert.True(assessment.IsEligible, assessment.DenialReason);
            Assert.Equal(prepared.LicenseSeatId, assessment.Assignment!.SeatId);
            Assert.Equal("active", requestAuthority.Enrollment.State);
            Assert.Equal("ACTIVE", persisted.State);
        }

        await using (var db = await factory.CreateDbContextAsync())
        await using (await runtime.Authority.AcquireMutationAsync(db, binding.Id))
        {
            var result = await runtime.Coordinator.ExecuteAmbientAsync(db, prepared, CancellationToken.None);
            var storedResult = await db.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                .SingleAsync(item => item.RequestId == requestId);
            Assert.True(result.StatusCode == StatusCodes.Status201Created,
                storedResult.ErrorCode ?? Encoding.UTF8.GetString(result.ExactResponseBody));
            Assert.False(result.Idempotent);
            using var statement = JsonDocument.Parse(result.ExactResponseBody);
            Assert.Equal(0, statement.RootElement.GetProperty("payload")
                .GetProperty("sequence").GetInt64());
            var locks = await CurrentAdvisoryLocksAsync(db);
            Assert.Contains("999831:1:2:ExclusiveLock", locks);
            Assert.Contains(await AdvisoryHashLockIdentityAsync(db, binding.Id.ToString("D"), 999831), locks);
            Assert.Contains(await AdvisoryHashLockIdentityAsync(db, requestId.ToString("D"), 62901), locks);
            Assert.Contains(await AdvisoryHashLockIdentityAsync(db, prepared.AttemptId.ToString("D"), 62902), locks);
            var tuple = $"{Encoding.UTF8.GetByteCount("softlicence")}:softlicence:{fixture.ProductId:D}:"
                + $"{Encoding.UTF8.GetByteCount(binding.GrantRef)}:{binding.GrantRef}:"
                + binding.LicenseSeatId.ToString("D");
            Assert.Contains(await AdvisoryHashLockIdentityAsync(
                db, "runtime-enrollment-v2:tuple:" + tuple, 999831), locks);
        }

        var calls = await Task.WhenAll(
            runtime.Service.IssueAuthorityGenerationV2Async(
                "website-step1", "s2s-runtime-test", Guid.NewGuid(), body, null, null),
            runtime.Service.IssueAuthorityGenerationV2Async(
                "website-step1", "s2s-runtime-test", Guid.NewGuid(), body, null, null));
        Assert.Single(calls, item => !item.Idempotent);
        Assert.Single(calls, item => item.Idempotent);
        Assert.Equal(calls[0].ExactResponseBody, calls[1].ExactResponseBody);
        var recoveredAfterLostResponse = await runtime.Service.IssueAuthorityGenerationV2Async(
            "website-step1", "s2s-runtime-test", Guid.NewGuid(), body, null, null);
        Assert.True(recoveredAfterLostResponse.Idempotent);
        Assert.Equal(calls[0].ExactResponseBody, recoveredAfterLostResponse.ExactResponseBody);
        await using var check = await factory.CreateDbContextAsync();
        var storedRequest = await check.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
            .SingleAsync(item => item.RequestId == requestId);
        var storedGeneration = await check.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleAsync(item => item.RequestId == requestId);
        var storedLineage = await check.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
            .SingleAsync(item => item.AuthorityLineageId == storedGeneration.AuthorityLineageId);
        Assert.Equal(storedGeneration.AuthorityGenerationId, storedLineage.HeadGenerationId);
        Assert.Equal(storedGeneration.Sequence, storedLineage.HeadSequence);
        Assert.Equal(storedGeneration.AuthorityGenerationId, storedRequest.AuthorityGenerationId);
        Assert.Equal(3, await check.RuntimeEnrollmentAuthorityAttempts.CountAsync(item => item.RequestId == requestId));
        Assert.All(await check.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
                .Where(item => item.RequestId == requestId).ToListAsync(),
            attempt =>
            {
                Assert.Equal("ACCEPTED", attempt.Status);
                Assert.Equal(storedGeneration.AuthorityGenerationId, attempt.AuthorityGenerationId);
                Assert.Equal(storedRequest.ExactResponseUtf8, attempt.ExactResponseUtf8);
            });

        var persistedEnrollment = await check.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(item => item.Id == enrollment.Id);
        var beforeEpoch = persistedEnrollment.Epoch;
        var beforeSecurityEpoch = persistedEnrollment.SecurityEpoch;
        var beforeAuthorityEpoch = persistedEnrollment.AuthorityEpoch;
        await using (var policyChange = await factory.CreateDbContextAsync())
        {
            var currentSeat = await policyChange.LicenseSeats.SingleAsync(item =>
                item.Id == binding.LicenseSeatId);
            currentSeat.IsActive = false;
            await policyChange.SaveChangesAsync();
        }

        var frozenReplay = await runtime.Service.IssueAuthorityGenerationV2Async(
            "website-step1", "s2s-runtime-test", Guid.NewGuid(), body, null, null);
        Assert.True(frozenReplay.Idempotent);
        Assert.Equal(StatusCodes.Status200OK, frozenReplay.StatusCode);
        Assert.Equal(storedRequest.ExactResponseUtf8, frozenReplay.ExactResponseBody);

        await using var deniedGrant = await factory.CreateDbContextAsync();
        var unchangedEnrollment = await deniedGrant.RuntimeEnrollments.AsNoTracking()
            .SingleAsync(item => item.Id == enrollment.Id);
        var approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
            deniedGrant, unchangedEnrollment, CancellationToken.None);
        var denial = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            RuntimeCommercialEligibilityValidator.ValidateAsync(
                deniedGrant, unchangedEnrollment, approved.Binaries,
                new DateTimeOffset(ExactUtcNow(), TimeSpan.Zero), CancellationToken.None));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, denial.StatusCode);
        Assert.Equal(beforeEpoch, unchangedEnrollment.Epoch);
        Assert.Equal(beforeSecurityEpoch, unchangedEnrollment.SecurityEpoch);
        Assert.Equal(beforeAuthorityEpoch, unchangedEnrollment.AuthorityEpoch);
        Assert.Single(await deniedGrant.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .Where(item => item.RequestId == requestId).ToListAsync());
    }

    /// <summary>
    /// Traverses the complete two-stage production recovery path for compromised and revoked predecessor
    /// instants using one provisioned registry identity for both enrollment key references, commits the
    /// server-reserved generation despite an application clock ahead of PostgreSQL, replays exact bytes,
    /// and rejects scope/head/key substitution.
    /// PostgreSQL execution remains owned by the separately supervised recipe.
    /// </summary>
    [Theory]
    [InlineData(-90)]
    [InlineData(0)]
    public async Task AuthorityRecovery_TwoStageProductionFlowCommitsAndReplaysExactly(
        int occurredMinutesFromNow)
    {
        await using var isolated = await ProvisionCleanedIsolatedAsync();
        var connections = (isolated.Admin, isolated.App);
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, "2.3.445", "*");
        await ProvisionEnrollmentEncryptionKeyAsync(connections.Admin, "test");
        DateTimeOffset now;
        await using (var clock = await factory.CreateDbContextAsync())
        {
            await clock.Database.OpenConnectionAsync();
            now = await RuntimeEnrollmentService.DatabaseNowAsync(clock, CancellationToken.None);
        }
        const string artifactDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        DistributionInstallationBinding binding;
        RuntimeEnrollment enrollment;
        License license;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            binding = await seed.DistributionInstallationBindings.SingleAsync(item => item.Id == fixture.BindingId);
            license = await seed.Licenses.SingleAsync(item => item.Id == binding.LicenseId);
            license.CreationDate = now.UtcDateTime.AddDays(-1);
            license.ActivationDate = license.CreationDate;
            license.ExpirationDate = now.UtcDateTime.AddDays(1);
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
                KeyThumbprint = Base64Url(SHA256.HashData(enrollmentId.ToByteArray())), ChallengeCiphertext = "test",
                ChallengeKeyId = "test", ChallengeKeyPurpose = "encryption",
                ChallengeDigestSha256 = new string('2', 64), State = "ACTIVE", Epoch = 1,
                SecurityEpoch = 7, ChallengeExpiresAtUtc = now.UtcDateTime.AddMinutes(5),
                CreatedAtUtc = license.CreationDate, ActivatedAtUtc = license.CreationDate
            };
            seed.RuntimeEnrollments.Add(enrollment);
            seed.ApprovedBinaryRegistrations.Add(new ApprovedBinaryRegistration
            {
                ProductId = fixture.ProductId, Version = binding.Version,
                RegistrationKey = $"runtime-recovery-proof-{fixture.ProductId:D}", ManifestDigestSha256 = new string('b', 64),
                BaselineDigestSha256 = artifactDigest, Source = "release", RegisteredAtUtc = now.UtcDateTime
            });
            await seed.SaveChangesAsync();
            await seed.Entry(binding).ReloadAsync();
            await seed.Entry(license).ReloadAsync();
            await seed.Entry(enrollment).ReloadAsync();
        }
        using var predecessorKey = RSA.Create(2048);
        using var successorKey = RSA.Create(2048);
        using var recoveryKey = RSA.Create(2048);
        using var registryAuthority = RSA.Create(2048);
        using var capabilityActive = RSA.Create(3072);
        using var capabilityNext = RSA.Create(3072);
        var genesisRuntime = AuthorityRuntime(factory, fixture.ProductId, now,
            predecessorKey, recoveryKey, registryAuthority, capabilityActive, capabilityNext);
        using var genesisCrypto = genesisRuntime.RuntimeCrypto;
        var genesisRequestId = Guid.NewGuid();
        var genesisBody = AuthorityGenesisRequest(genesisRequestId, fixture.ProductId,
            binding, enrollment, license, artifactDigest, now.UtcDateTime.AddHours(-3));
        var genesisResult = await genesisRuntime.Service.IssueAuthorityGenerationV2Async(
            "website-step1", "s2s-runtime-test", Guid.NewGuid(), genesisBody, null, null);
        string? genesisError = null;
        if (genesisResult.StatusCode != StatusCodes.Status201Created)
        {
            await using var genesisCheck = await factory.CreateDbContextAsync();
            genesisError = await genesisCheck.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                .Where(item => item.RequestId == genesisRequestId)
                .Select(item => item.ErrorCode)
                .SingleOrDefaultAsync();
        }
        Assert.True(genesisResult.StatusCode == StatusCodes.Status201Created,
            genesisError ?? Encoding.UTF8.GetString(genesisResult.ExactResponseBody));

        RuntimeEnrollmentAuthorityGenerationPayloadV2 predecessor;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var generation = await seed.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                .SingleAsync(item => item.RequestId == genesisRequestId);
            predecessor = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
                generation.CanonicalPayloadUtf8, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions())!;
            seed.RuntimeCriticalRecoveries.Add(new RuntimeCriticalRecovery
            {
                EnrollmentId = enrollment.Id, BindingId = binding.Id, ProductId = fixture.ProductId,
                InstallationId = binding.InstallationId, RequestedEventId = Guid.NewGuid().ToString("D"),
                OldSecurityEpoch = 7, NewSecurityEpoch = 8, ResolvedIncidentCount = 1,
                AuthorityEpoch = 1, RecoveredByClientId = "website-step1",
                RecoveredByKeyId = "s2s-runtime-test", RecoveredAtUtc = now.UtcDateTime
            });
            await seed.SaveChangesAsync();
        }
        var recoveryOptions = AuthorityRecoverySigningOptions(
            now, predecessorKey, successorKey, recoveryKey);
        var recoveryRuntime = AuthorityRuntime(factory, fixture.ProductId, now,
            recoveryOptions, registryAuthority, capabilityActive, capabilityNext);
        using var recoveryRuntimeCrypto = recoveryRuntime.RuntimeCrypto;
        if (occurredMinutesFromNow == 0)
        {
            var blockedRequestId = Guid.NewGuid();
            var blockedAttemptId = Guid.NewGuid();
            var blockedBody = AuthorityRecoveryRequest(
                blockedRequestId, predecessor, "operational-2026-02", 8, now.UtcDateTime);
            var blockedPreparation = await recoveryRuntime.Service.PrepareAuthorityRecoveryV2Async(
                "website-step1", "s2s-runtime-test", blockedAttemptId, blockedBody);
            using var blockedJson = JsonDocument.Parse(blockedPreparation.ExactResponseBody);
            var blockedPayload = DecodeBase64Url(blockedJson.RootElement
                .GetProperty("payloadUtf8Base64Url").GetString()!);
            var blockedSignature = Base64Url(recoveryKey.SignData(
                Encoding.UTF8.GetBytes(
                    "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n"
                    + Encoding.UTF8.GetString(blockedPayload)),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            Guid banId;
            await using (var ban = await factory.CreateDbContextAsync())
            {
                var seatHardware = await ban.LicenseSeats.AsNoTracking()
                    .Where(item => item.Id == binding.LicenseSeatId)
                    .Select(item => item.HardwareId)
                    .SingleAsync();
                var row = new BannedHardwareId
                {
                    HardwareId = seatHardware,
                    ProductId = fixture.ProductId,
                    Reason = "Item 3H-B recovery commercial recheck",
                    BanCategory = BannedHardwareId.Categories.Piracy,
                    IsActive = true
                };
                ban.BannedHardwareIds.Add(row);
                await ban.SaveChangesAsync();
                banId = row.Id;
            }

            var prepareDenied = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
                recoveryRuntime.Service.PrepareAuthorityRecoveryV2Async(
                    "website-step1", "s2s-runtime-test", Guid.NewGuid(),
                    AuthorityRecoveryRequest(Guid.NewGuid(), predecessor,
                        "operational-2026-02", 8, now.UtcDateTime)));
            Assert.Equal(StatusCodes.Status403Forbidden, prepareDenied.StatusCode);
            Assert.Equal("RECOVERY_NOT_AUTHORIZED", prepareDenied.DiagnosticCode);

            var finalizeDenied = await recoveryRuntime.Service.FinalizeAuthorityRecoveryV2Async(
                "website-step1", "s2s-runtime-test", blockedAttemptId, blockedBody,
                blockedJson.RootElement.GetProperty("preparationToken").GetString()!,
                "recovery-2026-01", blockedSignature);
            Assert.Equal(StatusCodes.Status403Forbidden, finalizeDenied.StatusCode);
            await using (var unban = await factory.CreateDbContextAsync())
            {
                var row = await unban.BannedHardwareIds.SingleAsync(item => item.Id == banId);
                row.IsActive = false;
                await unban.SaveChangesAsync();
            }
            await using var blockedCheck = await factory.CreateDbContextAsync();
            Assert.False(await blockedCheck.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                .AnyAsync(item => item.RequestId == blockedRequestId));
        }
        var attemptId = Guid.NewGuid();
        var occurred = now.AddMinutes(occurredMinutesFromNow).UtcDateTime;
        var recoveryRequestId = Guid.NewGuid();
        var recoveryBody = AuthorityRecoveryRequest(
            recoveryRequestId, predecessor, "operational-2026-02", 8, occurred);
        var preparation = await recoveryRuntime.Service.PrepareAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", attemptId, recoveryBody);
        using var preparationJson = JsonDocument.Parse(preparation.ExactResponseBody);
        var payload = DecodeBase64Url(preparationJson.RootElement
            .GetProperty("payloadUtf8Base64Url").GetString()!);
        var token = preparationJson.RootElement.GetProperty("preparationToken").GetString()!;
        var preparationExpiresAt = DateTimeOffset.Parse(
            preparationJson.RootElement.GetProperty("expiresAtUtc").GetString()!,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        var signature = Base64Url(recoveryKey.SignData(
            Encoding.UTF8.GetBytes(
                "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n"
                + Encoding.UTF8.GetString(payload)),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        var expiringAttemptId = Guid.NewGuid();
        var expiringBody = AuthorityRecoveryRequest(
            Guid.NewGuid(), predecessor, "operational-2026-02", 8, occurred);
        var expiringPreparation = await recoveryRuntime.Service.PrepareAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", expiringAttemptId, expiringBody);
        using var expiringJson = JsonDocument.Parse(expiringPreparation.ExactResponseBody);
        var expiringPayload = DecodeBase64Url(expiringJson.RootElement
            .GetProperty("payloadUtf8Base64Url").GetString()!);
        var expiringSignature = Base64Url(recoveryKey.SignData(
            Encoding.UTF8.GetBytes(
                "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n"
                + Encoding.UTF8.GetString(expiringPayload)),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var sameKey = AuthorityRecoveryRequest(Guid.NewGuid(), predecessor,
            "operational-2026-01", 8, occurred);
        var sameKeyAttempt = Guid.NewGuid();
        var sameKeyPreparation = await recoveryRuntime.Service.PrepareAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", sameKeyAttempt, sameKey);
        using (var sameKeyJson = JsonDocument.Parse(sameKeyPreparation.ExactResponseBody))
        {
            var sameKeyPayload = DecodeBase64Url(sameKeyJson.RootElement
                .GetProperty("payloadUtf8Base64Url").GetString()!);
            var sameKeySignature = Base64Url(recoveryKey.SignData(
                Encoding.UTF8.GetBytes(
                    "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n"
                    + Encoding.UTF8.GetString(sameKeyPayload)),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            var sameKeyResult = await recoveryRuntime.Service.FinalizeAuthorityRecoveryV2Async(
                "website-step1", "s2s-runtime-test", sameKeyAttempt, sameKey,
                sameKeyJson.RootElement.GetProperty("preparationToken").GetString()!,
                "recovery-2026-01", sameKeySignature);
            Assert.Equal(StatusCodes.Status403Forbidden, sameKeyResult.StatusCode);
        }
        // Prepare the competing candidate immediately before the winner commits so PostgreSQL TTL
        // validation reaches the intended lineage-CAS conflict instead of an unrelated expiry.
        var losingAttemptId = Guid.NewGuid();
        var losingPreparation = await recoveryRuntime.Service.PrepareAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", losingAttemptId, recoveryBody);
        using var losingJson = JsonDocument.Parse(losingPreparation.ExactResponseBody);
        var losingPayload = DecodeBase64Url(losingJson.RootElement
            .GetProperty("payloadUtf8Base64Url").GetString()!);
        Assert.NotEqual(payload, losingPayload);
        // PostgreSQL time is the decisive TTL authority after transactional waits. An application clock
        // beyond the token expiry must not reject a token that PostgreSQL still considers valid.
        var aheadRuntime = AuthorityRuntime(factory, fixture.ProductId,
            preparationExpiresAt.AddSeconds(1),
            recoveryOptions, registryAuthority, capabilityActive, capabilityNext);
        using var aheadCrypto = aheadRuntime.RuntimeCrypto;
        var aheadPrepared = aheadRuntime.Coordinator.PrepareRecoveryFinalization(
            "website-step1", "s2s-runtime-test", attemptId, recoveryBody,
            token, "recovery-2026-01", signature);
        Assert.NotNull(aheadPrepared.RecoveryPreparationExpiresAtUtc);
        Assert.Equal(preparationExpiresAt.UtcDateTime,
            aheadPrepared.RecoveryPreparationExpiresAtUtc);
        var committed = await recoveryRuntime.Service.FinalizeAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", attemptId, recoveryBody,
            token, "recovery-2026-01", signature);
        string? committedError = null;
        if (committed.StatusCode != StatusCodes.Status201Created)
        {
            await using var rejected = await factory.CreateDbContextAsync();
            committedError = await rejected.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
                .Where(item => item.AttemptId == attemptId)
                .Select(item => item.ErrorCode)
                .SingleOrDefaultAsync();
        }
        Assert.True(committed.StatusCode == StatusCodes.Status201Created,
            committedError ?? Encoding.UTF8.GetString(committed.ExactResponseBody));
        await using (var committedCheck = await factory.CreateDbContextAsync())
        {
            var committedGeneration = await committedCheck.RuntimeEnrollmentAuthorityGenerations
                .AsNoTracking().SingleAsync(item => item.RequestId == recoveryRequestId);
            var committedLineage = await committedCheck.RuntimeEnrollmentAuthorityLineages
                .AsNoTracking().SingleAsync(item =>
                    item.AuthorityLineageId == committedGeneration.AuthorityLineageId);
            Assert.Equal(1, committedGeneration.Sequence);
            Assert.Equal(committedGeneration.AuthorityGenerationId,
                committedLineage.HeadGenerationId);
            Assert.Equal(committedGeneration.Sequence, committedLineage.HeadSequence);
        }
        var replay = await recoveryRuntime.Service.FinalizeAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", attemptId, recoveryBody,
            token, "recovery-2026-01", signature);
        Assert.False(committed.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(committed.ExactResponseBody, replay.ExactResponseBody);
        var losingSignature = Base64Url(recoveryKey.SignData(
            Encoding.UTF8.GetBytes(
                "T-IA-CONNECT\0RUNTIME-ENROLLMENT\0AUTHORITY-GENERATION\0V2\n"
                + Encoding.UTF8.GetString(losingPayload)),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var losingResult = await recoveryRuntime.Service.FinalizeAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", losingAttemptId, recoveryBody,
            losingJson.RootElement.GetProperty("preparationToken").GetString()!,
            "recovery-2026-01", losingSignature);
        Assert.Equal(StatusCodes.Status409Conflict, losingResult.StatusCode);
        await using (var check = await factory.CreateDbContextAsync())
        {
            var lineageId = Guid.ParseExact(predecessor.AuthorityLineageId, "D");
            var lineage = await check.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                .SingleAsync(item => item.AuthorityLineageId == lineageId);
            var generations = await check.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
                .Where(item => item.AuthorityLineageId == lineageId)
                .OrderBy(item => item.Sequence)
                .ToListAsync();
            var attempts = await check.RuntimeEnrollmentAuthorityAttempts.AsNoTracking()
                .Where(item => item.RequestId == recoveryRequestId)
                .ToListAsync();
            Assert.Equal(1, lineage.HeadSequence);
            Assert.Collection(generations,
                genesis =>
                {
                    Assert.Equal(0, genesis.Sequence);
                    Assert.Equal(genesisRequestId, genesis.RequestId);
                    Assert.Null(genesis.PreviousGenerationId);
                },
                recoveryGeneration =>
                {
                    Assert.Equal(1, recoveryGeneration.Sequence);
                    Assert.Equal(recoveryRequestId, recoveryGeneration.RequestId);
                    Assert.Equal(generations[0].AuthorityGenerationId,
                        recoveryGeneration.PreviousGenerationId);
                });
            Assert.Equal(
                new[] { attemptId, losingAttemptId }.OrderBy(id => id).ToArray(),
                attempts.Select(item => item.AttemptId).OrderBy(id => id).ToArray());
            Assert.Single(attempts, item => item.AttemptId == attemptId && item.Status == "ACCEPTED");
            Assert.Single(attempts, item => item.AttemptId == losingAttemptId && item.Status == "REFUSED");
        }

        var lateRuntime = AuthorityRuntime(factory, fixture.ProductId, now.AddMinutes(2),
            recoveryOptions, registryAuthority, capabilityActive, capabilityNext);
        using var lateCrypto = lateRuntime.RuntimeCrypto;
        var lateReplay = await lateRuntime.Service.FinalizeAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", attemptId, recoveryBody,
            token, "recovery-2026-01", signature);
        Assert.True(lateReplay.Idempotent);
        Assert.Equal(committed.ExactResponseBody, lateReplay.ExactResponseBody);
        var lateConflict = await lateRuntime.Service.FinalizeAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", expiringAttemptId, expiringBody,
            expiringJson.RootElement.GetProperty("preparationToken").GetString()!,
            "recovery-2026-01", expiringSignature);
        Assert.Equal(StatusCodes.Status409Conflict, lateConflict.StatusCode);
        using var replacementKey = RSA.Create(2048);
        var tokenSigner = recoveryOptions.Keys.Single(item =>
            item.KeyId == "operational-2026-02");
        tokenSigner.Status = "retired";
        tokenSigner.RetiredAtUtc = now;
        tokenSigner.PrivateKeyPem = null;
        recoveryOptions.ActiveSigningKeyId = "operational-2026-03";
        var recoveryKeyIndex = recoveryOptions.Keys.FindIndex(item =>
            string.Equals(item.KeyId, "recovery-2026-01", StringComparison.Ordinal));
        Assert.True(recoveryKeyIndex >= 0);
        recoveryOptions.Keys.Insert(recoveryKeyIndex, new RuntimeAuthorityGenerationKeyOptions
        {
            KeyId = "operational-2026-03", Purpose = "operational", Domain = "generation",
            ContractVersion = 2, Status = "active", ActivatedAtUtc = now.AddHours(-1),
            PublicKeyPem = replacementKey.ExportSubjectPublicKeyInfoPem(),
            PrivateKeyPem = replacementKey.ExportPkcs8PrivateKeyPem()
        });
        var rotatedRuntime = AuthorityRuntime(factory, fixture.ProductId, now,
            recoveryOptions, registryAuthority, capabilityActive, capabilityNext);
        using var rotatedCrypto = rotatedRuntime.RuntimeCrypto;
        var rotatedReplay = await rotatedRuntime.Service.FinalizeAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", attemptId, recoveryBody,
            token, "recovery-2026-01", signature);
        Assert.True(rotatedReplay.Idempotent);
        Assert.Equal(committed.ExactResponseBody, rotatedReplay.ExactResponseBody);
        var rotatedConflictReplay = await rotatedRuntime.Service.FinalizeAuthorityRecoveryV2Async(
            "website-step1", "s2s-runtime-test", expiringAttemptId, expiringBody,
            expiringJson.RootElement.GetProperty("preparationToken").GetString()!,
            "recovery-2026-01", expiringSignature);
        Assert.True(rotatedConflictReplay.Idempotent);
        Assert.Equal(lateConflict.ExactResponseBody, rotatedConflictReplay.ExactResponseBody);
        var wrongScope = Assert.Throws<RuntimeEnrollmentException>(() =>
            recoveryRuntime.Coordinator.PrepareRecoveryFinalization(
                "other-client", "s2s-runtime-test", attemptId, recoveryBody,
                token, "recovery-2026-01", signature));
        Assert.Equal("RUNTIME_ENROLLMENT_DENIED", wrongScope.ErrorCode);
        var wrongHead = AuthorityRecoveryRequest(Guid.NewGuid(), predecessor,
            "operational-2026-02", 8, occurred, Guid.NewGuid());
        await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            recoveryRuntime.Service.PrepareAuthorityRecoveryV2Async(
                "website-step1", "s2s-runtime-test", Guid.NewGuid(), wrongHead));
    }

    /// <summary>
    /// Proves the ambient primitive requires a caller transaction, observes global/binding/tuple lock order,
    /// remains invisible before the caller's sole commit, and replays exact committed bytes afterward.
    /// </summary>
    [Fact]
    public async Task AuthorityGenerationPersistence_AmbientTransactionOwnsSingleCommitAndLockOrder()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var authority = AuthorityPersistence(factory);
        var bindingId = Guid.NewGuid();
        var candidate = AuthorityCandidate(bindingIds: [bindingId]);

        await using (var transactionless = await factory.CreateDbContextAsync())
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                authority.PersistValidatedGenerationInAmbientTransactionAsync(transactionless, candidate));

        await using var db = await factory.CreateDbContextAsync();
        await using var lease = await authority.AcquireMutationAsync(db, bindingId);
        Assert.Equal(2, await CurrentAdvisoryLockCountAsync(db));

        var created = await authority.PersistValidatedGenerationInAmbientTransactionAsync(db, candidate);

        Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created, created.Status);
        Assert.Equal(3, await CurrentAdvisoryLockCountAsync(db));
        await using (var observer = await factory.CreateDbContextAsync())
            Assert.False(await observer.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                .AnyAsync(row => row.RequestId == candidate.RequestId));

        await lease.CommitAsync();

        await using (var observer = await factory.CreateDbContextAsync())
        {
            var stored = await observer.RuntimeEnrollmentAuthorityRequests.AsNoTracking()
                .SingleAsync(row => row.RequestId == candidate.RequestId);
            Assert.Equal(candidate.AuthorityLineageId, stored.AuthorityLineageId);
            Assert.Equal(candidate.AuthorityGenerationId, stored.AuthorityGenerationId);
            Assert.Equal(StatusCodes.Status200OK, stored.HttpStatusCode);
            Assert.Equal(candidate.SignedStatementUtf8, stored.ExactResponseUtf8);
        }

        await using var replayDb = await factory.CreateDbContextAsync();
        var replay = await authority.PersistValidatedGenerationAsync(replayDb, candidate);
        Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult, replay.Status);
        Assert.Equal(created.AuthorityLineageId, replay.AuthorityLineageId);
        Assert.Equal(created.AuthorityGenerationId, replay.AuthorityGenerationId);
    }

    /// <summary>
    /// Proves concurrent exact genesis candidates converge to one tuple/lineage mapping and one immutable
    /// generation while the loser authoritatively rereads the winner.
    /// </summary>
    [Fact]
    public async Task AuthorityGenerationPersistence_ConcurrentExactGenesisConvergesOnWinner()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var authority = AuthorityPersistence(factory);
        var candidate = AuthorityCandidate();
        await using var firstDb = await factory.CreateDbContextAsync();
        await using var secondDb = await factory.CreateDbContextAsync();

        var outcomes = await Task.WhenAll(
            authority.PersistValidatedGenerationAsync(firstDb, candidate),
            authority.PersistValidatedGenerationAsync(secondDb, candidate));

        Assert.Single(outcomes, result => result.Status == RuntimeEnrollmentAuthorityPersistenceStatus.Created);
        Assert.Single(outcomes, result => result.Status == RuntimeEnrollmentAuthorityPersistenceStatus.ExactStoredResult);
        Assert.All(outcomes, result =>
        {
            Assert.Equal(candidate.AuthorityLineageId, result.AuthorityLineageId);
            Assert.Equal(candidate.AuthorityGenerationId, result.AuthorityGenerationId);
        });
        await using var check = await factory.CreateDbContextAsync();
        var lineage = await check.RuntimeEnrollmentAuthorityLineages.AsNoTracking().SingleAsync(row =>
            row.Provider == candidate.Provider && row.ProductId == candidate.ProductId
            && row.ProviderGrantRef == candidate.ProviderGrantRef);
        Assert.Equal(candidate.AuthorityLineageId, lineage.AuthorityLineageId);
        Assert.Equal(candidate.AuthorityGenerationId, lineage.HeadGenerationId);
        Assert.Equal(0, lineage.HeadSequence);
        Assert.Equal(1, await check.RuntimeEnrollmentAuthorityGenerations.CountAsync(row =>
            row.AuthorityLineageId == candidate.AuthorityLineageId));
        Assert.Equal(1, await check.RuntimeEnrollmentAuthorityRequests.CountAsync(row =>
            row.RequestId == candidate.RequestId));
    }

    /// <summary>
    /// Proves a provider grant can own independent lineages for distinct commercial seats while the
    /// database freezes each lineage's seat scope after creation.
    /// </summary>
    [Fact]
    public async Task AuthorityGenerationPersistence_SameGrantAcrossSeatsCreatesIndependentImmutableLineages()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var authority = AuthorityPersistence(factory);
        var productId = Guid.NewGuid();
        var grantRef = "shared-seat-grant:" + Guid.NewGuid().ToString("N");
        var first = AuthorityCandidate(productId: productId, providerGrantRef: grantRef);
        var second = AuthorityCandidate(productId: productId, providerGrantRef: grantRef);

        await using (var firstDb = await factory.CreateDbContextAsync())
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
                (await authority.PersistValidatedGenerationAsync(firstDb, first)).Status);
        await using (var secondDb = await factory.CreateDbContextAsync())
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
                (await authority.PersistValidatedGenerationAsync(secondDb, second)).Status);

        var firstSuccessor = AuthorityCandidate(
            lineageId: first.AuthorityLineageId,
            productId: first.ProductId,
            licenseSeatId: first.LicenseSeatId,
            providerGrantRef: first.ProviderGrantRef,
            sequence: 1,
            previousGenerationId: first.AuthorityGenerationId,
            lineageCreatedAtUtc: first.LineageCreatedAtUtc);
        var secondSuccessor = AuthorityCandidate(
            lineageId: second.AuthorityLineageId,
            productId: second.ProductId,
            licenseSeatId: second.LicenseSeatId,
            providerGrantRef: second.ProviderGrantRef,
            sequence: 1,
            previousGenerationId: second.AuthorityGenerationId,
            lineageCreatedAtUtc: second.LineageCreatedAtUtc);
        async Task<RuntimeEnrollmentAuthorityPersistenceResult> PersistSuccessorAsync(
            RuntimeEnrollmentAuthorityPersistenceCandidate candidate)
        {
            await using var db = await factory.CreateDbContextAsync();
            return await authority.PersistValidatedGenerationAsync(db, candidate);
        }
        var independentAdvances = await Task.WhenAll(
            PersistSuccessorAsync(firstSuccessor), PersistSuccessorAsync(secondSuccessor));
        Assert.All(independentAdvances, result =>
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created, result.Status));

        await using (var check = await factory.CreateDbContextAsync())
        {
            var lineages = await check.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                .Where(row => row.Provider == first.Provider && row.ProductId == productId
                    && row.ProviderGrantRef == grantRef)
                .OrderBy(row => row.LicenseSeatId).ToListAsync();
            Assert.Equal(2, lineages.Count);
            Assert.Equal(new[] { first.LicenseSeatId, second.LicenseSeatId }.Order(),
                lineages.Select(row => row.LicenseSeatId));
            Assert.All(lineages, lineage => Assert.Equal(1, lineage.HeadSequence));
            Assert.Contains(lineages, lineage =>
                lineage.AuthorityLineageId == first.AuthorityLineageId
                && lineage.HeadGenerationId == firstSuccessor.AuthorityGenerationId);
            Assert.Contains(lineages, lineage =>
                lineage.AuthorityLineageId == second.AuthorityLineageId
                && lineage.HeadGenerationId == secondSuccessor.AuthorityGenerationId);
        }

        var crossSeatSuccessor = AuthorityCandidate(
            lineageId: first.AuthorityLineageId,
            productId: first.ProductId,
            licenseSeatId: second.LicenseSeatId,
            providerGrantRef: first.ProviderGrantRef,
            sequence: 1,
            previousGenerationId: first.AuthorityGenerationId,
            lineageCreatedAtUtc: first.LineageCreatedAtUtc);
        await using (var successorDb = await factory.CreateDbContextAsync())
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict,
                (await authority.PersistValidatedGenerationAsync(successorDb, crossSeatSuccessor)).Status);
        await using (var unchanged = await factory.CreateDbContextAsync())
        {
            var firstLineage = await unchanged.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                .SingleAsync(row => row.AuthorityLineageId == first.AuthorityLineageId);
            Assert.Equal(firstSuccessor.AuthorityGenerationId, firstLineage.HeadGenerationId);
            Assert.Equal(1, firstLineage.HeadSequence);
            Assert.False(await unchanged.RuntimeEnrollmentAuthorityGenerations.AnyAsync(row =>
                row.AuthorityGenerationId == crossSeatSuccessor.AuthorityGenerationId));
            Assert.False(await unchanged.RuntimeEnrollmentAuthorityRequests.AnyAsync(row =>
                row.RequestId == crossSeatSuccessor.RequestId));
        }

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        var exception = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(admin, $"""
            UPDATE public."RuntimeEnrollmentAuthorityLineages"
            SET "LicenseSeatId" = '{Guid.NewGuid():D}'::uuid
            WHERE "AuthorityLineageId" = '{first.AuthorityLineageId:D}'::uuid;
            """));
        Assert.Equal("55000", exception.SqlState);
    }

    /// <summary>
    /// Proves the seat-scope migration backfills coherent history, rejects a lineage whose canonical
    /// generations cross seats, and refuses a lossy downgrade after two seats share one exact grant.
    /// </summary>
    [Fact]
    public async Task SeatScopedAuthorityLineageMigration_HistoryAndDowngradeFailClosed()
    {
        var shared = await ProvisionAsync();
        const string previousMigration = "20260826110000_AddTkt000686DistributionEntitlementAuthorityGeneration";
        var coherentDatabase = "softlicence_tkt732_coherent_" + Guid.NewGuid().ToString("N");
        var divergentDatabase = "softlicence_tkt732_divergent_" + Guid.NewGuid().ToString("N");
        await CreateDatabaseAsync(shared.Admin, coherentDatabase);
        await CreateDatabaseAsync(shared.Admin, divergentDatabase);
        try
        {
            var coherent = new NpgsqlConnectionStringBuilder(shared.Admin)
                { Database = coherentDatabase }.ConnectionString;
            var coherentOptions = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(coherent).Options;
            var firstLineage = Guid.NewGuid();
            var firstSeat = Guid.NewGuid();
            var productId = Guid.NewGuid();
            const string sharedGrant = "historical-shared-grant";
            await using (var db = new LicenseDbContext(coherentOptions))
            {
                var migrator = db.GetService<IMigrator>();
                await migrator.MigrateAsync(previousMigration);
                await SeedHistoricalSeatLineageAsync(coherent, firstLineage, productId,
                    firstSeat, sharedGrant);
                await migrator.MigrateAsync();
            }
            await using (var connection = new NpgsqlConnection(coherent))
            {
                await connection.OpenAsync();
                Assert.Equal(firstSeat, await ScalarAsync<Guid>(connection, $"""
                    SELECT "LicenseSeatId" AS "Value"
                    FROM public."RuntimeEnrollmentAuthorityLineages"
                    WHERE "AuthorityLineageId" = '{firstLineage:D}'::uuid;
                    """));
                await SeedHistoricalSeatLineageAsync(coherent, Guid.NewGuid(), productId,
                    Guid.NewGuid(), sharedGrant, seatScoped: true);
            }
            await using (var downgrade = new LicenseDbContext(coherentOptions))
            {
                var exception = await Assert.ThrowsAsync<PostgresException>(() =>
                    downgrade.GetService<IMigrator>().MigrateAsync(previousMigration));
                Assert.Equal(PostgresErrorCodes.UniqueViolation, exception.SqlState);
            }
            await using (var connection = new NpgsqlConnection(coherent))
            {
                await connection.OpenAsync();
                Assert.Equal(2L, await ScalarAsync<long>(connection, """
                    SELECT count(*)::bigint AS "Value"
                    FROM public."RuntimeEnrollmentAuthorityLineages"
                    WHERE "ProviderGrantRef" = 'historical-shared-grant'
                      AND "LicenseSeatId" IS NOT NULL;
                    """));
            }

            var divergent = new NpgsqlConnectionStringBuilder(shared.Admin)
                { Database = divergentDatabase }.ConnectionString;
            var divergentOptions = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(divergent).Options;
            await using (var db = new LicenseDbContext(divergentOptions))
            {
                var migrator = db.GetService<IMigrator>();
                await migrator.MigrateAsync(previousMigration);
                await SeedHistoricalSeatLineageAsync(divergent, Guid.NewGuid(), Guid.NewGuid(),
                    Guid.NewGuid(), "historical-divergent-grant", Guid.NewGuid());
                var exception = await Assert.ThrowsAsync<PostgresException>(() => migrator.MigrateAsync());
                Assert.Equal(PostgresErrorCodes.CheckViolation, exception.SqlState);
                Assert.Contains("crosses commercial seats", exception.MessageText, StringComparison.Ordinal);
            }
            await using (var connection = new NpgsqlConnection(divergent))
            {
                await connection.OpenAsync();
                Assert.False(await ScalarAsync<bool>(connection, """
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND table_name = 'RuntimeEnrollmentAuthorityLineages'
                          AND column_name = 'LicenseSeatId') AS "Value";
                    """));
            }
        }
        finally
        {
            await DropDatabaseAsync(shared.Admin, coherentDatabase);
            await DropDatabaseAsync(shared.Admin, divergentDatabase);
        }
    }

    /// <summary>Seeds one pre-TKT-000732 lineage with one or two canonical seat observations.</summary>
    private static async Task SeedHistoricalSeatLineageAsync(
        string connectionString, Guid lineageId, Guid productId, Guid firstSeatId, string grantRef,
        Guid? successorSeatId = null, bool seatScoped = false)
    {
        var firstGenerationId = Guid.NewGuid();
        var firstRequestId = Guid.NewGuid();
        var createdAt = ExactUtcNow();
        var firstPayload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            authorityLineageId = lineageId.ToString("D"),
            installation = new { seatId = firstSeatId.ToString("D") }
        }));
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = seatScoped ? """
                INSERT INTO public."RuntimeEnrollmentAuthorityLineages"
                    ("AuthorityLineageId","Provider","ProductId","LicenseSeatId","ProviderGrantRef",
                     "ProviderGrantRefScalarCount","CreatedAtUtc","HeadGenerationId","HeadSequence")
                VALUES (@lineage,'softlicence',@product,@seat,@grant,@grantScalars,@created,@generation,0);
                """ : """
                INSERT INTO public."RuntimeEnrollmentAuthorityLineages"
                    ("AuthorityLineageId","Provider","ProductId","ProviderGrantRef",
                     "ProviderGrantRefScalarCount","CreatedAtUtc","HeadGenerationId","HeadSequence")
                VALUES (@lineage,'softlicence',@product,@grant,@grantScalars,@created,@generation,0);
                """;
            command.Parameters.AddWithValue("lineage", lineageId);
            command.Parameters.AddWithValue("product", productId);
            command.Parameters.AddWithValue("seat", firstSeatId);
            command.Parameters.AddWithValue("grant", grantRef);
            command.Parameters.AddWithValue("grantScalars", grantRef.EnumerateRunes().Count());
            command.Parameters.AddWithValue("created", createdAt);
            command.Parameters.AddWithValue("generation", firstGenerationId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await InsertHistoricalSeatGenerationAsync(connection, transaction, lineageId,
            firstGenerationId, firstRequestId, firstPayload, 0, null, createdAt);
        if (successorSeatId is not null)
        {
            var successorGenerationId = Guid.NewGuid();
            var successorPayload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                authorityLineageId = lineageId.ToString("D"),
                installation = new { seatId = successorSeatId.Value.ToString("D") }
            }));
            await InsertHistoricalSeatGenerationAsync(connection, transaction, lineageId,
                successorGenerationId, Guid.NewGuid(), successorPayload, 1, firstGenerationId,
                createdAt.AddSeconds(1));
            await using var advance = connection.CreateCommand();
            advance.Transaction = transaction;
            advance.CommandText = """
                UPDATE public."RuntimeEnrollmentAuthorityLineages"
                SET "HeadGenerationId"=@generation,"HeadSequence"=1
                WHERE "AuthorityLineageId"=@lineage;
                """;
            advance.Parameters.AddWithValue("generation", successorGenerationId);
            advance.Parameters.AddWithValue("lineage", lineageId);
            Assert.Equal(1, await advance.ExecuteNonQueryAsync());
        }
        await transaction.CommitAsync();
    }

    /// <summary>Inserts one immutable pre-TKT-000732 canonical generation.</summary>
    private static async Task InsertHistoricalSeatGenerationAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, Guid lineageId,
        Guid generationId, Guid requestId, byte[] payload, long sequence,
        Guid? predecessorId, DateTime occurredAtUtc)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO public."RuntimeEnrollmentAuthorityGenerations"
                ("AuthorityGenerationId","AuthorityLineageId","Sequence","PreviousGenerationId",
                 "RequestId","CanonicalPayloadUtf8","SignedStatementUtf8","AuthorityDigest",
                 "SignatureAlgorithm","SignatureKeyId","SignatureValue","OccurredAtUtc","CreatedAtUtc")
            VALUES (@generation,@lineage,@sequence,@predecessor,@request,@payload,decode('01','hex'),
                    repeat('a',64),'PS256','historical-key',repeat('A',342),@occurred,@occurred);
            """;
        command.Parameters.AddWithValue("generation", generationId);
        command.Parameters.AddWithValue("lineage", lineageId);
        command.Parameters.AddWithValue("sequence", sequence);
        command.Parameters.AddWithValue("predecessor", predecessorId is null ? DBNull.Value : predecessorId.Value);
        command.Parameters.AddWithValue("request", requestId);
        command.Parameters.AddWithValue("payload", payload);
        command.Parameters.AddWithValue("occurred", occurredAtUtc);
        Assert.Equal(1, await command.ExecuteNonQueryAsync());
    }

    /// <summary>
    /// Proves a zero-row successor head CAS rolls back inserted generation/request rows, preserves the old
    /// head, and permits a fresh authoritative retry after the injected conflict is removed.
    /// </summary>
    [Fact]
    public async Task AuthorityGenerationPersistence_ZeroRowHeadCasRollsBackBeforeFreshRetry()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var authority = AuthorityPersistence(factory);
        var genesis = AuthorityCandidate();
        await using (var genesisDb = await factory.CreateDbContextAsync())
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created,
                (await authority.PersistValidatedGenerationAsync(genesisDb, genesis)).Status);
        var successor = AuthorityCandidate(
            lineageId: genesis.AuthorityLineageId,
            productId: genesis.ProductId,
            licenseSeatId: genesis.LicenseSeatId,
            providerGrantRef: genesis.ProviderGrantRef,
            sequence: 1,
            previousGenerationId: genesis.AuthorityGenerationId,
            lineageCreatedAtUtc: genesis.LineageCreatedAtUtc);

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await RemoveAuthorityHeadSuppressionAsync(admin);
        await ExecuteAsync(admin, $"""
            CREATE FUNCTION public.runtime_test_re_authority_suppress_head()
            RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN
                IF NEW."AuthorityLineageId" = '{genesis.AuthorityLineageId:D}'::uuid THEN
                    RETURN NULL;
                END IF;
                RETURN NEW;
            END;
            $body$;
            CREATE TRIGGER zzz_runtime_test_re_authority_suppress_head
            BEFORE UPDATE ON public."RuntimeEnrollmentAuthorityLineages"
            FOR EACH ROW EXECUTE FUNCTION public.runtime_test_re_authority_suppress_head();
            """);
        try
        {
            await using var losingDb = await factory.CreateDbContextAsync();
            var conflict = await authority.PersistValidatedGenerationAsync(losingDb, successor);
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.StructuralConflict, conflict.Status);
        }
        finally
        {
            await RemoveAuthorityHeadSuppressionAsync(admin);
        }

        await using (var check = await factory.CreateDbContextAsync())
        {
            var lineage = await check.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                .SingleAsync(row => row.AuthorityLineageId == genesis.AuthorityLineageId);
            Assert.Equal(genesis.AuthorityGenerationId, lineage.HeadGenerationId);
            Assert.Equal(0, lineage.HeadSequence);
            Assert.False(await check.RuntimeEnrollmentAuthorityGenerations.AnyAsync(row =>
                row.AuthorityGenerationId == successor.AuthorityGenerationId));
            Assert.False(await check.RuntimeEnrollmentAuthorityRequests.AnyAsync(row =>
                row.RequestId == successor.RequestId));
        }

        await using var retryDb = await factory.CreateDbContextAsync();
        var retried = await authority.PersistValidatedGenerationAsync(retryDb, successor);
        Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created, retried.Status);
        await using var final = await factory.CreateDbContextAsync();
        Assert.Equal(successor.AuthorityGenerationId,
            (await final.RuntimeEnrollmentAuthorityLineages.AsNoTracking().SingleAsync(row =>
                row.AuthorityLineageId == genesis.AuthorityLineageId)).HeadGenerationId);
    }
}

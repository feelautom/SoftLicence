using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Npgsql;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
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

    [Fact]
    public async Task PrepareConfirmCapability_EndToEnd_UsesFrozenReplayAndValidPs256Token()
    {
        var connections = await ProvisionAsync();
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(invalidationNow));
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
        Assert.Equal("binding_ineligible", rejected.ErrorCode);

        await using var check = await factory.CreateDbContextAsync();
        Assert.Equal("invalidated", (await check.DistributionInstallationBindings.SingleAsync(
            candidate => candidate.Id == fixture.BindingId)).State);
        Assert.Equal("INVALIDATED", (await check.RuntimeEnrollments.SingleAsync(
            candidate => candidate.Id == enrollmentId)).State);
        Assert.Single(await check.DistributionBindingInvalidations.Where(candidate =>
            candidate.BindingId == fixture.BindingId).ToListAsync());
    }

    [Fact]
    public async Task WebSetupTransitionV2_ExpiredSource_TransfersToSelectedEligibleLicenseAtomically()
    {
        var connections = await ProvisionAsync();
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
            factory, authority, registry, crypto, Options.Create(options), dataProtectionProvider: dataProtection);

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
                MaxSeats = 1,
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
            factory, dataProtection, TimeProvider.System);
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
        Assert.False((await check.LicenseSeats.SingleAsync(row => row.Id == sourceSeatId)).IsActive);
        Assert.True((await check.LicenseSeats.SingleAsync(row => row.Id == rebound.LicenseSeatId)).IsActive);
        Assert.Equal("finalized", (await check.DistributionEntitlements.SingleAsync(
            row => row.Id == rebound.EntitlementId)).State);
    }

    [Fact]
    public async Task WebSetupTransition_EndToEnd_IsOneShotAtomic_ReplaysFrozenResponse_AndAllowsHistoricalCriticalRecovery()
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
        Assert.Equal("CONSUMED", transition.State);
        Assert.Equal(authorizationDigest, transition.ConsumedPayloadDigestSha256);
        Assert.Single(await check.RuntimeEnrollmentRequests.Where(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade").ToListAsync());
        Assert.Equal(2, await check.RuntimeEnrollmentProofNonces.CountAsync(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "websetup-upgrade"));

        var license = await check.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
        license.RevokedAt = DateTime.UtcNow;
        await check.SaveChangesAsync();
        var revokedReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.UpgradeFromWebSetupAsync("website-step1", "s2s-test", relayDigest, relay));
        Assert.Equal("authority_ineligible", revokedReplay.ErrorCode);

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
    }

    [Fact]
    public async Task UpgradeAndRollback_EndToEnd_RebindAtomicallyAndReplayFrozenResponses()
    {
        var connections = await ProvisionAsync();
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
            RecoveryHardwareIdHash = hardwareIdHash,
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

        var upgraded = await service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay);
        var replayed = await service.UpgradeAsync("website-step1", "s2s-test", relayDigest, relay);

        Assert.False(upgraded.Idempotent);
        Assert.True(replayed.Idempotent);
        Assert.Equal(upgraded.ExactResponseBody, replayed.ExactResponseBody);
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
            Assert.Single(await check.RuntimeEnrollmentRequests.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
            Assert.Single(await check.RuntimeEnrollmentProofNonces.Where(row =>
                row.EnrollmentId == enrollmentId && row.Operation == "upgrade").ToListAsync());
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
            RecoveryHardwareIdHash = hardwareIdHash,
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

        var rolledBack = await service.RollbackAsync(
            "website-step1", "s2s-test", rollbackRelayDigest, rollbackRelay);
        var rollbackReplay = await service.RollbackAsync(
            "website-step1", "s2s-test", rollbackRelayDigest, rollbackRelay);

        Assert.False(rolledBack.Idempotent);
        Assert.True(rollbackReplay.Idempotent);
        Assert.Equal(rolledBack.ExactResponseBody, rollbackReplay.ExactResponseBody);
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
        Assert.Single(await rollbackCheck.RuntimeEnrollmentRequests.Where(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "rollback").ToListAsync());
        Assert.Single(await rollbackCheck.RuntimeEnrollmentProofNonces.Where(row =>
            row.EnrollmentId == enrollmentId && row.Operation == "rollback").ToListAsync());
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
        var connections = await ProvisionAsync();
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
        var mismatchError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, mismatchDigest, mismatched, mismatchProof, IPAddress.Loopback));
        Assert.Equal("canary_binding_mismatch", mismatchError.ErrorCode);

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

        await using (var invalidateEnrollmentOnly = await factory.CreateDbContextAsync())
        {
            var inactiveEnrollment = await invalidateEnrollmentOnly.RuntimeEnrollments.SingleAsync(
                candidate => candidate.Id == enrollmentId);
            inactiveEnrollment.State = "INVALIDATED";
            inactiveEnrollment.InvalidatedAtUtc = DateTime.UtcNow;
            inactiveEnrollment.InvalidationReason = "test-independent-enrollment-state";
            await invalidateEnrollmentOnly.SaveChangesAsync();
        }
        var inactiveEnrollmentError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, proof, IPAddress.Loopback));
        Assert.Equal("enrollment_inactive", inactiveEnrollmentError.ErrorCode);
        await using (var restoreEnrollment = await factory.CreateDbContextAsync())
        {
            var activeEnrollment = await restoreEnrollment.RuntimeEnrollments.SingleAsync(
                candidate => candidate.Id == enrollmentId);
            activeEnrollment.State = "ACTIVE";
            activeEnrollment.InvalidatedAtUtc = null;
            activeEnrollment.InvalidationReason = null;
            await restoreEnrollment.SaveChangesAsync();
        }

        await using (var revoke = await factory.CreateDbContextAsync())
        {
            var license = await revoke.Licenses.SingleAsync(candidate => candidate.Id == licenseId);
            license.IsActive = false;
            license.RevokedAt = DateTime.UtcNow;
            await revoke.SaveChangesAsync();
        }
        var revokedError = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, proof, IPAddress.Loopback));
        Assert.Equal("authority_ineligible", revokedError.ErrorCode);
        await using (var restoreAuthorityForNextIndependentCase = await factory.CreateDbContextAsync())
        {
            var license = await restoreAuthorityForNextIndependentCase.Licenses.SingleAsync(
                candidate => candidate.Id == licenseId);
            license.IsActive = true;
            license.RevokedAt = null;
            var restoredEnrollment = await restoreAuthorityForNextIndependentCase.RuntimeEnrollments.SingleAsync(
                candidate => candidate.Id == enrollmentId);
            restoredEnrollment.State = "ACTIVE";
            restoredEnrollment.InvalidatedAtUtc = null;
            restoredEnrollment.InvalidationReason = null;
            await restoreAuthorityForNextIndependentCase.SaveChangesAsync();
        }

        var invalidations = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), TimeProvider.System);
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
        var invalidatedReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() => service.ProcessCanaryAsync(
            enrollmentId, bodyDigest, request, proof, IPAddress.Loopback));
        Assert.Equal("binding_ineligible", invalidatedReplay.ErrorCode);

        await using var check = await factory.CreateDbContextAsync();
        Assert.Single(await check.RuntimeCanaryProofNonces.ToListAsync());
        Assert.Single(await check.RuntimeCriticalIncidents.Where(incident =>
            incident.State == "OPEN" && incident.EventId == request.EventId).ToListAsync());
        Assert.Single(await check.CanaryAlerts.Where(alert => alert.ServerAction == "authenticated_evidence").ToListAsync());
        Assert.False(await check.BannedHardwareIds.AnyAsync());
        Assert.True((await check.Licenses.SingleAsync(license => license.Id == licenseId)).IsActive);
        Assert.Equal("INVALIDATED", (await check.RuntimeEnrollments.SingleAsync(
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
            new TestDbFactory(isolated), new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
            await ExecuteAsync(admin, $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE);");
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
            factory, dataProtectionProvider, new FixedTimeProvider(now));
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

    [Fact]
    public async Task DistributionFinalize_ConcurrentInitialSeatClaims_RespectLicenseCapacity()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory, includeSeat: false);
        var now = new DateTimeOffset(2026, 7, 26, 9, 30, 0, TimeSpan.Zero);
        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
        Assert.Single(await check.LicenseSeats.Where(candidate =>
            candidate.LicenseId == fixture.LicenseId && candidate.IsActive).ToListAsync());
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(now));
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

    [Theory]
    [InlineData("binding-revoked")]
    [InlineData("runtime-key")]
    [InlineData("release")]
    [InlineData("approved-binary")]
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
            else if (mutation == "release")
            {
                binding.Version = "2.2.980";
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

    private static async Task<(string Admin, string App)> ProvisionIsolatedAsync()
    {
        var shared = await ProvisionAsync();
        var database = $"softlicence_runtime_rotation_{Guid.NewGuid():N}";
        await using (var connection = new NpgsqlConnection(shared.Admin))
        {
            await connection.OpenAsync();
            await ExecuteAsync(connection, $"CREATE DATABASE \"{database}\";");
        }
        var admin = new NpgsqlConnectionStringBuilder(shared.Admin) { Database = database }.ConnectionString;
        var app = new NpgsqlConnectionStringBuilder(admin)
        {
            Username = "softlicence_runtime_test_app",
            Password = "runtime-test-only"
        }.ConnectionString;
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(admin).Options;
        await using (var db = new LicenseDbContext(dbOptions))
            await db.Database.MigrateAsync();
        await using (var connection = new NpgsqlConnection(admin))
        {
            await connection.OpenAsync();
            await GrantApplicationRuntimePrivilegesAsync(connection);
        }
        return (admin, app);
    }

    private static async Task<(Guid ProductId, Guid BindingId, string HandoffDigest, string InstallationId, string Version)>
        SeedAuthorityAsync(
            IDbContextFactory<LicenseDbContext> factory,
            string version = "2.2.999",
            string allowedVersions = "2.2.*")
    {
        var productId = Guid.NewGuid();
        var typeId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var seatId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        var hardwareId = "runtime-hwid-" + Guid.NewGuid().ToString("N");
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
        var hardwareId = "DIST-RACE-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
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
            GRANT CONNECT ON DATABASE softlicence_runtime TO softlicence_runtime_test_app;
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
            """);

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (T)(await command.ExecuteScalarAsync())!;
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

    private sealed class TestDbFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

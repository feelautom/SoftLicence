using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public interface IRuntimeEnrollmentKeyRegistryService
{
    Task ValidateAsync(CancellationToken cancellationToken = default);
    Task ValidateConfiguredKeysAsync(LicenseDbContext db, CancellationToken cancellationToken = default);
}

public sealed class RuntimeEnrollmentKeyRegistryService(
    IDbContextFactory<LicenseDbContext> dbFactory,
    IOptions<RuntimeEnrollmentOptions> options) : IRuntimeEnrollmentKeyRegistryService
{
    internal const string RegistryVersionPurpose = "registry-version";
    internal const string RegistryVersionKeyId = "global";
    internal const string RegistryVersionDigest = "0000000000000000000000000000000000000000000000000000000000000000";

    internal const string GuardFunctionSource = """
        DECLARE
            referenced boolean;
        BEGIN
            PERFORM pg_catalog.pg_advisory_xact_lock(999831, 1);
            IF TG_OP = 'INSERT' THEN
                IF NEW."Purpose" = 'registry-version' THEN
                    IF NEW."KeyId" <> 'global'
                       OR NEW."MaterialDigestSha256" <> repeat('0', 64)
                       OR NEW."State" <> 'active'
                       OR NEW."Epoch" <> 1
                       OR NEW."RetainUntilUtc" IS NOT NULL
                       OR NEW."RetiredAtUtc" IS NOT NULL THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment registry version sentinel is invalid';
                    END IF;
                    RETURN NEW;
                END IF;
                IF NEW."RetiredAtUtc" IS NOT NULL
                   OR NEW."Epoch" <> 1
                   OR (NEW."State" = 'previous' AND (
                       NEW."Purpose" <> 'capability-signing' OR NEW."RetainUntilUtc" IS NULL))
                   OR (NEW."State" <> 'previous' AND NEW."RetainUntilUtc" IS NOT NULL) THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment key insertion is invalid';
                END IF;
                IF EXISTS (
                    SELECT 1 FROM public."RuntimeEnrollmentKeyRegistries" existing
                    WHERE existing."Purpose" = NEW."Purpose" AND existing."KeyId" = NEW."KeyId"
                      AND (existing."MaterialDigestSha256" IS DISTINCT FROM NEW."MaterialDigestSha256"
                           OR existing."State" IS DISTINCT FROM NEW."State"
                           OR existing."Epoch" IS DISTINCT FROM NEW."Epoch"
                           OR existing."RetainUntilUtc" IS DISTINCT FROM NEW."RetainUntilUtc"
                           OR existing."RetiredAtUtc" IS DISTINCT FROM NEW."RetiredAtUtc")
                ) THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment key id cannot be rebound';
                END IF;
                RETURN NEW;
            END IF;
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'runtime enrollment key tombstones are permanent';
            END IF;
            IF OLD."Purpose" = 'registry-version' THEN
                IF NEW."Purpose" IS DISTINCT FROM OLD."Purpose"
                   OR NEW."KeyId" IS DISTINCT FROM OLD."KeyId"
                   OR NEW."MaterialDigestSha256" IS DISTINCT FROM OLD."MaterialDigestSha256"
                   OR NEW."State" IS DISTINCT FROM OLD."State"
                   OR NEW."CreatedAtUtc" IS DISTINCT FROM OLD."CreatedAtUtc"
                   OR NEW."RetainUntilUtc" IS DISTINCT FROM OLD."RetainUntilUtc"
                   OR NEW."RetiredAtUtc" IS NOT NULL
                   OR NEW."Epoch" <> OLD."Epoch" + 1 THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment registry version transition is invalid';
                END IF;
                RETURN NEW;
            END IF;
            IF NEW."Purpose" IS DISTINCT FROM OLD."Purpose"
               OR NEW."KeyId" IS DISTINCT FROM OLD."KeyId"
               OR NEW."MaterialDigestSha256" IS DISTINCT FROM OLD."MaterialDigestSha256"
               OR NEW."CreatedAtUtc" IS DISTINCT FROM OLD."CreatedAtUtc"
               OR NEW."Epoch" <> OLD."Epoch" + 1
               OR (OLD."State" = 'retired' AND NEW."State" <> 'retired')
               OR (NEW."State" = 'retired' AND NEW."RetiredAtUtc" IS NULL)
               OR (NEW."State" <> 'retired' AND NEW."RetiredAtUtc" IS NOT NULL)
               OR (OLD."Purpose" = 'encryption' AND NOT (
                   NEW."RetainUntilUtc" IS NOT DISTINCT FROM OLD."RetainUntilUtc"
                   AND ((OLD."State" = 'active' AND NEW."State" IN ('decrypt-only', 'retired'))
                        OR (OLD."State" = 'decrypt-only' AND NEW."State" = 'retired'))
               ))
               OR (OLD."Purpose" = 'capability-signing' AND NOT (
                   (OLD."State" = 'next' AND NEW."State" = 'active'
                       AND OLD."RetainUntilUtc" IS NULL AND NEW."RetainUntilUtc" IS NULL)
                   OR (OLD."State" = 'active' AND NEW."State" = 'previous'
                       AND OLD."RetainUntilUtc" IS NULL
                       AND NEW."RetainUntilUtc" > clock_timestamp())
                   OR (OLD."State" = 'previous' AND NEW."State" = 'retired'
                       AND NEW."RetainUntilUtc" IS NOT DISTINCT FROM OLD."RetainUntilUtc"
                       AND OLD."RetainUntilUtc" <= clock_timestamp())
                   OR (OLD."State" = 'verify-only' AND NEW."State" = 'retired'
                       AND NEW."RetainUntilUtc" IS NOT DISTINCT FROM OLD."RetainUntilUtc")
               )) THEN
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'runtime enrollment key lifecycle transition is invalid';
            END IF;
            IF OLD."Purpose" = 'encryption' THEN
                SELECT EXISTS (
                    SELECT 1 FROM public."RuntimeEnrollments" e
                    WHERE e."PublicKeySpkiKeyId" = OLD."KeyId" OR e."ChallengeKeyId" = OLD."KeyId"
                    UNION ALL SELECT 1 FROM public."RuntimeEnrollmentRequests" r WHERE r."ResponseKeyId" = OLD."KeyId"
                    UNION ALL SELECT 1 FROM public."RuntimeEnrollmentProofNonces" p WHERE p."ResponseKeyId" = OLD."KeyId"
                    UNION ALL SELECT 1 FROM public."RuntimeEnrollmentEncryptionNonces" n WHERE n."KeyId" = OLD."KeyId"
                ) INTO referenced;
                IF referenced AND NEW."State" = 'retired' THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment key is still referenced';
                END IF;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END;
        """;

    private const string CanaryGuardFunctionSource = """
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
        """;

    public async Task ValidateAsync(CancellationToken cancellationToken = default)
    {
        if (options.Value.Mode == "off")
            return;
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        if (!db.Database.IsNpgsql())
            throw Invalid();

        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        await connection.OpenAsync(cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT EXISTS (
                    SELECT 1 FROM public."__EFMigrationsHistory"
                    WHERE "MigrationId" = '20260719024400_AddRuntimeEnrollments'
                )
                AND EXISTS (
                    SELECT 1 FROM public."__EFMigrationsHistory"
                    WHERE "MigrationId" = '20260719140242_AddRuntimeCanaryProofs'
                )
                AND EXISTS (
                    SELECT 1 FROM public."__EFMigrationsHistory"
                    WHERE "MigrationId" = '20260719190723_AddRuntimeCriticalRecovery'
                )
                AND EXISTS (
                    SELECT 1 FROM public."__EFMigrationsHistory"
                    WHERE "MigrationId" = '20260720102528_AddRuntimeMilestones'
                )
                AND pg_catalog.has_table_privilege(current_user,
                    'public."RuntimeEnrollmentKeyRegistries"', 'SELECT')
                AND NOT pg_catalog.has_table_privilege(current_user,
                    'public."RuntimeEnrollmentKeyRegistries"', 'INSERT')
                AND NOT pg_catalog.has_table_privilege(current_user,
                    'public."RuntimeEnrollmentKeyRegistries"', 'UPDATE')
                AND NOT pg_catalog.has_table_privilege(current_user,
                    'public."RuntimeEnrollmentKeyRegistries"', 'DELETE')
                AND NOT pg_catalog.has_table_privilege(current_user,
                    'public."RuntimeEnrollmentKeyRegistries"', 'TRUNCATE')
                AND (
                    SELECT owner_role.rolname
                    FROM pg_catalog.pg_class owner_table
                    JOIN pg_catalog.pg_namespace owner_ns ON owner_ns.oid = owner_table.relnamespace
                    JOIN pg_catalog.pg_roles owner_role ON owner_role.oid = owner_table.relowner
                    WHERE owner_ns.nspname = 'public'
                      AND owner_table.relname = 'RuntimeEnrollmentKeyRegistries'
                ) = 'softlicence_runtime_authority_owner'
                AND NOT pg_catalog.pg_has_role(current_user,
                    'softlicence_runtime_authority_owner', 'MEMBER')
                AND pg_catalog.has_table_privilege('softlicence_runtime_authority_owner',
                    'public."RuntimeEnrollmentAuthorityStates"', 'SELECT,UPDATE')
                AND pg_catalog.has_table_privilege('softlicence_runtime_authority_owner',
                    'public."RuntimeEnrollments"', 'SELECT')
                AND pg_catalog.has_table_privilege('softlicence_runtime_authority_owner',
                    'public."RuntimeEnrollmentRequests"', 'SELECT')
                AND pg_catalog.has_table_privilege('softlicence_runtime_authority_owner',
                    'public."RuntimeEnrollmentProofNonces"', 'SELECT')
                AND pg_catalog.has_table_privilege('softlicence_runtime_authority_owner',
                    'public."RuntimeEnrollmentEncryptionNonces"', 'SELECT')
                AND pg_catalog.has_table_privilege('softlicence_runtime_authority_owner',
                    'public."RuntimeCanaryProofNonces"', 'SELECT')
                AND (
                    SELECT count(*) = 1
                    FROM public."RuntimeEnrollmentKeyRegistries" version_row
                    WHERE version_row."Purpose" = 'registry-version'
                      AND version_row."KeyId" = 'global'
                      AND version_row."MaterialDigestSha256" = repeat('0', 64)
                      AND version_row."State" = 'active'
                      AND version_row."Epoch" = @registryVersion
                      AND version_row."RetiredAtUtc" IS NULL
                )
                AND (
                    SELECT count(*) = 1
                    FROM public."RuntimeEnrollmentKeyRegistries" version_row
                    WHERE version_row."Purpose" = 'registry-version'
                )
                AND EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_trigger t
                    JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public'
                      AND c.relname = 'RuntimeEnrollmentKeyRegistries'
                      AND t.tgname = 'trg_runtime_key_registry_guard'
                      AND t.tgenabled = 'O'
                      AND NOT t.tgisinternal
                      AND t.tgtype = 31
                      AND t.tgfoid = 'public.runtime_enrollment_guard_key_registry()'::regprocedure
                      AND pg_catalog.octet_length(t.tgargs) = 0
                )
                AND EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_proc p
                    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                    JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
                    WHERE n.nspname = 'public'
                      AND p.oid = 'public.runtime_enrollment_guard_key_registry()'::regprocedure
                      AND p.prosecdef AND NOT r.rolcanlogin
                      AND r.rolname = 'softlicence_runtime_authority_owner'
                      AND p.pronargs = 0 AND p.proargtypes = ''::oidvector
                      AND pg_catalog.regexp_replace(p.prosrc, '[[:space:]]', '', 'g')
                          = pg_catalog.regexp_replace(@source, '[[:space:]]', '', 'g')
                      AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']::text[]
                      AND NOT pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE')
                      AND NOT pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')
                )
                AND EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_trigger t
                    JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public'
                      AND c.relname = 'RuntimeEnrollmentKeyRegistries'
                      AND t.tgname = 'trg_runtime_canary_key_retirement_guard'
                      AND t.tgenabled = 'O'
                      AND NOT t.tgisinternal
                      AND t.tgtype = 19
                      AND t.tgfoid = 'public.runtime_canary_guard_key_retirement()'::regprocedure
                      AND pg_catalog.octet_length(t.tgargs) = 0
                )
                AND EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_proc p
                    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                    JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
                    WHERE n.nspname = 'public'
                      AND p.oid = 'public.runtime_canary_guard_key_retirement()'::regprocedure
                      AND p.prosecdef AND NOT r.rolcanlogin
                      AND r.rolname = 'softlicence_runtime_authority_owner'
                      AND p.pronargs = 0 AND p.proargtypes = ''::oidvector
                      AND pg_catalog.regexp_replace(p.prosrc, '[[:space:]]', '', 'g')
                          = pg_catalog.regexp_replace(@canarySource, '[[:space:]]', '', 'g')
                      AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']::text[]
                      AND NOT pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE')
                      AND NOT pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')
                );
                """;
            command.Parameters.AddWithValue("source", GuardFunctionSource);
            command.Parameters.AddWithValue("canarySource", CanaryGuardFunctionSource);
            command.Parameters.AddWithValue("registryVersion", options.Value.KeyRegistryVersion);
            if (await command.ExecuteScalarAsync(cancellationToken) is not true)
                throw Invalid();
        }

        await ValidateConfiguredKeysAsync(db, cancellationToken);

        var expected = BuildExpected(options.Value);
        var registered = await db.RuntimeEnrollmentKeyRegistries.AsNoTracking()
            .OrderBy(key => key.Purpose).ThenBy(key => key.KeyId)
            .ToListAsync(cancellationToken);
        foreach (var row in registered)
        {
            if (row.Purpose == RegistryVersionPurpose)
                continue;
            if (!expected.ContainsKey((row.Purpose, row.KeyId))
                && (row.State != "retired" || row.RetiredAtUtc == null))
                throw Invalid();
        }

        var referencedEncryptionIds = await db.RuntimeEnrollments.AsNoTracking().Select(row => row.PublicKeySpkiKeyId)
            .Concat(db.RuntimeEnrollments.AsNoTracking().Select(row => row.ChallengeKeyId))
            .Concat(db.RuntimeEnrollmentRequests.AsNoTracking().Select(row => row.ResponseKeyId))
            .Concat(db.RuntimeEnrollmentProofNonces.AsNoTracking().Select(row => row.ResponseKeyId))
            .Concat(db.RuntimeCanaryProofNonces.AsNoTracking().Select(row => row.ResponseKeyId))
            .Concat(db.DistributionLicenseBootstrapAuthorizations.AsNoTracking()
                .Where(row => row.ResponseKeyId != null).Select(row => row.ResponseKeyId!))
            .Concat(db.DistributionLicenseBootstrapRequests.AsNoTracking()
                .Where(row => row.ResponseKeyId != "purged").Select(row => row.ResponseKeyId))
            .Concat(db.RuntimeEnrollmentEncryptionNonces.AsNoTracking().Select(row => row.KeyId))
            .Distinct().ToListAsync(cancellationToken);
        if (referencedEncryptionIds.Any(keyId =>
                !expected.TryGetValue(("encryption", keyId), out var key) || key.State == "retired"))
            throw Invalid();
    }

    public async Task ValidateConfiguredKeysAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken = default)
    {
        var expected = BuildExpected(options.Value);
        var liveRows = await db.RuntimeEnrollmentKeyRegistries.AsNoTracking()
            .Where(row => row.State != "retired")
            .ToListAsync(cancellationToken);
        var versionRows = liveRows.Where(row => row.Purpose == RegistryVersionPurpose).ToList();
        if (versionRows.Count != 1
            || versionRows[0].KeyId != RegistryVersionKeyId
            || versionRows[0].MaterialDigestSha256 != RegistryVersionDigest
            || versionRows[0].State != "active"
            || versionRows[0].Epoch != options.Value.KeyRegistryVersion
            || versionRows[0].RetiredAtUtc != null)
            throw Invalid();
        var configuredRows = liveRows.Where(row => row.Purpose != RegistryVersionPurpose).ToList();
        if (configuredRows.Count != expected.Count)
            throw Invalid();
        foreach (var row in configuredRows)
        {
            if (!expected.TryGetValue((row.Purpose, row.KeyId), out var key)
                || row.MaterialDigestSha256 != key.Digest
                || row.State != key.State
                || row.Epoch < 1
                || row.RetainUntilUtc != key.RetainUntilUtc
                || row.RetiredAtUtc != null)
                throw Invalid();
        }
    }

    public static IReadOnlyDictionary<
        (string Purpose, string KeyId),
        (string Digest, string State, DateTime? RetainUntilUtc)>
        BuildExpected(RuntimeEnrollmentOptions options)
    {
        var result = new Dictionary<(string, string), (string, string, DateTime?)>();
        foreach (var key in options.Encryption.Keys)
        {
            var material = Convert.FromBase64String(key.KeyBase64);
            try
            {
                var digest = Convert.ToHexStringLower(SHA256.HashData(material));
                result.Add(("encryption", key.KeyId),
                    (digest, key.KeyId == options.Encryption.ActiveKeyId ? "active" : "decrypt-only", null));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material);
            }
        }
        foreach (var key in options.CapabilitySigning.Keys)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(key.PublicKeyPem);
            var digest = Convert.ToHexStringLower(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
            result.Add(("capability-signing", key.KeyId),
                (digest, key.Role, ToPostgreSqlTimestamp(key.RetainUntilUtc)));
        }
        return result;
    }

    private static DateTime? ToPostgreSqlTimestamp(DateTimeOffset? value)
    {
        if (!value.HasValue)
            return null;
        var utc = value.Value.UtcDateTime;
        return new DateTime(utc.Ticks - utc.Ticks % 10, DateTimeKind.Utc);
    }

    private static InvalidOperationException Invalid() =>
        new("Runtime enrollment key registry validation failed.");
}

public sealed class RuntimeEnrollmentKeyRegistryStartupValidator(
    IRuntimeEnrollmentKeyRegistryService registry,
    IOptions<RuntimeEnrollmentOptions> options,
    IHostApplicationLifetime lifetime,
    ILogger<RuntimeEnrollmentKeyRegistryStartupValidator> logger) : IHostedService
{
    private CancellationTokenSource? _stopping;
    private Task? _monitor;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (options.Value.Mode != "enabled")
            return;
        await registry.ValidateAsync(cancellationToken);
        _stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _monitor = MonitorAsync(_stopping.Token);
    }

    private async Task MonitorAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
                await registry.ValidateAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogCritical(exception, "Runtime enrollment key registry continuous validation failed");
            lifetime.StopApplication();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_stopping == null)
            return;
        await _stopping.CancelAsync();
        if (_monitor != null)
            await _monitor.WaitAsync(cancellationToken);
        _stopping.Dispose();
    }
}

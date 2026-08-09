using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed class RuntimeAuthorityLease : IAsyncDisposable
{
    private readonly IDbContextTransaction _transaction;
    public long AuthorityEpoch { get; }

    internal RuntimeAuthorityLease(IDbContextTransaction transaction, long authorityEpoch)
    {
        _transaction = transaction;
        AuthorityEpoch = authorityEpoch;
    }

    public Task CommitAsync(CancellationToken cancellationToken = default) =>
        _transaction.CommitAsync(cancellationToken);

    public ValueTask DisposeAsync() => _transaction.DisposeAsync();
}

public interface IRuntimeEnrollmentAuthorityService
{
    Task<RuntimeAuthorityLease> AcquireAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default);

    Task<RuntimeAuthorityLease> AcquireMutationAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default);

    Task ValidateInfrastructureAsync(CancellationToken cancellationToken = default);
}

public sealed class RuntimeEnrollmentAuthorityService : IRuntimeEnrollmentAuthorityService
{
    public const int GlobalLockNamespace = 999831;
    public const int GlobalLockKey = 1;
    public const long BindingLockSalt = 999831;

    private const string AuthorityFunctionSource = """
        BEGIN
            PERFORM pg_catalog.pg_advisory_xact_lock(999831, 1);
            UPDATE public."RuntimeEnrollmentAuthorityStates"
            SET "Epoch" = "Epoch" + 1,
                "UpdatedAtUtc" = statement_timestamp()
            WHERE "Id" = 1;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'runtime enrollment authority singleton is missing';
            END IF;
            RETURN NULL;
        END;
        """;

    private static readonly IReadOnlyDictionary<string, string[]> ProtectedTables =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["ApprovedBinaries"] = ["ProductId", "Version", "Key", "Hash", "Source"],
            ["BannedComponents"] = ["ComponentType", "ComponentHash", "ProductId", "ExpiresAt", "IsActive"],
            ["BannedHardwareIds"] = ["HardwareId", "ProductId", "ExpiresAt", "IsActive"],
            ["DistributionBindingRequests"] = ["ClientId", "Operation", "BindingId"],
            ["DistributionGrantOwnerships"] = ["ProductId", "GrantRefDigestSha256", "ClientId", "Source"],
            ["DistributionInstallationBindings"] = ["ProductId", "LicenseId", "LicenseSeatId", "EntitlementId", "SubjectRefDigestSha256", "GrantRef", "GrantRefDigestSha256", "HandoffDigestSha256", "HandoffIssuedAtUtc", "HandoffExpiresAtUtc", "DownloadCompletedAtUtc", "InstallationId", "HardwareIdHash", "Version", "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256", "CoreSha256", "ApprovedBinariesSource", "State", "SupersededBindingId", "InitialSecurityEpoch", "InvalidatedAtUtc", "InvalidationReason"],
            ["LicenseSeats"] = ["LicenseId", "HardwareId", "IsActive"],
            ["Licenses"] = ["ProductId", "IsActive", "RevokedAt", "ExpirationDate", "MaxSeats", "AllowedVersions"],
            ["Products"] = ["MinimumAllowedVersion"]
        };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly RuntimeEnrollmentOptions _options;

    public RuntimeEnrollmentAuthorityService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IOptions<RuntimeEnrollmentOptions> options)
    {
        _dbFactory = dbFactory;
        _options = options.Value;
    }

    public async Task<RuntimeAuthorityLease> AcquireAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default) =>
        await AcquireCoreAsync(db, bindingId, globalMutation: false, cancellationToken);

    public async Task<RuntimeAuthorityLease> AcquireMutationAsync(
        LicenseDbContext db,
        Guid bindingId,
        CancellationToken cancellationToken = default) =>
        await AcquireCoreAsync(db, bindingId, globalMutation: true, cancellationToken);

    private async Task<RuntimeAuthorityLease> AcquireCoreAsync(
        LicenseDbContext db,
        Guid bindingId,
        bool globalMutation,
        CancellationToken cancellationToken)
    {
        EnsureEnabledNpgsql(db);
        var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        try
        {
            await ExecuteNonQueryAsync(db,
                $"SET LOCAL lock_timeout = '{_options.LockTimeoutMilliseconds}ms'; " +
                $"SET LOCAL statement_timeout = '{_options.StatementTimeoutMilliseconds}ms';",
                cancellationToken);
            await ExecuteNonQueryAsync(db, globalMutation
                ? "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);"
                : "SELECT pg_catalog.pg_advisory_xact_lock_shared(999831, 1);", cancellationToken);

            var authorityEpoch = await ExecuteScalarAsync<long>(db,
                "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentAuthorityStates\" WHERE \"Id\" = 1;",
                cancellationToken);
            await ExecuteNonQueryAsync(db,
                "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(@bindingId, 999831));",
                cancellationToken,
                new NpgsqlParameter("bindingId", bindingId.ToString("D")));
            return new RuntimeAuthorityLease(transaction, authorityEpoch);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
            throw;
        }
    }

    public async Task ValidateInfrastructureAsync(CancellationToken cancellationToken = default)
    {
        if (_options.Mode == "off")
            return;
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        EnsureEnabledNpgsql(db);
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
            await connection.OpenAsync(cancellationToken);

        var singletonCount = await ScalarStandaloneAsync<long>(connection, """
            SELECT count(*)
            FROM public."RuntimeEnrollmentAuthorityStates"
            WHERE "Id" = 1 AND "Epoch" >= 0;
            """, cancellationToken);
        if (singletonCount != 1)
            throw InvalidInfrastructure();

        var triggerRows = await QueryStandaloneAsync(connection, """
            SELECT c.relname || '|' || t.tgname || '|' || t.tgtype::text || '|'
                || (t.tgfoid = 'public.runtime_enrollment_bump_authority_epoch()'::regprocedure)::text || '|'
                || pg_catalog.octet_length(t.tgargs)::text || '|'
                || COALESCE((
                    SELECT string_agg(a.attname, ',' ORDER BY attrs.ordinality)
                    FROM unnest(t.tgattr::smallint[]) WITH ORDINALITY attrs(attnum, ordinality)
                    JOIN pg_catalog.pg_attribute a ON a.attrelid = t.tgrelid AND a.attnum = attrs.attnum
                ), '')
            FROM pg_catalog.pg_trigger t
            JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND NOT t.tgisinternal
              AND c.relname = ANY(@tables)
              AND pg_catalog.starts_with(t.tgname, 'trg_runtime_authority_')
              AND t.tgenabled = 'O'
            ORDER BY c.relname, t.tgname;
            """, cancellationToken, new NpgsqlParameter("tables", ProtectedTables.Keys.ToArray()));
        foreach (var (table, updateColumns) in ProtectedTables)
        {
            var stem = table.ToLowerInvariant();
            var expected = new HashSet<string>(StringComparer.Ordinal)
            {
                $"{table}|trg_runtime_authority_{stem}_insert|6|true|0|",
                $"{table}|trg_runtime_authority_{stem}_update|18|true|0|{string.Join(',', updateColumns)}",
                $"{table}|trg_runtime_authority_{stem}_delete|10|true|0|",
                $"{table}|trg_runtime_authority_{stem}_truncate|34|true|0|"
            };
            if (!expected.SetEquals(triggerRows.Where(row => row.StartsWith(table + '|', StringComparison.Ordinal))))
                throw InvalidInfrastructure();
        }

        var hardening = await ScalarStandaloneAsync<bool>(connection, """
            SELECT p.prosecdef
               AND NOT r.rolcanlogin
               AND p.proacl IS NOT NULL
               AND NOT pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE')
               AND NOT pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')
               AND NOT current_role = r.rolname
               AND NOT pg_catalog.pg_has_role(current_user, r.rolname, 'MEMBER')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'INSERT')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'UPDATE')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'DELETE')
               AND NOT pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'TRUNCATE')
               AND pg_catalog.has_table_privilege(current_user,
                   'public."RuntimeEnrollmentAuthorityStates"', 'SELECT')
               AND (
                   SELECT owner_role.rolname
                   FROM pg_catalog.pg_class owner_table
                   JOIN pg_catalog.pg_namespace owner_ns ON owner_ns.oid = owner_table.relnamespace
                   JOIN pg_catalog.pg_roles owner_role ON owner_role.oid = owner_table.relowner
                   WHERE owner_ns.nspname = 'public'
                     AND owner_table.relname = 'RuntimeEnrollmentAuthorityStates'
               ) = 'softlicence_runtime_authority_owner'
               AND NOT EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = 'public'
                     AND c.relname = ANY(@tables)
                     AND pg_catalog.pg_get_userbyid(c.relowner) = current_role)
               AND pg_catalog.pg_get_function_result(p.oid) = 'trigger'
               AND p.pronargs = 0
               AND p.proargtypes = ''::oidvector
               AND pg_catalog.regexp_replace(p.prosrc, '[[:space:]]', '', 'g')
                   = pg_catalog.regexp_replace(@source, '[[:space:]]', '', 'g')
               AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']::text[]
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
            WHERE n.nspname = 'public'
              AND p.oid = 'public.runtime_enrollment_bump_authority_epoch()'::regprocedure
              AND r.rolname = 'softlicence_runtime_authority_owner';
            """, cancellationToken,
            new NpgsqlParameter("tables", ProtectedTables.Keys.ToArray()),
            new NpgsqlParameter("source", AuthorityFunctionSource));
        if (!hardening)
            throw InvalidInfrastructure();
    }

    private void EnsureEnabledNpgsql(LicenseDbContext db)
    {
        if (_options.Mode != "enabled" || !db.Database.IsNpgsql())
            throw InvalidInfrastructure();
    }

    private static async Task ExecuteNonQueryAsync(
        LicenseDbContext db,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<T> ExecuteScalarAsync<T>(
        LicenseDbContext db,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is T typed ? typed : (T)Convert.ChangeType(value!, typeof(T));
    }

    private static async Task<T> ScalarStandaloneAsync<T>(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        if (value == null || value is DBNull)
            throw InvalidInfrastructure();
        return value is T typed ? typed : (T)Convert.ChangeType(value, typeof(T));
    }

    private static async Task<IReadOnlyList<string>> QueryStandaloneAsync(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params NpgsqlParameter[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<string>();
        while (await reader.ReadAsync(cancellationToken))
            rows.Add(reader.GetString(0));
        return rows;
    }

    private static InvalidOperationException InvalidInfrastructure() =>
        new("Runtime enrollment enabled infrastructure validation failed.");
}

public sealed class RuntimeEnrollmentStartupValidator(
    IRuntimeEnrollmentAuthorityService authority,
    IOptions<RuntimeEnrollmentOptions> options) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) =>
        options.Value.Mode == "enabled"
            ? authority.ValidateInfrastructureAsync(cancellationToken)
            : Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

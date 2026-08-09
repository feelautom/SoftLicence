using System.Data;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public interface ICanaryAckKeyring
{
    CanaryAckKeyringConfiguration Configuration { get; }
    RSA LoadActivePrivateKey();
    bool TryGetPublicKey(string keyId, out CanaryAckPublicKeyResponse response);
}

public sealed class CanaryAckKeyring(IOptions<CanaryAckOptions> options) : ICanaryAckKeyring
{
    private readonly IOptions<CanaryAckOptions> _options = options;
    private readonly Lazy<CanaryAckKeyringConfiguration> _configuration = new(
        () => CanaryAckKeyringConfiguration.Build(options.Value),
        LazyThreadSafetyMode.ExecutionAndPublication);

    public CanaryAckKeyringConfiguration Configuration => _configuration.Value;

    public RSA LoadActivePrivateKey() => CanaryAckKeyringConfiguration.LoadActivePrivateKey(_options.Value);

    public bool TryGetPublicKey(string keyId, out CanaryAckPublicKeyResponse response)
    {
        response = default!;
        if (!CanaryAckKeyringConfiguration.IsCanonicalKeyId(keyId))
            return false;
        var key = Configuration.Keys.SingleOrDefault(candidate =>
            string.Equals(candidate.KeyId, keyId, StringComparison.Ordinal));
        if (key == null || key.Role == "retired")
            return false;
        response = new CanaryAckPublicKeyResponse
        {
            Schema = CanaryAckService.Schema,
            Alg = CanaryAckService.Algorithm,
            KeyId = key.KeyId,
            PublicKeySpkiBase64 = key.PublicSpkiBase64
        };
        return true;
    }
}

public interface ICanaryAckKeyRegistryService
{
    Task ValidateAsync(CancellationToken cancellationToken = default);
    Task<bool> IsRetentionElapsedAsync(string keyId, CancellationToken cancellationToken = default);
}

public sealed class CanaryAckKeyRegistryService(
    IDbContextFactory<LicenseDbContext> dbFactory,
    ICanaryAckKeyring keyring) : ICanaryAckKeyRegistryService
{
    public async Task ValidateAsync(CancellationToken cancellationToken = default)
    {
        var expected = keyring.Configuration;
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        if (!db.Database.IsNpgsql())
            throw new InvalidOperationException("Canary ACK key registry requires PostgreSQL.");

        var state = await db.CanaryAckKeyRegistryStates.AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        var rows = await db.CanaryAckKeyRegistries.AsNoTracking()
            .OrderBy(row => row.KeyId)
            .ToListAsync(cancellationToken);
        if (state == null
            || state.Id != CanaryAckKeyRegistryProvisioner.SingletonId
            || state.RegistryVersion != expected.RegistryVersion
            || !string.Equals(state.ContentDigestSha256, expected.ContentDigestSha256, StringComparison.Ordinal))
            throw Invalid();

        ValidateRows(expected, rows);
    }

    public async Task<bool> IsRetentionElapsedAsync(
        string keyId,
        CancellationToken cancellationToken = default)
    {
        if (!CanaryAckKeyringConfiguration.IsCanonicalKeyId(keyId))
            throw new ArgumentException("Canary ACK KeyId is invalid.", nameof(keyId));
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        if (!db.Database.IsNpgsql())
            throw new InvalidOperationException("Canary ACK key registry requires PostgreSQL.");
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            """
            SELECT "State" = 'previous'
               AND "RetainUntilUtc" IS NOT NULL
               AND "RetainUntilUtc" <= clock_timestamp()
            FROM public."CanaryAckKeyRegistries"
            WHERE "KeyId" = @keyId
            """,
            connection);
        command.Parameters.AddWithValue("keyId", keyId);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is true;
    }

    internal static void ValidateRows(
        CanaryAckKeyringConfiguration expected,
        IReadOnlyList<CanaryAckKeyRegistry> rows)
    {
        var liveRows = rows.Where(row => row.State != "retired").ToList();
        if (liveRows.Count != expected.Keys.Count)
            throw Invalid();
        foreach (var key in expected.Keys)
        {
            var row = liveRows.SingleOrDefault(candidate =>
                string.Equals(candidate.KeyId, key.KeyId, StringComparison.Ordinal));
            if (row == null
                || !string.Equals(row.MaterialDigestSha256, key.MaterialDigestSha256, StringComparison.Ordinal)
                || !string.Equals(row.State, key.Role, StringComparison.Ordinal)
                || row.Epoch < 1
                || row.RetiredAtUtc != null
                || row.RetainUntilUtc != key.RetainUntilUtc?.UtcDateTime)
                throw Invalid();
        }

        var activeRows = rows.Where(row => row.State == "active").ToList();
        if (activeRows.Count != 1
            || !string.Equals(activeRows[0].KeyId, expected.ActiveKeyId, StringComparison.Ordinal)
            || !string.Equals(
                activeRows[0].MaterialDigestSha256,
                expected.ActiveKey.MaterialDigestSha256,
                StringComparison.Ordinal))
            throw Invalid();
    }

    private static InvalidOperationException Invalid() =>
        new("Canary ACK key registry validation failed.");
}

public static class CanaryAckKeyRegistryProvisioner
{
    internal const int SingletonId = 1;

    public static async Task InitializeOrValidateAsync(
        string connectionString,
        CanaryAckOptions options,
        CancellationToken cancellationToken = default)
    {
        var expected = CanaryAckKeyringConfiguration.Build(options);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            cancellationToken);
        await ExecuteAsync(connection, transaction,
            "LOCK TABLE public.\"CanaryAckKeyRegistryStates\", public.\"CanaryAckKeyRegistries\" IN SHARE ROW EXCLUSIVE MODE",
            cancellationToken);

        var state = await ReadStateAsync(connection, transaction, cancellationToken);
        var rows = await ReadRowsAsync(connection, transaction, cancellationToken);
        if (state == null)
        {
            if (rows.Count != 0 || expected.RegistryVersion != 1)
                throw Invalid();
            if (expected.Keys.Any(key => key.Role == "previous"))
                throw Invalid();
            foreach (var key in expected.Keys)
                await InsertKeyAsync(connection, transaction, key, cancellationToken);
            await InsertStateAsync(connection, transaction, expected, cancellationToken);
        }
        else if (state.Value.RegistryVersion == expected.RegistryVersion)
        {
            if (!string.Equals(
                    state.Value.ContentDigestSha256,
                    expected.ContentDigestSha256,
                    StringComparison.Ordinal))
                throw Invalid();
            CanaryAckKeyRegistryService.ValidateRows(expected, rows);
        }
        else
        {
            await ApplyAdditiveVersionAsync(
                connection,
                transaction,
                state.Value,
                rows,
                expected,
                cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task ApplyAdditiveVersionAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        (int RegistryVersion, string ContentDigestSha256) state,
        IReadOnlyList<CanaryAckKeyRegistry> rows,
        CanaryAckKeyringConfiguration expected,
        CancellationToken cancellationToken)
    {
        if (expected.RegistryVersion != state.RegistryVersion + 1)
            throw Invalid();
        var existingLive = rows.Where(row => row.State != "retired").ToList();
        foreach (var row in existingLive)
        {
            var key = expected.Keys.SingleOrDefault(candidate =>
                string.Equals(candidate.KeyId, row.KeyId, StringComparison.Ordinal));
            if (key == null
                || !string.Equals(key.MaterialDigestSha256, row.MaterialDigestSha256, StringComparison.Ordinal)
                || !string.Equals(key.Role, row.State, StringComparison.Ordinal)
                || key.RetainUntilUtc?.UtcDateTime != row.RetainUntilUtc)
                throw Invalid();
        }

        var newKeys = expected.Keys.Where(key => rows.All(row =>
            !string.Equals(row.KeyId, key.KeyId, StringComparison.Ordinal))).ToList();
        if (newKeys.Count == 0 || newKeys.Any(key => key.Role != "next"))
            throw Invalid();
        foreach (var key in newKeys)
            await InsertKeyAsync(connection, transaction, key, cancellationToken);

        await using var update = new NpgsqlCommand(
            """
            UPDATE public."CanaryAckKeyRegistryStates"
            SET "RegistryVersion" = @version,
                "ContentDigestSha256" = @digest,
                "UpdatedAtUtc" = clock_timestamp()
            WHERE "Id" = 1 AND "RegistryVersion" = @previousVersion
            """,
            connection,
            transaction);
        update.Parameters.AddWithValue("version", expected.RegistryVersion);
        update.Parameters.AddWithValue("digest", expected.ContentDigestSha256);
        update.Parameters.AddWithValue("previousVersion", state.RegistryVersion);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw Invalid();
    }

    private static async Task<(int RegistryVersion, string ContentDigestSha256)?> ReadStateAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            SELECT "RegistryVersion", "ContentDigestSha256"
            FROM public."CanaryAckKeyRegistryStates"
            WHERE "Id" = 1
            FOR UPDATE
            """,
            connection,
            transaction);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            return null;
        var result = (reader.GetInt32(0), reader.GetString(1));
        if (await reader.ReadAsync(cancellationToken))
            throw Invalid();
        return result;
    }

    private static async Task<IReadOnlyList<CanaryAckKeyRegistry>> ReadRowsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        var result = new List<CanaryAckKeyRegistry>();
        await using var command = new NpgsqlCommand(
            """
            SELECT "KeyId", "MaterialDigestSha256", "State", "Epoch",
                   "CreatedAtUtc", "RetainUntilUtc", "RetiredAtUtc"
            FROM public."CanaryAckKeyRegistries"
            ORDER BY "KeyId" COLLATE "C"
            FOR UPDATE
            """,
            connection,
            transaction);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(new CanaryAckKeyRegistry
            {
                KeyId = reader.GetString(0),
                MaterialDigestSha256 = reader.GetString(1),
                State = reader.GetString(2),
                Epoch = reader.GetInt32(3),
                CreatedAtUtc = reader.GetDateTime(4),
                RetainUntilUtc = reader.IsDBNull(5) ? null : reader.GetDateTime(5),
                RetiredAtUtc = reader.IsDBNull(6) ? null : reader.GetDateTime(6)
            });
        }
        return result;
    }

    private static async Task InsertKeyAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CanaryAckConfiguredKey key,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO public."CanaryAckKeyRegistries"
                ("KeyId", "MaterialDigestSha256", "State", "Epoch",
                 "CreatedAtUtc", "RetainUntilUtc", "RetiredAtUtc")
            VALUES (@keyId, @digest, @state, 1, clock_timestamp(), @retainUntilUtc, NULL)
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("keyId", key.KeyId);
        command.Parameters.AddWithValue("digest", key.MaterialDigestSha256);
        command.Parameters.AddWithValue("state", key.Role);
        command.Parameters.AddWithValue(
            "retainUntilUtc",
            key.RetainUntilUtc.HasValue ? key.RetainUntilUtc.Value.UtcDateTime : DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task InsertStateAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CanaryAckKeyringConfiguration expected,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO public."CanaryAckKeyRegistryStates"
                ("Id", "RegistryVersion", "ContentDigestSha256", "UpdatedAtUtc")
            VALUES (1, @version, @digest, clock_timestamp())
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("version", expected.RegistryVersion);
        command.Parameters.AddWithValue("digest", expected.ContentDigestSha256);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ExecuteAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static InvalidOperationException Invalid() =>
        new("Canary ACK key registry provisioning failed.");
}

public sealed class CanaryAckKeyRegistryStartupValidator(
    IServiceProvider services,
    IOptions<RuntimeEnrollmentOptions> runtimeOptions,
    IHostApplicationLifetime lifetime,
    ILogger<CanaryAckKeyRegistryStartupValidator> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (runtimeOptions.Value.Mode == "off")
            return;
        try
        {
            var registry = services.GetRequiredService<ICanaryAckKeyRegistryService>();
            await registry.ValidateAsync(cancellationToken);
        }
        catch
        {
            logger.LogCritical("Canary ACK key registry startup validation failed.");
            lifetime.StopApplication();
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

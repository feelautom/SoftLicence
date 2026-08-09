using Npgsql;

namespace SoftLicence.Server.Services;

public static class RuntimeEnrollmentKeyRegistryProvisioner
{
    public static async Task InitializeOrValidateAsync(
        string migrationConnectionString,
        RuntimeEnrollmentOptions options,
        CancellationToken cancellationToken = default)
    {
        var expected = RuntimeEnrollmentKeyRegistryService.BuildExpected(options);
        await using var connection = new NpgsqlConnection(migrationConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (var authorityLock = connection.CreateCommand())
        {
            authorityLock.Transaction = transaction;
            authorityLock.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await authorityLock.ExecuteNonQueryAsync(cancellationToken);
        }

        var rows = await ReadRowsAsync(connection, transaction, cancellationToken);
        var configuredRows = rows.Where(row => row.Purpose != RuntimeEnrollmentKeyRegistryService.RegistryVersionPurpose)
            .ToList();
        if (configuredRows.Count == 0)
        {
            if (options.KeyRegistryVersion != 1 || !HasExpectedVersionSentinel(rows, options.KeyRegistryVersion))
            {
                throw new InvalidOperationException(
                    "A fresh runtime enrollment key registry must start at version 1.");
            }

            foreach (var entry in expected.OrderBy(entry => entry.Key.Purpose, StringComparer.Ordinal)
                         .ThenBy(entry => entry.Key.KeyId, StringComparer.Ordinal))
            {
                await InsertAsync(
                    connection,
                    transaction,
                    entry.Key.Purpose,
                    entry.Key.KeyId,
                    entry.Value.Digest,
                    entry.Value.State,
                    entry.Value.RetainUntilUtc,
                    cancellationToken);
            }

            rows = await ReadRowsAsync(connection, transaction, cancellationToken);
        }

        ValidateExisting(rows, expected, options.KeyRegistryVersion);
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task<List<RegistryRow>> ReadRowsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT "Purpose", "KeyId", "MaterialDigestSha256", "State", "Epoch",
                   "RetainUntilUtc", "RetiredAtUtc"
            FROM public."RuntimeEnrollmentKeyRegistries"
            ORDER BY "Purpose", "KeyId";
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<RegistryRow>();
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new RegistryRow(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt32(4),
                reader.IsDBNull(5) ? null : reader.GetDateTime(5),
                reader.IsDBNull(6) ? null : reader.GetDateTime(6)));
        }

        return rows;
    }

    private static async Task InsertAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string purpose,
        string keyId,
        string digest,
        string state,
        DateTime? retainUntilUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO public."RuntimeEnrollmentKeyRegistries"
                ("Purpose", "KeyId", "MaterialDigestSha256", "State", "Epoch", "CreatedAtUtc",
                 "RetainUntilUtc", "RetiredAtUtc")
            VALUES (@purpose, @keyId, @digest, @state, 1, statement_timestamp(), @retainUntilUtc, NULL);
            """;
        command.Parameters.AddWithValue("purpose", purpose);
        command.Parameters.AddWithValue("keyId", keyId);
        command.Parameters.AddWithValue("digest", digest);
        command.Parameters.AddWithValue("state", state);
        command.Parameters.AddWithValue("retainUntilUtc", retainUntilUtc ?? (object)DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void ValidateExisting(
        IReadOnlyCollection<RegistryRow> rows,
        IReadOnlyDictionary<
            (string Purpose, string KeyId),
            (string Digest, string State, DateTime? RetainUntilUtc)> expected,
        int registryVersion)
    {
        if (!HasExpectedVersionSentinel(rows, registryVersion))
            throw InvalidRegistry();

        var liveConfiguredRows = rows.Where(row =>
            row.Purpose != RuntimeEnrollmentKeyRegistryService.RegistryVersionPurpose
            && row.State != "retired").ToList();
        if (liveConfiguredRows.Count != expected.Count)
            throw InvalidRegistry();

        foreach (var row in liveConfiguredRows)
        {
            if (!expected.TryGetValue((row.Purpose, row.KeyId), out var configured)
                || row.Digest != configured.Digest
                || row.State != configured.State
                || row.Epoch < 1
                || row.RetainUntilUtc != configured.RetainUntilUtc
                || row.RetiredAtUtc != null)
            {
                throw InvalidRegistry();
            }
        }
    }

    private static bool HasExpectedVersionSentinel(
        IEnumerable<RegistryRow> rows,
        int registryVersion) =>
        rows.Count(row =>
            row.Purpose == RuntimeEnrollmentKeyRegistryService.RegistryVersionPurpose
            && row.KeyId == RuntimeEnrollmentKeyRegistryService.RegistryVersionKeyId
            && row.Digest == RuntimeEnrollmentKeyRegistryService.RegistryVersionDigest
            && row.State == "active"
            && row.Epoch == registryVersion
            && row.RetiredAtUtc == null) == 1;

    private static InvalidOperationException InvalidRegistry() =>
        new("Runtime enrollment key registry does not match the migration configuration.");

    private sealed record RegistryRow(
        string Purpose,
        string KeyId,
        string Digest,
        string State,
        int Epoch,
        DateTime? RetainUntilUtc,
        DateTime? RetiredAtUtc);
}

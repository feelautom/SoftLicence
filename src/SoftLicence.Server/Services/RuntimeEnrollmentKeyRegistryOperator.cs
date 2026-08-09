using System.Data;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace SoftLicence.Server.Services;

public sealed record RuntimeEnrollmentKeyRegistryOperationResult(
    string Mode,
    string Classification,
    int CurrentVersion,
    int TargetVersion,
    int InsertedKeys,
    int TransitionedKeys,
    int RetiredKeys,
    bool AlreadyApplied);

public static class RuntimeEnrollmentKeyRegistryOperator
{
    public const string ExecuteConfirmation = "APPLY_RUNTIME_ENROLLMENT_KEY_REGISTRY_TRANSITION";

    public static async Task<RuntimeEnrollmentKeyRegistryOperationResult> RunAsync(
        string migrationConnectionString,
        RuntimeEnrollmentOptions target,
        int expectedCurrentVersion,
        bool execute,
        string? executeConfirmation = null,
        CancellationToken cancellationToken = default)
    {
        ValidateInputs(migrationConnectionString, target, expectedCurrentVersion, execute, executeConfirmation);
        var expectedTarget = RuntimeEnrollmentKeyRegistryService.BuildExpected(target);

        await using var connection = new NpgsqlConnection(migrationConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            cancellationToken);

        await using (var authorityLock = connection.CreateCommand())
        {
            authorityLock.Transaction = transaction;
            authorityLock.CommandText = "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1);";
            await authorityLock.ExecuteNonQueryAsync(cancellationToken);
        }

        var databaseUtcNow = await ReadDatabaseUtcNowAsync(connection, transaction, cancellationToken);
        var rows = await ReadRowsAsync(connection, transaction, cancellationToken);
        var currentVersion = ReadCurrentVersion(rows);

        if (currentVersion == target.KeyRegistryVersion)
        {
            ValidateTargetState(rows, expectedTarget, target.KeyRegistryVersion);
            if (execute)
                await transaction.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentKeyRegistryOperationResult(
                execute ? "execute" : "dry-run",
                "already-applied",
                currentVersion,
                target.KeyRegistryVersion,
                0,
                0,
                0,
                true);
        }

        if (currentVersion != expectedCurrentVersion
            || target.KeyRegistryVersion != checked(currentVersion + 1))
            throw InvalidPlan();

        var plan = BuildPlan(rows, expectedTarget, target, databaseUtcNow);
        if (!execute)
        {
            return new RuntimeEnrollmentKeyRegistryOperationResult(
                "dry-run",
                plan.Classification,
                currentVersion,
                target.KeyRegistryVersion,
                plan.Inserts.Count,
                plan.Transitions.Count,
                plan.Retirements.Count,
                false);
        }

        foreach (var insert in plan.Inserts)
            await InsertAsync(connection, transaction, insert, cancellationToken);
        foreach (var transition in plan.Transitions)
            await TransitionAsync(connection, transaction, transition, false, cancellationToken);
        foreach (var retirement in plan.Retirements)
            await TransitionAsync(connection, transaction, retirement, true, cancellationToken);
        await AdvanceVersionAsync(connection, transaction, currentVersion, cancellationToken);

        rows = await ReadRowsAsync(connection, transaction, cancellationToken);
        ValidateTargetState(rows, expectedTarget, target.KeyRegistryVersion);
        await transaction.CommitAsync(cancellationToken);

        return new RuntimeEnrollmentKeyRegistryOperationResult(
            "execute",
            plan.Classification,
            currentVersion,
            target.KeyRegistryVersion,
            plan.Inserts.Count,
            plan.Transitions.Count,
            plan.Retirements.Count,
            false);
    }

    private static void ValidateInputs(
        string migrationConnectionString,
        RuntimeEnrollmentOptions target,
        int expectedCurrentVersion,
        bool execute,
        string? executeConfirmation)
    {
        if (string.IsNullOrWhiteSpace(migrationConnectionString))
            throw new InvalidOperationException("Runtime key registry operator requires a migration connection.");
        NpgsqlConnectionStringBuilder connectionBuilder;
        try
        {
            connectionBuilder = new NpgsqlConnectionStringBuilder(migrationConnectionString);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException("Runtime key registry operator connection is invalid.", exception);
        }
        if (string.Equals(connectionBuilder.Username, DatabaseMigrationRunner.ApplicationRole, StringComparison.Ordinal))
            throw new InvalidOperationException("Runtime key registry operator requires the authority owner role.");
        if (target.Mode != "enabled")
            throw new InvalidOperationException("Runtime key registry operator requires enabled Runtime Enrollment.");
        var validation = new RuntimeEnrollmentOptionsValidator().Validate(null, target);
        if (validation.Failed)
            throw new InvalidOperationException("Runtime key registry operator configuration is invalid.");
        if (expectedCurrentVersion < 1)
            throw new InvalidOperationException("Runtime key registry expected current version is invalid.");
        if (execute && !string.Equals(executeConfirmation, ExecuteConfirmation, StringComparison.Ordinal))
            throw new InvalidOperationException("Runtime key registry execute confirmation is invalid.");
    }

    private static OperationPlan BuildPlan(
        IReadOnlyCollection<RegistryRow> rows,
        IReadOnlyDictionary<
            (string Purpose, string KeyId),
            (string Digest, string State, DateTime? RetainUntilUtc)> target,
        RuntimeEnrollmentOptions targetOptions,
        DateTime databaseUtcNow)
    {
        var retired = rows.Where(row => row.State == "retired")
            .ToDictionary(row => (row.Purpose, row.KeyId));
        if (target.Keys.Any(retired.ContainsKey))
            throw InvalidPlan();

        var current = rows.Where(row =>
                row.Purpose != RuntimeEnrollmentKeyRegistryService.RegistryVersionPurpose
                && row.State != "retired")
            .ToDictionary(row => (row.Purpose, row.KeyId));
        if (current.Keys.Any(key => key.Purpose is not ("encryption" or "capability-signing")))
            throw InvalidPlan();

        var currentEncryption = current.Where(entry => entry.Key.Purpose == "encryption")
            .ToDictionary(entry => entry.Key, entry => entry.Value);
        var targetEncryption = target.Where(entry => entry.Key.Purpose == "encryption")
            .ToDictionary(entry => entry.Key, entry => entry.Value);
        if (currentEncryption.Count != targetEncryption.Count
            || currentEncryption.Any(entry =>
                !targetEncryption.TryGetValue(entry.Key, out var configured)
                || !Matches(entry.Value, configured)))
            throw InvalidPlan();

        var inserts = new List<PlannedInsert>();
        var transitions = new List<PlannedTransition>();
        var retirements = new List<PlannedTransition>();
        foreach (var entry in current.Where(entry => entry.Key.Purpose == "capability-signing"))
        {
            if (!target.TryGetValue(entry.Key, out var configured))
            {
                if (entry.Value.State != "previous"
                    || !entry.Value.RetainUntilUtc.HasValue
                    || entry.Value.RetainUntilUtc.Value > databaseUtcNow)
                    throw InvalidPlan();
                retirements.Add(new PlannedTransition(entry.Value, "retired", entry.Value.RetainUntilUtc));
                continue;
            }
            if (!string.Equals(entry.Value.Digest, configured.Digest, StringComparison.Ordinal))
                throw InvalidPlan();
            if (string.Equals(entry.Value.State, configured.State, StringComparison.Ordinal))
            {
                if (entry.Value.RetainUntilUtc != configured.RetainUntilUtc)
                    throw InvalidPlan();
                continue;
            }
            transitions.Add(new PlannedTransition(entry.Value, configured.State, configured.RetainUntilUtc));
        }

        foreach (var entry in target.Where(entry => entry.Key.Purpose == "capability-signing"))
        {
            if (current.ContainsKey(entry.Key))
                continue;
            if (entry.Value.State != "next" || entry.Value.RetainUntilUtc.HasValue)
                throw InvalidPlan();
            inserts.Add(new PlannedInsert(
                entry.Key.Purpose,
                entry.Key.KeyId,
                entry.Value.Digest,
                entry.Value.State,
                entry.Value.RetainUntilUtc));
        }

        var promoted = transitions.Count(change =>
            change.Current.State == "next" && change.TargetState == "active");
        var demoted = transitions.Count(change =>
            change.Current.State == "active" && change.TargetState == "previous");
        var invalidTransitions = transitions.Count - promoted - demoted;
        var minimumRetention = databaseUtcNow.AddSeconds(
            targetOptions.CapabilityTtlSeconds + targetOptions.ProofClockSkewSeconds);
        var demotedRetentionIsSafe = transitions.Where(change =>
                change.Current.State == "active" && change.TargetState == "previous")
            .All(change => change.TargetRetainUntilUtc.HasValue
                && change.TargetRetainUntilUtc.Value > minimumRetention);

        if (promoted == 1
            && demoted == 1
            && inserts.Count == 1
            && retirements.Count == 0
            && invalidTransitions == 0
            && demotedRetentionIsSafe)
            return new OperationPlan("rotation", inserts, transitions, retirements);

        if (promoted == 0
            && demoted == 0
            && inserts.Count == 0
            && transitions.Count == 0
            && retirements.Count > 0)
            return new OperationPlan("retirement", inserts, transitions, retirements);

        throw InvalidPlan();
    }

    private static bool Matches(
        RegistryRow row,
        (string Digest, string State, DateTime? RetainUntilUtc) configured) =>
        string.Equals(row.Digest, configured.Digest, StringComparison.Ordinal)
        && string.Equals(row.State, configured.State, StringComparison.Ordinal)
        && row.RetainUntilUtc == configured.RetainUntilUtc
        && row.RetiredAtUtc == null;

    private static void ValidateTargetState(
        IReadOnlyCollection<RegistryRow> rows,
        IReadOnlyDictionary<
            (string Purpose, string KeyId),
            (string Digest, string State, DateTime? RetainUntilUtc)> target,
        int targetVersion)
    {
        if (ReadCurrentVersion(rows) != targetVersion)
            throw InvalidState();
        var live = rows.Where(row =>
                row.Purpose != RuntimeEnrollmentKeyRegistryService.RegistryVersionPurpose
                && row.State != "retired")
            .ToList();
        if (live.Count != target.Count)
            throw InvalidState();
        foreach (var row in live)
        {
            if (!target.TryGetValue((row.Purpose, row.KeyId), out var configured)
                || !Matches(row, configured)
                || row.Epoch < 1)
                throw InvalidState();
        }
    }

    private static int ReadCurrentVersion(IReadOnlyCollection<RegistryRow> rows)
    {
        var sentinels = rows.Where(row =>
            row.Purpose == RuntimeEnrollmentKeyRegistryService.RegistryVersionPurpose).ToList();
        if (sentinels.Count != 1)
            throw InvalidState();
        var sentinel = sentinels[0];
        if (sentinel.KeyId != RuntimeEnrollmentKeyRegistryService.RegistryVersionKeyId
            || sentinel.Digest != RuntimeEnrollmentKeyRegistryService.RegistryVersionDigest
            || sentinel.State != "active"
            || sentinel.Epoch < 1
            || sentinel.RetainUntilUtc != null
            || sentinel.RetiredAtUtc != null)
            throw InvalidState();
        return sentinel.Epoch;
    }

    private static async Task<DateTime> ReadDatabaseUtcNowAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT clock_timestamp();";
        return (DateTime)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw InvalidState());
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
            ORDER BY "Purpose", "KeyId" COLLATE "C"
            FOR UPDATE;
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
        PlannedInsert insert,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO public."RuntimeEnrollmentKeyRegistries"
                ("Purpose", "KeyId", "MaterialDigestSha256", "State", "Epoch", "CreatedAtUtc",
                 "RetainUntilUtc", "RetiredAtUtc")
            VALUES (@purpose, @keyId, @digest, @state, 1, clock_timestamp(), @retainUntilUtc, NULL);
            """;
        command.Parameters.AddWithValue("purpose", insert.Purpose);
        command.Parameters.AddWithValue("keyId", insert.KeyId);
        command.Parameters.AddWithValue("digest", insert.Digest);
        command.Parameters.AddWithValue("state", insert.State);
        command.Parameters.AddWithValue("retainUntilUtc", insert.RetainUntilUtc ?? (object)DBNull.Value);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw InvalidState();
    }

    private static async Task TransitionAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        PlannedTransition transition,
        bool retirement,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE public."RuntimeEnrollmentKeyRegistries"
            SET "State" = @targetState,
                "Epoch" = "Epoch" + 1,
                "RetainUntilUtc" = @targetRetainUntilUtc,
                "RetiredAtUtc" = CASE WHEN @retirement THEN clock_timestamp() ELSE NULL END
            WHERE "Purpose" = @purpose
              AND "KeyId" = @keyId
              AND "MaterialDigestSha256" = @digest
              AND "State" = @currentState
              AND "Epoch" = @currentEpoch
              AND "RetainUntilUtc" IS NOT DISTINCT FROM @currentRetainUntilUtc
              AND "RetiredAtUtc" IS NULL;
            """;
        command.Parameters.AddWithValue("targetState", transition.TargetState);
        command.Parameters.AddWithValue(
            "targetRetainUntilUtc",
            transition.TargetRetainUntilUtc ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("retirement", retirement);
        command.Parameters.AddWithValue("purpose", transition.Current.Purpose);
        command.Parameters.AddWithValue("keyId", transition.Current.KeyId);
        command.Parameters.AddWithValue("digest", transition.Current.Digest);
        command.Parameters.AddWithValue("currentState", transition.Current.State);
        command.Parameters.AddWithValue("currentEpoch", transition.Current.Epoch);
        command.Parameters.AddWithValue(
            "currentRetainUntilUtc",
            transition.Current.RetainUntilUtc ?? (object)DBNull.Value);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw InvalidState();
    }

    private static async Task AdvanceVersionAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        int currentVersion,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE public."RuntimeEnrollmentKeyRegistries"
            SET "Epoch" = "Epoch" + 1
            WHERE "Purpose" = 'registry-version'
              AND "KeyId" = 'global'
              AND "MaterialDigestSha256" = repeat('0', 64)
              AND "State" = 'active'
              AND "Epoch" = @currentVersion
              AND "RetainUntilUtc" IS NULL
              AND "RetiredAtUtc" IS NULL;
            """;
        command.Parameters.AddWithValue("currentVersion", currentVersion);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw InvalidState();
    }

    private static InvalidOperationException InvalidPlan() =>
        new("Runtime enrollment key registry operation plan is invalid.");

    private static InvalidOperationException InvalidState() =>
        new("Runtime enrollment key registry changed or is invalid.");

    private sealed record RegistryRow(
        string Purpose,
        string KeyId,
        string Digest,
        string State,
        int Epoch,
        DateTime? RetainUntilUtc,
        DateTime? RetiredAtUtc);

    private sealed record PlannedInsert(
        string Purpose,
        string KeyId,
        string Digest,
        string State,
        DateTime? RetainUntilUtc);

    private sealed record PlannedTransition(
        RegistryRow Current,
        string TargetState,
        DateTime? TargetRetainUntilUtc);

    private sealed record OperationPlan(
        string Classification,
        IReadOnlyList<PlannedInsert> Inserts,
        IReadOnlyList<PlannedTransition> Transitions,
        IReadOnlyList<PlannedTransition> Retirements);
}

public static class RuntimeEnrollmentKeyRegistryOperatorRunner
{
    public static async Task RunAsync(
        IConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        var connectionString = configuration.GetConnectionString("MigrationConnection");
        var mode = configuration["Database:RuntimeKeyRegistryOperator:Mode"] ?? "dry-run";
        if (mode is not ("dry-run" or "execute"))
            throw new InvalidOperationException("Runtime key registry operator mode must be exact.");
        var expectedCurrentVersion = configuration.GetValue<int>(
            "Database:RuntimeKeyRegistryOperator:ExpectedCurrentVersion");
        var options = new RuntimeEnrollmentOptions();
        configuration.GetSection("RuntimeEnrollment").Bind(options);
        RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders(options);
        var result = await RuntimeEnrollmentKeyRegistryOperator.RunAsync(
            connectionString ?? string.Empty,
            options,
            expectedCurrentVersion,
            mode == "execute",
            configuration["Database:RuntimeKeyRegistryOperator:ExecuteConfirmation"],
            cancellationToken);
        Console.WriteLine(
            "Runtime key registry operator completed: "
            + $"mode={result.Mode}; classification={result.Classification}; "
            + $"currentVersion={result.CurrentVersion}; targetVersion={result.TargetVersion}; "
            + $"inserted={result.InsertedKeys}; transitioned={result.TransitionedKeys}; "
            + $"retired={result.RetiredKeys}; alreadyApplied={result.AlreadyApplied}.");
    }
}

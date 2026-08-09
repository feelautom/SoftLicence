using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class Tkt000217DuplicateBindingReconciliationPostgreSqlTests
{
    [Fact]
    public async Task PowerShellWrapper_PwshAcceptsCanonicalUtcTimestampFromRealManifestShape()
    {
        var temporaryDirectory = Directory.CreateTempSubdirectory("softlicence-tkt000217-pwsh-manifest-");
        try
        {
            var capturePath = Path.Combine(temporaryDirectory.FullName, "psql-arguments.txt");
            var fakePsqlPath = Path.Combine(temporaryDirectory.FullName, "psql.cmd");
            await File.WriteAllTextAsync(fakePsqlPath, "@echo off\r\necho %* > \"%TKT000217_CAPTURE%\"\r\nexit /b 0\r\n");

            var artifactBytes = "real-standard-backup-shape"u8.ToArray();
            var dumpName = $"softlicence_{DateTimeOffset.UtcNow:yyyy-MM-dd_HH-mm-ss-fff}_{Guid.NewGuid():N}.dump";
            var artifactPath = Path.Combine(temporaryDirectory.FullName, dumpName);
            await File.WriteAllBytesAsync(artifactPath, artifactBytes);
            var artifactSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(artifactBytes)).ToLowerInvariant();
            var createdAtText = DateTimeOffset.UtcNow.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            var manifestPath = artifactPath + ".manifest.json";
            await File.WriteAllTextAsync(manifestPath, $$"""
                {"schema":"softlicence-backup-manifest-v1","file":"{{dumpName}}","sizeBytes":{{artifactBytes.Length}},"sha256":"{{artifactSha256}}","createdAtUtc":"{{createdAtText}}","format":"postgresql-custom"}
                """);

            var result = await RunWrapperCoreAsync(
                fakePsqlPath,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["PGHOST"] = "local-test",
                    ["PGPORT"] = "5432",
                    ["PGDATABASE"] = "local-test",
                    ["PGUSER"] = "local-test",
                    ["PGPASSWORD"] = "local-test",
                    ["TKT000217_CAPTURE"] = capturePath
                },
                [
                    "-Apply", "-ExpectedSnapshotSha256", new string('0', 64),
                    "-VerifiedBackupManifestPath", manifestPath,
                    "-VerifiedBackupArtifactPath", artifactPath
                ],
                "pwsh.exe");

            Assert.True(result.ExitCode == 0,
                $"pwsh rejected a real standard backup manifest shape. stdout={result.StandardOutput} stderr={result.StandardError}");
            var arguments = await File.ReadAllTextAsync(capturePath);
            var expectedArgumentTimestamp = DateTimeOffset.ParseExact(
                createdAtText,
                "O",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime().ToString("O");
            Assert.Contains(expectedArgumentTimestamp, arguments, StringComparison.Ordinal);
        }
        finally
        {
            temporaryDirectory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task PowerShellWrapper_DefaultsToDryRun_AndApplyRequiresCanonicalBackupManifest()
    {
        var temporaryDirectory = Directory.CreateTempSubdirectory("softlicence-tkt000217-wrapper-");
        try
        {
            var capturePath = Path.Combine(temporaryDirectory.FullName, "psql-arguments.txt");
            var fakePsqlPath = Path.Combine(temporaryDirectory.FullName, "psql.cmd");
            await File.WriteAllTextAsync(fakePsqlPath, "@echo off\r\necho %* > \"%TKT000217_CAPTURE%\"\r\nexit /b 0\r\n");

            var dryRun = await RunWrapperAsync(fakePsqlPath, capturePath);
            Assert.Equal(0, dryRun.ExitCode);
            var dryRunArguments = await File.ReadAllTextAsync(capturePath);
            Assert.Contains("softlicence.tkt000217.apply = 'false'", dryRunArguments, StringComparison.Ordinal);
            Assert.Contains("--single-transaction", dryRunArguments, StringComparison.Ordinal);

            File.Delete(capturePath);
            var rejectedApply = await RunWrapperAsync(
                fakePsqlPath,
                capturePath,
                "-Apply",
                "-ExpectedSnapshotSha256",
                new string('0', 64));
            Assert.NotEqual(0, rejectedApply.ExitCode);
            Assert.False(File.Exists(capturePath));

            var backupCreatedAt = DateTimeOffset.UtcNow.ToUniversalTime();
            var dumpName = $"softlicence_{DateTimeOffset.UtcNow:yyyy-MM-dd_HH-mm-ss-fff}_{Guid.NewGuid():N}.dump";
            var artifactPath = Path.Combine(temporaryDirectory.FullName, dumpName);
            var artifactBytes = "real-postgresql-custom-backup"u8.ToArray();
            await File.WriteAllBytesAsync(artifactPath, artifactBytes);
            var artifactSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(artifactBytes)).ToLowerInvariant();
            var manifestPath = Path.Combine(temporaryDirectory.FullName, dumpName + ".manifest.json");
            await File.WriteAllTextAsync(manifestPath, $$"""
                {"schema":"softlicence-backup-manifest-v1","file":"{{dumpName}}","sizeBytes":{{artifactBytes.Length}},"sha256":"{{artifactSha256}}","createdAtUtc":"{{backupCreatedAt:O}}","format":"postgresql-custom"}
                """);
            var missingArtifact = await RunWrapperAsync(
                fakePsqlPath,
                capturePath,
                "-Apply",
                "-ExpectedSnapshotSha256",
                new string('0', 64),
                "-VerifiedBackupManifestPath",
                manifestPath);
            Assert.NotEqual(0, missingArtifact.ExitCode);
            Assert.False(File.Exists(capturePath));

            var mismatchedManifestPath = Path.Combine(temporaryDirectory.FullName, "mismatch.dump.manifest.json");
            await File.WriteAllTextAsync(mismatchedManifestPath, $$"""
                {"schema":"softlicence-backup-manifest-v1","file":"{{dumpName}}","sizeBytes":{{artifactBytes.Length}},"sha256":"{{new string('0', 64)}}","createdAtUtc":"{{backupCreatedAt:O}}","format":"postgresql-custom"}
                """);
            var mismatchedHash = await RunWrapperAsync(
                fakePsqlPath,
                capturePath,
                "-Apply",
                "-ExpectedSnapshotSha256",
                new string('0', 64),
                "-VerifiedBackupManifestPath",
                mismatchedManifestPath,
                "-VerifiedBackupArtifactPath",
                artifactPath);
            Assert.NotEqual(0, mismatchedHash.ExitCode);
            Assert.False(File.Exists(capturePath));

            var acceptedApply = await RunWrapperAsync(
                fakePsqlPath,
                capturePath,
                "-Apply",
                "-ExpectedSnapshotSha256",
                new string('0', 64),
                "-VerifiedBackupManifestPath",
                manifestPath,
                "-VerifiedBackupArtifactPath",
                artifactPath);
            Assert.Equal(0, acceptedApply.ExitCode);
            var applyArguments = await File.ReadAllTextAsync(capturePath);
            Assert.Contains("softlicence.tkt000217.apply = 'true'", applyArguments, StringComparison.Ordinal);
            Assert.Contains(backupCreatedAt.ToString("O"), applyArguments, StringComparison.Ordinal);
        }
        finally
        {
            temporaryDirectory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task PowerShellWrapper_WithRealPsqlAndMinimalOperatorRole_CommitsOneTransaction()
    {
        var containerName = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES_CONTAINER");
        if (string.IsNullOrWhiteSpace(containerName))
        {
            throw new InvalidOperationException(
                "SOFTLICENCE_RUNTIME_TEST_POSTGRES_CONTAINER is required for the real psql wrapper test.");
        }

        await using var database = await TestDatabase.CreateAsync();
        await SeedAsync(database.ConnectionString);
        var operatorCredentials = await database.CreateMinimalOperatorAsync();
        var temporaryDirectory = Directory.CreateTempSubdirectory("softlicence-tkt000217-real-psql-");
        try
        {
            var shimPath = Path.Combine(temporaryDirectory.FullName, "psql.ps1");
            var containerSqlPath = $"/tmp/tkt000217-{Guid.NewGuid():N}.sql";
            await File.WriteAllTextAsync(shimPath,
                $$"""
                param([Parameter(ValueFromRemainingArguments = $true)][string[]]$RemainingArguments)
                $translated = [Collections.Generic.List[string]]::new()
                for ($index = 0; $index -lt $RemainingArguments.Count; $index++) {
                    $translated.Add($RemainingArguments[$index])
                    if ($RemainingArguments[$index] -ceq '--file') {
                        $index++
                        $translated.Add('{{containerSqlPath}}')
                    }
                }
                & docker exec -i `
                    -e "PGHOST=$env:PGHOST" -e "PGPORT=$env:PGPORT" `
                    -e "PGDATABASE=$env:PGDATABASE" -e "PGUSER=$env:PGUSER" `
                    -e "PGPASSWORD=$env:PGPASSWORD" {{containerName}} psql @translated
                exit $LASTEXITCODE
                """);
            await RunProcessSuccessfullyAsync("docker", ["cp", FindSqlPath(), $"{containerName}:{containerSqlPath}"]);
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["PGHOST"] = "127.0.0.1",
                ["PGPORT"] = "5432",
                ["PGDATABASE"] = database.DatabaseName,
                ["PGUSER"] = operatorCredentials.Username,
                ["PGPASSWORD"] = operatorCredentials.Password
            };

            var dryRun = await RunWrapperCoreAsync(shimPath, environment, []);
            Assert.True(dryRun.ExitCode == 0,
                $"Real psql dry-run failed. stdout={dryRun.StandardOutput} stderr={dryRun.StandardError}");
            var snapshot = System.Text.RegularExpressions.Regex.Match(dryRun.StandardOutput, "[0-9a-f]{64}").Value;
            Assert.Matches("^[0-9a-f]{64}$", snapshot);

            var artifactBytes = "real-psql-backup-artifact"u8.ToArray();
            var dumpName = $"softlicence_{DateTimeOffset.UtcNow:yyyy-MM-dd_HH-mm-ss-fff}_{Guid.NewGuid():N}.dump";
            var artifactPath = Path.Combine(temporaryDirectory.FullName, dumpName);
            await File.WriteAllBytesAsync(artifactPath, artifactBytes);
            var artifactSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(artifactBytes)).ToLowerInvariant();
            var createdAt = DateTimeOffset.UtcNow.ToUniversalTime();
            var manifestPath = artifactPath + ".manifest.json";
            await File.WriteAllTextAsync(manifestPath, $$"""
                {"schema":"softlicence-backup-manifest-v1","file":"{{dumpName}}","sizeBytes":{{artifactBytes.Length}},"sha256":"{{artifactSha256}}","createdAtUtc":"{{createdAt:O}}","format":"postgresql-custom"}
                """);

            var apply = await RunWrapperCoreAsync(shimPath, environment,
            [
                "-Apply", "-ExpectedSnapshotSha256", snapshot,
                "-VerifiedBackupManifestPath", manifestPath,
                "-VerifiedBackupArtifactPath", artifactPath
            ]);
            Assert.True(apply.ExitCode == 0,
                $"Real psql apply failed. stdout={apply.StandardOutput} stderr={apply.StandardError}");
            await using var verify = new NpgsqlConnection(database.ConnectionString);
            await verify.OpenAsync();
            Assert.Equal(6L, await ScalarAsync<long>(verify, """
                SELECT count(*) FROM public."DistributionInstallationBindings" WHERE "State" = 'active';
                """));
        }
        finally
        {
            temporaryDirectory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task DryRun_LeavesEveryAuthorityUnchanged()
    {
        await using var database = await TestDatabase.CreateAsync();
        var fixture = await SeedAsync(database.ConnectionString);
        var before = await ReadStateAsync(database.ConnectionString);

        var result = await RunAsync(database.ConnectionString, apply: false);

        Assert.Equal("DRY_RUN", result.Mode);
        Assert.Equal(5, result.Groups);
        Assert.Equal(10, result.Bindings);
        Assert.Equal(7, result.Enrollments);
        Assert.Equal(5, result.Preserved);
        Assert.Equal(before, await ReadStateAsync(database.ConnectionString));
        Assert.Equal(16, fixture.ActiveBindings);
    }

    [Fact]
    public async Task Apply_InvalidatesOnlyHistoricalAuthorities_AndPreservesB1AndUnrelatedRows()
    {
        await using var database = await TestDatabase.CreateAsync();
        var fixture = await SeedAsync(database.ConnectionString);
        var dryRun = await RunAsync(database.ConnectionString, apply: false);
        await using var epochConnection = new NpgsqlConnection(database.ConnectionString);
        await epochConnection.OpenAsync();
        var epochBefore = await ScalarAsync<long>(epochConnection,
            "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentAuthorityStates\" WHERE \"Id\" = 1;");

        var result = await RunAsync(
            database.ConnectionString,
            apply: true,
            dryRun.Snapshot,
            DateTimeOffset.UtcNow);

        Assert.Equal("APPLIED", result.Mode);
        Assert.Equal(6, result.ActiveAfter);
        Assert.Equal(0, result.DuplicatesAfter);
        Assert.Equal(5, result.Preserved);
        Assert.True(await ScalarAsync<long>(epochConnection,
            "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentAuthorityStates\" WHERE \"Id\" = 1;") > epochBefore);
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        Assert.Equal(10L, await ScalarAsync<long>(connection, """
            SELECT count(*) FROM public."DistributionInstallationBindings"
            WHERE "State" = 'invalidated' AND "InvalidationReason" = 'tkt_000217_duplicate_reconciled';
            """));
        Assert.Equal(7L, await ScalarAsync<long>(connection, """
            SELECT count(*) FROM public."RuntimeEnrollments"
            WHERE "State" = 'INVALIDATED' AND "InvalidationReason" = 'tkt_000217_duplicate_reconciled';
            """));
        Assert.Equal(fixture.UnrelatedBindingId, await ScalarAsync<Guid>(connection, """
            SELECT "Id" FROM public."DistributionInstallationBindings"
            WHERE "State" = 'active' AND "ProductId" = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
            """));
        Assert.Equal(fixture.UnrelatedEnrollmentId, await ScalarAsync<Guid>(connection, """
            SELECT "Id" FROM public."RuntimeEnrollments"
            WHERE "State" = 'ACTIVE' AND "ProductId" = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
            """));
    }

    [Fact]
    public async Task Apply_WithStaleSnapshot_RollsBackWithoutPartialMutation()
    {
        await using var database = await TestDatabase.CreateAsync();
        await SeedAsync(database.ConnectionString);
        var before = await ReadStateAsync(database.ConnectionString);

        var error = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(
            database.ConnectionString,
            apply: true,
            new string('0', 64),
            DateTimeOffset.UtcNow));

        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, error.SqlState);
        Assert.Contains("snapshot approval is absent or stale", error.MessageText, StringComparison.Ordinal);
        Assert.Equal(before, await ReadStateAsync(database.ConnectionString));
    }

    [Fact]
    public async Task DivergentBindingEnrollmentLineage_IsRejectedBeforeMutation()
    {
        await using var database = await TestDatabase.CreateAsync();
        await SeedAsync(database.ConnectionString);
        await CorruptAsync(database.ConnectionString, """
            UPDATE public."RuntimeEnrollments" enrollments
            SET "InstallationId" = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
            WHERE enrollments."Id" = (
                SELECT e."Id"
                FROM public."RuntimeEnrollments" e
                JOIN public."DistributionInstallationBindings" b ON b."Id" = e."BindingId"
                WHERE e."State" = 'ACTIVE' AND b."ProductId" <> 'ffffffff-ffff-4fff-8fff-ffffffffffff'
                ORDER BY b."BoundAtUtc" DESC
                LIMIT 1);
            """);
        var before = await ReadStateAsync(database.ConnectionString);

        var error = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(database.ConnectionString, apply: false));

        Assert.Contains("authority lineage drifted", error.MessageText, StringComparison.Ordinal);
        Assert.Equal(before, await ReadStateAsync(database.ConnectionString));
    }

    [Fact]
    public async Task ActiveTargetWithInvalidationMetadata_IsRejectedBeforeMutation()
    {
        await using var database = await TestDatabase.CreateAsync();
        await SeedAsync(database.ConnectionString);
        await CorruptAsync(database.ConnectionString, """
            UPDATE public."DistributionInstallationBindings"
            SET "InvalidationReason" = 'preexisting_reason'
            WHERE "Id" = (
                SELECT "Id" FROM public."DistributionInstallationBindings"
                WHERE "State" = 'active' AND "ProductId" <> 'ffffffff-ffff-4fff-8fff-ffffffffffff'
                ORDER BY "BoundAtUtc" DESC LIMIT 1);
            """);
        var before = await ReadStateAsync(database.ConnectionString);

        var error = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(database.ConnectionString, apply: false));

        Assert.Contains("already carries invalidation metadata", error.MessageText, StringComparison.Ordinal);
        Assert.Equal(before, await ReadStateAsync(database.ConnectionString));
    }

    [Theory]
    [InlineData("uppercase")]
    [InlineData("leading-space")]
    public async Task Apply_WithNonCanonicalSnapshot_IsRejected(string mutation)
    {
        await using var database = await TestDatabase.CreateAsync();
        await SeedAsync(database.ConnectionString);
        var dryRun = await RunAsync(database.ConnectionString, apply: false);
        var nonCanonical = mutation == "uppercase"
            ? dryRun.Snapshot.ToUpperInvariant()
            : " " + dryRun.Snapshot;

        var error = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(
            database.ConnectionString,
            apply: true,
            nonCanonical,
            DateTimeOffset.UtcNow));

        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, error.SqlState);
        Assert.Contains("snapshot approval is absent or stale", error.MessageText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DriftedTopology_IsRejectedBeforeMutation()
    {
        await using var database = await TestDatabase.CreateAsync();
        await SeedAsync(database.ConnectionString);
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using (var replica = new NpgsqlCommand("SET session_replication_role = replica;", connection))
            {
                await replica.ExecuteNonQueryAsync();
            }
            await InsertBindingAsync(connection, 99, 1, DateTimeOffset.UtcNow.AddHours(-10));
            await using var origin = new NpgsqlCommand("SET session_replication_role = origin;", connection);
            await origin.ExecuteNonQueryAsync();
        }
        var before = await ReadStateAsync(database.ConnectionString);

        var error = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(database.ConnectionString, apply: false));

        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, error.SqlState);
        Assert.Contains("drifted", error.MessageText, StringComparison.Ordinal);
        Assert.Equal(before, await ReadStateAsync(database.ConnectionString));
    }

    [Fact]
    public async Task ConcurrentRun_WaitsForTheGlobalRuntimeAuthorityLock()
    {
        await using var database = await TestDatabase.CreateAsync();
        await SeedAsync(database.ConnectionString);
        await using var blocker = new NpgsqlConnection(database.ConnectionString);
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await using (var command = new NpgsqlCommand("SELECT pg_advisory_xact_lock(999831, 1);", blocker, transaction))
        {
            await command.ExecuteNonQueryAsync();
        }

        var waitingRun = RunAsync(database.ConnectionString, apply: false);
        var waitEvent = await WaitForAdvisoryWaiterAsync(database.ConnectionString);
        Assert.Equal("advisory", waitEvent);
        Assert.False(waitingRun.IsCompleted);

        await transaction.RollbackAsync();
        var result = await waitingRun;
        Assert.Equal("DRY_RUN", result.Mode);
    }

    private static async Task<string> WaitForAdvisoryWaiterAsync(string connectionString)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 50; attempt++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT wait_event
                FROM pg_catalog.pg_stat_activity
                WHERE datname = current_database()
                  AND state = 'active'
                  AND wait_event_type = 'Lock'
                  AND query LIKE '%pg_catalog.pg_advisory_xact_lock(999831, 1)%'
                LIMIT 1;
                """, observer);
            if (await command.ExecuteScalarAsync() is string waitEvent)
            {
                return waitEvent;
            }
            await Task.Delay(50);
        }
        throw new TimeoutException("Expected the reconciliation transaction to wait on the global advisory lock.");
    }

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)> RunWrapperAsync(
        string fakePsqlPath,
        string capturePath,
        params string[] additionalArguments)
    {
        var environment = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["PGHOST"] = "local-test",
            ["PGPORT"] = "5432",
            ["PGDATABASE"] = "local-test",
            ["PGUSER"] = "local-test",
            ["PGPASSWORD"] = "local-test",
            ["TKT000217_CAPTURE"] = capturePath
        };
        return await RunWrapperCoreAsync(fakePsqlPath, environment, additionalArguments);
    }

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)> RunWrapperCoreAsync(
        string psqlPath,
        IReadOnlyDictionary<string, string> environment,
        IReadOnlyList<string> additionalArguments,
        string powerShellExecutable = "powershell.exe")
    {
        var start = new ProcessStartInfo
        {
            FileName = powerShellExecutable,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(Path.Combine(FindRepositoryRoot(), "scripts", "Repair-Tkt000217DuplicateBindings.ps1"));
        start.ArgumentList.Add("-PsqlPath");
        start.ArgumentList.Add(psqlPath);
        foreach (var argument in additionalArguments)
        {
            start.ArgumentList.Add(argument);
        }
        foreach (var pair in environment)
        {
            start.Environment[pair.Key] = pair.Value;
        }
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, output, error);
    }

    private static async Task RunProcessSuccessfullyAsync(string fileName, IReadOnlyList<string> arguments)
    {
        var start = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Unable to start {fileName}.");
        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        Assert.True(process.ExitCode == 0, $"{fileName} failed. stdout={output} stderr={error}");
    }

    private static async Task<RunResult> RunAsync(
        string connectionString,
        bool apply,
        string? expectedSnapshot = null,
        DateTimeOffset? backupVerifiedAt = null)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await SetLocalAsync(connection, transaction, "softlicence.tkt000217.apply", apply ? "true" : "false");
        await SetLocalAsync(connection, transaction, "softlicence.tkt000217.expected_snapshot_sha256", expectedSnapshot ?? string.Empty);
        await SetLocalAsync(connection, transaction, "softlicence.tkt000217.backup_verified_at_utc", backupVerifiedAt?.ToUniversalTime().ToString("O") ?? string.Empty);

        var sql = await File.ReadAllTextAsync(FindSqlPath());
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 };
        await using var reader = await command.ExecuteReaderAsync();
        RunResult? result = null;
        do
        {
            if (reader.FieldCount == 8 && reader.GetName(0) == "mode" && await reader.ReadAsync())
            {
                result = new RunResult(
                    reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.GetInt32(3),
                    reader.GetInt32(4), reader.GetInt32(5), reader.GetInt32(6), reader.GetInt32(7));
            }
        } while (await reader.NextResultAsync());
        await reader.CloseAsync();
        await transaction.CommitAsync();
        return result ?? throw new InvalidOperationException("The reconciliation script returned no summary row.");
    }

    private static async Task SetLocalAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string key,
        string value)
    {
        await using var command = new NpgsqlCommand("SELECT set_config(@key, @value, true);", connection, transaction);
        command.Parameters.AddWithValue("key", key);
        command.Parameters.AddWithValue("value", value);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task CorruptAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using (var replica = new NpgsqlCommand("SET session_replication_role = replica;", connection))
        {
            await replica.ExecuteNonQueryAsync();
        }
        await using (var command = new NpgsqlCommand(sql, connection))
        {
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await using var origin = new NpgsqlCommand("SET session_replication_role = origin;", connection);
        await origin.ExecuteNonQueryAsync();
    }

    private static string FindSqlPath()
    {
        return Path.Combine(FindRepositoryRoot(), "scripts", "tkt-000217-reconcile-duplicate-bindings.sql");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "scripts", "tkt-000217-reconcile-duplicate-bindings.sql")))
            {
                return directory.FullName;
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("Unable to locate the TKT-000217 reconciliation SQL script.");
    }

    private static async Task<Fixture> SeedAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using (var replication = new NpgsqlCommand("SET session_replication_role = replica;", connection))
        {
            await replication.ExecuteNonQueryAsync();
        }
        var baseTime = new DateTimeOffset(2026, 8, 3, 18, 0, 0, TimeSpan.Zero);
        var groupSizes = new[] { 2, 7, 2, 2, 2 };
        var enrollmentCounts = new[] { 1, 5, 2, 2, 2 };
        for (var group = 1; group <= groupSizes.Length; group++)
        {
            for (var rank = 1; rank <= groupSizes[group - 1]; rank++)
            {
                var bindingId = await InsertBindingAsync(connection, group, rank, baseTime.AddHours(-group).AddMinutes(-rank));
                if (rank <= enrollmentCounts[group - 1])
                {
                    await InsertEnrollmentAsync(connection, group, rank, bindingId, baseTime.AddHours(-group).AddMinutes(-rank));
                }
            }
        }

        var unrelatedBindingId = await InsertBindingAsync(connection, 100, 1, baseTime.AddDays(-20));
        var unrelatedEnrollmentId = await InsertEnrollmentAsync(connection, 100, 1, unrelatedBindingId, baseTime.AddDays(-20));
        await using (var replication = new NpgsqlCommand("SET session_replication_role = origin;", connection))
        {
            await replication.ExecuteNonQueryAsync();
        }
        return new Fixture(16, unrelatedBindingId, unrelatedEnrollmentId);
    }

    private static async Task<Guid> InsertBindingAsync(
        NpgsqlConnection connection,
        int group,
        int rank,
        DateTimeOffset boundAt)
    {
        var bindingId = Guid.NewGuid();
        var productId = group == 100
            ? Guid.Parse("ffffffff-ffff-4fff-8fff-ffffffffffff")
            : Guid.Parse($"{group:x8}-1111-4111-8111-111111111111");
        var hardware = group == 100 ? new string('f', 64) : group.ToString("x2").PadLeft(64, 'a');
        var licenseId = Guid.Parse($"{group:x8}-2222-4222-8222-222222222222");
        var seatId = Guid.Parse($"{group:x8}-3333-4333-8333-333333333333");
        var grant = Guid.NewGuid().ToString("D");
        var bindingHex = bindingId.ToString("N");
        var handoff = bindingHex + bindingHex;
        var installation = Guid.NewGuid().ToString("D");
        await using var command = new NpgsqlCommand("""
            INSERT INTO public."DistributionInstallationBindings"
                ("Id", "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId",
                 "SubjectRefDigestSha256", "GrantRef", "GrantRefDigestSha256",
                 "HandoffDigestSha256", "HandoffIssuedAtUtc", "HandoffExpiresAtUtc",
                 "DownloadCompletedAtUtc", "InstallationId", "HardwareIdHash", "Version",
                 "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256",
                 "CoreSha256", "ApprovedBinariesSource", "State", "BoundAtUtc",
                 "InvalidatedAtUtc", "InvalidationReason")
            VALUES
                (@id, @product, @license, @seat, @entitlement, @subject, @grant, @grant_digest,
                 @handoff, @handoff_issued, @handoff_expires, @downloaded, @installation, @hardware,
                 @version, 'installer.exe', @installer, @executable, @native, @core, 'release',
                 'active', @bound, NULL, NULL);
            INSERT INTO public."DistributionBindingRequests"
                ("Id", "ClientId", "RequestId", "Operation", "PayloadDigest", "BindingId",
                 "ResponseJson", "CreatedAtUtc")
            VALUES
                (@request_row, 'website-step1', @request_id, 'finalize_binding', @payload,
                 @id, '{}', @bound);
            """, connection);
        command.Parameters.AddWithValue("id", bindingId);
        command.Parameters.AddWithValue("product", productId);
        command.Parameters.AddWithValue("license", licenseId);
        command.Parameters.AddWithValue("seat", seatId);
        command.Parameters.AddWithValue("entitlement", Guid.NewGuid());
        command.Parameters.AddWithValue("subject", rank == 1 ? new string('b', 64) : (object)DBNull.Value);
        command.Parameters.AddWithValue("grant", grant);
        command.Parameters.AddWithValue("grant_digest", bindingHex + bindingHex);
        command.Parameters.AddWithValue("handoff", handoff);
        command.Parameters.AddWithValue("handoff_issued", boundAt.AddMinutes(-2));
        command.Parameters.AddWithValue("handoff_expires", boundAt.AddMinutes(20));
        command.Parameters.AddWithValue("downloaded", boundAt.AddMinutes(-1));
        command.Parameters.AddWithValue("installation", installation);
        command.Parameters.AddWithValue("hardware", hardware);
        command.Parameters.AddWithValue("version", $"2.3.{50 - rank}");
        command.Parameters.AddWithValue("installer", new string('1', 64));
        command.Parameters.AddWithValue("executable", new string('2', 64));
        command.Parameters.AddWithValue("native", new string('3', 64));
        command.Parameters.AddWithValue("core", new string('4', 64));
        command.Parameters.AddWithValue("bound", boundAt);
        command.Parameters.AddWithValue("request_row", Guid.NewGuid());
        command.Parameters.AddWithValue("request_id", Guid.NewGuid().ToString("D"));
        command.Parameters.AddWithValue("payload", new string('5', 64));
        await command.ExecuteNonQueryAsync();
        return bindingId;
    }

    private static async Task<Guid> InsertEnrollmentAsync(
        NpgsqlConnection connection,
        int group,
        int rank,
        Guid bindingId,
        DateTimeOffset createdAt)
    {
        var enrollmentId = Guid.NewGuid();
        var enrollmentHex = enrollmentId.ToString("N");
        var enrollmentDigest = enrollmentHex + enrollmentHex;
        var productId = group == 100
            ? Guid.Parse("ffffffff-ffff-4fff-8fff-ffffffffffff")
            : Guid.Parse($"{group:x8}-1111-4111-8111-111111111111");
        await using var bindingRead = new NpgsqlCommand("""
            SELECT "InstallationId", "HandoffDigestSha256", "Version"
            FROM public."DistributionInstallationBindings" WHERE "Id" = @binding;
            """, connection);
        bindingRead.Parameters.AddWithValue("binding", bindingId);
        await using var bindingReader = await bindingRead.ExecuteReaderAsync();
        Assert.True(await bindingReader.ReadAsync());
        var installation = bindingReader.GetString(0);
        var handoff = bindingReader.GetString(1);
        var release = bindingReader.GetString(2);
        await bindingReader.CloseAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public."RuntimeEnrollments"
                ("Id", "ClientId", "BindingId", "ProductId", "LicenseId", "LicenseSeatId",
                 "InstallationId", "HardwareIdHash", "ReleaseVersion", "HandoffDigestSha256",
                 "SubjectRefDigestSha256", "ProtocolVersion", "Algorithm", "KeyBackend",
                 "AttestationLevel", "PublicKeySpkiCiphertext", "PublicKeySpkiKeyId",
                 "PublicKeySpkiKeyPurpose", "PublicKeySpkiSha256", "KeyThumbprint",
                 "ChallengeCiphertext", "ChallengeKeyId", "ChallengeKeyPurpose",
                 "ChallengeDigestSha256", "State", "Epoch", "SecurityEpoch",
                 "ChallengeExpiresAtUtc", "CreatedAtUtc", "ActivatedAtUtc",
                 "ChallengeConsumedAtUtc", "InvalidatedAtUtc", "AuthorityEpoch", "InvalidationReason")
            VALUES
                (@id, 'website-step1', @binding, @product, @license, @seat, @installation,
                 @hardware, @release, @handoff, @subject, 'runtime-enrollment-v1', 'ES256',
                 'windows-cng', 'hardware', 'ciphertext', @key_id, 'encryption', @public_hash,
                 @thumbprint, 'challenge', @challenge_key, 'encryption', @challenge_hash,
                 'ACTIVE', 1, @security, @expires, @created, @created, @created, NULL,
                 @authority, NULL);
            """, connection);
        command.Parameters.AddWithValue("id", enrollmentId);
        command.Parameters.AddWithValue("binding", bindingId);
        command.Parameters.AddWithValue("product", productId);
        command.Parameters.AddWithValue("license", Guid.Parse($"{group:x8}-2222-4222-8222-222222222222"));
        command.Parameters.AddWithValue("seat", Guid.Parse($"{group:x8}-3333-4333-8333-333333333333"));
        command.Parameters.AddWithValue("installation", installation);
        command.Parameters.AddWithValue("hardware", group == 100 ? new string('f', 64) : group.ToString("x2").PadLeft(64, 'a'));
        command.Parameters.AddWithValue("release", release);
        command.Parameters.AddWithValue("handoff", handoff);
        command.Parameters.AddWithValue("subject", rank == 1 ? new string('b', 64) : (object)DBNull.Value);
        command.Parameters.AddWithValue("key_id", enrollmentDigest);
        command.Parameters.AddWithValue("public_hash", enrollmentDigest);
        command.Parameters.AddWithValue("thumbprint", enrollmentHex + enrollmentHex[..11]);
        command.Parameters.AddWithValue("challenge_key", enrollmentDigest);
        command.Parameters.AddWithValue("challenge_hash", enrollmentDigest);
        command.Parameters.AddWithValue("security", group + rank);
        command.Parameters.AddWithValue("authority", (long)(100 + group + rank));
        command.Parameters.AddWithValue("expires", createdAt.AddHours(1));
        command.Parameters.AddWithValue("created", createdAt);
        await command.ExecuteNonQueryAsync();
        return enrollmentId;
    }

    private static async Task<string> ReadStateAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        return await ScalarAsync<string>(connection, """
            SELECT string_agg(value, E'\n' ORDER BY value)
            FROM (
                SELECT concat_ws('|', 'B', "Id"::text, "State", coalesce("InvalidationReason", '<null>')) AS value
                FROM public."DistributionInstallationBindings"
                UNION ALL
                SELECT concat_ws('|', 'E', "Id"::text, "State", "SecurityEpoch"::text,
                                 "AuthorityEpoch"::text, coalesce("InvalidationReason", '<null>')) AS value
                FROM public."RuntimeEnrollments"
            ) rows;
            """);
    }

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return (T)(await command.ExecuteScalarAsync() ?? throw new InvalidOperationException("Expected a scalar value."));
    }

    private sealed record RunResult(
        string Mode,
        string Snapshot,
        int Groups,
        int Bindings,
        int Enrollments,
        int Preserved,
        int ActiveAfter,
        int DuplicatesAfter);

    private sealed record Fixture(int ActiveBindings, Guid UnrelatedBindingId, Guid UnrelatedEnrollmentId);
    private sealed record OperatorCredentials(string Username, string Password);

    private sealed class TestDatabase : IAsyncDisposable
    {
        private readonly string _maintenanceConnectionString;
        private readonly string _databaseName;
        private string? _operatorRoleName;

        private TestDatabase(string maintenanceConnectionString, string databaseName, string connectionString)
        {
            _maintenanceConnectionString = maintenanceConnectionString;
            _databaseName = databaseName;
            ConnectionString = connectionString;
        }

        public string ConnectionString { get; }
        public string DatabaseName => _databaseName;

        public async Task<OperatorCredentials> CreateMinimalOperatorAsync()
        {
            _operatorRoleName = $"tkt000217_operator_{Guid.NewGuid():N}";
            var password = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            await using (var maintenance = new NpgsqlConnection(_maintenanceConnectionString))
            {
                await maintenance.OpenAsync();
                await using var create = new NpgsqlCommand($$"""
                    CREATE ROLE "{{_operatorRoleName}}" LOGIN PASSWORD '{{password}}'
                        NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    GRANT CONNECT, TEMPORARY ON DATABASE "{{_databaseName}}" TO "{{_operatorRoleName}}";
                    """, maintenance);
                await create.ExecuteNonQueryAsync();
            }
            await using (var target = new NpgsqlConnection(ConnectionString))
            {
                await target.OpenAsync();
                await using var grants = new NpgsqlCommand($$"""
                    GRANT USAGE ON SCHEMA public TO "{{_operatorRoleName}}";
                    GRANT SELECT, UPDATE ON public."DistributionInstallationBindings", public."RuntimeEnrollments"
                        TO "{{_operatorRoleName}}";
                    GRANT SELECT ON public."DistributionBindingRequests", public."RuntimeCriticalIncidents"
                        TO "{{_operatorRoleName}}";
                    """, target);
                await grants.ExecuteNonQueryAsync();
            }
            return new OperatorCredentials(_operatorRoleName, password);
        }

        public static async Task<TestDatabase> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
            {
                throw new InvalidOperationException("SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for PostgreSQL contract tests.");
            }
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            var databaseName = $"softlicence_tkt000217_{Guid.NewGuid():N}";
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                var serverVersion = int.Parse(
                    await ScalarAsync<string>(connection, "SHOW server_version_num;"),
                    System.Globalization.CultureInfo.InvariantCulture);
                Assert.True(serverVersion >= 170000,
                    "TKT-000217 reconciliation tests require PostgreSQL 17.");
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{databaseName}\";", connection);
                await create.ExecuteNonQueryAsync();
            }
            var target = new NpgsqlConnectionStringBuilder(configured) { Database = databaseName }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options;
            await using (var db = new LicenseDbContext(options))
            {
                await db.GetService<IMigrator>().MigrateAsync("20260802185000_PartitionAccessLogs");
            }
            return new TestDatabase(maintenance, databaseName, target);
        }

        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(_maintenanceConnectionString);
            await connection.OpenAsync();
            await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE);", connection);
            await drop.ExecuteNonQueryAsync();
            if (_operatorRoleName is not null)
            {
                await using var dropRole = new NpgsqlCommand($"DROP ROLE IF EXISTS \"{_operatorRoleName}\";", connection);
                await dropRole.ExecuteNonQueryAsync();
            }
        }
    }
}

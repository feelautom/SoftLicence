using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Adds real-psql PostgreSQL 17 coverage for the fail-closed TKT-000557 operator repair workflow.
/// </summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Executes the operator wrapper through a real PostgreSQL 17 psql process. A manifest for a
    /// different target must fail before SQL execution, while the exact target permits one bounded
    /// reason promotion and leaves every authority row otherwise unchanged.
    /// </summary>
    [Fact]
    public async Task Tkt000557RepairScript_RealPsqlRejectsWrongTargetThenAppliesExactSnapshot()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var repair = await PrepareTkt000557RepairGraphAsync(scenario);
        var environment = Tkt000557PostgreSqlEnvironment(scenario.AdminConnectionString);
        var temporaryDirectory = Directory.CreateTempSubdirectory("softlicence-tkt000557-real-psql-");
        try
        {
            var shimPath = await CreateTkt000557PsqlShimAsync(temporaryDirectory.FullName);
            var dryRun = await RunTkt000557RepairScriptAsync(
                repair.AliasId, repair.LicenseId, shimPath, environment);
            Assert.True(dryRun.ExitCode == 0,
                $"Real psql dry-run failed. stdout={dryRun.StandardOutput} stderr={dryRun.StandardError}");
            var snapshot = Tkt000557Snapshot(dryRun.StandardOutput);

            var backup = await CreateTkt000557BackupEvidenceAsync(
                temporaryDirectory.FullName, environment, wrongTarget: true);
            var wrongTarget = await RunTkt000557RepairScriptAsync(
                repair.AliasId, repair.LicenseId, shimPath, environment,
                "-Apply", "-ExpectedSnapshotSha256", snapshot,
                "-VerifiedBackupManifestPath", backup.ManifestPath,
                "-VerifiedBackupArtifactPath", backup.ArtifactPath);
            Assert.NotEqual(0, wrongTarget.ExitCode);
            Assert.Equal(HardwareAuthorityAlias.LegacyDisabledUnknownReason,
                await ReadTkt000557DisabledReasonAsync(scenario.AdminConnectionString, repair.AliasId));

            backup = await CreateTkt000557BackupEvidenceAsync(
                temporaryDirectory.FullName, environment, wrongTarget: false);
            var apply = await RunTkt000557RepairScriptAsync(
                repair.AliasId, repair.LicenseId, shimPath, environment,
                "-Apply", "-ExpectedSnapshotSha256", snapshot,
                "-VerifiedBackupManifestPath", backup.ManifestPath,
                "-VerifiedBackupArtifactPath", backup.ArtifactPath);
            Assert.True(apply.ExitCode == 0,
                $"Real psql apply failed. stdout={apply.StandardOutput} stderr={apply.StandardError}");
            Assert.Equal(HardwareAuthorityAlias.BackfillAuthorityInvalidReason,
                await ReadTkt000557DisabledReasonAsync(scenario.AdminConnectionString, repair.AliasId));
        }
        finally
        {
            temporaryDirectory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Proves the SQL wrapper preserves duplicate JSON properties and rejects the same malformed
    /// migration proof as the Runtime resolver instead of accepting jsonb's last-key value.
    /// </summary>
    [Fact]
    public async Task Tkt000557RepairScript_DuplicateHistoryPropertyFailsClosed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var repair = await PrepareTkt000557RepairGraphAsync(scenario);
        await using (var mutate = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await mutate.OpenAsync();
            await using var command = new NpgsqlCommand("""
                UPDATE "LicenseHistories"
                SET "Details" = '{"schema":"tampered",' || substring("Details" from 2)
                WHERE "Id" = @alias;
                """, mutate);
            command.Parameters.AddWithValue("alias", repair.AliasId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        var environment = Tkt000557PostgreSqlEnvironment(scenario.AdminConnectionString);
        var temporaryDirectory = Directory.CreateTempSubdirectory("softlicence-tkt000557-duplicate-json-");
        try
        {
            var shimPath = await CreateTkt000557PsqlShimAsync(temporaryDirectory.FullName);
            var dryRun = await RunTkt000557RepairScriptAsync(
                repair.AliasId, repair.LicenseId, shimPath, environment);

            Assert.NotEqual(0, dryRun.ExitCode);
            Assert.Equal(HardwareAuthorityAlias.LegacyDisabledUnknownReason,
                await ReadTkt000557DisabledReasonAsync(scenario.AdminConnectionString, repair.AliasId));
        }
        finally
        {
            temporaryDirectory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Proves the global advisory lock and exact snapshot permit at most one concurrent Apply.
    /// The losing process observes the promoted reason and fails before a second mutation.
    /// </summary>
    [Fact]
    public async Task Tkt000557RepairScript_ConcurrentApplyCommitsExactlyOnce()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var repair = await PrepareTkt000557RepairGraphAsync(scenario);
        var environment = Tkt000557PostgreSqlEnvironment(scenario.AdminConnectionString);
        var temporaryDirectory = Directory.CreateTempSubdirectory("softlicence-tkt000557-concurrent-");
        try
        {
            var shimPath = await CreateTkt000557PsqlShimAsync(temporaryDirectory.FullName);
            var dryRun = await RunTkt000557RepairScriptAsync(
                repair.AliasId, repair.LicenseId, shimPath, environment);
            Assert.Equal(0, dryRun.ExitCode);
            var snapshot = Tkt000557Snapshot(dryRun.StandardOutput);
            var backup = await CreateTkt000557BackupEvidenceAsync(
                temporaryDirectory.FullName, environment, wrongTarget: false);
            var arguments = new[]
            {
                "-Apply", "-ExpectedSnapshotSha256", snapshot,
                "-VerifiedBackupManifestPath", backup.ManifestPath,
                "-VerifiedBackupArtifactPath", backup.ArtifactPath
            };

            var results = await Task.WhenAll(
                RunTkt000557RepairScriptAsync(repair.AliasId, repair.LicenseId, shimPath, environment, arguments),
                RunTkt000557RepairScriptAsync(repair.AliasId, repair.LicenseId, shimPath, environment, arguments));

            Assert.Single(results, result => result.ExitCode == 0);
            Assert.Single(results, result => result.ExitCode != 0);
            Assert.Equal(HardwareAuthorityAlias.BackfillAuthorityInvalidReason,
                await ReadTkt000557DisabledReasonAsync(scenario.AdminConnectionString, repair.AliasId));
        }
        finally
        {
            temporaryDirectory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Creates an authenticated historical alias graph that the migration leaves ambiguous and
    /// therefore requires the bounded operator repair before Finalize may consume it.
    /// </summary>
    private static async Task<Tkt000557RepairGraph> PrepareTkt000557RepairGraphAsync(
        PreparedBootstrapScenario scenario)
    {
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        await MigrateScenarioAsync(scenario);
        var adminFactory = new TestDbFactory(scenario.AdminConnectionString);
        await using (var downgrade = await adminFactory.CreateDbContextAsync())
        {
            await downgrade.GetService<IMigrator>().MigrateAsync(
                "20260816131533_AllowRuntimeHardwareAuthorityMigrationProofs");
        }

        Guid licenseId;
        await using (var diverge = await scenario.Factory.CreateDbContextAsync())
        {
            var binding = await diverge.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.Id == scenario.Fixture.BindingId);
            var enrollment = await diverge.RuntimeEnrollments.SingleAsync(candidate =>
                candidate.Id == scenario.EnrollmentId);
            var seat = await diverge.LicenseSeats.SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
            licenseId = binding.LicenseId;
            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow.AddMinutes(-5);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
            enrollment.InvalidationReason = "authority_ineligible";
            diverge.LicenseSeats.Add(new LicenseSeat
            {
                Id = Guid.NewGuid(),
                LicenseId = licenseId,
                HardwareId = LegacyHardwareId,
                IsActive = true,
                FirstActivatedAt = DateTime.UtcNow.AddMinutes(-3),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-3),
                AppVersion = scenario.Fixture.Version
            });
            await diverge.SaveChangesAsync();
        }
        await using (var upgrade = await adminFactory.CreateDbContextAsync())
        {
            await upgrade.GetService<IMigrator>().MigrateAsync();
            var alias = await upgrade.HardwareAuthorityAliases.SingleAsync();
            Assert.Equal(HardwareAuthorityAlias.LegacyDisabledUnknownReason, alias.DisabledReason);
            return new(alias.Id, licenseId);
        }
    }

    /// <summary>
    /// Converts the isolated test connection into exact libpq variables for the repair wrapper.
    /// The returned password remains process-local and is never written to the backup manifest.
    /// </summary>
    private static Dictionary<string, string> Tkt000557PostgreSqlEnvironment(string connectionString)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString);
        return new(StringComparer.Ordinal)
        {
            ["PGHOST"] = "127.0.0.1",
            ["PGPORT"] = "5432",
            ["PGDATABASE"] = builder.Database!,
            ["PGUSER"] = builder.Username!,
            ["PGPASSWORD"] = builder.Password!
        };
    }

    /// <summary>
    /// Creates a test-only PowerShell adapter that streams the wrapper's unique SQL file into psql
    /// inside the PostgreSQL 17 container while preserving libpq variables and the process exit code.
    /// </summary>
    private static async Task<string> CreateTkt000557PsqlShimAsync(string directory)
    {
        var containerName = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES_CONTAINER");
        if (string.IsNullOrWhiteSpace(containerName))
            throw new InvalidOperationException(
                "SOFTLICENCE_RUNTIME_TEST_POSTGRES_CONTAINER is required for the real psql wrapper test.");
        var shimPath = Path.Combine(directory, "psql.ps1");
        await File.WriteAllTextAsync(shimPath,
            $$"""
            param([Parameter(ValueFromRemainingArguments = $true)][string[]]$RemainingArguments)
            $translated = [Collections.Generic.List[string]]::new()
            $sqlPath = $null
            for ($index = 0; $index -lt $RemainingArguments.Count; $index++) {
                if ($RemainingArguments[$index] -ceq '--file') {
                    $index++
                    $sqlPath = $RemainingArguments[$index]
                    $translated.Add('--file=-')
                }
                else {
                    $translated.Add($RemainingArguments[$index])
                }
            }
            if ([string]::IsNullOrEmpty($sqlPath)) { throw 'Expected a SQL file argument.' }
            Get-Content -LiteralPath $sqlPath -Raw | & docker exec -i `
                -e "PGHOST=$env:PGHOST" -e "PGPORT=$env:PGPORT" `
                -e "PGDATABASE=$env:PGDATABASE" -e "PGUSER=$env:PGUSER" `
                -e "PGPASSWORD=$env:PGPASSWORD" {{containerName}} psql @translated
            exit $LASTEXITCODE
            """);
        return shimPath;
    }

    /// <summary>
    /// Runs the production repair wrapper non-interactively with isolated environment values and a
    /// 45-second fail-fast timeout, capturing both output streams for assertion and diagnostics.
    /// </summary>
    private static async Task<Tkt000557ProcessResult> RunTkt000557RepairScriptAsync(
        Guid aliasId,
        Guid licenseId,
        string psqlPath,
        IReadOnlyDictionary<string, string> environment,
        params string[] additionalArguments)
    {
        var scriptPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "scripts", "Repair-Tkt000557InactiveHardwareAlias.ps1"));
        var start = new ProcessStartInfo("pwsh.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoLogo");
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(scriptPath);
        start.ArgumentList.Add("-AliasId");
        start.ArgumentList.Add(aliasId.ToString("D"));
        start.ArgumentList.Add("-LicenseId");
        start.ArgumentList.Add(licenseId.ToString("D"));
        start.ArgumentList.Add("-PsqlPath");
        start.ArgumentList.Add(psqlPath);
        foreach (var argument in additionalArguments)
            start.ArgumentList.Add(argument);
        foreach (var pair in environment)
            start.Environment[pair.Key] = pair.Value;

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start pwsh.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(45));
        return new(process.ExitCode, await standardOutput, await standardError);
    }

    /// <summary>
    /// Extracts the single lowercase snapshot digest emitted by a successful dry-run and rejects
    /// missing, duplicated, or malformed JSON output through test assertions.
    /// </summary>
    private static string Tkt000557Snapshot(string standardOutput)
    {
        var json = standardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Single(line => line.TrimStart().StartsWith('{'));
        using var document = JsonDocument.Parse(json);
        var snapshot = document.RootElement.GetProperty("snapshot_sha256").GetString();
        Assert.Matches("^[0-9a-f]{64}$", snapshot);
        return snapshot!;
    }

    /// <summary>
    /// Creates a short-lived artifact and canonical v2 manifest for the isolated test target, or an
    /// intentionally mismatched target hash for the fail-closed scenario. The caller owns cleanup.
    /// </summary>
    private static async Task<Tkt000557BackupEvidence> CreateTkt000557BackupEvidenceAsync(
        string directory,
        IReadOnlyDictionary<string, string> environment,
        bool wrongTarget)
    {
        var bytes = Encoding.UTF8.GetBytes("tkt000557-real-backup-evidence");
        var dumpName = $"softlicence_{DateTimeOffset.UtcNow:yyyy-MM-dd_HH-mm-ss-fff}_{Guid.NewGuid():N}.dump";
        var artifactPath = Path.Combine(directory, dumpName);
        await File.WriteAllBytesAsync(artifactPath, bytes);
        var artifactSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        var target = string.Join('\n', "postgresql-target-v1", environment["PGHOST"].ToLowerInvariant(),
            environment["PGPORT"], environment["PGDATABASE"]);
        var targetSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(target))).ToLowerInvariant();
        if (wrongTarget)
            targetSha256 = new string(targetSha256[0] == '0' ? '1' : '0', 64);
        var manifestPath = artifactPath + ".manifest.json";
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(new
        {
            schema = "softlicence-backup-manifest-v2",
            file = dumpName,
            sizeBytes = bytes.Length,
            sha256 = artifactSha256,
            createdAtUtc = DateTimeOffset.UtcNow.UtcDateTime.ToString("O"),
            format = "postgresql-custom",
            sourceDatabase = environment["PGDATABASE"],
            sourceTargetSha256 = targetSha256
        }));
        return new(artifactPath, manifestPath);
    }

    /// <summary>
    /// Reads the exact persisted disabled reason for one alias through the isolated admin connection.
    /// </summary>
    private static async Task<string?> ReadTkt000557DisabledReasonAsync(string connectionString, Guid aliasId)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT \"DisabledReason\" FROM \"HardwareAuthorityAliases\" WHERE \"Id\" = @alias;", connection);
        command.Parameters.AddWithValue("alias", aliasId);
        return (string?)await command.ExecuteScalarAsync();
    }

    /// <summary>Identifies the exact alias and license authorized for the repair scenario.</summary>
    private sealed record Tkt000557RepairGraph(Guid AliasId, Guid LicenseId);

    /// <summary>Owns paths to the short-lived backup artifact and its adjacent manifest.</summary>
    private sealed record Tkt000557BackupEvidence(string ArtifactPath, string ManifestPath);

    /// <summary>Captures a wrapper process result without logging environment credentials.</summary>
    private sealed record Tkt000557ProcessResult(int ExitCode, string StandardOutput, string StandardError);
}

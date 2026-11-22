using System.Data.Common;
using System.Runtime.ExceptionServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class ApprovedBinariesPostgreSqlTests
{
    [Fact]
    public async Task Registration_ReplayConflictsAndReadback_AreStableOnPostgreSql()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = await SeedProductAsync(provision.ConnectionString, "primary");
        var otherProductId = await SeedProductAsync(provision.ConnectionString, "other");
        var service = CreateService(provision.ConnectionString);
        var artifacts = Artifacts('A', 'B', 'C');

        var uppercaseManifest = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.39", "manifest-uppercase", Hash('D'), artifacts);
        var paddedManifest = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.39", "manifest-padded", $" {Hash('d')} ", artifacts);

        var created = await service.RegisterReleaseBaselineAsync(
            productId, " 2.3.40 ", "Release/2.3.40#A", Hash('d'), artifacts);
        var replay = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "Release/2.3.40#A", Hash('d'), artifacts);
        var changedBody = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "Release/2.3.40#A", Hash('d'), Artifacts('F', 'B', 'C'));
        var changedManifest = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "Release/2.3.40#A", Hash('e'), artifacts);
        var changedProduct = await service.RegisterReleaseBaselineAsync(
            otherProductId, "2.3.40", "Release/2.3.40#A", Hash('d'), artifacts);
        var changedVersion = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.41", "Release/2.3.40#A", Hash('d'), artifacts);
        var differentKey = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.40", "release/2.3.40#A", Hash('d'), artifacts);
        var caseDistinctKey = await service.RegisterReleaseBaselineAsync(
            otherProductId, "2.3.41", "release/2.3.40#A", Hash('d'), artifacts);
        var maximumLengthKey = await service.RegisterReleaseBaselineAsync(
            productId, "2.3.42", new string('x', 128), Hash('d'), artifacts);
        var readback = await service.GetAuthoritativeBaselineAsync(productId, "2.3.40");

        Assert.Equal("invalid_manifest_digest", uppercaseManifest.Result.ErrorCode);
        Assert.Equal("invalid_manifest_digest", paddedManifest.Result.ErrorCode);
        Assert.False(created.Result.Idempotent);
        Assert.True(replay.Result.Idempotent);
        Assert.Equal(created.Result.BaselineId, replay.Result.BaselineId);
        Assert.Equal(created.Result.BaselineId, readback.Result.BaselineId);
        Assert.Equal("Release/2.3.40#A", readback.Result.RegistrationId);
        Assert.Equal(Hash('d'), readback.Result.ManifestDigestSha256);
        Assert.Equal(ApprovedBinaryService.ReleaseSource, readback.Result.Source);
        Assert.Equal(["FP_EXE", "FP_DLL", "FP_CORE"], readback.Result.Artifacts.Select(a => a.Key));
        Assert.All(readback.Result.Artifacts, artifact => Assert.Equal(artifact.Sha256.ToLowerInvariant(), artifact.Sha256));
        Assert.Equal("registration_id_conflict", changedBody.Result.ErrorCode);
        Assert.Equal("registration_id_conflict", changedManifest.Result.ErrorCode);
        Assert.Equal("registration_id_conflict", changedProduct.Result.ErrorCode);
        Assert.Equal("registration_id_conflict", changedVersion.Result.ErrorCode);
        Assert.Equal("baseline_registration_conflict", differentKey.Result.ErrorCode);
        Assert.Equal(ApprovedBinaryVerdict.Approved, caseDistinctKey.Result.Verdict);
        Assert.Equal(ApprovedBinaryVerdict.Approved, maximumLengthKey.Result.Verdict);

        await using var db = CreateDb(provision.ConnectionString);
        Assert.Equal(3, await db.ApprovedBinaryRegistrations.CountAsync());
        Assert.Equal(9, await db.ApprovedBinaries.CountAsync());
    }

    [Fact]
    public async Task ConcurrentIdenticalAndDivergentRegistrations_HaveOneFrozenWinner()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = await SeedProductAsync(provision.ConnectionString, "concurrent-identical");
        var service = CreateService(provision.ConnectionString);
        var identical = Enumerable.Range(0, 2).Select(_ => service.RegisterReleaseBaselineAsync(
            productId, "2.3.41", "concurrent-identical", Hash('d'), Artifacts('a', 'b', 'c')));

        var identicalResults = await Task.WhenAll(identical);

        Assert.Single(identicalResults, result => !result.Result.Idempotent);
        Assert.Single(identicalResults, result => result.Result.Idempotent);
        Assert.Single(identicalResults.Select(result => result.Result.BaselineId).Distinct());

        var divergentProductId = await SeedProductAsync(provision.ConnectionString, "concurrent-divergent");
        var first = service.RegisterReleaseBaselineAsync(
            divergentProductId, "2.3.42", "divergent-a", Hash('d'), Artifacts('1', '2', '3'));
        var second = service.RegisterReleaseBaselineAsync(
            divergentProductId, "2.3.42", "divergent-b", Hash('e'), Artifacts('4', '5', '6'));
        var divergentResults = await Task.WhenAll(first, second);

        Assert.Single(divergentResults, result => result.Result.Verdict == ApprovedBinaryVerdict.Approved);
        Assert.Single(divergentResults, result => result.Result.ErrorCode == "baseline_registration_conflict");
        await using var db = CreateDb(provision.ConnectionString);
        Assert.Equal(2, await db.ApprovedBinaryRegistrations.CountAsync());
        Assert.Equal(6, await db.ApprovedBinaries.CountAsync());
    }

    /// <summary>
    /// Proves that a winner committed after each pre-write lookup is classified from its exact key
    /// and content rather than from the loser's stale Read Committed snapshot.
    /// </summary>
    /// <param name="pausePoint">The completed losing query after which the winner is committed.</param>
    [Theory]
    [InlineData(RegistrationReadPausePoint.AfterKeyLookup)]
    [InlineData(RegistrationReadPausePoint.AfterVersionLookup)]
    [InlineData(RegistrationReadPausePoint.AfterArtifactLookup)]
    public async Task ConcurrentRegistration_WhenWinnerCommitsBetweenReads_ClassifiesVisibleWinner(
        RegistrationReadPausePoint pausePoint)
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();

        var identical = await ExecuteRegistrationInterleavingAsync(
            provision.ConnectionString,
            pausePoint,
            "identical",
            winnerRegistrationId: "deterministic-identical",
            loserRegistrationId: "deterministic-identical",
            winnerManifest: Hash('a'),
            loserManifest: Hash('a'),
            winnerArtifacts: Artifacts('1', '2', '3'),
            loserArtifacts: Artifacts('1', '2', '3'));
        Assert.Equal(ApprovedBinaryVerdict.Approved, identical.Loser.Verdict);
        Assert.True(identical.Loser.Idempotent);
        Assert.Equal(identical.Winner.BaselineId, identical.Loser.BaselineId);

        var sameKeyDivergent = await ExecuteRegistrationInterleavingAsync(
            provision.ConnectionString,
            pausePoint,
            "same-key-divergent",
            winnerRegistrationId: "deterministic-same-key",
            loserRegistrationId: "deterministic-same-key",
            winnerManifest: Hash('b'),
            loserManifest: Hash('c'),
            winnerArtifacts: Artifacts('4', '5', '6'),
            loserArtifacts: Artifacts('7', '8', '9'));
        Assert.Equal("registration_id_conflict", sameKeyDivergent.Loser.ErrorCode);

        var differentKey = await ExecuteRegistrationInterleavingAsync(
            provision.ConnectionString,
            pausePoint,
            "different-key",
            winnerRegistrationId: "deterministic-winner",
            loserRegistrationId: "deterministic-loser",
            winnerManifest: Hash('d'),
            loserManifest: Hash('e'),
            winnerArtifacts: Artifacts('a', 'b', 'c'),
            loserArtifacts: Artifacts('d', 'e', 'f'));
        Assert.Equal("baseline_registration_conflict", differentKey.Loser.ErrorCode);

        var sameKeyDifferentProduct = await ExecuteRegistrationInterleavingAsync(
            provision.ConnectionString,
            pausePoint,
            "same-key-different-product",
            winnerRegistrationId: "deterministic-cross-product-key",
            loserRegistrationId: "deterministic-cross-product-key",
            winnerManifest: Hash('f'),
            loserManifest: Hash('f'),
            winnerArtifacts: Artifacts('1', '3', '5'),
            loserArtifacts: Artifacts('1', '3', '5'),
            winnerUsesDifferentProduct: true);
        Assert.Equal("registration_id_conflict", sameKeyDifferentProduct.Loser.ErrorCode);
    }

    /// <summary>
    /// Proves that release rows with no owning registration remain classified as non-authoritative
    /// after the concurrent-winner recheck. This preserves the historical-data safety boundary while
    /// allowing a newly committed aggregate owner to receive the stable registration-conflict result.
    /// </summary>
    [Fact]
    public async Task ReleaseRowsWithoutRegistration_RemainNonAuthoritative()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = await SeedProductAsync(provision.ConnectionString, "orphaned-release-rows");
        await SeedHistoricalBaselineAsync(
            provision.ConnectionString,
            productId,
            "2.3.42",
            ApprovedBinaryService.ReleaseSource,
            'a');
        var service = CreateService(provision.ConnectionString);

        var result = await service.RegisterReleaseBaselineAsync(
            productId,
            "2.3.42",
            "orphaned-release-registration",
            Hash('d'),
            Artifacts('d', 'e', 'f'));

        Assert.True(result.ProductExists);
        Assert.Equal("baseline_not_authoritative", result.Result.ErrorCode);
        await using var db = CreateDb(provision.ConnectionString);
        Assert.Empty(await db.ApprovedBinaryRegistrations.ToListAsync());
        Assert.Equal(3, await db.ApprovedBinaries.CountAsync());
    }

    [Fact]
    public async Task LegacyTiaConnect2362Adoption_IsSerializableAndLeavesOneExactAggregate()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = ApprovedBinaryService.TiaConnectLegacyAdoptionProductId;
        await SeedProductAsync(provision.ConnectionString, "tia-legacy", productId);
        await SeedHistoricalBaselineAsync(
            provision.ConnectionString, productId, "2.3.62", ApprovedBinaryService.ReleaseSource, 'a');
        List<object> metadataBefore;
        await using (var beforeDb = CreateDb(provision.ConnectionString))
            metadataBefore = await LoadLegacyMetadataAsync(beforeDb, productId);
        var service = CreateService(provision.ConnectionString);
        var artifacts = Artifacts('a', 'b', 'c');

        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ =>
            service.AdoptTiaConnect2362LegacyBaselineAsync(
                productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), artifacts)));

        Assert.All(results, result => Assert.Equal(ApprovedBinaryVerdict.Approved, result.Result.Verdict));
        Assert.Single(results, result => !result.Result.Idempotent);
        Assert.Single(results, result => result.Result.Idempotent);
        Assert.Single(results.Select(result => result.Result.BaselineId).Distinct());

        await using var db = CreateDb(provision.ConnectionString);
        Assert.Single(await db.ApprovedBinaryRegistrations.ToListAsync());
        var rows = await db.ApprovedBinaries.Where(row => row.ProductId == productId && row.Version == "2.3.62").ToListAsync();
        Assert.Equal(3, rows.Count);
        Assert.All(rows, row => Assert.Equal(results[0].Result.BaselineId, row.ApprovedBinaryRegistrationId));
        Assert.Equal(artifacts.OrderBy(item => item.Key).Select(item => item.Sha256), rows.OrderBy(row => row.Key).Select(row => row.Hash));
        Assert.Equal(metadataBefore, await LoadLegacyMetadataAsync(db, productId));
    }

    [Fact]
    public async Task LegacyTiaConnect2362Adoption_DivergentRelationalState_RollsBackWithoutMetadataMutation()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = ApprovedBinaryService.TiaConnectLegacyAdoptionProductId;
        await SeedProductAsync(provision.ConnectionString, "tia-legacy-adversarial", productId);
        await SeedHistoricalBaselineAsync(
            provision.ConnectionString, productId, "2.3.62", ApprovedBinaryService.ReleaseSource, 'a');

        await using (var mutationDb = CreateDb(provision.ConnectionString))
        {
            var mixedRow = await mutationDb.ApprovedBinaries.SingleAsync(row =>
                row.ProductId == productId && row.Version == "2.3.62" && row.Key == "FP_DLL");
            mixedRow.Source = ApprovedBinaryService.AdminSource;
            await mutationDb.SaveChangesAsync();
        }
        List<object> mixedBefore;
        await using (var beforeDb = CreateDb(provision.ConnectionString))
            mixedBefore = await LoadLegacyMetadataAsync(beforeDb, productId);

        var service = CreateService(provision.ConnectionString);
        var mixedResult = await service.AdoptTiaConnect2362LegacyBaselineAsync(
            productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), Artifacts('a', 'b', 'c'));

        Assert.Equal("legacy_baseline_not_adoptable", mixedResult.Result.ErrorCode);
        await using (var mixedVerification = CreateDb(provision.ConnectionString))
        {
            Assert.Empty(await mixedVerification.ApprovedBinaryRegistrations.ToListAsync());
            Assert.All(await mixedVerification.ApprovedBinaries.Where(row => row.ProductId == productId).ToListAsync(),
                row => Assert.Null(row.ApprovedBinaryRegistrationId));
            Assert.Equal(mixedBefore, await LoadLegacyMetadataAsync(mixedVerification, productId));
        }

        await using (var repairDb = CreateDb(provision.ConnectionString))
        {
            var mixedRow = await repairDb.ApprovedBinaries.SingleAsync(row =>
                row.ProductId == productId && row.Version == "2.3.62" && row.Key == "FP_DLL");
            mixedRow.Source = ApprovedBinaryService.ReleaseSource;
            await repairDb.SaveChangesAsync();
        }
        List<object> mismatchBefore;
        await using (var beforeDb = CreateDb(provision.ConnectionString))
            mismatchBefore = await LoadLegacyMetadataAsync(beforeDb, productId);

        var mismatchResult = await service.AdoptTiaConnect2362LegacyBaselineAsync(
            productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), Artifacts('f', 'b', 'c'));

        Assert.Equal("legacy_baseline_mismatch", mismatchResult.Result.ErrorCode);
        await using var mismatchVerification = CreateDb(provision.ConnectionString);
        Assert.Empty(await mismatchVerification.ApprovedBinaryRegistrations.ToListAsync());
        Assert.All(await mismatchVerification.ApprovedBinaries.Where(row => row.ProductId == productId).ToListAsync(),
            row => Assert.Null(row.ApprovedBinaryRegistrationId));
        Assert.Equal(mismatchBefore, await LoadLegacyMetadataAsync(mismatchVerification, productId));
    }

    [Fact]
    public async Task HistoricalPublishAndLocalTestRows_SurviveMigrationButRemainNonAuthoritative()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync(
            "20260803223205_AddSameAuthorityInstallationRecovery");
        var productId = await SeedProductAsync(provision.ConnectionString, "historical-sources");
        await SeedHistoricalBaselineAsync(provision.ConnectionString, productId, "2.3.38", "publish", '1');
        await SeedHistoricalBaselineAsync(provision.ConnectionString, productId, "2.3.39", "local-test", '4');

        await using (var migrationDb = CreateDb(provision.ConnectionString))
            await migrationDb.Database.MigrateAsync();

        await using (var verificationDb = CreateDb(provision.ConnectionString))
        {
            var rows = await verificationDb.ApprovedBinaries
                .OrderBy(row => row.Version)
                .ThenBy(row => row.Key)
                .ToListAsync();
            Assert.Equal(6, rows.Count);
            Assert.Equal(3, rows.Count(row => row.Source == "publish"));
            Assert.Equal(3, rows.Count(row => row.Source == "local-test"));
            Assert.All(rows, row => Assert.Null(row.ApprovedBinaryRegistrationId));
            Assert.Empty(await verificationDb.ApprovedBinaryRegistrations.ToListAsync());
        }

        var service = CreateService(provision.ConnectionString);
        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.38")).Result.ErrorCode);
        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.39")).Result.ErrorCode);
    }

    [Fact]
    public async Task SourceConstraintsCanonicalizationAndLookupPlan_AreRelationallyEnforced()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var productId = await SeedProductAsync(provision.ConnectionString, "constraints");
        var service = CreateService(provision.ConnectionString);
        await service.RegisterReleaseBaselineAsync(
            productId, "2.3.43+RC", "CaseSensitive", Hash('a'), Artifacts('A', 'B', 'C'));

        await using (var seed = CreateDb(provision.ConnectionString))
        {
            seed.ApprovedBinaries.AddRange(Artifacts('1', '2', '3').Select(artifact => new ApprovedBinary
            {
                ProductId = productId,
                Version = "2.3.44",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = ApprovedBinaryService.AdminSource,
                ApprovedBy = "admin"
            }));
            seed.ApprovedBinaries.AddRange(Artifacts('4', '5', '6').Select((artifact, index) => new ApprovedBinary
            {
                ProductId = productId,
                Version = "2.3.45",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = index == 0 ? ApprovedBinaryService.ReleaseSource : ApprovedBinaryService.AdminSource,
                ApprovedBy = "admin"
            }));
            await seed.SaveChangesAsync();
        }

        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.44")).Result.ErrorCode);
        Assert.Equal("baseline_source_conflict",
            (await service.GetAuthoritativeBaselineAsync(productId, "2.3.45")).Result.ErrorCode);

        Assert.False(ApprovedBinaryService.IsValidRegistrationKey(" CaseSensitive"));
        Assert.False(ApprovedBinaryService.IsValidRegistrationKey("CaseSensitive "));
        Assert.True(ApprovedBinaryService.IsValidRegistrationKey(new string('x', 128)));
        Assert.False(ApprovedBinaryService.IsValidRegistrationKey(new string('x', 129)));

        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaryRegistrations\" SET \"Source\"='admin'");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaryRegistrations\" SET \"ManifestDigestSha256\"=upper(\"ManifestDigestSha256\")");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Hash\"=upper(\"Hash\")");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Key\"=lower(\"Key\")");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Version\"=' invalid'");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Source\"='admin'");
        await AssertCheckViolationAsync(connection,
            "UPDATE \"ApprovedBinaries\" SET \"Source\"='unknown' WHERE \"ApprovedBinaryRegistrationId\" IS NULL");

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SET enable_seqscan=off; EXPLAIN (FORMAT TEXT) SELECT * FROM \"ApprovedBinaryRegistrations\" WHERE \"ProductId\"=@productId AND \"Version\"=@version";
            command.Parameters.AddWithValue("productId", productId);
            command.Parameters.AddWithValue("version", "2.3.43+RC");
            await using var reader = await command.ExecuteReaderAsync();
            var plan = new List<string>();
            while (await reader.ReadAsync())
                plan.Add(reader.GetString(0));
            Assert.Contains(plan, line => line.Contains(
                "IX_ApprovedBinaryRegistrations_ProductId_Version", StringComparison.Ordinal));
        }

        await using var db = CreateDb(provision.ConnectionString);
        var registrationSql = db.ApprovedBinaryRegistrations
            .Where(row => row.ProductId == productId && row.Version == "2.3.43+RC")
            .ToQueryString();
        Assert.DoesNotContain("lower(", registrationSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("upper(", registrationSql, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task AssertCheckViolationAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, exception.SqlState);
    }

    /// <summary>
    /// Runs one losing registration against a deliberately committed winner at an exact query
    /// boundary. Every exit releases, cancels if needed, and boundedly drains the loser while
    /// preserving any earlier setup, winner, assertion, or loser exception as the primary failure.
    /// </summary>
    /// <param name="connectionString">PostgreSQL connection string for the isolated test database.</param>
    /// <param name="pausePoint">Losing registration query that must complete before the winner commits.</param>
    /// <param name="suffix">Unique product-name suffix for the scenario.</param>
    /// <param name="winnerRegistrationId">Registration key committed by the winning service.</param>
    /// <param name="loserRegistrationId">Registration key submitted by the paused losing service.</param>
    /// <param name="winnerManifest">Canonical manifest digest committed by the winner.</param>
    /// <param name="loserManifest">Canonical manifest digest submitted by the loser.</param>
    /// <param name="winnerArtifacts">Canonical artifact set committed by the winner.</param>
    /// <param name="loserArtifacts">Canonical artifact set submitted by the loser.</param>
    /// <param name="winnerUsesDifferentProduct">
    /// Whether the winner owns another product while deliberately colliding on the global key.
    /// </param>
    /// <returns>The approved winner and the loser's final classification.</returns>
    private static async Task<(ApprovedBinaryVerificationResult Winner, ApprovedBinaryVerificationResult Loser)>
        ExecuteRegistrationInterleavingAsync(
            string connectionString,
            RegistrationReadPausePoint pausePoint,
            string suffix,
            string winnerRegistrationId,
            string loserRegistrationId,
            string winnerManifest,
            string loserManifest,
            IReadOnlyCollection<ApprovedBinaryArtifact> winnerArtifacts,
            IReadOnlyCollection<ApprovedBinaryArtifact> loserArtifacts,
            bool winnerUsesDifferentProduct = false)
    {
        var productId = await SeedProductAsync(connectionString, $"deterministic-{suffix}");
        var winnerProductId = winnerUsesDifferentProduct
            ? await SeedProductAsync(connectionString, $"deterministic-winner-{suffix}")
            : productId;
        var interceptor = new RegistrationReadPauseInterceptor(pausePoint);
        var pausedService = new ApprovedBinaryService(
            new InterceptingTestDbContextFactory(connectionString, interceptor),
            NullLogger<ApprovedBinaryService>.Instance);
        var winnerService = CreateService(connectionString);
        using var loserCancellation = new CancellationTokenSource();
        var loserTask = pausedService.RegisterReleaseBaselineAsync(
            productId,
            "2.3.46",
            loserRegistrationId,
            loserManifest,
            loserArtifacts,
            loserCancellation.Token);
        Exception? primaryException = null;

        try
        {
            var pausedCommand = await interceptor.WaitUntilPausedAsync();
            AssertPausedCommand(pausePoint, pausedCommand);
            var winner = await winnerService.RegisterReleaseBaselineAsync(
                winnerProductId,
                "2.3.46",
                winnerRegistrationId,
                winnerManifest,
                winnerArtifacts);
            Assert.Equal(ApprovedBinaryVerdict.Approved, winner.Result.Verdict);
            Assert.False(winner.Result.Idempotent);
            interceptor.Resume();
            var loser = await loserTask.WaitAsync(TimeSpan.FromSeconds(10));
            return (winner.Result, loser.Result);
        }
        catch (Exception exception)
        {
            primaryException = exception;
            throw;
        }
        finally
        {
            interceptor.Resume();
            Exception? cleanupException = null;
            if (!loserTask.IsCompleted)
            {
                try
                {
                    loserCancellation.Cancel();
                }
                catch (Exception exception)
                {
                    cleanupException = exception;
                }
            }

            try
            {
                await loserTask.WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (TimeoutException timeoutException)
            {
                // WaitAsync does not stop its underlying task. Observe any later fault so the
                // timed-out loser cannot surface an unobserved exception after fixture disposal.
                _ = loserTask.ContinueWith(
                    static faultedTask =>
                    {
                        _ = faultedTask.Exception;
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
                var drainTimeoutException = new TimeoutException(
                    "The losing registration task could not be drained within the 10-second timeout.",
                    timeoutException);
                cleanupException = cleanupException == null
                    ? drainTimeoutException
                    : new AggregateException(
                        drainTimeoutException.Message,
                        cleanupException,
                        drainTimeoutException);
            }
            catch (Exception drainException)
            {
                cleanupException = cleanupException == null
                    ? drainException
                    : new AggregateException("Loser cancellation and bounded drain both failed.", cleanupException, drainException);
            }

            if (cleanupException != null && !ReferenceEquals(primaryException, cleanupException))
            {
                if (primaryException != null)
                {
                    // Preserve the primary failure while retaining cleanup diagnostics for debuggers
                    // and test reporters that inspect Exception.Data.
                    primaryException.Data["LoserTaskCleanupException"] = cleanupException;
                }
                else
                {
                    ExceptionDispatchInfo.Capture(cleanupException).Throw();
                }
            }
        }
    }

    /// <summary>
    /// Verifies that the deterministic pause captured the intended SQL statement rather than an
    /// earlier query whose included navigation happens to mention the same tables.
    /// </summary>
    /// <param name="pausePoint">Expected pre-write query boundary.</param>
    /// <param name="command">Exact SQL and parameter names captured by the interceptor.</param>
    private static void AssertPausedCommand(
        RegistrationReadPausePoint pausePoint,
        PausedCommandSnapshot command)
    {
        var diagnostic = $"Paused SQL:{Environment.NewLine}{command.CommandText}{Environment.NewLine}" +
            $"Parameters: {string.Join(", ", command.ParameterNames)}";
        Assert.True(
            command.CommandText.Contains("SELECT", StringComparison.Ordinal),
            diagnostic);

        switch (pausePoint)
        {
            case RegistrationReadPausePoint.AfterKeyLookup:
                Assert.True(
                    command.CommandText.Contains("\"ApprovedBinaryRegistrations\"", StringComparison.Ordinal),
                    diagnostic);
                Assert.True(
                    command.ParameterNames.Any(name =>
                        name.Contains("registrationId", StringComparison.OrdinalIgnoreCase)),
                    diagnostic);
                break;
            case RegistrationReadPausePoint.AfterVersionLookup:
                Assert.True(
                    command.CommandText.Contains("\"ApprovedBinaryRegistrations\"", StringComparison.Ordinal),
                    diagnostic);
                Assert.True(
                    command.ParameterNames.Any(name =>
                        name.Contains("productId", StringComparison.OrdinalIgnoreCase)),
                    diagnostic);
                Assert.True(
                    command.ParameterNames.Any(name =>
                        name.Contains("version", StringComparison.OrdinalIgnoreCase)),
                    diagnostic);
                break;
            case RegistrationReadPausePoint.AfterArtifactLookup:
                Assert.True(command.CommandText.Contains("EXISTS", StringComparison.Ordinal), diagnostic);
                Assert.True(
                    command.CommandText.Contains("\"ApprovedBinaries\"", StringComparison.Ordinal),
                    diagnostic);
                Assert.False(
                    command.CommandText.Contains("\"ApprovedBinaryRegistrations\"", StringComparison.Ordinal),
                    diagnostic);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(pausePoint), pausePoint, null);
        }
    }

    private static ApprovedBinaryService CreateService(string connectionString) => new(
        new TestDbContextFactory(connectionString),
        NullLogger<ApprovedBinaryService>.Instance);

    private static LicenseDbContext CreateDb(string connectionString) => new(
        new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options);

    private static async Task<Guid> SeedProductAsync(string connectionString, string suffix, Guid? productId = null)
    {
        await using var db = CreateDb(connectionString);
        var product = new Product
        {
            Id = productId ?? Guid.NewGuid(),
            Name = $"ApprovedBinaries-{suffix}-{Guid.NewGuid():N}",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = Guid.NewGuid().ToString("N")
        };
        db.Products.Add(product);
        await db.SaveChangesAsync();
        return product.Id;
    }

    private static async Task SeedHistoricalBaselineAsync(
        string connectionString,
        Guid productId,
        string version,
        string source,
        char firstHashCharacter)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        for (var index = 0; index < 3; index++)
        {
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                INSERT INTO "ApprovedBinaries"
                    ("Id", "ProductId", "Version", "Key", "Hash", "ApprovedAt", "Source", "ApprovedBy")
                VALUES
                    (@id, @productId, @version, @key, @hash, @approvedAt, @source, @approvedBy)
                """;
            command.Parameters.AddWithValue("id", Guid.NewGuid());
            command.Parameters.AddWithValue("productId", productId);
            command.Parameters.AddWithValue("version", version);
            command.Parameters.AddWithValue("key", new[] { "FP_EXE", "FP_DLL", "FP_CORE" }[index]);
            command.Parameters.AddWithValue("hash", Hash((char)(firstHashCharacter + index)));
            command.Parameters.AddWithValue("approvedAt", DateTime.UtcNow);
            command.Parameters.AddWithValue("source", source);
            command.Parameters.AddWithValue("approvedBy", "historical-test");
            await command.ExecuteNonQueryAsync();
        }
    }

    private static List<ApprovedBinaryArtifact> Artifacts(char exe, char dll, char core) =>
    [
        new("FP_CORE", Hash(core)),
        new("FP_EXE", Hash(exe)),
        new("FP_DLL", Hash(dll))
    ];

    private static string Hash(char value) => new(value, 64);

    private static async Task<List<object>> LoadLegacyMetadataAsync(LicenseDbContext db, Guid productId) =>
        (await db.ApprovedBinaries.AsNoTracking()
            .Where(row => row.ProductId == productId && row.Version == "2.3.62")
            .OrderBy(row => row.Key)
            .Select(row => new
            {
                row.Id,
                row.Key,
                row.Hash,
                row.Source,
                row.ApprovedAt,
                row.ApprovedBy
            })
            .ToListAsync())
        .Cast<object>()
        .ToList();

    private sealed class TestDbContextFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connectionString).Options;

        public LicenseDbContext CreateDbContext() => new(_options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>
    /// Creates PostgreSQL contexts with the deterministic command interceptor used by one losing
    /// registration. The interceptor is scoped to this factory and never affects the winner.
    /// </summary>
    private sealed class InterceptingTestDbContextFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options;

        /// <summary>
        /// Builds immutable PostgreSQL options containing the scenario-specific interceptor.
        /// </summary>
        /// <param name="connectionString">Connection string for the isolated PostgreSQL database.</param>
        /// <param name="interceptor">Interceptor that pauses one selected registration query.</param>
        public InterceptingTestDbContextFactory(
            string connectionString,
            RegistrationReadPauseInterceptor interceptor)
        {
            _options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseNpgsql(connectionString)
                .AddInterceptors(interceptor)
                .Options;
        }

        /// <summary>
        /// Creates one context that participates in the deterministic losing-registration schedule.
        /// </summary>
        /// <returns>A new license database context.</returns>
        public LicenseDbContext CreateDbContext() => new(_options);

        /// <summary>
        /// Creates one context asynchronously without performing additional I/O during construction.
        /// </summary>
        /// <param name="cancellationToken">Unused construction token retained by the factory contract.</param>
        /// <returns>A completed task containing a new license database context.</returns>
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>
    /// Identifies the completed Read Committed pre-write query after which the test commits the
    /// competing winner.
    /// </summary>
    public enum RegistrationReadPausePoint
    {
        /// <summary>
        /// Pauses after the global registration-key lookup has fixed an empty statement snapshot.
        /// </summary>
        AfterKeyLookup,

        /// <summary>
        /// Pauses after the product/version lookup has fixed an empty statement snapshot.
        /// </summary>
        AfterVersionLookup,

        /// <summary>
        /// Pauses after the target version's release-artifact lookup has fixed an empty snapshot.
        /// </summary>
        AfterArtifactLookup
    }

    /// <summary>
    /// Immutable evidence for the exact PostgreSQL command selected by the pause interceptor.
    /// </summary>
    /// <param name="CommandText">Exact SQL text executed by PostgreSQL.</param>
    /// <param name="ParameterNames">Exact parameter names supplied by EF Core.</param>
    private sealed record PausedCommandSnapshot(
        string CommandText,
        IReadOnlyList<string> ParameterNames);

    /// <summary>
    /// Pauses exactly one selected pre-write query after PostgreSQL has fixed its statement
    /// snapshot but before EF consumes the reader, allowing the winner to commit deterministically.
    /// </summary>
    /// <param name="pausePoint">Pre-write query boundary selected by the theory row.</param>
    private sealed class RegistrationReadPauseInterceptor(RegistrationReadPausePoint pausePoint)
        : DbCommandInterceptor
    {
        /// <summary>
        /// Signals that the selected statement has executed and its PostgreSQL snapshot is fixed.
        /// </summary>
        private readonly TaskCompletionSource<PausedCommandSnapshot> _paused =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>
        /// Releases the open reader after the competing winner has committed or setup has failed.
        /// </summary>
        private readonly TaskCompletionSource _resume = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>
        /// Prevents a later matching query from introducing a second pause in the same scenario.
        /// </summary>
        private int _hasPaused;

        /// <summary>
        /// Waits until PostgreSQL has executed the selected losing query and its snapshot is fixed.
        /// </summary>
        /// <returns>
        /// A task containing the exact selected command, or one that fails quickly if the expected
        /// EF query shape is no longer observed.
        /// </returns>
        public Task<PausedCommandSnapshot> WaitUntilPausedAsync() =>
            _paused.Task.WaitAsync(TimeSpan.FromSeconds(10));

        /// <summary>
        /// Releases the intercepted reader. Repeated calls are safe so failure cleanup cannot leave
        /// the losing database operation blocked.
        /// </summary>
        public void Resume() => _resume.TrySetResult();

        /// <summary>
        /// Preserves the executed reader while suspending EF at the selected pre-write lookup.
        /// </summary>
        /// <param name="command">Executed PostgreSQL command.</param>
        /// <param name="eventData">EF command metadata.</param>
        /// <param name="result">Open reader whose statement snapshot is already fixed.</param>
        /// <param name="cancellationToken">Cancellation token for the losing registration.</param>
        /// <returns>The original reader after the test releases the pause.</returns>
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            DbDataReader result,
            CancellationToken cancellationToken = default)
        {
            if (ShouldPause(command) && Interlocked.CompareExchange(ref _hasPaused, 1, 0) == 0)
            {
                _paused.TrySetResult(new PausedCommandSnapshot(
                    command.CommandText,
                    command.Parameters
                        .Cast<DbParameter>()
                        .Select(parameter => parameter.ParameterName)
                        .ToArray()));
                await _resume.Task.WaitAsync(cancellationToken);
            }

            return result;
        }

        /// <summary>
        /// Matches only the requested pre-write lookup by table and parameter identity, excluding
        /// the product-existence query and every non-selected read.
        /// </summary>
        /// <param name="command">Executed EF command to classify.</param>
        /// <returns><see langword="true"/> only for the scenario's selected lookup.</returns>
        private bool ShouldPause(DbCommand command)
        {
            var parameterNames = command.Parameters
                .Cast<DbParameter>()
                .Select(parameter => parameter.ParameterName)
                .ToList();
            return pausePoint switch
            {
                RegistrationReadPausePoint.AfterKeyLookup =>
                    command.CommandText.Contains("\"ApprovedBinaryRegistrations\"", StringComparison.Ordinal)
                    && parameterNames.Any(name =>
                        name.Contains("registrationId", StringComparison.OrdinalIgnoreCase)),
                RegistrationReadPausePoint.AfterVersionLookup =>
                    command.CommandText.Contains("\"ApprovedBinaryRegistrations\"", StringComparison.Ordinal)
                    && parameterNames.Any(name => name.Contains("productId", StringComparison.OrdinalIgnoreCase))
                    && parameterNames.Any(name => name.Contains("version", StringComparison.OrdinalIgnoreCase)),
                RegistrationReadPausePoint.AfterArtifactLookup =>
                    command.CommandText.Contains("EXISTS", StringComparison.Ordinal)
                    && command.CommandText.Contains("\"ApprovedBinaries\"", StringComparison.Ordinal)
                    && !command.CommandText.Contains("\"ApprovedBinaryRegistrations\"", StringComparison.Ordinal)
                    && parameterNames.Any(name => name.Contains("productId", StringComparison.OrdinalIgnoreCase))
                    && parameterNames.Any(name => name.Contains("version", StringComparison.OrdinalIgnoreCase)),
                _ => false
            };
        }
    }

    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;

        public static async Task<PostgreSqlProvision> CreateAsync(string? targetMigration = null)
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("approved", targetMigration);
            return new PostgreSqlProvision(
                clone.MaintenanceConnectionString,
                clone.ConnectionString,
                clone.DatabaseName);
        }

        public async ValueTask DisposeAsync() => await DropDatabaseAsync(maintenanceConnectionString, database);

        private static async Task DropDatabaseAsync(string maintenanceConnectionString, string database)
            => await PostgreSqlModelDatabase.DropAsync(maintenanceConnectionString, database);
    }
}

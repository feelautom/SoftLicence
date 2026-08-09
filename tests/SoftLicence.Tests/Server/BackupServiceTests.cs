using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class BackupServiceTests
{
    [Fact]
    public void BackupSource_UsesCompressedCustomStreamingAndSafeProcessArguments()
    {
        var source = File.ReadAllText(SourcePath("BackupService.cs"));

        Assert.Contains("\"--format\", \"custom\"", source, StringComparison.Ordinal);
        Assert.Contains("rcat", source, StringComparison.Ordinal);
        Assert.Contains("pg_restore", source, StringComparison.Ordinal);
        Assert.Contains("PGPASSWORD", source, StringComparison.Ordinal);
        Assert.DoesNotContain("-F p", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Path.GetTempPath(), backupName", source, StringComparison.Ordinal);
        Assert.DoesNotContain("builder.Password}", source, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("softlicence_2026-07-29_00-00.sql", "psql")]
    [InlineData("softlicence_2026-07-29_00-00.dump", "pg_restore")]
    [InlineData("softlicence_2026-07-29_00-00.backup", "pg_restore")]
    public void RestoreTool_IsBackwardCompatible(string fileName, string expectedTool)
    {
        var method = typeof(BackupService).GetMethod(
            "GetRestoreTool", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        Assert.Equal(expectedTool, method.Invoke(null, [fileName]));
    }

    [Fact]
    public void RestoreTool_RejectsUnknownFormat()
    {
        var method = typeof(BackupService).GetMethod(
            "GetRestoreTool", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        var error = Assert.Throws<System.Reflection.TargetInvocationException>(
            () => method.Invoke(null, ["backup.zip"]));
        Assert.IsType<ArgumentException>(error.InnerException);
    }

    [Fact]
    public void RestoreArguments_StopOnFirstError()
    {
        var service = CreateService(new ControlledBackupRunner());
        var psql = InvokeArguments(service, "BuildPsqlRestoreArguments", "broken.sql");
        var pgRestore = InvokeArguments(service, "BuildRestoreArguments", "broken.dump");

        Assert.Contains("ON_ERROR_STOP=1", psql);
        Assert.Contains("--exit-on-error", pgRestore);
    }

    [Fact]
    public async Task RestoreProcessFailure_IsFailClosed()
    {
        var service = CreateService(new FailingRestoreRunner());
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.RestoreDatabaseAsync("broken.sql"));
        Assert.Equal("database_restore_failed", error.Message);
    }

    [Fact]
    public async Task ConcurrentBackups_AreSerializedAndUseDistinctRemoteObjects()
    {
        var runner = new ControlledBackupRunner();
        var service = CreateService(runner);
        var first = service.BackupDatabaseAsync();
        await runner.FirstPipeStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = service.BackupDatabaseAsync();
        await Task.Delay(150);
        Assert.Equal(1, runner.PipeCalls);

        runner.ReleaseFirstPipe.TrySetResult();
        await Task.WhenAll(first, second);

        Assert.Equal(2, runner.PipeCalls);
        Assert.Equal(1, runner.MaximumConcurrentPipes);
        Assert.Equal(2, runner.PartialTargets.Distinct(StringComparer.Ordinal).Count());
        Assert.All(runner.PartialTargets, target => Assert.Contains(".partial-", target, StringComparison.Ordinal));
        Assert.Equal(2, runner.FinalTargets.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task FailedRemoteHash_CleansPartialFinalAndManifestArtifacts()
    {
        var runner = new HashMismatchRunner();
        var service = CreateService(runner);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.BackupDatabaseAsync());

        Assert.Contains(runner.DeletedTargets, target => target.Contains(".partial-", StringComparison.Ordinal));
        Assert.Contains(runner.DeletedTargets, target => target.EndsWith(".dump", StringComparison.Ordinal));
        Assert.Contains(runner.DeletedTargets, target => target.EndsWith(".manifest.json", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Retry_CleansFailedAttemptBeforeUsingNewPartialObject()
    {
        var runner = new FirstHashMismatchRunner();
        var service = CreateService(runner, retryCount: 2);
        await service.BackupDatabaseAsync();

        Assert.Equal(2, runner.PartialTargets.Count);
        Assert.Equal(2, runner.PartialTargets.Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(runner.DeletedTargets, target => target == runner.PartialTargets[0]);
    }

    [Fact]
    public async Task CryptRemoteHash_RequiresPlaintextDownloadWithExactArgumentOrder()
    {
        var runner = new DownloadOnlyHashRunner(DownloadOnlyHashRunner.ExpectedHash);
        var service = CreateService(runner);

        await service.BackupDatabaseAsync();

        Assert.Equal(
            ["hashsum", "SHA-256", "--download", runner.HashedRemoteFile],
            runner.HashArguments);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-sha256  backup.dump")]
    [InlineData("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  backup.dump")]
    public async Task RemoteHash_InvalidEmptyOrMismatchedOutput_FailsClosed(string output)
    {
        var service = CreateService(new DownloadOnlyHashRunner(output));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => service.BackupDatabaseAsync());

        Assert.Equal("database_backup_failed", error.Message);
    }

    [Fact]
    public async Task Cleanup_DeleteFailure_IsLoggedAndRemainingArtifactsAreAttempted()
    {
        var runner = new DeleteFailureRunner();
        var logger = new Mock<ILogger<BackupService>>();
        var service = CreateService(runner, logger: logger.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.BackupDatabaseAsync());

        Assert.Equal(4, runner.DeleteAttempts.Count);
        logger.Verify(value => value.Log(
            LogLevel.Warning,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((state, _) => state.ToString()!.Contains("incomplet", StringComparison.OrdinalIgnoreCase)
                && state.ToString()!.Contains("17", StringComparison.Ordinal)),
            It.IsAny<Exception?>(),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task PipelineFailure_LogsOnlyAllowlistedMetadataAndPreservesTypedDiagnostics()
    {
        const string sensitiveDiagnostic = "password=synthetic-secret host=private-db remote=private:path";
        var logger = new Mock<ILogger<BackupService>>();
        var service = CreateService(new DiagnosticFailureRunner(sensitiveDiagnostic), logger: logger.Object);

        var error = await Assert.ThrowsAsync<BackupPipelineException>(() => service.BackupDatabaseAsync());

        Assert.Equal("database_backup_failed", error.Message);
        Assert.Equal("consumer", error.FailureStage);
        Assert.Equal(0, error.ProducerExitCode);
        Assert.Equal(9, error.ConsumerExitCode);
        Assert.Equal(456, error.BytesTransferred);
        Assert.Equal(789, error.DurationMilliseconds);
        Assert.Equal(1, error.Attempt);

        logger.Verify(value => value.Log(
            LogLevel.Error,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((state, _) =>
                state.ToString()!.Contains("FailureStage=consumer", StringComparison.Ordinal)
                && state.ToString()!.Contains("ProducerExitCode=0", StringComparison.Ordinal)
                && state.ToString()!.Contains("ConsumerExitCode=9", StringComparison.Ordinal)
                && state.ToString()!.Contains("BytesTransferred=456", StringComparison.Ordinal)
                && state.ToString()!.Contains("DurationMilliseconds=789", StringComparison.Ordinal)
                && !state.ToString()!.Contains(sensitiveDiagnostic, StringComparison.Ordinal)
                && !state.ToString()!.Contains("synthetic-secret", StringComparison.Ordinal)
                && !state.ToString()!.Contains("424242", StringComparison.Ordinal)
                && !state.ToString()!.Contains("434343", StringComparison.Ordinal)),
            null,
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
    }

    [Fact]
    public async Task LegacyPipelineFailureWithoutStage_UsesClosedCopyFallback()
    {
        var service = CreateService(new LegacyPipelineFailureRunner());

        var error = await Assert.ThrowsAsync<BackupPipelineException>(() => service.BackupDatabaseAsync());

        Assert.Equal("copy", error.FailureStage);
        Assert.Equal("database_backup_failed", error.Message);
    }

    [Fact]
    public async Task PipelineTimeout_RetriesConfiguredNumberOfAttempts()
    {
        var runner = new TimeoutPipelineRunner();
        var service = CreateService(runner, retryCount: 2);

        var error = await Assert.ThrowsAsync<BackupPipelineException>(() => service.BackupDatabaseAsync());

        Assert.Equal(2, runner.PipeCalls);
        Assert.Equal(2, error.Attempt);
        Assert.Equal("timeout", error.FailureStage);
    }

    [Fact]
    public async Task CallerCancellation_DoesNotRetryPipeline()
    {
        using var cancellation = new CancellationTokenSource();
        var runner = new CancelingPipelineRunner(cancellation);
        var service = CreateService(runner, retryCount: 3);

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.BackupDatabaseAsync(cancellation.Token));

        Assert.Equal(1, runner.PipeCalls);
        Assert.Equal(cancellation.Token, error.CancellationToken);
    }

    [Fact]
    public async Task ListBackups_RequiresValidManifestForManagedDumpAndPreservesLegacyFormats()
    {
        var runner = new ListingRunner();
        var service = CreateService(runner);

        var backups = await service.ListBackupsAsync();
        var names = backups.Select(value => value.Name).ToList();

        Assert.Contains(ListingRunner.ValidManagedDump, names);
        Assert.DoesNotContain(ListingRunner.MissingManifestDump, names);
        Assert.DoesNotContain(ListingRunner.InvalidManifestDump, names);
        Assert.DoesNotContain(ListingRunner.WrongSizeManifestDump, names);
        Assert.Contains("softlicence_2026-07-29_09-00.sql", names);
        Assert.Contains("legacy-manual.dump", names);
        Assert.Contains("legacy-manual.backup", names);
        Assert.DoesNotContain(names, value => value.Contains(".partial-", StringComparison.Ordinal));
        Assert.DoesNotContain(names, value => value.EndsWith(".manifest.json", StringComparison.Ordinal));
    }

    private static BackupService CreateService(
        IBackupProcessRunner runner,
        int retryCount = 1,
        ILogger<BackupService>? logger = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["ConnectionStrings:DefaultConnection"] = "Host=localhost;Database=test;Username=test;Password=test",
            ["BackupSettings:Enabled"] = "true",
            ["BackupSettings:RcloneRemote"] = "local:",
            ["BackupSettings:DatabaseBackupPath"] = "Backups/Database",
            ["BackupSettings:MinimumFreeSpaceBytes"] = "0",
            ["BackupSettings:RetryCount"] = retryCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options;
        var factory = new Mock<IDbContextFactory<LicenseDbContext>>();
        factory.Setup(value => value.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(options));
        var settings = new SettingsService(factory.Object, configuration, NullLogger<SettingsService>.Instance);
        return new BackupService(configuration, logger ?? NullLogger<BackupService>.Instance, settings, runner, TimeProvider.System);
    }

    private static IReadOnlyList<string> InvokeArguments(BackupService service, string methodName, string path)
    {
        var method = typeof(BackupService).GetMethod(methodName,
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        return Assert.IsAssignableFrom<IReadOnlyList<string>>(method.Invoke(service, [path]));
    }

    private sealed class ControlledBackupRunner : IBackupProcessRunner
    {
        private const string Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private int _activePipes;
        private int _maximumConcurrentPipes;
        private int _pipeCalls;

        public TaskCompletionSource FirstPipeStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirstPipe { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<string> PartialTargets { get; } = [];
        public List<string> FinalTargets { get; } = [];
        public int PipeCalls => Volatile.Read(ref _pipeCalls);
        public int MaximumConcurrentPipes => Volatile.Read(ref _maximumConcurrentPipes);

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (process.Arguments.Count > 0 && process.Arguments[0] == "size")
                return Task.FromResult(new BackupProcessResult(0, "{\"count\":1,\"bytes\":123}", ""));
            if (process.Arguments.Count > 0 && process.Arguments[0] == "hashsum")
                return Task.FromResult(new BackupProcessResult(0, Hash + "  backup.dump", ""));
            if (process.Arguments.Count > 0 && process.Arguments[0] == "moveto"
                && !process.Arguments[2].EndsWith(".manifest.json", StringComparison.Ordinal))
                FinalTargets.Add(process.Arguments[2]);
            return Task.FromResult(new BackupProcessResult(0, "", ""));
        }

        public async Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _pipeCalls);
            var active = Interlocked.Increment(ref _activePipes);
            UpdateMaximum(active);
            PartialTargets.Add(consumer.Arguments[1]);
            try
            {
                if (call == 1)
                {
                    FirstPipeStarted.TrySetResult();
                    await ReleaseFirstPipe.Task.WaitAsync(cancellationToken);
                }
                return new BackupProcessResult(0, "", "", 123, Hash);
            }
            finally
            {
                Interlocked.Decrement(ref _activePipes);
            }
        }

        private void UpdateMaximum(int value)
        {
            while (true)
            {
                var current = Volatile.Read(ref _maximumConcurrentPipes);
                if (current >= value || Interlocked.CompareExchange(ref _maximumConcurrentPipes, value, current) == current)
                    return;
            }
        }
    }

    private sealed class FailingRestoreRunner : IBackupProcessRunner
    {
        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(3, "", "intentional restore failure"));

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class HashMismatchRunner : IBackupProcessRunner
    {
        public List<string> DeletedTargets { get; } = [];

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (process.Arguments[0] == "size")
                return Task.FromResult(new BackupProcessResult(0, "{\"count\":1,\"bytes\":123}", ""));
            if (process.Arguments[0] == "hashsum")
                return Task.FromResult(new BackupProcessResult(0, new string('b', 64) + "  backup.dump", ""));
            if (process.Arguments[0] == "deletefile")
                DeletedTargets.Add(process.Arguments[1]);
            return Task.FromResult(new BackupProcessResult(0, "", ""));
        }

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(0, "", "", 123,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    private sealed class FirstHashMismatchRunner : IBackupProcessRunner
    {
        private const string ExpectedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private int _hashCalls;
        public List<string> PartialTargets { get; } = [];
        public List<string> DeletedTargets { get; } = [];

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (process.Arguments[0] == "size")
                return Task.FromResult(new BackupProcessResult(0, "{\"count\":1,\"bytes\":123}", ""));
            if (process.Arguments[0] == "hashsum")
            {
                var hash = Interlocked.Increment(ref _hashCalls) == 1 ? new string('b', 64) : ExpectedHash;
                return Task.FromResult(new BackupProcessResult(0, hash + "  backup.dump", ""));
            }
            if (process.Arguments[0] == "deletefile") DeletedTargets.Add(process.Arguments[1]);
            return Task.FromResult(new BackupProcessResult(0, "", ""));
        }

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            PartialTargets.Add(consumer.Arguments[1]);
            return Task.FromResult(new BackupProcessResult(0, "", "", 123, ExpectedHash));
        }
    }

    private sealed class DownloadOnlyHashRunner(string hashOutput) : IBackupProcessRunner
    {
        public const string ExpectedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        public IReadOnlyList<string> HashArguments { get; private set; } = [];
        public string HashedRemoteFile { get; private set; } = string.Empty;

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (process.Arguments[0] == "size")
                return Task.FromResult(new BackupProcessResult(0, "{\"count\":1,\"bytes\":123}", ""));
            if (process.Arguments[0] == "hashsum")
            {
                HashArguments = process.Arguments;
                HashedRemoteFile = process.Arguments[^1];
                var exactDownloadCommand = process.Arguments.Count == 4
                    && process.Arguments[1] == "SHA-256"
                    && process.Arguments[2] == "--download";
                return Task.FromResult(new BackupProcessResult(0, exactDownloadCommand ? hashOutput : string.Empty, ""));
            }
            return Task.FromResult(new BackupProcessResult(0, "", ""));
        }

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(0, "", "", 123, ExpectedHash));
    }

    private sealed class DeleteFailureRunner : IBackupProcessRunner
    {
        public List<string> DeleteAttempts { get; } = [];

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (process.Arguments[0] == "size")
                return Task.FromResult(new BackupProcessResult(0, "{\"count\":1,\"bytes\":123}", ""));
            if (process.Arguments[0] == "hashsum")
                return Task.FromResult(new BackupProcessResult(0, "", ""));
            if (process.Arguments[0] == "deletefile")
            {
                DeleteAttempts.Add(process.Arguments[1]);
                return Task.FromResult(new BackupProcessResult(17, "", "intentional delete failure"));
            }
            return Task.FromResult(new BackupProcessResult(0, "", ""));
        }

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(0, "", "", 123, DownloadOnlyHashRunner.ExpectedHash));
    }

    private sealed class DiagnosticFailureRunner(string standardError) : IBackupProcessRunner
    {
        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(4, string.Empty, string.Empty));

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(
                9,
                string.Empty,
                standardError,
                456,
                null,
                0,
                9,
                BackupPipelineFailureStage.Consumer,
                789,
                ProducerProcessId: 424242,
                ConsumerProcessId: 434343));
    }

    private sealed class LegacyPipelineFailureRunner : IBackupProcessRunner
    {
        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(0, string.Empty, string.Empty));

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(7, string.Empty, "synthetic-sensitive-stderr"));
    }

    private sealed class TimeoutPipelineRunner : IBackupProcessRunner
    {
        private int _pipeCalls;
        public int PipeCalls => _pipeCalls;

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(0, string.Empty, string.Empty));

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _pipeCalls);
            return Task.FromResult(new BackupProcessResult(
                -1,
                string.Empty,
                string.Empty,
                FailureStage: BackupPipelineFailureStage.Timeout));
        }
    }

    private sealed class CancelingPipelineRunner(CancellationTokenSource cancellation) : IBackupProcessRunner
    {
        private int _pipeCalls;
        private readonly BackupProcessRunner _runner = CreateRunnerWithCleanupAction(cancellation.Cancel);
        public int PipeCalls => _pipeCalls;

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new BackupProcessResult(0, string.Empty, string.Empty));

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _pipeCalls);
            var helper = Path.Combine(AppContext.BaseDirectory, "BackupProcessHelper.dll");
            return _runner.PipeAsync(
                new BackupProcessSpec("dotnet", [helper, "sleep-producer", "5000"]),
                new BackupProcessSpec("dotnet", [helper, "sleep-consumer", "5000"]),
                TimeSpan.FromMilliseconds(100),
                cancellationToken);
        }

        private static BackupProcessRunner CreateRunnerWithCleanupAction(Action cleanupAction) =>
            Assert.IsType<BackupProcessRunner>(Activator.CreateInstance(
                typeof(BackupProcessRunner),
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                binder: null,
                args: [cleanupAction],
                culture: null));
    }

    private sealed class ListingRunner : IBackupProcessRunner
    {
        private const string Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        public const string ValidManagedDump = "softlicence_2026-07-29_10-00-00-000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dump";
        public const string MissingManifestDump = "softlicence_2026-07-29_10-01-00-000_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.dump";
        public const string InvalidManifestDump = "softlicence_2026-07-29_10-02-00-000_cccccccccccccccccccccccccccccccc.dump";
        public const string WrongSizeManifestDump = "softlicence_2026-07-29_10-03-00-000_dddddddddddddddddddddddddddddddd.dump";

        public Task<BackupProcessResult> RunAsync(BackupProcessSpec process, ReadOnlyMemory<byte>? standardInput,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (process.Arguments[0] == "lsf")
            {
                var lines = new[]
                {
                    $"Backups/Database/{ValidManagedDump}|123|2026-07-29 10:00:00",
                    $"Backups/Database/{ValidManagedDump}.manifest.json|240|2026-07-29 10:00:01",
                    $"Backups/Database/{MissingManifestDump}|123|2026-07-29 10:01:00",
                    $"Backups/Database/{InvalidManifestDump}|123|2026-07-29 10:02:00",
                    $"Backups/Database/{InvalidManifestDump}.manifest.json|20|2026-07-29 10:02:01",
                    $"Backups/Database/{WrongSizeManifestDump}|123|2026-07-29 10:03:00",
                    $"Backups/Database/{WrongSizeManifestDump}.manifest.json|240|2026-07-29 10:03:01",
                    $"Backups/Database/{ValidManagedDump}.partial-deadbeef|50|2026-07-29 10:03:00",
                    "Backups/Database/softlicence_2026-07-29_09-00.sql|500|2026-07-29 09:00:00",
                    "Backups/Database/legacy-manual.dump|600|2026-07-28 09:00:00",
                    "Backups/Database/legacy-manual.backup|700|2026-07-27 09:00:00"
                };
                return Task.FromResult(new BackupProcessResult(0, string.Join('\n', lines), ""));
            }
            if (process.Arguments[0] == "cat")
            {
                var path = process.Arguments[1];
                if (path.EndsWith(ValidManagedDump + ".manifest.json", StringComparison.Ordinal))
                {
                    var json = $$"""{"schema":"softlicence-backup-manifest-v1","file":"{{ValidManagedDump}}","sizeBytes":123,"sha256":"{{Hash}}","createdAtUtc":"2026-07-29T10:00:00Z","format":"postgresql-custom"}""";
                    return Task.FromResult(new BackupProcessResult(0, json, ""));
                }
                if (path.EndsWith(WrongSizeManifestDump + ".manifest.json", StringComparison.Ordinal))
                {
                    var json = $$"""{"schema":"softlicence-backup-manifest-v1","file":"{{WrongSizeManifestDump}}","sizeBytes":122,"sha256":"{{Hash}}","createdAtUtc":"2026-07-29T10:03:00Z","format":"postgresql-custom"}""";
                    return Task.FromResult(new BackupProcessResult(0, json, ""));
                }
                return Task.FromResult(new BackupProcessResult(0, "{\"schema\":", ""));
            }
            return Task.FromResult(new BackupProcessResult(0, "", ""));
        }

        public Task<BackupProcessResult> PipeAsync(BackupProcessSpec producer, BackupProcessSpec consumer,
            TimeSpan timeout, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private static string SourcePath(string fileName) => Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..",
        "src", "SoftLicence.Server", "Services", fileName);
}

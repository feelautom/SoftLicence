using System.Security.Cryptography;
using System.Diagnostics;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class BackupProcessRunnerTests
{
    private const int MultiBufferBytes = 1024 * 1024 + 777;
    private readonly BackupProcessRunner _runner = new();

    [Fact]
    public async Task PipeAsync_SuccessfulMultiBufferFlow_ReturnsExactBytesAndHash()
    {
        var result = await _runner.PipeAsync(
            Helper("produce", MultiBufferBytes, 0),
            Helper("consume", 0),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(0, result.ProducerExitCode);
        Assert.Equal(0, result.ConsumerExitCode);
        Assert.Equal(BackupPipelineFailureStage.None, result.FailureStage);
        Assert.Equal(MultiBufferBytes, result.BytesTransferred);
        Assert.Equal(ExpectedHash(MultiBufferBytes), result.Sha256);
        Assert.True(result.DurationMilliseconds >= 0);
    }

    [Fact]
    public async Task PipeAsync_ProducerFailure_IdentifiesProducer()
    {
        var result = await _runner.PipeAsync(
            Helper("produce", 0, 17),
            Helper("consume", 0),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(17, result.ProducerExitCode);
        Assert.Equal(0, result.ConsumerExitCode);
        Assert.Equal(BackupPipelineFailureStage.Producer, result.FailureStage);
    }

    [Fact]
    public async Task PipeAsync_ConsumerFailureAfterEof_IdentifiesConsumer()
    {
        var result = await _runner.PipeAsync(
            Helper("produce", 4096, 0),
            Helper("consume", 19),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(0, result.ProducerExitCode);
        Assert.Equal(19, result.ConsumerExitCode);
        Assert.Equal(BackupPipelineFailureStage.Consumer, result.FailureStage);
    }

    [Fact]
    public async Task PipeAsync_DoubleFailure_IdentifiesBothProcesses()
    {
        var result = await _runner.PipeAsync(
            Helper("produce", 0, 17),
            Helper("consume", 19),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(17, result.ProducerExitCode);
        Assert.Equal(19, result.ConsumerExitCode);
        Assert.Equal(BackupPipelineFailureStage.Both, result.FailureStage);
    }

    [Fact]
    public async Task PipeAsync_ConsumerClosesEarly_IdentifiesConsumerWithoutThrowingDetails()
    {
        var producerPidFile = NewPidFile();
        var consumerPidFile = NewPidFile();
        var result = await _runner.PipeAsync(
            HelperRaw("produce", (8 * 1024 * 1024).ToString(System.Globalization.CultureInfo.InvariantCulture), "0", producerPidFile),
            HelperRaw("consume-early", "200000", "23", consumerPidFile),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(BackupPipelineFailureStage.Consumer, result.FailureStage);
        Assert.Equal(23, result.ConsumerExitCode);
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(result.BytesTransferred > 0);
        Assert.True(result.BytesTransferred < 8 * 1024 * 1024);
        Assert.True(result.DiagnosticDrainsObserved);
        await AssertProcessExitedAsync(await ReadPidAsync(producerPidFile));
        await AssertProcessExitedAsync(await ReadPidAsync(consumerPidFile));
    }

    [Fact]
    public async Task PipeAsync_ConsumerClosesPipeBeforeDelayedExit_PreservesConsumerIdentityWithoutKillCode()
    {
        var producerPidFile = NewPidFile();
        var consumerPidFile = NewPidFile();
        var result = await _runner.PipeAsync(
            HelperRaw("produce", "8388608", "0", producerPidFile),
            HelperRaw("consume-close-delay", "1", "1000", "29", consumerPidFile),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(BackupPipelineFailureStage.Consumer, result.FailureStage);
        Assert.Null(result.ConsumerExitCode);
        Assert.Equal(-1, result.ExitCode);
        Assert.Empty(result.StandardOutput);
        Assert.Empty(result.StandardError);
        Assert.True(result.DiagnosticDrainsObserved);
        await AssertProcessExitedAsync(await ReadPidAsync(producerPidFile));
        await AssertProcessExitedAsync(await ReadPidAsync(consumerPidFile));
    }

    [Fact]
    public async Task PipeAsync_ProducerStartFailure_ReturnsSafeClosedStage()
    {
        var result = await _runner.PipeAsync(
            MissingExecutable(),
            Helper("consume", 0),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(BackupPipelineFailureStage.ProducerStart, result.FailureStage);
        Assert.Equal("producer_start", result.FailureStage.ToDiagnosticCode());
        Assert.Equal(-1, result.ExitCode);
        Assert.Empty(result.StandardOutput);
        Assert.Empty(result.StandardError);
        Assert.True(result.DiagnosticDrainsObserved);
    }

    [Fact]
    public async Task PipeAsync_ConsumerStartFailure_TerminatesStartedProducer()
    {
        var result = await _runner.PipeAsync(
            Helper("sleep-producer", 5000),
            MissingExecutable(),
            TimeSpan.FromSeconds(20),
            default);

        Assert.Equal(BackupPipelineFailureStage.ConsumerStart, result.FailureStage);
        Assert.Equal("consumer_start", result.FailureStage.ToDiagnosticCode());
        Assert.Empty(result.StandardOutput);
        Assert.Empty(result.StandardError);
        Assert.True(result.DiagnosticDrainsObserved);
        Assert.NotNull(result.ProducerProcessId);
        await AssertProcessExitedAsync(result.ProducerProcessId.Value);
    }

    [Fact]
    public async Task PipeAsync_InternalDeadline_ReturnsCanonicalTimeoutStage()
    {
        var producerPidFile = NewPidFile();
        var consumerPidFile = NewPidFile();
        var result = await _runner.PipeAsync(
            HelperRaw("sleep-producer", "5000", producerPidFile),
            HelperRaw("sleep-consumer", "5000", consumerPidFile),
            TimeSpan.FromMilliseconds(100),
            default);

        Assert.Equal(BackupPipelineFailureStage.Timeout, result.FailureStage);
        Assert.Equal("timeout", result.FailureStage.ToDiagnosticCode());
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(result.DiagnosticDrainsObserved);
        await AssertProcessExitedAsync(await ReadPidAsync(producerPidFile));
        await AssertProcessExitedAsync(await ReadPidAsync(consumerPidFile));
    }

    [Fact]
    public async Task PipeAsync_CallerCancellation_RemainsCancellation()
    {
        var producerPidFile = NewPidFile();
        var consumerPidFile = NewPidFile();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _runner.PipeAsync(
            HelperRaw("sleep-producer", "5000", producerPidFile),
            HelperRaw("sleep-consumer", "5000", consumerPidFile),
            TimeSpan.FromSeconds(20),
            cancellation.Token));

        Assert.Equal(cancellation.Token, error.CancellationToken);
        await AssertProcessExitedAsync(await ReadPidAsync(producerPidFile));
        await AssertProcessExitedAsync(await ReadPidAsync(consumerPidFile));
    }

    [Fact]
    public async Task PipeAsync_CallerCancellationDuringTimeoutCleanup_WinsOverTimeoutResult()
    {
        using var cancellation = new CancellationTokenSource();
        var runner = CreateRunnerWithCleanupAction(cancellation.Cancel);
        var producerPidFile = NewPidFile();
        var consumerPidFile = NewPidFile();

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runner.PipeAsync(
            HelperRaw("sleep-producer", "5000", producerPidFile),
            HelperRaw("sleep-consumer", "5000", consumerPidFile),
            TimeSpan.FromMilliseconds(100),
            cancellation.Token));

        Assert.Equal(cancellation.Token, error.CancellationToken);
        await AssertProcessExitedAsync(await ReadPidAsync(producerPidFile));
        await AssertProcessExitedAsync(await ReadPidAsync(consumerPidFile));
    }

    [Fact]
    public async Task PipeAsync_CallerCancellationDuringCopyCleanup_WinsOverConsumerFailure()
    {
        using var cancellation = new CancellationTokenSource();
        var runner = CreateRunnerWithCleanupAction(cancellation.Cancel);
        var producerPidFile = NewPidFile();
        var consumerPidFile = NewPidFile();

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runner.PipeAsync(
            HelperRaw("produce", "8388608", "0", producerPidFile),
            HelperRaw("consume-close-delay", "1", "1000", "31", consumerPidFile),
            TimeSpan.FromSeconds(20),
            cancellation.Token));

        Assert.Equal(cancellation.Token, error.CancellationToken);
        await AssertProcessExitedAsync(await ReadPidAsync(producerPidFile));
        await AssertProcessExitedAsync(await ReadPidAsync(consumerPidFile));
    }

    private static BackupProcessSpec Helper(string operation, params int[] arguments) => new(
        "dotnet",
        [HelperAssemblyPath, operation, .. arguments.Select(value => value.ToString(System.Globalization.CultureInfo.InvariantCulture))]);

    private static BackupProcessSpec HelperRaw(string operation, params string[] arguments) => new(
        "dotnet",
        [HelperAssemblyPath, operation, .. arguments]);

    private static BackupProcessSpec MissingExecutable() => new(
        $"softlicence-missing-{Guid.NewGuid():N}",
        []);

    private static BackupProcessRunner CreateRunnerWithCleanupAction(Action cleanupAction) =>
        Assert.IsType<BackupProcessRunner>(Activator.CreateInstance(
            typeof(BackupProcessRunner),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
            binder: null,
            args: [cleanupAction],
            culture: null));

    private static string HelperAssemblyPath => Path.Combine(AppContext.BaseDirectory, "BackupProcessHelper.dll");

    private static string ExpectedHash(int byteCount)
    {
        var bytes = new byte[byteCount];
        for (var index = 0; index < bytes.Length; index++)
            bytes[index] = (byte)(index % 251);
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    private static string NewPidFile() =>
        Path.Combine(Path.GetTempPath(), $"softlicence-backup-pid-{Guid.NewGuid():N}.txt");

    private static async Task<int> ReadPidAsync(string path)
    {
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (!File.Exists(path) && DateTime.UtcNow < deadline)
            await Task.Delay(20);
        Assert.True(File.Exists(path), "The subprocess did not publish its PID before cleanup.");
        try
        {
            return int.Parse(await File.ReadAllTextAsync(path), System.Globalization.CultureInfo.InvariantCulture);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static async Task AssertProcessExitedAsync(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            if (!process.HasExited)
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
            Assert.True(process.HasExited);
        }
        catch (ArgumentException)
        {
            // The process no longer exists.
        }
    }
}

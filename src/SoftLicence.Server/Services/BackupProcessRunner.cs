using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SoftLicence.Server.Services;

public sealed record BackupProcessSpec(
    string FileName,
    IReadOnlyList<string> Arguments,
    IReadOnlyDictionary<string, string>? Environment = null);

public sealed record BackupProcessResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    long BytesTransferred = 0,
    string? Sha256 = null,
    int? ProducerExitCode = null,
    int? ConsumerExitCode = null,
    BackupPipelineFailureStage FailureStage = BackupPipelineFailureStage.None,
    long DurationMilliseconds = 0,
    bool DiagnosticDrainsObserved = true,
    int? ProducerProcessId = null,
    int? ConsumerProcessId = null);

public enum BackupPipelineFailureStage
{
    None,
    ProducerStart,
    ConsumerStart,
    Producer,
    Consumer,
    Both,
    Copy,
    Timeout
}

public static class BackupPipelineFailureStageExtensions
{
    public static string ToDiagnosticCode(this BackupPipelineFailureStage stage) => stage switch
    {
        BackupPipelineFailureStage.None => "none",
        BackupPipelineFailureStage.ProducerStart => "producer_start",
        BackupPipelineFailureStage.ConsumerStart => "consumer_start",
        BackupPipelineFailureStage.Producer => "producer",
        BackupPipelineFailureStage.Consumer => "consumer",
        BackupPipelineFailureStage.Both => "both",
        BackupPipelineFailureStage.Copy => "copy",
        BackupPipelineFailureStage.Timeout => "timeout",
        _ => throw new ArgumentOutOfRangeException(nameof(stage), stage, "Unknown backup pipeline failure stage.")
    };
}

public interface IBackupProcessRunner
{
    Task<BackupProcessResult> RunAsync(
        BackupProcessSpec process,
        ReadOnlyMemory<byte>? standardInput,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task<BackupProcessResult> PipeAsync(
        BackupProcessSpec producer,
        BackupProcessSpec consumer,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

public sealed class BackupProcessRunner : IBackupProcessRunner
{
    private const int MaximumDiagnosticCharacters = 64 * 1024;
    private static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(3);
    private readonly Action? _cleanupStartedForTests;

    public BackupProcessRunner()
    {
    }

    internal BackupProcessRunner(Action cleanupStartedForTests)
    {
        _cleanupStartedForTests = cleanupStartedForTests;
    }

    public async Task<BackupProcessResult> RunAsync(
        BackupProcessSpec process,
        ReadOnlyMemory<byte>? standardInput,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        using var instance = Start(process, redirectInput: standardInput.HasValue, redirectOutput: true);
        try
        {
            var outputTask = ReadBoundedAsync(instance.StandardOutput, timeoutSource.Token);
            var errorTask = ReadBoundedAsync(instance.StandardError, timeoutSource.Token);
            if (standardInput.HasValue)
            {
                await instance.StandardInput.BaseStream.WriteAsync(standardInput.Value, timeoutSource.Token);
                await instance.StandardInput.BaseStream.FlushAsync(timeoutSource.Token);
                instance.StandardInput.Close();
            }
            await instance.WaitForExitAsync(timeoutSource.Token);
            return new(instance.ExitCode, await outputTask, await errorTask);
        }
        catch
        {
            Kill(instance);
            throw;
        }
    }

    public async Task<BackupProcessResult> PipeAsync(
        BackupProcessSpec producer,
        BackupProcessSpec consumer,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        Process? producerProcess = null;
        Process? consumerProcess = null;
        Task<string>? producerErrorTask = null;
        Task<string>? consumerErrorTask = null;
        Task<string>? consumerOutputTask = null;
        long bytesTransferred = 0;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                producerProcess = Start(producer, redirectInput: false, redirectOutput: true);
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (timeoutSource.IsCancellationRequested)
                    return CreateFailureResult(
                        BackupPipelineFailureStage.Timeout,
                        stopwatch.ElapsedMilliseconds,
                        bytesTransferred);
                return CreateFailureResult(
                    BackupPipelineFailureStage.ProducerStart,
                    stopwatch.ElapsedMilliseconds,
                    bytesTransferred);
            }

            producerErrorTask = StartObservedDrain(producerProcess.StandardError);
            timeoutSource.Token.ThrowIfCancellationRequested();
            try
            {
                consumerProcess = Start(consumer, redirectInput: true, redirectOutput: true);
            }
            catch (Exception)
            {
                var cleanup = await CleanupAsync(producerProcess, null, [producerErrorTask]);
                cancellationToken.ThrowIfCancellationRequested();
                if (timeoutSource.IsCancellationRequested)
                    return CreateFailureResult(
                        BackupPipelineFailureStage.Timeout,
                        stopwatch.ElapsedMilliseconds,
                        bytesTransferred,
                        cleanup.ProducerExitCode,
                        cleanup.ConsumerExitCode,
                        cleanup.DiagnosticDrainsObserved,
                        cleanup.ProducerProcessId,
                        cleanup.ConsumerProcessId);
                return CreateFailureResult(
                    BackupPipelineFailureStage.ConsumerStart,
                    stopwatch.ElapsedMilliseconds,
                    bytesTransferred,
                    cleanup.ProducerExitCode,
                    cleanup.ConsumerExitCode,
                    cleanup.DiagnosticDrainsObserved,
                    cleanup.ProducerProcessId,
                    cleanup.ConsumerProcessId);
            }

            consumerErrorTask = StartObservedDrain(consumerProcess.StandardError);
            consumerOutputTask = StartObservedDrain(consumerProcess.StandardOutput);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            bytesTransferred = await CopyAndHashAsync(
                producerProcess.StandardOutput.BaseStream,
                consumerProcess.StandardInput.BaseStream,
                hash,
                value => bytesTransferred = value,
                timeoutSource.Token);
            consumerProcess.StandardInput.Close();
            await Task.WhenAll(
                producerProcess.WaitForExitAsync(timeoutSource.Token),
                consumerProcess.WaitForExitAsync(timeoutSource.Token));
            var producerError = await producerErrorTask;
            var consumerError = await consumerErrorTask;
            var combinedError = string.Join("\n", new[] { producerError, consumerError }
                .Where(value => !string.IsNullOrWhiteSpace(value)));
            var producerExitCode = producerProcess.ExitCode;
            var consumerExitCode = consumerProcess.ExitCode;
            var failureStage = GetFailureStage(producerExitCode, consumerExitCode);
            var exitCode = producerExitCode != 0 ? producerExitCode : consumerExitCode;
            return new(
                exitCode,
                await consumerOutputTask,
                combinedError,
                bytesTransferred,
                Convert.ToHexStringLower(hash.GetHashAndReset()),
                producerExitCode,
                consumerExitCode,
                failureStage,
                stopwatch.ElapsedMilliseconds,
                true,
                TryGetProcessId(producerProcess),
                TryGetProcessId(consumerProcess));
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            var cleanup = await CleanupAsync(
                producerProcess,
                consumerProcess,
                DrainTasks(producerErrorTask, consumerErrorTask, consumerOutputTask));
            cancellationToken.ThrowIfCancellationRequested();
            return CreateFailureResult(
                BackupPipelineFailureStage.Timeout,
                stopwatch.ElapsedMilliseconds,
                bytesTransferred,
                cleanup.ProducerExitCode,
                cleanup.ConsumerExitCode,
                cleanup.DiagnosticDrainsObserved,
                cleanup.ProducerProcessId,
                cleanup.ConsumerProcessId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await CleanupAsync(
                producerProcess,
                consumerProcess,
                DrainTasks(producerErrorTask, consumerErrorTask, consumerOutputTask));
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
        catch (Exception exception)
        {
            var cleanup = await CleanupAsync(
                producerProcess,
                consumerProcess,
                DrainTasks(producerErrorTask, consumerErrorTask, consumerOutputTask));
            cancellationToken.ThrowIfCancellationRequested();
            var signaledStage = exception is BackupPipeException pipeException
                ? pipeException.FailureStage
                : BackupPipelineFailureStage.None;
            var failureStage = GetFailureStage(
                cleanup.ProducerExitCode,
                cleanup.ConsumerExitCode,
                signaledStage);
            if (failureStage == BackupPipelineFailureStage.None)
                failureStage = BackupPipelineFailureStage.Copy;
            return CreateFailureResult(
                failureStage,
                stopwatch.ElapsedMilliseconds,
                bytesTransferred,
                cleanup.ProducerExitCode,
                cleanup.ConsumerExitCode,
                cleanup.DiagnosticDrainsObserved,
                cleanup.ProducerProcessId,
                cleanup.ConsumerProcessId);
        }
        finally
        {
            DisposeSafely(consumerProcess);
            DisposeSafely(producerProcess);
        }
    }

    private static BackupProcessResult CreateFailureResult(
        BackupPipelineFailureStage failureStage,
        long durationMilliseconds,
        long bytesTransferred,
        int? producerExitCode = null,
        int? consumerExitCode = null,
        bool diagnosticDrainsObserved = true,
        int? producerProcessId = null,
        int? consumerProcessId = null)
    {
        var exitCode = producerExitCode is not null and not 0
            ? producerExitCode.Value
            : consumerExitCode is not null and not 0 ? consumerExitCode.Value : -1;
        return new(
            exitCode,
            string.Empty,
            string.Empty,
            BytesTransferred: bytesTransferred,
            ProducerExitCode: producerExitCode,
            ConsumerExitCode: consumerExitCode,
            FailureStage: failureStage,
            DurationMilliseconds: durationMilliseconds,
            DiagnosticDrainsObserved: diagnosticDrainsObserved,
            ProducerProcessId: producerProcessId,
            ConsumerProcessId: consumerProcessId);
    }

    private static Task<string> StartObservedDrain(StreamReader reader)
    {
        var task = ReadBoundedAsync(reader, CancellationToken.None);
        ObserveFault(task);
        return task;
    }

    private static IReadOnlyList<Task> DrainTasks(params Task<string>?[] tasks) =>
        tasks.Where(task => task != null).Cast<Task>().ToArray();

    private async Task<BackupCleanupResult> CleanupAsync(
        Process? producer,
        Process? consumer,
        IReadOnlyList<Task> drainTasks)
    {
        _cleanupStartedForTests?.Invoke();
        CloseStandardInput(consumer);
        var producerProcessId = TryGetProcessId(producer);
        var consumerProcessId = TryGetProcessId(consumer);
        var producerExitCode = TryGetExitCode(producer);
        var consumerExitCode = TryGetExitCode(consumer);
        Kill(producer);
        Kill(consumer);

        var completionTasks = new List<Task>(drainTasks.Count + 2);
        if (producer != null)
            completionTasks.Add(WaitForExitSafelyAsync(producer));
        if (consumer != null)
            completionTasks.Add(WaitForExitSafelyAsync(consumer));
        completionTasks.AddRange(drainTasks);
        foreach (var task in completionTasks)
            ObserveFault(task);

        var drainsObserved = await WaitForCompletionAsync(completionTasks);
        return new(
            producerExitCode,
            consumerExitCode,
            drainsObserved,
            producerProcessId,
            consumerProcessId);
    }

    private static void CloseStandardInput(Process? process)
    {
        if (process == null)
            return;
        try
        {
            process.StandardInput.Close();
        }
        catch
        {
            // Best effort during bounded cleanup.
        }
    }

    private static void DisposeSafely(Process? process)
    {
        try
        {
            process?.Dispose();
        }
        catch
        {
            // Disposal must not replace the pipeline result or caller cancellation.
        }
    }

    private static async Task WaitForExitSafelyAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync(CancellationToken.None);
        }
        catch
        {
            // Cleanup remains best effort and must not mask the original outcome.
        }
    }

    private static async Task<bool> WaitForCompletionAsync(IReadOnlyList<Task> tasks)
    {
        if (tasks.Count == 0)
            return true;
        var completion = Task.WhenAll(tasks);
        ObserveFault(completion);
        try
        {
            await completion.WaitAsync(CleanupTimeout);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        catch
        {
            _ = completion.Exception;
            return true;
        }
    }

    private static void ObserveFault(Task task) =>
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    private static Process Start(BackupProcessSpec spec, bool redirectInput, bool redirectOutput)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = spec.FileName,
            RedirectStandardInput = redirectInput,
            RedirectStandardOutput = redirectOutput,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in spec.Arguments)
            startInfo.ArgumentList.Add(argument);
        if (spec.Environment != null)
        {
            foreach (var pair in spec.Environment)
                startInfo.Environment[pair.Key] = pair.Value;
        }
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Unable to start backup process '{spec.FileName}'.");
    }

    private static async Task<long> CopyAndHashAsync(
        Stream source,
        Stream destination,
        IncrementalHash hash,
        Action<long> reportProgress,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        long total = 0;
        try
        {
            while (true)
            {
                int read;
                try
                {
                    read = await source.ReadAsync(buffer.AsMemory(), cancellationToken);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    throw new BackupPipeException(BackupPipelineFailureStage.Producer, exception);
                }
                if (read == 0)
                    break;
                hash.AppendData(buffer, 0, read);
                try
                {
                    await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    throw new BackupPipeException(BackupPipelineFailureStage.Consumer, exception);
                }
                total += read;
                reportProgress(total);
            }
            try
            {
                await destination.FlushAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                throw new BackupPipeException(BackupPipelineFailureStage.Consumer, exception);
            }
            return total;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        var builder = new StringBuilder();
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0)
                break;
            if (builder.Length < MaximumDiagnosticCharacters)
                builder.Append(buffer, 0, Math.Min(read, MaximumDiagnosticCharacters - builder.Length));
        }
        if (builder.Length == MaximumDiagnosticCharacters)
            builder.Append("\n[TRUNCATED]");
        return builder.ToString();
    }

    private static void Kill(Process? process)
    {
        if (process == null)
            return;
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Best effort after cancellation.
        }
    }

    private static int? TryGetExitCode(Process? process)
    {
        if (process == null)
            return null;
        try
        {
            return process.HasExited ? process.ExitCode : null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static int? TryGetProcessId(Process? process)
    {
        if (process == null)
            return null;
        try
        {
            return process.Id;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static BackupPipelineFailureStage GetFailureStage(
        int? producerExitCode,
        int? consumerExitCode,
        BackupPipelineFailureStage signaledStage = BackupPipelineFailureStage.None)
    {
        var producerFailed = producerExitCode is not null and not 0;
        var consumerFailed = consumerExitCode is not null and not 0;
        if (producerFailed && consumerFailed) return BackupPipelineFailureStage.Both;
        if (signaledStage == BackupPipelineFailureStage.Consumer && producerFailed)
            return BackupPipelineFailureStage.Both;
        if (signaledStage == BackupPipelineFailureStage.Producer && consumerFailed)
            return BackupPipelineFailureStage.Both;
        if (producerFailed) return BackupPipelineFailureStage.Producer;
        if (consumerFailed) return BackupPipelineFailureStage.Consumer;
        if (signaledStage is BackupPipelineFailureStage.Producer or BackupPipelineFailureStage.Consumer)
            return signaledStage;
        return BackupPipelineFailureStage.None;
    }

    private sealed class BackupPipeException(
        BackupPipelineFailureStage failureStage,
        Exception innerException) : IOException("backup_pipe_failed", innerException)
    {
        public BackupPipelineFailureStage FailureStage { get; } = failureStage;
    }

    private sealed record BackupCleanupResult(
        int? ProducerExitCode,
        int? ConsumerExitCode,
        bool DiagnosticDrainsObserved,
        int? ProducerProcessId,
        int? ConsumerProcessId);
}

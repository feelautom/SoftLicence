using System.Globalization;
using System.Runtime.InteropServices;

if (args.Length == 0)
    return 64;

return args[0] switch
{
    "produce" => await ProduceAsync(ParseInt(args, 1), ParseInt(args, 2), OptionalString(args, 3)),
    "consume" => await ConsumeAsync(ParseInt(args, 1)),
    "consume-early" => await ConsumeEarlyAsync(ParseInt(args, 1), ParseInt(args, 2), OptionalString(args, 3)),
    "consume-close-delay" => await ConsumeCloseDelayAsync(
        ParseInt(args, 1),
        ParseInt(args, 2),
        ParseInt(args, 3),
        OptionalString(args, 4)),
    "sleep-producer" => await SleepAsync(ParseInt(args, 1), OptionalString(args, 2)),
    "sleep-consumer" => await SleepAsync(ParseInt(args, 1), OptionalString(args, 2)),
    _ => 64
};

static async Task<int> ProduceAsync(int byteCount, int exitCode, string? pidFile)
{
    await WritePidAsync(pidFile);
    var buffer = new byte[16 * 1024];
    var written = 0;
    while (written < byteCount)
    {
        var count = Math.Min(buffer.Length, byteCount - written);
        for (var index = 0; index < count; index++)
            buffer[index] = (byte)((written + index) % 251);
        await Console.OpenStandardOutput().WriteAsync(buffer.AsMemory(0, count));
        written += count;
    }
    await Console.OpenStandardOutput().FlushAsync();
    if (exitCode != 0)
        await Console.Error.WriteLineAsync("synthetic producer failure");
    return exitCode;
}

static async Task<int> ConsumeAsync(int exitCode)
{
    await Console.OpenStandardInput().CopyToAsync(Stream.Null);
    if (exitCode != 0)
        await Console.Error.WriteLineAsync("synthetic consumer failure");
    return exitCode;
}

static async Task<int> ConsumeEarlyAsync(int bytesToRead, int exitCode, string? pidFile)
{
    await WritePidAsync(pidFile);
    var buffer = new byte[Math.Max(1, bytesToRead)];
    _ = await Console.OpenStandardInput().ReadAsync(buffer.AsMemory(0, Math.Max(1, bytesToRead)));
    await Console.Error.WriteLineAsync("synthetic early consumer failure");
    return exitCode;
}

static async Task<int> ConsumeCloseDelayAsync(
    int bytesToRead,
    int delayMilliseconds,
    int exitCode,
    string? pidFile)
{
    await WritePidAsync(pidFile);
    var input = Console.OpenStandardInput();
    var buffer = new byte[Math.Max(1, bytesToRead)];
    _ = await input.ReadAsync(buffer.AsMemory());
    input.Dispose();
    NativeStandardInput.Close();
    await Task.Delay(delayMilliseconds);
    return exitCode;
}

static async Task<int> SleepAsync(int milliseconds, string? pidFile)
{
    await WritePidAsync(pidFile);
    await Task.Delay(milliseconds);
    return 0;
}

static Task WritePidAsync(string? pidFile) =>
    string.IsNullOrEmpty(pidFile)
        ? Task.CompletedTask
        : File.WriteAllTextAsync(pidFile, Environment.ProcessId.ToString(CultureInfo.InvariantCulture));

static string? OptionalString(string[] values, int index) =>
    index < values.Length ? values[index] : null;

static int ParseInt(string[] values, int index) =>
    index < values.Length
        ? int.Parse(values[index], NumberStyles.None, CultureInfo.InvariantCulture)
        : throw new ArgumentException("Missing integer argument.");

internal static class NativeStandardInput
{
    private const int StandardInputHandle = -10;

    public static void Close()
    {
        if (OperatingSystem.IsWindows())
            _ = CloseHandle(GetStdHandle(StandardInputHandle));
        else
            _ = CloseFileDescriptor(0);
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int CloseFileDescriptor(int fileDescriptor);
}

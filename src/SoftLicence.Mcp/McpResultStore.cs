using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace SoftLicence.Mcp;

public sealed class McpResultStore
{
    private const string ArtifactFilePrefix = "softlicence-mcp-";
    private const string SessionOwnerFileName = ".softlicence-mcp-session.owner";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly string _directory;
    private readonly int _maxInlineCharacters;
    private readonly int _chunkCharacters;
    private readonly TimeSpan _ttl;
    private readonly long _maxTotalBytes;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, ArtifactState> _artifacts = new(StringComparer.Ordinal);

    public McpResultStore(IOptions<SoftLicenceMcpOptions> options)
    {
        var values = options.Value;
        _directory = values.GetResultDirectory();
        _maxInlineCharacters = Math.Clamp(values.MaxInlineResultCharacters, 16_384, 4_000_000);
        _chunkCharacters = Math.Clamp(values.ResultChunkCharacters, 4_096, 65_536);
        _ttl = TimeSpan.FromMinutes(Math.Clamp(values.ResultTtlMinutes, 5, 24 * 60));
        _maxTotalBytes = Math.Clamp(values.ResultMaxTotalBytes, 10 * 1024 * 1024, 2L * 1024 * 1024 * 1024);
        InitializeSessionDirectory();
    }

    public async Task<JsonElement> DeliverAsync(JsonElement result, CancellationToken cancellationToken = default)
    {
        var json = result.GetRawText();
        if (json.Length <= _maxInlineCharacters)
            return result;

        return await StoreOversizedJsonAsync(json, cancellationToken);
    }

    public async Task<JsonElement> DeliverJsonAsync(string json, CancellationToken cancellationToken = default)
    {
        if (json.Length <= _maxInlineCharacters)
        {
            using var inlineDocument = JsonDocument.Parse(json);
            return inlineDocument.RootElement.Clone();
        }

        // Validate before publishing the artifact, then release parser memory before writing it.
        using (JsonDocument.Parse(json))
        {
        }

        return await StoreOversizedJsonAsync(json, cancellationToken);
    }

    private async Task<JsonElement> StoreOversizedJsonAsync(string json, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(_directory);
            CleanupExpired();

            var totalBytes = Utf8.GetByteCount(json);
            var usedBytes = EnumerateOwnedArtifactFiles(_directory).Sum(file => file.Length);
            if (totalBytes > _maxTotalBytes || usedBytes > _maxTotalBytes - totalBytes)
            {
                throw new IOException(
                    $"mcp_result_artifact_capacity_exceeded: requiredBytes={totalBytes}, availableBytes={Math.Max(0, _maxTotalBytes - usedBytes)}");
            }

            var artifactId = Guid.NewGuid().ToString("N");
            var finalPath = GetArtifactPath(artifactId);
            var temporaryPath = Path.Combine(_directory, $".{ArtifactFilePrefix}{artifactId}.tmp");
            try
            {
                await File.WriteAllTextAsync(temporaryPath, json, Utf8, cancellationToken);
                File.Move(temporaryPath, finalPath);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }

            var now = DateTime.UtcNow;
            var state = new ArtifactState(
                artifactId,
                finalPath,
                json.Length,
                totalBytes,
                ComputeSha256(json),
                now,
                now.Add(_ttl),
                File.GetLastWriteTimeUtc(finalPath),
                BuildChunkIndex(json));
            _artifacts.Add(artifactId, state);
            return BuildDeliveryEnvelope(BuildInfo(state));
        }
        finally
        {
            _gate.Release();
        }
    }

    public JsonElement GetInfo(string artifactId)
    {
        _gate.Wait();
        try
        {
            var state = GetExistingArtifact(NormalizeArtifactId(artifactId));
            return JsonSerializer.SerializeToElement(new
            {
                ok = true,
                artifact = BuildInfo(state)
            }, JsonOptions);
        }
        finally
        {
            _gate.Release();
        }
    }

    public JsonElement GetChunk(string artifactId, int offset, int? length)
    {
        _gate.Wait();
        try
        {
            var state = GetExistingArtifact(NormalizeArtifactId(artifactId));
            if (offset < 0 || offset > state.TotalCharacters)
                throw new ArgumentOutOfRangeException(nameof(offset), "mcp_result_artifact_offset_invalid");
            if (length.HasValue && length.Value <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "mcp_result_artifact_length_invalid");
            if (length.HasValue && length.Value != _chunkCharacters)
                throw new ArgumentException($"mcp_result_artifact_length_must_equal_{_chunkCharacters}", nameof(length));

            if (!state.Chunks.TryGetValue(offset, out var chunk))
            {
                if (offset == state.TotalCharacters)
                    return BuildEmptyFinalChunk(state, offset);

                throw new ArgumentException("mcp_result_artifact_offset_must_use_next_offset", nameof(offset));
            }

            var buffer = new byte[chunk.ByteLength];
            using (var stream = new FileStream(state.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                stream.Seek(chunk.ByteOffset, SeekOrigin.Begin);
                stream.ReadExactly(buffer);
            }

            var content = Utf8.GetString(buffer);
            var nextOffset = chunk.CharacterOffset + chunk.CharacterLength;
            var now = DateTime.UtcNow;
            File.SetLastWriteTimeUtc(state.Path, now);
            state.FileVersionUtc = File.GetLastWriteTimeUtc(state.Path);
            state.ExpiresAtUtc = now.Add(_ttl);
            return JsonSerializer.SerializeToElement(new
            {
                ok = true,
                artifactId = state.ArtifactId,
                offset = chunk.CharacterOffset,
                length = chunk.CharacterLength,
                totalCharacters = state.TotalCharacters,
                content,
                nextOffset = nextOffset < state.TotalCharacters ? nextOffset : (int?)null,
                hasMore = nextOffset < state.TotalCharacters,
                complete = nextOffset >= state.TotalCharacters,
                truncated = false,
                sha256 = state.Sha256
            }, JsonOptions);
        }
        finally
        {
            _gate.Release();
        }
    }

    private JsonElement BuildEmptyFinalChunk(ArtifactState state, int offset)
    {
        var now = DateTime.UtcNow;
        File.SetLastWriteTimeUtc(state.Path, now);
        state.FileVersionUtc = File.GetLastWriteTimeUtc(state.Path);
        state.ExpiresAtUtc = now.Add(_ttl);
        return JsonSerializer.SerializeToElement(new
        {
            ok = true,
            artifactId = state.ArtifactId,
            offset,
            length = 0,
            totalCharacters = state.TotalCharacters,
            content = string.Empty,
            nextOffset = (int?)null,
            hasMore = false,
            complete = true,
            truncated = false,
            sha256 = state.Sha256
        }, JsonOptions);
    }

    private object BuildInfo(ArtifactState state)
    {
        return new
        {
            artifactId = state.ArtifactId,
            contentType = "application/json",
            encoding = "utf-8",
            totalCharacters = state.TotalCharacters,
            totalBytes = state.TotalBytes,
            sha256 = state.Sha256,
            chunkCharacters = _chunkCharacters,
            chunkCount = state.Chunks.Count,
            createdAtUtc = state.CreatedAtUtc,
            expiresAtUtc = state.ExpiresAtUtc,
            complete = true,
            truncated = false
        };
    }

    private static JsonElement BuildDeliveryEnvelope(object info)
    {
        return JsonSerializer.SerializeToElement(new
        {
            ok = true,
            resultDelivery = "artifact",
            message = "The complete JSON result exceeded the inline limit. Read every chunk in offset order; no data was truncated.",
            artifact = info
        }, JsonOptions);
    }

    private IReadOnlyDictionary<int, ArtifactChunk> BuildChunkIndex(string json)
    {
        var chunks = new Dictionary<int, ArtifactChunk>();
        var characterOffset = 0;
        long byteOffset = 0;
        while (characterOffset < json.Length)
        {
            var characterLength = GetChunkLength(json, characterOffset, _chunkCharacters);
            var byteLength = Utf8.GetByteCount(json.AsSpan(characterOffset, characterLength));
            chunks.Add(characterOffset, new ArtifactChunk(characterOffset, characterLength, byteOffset, byteLength));
            characterOffset += characterLength;
            byteOffset += byteLength;
        }

        return chunks;
    }

    private static int GetChunkLength(string json, int offset, int requestedLength)
    {
        var returnedLength = Math.Min(requestedLength, json.Length - offset);
        if (returnedLength > 0
            && offset + returnedLength < json.Length
            && char.IsHighSurrogate(json[offset + returnedLength - 1])
            && char.IsLowSurrogate(json[offset + returnedLength]))
        {
            returnedLength--;
        }

        return returnedLength;
    }

    private static string ComputeSha256(string json)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var byteBuffer = new byte[Utf8.GetMaxByteCount(4_096)];
        var offset = 0;
        while (offset < json.Length)
        {
            var characterLength = GetChunkLength(json, offset, 4_096);
            var byteLength = Utf8.GetBytes(
                json.AsSpan(offset, characterLength),
                byteBuffer.AsSpan());
            hash.AppendData(byteBuffer, 0, byteLength);
            offset += characterLength;
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private ArtifactState GetExistingArtifact(string artifactId)
    {
        if (!_artifacts.TryGetValue(artifactId, out var state) || !File.Exists(state.Path))
            throw new KeyNotFoundException("mcp_result_artifact_not_found");

        var file = new FileInfo(state.Path);
        state.ExpiresAtUtc = file.LastWriteTimeUtc.Add(_ttl);
        if (DateTime.UtcNow > state.ExpiresAtUtc)
        {
            File.Delete(state.Path);
            _artifacts.Remove(artifactId);
            throw new KeyNotFoundException("mcp_result_artifact_expired");
        }

        if (file.Length != state.TotalBytes || file.LastWriteTimeUtc != state.FileVersionUtc)
            throw new IOException("mcp_result_artifact_integrity_invalid");

        return state;
    }

    private string GetArtifactPath(string artifactId)
    {
        var path = Path.GetFullPath(Path.Combine(_directory, $"{ArtifactFilePrefix}{artifactId}.json"));
        var root = Path.GetFullPath(_directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("mcp_result_artifact_path_invalid");

        return path;
    }

    private static string NormalizeArtifactId(string artifactId)
    {
        var candidate = artifactId?.Trim();
        if (!Guid.TryParseExact(candidate, "N", out var parsed))
            throw new ArgumentException("mcp_result_artifact_id_invalid", nameof(artifactId));

        return parsed.ToString("N");
    }

    private void CleanupExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var state in _artifacts.Values.ToList())
        {
            if (File.Exists(state.Path))
            {
                state.ExpiresAtUtc = new FileInfo(state.Path).LastWriteTimeUtc.Add(_ttl);
            }
            if (now <= state.ExpiresAtUtc)
                continue;

            if (File.Exists(state.Path))
                File.Delete(state.Path);
            _artifacts.Remove(state.ArtifactId);
        }

        foreach (var temporaryPath in Directory.EnumerateFiles(_directory, $".{ArtifactFilePrefix}*.tmp", SearchOption.TopDirectoryOnly))
        {
            var file = new FileInfo(temporaryPath);
            if (now - file.LastWriteTimeUtc > TimeSpan.FromMinutes(10))
                file.Delete();
        }
    }

    private void InitializeSessionDirectory()
    {
        var parent = Directory.GetParent(_directory)?.FullName
            ?? throw new InvalidOperationException("mcp_result_session_parent_invalid");
        Directory.CreateDirectory(parent);

        foreach (var sessionDirectory in Directory.EnumerateDirectories(parent, "session-*", SearchOption.TopDirectoryOnly))
        {
            if ((new DirectoryInfo(sessionDirectory).Attributes & FileAttributes.ReparsePoint) != 0)
                continue;

            var markerPath = Path.Combine(sessionDirectory, SessionOwnerFileName);
            if (!TryReadSessionOwner(markerPath, out var processId, out var processStartTicks)
                || IsMatchingProcessAlive(processId, processStartTicks))
            {
                continue;
            }

            foreach (var file in EnumerateOwnedArtifactFiles(sessionDirectory))
                file.Delete();
            foreach (var temporaryPath in Directory.EnumerateFiles(
                         sessionDirectory, $".{ArtifactFilePrefix}*.tmp", SearchOption.TopDirectoryOnly))
            {
                File.Delete(temporaryPath);
            }

            File.Delete(markerPath);
            if (!Directory.EnumerateFileSystemEntries(sessionDirectory).Any())
                Directory.Delete(sessionDirectory);
        }

        Directory.CreateDirectory(_directory);
        var current = Process.GetCurrentProcess();
        File.WriteAllText(
            Path.Combine(_directory, SessionOwnerFileName),
            $"{Environment.ProcessId}|{current.StartTime.ToUniversalTime().Ticks}",
            Utf8);
    }

    private static IEnumerable<FileInfo> EnumerateOwnedArtifactFiles(string directory)
    {
        if (!Directory.Exists(directory))
            return [];

        return Directory.EnumerateFiles(directory, $"{ArtifactFilePrefix}*.json", SearchOption.TopDirectoryOnly)
            .Select(path => new FileInfo(path))
            .Where(file =>
            {
                var name = Path.GetFileNameWithoutExtension(file.Name);
                return name.StartsWith(ArtifactFilePrefix, StringComparison.Ordinal)
                    && Guid.TryParseExact(name[ArtifactFilePrefix.Length..], "N", out _);
            })
            .ToList();
    }

    private static bool TryReadSessionOwner(string markerPath, out int processId, out long processStartTicks)
    {
        processId = 0;
        processStartTicks = 0;
        if (!File.Exists(markerPath))
            return false;

        var parts = File.ReadAllText(markerPath, Utf8).Split('|');
        return parts.Length == 2
            && int.TryParse(parts[0], out processId)
            && long.TryParse(parts[1], out processStartTicks);
    }

    private static bool IsMatchingProcessAlive(int processId, long processStartTicks)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.StartTime.ToUniversalTime().Ticks == processStartTicks && !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return true;
        }
    }

    private sealed record ArtifactChunk(int CharacterOffset, int CharacterLength, long ByteOffset, int ByteLength);

    private sealed class ArtifactState(
        string artifactId,
        string path,
        int totalCharacters,
        long totalBytes,
        string sha256,
        DateTime createdAtUtc,
        DateTime expiresAtUtc,
        DateTime fileVersionUtc,
        IReadOnlyDictionary<int, ArtifactChunk> chunks)
    {
        public string ArtifactId { get; } = artifactId;
        public string Path { get; } = path;
        public int TotalCharacters { get; } = totalCharacters;
        public long TotalBytes { get; } = totalBytes;
        public string Sha256 { get; } = sha256;
        public DateTime CreatedAtUtc { get; } = createdAtUtc;
        public DateTime ExpiresAtUtc { get; set; } = expiresAtUtc;
        public DateTime FileVersionUtc { get; set; } = fileVersionUtc;
        public IReadOnlyDictionary<int, ArtifactChunk> Chunks { get; } = chunks;
    }
}

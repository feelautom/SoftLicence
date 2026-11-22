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

    /// <summary>
    /// Serializes <see cref="InitializeSessionDirectory"/> across every store of this process (TKT-004110).
    /// </summary>
    /// <remarks>
    /// All stores of one process share the directory <c>session-&lt;process id&gt;</c> and its owner marker, and each
    /// one sweeps the abandoned sessions on construction. Built in parallel (xUnit test classes, several MCP clients),
    /// they used to write and read the same marker at once (Windows sharing violation) and delete the same abandoned
    /// directory twice (DirectoryNotFoundException, "access denied" on a delete-pending directory). Static on purpose:
    /// an instance lock would not see the other stores. Other processes are not covered by this lock; see
    /// <see cref="CleanupAbandonedSession"/> for that case.
    /// </remarks>
    private static readonly object SessionInitializationLock = new();
    private readonly Dictionary<string, ArtifactState> _artifacts = new(StringComparer.Ordinal);
    private readonly Func<string?> _currentOwner;

    /// <summary>
    /// Creates the store. <paramref name="currentOwner"/> returns the caller identity (HTTP mode: a
    /// fingerprint of the analytics key); artifacts are then readable only by the caller that produced
    /// them. Stdio mode has a single local caller and passes no owner.
    /// </summary>
    /// <remarks>
    /// Construction prepares this process's session directory under <see cref="SessionInitializationLock"/>, so
    /// stores built in parallel in one process run that step one at a time (TKT-004110). It throws when the result
    /// root, the session directory or the owner marker cannot be created or written, and when the sweep of an
    /// abandoned session hits a real error (see <see cref="CleanupAbandonedSession(string)"/>): a store without its
    /// session directory cannot work, so failing loudly is preferred to a store that loses results later.
    /// </remarks>
    public McpResultStore(IOptions<SoftLicenceMcpOptions> options, Func<string?>? currentOwner = null)
    {
        _currentOwner = currentOwner ?? (() => null);
        var values = options.Value;
        _directory = values.GetResultDirectory();
        _maxInlineCharacters = Math.Clamp(values.MaxInlineResultCharacters, 16_384, 4_000_000);
        _chunkCharacters = Math.Clamp(values.ResultChunkCharacters, 4_096, 65_536);
        _ttl = TimeSpan.FromMinutes(Math.Clamp(values.ResultTtlMinutes, 5, 24 * 60));
        _maxTotalBytes = Math.Clamp(values.ResultMaxTotalBytes, 10 * 1024 * 1024, 2L * 1024 * 1024 * 1024);
        lock (SessionInitializationLock)
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
                BuildChunkIndex(json))
            {
                Owner = _currentOwner(),
            };
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
        // Another caller's artifact is reported exactly like a missing one (no existence oracle).
        if (state.Owner != null && !string.Equals(state.Owner, _currentOwner(), StringComparison.Ordinal))
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

    /// <summary>
    /// Creates this process's session directory and owner marker, after removing the artifacts of abandoned sessions
    /// (owner process dead) left by crashed MCP processes in the same parent directory.
    /// </summary>
    /// <remarks>
    /// Must run under <see cref="SessionInitializationLock"/> (the constructor takes it). Sessions of live processes,
    /// unreadable markers and reparse points are left untouched. A failure to create the parent, the session
    /// directory or the marker propagates and fails the construction: the store cannot work without them.
    /// </remarks>
    private void InitializeSessionDirectory()
    {
        var parent = Directory.GetParent(_directory)?.FullName
            ?? throw new InvalidOperationException("mcp_result_session_parent_invalid");
        Directory.CreateDirectory(parent);

        foreach (var sessionDirectory in Directory.EnumerateDirectories(parent, "session-*", SearchOption.TopDirectoryOnly))
            CleanupAbandonedSession(sessionDirectory);

        Directory.CreateDirectory(_directory);
        var current = Process.GetCurrentProcess();
        PublishSessionOwner(_directory, $"{Environment.ProcessId}|{current.StartTime.ToUniversalTime().Ticks}");
    }

    /// <summary>
    /// Publishes the owner marker of <paramref name="sessionDirectory"/> atomically: the content is written to a
    /// temporary file in the same directory, then moved over the marker in one rename.
    /// </summary>
    /// <remarks>
    /// Another process may read this marker at any moment to decide whether the session is abandoned (TKT-004110
    /// review 2517). Rewriting the marker in place let a reader see an empty or truncated value, and a truncated
    /// <c>pid|ticks</c> can still parse as a valid but wrong owner. A rename within one directory replaces the file
    /// whole, so a reader sees the previous complete value or the new one, never a fragment. Readers open the marker
    /// with delete sharing, which lets the replace succeed while they hold it. The temporary name starts with
    /// <c>.softlicence-mcp-</c> and ends with <c>.tmp</c>, so a leftover from a crash between the write and the move
    /// is removed by the existing temporary-file sweeps.
    /// <para>
    /// Windows cannot replace a file that another handle holds open, even with delete sharing ("access denied").
    /// Two rules keep that rare and bounded. A marker that already holds exactly this value is not rewritten, which
    /// is the case of every store after the first one of the process. A real replace (for example a process id
    /// reused after a crash) is retried for about one second, but only on "access denied" or a sharing or lock
    /// violation, because a sweeping reader holds the marker for microseconds. Any other failure, or the last
    /// attempt's failure, propagates and fails the construction, after a best-effort removal of the temporary file
    /// that never replaces the primary error.
    /// </para>
    /// </remarks>
    private static void PublishSessionOwner(string sessionDirectory, string content)
    {
        var markerPath = Path.Combine(sessionDirectory, SessionOwnerFileName);
        if (MarkerAlreadyHolds(markerPath, content))
            return;

        var temporaryPath = Path.Combine(sessionDirectory, $".{ArtifactFilePrefix}owner-{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temporaryPath, content, Utf8);
            const int maxAttempts = 40;
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    File.Move(temporaryPath, markerPath, overwrite: true);
                    return;
                }
                catch (Exception exception) when (attempt < maxAttempts
                    && (exception is UnauthorizedAccessException
                        || exception is IOException io && IsSharingOrLockViolation(io)))
                {
                    // A sweeping reader holds the marker for an instant; the next attempt usually succeeds.
                    Thread.Sleep(25);
                }
            }
        }
        catch
        {
            try { File.Delete(temporaryPath); }
            catch (IOException) { /* leftover removed by the next temporary-file sweep */ }
            catch (UnauthorizedAccessException) { /* idem; the primary failure below is what matters */ }
            throw;
        }
    }

    /// <summary>
    /// Returns true when the marker already contains exactly <paramref name="content"/>, so no rewrite is needed.
    /// Any read failure (absent marker, momentary sharing) returns false, and the caller then publishes normally;
    /// this check only avoids needless replaces and never decides anything else.
    /// </summary>
    private static bool MarkerAlreadyHolds(string markerPath, string content)
    {
        try
        {
            return string.Equals(SessionCleanupOperations.Default.ReadMarker(markerPath), content, StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// The file-system operations of <see cref="CleanupAbandonedSession(string, SessionCleanupOperations)"/> whose
    /// failures decide between "leave intact", "already removed by another process" and "real error". Production
    /// uses <see cref="Default"/>; tests inject failures to prove each outcome deterministically (TKT-004110 reviews
    /// 2516 and 2517).
    /// </summary>
    /// <param name="GetAttributes">Reads the attributes of a path; must throw when the path is absent, as
    /// <see cref="File.GetAttributes(string)"/> does, instead of returning a sentinel.</param>
    /// <param name="DeleteDirectory">Deletes an empty directory, as <see cref="Directory.Delete(string)"/>.</param>
    /// <param name="ReadMarker">Reads the whole owner marker text; must throw the platform's own exceptions
    /// (not-found, sharing or lock violation, other I/O errors) unchanged.</param>
    public sealed record SessionCleanupOperations(
        Func<string, FileAttributes> GetAttributes,
        Action<string> DeleteDirectory,
        Func<string, string> ReadMarker)
    {
        /// <summary>The real file-system operations.</summary>
        public static SessionCleanupOperations Default { get; } =
            new(File.GetAttributes, Directory.Delete, ReadMarkerShared);

        /// <summary>
        /// Reads the marker with read, write and delete sharing, so a reader never blocks the owner's atomic
        /// replace of that marker.
        /// </summary>
        private static string ReadMarkerShared(string markerPath)
        {
            using var stream = new FileStream(
                markerPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Utf8);
            return reader.ReadToEnd();
        }
    }

    /// <summary>
    /// Removes one abandoned session with the real file system; see
    /// <see cref="CleanupAbandonedSession(string, SessionCleanupOperations)"/>.
    /// </summary>
    /// <param name="sessionDirectory">Full path of a <c>session-*</c> directory under the result root.</param>
    public static void CleanupAbandonedSession(string sessionDirectory)
        => CleanupAbandonedSession(sessionDirectory, SessionCleanupOperations.Default);

    /// <summary>
    /// Removes one abandoned session: its owned artifact files, its leftover temporary files, its owner marker, then
    /// the directory once empty. Does nothing for a live owner, a marker that cannot be read right now or is
    /// incomplete, or a reparse point.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Another MCP process sharing the same parent can sweep the same abandoned session at the same moment; the
    /// in-process lock cannot prevent that (TKT-004110, seen on the shared CI runner account). A session that
    /// disappears mid-cleanup is the expected "already removed" outcome, not an error. It is accepted only on proof
    /// of absence: <see cref="DirectoryNotFoundException"/> or <see cref="FileNotFoundException"/> from the failing
    /// operation itself, or, for any other <see cref="IOException"/> or <see cref="UnauthorizedAccessException"/>
    /// (Windows reports "access denied" on a directory another process is deleting), a follow-up
    /// <see cref="SessionCleanupOperations.GetAttributes"/> on the directory that itself reports not-found.
    /// </para>
    /// <para>
    /// When that probe succeeds (the directory is still there) or fails for another reason (permissions, disk
    /// error: absence cannot be established), the original exception is rethrown unchanged with its stack.
    /// <see cref="Directory.Exists(string)"/> is deliberately not used: it also returns false when it cannot
    /// determine existence, which would hide exactly those real errors (review 2516).
    /// </para>
    /// <para>
    /// Public, not internal, so the tests can prove these outcomes deterministically: exposing this assembly's
    /// internals to the test project would also expose its top-level <c>Program</c>, which clashes with the server's.
    /// It only ever touches the given <c>session-*</c> directory.
    /// </para>
    /// </remarks>
    /// <param name="sessionDirectory">Full path of a <c>session-*</c> directory under the result root.</param>
    /// <param name="operations">File-system operations; <see cref="SessionCleanupOperations.Default"/> in
    /// production.</param>
    public static void CleanupAbandonedSession(string sessionDirectory, SessionCleanupOperations operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        try
        {
            if ((new DirectoryInfo(sessionDirectory).Attributes & FileAttributes.ReparsePoint) != 0)
                return;

            var markerPath = Path.Combine(sessionDirectory, SessionOwnerFileName);
            if (!TryReadSessionOwner(markerPath, operations, out var processId, out var processStartTicks)
                || IsMatchingProcessAlive(processId, processStartTicks))
            {
                return;
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
                operations.DeleteDirectory(sessionDirectory);
        }
        catch (Exception exception) when (exception is DirectoryNotFoundException or FileNotFoundException)
        {
            // Another process removed this abandoned session first: the cleanup goal is already met.
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                                          && IsCertainlyAbsent(sessionDirectory, operations))
        {
            // Same outcome, reported by Windows as "access denied" or a sharing violation; absence is proven by the
            // probe. Every other case leaves the filter false and the original exception propagates.
        }
    }

    /// <summary>
    /// Returns true only when <paramref name="path"/> is proven absent: the attribute probe throws
    /// <see cref="FileNotFoundException"/> or <see cref="DirectoryNotFoundException"/>. Returns false when the path
    /// exists and when the probe fails for any other reason, so an undetermined state never counts as absence.
    /// </summary>
    /// <remarks>
    /// Runs inside an exception filter: it must never throw, otherwise the filter would silently evaluate to false.
    /// It catches every probe exception on purpose and turns it into "not proven absent", which rethrows the original
    /// cleanup failure, never the probe's.
    /// </remarks>
    private static bool IsCertainlyAbsent(string path, SessionCleanupOperations operations)
    {
        try
        {
            operations.GetAttributes(path);
            return false;
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return true;
        }
        catch (Exception)
        {
            return false;
        }
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

    /// <summary>
    /// Reads the owner (process id and start ticks) of a session from its marker. Returns false, meaning "leave this
    /// session intact", when the marker is absent, is held by a sharing or lock violation right now, or is not a
    /// complete <c>pid|ticks</c> value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The marker of a live session is rewritten by its owner process while other processes may sweep (the
    /// in-process lock does not cover them, TKT-004110 review 2516). The owner publishes it atomically
    /// (<see cref="PublishSessionOwner"/>) and the default reader opens it with read, write and delete sharing, so
    /// they do not collide; a transient sharing or lock violation that still occurs means "owner may be alive",
    /// and the session is skipped, never deleted. Skipping is the safe side: an abandoned session left behind is
    /// cleaned by a later sweep.
    /// </para>
    /// <para>
    /// Only those two conditions are tolerated (review 2517): <see cref="IsSharingOrLockViolation"/> recognises them
    /// by their Win32 code. Any other <see cref="IOException"/> (disk or read error on a present marker) and any
    /// <see cref="UnauthorizedAccessException"/> propagate unchanged to the caller, whose absence probe then decides.
    /// </para>
    /// </remarks>
    private static bool TryReadSessionOwner(
        string markerPath, SessionCleanupOperations operations, out int processId, out long processStartTicks)
    {
        processId = 0;
        processStartTicks = 0;
        string text;
        try
        {
            text = operations.ReadMarker(markerPath);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            // No marker: not a session this sweep owns the right to delete.
            return false;
        }
        catch (IOException exception) when (IsSharingOrLockViolation(exception))
        {
            // The owner holds it right now: treat as alive and leave the session alone.
            return false;
        }

        var parts = text.Split('|');
        return parts.Length == 2
            && int.TryParse(parts[0], out processId)
            && long.TryParse(parts[1], out processStartTicks);
    }

    /// <summary>
    /// Returns true only for a Win32 sharing violation (<c>ERROR_SHARING_VIOLATION</c>, 32) or lock violation
    /// (<c>ERROR_LOCK_VIOLATION</c>, 33), as .NET reports them in <see cref="Exception.HResult"/>
    /// (<c>0x80070020</c> and <c>0x80070021</c>).
    /// </summary>
    /// <remarks>
    /// These are the only transient "someone else holds the file" conditions. On Linux and macOS, .NET implements
    /// <see cref="FileShare"/> with advisory locks only for writers that deny sharing; the marker writer and reader
    /// both share, so no such condition is expected there, and every I/O error is treated as real. Matching the code,
    /// never the message text, keeps localized and unrelated failures out (review 2517).
    /// </remarks>
    private static bool IsSharingOrLockViolation(IOException exception)
    {
        const int Win32SharingViolation = unchecked((int)0x80070020);
        const int Win32LockViolation = unchecked((int)0x80070021);
        return exception.HResult is Win32SharingViolation or Win32LockViolation;
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
        /// <summary>Caller identity that produced the artifact, or null in single-caller stdio mode.</summary>
        public string? Owner { get; init; }
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

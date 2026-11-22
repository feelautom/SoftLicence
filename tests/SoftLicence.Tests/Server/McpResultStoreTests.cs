using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class McpResultStoreTests
{
    [Fact]
    public async Task DeliverAsync_WhenResultFitsInline_ReturnsOriginalJson()
    {
        var fixture = CreateFixture(maxInlineCharacters: 16_384, chunkCharacters: 4_096);
        var original = JsonSerializer.SerializeToElement(new { status = "ok", values = new[] { 1, 2, 3 } });

        var delivered = await fixture.Store.DeliverAsync(original);

        Assert.Equal(original.GetRawText(), delivered.GetRawText());
        Assert.Empty(Directory.EnumerateFiles(fixture.Directory, "*.json"));
    }

    [Fact]
    public async Task DeliverAsync_WhenResultIsOversized_AllChunksReconstructExactJson()
    {
        var fixture = CreateFixture(maxInlineCharacters: 16_384, chunkCharacters: 4_096);
        var original = JsonSerializer.SerializeToElement(new
        {
            title = "Résultat intégral 🚀",
            records = Enumerable.Range(0, 2_000).Select(index => new
            {
                index,
                value = $"équipement-{index:D4}-漢字-🚀"
            })
        });
        var expectedJson = original.GetRawText();

        var delivered = await fixture.Store.DeliverAsync(original);

        Assert.Equal("artifact", delivered.GetProperty("resultDelivery").GetString());
        var artifact = delivered.GetProperty("artifact");
        Assert.True(artifact.GetProperty("complete").GetBoolean());
        Assert.False(artifact.GetProperty("truncated").GetBoolean());
        Assert.Equal(expectedJson.Length, artifact.GetProperty("totalCharacters").GetInt32());

        var artifactId = artifact.GetProperty("artifactId").GetString()!;
        var reconstructed = new StringBuilder(expectedJson.Length);
        var offset = 0;
        var chunksRead = 0;
        while (true)
        {
            var chunk = fixture.Store.GetChunk(artifactId, offset, length: 4_096);
            reconstructed.Append(chunk.GetProperty("content").GetString());
            chunksRead++;

            if (!chunk.GetProperty("hasMore").GetBoolean())
            {
                Assert.True(chunk.GetProperty("complete").GetBoolean());
                break;
            }

            offset = chunk.GetProperty("nextOffset").GetInt32();
        }

        var reconstructedJson = reconstructed.ToString();
        Assert.Equal(expectedJson, reconstructedJson);
        Assert.Equal(artifact.GetProperty("chunkCount").GetInt32(), chunksRead);
        Assert.Equal(
            artifact.GetProperty("sha256").GetString(),
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(reconstructedJson))).ToLowerInvariant());
    }

    [Theory]
    [InlineData("../secrets")]
    [InlineData("0000000000000000000000000000000g")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("")]
    public void GetInfo_WhenArtifactIdIsNotCanonicalOpaqueId_RejectsInput(string artifactId)
    {
        var fixture = CreateFixture();

        var exception = Assert.Throws<ArgumentException>(() => fixture.Store.GetInfo(artifactId));

        Assert.Contains("artifact_id_invalid", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetInfo_WhenArtifactIdUsesUppercaseHex_CanonicalizesToLowercase()
    {
        var fixture = CreateFixture(maxInlineCharacters: 16_384, chunkCharacters: 4_096);
        var original = JsonSerializer.SerializeToElement(new { payload = new string('x', 20_000) });
        var delivered = await fixture.Store.DeliverAsync(original);
        var artifactId = delivered.GetProperty("artifact").GetProperty("artifactId").GetString()!;

        var info = fixture.Store.GetInfo(artifactId.ToUpperInvariant());

        Assert.Equal(artifactId, info.GetProperty("artifact").GetProperty("artifactId").GetString());
    }

    [Theory]
    [InlineData(-1, 100)]
    [InlineData(0, 0)]
    [InlineData(0, -1)]
    public async Task GetChunk_WhenRangeIsInvalid_RejectsInsteadOfSilentlyClamping(int offset, int length)
    {
        var fixture = CreateFixture(maxInlineCharacters: 16_384, chunkCharacters: 4_096);
        var original = JsonSerializer.SerializeToElement(new { payload = new string('x', 20_000) });
        var delivered = await fixture.Store.DeliverAsync(original);
        var artifactId = delivered.GetProperty("artifact").GetProperty("artifactId").GetString()!;

        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Store.GetChunk(artifactId, offset, length));
    }

    [Fact]
    public async Task GetChunk_WhenOffsetSplitsUnicodeScalar_RejectsOffsetNotReturnedByPreviousChunk()
    {
        var fixture = CreateFixture(maxInlineCharacters: 16_384, chunkCharacters: 4_096);
        using var document = JsonDocument.Parse($"{{\"payload\":\"{new string('x', 20_000)}🚀\"}}");
        var original = document.RootElement.Clone();
        var originalJson = original.GetRawText();
        var delivered = await fixture.Store.DeliverAsync(original);
        var artifactId = delivered.GetProperty("artifact").GetProperty("artifactId").GetString()!;
        var lowSurrogateOffset = originalJson.IndexOf("🚀", StringComparison.Ordinal) + 1;

        var exception = Assert.Throws<ArgumentException>(() =>
            fixture.Store.GetChunk(artifactId, lowSurrogateOffset, 4_096));

        Assert.Contains("must_use_next_offset", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cleanup_DoesNotDeleteUnrelatedGuidNamedJsonFile()
    {
        var fixture = CreateFixture(maxInlineCharacters: 16_384, chunkCharacters: 4_096, ttlMinutes: 5);
        var original = JsonSerializer.SerializeToElement(new { payload = new string('x', 20_000) });
        await fixture.Store.DeliverAsync(original);
        var ownedArtifact = Assert.Single(Directory.EnumerateFiles(fixture.Directory, "softlicence-mcp-*.json"));
        File.SetLastWriteTimeUtc(ownedArtifact, DateTime.UtcNow.AddMinutes(-6));
        var unrelatedPath = Path.Combine(fixture.Directory, $"{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(unrelatedPath, "{\"unrelated\":true}");

        await fixture.Store.DeliverAsync(original);

        Assert.True(File.Exists(unrelatedPath));
        Assert.False(File.Exists(ownedArtifact));
    }

    [Fact]
    public async Task GetInfo_WhenArtifactExpired_DeletesOnlyOwnedArtifactAndRejectsRead()
    {
        var fixture = CreateFixture(maxInlineCharacters: 16_384, chunkCharacters: 4_096, ttlMinutes: 5);
        var original = JsonSerializer.SerializeToElement(new { payload = new string('x', 20_000) });
        var delivered = await fixture.Store.DeliverAsync(original);
        var artifactId = delivered.GetProperty("artifact").GetProperty("artifactId").GetString()!;
        var artifactPath = Assert.Single(Directory.EnumerateFiles(fixture.Directory, "*.json"));
        File.SetLastWriteTimeUtc(artifactPath, DateTime.UtcNow.AddMinutes(-6));

        var exception = Assert.Throws<KeyNotFoundException>(() => fixture.Store.GetInfo(artifactId));

        Assert.Contains("artifact_expired", exception.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(artifactPath));
    }

    [Fact]
    public async Task DeliverAsync_WhenCapacityIsInsufficient_DoesNotEvictReadableArtifact()
    {
        var fixture = CreateFixture(
            maxInlineCharacters: 16_384,
            chunkCharacters: 4_096,
            ttlMinutes: 60,
            maxTotalBytes: 10 * 1024 * 1024);
        var first = JsonSerializer.SerializeToElement(new { payload = new string('a', 6 * 1024 * 1024) });
        var second = JsonSerializer.SerializeToElement(new { payload = new string('b', 6 * 1024 * 1024) });
        var delivered = await fixture.Store.DeliverAsync(first);
        var artifactId = delivered.GetProperty("artifact").GetProperty("artifactId").GetString()!;

        var exception = await Assert.ThrowsAsync<IOException>(() => fixture.Store.DeliverAsync(second));

        Assert.Contains("capacity_exceeded", exception.Message, StringComparison.Ordinal);
        var stillReadable = fixture.Store.GetInfo(artifactId);
        Assert.Equal(artifactId, stillReadable.GetProperty("artifact").GetProperty("artifactId").GetString());
    }

    [Fact]
    public void Constructor_RemovesOwnedArtifactsFromAbandonedSession()
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(),
            "SoftLicence.Tests",
            nameof(McpResultStoreTests),
            Guid.NewGuid().ToString("N"));
        var abandonedDirectory = Path.Combine(rootDirectory, "session-999999");
        Directory.CreateDirectory(abandonedDirectory);
        File.WriteAllText(Path.Combine(abandonedDirectory, ".softlicence-mcp-session.owner"), "999999|0");
        File.WriteAllText(
            Path.Combine(abandonedDirectory, $"softlicence-mcp-{Guid.NewGuid():N}.json"),
            "{\"sensitive\":true}");
        var options = Options.Create(new SoftLicenceMcpOptions { ResultDirectory = rootDirectory });

        _ = new McpResultStore(options);

        Assert.False(Directory.Exists(abandonedDirectory));
    }

    /// <summary>
    /// TKT-004110: many stores built at the same time in one process (xUnit runs test classes in parallel, the MCP
    /// host builds several clients) share the session directory of the process and its owner marker, and each one
    /// sweeps the abandoned sessions. Before the fix this failed intermittently with IOException on the owner marker
    /// (Windows sharing violation) or DirectoryNotFoundException on a stale session another store had just removed.
    /// Every round starts all constructions together behind a barrier; no construction may throw, every abandoned
    /// session must be gone and the live session must keep its owner marker.
    /// </summary>
    [Fact]
    public void Constructor_InParallelInOneProcess_NeverThrows_AndSweepsAbandonedSessions()
    {
        const int rounds = 30;
        const int builders = 12;
        const int abandonedSessions = 6;
        var failures = new System.Collections.Concurrent.ConcurrentQueue<Exception>();
        for (var round = 0; round < rounds; round++)
        {
            var rootDirectory = Path.Combine(
                Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
            var abandoned = Enumerable.Range(0, abandonedSessions)
                .Select(index => CreateAbandonedSession(rootDirectory, 900_000 + index))
                .ToList();
            var options = Options.Create(new SoftLicenceMcpOptions { ResultDirectory = rootDirectory });
            using var barrier = new Barrier(builders);
            var threads = Enumerable.Range(0, builders).Select(builder => new Thread(() =>
            {
                barrier.SignalAndWait();
                try { _ = new McpResultStore(options); }
                catch (Exception exception) { failures.Enqueue(exception); }
            })).ToList();
            threads.ForEach(thread => thread.Start());
            threads.ForEach(thread => thread.Join());

            Assert.All(abandoned, directory => Assert.False(Directory.Exists(directory)));
            Assert.True(File.Exists(Path.Combine(
                rootDirectory, $"session-{Environment.ProcessId}", ".softlicence-mcp-session.owner")));
        }

        Assert.True(failures.IsEmpty, string.Join(Environment.NewLine, failures.Select(failure => failure.GetType().Name + ": " + failure.Message).Distinct()));
    }

    /// <summary>
    /// TKT-004110, other processes: an abandoned session that another MCP process already removed (the directory
    /// vanished between the parent listing and its cleanup) is the "already removed" outcome. The cleanup returns
    /// without error, and a later sweep of an existing abandoned session still removes it.
    /// </summary>
    [Fact]
    public void CleanupAbandonedSession_WhenAnotherProcessRemovedIt_IsAlreadySatisfied()
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var vanished = CreateAbandonedSession(rootDirectory, 910_001);
        Directory.Delete(vanished, recursive: true);
        var present = CreateAbandonedSession(rootDirectory, 910_002);

        McpResultStore.CleanupAbandonedSession(vanished);
        McpResultStore.CleanupAbandonedSession(present);

        Assert.False(Directory.Exists(vanished));
        Assert.False(Directory.Exists(present));
    }

    /// <summary>
    /// TKT-004110 review 2516, point 1: a cleanup failure on a session that may still exist is never absorbed.
    /// The final directory deletion fails with an "access denied"; the absence probe then either cannot decide
    /// (IOException: disk or permission problem) or sees the directory still present. In both cases the ORIGINAL
    /// exception instance must surface, never the probe's and never silence.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void CleanupAbandonedSession_WhenAbsenceIsNotProven_RethrowsTheOriginalFailure(bool probeIndeterminate)
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var session = CreateAbandonedSession(rootDirectory, 920_001);
        var original = new UnauthorizedAccessException("original delete failure");
        var operations = new McpResultStore.SessionCleanupOperations(
            path => probeIndeterminate ? throw new IOException("probe cannot decide") : FileAttributes.Directory,
            _ => throw original,
            McpResultStore.SessionCleanupOperations.Default.ReadMarker);

        var thrown = Assert.Throws<UnauthorizedAccessException>(
            () => McpResultStore.CleanupAbandonedSession(session, operations));

        Assert.Same(original, thrown);
    }

    /// <summary>
    /// Review 2516, point 1, tolerated side: the same "access denied" is the expected outcome when the probe proves
    /// the directory is gone (another process deleted it), so the cleanup returns without error.
    /// </summary>
    [Fact]
    public void CleanupAbandonedSession_WhenProbeProvesAbsence_ToleratesTheConcurrentDelete()
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var session = CreateAbandonedSession(rootDirectory, 920_002);
        var operations = new McpResultStore.SessionCleanupOperations(
            path => throw new DirectoryNotFoundException("gone"),
            _ => throw new UnauthorizedAccessException("delete pending in another process"),
            McpResultStore.SessionCleanupOperations.Default.ReadMarker);

        McpResultStore.CleanupAbandonedSession(session, operations);
    }

    /// <summary>
    /// Review 2516, point 2, reader side: another process's owner is rewriting its marker (File.WriteAllText opens it
    /// truncated, write access, read sharing) while this process sweeps. The sweep must neither fail nor delete: the
    /// half-written marker means "owner may be alive". Before the fix the reader opened the marker with read-only
    /// sharing, which Windows refuses against the writer's open handle (IOException on a present directory).
    /// </summary>
    [Fact]
    public void CleanupAbandonedSession_WhileOwnerRewritesItsMarker_LeavesTheSessionIntact()
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var session = CreateAbandonedSession(rootDirectory, 920_003);
        var marker = Path.Combine(session, ".softlicence-mcp-session.owner");

        using (var writer = new FileStream(marker, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            writer.Write("920"u8);
            writer.Flush();

            McpResultStore.CleanupAbandonedSession(session);

            Assert.True(Directory.Exists(session));
            Assert.Single(Directory.EnumerateFiles(session, "softlicence-mcp-*.json"));
        }
    }

    /// <summary>
    /// Review 2516, point 2, writer side (and 2517 atomic replace): a store of this process replaces its own marker
    /// while another process's sweep holds that marker open for reading. The construction must succeed and the
    /// marker must name this process.
    /// </summary>
    [Fact]
    public async Task Constructor_WhileAnotherProcessReadsItsMarker_StillPublishesTheOwner()
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var ownSession = Path.Combine(rootDirectory, $"session-{Environment.ProcessId}");
        Directory.CreateDirectory(ownSession);
        var marker = Path.Combine(ownSession, ".softlicence-mcp-session.owner");
        File.WriteAllText(marker, "0|0");
        var options = Options.Create(new SoftLicenceMcpOptions { ResultDirectory = rootDirectory });

        // The reader holds the marker for 300 ms, far longer than a real sweep: Windows refuses the replace meanwhile,
        // and the bounded retry of the publication must ride it out instead of failing the construction.
        var held = new FileStream(marker, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var release = Task.Delay(300).ContinueWith(_ => held.Dispose(), TaskScheduler.Default);

        _ = new McpResultStore(options);
        await release;

        Assert.StartsWith($"{Environment.ProcessId}|", File.ReadAllText(marker), StringComparison.Ordinal);
    }

    /// <summary>
    /// Review 2517: a marker that cannot be read because its owner holds it (Win32 sharing violation 32 or lock
    /// violation 33) means "owner may be alive". The sweep leaves the session intact and does not fail.
    /// </summary>
    [Theory]
    [InlineData(unchecked((int)0x80070020))]
    [InlineData(unchecked((int)0x80070021))]
    public void CleanupAbandonedSession_WhenMarkerIsHeldBySharingOrLock_LeavesTheSessionIntact(int hResult)
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var session = CreateAbandonedSession(rootDirectory, 920_004);
        var defaults = McpResultStore.SessionCleanupOperations.Default;
        var operations = defaults with { ReadMarker = _ => throw new IOException("held by its owner", hResult) };

        McpResultStore.CleanupAbandonedSession(session, operations);

        Assert.True(Directory.Exists(session));
        Assert.Single(Directory.EnumerateFiles(session, "softlicence-mcp-*.json"));
    }

    /// <summary>
    /// Review 2517: any other I/O error while reading a marker that is present (a disk or read failure) is a real
    /// problem. It must surface as the same exception instance, and nothing in the session may be deleted.
    /// </summary>
    [Fact]
    public void CleanupAbandonedSession_WhenMarkerReadFailsForAnotherReason_RethrowsIt()
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var session = CreateAbandonedSession(rootDirectory, 920_005);
        var original = new IOException("disk read error");
        var operations = McpResultStore.SessionCleanupOperations.Default with { ReadMarker = _ => throw original };

        var thrown = Assert.Throws<IOException>(() => McpResultStore.CleanupAbandonedSession(session, operations));

        Assert.Same(original, thrown);
        Assert.Single(Directory.EnumerateFiles(session, "softlicence-mcp-*.json"));
    }

    /// <summary>
    /// Review 2517, atomic publication: while stores of this process keep replacing a stale owner marker, a reader
    /// that opens it like another process's sweep must only ever see a complete value (the stale one or the new
    /// one). Before the atomic rename, the in-place rewrite exposed an empty or truncated marker (red on 079d076:
    /// empty value read), and a truncated <c>pid|ticks</c> can parse as a wrong owner.
    /// </summary>
    [Fact]
    public async Task Constructor_RepublishingTheMarker_NeverExposesAPartialValue()
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(), "SoftLicence.Tests", nameof(McpResultStoreTests), Guid.NewGuid().ToString("N"));
        var options = Options.Create(new SoftLicenceMcpOptions { ResultDirectory = rootDirectory });
        _ = new McpResultStore(options);
        var marker = Path.Combine(rootDirectory, $"session-{Environment.ProcessId}", ".softlicence-mcp-session.owner");
        var expected = File.ReadAllText(marker);
        // Complete but not a pid|ticks pair: the sweep leaves the session alone (a dead owner would be swept away),
        // and the publication still has to replace it.
        const string stale = "previous-owner-value";
        var observed = new System.Collections.Concurrent.ConcurrentBag<string>();
        using var stop = new CancellationTokenSource();

        var reader = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                try { observed.Add(McpResultStore.SessionCleanupOperations.Default.ReadMarker(marker)); }
                catch (FileNotFoundException) { observed.Add("<missing>"); }
            }
        });
        for (var publication = 0; publication < 100; publication++)
        {
            // Force a real replace on every construction: an unchanged marker is not rewritten by design.
            ReplaceAtomically(marker, stale);
            _ = new McpResultStore(options);
        }
        stop.Cancel();
        await reader;

        Assert.NotEmpty(observed);
        Assert.All(observed, text => Assert.True(text == expected || text == stale, $"partial marker seen: '{text}'"));
        Assert.Contains(expected, observed);
    }

    /// <summary>
    /// Test-side atomic write of a marker value (temporary file then rename), retried briefly while the concurrent
    /// reader of the test holds the file, so the test itself never exposes a partial value.
    /// </summary>
    private static void ReplaceAtomically(string path, string content)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".testtmp";
        File.WriteAllText(temporary, content);
        for (var attempt = 1; ; attempt++)
        {
            try { File.Move(temporary, path, overwrite: true); return; }
            catch (Exception exception) when (attempt < 200 && exception is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(5);
            }
        }
    }

    /// <summary>
    /// Creates an abandoned session directory owned by a process that does not exist, holding one owned artifact,
    /// exactly as a crashed MCP process leaves it. Returns the session directory path.
    /// </summary>
    private static string CreateAbandonedSession(string rootDirectory, int processId)
    {
        var directory = Path.Combine(rootDirectory, $"session-{processId}");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, ".softlicence-mcp-session.owner"), $"{processId}|0");
        File.WriteAllText(Path.Combine(directory, $"softlicence-mcp-{Guid.NewGuid():N}.json"), "{\"stale\":true}");
        return directory;
    }

    private static ResultStoreFixture CreateFixture(
        int maxInlineCharacters = 16_384,
        int chunkCharacters = 4_096,
        int ttlMinutes = 60,
        long maxTotalBytes = 100 * 1024 * 1024)
    {
        var rootDirectory = Path.Combine(
            Path.GetTempPath(),
            "SoftLicence.Tests",
            nameof(McpResultStoreTests),
            Guid.NewGuid().ToString("N"));
        var directory = Path.Combine(rootDirectory, $"session-{Environment.ProcessId}");
        var options = Options.Create(new SoftLicenceMcpOptions
        {
            ResultDirectory = rootDirectory,
            MaxInlineResultCharacters = maxInlineCharacters,
            ResultChunkCharacters = chunkCharacters,
            ResultTtlMinutes = ttlMinutes,
            ResultMaxTotalBytes = maxTotalBytes
        });
        return new ResultStoreFixture(directory, new McpResultStore(options));
    }

    private sealed record ResultStoreFixture(string Directory, McpResultStore Store);
}

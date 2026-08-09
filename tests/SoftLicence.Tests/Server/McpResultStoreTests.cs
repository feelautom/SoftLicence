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

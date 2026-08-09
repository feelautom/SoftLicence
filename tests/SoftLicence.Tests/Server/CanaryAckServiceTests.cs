using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class CanaryAckServiceTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 7, 18, 17, 30, 0, TimeSpan.Zero);
    private readonly SqliteConnection _keepAlive;
    private readonly DbContextOptions<LicenseDbContext> _options;
    private readonly RSA _rsa;
    private readonly CanaryAckService _service;

    public CanaryAckServiceTests()
    {
        var databaseName = $"canary-{Guid.NewGuid():N}";
        var connectionString = $"Data Source={databaseName};Mode=Memory;Cache=Shared";
        _keepAlive = new SqliteConnection(connectionString);
        _keepAlive.Open();
        _options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(connectionString)
            .Options;
        using (var db = new LicenseDbContext(_options))
            db.Database.EnsureCreated();

        _rsa = RSA.Create(2048);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CanaryAck:PrivateKeyPem"] = _rsa.ExportPkcs8PrivateKeyPem()
            })
            .Build();
        _service = new CanaryAckService(
            new TestDbContextFactory(_options),
            configuration,
            new FixedTimeProvider(Now));
    }

    [Fact]
    public void ValidateCriticalRequest_WithExactContract_CanonicalizesNothing()
    {
        var request = CreateRequest();

        var validated = _service.ValidateCriticalRequest(request);

        Assert.Equal(request.EventId, validated.EventId);
        Assert.Equal(request.HardwareId, validated.HardwareId);
        Assert.Equal(request.AppVersion, validated.AppVersion);
        Assert.Equal(request.Trigger, validated.Trigger);
    }

    [Fact]
    public void ValidateCriticalRequest_WithLowercaseHardwareId_RejectsNonCanonicalValue()
    {
        var request = CreateRequest();
        request.HardwareId = "abc123";

        var exception = Assert.Throws<CanaryAckValidationException>(() => _service.ValidateCriticalRequest(request));

        Assert.Equal("hardware_id_invalid", exception.ErrorCode);
    }

    [Fact]
    public void ValidateCriticalRequest_WithLegacyOrUnknownField_RejectsPayload()
    {
        var legacyField = CreateRequest();
        legacyField.MachineName = "machine";
        Assert.Equal(
            "unexpected_field",
            Assert.Throws<CanaryAckValidationException>(() => _service.ValidateCriticalRequest(legacyField)).ErrorCode);

        var unknownField = CreateRequest();
        unknownField.ExtensionData = new() { ["extra"] = default };
        Assert.Equal(
            "unexpected_field",
            Assert.Throws<CanaryAckValidationException>(() => _service.ValidateCriticalRequest(unknownField)).ErrorCode);
    }

    [Fact]
    public async Task IssueAsync_ProducesElevenFieldPkcs1ReceiptWithinFixedWindow()
    {
        var validated = _service.ValidateCriticalRequest(CreateRequest());

        var receipt = await _service.IssueAsync(validated, "ack");

        Assert.Equal(CanaryAckService.Schema, receipt.Schema);
        Assert.Equal(CanaryAckService.Algorithm, receipt.Alg);
        Assert.Equal(CanaryAckService.KeyId, receipt.KeyId);
        Assert.Equal(validated.EventId, receipt.EventId);
        Assert.Equal(validated.HardwareId, receipt.HardwareId);
        Assert.Equal(validated.AppVersion, receipt.AppVersion);
        Assert.Equal("ack", receipt.Decision);
        Assert.Equal("2026-07-18T17:30:00.0000000Z", receipt.IssuedAtUtc);
        Assert.Equal("2026-07-18T17:33:00.0000000Z", receipt.ExpiresAtUtc);
        Assert.DoesNotContain('=', receipt.Signature);

        var signature = DecodeBase64Url(receipt.Signature);
        Assert.True(_rsa.VerifyData(
            Encoding.UTF8.GetBytes(CanaryAckService.BuildCanonicalPayload(receipt)),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));

        var json = System.Text.Json.JsonSerializer.SerializeToElement(
            receipt,
            new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        Assert.Equal(11, json.EnumerateObject().Count());
        Assert.Equal(
            new[] { "schema", "alg", "keyId", "eventId", "hardwareId", "appVersion", "decision", "issuedAtUtc", "expiresAtUtc", "receiptId", "signature" },
            json.EnumerateObject().Select(property => property.Name));
    }

    [Fact]
    public async Task IssueAsync_WithDuplicateEvent_ReturnsOriginalReceipt()
    {
        var validated = _service.ValidateCriticalRequest(CreateRequest());

        var first = await _service.IssueAsync(validated, "kill");
        var second = await _service.IssueAsync(validated, "kill");

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task IssueAsync_WithConcurrentDuplicateEvent_ReturnsOneDurableReceipt()
    {
        var validated = _service.ValidateCriticalRequest(CreateRequest());

        var receipts = await Task.WhenAll(Enumerable.Range(0, 8)
            .Select(_ => _service.IssueAsync(validated, "ack")));

        Assert.Single(receipts.Select(receipt => receipt.ReceiptId).Distinct(StringComparer.Ordinal));
        Assert.Single(receipts.Select(receipt => receipt.Signature).Distinct(StringComparer.Ordinal));
    }

    [Fact]
    public async Task IssueAsync_WithSameEventBoundToAnotherVersion_RejectsReplay()
    {
        var first = _service.ValidateCriticalRequest(CreateRequest());
        await _service.IssueAsync(first, "ack");
        var replayRequest = CreateRequest();
        replayRequest.AppVersion = "2.2.844";
        var replay = _service.ValidateCriticalRequest(replayRequest);

        await Assert.ThrowsAsync<CanaryAckReplayException>(() => _service.IssueAsync(replay, "ack"));
    }

    [Fact]
    public void GetPublicKey_ExportsOnlyMatchingSpkiPublicMaterial()
    {
        var published = _service.GetPublicKey();
        using var publicRsa = RSA.Create();
        publicRsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(published.PublicKeySpkiBase64), out _);

        Assert.Equal(_rsa.ExportParameters(false).Modulus, publicRsa.ExportParameters(false).Modulus);
        Assert.Equal(CanaryAckService.KeyId, published.KeyId);
        Assert.DoesNotContain("PRIVATE", published.PublicKeySpkiBase64, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        _rsa.Dispose();
        _keepAlive.Dispose();
    }

    private static CanaryPingRequest CreateRequest() => new()
    {
        Schema = CanaryAckService.Schema,
        EventId = "12345678-1234-4234-9234-1234567890ab",
        SentAtUtc = "2026-07-18T17:30:00.0000000Z",
        HardwareId = "72A4BC9E3A72C063",
        AppVersion = "2.2.843",
        Trigger = "RuntimeCheck_NativeDllSwapped",
        Severity = 3
    };

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        return Convert.FromBase64String(base64);
    }

    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}

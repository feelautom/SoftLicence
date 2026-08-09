using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class DistributionS2SAuthenticationServiceTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 7, 18, 18, 30, 0, TimeSpan.Zero);
    private const string ClientId = "tia-connect-website";
    private const string KeyId = "distribution-s2s-ps256-2026-01";
    private const string ProductId = "12345678-1234-4234-9234-1234567890ab";
    private const string Path = "/api/internal/v1/distribution-entitlements/issue";

    private readonly SqliteConnection _keepAlive;
    private readonly DbContextOptions<LicenseDbContext> _dbOptions;
    private readonly RSA _rsa = RSA.Create(2048);

    public DistributionS2SAuthenticationServiceTests()
    {
        var connectionString = $"Data Source=s2s-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        _keepAlive = new SqliteConnection(connectionString);
        _keepAlive.Open();
        _dbOptions = new DbContextOptionsBuilder<LicenseDbContext>().UseSqlite(connectionString).Options;
        using var db = new LicenseDbContext(_dbOptions);
        db.Database.EnsureCreated();
    }

    [Fact]
    public async Task Authenticate_ValidPssSignature_ReservesNonce()
    {
        var service = CreateService();
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var context = CreateSignedContext(body, Guid.NewGuid().ToString("D"));

        var principal = await service.AuthenticateAndReserveNonceAsync(context, body, ProductId);

        Assert.Equal(ClientId, principal.ClientId);
        await using var db = new LicenseDbContext(_dbOptions);
        var nonce = await db.DistributionS2SNonces.SingleAsync();
        Assert.Equal(context.Request.Headers[DistributionS2SAuthenticationService.NonceHeader], nonce.Nonce);
    }

    [Fact]
    public async Task Authenticate_PrivilegedOperations_AreIndependentAndFailClosedByDefault()
    {
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var denied = await CreateService().AuthenticateAndReserveNonceAsync(
            CreateSignedContext(body, Guid.NewGuid().ToString("D")), body, ProductId);
        var recovery = await CreateService(allowRuntimeRecovery: true).AuthenticateAndReserveNonceAsync(
            CreateSignedContext(body, Guid.NewGuid().ToString("D")), body, ProductId);
        var upgrade = await CreateService(allowRuntimeUpgrade: true).AuthenticateAndReserveNonceAsync(
            CreateSignedContext(body, Guid.NewGuid().ToString("D")), body, ProductId);
        var bootstrap = await CreateService(allowLicenseBootstrap: true).AuthenticateAndReserveNonceAsync(
            CreateSignedContext(body, Guid.NewGuid().ToString("D")), body, ProductId);

        Assert.False(denied.AllowRuntimeRecovery);
        Assert.False(denied.AllowRuntimeUpgrade);
        Assert.False(denied.AllowLicenseBootstrap);
        Assert.True(recovery.AllowRuntimeRecovery);
        Assert.False(recovery.AllowRuntimeUpgrade);
        Assert.False(upgrade.AllowRuntimeRecovery);
        Assert.True(upgrade.AllowRuntimeUpgrade);
        Assert.False(upgrade.AllowLicenseBootstrap);
        Assert.False(bootstrap.AllowRuntimeRecovery);
        Assert.False(bootstrap.AllowRuntimeUpgrade);
        Assert.True(bootstrap.AllowLicenseBootstrap);
    }

    [Fact]
    public async Task Authenticate_ReplayedNonce_IsRejectedBeforeBusiness()
    {
        var service = CreateService();
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var nonce = Guid.NewGuid().ToString("D");
        await service.AuthenticateAndReserveNonceAsync(CreateSignedContext(body, nonce), body, ProductId);

        var exception = await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            service.AuthenticateAndReserveNonceAsync(CreateSignedContext(body, nonce), body, ProductId));

        Assert.Equal("replay_rejected", exception.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, exception.StatusCode);
    }

    [Fact]
    public async Task Authenticate_ChangedExactBodyWithOriginalSignature_IsRejectedWithoutNonce()
    {
        var service = CreateService();
        var signedBody = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var changedBody = Encoding.UTF8.GetBytes("{ \"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var context = CreateSignedContext(signedBody, Guid.NewGuid().ToString("D"));

        var exception = await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            service.AuthenticateAndReserveNonceAsync(context, changedBody, ProductId));

        Assert.Equal("authentication_failed", exception.ErrorCode);
        await using var db = new LicenseDbContext(_dbOptions);
        Assert.Empty(await db.DistributionS2SNonces.ToListAsync());
    }

    [Fact]
    public async Task Authenticate_RevokedKeyOrWrongProduct_IsRejected()
    {
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var revoked = CreateService(revokedAtUtc: Now.AddMinutes(-1));
        await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            revoked.AuthenticateAndReserveNonceAsync(
                CreateSignedContext(body, Guid.NewGuid().ToString("D")), body, ProductId));

        var active = CreateService();
        await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            active.AuthenticateAndReserveNonceAsync(
                CreateSignedContext(body, Guid.NewGuid().ToString("D")), body,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
    }

    [Fact]
    public async Task Authenticate_DuringRotation_SelectsTheActiveKeyId()
    {
        using var nextRsa = RSA.Create(2048);
        const string nextKeyId = "distribution-s2s-ps256-2026-02";
        var options = Options.Create(new DistributionS2SOptions
        {
            Clients =
            [
                new DistributionS2SClientOptions
                {
                    ClientId = ClientId,
                    KeyId = KeyId,
                    PublicKeyPem = _rsa.ExportSubjectPublicKeyInfoPem(),
                    RevokedAtUtc = Now.AddMinutes(-1),
                    ProductIds = [ProductId],
                    AllowedCidrs = ["127.0.0.1/32"]
                },
                new DistributionS2SClientOptions
                {
                    ClientId = ClientId,
                    KeyId = nextKeyId,
                    PublicKeyPem = nextRsa.ExportSubjectPublicKeyInfoPem(),
                    ProductIds = [ProductId],
                    AllowedCidrs = ["127.0.0.1/32"]
                }
            ]
        });
        var service = new DistributionS2SAuthenticationService(
            new TestDbContextFactory(_dbOptions), options, new FixedTimeProvider(Now));
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");

        var principal = await service.AuthenticateAndReserveNonceAsync(
            CreateSignedContext(body, Guid.NewGuid().ToString("D"), nextKeyId, nextRsa), body, ProductId);

        Assert.Equal(nextKeyId, principal.KeyId);
    }

    [Fact]
    public async Task Authenticate_HttpWrongCidrOrStaleTimestamp_IsRejected()
    {
        var service = CreateService();
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");

        var http = CreateSignedContext(body, Guid.NewGuid().ToString("D"));
        http.Request.Scheme = "http";
        await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            service.AuthenticateAndReserveNonceAsync(http, body, ProductId));

        var wrongCidr = CreateSignedContext(body, Guid.NewGuid().ToString("D"));
        wrongCidr.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.1");
        await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            service.AuthenticateAndReserveNonceAsync(wrongCidr, body, ProductId));

        var stale = CreateSignedContext(
            body, Guid.NewGuid().ToString("D"), timestamp: "2026-07-18T18:28:59.0000000Z");
        await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            service.AuthenticateAndReserveNonceAsync(stale, body, ProductId));
    }

    [Fact]
    public async Task Authenticate_Pkcs1Signature_IsRejected()
    {
        var service = CreateService();
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var context = CreateSignedContext(
            body, Guid.NewGuid().ToString("D"), padding: RSASignaturePadding.Pkcs1);

        var exception = await Assert.ThrowsAsync<DistributionS2SAuthenticationException>(() =>
            service.AuthenticateAndReserveNonceAsync(context, body, ProductId));

        Assert.Equal("authentication_failed", exception.ErrorCode);
    }

    [Fact]
    public async Task Authenticate_ConcurrentSameNonce_AllowsExactlyOneReservation()
    {
        var service = CreateService();
        var body = Encoding.UTF8.GetBytes("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}");
        var nonce = Guid.NewGuid().ToString("D");
        var attempts = Enumerable.Range(0, 4).Select(async _ =>
        {
            try
            {
                await service.AuthenticateAndReserveNonceAsync(CreateSignedContext(body, nonce), body, ProductId);
                return "accepted";
            }
            catch (DistributionS2SAuthenticationException exception)
            {
                return exception.ErrorCode;
            }
        });

        var results = await Task.WhenAll(attempts);

        Assert.Single(results, result => result == "accepted");
        Assert.Equal(3, results.Count(result => result == "replay_rejected"));
    }

    [Fact]
    public void OptionsValidation_RejectsFailOpenAndDuplicateOrInvalidScopes()
    {
        var duplicatedClient = new DistributionS2SClientOptions
        {
            ClientId = ClientId,
            KeyId = KeyId,
            PublicKeyPem = _rsa.ExportSubjectPublicKeyInfoPem(),
            ProductIds = [ProductId],
            AllowedCidrs = ["127.0.0.1/32"]
        };
        var result = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            RequireHttps = false,
            ClockSkewSeconds = 61,
            Clients =
            [
                duplicatedClient,
                new DistributionS2SClientOptions
                {
                    ClientId = ClientId,
                    KeyId = KeyId,
                    PublicKeyPem = _rsa.ExportSubjectPublicKeyInfoPem(),
                    ProductIds = ["NOT-A-UUID"],
                    AllowedCidrs = ["not-a-cidr"]
                }
            ]
        });

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, failure => failure.Contains("HTTPS", StringComparison.Ordinal));
        Assert.Contains(result.Failures!, failure => failure.Contains("unique", StringComparison.Ordinal));
        Assert.Contains(result.Failures!, failure => failure.Contains("product", StringComparison.Ordinal));
        Assert.Contains(result.Failures!, failure => failure.Contains("network", StringComparison.Ordinal));
    }

    public void Dispose()
    {
        _rsa.Dispose();
        _keepAlive.Dispose();
    }

    private DistributionS2SAuthenticationService CreateService(
        DateTimeOffset? revokedAtUtc = null,
        bool allowRuntimeRecovery = false,
        bool allowRuntimeUpgrade = false,
        bool allowLicenseBootstrap = false)
    {
        var options = Options.Create(new DistributionS2SOptions
        {
            RequireHttps = true,
            Clients =
            [
                new DistributionS2SClientOptions
                {
                    ClientId = ClientId,
                    KeyId = KeyId,
                    PublicKeyPem = _rsa.ExportSubjectPublicKeyInfoPem(),
                    AllowRuntimeRecovery = allowRuntimeRecovery,
                    AllowRuntimeUpgrade = allowRuntimeUpgrade,
                    AllowLicenseBootstrap = allowLicenseBootstrap,
                    RevokedAtUtc = revokedAtUtc,
                    ProductIds = [ProductId],
                    AllowedCidrs = ["127.0.0.1/32"]
                }
            ]
        });
        return new DistributionS2SAuthenticationService(
            new TestDbContextFactory(_dbOptions), options, new FixedTimeProvider(Now));
    }

    private DefaultHttpContext CreateSignedContext(
        byte[] body,
        string nonce,
        string keyId = KeyId,
        RSA? signingKey = null,
        string timestamp = "2026-07-18T18:30:00.0000000Z",
        RSASignaturePadding? padding = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = Path;
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Headers[DistributionS2SAuthenticationService.ClientHeader] = ClientId;
        context.Request.Headers[DistributionS2SAuthenticationService.KeyIdHeader] = keyId;
        context.Request.Headers[DistributionS2SAuthenticationService.TimestampHeader] = timestamp;
        context.Request.Headers[DistributionS2SAuthenticationService.NonceHeader] = nonce;
        var payload = DistributionS2SAuthenticationService.BuildSignaturePayload(
            ClientId, keyId, HttpMethods.Post, Path, timestamp, nonce, body);
        var signature = (signingKey ?? _rsa).SignData(
            Encoding.UTF8.GetBytes(payload),
            HashAlgorithmName.SHA256,
            padding ?? RSASignaturePadding.Pss);
        context.Request.Headers[DistributionS2SAuthenticationService.SignatureHeader] = EncodeBase64Url(signature);
        return context;
    }

    private static string EncodeBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

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

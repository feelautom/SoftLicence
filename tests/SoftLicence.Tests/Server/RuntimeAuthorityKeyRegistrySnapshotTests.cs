using System.Text;
using System.Security.Cryptography;
using System.Reflection;
using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using Moq;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves the closed public key-registry request and response byte contracts.</summary>
public sealed class RuntimeAuthorityKeyRegistrySnapshotTests
{
    /// <summary>Accepts only the exact four-member canonical request and preserves both UUIDs.</summary>
    [Fact]
    public void ParseRequest_AcceptsOnlyCanonicalFourMemberBody()
    {
        const string requestId = "11111111-1111-4111-8111-111111111111";
        const string productId = "22222222-2222-4222-8222-222222222222";
        var body = Encoding.UTF8.GetBytes(
            "{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"" +
            requestId + "\",\"productId\":\"" + productId + "\"}");

        var parsed = RuntimeAuthorityKeyRegistryContract.ParseRequest(body);

        Assert.Equal(Guid.Parse(requestId), parsed.RequestId);
        Assert.Equal(Guid.Parse(productId), parsed.ProductId);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(body)), parsed.RequestDigestSha256);
        Assert.Throws<RuntimeAuthorityKeyRegistryContractException>(() =>
            RuntimeAuthorityKeyRegistryContract.ParseRequest([.. body, (byte)' ']));
    }

    /// <summary>Rejects non-canonical JSON aliases instead of normalizing equivalent values.</summary>
    [Theory]
    [InlineData("{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"productId\":\"22222222-2222-4222-8222-222222222222\",\"requestId\":\"11111111-1111-4111-8111-111111111111\"}")]
    [InlineData("{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\", \"contractVersion\":1,\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"22222222-2222-4222-8222-222222222222\"}")]
    [InlineData("{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1.0,\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"22222222-2222-4222-8222-222222222222\"}")]
    [InlineData("{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"22222222-2222-4222-8222-222222222222\",\"extra\":null}")]
    public void ParseRequest_RejectsEquivalentButNonCanonicalJson(string json) =>
        Assert.Throws<RuntimeAuthorityKeyRegistryContractException>(() =>
            RuntimeAuthorityKeyRegistryContract.ParseRequest(Encoding.UTF8.GetBytes(json)));

    /// <summary>Writes only authenticated public SPKI material and the two independently named digests.</summary>
    [Fact]
    public void BuildSnapshot_EmitsPublicOnlyCanonicalResponse()
    {
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = new DateTimeOffset(2026, 8, 30, 0, 0, 0, TimeSpan.Zero).AddTicks(1);
        var signing = new RuntimeAuthorityGenerationSigningOptions
        {
            ActiveSigningKeyId = "operational-2026-01",
            RegistrySnapshotId = "registry-snapshot-2026-08-30",
            RegistrySnapshotVersion = 1,
            Keys =
            [
                Key("operational-2026-01", "operational", "generation", operational, observed.AddDays(-1), operational.ExportPkcs8PrivateKeyPem()),
                Key("recovery-2026-01", "recovery", "recovery", recovery, observed.AddDays(-1), null)
            ]
        };
        var crypto = new RuntimeEnrollmentAuthorityCryptography(
            new FixedTimeProvider(observed), registry.ExportSubjectPublicKeyInfo());
        var input = crypto.GetRegistrySnapshotAuthenticationInput(signing, observed).Value!;
        var signature = Encode(registry.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var options = new RuntimeEnrollmentOptions
        {
            Mode = "enabled",
            AuthorityGenerationSigning = signing,
            AuthorityGenerationV2 = new()
            {
                Mode = "enabled",
                RegistryAuthoritySpkiBase64 = Convert.ToBase64String(registry.ExportSubjectPublicKeyInfo()),
                RegistryObservedAtUtc = observed.ToString("O"),
                RegistrySnapshotSignatureBase64Url = signature
            }
        };

        var snapshot = RuntimeAuthorityKeyRegistryContract.BuildSnapshot(options, observed);
        var json = Encoding.UTF8.GetString(snapshot.ExactResponseBody);

        Assert.Equal(observed.ToString("O"), (object)snapshot.ObservedAtUtc);
        Assert.Contains("\"observedAtUtc\":\"2026-08-30T00:00:00.0000001+00:00\"", json, StringComparison.Ordinal);
        Assert.True(RuntimeAuthorityKeyRegistryContract.HasExactObservedAtUtc(
            snapshot.ExactResponseBody, snapshot.ObservedAtUtc));
        Assert.False(RuntimeAuthorityKeyRegistryContract.HasExactObservedAtUtc(
            snapshot.ExactResponseBody, "2026-08-30T00:00:00.0000002+00:00"));
        Assert.Contains("\"metadataDigestSha256\":\"", json, StringComparison.Ordinal);
        Assert.Contains("\"registryAuthenticationInputDigestSha256\":\"", json, StringComparison.Ordinal);
        Assert.Contains("\"spkiDerBase64\":\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("PrivateKey", json, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", json, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(registry.ExportSubjectPublicKeyInfo()), json, StringComparison.Ordinal);
        Assert.True(RuntimeAuthorityKeyRegistryContract.HasExactBodyDigest(
            snapshot.ExactResponseBody, snapshot.ExactResponseBodySha256, snapshot.ExactResponseBodySha256));
    }

    /// <summary>Projects only the closed active, retired, revoked, and compromised lifecycle forms.</summary>
    [Theory]
    [InlineData("active", null, false)]
    [InlineData("retired", null, false)]
    [InlineData("revoked", "operator_revoked", false)]
    [InlineData("revoked", "compromised", true)]
    public void BuildSnapshot_ProjectsClosedLifecycle(
        string status, string? revocationCode, bool compromised)
    {
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero);
        var options = LifecycleOptions(
            registry, operational, recovery, observed, status, revocationCode, compromised);

        var json = Encoding.UTF8.GetString(
            RuntimeAuthorityKeyRegistryContract.BuildSnapshot(options, observed).ExactResponseBody);

        Assert.Contains($"\"status\":\"{status}\"", json, StringComparison.Ordinal);
        Assert.Contains(revocationCode is null
            ? "\"revocationCode\":null"
            : $"\"revocationCode\":\"{revocationCode}\"", json, StringComparison.Ordinal);
        Assert.Equal(compromised, json.Contains("\"compromiseFromUtc\":\"", StringComparison.Ordinal));
    }

    /// <summary>Rejects a provider-authenticated free-form revocation reason before publication.</summary>
    [Fact]
    public void BuildSnapshot_RejectsNonAllowlistedRevocationCode()
    {
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero);
        var options = LifecycleOptions(
            registry, operational, recovery, observed, "revoked", "operator note", false);

        var failure = Assert.Throws<RuntimeAuthorityKeyRegistryContractException>(() =>
            RuntimeAuthorityKeyRegistryContract.BuildSnapshot(options, observed));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
    }

    /// <summary>Uses the inclusive 300-second source bound and rejects the following tick.</summary>
    [Fact]
    public void BuildSnapshot_EnforcesExactInclusiveFreshnessBoundary()
    {
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero);
        var options = LifecycleOptions(
            registry, operational, recovery, observed, "active", null, false);

        _ = RuntimeAuthorityKeyRegistryContract.BuildSnapshot(options, observed.AddSeconds(300));
        var stale = Assert.Throws<RuntimeAuthorityKeyRegistryContractException>(() =>
            RuntimeAuthorityKeyRegistryContract.BuildSnapshot(
                options, observed.AddSeconds(300).AddTicks(1)));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, stale.StatusCode);
    }

    /// <summary>Rejects altered provider authentication bytes with the uniform closed outcome.</summary>
    [Fact]
    public void BuildSnapshot_RejectsAlteredRegistrySignature()
    {
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero);
        var options = LifecycleOptions(
            registry, operational, recovery, observed, "active", null, false);
        var signature = options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url;
        options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url =
            (signature[0] == 'A' ? "B" : "A") + signature[1..];

        var failure = Assert.Throws<RuntimeAuthorityKeyRegistryContractException>(() =>
            RuntimeAuthorityKeyRegistryContract.BuildSnapshot(options, observed));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
    }

    /// <summary>Requires closed outcomes for wrapped provider failures without inspecting message text.</summary>
    [Theory]
    [InlineData("40001", "RetryTransaction")]
    [InlineData("40P01", "RetryTransaction")]
    [InlineData("55P03", "Unavailable")]
    [InlineData("57014", "Unavailable")]
    [InlineData("23503", "Unavailable")]
    public void Service_ClassifiesWrappedPostgreSqlFailures(string sqlState, string expected)
    {
        var classifier = typeof(RuntimeAuthorityKeyRegistrySnapshotService).GetMethod(
            "ClassifyDatabaseFailure", BindingFlags.NonPublic | BindingFlags.Static);
        var postgres = new PostgresException("fixture", "ERROR", "ERROR", sqlState);
        var wrapped = new DbUpdateException("fixture wrapper", postgres);

        Assert.NotNull(classifier);
        Assert.Equal(expected, classifier.Invoke(null, [wrapped, CancellationToken.None])!.ToString());
    }

    /// <summary>Requires explicit caller cancellation to outrank a wrapped PostgreSQL query cancellation.</summary>
    [Fact]
    public void Service_CallerCancellationOutranksWrapped57014()
    {
        var classifier = typeof(RuntimeAuthorityKeyRegistrySnapshotService).GetMethod(
            "ClassifyDatabaseFailure", BindingFlags.NonPublic | BindingFlags.Static);
        var wrapped = new DbUpdateException("fixture wrapper",
            new PostgresException("fixture", "ERROR", "ERROR", PostgresErrorCodes.QueryCanceled));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.NotNull(classifier);
        Assert.Equal("CallerCancellation",
            classifier.Invoke(null, [wrapped, cancellation.Token])!.ToString());
    }

    /// <summary>Allows only the named semantic-readback PK collision to enter a bounded locked reread.</summary>
    [Fact]
    public void Service_ClassifiesOnlyExpectedReadbackUniqueRaceForReread()
    {
        var classifier = typeof(RuntimeAuthorityKeyRegistrySnapshotService).GetMethod(
            "ClassifyDatabaseFailure", BindingFlags.NonPublic | BindingFlags.Static);
        var expectedRace = new PostgresException(
            "fixture", "ERROR", "ERROR", PostgresErrorCodes.UniqueViolation,
            constraintName: "PK_RuntimeAuthorityKeyRegistryReadbacks");
        var unrelated = new PostgresException(
            "fixture", "ERROR", "ERROR", PostgresErrorCodes.UniqueViolation,
            constraintName: "UX_unrelated");

        Assert.NotNull(classifier);
        Assert.Equal("RereadExpectedReadbackRace",
            classifier.Invoke(null, [new DbUpdateException("wrapper", expectedRace), CancellationToken.None])!.ToString());
        Assert.Equal("Unavailable",
            classifier.Invoke(null, [new DbUpdateException("wrapper", unrelated), CancellationToken.None])!.ToString());
    }

    /// <summary>Collapses connection and timeout failures to the same closed provider outcome.</summary>
    [Theory]
    [MemberData(nameof(ClosedProviderFailures))]
    public void Service_ClassifiesConnectionAndTimeoutFailures(Exception failure)
    {
        var classifier = typeof(RuntimeAuthorityKeyRegistrySnapshotService).GetMethod(
            "ClassifyDatabaseFailure", BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(classifier);
        Assert.Equal("Unavailable", classifier.Invoke(null, [failure, CancellationToken.None])!.ToString());
    }

    /// <summary>Supplies provider failures that must never escape as HTTP 500.</summary>
    public static TheoryData<Exception> ClosedProviderFailures => new()
    {
        new TimeoutException("fixture"),
        new NpgsqlException("fixture"),
        new DbUpdateException("fixture")
    };

    /// <summary>Proves a provider timeout crossing the service boundary becomes the closed 503 contract error.</summary>
    [Fact]
    public async Task Service_MapsProviderTimeoutToClosed503()
    {
        var service = new RuntimeAuthorityKeyRegistrySnapshotService(
            new ThrowingDbFactory(new TimeoutException("fixture")),
            Options.Create(new RuntimeEnrollmentOptions { MaximumTransactionAttempts = 3 }));

        var failure = await Assert.ThrowsAsync<RuntimeAuthorityKeyRegistryContractException>(() =>
            service.ReadCurrentAsync("registry-client", CanonicalRequest(), CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
    }

    /// <summary>Proves actual service control flow propagates cancellation before wrapped 57014 mapping.</summary>
    [Fact]
    public async Task Service_PropagatesCallerCancellationBeforeWrapped57014()
    {
        var wrapped = new DbUpdateException("fixture wrapper",
            new PostgresException("fixture", "ERROR", "ERROR", PostgresErrorCodes.QueryCanceled));
        var service = new RuntimeAuthorityKeyRegistrySnapshotService(
            new ThrowingDbFactory(wrapped),
            Options.Create(new RuntimeEnrollmentOptions { MaximumTransactionAttempts = 3 }));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.ReadCurrentAsync("registry-client", CanonicalRequest(), cancellation.Token));
    }

    /// <summary>Proves the exact route uses real PS256 S2S verification and one-shot nonce persistence.</summary>
    [Fact]
    public async Task Endpoint_UsesRealS2SAndReturnsNoStoreByteExactReadback()
    {
        const string productId = "22222222-2222-4222-8222-222222222222";
        const string clientId = "registry-client";
        const string keyId = "transport-key";
        const string path = "/api/internal/v2/runtime-enrollment-authority/key-registry-snapshots";
        var body = Encoding.UTF8.GetBytes(
            "{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"" + productId + "\"}");
        using var transport = RSA.Create(2048);
        var now = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero);
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase($"tkt789-s2s-{Guid.NewGuid():N}").Options;
        var s2s = new DistributionS2SAuthenticationService(
            new TestDbFactory(dbOptions),
            Options.Create(new DistributionS2SOptions
            {
                Clients =
                [
                    new()
                    {
                        ClientId = clientId,
                        KeyId = keyId,
                        PublicKeyPem = transport.ExportSubjectPublicKeyInfoPem(),
                        AllowRuntimeUpgrade = true,
                        ProductIds = [productId],
                        AllowedCidrs = ["127.0.0.1/32"]
                    }
                ]
            }),
            new FixedTimeProvider(now));
        var registry = new Mock<IRuntimeAuthorityKeyRegistrySnapshotService>(MockBehavior.Strict);
        registry.Setup(value => value.ReadCurrentAsync(
                clientId, It.Is<ReadOnlyMemory<byte>>(actual => actual.ToArray().SequenceEqual(body)),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync("{\"ok\":true}"u8.ToArray());
        var controller = Controller(body, s2s, registry.Object);
        AddS2SHeaders(controller.HttpContext, transport, clientId, keyId, path, body, now,
            "33333333-3333-4333-8333-333333333333");

        var result = Assert.IsType<FileContentResult>(
            await controller.ReadAuthorityKeyRegistrySnapshotV2(CancellationToken.None));

        Assert.Equal("application/json", result.ContentType);
        Assert.Equal("{\"ok\":true}"u8.ToArray(), result.FileContents);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
        Assert.Equal("no-cache", controller.Response.Headers.Pragma);
        registry.VerifyAll();

        var deniedController = Controller(body, s2s, registry.Object);
        AddS2SHeaders(deniedController.HttpContext, transport, clientId, keyId, path, body, now,
            "44444444-4444-4444-8444-444444444444");
        deniedController.Request.Headers[DistributionS2SAuthenticationService.SignatureHeader] = new string('A', 342);
        var denied = Assert.IsType<ObjectResult>(
            await deniedController.ReadAuthorityKeyRegistrySnapshotV2(CancellationToken.None));
        Assert.Equal(StatusCodes.Status401Unauthorized, denied.StatusCode);
    }

    /// <summary>Maps an endpoint-adjacent provider outage to the uniform no-store 503 envelope.</summary>
    [Fact]
    public async Task Endpoint_MapsProviderFailureToClosed503()
    {
        const string productId = "22222222-2222-4222-8222-222222222222";
        var body = Encoding.UTF8.GetBytes(
            "{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"" + productId + "\"}");
        var s2s = new Mock<IDistributionS2SAuthenticationService>();
        s2s.Setup(value => value.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), productId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("registry-client", "transport-key", false, true, false));
        var registry = new Mock<IRuntimeAuthorityKeyRegistrySnapshotService>();
        registry.Setup(value => value.ReadCurrentAsync(
                It.IsAny<string>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new NpgsqlException("fixture outage"));
        var controller = Controller(body, s2s.Object, registry.Object);

        var result = Assert.IsType<ObjectResult>(
            await controller.ReadAuthorityKeyRegistrySnapshotV2(CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
    }

    /// <summary>Requires pre-MVC 404 and 405 responses under the v2 authority prefix to remain no-store.</summary>
    [Theory]
    [InlineData("POST", "/api/internal/v2/runtime-enrollment-authority/key-registry-snapshots/missing", HttpStatusCode.NotFound)]
    [InlineData("GET", "/api/internal/v2/runtime-enrollment-authority/key-registry-snapshots", HttpStatusCode.MethodNotAllowed)]
    public async Task Endpoint_RoutingFailuresRemainNoStore(
        string method, string path, HttpStatusCode expectedStatus)
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.UseSetting("IsIntegrationTest", "true"));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        using var response = await client.SendAsync(request);

        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.Equal("no-store, max-age=0", response.Headers.CacheControl?.ToString());
        Assert.Contains(response.Headers.Pragma, value => value.Name == "no-cache");
    }

    /// <summary>Creates one exact configured public registry key for a cryptographic fixture.</summary>
    private static RuntimeAuthorityGenerationKeyOptions Key(
        string id, string purpose, string domain, RSA rsa, DateTimeOffset activated, string? privateKey) => new()
    {
        KeyId = id,
        Purpose = purpose,
        Domain = domain,
        ContractVersion = 2,
        Status = "active",
        PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
        PrivateKeyPem = privateKey,
        ActivatedAtUtc = activated
    };

    /// <summary>Creates one provider-authenticated fixture with a caller-selected recovery lifecycle.</summary>
    private static RuntimeEnrollmentOptions LifecycleOptions(
        RSA registry,
        RSA operational,
        RSA recovery,
        DateTimeOffset observed,
        string recoveryStatus,
        string? revocationCode,
        bool compromised)
    {
        var activated = observed.AddDays(-1);
        var recoveryKey = Key(
            "recovery-2026-01", "recovery", "recovery", recovery, activated, null);
        recoveryKey.Status = recoveryStatus;
        recoveryKey.RetiredAtUtc = recoveryStatus == "retired" ? observed.AddHours(-12) : null;
        recoveryKey.RevokedAtUtc = recoveryStatus == "revoked" ? observed.AddHours(-1) : null;
        recoveryKey.RevocationReason = revocationCode;
        recoveryKey.CompromiseFromUtc = compromised ? observed.AddHours(-2) : null;
        var signing = new RuntimeAuthorityGenerationSigningOptions
        {
            ActiveSigningKeyId = "operational-2026-01",
            RegistrySnapshotId = $"registry-{recoveryStatus}-{(compromised ? "compromised" : "standard")}",
            RegistrySnapshotVersion = 1,
            Keys =
            [
                Key("operational-2026-01", "operational", "generation", operational, activated,
                    operational.ExportPkcs8PrivateKeyPem()),
                recoveryKey
            ]
        };
        var cryptography = new RuntimeEnrollmentAuthorityCryptography(
            new FixedTimeProvider(observed), registry.ExportSubjectPublicKeyInfo());
        var authenticationInput = cryptography.GetRegistrySnapshotAuthenticationInput(signing, observed).Value!;
        return new()
        {
            Mode = "enabled",
            AuthorityGenerationSigning = signing,
            AuthorityGenerationV2 = new()
            {
                Mode = "enabled",
                RegistryAuthoritySpkiBase64 = Convert.ToBase64String(registry.ExportSubjectPublicKeyInfo()),
                RegistryObservedAtUtc = observed.ToString("O"),
                RegistrySnapshotSignatureBase64Url = Encode(
                    registry.SignData(authenticationInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            }
        };
    }

    /// <summary>Encodes canonical unpadded Base64Url fixture bytes.</summary>
    private static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Returns one exact canonical semantic readback request.</summary>
    private static byte[] CanonicalRequest() => Encoding.UTF8.GetBytes(
        "{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"22222222-2222-4222-8222-222222222222\"}");

    /// <summary>Adds the five exact Distribution S2S headers signed over the route and request bytes.</summary>
    private static void AddS2SHeaders(
        HttpContext context,
        RSA signingKey,
        string clientId,
        string keyId,
        string path,
        byte[] body,
        DateTimeOffset now,
        string nonce)
    {
        var timestamp = now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        var payload = DistributionS2SAuthenticationService.BuildSignaturePayload(
            clientId, keyId, HttpMethods.Post, path, timestamp, nonce, body);
        var signature = signingKey.SignData(
            Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        context.Request.Scheme = "https";
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Headers[DistributionS2SAuthenticationService.ClientHeader] = clientId;
        context.Request.Headers[DistributionS2SAuthenticationService.KeyIdHeader] = keyId;
        context.Request.Headers[DistributionS2SAuthenticationService.TimestampHeader] = timestamp;
        context.Request.Headers[DistributionS2SAuthenticationService.NonceHeader] = nonce;
        context.Request.Headers[DistributionS2SAuthenticationService.SignatureHeader] = Encode(signature);
    }

    /// <summary>Creates the real controller around exact request bytes and strict mocked boundaries.</summary>
    private static RuntimeEnrollmentsController Controller(
        byte[] body,
        IDistributionS2SAuthenticationService s2s,
        IRuntimeAuthorityKeyRegistrySnapshotService registry)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/internal/v2/runtime-enrollment-authority/key-registry-snapshots";
        context.Request.ContentType = "application/json";
        context.Request.ContentLength = body.Length;
        context.Request.Body = new MemoryStream(body);
        return new RuntimeEnrollmentsController(
            s2s,
            Mock.Of<IRuntimeEnrollmentService>(),
            Options.Create(new RuntimeEnrollmentOptions
            {
                Mode = "enabled",
                AuthorityGenerationV2 = new() { Mode = "enabled" }
            }),
            keyRegistrySnapshots: registry)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }

    /// <summary>Supplies one immutable trusted instant to existing registry cryptography.</summary>
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        /// <inheritdoc />
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>Creates independent contexts for real nonce persistence in the S2S route fixture.</summary>
    private sealed class TestDbFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);
    }

    /// <summary>Injects one deterministic provider failure before any database side effect.</summary>
    private sealed class ThrowingDbFactory(Exception failure) : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => throw failure;
    }
}

using System.Security.Cryptography;
using System.Globalization;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Models;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves signed capability deadlines never exceed exact commercial expiry, including sub-second rounding.</summary>
public sealed class RuntimeEnrollmentCapabilityExpiryTests
{
    /// <summary>A capability requested one second before expiry gets at most that second in both modern and legacy JWTs.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PaidExpiryBoundsSignedCapability(bool legacy)
    {
        using var rsa = RSA.Create(2048);
        using var crypto = Crypto(rsa);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000).AddMilliseconds(250);
        var expiry = now.AddSeconds(1);
        var bounded = RuntimeEnrollmentCryptoService.BoundCapabilityExpiry(now, expiry);
        var token = legacy
            ? crypto.SignLegacyCapability(Guid.NewGuid(), 1, 1, "https://fixture.example.test", ["runtime.execute"], new string('a', 64), now, Guid.NewGuid().ToString(), bounded)
            : crypto.SignCapability(Guid.NewGuid(), 1, 1, "fixture-install", "2.2.999", "fixture-session", [],
                "https://fixture.example.test", ["runtime.execute"], new string('a', 64), now, Guid.NewGuid().ToString(), bounded);
        var encoded = token.Split('.')[1].Replace('-', '+').Replace('_', '/');
        using var payload = JsonDocument.Parse(Convert.FromBase64String(encoded.PadRight((encoded.Length + 3) / 4 * 4, '=')));
        Assert.Equal(bounded.ToUnixTimeSeconds(), payload.RootElement.GetProperty("exp").GetInt64());
        Assert.True(bounded <= expiry);
        Assert.Equal(750, (bounded - now).TotalMilliseconds);
    }

    /// <summary>No representable future second means refusal; unlimited licenses retain the existing maximum TTL.</summary>
    [Fact]
    public void RoundingNeverExtendsExpiredOrSubsecondAuthority()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000).AddMilliseconds(250);
        Assert.Throws<RuntimeEnrollmentException>(() => RuntimeEnrollmentCryptoService.BoundCapabilityExpiry(now, now));
        Assert.Throws<RuntimeEnrollmentException>(() => RuntimeEnrollmentCryptoService.BoundCapabilityExpiry(now, now.AddMilliseconds(100)));
        Assert.Equal(now.ToUnixTimeSeconds() + 120, RuntimeEnrollmentCryptoService.BoundCapabilityExpiry(now, null).ToUnixTimeSeconds());
        Assert.Equal(now.ToUnixTimeSeconds() + 120, RuntimeEnrollmentCryptoService.BoundCapabilityExpiry(now, now.AddDays(1)).ToUnixTimeSeconds());
        Assert.False(RuntimeEnrollmentCryptoService.IsCapabilityReplayCurrent(now, now.AddMilliseconds(500), null));
        Assert.False(RuntimeEnrollmentCryptoService.IsCapabilityReplayCurrent(now, now.AddSeconds(2), now.AddSeconds(1)));
        Assert.True(RuntimeEnrollmentCryptoService.IsCapabilityReplayCurrent(now, now.AddSeconds(1), now.AddSeconds(1)));
    }

    /// <summary>Creates in-memory signing keys only; no production vault or key files are read or written.</summary>
    private static RuntimeEnrollmentCryptoService Crypto(RSA rsa) => new(Options.Create(new RuntimeEnrollmentOptions
    {
        Mode = "enabled", Issuer = "https://fixture.example.test",
        CapabilitySigning = new RuntimeCapabilitySigningOptions
        {
            ActiveKeyId = "tkt991-synthetic",
            Keys = [new RuntimeCapabilitySigningKeyOptions { KeyId = "tkt991-synthetic", Role = "active",
                PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(), PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem() }]
        },
        Encryption = new RuntimeEncryptionOptions { Keys = [] }
    }));
}

/// <summary>Reuses the real authority fixture to qualify paid expiry through the service and PG lease, not only the signer.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Current paid time bounds token/JSON identically. After frozen replay succeeds, a real committed
    /// expiry, revocation or still-future shortening must reject that same receipt without a new token.
    /// The shortening case proves denial is not merely caused by passage of the original deadline.
    /// </summary>
    [Theory]
    [InlineData("expired")]
    [InlineData("revoked")]
    [InlineData("shortened")]
    public async Task PersonalDayPassCapability_TransactionBoundsExpiryAndRejectsStaleReplay(string mutation)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory, RuntimeEnrollmentService.LegacyCapabilityReleaseVersion);
        using var signing = CreateSigningKey(ActiveSigningPrivateKey);
        using var next = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        var options = RuntimeOptions(fixture.ProductId, signing, next);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(factory, authority, registry, crypto, Options.Create(options));
        var prepare = PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey);
        prepare.Schema = RuntimeEnrollmentService.PrepareV2Schema;
        var prepared = await service.PrepareAsync("website-step1", Sha256("tkt991-prepare"), prepare);
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirm = new RuntimeEnrollmentConfirmRequest { Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion, EnrollmentId = enrollmentId.ToString("D"), Epoch = 1 };
        var confirmDigest = Sha256("tkt991-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, confirm,
            Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience, prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);
        DateTime expiry;
        Guid licenseId;
        await using (var db = await factory.CreateDbContextAsync())
        {
            licenseId = await db.DistributionInstallationBindings.Where(b => b.Id == fixture.BindingId).Select(b => b.LicenseId).SingleAsync();
            // Ninety seconds leaves room to shorten to a still-future deadline; the pure test covers one second.
            await db.Database.OpenConnectionAsync();
            var databaseNow = await RuntimeEnrollmentService.DatabaseNowAsync(db, CancellationToken.None);
            expiry = DateTimeOffset.FromUnixTimeMilliseconds(databaseNow.ToUnixTimeMilliseconds()).UtcDateTime.AddSeconds(90);
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = {expiry} WHERE \"Id\" = {licenseId}");
            // This historically used an ordinary runtime type. Establish actual pass identity so the
            // paid-bound regression stays meaningful after ordinary clients regain their 120-second TTL.
            var typeId = await db.Licenses.Where(l => l.Id == licenseId).Select(l => l.LicenseTypeId).SingleAsync();
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"LicenseTypes\" SET \"Slug\" = {PersonalDayPassPolicy.TypeSlug}, \"IsRecurring\" = true WHERE \"Id\" = {typeId}");
            var subject = Guid.NewGuid();
            db.Add(new RuntimeRecoveryCommercialSubject { Id = subject, ProductId = fixture.ProductId, CreatedAtUtc = DateTime.UtcNow });
            await db.SaveChangesAsync();
            db.Add(new PersonalDayPass { ProductId = fixture.ProductId, CommercialSubjectId = subject, LicenseId = licenseId, PaidThroughUtc = expiry });
            await db.SaveChangesAsync();
        }
        var capability = new RuntimeEnrollmentCapabilityRequest { Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion, EnrollmentId = enrollmentId.ToString("D"), Epoch = 1,
            SecurityEpoch = 1, InstallationId = fixture.InstallationId, ReleaseVersion = fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"), Audience = "https://broker.example.test", Scope = ["runtime.execute"], Binaries = CapabilityBinaries() };
        var digest = Sha256("tkt991-capability");
        var proof = Proof(enrollmentKey, "capability", enrollmentId, capability.Audience, "-", digest);
        var issued = await service.CreateCapabilityAsync(enrollmentId, digest, capability, proof, IPAddress.Loopback);
        var responseExpiry = DateTimeOffset.Parse(issued.Response.ExpiresAtUtc, CultureInfo.InvariantCulture);
        using var token = JsonDocument.Parse(DecodeBase64Url(issued.Response.CapabilityToken.Split('.')[1]));
        Assert.Equal(responseExpiry.ToUnixTimeSeconds(), token.RootElement.GetProperty("exp").GetInt64());
        Assert.Equal(new DateTimeOffset(expiry).ToUnixTimeSeconds(), responseExpiry.ToUnixTimeSeconds());
        var replay = await service.CreateCapabilityAsync(enrollmentId, digest, capability, proof, IPAddress.Loopback);
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.ExactResponseBody, replay.ExactResponseBody);
        await using (var db = await factory.CreateDbContextAsync())
        {
            if (mutation == "revoked")
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevokedAt\" = now(), \"RevocationReason\" = 'tkt991-synthetic-revocation' WHERE \"Id\" = {licenseId}");
            else if (mutation == "shortened")
            {
                var shortened = responseExpiry.AddSeconds(-30).UtcDateTime;
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = {shortened} WHERE \"Id\" = {licenseId}");
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"PersonalDayPasses\" SET \"PaidThroughUtc\" = {shortened} WHERE \"LicenseId\" = {licenseId}");
                var observed = await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == licenseId);
                Assert.True(observed.IsActive);
                Assert.Null(observed.RevokedAt);
                Assert.True(observed.ExpirationDate > DateTime.UtcNow);
                Assert.True(observed.ExpirationDate < responseExpiry.UtcDateTime);
            }
            else
                await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = now() - interval '1 second' WHERE \"Id\" = {licenseId}");
        }
        var rejected = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.CreateCapabilityAsync(enrollmentId, digest, capability, proof, IPAddress.Loopback));
        Assert.Equal(mutation == "shortened" ? "capability_expired" : "authority_ineligible", rejected.ErrorCode);
    }
}

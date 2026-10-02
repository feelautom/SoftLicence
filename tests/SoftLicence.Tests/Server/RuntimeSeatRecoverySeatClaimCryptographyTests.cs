using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies the W8 nonce collision budget independently from provider state.</summary>
public sealed class RuntimeSeatRecoverySeatClaimCryptographyTests
{
    /// <summary>Proves a collision is retried and the successful candidate is reserved before encryption.</summary>
    [Fact]
    public async Task ReserveNonceAsync_CollisionThenSuccess_UsesSecondCandidate()
    {
        var first = Enumerable.Repeat((byte)0xa0, 12).ToArray();
        var second = Enumerable.Repeat((byte)0xb0, 12).ToArray();
        var reservations = new Queue<bool>([false, true]);
        var candidates = new Queue<byte[]>([first, second]);
        var service = new RuntimeSeatRecoverySeatClaimCryptography(
            (_, _, _, _) => Task.FromResult(reservations.Dequeue()),
            destination => candidates.Dequeue().CopyTo(destination));

        var nonce = await service.ReserveNonceAsync("seat-claim-key", Guid.NewGuid(), CancellationToken.None);

        Assert.Equal(second, nonce);
        Assert.Empty(reservations);
    }

    /// <summary>Proves exactly eight collisions fail closed without returning a reusable candidate.</summary>
    [Fact]
    public async Task ReserveNonceAsync_EightCollisions_FailsClosed()
    {
        var attempts = 0;
        var service = new RuntimeSeatRecoverySeatClaimCryptography(
            (_, _, _, _) => { attempts++; return Task.FromResult(false); },
            destination => destination.Fill(0x42));

        await Assert.ThrowsAsync<RuntimeSeatRecoveryCryptographyException>(() =>
            service.ReserveNonceAsync("seat-claim-key", Guid.NewGuid(), CancellationToken.None));
        Assert.Equal(8, attempts);
    }

    /// <summary>Proves a reserved nonce is owner-bound and the exact authenticated frame opens successfully.</summary>
    [Fact]
    public async Task SealAndOpen_ValidCanonicalClaim_RoundTripsAndPreservesOwner()
    {
        var key = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var options = new RuntimeEnrollmentOptions
        {
            Encryption = new RuntimeEncryptionOptions
            {
                ActiveKeyId = "seat-claim-key",
                Keys = [new() { KeyId = "seat-claim-key", KeyBase64 = Convert.ToBase64String(key) }]
            }
        };
        var expectedOwner = Guid.Parse("018f6fd4-2222-7222-8222-222222222222");
        Guid observedOwner = Guid.Empty;
        var service = new RuntimeSeatRecoverySeatClaimCryptography(options,
            (_, _, ownerId, _) => { observedOwner = ownerId; return Task.FromResult(true); },
            destination => destination.Fill(0x42));
        var claim = new RuntimeSeatRecoverySeatClaimPlaintext
        {
            Version = 1,
            Purpose = "runtime_identity_recovery_seat_selection",
            OwnerSubjectRefDigestSha256 = new('a', 64),
            ProductId = "018f6fd4-94b2-7f7e-8f47-13eb8aab8b11",
            LicenseId = "018f6fd4-1111-7111-8111-111111111111",
            SeatId = "018f6fd4-edf5-7524-9c37-1ae1a3764401",
            SeatRevision = 638920800000000000,
            IssuedAtUtc = "2026-08-29T05:55:00.000000Z",
            ExpiresAtUtc = "2026-08-29T06:00:00.000000Z",
            Nonce = "018f6fd4-3333-7333-8333-333333333333"
        };

        var token = await service.SealAsync(claim, expectedOwner, CancellationToken.None);
        var opened = service.Open(token);

        Assert.Equal(expectedOwner, observedOwner);
        Assert.NotNull(opened);
        Assert.Equal(claim.SeatId, opened.SeatId);
        Assert.Equal(claim.Nonce, opened.Nonce);
    }

    /// <summary>Proves a forged AEAD frame does not disclose whether key selection or authentication failed.</summary>
    [Fact]
    public async Task Open_ForgedTag_FailsClosed()
    {
        var options = new RuntimeEnrollmentOptions
        {
            Encryption = new RuntimeEncryptionOptions
            {
                ActiveKeyId = "k",
                Keys = [new() { KeyId = "k", KeyBase64 = Convert.ToBase64String(new byte[32]) }]
            }
        };
        var service = new RuntimeSeatRecoverySeatClaimCryptography(options,
            (_, _, _, _) => Task.FromResult(true), destination => destination.Fill(0x01));
        var token = await service.SealAsync(new RuntimeSeatRecoverySeatClaimPlaintext
        {
            Version = 1, Purpose = "runtime_identity_recovery_seat_selection",
            OwnerSubjectRefDigestSha256 = new('a', 64),
            ProductId = "018f6fd4-94b2-7f7e-8f47-13eb8aab8b11",
            LicenseId = "018f6fd4-1111-7111-8111-111111111111",
            SeatId = "018f6fd4-edf5-7524-9c37-1ae1a3764401", SeatRevision = 1,
            IssuedAtUtc = "2026-08-29T05:55:00.000000Z", ExpiresAtUtc = "2026-08-29T06:00:00.000000Z",
            Nonce = "018f6fd4-3333-7333-8333-333333333333"
        }, Guid.NewGuid(), CancellationToken.None);
        var padded = token.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty };
        var bytes = Convert.FromBase64String(padded);
        bytes[^1] ^= 0x01;
        var forged = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.Null(service.Open(forged));
    }
}

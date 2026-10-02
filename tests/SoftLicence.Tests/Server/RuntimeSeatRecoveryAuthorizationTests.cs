using System.Security.Cryptography;
using System.Text;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies frozen authorization material and exact W9 current-readback bytes.</summary>
public sealed class RuntimeSeatRecoveryAuthorizationTests
{
    /// <summary>Reproduces the normative W9 conflict literal without reserializing any opaque grant spelling.</summary>
    [Fact]
    public void SerializeReadback_W9ConflictFixture_HasExactLengthAndDigest()
    {
        var requestId = Guid.Parse("018f6fd4-fe06-75d7-ae93-b15d36ca5501");
        var recoveryRef = Guid.Parse("018f6fd4-7a01-7b01-8c01-0123456789ab");
        var reservationRef = Guid.Parse("018f6fd4-2222-7222-8222-222222222222");
        var ledger = new RuntimeSeatRecoveryAuthorization
        {
            AuthenticatedClientId = "website-recovery", RequestId = requestId,
            RequestDigestSha256 = "8fd3ff4e488e651ba3945e7e5d10fa3cdaf57cf3647159acd7cd439828ca673f",
            RecoveryOperationRef = recoveryRef, RecoveryDigestSha256 = new('a', 64),
            CanonicalRequestUtf8 = "{}"u8.ToArray(), ReservationRef = reservationRef,
            Decision = "AUTHORIZED", HttpStatusCode = 200, ContentType = "application/json; charset=utf-8",
            ExactResponseUtf8 = "{}"u8.ToArray(), CompletedAtUtc = Utc("2026-08-29T05:50:00.000000Z")
        };
        var reservation = new RuntimeSeatRecoveryReservation
        {
            ReservationRef = reservationRef, AuthenticatedClientId = "website-recovery", RequestId = requestId,
            ProductId = Guid.Parse("018f6fd4-94b2-7f7e-8f47-13eb8aab8b11"),
            LicenseId = Guid.Parse("018f6fd4-1111-7111-8111-111111111111"),
            LicenseSeatId = Guid.Parse("018f6fd4-edf5-7524-9c37-1ae1a3764401"),
            RecoveryOperationRef = recoveryRef, ProviderGrantRef = "grant:tenant-a:café:🚀",
            State = "COMMITTED", CreatedAtUtc = Utc("2026-08-29T05:50:00.000000Z"),
            ExpiresAtUtc = Utc("2026-08-29T06:00:00.000000Z")
        };
        var authority = new RuntimeSeatRecoveryAuthority
        {
            ReservationRef = reservationRef,
            AuthorityLineageId = Guid.Parse("018f6fd4-8f31-7cc2-8d19-9e79c8b87a01"),
            AuthorityGenerationId = Guid.Parse("018f6fd4-aad1-7a27-91fe-fec30a9ff201"),
            PreviousAuthorityGenerationId = Guid.NewGuid(),
            BindingId = Guid.Parse("018f6fd4-bbc2-7467-a238-0bf114bb3101"),
            EnrollmentId = Guid.Parse("018f6fd4-cbd3-7d7d-b8db-a905a7786201"),
            InstallationId = Guid.Parse("018f6fd4-dce4-7b2a-8202-5846e80d1301"),
            HardwareIdDigestSha256 = new('2', 64), ReleaseVersion = "2.3.445",
            ArtifactSetDigestSha256 = new('1', 64),
            PublicKeySpkiSha256 = "c61e282a88aa590621c577f7ffb08a92a2e057eb73813d73c1759c21c1f31b69",
            KeyThumbprint = "xh4oKoiqWQYhxXf3_7CKkqLgV-tzgT1zwXWcIcHzG2k",
            State = "PREPARED", IsCurrentHead = true, PreviousAuthorityState = "ACTIVE",
            SubjectRefDigestSha256 = "18ac38124f8e5dbb83a2d1805ecd7d362ea035cab30f02ccce0493bfca456e32",
            CreatedAtUtc = Utc("2026-08-29T05:50:00.000000Z")
        };

        var bytes = RuntimeSeatRecoveryAuthorizationService.SerializeReadback(
            "conflict", ledger, reservation, authority, Utc("2026-08-29T05:58:00.000000Z"));

        Assert.Equal(1555, bytes.Length);
        Assert.Equal("86fbd6cc8df13f1cf2af6531652f2110597452a5f745b11b2453922f93c31e24",
            Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    /// <summary>
    /// Proves recovery response writers preserve opaque NFC/NFD and non-BMP scalars while applying
    /// the exact W5 quote, backslash, slash, NEL, line-separator, and paragraph-separator table.
    /// </summary>
    [Fact]
    public void SerializeReadback_OpaqueGrant_UsesExactW5RuneEscaping()
    {
        var value = "quote:\"|slash:/|backslash:\\|rocket:🚀|nel:\u0085|ls:\u2028|ps:\u2029|nfd:cafe\u0301";

        var json = Encoding.UTF8.GetString(SerializeReadbackWithGrant(value));

        Assert.Contains(
            "\"providerGrantRef\":\"quote:\\\"|slash:/|backslash:\\\\|rocket:🚀|nel:\\u0085|ls:\\u2028|ps:\\u2029|nfd:cafe\u0301\"",
            json,
            StringComparison.Ordinal);
    }

    /// <summary>Proves the Rune writer refuses an isolated UTF-16 surrogate instead of repairing it.</summary>
    [Fact]
    public void SerializeReadback_IsolatedSurrogate_FailsClosed()
    {
        var invalid = new string('\ud800', 1);

        Assert.Throws<InvalidOperationException>(() => SerializeReadbackWithGrant(invalid));
    }

    /// <summary>
    /// Serializes a minimal readback fixture so writer tests observe the real response path without
    /// requiring persistence or changing any provider lifecycle state.
    /// </summary>
    private static byte[] SerializeReadbackWithGrant(string providerGrantRef)
    {
        var requestId = Guid.NewGuid();
        var recoveryRef = Guid.NewGuid();
        var reservationRef = Guid.NewGuid();
        return RuntimeSeatRecoveryAuthorizationService.SerializeReadback(
            "compatible",
            new RuntimeSeatRecoveryAuthorization
            {
                RequestId = requestId,
                RequestDigestSha256 = new string('a', 64),
                RecoveryOperationRef = recoveryRef
            },
            new RuntimeSeatRecoveryReservation
            {
                ReservationRef = reservationRef,
                ProductId = Guid.NewGuid(),
                LicenseId = Guid.NewGuid(),
                LicenseSeatId = Guid.NewGuid(),
                ProviderGrantRef = providerGrantRef,
                State = "RESERVED",
                ExpiresAtUtc = Utc("2026-08-29T06:00:00.000000Z")
            },
            new RuntimeSeatRecoveryAuthority
            {
                AuthorityLineageId = Guid.NewGuid(),
                AuthorityGenerationId = Guid.NewGuid(),
                BindingId = Guid.NewGuid(),
                EnrollmentId = Guid.NewGuid(),
                InstallationId = Guid.NewGuid(),
                State = "PREPARED",
                IsCurrentHead = true,
                PreviousAuthorityState = "ACTIVE"
            },
            Utc("2026-08-29T05:58:00.000000Z"));
    }

    /// <summary>Parses one canonical seven-component UTC fixture.</summary>
    private static DateTime Utc(string value) => DateTime.Parse(value, null,
        System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);
}

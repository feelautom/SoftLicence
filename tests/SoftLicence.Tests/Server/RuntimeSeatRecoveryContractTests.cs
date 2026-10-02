using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies the exact W9 authorization bytes and total current-readback classifier.</summary>
public sealed class RuntimeSeatRecoveryContractTests
{
    private const string GoldenRequest = "{\"schema\":\"runtime-seat-recovery-authorization-v1\",\"contractVersion\":1,\"requestId\":\"018f6fd4-fe06-75d7-ae93-b15d36ca5501\",\"recoveryOperationRef\":\"018f6fd4-7a01-7b01-8c01-0123456789ab\",\"recoveryDigestSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"provider\":\"softlicence\",\"providerGrantRef\":\"grant:tenant-a:café:🚀\",\"productId\":\"018f6fd4-94b2-7f7e-8f47-13eb8aab8b11\",\"licenseId\":\"018f6fd4-1111-7111-8111-111111111111\",\"seatClaim\":null,\"installation\":{\"installationId\":\"018f6fd4-dce4-7b2a-8202-5846e80d1301\",\"hardwareIdDigestSha256\":\"2222222222222222222222222222222222222222222222222222222222222222\"},\"release\":{\"version\":\"2.3.445\",\"artifactSetDigestSha256\":\"1111111111111111111111111111111111111111111111111111111111111111\"},\"newKeyCommitment\":{\"algorithm\":\"PS256\",\"publicKeySpkiSha256\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"keyThumbprint\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"},\"expiresAtUtc\":\"2026-08-29T06:00:00.000000Z\"}";
    private const string GoldenActivation = "{\"schema\":\"runtime-seat-recovery-activation-v1\",\"contractVersion\":1,\"productId\":\"018f6fd4-94b2-7f7e-8f47-13eb8aab8b11\",\"requestId\":\"018f6fd4-fe06-75d7-ae93-b15d36ca5501\",\"requestDigestSha256\":\"8fd3ff4e488e651ba3945e7e5d10fa3cdaf57cf3647159acd7cd439828ca673f\",\"recoveryOperationRef\":\"018f6fd4-7a01-7b01-8c01-0123456789ab\",\"reservationRef\":\"018f6fd4-2222-7222-8222-222222222222\",\"prepareRef\":\"018f6fd4-3333-7333-8333-333333333333\",\"confirmationRequestSha256\":\"c01d405243909bdd8a5ef406c8f770bd9971704329a178aa8925a64bb9210d3c\"}";
    private const string GoldenActivationReadback = "{\"schema\":\"runtime-seat-recovery-activation-readback-v1\",\"contractVersion\":1,\"productId\":\"018f6fd4-94b2-7f7e-8f47-13eb8aab8b11\",\"requestId\":\"018f6fd4-fe06-75d7-ae93-b15d36ca5501\",\"activationRequestDigestSha256\":\"bae81092c2d43c157d9853dc6481c5a0101f93aad3d1644861b1be230e834b6b\"}";
    private const string LegacyRsa2048Spki = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvZ6j5v+neDbMXkfA/s9H8TwuY9HY+cprNq5xIF4F8Ycgie8qVACFHQ7V5p2gMR3WFI5eGtxO8555CfeysYRE3GZtV5wqWXQyAuoJk7/LaiswfAspPXOX2qDkseM95B+DGBZsMsTu+uHWn2ysl2rlxBx1U7ukeBKFmYuLee9TArMU9w8YYpGhAFWtInleI9SRjGzaofJeR0mQiXaIpPkts8Fl9OuhZcXOVbr3N8RkQehfvwtFd0oCenAMDTOFCsl6xXMoYVdXwcC5XlCnL6iomTBuK7vsDWcEObNEr5ft2SUTo2ko+5NqqPn8OCZhP7OSGBNWwEBRm4OW1+arGBIbJQIDAQAB";
    private const string GoldenSpki = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxW+mqSGN5x5zbsqcPq2no2tgcC2baYidJHp+6c7CStL6pqFycYXmntGB/WFzds+H10SaGCwbEJPj4OutObzHFrucxSDcpIuRYvulif4So67Dh9PhAK3kJ/jhwv0Ojr/Q4kmcOlcaU1TOf5yWAorJLqQdHBYlCJLzuq5k8W1Wr6XsdOZINslzJAKCMFoUlnSdeTrgDD2jstND/cwZ9ageqzvXHxYJN71rjTUVWSMK1zVi3ghc4KAEIbxfoLqMcyadKW+49tUGHwNyuv00oDJpQ7fgcEqdPYtZIiPD8OtUqhz1M0JBlEeDDVYS8skn4UBv7nIGuxXdp9XgFnH3NuiTZnPnCzgWCzuyzMJzzACK7l5xLkWZ+keZjewnaKOnWD825qXTClpNPqi2p7Nq/+kQnziXv27RhyRbzUTS2kkuGy1m5SoUywlOxC6DEBuAqGJ/ZBC2B72OjS15y/V9RkOlsFiJ0AYyp0H1MMGENeeQnbgtUm0KOAll8ZPFBRtYWkpJAgMBAAE=";
    private const string GoldenPreparation = "{\"schema\":\"runtime-seat-recovery-key-prepare-v1\",\"contractVersion\":1,\"productId\":\"018f6fd4-94b2-7f7e-8f47-13eb8aab8b11\",\"requestId\":\"018f6fd4-fe06-75d7-ae93-b15d36ca5501\",\"requestDigestSha256\":\"8fd3ff4e488e651ba3945e7e5d10fa3cdaf57cf3647159acd7cd439828ca673f\",\"recoveryOperationRef\":\"018f6fd4-7a01-7b01-8c01-0123456789ab\",\"reservationRef\":\"018f6fd4-2222-7222-8222-222222222222\",\"enrollmentId\":\"018f6fd4-cbd3-7d7d-b8db-a905a7786201\",\"authorityGenerationId\":\"018f6fd4-aad1-7a27-91fe-fec30a9ff201\",\"publicKeySpki\":\"" + GoldenSpki + "\"}";
    private const string GoldenConfirmation = "{\"schema\":\"runtime-seat-recovery-key-confirmation-request-v1\",\"contractVersion\":1,\"productId\":\"018f6fd4-94b2-7f7e-8f47-13eb8aab8b11\",\"requestId\":\"018f6fd4-fe06-75d7-ae93-b15d36ca5501\",\"requestDigestSha256\":\"8fd3ff4e488e651ba3945e7e5d10fa3cdaf57cf3647159acd7cd439828ca673f\",\"recoveryOperationRef\":\"018f6fd4-7a01-7b01-8c01-0123456789ab\",\"reservationRef\":\"018f6fd4-2222-7222-8222-222222222222\",\"prepareRef\":\"018f6fd4-3333-7333-8333-333333333333\",\"enrollmentId\":\"018f6fd4-cbd3-7d7d-b8db-a905a7786201\",\"authorityGenerationId\":\"018f6fd4-aad1-7a27-91fe-fec30a9ff201\",\"publicKeySpkiSha256\":\"2cae535b4dba62dd646446ac029d21fbbf75ae9520f6f2a8c1d9070ed0a1c9f4\",\"confirmationStatement\":{\"schema\":\"runtime-seat-recovery-key-confirmation-v1\",\"contractVersion\":1,\"prepareRef\":\"018f6fd4-3333-7333-8333-333333333333\",\"requestId\":\"018f6fd4-fe06-75d7-ae93-b15d36ca5501\",\"requestDigestSha256\":\"8fd3ff4e488e651ba3945e7e5d10fa3cdaf57cf3647159acd7cd439828ca673f\",\"recoveryOperationRef\":\"018f6fd4-7a01-7b01-8c01-0123456789ab\",\"reservationRef\":\"018f6fd4-2222-7222-8222-222222222222\",\"enrollmentId\":\"018f6fd4-cbd3-7d7d-b8db-a905a7786201\",\"authorityGenerationId\":\"018f6fd4-aad1-7a27-91fe-fec30a9ff201\",\"challenge\":\"0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u8\",\"confirmAudience\":\"softlicence:runtime-identity-recovery:confirm:v1\"},\"confirmationAlgorithm\":\"PS256\",\"confirmationSignature\":\"A2luSeShwFdjdN_abZ47CEWeDr80D_Q0ycOZJkVTmHzRpH-rBlZgqIztHxFxCqrb73VKDVo8A2Q863plTLu-ICcAflt5vXRwLigo-kRsN7n_JKIZy8VL1avGrOaDkwAGAiXduQ2dCHfFzWVbNti8arOf0p8caeb2AX8T9297qw7T7IaVFRaSTxbZIUeREYIJyfk7FDOLDvnSF4Wxhy3ySv5N7ye5rBpI9PeNhd8EDj8faUyd8_qqAFU0IwJ2bZzVx6nnZaIdH5nzmbnejdVHUdbm64HaXoZiZ66dVdyVmkHAH5Nv1QcLQMCDxgsAwezEFmkwNev6c_JlSkKAOTnAirhF0Q-Ck09hDXhpPoKXnEGx7oFQHqmZ1b8KnVmmLqIQ0cCsdrsw4dfW5xUpe8omPn0SEr-rMaOr15EwXbSh6I5FCIYP8mEACw4lbB3QuvX-45wXpE9TIB80FYZUq0voqJDxBd8TZtVGuY_4QUqcnPDDpkpJLm7WG8U0jbK1AI7O\"}";

    /// <summary>Proves W10 product scope and the W8 raw statement remain byte-exact.</summary>
    [Fact]
    public void ParseKeyProofGoldens_ReturnsExactW10BytesAndDigests()
    {
        var preparation = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(
            Encoding.UTF8.GetBytes(GoldenPreparation));
        var confirmation = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(
            Encoding.UTF8.GetBytes(GoldenConfirmation));

        Assert.True(preparation.IsSuccess, preparation.ErrorCode);
        Assert.Equal(1078, preparation.CanonicalUtf8.Length);
        Assert.Equal("31e50b39db30e95a89b3b203b4780c76126fdceeacbba9a008f028bfb22149ca",
            Convert.ToHexStringLower(SHA256.HashData(preparation.CanonicalUtf8)));
        Assert.True(confirmation.IsSuccess, confirmation.ErrorCode);
        Assert.Equal(1873, confirmation.CanonicalUtf8.Length);
        Assert.Equal("1b436fc62fed5891de664e60c608472524807b5b635b2b14adffb0b97b83cd41",
            confirmation.ConfirmationRequestSha256);
        Assert.Equal(628, confirmation.ConfirmationStatementUtf8.Length);
        Assert.Equal("b396b7324be87359380c205d61556f4d1be25170776686dc027ed37a1d28ee68",
            Convert.ToHexStringLower(SHA256.HashData(confirmation.ConfirmationStatementUtf8)));
        Assert.Equal("dfd852dbf98a0b304f56b078d5247aa738ae55d8ccedbd8fc940c5b93866f6e9",
            Convert.ToHexStringLower(SHA256.HashData(
                RuntimeSeatRecoveryContractCodec.BuildConfirmationSignatureInput(
                    confirmation.ConfirmationStatementUtf8))));
        using var document = JsonDocument.Parse(GoldenConfirmation);
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(GoldenSpki), out var consumed);
        var signature = RuntimeSeatRecoveryContractCodec.DecodeBase64Url(
            document.RootElement.GetProperty("confirmationSignature").GetString()!);
        Assert.Equal(422, consumed);
        Assert.Equal(3072, rsa.KeySize);
        Assert.NotNull(signature);
        Assert.Equal(384, signature.Length);
        Assert.True(rsa.VerifyData(
            RuntimeSeatRecoveryContractCodec.BuildConfirmationSignatureInput(
                confirmation.ConfirmationStatementUtf8),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
    }

    /// <summary>Proves the legacy RSA-2048 preparation and 342-character signature receive no fallback.</summary>
    [Fact]
    public void ParseKeyProofLegacyRsa2048Goldens_ReturnClosedInvalidRequest()
    {
        using var confirmationDocument = JsonDocument.Parse(GoldenConfirmation);
        var signature = confirmationDocument.RootElement.GetProperty("confirmationSignature").GetString()!;
        var legacyPreparation = GoldenPreparation.Replace(GoldenSpki, LegacyRsa2048Spki, StringComparison.Ordinal);
        var legacyConfirmation = GoldenConfirmation
            .Replace("2cae535b4dba62dd646446ac029d21fbbf75ae9520f6f2a8c1d9070ed0a1c9f4",
                "c61e282a88aa590621c577f7ffb08a92a2e057eb73813d73c1759c21c1f31b69", StringComparison.Ordinal)
            .Replace(signature, new string('A', 342), StringComparison.Ordinal);

        var preparation = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(
            Encoding.UTF8.GetBytes(legacyPreparation));
        var confirmation = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(
            Encoding.UTF8.GetBytes(legacyConfirmation));

        Assert.Equal(906, Encoding.UTF8.GetByteCount(legacyPreparation));
        Assert.Equal(1703, Encoding.UTF8.GetByteCount(legacyConfirmation));
        Assert.False(preparation.IsSuccess);
        Assert.Equal("invalid_request", preparation.ErrorCode);
        Assert.False(confirmation.IsSuccess);
        Assert.Equal("invalid_request", confirmation.ErrorCode);
    }

    /// <summary>Proves the activation command and readback retain their normative exact bytes and digest.</summary>
    [Fact]
    public void ParseActivationGoldens_ReturnExactContractVectors()
    {
        var activation = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(
            Encoding.UTF8.GetBytes(GoldenActivation));
        var readback = RuntimeSeatRecoveryContractCodec.ParseActivationReadbackRequest(
            Encoding.UTF8.GetBytes(GoldenActivationReadback));

        Assert.True(activation.IsSuccess, activation.ErrorCode);
        Assert.Equal(524, activation.CanonicalUtf8.Length);
        Assert.Equal("b92a4d5f4143239d9455575372c0d77d6fa0a26cae958be586d36c37525abc3f",
            Convert.ToHexStringLower(SHA256.HashData(activation.CanonicalUtf8)));
        Assert.Equal("bae81092c2d43c157d9853dc6481c5a0101f93aad3d1644861b1be230e834b6b",
            activation.ActivationRequestDigestSha256);
        Assert.True(readback.IsSuccess, readback.ErrorCode);
        Assert.Equal("2f1be924031469ebefd045b40df88c95ca5d8f602c0020dba8d43582aa3ad696",
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(GoldenActivationReadback))));
        Assert.DoesNotContain("Jti", typeof(RuntimeSeatRecoveryActivationRequest).GetProperties()
            .Select(property => property.Name));
        Assert.DoesNotContain("ActivationRef", typeof(RuntimeSeatRecoveryActivationRequest).GetProperties()
            .Select(property => property.Name));
    }

    /// <summary>Proves positive, expired, and conflict activation terminals match every published golden.</summary>
    [Fact]
    public void SerializeActivationTerminals_ReturnExactGoldenVectors()
    {
        var parsed = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(
            Encoding.UTF8.GetBytes(GoldenActivation));
        var proof = new RuntimeSeatRecoveryProofReceipt
        {
            ExpiresAtUtc = Utc("2026-08-29T05:55:00.0000000Z")
        };
        var reservation = new RuntimeSeatRecoveryReservation
        {
            ReservationRef = Guid.Parse("018f6fd4-2222-7222-8222-222222222222")
        };
        var authority = new RuntimeSeatRecoveryAuthority
        {
            PreviousAuthorityLineageId = Guid.Parse("018f6fd4-aad1-7a27-91fe-fec30a9ff100"),
            PreviousAuthorityGenerationId = Guid.Parse("018f6fd4-aad1-7a27-91fe-fec30a9ff101"),
            AuthorityLineageId = Guid.Parse("018f6fd4-aad1-7a27-91fe-fec30a9ff200"),
            AuthorityGenerationId = Guid.Parse("018f6fd4-aad1-7a27-91fe-fec30a9ff201"),
            EnrollmentId = Guid.Parse("018f6fd4-cbd3-7d7d-b8db-a905a7786201")
        };
        var scope = new RuntimeSeatRecoveryAuthorizationService.ActivationScope(
            proof, reservation, authority, true);

        var success = RuntimeSeatRecoveryAuthorizationService.SerializeActivationResponse(parsed.Request!,
            parsed.ActivationRequestDigestSha256!, scope, Utc("2026-08-29T05:54:00.0000000Z"));
        var expired = RuntimeSeatRecoveryAuthorizationService.SerializeActivationError(parsed.Request!,
            parsed.ActivationRequestDigestSha256!, "activation_expired", Utc("2026-08-29T05:55:00.0000000Z"));
        var conflict = RuntimeSeatRecoveryAuthorizationService.SerializeActivationError(parsed.Request!,
            parsed.ActivationRequestDigestSha256!, "activation_conflict", Utc("2026-08-29T05:55:00.0000000Z"));

        AssertVector(success, 1215, "7a0aebc5cf4a2b4383a225f226d9b10da703e777051f6cd43f134a69e66a0b45");
        AssertVector(expired, 375, "0738d7e2126b2106ca64167ce616111d1f94f6a85a64c2bb8099ddbc90b2402f");
        AssertVector(conflict, 376, "c45a7125507e7b721b5ea414bd871b23e06ad3f75434c5958689bbe747210034");
    }

    /// <summary>Proves alternate JSON spelling, member order, and unknown members never gain identity.</summary>
    [Theory]
    [InlineData("unknown")]
    [InlineData("order")]
    [InlineData("whitespace")]
    [InlineData("unicode")]
    public void ParseActivation_NonCanonicalWire_IsInvalidRequest(string mutation)
    {
        var value = mutation switch
        {
            "unknown" => GoldenActivation.Replace("{\"schema\"", "{\"extra\":1,\"schema\"", StringComparison.Ordinal),
            "order" => GoldenActivation.Replace("\"schema\":\"runtime-seat-recovery-activation-v1\",\"contractVersion\":1",
                "\"contractVersion\":1,\"schema\":\"runtime-seat-recovery-activation-v1\"", StringComparison.Ordinal),
            "whitespace" => GoldenActivation + "\n",
            _ => GoldenActivation.Replace("runtime-seat", "runtime\\u002dseat", StringComparison.Ordinal)
        };

        var result = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(Encoding.UTF8.GetBytes(value));

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_request", result.ErrorCode);
    }

    /// <summary>Proves an invented JTI is an unknown property and never enters the provider model.</summary>
    [Fact]
    public void ParseKeyConfirmation_AdditionalJti_IsClosedInvalidRequest()
    {
        var withJti = GoldenConfirmation.Replace(
            "\"prepareRef\":\"018f6fd4-3333-7333-8333-333333333333\",\"enrollmentId\"",
            "\"prepareRef\":\"018f6fd4-3333-7333-8333-333333333333\",\"jti\":\"018f6fd4-4444-7444-8444-444444444444\",\"enrollmentId\"",
            StringComparison.Ordinal);

        var result = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(Encoding.UTF8.GetBytes(withJti));

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_request", result.ErrorCode);
        Assert.DoesNotContain("Jti", typeof(RuntimeSeatRecoveryKeyConfirmationRequest).GetProperties()
            .Select(property => property.Name));
    }

    /// <summary>Proves W10.2 G1 and N1-N4 use the canonical seven-digit proof wire.</summary>
    [Fact]
    public void SerializeProofResponse_W10Point2Corpus_IsByteExact()
    {
        var parsed = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(
            Encoding.UTF8.GetBytes(GoldenConfirmation));
        var bytes = RuntimeSeatRecoveryAuthorizationService.SerializeProofResponse(parsed.Request!, 1,
            parsed.ConfirmationRequestSha256!, Utc("2026-08-29T05:53:00.0000000Z"),
            Utc("2026-08-29T05:55:00.0000000Z"));
        var body = Encoding.UTF8.GetString(bytes);

        AssertVector(bytes, 872, "ec19f6159f6959811db9f03d2610fac9110dd0541fbefd53d531ce7b3d2650cf");
        AssertVector(Encoding.UTF8.GetBytes(body.Replace(
            ",\"expiresAtUtc\":\"2026-08-29T05:55:00.0000000Z\"", string.Empty, StringComparison.Ordinal)),
            826, "99bade4dc51dc56229a5e9b012f8fa7a181c63e85e53752e29b3fd03bbe7b7b3");
        AssertVector(Encoding.UTF8.GetBytes(body.Replace("05:55:00.0000000Z", "06:00:00.0000000Z", StringComparison.Ordinal)),
            872, "b13bb5b8fb1d747ae13adfa4a54139f0050e73448699bb632f05229c64cce229");
        AssertVector(Encoding.UTF8.GetBytes(body.Replace("05:55:00.0000000Z", "05:55:00.000000Z", StringComparison.Ordinal)),
            871, "8d91143faeaa7e44fb73f01b49591d627bdbe3034101863c882c650ac20a94c8");
        AssertVector(Encoding.UTF8.GetBytes(body.Replace("05:53:00.0000000Z", "05:55:00.0000000Z", StringComparison.Ordinal)),
            872, "0b640f03f263b6a4fbde72abffa95eaf6c18bc70a4dbece77060a1d64e6f8c09");
    }

    /// <summary>Proves W10 freezes the same positive signed-generation epoch in canonical member order.</summary>
    [Fact]
    public void SerializeKeyPreparationResponse_W10Corpus_IsByteExact()
    {
        var parsed = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(
            Encoding.UTF8.GetBytes(GoldenPreparation));

        var bytes = RuntimeSeatRecoveryAuthorizationService.SerializeKeyPreparationResponse(
            parsed.Request!, Guid.Parse("018f6fd4-3333-7333-8333-333333333333"), 1,
            "0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u8", Utc("2026-08-29T05:55:00.0000000Z"));

        AssertVector(bytes, 715, "a0285c8dc379abc212a3c284e32cb98ef0b8f5a60f55bae848af79d6283ee09f");
        Assert.Contains(
            "\"authorityGenerationId\":\"018f6fd4-aad1-7a27-91fe-fec30a9ff201\",\"securityEpoch\":1,\"challenge\"",
            Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
    }

    /// <summary>Proves W10/W10.2 accept the closed Int32 maximum and reject every non-positive epoch.</summary>
    [Fact]
    public void SerializeKeyProofResponses_SecurityEpochBoundsAreClosed()
    {
        var preparation = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(
            Encoding.UTF8.GetBytes(GoldenPreparation));
        var confirmation = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(
            Encoding.UTF8.GetBytes(GoldenConfirmation));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            RuntimeSeatRecoveryAuthorizationService.SerializeKeyPreparationResponse(
                preparation.Request!, Guid.Parse("018f6fd4-3333-7333-8333-333333333333"), 0,
                "0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u8", Utc("2026-08-29T05:55:00.0000000Z")));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            RuntimeSeatRecoveryAuthorizationService.SerializeProofResponse(
                confirmation.Request!, -1, confirmation.ConfirmationRequestSha256!,
                Utc("2026-08-29T05:53:00.0000000Z"), Utc("2026-08-29T05:55:00.0000000Z")));

        var maximumPreparation = RuntimeSeatRecoveryAuthorizationService.SerializeKeyPreparationResponse(
            preparation.Request!, Guid.Parse("018f6fd4-3333-7333-8333-333333333333"), int.MaxValue,
            "0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u8", Utc("2026-08-29T05:55:00.0000000Z"));
        var maximumProof = RuntimeSeatRecoveryAuthorizationService.SerializeProofResponse(
            confirmation.Request!, int.MaxValue, confirmation.ConfirmationRequestSha256!,
            Utc("2026-08-29T05:53:00.0000000Z"), Utc("2026-08-29T05:55:00.0000000Z"));
        Assert.Contains("\"securityEpoch\":2147483647", Encoding.UTF8.GetString(maximumPreparation),
            StringComparison.Ordinal);
        Assert.Contains("\"securityEpoch\":2147483647", Encoding.UTF8.GetString(maximumProof),
            StringComparison.Ordinal);
    }

    /// <summary>Proves the signed-generation source rejects 2147483648 before W10/W10.2 emission.</summary>
    [Fact]
    public void ReadSignedSecurityEpoch_AboveInt32Maximum_IsRejected()
    {
        var payload = Encoding.UTF8.GetBytes(
            "{\"key\":{\"authorityKeyId\":\"runtime-authority-k1\",\"securityEpoch\":2147483648}}");
        var generation = new RuntimeEnrollmentAuthorityGeneration
        {
            CanonicalPayloadUtf8 = payload
        };

        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(payload));
        Assert.False(RuntimeSeatRecoveryAuthorizationService.TryReadSignedSecurityEpoch(
            generation, out var securityEpoch));
        Assert.Equal(0, securityEpoch);
    }

    /// <summary>Proves the published W5 request remains byte-exact and produces its normative domain-separated digest.</summary>
    [Fact]
    public void ParseAuthorizationRequest_GoldenBytes_ReturnsNormativeDigest()
    {
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(Encoding.UTF8.GetBytes(GoldenRequest));

        Assert.True(result.IsSuccess, result.ErrorCode + ":" + Encoding.UTF8.GetString(result.CanonicalUtf8));
        Assert.Equal(992, result.CanonicalUtf8.Length);
        Assert.Equal("19afb5a1b9fccaa21a766a5624f9a50339bf5ee6e9e81f6083328fe5df149f47", result.RequestDigestSha256);
        Assert.Equal("grant:tenant-a:café:🚀", result.Request!.ProviderGrantRef);
    }

    /// <summary>Proves logically equivalent but non-canonical wire bytes never acquire a business identity.</summary>
    [Theory]
    [InlineData("\n")]
    [InlineData(" ")]
    public void ParseAuthorizationRequest_TrailingByte_IsTransportInvalid(string suffix)
    {
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(Encoding.UTF8.GetBytes(GoldenRequest + suffix));

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_request", result.ErrorCode);
    }

    /// <summary>
    /// Proves a canonically escaped JSON backslash preserves the literal six-character opaque text
    /// sequence instead of being mistaken for a Unicode escape token.
    /// </summary>
    [Fact]
    public void ParseAuthorizationRequest_LiteralBackslashUText_PreservesOpaqueValue()
    {
        var wire = ReplaceGrantWire("literal:\\\\u0022");

        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(Encoding.UTF8.GetBytes(wire));

        Assert.True(result.IsSuccess, result.ErrorCode);
        Assert.Equal("literal:\\u0022", result.Request!.ProviderGrantRef);
        Assert.Equal(Encoding.UTF8.GetBytes(wire), result.CanonicalUtf8);
    }

    /// <summary>Proves the three W5 mandatory escapes are accepted only in their canonical escaped form.</summary>
    [Fact]
    public void ParseAuthorizationRequest_W5MandatoryUnicodeEscapes_AreCanonical()
    {
        var wire = ReplaceGrantWire("grant:\\u0085:\\u2028:\\u2029:end");

        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(Encoding.UTF8.GetBytes(wire));

        Assert.True(result.IsSuccess, result.ErrorCode);
        Assert.Equal("grant:\u0085:\u2028:\u2029:end", result.Request!.ProviderGrantRef);
        Assert.Equal(Encoding.UTF8.GetBytes(wire), result.CanonicalUtf8);
        Assert.Equal(997, result.CanonicalUtf8.Length);
        Assert.Equal("9098c5c6b8a412b3a8d82d2f55be69c6f9c55077baf9d7a1f2393452c8748893", result.RequestDigestSha256);
    }

    /// <summary>Proves canonical quote, backslash, slash, and opaque spaces round-trip without aliases.</summary>
    [Theory]
    [InlineData("quote:\\\"|backslash:\\\\|slash:/")]
    [InlineData(" leading and trailing ")]
    public void ParseAuthorizationRequest_CanonicalOpaquePunctuationAndSpaces_RoundTrips(string encodedGrant)
    {
        var wire = ReplaceGrantWire(encodedGrant);

        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(Encoding.UTF8.GetBytes(wire));

        Assert.True(result.IsSuccess, result.ErrorCode);
        Assert.Equal(Encoding.UTF8.GetBytes(wire), result.CanonicalUtf8);
    }

    /// <summary>Proves NFC and NFD remain distinct valid opaque values with distinct request digests.</summary>
    [Fact]
    public void ParseAuthorizationRequest_NfcAndNfdOpaqueText_AreNotNormalized()
    {
        var nfc = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceGrantWire("grant:tenant-a:café:🚀")));
        var nfd = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceGrantWire("grant:tenant-a:cafe\u0301:🚀")));

        Assert.True(nfc.IsSuccess, nfc.ErrorCode);
        Assert.True(nfd.IsSuccess, nfd.ErrorCode);
        Assert.NotEqual(nfc.Request!.ProviderGrantRef, nfd.Request!.ProviderGrantRef);
        Assert.Equal(992, nfc.CanonicalUtf8.Length);
        Assert.Equal(993, nfd.CanonicalUtf8.Length);
        Assert.Equal("19afb5a1b9fccaa21a766a5624f9a50339bf5ee6e9e81f6083328fe5df149f47", nfc.RequestDigestSha256);
        Assert.Equal("7f262f718f5c126af1ee0ff26416e678edbb11a5775789d93f9b0bd984d5a693", nfd.RequestDigestSha256);
    }

    /// <summary>Proves opaque grant cardinality is measured by Unicode scalar, including non-BMP runes.</summary>
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(256, true)]
    [InlineData(257, false)]
    public void ParseAuthorizationRequest_OpaqueRuneBoundary_IsClosed(int runeCount, bool expectedSuccess)
    {
        var grant = string.Concat(Enumerable.Repeat("🚀", runeCount));
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceGrantWire(grant)));

        Assert.Equal(expectedSuccess, result.IsSuccess);
    }

    /// <summary>Proves alternate JSON spellings never acquire the same canonical business identity.</summary>
    [Theory]
    [InlineData("opaque\\/slash")]
    [InlineData("opaque\\u0022quote")]
    [InlineData("opaque\\u00e9accent")]
    [InlineData("opaque\\ud83d\\ude80rocket")]
    public void ParseAuthorizationRequest_NonCanonicalJsonEscape_IsTransportInvalid(string encodedGrant)
    {
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceGrantWire(encodedGrant)));

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_request", result.ErrorCode);
    }

    /// <summary>Proves mandatory W5 escape scalars are rejected when sent literally on the wire.</summary>
    [Theory]
    [InlineData("\u0085")]
    [InlineData("\u2028")]
    [InlineData("\u2029")]
    public void ParseAuthorizationRequest_MandatoryEscapeScalarSentLiterally_IsTransportInvalid(string scalar)
    {
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceGrantWire("opaque:" + scalar)));

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_request", result.ErrorCode);
    }

    /// <summary>Proves both exact W5 seat-claim size boundaries accept canonical unpadded Base64Url.</summary>
    [Theory]
    [InlineData(32)]
    [InlineData(1536)]
    public void ParseAuthorizationRequest_CanonicalSeatClaimBoundary_IsAccepted(int byteCount)
    {
        var claim = Base64Url(new byte[byteCount]);
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceSeatClaim(claim)));

        Assert.True(result.IsSuccess, result.ErrorCode);
        Assert.Equal(claim, result.Request!.SeatClaim);
        Assert.InRange(claim.Length, 43, 2048);
    }

    /// <summary>Proves invalid alphabet, padding, size, and non-canonical trailing bits fail closed.</summary>
    [Theory]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")]
    public void ParseAuthorizationRequest_InvalidSeatClaimEncoding_IsTransportInvalid(string claim)
    {
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceSeatClaim(claim)));

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_request", result.ErrorCode);
    }

    /// <summary>Proves the seat-claim upper character bound rejects 2049 canonical-alphabet bytes.</summary>
    [Fact]
    public void ParseAuthorizationRequest_SeatClaimAboveMaximum_IsTransportInvalid()
    {
        var result = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(
            Encoding.UTF8.GetBytes(ReplaceSeatClaim(new string('A', 2049))));

        Assert.False(result.IsSuccess);
        Assert.Equal("invalid_request", result.ErrorCode);
    }

    /// <summary>Builds one exact request whose opaque grant member contains the supplied JSON token bytes.</summary>
    private static string ReplaceGrantWire(string encodedGrant) => GoldenRequest.Replace(
        "grant:tenant-a:café:🚀", encodedGrant, StringComparison.Ordinal);

    /// <summary>Builds one exact request with a non-null seat claim and no other wire change.</summary>
    private static string ReplaceSeatClaim(string claim) => GoldenRequest.Replace(
        "\"seatClaim\":null", $"\"seatClaim\":\"{claim}\"", StringComparison.Ordinal);

    /// <summary>Encodes bytes as canonical unpadded Base64Url without normalizing any input text.</summary>
    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Proves every allowlisted provider tuple maps to exactly the W9 status and no mutation is performed.</summary>
    [Theory]
    [InlineData("reserved", "prepared", true, "active", false, "compatible")]
    [InlineData("reserved", "prepared", true, "active", true, "expired")]
    [InlineData("committed", "active", true, "superseded", false, "committed")]
    [InlineData("abandoned", "abandoned", false, "active", false, "abandoned")]
    [InlineData("reserved", "superseded", false, "active", false, "superseded")]
    [InlineData("committed", "prepared", true, "active", false, "conflict")]
    public void ClassifyCurrentReadback_AllowlistedTuple_IsTotal(
        string reservation, string authority, bool current, string previous, bool expired, string expected)
    {
        Assert.Equal(expected, RuntimeSeatRecoveryContractCodec.ClassifyCurrentReadback(
            reservation, authority, current, previous, expired));
    }

    private static void AssertVector(byte[] bytes, int expectedLength, string expectedDigest)
    {
        Assert.Equal(expectedLength, bytes.Length);
        Assert.Equal(expectedDigest, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    private static DateTime Utc(string value) => DateTime.ParseExact(value,
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
}

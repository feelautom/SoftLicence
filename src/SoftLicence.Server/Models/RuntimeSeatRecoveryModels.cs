using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

/// <summary>Represents the closed runtime-seat-recovery-authorization-v1 request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryAuthorizationRequest
{
    /// <summary>Gets or sets the exact schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the only supported contract version.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the client-scoped idempotency identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the Website recovery-operation identifier.</summary>
    [JsonPropertyName("recoveryOperationRef")] public required string RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the immutable Website recovery-operation digest.</summary>
    [JsonPropertyName("recoveryDigestSha256")] public required string RecoveryDigestSha256 { get; set; }
    /// <summary>Gets or sets the exact provider discriminator.</summary>
    [JsonPropertyName("provider")] public required string Provider { get; set; }
    /// <summary>Gets or sets the opaque grant reference without normalization.</summary>
    [JsonPropertyName("providerGrantRef")] public required string ProviderGrantRef { get; set; }
    /// <summary>Gets or sets the product identifier asserted for provider revalidation.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the license identifier asserted for provider revalidation.</summary>
    [JsonPropertyName("licenseId")] public required string LicenseId { get; set; }
    /// <summary>Gets or sets an opaque provider-owned seat claim, or explicit null for provider arbitration.</summary>
    [JsonPropertyName("seatClaim")] public required string? SeatClaim { get; set; }
    /// <summary>Gets or sets the proposed installation identity.</summary>
    [JsonPropertyName("installation")] public required RuntimeSeatRecoveryInstallation Installation { get; set; }
    /// <summary>Gets or sets the exact release evidence to revalidate.</summary>
    [JsonPropertyName("release")] public required RuntimeSeatRecoveryRelease Release { get; set; }
    /// <summary>Gets or sets the future Runtime public-key commitment.</summary>
    [JsonPropertyName("newKeyCommitment")] public required RuntimeSeatRecoveryKeyCommitment NewKeyCommitment { get; set; }
    /// <summary>Gets or sets the upstream authorization expiry without allowing provider extension.</summary>
    [JsonPropertyName("expiresAtUtc")] public required string ExpiresAtUtc { get; set; }
}

/// <summary>Represents the closed installation scope carried by recovery authorization.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryInstallation
{
    /// <summary>Gets or sets the new canonical installation identifier.</summary>
    [JsonPropertyName("installationId")] public required string InstallationId { get; set; }
    /// <summary>Gets or sets the lowercase digest of the hardware identity.</summary>
    [JsonPropertyName("hardwareIdDigestSha256")] public required string HardwareIdDigestSha256 { get; set; }
}

/// <summary>Represents the closed release scope carried by recovery authorization.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryRelease
{
    /// <summary>Gets or sets the canonical release version.</summary>
    [JsonPropertyName("version")] public required string Version { get; set; }
    /// <summary>Gets or sets the lowercase digest of the authoritative artifact set.</summary>
    [JsonPropertyName("artifactSetDigestSha256")] public required string ArtifactSetDigestSha256 { get; set; }
}

/// <summary>Represents two exactly equivalent encodings of the future Runtime SPKI digest.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryKeyCommitment
{
    /// <summary>Gets or sets the exact PS256 algorithm marker.</summary>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; set; }
    /// <summary>Gets or sets the lowercase hexadecimal SHA-256 of the DER SPKI.</summary>
    [JsonPropertyName("publicKeySpkiSha256")] public required string PublicKeySpkiSha256 { get; set; }
    /// <summary>Gets or sets the canonical unpadded Base64Url representation of the same digest.</summary>
    [JsonPropertyName("keyThumbprint")] public required string KeyThumbprint { get; set; }
}

/// <summary>Represents the closed encrypted provider-owned seat-claim plaintext.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoverySeatClaimPlaintext
{
    /// <summary>Gets or sets the only supported plaintext version.</summary>
    [JsonPropertyName("version")] public required int Version { get; set; }
    /// <summary>Gets or sets the exact seat-selection purpose.</summary>
    [JsonPropertyName("purpose")] public required string Purpose { get; set; }
    /// <summary>Gets or sets the provider-owned subject digest.</summary>
    [JsonPropertyName("ownerSubjectRefDigestSha256")] public required string OwnerSubjectRefDigestSha256 { get; set; }
    /// <summary>Gets or sets the exact product identifier.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the exact license identifier.</summary>
    [JsonPropertyName("licenseId")] public required string LicenseId { get; set; }
    /// <summary>Gets or sets the exact seat identifier selected by the provider.</summary>
    [JsonPropertyName("seatId")] public required string SeatId { get; set; }
    /// <summary>Gets or sets the seat revision against which the claim was issued.</summary>
    [JsonPropertyName("seatRevision")] public required long SeatRevision { get; set; }
    /// <summary>Gets or sets the inclusive canonical UTC issue instant.</summary>
    [JsonPropertyName("issuedAtUtc")] public required string IssuedAtUtc { get; set; }
    /// <summary>Gets or sets the exclusive canonical UTC expiry instant.</summary>
    [JsonPropertyName("expiresAtUtc")] public required string ExpiresAtUtc { get; set; }
    /// <summary>Gets or sets the provider revocation identifier, distinct from the GCM nonce.</summary>
    [JsonPropertyName("nonce")] public required string Nonce { get; set; }
}

/// <summary>Represents the closed current-readback request that never mutates provider state.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryCurrentReadbackRequest
{
    /// <summary>Gets or sets the exact readback schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the only supported contract version.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the exact product used for S2S scope authorization.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the client-scoped authorization request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the immutable authorization request digest.</summary>
    [JsonPropertyName("requestDigestSha256")] public required string RequestDigestSha256 { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation identifier.</summary>
    [JsonPropertyName("recoveryOperationRef")] public required string RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the exact provider reservation identifier.</summary>
    [JsonPropertyName("reservationRef")] public required string ReservationRef { get; set; }
}

/// <summary>Owns a strictly parsed current-readback request or one generic transport failure.</summary>
public sealed record RuntimeSeatRecoveryReadbackParseResult(
    RuntimeSeatRecoveryCurrentReadbackRequest? Request,
    string? ErrorCode)
{
    /// <summary>Gets whether canonical readback identity was established.</summary>
    public bool IsSuccess => Request is not null && ErrorCode is null;
}

/// <summary>Represents the closed runtime-seat-recovery activation command.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryActivationRequest
{
    /// <summary>Gets or sets the exact activation schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the only supported contract version.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the authenticated product scope.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the existing authorization request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the exact authorization request digest.</summary>
    [JsonPropertyName("requestDigestSha256")] public required string RequestDigestSha256 { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation reference.</summary>
    [JsonPropertyName("recoveryOperationRef")] public required string RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the exact provider reservation reference.</summary>
    [JsonPropertyName("reservationRef")] public required string ReservationRef { get; set; }
    /// <summary>Gets or sets the exact PROVED preparation reference.</summary>
    [JsonPropertyName("prepareRef")] public required string PrepareRef { get; set; }
    /// <summary>Gets or sets the digest of the exact W10.2 confirmation request.</summary>
    [JsonPropertyName("confirmationRequestSha256")] public required string ConfirmationRequestSha256 { get; set; }
}

/// <summary>Represents the closed activation receipt readback identity.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryActivationReadbackRequest
{
    /// <summary>Gets or sets the exact readback schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the only supported contract version.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the authenticated product scope.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the existing activation request identity.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the exact activation command digest.</summary>
    [JsonPropertyName("activationRequestDigestSha256")] public required string ActivationRequestDigestSha256 { get; set; }
}

/// <summary>Represents the closed W10 key-preparation request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryKeyPreparationRequest
{
    /// <summary>Gets or sets the exact schema discriminator.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the only supported contract version.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the exact product carried by the authenticated outer.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the original authorization request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the original authorization request digest.</summary>
    [JsonPropertyName("requestDigestSha256")] public required string RequestDigestSha256 { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation reference.</summary>
    [JsonPropertyName("recoveryOperationRef")] public required string RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the exact provider reservation reference.</summary>
    [JsonPropertyName("reservationRef")] public required string ReservationRef { get; set; }
    /// <summary>Gets or sets the prepared enrollment identifier.</summary>
    [JsonPropertyName("enrollmentId")] public required string EnrollmentId { get; set; }
    /// <summary>Gets or sets the prepared authority-generation identifier.</summary>
    [JsonPropertyName("authorityGenerationId")] public required string AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the canonical RSA public SPKI in padded Base64.</summary>
    [JsonPropertyName("publicKeySpki")] public required string PublicKeySpki { get; set; }
}

/// <summary>Represents the closed raw statement signed by the Runtime recovery key.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryKeyConfirmationStatement
{
    /// <summary>Gets or sets the exact statement schema.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the only supported contract version.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the provider preparation reference.</summary>
    [JsonPropertyName("prepareRef")] public required string PrepareRef { get; set; }
    /// <summary>Gets or sets the original authorization request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the original authorization request digest.</summary>
    [JsonPropertyName("requestDigestSha256")] public required string RequestDigestSha256 { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation reference.</summary>
    [JsonPropertyName("recoveryOperationRef")] public required string RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the exact provider reservation reference.</summary>
    [JsonPropertyName("reservationRef")] public required string ReservationRef { get; set; }
    /// <summary>Gets or sets the prepared enrollment identifier.</summary>
    [JsonPropertyName("enrollmentId")] public required string EnrollmentId { get; set; }
    /// <summary>Gets or sets the prepared authority-generation identifier.</summary>
    [JsonPropertyName("authorityGenerationId")] public required string AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the canonical unpadded Base64Url 32-byte challenge.</summary>
    [JsonPropertyName("challenge")] public required string Challenge { get; set; }
    /// <summary>Gets or sets the exact confirmation audience.</summary>
    [JsonPropertyName("confirmAudience")] public required string ConfirmAudience { get; set; }
}

/// <summary>Represents the closed W10 key-confirmation outer.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RuntimeSeatRecoveryKeyConfirmationRequest
{
    /// <summary>Gets or sets the exact request schema.</summary>
    [JsonPropertyName("schema")] public required string Schema { get; set; }
    /// <summary>Gets or sets the only supported contract version.</summary>
    [JsonPropertyName("contractVersion")] public required int ContractVersion { get; set; }
    /// <summary>Gets or sets the product carried only by the authenticated outer.</summary>
    [JsonPropertyName("productId")] public required string ProductId { get; set; }
    /// <summary>Gets or sets the original authorization request identifier.</summary>
    [JsonPropertyName("requestId")] public required string RequestId { get; set; }
    /// <summary>Gets or sets the original authorization request digest.</summary>
    [JsonPropertyName("requestDigestSha256")] public required string RequestDigestSha256 { get; set; }
    /// <summary>Gets or sets the immutable recovery-operation reference.</summary>
    [JsonPropertyName("recoveryOperationRef")] public required string RecoveryOperationRef { get; set; }
    /// <summary>Gets or sets the exact provider reservation reference.</summary>
    [JsonPropertyName("reservationRef")] public required string ReservationRef { get; set; }
    /// <summary>Gets or sets the provider preparation reference.</summary>
    [JsonPropertyName("prepareRef")] public required string PrepareRef { get; set; }
    /// <summary>Gets or sets the prepared enrollment identifier.</summary>
    [JsonPropertyName("enrollmentId")] public required string EnrollmentId { get; set; }
    /// <summary>Gets or sets the prepared authority-generation identifier.</summary>
    [JsonPropertyName("authorityGenerationId")] public required string AuthorityGenerationId { get; set; }
    /// <summary>Gets or sets the lowercase digest of the prepared SPKI.</summary>
    [JsonPropertyName("publicKeySpkiSha256")] public required string PublicKeySpkiSha256 { get; set; }
    /// <summary>Gets or sets the structured view of the raw signed statement.</summary>
    [JsonPropertyName("confirmationStatement")] public required RuntimeSeatRecoveryKeyConfirmationStatement ConfirmationStatement { get; set; }
    /// <summary>Gets or sets the exact PS256 marker.</summary>
    [JsonPropertyName("confirmationAlgorithm")] public required string ConfirmationAlgorithm { get; set; }
    /// <summary>Gets or sets the canonical unpadded Base64Url PS256 signature.</summary>
    [JsonPropertyName("confirmationSignature")] public required string ConfirmationSignature { get; set; }
}

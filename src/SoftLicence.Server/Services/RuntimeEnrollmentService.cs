using System.Data;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>
/// Represents a stable public Runtime Enrollment failure and, when available, a bounded
/// internal diagnostic code that must never be serialized to an API client.
/// </summary>
/// <param name="errorCode">Stable public API error code.</param>
/// <param name="statusCode">HTTP status associated with the public error.</param>
/// <param name="diagnosticCode">Optional allowlisted server-only diagnostic code.</param>
public sealed class RuntimeEnrollmentException(
    string errorCode,
    int statusCode,
    string? diagnosticCode = null) : Exception(errorCode)
{
    /// <summary>Gets the stable error code returned by the public API.</summary>
    public string ErrorCode { get; } = errorCode;

    /// <summary>Gets the HTTP status associated with the public error.</summary>
    public int StatusCode { get; } = statusCode;

    /// <summary>
    /// Gets an optional allowlisted server-only diagnostic code. Controllers may log it,
    /// but response contracts must expose only <see cref="ErrorCode"/>.
    /// </summary>
    public string? DiagnosticCode { get; } = diagnosticCode;
}

public interface IRuntimeEnrollmentService
{
    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>> PrepareAsync(
        string clientId,
        string exactBodyDigest,
        RuntimeEnrollmentPrepareRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>> RefreshPendingAsync(
        string clientId,
        string exactBodyDigest,
        RuntimeEnrollmentRefreshRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>> ConfirmAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeEnrollmentConfirmRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Migrates the exact active Runtime authority from legacy HWID to deterministic HWID V2.
    /// </summary>
    Task<RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>> MigrateHardwareAuthorityAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeHardwareAuthorityMigrationRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>> CreateCapabilityAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeEnrollmentCapabilityRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeMilestoneAckResponse>> RecordMilestoneAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeMilestoneRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>> RefetchCriticalRecoveryForClientAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeCriticalRecoveryClientRefetchRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<CanaryAckResponse>> ProcessCanaryAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        CanaryPingRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>> RecoverCriticalAsync(
        string clientId,
        string keyId,
        string exactBodyDigest,
        RuntimeCriticalRecoveryRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>> RefetchCriticalRecoveryAsync(
        string clientId,
        string keyId,
        string exactBodyDigest,
        RuntimeCriticalRecoveryRefetchRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>> UpgradeAsync(
        string clientId,
        string keyId,
        string exactRelayDigest,
        RuntimeEnrollmentUpgradeRelayRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>> RollbackAsync(
        string clientId,
        string keyId,
        string exactRelayDigest,
        RuntimeEnrollmentUpgradeRelayRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>> IssueWebSetupTransitionAsync(
        string clientId,
        string exactBodyDigest,
        RuntimeWebSetupTransitionIssueRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeWebSetupUpgradeResponse>> UpgradeFromWebSetupAsync(
        string clientId,
        string keyId,
        string exactBodyDigest,
        RuntimeWebSetupUpgradeRelayRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeReinstallAuthorityResponse> AuthorizeReinstallAsync(
        string clientId,
        RuntimeReinstallAuthorityRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeEnrollmentOperationResult<RuntimeLicenseBootstrapResultResponse>> RedeemLicenseBootstrapAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeLicenseBootstrapRedeemRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);
}

public sealed class RuntimeEnrollmentService : IRuntimeEnrollmentService
{
    public const string ProtocolVersion = "runtime-enrollment-v1";
    public const string PrepareSchema = "runtime-enrollment-prepare-v1";
    public const string PrepareResponseSchema = "runtime-enrollment-prepare-response-v1";
    public const string PrepareV2Schema = "runtime-enrollment-prepare-v2";
    public const string PrepareV2ResponseSchema = "runtime-enrollment-prepare-response-v2";
    public const string RefreshSchema = "runtime-enrollment-refresh-v1";
    public const string RefreshResponseSchema = "runtime-enrollment-refresh-response-v1";
    public const string RefreshV2Schema = "runtime-enrollment-refresh-v2";
    public const string RefreshV2ResponseSchema = "runtime-enrollment-refresh-response-v2";
    public const string ConfirmSchema = "runtime-enrollment-confirm-v1";
    public const string ConfirmResponseSchema = "runtime-enrollment-confirm-response-v1";
    public const string HardwareAuthorityMigrationSchema = "runtime-hardware-authority-migration-v1";
    public const string HardwareAuthorityMigrationResponseSchema = "runtime-hardware-authority-migration-response-v1";
    public const string CapabilitySchema = "runtime-enrollment-capability-v1";
    public const string LegacyCapabilityReleaseVersion = "2.2.916";
    public const string CapabilityResponseSchema = "runtime-enrollment-capability-response-v1";
    public const string MilestoneSchema = "runtime-milestone-v1";
    public const string MilestoneAckSchema = "runtime-milestone-ack-v1";
    public const string CriticalRecoverySchema = "runtime-critical-recovery-v1";
    public const string CriticalRecoveryRefetchSchema = "runtime-critical-recovery-refetch-v1";
    public const string CriticalRecoveryClientRefetchSchema = "runtime-critical-recovery-client-refetch-v1";
    public const string CriticalRecoveryResponseSchema = "runtime-critical-recovery-receipt-v1";
    public const string CriticalRecoveryAudience = "urn:softlicence:runtime-critical-recovery-v1";
    public const string CriticalRecoveryUse = "critical-recovery";
    public const string UpgradeRelaySchema = "runtime-enrollment-upgrade-relay-v1";
    public const string UpgradeAuthorizationSchema = "runtime-enrollment-upgrade-authorization-v1";
    public const string UpgradeResponseSchema = "runtime-enrollment-upgrade-response-v1";
    public const string UpgradeAudience = "https://softlicence.app/runtime-enrollment/upgrade";
    public const string UpgradeUse = "runtime-enrollment-upgrade";
    public const string RollbackRelaySchema = "runtime-enrollment-recovery-rollback-relay-v1";
    public const string RollbackAuthorizationSchema = "runtime-enrollment-recovery-rollback-authorization-v1";
    public const string RollbackResponseSchema = "runtime-enrollment-recovery-rollback-response-v1";
    public const string RollbackAudience = "https://softlicence.app/runtime-enrollment/recovery-rollback";
    public const string RollbackUse = "runtime-enrollment-recovery-rollback";
    public const string WebSetupTransitionIssueSchema = "runtime-websetup-transition-issue-v1";
    public const string WebSetupTransitionIssueV2Schema = "runtime-websetup-transition-issue-v2";
    public const string WebSetupTransitionCapabilitySchema = "runtime-websetup-transition-capability-v1";
    public const string WebSetupUpgradeSchema = "runtime-enrollment-websetup-upgrade-v1";
    public const string WebSetupUpgradeAuthorizationSchema = "runtime-enrollment-websetup-upgrade-authorization-v1";
    public const string WebSetupUpgradeResponseSchema = "runtime-enrollment-websetup-upgrade-response-v1";
    public const string WebSetupUpgradeAudience = "https://softlicence.app/runtime-enrollment/websetup-upgrade";
    public const string WebSetupUpgradeUse = "runtime-enrollment-websetup-upgrade";
    public const string ReinstallAuthoritySchema = "runtime-enrollment-reinstall-authority-v1";
    public const string ReinstallAuthorityV2Schema = "runtime-enrollment-reinstall-authority-v2";
    public const string ReinstallAuthorityLegacyV2Schema = ReinstallAuthorityV2Schema;
    public const string ReinstallAuthorityResponseSchema = "runtime-enrollment-reinstall-authority-response-v1";
    public const string LicenseBootstrapSchema = "runtime-license-bootstrap-v1";
    public const string LicenseBootstrapResponseSchema = "runtime-license-bootstrap-result-v1";
    private const int CriticalRecoveryReceiptTtlHours = 24;
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";
    private static readonly Regex LowerUuidPattern = new(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex LowerSha256Pattern = new(
        "^[0-9a-f]{64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Base64Url43Pattern = new(
        "^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex SignaturePattern = new(
        "^[A-Za-z0-9_-]{512}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex ReleaseVersionPattern = new(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex HardwareIdPattern = new(
        "^[0-9A-F]{16}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly HashSet<string> MilestoneCodes = new(StringComparer.Ordinal)
    {
        "api_opened",
        "bootstrap_entered",
        "capability_issued",
        "integrity_allowed",
        "integrity_denied",
        "license_allowed",
        "license_denied",
        "mcp_invocation_allowed",
        "mcp_invocation_denied",
        "mcp_invocation_requested",
        "mcp_opened",
        "rest_invocation_allowed",
        "rest_invocation_denied",
        "rest_invocation_requested",
        "tia_connected",
        "tia_detection_allowed",
        "tia_detection_denied",
        "tia_operation_completed",
        "tia_operation_failed",
        "tia_operation_started"
    };
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly JsonSerializerOptions StrictJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IRuntimeEnrollmentAuthorityService _authority;
    private readonly IRuntimeEnrollmentKeyRegistryService _keyRegistry;
    private readonly IRuntimeEnrollmentCryptoService _crypto;
    private readonly RuntimeEnrollmentOptions _options;
    private readonly CanaryAckService? _canaryAck;
    private readonly ISignedLicenseFileService? _signedLicenseFiles;
    private readonly IDataProtector? _distributionEntitlementProtector;

    public RuntimeEnrollmentService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IRuntimeEnrollmentAuthorityService authority,
        IRuntimeEnrollmentKeyRegistryService keyRegistry,
        IRuntimeEnrollmentCryptoService crypto,
        IOptions<RuntimeEnrollmentOptions> options,
        CanaryAckService? canaryAck = null,
        ISignedLicenseFileService? signedLicenseFiles = null,
        IDataProtectionProvider? dataProtectionProvider = null)
    {
        _dbFactory = dbFactory;
        _authority = authority;
        _keyRegistry = keyRegistry;
        _crypto = crypto;
        _options = options.Value;
        _canaryAck = canaryAck;
        _signedLicenseFiles = signedLicenseFiles;
        _distributionEntitlementProtector = dataProtectionProvider?.CreateProtector(
            DistributionInstallationBindingService.EntitlementPurpose);
    }

    public async Task<RuntimeReinstallAuthorityResponse> AuthorizeReinstallAsync(
        string clientId,
        RuntimeReinstallAuthorityRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateReinstallAuthority(request);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var preflight = await db.RuntimeEnrollments.AsNoTracking()
            .Where(candidate => candidate.Id == validated.EnrollmentId)
            .Select(candidate => new
            {
                BindingId = (Guid?)candidate.BindingId,
                BindingSubjectRefDigestSha256 = candidate.Binding!.SubjectRefDigestSha256
            })
            .SingleOrDefaultAsync(cancellationToken)
            ?? throw new RuntimeEnrollmentException(
                "reinstall_enrollment_unavailable", StatusCodes.Status404NotFound);
        var preflightBindingId = preflight.BindingId
            ?? throw new RuntimeEnrollmentException(
                "reinstall_enrollment_unavailable", StatusCodes.Status404NotFound);
        var mutationLeaseRequested = validated.IsV2
            && preflight.BindingSubjectRefDigestSha256 == null;
        await using var lease = mutationLeaseRequested
            ? await _authority.AcquireMutationAsync(db, preflightBindingId, cancellationToken)
            : await _authority.AcquireAsync(db, preflightBindingId, cancellationToken);
        await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
        var enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);

        if (enrollment.State != "ACTIVE"
            || enrollment.BindingId != preflightBindingId
            || enrollment.ClientId != clientId
            || enrollment.ProductId != validated.ProductId
            || enrollment.InstallationId != validated.InstallationId
            || enrollment.ReleaseVersion != validated.ReleaseVersion
            || enrollment.KeyThumbprint != validated.KeyThumbprint
            || enrollment.SecurityEpoch != validated.SecurityEpoch)
        {
            if (validated.IsV2)
                throw ReinstallAuthorityIneligible();
            throw new RuntimeEnrollmentException(
                "reinstall_binding_mismatch", StatusCodes.Status409Conflict);
        }

        var now = await DatabaseNowAsync(db, cancellationToken);
        var binding = await db.DistributionInstallationBindings
            .SingleAsync(candidate => candidate.Id == enrollment.BindingId, cancellationToken);
        ReinstallAuthorityClassification? classification = null;
        if (validated.IsV2)
        {
            classification = await ClassifyAndValidateV2ReinstallAuthorityAsync(
                db, enrollment, binding, clientId, validated, lease.AuthorityEpoch, now, cancellationToken);
            if (classification == ReinstallAuthorityClassification.LegacyIncomplete
                && !mutationLeaseRequested)
                throw ReinstallAuthorityIneligible();
        }
        else
        {
            await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            if (binding.SubjectRefDigestSha256 is not { Length: 64 }
                || !LowerSha256Pattern.IsMatch(binding.SubjectRefDigestSha256)
                || !LowerUuidPattern.IsMatch(binding.GrantRef))
                throw ReinstallAuthorityIneligible();
        }

        byte[] spki = [];
        byte[]? signature = null;
        try
        {
            spki = _crypto.Open(
                "enrollment-spki", enrollment.Id, enrollment.Epoch,
                enrollment.PublicKeySpkiKeyId, enrollment.PublicKeySpkiCiphertext,
                EnrollmentFieldReference(enrollment.Id, "PublicKeySpkiCiphertext"));
            signature = DecodeBase64Url(validated.Signature);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
            if (consumed != spki.Length || rsa.KeySize != 3072
                || !rsa.VerifyData(
                    Encoding.UTF8.GetBytes(BuildReinstallProofPayload(validated)),
                    signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw new RuntimeEnrollmentException(
                    "reinstall_signature_invalid", StatusCodes.Status403Forbidden);
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or FormatException)
        {
            throw new RuntimeEnrollmentException(
                "reinstall_signature_invalid", StatusCodes.Status403Forbidden);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
            if (signature != null)
                CryptographicOperations.ZeroMemory(signature);
        }

        if (classification == ReinstallAuthorityClassification.LegacyIncomplete)
        {
            binding.SubjectRefDigestSha256 = validated.SubjectRefDigestSha256;
            enrollment.SubjectRefDigestSha256 = validated.SubjectRefDigestSha256;
            await db.SaveChangesAsync(cancellationToken);
            var upgradedAuthorityEpoch = await CurrentAuthorityEpochAsync(db, cancellationToken);
            if (upgradedAuthorityEpoch <= lease.AuthorityEpoch)
                throw new RuntimeEnrollmentException(
                    "authority_unavailable", StatusCodes.Status503ServiceUnavailable);
            enrollment.AuthorityEpoch = upgradedAuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
        }

        var sourceLicense = await db.Licenses.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == binding.LicenseId, cancellationToken);
        var sourceActiveSeatCount = await db.LicenseSeats.AsNoTracking().CountAsync(
            candidate => candidate.LicenseId == binding.LicenseId && candidate.IsActive,
            cancellationToken);
        var sourceLicenseEligible = sourceLicense.IsActive
            && sourceLicense.RevokedAt == null
            && (!sourceLicense.ExpirationDate.HasValue || sourceLicense.ExpirationDate.Value > now.UtcDateTime)
            && sourceLicense.MaxSeats > 0
            && sourceActiveSeatCount <= sourceLicense.MaxSeats;
        var response = new RuntimeReinstallAuthorityResponse(
            ReinstallAuthorityResponseSchema,
            ProtocolVersion,
            sourceLicenseEligible ? "authorized" : "identity_confirmed",
            validated.RequestId.ToString("D"),
            validated.BootstrapId.ToString("D"),
            enrollment.ProductId.ToString("D"),
            enrollment.Id.ToString("D"),
            binding.Id.ToString("D"),
            enrollment.InstallationId,
            enrollment.ReleaseVersion,
            enrollment.KeyThumbprint,
            enrollment.SecurityEpoch,
            binding.GrantRef,
            binding.SubjectRefDigestSha256!,
            binding.LicenseId.ToString("D"),
            binding.LicenseSeatId.ToString("D"));
        await lease.CommitAsync(cancellationToken);
        return response;
    }

    /// <summary>
    /// Classifies a v2 reinstall authority without mutating it. Finalization history is
    /// owner-authoritative: repeated requests are valid only when every distinct owner
    /// exactly matches the authenticated S2S client.
    /// </summary>
    /// <param name="db">Database context participating in the authority lease.</param>
    /// <param name="enrollment">Locked enrollment being proven.</param>
    /// <param name="binding">Locked installation binding linked to the enrollment.</param>
    /// <param name="clientId">Authenticated S2S client identifier, compared ordinally.</param>
    /// <param name="request">Strictly validated v2 proof request.</param>
    /// <param name="currentAuthorityEpoch">Authority epoch observed under the lease.</param>
    /// <param name="now">Database time used for eligibility checks.</param>
    /// <param name="cancellationToken">Cancellation token for database operations.</param>
    /// <returns>The compatible authority generation after all checks pass.</returns>
    /// <exception cref="RuntimeEnrollmentException">The authority is incomplete, divergent, or ineligible.</exception>
    private static async Task<ReinstallAuthorityClassification> ClassifyAndValidateV2ReinstallAuthorityAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        DistributionInstallationBinding binding,
        string clientId,
        ReinstallAuthorityValidated request,
        long currentAuthorityEpoch,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.LicenseId != enrollment.LicenseId
            || binding.LicenseSeatId != enrollment.LicenseSeatId
            || binding.InstallationId != enrollment.InstallationId
            || binding.HardwareIdHash != enrollment.HardwareIdHash
            || binding.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || binding.Version != enrollment.ReleaseVersion
            || binding.GrantRef != request.GrantRef
            || !LowerUuidPattern.IsMatch(binding.GrantRef)
            || binding.GrantRefDigestSha256 != Sha256(binding.GrantRef))
            throw ReinstallAuthorityIneligible();

        var bindingSubject = binding.SubjectRefDigestSha256;
        var enrollmentSubject = enrollment.SubjectRefDigestSha256;
        if ((bindingSubject == null) != (enrollmentSubject == null))
            throw ReinstallAuthorityIneligible();

        var ownership = await db.DistributionGrantOwnerships.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ProductId == binding.ProductId
            && candidate.GrantRefDigestSha256 == binding.GrantRefDigestSha256,
            cancellationToken);
        var entitlement = await db.DistributionEntitlements.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.Id == binding.EntitlementId, cancellationToken);
        var finalizeOwners = await db.DistributionBindingRequests.AsNoTracking()
            .Where(candidate => candidate.BindingId == binding.Id
                && candidate.Operation == "finalize_binding")
            .Select(candidate => candidate.ClientId)
            .Distinct()
            .Take(2)
            .ToListAsync(cancellationToken);
        var hasSingleAuthenticatedFinalizeOwner = finalizeOwners.Count == 1
            && string.Equals(finalizeOwners[0], clientId, StringComparison.Ordinal);
        var finalizeOwnerDiagnosticCode = finalizeOwners.Count == 0
            ? "v2_finalize_owner_missing"
            : hasSingleAuthenticatedFinalizeOwner
                ? null
                : "v2_finalize_owner_mismatch";

        ReinstallAuthorityClassification classification;
        if (ownership is { Source: "issue_v2" }
            && entitlement == null
            && finalizeOwners.Count == 0)
        {
            if (ownership.ClientId != clientId)
                throw ReinstallAuthorityIneligible();
            if (bindingSubject == null)
            {
                if (enrollment.AuthorityEpoch != currentAuthorityEpoch)
                    throw ReinstallAuthorityIneligible();
                classification = ReinstallAuthorityClassification.LegacyIncomplete;
            }
            else if (bindingSubject == request.SubjectRefDigestSha256
                && enrollmentSubject == request.SubjectRefDigestSha256)
            {
                classification = ReinstallAuthorityClassification.LegacyReconciled;
            }
            else
            {
                throw ReinstallAuthorityIneligible();
            }
        }
        else if (ownership is { Source: "issue_v3" }
            && ownership.ClientId == clientId
            && entitlement is
            {
                ContractVersion: 3,
                State: "finalized",
                FinalizedAtUtc: not null
            }
            && entitlement.ClientId == clientId
            && entitlement.ProductId == binding.ProductId
            && entitlement.LicenseId == binding.LicenseId
            && entitlement.GrantRefDigestSha256 == binding.GrantRefDigestSha256
            && entitlement.SubjectRefDigestSha256 == request.SubjectRefDigestSha256
            && bindingSubject == request.SubjectRefDigestSha256
            && enrollmentSubject == request.SubjectRefDigestSha256
            && entitlement.FinalizedAtUtc >= entitlement.IssuedAtUtc
            && entitlement.FinalizedAtUtc <= entitlement.ExpiresAtUtc
            && hasSingleAuthenticatedFinalizeOwner)
        {
            classification = ReinstallAuthorityClassification.ModernComplete;
        }
        else if (ownership is { Source: "finalize_v1" }
            && ownership.ClientId == clientId
            && entitlement == null
            && bindingSubject == request.SubjectRefDigestSha256
            && enrollmentSubject == request.SubjectRefDigestSha256
            && hasSingleAuthenticatedFinalizeOwner)
        {
            classification = ReinstallAuthorityClassification.ModernComplete;
        }
        else
        {
            throw ReinstallAuthorityIneligible(
                finalizeOwnerDiagnosticCode ?? "v2_authority_invariant_mismatch");
        }

        try
        {
            // A complete modern authority may describe an inactive source that the Website
            // will replace with the caller's current account and licence authority. Legacy
            // authorities have no such replacement proof and must remain fully eligible.
            await ValidateBindingRowsAsync(
                db,
                binding,
                now,
                cancellationToken,
                allowIneligibleSourceLicense: classification == ReinstallAuthorityClassification.ModernComplete);
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.ErrorCode is "binding_ineligible" or "authority_ineligible")
        {
            throw ReinstallAuthorityIneligible("v2_binding_rows_ineligible");
        }
        return classification;
    }

    /// <summary>
    /// Creates the generic public refusal while retaining only an allowlisted internal
    /// diagnostic code for server-side operations.
    /// </summary>
    /// <param name="diagnosticCode">A constant diagnostic code that contains no authority identifiers.</param>
    /// <returns>A fail-closed refusal whose public error remains generic.</returns>
    private static RuntimeEnrollmentException ReinstallAuthorityIneligible(
        string diagnosticCode = "v2_authority_invariant_mismatch") =>
        new("reinstall_authority_ineligible", StatusCodes.Status403Forbidden, diagnosticCode);

    public async Task<RuntimeEnrollmentOperationResult<RuntimeLicenseBootstrapResultResponse>> RedeemLicenseBootstrapAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeLicenseBootstrapRedeemRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        if (_signedLicenseFiles == null
            || request.ExtensionData is { Count: > 0 }
            || request.Schema != LicenseBootstrapSchema
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.InstallationId, out _)
            || !TryUuid(request.BootstrapId, out var bootstrapId)
            || request.Capability is not { Length: 43 }
            || !Base64Url43Pattern.IsMatch(request.Capability)
            || !LowerSha256Pattern.IsMatch(exactBodyDigest))
            throw Invalid();
        var validatedProof = ValidateProofHeaders(proof);
        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);
        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            var authorization = await db.DistributionLicenseBootstrapAuthorizations
                .SingleOrDefaultAsync(row => row.Id == bootstrapId, cancellationToken)
                ?? throw Reject("bootstrap_ineligible");
            var now = await DatabaseNowAsync(db, cancellationToken);
            var proofDigest = validatedProof.ProofDigest;
            if (authorization.State == "CONSUMED")
            {
                if (authorization.ConsumedRequestId != requestId.ToString("D")
                    || authorization.ConsumedJti != validatedProof.Jti.ToString("D")
                    || authorization.ConsumedBodyDigestSha256 != exactBodyDigest
                    || authorization.ConsumedProofDigestSha256 != proofDigest
                    || authorization.ExpiresAtUtc <= now.UtcDateTime)
                    throw Conflict("bootstrap_replay_conflict");
                try
                {
                    EnsurePreflightUnchanged(enrollment, preflight);
                    VerifyProof(preflight, "license-bootstrap", exactBodyDigest, validatedProof, challengeRequired: true);
                    await ValidateLicenseBootstrapAuthorityAsync(
                        db, enrollment, authorization, productId, bindingId, request.InstallationId!,
                        "CONSUMED", lease.AuthorityEpoch, now, cancellationToken);
                }
                catch (RuntimeEnrollmentException)
                {
                    throw new RuntimeEnrollmentException(
                        "bootstrap_replay_authority_invalid", StatusCodes.Status409Conflict);
                }
                if (authorization.ResponseCiphertext == null
                    || authorization.ResponseKeyId == null
                    || authorization.ResponseCiphertextLength != authorization.ResponseCiphertext.Length
                    || authorization.ResponsePlaintextLength is not (>= 1 and <= 65536))
                    throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                byte[] replayBytes;
                try
                {
                    replayBytes = OpenBootstrapResponse(authorization);
                }
                catch (CryptographicException)
                {
                    throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                }
                try
                {
                    var replayResponse = JsonSerializer.Deserialize<RuntimeLicenseBootstrapResultResponse>(replayBytes, JsonOptions)
                        ?? throw new JsonException();
                    if (replayResponse.Schema != LicenseBootstrapResponseSchema
                        || replayResponse.RequestId != authorization.ConsumedRequestId
                        || replayResponse.BootstrapId != authorization.Id.ToString("D")
                        || replayResponse.LicenseFile == null
                        || Encoding.UTF8.GetByteCount(replayResponse.LicenseFile) != authorization.ResponsePlaintextLength)
                        throw new JsonException();
                    await lease.CommitAsync(cancellationToken);
                    return new RuntimeEnrollmentOperationResult<RuntimeLicenseBootstrapResultResponse>(
                        replayResponse, true, replayBytes.ToArray());
                }
                catch (Exception exception) when (exception is CryptographicException or JsonException)
                {
                    throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                }
                finally { CryptographicOperations.ZeroMemory(replayBytes); }
            }

            EnsurePreflightUnchanged(enrollment, preflight);
            await ReserveQuotasAsync(db, now,
                [("license-bootstrap-binding", preflight.BindingId.ToString("D"), 20),
                 ("license-bootstrap-credential", preflight.EnrollmentId.ToString("D"), 10),
                 ("license-bootstrap-ip", PseudonymizeAddress(clientAddress), 10),
                 ("license-bootstrap-global", "all", 120)], cancellationToken);
            VerifyProof(preflight, "license-bootstrap", exactBodyDigest, validatedProof, challengeRequired: true);
            ValidateProofTime(validatedProof.SentAtUtc, now);
            await ValidateLicenseBootstrapAuthorityAsync(
                db, enrollment, authorization, productId, bindingId, request.InstallationId!,
                "ISSUED", lease.AuthorityEpoch, now, cancellationToken);

            var capabilityDigest = Sha256(request.Capability);
            var capability = await db.DistributionLicenseBootstrapCapabilities
                .SingleOrDefaultAsync(row => row.AuthorizationId == authorization.Id
                    && row.CapabilityDigestSha256 == capabilityDigest, cancellationToken)
                ?? throw AuthenticationFailed();
            if (capability.State != "ISSUED" || capability.ExpiresAtUtc <= now.UtcDateTime)
                throw new RuntimeEnrollmentException("bootstrap_expired", StatusCodes.Status410Gone);
            var license = await db.Licenses.Include(row => row.Product).Include(row => row.Type)
                .ThenInclude(type => type!.CustomParams)
                .SingleOrDefaultAsync(row => row.Id == enrollment.LicenseId, cancellationToken)
                ?? throw Reject("bootstrap_ineligible");
            var seat = await db.LicenseSeats.AsNoTracking()
                .SingleOrDefaultAsync(row => row.Id == enrollment.LicenseSeatId && row.IsActive, cancellationToken)
                ?? throw Reject("bootstrap_ineligible");
            if (seat.LicenseId != license.Id || Sha256(seat.HardwareId) != enrollment.HardwareIdHash)
                throw Reject("bootstrap_ineligible");
            var licenseFile = _signedLicenseFiles.Generate(license, seat.HardwareId);
            var licenseBytes = Encoding.UTF8.GetBytes(licenseFile);
            if (licenseBytes.Length is < 1 or > 65536)
            {
                CryptographicOperations.ZeroMemory(licenseBytes);
                throw new RuntimeEnrollmentException("license_file_size_exceeded", StatusCodes.Status422UnprocessableEntity);
            }
            var licenseLength = licenseBytes.Length;
            CryptographicOperations.ZeroMemory(licenseBytes);
            var response = new RuntimeLicenseBootstrapResultResponse(
                LicenseBootstrapResponseSchema, requestId.ToString("D"), bootstrapId.ToString("D"), licenseFile);
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var envelope = await _crypto.SealAsync(db, "bootstrap-redeem-response", authorization.Id,
                enrollment.Epoch, responseBytes, BootstrapResponseReference(authorization.Id), cancellationToken);
            authorization.State = "CONSUMED";
            authorization.ConsumedAtUtc = now.UtcDateTime;
            authorization.ConsumedRequestId = requestId.ToString("D");
            authorization.ConsumedJti = validatedProof.Jti.ToString("D");
            authorization.ConsumedBodyDigestSha256 = exactBodyDigest;
            authorization.ConsumedProofDigestSha256 = proofDigest;
            authorization.ResponseCiphertext = Encoding.ASCII.GetBytes(envelope.Ciphertext);
            authorization.ResponseKeyId = envelope.KeyId;
            authorization.ResponsePlaintextLength = licenseLength;
            authorization.ResponseCiphertextLength = authorization.ResponseCiphertext.Length;
            authorization.ReplayExpiresAtUtc = authorization.ExpiresAtUtc;
            capability.State = "CONSUMED";
            capability.ConsumedAtUtc = now.UtcDateTime;
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeLicenseBootstrapResultResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    private byte[] OpenBootstrapResponse(DistributionLicenseBootstrapAuthorization authorization) =>
        _crypto.Open("bootstrap-redeem-response", authorization.Id, authorization.RuntimeEpoch,
            authorization.ResponseKeyId!, Encoding.ASCII.GetString(authorization.ResponseCiphertext!),
            BootstrapResponseReference(authorization.Id));

    private static string BootstrapResponseReference(Guid authorizationId) =>
        $"license-bootstrap/{authorizationId:D}";

    private async Task ValidateLicenseBootstrapAuthorityAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        DistributionLicenseBootstrapAuthorization authorization,
        Guid productId,
        Guid bindingId,
        string installationId,
        string expectedAuthorizationState,
        long currentAuthorityEpoch,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (enrollment.State is not ("PENDING" or "ACTIVE")
            || enrollment.ProductId != productId
            || enrollment.BindingId != bindingId
            || enrollment.InstallationId != installationId
            || enrollment.SubjectRefDigestSha256 is not { Length: 64 }
            || enrollment.AuthorityEpoch != currentAuthorityEpoch)
            throw Reject("bootstrap_ineligible");

        await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == enrollment.BindingId, cancellationToken)
            ?? throw Reject("bootstrap_ineligible");
        var entitlement = await db.DistributionEntitlements.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == binding.EntitlementId, cancellationToken)
            ?? throw Reject("bootstrap_ineligible");
        if (entitlement.ContractVersion != 3
            || entitlement.State != "finalized"
            || entitlement.ExpiresAtUtc <= now.UtcDateTime
            || entitlement.ClientId != enrollment.ClientId
            || entitlement.ProductId != binding.ProductId
            || entitlement.LicenseId != binding.LicenseId
            || entitlement.GrantRefDigestSha256 != binding.GrantRefDigestSha256
            || entitlement.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256
            || authorization.State != expectedAuthorizationState
            || authorization.ExpiresAtUtc <= now.UtcDateTime
            || authorization.ClientId != enrollment.ClientId
            || authorization.ProductId != enrollment.ProductId
            || authorization.LicenseId != enrollment.LicenseId
            || authorization.LicenseSeatId != enrollment.LicenseSeatId
            || authorization.EntitlementId != entitlement.Id
            || authorization.BindingId != enrollment.BindingId
            || authorization.RuntimeEnrollmentId != enrollment.Id
            || authorization.InstallationId != enrollment.InstallationId
            || authorization.HardwareIdHash != enrollment.HardwareIdHash
            || authorization.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || authorization.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256
            || authorization.GrantRefDigestSha256 != binding.GrantRefDigestSha256
            || authorization.ReleaseVersion != binding.Version
            || authorization.ApprovedBinariesDigestSha256 != Sha256(string.Join('\n',
                binding.ExecutableSha256, binding.NativeDllSha256, binding.CoreSha256))
            || binding.HandoffExpiresAtUtc <= now.UtcDateTime
            || authorization.ExpiresAtUtc != binding.HandoffExpiresAtUtc
            || authorization.RuntimePublicKeySpkiSha256 != enrollment.PublicKeySpkiSha256
            || authorization.RuntimeKeyThumbprint != enrollment.KeyThumbprint
            || authorization.RuntimeEpoch != enrollment.Epoch
            || authorization.SecurityEpoch != enrollment.SecurityEpoch
            || authorization.AuthorityEpoch != enrollment.AuthorityEpoch
            || authorization.AuthorityEpoch != currentAuthorityEpoch
            || authorization.Audience != DistributionLicenseBootstrapService.Audience
            || authorization.Use != "license-bootstrap")
            throw Reject("bootstrap_ineligible");
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>> PrepareAsync(
        string clientId,
        string exactBodyDigest,
        RuntimeEnrollmentPrepareRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidatePrepare(request, exactBodyDigest);
        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, validated.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var existing = await FindPrepareReplayAsync(
                db, clientId, validated.RequestId, exactBodyDigest,
                validated.ExposesSecurityEpoch, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            var now = await DatabaseNowAsync(db, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("prepare-binding", validated.BindingId.ToString("D"), 30), ("prepare-global", "all", 240)],
                cancellationToken);
            var key = ValidateEnrollmentKey(request.Key!);
            await LockThumbprintAsync(db, key.Thumbprint, cancellationToken);
            var binding = await LoadBindingForUpdateAsync(db, validated.BindingId, cancellationToken);
            await ValidateBindingAuthorityAsync(db, binding, clientId, validated, now, cancellationToken);
            if (!validated.ExposesSecurityEpoch && binding.InitialSecurityEpoch != 1)
                throw PrepareV2Required();
            var live = await db.RuntimeEnrollments.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollments"
                WHERE "State" IN ('PENDING', 'ACTIVE')
                  AND ("BindingId" = {binding.Id} OR "KeyThumbprint" = {key.Thumbprint})
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken);
            foreach (var candidate in live.Where(candidate =>
                         candidate.State == "PENDING" && candidate.ChallengeExpiresAtUtc <= now.UtcDateTime))
            {
                candidate.State = "INVALIDATED";
                candidate.InvalidatedAtUtc = now.UtcDateTime;
                candidate.InvalidationReason = "challenge_expired";
                candidate.AuthorityEpoch = lease.AuthorityEpoch;
            }
            if (db.ChangeTracker.HasChanges())
                await db.SaveChangesAsync(cancellationToken);
            if (live.Any(candidate => candidate.State is "PENDING" or "ACTIVE"))
                throw Conflict("enrollment_conflict");

            var enrollment = new RuntimeEnrollment
            {
                ClientId = clientId,
                BindingId = binding.Id,
                ProductId = binding.ProductId,
                LicenseId = binding.LicenseId,
                LicenseSeatId = binding.LicenseSeatId,
                InstallationId = binding.InstallationId,
                HardwareIdHash = binding.HardwareIdHash,
                ReleaseVersion = binding.Version,
                HandoffDigestSha256 = binding.HandoffDigestSha256,
                SubjectRefDigestSha256 = binding.SubjectRefDigestSha256,
                ProtocolVersion = ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = request.Key!.Backend!,
                AttestationLevel = "none",
                PublicKeySpkiSha256 = key.SpkiSha256,
                KeyThumbprint = key.Thumbprint,
                State = "PENDING",
                Epoch = 1,
                SecurityEpoch = binding.InitialSecurityEpoch,
                AuthorityEpoch = lease.AuthorityEpoch,
                CreatedAtUtc = now.UtcDateTime,
                ChallengeExpiresAtUtc = now.AddSeconds(_options.ChallengeTtlSeconds).UtcDateTime
            };
            var challenge = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
            enrollment.ChallengeDigestSha256 = Sha256(challenge);
            var spkiEnvelope = await _crypto.SealAsync(db, "enrollment-spki", enrollment.Id, 1, key.Spki,
                EnrollmentFieldReference(enrollment.Id, "PublicKeySpkiCiphertext"), cancellationToken);
            enrollment.PublicKeySpkiCiphertext = spkiEnvelope.Ciphertext;
            enrollment.PublicKeySpkiKeyId = spkiEnvelope.KeyId;
            var challengeEnvelope = await _crypto.SealAsync(
                db, "enrollment-challenge", enrollment.Id, 1, Encoding.ASCII.GetBytes(challenge),
                EnrollmentFieldReference(enrollment.Id, "ChallengeCiphertext"), cancellationToken);
            enrollment.ChallengeCiphertext = challengeEnvelope.Ciphertext;
            enrollment.ChallengeKeyId = challengeEnvelope.KeyId;

            var response = new RuntimeEnrollmentPrepareResponse(
                validated.ExposesSecurityEpoch ? PrepareV2ResponseSchema : PrepareResponseSchema,
                ProtocolVersion, "pending", enrollment.Id.ToString("D"), 1,
                challenge, FormatUtc(enrollment.ChallengeExpiresAtUtc), _options.ConfirmAudience)
            {
                SecurityEpoch = validated.ExposesSecurityEpoch ? enrollment.SecurityEpoch : null
            };
            var operation = new RuntimeEnrollmentRequest
            {
                ClientId = clientId,
                RequestId = validated.RequestId,
                Operation = "prepare",
                PayloadDigestSha256 = exactBodyDigest,
                EnrollmentId = enrollment.Id,
                CreatedAtUtc = now.UtcDateTime
            };
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var responseEnvelope = await _crypto.SealAsync(
                db, "prepare-response", operation.Id, 1,
                responseBytes,
                PrepareResponseReference(operation), cancellationToken);
            operation.ResponseCiphertext = responseEnvelope.Ciphertext;
            operation.ResponseKeyId = responseEnvelope.KeyId;
            db.RuntimeEnrollments.Add(enrollment);
            db.RuntimeEnrollmentRequests.Add(operation);
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsLiveEnrollmentConstraint(exception))
            {
                throw Conflict("enrollment_conflict");
            }
            catch (DbUpdateException exception) when (IsPrepareRequestConstraint(exception))
            {
                throw Conflict("idempotency_conflict");
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>> RefreshPendingAsync(
        string clientId,
        string exactBodyDigest,
        RuntimeEnrollmentRefreshRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateRefresh(request, exactBodyDigest);
        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, validated.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            EnsureRefreshIdentity(enrollment, clientId, validated);
            if (validated.ExposesSecurityEpoch
                && validated.ExpectedSecurityEpoch != enrollment.SecurityEpoch)
                throw Conflict("security_epoch_mismatch");
            if (enrollment.State != "PENDING" || enrollment.ChallengeConsumedAtUtc != null)
                throw Conflict("enrollment_not_pending");
            var authorization = await db.DistributionLicenseBootstrapAuthorizations
                .SingleOrDefaultAsync(candidate => candidate.RuntimeEnrollmentId == enrollment.Id,
                    cancellationToken)
                ?? throw Reject("refresh_ineligible");
            try
            {
                await ValidateLicenseBootstrapAuthorityAsync(
                    db, enrollment, authorization, enrollment.ProductId, enrollment.BindingId,
                    enrollment.InstallationId, "CONSUMED", lease.AuthorityEpoch, now, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception)
                when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                throw Reject("refresh_ineligible");
            }

            if (!validated.ExposesSecurityEpoch && enrollment.SecurityEpoch != 1)
                throw RefreshV2Required();

            var existing = await FindRefreshReplayAsync(
                db, enrollment, clientId, validated.RequestId, exactBodyDigest,
                validated.ExposesSecurityEpoch, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            if (enrollment.ChallengeDigestSha256 != validated.ExpectedChallengeDigest)
                throw Conflict("refresh_conflict");
            await ReserveQuotasAsync(db, now,
                [("refresh-binding", validated.BindingId.ToString("D"), 30),
                 ("refresh-global", "all", 240)], cancellationToken);

            var challenge = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
            var challengeEnvelope = await _crypto.SealAsync(
                db, "enrollment-challenge", enrollment.Id, enrollment.Epoch,
                Encoding.ASCII.GetBytes(challenge),
                EnrollmentFieldReference(enrollment.Id, "ChallengeCiphertext"), cancellationToken);
            enrollment.ChallengeCiphertext = challengeEnvelope.Ciphertext;
            enrollment.ChallengeKeyId = challengeEnvelope.KeyId;
            enrollment.ChallengeDigestSha256 = Sha256(challenge);
            enrollment.ChallengeExpiresAtUtc = now.AddSeconds(_options.ChallengeTtlSeconds).UtcDateTime;
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;

            var response = new RuntimeEnrollmentPrepareResponse(
                validated.ExposesSecurityEpoch ? RefreshV2ResponseSchema : RefreshResponseSchema,
                ProtocolVersion, "pending", enrollment.Id.ToString("D"),
                enrollment.Epoch, challenge, FormatUtc(enrollment.ChallengeExpiresAtUtc),
                _options.ConfirmAudience)
            {
                SecurityEpoch = validated.ExposesSecurityEpoch ? enrollment.SecurityEpoch : null
            };
            var operation = new RuntimeEnrollmentRequest
            {
                ClientId = clientId,
                RequestId = validated.RequestId,
                Operation = "prepare",
                PayloadDigestSha256 = exactBodyDigest,
                EnrollmentId = enrollment.Id,
                CreatedAtUtc = now.UtcDateTime
            };
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var responseEnvelope = await _crypto.SealAsync(
                db, "prepare-response", operation.Id, 1, responseBytes,
                PrepareResponseReference(operation), cancellationToken);
            operation.ResponseCiphertext = responseEnvelope.Ciphertext;
            operation.ResponseKeyId = responseEnvelope.KeyId;
            db.RuntimeEnrollmentRequests.Add(operation);
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsPrepareRequestConstraint(exception))
            {
                throw Conflict("idempotency_conflict");
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>> IssueWebSetupTransitionAsync(
        string clientId,
        string exactBodyDigest,
        RuntimeWebSetupTransitionIssueRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var isLicenseTransfer = request.Schema == WebSetupTransitionIssueV2Schema;
        if (request.ExtensionData is { Count: > 0 }
            || (request.Schema != WebSetupTransitionIssueSchema && !isLicenseTransfer)
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId)
            || (isLicenseTransfer
                ? !TryUuid(request.SourceLicenseId, out _)
                    || !IsCanonicalReinstallSubjectRef(request.SourceSubjectRef)
                    || !TryUuid(request.TargetGrantRef, out _)
                    || !TryUuid(request.TargetLicenseId, out _)
                    || !IsCanonicalReinstallSubjectRef(request.TargetSubjectRef)
                    || request.TargetEntitlementRef is not { Length: >= 40 and <= 4096 }
                : request.SourceLicenseId != null || request.SourceSubjectRef != null
                    || request.TargetGrantRef != null || request.TargetLicenseId != null
                    || request.TargetSubjectRef != null || request.TargetEntitlementRef != null)
            || !SemanticVersion.TryParse(request.SourceVersion ?? string.Empty, out var sourceVersion)
            || !SemanticVersion.TryParse(request.TargetVersion ?? string.Empty, out var targetVersion)
            || targetVersion.CompareTo(sourceVersion) <= 0
            || request.TargetInstallerFilename is not { Length: >= 5 and <= 200 }
            || request.TargetInstallerFilename != Path.GetFileName(request.TargetInstallerFilename)
            || !request.TargetInstallerFilename.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
            || request.TargetInstallerFilename.Any(character => character < 0x20 || character > 0x7e)
            || !LowerSha256Pattern.IsMatch(request.TargetInstallerSha256 ?? string.Empty)
            || !LowerSha256Pattern.IsMatch(exactBodyDigest))
            throw Invalid();

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = isLicenseTransfer
                ? await _authority.AcquireMutationAsync(db, bindingId, cancellationToken)
                : await _authority.AcquireAsync(db, bindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, enrollmentId, cancellationToken);
            if (enrollment.BindingId != bindingId || enrollment.ClientId != clientId)
                throw Reject("websetup_transition_ineligible");
            var binding = await LoadBindingForUpdateAsync(db, bindingId, cancellationToken);
            var bindingOwnedByClient = await db.DistributionBindingRequests.AsNoTracking().AnyAsync(row =>
                row.BindingId == binding.Id && row.Operation == "finalize_binding" && row.ClientId == clientId,
                cancellationToken);
            if (!bindingOwnedByClient
                || binding.ProductId != productId
                || enrollment.ProductId != productId
                || binding.Version != request.SourceVersion
                || enrollment.ReleaseVersion != request.SourceVersion
                || binding.State != "active"
                || enrollment.State != "ACTIVE")
                throw Reject("websetup_transition_ineligible");

            var replay = await db.RuntimeEnrollmentWebSetupTransitionRequests.AsNoTracking()
                .SingleOrDefaultAsync(row => row.ClientId == clientId && row.Operation == "issue"
                    && row.RequestId == requestId.ToString("D"), cancellationToken);
            if (replay != null)
            {
                if (replay.PayloadDigestSha256 != exactBodyDigest)
                    throw Conflict("idempotency_conflict");
                var transition = await db.RuntimeEnrollmentWebSetupTransitions.AsNoTracking()
                    .SingleOrDefaultAsync(row => row.Id == replay.TransitionId, cancellationToken)
                    ?? throw Unavailable();
                if (transition.State != "ISSUED" || transition.ExpiresAtUtc <= now.UtcDateTime
                    || !WebSetupTransitionMatches(transition, clientId, binding, enrollment, request, lease.AuthorityEpoch))
                    throw Gone("websetup_transition_expired");
                var bytes = OpenWebSetupTransitionIssueResponse(replay);
                try
                {
                    var replayResponse = JsonSerializer.Deserialize<RuntimeWebSetupTransitionIssuedResponse>(bytes, JsonOptions)
                        ?? throw Unavailable();
                    await lease.CommitAsync(cancellationToken);
                    return new RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>(
                        replayResponse, true, bytes.ToArray());
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }

            if (isLicenseTransfer)
            {
                if (binding.LicenseId.ToString("D") != request.SourceLicenseId
                    || binding.SubjectRefDigestSha256 != Sha256(request.SourceSubjectRef!)
                    || enrollment.LicenseId != binding.LicenseId
                    || enrollment.LicenseSeatId != binding.LicenseSeatId
                    || enrollment.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256
                    || enrollment.InstallationId != binding.InstallationId
                    || enrollment.HardwareIdHash != binding.HardwareIdHash)
                    throw Reject("websetup_transition_ineligible");
                await ValidateBindingRowsAsync(
                    db, binding, now, cancellationToken, allowIneligibleSourceLicense: true);
            }
            else
            {
                await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            }

            var activeExists = await db.RuntimeEnrollmentWebSetupTransitions.AsNoTracking().AnyAsync(row =>
                row.EnrollmentId == enrollment.Id && row.State == "ISSUED" && row.ExpiresAtUtc > now.UtcDateTime,
                cancellationToken);
            if (activeExists) throw Conflict("websetup_transition_active");

            var targetBaselineCount = await db.ApprovedBinaries.AsNoTracking().CountAsync(candidate =>
                candidate.ProductId == productId && candidate.Version == request.TargetVersion
                    && candidate.Source == ApprovedBinaryService.ReleaseSource,
                cancellationToken);
            if (targetBaselineCount != 3) throw Reject("release_unapproved");
            var effectiveLicenseId = isLicenseTransfer
                ? Guid.Parse(request.TargetLicenseId!)
                : binding.LicenseId;
            var license = await db.Licenses.Include(candidate => candidate.Product)
                .Include(candidate => candidate.Type)
                .Include(candidate => candidate.Seats)
                .SingleOrDefaultAsync(candidate => candidate.Id == effectiveLicenseId, cancellationToken);
            if (license == null
                || !license.IsActive || license.RevokedAt != null
                || (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now.UtcDateTime)
                || license.MaxSeats < 1
                || !IsVersionAllowed(request.TargetVersion!, license.AllowedVersions)
                || IsVersionBelow(request.TargetVersion!, license.Product?.MinimumAllowedVersion))
                throw Reject("version_not_allowed");

            if (isLicenseTransfer)
            {
                if (await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(
                    incident => incident.BindingId == binding.Id && incident.State == "OPEN",
                    cancellationToken))
                    throw Reject("websetup_transition_ineligible");
                if (_distributionEntitlementProtector == null)
                    throw Unavailable();
                var entitlement = await DistributionInstallationBindingService.ReadEntitlementAsync(
                    db, _distributionEntitlementProtector, request.TargetEntitlementRef!, clientId,
                    productId, now, cancellationToken);
                if (entitlement.ContractVersion != 3
                    || entitlement.LicenseId != effectiveLicenseId
                    || entitlement.GrantRefDigestSha256 != Sha256(request.TargetGrantRef!)
                    || entitlement.SubjectRefDigestSha256 != Sha256(request.TargetSubjectRef!))
                    throw Reject("websetup_transition_ineligible");

                if (effectiveLicenseId == binding.LicenseId)
                    throw Reject("websetup_transition_ineligible");
                if (string.Equals(request.SourceSubjectRef, request.TargetSubjectRef, StringComparison.Ordinal))
                    throw Reject("websetup_transition_ineligible");
                var sourceLicenseId = binding.LicenseId;
                var sourceSeat = await db.LicenseSeats.SingleAsync(
                    candidate => candidate.Id == binding.LicenseSeatId, cancellationToken);
                sourceSeat.IsActive = false;
                sourceSeat.UnlinkedAt = now.UtcDateTime;
                var targetSeat = await EnsureRuntimeTransferSeatAsync(
                    db, license, sourceLicenseId, sourceSeat.HardwareId, request.TargetVersion!, clientId,
                    now, cancellationToken);
                binding.LicenseId = effectiveLicenseId;
                binding.LicenseSeatId = targetSeat.Id;
                binding.EntitlementId = entitlement.EntitlementId;
                binding.GrantRef = request.TargetGrantRef!;
                binding.GrantRefDigestSha256 = Sha256(request.TargetGrantRef!);
                binding.SubjectRefDigestSha256 = Sha256(request.TargetSubjectRef!);
                enrollment.LicenseId = effectiveLicenseId;
                enrollment.LicenseSeatId = targetSeat.Id;
                enrollment.SubjectRefDigestSha256 = binding.SubjectRefDigestSha256;
                var entitlementRow = await db.DistributionEntitlements.SingleAsync(
                    candidate => candidate.Id == entitlement.EntitlementId, cancellationToken);
                entitlementRow.State = "finalized";
                entitlementRow.FinalizedAtUtc = now.UtcDateTime;
            }

            var capabilityBytes = RandomNumberGenerator.GetBytes(32);
            var capability = EncodeBase64Url(capabilityBytes);
            CryptographicOperations.ZeroMemory(capabilityBytes);
            var transitionId = Guid.NewGuid();
            var expiresAt = now.AddSeconds(120);
            var transitionRow = new RuntimeEnrollmentWebSetupTransition
            {
                Id = transitionId,
                ClientId = clientId,
                ProductId = productId,
                BindingId = binding.Id,
                EnrollmentId = enrollment.Id,
                InstallationId = enrollment.InstallationId,
                SourceVersion = request.SourceVersion!,
                TargetVersion = request.TargetVersion!,
                TargetInstallerFilename = request.TargetInstallerFilename!,
                TargetInstallerSha256 = request.TargetInstallerSha256!,
                CapabilityDigestSha256 = Sha256(capability),
                SourceSecurityEpoch = enrollment.SecurityEpoch,
                AuthorityEpoch = lease.AuthorityEpoch,
                State = "ISSUED",
                IssuedAtUtc = now.UtcDateTime,
                ExpiresAtUtc = expiresAt.UtcDateTime
            };
            var response = new RuntimeWebSetupTransitionIssuedResponse(
                WebSetupTransitionCapabilitySchema, ProtocolVersion, transitionId.ToString("D"), capability,
                FormatUtc(expiresAt.UtcDateTime));
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var ownerReference = WebSetupTransitionIssueResponseReference(clientId, requestId, transitionId);
            var envelope = await _crypto.SealAsync(db, "websetup-transition-response", transitionId, 1,
                responseBytes, ownerReference, cancellationToken);
            db.RuntimeEnrollmentWebSetupTransitions.Add(transitionRow);
            db.RuntimeEnrollmentWebSetupTransitionRequests.Add(new RuntimeEnrollmentWebSetupTransitionRequest
            {
                ClientId = clientId,
                RequestId = requestId.ToString("D"),
                Operation = "issue",
                PayloadDigestSha256 = exactBodyDigest,
                TransitionId = transitionId,
                ExactResponseCiphertext = Encoding.ASCII.GetBytes(envelope.Ciphertext),
                ResponseKeyId = envelope.KeyId,
                CreatedAtUtc = now.UtcDateTime,
                ExpiresAtUtc = expiresAt.UtcDateTime
            });
            await db.SaveChangesAsync(cancellationToken);
            if (isLicenseTransfer)
            {
                var upgradedAuthorityEpoch = await CurrentAuthorityEpochAsync(db, cancellationToken);
                if (upgradedAuthorityEpoch <= lease.AuthorityEpoch)
                    throw Unavailable();
                enrollment.AuthorityEpoch = upgradedAuthorityEpoch;
                transitionRow.AuthorityEpoch = upgradedAuthorityEpoch;
                await db.SaveChangesAsync(cancellationToken);
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeWebSetupUpgradeResponse>> UpgradeFromWebSetupAsync(
        string clientId,
        string keyId,
        string exactBodyDigest,
        RuntimeWebSetupUpgradeRelayRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateWebSetupUpgradeRelay(request, exactBodyDigest);
        var preflight = await LoadProofPreflightAsync(validated.EnrollmentId, cancellationToken);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireMutationAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);
            VerifyProof(preflight, "websetup-upgrade", validated.AuthorizationDigest, validated.Proof,
                challengeRequired: false, audience: WebSetupUpgradeAudience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            var transition = await db.RuntimeEnrollmentWebSetupTransitions
                .SingleOrDefaultAsync(row => row.Id == validated.TransitionId, cancellationToken)
                ?? throw Reject("websetup_transition_invalid");
            if (!FixedDigestEquals(transition.CapabilityDigestSha256, Sha256(validated.Capability))
                || transition.ClientId != clientId
                || transition.ProductId != validated.ProductId
                || transition.EnrollmentId != validated.EnrollmentId
                || transition.BindingId != preflight.BindingId
                || transition.SourceVersion != validated.SourceVersion
                || transition.TargetVersion != validated.TargetVersion)
                throw Reject("websetup_transition_invalid");

            if (transition.State == "CONSUMED")
            {
                if (transition.ConsumedPayloadDigestSha256 != validated.AuthorizationDigest)
                    throw Conflict("websetup_transition_replay_rejected");
                await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
                var proofReplay = await FindProofReplayAsync<RuntimeWebSetupUpgradeResponse>(
                    db, enrollment, "websetup-upgrade", validated.Proof,
                    validated.AuthorizationDigest, cancellationToken);
                if (enrollment.ReleaseVersion != transition.TargetVersion
                    || enrollment.SecurityEpoch != checked(transition.SourceSecurityEpoch + 1))
                    throw Conflict("websetup_transition_replay_rejected");
                if (proofReplay != null)
                {
                    await lease.CommitAsync(cancellationToken);
                    return new RuntimeEnrollmentOperationResult<RuntimeWebSetupUpgradeResponse>(
                        proofReplay.Response, true, proofReplay.ExactBytes);
                }
                var operationReplay = await FindWebSetupUpgradeReplayAsync(
                    db, clientId, transition.Id, validated.AuthorizationDigest, cancellationToken)
                    ?? throw Conflict("websetup_transition_replay_rejected");
                if (!TryUtc(operationReplay.Response.ExpiresAtUtc, out var replayExpiresAt)
                    || replayExpiresAt <= now)
                    throw Gone("websetup_transition_replay_expired");
                var replayEnvelope = await _crypto.SealAsync(
                    db, ProofResponseOwnerType("websetup-upgrade"), validated.Proof.Jti,
                    enrollment.Epoch, operationReplay.ExactBytes,
                    ProofResponseReference(enrollment.Id, "websetup-upgrade", validated.Proof.Jti),
                    cancellationToken);
                db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                    enrollment, "websetup-upgrade", validated.Proof, validated.AuthorizationDigest,
                    replayEnvelope, lease.AuthorityEpoch, now));
                await db.SaveChangesAsync(cancellationToken);
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeWebSetupUpgradeResponse>(
                    operationReplay.Response, true, operationReplay.ExactBytes);
            }
            EnsurePreflightUnchanged(enrollment, preflight);
            if (transition.State != "ISSUED" || transition.ExpiresAtUtc <= now.UtcDateTime)
                throw Gone("websetup_transition_expired");

            try { await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken); }
            catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                await CommitInvalidationAsync(db, lease, enrollment, exception.ErrorCode, now, cancellationToken);
                throw;
            }
            var binding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
            if (enrollment.State != "ACTIVE"
                || enrollment.ProductId != validated.ProductId
                || enrollment.InstallationId != transition.InstallationId
                || enrollment.SecurityEpoch != transition.SourceSecurityEpoch
                || enrollment.ReleaseVersion != transition.SourceVersion
                || binding.State != "active"
                || binding.ProductId != validated.ProductId
                || binding.InstallationId != transition.InstallationId
                || binding.Version != transition.SourceVersion
                || transition.AuthorityEpoch != lease.AuthorityEpoch)
                throw Conflict("websetup_transition_binding_changed");

            var license = await db.Licenses.AsNoTracking().Include(candidate => candidate.Product)
                .SingleOrDefaultAsync(candidate => candidate.Id == binding.LicenseId, cancellationToken);
            if (license == null
                || !IsVersionAllowed(transition.TargetVersion, license.AllowedVersions)
                || IsVersionBelow(transition.TargetVersion, license.Product?.MinimumAllowedVersion))
                throw Reject("version_not_allowed");
            var targetBaselineRows = await db.ApprovedBinaries.AsNoTracking().Where(candidate =>
                    candidate.ProductId == validated.ProductId && candidate.Version == transition.TargetVersion)
                .ToListAsync(cancellationToken);
            var targetBaseline = targetBaselineRows
                .Where(candidate => candidate.Source == ApprovedBinaryService.ReleaseSource)
                .ToDictionary(candidate => candidate.Key, candidate => candidate.Hash, StringComparer.Ordinal);
            if (targetBaselineRows.Count != 3 || targetBaseline.Count != 3
                || validated.Binaries.Any(binary => !targetBaseline.TryGetValue(binary.Key!, out var expected)
                    || expected != binary.Sha256))
                throw Reject("release_unapproved");

            var componentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
                    ban.IsActive && (ban.ProductId == null || ban.ProductId == validated.ProductId)
                    && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
                .Select(ban => new { ban.ComponentType, ban.ComponentHash })
                .ToListAsync(cancellationToken);
            if (componentBans.Any(ban => validated.Binaries.Any(binary =>
                    string.Equals(binary.Key, ban.ComponentType, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(binary.Sha256,
                        ApprovedBinaryService.NormalizeSha256(ban.ComponentHash), StringComparison.Ordinal))))
                throw Reject("binary_mismatch");

            var oldSecurityEpoch = enrollment.SecurityEpoch;
            var newSecurityEpoch = checked(oldSecurityEpoch + 1);
            var transitionDigest = Sha256(string.Join('\n', transition.Id.ToString("D"),
                transition.ProductId.ToString("D"), transition.EnrollmentId.ToString("D"),
                transition.SourceVersion, transition.TargetVersion, transition.TargetInstallerFilename,
                transition.TargetInstallerSha256, transition.SourceSecurityEpoch.ToString(CultureInfo.InvariantCulture)));
            var response = new RuntimeWebSetupUpgradeResponse
            {
                Schema = WebSetupUpgradeResponseSchema,
                ProtocolVersion = ProtocolVersion,
                Alg = "PS256",
                KeyId = _crypto.ActiveSigningKeyId,
                Audience = WebSetupUpgradeAudience,
                Use = WebSetupUpgradeUse,
                RequestId = transition.Id.ToString("D"),
                ProductId = validated.ProductId.ToString("D"),
                EnrollmentId = enrollment.Id.ToString("D"),
                BindingId = binding.Id.ToString("D"),
                InstallationId = enrollment.InstallationId,
                SourceVersion = transition.SourceVersion,
                TargetVersion = transition.TargetVersion,
                OldSecurityEpoch = oldSecurityEpoch,
                NewSecurityEpoch = newSecurityEpoch,
                TransitionId = transition.Id.ToString("D"),
                TransitionDigestSha256 = transitionDigest,
                Decision = "upgraded",
                IssuedAtUtc = FormatUtc(now.UtcDateTime),
                ExpiresAtUtc = FormatUtc(now.AddMinutes(10).UtcDateTime),
                Signature = string.Empty
            };
            response = response with { Signature = _crypto.SignWebSetupUpgrade(response) };
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var operation = new RuntimeEnrollmentRequest
            {
                ClientId = clientId,
                RequestId = transition.Id.ToString("D"),
                Operation = "websetup-upgrade",
                PayloadDigestSha256 = validated.AuthorizationDigest,
                EnrollmentId = enrollment.Id,
                CreatedAtUtc = now.UtcDateTime
            };
            var operationEnvelope = await _crypto.SealAsync(db, "websetup-upgrade-response", operation.Id,
                enrollment.Epoch, responseBytes, ReleaseTransitionResponseReference(operation, "websetup-upgrade"),
                cancellationToken);
            operation.ResponseCiphertext = operationEnvelope.Ciphertext;
            operation.ResponseKeyId = operationEnvelope.KeyId;
            var proofEnvelope = await _crypto.SealAsync(db, ProofResponseOwnerType("websetup-upgrade"), validated.Proof.Jti,
                enrollment.Epoch, responseBytes,
                ProofResponseReference(enrollment.Id, "websetup-upgrade", validated.Proof.Jti), cancellationToken);

            var binaries = validated.Binaries.ToDictionary(binary => binary.Key!, binary => binary.Sha256!, StringComparer.Ordinal);
            binding.Version = transition.TargetVersion;
            binding.InstallerFilename = transition.TargetInstallerFilename;
            binding.InstallerSha256 = transition.TargetInstallerSha256;
            binding.ExecutableSha256 = binaries["FP_EXE"];
            binding.NativeDllSha256 = binaries["FP_DLL"];
            binding.CoreSha256 = binaries["FP_CORE"];
            binding.BoundAtUtc = now.UtcDateTime;
            enrollment.ReleaseVersion = transition.TargetVersion;
            enrollment.SecurityEpoch = newSecurityEpoch;
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            transition.State = "CONSUMED";
            transition.ConsumedAtUtc = now.UtcDateTime;
            transition.ConsumedPayloadDigestSha256 = validated.AuthorizationDigest;
            db.RuntimeEnrollmentRequests.Add(operation);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, "websetup-upgrade", validated.Proof, validated.AuthorizationDigest,
                proofEnvelope, lease.AuthorityEpoch, now));
            await db.SaveChangesAsync(cancellationToken);
            var upgradedAuthorityEpoch = await CurrentAuthorityEpochAsync(db, cancellationToken);
            if (upgradedAuthorityEpoch <= lease.AuthorityEpoch)
                throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
            enrollment.AuthorityEpoch = upgradedAuthorityEpoch;
            var proofNonce = await db.RuntimeEnrollmentProofNonces.SingleAsync(candidate =>
                candidate.EnrollmentId == enrollment.Id
                    && candidate.Jti == validated.Proof.Jti.ToString("D"), cancellationToken);
            proofNonce.AuthorityEpoch = upgradedAuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            _ = keyId;
            return new RuntimeEnrollmentOperationResult<RuntimeWebSetupUpgradeResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>> UpgradeAsync(
        string clientId,
        string keyId,
        string exactRelayDigest,
        RuntimeEnrollmentUpgradeRelayRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteReleaseTransitionAsync(
            clientId, keyId, exactRelayDigest, request, ReleaseTransition.Upgrade, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>> RollbackAsync(
        string clientId,
        string keyId,
        string exactRelayDigest,
        RuntimeEnrollmentUpgradeRelayRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteReleaseTransitionAsync(
            clientId, keyId, exactRelayDigest, request, ReleaseTransition.Rollback, cancellationToken);
    }

    private async Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>> ExecuteReleaseTransitionAsync(
        string clientId,
        string keyId,
        string exactRelayDigest,
        RuntimeEnrollmentUpgradeRelayRequest request,
        ReleaseTransition transition,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var validated = ValidateReleaseTransitionRelay(request, exactRelayDigest, transition);
        var preflight = await LoadProofPreflightAsync(validated.EnrollmentId, cancellationToken);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var replay = await FindReleaseTransitionReplayAsync(
                db, clientId, validated.RecoveryReceiptId, validated.AuthorizationDigest,
                transition, cancellationToken);
            if (replay != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>(
                    replay.Response, true, replay.ExactBytes);
            }

            var enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            var now = await DatabaseNowAsync(db, cancellationToken);
            VerifyProof(preflight, transition.Operation, validated.AuthorizationDigest, validated.Proof,
                challengeRequired: false, audience: transition.Audience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            try
            {
                await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                await CommitInvalidationAsync(db, lease, enrollment, exception.ErrorCode, now, cancellationToken);
                throw;
            }
            if (enrollment.State != "ACTIVE"
                || enrollment.ProductId != validated.ProductId
                || enrollment.InstallationId != validated.InstallationId
                || enrollment.SecurityEpoch != validated.SecurityEpoch
                || enrollment.ReleaseVersion != validated.SourceVersion)
                throw Conflict(transition.BindingConflictCode);

            var binding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
            if (binding.State != "active"
                || binding.ProductId != validated.ProductId
                || binding.InstallationId != validated.InstallationId
                || binding.Version != validated.SourceVersion
                || binding.HardwareIdHash != validated.RecoveryHardwareIdHash)
                throw Conflict(transition.BindingConflictCode);

            var license = await db.Licenses.AsNoTracking().Include(candidate => candidate.Product)
                .SingleOrDefaultAsync(candidate => candidate.Id == binding.LicenseId, cancellationToken);
            if (license == null
                || !IsVersionAllowed(validated.TargetVersion, license.AllowedVersions)
                || IsVersionBelow(validated.TargetVersion, license.Product?.MinimumAllowedVersion))
                throw Reject("version_not_allowed");

            var targetBaselineRows = await db.ApprovedBinaries.AsNoTracking().Where(candidate =>
                    candidate.ProductId == validated.ProductId && candidate.Version == validated.TargetVersion)
                .ToListAsync(cancellationToken);
            var targetBaseline = targetBaselineRows
                .Where(candidate => candidate.Source == ApprovedBinaryService.ReleaseSource)
                .ToDictionary(candidate => candidate.Key, candidate => candidate.Hash, StringComparer.Ordinal);
            if (targetBaselineRows.Count != 3 || targetBaseline.Count != 3
                || validated.Binaries.Any(binary => !targetBaseline.TryGetValue(binary.Key!, out var expected)
                    || expected != binary.Sha256))
                throw Reject("release_unapproved");

            var componentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
                    ban.IsActive && (ban.ProductId == null || ban.ProductId == validated.ProductId)
                    && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
                .Select(ban => new { ban.ComponentType, ban.ComponentHash })
                .ToListAsync(cancellationToken);
            if (componentBans.Any(ban => validated.Binaries.Any(binary =>
                    string.Equals(binary.Key, ban.ComponentType, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(binary.Sha256,
                        ApprovedBinaryService.NormalizeSha256(ban.ComponentHash), StringComparison.Ordinal))))
                throw Reject("binary_mismatch");

            var oldSecurityEpoch = enrollment.SecurityEpoch;
            var newSecurityEpoch = checked(oldSecurityEpoch + 1);
            var response = new RuntimeEnrollmentUpgradeResponse
            {
                Schema = transition.ResponseSchema,
                ProtocolVersion = ProtocolVersion,
                Alg = "PS256",
                KeyId = _crypto.ActiveSigningKeyId,
                Audience = transition.Audience,
                Use = transition.Use,
                RequestId = validated.RequestId,
                ProductId = validated.ProductId.ToString("D"),
                EnrollmentId = enrollment.Id.ToString("D"),
                BindingId = binding.Id.ToString("D"),
                InstallationId = enrollment.InstallationId,
                SourceVersion = validated.SourceVersion,
                TargetVersion = validated.TargetVersion,
                OldSecurityEpoch = oldSecurityEpoch,
                NewSecurityEpoch = newSecurityEpoch,
                RecoveryReceiptId = validated.RecoveryReceiptId,
                RecoveryReceiptDigestSha256 = validated.RecoveryReceiptDigestSha256,
                Decision = transition.Decision,
                IssuedAtUtc = FormatUtc(now.UtcDateTime),
                ExpiresAtUtc = FormatUtc(now.AddMinutes(10).UtcDateTime),
                Signature = string.Empty
            };
            response = response with { Signature = _crypto.SignUpgrade(response) };
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var operation = new RuntimeEnrollmentRequest
            {
                ClientId = clientId,
                RequestId = validated.RecoveryReceiptId,
                Operation = transition.Operation,
                PayloadDigestSha256 = validated.AuthorizationDigest,
                EnrollmentId = enrollment.Id,
                CreatedAtUtc = now.UtcDateTime
            };
            var operationEnvelope = await _crypto.SealAsync(
                db, transition.ResponseOwnerType, operation.Id, enrollment.Epoch, responseBytes,
                ReleaseTransitionResponseReference(operation, transition.Operation), cancellationToken);
            operation.ResponseCiphertext = operationEnvelope.Ciphertext;
            operation.ResponseKeyId = operationEnvelope.KeyId;
            var proofEnvelope = await _crypto.SealAsync(
                db, transition.ResponseOwnerType, validated.Proof.Jti, enrollment.Epoch, responseBytes,
                ProofResponseReference(enrollment.Id, transition.Operation, validated.Proof.Jti), cancellationToken);

            var binaries = validated.Binaries.ToDictionary(binary => binary.Key!, binary => binary.Sha256!, StringComparer.Ordinal);
            binding.Version = validated.TargetVersion;
            binding.InstallerFilename = validated.TargetInstallerFilename;
            binding.InstallerSha256 = validated.TargetInstallerSha256;
            binding.ExecutableSha256 = binaries["FP_EXE"];
            binding.NativeDllSha256 = binaries["FP_DLL"];
            binding.CoreSha256 = binaries["FP_CORE"];
            binding.BoundAtUtc = now.UtcDateTime;
            enrollment.ReleaseVersion = validated.TargetVersion;
            enrollment.SecurityEpoch = newSecurityEpoch;
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            db.RuntimeEnrollmentRequests.Add(operation);
            var proofNonce = NewProofNonce(
                enrollment, transition.Operation, validated.Proof, validated.AuthorizationDigest,
                proofEnvelope, lease.AuthorityEpoch, now);
            db.RuntimeEnrollmentProofNonces.Add(proofNonce);
            try
            {
                await db.SaveChangesAsync(cancellationToken);
                var upgradedAuthorityEpoch = await CurrentAuthorityEpochAsync(db, cancellationToken);
                if (upgradedAuthorityEpoch <= lease.AuthorityEpoch)
                    throw new RuntimeEnrollmentException(
                        "authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                enrollment.AuthorityEpoch = upgradedAuthorityEpoch;
                proofNonce.AuthorityEpoch = upgradedAuthorityEpoch;
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsPrepareRequestConstraint(exception))
            {
                throw Conflict(transition.ConflictCode);
            }
            await lease.CommitAsync(cancellationToken);
            _ = keyId;
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>> ConfirmAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeEnrollmentConfirmRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateConfirm(routeEnrollmentId, request, proof, exactBodyDigest);
        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            var existing = await FindProofReplayAsync<RuntimeEnrollmentConfirmResponse>(
                db, enrollment, "confirm", validated.Proof, exactBodyDigest, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>(
                    existing.Response, true, existing.ExactBytes);
            }
            var now = await DatabaseNowAsync(db, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("confirm-binding", preflight.BindingId.ToString("D"), 60),
                 ("confirm-credential", preflight.EnrollmentId.ToString("D"), 30),
                 ("confirm-ip", PseudonymizeAddress(clientAddress), 30),
                 ("confirm-global", "all", 240)], cancellationToken);
            VerifyProof(preflight, "confirm", exactBodyDigest, validated.Proof, challengeRequired: true);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            try
            {
                await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                await CommitInvalidationAsync(db, lease, enrollment, exception.ErrorCode, now, cancellationToken);
                throw;
            }
            if (enrollment.State != "PENDING")
                throw Conflict("enrollment_conflict");
            if (now.UtcDateTime >= enrollment.ChallengeExpiresAtUtc)
                throw new RuntimeEnrollmentException("challenge_expired", StatusCodes.Status410Gone);

            var response = new RuntimeEnrollmentConfirmResponse(
                ConfirmResponseSchema, ProtocolVersion, "active", enrollment.Id.ToString("D"),
                enrollment.Epoch, FormatUtc(now.UtcDateTime));
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var nonceOwnerId = validated.Proof.Jti;
            var envelope = await _crypto.SealAsync(db, "confirm-response", nonceOwnerId, enrollment.Epoch,
                responseBytes,
                ProofResponseReference(enrollment.Id, "confirm", nonceOwnerId), cancellationToken);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, "confirm", validated.Proof, exactBodyDigest, envelope, lease.AuthorityEpoch, now));
            enrollment.State = "ACTIVE";
            enrollment.ActivatedAtUtc = now.UtcDateTime;
            enrollment.ChallengeConsumedAtUtc = now.UtcDateTime;
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    /// <summary>
    /// Atomically replaces the current legacy seat identity with its deterministic V2 identity
    /// after proving the active Runtime enrollment and every linked server-side authority row.
    /// </summary>
    /// <param name="routeEnrollmentId">Canonical enrollment identifier from the request path.</param>
    /// <param name="exactBodyDigest">SHA-256 digest of the exact request body bytes.</param>
    /// <param name="request">Strict migration request signed by the enrolled Runtime key.</param>
    /// <param name="proof">Detached Runtime proof headers.</param>
    /// <param name="clientAddress">Remote address used only for bounded rate limiting.</param>
    /// <param name="cancellationToken">Request cancellation token.</param>
    /// <returns>The migrated authority generation and a license file signed for the V2 identifier.</returns>
    public async Task<RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>> MigrateHardwareAuthorityAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeHardwareAuthorityMigrationRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        if (_signedLicenseFiles == null)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        var validated = ValidateHardwareAuthorityMigration(routeEnrollmentId, request, proof, exactBodyDigest);
        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireMutationAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            if (await HasOpenCriticalIncidentAsync(
                    db, enrollment.BindingId, enrollment.InstallationId, cancellationToken))
            {
                throw new RuntimeEnrollmentException(
                    "critical_incident_unresolved", StatusCodes.Status423Locked);
            }
            var existing = await FindProofReplayAsync<RuntimeHardwareAuthorityMigrationResponse>(
                db, enrollment, "hardware-authority-migration", validated.Proof, exactBodyDigest, cancellationToken);
            if (existing != null)
            {
                var replayNow = await DatabaseNowAsync(db, cancellationToken);
                await ValidateEnrollmentAuthorityAsync(db, enrollment, replayNow, cancellationToken);
                var replayBinding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
                var replaySeat = await db.LicenseSeats.AsNoTracking().SingleOrDefaultAsync(candidate =>
                    candidate.Id == enrollment.LicenseSeatId, cancellationToken);
                var replayHardwareHash = Sha256(existing.Response.HardwareIdV2);
                var replayConflict = replaySeat == null
                    || enrollment.State != "ACTIVE"
                    || enrollment.SecurityEpoch != existing.Response.NewSecurityEpoch
                    || existing.Response.EnrollmentId != enrollment.Id.ToString("D")
                    || existing.Response.BindingId != replayBinding.Id.ToString("D")
                    || existing.Response.LicenseSeatId != replaySeat.Id.ToString("D")
                    || replayBinding.HardwareIdHash != replayHardwareHash
                    || enrollment.HardwareIdHash != replayHardwareHash
                    || !string.Equals(
                        replaySeat.HardwareId.ToUpperInvariant(), existing.Response.HardwareIdV2,
                        StringComparison.Ordinal)
                    || await db.LicenseSeats.AsNoTracking().AnyAsync(candidate =>
                        candidate.Id != replaySeat.Id && candidate.IsActive
                        && candidate.License!.ProductId == enrollment.ProductId
                        && candidate.HardwareId.ToUpper() == existing.Response.HardwareIdV2,
                        cancellationToken)
                    || await db.DistributionInstallationBindings.AsNoTracking().AnyAsync(candidate =>
                        candidate.Id != replayBinding.Id && candidate.ProductId == enrollment.ProductId
                        && candidate.State == "active" && candidate.HardwareIdHash == replayHardwareHash,
                        cancellationToken);
                if (replayConflict)
                    throw Conflict("hardware_authority_migration_conflict");
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            var now = await DatabaseNowAsync(db, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("hardware-migration-binding", preflight.BindingId.ToString("D"), 12),
                 ("hardware-migration-credential", preflight.EnrollmentId.ToString("D"), 6),
                 ("hardware-migration-ip", PseudonymizeAddress(clientAddress), 12),
                 ("hardware-migration-global", "all", 120)], cancellationToken);
            VerifyProof(preflight, "hardware-authority-migration", exactBodyDigest, validated.Proof,
                challengeRequired: false, _options.ConfirmAudience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            if (enrollment.State != "ACTIVE" || enrollment.SecurityEpoch != validated.SecurityEpoch)
                throw Conflict("hardware_authority_migration_conflict");

            var binding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
            var seat = await db.LicenseSeats.FromSqlInterpolated($"""
                SELECT * FROM public."LicenseSeats" WHERE "Id" = {enrollment.LicenseSeatId} FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken)
                ?? throw Reject("hardware_authority_migration_ineligible");
            var license = await db.Licenses.FromSqlInterpolated($"""
                SELECT * FROM public."Licenses" WHERE "Id" = {enrollment.LicenseId} FOR UPDATE
                """).Include(candidate => candidate.Product)
                .Include(candidate => candidate.Type).ThenInclude(type => type!.CustomParams)
                .SingleOrDefaultAsync(cancellationToken)
                ?? throw Reject("hardware_authority_migration_ineligible");

            var legacyHash = Sha256(validated.LegacyHardwareId);
            var stableHash = Sha256(validated.HardwareIdV2);
            var seatHardwareId = seat.HardwareId.ToUpperInvariant();
            var sourceIsLegacy = string.Equals(
                seatHardwareId, validated.LegacyHardwareId, StringComparison.Ordinal)
                && binding.HardwareIdHash == legacyHash && enrollment.HardwareIdHash == legacyHash;
            var targetIsAlreadyAuthoritative = string.Equals(
                seatHardwareId, validated.HardwareIdV2, StringComparison.Ordinal)
                && binding.HardwareIdHash == stableHash && enrollment.HardwareIdHash == stableHash;
            if (license.ProductId != enrollment.ProductId
                || !license.IsActive || license.RevokedAt != null
                || (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now.UtcDateTime)
                || seat.LicenseId != license.Id || !seat.IsActive
                || (!sourceIsLegacy && !targetIsAlreadyAuthoritative)
                || binding.LicenseId != license.Id || binding.LicenseSeatId != seat.Id
                || binding.ProductId != license.ProductId || binding.State != "active"
                || binding.InstallationId != enrollment.InstallationId
                || binding.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256)
                throw Reject("hardware_authority_migration_ineligible");

            await LockHardwareAuthorityAsync(db, license.ProductId, validated.HardwareIdV2, cancellationToken);
            var competingSeat = await db.LicenseSeats.AsNoTracking()
                .Where(candidate => candidate.Id != seat.Id && candidate.IsActive
                    && candidate.License!.ProductId == license.ProductId
                    && candidate.HardwareId.ToUpper() == validated.HardwareIdV2)
                .AnyAsync(cancellationToken);
            var competingBinding = await db.DistributionInstallationBindings.AsNoTracking().AnyAsync(candidate =>
                candidate.Id != binding.Id && candidate.ProductId == license.ProductId
                && candidate.State == "active" && candidate.HardwareIdHash == stableHash, cancellationToken);
            var ambiguousSeatAuthority = await db.DistributionInstallationBindings.AsNoTracking().AnyAsync(candidate =>
                candidate.Id != binding.Id && candidate.LicenseSeatId == seat.Id && candidate.State == "active",
                cancellationToken);
            var targetBanned = await db.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == license.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime)
                && ban.HardwareId.ToUpper() == validated.HardwareIdV2, cancellationToken);
            if (competingSeat || competingBinding || ambiguousSeatAuthority || targetBanned)
                throw Conflict("hardware_authority_migration_conflict");

            var oldSecurityEpoch = enrollment.SecurityEpoch;
            var migrated = sourceIsLegacy && !targetIsAlreadyAuthoritative;
            var committedSecurityEpoch = migrated
                ? checked(enrollment.SecurityEpoch + 1)
                : enrollment.SecurityEpoch;
            var requiresAlias = !string.Equals(
                validated.LegacyHardwareId, validated.HardwareIdV2, StringComparison.Ordinal);
            HardwareAuthorityAlias? existingAlias = null;
            if (requiresAlias)
            {
                existingAlias = await db.HardwareAuthorityAliases.SingleOrDefaultAsync(alias =>
                    alias.LicenseId == license.Id
                    && alias.LegacyHardwareIdSha256 == legacyHash,
                    cancellationToken);
                if (existingAlias != null
                    && (!existingAlias.IsActive
                        || existingAlias.ProductId != license.ProductId
                        || existingAlias.LicenseSeatId != seat.Id
                        || existingAlias.RuntimeEnrollmentId != enrollment.Id
                        || existingAlias.BindingId != binding.Id
                        || existingAlias.CanonicalHardwareIdSha256 != stableHash
                        || existingAlias.SecurityEpoch > committedSecurityEpoch
                        || existingAlias.AuthorityEpoch > lease.AuthorityEpoch))
                {
                    throw Conflict("hardware_authority_migration_conflict");
                }
                if (existingAlias == null)
                {
                    // The alias is created only inside the signed migration transaction after every
                    // seat, binding, enrollment, ban, and uniqueness authority check has succeeded.
                    db.HardwareAuthorityAliases.Add(new HardwareAuthorityAlias
                    {
                        ProductId = license.ProductId,
                        LicenseId = license.Id,
                        LicenseSeatId = seat.Id,
                        RuntimeEnrollmentId = enrollment.Id,
                        BindingId = binding.Id,
                        MigrationRequestId = validated.RequestId,
                        LegacyHardwareIdSha256 = legacyHash,
                        CanonicalHardwareIdSha256 = stableHash,
                        SecurityEpoch = committedSecurityEpoch,
                        AuthorityEpoch = lease.AuthorityEpoch,
                        CreatedAtUtc = now.UtcDateTime
                    });
                }
            }

            if (migrated)
            {
                seat.HardwareId = validated.HardwareIdV2;
                binding.HardwareIdHash = stableHash;
                enrollment.HardwareIdHash = stableHash;
                enrollment.SecurityEpoch = checked(enrollment.SecurityEpoch + 1);
                if (!string.IsNullOrEmpty(license.HardwareId)
                    && string.Equals(license.HardwareId.ToUpperInvariant(), validated.LegacyHardwareId, StringComparison.Ordinal))
                    license.HardwareId = validated.HardwareIdV2;
                db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = license.Id,
                    Timestamp = now.UtcDateTime,
                    Action = "HWID_V2_MIGRATED",
                    PerformedBy = enrollment.ClientId,
                    Details = JsonSerializer.Serialize(new
                    {
                        schema = HardwareAuthorityMigrationSchema,
                        enrollmentId = enrollment.Id.ToString("D"),
                        bindingId = binding.Id.ToString("D"),
                        seatId = seat.Id.ToString("D"),
                        legacyHardwareIdSha256 = legacyHash,
                        hardwareIdV2Sha256 = stableHash,
                        validated.LegacyAlgorithm,
                        validated.HardwareIdV2Algorithm,
                        validated.SdkVersion
                    }, JsonOptions)
                });
            }

            var licenseFile = _signedLicenseFiles.Generate(license, validated.HardwareIdV2);
            var response = new RuntimeHardwareAuthorityMigrationResponse(
                HardwareAuthorityMigrationResponseSchema, ProtocolVersion,
                migrated ? "migrated" : "already_current", validated.RequestId.ToString("D"),
                enrollment.Id.ToString("D"), binding.Id.ToString("D"), seat.Id.ToString("D"),
                oldSecurityEpoch, enrollment.SecurityEpoch, validated.HardwareIdV2, licenseFile,
                FormatUtc(now.UtcDateTime));
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var responseEnvelope = await _crypto.SealAsync(
                db, ProofResponseOwnerType("hardware-authority-migration"), validated.Proof.Jti,
                enrollment.Epoch, responseBytes,
                ProofResponseReference(enrollment.Id, "hardware-authority-migration", validated.Proof.Jti),
                cancellationToken);
            var proofNonce = NewProofNonce(
                enrollment, "hardware-authority-migration", validated.Proof, exactBodyDigest,
                responseEnvelope, lease.AuthorityEpoch, now);
            db.RuntimeEnrollmentProofNonces.Add(proofNonce);
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
            if (migrated)
            {
                var upgradedAuthorityEpoch = await CurrentAuthorityEpochAsync(db, cancellationToken);
                if (upgradedAuthorityEpoch <= lease.AuthorityEpoch)
                    throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                enrollment.AuthorityEpoch = upgradedAuthorityEpoch;
                proofNonce.AuthorityEpoch = upgradedAuthorityEpoch;
                var committedAlias = existingAlias ?? db.ChangeTracker.Entries<HardwareAuthorityAlias>()
                    .Select(entry => entry.Entity)
                    .Single(alias => alias.LicenseId == license.Id
                        && alias.LegacyHardwareIdSha256 == legacyHash
                        && alias.IsActive);
                committedAlias.AuthorityEpoch = upgradedAuthorityEpoch;
                await db.SaveChangesAsync(cancellationToken);
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>> CreateCapabilityAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeEnrollmentCapabilityRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateCapability(routeEnrollmentId, request, proof, exactBodyDigest);
        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);
        ValidateCapabilityAuthorization(preflight.ProductId, validated.Audience, validated.Scopes);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            if (await HasOpenCriticalIncidentAsync(
                    db, enrollment.BindingId, enrollment.InstallationId, cancellationToken))
            {
                throw new RuntimeEnrollmentException(
                    "critical_incident_unresolved", StatusCodes.Status423Locked);
            }
            if (validated.SecurityEpoch != enrollment.SecurityEpoch)
                throw Conflict("security_epoch_mismatch");
            var existing = await FindProofReplayAsync<RuntimeEnrollmentCapabilityResponse>(
                db, enrollment, "capability", validated.Proof, exactBodyDigest, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>(
                    existing.Response, true, existing.ExactBytes);
            }
            var now = await DatabaseNowAsync(db, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("capability-binding", preflight.BindingId.ToString("D"), 60),
                 ("capability-credential", preflight.EnrollmentId.ToString("D"), 30),
                 ("capability-ip", PseudonymizeAddress(clientAddress), 30),
                 ("capability-global", "all", 240)], cancellationToken);
            VerifyProof(preflight, "capability", exactBodyDigest, validated.Proof,
                challengeRequired: false, validated.Audience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            try
            {
                await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                await CommitInvalidationAsync(db, lease, enrollment, exception.ErrorCode, now, cancellationToken);
                throw;
            }
            if (enrollment.State != "ACTIVE")
                throw Reject("enrollment_inactive");
            ValidateCapabilityAuthorization(enrollment.ProductId, validated.Audience, validated.Scopes);
            var binding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
            ValidateCapabilityBinding(enrollment, binding, validated);

            var tokenJti = Guid.NewGuid().ToString("D");
            var token = validated.IsLegacy
                ? _crypto.SignLegacyCapability(
                    enrollment.Id, enrollment.Epoch, enrollment.SecurityEpoch,
                    validated.Audience, validated.Scopes,
                    enrollment.PublicKeySpkiSha256, now, tokenJti)
                : _crypto.SignCapability(
                    enrollment.Id, enrollment.Epoch, enrollment.SecurityEpoch,
                    enrollment.InstallationId, enrollment.ReleaseVersion, validated.SessionId!, validated.Binaries!,
                    validated.Audience, validated.Scopes,
                    enrollment.PublicKeySpkiSha256, now, tokenJti);
            var response = new RuntimeEnrollmentCapabilityResponse(
                CapabilityResponseSchema, ProtocolVersion, token, FormatUtc(now.AddSeconds(120).UtcDateTime));
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var envelope = await _crypto.SealAsync(db, "capability-response", validated.Proof.Jti,
                enrollment.Epoch, responseBytes,
                ProofResponseReference(enrollment.Id, "capability", validated.Proof.Jti), cancellationToken);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, "capability", validated.Proof, exactBodyDigest, envelope, lease.AuthorityEpoch, now));
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeMilestoneAckResponse>> RecordMilestoneAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeMilestoneRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateMilestone(routeEnrollmentId, request, proof, exactBodyDigest);
        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);
        ValidateMilestoneAuthorization(preflight.ProductId);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            var now = await DatabaseNowAsync(db, cancellationToken);
            try
            {
                await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                await CommitInvalidationAsync(db, lease, enrollment, exception.ErrorCode, now, cancellationToken);
                throw;
            }
            if (enrollment.State != "ACTIVE")
                throw Reject("enrollment_inactive");
            if (validated.SecurityEpoch != enrollment.SecurityEpoch)
                throw Conflict("security_epoch_mismatch");
            ValidateMilestoneAuthorization(enrollment.ProductId);

            var session = await db.RuntimeMilestoneSessions.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeMilestoneSessions"
                WHERE "EnrollmentId" = {enrollment.Id} AND "SessionId" = {validated.SessionId}
                FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken);
            if (session != null)
                EnsureMilestoneSessionActive(session, now);

            var existing = await FindProofReplayAsync<RuntimeMilestoneAckResponse>(
                db, enrollment, "milestone", validated.Proof, exactBodyDigest, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeMilestoneAckResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            await ReserveQuotasAsync(db, now,
                [("milestone-binding", preflight.BindingId.ToString("D"), 240),
                 ("milestone-credential", preflight.EnrollmentId.ToString("D"), 120),
                 ("milestone-ip", PseudonymizeAddress(clientAddress), 120),
                 ("milestone-global", "all", 960)], cancellationToken);
            VerifyProof(preflight, "milestone", exactBodyDigest, validated.Proof,
                challengeRequired: false, _options.ConfirmAudience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            var oldestAccepted = now.AddHours(-_options.ProofNonceRetentionHours);
            if (validated.OccurredAtUtc < oldestAccepted
                || validated.OccurredAtUtc > validated.Proof.SentAtUtc.AddSeconds(_options.ProofClockSkewSeconds))
                throw Invalid();

            if (session == null)
            {
                if (validated.Sequence != 1)
                    throw Conflict("sequence_out_of_order");
                session = new RuntimeMilestoneSession
                {
                    EnrollmentId = enrollment.Id,
                    SessionId = validated.SessionId,
                    SecurityEpoch = enrollment.SecurityEpoch,
                    LastSequence = 1,
                    CreatedAtUtc = now.UtcDateTime,
                    LastAcceptedAtUtc = now.UtcDateTime,
                    ExpiresAtUtc = now.AddHours(_options.ProofNonceRetentionHours).UtcDateTime
                };
                db.RuntimeMilestoneSessions.Add(session);
            }
            else
            {
                if (session.SecurityEpoch != enrollment.SecurityEpoch)
                    throw Conflict("security_epoch_mismatch");
                if (validated.Sequence != checked(session.LastSequence + 1))
                    throw Conflict("sequence_out_of_order");
                session.LastSequence = validated.Sequence;
                session.LastAcceptedAtUtc = now.UtcDateTime;
            }

            var response = new RuntimeMilestoneAckResponse(
                MilestoneAckSchema, ProtocolVersion, enrollment.Id.ToString("D"),
                validated.SessionId, validated.Sequence, validated.EventId,
                "client_declared", FormatUtc(now.UtcDateTime));
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var envelope = await _crypto.SealAsync(
                db, "milestone-response", validated.Proof.Jti, enrollment.Epoch, responseBytes,
                ProofResponseReference(enrollment.Id, "milestone", validated.Proof.Jti), cancellationToken);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, "milestone", validated.Proof, exactBodyDigest, envelope, lease.AuthorityEpoch, now));
            db.RuntimeMilestones.Add(new RuntimeMilestone
            {
                EnrollmentId = enrollment.Id,
                SessionId = validated.SessionId,
                Sequence = validated.Sequence,
                EventId = validated.EventId,
                Jti = validated.Proof.Jti.ToString("D"),
                Code = validated.Code,
                EvidenceClass = "client_declared",
                BodyDigestSha256 = exactBodyDigest,
                ProofDigestSha256 = validated.Proof.ProofDigest,
                AuthorityEpoch = lease.AuthorityEpoch,
                OccurredAtUtc = validated.OccurredAtUtc.UtcDateTime,
                AcceptedAtUtc = now.UtcDateTime,
                ExpiresAtUtc = session.ExpiresAtUtc
            });
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsMilestoneConstraint(exception))
            {
                throw Conflict("milestone_conflict");
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeMilestoneAckResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>> RefetchCriticalRecoveryForClientAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeCriticalRecoveryClientRefetchRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateCriticalRecoveryClientRefetch(
            routeEnrollmentId, request, proof, exactBodyDigest);
        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            var now = await DatabaseNowAsync(db, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("recovery-refetch-binding", preflight.BindingId.ToString("D"), 30),
                 ("recovery-refetch-credential", preflight.EnrollmentId.ToString("D"), 15),
                 ("recovery-refetch-ip", PseudonymizeAddress(clientAddress), 15),
                 ("recovery-refetch-global", "all", 120)], cancellationToken);
            VerifyProof(preflight, "critical-recovery-refetch", exactBodyDigest, validated.Proof,
                challengeRequired: false, _options.ConfirmAudience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            if (enrollment.State != "ACTIVE")
                throw Reject("enrollment_inactive");
            if (await HasOpenCriticalIncidentAsync(
                    db, enrollment.BindingId, enrollment.InstallationId, cancellationToken))
            {
                throw new RuntimeEnrollmentException(
                    "critical_incident_unresolved", StatusCodes.Status423Locked);
            }
            if (validated.SecurityEpoch >= enrollment.SecurityEpoch)
                throw Conflict("recovery_not_required");

            var existing = await FindProofReplayAsync<RuntimeCriticalRecoveryResponse>(
                db, enrollment, "critical-recovery-refetch", validated.Proof, exactBodyDigest, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            var nextEpoch = checked(validated.SecurityEpoch + 1);
            var recovery = await db.RuntimeCriticalRecoveries.AsNoTracking()
                .SingleOrDefaultAsync(candidate =>
                    candidate.EnrollmentId == enrollment.Id
                    && candidate.BindingId == enrollment.BindingId
                    && candidate.InstallationId == enrollment.InstallationId
                    && candidate.OldSecurityEpoch == validated.SecurityEpoch
                    && candidate.NewSecurityEpoch == nextEpoch,
                    cancellationToken)
                ?? throw new RuntimeEnrollmentException("recovery_unavailable", StatusCodes.Status404NotFound);
            var response = CreateCriticalRecoveryResponse(
                recovery.Id, validated.RequestId, recovery, now);
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var envelope = await _crypto.SealAsync(
                db, ProofResponseOwnerType("critical-recovery-refetch"), validated.Proof.Jti,
                enrollment.Epoch, responseBytes,
                ProofResponseReference(enrollment.Id, "critical-recovery-refetch", validated.Proof.Jti),
                cancellationToken);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, "critical-recovery-refetch", validated.Proof,
                exactBodyDigest, envelope, lease.AuthorityEpoch, now));
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<CanaryAckResponse>> ProcessCanaryAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        CanaryPingRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        if (_canaryAck == null)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        var canary = _canaryAck.ValidateCriticalRequest(request);
        var validatedProof = ValidateProofHeaders(proof);
        if (!LowerSha256Pattern.IsMatch(exactBodyDigest)
            || !_options.CanaryTriggers.Contains(canary.Trigger, StringComparer.Ordinal))
            throw Invalid();

        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);
        VerifyCanaryProof(preflight, canary.EventId, exactBodyDigest, validatedProof);

        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);

            var now = await DatabaseNowAsync(db, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("canary-binding", preflight.BindingId.ToString("D"), 60),
                 ("canary-credential", preflight.EnrollmentId.ToString("D"), 30),
                 ("canary-ip", PseudonymizeAddress(clientAddress), 30),
                 ("canary-global", "all", 240)], cancellationToken);
            ValidateProofTime(validatedProof.SentAtUtc, now);
            try
            {
                await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                await CommitInvalidationAsync(db, lease, enrollment, exception.ErrorCode, now, cancellationToken);
                throw;
            }
            if (enrollment.State != "ACTIVE")
                throw Reject("enrollment_inactive");
            if (Sha256(canary.HardwareId) != enrollment.HardwareIdHash
                || !string.Equals(canary.AppVersion, enrollment.ReleaseVersion, StringComparison.Ordinal))
                throw Reject("canary_binding_mismatch");

            var existing = await db.RuntimeCanaryProofNonces.AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.EnrollmentId == enrollment.Id
                    && candidate.Jti == validatedProof.Jti.ToString("D"), cancellationToken);
            if (existing != null)
            {
                if (!await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(
                        incident => incident.EventId == canary.EventId
                            && incident.BindingId == enrollment.BindingId
                            && incident.InstallationId == enrollment.InstallationId,
                        cancellationToken))
                {
                    throw new RuntimeEnrollmentException(
                        "authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                }
                var replay = OpenCanaryResponse(
                    enrollment, existing, canary, exactBodyDigest, validatedProof);
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<CanaryAckResponse>(replay.Response, true, replay.ExactBytes);
            }

            var response = _canaryAck.CreateReceipt(canary, "ack", now);
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var responseEnvelope = await _crypto.SealAsync(
                db, "canary-response", validatedProof.Jti, enrollment.Epoch, responseBytes,
                CanaryResponseReference(enrollment.Id, validatedProof.Jti), cancellationToken);

            db.RuntimeCanaryProofNonces.Add(new RuntimeCanaryProofNonce
            {
                EnrollmentId = enrollment.Id,
                Jti = validatedProof.Jti.ToString("D"),
                EventId = canary.EventId,
                BindingId = enrollment.BindingId,
                InstallationId = enrollment.InstallationId,
                HardwareIdHash = enrollment.HardwareIdHash,
                ReleaseVersion = enrollment.ReleaseVersion,
                BodyDigestSha256 = exactBodyDigest,
                ProofDigestSha256 = validatedProof.ProofDigest,
                ResponseCiphertext = responseEnvelope.Ciphertext,
                ResponseKeyId = responseEnvelope.KeyId,
                AuthorityEpoch = lease.AuthorityEpoch,
                SentAtUtc = validatedProof.SentAtUtc.UtcDateTime,
                ReservedAtUtc = now.UtcDateTime,
                ExpiresAtUtc = now.AddHours(_options.ProofNonceRetentionHours).UtcDateTime
            });
            db.RuntimeCriticalIncidents.Add(new RuntimeCriticalIncident
            {
                EnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                ProductId = enrollment.ProductId,
                InstallationId = enrollment.InstallationId,
                EventId = canary.EventId,
                Trigger = canary.Trigger,
                State = "OPEN",
                OpenedSecurityEpoch = enrollment.SecurityEpoch,
                OpenedAuthorityEpoch = lease.AuthorityEpoch,
                OpenedAtUtc = now.UtcDateTime
            });
            db.CanaryAlerts.Add(new CanaryAlert
            {
                HardwareId = canary.HardwareId,
                AppVersion = canary.AppVersion,
                Trigger = canary.Trigger,
                Severity = canary.Severity,
                ProductId = enrollment.ProductId,
                ServerAction = "authenticated_evidence"
            });
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsCanaryProofConstraint(exception))
            {
                throw Conflict("event_conflict");
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<CanaryAckResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>> RecoverCriticalAsync(
        string clientId,
        string keyId,
        string exactBodyDigest,
        RuntimeCriticalRecoveryRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateCriticalRecovery(request, exactBodyDigest);
        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, validated.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);

            var enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);
            if (enrollment.State != "ACTIVE"
                || enrollment.ProductId != validated.ProductId
                || enrollment.BindingId != validated.BindingId
                || enrollment.InstallationId != validated.InstallationId)
            {
                throw Conflict("recovery_binding_conflict");
            }
            var now = await DatabaseNowAsync(db, cancellationToken);
            await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);

            var replay = await FindCriticalRecoveryReceiptReplayAsync(
                db, validated.RequestId, exactBodyDigest, clientId, now, cancellationToken);
            if (replay != null)
            {
                if (enrollment.SecurityEpoch != validated.NewSecurityEpoch)
                    throw Conflict("recovery_generation_conflict");
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                    replay.Response, true, replay.ExactBytes);
            }

            if (enrollment.SecurityEpoch != validated.OldSecurityEpoch
                || validated.NewSecurityEpoch != checked(enrollment.SecurityEpoch + 1))
            {
                throw Conflict("recovery_binding_conflict");
            }

            var incidents = await db.RuntimeCriticalIncidents.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeCriticalIncidents"
                WHERE "BindingId" = {enrollment.BindingId}
                  AND "InstallationId" = {enrollment.InstallationId}
                  AND "State" = 'OPEN'
                ORDER BY "EventId" FOR UPDATE
                """).ToListAsync(cancellationToken);
            if (incidents.Count == 0
                || incidents.Any(incident => incident.OpenedSecurityEpoch > validated.OldSecurityEpoch)
                || !incidents.Any(incident => incident.EventId == validated.EventId))
            {
                throw Conflict("recovery_generation_conflict");
            }

            var recovery = new RuntimeCriticalRecovery
            {
                EnrollmentId = enrollment.Id,
                BindingId = enrollment.BindingId,
                ProductId = enrollment.ProductId,
                InstallationId = enrollment.InstallationId,
                RequestedEventId = validated.EventId,
                OldSecurityEpoch = validated.OldSecurityEpoch,
                NewSecurityEpoch = validated.NewSecurityEpoch,
                ResolvedIncidentCount = incidents.Count,
                AuthorityEpoch = lease.AuthorityEpoch,
                RecoveredByClientId = clientId,
                RecoveredByKeyId = keyId,
                RecoveredAtUtc = now.UtcDateTime
            };
            db.RuntimeCriticalRecoveries.Add(recovery);

            var response = CreateCriticalRecoveryResponse(
                recovery.Id, validated.RequestId, recovery, now);
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            db.RuntimeCriticalRecoveryReceipts.Add(new RuntimeCriticalRecoveryReceipt
            {
                RecoveryId = recovery.Id,
                RequestId = validated.RequestId,
                RequestDigestSha256 = exactBodyDigest,
                RequestedByClientId = clientId,
                RequestedByKeyId = keyId,
                IssuedAtUtc = now.UtcDateTime,
                ExpiresAtUtc = now.AddHours(CriticalRecoveryReceiptTtlHours).UtcDateTime,
                ExactResponseBody = responseBytes
            });

            foreach (var incident in incidents)
            {
                incident.State = "RESOLVED";
                incident.RecoveryId = recovery.Id;
                incident.RecoveredSecurityEpoch = validated.NewSecurityEpoch;
                incident.RecoveredAuthorityEpoch = lease.AuthorityEpoch;
                incident.RecoveredAtUtc = now.UtcDateTime;
            }
            enrollment.SecurityEpoch = validated.NewSecurityEpoch;
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsCriticalRecoveryConstraint(exception))
            {
                throw Conflict("recovery_conflict");
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    public async Task<RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>> RefetchCriticalRecoveryAsync(
        string clientId,
        string keyId,
        string exactBodyDigest,
        RuntimeCriticalRecoveryRefetchRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateCriticalRecoveryRefetch(request, exactBodyDigest);
        return await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, validated.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);

            var recovery = await db.RuntimeCriticalRecoveries.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeCriticalRecoveries"
                WHERE "Id" = {validated.RecoveryId} FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken)
                ?? throw new RuntimeEnrollmentException("recovery_unavailable", StatusCodes.Status404NotFound);
            if (recovery.ProductId != validated.ProductId
                || recovery.BindingId != validated.BindingId
                || recovery.InstallationId != validated.InstallationId
                || recovery.RequestedEventId != validated.EventId
                || recovery.NewSecurityEpoch != validated.NewSecurityEpoch)
            {
                throw Conflict("recovery_binding_conflict");
            }

            var enrollment = await LoadEnrollmentForUpdateAsync(db, recovery.EnrollmentId, cancellationToken);
            if (enrollment.State != "ACTIVE"
                || enrollment.ProductId != recovery.ProductId
                || enrollment.BindingId != recovery.BindingId
                || enrollment.InstallationId != recovery.InstallationId
                || enrollment.SecurityEpoch != recovery.NewSecurityEpoch)
            {
                throw Conflict("recovery_generation_conflict");
            }
            var now = await DatabaseNowAsync(db, cancellationToken);
            await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
            if (await HasOpenCriticalIncidentAsync(
                    db, recovery.BindingId, recovery.InstallationId, cancellationToken))
            {
                throw Conflict("recovery_generation_conflict");
            }

            var replay = await FindCriticalRecoveryReceiptReplayAsync(
                db, validated.RequestId, exactBodyDigest, clientId, now, cancellationToken);
            if (replay != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                    replay.Response, true, replay.ExactBytes);
            }

            var response = CreateCriticalRecoveryResponse(
                recovery.Id, validated.RequestId, recovery, now);
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            db.RuntimeCriticalRecoveryReceipts.Add(new RuntimeCriticalRecoveryReceipt
            {
                RecoveryId = recovery.Id,
                RequestId = validated.RequestId,
                RequestDigestSha256 = exactBodyDigest,
                RequestedByClientId = clientId,
                RequestedByKeyId = keyId,
                IssuedAtUtc = now.UtcDateTime,
                ExpiresAtUtc = now.AddHours(CriticalRecoveryReceiptTtlHours).UtcDateTime,
                ExactResponseBody = responseBytes
            });
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsCriticalRecoveryConstraint(exception))
            {
                throw Conflict("recovery_conflict");
            }
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    private RuntimeCriticalRecoveryResponse CreateCriticalRecoveryResponse(
        Guid recoveryId,
        string requestId,
        RuntimeCriticalRecovery recovery,
        DateTimeOffset issuedAt)
    {
        var response = new RuntimeCriticalRecoveryResponse
        {
            Schema = CriticalRecoveryResponseSchema,
            ProtocolVersion = ProtocolVersion,
            Alg = "PS256",
            KeyId = _crypto.ActiveSigningKeyId,
            Audience = CriticalRecoveryAudience,
            Use = CriticalRecoveryUse,
            RecoveryId = recoveryId.ToString("D"),
            RequestId = requestId,
            ProductId = recovery.ProductId.ToString("D"),
            EnrollmentId = recovery.EnrollmentId.ToString("D"),
            BindingId = recovery.BindingId.ToString("D"),
            InstallationId = recovery.InstallationId,
            EventId = recovery.RequestedEventId,
            OldSecurityEpoch = recovery.OldSecurityEpoch,
            NewSecurityEpoch = recovery.NewSecurityEpoch,
            Decision = "recovered",
            IssuedAtUtc = FormatUtc(issuedAt.UtcDateTime),
            ExpiresAtUtc = FormatUtc(issuedAt.AddHours(CriticalRecoveryReceiptTtlHours).UtcDateTime),
            Signature = string.Empty
        };
        return response with { Signature = _crypto.SignRecovery(response) };
    }

    private static async Task<StoredResponse<RuntimeCriticalRecoveryResponse>?> FindCriticalRecoveryReceiptReplayAsync(
        LicenseDbContext db,
        string requestId,
        string bodyDigest,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var receipt = await db.RuntimeCriticalRecoveryReceipts.AsNoTracking()
            .Include(candidate => candidate.Recovery)
            .SingleOrDefaultAsync(candidate => candidate.RequestId == requestId, cancellationToken);
        if (receipt == null)
            return null;
        if (receipt.RequestDigestSha256 != bodyDigest
            || receipt.RequestedByClientId != clientId
            || receipt.Recovery == null)
        {
            throw Conflict("recovery_conflict");
        }
        if (await HasOpenCriticalIncidentAsync(
                db, receipt.Recovery.BindingId, receipt.Recovery.InstallationId, cancellationToken))
        {
            throw Conflict("recovery_generation_conflict");
        }
        if (receipt.ExpiresAtUtc <= now.UtcDateTime || receipt.ExactResponseBody == null)
        {
            throw new RuntimeEnrollmentException(
                "recovery_receipt_expired", StatusCodes.Status410Gone);
        }
        if (receipt.ExactResponseBody.Length is < 1 or > 8192)
            throw new RuntimeEnrollmentException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        try
        {
            var response = JsonSerializer.Deserialize<RuntimeCriticalRecoveryResponse>(
                receipt.ExactResponseBody, JsonOptions) ?? throw new JsonException();
            return new StoredResponse<RuntimeCriticalRecoveryResponse>(
                response, receipt.ExactResponseBody.ToArray());
        }
        catch (JsonException)
        {
            throw new RuntimeEnrollmentException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        }
    }

    private StoredResponse<CanaryAckResponse> OpenCanaryResponse(
        RuntimeEnrollment enrollment,
        RuntimeCanaryProofNonce nonce,
        CanaryAckValidatedRequest canary,
        string bodyDigest,
        ProofValidated proof)
    {
        if (nonce.EventId != canary.EventId
            || nonce.BindingId != enrollment.BindingId
            || nonce.InstallationId != enrollment.InstallationId
            || nonce.HardwareIdHash != enrollment.HardwareIdHash
            || nonce.ReleaseVersion != enrollment.ReleaseVersion
            || nonce.BodyDigestSha256 != bodyDigest
            || nonce.ProofDigestSha256 != proof.ProofDigest)
            throw Conflict("event_conflict");
        try
        {
            var bytes = _crypto.Open("canary-response", proof.Jti, enrollment.Epoch,
                nonce.ResponseKeyId, nonce.ResponseCiphertext,
                CanaryResponseReference(enrollment.Id, proof.Jti));
            var response = JsonSerializer.Deserialize<CanaryAckResponse>(bytes, JsonOptions)
                ?? throw new JsonException();
            return new StoredResponse<CanaryAckResponse>(response, bytes);
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        }
    }

    private async Task<StoredResponse<RuntimeEnrollmentPrepareResponse>?> FindPrepareReplayAsync(
        LicenseDbContext db,
        string clientId,
        string requestId,
        string bodyDigest,
        bool exposesSecurityEpoch,
        CancellationToken cancellationToken)
    {
        var operation = await db.RuntimeEnrollmentRequests.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ClientId == clientId && candidate.Operation == "prepare" && candidate.RequestId == requestId,
            cancellationToken);
        if (operation == null)
            return null;
        if (operation.PayloadDigestSha256 != bodyDigest)
            throw Conflict("idempotency_conflict");
        var stored = OpenResponse<RuntimeEnrollmentPrepareResponse>(
            "prepare-response", operation.Id, 1, operation.ResponseKeyId, operation.ResponseCiphertext,
            PrepareResponseReference(operation));
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == operation.EnrollmentId, cancellationToken)
            ?? throw new RuntimeEnrollmentException("enrollment_unavailable", StatusCodes.Status404NotFound);
        if (!exposesSecurityEpoch && enrollment.SecurityEpoch != 1)
            throw PrepareV2Required();
        var expectedSchema = exposesSecurityEpoch ? PrepareV2ResponseSchema : PrepareResponseSchema;
        if (stored.Response.Schema != expectedSchema
            || stored.Response.ProtocolVersion != ProtocolVersion
            || stored.Response.Epoch != enrollment.Epoch
            || (exposesSecurityEpoch
                ? stored.Response.SecurityEpoch != enrollment.SecurityEpoch
                : stored.Response.SecurityEpoch != null)
            || enrollment.ChallengeDigestSha256 != Sha256(stored.Response.Challenge))
            throw Conflict("prepare_superseded");
        return stored;
    }

    private async Task<StoredResponse<RuntimeEnrollmentPrepareResponse>?> FindRefreshReplayAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        string clientId,
        string requestId,
        string bodyDigest,
        bool exposesSecurityEpoch,
        CancellationToken cancellationToken)
    {
        var operation = await db.RuntimeEnrollmentRequests.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ClientId == clientId && candidate.Operation == "prepare" && candidate.RequestId == requestId,
            cancellationToken);
        if (operation == null)
            return null;
        if (operation.PayloadDigestSha256 != bodyDigest || operation.EnrollmentId != enrollment.Id)
            throw Conflict("idempotency_conflict");
        var stored = OpenResponse<RuntimeEnrollmentPrepareResponse>(
            "prepare-response", operation.Id, 1, operation.ResponseKeyId, operation.ResponseCiphertext,
            PrepareResponseReference(operation));
        var expectedSchema = exposesSecurityEpoch ? RefreshV2ResponseSchema : RefreshResponseSchema;
        int? expectedSecurityEpoch = exposesSecurityEpoch ? enrollment.SecurityEpoch : null;
        if (stored.Response.Schema != expectedSchema
            || stored.Response.ProtocolVersion != ProtocolVersion
            || stored.Response.SecurityEpoch != expectedSecurityEpoch
            || enrollment.ChallengeDigestSha256 != Sha256(stored.Response.Challenge))
            throw Conflict("refresh_superseded");
        return stored;
    }

    private async Task<StoredResponse<RuntimeEnrollmentUpgradeResponse>?> FindReleaseTransitionReplayAsync(
        LicenseDbContext db,
        string clientId,
        string recoveryReceiptId,
        string authorizationDigest,
        ReleaseTransition transition,
        CancellationToken cancellationToken)
    {
        var operation = await db.RuntimeEnrollmentRequests.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ClientId == clientId && candidate.Operation == transition.Operation
                && candidate.RequestId == recoveryReceiptId, cancellationToken);
        if (operation == null)
            return null;
        if (operation.PayloadDigestSha256 != authorizationDigest)
            throw Conflict(transition.ReceiptReusedCode);
        return OpenResponse<RuntimeEnrollmentUpgradeResponse>(
            transition.ResponseOwnerType, operation.Id, 1, operation.ResponseKeyId,
            operation.ResponseCiphertext,
            ReleaseTransitionResponseReference(operation, transition.Operation));
    }

    private async Task<StoredResponse<RuntimeWebSetupUpgradeResponse>?> FindWebSetupUpgradeReplayAsync(
        LicenseDbContext db,
        string clientId,
        Guid transitionId,
        string authorizationDigest,
        CancellationToken cancellationToken)
    {
        var requestId = transitionId.ToString("D");
        var operation = await db.RuntimeEnrollmentRequests.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ClientId == clientId && candidate.Operation == "websetup-upgrade"
                && candidate.RequestId == requestId, cancellationToken);
        if (operation == null)
            return null;
        if (operation.PayloadDigestSha256 != authorizationDigest)
            throw Conflict("websetup_transition_replay_rejected");
        return OpenResponse<RuntimeWebSetupUpgradeResponse>(
            "websetup-upgrade-response", operation.Id, 1, operation.ResponseKeyId,
            operation.ResponseCiphertext,
            ReleaseTransitionResponseReference(operation, "websetup-upgrade"));
    }

    private async Task<StoredResponse<T>?> FindProofReplayAsync<T>(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        string operation,
        ProofValidated proof,
        string bodyDigest,
        CancellationToken cancellationToken)
    {
        var nonce = await db.RuntimeEnrollmentProofNonces.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.EnrollmentId == enrollment.Id && candidate.Jti == proof.Jti.ToString("D"), cancellationToken);
        if (nonce == null)
            return default;
        if (nonce.Operation != operation
            || nonce.BodyDigestSha256 != bodyDigest
            || nonce.ProofDigestSha256 != proof.ProofDigest)
            throw Conflict("replay_rejected");
        return OpenResponse<T>(ProofResponseOwnerType(operation), proof.Jti, enrollment.Epoch,
            nonce.ResponseKeyId, nonce.ResponseCiphertext,
            ProofResponseReference(enrollment.Id, operation, proof.Jti));
    }

    /// <summary>Maps proof operations to bounded cryptographic owner domains.</summary>
    private static string ProofResponseOwnerType(string operation) =>
        operation == "critical-recovery-refetch"
            ? "recovery-refetch-response"
            : operation == "hardware-authority-migration"
                ? "hardware-migration-response"
                : operation + "-response";

    private StoredResponse<T> OpenResponse<T>(
        string ownerType, Guid ownerId, int epoch, string keyId, string ciphertext, string ownerReference)
    {
        try
        {
            var bytes = _crypto.Open(ownerType, ownerId, epoch, keyId, ciphertext, ownerReference);
            try
            {
                var response = JsonSerializer.Deserialize<T>(bytes, JsonOptions)
                    ?? throw new JsonException("Runtime response empty.");
                return new StoredResponse<T>(response, bytes);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw;
            }
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        }
    }

    private async Task<ProofPreflight> LoadProofPreflightAsync(Guid enrollmentId, CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == enrollmentId, cancellationToken)
            ?? throw new RuntimeEnrollmentException("enrollment_unavailable", StatusCodes.Status404NotFound);
        byte[] spki = [];
        byte[] challengeBytes = [];
        try
        {
            spki = _crypto.Open("enrollment-spki", enrollment.Id, enrollment.Epoch,
                enrollment.PublicKeySpkiKeyId, enrollment.PublicKeySpkiCiphertext,
                EnrollmentFieldReference(enrollment.Id, "PublicKeySpkiCiphertext"));
            challengeBytes = _crypto.Open("enrollment-challenge", enrollment.Id, enrollment.Epoch,
                enrollment.ChallengeKeyId, enrollment.ChallengeCiphertext,
                EnrollmentFieldReference(enrollment.Id, "ChallengeCiphertext"));
            return new ProofPreflight(
                enrollment.Id, enrollment.BindingId, enrollment.ProductId, enrollment.Epoch,
                enrollment.State, enrollment.PublicKeySpkiSha256, enrollment.KeyThumbprint,
                spki.ToArray(), Encoding.ASCII.GetString(challengeBytes));
        }
        catch (CryptographicException)
        {
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
            CryptographicOperations.ZeroMemory(challengeBytes);
        }
    }

    private static void EnsurePreflightUnchanged(RuntimeEnrollment enrollment, ProofPreflight preflight)
    {
        if (enrollment.BindingId != preflight.BindingId
            || enrollment.ProductId != preflight.ProductId
            || enrollment.Epoch != preflight.Epoch
            || enrollment.PublicKeySpkiSha256 != preflight.SpkiSha256
            || enrollment.KeyThumbprint != preflight.Thumbprint)
            throw Conflict("enrollment_conflict");
    }

    private async Task ValidateBindingAuthorityAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        string clientId,
        PrepareValidated request,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (binding.State != "active"
            || binding.ProductId != request.ProductId
            || binding.HandoffDigestSha256 != request.HandoffDigest
            || binding.InstallationId != request.InstallationId
            || binding.Version != request.ReleaseVersion)
            throw Reject("binding_ineligible");
        var owned = await db.DistributionBindingRequests.AsNoTracking().AnyAsync(candidate =>
            candidate.BindingId == binding.Id
            && candidate.Operation == "finalize_binding"
            && candidate.ClientId == clientId, cancellationToken);
        if (!owned)
            throw Reject("binding_ineligible");
        await ValidateBindingRowsAsync(db, binding, now, cancellationToken);
    }

    internal static async Task ValidateEnrollmentAuthorityAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == enrollment.BindingId, cancellationToken)
            ?? throw Reject("binding_ineligible");
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.LicenseId != enrollment.LicenseId
            || binding.LicenseSeatId != enrollment.LicenseSeatId
            || binding.InstallationId != enrollment.InstallationId
            || binding.HardwareIdHash != enrollment.HardwareIdHash
            || binding.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || binding.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256
            || binding.Version != enrollment.ReleaseVersion)
            throw Reject("binding_ineligible");
        var owned = await db.DistributionBindingRequests.AsNoTracking().AnyAsync(candidate =>
            candidate.BindingId == binding.Id
            && candidate.Operation == "finalize_binding"
            && candidate.ClientId == enrollment.ClientId, cancellationToken);
        if (!owned)
            throw Reject("binding_ineligible");
        await ValidateBindingRowsAsync(db, binding, now, cancellationToken);
    }

    private static async Task CommitInvalidationAsync(
        LicenseDbContext db,
        RuntimeAuthorityLease lease,
        RuntimeEnrollment enrollment,
        string reason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        enrollment.State = "INVALIDATED";
        enrollment.InvalidatedAtUtc = now.UtcDateTime;
        enrollment.InvalidationReason = reason;
        enrollment.AuthorityEpoch = lease.AuthorityEpoch;
        await db.SaveChangesAsync(cancellationToken);
        await lease.CommitAsync(cancellationToken);
    }

    private static async Task ValidateBindingRowsAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        bool allowIneligibleSourceLicense = false)
    {
        var license = await db.Licenses.AsNoTracking().Include(candidate => candidate.Product)
            .SingleOrDefaultAsync(candidate => candidate.Id == binding.LicenseId, cancellationToken);
        var seat = await db.LicenseSeats.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == binding.LicenseSeatId, cancellationToken);
        if (license == null || seat == null
            || license.ProductId != binding.ProductId
            || (!allowIneligibleSourceLicense && (!license.IsActive || license.RevokedAt != null
                || (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now.UtcDateTime)
                || license.MaxSeats < 1))
            || !seat.IsActive || seat.LicenseId != license.Id
            || Sha256(seat.HardwareId) != binding.HardwareIdHash
            || (!allowIneligibleSourceLicense
                && (!IsVersionAllowed(binding.Version, license.AllowedVersions)
                    || IsVersionBelow(binding.Version, license.Product?.MinimumAllowedVersion))))
            throw Reject("authority_ineligible");

        var activeSeatCount = await db.LicenseSeats.AsNoTracking()
            .CountAsync(candidate => candidate.LicenseId == license.Id && candidate.IsActive, cancellationToken);
        if (!allowIneligibleSourceLicense && activeSeatCount > license.MaxSeats)
            throw Reject("authority_ineligible");
        var canonicalHardwareId = seat.HardwareId.ToUpperInvariant();
        var hardwareBanned = await db.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
            ban.IsActive && (ban.ProductId == null || ban.ProductId == binding.ProductId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime)
            && ban.HardwareId.ToUpper() == canonicalHardwareId, cancellationToken);
        if (hardwareBanned)
            throw Reject("authority_ineligible");
        var componentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
            ban.IsActive && (ban.ProductId == null || ban.ProductId == binding.ProductId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash }).ToListAsync(cancellationToken);
        var evidence = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["FP_EXE"] = binding.ExecutableSha256,
            ["FP_DLL"] = binding.NativeDllSha256,
            ["FP_CORE"] = binding.CoreSha256
        };
        if (componentBans.Any(ban => evidence.TryGetValue(ban.ComponentType, out var hash)
            && string.Equals(ApprovedBinaryService.NormalizeSha256(ban.ComponentHash), hash,
                StringComparison.OrdinalIgnoreCase)))
            throw Reject("authority_ineligible");
        var baselines = await db.ApprovedBinaries.AsNoTracking().Where(row =>
            row.ProductId == binding.ProductId && row.Version == binding.Version).ToListAsync(cancellationToken);
        if (baselines.Count != evidence.Count || baselines.Any(row =>
            row.Source != ApprovedBinaryService.ReleaseSource
            || !evidence.TryGetValue(row.Key, out var expected)
            || !string.Equals(row.Hash, expected, StringComparison.OrdinalIgnoreCase)))
            throw Reject("authority_ineligible");
    }

    /// <summary>
    /// Moves the current hardware to the user-selected eligible license while the source binding
    /// remains locked. The caller deactivates the source seat in the same transaction first.
    /// </summary>
    private static async Task<LicenseSeat> EnsureRuntimeTransferSeatAsync(
        LicenseDbContext db,
        License targetLicense,
        Guid sourceLicenseId,
        string hardwareId,
        string targetVersion,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var activeSeat = targetLicense.Seats.SingleOrDefault(candidate =>
            candidate.IsActive && string.Equals(candidate.HardwareId, hardwareId, StringComparison.Ordinal));
        if (activeSeat != null)
        {
            activeSeat.LastCheckInAt = now.UtcDateTime;
            activeSeat.AppVersion = targetVersion;
            return activeSeat;
        }
        if (targetLicense.Type?.DisableNewActivations == true)
            throw Reject("new_activations_disabled");
        var conflictingHardware = await db.LicenseSeats.AsNoTracking().AnyAsync(candidate =>
            candidate.IsActive && candidate.HardwareId == hardwareId
                && candidate.LicenseId != sourceLicenseId && candidate.LicenseId != targetLicense.Id
                && candidate.License != null && candidate.License.ProductId == targetLicense.ProductId,
            cancellationToken);
        if (conflictingHardware)
            throw Reject("hardware_already_bound");
        if (targetLicense.Type?.EnforceSingleUsePerHardwareId == true)
        {
            var consumedElsewhere = await db.Licenses.AsNoTracking().AnyAsync(candidate =>
                candidate.ProductId == targetLicense.ProductId
                    && candidate.LicenseTypeId == targetLicense.LicenseTypeId
                    && candidate.Id != targetLicense.Id && candidate.Id != sourceLicenseId
                    && (candidate.HardwareId == hardwareId
                        || candidate.Seats.Any(seat => seat.HardwareId == hardwareId)),
                cancellationToken);
            if (consumedElsewhere)
                throw Reject("hardware_already_consumed");
        }
        var activeSeatCount = targetLicense.Seats.Count(candidate => candidate.IsActive);
        if (activeSeatCount >= targetLicense.MaxSeats)
            throw Reject("seat_limit_reached");
        var maxActivationsPerDay = targetLicense.Type?.MaxActivationsPerDay ?? 0;
        if (maxActivationsPerDay > 0)
        {
            var dayStart = now.UtcDateTime.Date;
            var activationsToday = await db.LicenseSeats.AsNoTracking().CountAsync(candidate =>
                candidate.LicenseId == targetLicense.Id && candidate.FirstActivatedAt >= dayStart,
                cancellationToken);
            if (activationsToday >= maxActivationsPerDay)
                throw Reject("activation_rate_limited");
        }
        var seat = targetLicense.Seats
            .Where(candidate => !candidate.IsActive
                && string.Equals(candidate.HardwareId, hardwareId, StringComparison.Ordinal))
            .OrderByDescending(candidate => candidate.FirstActivatedAt)
            .FirstOrDefault();
        var action = "RUNTIME_WEBSETUP_SEAT_REACTIVATED";
        if (seat == null)
        {
            seat = new LicenseSeat
            {
                LicenseId = targetLicense.Id,
                HardwareId = hardwareId,
                FirstActivatedAt = now.UtcDateTime
            };
            db.LicenseSeats.Add(seat);
            action = "RUNTIME_WEBSETUP_SEAT_CREATED";
        }
        seat.IsActive = true;
        seat.UnlinkedAt = null;
        seat.LastCheckInAt = now.UtcDateTime;
        seat.AppVersion = targetVersion;
        if (activeSeatCount == 0 || string.IsNullOrEmpty(targetLicense.HardwareId))
        {
            targetLicense.HardwareId = hardwareId;
            targetLicense.ActivationDate = seat.FirstActivatedAt;
        }
        db.LicenseHistories.Add(new LicenseHistory
        {
            LicenseId = targetLicense.Id,
            Timestamp = now.UtcDateTime,
            Action = action,
            Details = "Authenticated WebSetup selection transferred the existing runtime installation.",
            PerformedBy = clientId
        });
        return seat;
    }

    private static async Task<DistributionInstallationBinding> LoadBindingForUpdateAsync(
        LicenseDbContext db, Guid bindingId, CancellationToken cancellationToken) =>
        await db.DistributionInstallationBindings.FromSqlInterpolated(
            $"SELECT * FROM public.\"DistributionInstallationBindings\" WHERE \"Id\" = {bindingId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken)
        ?? throw new RuntimeEnrollmentException("binding_unavailable", StatusCodes.Status404NotFound);

    private static async Task<RuntimeEnrollment> LoadEnrollmentForUpdateAsync(
        LicenseDbContext db, Guid enrollmentId, CancellationToken cancellationToken) =>
        await db.RuntimeEnrollments.FromSqlInterpolated(
            $"SELECT * FROM public.\"RuntimeEnrollments\" WHERE \"Id\" = {enrollmentId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken)
        ?? throw new RuntimeEnrollmentException("enrollment_unavailable", StatusCodes.Status404NotFound);

    private static Task<bool> HasOpenCriticalIncidentAsync(
        LicenseDbContext db,
        Guid bindingId,
        string installationId,
        CancellationToken cancellationToken) =>
        db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(incident =>
            incident.BindingId == bindingId
            && incident.InstallationId == installationId
            && incident.State == "OPEN", cancellationToken);

    private static async Task LockThumbprintAsync(
        LicenseDbContext db,
        string thumbprint,
        CancellationToken cancellationToken)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText =
            "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(@thumbprint, 999832));";
        command.Parameters.Add(new NpgsqlParameter("thumbprint", thumbprint));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// Serializes migrations targeting the same product and canonical hardware identity so
    /// competing seats cannot pass conflict checks concurrently.
    /// </summary>
    /// <param name="db">Database context with an active authority transaction.</param>
    /// <param name="productId">Product authority boundary.</param>
    /// <param name="hardwareId">Canonical uppercase V2 hardware identifier.</param>
    /// <param name="cancellationToken">Request cancellation token.</param>
    private static async Task LockHardwareAuthorityAsync(
        LicenseDbContext db,
        Guid productId,
        string hardwareId,
        CancellationToken cancellationToken)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText =
            "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(@authority, 999833));";
        command.Parameters.Add(new NpgsqlParameter(
            "authority", string.Concat(productId.ToString("D"), ":", hardwareId)));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private void VerifyProof(
        ProofPreflight enrollment,
        string operation,
        string bodyDigest,
        ProofValidated proof,
        bool challengeRequired,
        string? audience = null)
    {
        var path = BuildProofPath(enrollment.EnrollmentId, operation);
        var payload = BuildProofPayload(
            operation, enrollment.EnrollmentId, enrollment.Epoch, path,
            audience ?? _options.ConfirmAudience, proof.Timestamp,
            proof.Jti.ToString("D"), challengeRequired ? enrollment.Challenge : "-", bodyDigest);
        byte[]? signature = null;
        try
        {
            signature = DecodeBase64Url(proof.SignatureBase64Url);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(enrollment.Spki, out var consumed);
            if (consumed != enrollment.Spki.Length || rsa.KeySize != 3072
                || !rsa.VerifyData(Encoding.UTF8.GetBytes(payload), signature,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw AuthenticationFailed();
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            throw AuthenticationFailed();
        }
        finally
        {
            if (signature != null)
                CryptographicOperations.ZeroMemory(signature);
        }
    }

    /// <summary>Builds the canonical request path bound into a Runtime possession proof.</summary>
    /// <param name="enrollmentId">Enrollment identifier formatted as a lowercase UUID.</param>
    /// <param name="operation">Reviewed proof operation identifier.</param>
    /// <returns>The exact public API path for the operation.</returns>
    public static string BuildProofPath(Guid enrollmentId, string operation)
    {
        var suffix = operation == "license-bootstrap"
            ? "license-bootstrap"
            : operation == "hardware-authority-migration"
            ? "hardware-authority-migrations"
            : operation == "confirm"
            ? "confirm"
            : operation == "capability"
                ? "capabilities"
                : operation == "milestone"
                    ? "milestones"
                    : operation == "upgrade"
                        ? "upgrades"
                        : operation == "websetup-upgrade"
                            ? "websetup-upgrades"
                        : operation == "rollback"
                            ? "recovery-rollbacks"
                            : "critical-recoveries/refetch";
        return $"/api/v1/runtime-enrollments/{enrollmentId:D}/{suffix}";
    }

    private void VerifyCanaryProof(
        ProofPreflight enrollment,
        string eventId,
        string bodyDigest,
        ProofValidated proof)
    {
        var payload = BuildCanaryProofPayload(
            enrollment.EnrollmentId, enrollment.Epoch, _options.CanaryAudience,
            proof.Timestamp, proof.Jti.ToString("D"), eventId, bodyDigest);
        byte[]? signature = null;
        try
        {
            signature = DecodeBase64Url(proof.SignatureBase64Url);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(enrollment.Spki, out var consumed);
            if (consumed != enrollment.Spki.Length || rsa.KeySize != 3072
                || !rsa.VerifyData(Encoding.UTF8.GetBytes(payload), signature,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw AuthenticationFailed();
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            throw AuthenticationFailed();
        }
        finally
        {
            if (signature != null)
                CryptographicOperations.ZeroMemory(signature);
        }
    }

    public static string BuildCanaryProofPayload(
        Guid enrollmentId,
        int epoch,
        string audience,
        string timestamp,
        string jti,
        string eventId,
        string bodyDigest) => string.Join('\n',
            "canary-event-proof-v1", "PS256", enrollmentId.ToString("D"),
            epoch.ToString(CultureInfo.InvariantCulture), "POST", "/api/health/ping", audience,
            timestamp, jti, eventId, bodyDigest);

    public static string BuildProofPayload(
        string operation,
        Guid enrollmentId,
        int epoch,
        string path,
        string audience,
        string timestamp,
        string jti,
        string challenge,
        string bodyDigest) => string.Join('\n',
            "runtime-enrollment-proof-v1", "PS256", operation, enrollmentId.ToString("D"),
            epoch.ToString(CultureInfo.InvariantCulture), "POST", path, audience,
            timestamp, jti, challenge, bodyDigest);

    private void ValidateCapabilityAuthorization(Guid productId, string audience, IReadOnlyList<string> scopes)
    {
        var product = _options.Products.SingleOrDefault(candidate => candidate.ProductId == productId.ToString("D"));
        var grant = product?.Capabilities.SingleOrDefault(candidate => candidate.Audience == audience);
        if (grant == null || scopes.Any(scope => !grant.Scopes.Contains(scope, StringComparer.Ordinal)))
            throw Reject("capability_not_allowed");
    }

    private void ValidateMilestoneAuthorization(Guid productId)
    {
        var product = _options.Products.SingleOrDefault(candidate => candidate.ProductId == productId.ToString("D"));
        if (product == null || !product.Capabilities.Any(capability =>
                capability.Scopes.Contains("milestone:write", StringComparer.Ordinal)))
            throw Reject("capability_not_allowed");
    }

    private static void EnsureMilestoneSessionActive(
        RuntimeMilestoneSession session,
        DateTimeOffset now)
    {
        if (session.ExpiresAtUtc <= now.UtcDateTime)
            throw Conflict("session_expired");
    }

    private static async Task ReserveQuotasAsync(
        LicenseDbContext db,
        DateTimeOffset now,
        IReadOnlyList<(string Scope, string Subject, int Limit)> quotas,
        CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql() || db.Database.CurrentTransaction == null)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        var window = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0, DateTimeKind.Utc);
        foreach (var quota in quotas)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = (NpgsqlTransaction)db.Database.CurrentTransaction.GetDbTransaction();
            command.CommandText = """
                INSERT INTO public."RuntimeEnrollmentQuotas"
                    ("Scope", "SubjectPseudonym", "WindowStartedAtUtc", "Count", "ExpiresAtUtc")
                VALUES (@scope, @subject, @window, 1, @expires)
                ON CONFLICT ("Scope", "SubjectPseudonym", "WindowStartedAtUtc") DO UPDATE
                SET "Count" = public."RuntimeEnrollmentQuotas"."Count" + 1
                WHERE public."RuntimeEnrollmentQuotas"."Count" < @limit
                RETURNING "Count";
                """;
            command.Parameters.AddWithValue("scope", quota.Scope);
            command.Parameters.AddWithValue("subject", quota.Subject);
            command.Parameters.AddWithValue("window", window);
            command.Parameters.AddWithValue("expires", window.AddMinutes(2));
            command.Parameters.AddWithValue("limit", quota.Limit);
            if (await command.ExecuteScalarAsync(cancellationToken) == null)
                throw new RuntimeEnrollmentException("rate_limited", StatusCodes.Status429TooManyRequests);
        }
    }

    private string PseudonymizeAddress(IPAddress? address)
    {
        if (address == null)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        var key = Convert.FromBase64String(_options.IpPseudonymKeyBase64);
        try
        {
            using var hmac = new HMACSHA256(key);
            return Convert.ToHexStringLower(hmac.ComputeHash(address.GetAddressBytes()));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private async Task<T> ExecuteWithRetriesAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < _options.MaximumTransactionAttempts; attempt++)
        {
            try
            {
                return await action();
            }
            catch (Exception exception) when (IsRetryable(exception))
            {
                if (attempt + 1 >= _options.MaximumTransactionAttempts)
                    throw new RuntimeEnrollmentException(
                        "authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                await Task.Delay(Random.Shared.Next(20, 80) * (attempt + 1), cancellationToken);
            }
        }
        throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
    }

    private static bool IsRetryable(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres && postgres.SqlState is "40001" or "40P01" or "55P03")
                return true;
        return false;
    }

    private static bool IsLiveEnrollmentConstraint(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres && postgres.SqlState == PostgresErrorCodes.UniqueViolation
                && postgres.ConstraintName is "IX_RuntimeEnrollments_BindingId" or "IX_RuntimeEnrollments_KeyThumbprint")
                return true;
        return false;
    }

    private static bool IsPrepareRequestConstraint(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres && postgres.SqlState == PostgresErrorCodes.UniqueViolation
                && postgres.ConstraintName == "IX_RuntimeEnrollmentRequests_ClientId_Operation_RequestId")
                return true;
        return false;
    }

    private static bool IsCanaryProofConstraint(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres
                && postgres.SqlState == PostgresErrorCodes.UniqueViolation
                && postgres.ConstraintName is "PK_RuntimeCanaryProofNonces"
                    or "IX_RuntimeCanaryProofNonces_EventId"
                    or "IX_RuntimeCriticalIncidents_EventId")
                return true;
        return false;
    }

    private static bool IsCriticalRecoveryConstraint(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres
                && postgres.SqlState == PostgresErrorCodes.UniqueViolation
                && (postgres.ConstraintName == "IX_RuntimeCriticalRecoveryReceipts_RequestId"
                    || (postgres.ConstraintName?.StartsWith(
                        "IX_RuntimeCriticalRecoveries_BindingId_InstallationId_NewSecur",
                        StringComparison.Ordinal) ?? false)))
                return true;
        return false;
    }

    private static bool IsMilestoneConstraint(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres
                && postgres.SqlState == PostgresErrorCodes.UniqueViolation
                && postgres.ConstraintName is "PK_RuntimeMilestones"
                    or "IX_RuntimeMilestones_EventId"
                    or "IX_RuntimeMilestones_EnrollmentId_Jti"
                    or "IX_RuntimeMilestones_EnrollmentId_SessionId_Code")
                return true;
        return false;
    }

    private RuntimeEnrollmentProofNonce NewProofNonce(
        RuntimeEnrollment enrollment,
        string operation,
        ProofValidated proof,
        string bodyDigest,
        RuntimeEncryptedValue envelope,
        long authorityEpoch,
        DateTimeOffset now) => new()
    {
        EnrollmentId = enrollment.Id,
        Operation = operation,
        Jti = proof.Jti.ToString("D"),
        ProofDigestSha256 = proof.ProofDigest,
        BodyDigestSha256 = bodyDigest,
        ResponseCiphertext = envelope.Ciphertext,
        ResponseKeyId = envelope.KeyId,
        AuthorityEpoch = authorityEpoch,
        SentAtUtc = proof.SentAtUtc.UtcDateTime,
        ReservedAtUtc = now.UtcDateTime,
        ExpiresAtUtc = now.AddHours(_options.ProofNonceRetentionHours).UtcDateTime
    };

    private static PrepareValidated ValidatePrepare(RuntimeEnrollmentPrepareRequest request, string digest)
    {
        var exposesSecurityEpoch = request.Schema == PrepareV2Schema;
        if (!LowerSha256Pattern.IsMatch(digest)
            || request.ExtensionData is { Count: > 0 }
            || (!exposesSecurityEpoch && request.Schema != PrepareSchema)
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out _)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.InstallationId, out _)
            || !LowerSha256Pattern.IsMatch(request.HandoffDigestSha256 ?? string.Empty)
            || !SemanticVersion.TryParse(request.ReleaseVersion ?? string.Empty, out _)
            || request.Epoch != 1 || request.Key == null || request.Key.ExtensionData is { Count: > 0 })
            throw Invalid();
        return new PrepareValidated(request.RequestId!, productId, bindingId, request.HandoffDigestSha256!,
            request.InstallationId!, request.ReleaseVersion!, exposesSecurityEpoch);
    }

    private static RefreshValidated ValidateRefresh(RuntimeEnrollmentRefreshRequest request, string digest)
    {
        var exposesSecurityEpoch = request.Schema == RefreshV2Schema;
        if (!LowerSha256Pattern.IsMatch(digest)
            || request.ExtensionData is { Count: > 0 }
            || (!exposesSecurityEpoch && request.Schema != RefreshSchema)
            || (exposesSecurityEpoch
                ? request.ExpectedSecurityEpoch is null or <= 0
                : request.ExpectedSecurityEpoch != null)
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out _)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId)
            || !LowerSha256Pattern.IsMatch(request.ExpectedChallengeDigestSha256 ?? string.Empty))
            throw Invalid();
        return new RefreshValidated(
            request.RequestId!, productId, bindingId, enrollmentId,
            request.ExpectedChallengeDigestSha256!, request.ExpectedSecurityEpoch, exposesSecurityEpoch);
    }

    private static void EnsureRefreshIdentity(
        RuntimeEnrollment enrollment,
        string clientId,
        RefreshValidated request)
    {
        if (enrollment.ClientId != clientId
            || enrollment.ProductId != request.ProductId
            || enrollment.BindingId != request.BindingId
            || enrollment.Id != request.EnrollmentId
            || !LowerSha256Pattern.IsMatch(enrollment.SubjectRefDigestSha256 ?? string.Empty))
            throw Reject("refresh_ineligible");
    }

    private static UpgradeValidated ValidateReleaseTransitionRelay(
        RuntimeEnrollmentUpgradeRelayRequest request,
        string exactRelayDigest,
        ReleaseTransition transition)
    {
        if (!LowerSha256Pattern.IsMatch(exactRelayDigest)
            || request.ExtensionData is { Count: > 0 }
            || request.Schema != transition.RelaySchema
            || request.ProtocolVersion != ProtocolVersion
            || request.AuthorizationBodyBase64Url is not { Length: >= 100 and <= 3500 }
            || request.AuthorizationBodyBase64Url.Contains('=')
            || request.AuthorizationBodyBase64Url.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            throw Invalid();

        byte[] authorizationBytes;
        try
        {
            authorizationBytes = DecodeBase64Url(request.AuthorizationBodyBase64Url);
            if (EncodeBase64Url(authorizationBytes) != request.AuthorizationBodyBase64Url)
                throw Invalid();
        }
        catch (FormatException)
        {
            throw Invalid();
        }
        try
        {
            ValidateStrictJson(authorizationBytes);
            var authorization = JsonSerializer.Deserialize<RuntimeEnrollmentUpgradeAuthorization>(
                authorizationBytes, StrictJsonOptions) ?? throw Invalid();
            var proof = ValidateProofHeaders(new RuntimeProofHeaders(
                request.ProofTimestamp ?? string.Empty,
                request.ProofJti ?? string.Empty,
                request.ProofSignature ?? string.Empty));
            if (authorization.ExtensionData is { Count: > 0 }
                || authorization.Schema != transition.AuthorizationSchema
                || authorization.ProtocolVersion != ProtocolVersion
                || !TryUuid(authorization.RequestId, out _)
                || !TryUuid(authorization.RecoveryReceiptId, out _)
                || authorization.RequestId != authorization.RecoveryReceiptId
                || !TryUuid(authorization.ProductId, out var productId)
                || !TryUuid(authorization.EnrollmentId, out var enrollmentId)
                || !TryUuid(authorization.InstallationId, out _)
                || authorization.Epoch != 1
                || authorization.SecurityEpoch is null or < 1
                || !SemanticVersion.TryParse(authorization.SourceVersion ?? string.Empty, out var sourceVersion)
                || !SemanticVersion.TryParse(authorization.TargetVersion ?? string.Empty, out var targetVersion)
                || (transition.IsRollback
                    ? targetVersion.CompareTo(sourceVersion) >= 0
                    : targetVersion.CompareTo(sourceVersion) <= 0)
                || authorization.TargetInstallerFilename is not { Length: >= 5 and <= 200 }
                || authorization.TargetInstallerFilename != Path.GetFileName(authorization.TargetInstallerFilename)
                || !authorization.TargetInstallerFilename.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
                || authorization.TargetInstallerFilename.Any(character => character < 0x20 || character > 0x7e)
                || !LowerSha256Pattern.IsMatch(authorization.TargetInstallerSha256 ?? string.Empty)
                || !LowerSha256Pattern.IsMatch(authorization.RecoveryReceiptDigestSha256 ?? string.Empty)
                || !LowerSha256Pattern.IsMatch(authorization.RecoveryHardwareIdHash ?? string.Empty)
                || authorization.Binaries is not { Count: 3 }
                || authorization.Binaries.Any(binary => binary.ExtensionData is { Count: > 0 }
                    || binary.Key == null || binary.Sha256 == null)
                || !authorization.Binaries.Select(binary => binary.Key!).SequenceEqual(
                    new[] { "FP_CORE", "FP_DLL", "FP_EXE" }, StringComparer.Ordinal)
                || authorization.Binaries.Any(binary => !LowerSha256Pattern.IsMatch(binary.Sha256!)))
                throw Invalid();
            return new UpgradeValidated(
                authorization.RequestId!, productId, enrollmentId, authorization.InstallationId!,
                authorization.SecurityEpoch.Value, authorization.SourceVersion!, authorization.TargetVersion!,
                authorization.TargetInstallerFilename!, authorization.TargetInstallerSha256!,
                authorization.RecoveryReceiptId!, authorization.RecoveryReceiptDigestSha256!,
                authorization.RecoveryHardwareIdHash!, authorization.Binaries,
                Convert.ToHexStringLower(SHA256.HashData(authorizationBytes)), proof);
        }
        catch (JsonException)
        {
            throw Invalid();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authorizationBytes);
        }
    }

    private static WebSetupUpgradeValidated ValidateWebSetupUpgradeRelay(
        RuntimeWebSetupUpgradeRelayRequest request,
        string exactRelayDigest)
    {
        if (!LowerSha256Pattern.IsMatch(exactRelayDigest)
            || request.ExtensionData is { Count: > 0 }
            || request.Schema != WebSetupUpgradeSchema
            || request.ProtocolVersion != ProtocolVersion
            || request.AuthorizationBodyBase64Url is not { Length: >= 100 and <= 3500 }
            || request.AuthorizationBodyBase64Url.Contains('=')
            || request.AuthorizationBodyBase64Url.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            throw Invalid();

        byte[] authorizationBytes;
        try
        {
            authorizationBytes = DecodeBase64Url(request.AuthorizationBodyBase64Url);
            if (EncodeBase64Url(authorizationBytes) != request.AuthorizationBodyBase64Url)
                throw Invalid();
        }
        catch (FormatException)
        {
            throw Invalid();
        }
        try
        {
            ValidateStrictJson(authorizationBytes);
            var authorization = JsonSerializer.Deserialize<RuntimeWebSetupUpgradeAuthorization>(
                authorizationBytes, StrictJsonOptions) ?? throw Invalid();
            var proof = ValidateProofHeaders(new RuntimeProofHeaders(
                request.ProofTimestamp ?? string.Empty,
                request.ProofJti ?? string.Empty,
                request.ProofSignature ?? string.Empty));
            if (authorization.ExtensionData is { Count: > 0 }
                || authorization.Schema != WebSetupUpgradeAuthorizationSchema
                || authorization.ProtocolVersion != ProtocolVersion
                || !TryUuid(authorization.ProductId, out var productId)
                || !TryUuid(authorization.EnrollmentId, out var enrollmentId)
                || !TryUuid(authorization.TransitionId, out var transitionId)
                || authorization.Capability is not { Length: 43 }
                || !Base64Url43Pattern.IsMatch(authorization.Capability)
                || !SemanticVersion.TryParse(authorization.SourceVersion ?? string.Empty, out var sourceVersion)
                || !SemanticVersion.TryParse(authorization.TargetVersion ?? string.Empty, out var targetVersion)
                || targetVersion.CompareTo(sourceVersion) <= 0
                || authorization.Binaries is not { Count: 3 }
                || authorization.Binaries.Any(binary => binary.ExtensionData is { Count: > 0 }
                    || binary.Key == null || binary.Sha256 == null)
                || !authorization.Binaries.Select(binary => binary.Key!).SequenceEqual(
                    new[] { "FP_CORE", "FP_DLL", "FP_EXE" }, StringComparer.Ordinal)
                || authorization.Binaries.Any(binary => !LowerSha256Pattern.IsMatch(binary.Sha256!)))
                throw Invalid();
            return new WebSetupUpgradeValidated(
                productId, enrollmentId, transitionId, authorization.Capability!,
                authorization.SourceVersion!, authorization.TargetVersion!, authorization.Binaries,
                Convert.ToHexStringLower(SHA256.HashData(authorizationBytes)), proof);
        }
        catch (JsonException)
        {
            throw Invalid();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authorizationBytes);
        }
    }

    private static void ValidateStrictJson(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw Invalid();
        ValidateNoDuplicateJsonProperties(document.RootElement);
    }

    private static void ValidateNoDuplicateJsonProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw Invalid();
                ValidateNoDuplicateJsonProperties(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
                ValidateNoDuplicateJsonProperties(item);
        }
    }

    private static EnrollmentKeyValidated ValidateEnrollmentKey(RuntimeEnrollmentKeyRequest key)
    {
        if (key.Alg != "PS256" || key.Attestation != "none"
            || key.Backend is not ("platform-cng-unattested" or "software-cng-unattested")
            || key.PublicKeySpkiBase64 == null || key.PublicKeySpkiBase64.Length > 2048
            || !LowerSha256Pattern.IsMatch(key.PublicKeySpkiSha256 ?? string.Empty)
            || !Base64Url43Pattern.IsMatch(key.KeyThumbprint ?? string.Empty))
            throw Invalid();
        try
        {
            var spki = Convert.FromBase64String(key.PublicKeySpkiBase64);
            if (spki.Length is < 300 or > 1024 || Convert.ToBase64String(spki) != key.PublicKeySpkiBase64)
                throw Invalid();
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
            var parameters = rsa.ExportParameters(false);
            if (consumed != spki.Length || rsa.KeySize != 3072
                || parameters.Exponent is not [0x01, 0x00, 0x01]
                || !spki.AsSpan().SequenceEqual(rsa.ExportSubjectPublicKeyInfo()))
                throw Invalid();
            var digest = SHA256.HashData(spki);
            var hex = Convert.ToHexStringLower(digest);
            var thumbprint = EncodeBase64Url(digest);
            if (hex != key.PublicKeySpkiSha256 || thumbprint != key.KeyThumbprint)
                throw Invalid();
            return new EnrollmentKeyValidated(spki, hex, thumbprint);
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException or ArgumentException)
        {
            throw Invalid();
        }
    }

    private static ReinstallAuthorityValidated ValidateReinstallAuthority(
        RuntimeReinstallAuthorityRequest request)
    {
        var isV2 = request.Schema == ReinstallAuthorityV2Schema;
        if (request.ExtensionData is { Count: > 0 }
            || (request.Schema != ReinstallAuthoritySchema && !isV2)
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BootstrapId, out var bootstrapId)
            || !TryUuid(request.InstallationId, out var installationId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId)
            || request.ReleaseVersion is not { Length: >= 1 and <= 64 }
            || !ReleaseVersionPattern.IsMatch(request.ReleaseVersion)
            || !Base64Url43Pattern.IsMatch(request.KeyThumbprint ?? string.Empty)
            || request.SecurityEpoch is null or < 1
            || (isV2
                ? !TryUuid(request.GrantRef, out _)
                    || !IsCanonicalReinstallSubjectRef(request.SubjectRef)
                : request.GrantRef != null || request.SubjectRef != null)
            || !IsCanonicalReinstallChallenge(request.Challenge)
            || !SignaturePattern.IsMatch(request.Signature ?? string.Empty))
            throw Invalid();
        return new ReinstallAuthorityValidated(
            requestId, productId, bootstrapId, installationId.ToString("D"), enrollmentId,
            request.ReleaseVersion, request.KeyThumbprint!, request.SecurityEpoch.Value,
            isV2, request.GrantRef, request.SubjectRef,
            request.SubjectRef == null ? null : Sha256(request.SubjectRef),
            request.Challenge!, request.Signature!);
    }

    private static string BuildReinstallProofPayload(ReinstallAuthorityValidated request)
    {
        var fields = new List<string>
        {
            request.IsV2 ? "distribution-reinstall-proof-v2" : "distribution-reinstall-proof-v1",
            request.BootstrapId.ToString("D"),
            request.RequestId.ToString("D"),
            request.InstallationId,
            request.EnrollmentId.ToString("D"),
            request.ReleaseVersion,
            request.KeyThumbprint,
            request.SecurityEpoch.ToString(CultureInfo.InvariantCulture)
        };
        if (request.IsV2)
        {
            fields.Add(request.GrantRef!);
            fields.Add(request.SubjectRef!);
        }
        fields.Add(request.Challenge);
        return string.Join('\n', fields);
    }

    private static bool IsCanonicalReinstallSubjectRef(string? value)
    {
        if (!Base64Url43Pattern.IsMatch(value ?? string.Empty))
            return false;
        byte[] decoded = [];
        try
        {
            decoded = DecodeBase64Url(value!);
            return decoded.Length == 32 && EncodeBase64Url(decoded) == value;
        }
        catch (FormatException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static bool IsCanonicalReinstallChallenge(string? value)
    {
        if (value is not { Length: >= 64 and <= 2048 }) return false;
        foreach (var character in value)
        {
            if (!((character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9')
                || character is '.' or '_' or '-'))
                return false;
        }
        return true;
    }

    private static ConfirmValidated ValidateConfirm(
        Guid routeEnrollmentId,
        RuntimeEnrollmentConfirmRequest request,
        RuntimeProofHeaders proof,
        string bodyDigest)
    {
        if (request.ExtensionData is { Count: > 0 } || request.Schema != ConfirmSchema
            || request.ProtocolVersion != ProtocolVersion || request.Epoch != 1
            || !TryUuid(request.EnrollmentId, out var bodyId) || bodyId != routeEnrollmentId
            || !LowerSha256Pattern.IsMatch(bodyDigest))
            throw Invalid();
        return new ConfirmValidated(ValidateProofHeaders(proof));
    }

    /// <summary>
    /// Validates the exact, versioned hardware authority migration contract without applying
    /// culture-sensitive or permissive normalization to authority identifiers.
    /// </summary>
    /// <param name="routeEnrollmentId">Enrollment identifier from the canonical route.</param>
    /// <param name="request">Deserialized request with unknown members rejected.</param>
    /// <param name="proof">Detached Runtime proof headers.</param>
    /// <param name="bodyDigest">Digest of the exact request body.</param>
    /// <returns>A strongly typed request containing canonical authority values.</returns>
    private static HardwareAuthorityMigrationValidated ValidateHardwareAuthorityMigration(
        Guid routeEnrollmentId,
        RuntimeHardwareAuthorityMigrationRequest request,
        RuntimeProofHeaders proof,
        string bodyDigest)
    {
        if (!SemanticVersion.TryParse(request.SdkVersion ?? string.Empty, out var sdkVersion)
            || !SemanticVersion.TryParse("1.1.13", out var minimumSdkVersion)
            || request.ExtensionData is { Count: > 0 }
            || request.Schema != HardwareAuthorityMigrationSchema
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId) || enrollmentId != routeEnrollmentId
            || request.Epoch != 1
            || request.SecurityEpoch is null or < 1 or int.MaxValue
            || !HardwareIdPattern.IsMatch(request.LegacyHardwareId ?? string.Empty)
            || !HardwareIdPattern.IsMatch(request.HardwareIdV2 ?? string.Empty)
            || request.LegacyAlgorithm != "legacy-wmi-first-disk"
            || request.HardwareIdV2Algorithm != "v2-wmi-disk-index-0"
            || sdkVersion.CompareTo(minimumSdkVersion) < 0
            || !LowerSha256Pattern.IsMatch(bodyDigest))
            throw Invalid();
        return new HardwareAuthorityMigrationValidated(
            requestId, request.SecurityEpoch.Value, request.LegacyHardwareId!, request.HardwareIdV2!,
            request.LegacyAlgorithm, request.HardwareIdV2Algorithm, request.SdkVersion!,
            ValidateProofHeaders(proof));
    }

    private static CapabilityValidated ValidateCapability(
        Guid routeEnrollmentId,
        RuntimeEnrollmentCapabilityRequest request,
        RuntimeProofHeaders proof,
        string bodyDigest)
    {
        var legacyShape = !request.InstallationIdPresent
            && !request.ReleaseVersionPresent
            && !request.SessionIdPresent
            && !request.BinariesPresent;
        var currentShape = request.InstallationIdPresent
            && request.ReleaseVersionPresent
            && request.SessionIdPresent
            && request.BinariesPresent;
        if (request.ExtensionData is { Count: > 0 } || request.Schema != CapabilitySchema
            || request.ProtocolVersion != ProtocolVersion || request.Epoch != 1
            || request.SecurityEpoch is null or < 1
            || !TryUuid(request.EnrollmentId, out var bodyId) || bodyId != routeEnrollmentId
            || (!legacyShape && !currentShape)
            || (currentShape && (!TryUuid(request.InstallationId, out _)
                || !TryUuid(request.SessionId, out _)
                || request.ReleaseVersion is not { Length: >= 1 and <= 64 }
                || !ReleaseVersionPattern.IsMatch(request.ReleaseVersion)))
            || request.Audience is not { Length: >= 1 and <= 256 }
            || request.Audience.Any(character => character is '\r' or '\n')
            || request.Scope is not { Count: >= 1 and <= 8 }
            || !IsStrictlySorted(request.Scope)
            || request.Scope.Any(scope => scope.Length is < 3 or > 64 || scope.Any(character => character is '\r' or '\n'))
            || (currentShape && (request.Binaries is not { Count: 3 }
                || request.Binaries.Any(binary => binary.ExtensionData is { Count: > 0 }
                    || binary.Key is null || binary.Sha256 is null)
                || !request.Binaries.Select(binary => binary.Key!).SequenceEqual(
                    new[] { "FP_CORE", "FP_DLL", "FP_EXE" }, StringComparer.Ordinal)
                || request.Binaries.Any(binary => !LowerSha256Pattern.IsMatch(binary.Sha256!))))
            || !LowerSha256Pattern.IsMatch(bodyDigest))
            throw Invalid();
        return new CapabilityValidated(
            legacyShape, request.SecurityEpoch.Value, request.InstallationId, request.ReleaseVersion, request.SessionId,
            request.Binaries, request.Audience, request.Scope, ValidateProofHeaders(proof));
    }

    private static void ValidateCapabilityBinding(
        RuntimeEnrollment enrollment,
        DistributionInstallationBinding binding,
        CapabilityValidated capability)
    {
        if (capability.IsLegacy)
        {
            if (binding.Id != enrollment.BindingId
                || !string.Equals(enrollment.ReleaseVersion, LegacyCapabilityReleaseVersion, StringComparison.Ordinal)
                || !string.Equals(binding.Version, LegacyCapabilityReleaseVersion, StringComparison.Ordinal)
                || !string.Equals(binding.InstallationId, enrollment.InstallationId, StringComparison.Ordinal))
                throw Conflict("capability_binding_mismatch");
            return;
        }

        if (binding.Id != enrollment.BindingId
            || !string.Equals(capability.InstallationId, enrollment.InstallationId, StringComparison.Ordinal)
            || !string.Equals(capability.ReleaseVersion, enrollment.ReleaseVersion, StringComparison.Ordinal))
            throw Conflict("capability_binding_mismatch");

        var authoritative = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FP_CORE"] = binding.CoreSha256,
            ["FP_DLL"] = binding.NativeDllSha256,
            ["FP_EXE"] = binding.ExecutableSha256
        };
        if (capability.Binaries!.Any(binary =>
                !authoritative.TryGetValue(binary.Key!, out var expected)
                || !string.Equals(binary.Sha256, expected, StringComparison.Ordinal)))
            throw Conflict("capability_binary_mismatch");
    }

    private static MilestoneValidated ValidateMilestone(
        Guid routeEnrollmentId,
        RuntimeMilestoneRequest request,
        RuntimeProofHeaders proof,
        string bodyDigest)
    {
        if (request.ExtensionData is { Count: > 0 }
            || request.Schema != MilestoneSchema
            || request.ProtocolVersion != ProtocolVersion
            || request.Epoch != 1
            || request.SecurityEpoch is null or < 1
            || !TryUuid(request.EnrollmentId, out var bodyId) || bodyId != routeEnrollmentId
            || !TryUuid(request.SessionId, out _)
            || request.Sequence is null or < 1
            || !TryUuid(request.EventId, out _)
            || request.Code == null || !MilestoneCodes.Contains(request.Code)
            || request.OccurredAtUtc == null || !TryUtc(request.OccurredAtUtc, out var occurredAtUtc)
            || !LowerSha256Pattern.IsMatch(bodyDigest))
            throw Invalid();
        return new MilestoneValidated(
            request.SecurityEpoch.Value, request.SessionId!, request.Sequence.Value,
            request.EventId!, request.Code, occurredAtUtc, ValidateProofHeaders(proof));
    }

    private static CriticalRecoveryClientRefetchValidated ValidateCriticalRecoveryClientRefetch(
        Guid routeEnrollmentId,
        RuntimeCriticalRecoveryClientRefetchRequest request,
        RuntimeProofHeaders proof,
        string bodyDigest)
    {
        if (request.ExtensionData is { Count: > 0 }
            || request.Schema != CriticalRecoveryClientRefetchSchema
            || request.ProtocolVersion != ProtocolVersion
            || request.Epoch != 1
            || request.SecurityEpoch is null or < 1 or int.MaxValue
            || !TryUuid(request.RequestId, out _)
            || !TryUuid(request.EnrollmentId, out var bodyId) || bodyId != routeEnrollmentId
            || !LowerSha256Pattern.IsMatch(bodyDigest))
            throw Invalid();
        return new CriticalRecoveryClientRefetchValidated(
            request.RequestId!, request.SecurityEpoch.Value, ValidateProofHeaders(proof));
    }

    private static CriticalRecoveryValidated ValidateCriticalRecovery(
        RuntimeCriticalRecoveryRequest request,
        string bodyDigest)
    {
        if (request.ExtensionData is { Count: > 0 }
            || request.Schema != CriticalRecoverySchema
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out _)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.InstallationId, out _)
            || !TryUuid(request.EventId, out _)
            || request.OldSecurityEpoch is null or < 1 or int.MaxValue
            || request.NewSecurityEpoch != request.OldSecurityEpoch + 1
            || !LowerSha256Pattern.IsMatch(bodyDigest))
        {
            throw Invalid();
        }
        return new CriticalRecoveryValidated(
            request.RequestId!, productId, enrollmentId, bindingId,
            request.InstallationId!, request.EventId!, request.OldSecurityEpoch.Value,
            request.NewSecurityEpoch!.Value);
    }

    private static CriticalRecoveryRefetchValidated ValidateCriticalRecoveryRefetch(
        RuntimeCriticalRecoveryRefetchRequest request,
        string bodyDigest)
    {
        if (request.ExtensionData is { Count: > 0 }
            || request.Schema != CriticalRecoveryRefetchSchema
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out _)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.RecoveryId, out var recoveryId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.InstallationId, out _)
            || !TryUuid(request.EventId, out _)
            || request.NewSecurityEpoch is null or < 2
            || !LowerSha256Pattern.IsMatch(bodyDigest))
        {
            throw Invalid();
        }
        return new CriticalRecoveryRefetchValidated(
            request.RequestId!, productId, recoveryId, bindingId,
            request.InstallationId!, request.EventId!, request.NewSecurityEpoch.Value);
    }

    private static ProofValidated ValidateProofHeaders(RuntimeProofHeaders proof)
    {
        if (!TryUtc(proof.Timestamp, out var timestamp)
            || !TryUuid(proof.Jti, out var jti)
            || !SignaturePattern.IsMatch(proof.Signature))
            throw AuthenticationFailed();
        var signature = DecodeBase64Url(proof.Signature);
        try
        {
            if (signature.Length != 384 || EncodeBase64Url(signature) != proof.Signature)
                throw AuthenticationFailed();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
        var proofDigest = Sha256(string.Join('\n', proof.Timestamp, proof.Jti, proof.Signature));
        return new ProofValidated(proof.Timestamp, timestamp, jti, proof.Signature, proofDigest);
    }

    private void ValidateProofTime(DateTimeOffset sentAt, DateTimeOffset now)
    {
        var skew = TimeSpan.FromSeconds(_options.ProofClockSkewSeconds);
        if (sentAt < now - skew || sentAt > now + skew)
            throw AuthenticationFailed();
    }

    private static bool TryUuid(string? value, out Guid parsed)
    {
        parsed = default;
        return value != null && LowerUuidPattern.IsMatch(value)
            && Guid.TryParseExact(value, "D", out parsed) && value == parsed.ToString("D");
    }

    private static bool TryUtc(string value, out DateTimeOffset parsed)
    {
        parsed = default;
        return DateTimeOffset.TryParseExact(value, UtcFormat, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed)
            && value == parsed.UtcDateTime.ToString(UtcFormat, CultureInfo.InvariantCulture);
    }

    private static bool IsStrictlySorted(IReadOnlyList<string> values)
    {
        for (var index = 1; index < values.Count; index++)
            if (string.CompareOrdinal(values[index - 1], values[index]) >= 0)
                return false;
        return true;
    }

    private static bool IsVersionAllowed(string version, string? allowedMask)
    {
        if (string.IsNullOrEmpty(allowedMask) || allowedMask == "*")
            return true;
        if (!SemanticVersion.TryParse(version, out var current))
            return false;
        if (allowedMask.EndsWith(".*", StringComparison.Ordinal))
        {
            var prefix = allowedMask[..^2].Split('.');
            return prefix.Length is 1 or 2
                && prefix.All(IsCanonicalNumericIdentifier)
                && current.Core.Take(prefix.Length).SequenceEqual(prefix, StringComparer.Ordinal);
        }
        return SemanticVersion.TryParse(allowedMask, out _) && version == allowedMask;
    }

    private static bool IsVersionBelow(string current, string? minimum)
    {
        if (string.IsNullOrWhiteSpace(minimum))
            return false;
        return !SemanticVersion.TryParse(current, out var currentVersion)
            || !SemanticVersion.TryParse(minimum, out var minimumVersion)
            || currentVersion.CompareTo(minimumVersion) < 0;
    }

    private static bool IsCanonicalNumericIdentifier(string value) =>
        value.Length > 0 && value.All(character => character is >= '0' and <= '9')
        && (value.Length == 1 || value[0] != '0');

    private sealed record SemanticVersion(string[] Core, string[] PreRelease) : IComparable<SemanticVersion>
    {
        public static bool TryParse(string value, out SemanticVersion version)
        {
            version = null!;
            var match = ReleaseVersionPattern.Match(value);
            if (!match.Success)
                return false;
            var core = value.Split(['-', '+'], 2)[0].Split('.');
            var dash = value.IndexOf('-');
            var plus = value.IndexOf('+');
            var prerelease = dash < 0
                ? []
                : value[(dash + 1)..(plus < 0 ? value.Length : plus)].Split('.');
            if (prerelease.Any(identifier => IsNumeric(identifier)
                    && !IsCanonicalNumericIdentifier(identifier)))
                return false;
            version = new SemanticVersion(core, prerelease);
            return true;
        }

        public int CompareTo(SemanticVersion? other)
        {
            if (other == null)
                return 1;
            for (var index = 0; index < 3; index++)
            {
                var comparison = CompareNumeric(Core[index], other.Core[index]);
                if (comparison != 0)
                    return comparison;
            }
            if (PreRelease.Length == 0 || other.PreRelease.Length == 0)
                return PreRelease.Length.CompareTo(other.PreRelease.Length) * -1;
            for (var index = 0; index < Math.Min(PreRelease.Length, other.PreRelease.Length); index++)
            {
                var leftNumeric = IsNumeric(PreRelease[index]);
                var rightNumeric = IsNumeric(other.PreRelease[index]);
                var comparison = leftNumeric && rightNumeric
                    ? CompareNumeric(PreRelease[index], other.PreRelease[index])
                    : leftNumeric != rightNumeric
                        ? leftNumeric ? -1 : 1
                        : string.CompareOrdinal(PreRelease[index], other.PreRelease[index]);
                if (comparison != 0)
                    return comparison;
            }
            return PreRelease.Length.CompareTo(other.PreRelease.Length);
        }

        private static bool IsNumeric(string value) =>
            value.Length > 0 && value.All(character => character is >= '0' and <= '9');

        private static int CompareNumeric(string left, string right) =>
            left.Length != right.Length
                ? left.Length.CompareTo(right.Length)
                : string.CompareOrdinal(left, right);
    }

    internal static async Task<DateTimeOffset> DatabaseNowAsync(LicenseDbContext db, CancellationToken cancellationToken)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText = "SELECT clock_timestamp();";
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is DateTime dateTime
            ? new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc))
            : (DateTimeOffset)value!;
    }

    private static async Task<long> CurrentAuthorityEpochAsync(
        LicenseDbContext db, CancellationToken cancellationToken)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        command.CommandText = "SELECT \"Epoch\" FROM public.\"RuntimeEnrollmentAuthorityStates\" WHERE \"Id\" = 1;";
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is long epoch
            ? epoch
            : throw new RuntimeEnrollmentException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable);
    }

    private static string Sha256(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string EnrollmentFieldReference(Guid enrollmentId, string field) =>
        $"RuntimeEnrollments:{enrollmentId:D}:{field}";

    private static string PrepareResponseReference(RuntimeEnrollmentRequest request) =>
        $"RuntimeEnrollmentRequests:{request.Id:D}:{request.EnrollmentId:D}:prepare:{request.ClientId}:{request.RequestId}";

    private static string ReleaseTransitionResponseReference(
        RuntimeEnrollmentRequest request,
        string operation) =>
        $"RuntimeEnrollmentRequests:{request.Id:D}:{request.EnrollmentId:D}:{operation}:{request.ClientId}:{request.RequestId}";

    private byte[] OpenWebSetupTransitionIssueResponse(
        RuntimeEnrollmentWebSetupTransitionRequest request) =>
        _crypto.Open(
            "websetup-transition-response",
            request.TransitionId,
            1,
            request.ResponseKeyId,
            Encoding.ASCII.GetString(request.ExactResponseCiphertext),
            WebSetupTransitionIssueResponseReference(
                request.ClientId, Guid.ParseExact(request.RequestId, "D"), request.TransitionId));

    private static string WebSetupTransitionIssueResponseReference(
        string clientId,
        Guid requestId,
        Guid transitionId) =>
        $"RuntimeEnrollmentWebSetupTransitionRequests:{clientId}:{requestId:D}:issue:{transitionId:D}:ExactResponseCiphertext";

    private static bool WebSetupTransitionMatches(
        RuntimeEnrollmentWebSetupTransition transition,
        string clientId,
        DistributionInstallationBinding binding,
        RuntimeEnrollment enrollment,
        RuntimeWebSetupTransitionIssueRequest request,
        long authorityEpoch) =>
        transition.ClientId == clientId
        && transition.ProductId == binding.ProductId
        && transition.BindingId == binding.Id
        && transition.EnrollmentId == enrollment.Id
        && transition.InstallationId == enrollment.InstallationId
        && transition.SourceVersion == request.SourceVersion
        && transition.TargetVersion == request.TargetVersion
        && transition.TargetInstallerFilename == request.TargetInstallerFilename
        && transition.TargetInstallerSha256 == request.TargetInstallerSha256
        && (request.Schema != WebSetupTransitionIssueV2Schema
            || binding.LicenseId.ToString("D") == request.TargetLicenseId
            && binding.GrantRef == request.TargetGrantRef
            && binding.SubjectRefDigestSha256 == Sha256(request.TargetSubjectRef!))
        && transition.SourceSecurityEpoch == enrollment.SecurityEpoch
        && transition.AuthorityEpoch == authorityEpoch;

    private static bool FixedDigestEquals(string left, string right)
    {
        if (!LowerSha256Pattern.IsMatch(left) || !LowerSha256Pattern.IsMatch(right))
            return false;
        var leftBytes = Encoding.ASCII.GetBytes(left);
        var rightBytes = Encoding.ASCII.GetBytes(right);
        try { return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes); }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static string ProofResponseReference(Guid enrollmentId, string operation, Guid jti) =>
        $"RuntimeEnrollmentProofNonces:{enrollmentId:D}:{jti:D}:{operation}:ResponseCiphertext";

    private static string CanaryResponseReference(Guid enrollmentId, Guid jti) =>
        $"RuntimeCanaryProofNonces:{enrollmentId:D}:{jti:D}:ResponseCiphertext";

    private static string FormatUtc(DateTime value) =>
        DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString(UtcFormat, CultureInfo.InvariantCulture);

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        return Convert.FromBase64String(base64);
    }

    private void EnsureEnabled()
    {
        if (_options.Mode != "enabled")
            throw new RuntimeEnrollmentException("runtime_enrollment_unavailable", StatusCodes.Status503ServiceUnavailable);
    }

    private static RuntimeEnrollmentException Invalid() =>
        new("invalid_request", StatusCodes.Status400BadRequest);
    private static RuntimeEnrollmentException AuthenticationFailed() =>
        new("authentication_failed", StatusCodes.Status401Unauthorized);
    private static RuntimeEnrollmentException Reject(string error) =>
        new(error, StatusCodes.Status422UnprocessableEntity);
    private static RuntimeEnrollmentException Conflict(string error) =>
        new(error, StatusCodes.Status409Conflict);
    private static RuntimeEnrollmentException Gone(string error) =>
        new(error, StatusCodes.Status410Gone);
    private static RuntimeEnrollmentException Unavailable() =>
        new("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
    private static RuntimeEnrollmentException PrepareV2Required() =>
        new("prepare_v2_required", StatusCodes.Status426UpgradeRequired);
    private static RuntimeEnrollmentException RefreshV2Required() =>
        new("refresh_v2_required", StatusCodes.Status426UpgradeRequired);

    private sealed record PrepareValidated(
        string RequestId, Guid ProductId, Guid BindingId, string HandoffDigest,
        string InstallationId, string ReleaseVersion, bool ExposesSecurityEpoch);
    private sealed record RefreshValidated(
        string RequestId, Guid ProductId, Guid BindingId, Guid EnrollmentId,
        string ExpectedChallengeDigest, int? ExpectedSecurityEpoch, bool ExposesSecurityEpoch);
    private sealed record EnrollmentKeyValidated(byte[] Spki, string SpkiSha256, string Thumbprint);
    private sealed record ReinstallAuthorityValidated(
        Guid RequestId,
        Guid ProductId,
        Guid BootstrapId,
        string InstallationId,
        Guid EnrollmentId,
        string ReleaseVersion,
        string KeyThumbprint,
        int SecurityEpoch,
        bool IsV2,
        string? GrantRef,
        string? SubjectRef,
        string? SubjectRefDigestSha256,
        string Challenge,
        string Signature);
    private enum ReinstallAuthorityClassification
    {
        LegacyIncomplete,
        LegacyReconciled,
        ModernComplete
    }
    private sealed record ProofPreflight(
        Guid EnrollmentId, Guid BindingId, Guid ProductId, int Epoch, string State,
        string SpkiSha256, string Thumbprint, byte[] Spki, string Challenge);
    private sealed record ProofValidated(
        string Timestamp, DateTimeOffset SentAtUtc, Guid Jti, string SignatureBase64Url, string ProofDigest);
    private sealed record ConfirmValidated(ProofValidated Proof);
    private sealed record CapabilityValidated(
        bool IsLegacy, int SecurityEpoch, string? InstallationId, string? ReleaseVersion, string? SessionId,
        IReadOnlyList<RuntimeEnrollmentBinaryEvidenceRequest>? Binaries,
        string Audience, IReadOnlyList<string> Scopes, ProofValidated Proof);
    private sealed record HardwareAuthorityMigrationValidated(
        Guid RequestId,
        int SecurityEpoch,
        string LegacyHardwareId,
        string HardwareIdV2,
        string LegacyAlgorithm,
        string HardwareIdV2Algorithm,
        string SdkVersion,
        ProofValidated Proof);
    private sealed record UpgradeValidated(
        string RequestId, Guid ProductId, Guid EnrollmentId, string InstallationId,
        int SecurityEpoch, string SourceVersion, string TargetVersion,
        string TargetInstallerFilename, string TargetInstallerSha256,
        string RecoveryReceiptId, string RecoveryReceiptDigestSha256, string RecoveryHardwareIdHash,
        IReadOnlyList<RuntimeEnrollmentBinaryEvidenceRequest> Binaries,
        string AuthorizationDigest, ProofValidated Proof);
    private sealed record WebSetupUpgradeValidated(
        Guid ProductId,
        Guid EnrollmentId,
        Guid TransitionId,
        string Capability,
        string SourceVersion,
        string TargetVersion,
        IReadOnlyList<RuntimeEnrollmentBinaryEvidenceRequest> Binaries,
        string AuthorizationDigest,
        ProofValidated Proof);
    private sealed record ReleaseTransition(
        string Operation,
        string RelaySchema,
        string AuthorizationSchema,
        string ResponseSchema,
        string Audience,
        string Use,
        string Decision,
        string ResponseOwnerType,
        string BindingConflictCode,
        string ConflictCode,
        string ReceiptReusedCode,
        bool IsRollback)
    {
        public static readonly ReleaseTransition Upgrade = new(
            "upgrade", UpgradeRelaySchema, UpgradeAuthorizationSchema, UpgradeResponseSchema,
            UpgradeAudience, UpgradeUse, "upgraded", "upgrade-response",
            "upgrade_binding_conflict", "upgrade_conflict", "upgrade_receipt_reused", false);

        public static readonly ReleaseTransition Rollback = new(
            "rollback", RollbackRelaySchema, RollbackAuthorizationSchema, RollbackResponseSchema,
            RollbackAudience, RollbackUse, "rolled_back", "rollback-response",
            "rollback_binding_conflict", "rollback_conflict", "rollback_receipt_reused", true);
    }
    private sealed record MilestoneValidated(
        int SecurityEpoch, string SessionId, long Sequence, string EventId, string Code,
        DateTimeOffset OccurredAtUtc, ProofValidated Proof);
    private sealed record CriticalRecoveryClientRefetchValidated(
        string RequestId, int SecurityEpoch, ProofValidated Proof);
    private sealed record CriticalRecoveryValidated(
        string RequestId, Guid ProductId, Guid EnrollmentId, Guid BindingId,
        string InstallationId, string EventId, int OldSecurityEpoch, int NewSecurityEpoch);
    private sealed record CriticalRecoveryRefetchValidated(
        string RequestId, Guid ProductId, Guid RecoveryId, Guid BindingId,
        string InstallationId, string EventId, int NewSecurityEpoch);
    private sealed record StoredResponse<T>(T Response, byte[] ExactBytes);
}

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
using SoftLicence.SDK;
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
    /// <summary>Prepares exact server-owned recovery payload bytes under the current authority head lock.</summary>
    Task<RuntimeEnrollmentAuthorityRecoveryPreparationResult> PrepareAuthorityRecoveryV2Async(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlyMemory<byte> exactBody,
        CancellationToken cancellationToken = default);
    /// <summary>Finalizes one authenticated recovery preparation with its detached recovery signature.</summary>
    Task<RuntimeEnrollmentAuthorityV2OperationResult> FinalizeAuthorityRecoveryV2Async(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlyMemory<byte> exactBody,
        string preparationToken, string recoveryKeyId, string recoverySignature,
        CancellationToken cancellationToken = default);
    /// <summary>Issues or replays one authenticated v2 authority generation from exact request bytes.</summary>
    Task<RuntimeEnrollmentAuthorityV2OperationResult> IssueAuthorityGenerationV2Async(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlyMemory<byte> exactBody,
        string? recoveryKeyId, string? recoverySignature,
        CancellationToken cancellationToken = default);
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

    /// <summary>
    /// Activates one pending enrollment after verifying its exact challenge-bound client proof.
    /// </summary>
    /// <param name="routeEnrollmentId">Enrollment identifier selected by the authenticated route.</param>
    /// <param name="exactBodyDigest">Lowercase SHA-256 digest of the exact Confirm request bytes.</param>
    /// <param name="request">Validated protocol and enrollment identity supplied by the client.</param>
    /// <param name="proof">Signed proof headers bound to the request digest and enrollment challenge.</param>
    /// <param name="clientAddress">Optional client address used only for bounded quota enforcement.</param>
    /// <param name="cancellationToken">Cancels the operation before the authority transaction commits.</param>
    /// <returns>The active enrollment response and whether the exact signed request was replayed.</returns>
    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>> ConfirmAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeEnrollmentConfirmRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Migrates the exact active licensing seat from legacy HWID to deterministic HWID V2 while
    /// preserving the Runtime enrollment's key and installation identity. Retained Runtime HWID
    /// values are immutable compatibility evidence and do not authorize the operation.
    /// </summary>
    /// <param name="routeEnrollmentId">Canonical enrollment identifier authenticated by the route proof.</param>
    /// <param name="exactBodyDigest">Lowercase SHA-256 of the exact request body.</param>
    /// <param name="request">Strict legacy-to-current licensing hardware transition.</param>
    /// <param name="proof">Detached proof from the enrolled Runtime key.</param>
    /// <param name="clientAddress">Optional rate-limit input that is not part of identity.</param>
    /// <param name="cancellationToken">Cancels before the atomic authority transaction commits.</param>
    /// <returns>The current signed licensing result and exact replay classification.</returns>
    Task<RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>> MigrateHardwareAuthorityAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeHardwareAuthorityMigrationRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);

    /// <summary>Issues or replays a proof-bound capability only within current paid authority, without refreshing replay TTL.</summary>
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

    /// <summary>Processes one authenticated security lock report (TKT-001177).</summary>
    Task<RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>> ProcessSecurityLockReportAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        SecurityLockReportRequest request,
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

    /// <summary>
    /// Applies or exactly replays a signed release upgrade under the current locked assignment.
    /// Historical signed recovery HWID remains evidence only and is not a Runtime identity predicate.
    /// </summary>
    /// <param name="clientId">Authenticated S2S owner of the release request.</param>
    /// <param name="keyId">Authenticated S2S key identifier.</param>
    /// <param name="exactRelayDigest">Lowercase SHA-256 of the exact relay bytes.</param>
    /// <param name="request">Strict signed upgrade relay.</param>
    /// <param name="cancellationToken">Cancels before the release transaction commits.</param>
    /// <returns>The signed release result and exact replay classification.</returns>
    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>> UpgradeAsync(
        string clientId,
        string keyId,
        string exactRelayDigest,
        RuntimeEnrollmentUpgradeRelayRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Applies or exactly replays a signed release rollback under the current locked assignment.
    /// Historical signed recovery HWID remains evidence only and is not a Runtime identity predicate.
    /// </summary>
    /// <param name="clientId">Authenticated S2S owner of the release request.</param>
    /// <param name="keyId">Authenticated S2S key identifier.</param>
    /// <param name="exactRelayDigest">Lowercase SHA-256 of the exact relay bytes.</param>
    /// <param name="request">Strict signed rollback relay.</param>
    /// <param name="cancellationToken">Cancels before the release transaction commits.</param>
    /// <returns>The signed release result and exact replay classification.</returns>
    Task<RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>> RollbackAsync(
        string clientId,
        string keyId,
        string exactRelayDigest,
        RuntimeEnrollmentUpgradeRelayRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues or exactly replays a Website transition after current binding and assignment checks.
    /// The retained Runtime HWID column is compatibility data and does not identify the enrollment.
    /// </summary>
    /// <param name="clientId">Authenticated S2S owner of the transition.</param>
    /// <param name="exactBodyDigest">Lowercase SHA-256 of the exact request bytes.</param>
    /// <param name="request">Strict upgrade or licence-transfer transition request.</param>
    /// <param name="cancellationToken">Cancels before issuance persistence commits.</param>
    /// <returns>The sealed transition and exact replay classification.</returns>
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

    /// <summary>
    /// Verifies the signed Runtime identity and returns a closed, non-authorizing identity confirmation.
    /// </summary>
    /// <param name="clientId">The authenticated Distribution client identifier.</param>
    /// <param name="request">The exact signed reinstall-authority request.</param>
    /// <param name="cancellationToken">The token used to cancel database and cryptographic work.</param>
    /// <returns>The identity-only v1 provider assertion bound to the verified Runtime scope.</returns>
    /// <exception cref="RuntimeEnrollmentException">
    /// The request, Runtime identity, binding authority, licence, seat, version, or provider state is invalid.
    /// </exception>
    /// <exception cref="OperationCanceledException">The operation was canceled.</exception>
    Task<RuntimeReinstallAuthorityResponse> AuthorizeReinstallAsync(
        string clientId,
        RuntimeReinstallAuthorityRequest request,
        CancellationToken cancellationToken = default);

    Task<RuntimeReinstallSourceResolutionResponse> ResolveReinstallSourceAuthorityAsync(
        string clientId,
        RuntimeReinstallSourceResolutionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Redeems or exactly replays an enrollment-bound bootstrap capability under the current locked
    /// assignment. Its stored hardware digest remains immutable history; the active seat supplies
    /// the licensing HWID signed into a new response.
    /// </summary>
    /// <param name="routeEnrollmentId">Canonical enrollment identifier authenticated by the route proof.</param>
    /// <param name="exactBodyDigest">Lowercase SHA-256 of the exact request body.</param>
    /// <param name="request">Strict one-use capability redemption body.</param>
    /// <param name="proof">Detached proof from the enrolled Runtime key.</param>
    /// <param name="clientAddress">Optional rate-limit input that is not part of identity.</param>
    /// <param name="cancellationToken">Cancels before the capability transaction commits.</param>
    /// <returns>The signed licensing response and exact replay classification.</returns>
    Task<RuntimeEnrollmentOperationResult<RuntimeLicenseBootstrapResultResponse>> RedeemLicenseBootstrapAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        RuntimeLicenseBootstrapRedeemRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default);
}

/// <summary>Owns the exact frozen HTTP response for a v2 authority issuance or semantic replay.</summary>
public sealed class RuntimeEnrollmentAuthorityV2OperationResult
{
    private readonly byte[] exactResponseBody;
    /// <summary>Copies one terminal response.</summary>
    public RuntimeEnrollmentAuthorityV2OperationResult(int statusCode, ReadOnlySpan<byte> response, bool idempotent)
    { StatusCode = statusCode; exactResponseBody = response.ToArray(); Idempotent = idempotent; }
    /// <summary>Gets the terminal HTTP status.</summary>
    public int StatusCode { get; }
    /// <summary>Gets whether the bytes came from an exact stored replay.</summary>
    public bool Idempotent { get; }
    /// <summary>Gets a defensive copy of the exact response bytes.</summary>
    public byte[] ExactResponseBody => [.. exactResponseBody];
}

/// <summary>Owns the exact recovery payload and signed short-lived preparation token response.</summary>
public sealed class RuntimeEnrollmentAuthorityRecoveryPreparationResult
{
    private readonly byte[] exactResponseBody;
    /// <summary>Copies the exact public preparation response bytes.</summary>
    internal RuntimeEnrollmentAuthorityRecoveryPreparationResult(byte[] response)
    { exactResponseBody = [.. response]; }
    /// <summary>Gets a defensive copy of the exact response bytes.</summary>
    public byte[] ExactResponseBody => [.. exactResponseBody];
}

public sealed partial class RuntimeEnrollmentService : IRuntimeEnrollmentService
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
    // LEGACY-EXPIRY(TKT-001430, 2026-12-31): the signed hardware authority migration moves a pre-UUID seat to its UUID
    // identifier. Remove the endpoint, its request contract and its aliases by 31/12/2026 (see TKT-001430).
    /// <summary>Source algorithm: the identifier bound in the client's current signed licence file (TKT-001277 lot 5).</summary>
    public const string HardwareMigrationSourceAlgorithm = "licensed-hardware-id";
    /// <summary>Target algorithm: the SDK 2.0 identifier derived from the SMBIOS UUID (TKT-001277 lot 5).</summary>
    public const string HardwareMigrationTargetAlgorithm = "smbios-uuid-v1";
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
    public const string ReinstallSourceResolutionSchema = "distribution-runtime-reinstall-source-resolution-v1";
    /// <summary>Names the additive request schema that negotiates signed authority provenance.</summary>
    public const string ReinstallSourceResolutionV2Schema = "distribution-runtime-reinstall-source-resolution-v2";
    public const string ReinstallSourceResolutionResponseSchema = "distribution-runtime-reinstall-source-resolution-result-v1";
    /// <summary>Names the additive response schema carrying optional provider-issued provenance.</summary>
    public const string ReinstallSourceResolutionV2ResponseSchema = "distribution-runtime-reinstall-source-resolution-result-v2";
    public const string ReinstallDiscoveryAuthoritySchema = "runtime-enrollment-reinstall-authority-v2";
    public const string ReinstallAuthorityLegacyV2Schema = ReinstallAuthorityV2Schema;
    public const string ReinstallAuthorityResponseSchema = RuntimeReinstallAuthorityV1Producer.ResponseSchema;
    public const string LicenseBootstrapSchema = "runtime-license-bootstrap-v1";
    public const string LicenseBootstrapResponseSchema = "runtime-license-bootstrap-result-v1";
    /// <summary>Server-only diagnostic for a validly parsed proof outside the accepted clock window.</summary>
    public const string ProofClockSkewDiagnosticCode = "runtime_proof_clock_skew";
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
    /// <summary>Optional v2 coordinator; absence preserves startup compatibility while v2 is disabled.</summary>
    private readonly RuntimeEnrollmentAuthorityV2Coordinator? _authorityV2;
    /// <summary>Host shutdown cancels the awaited five-second history-only finalization; HTTP cancellation does not.</summary>
    private readonly CancellationToken _historyApplicationStopping;
    /// <summary>Emits only bounded decision/persistence diagnostics, never tokens or request bodies.</summary>
    private readonly ILogger<RuntimeEnrollmentService>? _historyLogger;
    /// <summary>Supplies observation-only request transport metadata; non-HTTP callers may omit it.</summary>
    private readonly IHttpContextAccessor? _httpContextAccessor;

    /// <summary>Creates the Runtime authority service with existing scoped factories and optional bounded decision-history shutdown/logging dependencies.</summary>
    /// <remarks>Factories and cryptography remain caller-owned. History uses the existing lease transaction; no background work or fallback transaction is created. Optional dependencies preserve isolated-service callers while DI supplies host lifetime and observed HTTP transport metadata in the server. Transport metadata never grants authority.</remarks>
    public RuntimeEnrollmentService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IRuntimeEnrollmentAuthorityService authority,
        IRuntimeEnrollmentKeyRegistryService keyRegistry,
        IRuntimeEnrollmentCryptoService crypto,
        IOptions<RuntimeEnrollmentOptions> options,
        CanaryAckService? canaryAck = null,
        ISignedLicenseFileService? signedLicenseFiles = null,
        IDataProtectionProvider? dataProtectionProvider = null,
        RuntimeEnrollmentAuthorityV2Coordinator? authorityV2 = null,
        IHostApplicationLifetime? applicationLifetime = null,
        ILogger<RuntimeEnrollmentService>? historyLogger = null,
        IHttpContextAccessor? httpContextAccessor = null)
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
        _authorityV2 = authorityV2;
        _historyApplicationStopping = applicationLifetime?.ApplicationStopping ?? CancellationToken.None;
        _historyLogger = historyLogger;
        _httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc />
    public async Task<RuntimeEnrollmentAuthorityV2OperationResult> IssueAuthorityGenerationV2Async(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlyMemory<byte> exactBody,
        string? recoveryKeyId, string? recoverySignature,
        CancellationToken cancellationToken = default)
    {
        if (_options.Mode != "enabled" || _options.AuthorityGenerationV2.Mode != "enabled" || _authorityV2 is null)
            throw new RuntimeEnrollmentException(
                "RUNTIME_ENROLLMENT_UNSUPPORTED", StatusCodes.Status503ServiceUnavailable,
                "AUTHORITY_V2_UNAVAILABLE");
        var prepared = _authorityV2.Prepare(
            clientId, transportKeyId, attemptId, exactBody.Span, recoveryKeyId, recoverySignature);
        if (prepared.Request.Transition.Kind == "recovery")
            throw new RuntimeEnrollmentException(
                "RUNTIME_ENROLLMENT_DENIED", StatusCodes.Status403Forbidden,
                "RECOVERY_PREPARATION_REQUIRED");
        return await ExecuteAuthorityPreparedAsync(prepared, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<RuntimeEnrollmentAuthorityRecoveryPreparationResult> PrepareAuthorityRecoveryV2Async(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlyMemory<byte> exactBody,
        CancellationToken cancellationToken = default)
    {
        if (_options.Mode != "enabled" || _options.AuthorityGenerationV2.Mode != "enabled" || _authorityV2 is null)
            throw new RuntimeEnrollmentException(
                "RUNTIME_ENROLLMENT_UNSUPPORTED", StatusCodes.Status503ServiceUnavailable,
                "AUTHORITY_V2_UNAVAILABLE");
        var coordinator = _authorityV2!;
        var prepared = coordinator.PrepareRecovery(clientId, transportKeyId, attemptId, exactBody.Span);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var lease = await _authority.AcquireMutationAsync(db, prepared.BindingId, cancellationToken);
        var result = await coordinator.PrepareRecoveryAmbientAsync(db, prepared, cancellationToken);
        await lease.CommitAsync(cancellationToken);
        var response = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schema = "runtime-enrollment-authority-recovery-preparation-v2",
            payloadUtf8Base64Url = EncodeBase64Url(result.CanonicalPayloadUtf8),
            preparationToken = result.Token,
            expiresAtUtc = result.ExpiresAtUtc.ToString(
                "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture)
        });
        return new(response);
    }

    /// <inheritdoc />
    public Task<RuntimeEnrollmentAuthorityV2OperationResult> FinalizeAuthorityRecoveryV2Async(
        string clientId, string transportKeyId, Guid attemptId, ReadOnlyMemory<byte> exactBody,
        string preparationToken, string recoveryKeyId, string recoverySignature,
        CancellationToken cancellationToken = default)
    {
        if (_options.Mode != "enabled" || _options.AuthorityGenerationV2.Mode != "enabled" || _authorityV2 is null)
            throw new RuntimeEnrollmentException(
                "RUNTIME_ENROLLMENT_UNSUPPORTED", StatusCodes.Status503ServiceUnavailable,
                "AUTHORITY_V2_UNAVAILABLE");
        var coordinator = _authorityV2!;
        var replayProbe = coordinator.PrepareRecoveryFinalization(
            clientId, transportKeyId, attemptId, exactBody.Span,
            preparationToken, recoveryKeyId, recoverySignature, authorizeCurrentToken: false);
        return ExecuteAuthorityRecoveryFinalizationAsync(
            replayProbe, exactBody, preparationToken, recoveryKeyId, recoverySignature,
            cancellationToken);
    }

    /// <summary>
    /// Returns a committed exact attempt before current token authorization; every new attempt then
    /// validates the complete preparation and uses the ordinary atomic execution path.
    /// </summary>
    private async Task<RuntimeEnrollmentAuthorityV2OperationResult> ExecuteAuthorityRecoveryFinalizationAsync(
        RuntimeEnrollmentAuthorityV2Prepared replayProbe, ReadOnlyMemory<byte> exactBody,
        string preparationToken, string recoveryKeyId, string recoverySignature,
        CancellationToken cancellationToken)
    {
        var coordinator = _authorityV2!;
        await using (var db = await _dbFactory.CreateDbContextAsync(cancellationToken))
        await using (var lease = await _authority.AcquireMutationAsync(
            db, replayProbe.BindingId, cancellationToken))
        {
            var replay = await coordinator.ResolveExactAttemptAmbientAsync(
                db, replayProbe, cancellationToken);
            if (replay is not null)
            {
                await lease.CommitAsync(cancellationToken);
                return replay;
            }
        }
        var authorized = coordinator.PrepareRecoveryFinalization(
            replayProbe.ClientId, replayProbe.TransportKeyId, replayProbe.AttemptId,
            exactBody.Span, preparationToken, recoveryKeyId, recoverySignature);
        return await ExecuteAuthorityPreparedAsync(authorized, cancellationToken);
    }

    /// <summary>Owns the complete bounded transaction retry envelope for one frozen v2 operation.</summary>
    private async Task<RuntimeEnrollmentAuthorityV2OperationResult> ExecuteAuthorityPreparedAsync(
        RuntimeEnrollmentAuthorityV2Prepared prepared, CancellationToken cancellationToken)
    {
        var coordinator = _authorityV2!;
        for (var attempt = 0; attempt < _options.MaximumTransactionAttempts; attempt++)
        {
            try
            {
                await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
                await using var lease = await _authority.AcquireMutationAsync(db, prepared.BindingId, cancellationToken);
                var result = await coordinator.ExecuteAmbientAsync(db, prepared, cancellationToken);
                await lease.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception exception) when (exception is RuntimeEnrollmentAuthorityTransactionInvalidatedException
                || IsRetryable(exception))
            {
                if (attempt + 1 >= _options.MaximumTransactionAttempts)
                {
                    await using var readDb = await _dbFactory.CreateDbContextAsync(cancellationToken);
                    await using var readLease = await _authority.AcquireMutationAsync(
                        readDb, prepared.BindingId, cancellationToken);
                    var resolved = await coordinator.ResolveAfterRollbackAmbientAsync(
                        readDb, prepared, cancellationToken);
                    await readLease.CommitAsync(cancellationToken);
                    return resolved;
                }
                await Task.Delay(Random.Shared.Next(20, 80) * (attempt + 1), cancellationToken);
            }
        }
        throw new RuntimeEnrollmentException(
            "RUNTIME_ENROLLMENT_TEMPORARILY_UNAVAILABLE", StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>
    /// Verifies the signed Runtime identity under its authority lease and returns only a
    /// non-authorizing identity confirmation bound to the exact verified scope.
    /// </summary>
    /// <param name="clientId">The authenticated Distribution client identifier.</param>
    /// <param name="request">The exact signed reinstall-authority request.</param>
    /// <param name="cancellationToken">The token used to cancel database and cryptographic work.</param>
    /// <returns>The identity-only v1 provider assertion bound to the verified Runtime scope.</returns>
    /// <exception cref="RuntimeEnrollmentException">
    /// The request, Runtime identity, binding authority, licence, seat, version, or provider state is invalid.
    /// </exception>
    /// <exception cref="OperationCanceledException">The operation was canceled.</exception>
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
        var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
            db, enrollment, "ACTIVE", true, null, cancellationToken);
        VerifyReinstallAuthorityProof(enrollment, validated);
        var binding = await db.DistributionInstallationBindings
            .SingleAsync(candidate => candidate.Id == enrollment.BindingId, cancellationToken);
        ReinstallAuthorityClassification? classification = null;
        if (validated.IsV2)
        {
            classification = await ClassifyAndValidateV2ReinstallAuthorityAsync(
                db, enrollment, binding, clientId, validated, cancellationToken);
            if (classification == ReinstallAuthorityClassification.LegacyIncomplete
                && !mutationLeaseRequested)
                throw ReinstallAuthorityIneligible();
        }
        else
        {
            await ValidateV1ReinstallProvenanceAsync(
                db, enrollment, binding, clientId, cancellationToken);
        }

        if (classification == ReinstallAuthorityClassification.LegacyIncomplete)
        {
            // The legacy digest repair is a commercial mutation, unlike the identity-only
            // modern and reconciled paths. Serialize it against item-2 assignment writers.
            await db.Database.ExecuteSqlRawAsync(
                "SELECT pg_catalog.pg_advisory_xact_lock(1312, 1);", cancellationToken);
            now = await DatabaseNowAsync(db, cancellationToken);
            if (enrollment.AuthorityEpoch != lease.AuthorityEpoch)
                throw ReinstallAuthorityIneligible("v2_legacy_repair_epoch_mismatch");
            await ValidateReinstallSourceCommercialAsync(
                db, enrollment, binding, approved.Binaries, now, cancellationToken);
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

        // The closed v1 response confirms possession and source provenance only.
        // A selected target's current commercial eligibility is decided by Finalize.
        var decision = RuntimeReinstallAuthorityV1Decision.IdentityConfirmed;
        var response = RuntimeReinstallAuthorityV1Producer.Produce(new RuntimeReinstallAuthorityV1Scope(
            ProtocolVersion,
            decision,
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
            binding.LicenseSeatId.ToString("D")));
        await lease.CommitAsync(cancellationToken);
        return response;
    }

    /// <summary>
    /// Resolves a missing Website source from the provider-owned active Runtime enrollment and
    /// verifies the exact WebSetup discovery proof before returning bounded lineage identifiers.
    /// The operation is read-only and deliberately permits an ineligible modern source licence:
    /// replacement eligibility remains governed by the later target-finalization authority.
    /// </summary>
    public async Task<RuntimeReinstallSourceResolutionResponse> ResolveReinstallSourceAuthorityAsync(
        string clientId,
        RuntimeReinstallSourceResolutionRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var validated = ValidateReinstallSourceResolution(request);
        var responseSchema = validated.IsV2
            ? ReinstallSourceResolutionV2ResponseSchema
            : ReinstallSourceResolutionResponseSchema;
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var enrollment = await db.RuntimeEnrollments
            .SingleOrDefaultAsync(candidate => candidate.Id == validated.EnrollmentId, cancellationToken);
        if (enrollment == null)
            return NoReinstallSource(validated.RequestId, responseSchema);

        var preflightBindingId = enrollment.BindingId;
        await using var lease = await _authority.AcquireAsync(db, preflightBindingId, cancellationToken);
        await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
        enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);
        if (enrollment.State != "ACTIVE"
            || enrollment.BindingId != preflightBindingId
            || enrollment.ClientId != clientId
            || enrollment.ProductId != validated.ProductId
            || enrollment.InstallationId != validated.InstallationId
            || enrollment.ReleaseVersion != validated.ReleaseVersion
            || enrollment.KeyThumbprint != validated.KeyThumbprint
            || enrollment.SecurityEpoch != validated.SecurityEpoch)
            return NoReinstallSource(validated.RequestId, responseSchema);

        var binding = await db.DistributionInstallationBindings
            .SingleAsync(candidate => candidate.Id == enrollment.BindingId, cancellationToken);
        var authorityRequest = new ReinstallAuthorityValidated(
            validated.RequestId, validated.ProductId, validated.BootstrapId,
            validated.InstallationId, validated.EnrollmentId, validated.ReleaseVersion,
            validated.KeyThumbprint, validated.SecurityEpoch, true, binding.GrantRef, null,
            binding.SubjectRefDigestSha256, validated.Challenge, validated.Signature);
        var now = await DatabaseNowAsync(db, cancellationToken);
        ReinstallAuthorityClassification classification;
        try
        {
            var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "ACTIVE", true, null, cancellationToken);
            VerifyReinstallDiscoveryProof(enrollment, validated);
            classification = await ClassifyAndValidateV2ReinstallAuthorityAsync(
                db, enrollment, binding, clientId, authorityRequest, cancellationToken);
            if (classification != ReinstallAuthorityClassification.ModernComplete)
            {
                // Legacy discovery is source fallback, so it needs one current assignment.
                // Modern finalized discovery is historical identity evidence and never waits
                // on the commercial assignment barrier or reads current source commerce.
                await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
                now = await DatabaseNowAsync(db, cancellationToken);
                await ValidateReinstallSourceCommercialAsync(
                    db, enrollment, binding, approved.Binaries, now, cancellationToken);
            }
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.ErrorCode is "reinstall_authority_ineligible" or "reinstall_signature_invalid"
                or "authority_ineligible" or "enrollment_inactive" or "critical_incident_unresolved")
        {
            return NoReinstallSource(validated.RequestId, responseSchema);
        }

        var authority = validated.IsV2
            ? await ResolveReinstallSourceAuthorityProvenanceAsync(db, binding, cancellationToken)
            : null;
        await lease.CommitAsync(cancellationToken);
        return new RuntimeReinstallSourceResolutionResponse(
            responseSchema,
            "source",
            validated.RequestId.ToString("D"),
            binding.LicenseId.ToString("D"),
            classification == ReinstallAuthorityClassification.ModernComplete ? "modern" : "legacy",
            binding.GrantRef,
            binding.Id.ToString("D"),
            binding.SubjectRefDigestSha256,
            authority);
    }

    /// <summary>Returns the negotiated bounded none result without authority material.</summary>
    private static RuntimeReinstallSourceResolutionResponse NoReinstallSource(
        Guid requestId,
        string responseSchema) =>
        new(responseSchema, "none", requestId.ToString("D"),
            null, null, null, null, null, null);

    /// <summary>
    /// Resolves only an entitlement-v4 provider-issued generation. Older authorities remain valid
    /// source results but deliberately carry no synthetic or digest-derived provenance.
    /// </summary>
    private static async Task<RuntimeReinstallSourceAuthorityProvenance?>
        ResolveReinstallSourceAuthorityProvenanceAsync(
            LicenseDbContext db,
            DistributionInstallationBinding binding,
            CancellationToken cancellationToken)
    {
        var entitlement = await db.DistributionEntitlements.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == binding.EntitlementId, cancellationToken);
        if (entitlement is not
            {
                ContractVersion: 4,
                AuthorityLineageId: { } authorityLineageId,
                AuthorityGenerationId: { } authorityGenerationId
            })
            return null;

        var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleOrDefaultAsync(candidate =>
                candidate.AuthorityLineageId == authorityLineageId
                && candidate.AuthorityGenerationId == authorityGenerationId,
                cancellationToken);
        if (generation is null || generation.SignedStatementUtf8.Length is < 1 or > 3569)
            throw ReinstallAuthorityIneligible("v2_authority_generation_projection_invalid");

        return new RuntimeReinstallSourceAuthorityProvenance(
            authorityLineageId.ToString("D"),
            authorityGenerationId.ToString("D"),
            EncodeBase64Url(generation.SignedStatementUtf8));
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
    /// <param name="cancellationToken">Cancellation token for database operations.</param>
    /// <returns>The compatible authority generation after all checks pass.</returns>
    /// <exception cref="RuntimeEnrollmentException">The authority is incomplete, divergent, or ineligible.</exception>
    private static async Task<ReinstallAuthorityClassification> ClassifyAndValidateV2ReinstallAuthorityAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        DistributionInstallationBinding binding,
        string clientId,
        ReinstallAuthorityValidated request,
        CancellationToken cancellationToken)
    {
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.InstallationId != enrollment.InstallationId
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
        else if (ownership != null
            && ownership.ClientId == clientId
            && entitlement is { State: "finalized", FinalizedAtUtc: not null }
            && IsMatchingModernIssueSource(entitlement.ContractVersion, ownership.Source)
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

        return classification;
    }

    /// <summary>
    /// Verifies the exact v1/v2 reinstall request with the enrolled public key. Commercial
    /// policy and historical Distribution ownership do not participate in key possession.
    /// </summary>
    /// <param name="enrollment">Locked active credential whose encrypted SPKI is opened.</param>
    /// <param name="request">Strict request and exact signed payload fields.</param>
    private void VerifyReinstallAuthorityProof(
        RuntimeEnrollment enrollment, ReinstallAuthorityValidated request)
    {
        byte[] spki = [];
        byte[]? signature = null;
        try
        {
            spki = _crypto.Open(
                "enrollment-spki", enrollment.Id, enrollment.Epoch,
                enrollment.PublicKeySpkiKeyId, enrollment.PublicKeySpkiCiphertext,
                EnrollmentFieldReference(enrollment.Id, "PublicKeySpkiCiphertext"));
            signature = DecodeBase64Url(request.Signature);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
            if (consumed != spki.Length || rsa.KeySize != 3072
                || !rsa.VerifyData(
                    Encoding.UTF8.GetBytes(BuildReinstallProofPayload(request)),
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
    }

    /// <summary>
    /// Checks only the historical v1 binding and its authenticated Finalize owner. It neither
    /// reads current commercial rows nor uses copied licence, seat or hardware as identity.
    /// </summary>
    /// <param name="db">Authority-lease context holding the locked enrollment.</param>
    /// <param name="enrollment">Proved active Runtime credential.</param>
    /// <param name="binding">Persisted source generation linked to the credential.</param>
    /// <param name="clientId">Exact authenticated S2S owner.</param>
    /// <param name="cancellationToken">Cancels provider-history reads.</param>
    private static async Task ValidateV1ReinstallProvenanceAsync(
        LicenseDbContext db, RuntimeEnrollment enrollment,
        DistributionInstallationBinding binding, string clientId,
        CancellationToken cancellationToken)
    {
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.InstallationId != enrollment.InstallationId
            || binding.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || binding.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256
            || binding.Version != enrollment.ReleaseVersion)
            throw Reject("binding_ineligible");
        if (binding.SubjectRefDigestSha256 is not { Length: 64 }
            || !LowerSha256Pattern.IsMatch(binding.SubjectRefDigestSha256)
            || !LowerUuidPattern.IsMatch(binding.GrantRef))
            throw ReinstallAuthorityIneligible();
        var finalizeOwners = await db.DistributionBindingRequests.AsNoTracking()
            .Where(candidate => candidate.BindingId == binding.Id
                && candidate.Operation == "finalize_binding")
            .Select(candidate => candidate.ClientId).Distinct().Take(2)
            .ToListAsync(cancellationToken);
        if (finalizeOwners.Count != 1
            || !string.Equals(finalizeOwners[0], clientId, StringComparison.Ordinal))
            throw Reject("binding_ineligible");
    }

    /// <summary>
    /// Requires one current source assignment only for legacy fallback or its one-time repair.
    /// The caller already holds the shared or exclusive commercial barrier and a fresh DB time.
    /// A denied graph remains a bounded source refusal; storage failures still propagate.
    /// </summary>
    /// <param name="db">Authority transaction holding the commercial barrier.</param>
    /// <param name="enrollment">Proved Runtime credential used to find its assignment.</param>
    /// <param name="binding">Historical source scope that the assignment must still match.</param>
    /// <param name="approvedBinaries">A-validated release hashes for current ban checks.</param>
    /// <param name="now">Database time sampled after the barrier wait.</param>
    /// <param name="cancellationToken">Cancels read-only current-policy checks.</param>
    private static async Task ValidateReinstallSourceCommercialAsync(
        LicenseDbContext db, RuntimeEnrollment enrollment,
        DistributionInstallationBinding binding,
        IReadOnlyDictionary<string, string> approvedBinaries,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        RuntimeCommercialEligibilityValidator.EligibleAssignment assignment;
        try
        {
            assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approvedBinaries, now, cancellationToken);
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
        {
            throw ReinstallAuthorityIneligible("v2_binding_rows_ineligible");
        }
        if (assignment.LicenseId != binding.LicenseId
            || assignment.SeatId != binding.LicenseSeatId)
            throw ReinstallAuthorityIneligible("v2_binding_rows_ineligible");
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

    /// <summary>
    /// Redeems one enrollment-bound bootstrap capability under its possession proof and the
    /// current commercial assignment. New responses sign the current assignment seat's HWID
    /// and consume the generation atomically. A consumed exact replay rechecks A and B before
    /// returning stored bytes; it never re-signs or changes the enrollment key or epochs.
    /// The authorization's stored hardware digest remains historical evidence and is not compared
    /// with the current binding or used as Runtime identity.
    /// Commercial denials roll back quota and capability changes, while infrastructure failure
    /// remains unavailable rather than a replay-authority conflict.
    /// </summary>
    /// <param name="routeEnrollmentId">Credential identifier from the canonical public route.</param>
    /// <param name="exactBodyDigest">SHA-256 of the exact strict JSON body.</param>
    /// <param name="request">Capability redemption body bound into the possession proof.</param>
    /// <param name="proof">Signed timestamp, JTI and key-possession evidence.</param>
    /// <param name="clientAddress">Optional rate-limit input; never part of identity.</param>
    /// <param name="cancellationToken">Cancels and rolls back the operation.</param>
    /// <returns>New signed license response or verified byte-identical replay.</returns>
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
            // The lease serializes this binding's redemption; its global epoch can advance
            // for commercial policy alone and must not replace the frozen authorization-to-
            // enrollment epoch equality checked by the bootstrap validator.
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            // Item-2 deferred writers hold this enrollment row until they can acquire the
            // exclusive commercial barrier. Take the row first to preserve that lock order.
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
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
                }
                catch (RuntimeEnrollmentException exception) when (
                    exception.StatusCode != StatusCodes.Status503ServiceUnavailable)
                {
                    throw new RuntimeEnrollmentException(
                        "bootstrap_replay_authority_invalid", StatusCodes.Status409Conflict,
                        exception.DiagnosticCode);
                }
                // A proved exact replay still needs current A and B authority. Business denial
                // remains 422, distinct from an idempotency conflict; unavailable stays 503.
                await ValidateLicenseBootstrapRedeemAuthorityAsync(
                    db, enrollment, authorization, productId, bindingId, request.InstallationId!,
                    "CONSUMED", now, cancellationToken);
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
            var assignment = await ValidateLicenseBootstrapRedeemAuthorityAsync(
                db, enrollment, authorization, productId, bindingId, request.InstallationId!,
                "ISSUED", now, cancellationToken);

            var capabilityDigest = Sha256(request.Capability);
            var capability = await db.DistributionLicenseBootstrapCapabilities
                .SingleOrDefaultAsync(row => row.AuthorizationId == authorization.Id
                    && row.CapabilityDigestSha256 == capabilityDigest, cancellationToken)
                ?? throw AuthenticationFailed();
            if (capability.State != "ISSUED" || capability.ExpiresAtUtc <= now.UtcDateTime)
                throw new RuntimeEnrollmentException("bootstrap_expired", StatusCodes.Status410Gone);
            var license = await db.Licenses.Include(row => row.Product).Include(row => row.Type)
                .ThenInclude(type => type!.CustomParams)
                .SingleOrDefaultAsync(row => row.Id == assignment.LicenseId, cancellationToken)
                ?? throw Reject("bootstrap_ineligible");
            // The eligible assignment already carries the exact seat value checked with
            // bans/quota under the barrier. A second seat read could select another value.
            var licenseFile = _signedLicenseFiles.Generate(license, assignment.HardwareId);
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

    /// <summary>
    /// Composes the bootstrap generation's credential and lineage evidence with the current
    /// assignment. Historical hardware, licence and seat copies remain evidence of issuance;
    /// they cannot supply a current grant. The caller holds the binding lease and commercial
    /// read barrier. Refresh checks the consumed generation before challenge rotation; Redeem
    /// uses the returned assignment when producing a new signed file. This validator never
    /// changes enrollment state, keys or epochs and does not verify workflow-specific proof.
    /// </summary>
    /// <param name="db">Lease-scoped PostgreSQL context holding the commercial read barrier.</param>
    /// <param name="enrollment">Locked credential associated with this bootstrap generation.</param>
    /// <param name="authorization">Stored generation whose historical scope cannot be retargeted.</param>
    /// <param name="productId">Canonical product identifier from the request.</param>
    /// <param name="bindingId">Canonical binding identifier from the request.</param>
    /// <param name="installationId">Canonical installation identifier from the request.</param>
    /// <param name="expectedAuthorizationState">Exact ISSUED or CONSUMED lifecycle state.</param>
    /// <param name="now">Database UTC time for expiry and live policy decisions.</param>
    /// <param name="cancellationToken">Cancels reads without committing the caller's transaction.</param>
    /// <returns>The single live assignment scope for Refresh or Redeem validation.</returns>
    private async Task<RuntimeCommercialEligibilityValidator.EligibleAssignment>
        ValidateLicenseBootstrapRedeemAuthorityAsync(
            LicenseDbContext db,
            RuntimeEnrollment enrollment,
            DistributionLicenseBootstrapAuthorization authorization,
            Guid productId,
            Guid bindingId,
            string installationId,
            string expectedAuthorizationState,
            DateTimeOffset now,
            CancellationToken cancellationToken)
    {
        if (enrollment.ProductId != productId
            || enrollment.BindingId != bindingId
            || enrollment.InstallationId != installationId
            || enrollment.SubjectRefDigestSha256 is not { Length: 64 })
            throw Reject("bootstrap_ineligible");

        RuntimeEnrollmentIdentityValidator.ApprovedRelease approved;
        try
        {
            approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
                db, enrollment, cancellationToken);
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
        {
            throw new RuntimeEnrollmentException("bootstrap_ineligible",
                StatusCodes.Status422UnprocessableEntity, exception.DiagnosticCode);
        }
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == enrollment.BindingId, cancellationToken)
            ?? throw Reject("bootstrap_ineligible");
        var entitlement = await db.DistributionEntitlements.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == binding.EntitlementId, cancellationToken)
            ?? throw Reject("bootstrap_ineligible");
        var bindingOwnedByClient = await db.DistributionBindingRequests.AsNoTracking()
            .AnyAsync(row => row.BindingId == binding.Id && row.Operation == "finalize_binding"
                && row.ClientId == enrollment.ClientId, cancellationToken);
        if (!IsModernEntitlementContractVersion(entitlement.ContractVersion)
            || !bindingOwnedByClient
            || entitlement.State != "finalized"
            || entitlement.ExpiresAtUtc <= now.UtcDateTime
            || entitlement.ClientId != enrollment.ClientId
            || entitlement.ProductId != binding.ProductId
            || entitlement.LicenseId != binding.LicenseId
            || entitlement.GrantRefDigestSha256 != binding.GrantRefDigestSha256
            || entitlement.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256
            || binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.InstallationId != enrollment.InstallationId
            || binding.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || binding.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256
            || binding.Version != enrollment.ReleaseVersion
            || binding.HandoffExpiresAtUtc is null
            || binding.HandoffExpiresAtUtc <= now.UtcDateTime
            || !approved.Binaries.TryGetValue("FP_EXE", out var executable)
            || !approved.Binaries.TryGetValue("FP_DLL", out var nativeDll)
            || !approved.Binaries.TryGetValue("FP_CORE", out var core)
            || !string.Equals(executable, binding.ExecutableSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(nativeDll, binding.NativeDllSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(core, binding.CoreSha256, StringComparison.OrdinalIgnoreCase)
            || authorization.State != expectedAuthorizationState
            || authorization.ExpiresAtUtc <= now.UtcDateTime
            || authorization.ClientId != enrollment.ClientId
            || authorization.ProductId != enrollment.ProductId
            || authorization.LicenseId != binding.LicenseId
            || authorization.LicenseSeatId != binding.LicenseSeatId
            || authorization.EntitlementId != entitlement.Id
            || authorization.BindingId != enrollment.BindingId
            || authorization.RuntimeEnrollmentId != enrollment.Id
            || authorization.InstallationId != enrollment.InstallationId
            || authorization.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || authorization.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256
            || authorization.GrantRefDigestSha256 != binding.GrantRefDigestSha256
            || authorization.ReleaseVersion != binding.Version
            || authorization.ApprovedBinariesDigestSha256 != Sha256(string.Join('\n',
                binding.ExecutableSha256, binding.NativeDllSha256, binding.CoreSha256))
            || authorization.ExpiresAtUtc != binding.HandoffExpiresAtUtc
            || authorization.RuntimePublicKeySpkiSha256 != enrollment.PublicKeySpkiSha256
            || authorization.RuntimeKeyThumbprint != enrollment.KeyThumbprint
            || authorization.RuntimeEpoch != enrollment.Epoch
            || authorization.SecurityEpoch != enrollment.SecurityEpoch
            || authorization.AuthorityEpoch != enrollment.AuthorityEpoch
            || authorization.Audience != DistributionLicenseBootstrapService.Audience
            || authorization.Use != "license-bootstrap")
            throw Reject("bootstrap_ineligible");

        RuntimeCommercialEligibilityValidator.EligibleAssignment assignment;
        try
        {
            assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
        {
            throw new RuntimeEnrollmentException("bootstrap_ineligible",
                StatusCodes.Status422UnprocessableEntity, exception.DiagnosticCode);
        }
        // A commercial transfer changes the scope of the old capability. A change to the
        // hardware value on the SAME seat does not: the file will use that seat's live value.
        if (assignment.LicenseId != authorization.LicenseId
            || assignment.SeatId != authorization.LicenseSeatId)
            throw Reject("bootstrap_ineligible");
        return assignment;
    }

    /// <summary>
    /// Creates the first pending Runtime credential and its commercial assignment atomically, or
    /// replays the frozen response while the pending challenge, cryptographic identity and current
    /// commercial authority all remain valid.
    /// </summary>
    /// <remarks>
    /// New requests lock mutable binding and live enrollment rows before the exclusive commercial
    /// barrier, then use fresh database time and force the deferred assignment trigger before P,
    /// A and B validation.
    /// Exact replay locks the enrollment before the shared barrier and returns no bytes for an
    /// active, consumed, expired or commercially ineligible credential. Infrastructure failures
    /// remain distinct from bounded business refusal and every failed attempt rolls back.
    /// </remarks>
    /// <param name="clientId">Authenticated S2S client namespace for request idempotency.</param>
    /// <param name="exactBodyDigest">Lowercase SHA-256 digest of the exact request bytes.</param>
    /// <param name="request">Strict Prepare request and installation possession key.</param>
    /// <param name="cancellationToken">Cancels and rolls back the transactional attempt.</param>
    /// <returns>Created response or byte-identical eligible replay with its idempotency marker.</returns>
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
                validated, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            var key = ValidateEnrollmentKey(request.Key!);
            await LockThumbprintAsync(db, key.Thumbprint, cancellationToken);
            var binding = await LoadBindingForUpdateAsync(db, validated.BindingId, cancellationToken);
            await ValidatePrepareProvenanceAsync(db, binding, clientId, validated, cancellationToken);
            if (!validated.IncludesSecurityEpochInBoundaryResponse && binding.InitialSecurityEpoch != 1)
                throw PrepareV2Required();
            var live = await db.RuntimeEnrollments.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollments"
                WHERE "State" IN ('PENDING', 'ACTIVE')
                  AND ("BindingId" = {binding.Id} OR "KeyThumbprint" = {key.Thumbprint})
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken);
            await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
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
                Id = Guid.NewGuid(),
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
                validated.IncludesSecurityEpochInBoundaryResponse ? PrepareV2ResponseSchema : PrepareResponseSchema,
                ProtocolVersion, "pending", enrollment.Id.ToString("D"), 1,
                challenge, FormatUtc(enrollment.ChallengeExpiresAtUtc), _options.ConfirmAudience)
            {
                SecurityEpoch = validated.IncludesSecurityEpochInBoundaryResponse ? enrollment.SecurityEpoch : null
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
            try
            {
                await db.Database.ExecuteSqlRawAsync(
                    "SET CONSTRAINTS \"TR_RuntimeEnrollments_AssignmentDualWrite\" IMMEDIATE;",
                    cancellationToken);
            }
            catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.CheckViolation)
            {
                throw new RuntimeEnrollmentException(
                    "binding_ineligible", StatusCodes.Status422UnprocessableEntity,
                    "assignment_trigger_refused");
            }

            var approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
                db, enrollment, cancellationToken);
            ValidatePrepareApprovedBinaries(binding, approved.Binaries);
            var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("prepare-binding", validated.BindingId.ToString("D"), 30), ("prepare-global", "all", 240)],
                cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentPrepareResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    /// <summary>
    /// Rotates an unconsumed PENDING challenge for a consumed bootstrap generation after
    /// checking its immutable credential lineage and current independent commercial assignment.
    /// The enrollment row is locked before the shared commercial barrier; both new requests
    /// and exact replays recheck A and B, and a denial changes no challenge or credential epoch.
    /// A commercial-only advance of the global lease epoch does not rewrite the historical
    /// authorization-to-enrollment AuthorityEpoch equality.
    /// </summary>
    /// <param name="clientId">Authenticated S2S client that owns the bootstrap generation.</param>
    /// <param name="exactBodyDigest">Lowercase digest of the exact authenticated request body.</param>
    /// <param name="request">Strict v1/v2 refresh request with optimistic challenge digest.</param>
    /// <param name="cancellationToken">Cancels pending database work when observed.</param>
    /// <returns>Created challenge or byte-identical replay, with its idempotency marker.</returns>
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
            // Lock the enrollment before the shared commercial barrier. Item 2 writers
            // update this row before their deferred trigger takes the exclusive barrier.
            // Read database time only after a possible barrier wait, so expiry decisions
            // and challenge/quota timestamps use the same fresh authority instant.
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            try
            {
                await ValidateLicenseBootstrapRedeemAuthorityAsync(
                    db, enrollment, authorization, enrollment.ProductId, enrollment.BindingId,
                    enrollment.InstallationId, "CONSUMED", now, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception)
                when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                throw new RuntimeEnrollmentException("refresh_ineligible",
                    StatusCodes.Status422UnprocessableEntity, exception.DiagnosticCode);
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
            // Commercial policy may advance the global lease epoch without changing the
            // signed bootstrap generation. Keep its historical authority lineage intact.

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

    /// <summary>
    /// Issues the versioned transition and records authenticated licence-transfer decisions.
    /// Replays revalidate current installation and assignment authority while tolerating unrelated
    /// global epoch advances; the retained Runtime HWID compatibility value is not identity.
    /// </summary>
    /// <param name="clientId">Existing authenticated S2S client; binding/enrollment ownership is checked without new authorization rules.</param>
    /// <param name="exactBodyDigest">Validated lowercase SHA256 of the exact request bytes, preserving existing replay semantics.</param>
    /// <param name="request">Existing versioned upgrade or licence-transfer request. Claimed source/target UUIDs alone cannot own history.</param>
    /// <param name="cancellationToken">Cancels work before decision; captured refusal finalization uses a separate5s host-linked token.</param>
    /// <remarks>Request validation and frozen replay bytes retain their contracts. Issuance locks the enrollment and binding before its shared commercial barrier for v1 or exclusive barrier for a v2 transfer, then reads fresh database time and revalidates Runtime identity and finalized-binding provenance. V1 and completed v2 replay use the current assignment; a new v2 transfer assesses the prospective target from server-owned target rows before any graph mutation. V2's documented source compatibility witness remains historical only. Distinct early-source and later-business savepoints preserve the original source-seat/nonce rollback boundary; Clear is terminal on this private context and the lease retains no entities. Unconfirmed persistence returns existing authority_unavailable503; commit acknowledgement loss is indeterminate. Invalid target entitlement retains the wrapper's generic500 with internal refusal reason stored separately. Successful exact replay adds no event and no historical backfill.</remarks>

    public async Task<RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>> IssueWebSetupTransitionAsync(
        string clientId,
        string exactBodyDigest,
        RuntimeWebSetupTransitionIssueRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var isLicenseTransfer = request.Schema == WebSetupTransitionIssueV2Schema;
        var transport = AutomaticSeatSwitch.CaptureTransport(_httpContextAccessor?.HttpContext);
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
            var enrollment = await LoadEnrollmentForUpdateAsync(db, enrollmentId, cancellationToken);
            if (enrollment.BindingId != bindingId || enrollment.ClientId != clientId)
                throw Reject("websetup_transition_ineligible");
            var binding = await LoadBindingForUpdateAsync(db, bindingId, cancellationToken);
            if (isLicenseTransfer)
                await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(db, cancellationToken);
            else
                await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
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

            // Establish history ownership from the authenticated binding's exact database
            // licence/product link, never from the caller's claimed source or target UUID.
            LicenseDecisionSnapshot? identityHistory = null;
            var identityHistoryPhase = "runtime_transfer_from_source_target_unestablished";
            string? identityHistoryHardwareId = null;
            RuntimeTransferHistoryObservation? transferHistory = null;
            var historyCommitStarted = false;
            if (isLicenseTransfer)
            {
                var sourceIdentity = await db.Licenses.AsNoTracking()
                    .Where(candidate => candidate.Id == binding.LicenseId && candidate.ProductId == binding.ProductId)
                    .Select(candidate => new { candidate.Id, candidate.ProductId }).SingleOrDefaultAsync(cancellationToken);
                if (sourceIdentity != null)
                {
                    identityHistory = new(sourceIdentity.ProductId, sourceIdentity.Id, null, lease.AuthorityEpoch,
                        null, null, null, null, null, null, false, null, "authenticated_source_identity_only");
                    await db.Database.CurrentTransaction!.CreateSavepointAsync(RuntimeSourceHistorySavepoint, cancellationToken);
                }
            }
            try
            {
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
                // The global epoch is not an installation revision. Re-read current rights
                // before returning an older reservation, including a completed v2 transfer.
                var replayApproved = await ValidateWebSetupIssueIdentityAsync(
                    db, enrollment, binding, clientId, cancellationToken);
                await RuntimeCommercialEligibilityValidator.ValidateAsync(
                    db, enrollment, replayApproved.Binaries, now, cancellationToken);
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

            var approved = await ValidateWebSetupIssueIdentityAsync(
                db, enrollment, binding, clientId, cancellationToken);
            if (isLicenseTransfer)
            {
                // This is a source-compatibility witness for legacy transfer only. It establishes
                // no current commercial grant: the target is assessed before any seat or binding mutation.
                if (binding.LicenseId.ToString("D") != request.SourceLicenseId
                    || binding.SubjectRefDigestSha256 != Sha256(request.SourceSubjectRef!)
                    || enrollment.LicenseId != binding.LicenseId
                    || enrollment.LicenseSeatId != binding.LicenseSeatId
                    || enrollment.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256
                    || enrollment.InstallationId != binding.InstallationId)
                    throw Reject("websetup_transition_ineligible");
                await ValidateBindingRowsAsync(
                    db, binding, now, cancellationToken, allowIneligibleSourceLicense: true, migrationCrypto: _crypto);
            }
            else
            {
                await RuntimeCommercialEligibilityValidator.ValidateAsync(
                    db, enrollment, approved.Binaries, now, cancellationToken);
            }

            var activeExists = await db.RuntimeEnrollmentWebSetupTransitions.AsNoTracking().AnyAsync(row =>
                row.EnrollmentId == enrollment.Id && row.State == "ISSUED" && row.ExpiresAtUtc > now.UtcDateTime,
                cancellationToken);
            if (activeExists) throw Conflict("websetup_transition_active");

            IReadOnlyDictionary<string, string>? targetApprovedBinaries = null;
            if (isLicenseTransfer)
            {
                var targetBinaries = await db.ApprovedBinaries.AsNoTracking().Where(candidate =>
                    candidate.ProductId == productId && candidate.Version == request.TargetVersion
                        && candidate.Source == ApprovedBinaryService.ReleaseSource)
                    .Select(candidate => new { candidate.Key, candidate.Hash })
                    .ToListAsync(cancellationToken);
                if (targetBinaries.Count != 3
                    || targetBinaries.Select(candidate => candidate.Key).Distinct(StringComparer.Ordinal).Count() != 3)
                    throw Reject("release_unapproved");
                targetApprovedBinaries = targetBinaries.ToDictionary(
                    candidate => candidate.Key, candidate => candidate.Hash, StringComparer.Ordinal);
            }
            else
            {
                var targetBaselineCount = await db.ApprovedBinaries.AsNoTracking().CountAsync(candidate =>
                    candidate.ProductId == productId && candidate.Version == request.TargetVersion
                        && candidate.Source == ApprovedBinaryService.ReleaseSource,
                    cancellationToken);
                if (targetBaselineCount != 3) throw Reject("release_unapproved");
            }
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

            try
            {
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
                    if (!IsModernEntitlementContractVersion(entitlement.ContractVersion)
                        || entitlement.LicenseId != effectiveLicenseId
                        || entitlement.GrantRefDigestSha256 != Sha256(request.TargetGrantRef!)
                        || entitlement.SubjectRefDigestSha256 != Sha256(request.TargetSubjectRef!))
                        throw Reject("websetup_transition_ineligible");

                    // Target ownership replaces source ownership only after the complete
                    // entitlement match. This read-only attribution never adds an auth rule.
                    if (identityHistory != null && license.ProductId == productId)
                    {
                        identityHistory = LicenseDecisionHistoryWriter.CaptureObserved(license, now, null,
                            "runtime_authority_locks", lease.AuthorityEpoch);
                        identityHistoryPhase = "runtime_license_transfer";
                    }
                    if (effectiveLicenseId == binding.LicenseId)
                        throw Reject("websetup_transition_ineligible");
                    if (string.Equals(request.SourceSubjectRef, request.TargetSubjectRef, StringComparison.Ordinal))
                        throw Reject("websetup_transition_ineligible");
                    var sourceLicenseId = binding.LicenseId;
                    var sourceSeat = await db.LicenseSeats.SingleAsync(
                        candidate => candidate.Id == binding.LicenseSeatId, cancellationToken);
                    // Source binding authority and target entitlement are already authenticated.
                    // Preserve this provider identity if the next commercial guard refuses,
                    // without implying that the later business savepoint has been created.
                    identityHistoryHardwareId = sourceSeat.HardwareId;
                    if (identityHistory != null)
                        identityHistory = LicenseDecisionHistoryWriter.CaptureObserved(license, now,
                            identityHistoryHardwareId, "runtime_authority_locks", lease.AuthorityEpoch);
                    await ValidateWebSetupTransferTargetCommercialEligibilityAsync(
                        db, license, productId, sourceLicenseId, sourceSeat.HardwareId,
                        request.TargetVersion!, targetApprovedBinaries!, now, cancellationToken);
                    transferHistory = new RuntimeTransferHistoryObservation(
                        LicenseDecisionHistoryWriter.CaptureObserved(license, now, sourceSeat.HardwareId,
                            "runtime_authority_locks", lease.AuthorityEpoch), sourceSeat.HardwareId);
                    // All existing authority/binding/row locks already precede this point.
                    // This checkpoint precedes EF source-seat mutation AND SealAsync's SQL nonce reservation.
                    await db.Database.CurrentTransaction!.CreateSavepointAsync(RuntimeHistorySavepoint, cancellationToken);
                    sourceSeat.IsActive = false;
                    sourceSeat.UnlinkedAt = now.UtcDateTime;
                    var targetSeat = await EnsureRuntimeTransferSeatAsync(
                        db, license, sourceLicenseId, sourceSeat.HardwareId, request.TargetVersion!, clientId,
                        now, cancellationToken, transferHistory, transport);
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
                // DOC-510: WebSetup persists this reservation before MSI. Thirty minutes covers the
                // bounded install/restart window while keeping an abandoned capability short-lived.
                var expiresAt = now.AddMinutes(30);
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
                if (transferHistory != null)
                    await AddRuntimeTransferDecisionAsync(db, transferHistory, request, clientId, exactBodyDigest,
                        "accepted", "accepted", StatusCodes.Status201Created, now, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
                historyCommitStarted = true;
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeWebSetupTransitionIssuedResponse>(
                    response, false, responseBytes);
            }
            catch (RuntimeEnrollmentException exception) when (transferHistory != null
                && !historyCommitStarted && exception.StatusCode < 500)
            {
                await PersistRuntimeTransferRefusalAsync(db, lease, transferHistory, request, clientId,
                    exactBodyDigest, exception, now);
                throw;
            }
            }
            catch (RuntimeEnrollmentException exception) when (identityHistory != null && transferHistory == null
                && !historyCommitStarted && exception.StatusCode < 500)
            {
                await PersistRuntimeIdentityRefusalAsync(db, lease, identityHistory, identityHistoryPhase,
                    request, clientId, exactBodyDigest, exception.ErrorCode, null, exception.StatusCode, now,
                    identityHistoryHardwareId);
                throw;
            }
            catch (DistributionOperationException exception) when (identityHistory != null && transferHistory == null
                && !historyCommitStarted)
            {
                // The existing Runtime HTTP wrapper maps this exception to generic500.
                // Preserve it and distinguish the observed internal refusal in ReasonCode.
                await PersistRuntimeIdentityRefusalAsync(db, lease, identityHistory, identityHistoryPhase,
                    request, clientId, exactBodyDigest, "internal_error", exception.ErrorCode, 500, now,
                    identityHistoryHardwareId);
                throw;
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Consumes a signed WebSetup transition after independently validating enrollment identity,
    /// immutable transition proof, and current assignment authority under mutation locks. The
    /// signed release transition advances SecurityEpoch; global commercial epochs remain audit
    /// snapshots and do not rewrite the enrollment's historical AuthorityEpoch lineage.
    /// </summary>
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
            var enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);
            var binding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
            // Authenticate the signed proof before looking up transition scope; only its time
            // validity needs the fresh PostgreSQL clock sampled after the commercial barrier.
            VerifyProof(preflight, "websetup-upgrade", validated.AuthorizationDigest, validated.Proof,
                challengeRequired: false, audience: WebSetupUpgradeAudience);
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

            if (transition.State == "CONSUMED"
                && transition.ConsumedPayloadDigestSha256 != validated.AuthorizationDigest)
                throw Conflict("websetup_transition_replay_rejected");
            if (transition.State == "CONSUMED")
                await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            else
                await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            if (transition.State != "CONSUMED"
                && (transition.State != "ISSUED" || transition.ExpiresAtUtc <= now.UtcDateTime))
                throw Gone("websetup_transition_expired");
            var approved = await ValidateWebSetupIssueIdentityAsync(
                db, enrollment, binding, clientId, cancellationToken);
            var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);

            if (transition.State == "CONSUMED")
            {
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
            if (enrollment.State != "ACTIVE"
                || enrollment.ProductId != validated.ProductId
                || enrollment.InstallationId != transition.InstallationId
                || enrollment.SecurityEpoch != transition.SourceSecurityEpoch
                || enrollment.ReleaseVersion != transition.SourceVersion
                || binding.State != "active"
                || binding.ProductId != validated.ProductId
                || binding.InstallationId != transition.InstallationId
                || binding.Version != transition.SourceVersion
                || transition.AuthorityEpoch > lease.AuthorityEpoch)
                throw Conflict("websetup_transition_binding_changed");

            var license = await db.Licenses.AsNoTracking().Include(candidate => candidate.Product)
                .SingleOrDefaultAsync(candidate => candidate.Id == assignment.LicenseId, cancellationToken);
            if (license == null
                || license.ProductId != enrollment.ProductId
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
            transition.State = "CONSUMED";
            transition.ConsumedAtUtc = now.UtcDateTime;
            transition.ConsumedPayloadDigestSha256 = validated.AuthorizationDigest;
            db.RuntimeEnrollmentRequests.Add(operation);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, "websetup-upgrade", validated.Proof, validated.AuthorizationDigest,
                proofEnvelope, lease.AuthorityEpoch, now));
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            _ = keyId;
            return new RuntimeEnrollmentOperationResult<RuntimeWebSetupUpgradeResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    /// <summary>
    /// Applies the canonical signed upgrade transition after strict boundary validation.
    /// </summary>
    /// <param name="clientId">Authenticated S2S caller that scopes receipt idempotency.</param>
    /// <param name="keyId">Authenticated S2S key identifier retained by the route contract.</param>
    /// <param name="exactRelayDigest">Lowercase digest of the exact relay bytes.</param>
    /// <param name="request">The deployed v1 relay carrying authorization bytes and proof headers.</param>
    /// <param name="cancellationToken">Cancels before the release transaction commits.</param>
    /// <returns>New signed bytes or an exact frozen replay after current authority is revalidated.</returns>
    /// <exception cref="RuntimeEnrollmentException">Thrown with the stable release error contract when validation or current authority fails.</exception>
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

    /// <summary>
    /// Applies the canonical signed recovery rollback after strict boundary validation.
    /// </summary>
    /// <param name="clientId">Authenticated S2S caller that scopes receipt idempotency.</param>
    /// <param name="keyId">Authenticated S2S key identifier retained by the route contract.</param>
    /// <param name="exactRelayDigest">Lowercase digest of the exact relay bytes.</param>
    /// <param name="request">The deployed v1 relay carrying authorization bytes and proof headers.</param>
    /// <param name="cancellationToken">Cancels before the release transaction commits.</param>
    /// <returns>New signed bytes or an exact frozen replay after current authority is revalidated.</returns>
    /// <exception cref="RuntimeEnrollmentException">Thrown with the stable rollback error contract when validation or current authority fails.</exception>
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

    /// <summary>
    /// Applies a signed upgrade or recovery rollback after proof, source identity and current
    /// assignment policy have each passed under ordered locks. Exact replay rechecks current
    /// authority before returning frozen bytes; a fresh proof JTI may reuse those bytes only
    /// within their signed lifetime. Commercial denial never invalidates the enrollment.
    /// A v1 signed recovery HWID is preserved as immutable historical evidence and never replaces
    /// the current locked assignment as the authorization source.
    /// </summary>
    /// <param name="clientId">Authenticated S2S caller used to scope the receipt idempotency key.</param>
    /// <param name="keyId">Authenticated S2S key identifier retained for the route contract.</param>
    /// <param name="exactRelayDigest">Digest of the exact S2S relay body.</param>
    /// <param name="request">Relay carrying the signed enrollment proof and release authorization.</param>
    /// <param name="transition">Operation-specific signed schema, audience and error contract.</param>
    /// <param name="cancellationToken">Cancels before the transaction commits.</param>
    /// <returns>Newly signed release bytes or the exact stored response after current A/P/B checks.</returns>
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
            await using var lease = await _authority.AcquireMutationAsync(db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, validated.EnrollmentId, cancellationToken);
            var binding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
            // Authenticate the recovery proof before receipt lookup can expose its scope.
            VerifyProof(preflight, transition.Operation, validated.AuthorizationDigest, validated.Proof,
                challengeRequired: false, audience: transition.Audience);
            var replay = await FindReleaseTransitionReplayAsync(
                db, clientId, validated.RecoveryReceiptId, validated.AuthorizationDigest,
                transition, cancellationToken);
            if (replay is null)
                await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(db, cancellationToken);
            else
                await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            var approved = await ValidateReleaseTransitionIdentityAsync(
                db, enrollment, binding, cancellationToken);
            var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);
            // The v1 recovery HWID remains immutable signed historical evidence. It does not
            // participate in current Runtime authority, which is derived from the locked assignment.
            if (replay != null)
            {
                var proofReplay = await FindProofReplayAsync<RuntimeEnrollmentUpgradeResponse>(
                    db, enrollment, transition.Operation, validated.Proof,
                    validated.AuthorizationDigest, cancellationToken);
                if (enrollment.ProductId != validated.ProductId
                    || enrollment.InstallationId != validated.InstallationId
                    || enrollment.ReleaseVersion != replay.Response.TargetVersion
                    || enrollment.SecurityEpoch != replay.Response.NewSecurityEpoch
                    || binding.Version != replay.Response.TargetVersion
                    || replay.Response.EnrollmentId != enrollment.Id.ToString("D")
                    || replay.Response.BindingId != binding.Id.ToString("D")
                    || replay.Response.RecoveryReceiptId != validated.RecoveryReceiptId
                    || replay.Response.RecoveryReceiptDigestSha256 != validated.RecoveryReceiptDigestSha256
                    || replay.Response.SourceVersion != validated.SourceVersion
                    || replay.Response.TargetVersion != validated.TargetVersion
                    || replay.Response.OldSecurityEpoch != validated.SecurityEpoch)
                    throw Conflict(transition.BindingConflictCode);
                if (proofReplay != null)
                {
                    if (!proofReplay.ExactBytes.AsSpan().SequenceEqual(replay.ExactBytes))
                        throw new RuntimeEnrollmentException(
                            "authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                            "release_replay_response_mismatch");
                    await lease.CommitAsync(cancellationToken);
                    return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>(
                        replay.Response, true, replay.ExactBytes);
                }
                if (!TryUtc(replay.Response.ExpiresAtUtc, out var replayExpiresAt)
                    || replayExpiresAt <= now)
                    throw Gone(transition.IsRollback
                        ? "rollback_replay_expired" : "upgrade_replay_expired");
                var replayEnvelope = await _crypto.SealAsync(
                    db, transition.ResponseOwnerType, validated.Proof.Jti, enrollment.Epoch,
                    replay.ExactBytes,
                    ProofResponseReference(enrollment.Id, transition.Operation, validated.Proof.Jti),
                    cancellationToken);
                db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                    enrollment, transition.Operation, validated.Proof, validated.AuthorizationDigest,
                    replayEnvelope, lease.AuthorityEpoch, now));
                await db.SaveChangesAsync(cancellationToken);
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentUpgradeResponse>(
                    replay.Response, true, replay.ExactBytes);
            }

            if (enrollment.State != "ACTIVE"
                || enrollment.ProductId != validated.ProductId
                || enrollment.InstallationId != validated.InstallationId
                || enrollment.SecurityEpoch != validated.SecurityEpoch
                || enrollment.ReleaseVersion != validated.SourceVersion)
                throw Conflict(transition.BindingConflictCode);

            if (binding.State != "active"
                || binding.ProductId != validated.ProductId
                || binding.InstallationId != validated.InstallationId
                || binding.Version != validated.SourceVersion)
                throw Conflict(transition.BindingConflictCode);

            var license = await db.Licenses.AsNoTracking().Include(candidate => candidate.Product)
                .SingleOrDefaultAsync(candidate => candidate.Id == assignment.LicenseId, cancellationToken);
            if (license == null
                || license.ProductId != enrollment.ProductId
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
            db.RuntimeEnrollmentRequests.Add(operation);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, transition.Operation, validated.Proof, validated.AuthorizationDigest,
                proofEnvelope, lease.AuthorityEpoch, now));
            try
            {
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

    /// <inheritdoc />
    /// <remarks>
    /// A successful intergeneration Confirm also advances one coherent active hardware alias from
    /// the terminal direct predecessor to this enrollment. The alias update shares the enrollment
    /// activation transaction; missing or disabled aliases are unchanged and unsafe evidence fails
    /// through the existing Confirm conflict contract. Activation preserves the credential's
    /// historical AuthorityEpoch; commercial-only global lease advances are not new bootstrap
    /// generations. The proof nonce may retain the current lease epoch as audit evidence.
    /// </remarks>
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
                var replayNow = await DatabaseNowAsync(db, cancellationToken);
                var replayIdentity = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                    db, enrollment, "ACTIVE", false, null, cancellationToken);
                await RuntimeCommercialEligibilityValidator.ValidateAsync(
                    db, enrollment, replayIdentity.Binaries, replayNow, cancellationToken);
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
            var identity = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "PENDING", false, null, cancellationToken);
            await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, identity.Binaries, now, cancellationToken);
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
            // Confirm activates the existing credential; a commercial-only global epoch
            // advance does not mint a new bootstrap authority generation.
            await RepointHardwareAuthorityAliasAfterConfirmAsync(db, enrollment, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentConfirmResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    /// <summary>
    /// Atomically replaces the current licensing seat identity with its deterministic V2 identity
    /// after proving the active Runtime enrollment and every linked server-side authority row.
    /// The binding, enrollment, cryptographic epochs, and commercial assignment remain immutable:
    /// their copied hardware digests are historical evidence, while the seat and newly signed
    /// licence carry the current licensing identity. Accepted moves record durable authenticated lineage
    /// in the same transaction when their root or complete parent chain is proved; historical gaps are not backfilled.
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
            if (existing == null)
            {
                VerifyProof(preflight, "hardware-authority-migration", exactBodyDigest, validated.Proof,
                    challengeRequired: false, _options.ConfirmAudience);
            }

            var binding = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
            License? license = null;
            LicenseSeat? seat = null;
            var activeAssignments = await db.EnrollmentLicenseAssignments.AsNoTracking()
                .Where(candidate => candidate.EnrollmentId == enrollment.Id && candidate.State == "ACTIVE")
                .Take(2).ToListAsync(cancellationToken);
            if (activeAssignments.Count == 1)
            {
                var selected = activeAssignments[0];
                license = await db.Licenses.FromSqlInterpolated($"""
                    SELECT * FROM public."Licenses" WHERE "Id" = {selected.LicenseId} FOR UPDATE
                    """).Include(candidate => candidate.Product)
                    .Include(candidate => candidate.Type).ThenInclude(type => type!.CustomParams)
                    .SingleOrDefaultAsync(cancellationToken);
                seat = await db.LicenseSeats.FromSqlInterpolated($"""
                    SELECT * FROM public."LicenseSeats" WHERE "Id" = {selected.LicenseSeatId} FOR UPDATE
                    """).SingleOrDefaultAsync(cancellationToken);
            }

            var targetHardwareId = existing?.Response.HardwareIdV2 ?? validated.HardwareIdV2;
            await SecurityService.AcquireHardwareBanMutationAsync(db, targetHardwareId);
            await LockHardwareAuthorityAsync(db, enrollment.ProductId, targetHardwareId, cancellationToken);
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            if (existing == null)
                ValidateProofTime(validated.Proof.SentAtUtc, now);
            var approved = await ValidateHardwareMigrationIdentityAsync(
                db, enrollment, binding, cancellationToken);
            var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);
            if (license == null || seat == null
                || assignment.AssignmentId != activeAssignments[0].Id
                || assignment.Revision != activeAssignments[0].Revision
                || assignment.LicenseId != license.Id || assignment.SeatId != seat.Id
                || binding.LicenseId != assignment.LicenseId
                || binding.LicenseSeatId != assignment.SeatId)
                throw Reject("hardware_authority_migration_ineligible");

            if (existing != null)
            {
                var replayHardwareHash = Sha256(existing.Response.HardwareIdV2);
                var replayConflict = enrollment.State != "ACTIVE"
                    || enrollment.SecurityEpoch != existing.Response.NewSecurityEpoch
                    || existing.Response.EnrollmentId != enrollment.Id.ToString("D")
                    || existing.Response.BindingId != binding.Id.ToString("D")
                    || existing.Response.LicenseSeatId != assignment.SeatId.ToString("D")
                    || !string.Equals(
                        assignment.HardwareId.ToUpperInvariant(), existing.Response.HardwareIdV2,
                        StringComparison.Ordinal)
                    || await db.LicenseSeats.AsNoTracking().AnyAsync(candidate =>
                        candidate.Id != assignment.SeatId && candidate.IsActive
                        && candidate.License!.ProductId == enrollment.ProductId
                        && candidate.HardwareId.ToUpper() == existing.Response.HardwareIdV2,
                        cancellationToken)
                    || await db.DistributionInstallationBindings.AsNoTracking().AnyAsync(candidate =>
                        candidate.Id != binding.Id && candidate.ProductId == enrollment.ProductId
                        && candidate.State == "active" && candidate.HardwareIdHash == replayHardwareHash,
                        cancellationToken);
                if (replayConflict)
                    throw Conflict("hardware_authority_migration_conflict");
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            if (enrollment.State != "ACTIVE" || enrollment.SecurityEpoch != validated.SecurityEpoch)
                throw Conflict("hardware_authority_migration_conflict");
            await ReserveQuotasAsync(db, now,
                [("hardware-migration-binding", preflight.BindingId.ToString("D"), 12),
                 ("hardware-migration-credential", preflight.EnrollmentId.ToString("D"), 6),
                 ("hardware-migration-ip", PseudonymizeAddress(clientAddress), 12),
                 ("hardware-migration-global", "all", 120)], cancellationToken);

            var legacyHash = Sha256(validated.LegacyHardwareId);
            var stableHash = Sha256(validated.HardwareIdV2);
            var seatHardwareId = seat.HardwareId.ToUpperInvariant();
            var sourceIsLegacy = string.Equals(
                seatHardwareId, validated.LegacyHardwareId, StringComparison.Ordinal);
            var targetIsAlreadyAuthoritative = string.Equals(
                seatHardwareId, validated.HardwareIdV2, StringComparison.Ordinal);
            if ((!sourceIsLegacy && !targetIsAlreadyAuthoritative)
                || binding.ProductId != license.ProductId || binding.State != "active"
                || binding.InstallationId != enrollment.InstallationId
                || binding.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256)
                throw Reject("hardware_authority_migration_ineligible");
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
            var committedSecurityEpoch = enrollment.SecurityEpoch;
            var committedAuthorityEpoch = enrollment.AuthorityEpoch;
            if (migrated)
            {
                // TKT-001277 (Franck): moving a seat to another identifier consumes the customer's daily seat
                // change and is refused when the quota is exhausted, exactly like the activation switch. A replay
                // returned above and an already_current request never reach this point, so nothing is charged twice.
                var seatChangeQuota = await SeatChangeQuota.GetStatusAsync(
                    db, license, now.UtcDateTime, cancellationToken);
                if (seatChangeQuota.IsExhausted)
                    throw Reject("max_daily_deactivations_reached");
            }
            // LEGACY-EXPIRY(TKT-001430, 2026-12-31): the alias links the pre-UUID identifier to the migrated seat so the
            // existing binding, eligibility and reinstall checks keep resolving. Remove with the migration endpoint.
            var requiresAlias = !string.Equals(
                validated.LegacyHardwareId, validated.HardwareIdV2, StringComparison.Ordinal);
            // TKT-001277 (review B1): a seat already moved from L to S keeps its binding digest. When that binding still
            // carries L, the resolver can only find the seat through an alias whose source is exactly that digest, and it
            // accepts one alias per target. So the existing L to S alias is repointed to U instead of adding S to U.
            // When the binding carries S (every production case measured on 30/09/2026), S to U is created as before.
            HardwareAuthorityAlias? chainedAlias = null;
            if (migrated && requiresAlias && binding.HardwareIdHash != legacyHash)
            {
                chainedAlias = await db.HardwareAuthorityAliases.SingleOrDefaultAsync(alias =>
                    alias.LicenseId == license.Id
                    && alias.ProductId == license.ProductId
                    && alias.LicenseSeatId == seat.Id
                    && alias.IsActive && alias.DisabledAtUtc == null
                    && alias.LegacyHardwareIdSha256 == binding.HardwareIdHash
                    && alias.CanonicalHardwareIdSha256 == legacyHash,
                    cancellationToken);
            }
            if (chainedAlias != null)
            {
                _historyLogger?.LogWarning(
                    "HARDWARE_ID_ALIAS_CHAINED Hardware authority alias {AliasId} of licence {LicenseId}, seat {LicenseSeatId} retargeted from the previous identifier to the UUID identifier by migration request {RequestId}.",
                    chainedAlias.Id, license.Id, seat.Id, validated.RequestId);
                chainedAlias.CanonicalHardwareIdSha256 = stableHash;
                chainedAlias.RuntimeEnrollmentId = enrollment.Id;
                chainedAlias.BindingId = binding.Id;
                chainedAlias.MigrationRequestId = validated.RequestId;
                chainedAlias.SecurityEpoch = committedSecurityEpoch;
                chainedAlias.AuthorityEpoch = committedAuthorityEpoch;
                requiresAlias = false;
            }
            else if (!migrated && requiresAlias
                && await db.HardwareAuthorityAliases.AnyAsync(alias =>
                    alias.LicenseId == license.Id && alias.LicenseSeatId == seat.Id
                    && alias.CanonicalHardwareIdSha256 == stableHash
                    && alias.LegacyHardwareIdSha256 != legacyHash, cancellationToken))
            {
                // already_current after a chained migration: the target already has its one alias; a second one
                // would make the target ambiguous for the resolver.
                requiresAlias = false;
            }
            HardwareAuthorityAlias? existingAlias = null;
            if (requiresAlias)
            {
                existingAlias = await db.HardwareAuthorityAliases.SingleOrDefaultAsync(alias =>
                    alias.LicenseId == license.Id
                    && alias.LegacyHardwareIdSha256 == legacyHash,
                    cancellationToken);
                // An alias of another seat, another machine or disabled by an operator is a real
                // conflict and keeps refusing.
                if (existingAlias != null
                    && (!existingAlias.IsActive
                        || existingAlias.ProductId != license.ProductId
                        || existingAlias.LicenseSeatId != seat.Id
                        || existingAlias.CanonicalHardwareIdSha256 != stableHash))
                {
                    throw Conflict("hardware_authority_migration_conflict");
                }
                // TEMP-FAIL-OPEN(TKT-001262) ALIAS-REPOINT: the strict rule is that an alias must
                // already identify the current binding and enrollment. Finalize is known to rotate
                // those rows without moving the alias, which made valid clients fail later with
                // hardware_authority_rejected (SUP-000040). Franck requested that this known data/code
                // defect no longer block customers: the signed migration transaction repoints the same
                // product/license/seat/machine alias and logs every repair. Analyse every occurrence,
                // correct the producer, restore the strict decision, then remove this marker. Alias
                // epochs are authenticated minimums; lower values remain valid, while a higher value is
                // an observable regression that is temporarily repaired here instead of being refused.
                if (existingAlias != null
                    && (existingAlias.RuntimeEnrollmentId != enrollment.Id
                        || existingAlias.BindingId != binding.Id
                        || existingAlias.SecurityEpoch > committedSecurityEpoch
                        || existingAlias.AuthorityEpoch > committedAuthorityEpoch))
                {
                    _historyLogger?.LogWarning(
                        "TEMP-FAIL-OPEN(TKT-001262) ALIAS-REPOINT Hardware authority alias {AliasId} repointed during migration: licence {LicenseId}, seat {LicenseSeatId}, binding {PreviousBindingId} -> {BindingId}, enrollment {PreviousEnrollmentId} -> {EnrollmentId}, security epoch {PreviousSecurityEpoch} -> {SecurityEpoch}, authority epoch {PreviousAuthorityEpoch} -> {AuthorityEpoch}, previous migration request {PreviousMigrationRequestId} -> {RequestId}.",
                        existingAlias.Id,
                        license.Id,
                        seat.Id,
                        existingAlias.BindingId,
                        binding.Id,
                        existingAlias.RuntimeEnrollmentId,
                        enrollment.Id,
                        existingAlias.SecurityEpoch,
                        committedSecurityEpoch,
                        existingAlias.AuthorityEpoch,
                        committedAuthorityEpoch,
                        existingAlias.MigrationRequestId,
                        validated.RequestId);
                    existingAlias.RuntimeEnrollmentId = enrollment.Id;
                    existingAlias.BindingId = binding.Id;
                    existingAlias.MigrationRequestId = validated.RequestId;
                    existingAlias.SecurityEpoch = committedSecurityEpoch;
                    existingAlias.AuthorityEpoch = committedAuthorityEpoch;
                }
                if (existingAlias == null)
                {
                    // The alias is created only inside the signed migration transaction after every
                    // seat, binding, enrollment, ban, and uniqueness authority check has succeeded.
                    existingAlias = new HardwareAuthorityAlias
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
                        AuthorityEpoch = committedAuthorityEpoch,
                        CreatedAtUtc = now.UtcDateTime
                    };
                    db.HardwareAuthorityAliases.Add(existingAlias);
                }
            }

            if (migrated)
            {
                // Persist acceptance in the same transaction, before any commercial or alias changes can commit.
                // An old alias without a provable parent is never silently upgraded into trusted lineage.
                var receiptAlias = chainedAlias ?? existingAlias;
                if (receiptAlias != null)
                    await RecordMigrationLineageAsync(db, receiptAlias, binding, enrollment, validated,
                        exactBodyDigest, now, cancellationToken);
                seat.HardwareId = validated.HardwareIdV2;
                if (!string.IsNullOrEmpty(license.HardwareId)
                    && string.Equals(license.HardwareId.ToUpperInvariant(), validated.LegacyHardwareId, StringComparison.Ordinal))
                    license.HardwareId = validated.HardwareIdV2;
                db.LicenseHistories.Add(new LicenseHistory
                {
                    LicenseId = license.Id,
                    Timestamp = now.UtcDateTime,
                    Action = HistoryActions.HardwareIdMigrated,
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
            await db.SaveChangesAsync(cancellationToken);
            if (migrated)
            {
                await db.Database.ExecuteSqlRawAsync("""
                    SET CONSTRAINTS
                        "TR_RuntimeEnrollments_AssignmentDualWrite",
                        "TR_DistributionBindings_AssignmentDualWrite",
                        "TR_LicenseSeats_AssignmentDualWrite",
                        "TR_Licenses_AssignmentDualWrite"
                    IMMEDIATE;
                    """, cancellationToken);
            }
            var committedAssignment = await db.EnrollmentLicenseAssignments.AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.Id == assignment.AssignmentId
                    && candidate.EnrollmentId == enrollment.Id && candidate.State == "ACTIVE",
                    cancellationToken);
            if (committedAssignment == null
                || committedAssignment.Revision != assignment.Revision
                || committedAssignment.LicenseId != assignment.LicenseId
                || committedAssignment.LicenseSeatId != assignment.SeatId)
                throw new RuntimeEnrollmentException(
                    "authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                    "assignment_changed_during_hardware_migration");
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeHardwareAuthorityMigrationResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    /// <summary>
    /// Issues or replays a proof-bound capability under the existing authority lease. Current license
    /// validity is checked for both paths after classification locks. Ordinary licenses retain the
    /// exact 120-second client contract; identified paid passes additionally require a coherent paid
    /// horizon and cannot outlive it. Replays retain their original bytes and never refresh TTL.
    /// </summary>
    /// <inheritdoc />
    /// <remarks>
    /// A successful capability records the current global lease epoch in its proof nonce for
    /// audit, but does not replace the enrollment's historical bootstrap AuthorityEpoch.
    /// Commercial eligibility is checked independently on new issuance and exact replay.
    /// </remarks>
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
            if (validated.SecurityEpoch != enrollment.SecurityEpoch)
                throw Conflict("security_epoch_mismatch");
            var existing = await FindProofReplayAsync<RuntimeEnrollmentCapabilityResponse>(
                db, enrollment, "capability", validated.Proof, exactBodyDigest, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            if (existing != null)
            {
                var replayIdentity = await ValidateCapabilityIdentityAsync(
                    db, enrollment, validated, cancellationToken);
                var replayAssignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                    db, enrollment, replayIdentity.Binaries, now, cancellationToken);
                var paidExpiry = await LoadCapabilityPaidExpiryAsync(
                    db, enrollment, replayAssignment.LicenseId, cancellationToken);
                now = await DatabaseNowAsync(db, cancellationToken);
                // Recheck after any classification lock wait: historical proof success cannot bypass current authority.
                var replayRecheck = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                    db, enrollment, replayIdentity.Binaries, now, cancellationToken);
                EnsureCapabilityAssignmentUnchanged(replayAssignment, replayRecheck);
                if (!DateTimeOffset.TryParse(existing.Response.ExpiresAtUtc, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var replayExpiry)
                    || !RuntimeEnrollmentCryptoService.IsCapabilityReplayCurrent(now, replayExpiry, paidExpiry))
                    throw Conflict("capability_expired");
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>(
                    existing.Response, true, existing.ExactBytes);
            }
            await ReserveQuotasAsync(db, now,
                [("capability-binding", preflight.BindingId.ToString("D"), 60),
                 ("capability-credential", preflight.EnrollmentId.ToString("D"), 30),
                 ("capability-ip", PseudonymizeAddress(clientAddress), 30),
                 ("capability-global", "all", 240)], cancellationToken);
            VerifyProof(preflight, "capability", exactBodyDigest, validated.Proof,
                challengeRequired: false, validated.Audience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            var identity = await ValidateCapabilityIdentityAsync(
                db, enrollment, validated, cancellationToken);
            var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, identity.Binaries, now, cancellationToken);
            var licenseExpiry = await LoadCapabilityPaidExpiryAsync(
                db, enrollment, assignment.LicenseId, cancellationToken);
            now = await DatabaseNowAsync(db, cancellationToken);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            var recheckedAssignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, identity.Binaries, now, cancellationToken);
            EnsureCapabilityAssignmentUnchanged(assignment, recheckedAssignment);
            ValidateCapabilityAuthorization(enrollment.ProductId, validated.Audience, validated.Scopes);

            // Null deliberately preserves exp-iat=120 for ordinary clients, even near commercial expiry.
            // Identified passes have a locked, coherent paid horizon and never fall back to ordinary TTL.
            var capabilityExpiry = RuntimeEnrollmentCryptoService.BoundCapabilityExpiry(now, licenseExpiry);
            var tokenJti = Guid.NewGuid().ToString("D");
            var token = validated.IsLegacy
                ? _crypto.SignLegacyCapability(
                    enrollment.Id, enrollment.Epoch, enrollment.SecurityEpoch,
                    validated.Audience, validated.Scopes,
                    enrollment.PublicKeySpkiSha256, now, tokenJti, capabilityExpiry)
                : _crypto.SignCapability(
                    enrollment.Id, enrollment.Epoch, enrollment.SecurityEpoch,
                    enrollment.InstallationId, enrollment.ReleaseVersion, validated.SessionId!, validated.Binaries!,
                    validated.Audience, validated.Scopes,
                    enrollment.PublicKeySpkiSha256, now, tokenJti, capabilityExpiry);
            var response = new RuntimeEnrollmentCapabilityResponse(
                CapabilityResponseSchema, ProtocolVersion, token, FormatUtc(capabilityExpiry.UtcDateTime));
            var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            var envelope = await _crypto.SealAsync(db, "capability-response", validated.Proof.Jti,
                enrollment.Epoch, responseBytes,
                ProofResponseReference(enrollment.Id, "capability", validated.Proof.Jti), cancellationToken);
            db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(
                enrollment, "capability", validated.Proof, exactBodyDigest, envelope, lease.AuthorityEpoch, now));
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeEnrollmentCapabilityResponse>(response, false, responseBytes);
        }, cancellationToken);
    }

    /// <summary>
    /// Returns a coherent paid-pass horizon, or null for an ordinary license's historical 120-second
    /// capability contract. The caller must hold the existing global authority lease and re-read DB time
    /// and current eligibility after this method, because classification can wait on row locks.
    /// </summary>
    /// <remarks>
    /// Lock order is the existing global/binding lease, enrollment, license, type, then paid identity.
    /// FOR SHARE also stabilizes LicenseTypeId and type fields omitted from the authority epoch triggers.
    /// The existing paid issuer takes the exclusive global authority lock before creating/changing ledger
    /// identity, so absence of an ordinary license's ledger cannot race that writer. Slug comparison uses
    /// the established ordinal-ignore-case policy in memory; UUID predicates remain exact, indexed PG
    /// lookups. A ledger survives type renaming/reassignment as a pass signal. Missing or divergent pass
    /// authority is rejected, never converted into an unrestricted ordinary capability. No data is repaired.
    /// </remarks>
    private static async Task<DateTimeOffset?> LoadCapabilityPaidExpiryAsync(LicenseDbContext db,
        RuntimeEnrollment enrollment, Guid licenseId, CancellationToken cancellationToken)
    {
        var license = await db.Licenses.FromSqlInterpolated($"""
            SELECT * FROM public."Licenses"
            WHERE "Id" = {licenseId} AND "ProductId" = {enrollment.ProductId}
            FOR SHARE
            """).AsNoTracking().SingleAsync(cancellationToken);
        var type = await db.LicenseTypes.FromSqlInterpolated($"""
            SELECT * FROM public."LicenseTypes" WHERE "Id" = {license.LicenseTypeId} FOR SHARE
            """).AsNoTracking().SingleAsync(cancellationToken);
        var pass = await db.PersonalDayPasses.FromSqlInterpolated($"""
            SELECT * FROM public."PersonalDayPasses"
            WHERE "ProductId" = {enrollment.ProductId} AND "LicenseId" = {license.Id}
            FOR SHARE
            """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        // TIA-CONNECT-PRO is also the ordinary paid type. Only an existing ledger opts the
        // licence into paid-period expiry; the slug alone must never change ordinary Runtime TTL.
        if (pass is null) return null;

        // Once a ledger exists, every authority field must agree before paid time is issued.
        if (!PersonalDayPassPolicy.IsPassType(type.Slug) || type.ProductId != enrollment.ProductId
            || type.IsFree || !type.IsRecurring || type.AllowAnonymous || type.EnforceSingleUsePerHardwareId
            || !license.ExpirationDate.HasValue || license.ExpirationDate.Value != pass.PaidThroughUtc)
            throw Reject("authority_ineligible");
        return new DateTimeOffset(pass.PaidThroughUtc);
    }

    /// <summary>
    /// A paid-pass classification may wait for a licence lock. Its expiry is valid only for the
    /// same commercial assignment that was selected before the wait.
    /// </summary>
    private static void EnsureCapabilityAssignmentUnchanged(
        RuntimeCommercialEligibilityValidator.EligibleAssignment selected,
        RuntimeCommercialEligibilityValidator.EligibleAssignment current)
    {
        if (selected != current)
            throw new RuntimeEnrollmentException(
                "authority_ineligible", StatusCodes.Status422UnprocessableEntity,
                "assignment_changed");
    }

    /// <summary>
    /// Records one proof-bearing Runtime milestone after the locked enrollment and milestone
    /// session pass independent cryptographic and current commercial authority checks.
    /// </summary>
    /// <remarks>
    /// Enrollment and session rows are locked before the shared item-2 barrier. PostgreSQL time is
    /// sampled after those waits, and exact replay rechecks identity, proof signature, session state
    /// and commercial eligibility before returning frozen bytes. Proof time applies only when a new
    /// ACK is created. The global lease epoch remains nonce and milestone audit data and is not copied
    /// into the enrollment's historical lineage.
    /// </remarks>
    /// <param name="routeEnrollmentId">Enrollment identifier fixed by the public route.</param>
    /// <param name="exactBodyDigest">SHA-256 digest of the exact request bytes.</param>
    /// <param name="request">Milestone sequence and client-declared evidence.</param>
    /// <param name="proof">Enrollment-key signature, time and replay identifier.</param>
    /// <param name="clientAddress">Optional address used only for bounded quota attribution.</param>
    /// <param name="cancellationToken">Cancels the transactional attempt.</param>
    /// <returns>A new or exact frozen milestone acknowledgement and its idempotency flag.</returns>
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
            var session = await db.RuntimeMilestoneSessions.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeMilestoneSessions"
                WHERE "EnrollmentId" = {enrollment.Id} AND "SessionId" = {validated.SessionId}
                FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken);
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "ACTIVE", false, null, cancellationToken);
            if (validated.SecurityEpoch != enrollment.SecurityEpoch)
                throw Conflict("security_epoch_mismatch");
            ValidateMilestoneAuthorization(enrollment.ProductId);
            VerifyProof(preflight, "milestone", exactBodyDigest, validated.Proof,
                challengeRequired: false, _options.ConfirmAudience);
            if (session != null)
                EnsureMilestoneSessionActive(session, now);

            await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);

            var existing = await FindProofReplayAsync<RuntimeMilestoneAckResponse>(
                db, enrollment, "milestone", validated.Proof, exactBodyDigest, cancellationToken);
            if (existing != null)
            {
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<RuntimeMilestoneAckResponse>(
                    existing.Response, true, existing.ExactBytes);
            }

            ValidateProofTime(validated.Proof.SentAtUtc, now);
            await ReserveQuotasAsync(db, now,
                [("milestone-binding", preflight.BindingId.ToString("D"), 240),
                 ("milestone-credential", preflight.EnrollmentId.ToString("D"), 120),
                 ("milestone-ip", PseudonymizeAddress(clientAddress), 120),
                 ("milestone-global", "all", 960)], cancellationToken);
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

    /// <summary>
    /// Reissues a stored critical-recovery receipt to its proof-bearing enrollment without
    /// advancing its historical authority lineage. A valid old-security-epoch proof and current
    /// commercial assignment are both required, including on exact replay. Commercial denial
    /// precedes quota charging; accepted new requests and exact replays both charge quota, while
    /// only a new request persists a proof nonce. The enrollment row precedes the shared commercial
    /// barrier, and database time is sampled after that wait.
    /// </summary>
    /// <remarks>Stored response bytes are returned exactly; proof conflicts remain 409, commercial
    /// denial 422, and unavailable assignment relations 503 without a partial commit.</remarks>
    /// <param name="routeEnrollmentId">Credential identifier fixed by the public route.</param>
    /// <param name="exactBodyDigest">SHA-256 digest of the exact received request bytes.</param>
    /// <param name="request">Validated old-epoch refetch request and idempotency identifier.</param>
    /// <param name="proof">Enrollment-key signature, time and replay identifier.</param>
    /// <param name="clientAddress">Optional address used only for bounded quota attribution.</param>
    /// <param name="cancellationToken">Cancels the transactional attempt.</param>
    /// <returns>New or exact frozen receipt bytes with an idempotency flag.</returns>
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
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            VerifyProof(preflight, "critical-recovery-refetch", exactBodyDigest, validated.Proof,
                challengeRequired: false, _options.ConfirmAudience);
            ValidateProofTime(validated.Proof.SentAtUtc, now);
            var approved = await ValidateCriticalRecoveryProvenanceAsync(
                db, enrollment, cancellationToken);
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
            await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("recovery-refetch-binding", preflight.BindingId.ToString("D"), 30),
                 ("recovery-refetch-credential", preflight.EnrollmentId.ToString("D"), 15),
                 ("recovery-refetch-ip", PseudonymizeAddress(clientAddress), 15),
                 ("recovery-refetch-global", "all", 120)], cancellationToken);

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
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse>(
                response, false, responseBytes);
        }, cancellationToken);
    }

    /// <summary>
    /// Authenticates and stores one Runtime Canary security report and returns its signed ACK.
    /// </summary>
    /// <remarks>
    /// The locked enrollment precedes the shared item-2 barrier and fresh PostgreSQL time. Current
    /// commercial eligibility is assessed after identity and proof validation, but denial never
    /// discards authenticated security evidence or turns the ACK into a grant. Exact replay returns
    /// frozen signed bytes after the same decisive checks. Lease epochs remain incident and nonce
    /// audit data and are not copied into the enrollment's historical lineage.
    /// </remarks>
    /// <param name="routeEnrollmentId">Enrollment identifier fixed by the public route.</param>
    /// <param name="exactBodyDigest">SHA-256 digest of the exact report bytes.</param>
    /// <param name="request">Authenticated Canary evidence supplied by Runtime.</param>
    /// <param name="proof">Enrollment-key signature, time and replay identifier.</param>
    /// <param name="clientAddress">Optional address used only for bounded quota attribution.</param>
    /// <param name="cancellationToken">Cancels the transactional attempt.</param>
    /// <returns>A new or exact frozen signed Canary acknowledgement and its idempotency flag.</returns>
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

            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            ValidateProofTime(validatedProof.SentAtUtc, now);
            var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "ACTIVE", false, null, cancellationToken);
            if (!string.Equals(canary.AppVersion, enrollment.ReleaseVersion, StringComparison.Ordinal))
                throw Reject("canary_binding_mismatch");
            var commercial = await RuntimeCommercialEligibilityValidator.AssessAsync(
                db, enrollment, approved.Binaries, now, canary.HardwareId, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("canary-binding", preflight.BindingId.ToString("D"), 60),
                 ("canary-credential", preflight.EnrollmentId.ToString("D"), 30),
                 ("canary-ip", PseudonymizeAddress(clientAddress), 30),
                 ("canary-global", "all", 240)], cancellationToken);

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
                HardwareIdHash = Sha256(canary.HardwareId),
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
                ServerAction = "authenticated_evidence",
                Details = !commercial.IsEligible
                    ? "commercial_denial:" + commercial.DenialReason
                    : commercial.ReportHardwareLinked ? null : "report_hardware_unlinked"
            });
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

    /// <summary>
    /// Closes one authenticated open critical incident and signs its recovery receipt atomically
    /// with the new SecurityEpoch. The locked enrollment's cryptographic provenance and current
    /// commercial assignment are checked independently after the shared commercial barrier;
    /// a commercial denial leaves the incident and credential unchanged. Exact requests replay
    /// frozen bytes only while both authorities remain valid.
    /// </summary>
    /// <remarks>The global authority epoch remains receipt audit data and is never copied into
    /// the enrolled credential. Receipt conflicts stay 409, commercial denial 422, and provider
    /// failure 503; the authority lease and transaction roll back together on failure.</remarks>
    /// <param name="clientId">Authenticated S2S client namespace for immutable receipt replay.</param>
    /// <param name="keyId">Validated S2S key identifier recorded with the receipt.</param>
    /// <param name="exactBodyDigest">SHA-256 digest of the exact received request bytes.</param>
    /// <param name="request">Incident scope and next security generation.</param>
    /// <param name="cancellationToken">Cancels the transactional attempt.</param>
    /// <returns>New or exact frozen signed recovery bytes with an idempotency flag.</returns>
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
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            var approved = await ValidateCriticalRecoveryProvenanceAsync(
                db, enrollment, cancellationToken);
            await EnsureCriticalRecoveryReceiptRequestMatchesAsync(
                db, validated.RequestId, exactBodyDigest, clientId, cancellationToken);
            await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);

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

    /// <summary>
    /// Refetches one signed S2S critical-recovery receipt for its original recovery generation.
    /// Resolves scope read-only before taking the enrollment row lock, then locks the recovery row
    /// and rechecks scope before crossing the shared commercial barrier. Current A/P and B gate
    /// both new requests and exact frozen-byte replay; a new request persists only its receipt.
    /// </summary>
    /// <remarks>The pre-lock scope read grants nothing. Generation or request conflicts remain
    /// 409, commercial denial 422, and unavailable authority 503 with transaction rollback.</remarks>
    /// <param name="clientId">Authenticated S2S client namespace for immutable receipt replay.</param>
    /// <param name="keyId">Validated S2S key identifier recorded on a new receipt.</param>
    /// <param name="exactBodyDigest">SHA-256 digest of the exact received request bytes.</param>
    /// <param name="request">Recovery identifier, generation scope and idempotency identifier.</param>
    /// <param name="cancellationToken">Cancels the transactional attempt.</param>
    /// <returns>New or exact frozen signed receipt bytes with an idempotency flag.</returns>
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

            var recoveryScope = await db.RuntimeCriticalRecoveries.AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.Id == validated.RecoveryId, cancellationToken)
                ?? throw new RuntimeEnrollmentException("recovery_unavailable", StatusCodes.Status404NotFound);
            if (recoveryScope.ProductId != validated.ProductId
                || recoveryScope.BindingId != validated.BindingId
                || recoveryScope.InstallationId != validated.InstallationId
                || recoveryScope.RequestedEventId != validated.EventId
                || recoveryScope.NewSecurityEpoch != validated.NewSecurityEpoch)
            {
                throw Conflict("recovery_binding_conflict");
            }

            var enrollment = await LoadEnrollmentForUpdateAsync(db, recoveryScope.EnrollmentId, cancellationToken);
            var recovery = await db.RuntimeCriticalRecoveries.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeCriticalRecoveries"
                WHERE "Id" = {validated.RecoveryId} FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken)
                ?? throw new RuntimeEnrollmentException("recovery_unavailable", StatusCodes.Status404NotFound);
            if (enrollment.State != "ACTIVE"
                || recovery.EnrollmentId != enrollment.Id
                || enrollment.ProductId != recovery.ProductId
                || enrollment.BindingId != recovery.BindingId
                || enrollment.InstallationId != recovery.InstallationId
                || enrollment.SecurityEpoch != recovery.NewSecurityEpoch
                || recovery.ProductId != validated.ProductId
                || recovery.BindingId != validated.BindingId
                || recovery.InstallationId != validated.InstallationId
                || recovery.RequestedEventId != validated.EventId
                || recovery.NewSecurityEpoch != validated.NewSecurityEpoch)
            {
                throw Conflict("recovery_generation_conflict");
            }
            await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            var now = await DatabaseNowAsync(db, cancellationToken);
            var approved = await ValidateCriticalRecoveryProvenanceAsync(
                db, enrollment, cancellationToken);
            if (await HasOpenCriticalIncidentAsync(
                    db, recovery.BindingId, recovery.InstallationId, cancellationToken))
            {
                throw Conflict("recovery_generation_conflict");
            }
            await EnsureCriticalRecoveryReceiptRequestMatchesAsync(
                db, validated.RequestId, exactBodyDigest, clientId, cancellationToken);
            await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);

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

    /// <summary>
    /// Preserves a recovery receipt's exact request and S2S client namespace before commercial
    /// assessment. A conflicting retry remains a 409 even when current commerce is ineligible;
    /// no stored response bytes are returned until the later current-B check succeeds.
    /// </summary>
    /// <param name="db">Recovery transaction under the binding authority lease.</param>
    /// <param name="requestId">Canonical request identifier whose receipt is immutable.</param>
    /// <param name="bodyDigest">Digest of the exact received request body.</param>
    /// <param name="clientId">Authenticated S2S client namespace.</param>
    /// <param name="cancellationToken">Cancels the receipt lookup.</param>
    private static async Task EnsureCriticalRecoveryReceiptRequestMatchesAsync(
        LicenseDbContext db, string requestId, string bodyDigest, string clientId,
        CancellationToken cancellationToken)
    {
        var receipt = await db.RuntimeCriticalRecoveryReceipts.AsNoTracking()
            .Where(candidate => candidate.RequestId == requestId)
            .Select(candidate => new { candidate.RequestDigestSha256, candidate.RequestedByClientId })
            .SingleOrDefaultAsync(cancellationToken);
        if (receipt != null && (receipt.RequestDigestSha256 != bodyDigest
            || receipt.RequestedByClientId != clientId))
            throw Conflict("recovery_conflict");
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
            || nonce.HardwareIdHash != Sha256(canary.HardwareId)
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

    /// <summary>
    /// Resolves an exact Prepare request replay only while its locked enrollment remains a live,
    /// unconsumed pending challenge with valid cryptographic and current commercial authority.
    /// </summary>
    /// <param name="db">Context owning the authority lease transaction.</param>
    /// <param name="clientId">Authenticated S2S client namespace recorded by the original request.</param>
    /// <param name="requestId">Canonical idempotency identifier.</param>
    /// <param name="bodyDigest">Lowercase digest of the exact replay body.</param>
    /// <param name="request">Normalized Prepare command, including only its response-boundary compatibility flag.</param>
    /// <param name="cancellationToken">Cancels the database reads and barrier wait.</param>
    /// <returns>The verified frozen response, or <see langword="null"/> when no request exists.</returns>
    /// <exception cref="RuntimeEnrollmentException">
    /// Thrown for digest conflict, superseded challenge, identity or commercial refusal, or
    /// unavailable database authority; no frozen bytes are returned on these paths.
    /// </exception>
    private async Task<StoredResponse<RuntimeEnrollmentPrepareResponse>?> FindPrepareReplayAsync(
        LicenseDbContext db,
        string clientId,
        string requestId,
        string bodyDigest,
        PrepareCommand request,
        CancellationToken cancellationToken)
    {
        var operation = await db.RuntimeEnrollmentRequests.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ClientId == clientId && candidate.Operation == "prepare" && candidate.RequestId == requestId,
            cancellationToken);
        if (operation == null)
            return null;
        if (operation.PayloadDigestSha256 != bodyDigest)
            throw Conflict("idempotency_conflict");
        var enrollment = await LoadEnrollmentForUpdateAsync(db, operation.EnrollmentId, cancellationToken);
        await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
        var now = await DatabaseNowAsync(db, cancellationToken);
        var approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
            db, enrollment, cancellationToken);
        var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
            db, enrollment, approved.Binaries, now, cancellationToken);
        if (enrollment.State != "PENDING"
            || enrollment.ChallengeConsumedAtUtc != null
            || enrollment.ChallengeExpiresAtUtc <= now.UtcDateTime)
            throw Conflict("prepare_superseded");
        if (!request.IncludesSecurityEpochInBoundaryResponse && enrollment.SecurityEpoch != 1)
            throw PrepareV2Required();
        var stored = OpenResponse<RuntimeEnrollmentPrepareResponse>(
            "prepare-response", operation.Id, 1, operation.ResponseKeyId, operation.ResponseCiphertext,
            PrepareResponseReference(operation));
        var expectedSchema = request.IncludesSecurityEpochInBoundaryResponse ? PrepareV2ResponseSchema : PrepareResponseSchema;
        if (stored.Response.Schema != expectedSchema
            || stored.Response.ProtocolVersion != ProtocolVersion
            || stored.Response.Epoch != enrollment.Epoch
            || (request.IncludesSecurityEpochInBoundaryResponse
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

    /// <summary>
    /// Validates only Prepare's finalized binding provenance. Licence, seat, quota, hardware and
    /// ban policy are deliberately excluded and are read from the assignment ledger after the
    /// deferred item-2 trigger has created the first assignment.
    /// </summary>
    private async Task ValidatePrepareProvenanceAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        string clientId,
        PrepareCommand request,
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
    }

    /// <summary>
    /// Requires the finalized binding's three signed binary digests to match the independently
    /// approved release exactly. This provenance check intentionally excludes licence, seat,
    /// hardware and ban policy, which the assignment-based commercial validator owns separately.
    /// </summary>
    /// <param name="binding">Locked finalized binding copied into the pending enrollment.</param>
    /// <param name="approvedBinaries">A-validated release digest map keyed by canonical component.</param>
    /// <exception cref="RuntimeEnrollmentException">
    /// Thrown as a bounded binding refusal when any component is absent or differs ordinally.
    /// The caller owns rollback of the pending enrollment, request and generated assignment.
    /// </exception>
    private static void ValidatePrepareApprovedBinaries(
        DistributionInstallationBinding binding,
        IReadOnlyDictionary<string, string> approvedBinaries)
    {
        if (!approvedBinaries.TryGetValue("FP_EXE", out var executable)
            || !approvedBinaries.TryGetValue("FP_DLL", out var nativeDll)
            || !approvedBinaries.TryGetValue("FP_CORE", out var core)
            || !string.Equals(binding.ExecutableSha256, executable, StringComparison.Ordinal)
            || !string.Equals(binding.NativeDllSha256, nativeDll, StringComparison.Ordinal)
            || !string.Equals(binding.CoreSha256, core, StringComparison.Ordinal))
            throw Reject("binding_ineligible");
    }

    /// <summary>
    /// Validates WebSetup issue identity and immutable finalized-binding provenance without using
    /// copied licence, seat or hardware fields as a current commercial grant. The returned release
    /// evidence feeds the independent assignment assessment, except for the documented v2 source
    /// compatibility mode whose prospective target policy is checked before graph mutation.
    /// </summary>
    /// <param name="db">Transaction holding the enrollment, binding and commercial barrier locks.</param>
    /// <param name="enrollment">Locked active Runtime credential requesting an MSI transition.</param>
    /// <param name="binding">Locked finalized binding used only as signed historical provenance.</param>
    /// <param name="clientId">Authenticated S2S client expected to own the finalization request.</param>
    /// <param name="cancellationToken">Cancels provider-history reads before any transition is issued.</param>
    /// <returns>Approved release binary evidence for subsequent B assessment.</returns>
    private static async Task<RuntimeEnrollmentIdentityValidator.ApprovedRelease>
        ValidateWebSetupIssueIdentityAsync(
            LicenseDbContext db,
            RuntimeEnrollment enrollment,
            DistributionInstallationBinding binding,
            string clientId,
            CancellationToken cancellationToken)
    {
        var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
            db, enrollment, "ACTIVE", false, null, cancellationToken);
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.InstallationId != enrollment.InstallationId
            || binding.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || binding.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256
            || binding.Version != enrollment.ReleaseVersion)
            throw Reject("websetup_transition_ineligible");
        var owned = await db.DistributionBindingRequests.AsNoTracking().AnyAsync(row =>
            row.BindingId == binding.Id && row.Operation == "finalize_binding" && row.ClientId == clientId,
            cancellationToken);
        if (!owned)
            throw Reject("websetup_transition_ineligible");
        ValidatePrepareApprovedBinaries(binding, approved.Binaries);
        return approved;
    }

    /// <summary>
    /// Validates the active release credential and finalized Distribution binding provenance for
    /// upgrade or rollback. Copied licence, seat and hardware fields never establish commercial
    /// eligibility; the caller checks the signed recovery hardware scope and current assignment
    /// separately under the item-2 barrier. A policy denial cannot invalidate the credential.
    /// </summary>
    /// <param name="db">Transaction holding the enrollment, binding and commercial barrier.</param>
    /// <param name="enrollment">Locked active credential whose source release is being changed or replayed.</param>
    /// <param name="binding">Locked finalized source binding.</param>
    /// <param name="cancellationToken">Cancels approved-release and ownership reads.</param>
    /// <returns>Approved current-release hashes for the separate commercial assessment.</returns>
    private static async Task<RuntimeEnrollmentIdentityValidator.ApprovedRelease>
        ValidateReleaseTransitionIdentityAsync(
            LicenseDbContext db,
            RuntimeEnrollment enrollment,
            DistributionInstallationBinding binding,
            CancellationToken cancellationToken)
    {
        var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
            db, enrollment, "ACTIVE", false, null, cancellationToken);
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.InstallationId != enrollment.InstallationId
            || binding.HandoffDigestSha256 != enrollment.HandoffDigestSha256
            || binding.SubjectRefDigestSha256 != enrollment.SubjectRefDigestSha256
            || binding.Version != enrollment.ReleaseVersion)
            throw Reject("binding_ineligible");
        var owned = await db.DistributionBindingRequests.AsNoTracking().AnyAsync(row =>
            row.BindingId == binding.Id && row.Operation == "finalize_binding"
                && row.ClientId == enrollment.ClientId, cancellationToken);
        if (!owned)
            throw Reject("binding_ineligible");
        ValidatePrepareApprovedBinaries(binding, approved.Binaries);
        return approved;
    }

    /// <summary>
    /// Validates the critical-recovery credential and immutable Distribution source provenance.
    /// An open incident is expected during Recover and checked explicitly by each workflow.
    /// Current licence, seat, assignment and hardware policy are assessed separately under the
    /// caller's shared commercial barrier; copied enrollment commercial fields grant nothing.
    /// </summary>
    /// <param name="db">Recovery transaction holding the enrollment row and commercial barrier.</param>
    /// <param name="enrollment">Locked enrolled credential.</param>
    /// <param name="cancellationToken">Cancels provider-history reads.</param>
    /// <returns>Approved release hashes for the separate commercial assessment.</returns>
    private static async Task<RuntimeEnrollmentIdentityValidator.ApprovedRelease>
        ValidateCriticalRecoveryProvenanceAsync(
            LicenseDbContext db, RuntimeEnrollment enrollment, CancellationToken cancellationToken)
    {
        var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
            db, enrollment, "ACTIVE", false, null, cancellationToken);
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == enrollment.BindingId, cancellationToken)
            ?? throw Reject("binding_ineligible");
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.InstallationId != enrollment.InstallationId
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
        return approved;
    }

    /// <summary>
    /// Validates the migration's immutable Distribution binding provenance before the active
    /// enrollment credential. The binding-first order preserves the existing terminal replay
    /// error contract while licence, seat, assignment and hardware policy remain excluded.
    /// </summary>
    /// <param name="db">Transaction holding the enrollment, binding and commercial barrier.</param>
    /// <param name="enrollment">Locked active credential that signed the migration.</param>
    /// <param name="binding">Locked finalized binding whose historical binaries remain proof.</param>
    /// <param name="cancellationToken">Cancels provenance reads without granting authority.</param>
    /// <returns>Approved release hashes for the separate commercial assessment.</returns>
    private static async Task<RuntimeEnrollmentIdentityValidator.ApprovedRelease>
        ValidateHardwareMigrationIdentityAsync(
            LicenseDbContext db,
            RuntimeEnrollment enrollment,
            DistributionInstallationBinding binding,
            CancellationToken cancellationToken)
    {
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.InstallationId != enrollment.InstallationId
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
        var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
            db, enrollment, "ACTIVE", false, null, cancellationToken);
        ValidatePrepareApprovedBinaries(binding, approved.Binaries);
        return approved;
    }

    /// <summary>
    /// Revalidates the enrollment's server-owned binding lineage and current licensing rows without
    /// treating the retained Runtime HWID compatibility value as identity authority.
    /// </summary>
    /// <param name="db">Context that owns the caller's authority transaction.</param>
    /// <param name="enrollment">Enrollment whose binding, installation, release, and licence scope are checked.</param>
    /// <param name="now">Database time used for current licence and seat eligibility.</param>
    /// <param name="cancellationToken">Cancels database reads before the caller commits.</param>
    /// <param name="migrationCrypto">Server receipt authenticator for a migrated binding; absence fails closed.</param>
    /// <returns>A task that completes only when the current binding and licensing authority are eligible.</returns>
    /// <exception cref="RuntimeEnrollmentException">The binding lineage or licensing authority is absent or ineligible.</exception>
    internal static async Task ValidateEnrollmentAuthorityAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        IRuntimeEnrollmentCryptoService? migrationCrypto = null)
    {
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == enrollment.BindingId, cancellationToken)
            ?? throw Reject("binding_ineligible");
        if (binding.State != "active"
            || binding.ProductId != enrollment.ProductId
            || binding.LicenseId != enrollment.LicenseId
            || binding.LicenseSeatId != enrollment.LicenseSeatId
            || binding.InstallationId != enrollment.InstallationId
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
        await ValidateBindingRowsAsync(db, binding, now, cancellationToken, migrationCrypto: migrationCrypto);
    }

    /// <summary>
    /// Advances one authenticated hardware alias only when Confirm has established the complete
    /// successor Runtime generation. Missing or deliberately disabled aliases remain unchanged;
    /// active ambiguous or cross-boundary evidence fails through Confirm's existing public conflict.
    /// </summary>
    /// <param name="db">The authority-lease context that owns the Confirm transaction.</param>
    /// <param name="enrollment">The proof-verified successor enrollment already marked active in memory.</param>
    /// <param name="cancellationToken">Cancels the operation before the Confirm transaction commits.</param>
    private async Task RepointHardwareAuthorityAliasAfterConfirmAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        CancellationToken cancellationToken)
    {
        var successor = await LoadBindingForUpdateAsync(db, enrollment.BindingId, cancellationToken);
        if (successor.SupersededBindingId is not { } predecessorId)
            return;

        var predecessor = await LoadBindingForUpdateAsync(db, predecessorId, cancellationToken);
        var predecessorEnrollments = db.Database.IsNpgsql()
            ? await db.RuntimeEnrollments.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollments"
                WHERE "BindingId" = {predecessorId}
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.RuntimeEnrollments.Where(candidate => candidate.BindingId == predecessorId)
                .OrderBy(candidate => candidate.Id)
                .ToListAsync(cancellationToken);
        var aliases = db.Database.IsNpgsql()
            ? await db.HardwareAuthorityAliases.FromSqlInterpolated($"""
                SELECT * FROM public."HardwareAuthorityAliases"
                WHERE "BindingId" = {predecessorId}
                   OR "RuntimeEnrollmentId" IN (
                       SELECT "Id" FROM public."RuntimeEnrollments" WHERE "BindingId" = {predecessorId})
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.HardwareAuthorityAliases.Where(candidate =>
                    candidate.BindingId == predecessorId
                    || predecessorEnrollments.Select(source => source.Id)
                        .Contains(candidate.RuntimeEnrollmentId))
                .OrderBy(candidate => candidate.Id)
                .ToListAsync(cancellationToken);
        var activeAliases = aliases.Where(candidate =>
                candidate.IsActive && !candidate.DisabledAtUtc.HasValue)
            .ToList();
        if (activeAliases.Count == 0)
            return;
        var alias = activeAliases.Count == 1 ? activeAliases[0]
            : await SelectAuthenticatedCurrentAliasAsync(db, activeAliases, predecessor,
                predecessorEnrollments, successor, cancellationToken);
        if (alias == null)
        {
            const string ambiguityDiagnosticCode = "confirm_alias_ambiguous";
            LogConfirmAliasRefusal(
                ambiguityDiagnosticCode, predecessor, successor, enrollment, null, null, activeAliases.Count);
            throw ConfirmAliasConflict(ambiguityDiagnosticCode);
        }

        var predecessorEnrollment = predecessorEnrollments.SingleOrDefault(candidate =>
            candidate.Id == alias.RuntimeEnrollmentId);
        var finalizeOwnerRows = await db.DistributionBindingRequests.AsNoTracking()
            .Where(candidate =>
                (candidate.BindingId == predecessor.Id || candidate.BindingId == successor.Id)
                && candidate.Operation == "finalize_binding")
            .Select(candidate => new { candidate.BindingId, candidate.ClientId })
            .Distinct()
            .ToListAsync(cancellationToken);
        var predecessorOwners = finalizeOwnerRows.Where(candidate =>
                candidate.BindingId == predecessor.Id)
            .Select(candidate => candidate.ClientId)
            .ToList();
        var successorOwners = finalizeOwnerRows.Where(candidate =>
                candidate.BindingId == successor.Id)
            .Select(candidate => candidate.ClientId)
            .ToList();
        var diagnosticCode = ConfirmAliasInvariantFailure(
            alias,
            predecessor,
            predecessorEnrollment,
            successor,
            enrollment,
            predecessorOwners,
            successorOwners);
        // Keep the original diagnostic ordering; only a coherent graph reaches the historical digest exception.
        if (diagnosticCode == null && predecessor.HardwareIdHash != successor.HardwareIdHash
            && !await HasAcceptedMigrationLineageAsync(db, alias, predecessor, predecessorEnrollment!,
                successor.HardwareIdHash, cancellationToken))
            diagnosticCode = "confirm_alias_boundary_mismatch";
        if (diagnosticCode != null)
        {
            LogConfirmAliasRefusal(
                diagnosticCode,
                predecessor,
                successor,
                enrollment,
                alias,
                predecessorEnrollment,
                activeAliases.Count);
            throw ConfirmAliasConflict(diagnosticCode);
        }

        alias.BindingId = successor.Id;
        alias.RuntimeEnrollmentId = enrollment.Id;
        alias.SecurityEpoch = enrollment.SecurityEpoch;
        alias.AuthorityEpoch = enrollment.AuthorityEpoch;
    }

    /// <summary>
    /// Returns the first stable server-only diagnostic for an unsafe predecessor alias graph.
    /// The allowlisted order is lineage, authority boundary, predecessor binding terminal state,
    /// predecessor enrollment terminal state, generation continuity, authenticated owner continuity,
    /// then monotonic epochs. This helper is pure: its caller owns the Confirm transaction and must
    /// hold the predecessor, successor, enrollment and candidate-alias row locks for the supplied snapshot.
    /// Retained predecessor and successor enrollment HWID values are excluded from Runtime identity;
    /// binding and canonical alias hardware remain licensing-boundary evidence. A differing predecessor
    /// binding digest is checked by the caller against durable signed-migration receipts before any repoint.
    /// </summary>
    /// <param name="alias">The single active alias selected under the direct predecessor row locks.</param>
    /// <param name="predecessor">The locked binding declared as the successor's direct predecessor.</param>
    /// <param name="predecessorEnrollment">The locked enrollment referenced by the selected alias, or <see langword="null"/> when lineage is missing.</param>
    /// <param name="successor">The locked successor binding being confirmed.</param>
    /// <param name="enrollment">The locked successor enrollment after signed Confirm proof validation.</param>
    /// <param name="predecessorOwners">Distinct authenticated S2S client owners recorded for successful predecessor Finalize requests.</param>
    /// <param name="successorOwners">Distinct authenticated S2S client owners recorded for successful successor Finalize requests.</param>
    /// <returns>The first allowlisted internal diagnostic code, or <see langword="null"/> when every invariant is coherent.</returns>
    private static string? ConfirmAliasInvariantFailure(
        HardwareAuthorityAlias alias,
        DistributionInstallationBinding predecessor,
        RuntimeEnrollment? predecessorEnrollment,
        DistributionInstallationBinding successor,
        RuntimeEnrollment enrollment,
        IReadOnlyList<string> predecessorOwners,
        IReadOnlyList<string> successorOwners)
    {
        if (predecessorEnrollment == null
            || successor.SupersededBindingId != predecessor.Id
            || alias.BindingId != predecessor.Id
            || predecessorEnrollment.BindingId != predecessor.Id)
            return "confirm_alias_lineage_mismatch";
        if (alias.ProductId != successor.ProductId
            || alias.LicenseId != successor.LicenseId
            || alias.LicenseSeatId != successor.LicenseSeatId
            || alias.CanonicalHardwareIdSha256 != successor.HardwareIdHash
            || predecessor.ProductId != successor.ProductId
            || predecessor.LicenseId != successor.LicenseId
            || predecessor.LicenseSeatId != successor.LicenseSeatId
            || predecessorEnrollment.ProductId != successor.ProductId
            || predecessorEnrollment.LicenseId != successor.LicenseId
            || predecessorEnrollment.LicenseSeatId != successor.LicenseSeatId
            || enrollment.BindingId != successor.Id
            || enrollment.ProductId != successor.ProductId
            || enrollment.LicenseId != successor.LicenseId
            || enrollment.LicenseSeatId != successor.LicenseSeatId)
            return "confirm_alias_boundary_mismatch";
        if (successor.State != "active"
            || predecessor.State != "invalidated"
            || predecessor.InvalidationReason != "installation_superseded")
            return "confirm_alias_predecessor_terminal_mismatch";
        if (predecessorEnrollment.State != "INVALIDATED"
            || predecessorEnrollment.InvalidationReason != "binding_superseded")
            return "confirm_alias_enrollment_terminal_mismatch";
        if (predecessor.SubjectRefDigestSha256 != successor.SubjectRefDigestSha256
            || predecessorEnrollment.InstallationId != predecessor.InstallationId
            || predecessorEnrollment.HandoffDigestSha256 != predecessor.HandoffDigestSha256
            || predecessorEnrollment.SubjectRefDigestSha256 != successor.SubjectRefDigestSha256
            || predecessorEnrollment.ReleaseVersion != predecessor.Version
            || enrollment.InstallationId != successor.InstallationId
            || enrollment.HandoffDigestSha256 != successor.HandoffDigestSha256
            || enrollment.SubjectRefDigestSha256 != successor.SubjectRefDigestSha256
            || enrollment.ReleaseVersion != successor.Version)
            return "confirm_alias_generation_mismatch";
        if (predecessorEnrollment.ClientId != enrollment.ClientId
            || predecessorOwners.Count != 1
            || successorOwners.Count != 1
            || predecessorOwners[0] != enrollment.ClientId
            || successorOwners[0] != enrollment.ClientId)
            return "confirm_alias_owner_mismatch";
        if (enrollment.SecurityEpoch != successor.InitialSecurityEpoch
            || enrollment.SecurityEpoch <= predecessorEnrollment.SecurityEpoch
            || enrollment.SecurityEpoch < alias.SecurityEpoch
            || enrollment.AuthorityEpoch < predecessorEnrollment.AuthorityEpoch
            || enrollment.AuthorityEpoch < alias.AuthorityEpoch)
            return "confirm_alias_epoch_mismatch";
        return null;
    }

    /// <summary>
    /// Logs one bounded server-side warning for a refused alias repoint. The event contains only the
    /// allowlisted diagnostic, internal GUIDs, bounded states and reasons, alias count and epochs; it
    /// deliberately excludes raw hardware identifiers, hashes, proof bodies, challenges and key material.
    /// Logging is optional and does not alter the caller-owned Confirm transaction or row locks.
    /// </summary>
    /// <param name="diagnosticCode">Stable allowlisted internal reason selected by invariant evaluation.</param>
    /// <param name="predecessor">Locked direct-predecessor binding whose bounded state is logged.</param>
    /// <param name="successor">Locked successor binding whose bounded state is logged.</param>
    /// <param name="enrollment">Locked successor enrollment whose safe identifier and epochs are logged.</param>
    /// <param name="alias">Selected locked alias, or <see langword="null"/> when ambiguity prevented selection.</param>
    /// <param name="predecessorEnrollment">Selected locked predecessor enrollment, or <see langword="null"/> when absent or ambiguous.</param>
    /// <param name="activeAliasCount">Number of active predecessor-scoped aliases observed under lock.</param>
    private void LogConfirmAliasRefusal(
        string diagnosticCode,
        DistributionInstallationBinding predecessor,
        DistributionInstallationBinding successor,
        RuntimeEnrollment enrollment,
        HardwareAuthorityAlias? alias,
        RuntimeEnrollment? predecessorEnrollment,
        int activeAliasCount) =>
        _historyLogger?.LogWarning(
            "Runtime Confirm alias repoint refused {DiagnosticCode}: predecessor binding {PredecessorBindingId} state {PredecessorBindingState}/{PredecessorBindingReason}, successor binding {SuccessorBindingId} state {SuccessorBindingState}, successor enrollment {SuccessorEnrollmentId}, active predecessor aliases {ActiveAliasCount}, selected alias {AliasId}, predecessor enrollment {PredecessorEnrollmentId} state {PredecessorEnrollmentState}/{PredecessorEnrollmentReason}, epochs alias {AliasSecurityEpoch}/{AliasAuthorityEpoch}, predecessor {PredecessorSecurityEpoch}/{PredecessorAuthorityEpoch}, successor {SuccessorSecurityEpoch}/{SuccessorAuthorityEpoch}.",
            diagnosticCode,
            predecessor.Id,
            predecessor.State,
            predecessor.InvalidationReason ?? "none",
            successor.Id,
            successor.State,
            enrollment.Id,
            activeAliasCount,
            alias?.Id.ToString("D") ?? "none",
            predecessorEnrollment?.Id.ToString("D") ?? "none",
            predecessorEnrollment?.State ?? "none",
            predecessorEnrollment?.InvalidationReason ?? "none",
            alias?.SecurityEpoch ?? -1,
            alias?.AuthorityEpoch ?? -1,
            predecessorEnrollment?.SecurityEpoch ?? -1,
            predecessorEnrollment?.AuthorityEpoch ?? -1,
            enrollment.SecurityEpoch,
            enrollment.AuthorityEpoch);

    /// <summary>
    /// Creates Confirm's stable public conflict while retaining one allowlisted server-only diagnostic.
    /// The client-visible error remains <c>enrollment_conflict</c> with HTTP 409; the diagnostic is kept
    /// separate for trusted server logs and tests and must never contain user-controlled evidence.
    /// </summary>
    /// <param name="diagnosticCode">Stable allowlisted internal reason for the refusal.</param>
    /// <returns>A public 409 enrollment conflict carrying the private diagnostic code separately.</returns>
    private static RuntimeEnrollmentException ConfirmAliasConflict(string diagnosticCode) =>
        new("enrollment_conflict", StatusCodes.Status409Conflict, diagnosticCode);

    /// <summary>
    /// Persists the terminal outcome of a Runtime authority refusal (HTTP 422) for a live
    /// enrollment, then commits the caller's authority lease so the refusal is durable before the
    /// caller rethrows it. A live enrollment becomes <c>INVALIDATED</c> with the refusal reason,
    /// the database instant and the lease authority epoch.
    /// </summary>
    /// <param name="db">The lease-scoped context that loaded <paramref name="enrollment"/> for update.</param>
    /// <param name="lease">The held Runtime authority lease; it is committed on success.</param>
    /// <param name="enrollment">The locked enrollment whose authority was refused.</param>
    /// <param name="refusal">The public refusal plus any bounded server-only terminal reason.</param>
    /// <param name="now">The database clock of the current attempt.</param>
    /// <param name="cancellationToken">Cancels persistence; the lease then rolls back on disposal.</param>
    /// <remarks>
    /// An enrollment that is already terminal keeps its first terminal reason, instant and epoch:
    /// that record is the audit and recovery evidence (for example a portal seat release's
    /// <c>seat_released</c>, which a later reinstallation must be able to prove). Only the lease is
    /// committed in that case; the caller still rethrows the refusal to the client.
    /// </remarks>
    private static async Task CommitInvalidationAsync(
        LicenseDbContext db,
        RuntimeAuthorityLease lease,
        RuntimeEnrollment enrollment,
        RuntimeEnrollmentException refusal,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Callers validate authority before checking enrollment state, so a stale client call on an
        // already terminal credential reaches this point. Overwriting it destroyed the seat_released
        // evidence and permanently blocked the customer's reinstallation (TKT-001198).
        if (enrollment.State is "ACTIVE" or "PENDING")
        {
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = now.UtcDateTime;
            enrollment.InvalidationReason = refusal.DiagnosticCode == "version_ineligible"
                ? "version_ineligible"
                : refusal.ErrorCode;
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
        }
        await db.SaveChangesAsync(cancellationToken);
        await lease.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Requires current commercial and binary rights after authenticating any historical hardware
    /// transition. A version-only refusal remains distinct; the existing transfer-source exception
    /// is explicit and never bypasses receipt, seat, hardware-ban or component checks.
    /// </summary>
    private static async Task ValidateBindingRowsAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        bool allowIneligibleSourceLicense = false,
        IRuntimeEnrollmentCryptoService? migrationCrypto = null)
    {
        var eligibility = await RuntimeBindingEligibilityEvaluator.EvaluateAsync(
            db, binding, now, allowIneligibleSourceLicense, cancellationToken, migrationCrypto);
        if (eligibility == RuntimeBindingEligibility.VersionIneligible)
            throw new RuntimeEnrollmentException(
                "authority_ineligible",
                StatusCodes.Status422UnprocessableEntity,
                "version_ineligible");
        if (eligibility != RuntimeBindingEligibility.Eligible)
            throw Reject("authority_ineligible");
    }

    /// <summary>
    /// Assesses the prospective v2 WebSetup target before any source seat, binding, or enrollment
    /// mutation. A target assignment does not exist until the item-2 deferred trigger observes the
    /// committed graph, so this method evaluates the same current licence, seat, quota, component,
    /// and hardware policy from server-owned target rows without treating copied source fields as a grant.
    /// </summary>
    /// <param name="db">Transaction holding the source enrollment, binding, and exclusive commercial barrier.</param>
    /// <param name="targetLicense">Tracked selected target licence with its current product, type, and seats.</param>
    /// <param name="productId">Product boundary independently authenticated by the request and binding.</param>
    /// <param name="sourceLicenseId">Current source licence excluded from cross-licence hardware checks.</param>
    /// <param name="currentHardwareId">Hardware read from the current server-owned source seat.</param>
    /// <param name="targetVersion">Target release evaluated against the selected licence policy.</param>
    /// <param name="targetApprovedBinaries">Current approved target release hashes used for component policy.</param>
    /// <param name="now">Fresh PostgreSQL clock read after the commercial barrier.</param>
    /// <param name="cancellationToken">Cancels database policy reads before any graph mutation.</param>
    /// <exception cref="RuntimeEnrollmentException">The target commercial authority is not currently eligible.</exception>
    private static async Task ValidateWebSetupTransferTargetCommercialEligibilityAsync(
        LicenseDbContext db,
        License targetLicense,
        Guid productId,
        Guid sourceLicenseId,
        string currentHardwareId,
        string targetVersion,
        IReadOnlyDictionary<string, string> targetApprovedBinaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (targetLicense.ProductId != productId
            || !targetLicense.IsActive
            || targetLicense.RevokedAt is not null
            || targetLicense.ExpirationDate is { } expiry && expiry <= now.UtcDateTime
            || targetLicense.MaxSeats < 1
            || !IsVersionAllowed(targetVersion, targetLicense.AllowedVersions)
            || IsVersionBelow(targetVersion, targetLicense.Product?.MinimumAllowedVersion)
            || string.IsNullOrWhiteSpace(currentHardwareId))
            throw Reject("commercial_authority_ineligible");

        var activeHardwareBan = await db.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == productId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime)
                && ban.HardwareId.ToUpper() == currentHardwareId.ToUpper(), cancellationToken);
        if (activeHardwareBan)
            throw Reject("hardware_banned");

        var componentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
                ban.IsActive && (ban.ProductId == null || ban.ProductId == productId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash })
            .ToListAsync(cancellationToken);
        if (componentBans.Any(ban => targetApprovedBinaries.TryGetValue(ban.ComponentType, out var hash)
            && string.Equals(ApprovedBinaryService.NormalizeSha256(ban.ComponentHash), hash,
                StringComparison.OrdinalIgnoreCase)))
            throw Reject("component_banned");

        var activeSeatCount = targetLicense.Seats.Count(candidate => candidate.IsActive);
        if (activeSeatCount > targetLicense.MaxSeats)
            throw Reject("seat_limit_reached");
        var activeSeat = targetLicense.Seats.SingleOrDefault(candidate =>
            candidate.IsActive && string.Equals(candidate.HardwareId, currentHardwareId, StringComparison.Ordinal));
        if (activeSeat is not null)
            return;
        if (targetLicense.Type?.DisableNewActivations == true)
            throw Reject("new_activations_disabled");
        var conflictingHardware = await db.LicenseSeats.AsNoTracking().AnyAsync(candidate =>
            candidate.IsActive && candidate.HardwareId == currentHardwareId
                && candidate.LicenseId != sourceLicenseId && candidate.LicenseId != targetLicense.Id
                && candidate.License != null && candidate.License.ProductId == productId,
            cancellationToken);
        if (conflictingHardware)
            throw Reject("hardware_already_bound");
        if (targetLicense.Type?.EnforceSingleUsePerHardwareId == true)
        {
            var consumedElsewhere = await db.Licenses.AsNoTracking().AnyAsync(candidate =>
                candidate.ProductId == productId
                    && candidate.LicenseTypeId == targetLicense.LicenseTypeId
                    && candidate.Id != targetLicense.Id && candidate.Id != sourceLicenseId
                    && (candidate.HardwareId == currentHardwareId
                        || candidate.Seats.Any(seat => seat.HardwareId == currentHardwareId)),
                cancellationToken);
            if (consumedElsewhere)
                throw Reject("hardware_already_consumed");
        }
        try
        {
            // Validate replacement quota before the transfer's first source mutation.
            await AutomaticSeatSwitch.PrepareAsync(
                db, targetLicense, currentHardwareId, now.UtcDateTime, cancellationToken);
        }
        catch (DistributionOperationException exception)
        {
            throw new RuntimeEnrollmentException(exception.ErrorCode, exception.StatusCode, exception.ReasonCode);
        }
        if (activeSeatCount >= targetLicense.MaxSeats && targetLicense.MaxSeats != 1)
            throw Reject("seat_limit_reached");
        var maxActivationsPerDay = targetLicense.Type?.MaxActivationsPerDay ?? 0;
        if (maxActivationsPerDay > 0 && targetLicense.MaxSeats != 1)
        {
            var dayStart = now.UtcDateTime.Date;
            var activationsToday = await db.LicenseSeats.AsNoTracking().CountAsync(candidate =>
                candidate.LicenseId == targetLicense.Id && candidate.FirstActivatedAt >= dayStart,
                cancellationToken);
            if (activationsToday >= maxActivationsPerDay)
                throw Reject("activation_rate_limited");
        }
    }

    /// <summary>
    /// Moves the current hardware to the user-selected eligible license while the source binding
    /// remains locked. The caller deactivates the source seat in the same transaction first.
    /// </summary>
    /// <remarks>Preserves all existing predicates and lock assumptions. When supplied, the observation receives the exact daily-count query value before its predicate; no post-refusal reread is allowed. Transport metadata is an immutable server snapshot for history only. The caller owns rollback of pending source/target changes on failure.</remarks>
    private static async Task<LicenseSeat> EnsureRuntimeTransferSeatAsync(
        LicenseDbContext db,
        License targetLicense,
        Guid sourceLicenseId,
        string hardwareId,
        string targetVersion,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        RuntimeTransferHistoryObservation? historyObservation = null,
        AutomaticSeatSwitch.TransportObservation? transport = null)
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
        try
        {
            var automaticSwitch = await AutomaticSeatSwitch.PrepareAsync(
                db, targetLicense, hardwareId, now.UtcDateTime, cancellationToken);
            if (automaticSwitch != null)
            {
                await AutomaticSeatSwitch.CompleteAsync(
                    db, targetLicense, automaticSwitch, hardwareId, clientId, cancellationToken, transport);
                now = new DateTimeOffset(automaticSwitch.Scope.ObservedAtUtc);
                activeSeatCount = targetLicense.Seats.Count(candidate => candidate.IsActive);
            }
        }
        catch (DistributionOperationException exception)
        {
            throw new RuntimeEnrollmentException(exception.ErrorCode, exception.StatusCode, exception.ReasonCode);
        }
        if (activeSeatCount >= targetLicense.MaxSeats)
            throw Reject("seat_limit_reached");
        var maxActivationsPerDay = targetLicense.Type?.MaxActivationsPerDay ?? 0;
        if (maxActivationsPerDay > 0 && targetLicense.MaxSeats != 1)
        {
            var dayStart = now.UtcDateTime.Date;
            var activationsToday = await db.LicenseSeats.AsNoTracking().CountAsync(candidate =>
                candidate.LicenseId == targetLicense.Id && candidate.FirstActivatedAt >= dayStart,
                cancellationToken);
            if (historyObservation != null)
                historyObservation.Snapshot = historyObservation.Snapshot with { ActivationsToday = activationsToday };
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

    private async Task<T> ExecuteWithRetriesAsync<T>(
        Func<Task<T>> action, CancellationToken cancellationToken,
        string exhaustionCode = "authority_unavailable")
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
                        exhaustionCode, StatusCodes.Status503ServiceUnavailable);
                await Task.Delay(Random.Shared.Next(20, 80) * (attempt + 1), cancellationToken);
            }
        }
        throw new RuntimeEnrollmentException(exhaustionCode, StatusCodes.Status503ServiceUnavailable);
    }

    private static bool IsRetryable(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
            if (current is PostgresException postgres)
            {
                if (postgres.SqlState is "40001" or "40P01" or "55P03") return true;
                if (postgres.SqlState == PostgresErrorCodes.UniqueViolation
                    && postgres.ConstraintName is "PK_REAuthorityLineages"
                        or "UX_REAuthorityLineages_Provider_ProductId_GrantRef_SeatId"
                        or "PK_REAuthorityGenerations"
                        or "AK_REAuthorityGenerations_LineageId_GenerationId"
                        or "AK_REAuthorityGenerations_LineageId_GenerationId_Sequence"
                        or "AK_REAuthorityGenerations_GenerationId_RequestId"
                        or "AK_REAuthorityGenerations_LineageId_GenerationId_RequestId"
                        or "UX_REAuthorityGenerations_LineageId_Sequence"
                        or "UX_REAuthorityGenerations_LineageId_PredecessorId"
                        or "UX_REAuthorityRequests_RequestId_LineageId_GenerationId"
                        or "PK_REAuthorityRequests"
                        or "PK_REAuthorityAttempts") return true;
            }
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

    /// <summary>
    /// Validates either temporarily supported Prepare boundary shape and normalizes it into the
    /// single current internal command used by the enrollment engine.
    /// </summary>
    /// <param name="request">Strict boundary request whose opaque identifiers retain ordinal semantics.</param>
    /// <param name="digest">Lowercase hexadecimal digest of the exact boundary bytes.</param>
    /// <returns>The normalized command plus the response-only boundary compatibility flag.</returns>
    /// <exception cref="RuntimeEnrollmentException">Thrown with <c>invalid_request</c> for any non-canonical field or unsupported shape.</exception>
    private static PrepareCommand ValidatePrepare(
        RuntimeEnrollmentPrepareRequest request,
        string digest)
    {
        var exposesSecurityEpoch = request.Schema == PrepareV2Schema;
        if (!LowerSha256Pattern.IsMatch(digest)
            || request.ExtensionData is { Count: > 0 }
            || request.Schema is not (PrepareSchema or PrepareV2Schema)
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out _)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.InstallationId, out _)
            || !LowerSha256Pattern.IsMatch(request.HandoffDigestSha256 ?? string.Empty)
            || !SemanticVersion.TryParse(request.ReleaseVersion ?? string.Empty, out _)
            || request.Epoch != 1 || request.Key == null || request.Key.ExtensionData is { Count: > 0 })
            throw Invalid();
        return new PrepareCommand(request.RequestId!, productId, bindingId, request.HandoffDigestSha256!,
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

    /// <summary>
    /// Validates the deployed release relay and normalizes its signed authorization into the one
    /// internal upgrade/rollback command without using historical HWID evidence as current authority.
    /// </summary>
    /// <param name="request">The strict v1 relay containing canonical base64url authorization bytes.</param>
    /// <param name="exactRelayDigest">Lowercase SHA-256 digest of the exact relay body.</param>
    /// <param name="transition">The fixed upgrade or rollback operation contract selected by the route.</param>
    /// <returns>A canonical command whose authorization digest binds the complete signed boundary evidence.</returns>
    /// <exception cref="RuntimeEnrollmentException">Thrown with <c>invalid_request</c> for any malformed or non-canonical boundary value.</exception>
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
                authorization.TargetInstallerFilename, authorization.TargetInstallerSha256!,
                authorization.RecoveryReceiptId!, authorization.RecoveryReceiptDigestSha256!,
                authorization.Binaries, Convert.ToHexStringLower(SHA256.HashData(authorizationBytes)), proof);
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

    private static ReinstallSourceResolutionValidated ValidateReinstallSourceResolution(
        RuntimeReinstallSourceResolutionRequest request)
    {
        var isV2 = request.Schema == ReinstallSourceResolutionV2Schema;
        if (request.ExtensionData is { Count: > 0 }
            || (!isV2 && request.Schema != ReinstallSourceResolutionSchema)
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BootstrapId, out var bootstrapId)
            || !TryUuid(request.InstallationId, out var installationId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId)
            || !TryUuid(request.AttemptId, out var attemptId)
            || request.ReleaseVersion is not { Length: >= 1 and <= 64 }
            || !ReleaseVersionPattern.IsMatch(request.ReleaseVersion)
            || !Base64Url43Pattern.IsMatch(request.KeyThumbprint ?? string.Empty)
            || request.SecurityEpoch is null or < 1
            || request.AuthoritySchema != ReinstallDiscoveryAuthoritySchema
            || !IsCanonicalReinstallChallenge(request.Challenge)
            || !SignaturePattern.IsMatch(request.Signature ?? string.Empty))
            throw Invalid();
        return new ReinstallSourceResolutionValidated(
            requestId, productId, bootstrapId, installationId.ToString("D"), enrollmentId,
            request.ReleaseVersion, request.KeyThumbprint!, request.SecurityEpoch.Value,
            attemptId, request.AuthoritySchema, request.Challenge!, request.Signature!, isV2);
    }

    private void VerifyReinstallDiscoveryProof(
        RuntimeEnrollment enrollment,
        ReinstallSourceResolutionValidated request)
    {
        byte[] spki = [];
        byte[]? signature = null;
        try
        {
            spki = _crypto.Open(
                "enrollment-spki", enrollment.Id, enrollment.Epoch,
                enrollment.PublicKeySpkiKeyId, enrollment.PublicKeySpkiCiphertext,
                EnrollmentFieldReference(enrollment.Id, "PublicKeySpkiCiphertext"));
            signature = DecodeBase64Url(request.Signature);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
            if (consumed != spki.Length || rsa.KeySize != 3072
                || !rsa.VerifyData(
                    Encoding.UTF8.GetBytes(BuildReinstallDiscoveryProofPayload(request)),
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
    }

    private static string BuildReinstallDiscoveryProofPayload(ReinstallSourceResolutionValidated request) =>
        string.Join('\n',
            "distribution-reinstall-discovery-proof-v1",
            request.BootstrapId.ToString("D"),
            request.RequestId.ToString("D"),
            request.InstallationId,
            request.EnrollmentId.ToString("D"),
            request.ReleaseVersion,
            request.KeyThumbprint,
            request.SecurityEpoch.ToString(CultureInfo.InvariantCulture),
            request.AttemptId.ToString("D"),
            request.AuthoritySchema,
            request.Challenge);

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
    /// <remarks>
    /// TKT-001277 lot 5: only the SDK 2.0 contract is accepted. The source identifier is the one bound in the
    /// client's current licence file (<see cref="HardwareMigrationSourceAlgorithm"/>), the target is derived from
    /// <c>SystemUuid</c> (<see cref="HardwareMigrationTargetAlgorithm"/>). A refused UUID, or a target that is not
    /// the identifier derived from it, is refused as <c>device_refused</c> before any database access.
    /// </remarks>
    /// <exception cref="RuntimeEnrollmentException">
    /// <c>invalid_request</c> for a malformed contract, <c>device_refused</c> for a refused machine identity.
    /// </exception>
    private static HardwareAuthorityMigrationValidated ValidateHardwareAuthorityMigration(
        Guid routeEnrollmentId,
        RuntimeHardwareAuthorityMigrationRequest request,
        RuntimeProofHeaders proof,
        string bodyDigest)
    {
        if (!SemanticVersion.TryParse(request.SdkVersion ?? string.Empty, out var sdkVersion)
            || !SemanticVersion.TryParse("2.0.0", out var minimumSdkVersion)
            || request.ExtensionData is { Count: > 0 }
            || request.Schema != HardwareAuthorityMigrationSchema
            || request.ProtocolVersion != ProtocolVersion
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId) || enrollmentId != routeEnrollmentId
            || request.Epoch != 1
            || request.SecurityEpoch is null or < 1 or int.MaxValue
            || !HardwareIdPattern.IsMatch(request.LegacyHardwareId ?? string.Empty)
            || !HardwareIdPattern.IsMatch(request.HardwareIdV2 ?? string.Empty)
            || request.LegacyAlgorithm != HardwareMigrationSourceAlgorithm
            || request.HardwareIdV2Algorithm != HardwareMigrationTargetAlgorithm
            || sdkVersion.CompareTo(minimumSdkVersion) < 0
            || !LowerSha256Pattern.IsMatch(bodyDigest))
            throw Invalid();
        var identity = request.SystemUuid is { Length: > MachineIdentityObservationService.MaxSystemUuidLength }
            ? null
            : MachineIdentity.FromUuid(request.SystemUuid);
        if (identity is null || !identity.IsAccepted
            || !string.Equals(identity.HardwareId, request.HardwareIdV2, StringComparison.Ordinal))
            throw Reject("device_refused");
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

    /// <summary>
    /// Composes capability-specific installation and release claims with the independent credential
    /// validator. A copied binding or hardware identifier cannot establish key ownership.
    /// </summary>
    private static Task<RuntimeEnrollmentIdentityValidator.ApprovedRelease> ValidateCapabilityIdentityAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        CapabilityValidated capability,
        CancellationToken cancellationToken)
    {
        if (capability.IsLegacy)
        {
            if (!string.Equals(enrollment.ReleaseVersion, LegacyCapabilityReleaseVersion, StringComparison.Ordinal))
                throw Conflict("capability_binding_mismatch");
            return RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "ACTIVE", true, null, cancellationToken);
        }

        if (!string.Equals(capability.InstallationId, enrollment.InstallationId, StringComparison.Ordinal)
            || !string.Equals(capability.ReleaseVersion, enrollment.ReleaseVersion, StringComparison.Ordinal))
            throw Conflict("capability_binding_mismatch");

        var presented = capability.Binaries!.ToDictionary(
            binary => binary.Key!, binary => binary.Sha256!, StringComparer.Ordinal);
        return RuntimeEnrollmentIdentityValidator.ValidateAsync(
            db, enrollment, "ACTIVE", true, presented, cancellationToken);
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
            throw AuthenticationFailed(ProofClockSkewDiagnosticCode);
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

    /// <summary>Applies the canonical Runtime semantic-version allow-mask contract.</summary>
    internal static bool IsVersionAllowed(string version, string? allowedMask)
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

    /// <summary>Returns whether a Runtime version is malformed or lower than the configured minimum.</summary>
    internal static bool IsVersionBelow(string current, string? minimum)
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

    /// <summary>Recognizes only persisted Distribution entitlement contracts with relational authority.</summary>
    private static bool IsModernEntitlementContractVersion(int contractVersion) => contractVersion is 3 or 4;

    /// <summary>Requires the persisted grant owner source to identify the exact modern entitlement contract.</summary>
    private static bool IsMatchingModernIssueSource(int contractVersion, string source) =>
        (contractVersion == 3 && string.Equals(source, "issue_v3", StringComparison.Ordinal))
        || (contractVersion == 4 && string.Equals(source, "issue_v4", StringComparison.Ordinal));

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

    /// <summary>
    /// Matches the immutable reservation to its installation and request. The caller must
    /// separately validate current authority under its lease: an issuance epoch is a global
    /// historical watermark, not proof that this installation's rights remain unchanged.
    /// </summary>
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
        && transition.AuthorityEpoch <= authorityEpoch;

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
    private static RuntimeEnrollmentException AuthenticationFailed(string diagnosticCode) =>
        new("authentication_failed", StatusCodes.Status401Unauthorized, diagnosticCode);
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

    /// <summary>Recognizes PostgreSQL unique violations without converting other database failures.</summary>
    private static bool IsUniqueViolation(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
            if (current is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
                return true;
        return false;
    }

    /// <summary>Represents the one normalized Prepare command consumed by the enrollment engine.</summary>
    /// <param name="RequestId">Canonical external idempotency identifier.</param>
    /// <param name="ProductId">Canonical product UUID selected by the request.</param>
    /// <param name="BindingId">Canonical finalized-binding UUID selected by the request.</param>
    /// <param name="HandoffDigest">Exact lowercase hexadecimal handoff digest.</param>
    /// <param name="InstallationId">Exact opaque installation identifier.</param>
    /// <param name="ReleaseVersion">Canonical semantic release version.</param>
    /// <param name="IncludesSecurityEpochInBoundaryResponse">Whether the temporary external response shape includes the security epoch.</param>
    private sealed record PrepareCommand(
        string RequestId, Guid ProductId, Guid BindingId, string HandoffDigest,
        string InstallationId, string ReleaseVersion, bool IncludesSecurityEpochInBoundaryResponse);
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
    private sealed record ReinstallSourceResolutionValidated(
        Guid RequestId,
        Guid ProductId,
        Guid BootstrapId,
        string InstallationId,
        Guid EnrollmentId,
        string ReleaseVersion,
        string KeyThumbprint,
        int SecurityEpoch,
        Guid AttemptId,
        string AuthoritySchema,
        string Challenge,
        string Signature,
        bool IsV2);
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
    /// <summary>
    /// Canonical validated release transition normalized from the deployed v1 boundary. The authorization
    /// digest binds RecoveryHardwareIdHash as immutable signed evidence without carrying it into authority.
    /// </summary>
    private sealed record UpgradeValidated(
        string RequestId, Guid ProductId, Guid EnrollmentId, string InstallationId,
        int SecurityEpoch, string SourceVersion, string TargetVersion,
        string TargetInstallerFilename, string TargetInstallerSha256,
        string RecoveryReceiptId, string RecoveryReceiptDigestSha256,
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
    /// <summary>
    /// Defines the canonical deployed upgrade or rollback boundary and its stable error semantics.
    /// </summary>
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
        /// <summary>Canonical upgrade boundary normalized into the shared release transaction.</summary>
        public static readonly ReleaseTransition Upgrade = new(
            "upgrade", UpgradeRelaySchema, UpgradeAuthorizationSchema, UpgradeResponseSchema,
            UpgradeAudience, UpgradeUse, "upgraded", "upgrade-response",
            "upgrade_binding_conflict", "upgrade_conflict", "upgrade_receipt_reused", false);

        /// <summary>Canonical rollback boundary normalized into the shared release transaction.</summary>
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

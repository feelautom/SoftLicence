using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public interface IDistributionInstallationBindingService
{
    /// <summary>Resolves the unique Runtime-owned source licence without mutating its authority graph.</summary>
    /// <param name="clientId">Exact authenticated Distribution S2S client identifier.</param>
    /// <param name="request">Exact product, target licence, and opaque hardware boundary.</param>
    /// <param name="cancellationToken">Cancels the read-only authority lookup.</param>
    /// <returns>A bounded none, legacy-source, or modern-source decision.</returns>
    Task<DistributionRuntimeSourceResolutionResponse> ResolveRuntimeSourceAsync(
        string clientId,
        DistributionRuntimeSourceResolutionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Issues or exactly replays a versioned Distribution entitlement for an authenticated client.</summary>
    /// <param name="clientId">Exact authenticated S2S client identifier.</param>
    /// <param name="exactPayloadDigest">Lowercase SHA-256 of the exact request body.</param>
    /// <param name="request">Closed issue request whose schema selects legacy or generation-bound behavior.</param>
    /// <param name="cancellationToken">Cancels database locking or persistence before commit.</param>
    /// <returns>The frozen response and whether it came from exact replay storage.</returns>
    Task<DistributionOperationResult<DistributionEntitlementIssueResponse>> IssueEntitlementAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionEntitlementIssueRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Finalizes or exactly replays authenticated installation authority using the existing ordered locks and licensing predicates.</summary>
    /// <remarks>Decisions captured after the licence lock share the business commit, or survive business rollback through an outer-transaction savepoint. Earlier unestablished identities are not attributed. A history persistence failure remains the existing technical error, never an asserted durable refusal.</remarks>
    /// <param name="clientId">Exact authenticated S2S client namespace.</param>
    /// <param name="exactPayloadDigest">Lowercase SHA-256 of the exact authenticated request.</param>
    /// <param name="request">Closed versioned finalization evidence; no telemetry-derived authority.</param>
    /// <param name="cancellationToken">Cancels work before a decision; a captured refusal has bounded shutdown-aware persistence independent of request cancellation.</param>
    /// <returns>Original binding response and existing replay indicator after a confirmed commit.</returns>
    Task<DistributionOperationResult<DistributionInstallationBindingResponse>> FinalizeAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionInstallationFinalizeRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates the exact authenticated installation authority and replays an identical request from
    /// frozen storage. The closed <c>seat_released</c> reason additionally deactivates only the binding's
    /// exact commercial seat and terminalizes its live enrollments in the same transaction; security
    /// invalidation reasons never release seat capacity.
    /// </summary>
    /// <param name="clientId">Exact authenticated S2S client that must own the finalized binding.</param>
    /// <param name="exactPayloadDigest">Lowercase SHA-256 of the exact request body, used to distinguish exact replay from divergence.</param>
    /// <param name="request">Closed v1 invalidation request containing exact product, binding, grant digest, reason, time, and epoch values.</param>
    /// <param name="cancellationToken">Cancels validation, locking, or persistence before the atomic commit completes.</param>
    /// <returns>The committed frozen response and whether it was recovered from exact replay storage.</returns>
    /// <exception cref="DistributionOperationException">
    /// The request is malformed, not owned, too far in the future, divergent, relationally inconsistent, or conflicts with a prior invalidation.
    /// </exception>
    Task<DistributionOperationResult<DistributionInstallationInvalidationResponse>> InvalidateAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionInstallationInvalidationRequest request,
        CancellationToken cancellationToken = default);

    Task<DistributionInstallationBindingResponse> RevalidateForCapabilityAsync(
        Guid bindingId,
        CancellationToken cancellationToken = default);
}

public sealed class DistributionOperationException(
    string errorCode,
    int statusCode,
    string? reasonCode = null,
    HardwareAuthorityRefusalEvent? hardwareAuthorityRefusal = null)
    : Exception(errorCode)
{
    public string ErrorCode { get; } = errorCode;
    public int StatusCode { get; } = statusCode;
    public string? ReasonCode { get; } = reasonCode;
    public HardwareAuthorityRefusalEvent? HardwareAuthorityRefusal { get; } = hardwareAuthorityRefusal;
}

public sealed partial class DistributionInstallationBindingService : IDistributionInstallationBindingService
{
    public const string IssueSchema = "distribution-entitlement-issue-v1";
    public const string IssueV2Schema = "distribution-entitlement-issue-v2";
    public const string IssueV3Schema = "distribution-entitlement-issue-v3";
    /// <summary>Requires an exact provider-issued Runtime Enrollment generation.</summary>
    public const string IssueV4Schema = "distribution-entitlement-issue-v4";
    public const string IssueResponseSchema = "distribution-entitlement-v1";
    /// <summary>Returns the provider-issued generation only for issue contract v4.</summary>
    public const string IssueV2ResponseSchema = "distribution-entitlement-v2";
    public const string FinalizeSchema = "distribution-installation-finalize-v1";
    public const string FinalizeV2Schema = "distribution-installation-finalize-v2";
    public const string FinalizeV3Schema = "distribution-installation-finalize-v3";
    public const string FinalizeV4Schema = "distribution-installation-finalize-v4";
    public const string FinalizeV5Schema = "distribution-installation-finalize-v5";
    public const string LicenseReplacementSchema = "distribution-license-replacement-v1";
    public const string LicenseReplacementCandidatesSchema = "distribution-license-replacement-candidates-v1";
    public const string LegacyLicenseReplacementSchema = "distribution-legacy-license-replacement-v1";
    public const string BindingResponseSchema = "distribution-installation-binding-v1";
    /// <summary>Exact request schema for Runtime-owned source resolution.</summary>
    public const string RuntimeSourceResolutionSchema = "distribution-runtime-source-resolution-v1";

    /// <summary>Exact bounded response schema for Runtime-owned source resolution.</summary>
    public const string RuntimeSourceResolutionResponseSchema = "distribution-runtime-source-resolution-result-v1";
    public const string InvalidationSchema = "distribution-installation-invalidation-v1";
    public const string InvalidationResponseSchema = "distribution-installation-invalidation-result-v1";
    private const string IssueOperation = "issue_entitlement";
    private const string IssueV2Operation = "issue_entitlement_v2";
    private const string IssueV3Operation = "issue_entitlement_v3";
    private const string IssueV4Operation = "issue_entitlement_v4";
    private const string FinalizeOperation = "finalize_binding";
    private const string InvalidateOperation = "invalidate_binding";
    internal const string EntitlementPurpose = "SoftLicence.DistributionEntitlement.v1";
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";
    private const int MaximumLicenseReplacementCandidates = 16;

    private static readonly string[] RequiredBinaryKeys = ["FP_EXE", "FP_DLL", "FP_CORE"];
    private static readonly HashSet<string> RequiredBinaryKeySet = new(RequiredBinaryKeys, StringComparer.Ordinal);
    /// <summary>
    /// Defines the exact, ordinal S2S invalidation vocabulary. Only <c>seat_released</c> carries
    /// commercial seat-release semantics; the security reasons invalidate authority without freeing capacity.
    /// </summary>
    private static readonly HashSet<string> InvalidationReasons = new(
        ["account_closed", "fraud_flagged", "grant_revoked", "security_lockdown", "seat_released"],
        StringComparer.Ordinal);
    private static readonly Regex LowerUuidPattern = new(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex HardwareIdPattern = new(
        "^[A-Z0-9][A-Z0-9:_-]{4,199}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IDataProtector _entitlementProtector;
    private readonly TimeProvider _timeProvider;
    private readonly IHardwareAuthorityAliasResolver _hardwareAuthorityAliases;
    private readonly ILogger<DistributionInstallationBindingService> _logger;
    /// <summary>Stops bounded refusal finalization during application shutdown; request cancellation is a separate boundary.</summary>
    private readonly CancellationToken _applicationStopping;
    /// <summary>Supplies observation-only request transport metadata; non-HTTP callers may omit it.</summary>
    private readonly IHttpContextAccessor? _httpContextAccessor;

    /// <summary>
    /// Creates the production distribution binding service with authenticated hardware authority resolution.
    /// </summary>
    /// <param name="dbFactory">Creates isolated database contexts for transactional distribution operations.</param>
    /// <param name="dataProtectionProvider">Protects and authenticates short-lived entitlement references.</param>
    /// <param name="timeProvider">Supplies the request time used by eligibility and handoff checks.</param>
    /// <param name="hardwareAuthorityAliases">Resolves only server-owned aliases created by authenticated Runtime migrations.</param>
    /// <param name="logger">Writes the bounded provider event before the HTTP response is attempted.</param>
    /// <param name="applicationLifetime">Production host shutdown signal; isolated tests may omit the host.</param>
    /// <param name="httpContextAccessor">Optional server request metadata for observation-only S2S seat-change history.</param>
    public DistributionInstallationBindingService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider,
        IHardwareAuthorityAliasResolver hardwareAuthorityAliases,
        ILogger<DistributionInstallationBindingService>? logger = null,
        IHostApplicationLifetime? applicationLifetime = null,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _dbFactory = dbFactory;
        _httpContextAccessor = httpContextAccessor;
        _entitlementProtector = dataProtectionProvider.CreateProtector(EntitlementPurpose);
        _timeProvider = timeProvider;
        _hardwareAuthorityAliases = hardwareAuthorityAliases;
        _logger = logger ?? NullLogger<DistributionInstallationBindingService>.Instance;
        _applicationStopping = applicationLifetime?.ApplicationStopping ?? CancellationToken.None;
    }

    /// <summary>
    /// Resolves one exact Runtime binding to a different source licence and classifies its proof generation.
    /// </summary>
    /// <remarks>
    /// A coherent binding already owned by the target licence is not a replacement source and returns none.
    /// Finalize remains the mutation authority and repeats the complete binding, seat, enrollment, incident,
    /// entitlement, and ownership validation under locks before allowing same-authority recovery.
    /// Hardware strings remain exact and opaque; only their lowercase SHA-256 digest is compared in storage.
    /// </remarks>
    /// <param name="clientId">Exact authenticated Distribution S2S client identifier.</param>
    /// <param name="request">Exact source-resolution request.</param>
    /// <param name="cancellationToken">Cancels the read-only authority lookup.</param>
    /// <returns>A bounded none, legacy-source, or modern-source decision.</returns>
    /// <exception cref="DistributionOperationException">Thrown when the request or authority graph fails closed.</exception>
    public async Task<DistributionRuntimeSourceResolutionResponse> ResolveRuntimeSourceAsync(
        string clientId,
        DistributionRuntimeSourceResolutionRequest request,
        CancellationToken cancellationToken = default)
    {
        var validated = ValidateRuntimeSourceResolutionRequest(request);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var authority = await _hardwareAuthorityAliases.ResolveAsync(
            db,
            validated.ProductId,
            validated.TargetLicenseId,
            validated.HardwareId,
            HardwareAuthorityResolutionIntent.Finalize,
            cancellationToken);
        var requiresAliasSeatReconciliation = authority.Refused
            && authority.RefusalReason == HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired;
        if (authority.Refused && !requiresAliasSeatReconciliation)
            throw Conflict("binding_conflict", "replacement_source_authority_mismatch");

        var now = _timeProvider.GetUtcNow();
        var targetLicense = await db.Licenses.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.Id == validated.TargetLicenseId && candidate.ProductId == validated.ProductId,
            cancellationToken);
        if (!IsEligibleLicense(targetLicense, now))
            throw Reject("entitlement_ineligible");

        if (requiresAliasSeatReconciliation)
        {
            if (authority.BindingId == null || authority.LicenseSeatId == null)
            {
                throw Conflict(
                    "binding_conflict",
                    HardwareAuthorityRefusalDiagnostics.AliasReconciliationIdentityMissing);
            }
            return new(RuntimeSourceResolutionResponseSchema, "none", null, null);
        }

        var hardwareIdHash = Sha256(authority.EffectiveHardwareId);
        var bindings = await db.DistributionInstallationBindings.AsNoTracking()
            .Where(candidate => candidate.ProductId == validated.ProductId
                && candidate.HardwareIdHash == hardwareIdHash
                && candidate.State == "active"
                && candidate.InvalidatedAtUtc == null
                && candidate.InvalidationReason == null)
            .OrderBy(candidate => candidate.Id)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (bindings.Count == 0)
            return new(RuntimeSourceResolutionResponseSchema, "none", null, null);
        if (bindings.Count != 1)
            throw Conflict("binding_conflict", "replacement_hardware_ambiguous");

        var source = bindings[0];
        if (!string.Equals(source.HardwareIdHash, hardwareIdHash, StringComparison.Ordinal)
            || !string.Equals(source.GrantRefDigestSha256, Sha256(source.GrantRef), StringComparison.Ordinal))
        {
            throw Conflict("binding_conflict", "replacement_source_authority_mismatch");
        }

        if (source.LicenseId == validated.TargetLicenseId)
            return new(RuntimeSourceResolutionResponseSchema, "none", null, null);

        var sourceLicense = await db.Licenses.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.Id == source.LicenseId && candidate.ProductId == source.ProductId,
            cancellationToken);
        if (sourceLicense == null || !IsReplacementSourceIneligible(sourceLicense, now))
            throw Conflict("binding_conflict", "replacement_source_authority_mismatch");

        var finalizeOwners = await db.DistributionBindingRequests.AsNoTracking()
            .Where(candidate => candidate.BindingId == source.Id && candidate.Operation == FinalizeOperation)
            .Select(candidate => candidate.ClientId)
            .Distinct()
            .ToListAsync(cancellationToken);
        if (finalizeOwners.Count != 1 || !string.Equals(finalizeOwners[0], clientId, StringComparison.Ordinal))
            throw Conflict("binding_conflict", "cross_generation_finalize_owner_mismatch");

        var previousEntitlements = await db.DistributionEntitlements.AsNoTracking()
            .Where(candidate => candidate.Id == source.EntitlementId
                || (candidate.ProductId == source.ProductId
                    && candidate.GrantRefDigestSha256 == source.GrantRefDigestSha256))
            .ToListAsync(cancellationToken);
        var previousGrantOwners = await db.DistributionGrantOwnerships.AsNoTracking()
            .Where(candidate => candidate.ProductId == source.ProductId
                && candidate.GrantRefDigestSha256 == source.GrantRefDigestSha256)
            .ToListAsync(cancellationToken);
        var coherentModernAuthority = previousEntitlements.Count == 1
            && previousGrantOwners.Count == 1
            && previousEntitlements[0].Id == source.EntitlementId
            && IsModernEntitlementContractVersion(previousEntitlements[0].ContractVersion)
            && previousEntitlements[0].State == "finalized"
            && previousEntitlements[0].ClientId == clientId
            && previousEntitlements[0].ProductId == source.ProductId
            && previousEntitlements[0].LicenseId == source.LicenseId
            && previousEntitlements[0].GrantRefDigestSha256 == source.GrantRefDigestSha256
            && previousEntitlements[0].SubjectRefDigestSha256 == source.SubjectRefDigestSha256
            && source.SubjectRefDigestSha256 is { Length: 64 }
            && previousGrantOwners[0].ClientId == clientId
            && IsMatchingModernIssueSource(previousEntitlements[0].ContractVersion, previousGrantOwners[0].Source);
        var sourceKind = coherentModernAuthority
            ? "modern"
            : previousEntitlements.Count == 0 && previousGrantOwners.Count == 0
                ? "legacy"
                : throw Conflict("binding_conflict", "replacement_source_authority_mismatch");
        return new(RuntimeSourceResolutionResponseSchema, "source", source.LicenseId.ToString("D"), sourceKind);
    }

    /// <inheritdoc />
    public async Task<DistributionOperationResult<DistributionEntitlementIssueResponse>> IssueEntitlementAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionEntitlementIssueRequest request,
        CancellationToken cancellationToken = default)
    {
        var validated = ValidateIssueRequest(request);
        ValidateDigest(exactPayloadDigest);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var existing = await FindExistingAsync<DistributionEntitlementIssueResponse>(
            db, clientId, validated.RequestId, validated.Operation, exactPayloadDigest, cancellationToken);
        if (existing != null)
            return new(existing, true);

        await using var transaction = validated.GrantRefDigestSha256 == null
            ? await BeginSerializableAsync(db, cancellationToken)
            : await BeginBindingAuthorityTransactionAsync(db, cancellationToken);
        if (validated.GrantRefDigestSha256 != null)
        {
            await AcquireBindingAuthorityLockAsync(
                db, validated.ProductId, validated.GrantRefDigestSha256, cancellationToken);
        }
        existing = await FindExistingAsync<DistributionEntitlementIssueResponse>(
            db, clientId, validated.RequestId, validated.Operation, exactPayloadDigest, cancellationToken);
        if (existing != null)
        {
            if (transaction != null)
                await transaction.RollbackAsync(cancellationToken);
            return new(existing, true);
        }
        AuthorityGenerationProjection? authority = null;
        if (validated.ContractVersion == 4)
        {
            authority = await ValidateAuthorityGenerationProjectionAsync(
                db, validated, cancellationToken);
        }

        var existingGrantOwnership = validated.GrantRefDigestSha256 == null
            ? null
            : await db.DistributionGrantOwnerships.AsNoTracking().SingleOrDefaultAsync(candidate =>
                candidate.ProductId == validated.ProductId
                && candidate.GrantRefDigestSha256 == validated.GrantRefDigestSha256,
                cancellationToken);
        if (existingGrantOwnership != null
            && (validated.ContractVersion != 4
                || !string.Equals(existingGrantOwnership.ClientId, clientId, StringComparison.Ordinal)
                || !IsMatchingIssueSource(validated.ContractVersion, existingGrantOwnership.Source)))
        {
            throw Conflict("grant_ownership_conflict");
        }

        var now = _timeProvider.GetUtcNow();
        var license = await db.Licenses.AsNoTracking()
            .Include(candidate => candidate.Seats)
            .SingleOrDefaultAsync(candidate =>
                candidate.Id == validated.LicenseId && candidate.ProductId == validated.ProductId,
                cancellationToken);
        if (!IsEligibleLicense(license, now))
            throw Reject("entitlement_ineligible");

        var issuedAt = validated.ContractVersion is 3 or 4
            ? ToPostgreSqlTimestampPrecision(now)
            : now;
        var expiresAt = issuedAt.AddHours(2);
        var entitlementId = Guid.NewGuid();
        var subjectRefDigest = validated.SubjectRef == null ? null : Sha256(validated.SubjectRef);
        var tokenPayload = new EntitlementTokenPayload(
            validated.ContractVersion == 4 ? IssueV2ResponseSchema : IssueResponseSchema,
            entitlementId.ToString("D"),
            clientId,
            validated.LicenseId.ToString("D"),
            validated.ProductId.ToString("D"),
            FormatUtc(issuedAt),
            FormatUtc(expiresAt),
            validated.GrantRefDigestSha256,
            subjectRefDigest,
            validated.ContractVersion,
            authority?.AuthorityLineageId.ToString("D"),
            authority?.AuthorityGenerationId.ToString("D"),
            authority?.ArtifactSetDigestSha256);
        var entitlementRef = _entitlementProtector.Protect(JsonSerializer.Serialize(tokenPayload, JsonOptions));
        var response = new DistributionEntitlementIssueResponse(
            validated.ContractVersion == 4 ? IssueV2ResponseSchema : IssueResponseSchema,
            entitlementRef,
            FormatUtc(expiresAt),
            authority?.AuthorityGenerationId.ToString("D"));

        db.DistributionBindingRequests.Add(new DistributionBindingRequest
        {
            ClientId = clientId,
            RequestId = validated.RequestId,
            Operation = validated.Operation,
            PayloadDigest = exactPayloadDigest,
            ResponseJson = JsonSerializer.Serialize(response, JsonOptions),
            CreatedAtUtc = issuedAt.UtcDateTime
        });
        if (validated.ContractVersion is 3 or 4)
        {
            db.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = entitlementId,
                ClientId = clientId,
                ProductId = validated.ProductId,
                LicenseId = validated.LicenseId,
                GrantRefDigestSha256 = validated.GrantRefDigestSha256!,
                SubjectRefDigestSha256 = subjectRefDigest!,
                AuthorityLineageId = authority?.AuthorityLineageId,
                AuthorityGenerationId = authority?.AuthorityGenerationId,
                ArtifactSetDigestSha256 = authority?.ArtifactSetDigestSha256,
                ContractVersion = validated.ContractVersion,
                State = "issued",
                IssuedAtUtc = issuedAt.UtcDateTime,
                ExpiresAtUtc = expiresAt.UtcDateTime
            });
        }
        if (validated.GrantRefDigestSha256 != null && existingGrantOwnership == null)
        {
            db.DistributionGrantOwnerships.Add(new DistributionGrantOwnership
            {
                ProductId = validated.ProductId,
                GrantRefDigestSha256 = validated.GrantRefDigestSha256,
                ClientId = clientId,
                Source = validated.ContractVersion switch
                {
                    4 => "issue_v4",
                    3 => "issue_v3",
                    _ => "issue_v2"
                },
                CreatedAtUtc = issuedAt.UtcDateTime
            });
        }

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new(response, false);
        }
        catch (Exception exception) when (IsRetryableWriteFailure(exception, db))
        {
            await TryRollbackAsync(transaction, cancellationToken);
            return new(
                await ReloadConcurrentAsync<DistributionEntitlementIssueResponse>(
                    clientId, validated.RequestId, validated.Operation, exactPayloadDigest, cancellationToken),
                true);
        }
    }

    /// <summary>
    /// Finalizes a fresh installation binding under the product, grant, installation and Runtime authority locks.
    /// </summary>
    /// <param name="clientId">The exact authorized Distribution S2S client identifier.</param>
    /// <param name="exactPayloadDigest">The canonical SHA-256 digest used for request idempotency.</param>
    /// <param name="request">The validated finalize intent and its bounded authority evidence.</param>
    /// <param name="cancellationToken">Cancels the database operation before commit.</param>
    /// <returns>The committed binding response and whether it came from an exact replay.</returns>
    /// <exception cref="DistributionOperationException">
    /// Thrown when entitlement, ownership, authority, security history or replay evidence fails closed.
    /// </exception>
    /// <remarks>
    /// A terminal business enrollment can seed a new cryptographic generation only when its binding is the
    /// unique exact current authority. Historical cross-license candidates cannot override that server-owned
    /// decision. A legacy identifier resolves to V2 only through a server-authenticated Runtime migration alias,
    /// whose exact binding also outranks unrelated v4 history candidates during bounded seat reconciliation.
    /// Finalize v5 accepts a signed source and target licence pair only as Website's same-owner assertion, then
    /// derives the unique grantless binding, seat, hardware and Runtime authority from locked server rows. Any
    /// modern relational contract-v3 or contract-v4 entitlement authority, or any modern grant ownership
    /// evidence, disables v5 instead of permitting a legacy fallback. See DevBrain DOC-324, DOC-327,
    /// DOC-475 and DOC-493.
    /// </remarks>
    public async Task<DistributionOperationResult<DistributionInstallationBindingResponse>> FinalizeAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionInstallationFinalizeRequest request,
        CancellationToken cancellationToken = default)
    {
        var validated = ValidateFinalizeRequest(request);
        var transport = AutomaticSeatSwitch.CaptureTransport(_httpContextAccessor?.HttpContext);
        ValidateDigest(exactPayloadDigest);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var existing = await FindExistingAsync<DistributionInstallationBindingResponse>(
            db, clientId, validated.RequestId, FinalizeOperation, exactPayloadDigest, cancellationToken);
        if (existing != null)
            return new(existing, true);

        await using var transaction = await BeginBindingAuthorityTransactionAsync(db, cancellationToken);
        var grantRefDigest = Sha256(validated.GrantRef);
        await AcquireBindingAuthorityLockAsync(db, validated.ProductId, grantRefDigest, cancellationToken);
        await AcquireInstallationAuthorityLockAsync(
            db, validated.ProductId, validated.InstallationId, cancellationToken);
        existing = await FindExistingAsync<DistributionInstallationBindingResponse>(
            db, clientId, validated.RequestId, FinalizeOperation, exactPayloadDigest, cancellationToken);
        if (existing != null)
        {
            if (transaction != null)
                await transaction.RollbackAsync(cancellationToken);
            return new(existing, true);
        }

        if (await db.DistributionBindingInvalidations.AsNoTracking().AnyAsync(candidate =>
                candidate.ProductId == validated.ProductId
                && candidate.GrantRefDigestSha256 == grantRefDigest,
                cancellationToken))
        {
            throw Conflict("binding_invalidated");
        }

        var now = _timeProvider.GetUtcNow();
        ValidateHandoffWindow(validated, now);
        var entitlement = await ReadEntitlementAsync(db, validated.EntitlementRef, clientId, validated.ProductId, now, cancellationToken);
        var earlyDecisionSnapshot = await CaptureEarlyFinalizeIdentityAsync(
            db, entitlement, validated.ProductId, cancellationToken);
        var submittedHardwareId = validated.HardwareId;
        HardwareAuthorityResolution authority;
        bool requiresAliasSeatReconciliation;
        try
        {
        if (validated.LegacyLicenseReplacement is { } legacyReplacement
            && (!IsModernEntitlementContractVersion(entitlement.ContractVersion)
                || legacyReplacement.TargetLicenseId != entitlement.LicenseId))
        {
            throw Conflict("binding_conflict", "legacy_replacement_target_mismatch");
        }
        if (entitlement.GrantRefDigestSha256 != null
            && !string.Equals(entitlement.GrantRefDigestSha256, grantRefDigest, StringComparison.Ordinal))
        {
            throw Conflict("grant_ownership_mismatch");
        }
        await EnsureGrantOwnershipForFinalizeAsync(
            db, clientId, validated.ProductId, grantRefDigest,
            entitlement.ContractVersion, entitlement.GrantRefDigestSha256 != null, now, cancellationToken);

        // Every Finalize authority mutation takes the Runtime global lock before either the
        // submitted or canonical hardware lock. Recovery helpers must never acquire it later,
        // because a direct V2 request could otherwise invert the alias path's lock order.
        await AcquireRuntimeMutationLockAsync(db, cancellationToken);
        // Refresh the request clock after the common mutation barrier. The automatic
        // replacement below additionally reads the provider clock before its policy checks.
        if (db.Database.IsNpgsql())
            await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(db, cancellationToken);
        now = _timeProvider.GetUtcNow();
        ValidateHandoffWindow(validated, now);
        entitlement = await ReadEntitlementAsync(
            db, validated.EntitlementRef, clientId, validated.ProductId, now, cancellationToken);
        if (earlyDecisionSnapshot != null)
            earlyDecisionSnapshot = earlyDecisionSnapshot with
            {
                AuthorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                    .Where(row => row.Id == 1).Select(row => (long?)row.Epoch).SingleOrDefaultAsync(cancellationToken)
            };
        if (entitlement.ContractVersion == 4)
        {
            await ValidateAuthorityGenerationForFinalizeAsync(
                db, entitlement, validated, grantRefDigest, cancellationToken);
        }
        await ProductHardwareSeatLockAuthority.AcquireAsync(
            db, validated.ProductId, submittedHardwareId, cancellationToken);
        authority = await _hardwareAuthorityAliases.ResolveAsync(
            db,
            validated.ProductId,
            entitlement.LicenseId,
            submittedHardwareId,
            HardwareAuthorityResolutionIntent.Finalize,
            cancellationToken);
        if (!authority.UsedAlias
            && !authority.Refused
            && _hardwareAuthorityAliases is ICanonicalFinalizeHardwareAuthorityResolver canonicalResolver)
        {
            authority = await canonicalResolver.ResolveFinalizeSourceByCanonicalAsync(
                db,
                validated.ProductId,
                entitlement.LicenseId,
                submittedHardwareId,
                cancellationToken);
        }
        if (authority.Refused
            && authority.RefusalReason != HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired)
        {
            var refusal = HardwareAuthorityRefusalDiagnostics.DescribeAliasRefusal(authority.RefusalReason);
            throw RejectHardwareAuthority(
                validated.RequestId,
                refusal.ReasonCode,
                refusal.Guard,
                new HardwareAuthorityDecisionMatrix(AliasResolutionRefused: true));
        }
        requiresAliasSeatReconciliation = authority.Refused
            && authority.RefusalReason == HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired;
        if ((authority.UsedAlias || requiresAliasSeatReconciliation)
            && (authority.BindingId == null || authority.LicenseSeatId == null))
        {
            throw RejectHardwareAuthority(
                validated.RequestId,
                HardwareAuthorityRefusalDiagnostics.AliasReconciliationIdentityMissing,
                "alias_reconciliation_identity_guard",
                new HardwareAuthorityDecisionMatrix(
                    AliasResolutionRefused: authority.Refused,
                    AliasUsed: authority.UsedAlias,
                    SeatReconciliationRequired: requiresAliasSeatReconciliation,
                    BindingIdentityPresent: authority.BindingId != null,
                    SeatIdentityPresent: authority.LicenseSeatId != null));
        }
        if (!string.Equals(
                authority.EffectiveHardwareId,
                submittedHardwareId,
                StringComparison.Ordinal))
        {
            // Serialize both the submitted compatibility key and its authenticated canonical
            // authority before any seat or quota mutation. No client-supplied pair is consulted.
            await ProductHardwareSeatLockAuthority.AcquireAsync(
                db, validated.ProductId, authority.EffectiveHardwareId, cancellationToken);
        }
        }
        catch (DistributionOperationException refusal) when (earlyDecisionSnapshot != null)
        {
            // This terminal path precedes every business SQL write. It must not reuse the
            // later savepoint or resolve missing facts after observing a refusal.
            await PersistEarlyFinalizeRefusalAsync(db, transaction, earlyDecisionSnapshot,
                clientId, exactPayloadDigest, validated, now, refusal);
            throw;
        }
        // Direct and alias paths now share the same hardware-then-license lock order. Taking
        // the licence lock earlier would deadlock an alias request against a direct V2 request.
        var lockedLicenseIds = validated.LegacyLicenseReplacement == null
            ? [entitlement.LicenseId]
            : new[]
            {
                entitlement.LicenseId,
                validated.LegacyLicenseReplacement.SourceLicenseId
            }.Distinct().Order().ToArray();
        foreach (var licenseId in lockedLicenseIds)
            await AcquireLicenseSeatLockAsync(db, licenseId, cancellationToken);
        validated = validated with { HardwareId = authority.EffectiveHardwareId };

        var license = await db.Licenses
            .Include(candidate => candidate.Seats)
            .Include(candidate => candidate.Product)
            .Include(candidate => candidate.Type)
            .SingleOrDefaultAsync(candidate =>
                candidate.Id == entitlement.LicenseId && candidate.ProductId == validated.ProductId,
                cancellationToken);
        var automaticReplacement = license is { MaxSeats: 1 }
            && license.Seats.Any(row => row.IsActive && row.HardwareId != validated.HardwareId);
        if (automaticReplacement && db.Database.IsNpgsql())
            now = await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken);
        var decisionSnapshot = license == null ? null
            : await LicenseDecisionHistoryWriter.CaptureAsync(db, license, now, cancellationToken, authority.EffectiveHardwareId);
        IReadOnlyList<LicenseReplacementCandidateDecision> replacementCandidateDecisions =
            CaptureUnevaluatedReplacementCandidates(validated.LicenseReplacementCandidates);
        var replacementSelectionOutcome = replacementCandidateDecisions.Count == 0 ? "none" : "not_evaluated";
        var decisionTransactionEnded = false;
        if (transaction != null && decisionSnapshot != null)
            await transaction.CreateSavepointAsync(FinalizeHistorySavepoint, cancellationToken);
        try
        {
        if (automaticReplacement)
        {
            ValidateHandoffWindow(validated, now);
            entitlement = await ReadEntitlementAsync(
                db, validated.EntitlementRef, clientId, validated.ProductId, now, cancellationToken);
        }
        if (!IsEligibleLicense(license, now))
            throw Reject("entitlement_ineligible");
        if (!IsVersionAllowed(validated.Version, license!.AllowedVersions)
            || IsVersionBelow(validated.Version, license.Product?.MinimumAllowedVersion))
        {
            throw Reject("version_not_allowed");
        }

        var activeHardwareBans = await db.BannedHardwareIds.AsNoTracking().Where(ban =>
            ban.IsActive
            && (ban.ProductId == null || ban.ProductId == validated.ProductId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => ban.HardwareId)
            .ToListAsync(cancellationToken);
        if (activeHardwareBans.Any(hardwareId =>
                string.Equals(hardwareId, submittedHardwareId, StringComparison.OrdinalIgnoreCase)
                || string.Equals(hardwareId, validated.HardwareId, StringComparison.OrdinalIgnoreCase)))
            throw Reject("entitlement_ineligible");

        var activeComponentBans = await db.BannedComponents.AsNoTracking().Where(ban =>
            ban.IsActive
            && (ban.ProductId == null || ban.ProductId == validated.ProductId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash })
            .ToListAsync(cancellationToken);
        if (activeComponentBans.Any(ban => validated.Binaries.Any(binary =>
                string.Equals(binary.Key, ban.ComponentType, StringComparison.OrdinalIgnoreCase)
                && string.Equals(
                    binary.Sha256,
                    ApprovedBinaryService.NormalizeSha256(ban.ComponentHash),
                    StringComparison.Ordinal))))
            throw Reject("binary_mismatch");

        var baselineRows = await db.ApprovedBinaries.AsNoTracking()
            .Where(row => row.ProductId == validated.ProductId && row.Version == validated.Version)
            .ToListAsync(cancellationToken);
        var baseline = baselineRows
            .Where(row => string.Equals(row.Source, ApprovedBinaryService.ReleaseSource, StringComparison.Ordinal))
            .ToDictionary(row => row.Key, row => row.Hash, StringComparer.Ordinal);
        if (baselineRows.Count != RequiredBinaryKeys.Length
            || baseline.Count != RequiredBinaryKeys.Length
            || RequiredBinaryKeys.Any(key => !baseline.ContainsKey(key)))
        {
            throw Reject("release_unapproved");
        }
        if (validated.Binaries.Any(binary =>
                !baseline.TryGetValue(binary.Key, out var expected)
                || !string.Equals(expected, binary.Sha256, StringComparison.Ordinal)))
        {
            throw Reject("binary_mismatch");
        }

        if (requiresAliasSeatReconciliation)
        {
            // The submitted legacy seat is only a transition marker. Under the Runtime-global,
            // both hardware, and licence locks, retire it before the standard seat path reactivates
            // the exact V2 seat referenced by the signed alias. A failure later rolls back both sides.
            var canonicalSourceSeat = license.Seats.SingleOrDefault(candidate =>
                candidate.Id == authority.LicenseSeatId
                && !candidate.IsActive
                && candidate.UnlinkedAt.HasValue
                && string.Equals(candidate.HardwareId, validated.HardwareId, StringComparison.Ordinal));
            var activeLegacySeats = license.Seats.Where(candidate =>
                    candidate.IsActive
                    && string.Equals(candidate.HardwareId, submittedHardwareId, StringComparison.Ordinal))
                .ToList();
            if (canonicalSourceSeat == null
                || activeLegacySeats.Count != 1
                || activeLegacySeats[0].Id == canonicalSourceSeat.Id)
            {
                throw RejectHardwareAuthority(
                    validated.RequestId,
                    HardwareAuthorityRefusalDiagnostics.CanonicalSeatCardinalityMismatch,
                    "canonical_seat_cardinality_guard",
                    new HardwareAuthorityDecisionMatrix(
                        AliasResolutionRefused: authority.Refused,
                        AliasUsed: authority.UsedAlias,
                        SeatReconciliationRequired: requiresAliasSeatReconciliation,
                        BindingIdentityPresent: authority.BindingId != null,
                        SeatIdentityPresent: authority.LicenseSeatId != null,
                        CanonicalSeatPresent: canonicalSourceSeat != null,
                        SingleLegacySeatPresent: activeLegacySeats.Count == 1));
            }

            activeLegacySeats[0].IsActive = false;
            activeLegacySeats[0].UnlinkedAt = now.UtcDateTime;
        }

        Guid? legacyReplacementSourceBindingId = null;
        if (validated.LegacyLicenseReplacement != null)
        {
            legacyReplacementSourceBindingId = await PrepareLegacyReplacementSourceAsync(
                db,
                clientId,
                validated,
                entitlement,
                validated.LegacyLicenseReplacement,
                now,
                cancellationToken);
        }

        // A used entitlement cannot become a new switch instruction after another machine
        // wins the seat. Exact request replays already returned before entering this mutation.
        if (license!.MaxSeats == 1
            && license.Seats.Any(row => row.IsActive && row.HardwareId != validated.HardwareId)
            && await db.DistributionInstallationBindings.AsNoTracking().AnyAsync(
                row => row.EntitlementId == entitlement.EntitlementId, cancellationToken))
            throw Reject("entitlement_ineligible");

        var seat = await EnsureInitialSeatAsync(
            db, license, validated.HardwareId, validated.Version, clientId, now, cancellationToken, transport);

        var existingHandoff = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(binding => binding.HandoffDigestSha256 == validated.HandoffDigestSha256, cancellationToken);
        if (existingHandoff != null)
        {
            if (BindingMatches(existingHandoff, validated, entitlement, seat.Id))
            {
                if (!string.Equals(existingHandoff.State, "active", StringComparison.Ordinal))
                    throw Conflict("binding_invalidated");
                var existingResponse = ToResponse(existingHandoff);
                db.DistributionBindingRequests.Add(new DistributionBindingRequest
                {
                    ClientId = clientId,
                    RequestId = validated.RequestId,
                    Operation = FinalizeOperation,
                    PayloadDigest = exactPayloadDigest,
                    BindingId = existingHandoff.Id,
                    ResponseJson = JsonSerializer.Serialize(existingResponse, JsonOptions),
                    CreatedAtUtc = now.UtcDateTime
                });
                try
                {
                    if (decisionSnapshot != null)
                        await AddFinalizeDecisionAsync(db, decisionSnapshot, clientId, exactPayloadDigest,
                            validated, submittedHardwareId, authority, now, "accepted", "accepted", null, 200,
                            replacementCandidateDecisions, replacementSelectionOutcome, cancellationToken);
                    await db.SaveChangesAsync(cancellationToken);
                    decisionTransactionEnded = true;
                    if (transaction != null)
                        await transaction.CommitAsync(cancellationToken);
                    return new(existingResponse, true);
                }
                catch (Exception exception) when (IsRetryableWriteFailure(exception, db) && !IsHistoryWriteFailure(exception))
                {
                    decisionTransactionEnded = true;
                    await TryRollbackAsync(transaction, cancellationToken);
                    return new(
                        await ReloadConcurrentAsync<DistributionInstallationBindingResponse>(
                            clientId, validated.RequestId, FinalizeOperation, exactPayloadDigest, cancellationToken),
                        true);
                }
            }
            throw Conflict("binding_conflict");
        }

        var existingInstallation = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(binding =>
                binding.ProductId == validated.ProductId && binding.InstallationId == validated.InstallationId,
                cancellationToken);
        var hardwareIdHash = Sha256(validated.HardwareId);
        var binaryMap = validated.Binaries.ToDictionary(binary => binary.Key, binary => binary.Sha256, StringComparer.Ordinal);
        DistributionInstallationBinding binding;
        IReadOnlyList<RuntimeEnrollment> supersededEnrollments = [];
        if (existingInstallation != null)
        {
            if (validated.LicenseReplacement != null
                || validated.LicenseReplacementCandidates.Count > 0
                || validated.LegacyLicenseReplacement != null)
                throw Conflict("binding_conflict", "replacement_existing_installation_conflict");
            var rotation = await RotateCrossGenerationBindingAsync(
                db, clientId, validated, entitlement, seat.Id, grantRefDigest,
                hardwareIdHash, binaryMap, now, cancellationToken);
            binding = rotation.Binding;
            supersededEnrollments = rotation.Enrollments;
        }
        else
        {
            var hardwareBindings = await db.DistributionInstallationBindings.AsNoTracking()
                .Where(candidate => candidate.ProductId == validated.ProductId
                    && candidate.HardwareIdHash == hardwareIdHash)
                .OrderBy(candidate => candidate.Id)
                .ToListAsync(cancellationToken);
            if ((authority.UsedAlias || requiresAliasSeatReconciliation)
                && authority.BindingId is { } authenticatedBindingId
                && hardwareBindings.All(candidate => candidate.Id != authenticatedBindingId))
            {
                var authenticatedSource = await db.DistributionInstallationBindings.AsNoTracking()
                    .SingleOrDefaultAsync(candidate =>
                        candidate.Id == authenticatedBindingId
                        && candidate.ProductId == validated.ProductId
                        && candidate.LicenseId == entitlement.LicenseId
                        && candidate.LicenseSeatId == authority.LicenseSeatId,
                        cancellationToken);
                if (authenticatedSource != null)
                    hardwareBindings.Add(authenticatedSource);
            }
            LicenseReplacementValidated? replacement = validated.LicenseReplacement;
            var proofs = validated.LicenseReplacementCandidates.Count > 0
                ? validated.LicenseReplacementCandidates
                : replacement == null ? [] : [replacement];
            var isSameLicenseSeatTransition = false;
            DistributionInstallationBinding? recoverySource = authority.UsedAlias || requiresAliasSeatReconciliation
                ? hardwareBindings.SingleOrDefault(candidate => candidate.Id == authority.BindingId)
                : legacyReplacementSourceBindingId.HasValue
                    ? hardwareBindings.SingleOrDefault(candidate => candidate.Id == legacyReplacementSourceBindingId.Value)
                    : null;
            if (authority.UsedAlias && recoverySource == null)
                throw RejectHardwareAuthority(
                    validated.RequestId,
                    HardwareAuthorityRefusalDiagnostics.RecoverySourceMissing,
                    "recovery_source_presence_guard",
                    new HardwareAuthorityDecisionMatrix(
                        AliasResolutionRefused: authority.Refused,
                        AliasUsed: authority.UsedAlias,
                        SeatReconciliationRequired: requiresAliasSeatReconciliation,
                        BindingIdentityPresent: authority.BindingId != null,
                        SeatIdentityPresent: authority.LicenseSeatId != null,
                        RecoverySourcePresent: false));
            var releasedBindings = await FindCoherentSeatReleasesAsync(db, hardwareBindings, now.UtcDateTime, cancellationToken);
            var hasActiveHardwareAuthority = hardwareBindings.Any(candidate => candidate.State == "active");
            var hasSecurityTerminalHardwareAuthority = hardwareBindings.Any(candidate =>
                !releasedBindings.Contains(candidate.Id)
                && !RuntimeAuthorityTransitionResolver.IsRecoverableBinding(
                    candidate.State, candidate.InvalidationReason));
            if (!hasActiveHardwareAuthority
                && !hasSecurityTerminalHardwareAuthority
                && recoverySource == null
                && !requiresAliasSeatReconciliation
                && replacement == null
                && IsModernEntitlementContractVersion(entitlement.ContractVersion)
                && entitlement.SubjectRefDigestSha256 is { Length: 64 })
            {
                recoverySource = await ResolveSameLicenseSeatTransitionSourceAsync(
                    db, validated.ProductId, entitlement.LicenseId, seat.Id,
                    entitlement.SubjectRefDigestSha256, hardwareIdHash, cancellationToken);
                isSameLicenseSeatTransition = recoverySource != null;
            }
            if (recoverySource == null)
            {
                var bindingDecision = RuntimeAuthorityTransitionResolver.ResolveBinding(
                    hardwareBindings.Select(candidate => new RuntimeAuthorityBindingSnapshot(
                            candidate.Id,
                            candidate.SupersededBindingId,
                            candidate.State,
                            candidate.InvalidationReason,
                            (releasedBindings.Contains(candidate.Id)
                                && candidate.LicenseId == entitlement.LicenseId
                                && candidate.LicenseSeatId == seat.Id
                                && candidate.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256)
                            || (proofs.Count > 0
                                ? proofs.Count(proof =>
                                    proof.SourceBindingId == candidate.Id
                                    && proof.SourceLicenseId == candidate.LicenseId
                                    && proof.SourceSubjectRefDigestSha256 == candidate.SubjectRefDigestSha256) == 1
                                : candidate.LicenseId == entitlement.LicenseId
                                    && candidate.LicenseSeatId == seat.Id
                                    && candidate.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256),
                            releasedBindings.Contains(candidate.Id)))
                        .ToList());
                if (bindingDecision.Kind == RuntimeAuthorityBindingDecisionKind.RejectAmbiguous)
                    throw Conflict("binding_conflict", "replacement_hardware_ambiguous");
                recoverySource = bindingDecision.BindingId.HasValue
                    ? hardwareBindings.Single(candidate => candidate.Id == bindingDecision.BindingId.Value)
                    : null;
            }
            // The bounded Finalize refusal is not a generic recovery grant. The unique V2
            // historical source must be the exact binding persisted by the signed alias.
            if (requiresAliasSeatReconciliation && recoverySource == null)
            {
                throw RejectHardwareAuthority(
                    validated.RequestId,
                    HardwareAuthorityRefusalDiagnostics.RecoverySourceMissing,
                    "recovery_source_presence_guard",
                    new HardwareAuthorityDecisionMatrix(
                        AliasResolutionRefused: authority.Refused,
                        AliasUsed: authority.UsedAlias,
                        SeatReconciliationRequired: requiresAliasSeatReconciliation,
                        BindingIdentityPresent: authority.BindingId != null,
                        SeatIdentityPresent: authority.LicenseSeatId != null,
                        RecoverySourcePresent: false));
            }
            if (requiresAliasSeatReconciliation
                && recoverySource is { } selectedRecoverySource
                && selectedRecoverySource.Id != authority.BindingId)
            {
                throw RejectHardwareAuthority(
                    validated.RequestId,
                    HardwareAuthorityRefusalDiagnostics.RecoverySourceBindingMismatch,
                    "recovery_source_binding_guard",
                    new HardwareAuthorityDecisionMatrix(
                        AliasResolutionRefused: authority.Refused,
                        AliasUsed: authority.UsedAlias,
                        SeatReconciliationRequired: requiresAliasSeatReconciliation,
                        BindingIdentityPresent: authority.BindingId != null,
                        SeatIdentityPresent: authority.LicenseSeatId != null,
                        RecoverySourcePresent: recoverySource != null,
                        RecoverySourceMatchesBinding: false));
            }
            if (validated.LicenseReplacementCandidates.Count > 0)
            {
                replacementCandidateDecisions = DiagnoseReplacementCandidates(
                    validated.LicenseReplacementCandidates, hardwareBindings, releasedBindings, recoverySource);
                replacementSelectionOutcome = replacementCandidateDecisions.Any(candidate => candidate.Outcome == "selected")
                    ? "selected" : "none";
            }
            var authenticatedAliasSource = recoverySource != null
                && (authority.UsedAlias || requiresAliasSeatReconciliation)
                && recoverySource.Id == authority.BindingId;
            var isExactAuthorityRecovery = recoverySource != null
                && ((recoverySource.State == "active"
                    && recoverySource.InvalidatedAtUtc == null
                    && recoverySource.InvalidationReason == null)
                    || releasedBindings.Contains(recoverySource.Id))
                && !hasSecurityTerminalHardwareAuthority
                && recoverySource.ProductId == validated.ProductId
                && recoverySource.LicenseId == entitlement.LicenseId
                && recoverySource.LicenseSeatId == seat.Id
                && string.Equals(
                    recoverySource.SubjectRefDigestSha256,
                    entitlement.SubjectRefDigestSha256,
                    StringComparison.Ordinal)
                && (string.Equals(recoverySource.HardwareIdHash, hardwareIdHash, StringComparison.Ordinal)
                    || authenticatedAliasSource);
            if (recoverySource != null
                && validated.LicenseReplacementCandidates.Count > 0
                && !isSameLicenseSeatTransition
                && !requiresAliasSeatReconciliation
                && !isExactAuthorityRecovery)
            {
                var matches = validated.LicenseReplacementCandidates.Where(proof =>
                        proof.SourceBindingId == recoverySource.Id
                        && proof.SourceLicenseId == recoverySource.LicenseId
                        && proof.SourceSubjectRefDigestSha256 == recoverySource.SubjectRefDigestSha256)
                    .ToList();
                if (matches.Count != 1)
                    throw Conflict("binding_conflict", "replacement_candidate_none");
                replacement = matches[0];
            }
            DistributionInstallationBinding? recoveredBinding = null;
            if (recoverySource != null)
            {
                if (!validated.AllowSameAuthorityRecovery)
                    throw Conflict("binding_conflict", "replacement_authority_missing");
                if (validated.LicenseReplacementCandidates.Count > 0
                    && replacement == null
                    && !isSameLicenseSeatTransition
                    && !requiresAliasSeatReconciliation
                    && !isExactAuthorityRecovery)
                    throw Conflict("binding_conflict", "replacement_candidate_none");
                if (replacement is { } exactReplacement
                    && exactReplacement.SourceBindingId != recoverySource.Id)
                    throw Conflict("binding_conflict", "replacement_source_binding_mismatch");
                try
                {
                    var recovery = await RecoverSameAuthorityInstallationAsync(
                        db, clientId, recoverySource.Id,
                        isExactAuthorityRecovery && validated.LicenseReplacementCandidates.Count > 0,
                        authenticatedAliasSource,
                        authority.UsedAlias || requiresAliasSeatReconciliation,
                        replacement,
                        validated.LegacyLicenseReplacement,
                        validated, entitlement, seat.Id,
                        grantRefDigest, hardwareIdHash, binaryMap, now, cancellationToken);
                    recoveredBinding = recovery.Binding;
                    supersededEnrollments = recovery.Enrollments;
                }
                catch (DistributionOperationException exception) when (
                    isSameLicenseSeatTransition
                    && !string.Equals(recoverySource.State, "active", StringComparison.Ordinal)
                    && exception.ErrorCode == "binding_conflict"
                    && exception.ReasonCode == "same_authority_mismatch")
                {
                    // TEMP-FAIL-OPEN(TKT-001221): TEMPORARY, never leave as is. A terminal
                    // same-license source that fails the exact same-authority proof should be
                    // resolved correctly; the proof is currently known to refuse legitimate
                    // histories (for example an orphan superseded leaf), so Franck's policy
                    // (2026-09-21) asks for logging only. The refusal happens before any write
                    // (reads and row locks only), so the initial path below stays consistent.
                    // A live source keeps its refusal. Fix the logged cases, restore the refusal
                    // where it is right, then remove this marker.
                    _logger.LogWarning(
                        "TEMP-FAIL-OPEN(TKT-001221) Finalize same-license source {SourceBindingId} (state {SourceState}, reason {SourceReason}, licence {LicenseId}, seat {SourceSeatId}) failed same_authority_mismatch for request {RequestId}; an initial binding is created instead.",
                        recoverySource.Id,
                        recoverySource.State,
                        recoverySource.InvalidationReason ?? "none",
                        recoverySource.LicenseId,
                        recoverySource.LicenseSeatId,
                        validated.RequestId);
                }
            }
            if (recoveredBinding != null)
            {
                binding = recoveredBinding;
            }
            else
            {
                if (validated.LicenseReplacement != null
                    || validated.LegacyLicenseReplacement != null)
                    throw Conflict("binding_conflict", "replacement_candidate_none");
                if (hardwareBindings.Count > 0)
                {
                    if (validated.LicenseReplacementCandidates.Count > 0)
                        throw Conflict("binding_conflict", "replacement_candidate_none");
                    throw Conflict("binding_conflict", "replacement_authority_missing");
                }
                if (validated.LicenseReplacementCandidates.Count > 0)
                {
                    // TEMP-FAIL-OPEN(TKT-001221): TEMPORARY, never leave as is. The history rules
                    // below are the intended behavior, but the current graph data and code are known
                    // to be buggy, so Franck's policy (2026-09-21) asks for logging only: a doubtful
                    // history never blocks a client on its own licence. Each logged divergence must
                    // be analysed and fixed, then this branch must go back to a correct decision and
                    // this marker be removed. Active bans stay enforced by the dedicated ban checks of
                    // this Finalize, independently of this history scan.
                    var historyDivergence = await FindTargetLicenseHistoryDivergenceAsync(
                        db, validated.ProductId, entitlement.LicenseId, seat.Id, now.UtcDateTime, cancellationToken);
                    if (historyDivergence is { } divergence)
                    {
                        _logger.LogWarning(
                            "TEMP-FAIL-OPEN(TKT-001221) Finalize v4 initial binding proceeded despite target-licence history divergence {Divergence} for request {RequestId}: licence {LicenseId}, binding {BindingId}, seat {SeatId}, binding state {BindingState}, binding reason {BindingReason}, successors {SuccessorCount}, seat active {SeatActive}, seat unlinked {SeatUnlinked}, enrollments {EnrollmentCount}, enrollment states {EnrollmentStates}, enrollment reasons {EnrollmentReasons}, history bindings {HistoryCount}.",
                            divergence.Code,
                            validated.RequestId,
                            entitlement.LicenseId,
                            divergence.BindingId,
                            divergence.SeatId,
                            divergence.BindingState,
                            divergence.BindingReason ?? "none",
                            divergence.SuccessorCount,
                            divergence.SeatActive?.ToString() ?? "missing",
                            divergence.SeatUnlinked?.ToString() ?? "missing",
                            divergence.EnrollmentCount,
                            divergence.EnrollmentStates,
                            divergence.EnrollmentReasons,
                            divergence.HistoryCount);
                    }
                }
                // Finalize v4 candidates are account-scoped possibilities, not proof that this
                // exact hardware has a predecessor. Only the provider-owned hardware graph can
                // distinguish a fresh installation from unresolved historical authority. The
                // intended rule requires every target-license authority on another machine to be
                // either a live seat counted by the seat quota or a closed, released history
                // (TKT-001221); under TEMP-FAIL-OPEN(TKT-001221) an unresolved history is only
                // logged above and does not refuse. Unrelated cross-license candidates neither
                // authorize nor veto that path. The candidate-free path keeps its historical
                // behavior: production history outside the rule exists and must be classified
                // before that path changes.
                binding = CreateBinding(
                    validated, entitlement, seat.Id, grantRefDigest, hardwareIdHash, binaryMap, now,
                    supersededBindingId: null, initialSecurityEpoch: 1);
                db.DistributionInstallationBindings.Add(binding);
            }
        }
        var response = ToResponse(binding);
        if (entitlement.ContractVersion is 3 or 4)
        {
            var entitlementRow = await db.DistributionEntitlements.SingleAsync(row => row.Id == entitlement.EntitlementId, cancellationToken);
            entitlementRow.State = "finalized";
            entitlementRow.FinalizedAtUtc = now.UtcDateTime;
        }
        db.DistributionBindingRequests.Add(new DistributionBindingRequest
        {
            ClientId = clientId,
            RequestId = validated.RequestId,
            Operation = FinalizeOperation,
            PayloadDigest = exactPayloadDigest,
            BindingId = binding.Id,
            ResponseJson = JsonSerializer.Serialize(response, JsonOptions),
            CreatedAtUtc = now.UtcDateTime
        });

        try
        {
            if (decisionSnapshot != null)
                await AddFinalizeDecisionAsync(db, decisionSnapshot, clientId, exactPayloadDigest,
                    validated, submittedHardwareId, authority, now, "accepted", "accepted", null, 201,
                    replacementCandidateDecisions, replacementSelectionOutcome, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            if (supersededEnrollments.Count > 0)
            {
                var authorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
                    .Where(candidate => candidate.Id == 1)
                    .Select(candidate => (long?)candidate.Epoch)
                    .SingleOrDefaultAsync(cancellationToken)
                    ?? supersededEnrollments.Max(candidate => candidate.AuthorityEpoch);
                foreach (var enrollment in supersededEnrollments)
                    enrollment.AuthorityEpoch = authorityEpoch;
                await db.SaveChangesAsync(cancellationToken);
            }
            decisionTransactionEnded = true;
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new(response, false);
        }
        catch (Exception exception) when (IsRetryableWriteFailure(exception, db) && !IsHistoryWriteFailure(exception))
        {
            decisionTransactionEnded = true;
            await TryRollbackAsync(transaction, cancellationToken);
            return new(
                await ReloadConcurrentAsync<DistributionInstallationBindingResponse>(
                    clientId, validated.RequestId, FinalizeOperation, exactPayloadDigest, cancellationToken),
                true);
        }
        }
        catch (DistributionOperationException refusal) when (decisionSnapshot != null && !decisionTransactionEnded)
        {
            await PersistFinalizeRefusalAsync(db, transaction, decisionSnapshot, clientId, exactPayloadDigest,
                validated, submittedHardwareId, authority, now, refusal,
                replacementCandidateDecisions, replacementSelectionOutcome);
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<DistributionOperationResult<DistributionInstallationInvalidationResponse>> InvalidateAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionInstallationInvalidationRequest request,
        CancellationToken cancellationToken = default)
    {
        var validated = ValidateInvalidationRequest(request);
        ValidateDigest(exactPayloadDigest);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var existing = await FindExistingAsync<DistributionInstallationInvalidationResponse>(
            db, clientId, validated.RequestId, InvalidateOperation, exactPayloadDigest, cancellationToken);
        if (existing != null)
            return new(existing, true);

        await using var transaction = await BeginBindingAuthorityTransactionAsync(db, cancellationToken);
        await AcquireBindingAuthorityLockAsync(
            db, validated.ProductId, validated.GrantRefDigestSha256, cancellationToken);
        existing = await FindExistingAsync<DistributionInstallationInvalidationResponse>(
            db, clientId, validated.RequestId, InvalidateOperation, exactPayloadDigest, cancellationToken);
        if (existing != null)
        {
            if (transaction != null)
                await transaction.RollbackAsync(cancellationToken);
            return new(existing, true);
        }

        await ValidateGrantOwnershipAsync(
            db, clientId, validated.ProductId, validated.GrantRefDigestSha256, cancellationToken);

        var prior = await db.DistributionBindingInvalidations.AsNoTracking()
            .SingleOrDefaultAsync(candidate =>
                candidate.ProductId == validated.ProductId
                && candidate.GrantRefDigestSha256 == validated.GrantRefDigestSha256,
                cancellationToken);
        if (prior != null)
            throw Conflict("invalidation_conflict");

        var now = _timeProvider.GetUtcNow();
        if (validated.OccurredAtUtc > now.AddSeconds(60))
            throw Invalid();
        var invalidatedAt = now.UtcDateTime;

        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(candidate =>
                candidate.ProductId == validated.ProductId
                && candidate.GrantRefDigestSha256 == validated.GrantRefDigestSha256,
                cancellationToken);
        if (binding == null && validated.BindingId.HasValue)
            throw new DistributionOperationException("binding_mismatch", StatusCodes.Status404NotFound);
        if (binding != null && validated.BindingId.HasValue && binding.Id != validated.BindingId.Value)
            throw Conflict("binding_mismatch");
        if (binding != null)
        {
            var owned = await db.DistributionBindingRequests.AsNoTracking().AnyAsync(candidate =>
                candidate.BindingId == binding.Id
                && candidate.Operation == FinalizeOperation
                && candidate.ClientId == clientId,
                cancellationToken);
            if (!owned)
                throw Conflict("binding_mismatch");
        }

        if (string.Equals(validated.Reason, "seat_released", StringComparison.Ordinal))
        {
            if (binding == null
                || !string.Equals(binding.State, "active", StringComparison.Ordinal)
                || binding.InvalidatedAtUtc != null
                || binding.InvalidationReason != null)
            {
                throw Conflict("binding_mismatch");
            }

            var discoveredSeat = await db.LicenseSeats.AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.Id == binding.LicenseSeatId, cancellationToken);
            if (discoveredSeat == null
                || discoveredSeat.LicenseId != binding.LicenseId
                || !discoveredSeat.IsActive
                || !string.Equals(Sha256(discoveredSeat.HardwareId), binding.HardwareIdHash,
                    StringComparison.Ordinal))
            {
                throw Conflict("binding_mismatch");
            }

            // Keep the same partial order as Finalize: grant, installation, Runtime,
            // product+exact hardware, then licence. No later lock is acquired first.
            await AcquireInstallationAuthorityLockAsync(
                db, binding.ProductId, binding.InstallationId, cancellationToken);
            await AcquireRuntimeMutationLockAsync(db, cancellationToken);
            await ProductHardwareSeatLockAuthority.AcquireAsync(
                db, binding.ProductId, discoveredSeat.HardwareId, cancellationToken);
            await AcquireLicenseSeatLockAsync(db, binding.LicenseId, cancellationToken);

            binding = db.Database.IsNpgsql()
                ? await db.DistributionInstallationBindings.FromSqlInterpolated($$"""
                    SELECT * FROM "DistributionInstallationBindings"
                    WHERE "Id" = {{binding.Id}} FOR UPDATE
                    """).SingleOrDefaultAsync(cancellationToken)
                : await db.DistributionInstallationBindings
                    .SingleOrDefaultAsync(candidate => candidate.Id == binding.Id, cancellationToken);
            var seat = db.Database.IsNpgsql()
                ? await db.LicenseSeats.FromSqlInterpolated($$"""
                    SELECT * FROM "LicenseSeats" WHERE "Id" = {{discoveredSeat.Id}} FOR UPDATE
                    """).SingleOrDefaultAsync(cancellationToken)
                : await db.LicenseSeats
                    .SingleOrDefaultAsync(candidate => candidate.Id == discoveredSeat.Id, cancellationToken);
            if (binding == null
                || seat == null
                || binding.ProductId != validated.ProductId
                || !string.Equals(binding.GrantRefDigestSha256, validated.GrantRefDigestSha256,
                    StringComparison.Ordinal)
                || binding.LicenseSeatId != discoveredSeat.Id
                || binding.LicenseId != seat.LicenseId
                || !string.Equals(binding.State, "active", StringComparison.Ordinal)
                || binding.InvalidatedAtUtc != null
                || binding.InvalidationReason != null
                || !seat.IsActive
                || !string.Equals(seat.HardwareId, discoveredSeat.HardwareId, StringComparison.Ordinal)
                || !string.Equals(Sha256(seat.HardwareId), binding.HardwareIdHash, StringComparison.Ordinal))
            {
                throw Conflict("binding_mismatch");
            }

            var liveEnrollments = db.Database.IsNpgsql()
                ? await db.RuntimeEnrollments.FromSqlInterpolated($$"""
                    SELECT * FROM "RuntimeEnrollments"
                    WHERE "BindingId" = {{binding.Id}} AND "State" IN ('PENDING', 'ACTIVE')
                    ORDER BY "Id" FOR UPDATE
                    """).ToListAsync(cancellationToken)
                : await db.RuntimeEnrollments
                    .Where(candidate => candidate.BindingId == binding.Id
                        && (candidate.State == "PENDING" || candidate.State == "ACTIVE"))
                    .OrderBy(candidate => candidate.Id)
                    .ToListAsync(cancellationToken);
            if (liveEnrollments.Any(enrollment =>
                    !string.Equals(enrollment.ClientId, clientId, StringComparison.Ordinal)
                    || enrollment.BindingId != binding.Id
                    || enrollment.ProductId != binding.ProductId
                    || enrollment.LicenseId != binding.LicenseId
                    || enrollment.LicenseSeatId != seat.Id
                    || !string.Equals(enrollment.InstallationId, binding.InstallationId, StringComparison.Ordinal)))
            {
                throw Conflict("binding_mismatch");
            }

            seat.IsActive = false;
            seat.UnlinkedAt = invalidatedAt;
            foreach (var enrollment in liveEnrollments)
            {
                enrollment.State = "INVALIDATED";
                enrollment.InvalidatedAtUtc = invalidatedAt;
                enrollment.InvalidationReason = "seat_released";
            }
            db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = binding.LicenseId,
                Timestamp = invalidatedAt,
                Action = "RUNTIME_SEAT_RELEASED",
                Details = "Provider seat release terminalized the exact binding and its live enrollments.",
                PerformedBy = clientId
            });
        }
        else if (binding != null)
        {
            binding = await db.DistributionInstallationBindings
                .SingleAsync(candidate => candidate.Id == binding.Id, cancellationToken);
        }

        if (binding != null && string.Equals(binding.State, "active", StringComparison.Ordinal))
        {
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = invalidatedAt;
            binding.InvalidationReason = validated.Reason;
        }

        var response = new DistributionInstallationInvalidationResponse(
            InvalidationResponseSchema,
            binding?.Id.ToString("D"),
            "invalidated",
            validated.GrantRefDigestSha256,
            validated.Reason,
            FormatUtc(validated.OccurredAtUtc),
            validated.Epoch,
            FormatUtc(now));
        db.DistributionBindingInvalidations.Add(new DistributionBindingInvalidation
        {
            ProductId = validated.ProductId,
            GrantRefDigestSha256 = validated.GrantRefDigestSha256,
            ClientId = clientId,
            RequestId = validated.RequestId,
            BindingId = binding?.Id,
            Reason = validated.Reason,
            OccurredAtUtc = validated.OccurredAtUtc.UtcDateTime,
            Epoch = validated.Epoch,
            ReceivedAtUtc = invalidatedAt
        });
        db.DistributionBindingRequests.Add(new DistributionBindingRequest
        {
            ClientId = clientId,
            RequestId = validated.RequestId,
            Operation = InvalidateOperation,
            PayloadDigest = exactPayloadDigest,
            BindingId = binding?.Id,
            ResponseJson = JsonSerializer.Serialize(response, JsonOptions),
            CreatedAtUtc = invalidatedAt
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new(response, false);
        }
        catch (Exception exception) when (IsRetryableWriteFailure(exception, db))
        {
            await TryRollbackAsync(transaction, cancellationToken);
            return new(
                await ReloadConcurrentAsync<DistributionInstallationInvalidationResponse>(
                    clientId, validated.RequestId, InvalidateOperation, exactPayloadDigest, cancellationToken),
                true);
        }
    }

    public async Task<DistributionInstallationBindingResponse> RevalidateForCapabilityAsync(
        Guid bindingId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var binding = await db.DistributionInstallationBindings
            .SingleOrDefaultAsync(candidate => candidate.Id == bindingId, cancellationToken)
            ?? throw new DistributionOperationException("binding_unavailable", StatusCodes.Status404NotFound);
        if (!string.Equals(binding.State, "active", StringComparison.Ordinal))
            return ToResponse(binding);

        var now = _timeProvider.GetUtcNow();
        var license = await db.Licenses.AsNoTracking()
            .Include(candidate => candidate.Seats)
            .Include(candidate => candidate.Product)
            .SingleOrDefaultAsync(candidate =>
                candidate.Id == binding.LicenseId && candidate.ProductId == binding.ProductId,
                cancellationToken);
        var seat = license?.Seats.SingleOrDefault(candidate => candidate.Id == binding.LicenseSeatId);
        string? invalidationReason = null;
        if (!IsEligibleLicense(license, now))
            invalidationReason = "license_ineligible";
        else if (seat == null || !seat.IsActive || Sha256(seat.HardwareId) != binding.HardwareIdHash)
            invalidationReason = "seat_ineligible";
        else if (!IsVersionAllowed(binding.Version, license!.AllowedVersions)
                 || IsVersionBelow(binding.Version, license.Product?.MinimumAllowedVersion))
            invalidationReason = "version_ineligible";
        else if (await HasActiveSecurityBanAsync(db, binding, seat.HardwareId, now, cancellationToken))
            invalidationReason = "security_lockdown";
        else if (!await HasMatchingReleaseBaselineAsync(db, binding, cancellationToken))
            invalidationReason = "release_changed";

        if (invalidationReason == null)
            return ToResponse(binding);

        binding.State = "invalidated";
        binding.InvalidatedAtUtc = now.UtcDateTime;
        binding.InvalidationReason = invalidationReason;
        await db.SaveChangesAsync(cancellationToken);
        return ToResponse(binding);
    }

    private Task<EntitlementIdentity> ReadEntitlementAsync(
        LicenseDbContext db,
        string entitlementRef,
        string expectedClientId,
        Guid expectedProductId,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        ReadEntitlementAsync(
            db, _entitlementProtector, entitlementRef, expectedClientId, expectedProductId, now,
            cancellationToken);

    internal static async Task<EntitlementIdentity> ReadEntitlementAsync(
        LicenseDbContext db,
        IDataProtector entitlementProtector,
        string entitlementRef,
        string expectedClientId,
        Guid expectedProductId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!IsOpaqueToken(entitlementRef))
            throw Reject("entitlement_ineligible");
        try
        {
            var json = entitlementProtector.Unprotect(entitlementRef);
            var payload = JsonSerializer.Deserialize<EntitlementTokenPayload>(json, JsonOptions);
            if (payload == null
                || (payload.ContractVersion == 4
                    ? payload.Schema != IssueV2ResponseSchema
                    : payload.Schema != IssueResponseSchema)
                || !string.Equals(payload.ClientId, expectedClientId, StringComparison.Ordinal)
                || !TryCanonicalUuid(payload.EntitlementId, out var entitlementId)
                || !TryCanonicalUuid(payload.LicenseId, out var licenseId)
                || !TryCanonicalUuid(payload.ProductId, out var productId)
                || productId != expectedProductId
                || !TryCanonicalUtc(payload.IssuedAtUtc, out var issuedAt)
                || !TryCanonicalUtc(payload.ExpiresAtUtc, out var expiresAt)
                || (payload.GrantRefDigestSha256 != null && !IsLowerSha256(payload.GrantRefDigestSha256))
                || issuedAt > now.AddMinutes(1)
                || expiresAt <= now
                || expiresAt > issuedAt.AddHours(2))
            {
                throw Reject("entitlement_ineligible");
            }
            if (payload.ContractVersion is 3 or 4)
            {
                var persisted = await db.DistributionEntitlements.AsNoTracking()
                    .SingleOrDefaultAsync(row => row.Id == entitlementId, cancellationToken);
                if (persisted == null
                    || persisted.ContractVersion != payload.ContractVersion
                    || !string.Equals(persisted.ClientId, expectedClientId, StringComparison.Ordinal)
                    || persisted.ProductId != productId
                    || persisted.LicenseId != licenseId
                    || !string.Equals(persisted.GrantRefDigestSha256, payload.GrantRefDigestSha256, StringComparison.Ordinal)
                    || !string.Equals(persisted.SubjectRefDigestSha256, payload.SubjectRefDigestSha256, StringComparison.Ordinal)
                    || persisted.ExpiresAtUtc != ToPostgreSqlTimestampPrecision(expiresAt).UtcDateTime
                    || !string.Equals(persisted.State, "issued", StringComparison.Ordinal))
                    throw Reject("entitlement_ineligible");
                if (payload.ContractVersion == 4
                    && (!TryCanonicalUuid(payload.AuthorityLineageId, out var authorityLineageId)
                        || !TryCanonicalUuid(payload.AuthorityGenerationId, out var authorityGenerationId)
                        || !IsLowerSha256(payload.ArtifactSetDigestSha256)
                        || persisted.AuthorityLineageId != authorityLineageId
                        || persisted.AuthorityGenerationId != authorityGenerationId
                        || !string.Equals(persisted.ArtifactSetDigestSha256,
                            payload.ArtifactSetDigestSha256, StringComparison.Ordinal)))
                    throw Reject("entitlement_ineligible");
            }
            return new(entitlementId, licenseId, payload.GrantRefDigestSha256,
                payload.SubjectRefDigestSha256, payload.ContractVersion,
                payload.ContractVersion == 4 ? Guid.Parse(payload.AuthorityLineageId!) : null,
                payload.ContractVersion == 4 ? Guid.Parse(payload.AuthorityGenerationId!) : null,
                payload.ContractVersion == 4 ? payload.ArtifactSetDigestSha256 : null);
        }
        catch (CryptographicException)
        {
            throw Reject("entitlement_ineligible");
        }
        catch (JsonException)
        {
            throw Reject("entitlement_ineligible");
        }
    }

    /// <summary>
    /// Validates the exact issue schema without repairing identifiers or accepting additive members in v1-v3.
    /// </summary>
    /// <param name="request">Deserialized request with JSON-member presence metadata.</param>
    /// <returns>The canonical typed identities and schema-specific persistence contract.</returns>
    /// <exception cref="DistributionOperationException">Thrown with invalid-request semantics for any shape violation.</exception>
    private static IssueValidated ValidateIssueRequest(DistributionEntitlementIssueRequest request)
    {
        if (request.ExtensionData is { Count: > 0 }
            || !TryCanonicalUuid(request.RequestId, out _)
            || !TryCanonicalUuid(request.ProductId, out var productId)
            || !TryCanonicalUuid(request.SoftLicenceLicenseId, out var licenseId))
        {
            throw Invalid();
        }
        if (request.Schema == IssueSchema && request.GrantRefDigestSha256 == null && request.SubjectRef == null
            && !request.AuthorityGenerationIdPresent)
            return new(request.RequestId!, productId, licenseId, IssueOperation, null, null, 1);
        if (request.Schema == IssueV2Schema && IsLowerSha256(request.GrantRefDigestSha256) && request.SubjectRef == null
            && !request.AuthorityGenerationIdPresent)
            return new(request.RequestId!, productId, licenseId, IssueV2Operation, request.GrantRefDigestSha256, null, 2);
        if (request.Schema == IssueV3Schema
            && IsLowerSha256(request.GrantRefDigestSha256)
            && IsCanonicalSubjectRef(request.SubjectRef)
            && !request.AuthorityGenerationIdPresent)
            return new(request.RequestId!, productId, licenseId, IssueV3Operation, request.GrantRefDigestSha256, request.SubjectRef, 3);
        if (request.Schema == IssueV4Schema
            && IsLowerSha256(request.GrantRefDigestSha256)
            && IsCanonicalSubjectRef(request.SubjectRef)
            && request.AuthorityGenerationIdPresent
            && TryCanonicalUuid(request.AuthorityGenerationId, out var authorityGenerationId))
            return new(request.RequestId!, productId, licenseId, IssueV4Operation, request.GrantRefDigestSha256,
                request.SubjectRef, 4, authorityGenerationId);
        throw Invalid();
    }

    /// <summary>
    /// Locks and validates the immutable Runtime Enrollment generation selected by issue v4.
    /// The method preserves the opaque grant bytes and proves the release registration from its stored artifacts.
    /// </summary>
    /// <param name="db">The transaction-scoped PostgreSQL context.</param>
    /// <param name="request">The already shape-validated issue v4 request.</param>
    /// <param name="cancellationToken">Cancels lock acquisition or relational validation.</param>
    /// <returns>The exact lineage, generation, and artifact-set tuple to freeze in the entitlement.</returns>
    /// <exception cref="DistributionOperationException">Thrown when any provider authority relation is absent or divergent.</exception>
    private static async Task<AuthorityGenerationProjection> ValidateAuthorityGenerationProjectionAsync(
        LicenseDbContext db,
        IssueValidated request,
        CancellationToken cancellationToken)
    {
        if (request.AuthorityGenerationId is not { } requestedGenerationId)
            throw Invalid();

        if (db.Database.IsNpgsql())
        {
            await db.Database.ExecuteSqlRawAsync(
                "SELECT pg_catalog.pg_advisory_xact_lock_shared(999831, 1)", cancellationToken);
        }

        var discoveredLineageId = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .Where(item => item.AuthorityGenerationId == requestedGenerationId)
            .Select(item => (Guid?)item.AuthorityLineageId)
            .SingleOrDefaultAsync(cancellationToken);
        if (discoveredLineageId is not { } lineageId)
            throw Reject("entitlement_ineligible");

        if (db.Database.IsNpgsql())
        {
            var lineageLock = $"runtime-enrollment-authority-lineage:{lineageId:D}";
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({lineageLock}, 999831))",
                cancellationToken);
        }

        var lineage = db.Database.IsNpgsql()
            ? await db.RuntimeEnrollmentAuthorityLineages.FromSqlInterpolated($$"""
                SELECT * FROM "RuntimeEnrollmentAuthorityLineages"
                WHERE "AuthorityLineageId" = {{lineageId}} FOR SHARE
                """).AsNoTracking().SingleOrDefaultAsync(cancellationToken)
            : await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
                .SingleOrDefaultAsync(item => item.AuthorityLineageId == lineageId, cancellationToken);
        var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AuthorityGenerationId == requestedGenerationId
                && item.AuthorityLineageId == lineageId, cancellationToken);
        if (lineage is null || generation is null
            || !string.Equals(lineage.Provider, "softlicence", StringComparison.Ordinal)
            || lineage.ProductId != request.ProductId
            || lineage.HeadGenerationId != requestedGenerationId
            || lineage.HeadSequence != generation.Sequence
            || !string.Equals(Sha256(lineage.ProviderGrantRef), request.GrantRefDigestSha256, StringComparison.Ordinal))
        {
            throw Reject("entitlement_ineligible");
        }

        RuntimeEnrollmentAuthorityGenerationPayloadV2 payload;
        try
        {
            var options = RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions();
            payload = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
                generation.CanonicalPayloadUtf8, options) ?? throw new JsonException();
            if (!JsonSerializer.SerializeToUtf8Bytes(payload, options).AsSpan()
                    .SequenceEqual(generation.CanonicalPayloadUtf8))
                throw new JsonException();
        }
        catch (JsonException)
        {
            throw Reject("entitlement_ineligible");
        }

        if (payload.Schema != "runtime-enrollment-authority-generation-v2"
            || payload.ContractVersion != 2
            || payload.AuthorityLineageId != lineageId.ToString("D")
            || payload.AuthorityGenerationId != requestedGenerationId.ToString("D")
            || payload.Provider != lineage.Provider
            || payload.ProductId != request.ProductId.ToString("D")
            || !string.Equals(payload.ProviderGrantRef, lineage.ProviderGrantRef, StringComparison.Ordinal)
            || !IsLowerSha256(payload.Release.ArtifactSetDigest))
        {
            throw Reject("entitlement_ineligible");
        }

        var registrations = await db.ApprovedBinaryRegistrations.AsNoTracking()
            .Include(item => item.Artifacts)
            .Where(item => item.ProductId == request.ProductId
                && item.Version == payload.Release.Version
                && item.Source == ApprovedBinaryService.ReleaseSource)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (registrations.Count != 1
            || !TryBuildCanonicalRegistrationArtifacts(
                registrations[0], request.ProductId, payload.Release.Version, out var registeredArtifacts)
            || !string.Equals(registrations[0].BaselineDigestSha256,
                payload.Release.ArtifactSetDigest, StringComparison.Ordinal)
            || !string.Equals(ApprovedBinaryService.ComputeBaselineDigestSha256(registeredArtifacts),
                payload.Release.ArtifactSetDigest, StringComparison.Ordinal))
        {
            throw Reject("entitlement_ineligible");
        }

        return new(lineageId, requestedGenerationId, payload.Release.ArtifactSetDigest);
    }

    /// <summary>
    /// Revalidates a frozen v4 authority tuple after Finalize owns the exclusive Runtime lock.
    /// A later lineage-head rotation is deliberately irrelevant; the immutable selected generation remains authoritative.
    /// </summary>
    /// <param name="db">Transaction-scoped context that owns the exclusive Runtime lock.</param>
    /// <param name="entitlement">Exact authority tuple recovered from both token and persisted entitlement.</param>
    /// <param name="request">Validated Finalize release and binary evidence.</param>
    /// <param name="grantRefDigestSha256">Lowercase digest of the exact opaque Finalize grant.</param>
    /// <param name="cancellationToken">Cancels relational revalidation before any binding mutation.</param>
    /// <returns>A task completing only when every frozen authority relation remains exact.</returns>
    /// <exception cref="DistributionOperationException">Thrown fail closed for missing, ambiguous, or divergent authority.</exception>
    private static async Task ValidateAuthorityGenerationForFinalizeAsync(
        LicenseDbContext db,
        EntitlementIdentity entitlement,
        FinalizeValidated request,
        string grantRefDigestSha256,
        CancellationToken cancellationToken)
    {
        if (entitlement.AuthorityLineageId is not { } lineageId
            || entitlement.AuthorityGenerationId is not { } generationId
            || !IsLowerSha256(entitlement.ArtifactSetDigestSha256))
            throw Reject("entitlement_ineligible");

        var persisted = await db.DistributionEntitlements.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == entitlement.EntitlementId, cancellationToken);
        var lineage = await db.RuntimeEnrollmentAuthorityLineages.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AuthorityLineageId == lineageId, cancellationToken);
        var generation = await db.RuntimeEnrollmentAuthorityGenerations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AuthorityLineageId == lineageId
                && item.AuthorityGenerationId == generationId, cancellationToken);
        if (persisted is null || lineage is null || generation is null
            || persisted.ContractVersion != 4
            || persisted.AuthorityLineageId != lineageId
            || persisted.AuthorityGenerationId != generationId
            || !string.Equals(persisted.ArtifactSetDigestSha256,
                entitlement.ArtifactSetDigestSha256, StringComparison.Ordinal)
            || !string.Equals(lineage.Provider, "softlicence", StringComparison.Ordinal)
            || lineage.ProductId != request.ProductId
            || !string.Equals(Sha256(lineage.ProviderGrantRef), grantRefDigestSha256, StringComparison.Ordinal))
            throw Reject("entitlement_ineligible");

        var payload = DeserializeCanonicalAuthorityPayload(generation.CanonicalPayloadUtf8);
        if (payload is null
            || payload.Schema != "runtime-enrollment-authority-generation-v2"
            || payload.ContractVersion != 2
            || payload.AuthorityLineageId != lineageId.ToString("D")
            || payload.AuthorityGenerationId != generationId.ToString("D")
            || payload.Provider != lineage.Provider
            || payload.ProductId != request.ProductId.ToString("D")
            || !string.Equals(payload.ProviderGrantRef, lineage.ProviderGrantRef, StringComparison.Ordinal)
            || !string.Equals(payload.Release.ArtifactSetDigest,
                entitlement.ArtifactSetDigestSha256, StringComparison.Ordinal)
            || !string.Equals(payload.Release.Version, request.Version, StringComparison.Ordinal))
            throw Reject("entitlement_ineligible");

        var registrations = await db.ApprovedBinaryRegistrations.AsNoTracking()
            .Include(item => item.Artifacts)
            .Where(item => item.ProductId == request.ProductId
                && item.Version == payload.Release.Version
                && item.Source == ApprovedBinaryService.ReleaseSource)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (registrations.Count != 1
            || !TryBuildCanonicalRegistrationArtifacts(
                registrations[0], request.ProductId, payload.Release.Version, out var storedArtifacts)
            || !string.Equals(registrations[0].BaselineDigestSha256,
                entitlement.ArtifactSetDigestSha256, StringComparison.Ordinal))
            throw Reject("release_unapproved");

        if (!string.Equals(ApprovedBinaryService.ComputeBaselineDigestSha256(storedArtifacts),
                entitlement.ArtifactSetDigestSha256, StringComparison.Ordinal))
            throw Reject("release_unapproved");

        var exactArtifacts = storedArtifacts.ToDictionary(item => item.Key, item => item.Sha256, StringComparer.Ordinal);
        if (exactArtifacts.Count != RequiredBinaryKeys.Length
            || RequiredBinaryKeys.Any(key => !exactArtifacts.ContainsKey(key))
            || request.Binaries.Any(item => !exactArtifacts.TryGetValue(item.Key, out var expected)
                || !string.Equals(item.Sha256, expected, StringComparison.Ordinal)))
            throw Reject("binary_mismatch");
    }

    /// <summary>
    /// Deserializes only production-canonical Runtime Enrollment v2 generation payload bytes.
    /// It returns null instead of repairing malformed JSON, member order, casing, or string values.
    /// </summary>
    /// <param name="canonicalPayloadUtf8">Persisted bytes claimed to be the closed canonical payload.</param>
    /// <returns>The exact DTO when serialization round-trips byte-for-byte; otherwise null.</returns>
    private static RuntimeEnrollmentAuthorityGenerationPayloadV2? DeserializeCanonicalAuthorityPayload(
        byte[] canonicalPayloadUtf8)
    {
        try
        {
            var options = RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions();
            var payload = JsonSerializer.Deserialize<RuntimeEnrollmentAuthorityGenerationPayloadV2>(
                canonicalPayloadUtf8, options);
            return payload != null
                && JsonSerializer.SerializeToUtf8Bytes(payload, options).AsSpan().SequenceEqual(canonicalPayloadUtf8)
                    ? payload
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Validates the exact source-resolution request without normalizing identifiers.</summary>
    private static RuntimeSourceResolutionValidated ValidateRuntimeSourceResolutionRequest(
        DistributionRuntimeSourceResolutionRequest request)
    {
        if (request.ExtensionData is { Count: > 0 }
            || request.Schema != RuntimeSourceResolutionSchema
            || !TryCanonicalUuid(request.RequestId, out _)
            || !TryCanonicalUuid(request.ProductId, out var productId)
            || !TryCanonicalUuid(request.TargetLicenseId, out var targetLicenseId)
            || request.HardwareId == null
            || !HardwareIdPattern.IsMatch(request.HardwareId))
        {
            throw Invalid();
        }

        return new(productId, targetLicenseId, request.HardwareId);
    }

    private static bool IsCanonicalSubjectRef(string? value)
    {
        if (value is not { Length: 43 } || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
            return false;
        try
        {
            var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "=");
            return bytes.Length == 32
                && string.Equals(
                    Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
                    value,
                    StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static FinalizeValidated ValidateFinalizeRequest(DistributionInstallationFinalizeRequest request)
    {
        var replacementAuthority = request.Schema switch
        {
            FinalizeSchema when !request.AllowSameAuthorityRecoveryPresent
                && !request.LicenseReplacementPresent
                && !request.LicenseReplacementCandidatesPresent
                && !request.LegacyLicenseReplacementPresent =>
                new FinalizeReplacementAuthority(false, null, [], null),
            FinalizeV2Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true
                && !request.LicenseReplacementPresent
                && !request.LicenseReplacementCandidatesPresent
                && !request.LegacyLicenseReplacementPresent => new FinalizeReplacementAuthority(true, null, [], null),
            FinalizeV3Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true
                && request.LicenseReplacementPresent
                && !request.LicenseReplacementCandidatesPresent
                && !request.LegacyLicenseReplacementPresent =>
                new FinalizeReplacementAuthority(true, ValidateLicenseReplacement(request.LicenseReplacement), [], null),
            FinalizeV4Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true
                && !request.LicenseReplacementPresent
                && request.LicenseReplacementCandidatesPresent
                && !request.LegacyLicenseReplacementPresent =>
                new FinalizeReplacementAuthority(true, null, ValidateLicenseReplacementCandidates(request.LicenseReplacementCandidates), null),
            FinalizeV5Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true
                && !request.LicenseReplacementPresent
                && !request.LicenseReplacementCandidatesPresent
                && request.LegacyLicenseReplacementPresent =>
                new FinalizeReplacementAuthority(true, null, [], ValidateLegacyLicenseReplacement(request.LegacyLicenseReplacement)),
            _ => throw Invalid()
        };
        if (request.ExtensionData is { Count: > 0 }
            || !TryCanonicalUuid(request.RequestId, out _)
            || !TryCanonicalUuid(request.GrantRef, out _)
            || !TryCanonicalUuid(request.ProductId, out var productId)
            || !TryCanonicalUuid(request.InstallationId, out _)
            || !IsLowerSha256(request.HandoffDigestSha256)
            || request.HardwareId == null || !HardwareIdPattern.IsMatch(request.HardwareId)
            || request.EntitlementRef == null || !IsOpaqueToken(request.EntitlementRef)
            || request.Release == null || request.Release.ExtensionData is { Count: > 0 }
            || request.Release.Version == null
            || ApprovedBinaryService.NormalizeVersion(request.Release.Version) != request.Release.Version
            || !IsSafeFilename(request.Release.InstallerFilename)
            || !IsLowerSha256(request.Release.InstallerSha256)
            || !TryCanonicalUtc(request.HandoffIssuedAtUtc, out var issuedAt)
            || !TryCanonicalUtc(request.HandoffExpiresAtUtc, out var expiresAt)
            || !TryCanonicalUtc(request.DownloadCompletedAtUtc, out var downloadedAt))
        {
            throw Invalid();
        }

        var binaries = ValidateBinaries(request.Binaries);
        return new(
            request.RequestId!,
            request.GrantRef!,
            request.HandoffDigestSha256!,
            issuedAt,
            expiresAt,
            downloadedAt,
            productId,
            request.EntitlementRef!,
            request.InstallationId!,
            request.HardwareId,
            request.Release.Version,
            request.Release.InstallerFilename!,
            request.Release.InstallerSha256!,
            binaries,
            replacementAuthority.AllowSameAuthorityRecovery,
            replacementAuthority.LicenseReplacement,
            replacementAuthority.LicenseReplacementCandidates,
            replacementAuthority.LegacyLicenseReplacement);
    }

    private static LicenseReplacementValidated ValidateLicenseReplacement(
        DistributionLicenseReplacementProof? replacement)
    {
        if (replacement == null
            || replacement.ExtensionData is { Count: > 0 }
            || replacement.Schema != LicenseReplacementSchema
            || !TryCanonicalUuid(replacement.SourceBindingId, out var sourceBindingId)
            || !TryCanonicalUuid(replacement.SourceLicenseId, out var sourceLicenseId)
            || !IsCanonicalSubjectRef(replacement.SourceSubjectRef))
        {
            throw Invalid();
        }

        return new(
            sourceBindingId,
            sourceLicenseId,
            Sha256(replacement.SourceSubjectRef!));
    }

    private static IReadOnlyList<LicenseReplacementValidated> ValidateLicenseReplacementCandidates(
        DistributionLicenseReplacementCandidateSet? candidateSet)
    {
        if (candidateSet == null
            || candidateSet.ExtensionData is { Count: > 0 }
            || candidateSet.Schema != LicenseReplacementCandidatesSchema
            || candidateSet.Sources is not { Count: > 0 }
            || candidateSet.Sources.Count > MaximumLicenseReplacementCandidates)
        {
            throw Invalid();
        }

        var candidates = candidateSet.Sources.Select(ValidateLicenseReplacement).ToList();
        if (candidates.Select(candidate => candidate.SourceBindingId).Distinct().Count() != candidates.Count)
            throw Invalid();
        return candidates;
    }

    /// <summary>
    /// Validates the minimal Website same-owner assertion without accepting any caller-selected
    /// binding, seat, hardware, customer, grant, key, or historical subject authority.
    /// </summary>
    /// <param name="replacement">The exact nested v5 proof from the signed S2S body.</param>
    /// <returns>The canonical source and target licence identifiers.</returns>
    /// <exception cref="DistributionOperationException">Thrown when the proof shape or identifier spelling is not exact.</exception>
    private static LegacyLicenseReplacementValidated ValidateLegacyLicenseReplacement(
        DistributionLegacyLicenseReplacementProof? replacement)
    {
        if (replacement == null
            || replacement.ExtensionData is { Count: > 0 }
            || replacement.Schema != LegacyLicenseReplacementSchema
            || !TryCanonicalUuid(replacement.SourceLicenseId, out var sourceLicenseId)
            || !TryCanonicalUuid(replacement.TargetLicenseId, out var targetLicenseId)
            || sourceLicenseId == targetLicenseId)
        {
            throw Invalid();
        }

        return new(sourceLicenseId, targetLicenseId);
    }

    /// <summary>Validates the closed invalidation wire contract without normalizing opaque request values.</summary>
    /// <param name="request">Deserialized S2S request whose exact schema, identifiers, reason, time, and epoch are required.</param>
    /// <returns>A typed request containing parsed identifiers and the exact accepted reason.</returns>
    /// <exception cref="DistributionOperationException">The request is outside the closed v1 contract.</exception>
    private static InvalidationValidated ValidateInvalidationRequest(
        DistributionInstallationInvalidationRequest request)
    {
        Guid? bindingId = null;
        if (request.BindingId != null)
        {
            if (!TryCanonicalUuid(request.BindingId, out var parsedBindingId))
                throw Invalid();
            bindingId = parsedBindingId;
        }
        if (request.ExtensionData is { Count: > 0 }
            || request.Schema != InvalidationSchema
            || !TryCanonicalUuid(request.RequestId, out _)
            || !TryCanonicalUuid(request.ProductId, out var productId)
            || !IsLowerSha256(request.GrantRefDigestSha256)
            || request.Reason == null || !InvalidationReasons.Contains(request.Reason)
            || !TryCanonicalUtc(request.OccurredAtUtc, out var occurredAt)
            || request.Epoch != 1)
        {
            throw Invalid();
        }
        return new(
            request.RequestId!, productId, bindingId, request.GrantRefDigestSha256!,
            request.Reason, occurredAt, request.Epoch.Value);
    }

    private static IReadOnlyList<BinaryValidated> ValidateBinaries(IReadOnlyCollection<DistributionBinaryEvidence>? binaries)
    {
        if (binaries == null || binaries.Count != RequiredBinaryKeys.Length)
            throw Invalid();
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var binary in binaries)
        {
            if (binary.ExtensionData is { Count: > 0 }
                || binary.Key == null
                || !RequiredBinaryKeySet.Contains(binary.Key)
                || !IsLowerSha256(binary.Sha256)
                || !result.TryAdd(binary.Key, binary.Sha256!))
            {
                throw Invalid();
            }
        }
        if (RequiredBinaryKeys.Any(key => !result.ContainsKey(key)))
            throw Invalid();
        return RequiredBinaryKeys.Select(key => new BinaryValidated(key, result[key])).ToList();
    }

    /// <summary>
    /// Proves that one release registration owns exactly the three canonical child artifacts and
    /// returns them in protocol order rather than database or ordinal-key order.
    /// </summary>
    private static bool TryBuildCanonicalRegistrationArtifacts(
        ApprovedBinaryRegistration registration,
        Guid productId,
        string version,
        out IReadOnlyList<ApprovedBinaryArtifact> artifacts)
    {
        artifacts = [];
        if (registration.ProductId != productId
            || !string.Equals(registration.Version, version, StringComparison.Ordinal)
            || !string.Equals(registration.Source, ApprovedBinaryService.ReleaseSource, StringComparison.Ordinal)
            || !IsLowerSha256(registration.BaselineDigestSha256)
            || registration.Artifacts.Count != RequiredBinaryKeys.Length)
            return false;

        var exact = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var artifact in registration.Artifacts)
        {
            if (artifact.ApprovedBinaryRegistrationId != registration.Id
                || artifact.ProductId != productId
                || !string.Equals(artifact.Version, version, StringComparison.Ordinal)
                || !string.Equals(artifact.Source, ApprovedBinaryService.ReleaseSource, StringComparison.Ordinal)
                || !RequiredBinaryKeySet.Contains(artifact.Key)
                || !IsLowerSha256(artifact.Hash)
                || !exact.TryAdd(artifact.Key, artifact.Hash))
                return false;
        }

        if (RequiredBinaryKeys.Any(key => !exact.ContainsKey(key)))
            return false;
        artifacts = RequiredBinaryKeys
            .Select(key => new ApprovedBinaryArtifact(key, exact[key]))
            .ToList();
        return true;
    }

    private static void ValidateHandoffWindow(FinalizeValidated request, DateTimeOffset now)
    {
        if (request.HandoffIssuedAtUtc > now.AddMinutes(1)
            || request.HandoffExpiresAtUtc <= now
            || request.HandoffExpiresAtUtc > request.HandoffIssuedAtUtc.AddHours(2)
            || request.DownloadCompletedAtUtc < request.HandoffIssuedAtUtc
            || request.DownloadCompletedAtUtc > now.AddMinutes(1)
            || request.DownloadCompletedAtUtc > request.HandoffExpiresAtUtc)
        {
            throw new DistributionOperationException("handoff_unavailable", StatusCodes.Status410Gone);
        }
    }

    private static bool IsEligibleLicense(License? license, DateTimeOffset now) =>
        license != null
        && license.IsActive
        && license.RevokedAt == null
        && (!license.ExpirationDate.HasValue || license.ExpirationDate.Value > now.UtcDateTime)
        && license.MaxSeats > 0
        && license.Seats.Count(seat => seat.IsActive) <= license.MaxSeats;

    /// <summary>
    /// Resolves and retires the sole active grantless source seat before target-seat establishment.
    /// </summary>
    /// <param name="db">The transaction-scoped database context holding Runtime and both licence locks.</param>
    /// <param name="clientId">The exact S2S client that signed the source and target licence assertion.</param>
    /// <param name="request">The validated target finalize request.</param>
    /// <param name="entitlement">The authenticated target entitlement from the closed contract set {3,4}.</param>
    /// <param name="replacement">The canonical source and target licence pair asserted by Website.</param>
    /// <param name="now">The authoritative transition time.</param>
    /// <param name="cancellationToken">Cancels the transaction before any commit.</param>
    /// <returns>The exact server-derived source binding identifier.</returns>
    /// <exception cref="DistributionOperationException">
    /// Thrown when authority is ambiguous, modern grant proof exists, or any source invariant fails closed.
    /// </exception>
    private static async Task<Guid> PrepareLegacyReplacementSourceAsync(
        LicenseDbContext db,
        string clientId,
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        LegacyLicenseReplacementValidated replacement,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var hardwareIdHash = Sha256(request.HardwareId);
        var hardwareBindings = db.Database.IsNpgsql()
            ? await db.DistributionInstallationBindings.FromSqlInterpolated($"""
                SELECT * FROM public."DistributionInstallationBindings"
                WHERE "ProductId" = {request.ProductId}
                  AND "HardwareIdHash" = {hardwareIdHash}
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.DistributionInstallationBindings.Where(candidate =>
                    candidate.ProductId == request.ProductId
                    && candidate.HardwareIdHash == hardwareIdHash)
                .OrderBy(candidate => candidate.Id)
                .ToListAsync(cancellationToken);
        if (hardwareBindings.Count != 1
            || hardwareBindings[0].State != "active"
            || hardwareBindings[0].InvalidatedAtUtc != null
            || hardwareBindings[0].InvalidationReason != null)
        {
            throw Conflict("binding_conflict", "legacy_replacement_source_ambiguous");
        }

        var source = hardwareBindings[0];
        if (source.LicenseId != replacement.SourceLicenseId
            || entitlement.LicenseId != replacement.TargetLicenseId
            || source.LicenseId == entitlement.LicenseId
            || source.ProductId != request.ProductId
            || !string.Equals(source.HardwareIdHash, hardwareIdHash, StringComparison.Ordinal)
            || !string.Equals(source.GrantRefDigestSha256, Sha256(source.GrantRef), StringComparison.Ordinal))
        {
            throw Conflict("binding_conflict", "legacy_replacement_source_mismatch");
        }

        var previousEntitlements = await db.DistributionEntitlements.AsNoTracking()
            .Where(candidate => candidate.Id == source.EntitlementId
                || (candidate.ProductId == source.ProductId
                    && candidate.GrantRefDigestSha256 == source.GrantRefDigestSha256))
            .ToListAsync(cancellationToken);
        var previousGrantOwners = await db.DistributionGrantOwnerships.AsNoTracking()
            .Where(candidate => candidate.ProductId == source.ProductId
                && candidate.GrantRefDigestSha256 == source.GrantRefDigestSha256)
            .ToListAsync(cancellationToken);
        var coherentModernAuthority = previousEntitlements.Count == 1
            && previousGrantOwners.Count == 1
            && previousEntitlements[0].Id == source.EntitlementId
            && IsModernEntitlementContractVersion(previousEntitlements[0].ContractVersion)
            && previousEntitlements[0].State == "finalized"
            && previousEntitlements[0].ClientId == clientId
            && previousEntitlements[0].ProductId == source.ProductId
            && previousEntitlements[0].LicenseId == source.LicenseId
            && previousEntitlements[0].GrantRefDigestSha256 == source.GrantRefDigestSha256
            && previousEntitlements[0].SubjectRefDigestSha256 == source.SubjectRefDigestSha256
            && source.SubjectRefDigestSha256 is { Length: 64 }
            && previousGrantOwners[0].ClientId == clientId
            && IsMatchingModernIssueSource(previousEntitlements[0].ContractVersion, previousGrantOwners[0].Source);
        if (coherentModernAuthority)
            throw Conflict("binding_conflict", "legacy_replacement_modern_authority_required");
        if (previousEntitlements.Count != 0 || previousGrantOwners.Count != 0)
            throw Conflict("binding_conflict", "legacy_replacement_modern_authority_inconsistent");

        var finalizeOwners = await db.DistributionBindingRequests.AsNoTracking()
            .Where(candidate => candidate.BindingId == source.Id && candidate.Operation == FinalizeOperation)
            .Select(candidate => candidate.ClientId)
            .Distinct()
            .ToListAsync(cancellationToken);
        if (finalizeOwners.Count != 1 || finalizeOwners[0] != clientId)
            throw Conflict("binding_conflict", "legacy_replacement_finalize_owner_mismatch");

        var sourceLicense = await db.Licenses.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.Id == source.LicenseId && candidate.ProductId == source.ProductId,
            cancellationToken);
        if (sourceLicense == null || !IsReplacementSourceIneligible(sourceLicense, now))
            throw Conflict("binding_conflict", "legacy_replacement_source_eligible");

        var sourceSeat = db.Database.IsNpgsql()
            ? await db.LicenseSeats.FromSqlInterpolated($"""
                SELECT * FROM public."LicenseSeats"
                WHERE "Id" = {source.LicenseSeatId}
                FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken)
            : await db.LicenseSeats.SingleOrDefaultAsync(candidate =>
                candidate.Id == source.LicenseSeatId, cancellationToken);
        var activeHardwareSeats = await db.LicenseSeats.AsNoTracking()
            .Where(candidate => candidate.IsActive
                && candidate.HardwareId == request.HardwareId
                && candidate.License != null
                && candidate.License.ProductId == request.ProductId)
            .Select(candidate => candidate.Id)
            .ToListAsync(cancellationToken);
        if (sourceSeat == null
            || !sourceSeat.IsActive
            || sourceSeat.LicenseId != source.LicenseId
            || !string.Equals(sourceSeat.HardwareId, request.HardwareId, StringComparison.Ordinal)
            || activeHardwareSeats.Count != 1
            || activeHardwareSeats[0] != sourceSeat.Id)
        {
            throw Conflict("binding_conflict", "legacy_replacement_source_seat_mismatch");
        }

        var enrollments = db.Database.IsNpgsql()
            ? await db.RuntimeEnrollments.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollments"
                WHERE "BindingId" = {source.Id}
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.RuntimeEnrollments.Where(candidate => candidate.BindingId == source.Id)
                .OrderBy(candidate => candidate.Id)
                .ToListAsync(cancellationToken);
        if (enrollments.Count != 1
            || enrollments[0].State != RuntimeAuthorityTransitionResolver.ActiveState
            || !EnrollmentMatchesBinding(enrollments[0], source, clientId))
        {
            throw Conflict("binding_conflict", "legacy_replacement_enrollment_mismatch");
        }
        if (await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(
                incident => incident.BindingId == source.Id && incident.State == "OPEN",
                cancellationToken))
        {
            throw Conflict("binding_conflict", "legacy_replacement_source_incident");
        }

        // The source seat must be retired before the normal target-seat path checks product-wide
        // hardware ownership. Every later refusal rolls this state change back with the transaction.
        sourceSeat.IsActive = false;
        sourceSeat.UnlinkedAt = now.UtcDateTime;
        db.LicenseHistories.Add(new LicenseHistory
        {
            LicenseId = source.LicenseId,
            Timestamp = now.UtcDateTime,
            Action = "RUNTIME_LEGACY_LICENSE_REPLACED",
            Details = "Authenticated Website ownership assertion transferred Runtime authority to a new licence.",
            PerformedBy = clientId
        });
        // Flush only inside the still-open transaction so the normal product-wide seat query sees
        // the exact source as retired. Every later failure must roll this intermediate write back.
        await db.SaveChangesAsync(cancellationToken);
        return source.Id;
    }

    /// <summary>
    /// Compares one active enrollment with its Runtime binding authority using exact ordinal strings.
    /// Hardware remains a licensing and seat concern and is not part of Runtime identity.
    /// </summary>
    /// <param name="enrollment">The enrollment selected under the Runtime lock.</param>
    /// <param name="binding">The server-derived source binding.</param>
    /// <param name="clientId">The exact current S2S client.</param>
    /// <returns><see langword="true"/> only for a complete exact authority match.</returns>
    private static bool EnrollmentMatchesBinding(
        RuntimeEnrollment enrollment,
        DistributionInstallationBinding binding,
        string clientId) =>
        string.Equals(enrollment.ClientId, clientId, StringComparison.Ordinal)
        && enrollment.BindingId == binding.Id
        && enrollment.ProductId == binding.ProductId
        && enrollment.LicenseId == binding.LicenseId
        && enrollment.LicenseSeatId == binding.LicenseSeatId
        && string.Equals(enrollment.InstallationId, binding.InstallationId, StringComparison.Ordinal)
        && string.Equals(enrollment.SubjectRefDigestSha256, binding.SubjectRefDigestSha256, StringComparison.Ordinal)
        && string.Equals(enrollment.HandoffDigestSha256, binding.HandoffDigestSha256, StringComparison.Ordinal)
        && string.Equals(enrollment.ReleaseVersion, binding.Version, StringComparison.Ordinal)
        && string.Equals(enrollment.ProtocolVersion, RuntimeEnrollmentService.ProtocolVersion, StringComparison.Ordinal)
        && enrollment.Epoch == 1
        && enrollment.SecurityEpoch >= 1;

    /// <summary>Obtains the eligible current seat or replaces a full single-seat licence inside the caller's locked transaction.</summary>
    /// <remarks>All licensing and quota guards precede release. Observed S2S transport metadata is history-only; the caller must roll back every pending change on later failure.</remarks>
    private static async Task<LicenseSeat> EnsureInitialSeatAsync(
        LicenseDbContext db,
        License license,
        string hardwareId,
        string version,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        AutomaticSeatSwitch.TransportObservation transport)
    {
        var activeSeat = license.Seats.SingleOrDefault(candidate =>
            candidate.IsActive && string.Equals(candidate.HardwareId, hardwareId, StringComparison.Ordinal));
        if (activeSeat != null)
        {
            activeSeat.LastCheckInAt = now.UtcDateTime;
            activeSeat.AppVersion = version;
            return activeSeat;
        }

        if (license.Type?.DisableNewActivations == true)
            throw Reject("new_activations_disabled");

        var hardwareIsActiveOnAnotherLicense = await db.LicenseSeats.AsNoTracking().AnyAsync(candidate =>
            candidate.IsActive
            && candidate.HardwareId == hardwareId
            && candidate.LicenseId != license.Id
            && candidate.License != null
            && candidate.License.ProductId == license.ProductId,
            cancellationToken);
        if (hardwareIsActiveOnAnotherLicense)
            throw Reject("hardware_already_bound");

        if (license.Type?.EnforceSingleUsePerHardwareId == true)
        {
            var consumedOnAnotherLicense = await db.Licenses.AsNoTracking().AnyAsync(candidate =>
                candidate.ProductId == license.ProductId
                && candidate.LicenseTypeId == license.LicenseTypeId
                && candidate.Id != license.Id
                && (candidate.HardwareId == hardwareId
                    || candidate.Seats.Any(seat => seat.HardwareId == hardwareId)),
                cancellationToken);
            if (consumedOnAnotherLicense)
                throw Reject("hardware_already_consumed");
        }

        var automaticSwitch = await AutomaticSeatSwitch.PrepareAsync(
            db, license, hardwareId, now.UtcDateTime, cancellationToken);
        if (automaticSwitch != null)
        {
            // A previously finalized handoff is replay evidence, never authority to evict
            // the machine which became current after that original activation.
            await AutomaticSeatSwitch.CompleteAsync(
                db, license, automaticSwitch, hardwareId, clientId, cancellationToken, transport);
            now = new DateTimeOffset(automaticSwitch.Scope.ObservedAtUtc);
        }
        var activeSeatCount = license.Seats.Count(candidate => candidate.IsActive);
        if (activeSeatCount >= license.MaxSeats)
            throw Reject("seat_limit_reached");

        var maxActivationsPerDay = license.Type?.MaxActivationsPerDay ?? 0;
        if (maxActivationsPerDay > 0 && license.MaxSeats != 1)
        {
            var dayStart = now.UtcDateTime.Date;
            var activationsToday = await db.LicenseSeats.AsNoTracking().CountAsync(candidate =>
                candidate.LicenseId == license.Id && candidate.FirstActivatedAt >= dayStart,
                cancellationToken);
            if (activationsToday >= maxActivationsPerDay)
                throw Reject("activation_rate_limited");
        }

        await PersonalDayPassActivationService.StartPendingAsync(
            db, license, now.UtcDateTime, clientId, cancellationToken);

        var seat = license.Seats
            .Where(candidate => !candidate.IsActive
                && string.Equals(candidate.HardwareId, hardwareId, StringComparison.Ordinal))
            .OrderByDescending(candidate => candidate.FirstActivatedAt)
            .FirstOrDefault();
        var action = "RUNTIME_INITIAL_SEAT_REACTIVATED";
        if (seat == null)
        {
            seat = new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = hardwareId,
                FirstActivatedAt = now.UtcDateTime
            };
            db.LicenseSeats.Add(seat);
            action = "RUNTIME_INITIAL_SEAT_CREATED";
        }

        seat.IsActive = true;
        seat.UnlinkedAt = null;
        seat.LastCheckInAt = now.UtcDateTime;
        seat.AppVersion = version;
        if (activeSeatCount == 0 || string.IsNullOrEmpty(license.HardwareId))
        {
            license.HardwareId = hardwareId;
            license.ActivationDate = seat.FirstActivatedAt;
            if (license.ValidityDays.HasValue && !license.ExpirationDate.HasValue)
                license.ExpirationDate = now.UtcDateTime.AddDays(license.ValidityDays.Value);
        }

        db.LicenseHistories.Add(new LicenseHistory
        {
            LicenseId = license.Id,
            Timestamp = now.UtcDateTime,
            Action = action,
            Details = "Authenticated distribution finalize established the initial runtime seat.",
            PerformedBy = clientId
        });
        return seat;
    }

    private static bool IsVersionAllowed(string version, string? allowedMask)
    {
        if (string.IsNullOrEmpty(allowedMask) || allowedMask == "*")
            return true;
        if (allowedMask.EndsWith(".*", StringComparison.Ordinal))
            return version.StartsWith(allowedMask[..^1], StringComparison.Ordinal);
        return string.Equals(version, allowedMask, StringComparison.Ordinal);
    }

    private static bool IsVersionBelow(string current, string? minimum)
    {
        if (string.IsNullOrWhiteSpace(minimum))
            return false;
        if (Version.TryParse(current, out var currentVersion) && Version.TryParse(minimum, out var minimumVersion))
            return currentVersion < minimumVersion;
        return string.Compare(current, minimum, StringComparison.Ordinal) < 0;
    }

    /// <summary>
    /// Compares a frozen binding with exact Finalize evidence, including the v3/v4 relational handoff tuple.
    /// Legacy contracts intentionally retain their historical comparison surface.
    /// </summary>
    private static bool BindingMatches(
        DistributionInstallationBinding binding,
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        Guid seatId) =>
        binding.ProductId == request.ProductId
        && binding.LicenseId == entitlement.LicenseId
        && binding.LicenseSeatId == seatId
        && binding.EntitlementId == entitlement.EntitlementId
        && binding.GrantRef == request.GrantRef
        && (!IsModernEntitlementContractVersion(entitlement.ContractVersion)
            || (binding.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256
                && binding.HandoffIssuedAtUtc == request.HandoffIssuedAtUtc.UtcDateTime
                && binding.HandoffExpiresAtUtc == request.HandoffExpiresAtUtc.UtcDateTime
                && binding.DownloadCompletedAtUtc == request.DownloadCompletedAtUtc.UtcDateTime))
        && binding.InstallationId == request.InstallationId
        && binding.HardwareIdHash == Sha256(request.HardwareId)
        && binding.Version == request.Version
        && binding.InstallerFilename == request.InstallerFilename
        && binding.InstallerSha256 == request.InstallerSha256
        && binding.ExecutableSha256 == request.Binaries.Single(binary => binary.Key == "FP_EXE").Sha256
        && binding.NativeDllSha256 == request.Binaries.Single(binary => binary.Key == "FP_DLL").Sha256
        && binding.CoreSha256 == request.Binaries.Single(binary => binary.Key == "FP_CORE").Sha256;

    private static async Task<CrossGenerationRotation> RotateCrossGenerationBindingAsync(
        LicenseDbContext db,
        string clientId,
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        Guid seatId,
        string grantRefDigestSha256,
        string hardwareIdHash,
        IReadOnlyDictionary<string, string> binaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var binding = db.Database.IsNpgsql()
            ? await db.DistributionInstallationBindings.FromSqlInterpolated($"""
                SELECT * FROM public."DistributionInstallationBindings"
                WHERE "ProductId" = {request.ProductId}
                  AND "InstallationId" = {request.InstallationId}
                FOR UPDATE
                """).SingleAsync(cancellationToken)
            : await db.DistributionInstallationBindings.SingleAsync(candidate =>
                candidate.ProductId == request.ProductId
                && candidate.InstallationId == request.InstallationId, cancellationToken);

        var previousEntitlement = await db.DistributionEntitlements.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == binding.EntitlementId, cancellationToken);
        var finalizeOwners = await db.DistributionBindingRequests.AsNoTracking()
            .Where(candidate => candidate.BindingId == binding.Id && candidate.Operation == FinalizeOperation)
            .Select(candidate => candidate.ClientId)
            .Distinct()
            .ToListAsync(cancellationToken);
        var previousGrantOwner = await db.DistributionGrantOwnerships.AsNoTracking()
            .SingleOrDefaultAsync(candidate =>
                candidate.ProductId == binding.ProductId
                && candidate.GrantRefDigestSha256 == binding.GrantRefDigestSha256,
                cancellationToken);
        var hasSuccessor = await db.DistributionInstallationBindings.AsNoTracking().AnyAsync(
            candidate => candidate.SupersededBindingId == binding.Id,
            cancellationToken);
        var hasCompetingActiveHardwareAuthority = await db.DistributionInstallationBindings.AsNoTracking()
            .AnyAsync(candidate =>
                candidate.Id != binding.Id
                && candidate.ProductId == binding.ProductId
                && candidate.HardwareIdHash == binding.HardwareIdHash
                && candidate.State == "active",
                cancellationToken);

        var authorityFailureReason = GetCrossGenerationAuthorityFailureReason(
            clientId,
            request,
            entitlement,
            seatId,
            grantRefDigestSha256,
            hardwareIdHash,
            binding,
            previousEntitlement,
            previousGrantOwner,
            finalizeOwners,
            hasSuccessor,
            hasCompetingActiveHardwareAuthority);
        if (authorityFailureReason != null)
            throw Conflict("binding_conflict", authorityFailureReason);

        var enrollments = db.Database.IsNpgsql()
            ? await db.RuntimeEnrollments.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollments"
                WHERE "BindingId" = {binding.Id}
                  AND "State" IN ('PENDING', 'ACTIVE')
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.RuntimeEnrollments.Where(candidate =>
                    candidate.BindingId == binding.Id
                    && (candidate.State == "PENDING" || candidate.State == "ACTIVE"))
                .OrderBy(candidate => candidate.Id)
                .ToListAsync(cancellationToken);

        foreach (var enrollment in enrollments)
        {
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = now.UtcDateTime;
            enrollment.InvalidationReason = "binding_superseded";
        }

        // Recoverable invalidations describe an interrupted business transition. They may be
        // revived only after every exact same-authority check above has succeeded.
        binding.State = "active";
        binding.InvalidatedAtUtc = null;
        binding.InvalidationReason = null;
        binding.EntitlementId = entitlement.EntitlementId;
        binding.SubjectRefDigestSha256 = entitlement.SubjectRefDigestSha256;
        binding.GrantRef = request.GrantRef;
        binding.GrantRefDigestSha256 = grantRefDigestSha256;
        binding.HandoffDigestSha256 = request.HandoffDigestSha256;
        binding.HandoffIssuedAtUtc = request.HandoffIssuedAtUtc.UtcDateTime;
        binding.HandoffExpiresAtUtc = request.HandoffExpiresAtUtc.UtcDateTime;
        binding.DownloadCompletedAtUtc = request.DownloadCompletedAtUtc.UtcDateTime;
        binding.Version = request.Version;
        binding.InstallerFilename = request.InstallerFilename;
        binding.InstallerSha256 = request.InstallerSha256;
        binding.ExecutableSha256 = binaries["FP_EXE"];
        binding.NativeDllSha256 = binaries["FP_DLL"];
        binding.CoreSha256 = binaries["FP_CORE"];
        binding.ApprovedBinariesSource = ApprovedBinaryService.ReleaseSource;
        binding.BoundAtUtc = now.UtcDateTime;
        return new CrossGenerationRotation(binding, enrollments);
    }

    /// <summary>
    /// Identifies the first bounded reason why an existing installation cannot be rotated to
    /// a newer distribution generation owned by the same authority.
    /// </summary>
    /// <param name="clientId">The exact authenticated S2S client identifier.</param>
    /// <param name="request">The validated finalize request for the candidate generation.</param>
    /// <param name="entitlement">The validated entitlement carried by the candidate request.</param>
    /// <param name="seatId">The exact seat selected for the candidate authority.</param>
    /// <param name="grantRefDigestSha256">The exact candidate grant digest.</param>
    /// <param name="hardwareIdHash">The exact candidate hardware digest.</param>
    /// <param name="binding">The locked binding for the reused installation identifier.</param>
    /// <param name="previousEntitlement">The entitlement referenced by the locked binding.</param>
    /// <param name="previousGrantOwner">The registered owner of the binding grant.</param>
    /// <param name="finalizeOwners">The distinct clients that finalized the locked binding.</param>
    /// <param name="hasSuccessor">Whether the locked binding already has a successor generation.</param>
    /// <param name="hasCompetingActiveHardwareAuthority">
    /// Whether another active binding already owns the same product and hardware authority.
    /// </param>
    /// <returns>
    /// A stable ASCII reason code containing no customer or authority value, or <see langword="null"/>
    /// when every existing same-authority invariant is satisfied.
    /// </returns>
    /// <remarks>
    /// The checks deliberately preserve the former conjunction order and exact string semantics.
    /// These codes are intended only for the authenticated Website S2S diagnostic boundary. They
    /// do not weaken authorization and must not be rendered as detailed public client messages.
    /// </remarks>
    private static string? GetCrossGenerationAuthorityFailureReason(
        string clientId,
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        Guid seatId,
        string grantRefDigestSha256,
        string hardwareIdHash,
        DistributionInstallationBinding binding,
        DistributionEntitlement? previousEntitlement,
        DistributionGrantOwnership? previousGrantOwner,
        IReadOnlyList<string> finalizeOwners,
        bool hasSuccessor,
        bool hasCompetingActiveHardwareAuthority)
    {
        if (!IsModernEntitlementContractVersion(entitlement.ContractVersion)
            || entitlement.SubjectRefDigestSha256 is not { Length: 64 })
            return "cross_generation_candidate_entitlement_invalid";
        if (previousEntitlement is not { State: "finalized", SubjectRefDigestSha256.Length: 64 }
            || !IsModernEntitlementContractVersion(previousEntitlement.ContractVersion))
            return "cross_generation_previous_entitlement_invalid";
        if (binding.State != "active"
            && !RuntimeAuthorityTransitionResolver.IsRecoverableBinding(
                binding.State,
                binding.InvalidationReason))
            return "cross_generation_binding_inactive";
        if (hasSuccessor || hasCompetingActiveHardwareAuthority)
            return "cross_generation_binding_inactive";
        if (binding.ProductId != request.ProductId)
            return "cross_generation_product_mismatch";
        if (binding.LicenseId != entitlement.LicenseId)
            return "cross_generation_license_mismatch";
        if (binding.LicenseSeatId != seatId)
            return "cross_generation_seat_mismatch";
        if (binding.HardwareIdHash != hardwareIdHash)
            return "cross_generation_hardware_mismatch";
        if (binding.SubjectRefDigestSha256 != entitlement.SubjectRefDigestSha256)
            return "cross_generation_subject_mismatch";
        if (previousEntitlement.Id != binding.EntitlementId)
            return "cross_generation_entitlement_reference_mismatch";
        if (previousEntitlement.ClientId != clientId)
            return "cross_generation_entitlement_client_mismatch";
        if (previousEntitlement.ProductId != binding.ProductId)
            return "cross_generation_entitlement_product_mismatch";
        if (previousEntitlement.LicenseId != binding.LicenseId)
            return "cross_generation_entitlement_license_mismatch";
        if (previousEntitlement.GrantRefDigestSha256 != binding.GrantRefDigestSha256)
            return "cross_generation_entitlement_grant_mismatch";
        if (previousEntitlement.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256)
            return "cross_generation_entitlement_subject_mismatch";
        if (previousGrantOwner == null || previousGrantOwner.ClientId != clientId
            || !IsMatchingModernIssueSource(previousEntitlement.ContractVersion, previousGrantOwner.Source))
            return "cross_generation_grant_owner_mismatch";
        if (finalizeOwners.Count != 1 || finalizeOwners[0] != clientId)
            return "cross_generation_finalize_owner_mismatch";
        if (binding.GrantRefDigestSha256 != Sha256(binding.GrantRef))
            return "cross_generation_binding_grant_invalid";
        if (binding.GrantRefDigestSha256 == grantRefDigestSha256)
            return "cross_generation_grant_reused";
        if (!binding.HandoffIssuedAtUtc.HasValue)
            return "cross_generation_previous_handoff_missing";
        if (request.HandoffIssuedAtUtc.UtcDateTime <= binding.HandoffIssuedAtUtc.Value)
            return "cross_generation_handoff_not_newer";
        if (IsVersionBelow(request.Version, binding.Version))
            return "cross_generation_version_regression";
        return null;
    }

    /// <summary>
    /// Reads complete terminal generations under the caller's Runtime global lock. The result
    /// selects candidates only; Finalize rechecks client/grant ownership, security and identity
    /// under row locks before creating a successor. No bare reason changes the global matrix.
    /// </summary>
    private static async Task<HashSet<Guid>> FindCoherentSeatReleasesAsync(
        LicenseDbContext db, IReadOnlyList<DistributionInstallationBinding> bindings,
        DateTime now, CancellationToken cancellationToken)
    {
        var released = bindings.Where(binding => binding.State == "invalidated"
            && binding.InvalidationReason == SeatRuntimeReleaseAuthority.Reason).ToList();
        if (released.Count == 0) return [];
        var ids = released.Select(binding => binding.Id).ToList();
        var enrollments = await db.RuntimeEnrollments.AsNoTracking()
            .Where(enrollment => ids.Contains(enrollment.BindingId)).ToListAsync(cancellationToken);
        return released.Where(binding => RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
                binding, enrollments.Where(enrollment => enrollment.BindingId == binding.Id).ToList(), now))
            .Select(binding => binding.Id).ToHashSet();
    }

    /// <summary>
    /// Bounded, identifier-safe facts of the first target-license history node that is not in a
    /// released state (TKT-001221). Only internal UUIDs, states, reasons and counts are carried: no
    /// hardware identifier or digest. Logged under <c>TEMP-FAIL-OPEN(TKT-001221)</c> for later repair.
    /// </summary>
    /// <param name="Code">Stable divergence code.</param>
    /// <param name="BindingId">Internal UUID of the divergent binding.</param>
    /// <param name="SeatId">Internal UUID of the seat referenced by that binding.</param>
    /// <param name="BindingState">Persisted binding state.</param>
    /// <param name="BindingReason">Persisted binding invalidation reason, if any.</param>
    /// <param name="SuccessorCount">Number of bindings superseding it.</param>
    /// <param name="SeatActive">Whether the seat is active, or null when the seat is missing.</param>
    /// <param name="SeatUnlinked">Whether the seat has <c>UnlinkedAt</c>, or null when missing.</param>
    /// <param name="EnrollmentCount">Number of enrollments persisted for the binding.</param>
    /// <param name="EnrollmentStates">Distinct, ordinally sorted, comma-separated enrollment states.</param>
    /// <param name="EnrollmentReasons">Distinct, ordinally sorted, comma-separated invalidation reasons.</param>
    /// <param name="HistoryCount">Total persisted target-license bindings inspected.</param>
    private sealed record TargetLicenseHistoryDivergence(
        string Code,
        Guid BindingId,
        Guid SeatId,
        string BindingState,
        string? BindingReason,
        int SuccessorCount,
        bool? SeatActive,
        bool? SeatUnlinked,
        int EnrollmentCount,
        string EnrollmentStates,
        string EnrollmentReasons,
        int HistoryCount);

    /// <summary>
    /// Enrollment terminal reasons that a closed, released target-license history may carry.
    /// Any other reason is reported as a logged, non-blocking divergence. Values are exact persisted
    /// protocol codes compared ordinally.
    /// </summary>
    private static readonly HashSet<string> ReleasedHistoryEnrollmentReasons = new(StringComparer.Ordinal)
    {
        "authority_ineligible",
        "binding_ineligible",
        "binding_superseded",
        "challenge_expired",
        SeatRuntimeReleaseAuthority.Reason,
        "version_ineligible"
    };

    /// <summary>
    /// TEMP-FAIL-OPEN(TKT-001221): the caller currently only logs the returned divergence; the
    /// target is a correct, blocking decision once the logged cases are understood and repaired.
    /// Classifies the target-license history before a fresh hardware receives an initial binding
    /// while v4 candidates are present (TKT-001221, SUP-000027). The history is released when every
    /// persisted target-license binding is either:
    /// <list type="bullet">
    /// <item>active on an active seat of the same license, a live installation already counted by the seat quota;</item>
    /// <item>an interior <c>installation_superseded</c> or coherent <c>seat_released</c> node with exactly one
    /// successor of the same product, license and subject, bound no earlier than its predecessor ended;</item>
    /// <item>a coherent <c>seat_released</c> leaf whose seat is inactive and explicitly unlinked.</item>
    /// </list>
    /// Edges entering the subgraph from another license are accepted: renewals start there. An edge
    /// leaving the target license, a fork, an orphan, a live or security-terminal enrollment, an unknown
    /// reason, a historical security terminal or an inactive seat without <c>UnlinkedAt</c> is a
    /// divergence: the caller logs its bounded code and proceeds. Seat quota, active bans,
    /// entitlement and release checks still run afterwards.
    /// </summary>
    /// <param name="db">The Finalize transaction context holding the Runtime authority locks.</param>
    /// <param name="productId">The exact target product.</param>
    /// <param name="licenseId">The exact target license.</param>
    /// <param name="targetSeatId">The seat that will receive the initial binding; any history on it refuses.</param>
    /// <param name="now">The authoritative database-aligned decision time.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <returns><see langword="null"/> for a released history, otherwise the first bounded divergence.</returns>
    private static async Task<TargetLicenseHistoryDivergence?> FindTargetLicenseHistoryDivergenceAsync(
        LicenseDbContext db,
        Guid productId,
        Guid licenseId,
        Guid targetSeatId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var history = await db.DistributionInstallationBindings.AsNoTracking()
            .Where(candidate => candidate.ProductId == productId && candidate.LicenseId == licenseId)
            .ToListAsync(cancellationToken);
        if (history.Count == 0) return null;

        var ids = history.Select(candidate => candidate.Id).ToList();
        var successors = await db.DistributionInstallationBindings.AsNoTracking()
            .Where(candidate => candidate.SupersededBindingId != null && ids.Contains(candidate.SupersededBindingId.Value))
            .ToListAsync(cancellationToken);
        var enrollments = await db.RuntimeEnrollments.AsNoTracking()
            .Where(candidate => ids.Contains(candidate.BindingId))
            .ToListAsync(cancellationToken);
        var seatIds = history.Select(candidate => candidate.LicenseSeatId).Distinct().ToList();
        var seats = await db.LicenseSeats.AsNoTracking()
            .Where(candidate => seatIds.Contains(candidate.Id))
            .ToDictionaryAsync(candidate => candidate.Id, cancellationToken);

        foreach (var binding in history)
        {
            var bindingEnrollments = enrollments.Where(candidate => candidate.BindingId == binding.Id).ToList();
            var next = successors.Where(candidate => candidate.SupersededBindingId == binding.Id).ToList();
            seats.TryGetValue(binding.LicenseSeatId, out var observedSeat);
            TargetLicenseHistoryDivergence Divergence(string code) => new(
                code,
                binding.Id,
                binding.LicenseSeatId,
                binding.State,
                binding.InvalidationReason,
                next.Count,
                observedSeat?.IsActive,
                observedSeat == null ? null : observedSeat.UnlinkedAt != null,
                bindingEnrollments.Count,
                string.Join(',', bindingEnrollments.Select(item => item.State)
                    .Distinct(StringComparer.Ordinal).OrderBy(item => item, StringComparer.Ordinal)),
                string.Join(',', bindingEnrollments.Select(item => item.InvalidationReason ?? "none")
                    .Distinct(StringComparer.Ordinal).OrderBy(item => item, StringComparer.Ordinal)),
                history.Count);
            if (binding.InvalidationReason?.StartsWith("security", StringComparison.Ordinal) == true
                || enrollments.Any(candidate => candidate.BindingId == binding.Id
                    && candidate.InvalidationReason?.StartsWith("security", StringComparison.Ordinal) == true))
                return Divergence("security_terminal_history");
            if (binding.LicenseSeatId == targetSeatId
                || !seats.TryGetValue(binding.LicenseSeatId, out var bindingSeat)
                || bindingSeat.LicenseId != licenseId)
                return Divergence("seat_mismatch");

            if (binding.State == "active")
            {
                if (!bindingSeat.IsActive || binding.InvalidationReason != null) return Divergence("active_binding_on_inactive_seat");
                continue;
            }
            if (binding.State != "invalidated" || !binding.InvalidatedAtUtc.HasValue
                || binding.InvalidatedAtUtc > now
                || bindingEnrollments.Any(candidate => candidate.State != RuntimeAuthorityTransitionResolver.InvalidatedState
                    || candidate.InvalidationReason is not { } reason
                    || !ReleasedHistoryEnrollmentReasons.Contains(reason)
                    || !candidate.InvalidatedAtUtc.HasValue
                    || candidate.InvalidatedAtUtc > now))
                return Divergence("terminal_state_incoherent");

            var isInstallationSuperseded = string.Equals(
                binding.InvalidationReason, "installation_superseded", StringComparison.Ordinal);
            var isCoherentRelease = string.Equals(
                    binding.InvalidationReason, SeatRuntimeReleaseAuthority.Reason, StringComparison.Ordinal)
                && RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(binding, bindingEnrollments, now);
            if (!isInstallationSuperseded && !isCoherentRelease) return Divergence("terminal_reason_unrecognized");

            if (next.Count == 1)
            {
                var successor = next[0];
                if (successor.ProductId != binding.ProductId
                    || successor.LicenseId != binding.LicenseId
                    || !string.Equals(
                        successor.SubjectRefDigestSha256, binding.SubjectRefDigestSha256, StringComparison.Ordinal)
                    || successor.BoundAtUtc < binding.InvalidatedAtUtc.Value
                    || (!bindingSeat.IsActive && bindingSeat.UnlinkedAt == null
                        && successor.LicenseSeatId != binding.LicenseSeatId))
                    return Divergence("successor_edge_incoherent");
                continue;
            }
            // A leaf must be an explicit release: a superseded node without successor is an orphan.
            if (next.Count != 0 || !isCoherentRelease
                || bindingSeat.IsActive || bindingSeat.UnlinkedAt == null)
                return Divergence("unreleased_leaf");
        }
        return null;
    }

    /// <summary>
    /// Resolves the unique previous Runtime authority after the same license was explicitly
    /// unlinked from one seat and activated on another. Historical replacement proofs belong
    /// to cross-license renewal and therefore cannot select or veto this same-license path.
    /// Successor existence is checked against the complete product history before hardware/seat
    /// eligibility can hide an edge. A successor only vetoes an obsolete source; it grants no rights.
    /// An absent source returns null for the guarded hardware fallback; competing sources still throw.
    /// The selected rows are revalidated under authority and row locks before mutation.
    /// See DevBrain DOC-324 and DOC-930 (TKT-001078).
    /// </summary>
    private static async Task<DistributionInstallationBinding?> ResolveSameLicenseSeatTransitionSourceAsync(
        LicenseDbContext db,
        Guid productId,
        Guid licenseId,
        Guid targetSeatId,
        string subjectRefDigestSha256,
        string targetHardwareIdHash,
        CancellationToken cancellationToken)
    {
        var candidates = await (
                from binding in db.DistributionInstallationBindings.AsNoTracking()
                join sourceSeat in db.LicenseSeats.AsNoTracking()
                    on binding.LicenseSeatId equals sourceSeat.Id
                where binding.ProductId == productId
                    && binding.LicenseId == licenseId
                    && binding.LicenseSeatId != targetSeatId
                    && binding.HardwareIdHash != targetHardwareIdHash
                    && binding.SubjectRefDigestSha256 == subjectRefDigestSha256
                    && sourceSeat.LicenseId == licenseId
                    && !sourceSeat.IsActive
                    && sourceSeat.UnlinkedAt != null
                    && !db.DistributionInstallationBindings.Any(successor =>
                        successor.ProductId == productId
                        && successor.SupersededBindingId == binding.Id)
                orderby binding.Id
                select binding)
            .ToListAsync(cancellationToken);
        var decision = RuntimeAuthorityTransitionResolver.ResolveBinding(
            candidates.Select(candidate => new RuntimeAuthorityBindingSnapshot(
                    candidate.Id,
                    candidate.SupersededBindingId,
                    candidate.State,
                    candidate.InvalidationReason,
                    IsAuthorizedCandidate: true))
                .ToList());
        if (decision.Kind == RuntimeAuthorityBindingDecisionKind.RejectAmbiguous)
            throw Conflict("binding_conflict", "same_license_seat_transition_ambiguous");
        return decision.BindingId.HasValue
            ? candidates.Single(candidate => candidate.Id == decision.BindingId.Value)
            : null;
    }

    /// <summary>
    /// Revalidates and supersedes one persisted Runtime authority inside the caller's binding transaction.
    /// </summary>
    /// <param name="db">The transaction-scoped database context.</param>
    /// <param name="clientId">The exact Distribution S2S owner.</param>
    /// <param name="sourceBindingId">The unique binding selected from authoritative server history.</param>
    /// <param name="requireExactRecoverableEnrollment">
    /// Requires the exact source binding to have either one active enrollment or one business-terminal
    /// enrollment whose reason is <c>authority_ineligible</c>, or one fully matched released
    /// generation. The latter never reactivates its old credential (TKT-000998).
    /// </param>
    /// <param name="authenticatedAliasSource">
    /// Allows only the exact source binding selected by a server-authenticated alias to retain its
    /// immutable legacy copied digest while the target seat uses the canonical hardware identifier.
    /// </param>
    /// <param name="allowUnengagedAliasSuccessor">
    /// Permits an authenticated alias path to advance an already-created successor that never
    /// reached Runtime enrollment. Every binding, entitlement, ownership, seat, release and
    /// incident predicate remains mandatory; a bare historical binding cannot enable this path.
    /// </param>
    /// <param name="replacement">The optional exact cross-license replacement proof.</param>
    /// <param name="legacyReplacement">
    /// The optional Website licence-pair assertion for a server-derived grantless legacy source.
    /// </param>
    /// <param name="request">The validated fresh finalize request.</param>
    /// <param name="entitlement">The authoritative target entitlement.</param>
    /// <param name="seatId">The authoritative active target seat.</param>
    /// <param name="grantRefDigestSha256">The exact target grant digest.</param>
    /// <param name="hardwareIdHash">The exact target hardware digest.</param>
    /// <param name="binaries">The validated approved-binary evidence keyed by canonical component code.</param>
    /// <param name="now">The authoritative operation time.</param>
    /// <param name="cancellationToken">Cancels the operation before commit.</param>
    /// <returns>The fresh successor and any live source enrollments terminalized by the transition.</returns>
    /// <remarks>
    /// Existing target seats are read under the original row lock. A server-created target seat
    /// not yet persisted is resolved only by its exact ID and Added state in this transaction's
    /// context; it still undergoes every authority check below. An authenticated alias may also
    /// advance its active successor when that successor has no Runtime enrollment; this preserves
    /// the unique chain after a client disappears between Finalize and Prepare. No early save is introduced.
    /// </remarks>
    /// <exception cref="DistributionOperationException">
    /// Thrown when ownership, history, security, freshness or exact-authority checks fail closed.
    /// An exact-authority refusal emits bounded internal predicate diagnostics keyed by request ID;
    /// neither the diagnostic output nor a failing logging provider changes the refusal contract.
    /// </exception>
    private async Task<CrossGenerationRotation> RecoverSameAuthorityInstallationAsync(
        LicenseDbContext db,
        string clientId,
        Guid sourceBindingId,
        bool requireExactRecoverableEnrollment,
        bool authenticatedAliasSource,
        bool allowUnengagedAliasSuccessor,
        LicenseReplacementValidated? replacement,
        LegacyLicenseReplacementValidated? legacyReplacement,
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        Guid seatId,
        string grantRefDigestSha256,
        string hardwareIdHash,
        IReadOnlyDictionary<string, string> binaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var source = db.Database.IsNpgsql()
            ? await db.DistributionInstallationBindings.FromSqlInterpolated($"""
                SELECT * FROM public."DistributionInstallationBindings"
                WHERE "Id" = {sourceBindingId}
                FOR UPDATE
                """).SingleAsync(cancellationToken)
            : await db.DistributionInstallationBindings.SingleAsync(
                candidate => candidate.Id == sourceBindingId, cancellationToken);

        var previousEntitlement = await db.DistributionEntitlements.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == source.EntitlementId, cancellationToken);
        var finalizeOwners = await db.DistributionBindingRequests.AsNoTracking()
            .Where(candidate => candidate.BindingId == source.Id && candidate.Operation == FinalizeOperation)
            .Select(candidate => candidate.ClientId)
            .Distinct()
            .ToListAsync(cancellationToken);
        var previousGrantOwner = await db.DistributionGrantOwnerships.AsNoTracking()
            .SingleOrDefaultAsync(candidate =>
                candidate.ProductId == source.ProductId
                && candidate.GrantRefDigestSha256 == source.GrantRefDigestSha256,
                cancellationToken);

        var sourceLicense = replacement == null && legacyReplacement == null
            ? null
            : await db.Licenses.AsNoTracking().SingleOrDefaultAsync(candidate =>
                candidate.Id == source.LicenseId
                && candidate.ProductId == source.ProductId,
                cancellationToken);
        var sourceSeat = db.Database.IsNpgsql()
            ? await db.LicenseSeats.FromSqlInterpolated($"""
                SELECT * FROM public."LicenseSeats"
                WHERE "Id" = {source.LicenseSeatId}
                FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken)
            : await db.LicenseSeats.SingleOrDefaultAsync(
                candidate => candidate.Id == source.LicenseSeatId, cancellationToken);
        var targetSeat = db.Database.IsNpgsql()
            ? await db.LicenseSeats.FromSqlInterpolated($"""
                SELECT * FROM public."LicenseSeats"
                WHERE "Id" = {seatId}
                FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken)
            : await db.LicenseSeats.SingleOrDefaultAsync(
                candidate => candidate.Id == seatId, cancellationToken);
        // EnsureInitialSeatAsync can have created this exact seat after quota/authority checks
        // without saving it yet. Queries do not return Added entities. Reuse only that pending
        // server-owned seat; keep persisted-row locking and the caller's atomic save/rollback.
        targetSeat ??= db.ChangeTracker.Entries<LicenseSeat>()
            .Where(entry => entry.State == EntityState.Added && entry.Entity.Id == seatId)
            .Select(entry => entry.Entity)
            .SingleOrDefault();
        var exactSameLicenseAuthority = source.LicenseId == entitlement.LicenseId
            && source.LicenseSeatId == seatId
            && source.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256;
        var exactSameLicenseSeatTransition = replacement == null
            && source.LicenseId == entitlement.LicenseId
            && source.LicenseSeatId != seatId
            && source.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256
            && source.HardwareIdHash != hardwareIdHash
            && sourceSeat != null
            && sourceSeat.LicenseId == source.LicenseId
            && !sourceSeat.IsActive
            && sourceSeat.UnlinkedAt != null
            && Sha256(sourceSeat.HardwareId) == source.HardwareIdHash
            && targetSeat != null
            && targetSeat.LicenseId == entitlement.LicenseId
            && targetSeat.IsActive
            && string.Equals(targetSeat.HardwareId, request.HardwareId, StringComparison.Ordinal)
            && Sha256(targetSeat.HardwareId) == hardwareIdHash;
        var exactRenewalAuthority = replacement != null
            && replacement.SourceBindingId == source.Id
            && replacement.SourceLicenseId == source.LicenseId
            && replacement.SourceSubjectRefDigestSha256 == source.SubjectRefDigestSha256
            && source.LicenseId != entitlement.LicenseId
            && source.LicenseSeatId != seatId
            && sourceLicense != null
            && IsReplacementSourceIneligible(sourceLicense, now);
        var exactLegacyRenewalAuthority = legacyReplacement != null
            && legacyReplacement.SourceLicenseId == source.LicenseId
            && legacyReplacement.TargetLicenseId == entitlement.LicenseId
            && source.LicenseId != entitlement.LicenseId
            && source.LicenseSeatId != seatId
            && sourceLicense != null
            && IsReplacementSourceIneligible(sourceLicense, now);

        var modernSourceAuthority = legacyReplacement == null
            && previousEntitlement is { State: "finalized", SubjectRefDigestSha256.Length: 64 }
            && IsModernEntitlementContractVersion(previousEntitlement.ContractVersion)
            && previousEntitlement.Id == source.EntitlementId
            && previousEntitlement.ClientId == clientId
            && previousEntitlement.ProductId == source.ProductId
            && previousEntitlement.LicenseId == source.LicenseId
            && previousEntitlement.GrantRefDigestSha256 == source.GrantRefDigestSha256
            && previousEntitlement.SubjectRefDigestSha256 == source.SubjectRefDigestSha256
            && previousGrantOwner != null
            && previousGrantOwner.ClientId == clientId
            && IsMatchingModernIssueSource(previousEntitlement.ContractVersion, previousGrantOwner.Source);
        var grantlessSourceAuthority = legacyReplacement != null
            && previousEntitlement == null
            && previousGrantOwner == null;

        var enrollments = db.Database.IsNpgsql()
            ? await db.RuntimeEnrollments.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeEnrollments"
                WHERE "BindingId" = {source.Id}
                ORDER BY "Id" FOR UPDATE
                """).ToListAsync(cancellationToken)
            : await db.RuntimeEnrollments.Where(candidate => candidate.BindingId == source.Id)
                .OrderBy(candidate => candidate.Id)
                .ToListAsync(cancellationToken);
        var coherentSeatRelease = RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
            source, enrollments, now.UtcDateTime);
        // Alias repointing deliberately waits for Confirm. A new WebSetup can therefore observe the
        // already-created active successor through the alias graph before that successor owns an
        // enrollment. Treat only that exact provider-authenticated gap as replaceable; every other
        // missing enrollment remains ambiguous and fails closed.
        var isUnengagedAliasSuccessor = allowUnengagedAliasSuccessor
            && source.State == "active"
            && source.SupersededBindingId.HasValue
            && enrollments.Count == 0;

        var sameAuthority = IsModernEntitlementContractVersion(entitlement.ContractVersion)
            && entitlement.SubjectRefDigestSha256 is { Length: 64 }
            && (coherentSeatRelease
                || RuntimeAuthorityTransitionResolver.IsRecoverableBinding(source.State, source.InvalidationReason))
            && source.ProductId == request.ProductId
            && (exactSameLicenseAuthority
                || exactSameLicenseSeatTransition
                || exactRenewalAuthority
                || exactLegacyRenewalAuthority)
            && source.InstallationId != request.InstallationId
            && (source.HardwareIdHash == hardwareIdHash
                || exactSameLicenseSeatTransition
                || authenticatedAliasSource)
            && (modernSourceAuthority || grantlessSourceAuthority)
            && finalizeOwners.Count == 1
            && finalizeOwners[0] == clientId
            && source.GrantRefDigestSha256 == Sha256(source.GrantRef)
            && source.GrantRefDigestSha256 != grantRefDigestSha256
            && source.HandoffIssuedAtUtc.HasValue
            && request.HandoffIssuedAtUtc.UtcDateTime > source.HandoffIssuedAtUtc.Value
            && !IsVersionBelow(request.Version, source.Version);
        if (!sameAuthority)
        {
            // Diagnose the already-made refusal; logging must never become an authority decision.
            WriteSameAuthorityRefusalDiagnostics(
                clientId, source, replacement, legacyReplacement, request, entitlement, seatId,
                grantRefDigestSha256, hardwareIdHash, previousEntitlement, previousGrantOwner,
                sourceLicense, sourceSeat, targetSeat, finalizeOwners, now);
            throw Conflict("binding_conflict", replacement == null && legacyReplacement == null
                ? "same_authority_mismatch"
                : "replacement_source_authority_mismatch");
        }

        if (await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(
                incident => incident.BindingId == source.Id && incident.State == "OPEN",
                cancellationToken))
        {
            throw Conflict("binding_conflict", "replacement_source_incident");
        }
        if (isUnengagedAliasSuccessor)
        {
            _logger.LogInformation(
                "Finalize request {RequestId} advances unengaged alias successor {SourceBindingId}; the binding passed exact authority checks and has no Runtime enrollment.",
                request.RequestId,
                source.Id);
        }

        var enrollmentDecision = isUnengagedAliasSuccessor || coherentSeatRelease
            ? RuntimeAuthorityEnrollmentDecision.UseBusinessTerminal
            : RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
            enrollments.Select(candidate => new RuntimeAuthorityEnrollmentSnapshot(
                    candidate.State,
                    candidate.InvalidationReason,
                    candidate.ChallengeExpiresAtUtc,
                    candidate.ChallengeConsumedAtUtc,
                    candidate.ActivatedAtUtc,
                    candidate.InvalidatedAtUtc))
                .ToList(),
            now.UtcDateTime);
        if (enrollmentDecision is RuntimeAuthorityEnrollmentDecision.RejectAmbiguous)
            throw Conflict("binding_conflict", "replacement_enrollment_ambiguous");
        if (enrollmentDecision is RuntimeAuthorityEnrollmentDecision.RejectSecurity)
            throw Conflict("binding_conflict", "replacement_enrollment_security_terminal");
        var isExactActiveEnrollment = enrollmentDecision == RuntimeAuthorityEnrollmentDecision.UseActive
            && enrollments.Count == 1;
        var isExactRecoverableExecutionTerminal =
            enrollmentDecision == RuntimeAuthorityEnrollmentDecision.UseBusinessTerminal
            && enrollments.Count == 1
            && enrollments[0].InvalidationReason is "authority_ineligible" or "version_ineligible";
        if (requireExactRecoverableEnrollment
            && !isExactActiveEnrollment
            && !isExactRecoverableExecutionTerminal
            && !coherentSeatRelease
            && !isUnengagedAliasSuccessor)
        {
            throw Conflict("binding_conflict", "same_authority_active_enrollment_mismatch");
        }

        RuntimeEnrollment? sourceEnrollment = null;
        if (!isUnengagedAliasSuccessor)
        {
            sourceEnrollment = enrollmentDecision == RuntimeAuthorityEnrollmentDecision.UseActive
                ? enrollments.Single(candidate => candidate.State == RuntimeAuthorityTransitionResolver.ActiveState)
                : enrollments.Single();
            if (!EnrollmentMatchesBinding(sourceEnrollment, source, clientId))
                throw Conflict("binding_conflict");
        }

        var initialSecurityEpoch = isUnengagedAliasSuccessor
            ? checked(source.InitialSecurityEpoch + 1)
            : checked(enrollments.Max(candidate => candidate.SecurityEpoch) + 1);
        IReadOnlyList<RuntimeEnrollment> enrollmentsToInvalidate =
            enrollmentDecision == RuntimeAuthorityEnrollmentDecision.UseActive
                ? [sourceEnrollment!]
                : Array.Empty<RuntimeEnrollment>();
        foreach (var enrollment in enrollmentsToInvalidate)
        {
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = now.UtcDateTime;
            enrollment.InvalidationReason = "binding_superseded";
        }
        if (source.State == "active")
        {
            source.State = "invalidated";
            source.InvalidatedAtUtc = now.UtcDateTime;
            source.InvalidationReason = "installation_superseded";
        }

        // Free the active-HWID uniqueness slot before inserting the successor in this transaction.
        await db.SaveChangesAsync(cancellationToken);

        var successor = CreateBinding(
            request, entitlement, seatId, grantRefDigestSha256, hardwareIdHash, binaries, now,
            source.Id, initialSecurityEpoch);
        db.DistributionInstallationBindings.Add(successor);
        return new CrossGenerationRotation(successor, enrollmentsToInvalidate);
    }

    private static bool IsReplacementSourceIneligible(License license, DateTimeOffset now) =>
        !license.IsActive
        || license.RevokedAt != null
        || (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now.UtcDateTime);

    private static DistributionInstallationBinding CreateBinding(
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        Guid seatId,
        string grantRefDigestSha256,
        string hardwareIdHash,
        IReadOnlyDictionary<string, string> binaries,
        DateTimeOffset now,
        Guid? supersededBindingId,
        int initialSecurityEpoch) => new()
    {
        ProductId = request.ProductId,
        LicenseId = entitlement.LicenseId,
        LicenseSeatId = seatId,
        EntitlementId = entitlement.EntitlementId,
        SubjectRefDigestSha256 = entitlement.SubjectRefDigestSha256,
        GrantRef = request.GrantRef,
        GrantRefDigestSha256 = grantRefDigestSha256,
        HandoffDigestSha256 = request.HandoffDigestSha256,
        HandoffIssuedAtUtc = request.HandoffIssuedAtUtc.UtcDateTime,
        HandoffExpiresAtUtc = request.HandoffExpiresAtUtc.UtcDateTime,
        DownloadCompletedAtUtc = request.DownloadCompletedAtUtc.UtcDateTime,
        InstallationId = request.InstallationId,
        HardwareIdHash = hardwareIdHash,
        Version = request.Version,
        InstallerFilename = request.InstallerFilename,
        InstallerSha256 = request.InstallerSha256,
        ExecutableSha256 = binaries["FP_EXE"],
        NativeDllSha256 = binaries["FP_DLL"],
        CoreSha256 = binaries["FP_CORE"],
        ApprovedBinariesSource = ApprovedBinaryService.ReleaseSource,
        State = "active",
        BoundAtUtc = now.UtcDateTime,
        SupersededBindingId = supersededBindingId,
        InitialSecurityEpoch = initialSecurityEpoch
    };

    private static async Task<bool> HasActiveSecurityBanAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        string hardwareId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var hardwareBans = await db.BannedHardwareIds.AsNoTracking()
            .Where(ban => ban.IsActive
                && (ban.ProductId == null || ban.ProductId == binding.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => ban.HardwareId)
            .ToListAsync(cancellationToken);
        if (hardwareBans.Any(candidate => string.Equals(candidate, hardwareId, StringComparison.OrdinalIgnoreCase)))
            return true;

        var componentBans = await db.BannedComponents.AsNoTracking()
            .Where(ban => ban.IsActive
                && (ban.ProductId == null || ban.ProductId == binding.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime))
            .Select(ban => new { ban.ComponentType, ban.ComponentHash })
            .ToListAsync(cancellationToken);
        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FP_EXE"] = binding.ExecutableSha256,
            ["FP_DLL"] = binding.NativeDllSha256,
            ["FP_CORE"] = binding.CoreSha256
        };
        return componentBans.Any(ban => evidence.Any(binary =>
            string.Equals(binary.Key, ban.ComponentType, StringComparison.OrdinalIgnoreCase)
            && string.Equals(
                binary.Value,
                ApprovedBinaryService.NormalizeSha256(ban.ComponentHash),
                StringComparison.Ordinal)));
    }

    private static async Task<bool> HasMatchingReleaseBaselineAsync(
        LicenseDbContext db,
        DistributionInstallationBinding binding,
        CancellationToken cancellationToken)
    {
        var rows = await db.ApprovedBinaries.AsNoTracking()
            .Where(row => row.ProductId == binding.ProductId && row.Version == binding.Version)
            .ToListAsync(cancellationToken);
        if (rows.Count != RequiredBinaryKeys.Length
            || rows.Any(row => !string.Equals(row.Source, ApprovedBinaryService.ReleaseSource, StringComparison.Ordinal)))
            return false;
        var expected = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FP_EXE"] = binding.ExecutableSha256,
            ["FP_DLL"] = binding.NativeDllSha256,
            ["FP_CORE"] = binding.CoreSha256
        };
        return rows.Count == expected.Count
            && rows.All(row => expected.TryGetValue(row.Key, out var hash)
                && string.Equals(row.Hash, hash, StringComparison.Ordinal));
    }

    private static async Task ValidateGrantOwnershipAsync(
        LicenseDbContext db,
        string clientId,
        Guid productId,
        string grantRefDigestSha256,
        CancellationToken cancellationToken)
    {
        var owner = await db.DistributionGrantOwnerships.AsNoTracking()
            .SingleOrDefaultAsync(candidate =>
                candidate.ProductId == productId
                && candidate.GrantRefDigestSha256 == grantRefDigestSha256,
                cancellationToken);
        if (owner == null
            || !string.Equals(owner.ClientId, clientId, StringComparison.Ordinal))
        {
            throw Conflict("grant_ownership_mismatch");
        }
    }

    /// <summary>
    /// Requires pre-issued grants to retain the exact issue source for their entitlement contract,
    /// while preserving finalize-v1 ownership creation for the grantless legacy path.
    /// </summary>
    private static async Task EnsureGrantOwnershipForFinalizeAsync(
        LicenseDbContext db,
        string clientId,
        Guid productId,
        string grantRefDigestSha256,
        int contractVersion,
        bool requiresPreexistingOwnership,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var owner = await db.DistributionGrantOwnerships.AsNoTracking()
            .SingleOrDefaultAsync(candidate =>
                candidate.ProductId == productId
                && candidate.GrantRefDigestSha256 == grantRefDigestSha256,
                cancellationToken);
        if (owner != null)
        {
            if (!string.Equals(owner.ClientId, clientId, StringComparison.Ordinal)
                || !IsMatchingIssueSource(contractVersion, owner.Source))
                throw Conflict("grant_ownership_mismatch");
            return;
        }
        if (requiresPreexistingOwnership)
            throw Conflict("grant_ownership_mismatch");
        db.DistributionGrantOwnerships.Add(new DistributionGrantOwnership
        {
            ProductId = productId,
            GrantRefDigestSha256 = grantRefDigestSha256,
            ClientId = clientId,
            Source = "finalize_v1",
            CreatedAtUtc = now.UtcDateTime
        });
    }

    private static DistributionInstallationBindingResponse ToResponse(DistributionInstallationBinding binding) =>
        new(
            BindingResponseSchema,
            binding.Id.ToString("D"),
            binding.State,
            binding.InstallationId,
            binding.HardwareIdHash,
            binding.Version,
            binding.ApprovedBinariesSource,
            FormatUtc(new DateTimeOffset(DateTime.SpecifyKind(binding.BoundAtUtc, DateTimeKind.Utc))),
            binding.InvalidatedAtUtc.HasValue
                ? FormatUtc(new DateTimeOffset(DateTime.SpecifyKind(binding.InvalidatedAtUtc.Value, DateTimeKind.Utc)))
                : null);

    private static async Task<T?> FindExistingAsync<T>(
        LicenseDbContext db,
        string clientId,
        string requestId,
        string operation,
        string digest,
        CancellationToken cancellationToken)
    {
        var existing = await db.DistributionBindingRequests.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.ClientId == clientId && candidate.RequestId == requestId, cancellationToken);
        if (existing == null)
            return default;
        if (existing.Operation != operation || existing.PayloadDigest != digest)
            throw Conflict("idempotency_conflict");
        try
        {
            return JsonSerializer.Deserialize<T>(existing.ResponseJson, JsonOptions)
                ?? throw new JsonException("Stored response was empty.");
        }
        catch (JsonException)
        {
            throw new DistributionOperationException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        }
    }

    private async Task<T> ReloadConcurrentAsync<T>(
        string clientId,
        string requestId,
        string operation,
        string digest,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            await using var retryDb = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var existing = await FindExistingAsync<T>(
                retryDb, clientId, requestId, operation, digest, cancellationToken);
            if (existing != null)
                return existing;
            if (attempt < 4)
                await Task.Delay(TimeSpan.FromMilliseconds(25 * (attempt + 1)), cancellationToken);
        }
        throw Conflict("binding_conflict");
    }

    private static bool IsRetryableWriteFailure(Exception exception, LicenseDbContext db)
    {
        if (!db.Database.IsNpgsql())
            return exception is DbUpdateException;

        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is PostgresException postgresException
                && IsRetryablePostgresSqlState(postgresException.SqlState))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsRetryablePostgresSqlState(string? sqlState) =>
        sqlState is PostgresErrorCodes.UniqueViolation or PostgresErrorCodes.SerializationFailure;

    private static async Task TryRollbackAsync(
        IDbContextTransaction? transaction,
        CancellationToken cancellationToken)
    {
        if (transaction == null)
            return;
        try
        {
            await transaction.RollbackAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is DbException or InvalidOperationException)
        {
            // The transaction may already have been aborted by PostgreSQL. The original
            // classified conflict remains authoritative and is reloaded below.
        }
    }

    private static async Task<IDbContextTransaction?> BeginSerializableAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken) =>
        db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            : null;

    private static async Task<IDbContextTransaction?> BeginBindingAuthorityTransactionAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken) =>
        db.Database.IsRelational()
            // The PostgreSQL advisory lock is the serialization primitive for a grant.
            // READ COMMITTED is intentional: a waiter must take a fresh snapshot after
            // acquiring the lock and observe the preceding issue/finalize/invalidation commit.
            ? await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            : null;

    private static async Task AcquireBindingAuthorityLockAsync(
        LicenseDbContext db,
        Guid productId,
        string grantRefDigestSha256,
        CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql())
            return;
        var lockName = $"distribution-binding:{productId:D}:{grantRefDigestSha256}";
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({lockName}, 0))",
            cancellationToken);
    }

    private static async Task AcquireInstallationAuthorityLockAsync(
        LicenseDbContext db,
        Guid productId,
        string installationId,
        CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql())
            return;
        var lockName = $"distribution-installation:{productId:D}:{installationId}";
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({lockName}, 0))",
            cancellationToken);
    }

    /// <summary>
    /// Acquires the exclusive Runtime authority mutation lock before all Finalize hardware locks.
    /// </summary>
    /// <param name="db">Database context whose current transaction owns the finalize mutation.</param>
    /// <param name="cancellationToken">Cancels lock acquisition while waiting for an active Runtime mutation.</param>
    /// <remarks>
    /// Signed Runtime migration takes this lock before its V2 hardware lock. Every Finalize path
    /// uses the same global order so direct V2 recovery cannot invert an alias request's order.
    /// </remarks>
    private static async Task AcquireRuntimeMutationLockAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql())
            return;
        await db.Database.ExecuteSqlRawAsync(
            "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)",
            cancellationToken);
    }

    private static async Task AcquireLicenseSeatLockAsync(
        LicenseDbContext db,
        Guid licenseId,
        CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql())
            return;
        var lockName = $"distribution-license-seat:{licenseId:D}";
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({lockName}, 0))",
            cancellationToken);
    }

    private static void ValidateDigest(string digest)
    {
        if (!IsLowerSha256(digest))
            throw Invalid();
    }

    private static bool TryCanonicalUuid(string? value, out Guid parsed)
    {
        parsed = default;
        return value != null
            && LowerUuidPattern.IsMatch(value)
            && Guid.TryParseExact(value, "D", out parsed)
            && value == parsed.ToString("D");
    }

    private static bool TryCanonicalUtc(string? value, out DateTimeOffset parsed)
    {
        parsed = default;
        return value != null
            && DateTimeOffset.TryParseExact(
                value,
                UtcFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out parsed)
            && value == FormatUtc(parsed);
    }

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 }
        && ApprovedBinaryService.NormalizeSha256(value) == value;

    private static bool IsOpaqueToken(string value)
    {
        if (value.Length is < 40 or > 4096)
            return false;
        foreach (var character in value)
        {
            if (!((character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9')
                || character is '_' or '-'))
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsSafeFilename(string? value) =>
        value is { Length: > 0 and <= 200 }
        && value == value.Trim()
        && value.IndexOfAny(['/', '\\', '\0', '\r', '\n']) < 0
        && string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal);

    /// <summary>Recognizes only persisted Distribution entitlement contracts with relational authority.</summary>
    private static bool IsModernEntitlementContractVersion(int contractVersion) => contractVersion is 3 or 4;

    /// <summary>Requires the persisted grant owner source to identify the exact modern entitlement contract.</summary>
    private static bool IsMatchingModernIssueSource(int contractVersion, string source) =>
        (contractVersion == 3 && string.Equals(source, "issue_v3", StringComparison.Ordinal))
        || (contractVersion == 4 && string.Equals(source, "issue_v4", StringComparison.Ordinal));

    /// <summary>Requires the grant owner source to match the exact entitlement issue contract.</summary>
    private static bool IsMatchingIssueSource(int contractVersion, string source) =>
        (contractVersion == 2 && string.Equals(source, "issue_v2", StringComparison.Ordinal))
        || IsMatchingModernIssueSource(contractVersion, source);

    private static string Sha256(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string FormatUtc(DateTimeOffset value) =>
        value.UtcDateTime.ToString(UtcFormat, CultureInfo.InvariantCulture);

    private static DateTimeOffset ToPostgreSqlTimestampPrecision(DateTimeOffset value)
    {
        var utcTicks = value.UtcDateTime.Ticks;
        return new DateTimeOffset(
            utcTicks - utcTicks % TimeSpan.TicksPerMicrosecond,
            TimeSpan.Zero);
    }

    private static DistributionOperationException Invalid() =>
        new("invalid_request", StatusCodes.Status400BadRequest);

    private static DistributionOperationException Reject(string errorCode) =>
        new(errorCode, StatusCodes.Status422UnprocessableEntity);

    /// <summary>
    /// Emits exactly one bounded provider event before returning the compatible HTTP 422 exception.
    /// </summary>
    private DistributionOperationException RejectHardwareAuthority(
        string requestId,
        string reasonCode,
        string guard,
        HardwareAuthorityDecisionMatrix decision)
    {
        var refusal = new HardwareAuthorityRefusalEvent(reasonCode, guard, requestId, decision);
        _logger.LogWarning(
            "HardwareAuthorityRefused ReasonCode={ReasonCode} Guard={Guard} RequestId={RequestId} " +
            "AliasResolutionRefused={AliasResolutionRefused} AliasUsed={AliasUsed} " +
            "SeatReconciliationRequired={SeatReconciliationRequired} BindingIdentityPresent={BindingIdentityPresent} " +
            "SeatIdentityPresent={SeatIdentityPresent} CanonicalSeatPresent={CanonicalSeatPresent} " +
            "SingleLegacySeatPresent={SingleLegacySeatPresent} RecoverySourcePresent={RecoverySourcePresent} " +
            "RecoverySourceMatchesBinding={RecoverySourceMatchesBinding}",
            refusal.ReasonCode,
            refusal.Guard,
            refusal.RequestId,
            refusal.Decision.AliasResolutionRefused,
            refusal.Decision.AliasUsed,
            refusal.Decision.SeatReconciliationRequired,
            refusal.Decision.BindingIdentityPresent,
            refusal.Decision.SeatIdentityPresent,
            refusal.Decision.CanonicalSeatPresent,
            refusal.Decision.SingleLegacySeatPresent,
            refusal.Decision.RecoverySourcePresent,
            refusal.Decision.RecoverySourceMatchesBinding);
        return new DistributionOperationException(
            "hardware_authority_refused",
            StatusCodes.Status422UnprocessableEntity,
            reasonCode,
            refusal);
    }

    private static DistributionOperationException Conflict(string errorCode) =>
        new(errorCode, StatusCodes.Status409Conflict);

    private static DistributionOperationException Conflict(string errorCode, string reasonCode) =>
        new(errorCode, StatusCodes.Status409Conflict, reasonCode);

    private sealed record EntitlementTokenPayload(
        string Schema,
        string EntitlementId,
        string ClientId,
        string LicenseId,
        string ProductId,
        string IssuedAtUtc,
        string ExpiresAtUtc,
        string? GrantRefDigestSha256 = null,
        string? SubjectRefDigestSha256 = null,
        int ContractVersion = 1,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AuthorityLineageId = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AuthorityGenerationId = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ArtifactSetDigestSha256 = null);

    internal sealed record EntitlementIdentity(
        Guid EntitlementId,
        Guid LicenseId,
        string? GrantRefDigestSha256,
        string? SubjectRefDigestSha256,
        int ContractVersion,
        Guid? AuthorityLineageId = null,
        Guid? AuthorityGenerationId = null,
        string? ArtifactSetDigestSha256 = null);
    private sealed record IssueValidated(
        string RequestId,
        Guid ProductId,
        Guid LicenseId,
        string Operation,
        string? GrantRefDigestSha256,
        string? SubjectRef,
        int ContractVersion,
        Guid? AuthorityGenerationId = null);
    /// <summary>Freezes the relational authority tuple selected by issue v4.</summary>
    private sealed record AuthorityGenerationProjection(
        Guid AuthorityLineageId,
        Guid AuthorityGenerationId,
        string ArtifactSetDigestSha256);
    /// <summary>Holds the canonical identities and exact hardware bytes accepted at the S2S boundary.</summary>
    private sealed record RuntimeSourceResolutionValidated(
        Guid ProductId,
        Guid TargetLicenseId,
        string HardwareId);
    private sealed record BinaryValidated(string Key, string Sha256);
    private sealed record CrossGenerationRotation(
        DistributionInstallationBinding Binding,
        IReadOnlyList<RuntimeEnrollment> Enrollments);
    private sealed record FinalizeValidated(
        string RequestId,
        string GrantRef,
        string HandoffDigestSha256,
        DateTimeOffset HandoffIssuedAtUtc,
        DateTimeOffset HandoffExpiresAtUtc,
        DateTimeOffset DownloadCompletedAtUtc,
        Guid ProductId,
        string EntitlementRef,
        string InstallationId,
        string HardwareId,
        string Version,
        string InstallerFilename,
        string InstallerSha256,
        IReadOnlyList<BinaryValidated> Binaries,
        bool AllowSameAuthorityRecovery,
        LicenseReplacementValidated? LicenseReplacement,
        IReadOnlyList<LicenseReplacementValidated> LicenseReplacementCandidates,
        LegacyLicenseReplacementValidated? LegacyLicenseReplacement);
    private sealed record FinalizeReplacementAuthority(
        bool AllowSameAuthorityRecovery,
        LicenseReplacementValidated? LicenseReplacement,
        IReadOnlyList<LicenseReplacementValidated> LicenseReplacementCandidates,
        LegacyLicenseReplacementValidated? LegacyLicenseReplacement);
    private sealed record LicenseReplacementValidated(
        Guid SourceBindingId,
        Guid SourceLicenseId,
        string SourceSubjectRefDigestSha256);
    private sealed record LegacyLicenseReplacementValidated(
        Guid SourceLicenseId,
        Guid TargetLicenseId);
    private sealed record InvalidationValidated(
        string RequestId,
        Guid ProductId,
        Guid? BindingId,
        string GrantRefDigestSha256,
        string Reason,
        DateTimeOffset OccurredAtUtc,
        long Epoch);
}

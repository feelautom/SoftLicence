using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public interface IDistributionInstallationBindingService
{
    Task<DistributionOperationResult<DistributionEntitlementIssueResponse>> IssueEntitlementAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionEntitlementIssueRequest request,
        CancellationToken cancellationToken = default);

    Task<DistributionOperationResult<DistributionInstallationBindingResponse>> FinalizeAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionInstallationFinalizeRequest request,
        CancellationToken cancellationToken = default);

    Task<DistributionOperationResult<DistributionInstallationInvalidationResponse>> InvalidateAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionInstallationInvalidationRequest request,
        CancellationToken cancellationToken = default);

    Task<DistributionInstallationBindingResponse> RevalidateForCapabilityAsync(
        Guid bindingId,
        CancellationToken cancellationToken = default);
}

public sealed class DistributionOperationException(string errorCode, int statusCode, string? reasonCode = null)
    : Exception(errorCode)
{
    public string ErrorCode { get; } = errorCode;
    public int StatusCode { get; } = statusCode;
    public string? ReasonCode { get; } = reasonCode;
}

public sealed class DistributionInstallationBindingService : IDistributionInstallationBindingService
{
    public const string IssueSchema = "distribution-entitlement-issue-v1";
    public const string IssueV2Schema = "distribution-entitlement-issue-v2";
    public const string IssueV3Schema = "distribution-entitlement-issue-v3";
    public const string IssueResponseSchema = "distribution-entitlement-v1";
    public const string FinalizeSchema = "distribution-installation-finalize-v1";
    public const string FinalizeV2Schema = "distribution-installation-finalize-v2";
    public const string FinalizeV3Schema = "distribution-installation-finalize-v3";
    public const string FinalizeV4Schema = "distribution-installation-finalize-v4";
    public const string LicenseReplacementSchema = "distribution-license-replacement-v1";
    public const string LicenseReplacementCandidatesSchema = "distribution-license-replacement-candidates-v1";
    public const string BindingResponseSchema = "distribution-installation-binding-v1";
    public const string InvalidationSchema = "distribution-installation-invalidation-v1";
    public const string InvalidationResponseSchema = "distribution-installation-invalidation-result-v1";
    private const string IssueOperation = "issue_entitlement";
    private const string IssueV2Operation = "issue_entitlement_v2";
    private const string IssueV3Operation = "issue_entitlement_v3";
    private const string FinalizeOperation = "finalize_binding";
    private const string InvalidateOperation = "invalidate_binding";
    internal const string EntitlementPurpose = "SoftLicence.DistributionEntitlement.v1";
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";
    private const int MaximumLicenseReplacementCandidates = 16;

    private static readonly string[] RequiredBinaryKeys = ["FP_EXE", "FP_DLL", "FP_CORE"];
    private static readonly HashSet<string> RequiredBinaryKeySet = new(RequiredBinaryKeys, StringComparer.Ordinal);
    private static readonly HashSet<string> InvalidationReasons = new(
        ["account_closed", "fraud_flagged", "grant_revoked", "security_lockdown"],
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

    public DistributionInstallationBindingService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider)
    {
        _dbFactory = dbFactory;
        _entitlementProtector = dataProtectionProvider.CreateProtector(EntitlementPurpose);
        _timeProvider = timeProvider;
    }

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

        if (validated.GrantRefDigestSha256 != null
            && await db.DistributionGrantOwnerships.AsNoTracking().AnyAsync(candidate =>
                candidate.ProductId == validated.ProductId
                && candidate.GrantRefDigestSha256 == validated.GrantRefDigestSha256,
                cancellationToken))
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

        var issuedAt = validated.ContractVersion == 3
            ? ToPostgreSqlTimestampPrecision(now)
            : now;
        var expiresAt = issuedAt.AddHours(2);
        var entitlementId = Guid.NewGuid();
        var subjectRefDigest = validated.SubjectRef == null ? null : Sha256(validated.SubjectRef);
        var tokenPayload = new EntitlementTokenPayload(
            IssueResponseSchema,
            entitlementId.ToString("D"),
            clientId,
            validated.LicenseId.ToString("D"),
            validated.ProductId.ToString("D"),
            FormatUtc(issuedAt),
            FormatUtc(expiresAt),
            validated.GrantRefDigestSha256,
            subjectRefDigest,
            validated.ContractVersion);
        var entitlementRef = _entitlementProtector.Protect(JsonSerializer.Serialize(tokenPayload, JsonOptions));
        var response = new DistributionEntitlementIssueResponse(
            IssueResponseSchema,
            entitlementRef,
            FormatUtc(expiresAt));

        db.DistributionBindingRequests.Add(new DistributionBindingRequest
        {
            ClientId = clientId,
            RequestId = validated.RequestId,
            Operation = validated.Operation,
            PayloadDigest = exactPayloadDigest,
            ResponseJson = JsonSerializer.Serialize(response, JsonOptions),
            CreatedAtUtc = issuedAt.UtcDateTime
        });
        if (validated.ContractVersion == 3)
        {
            db.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = entitlementId,
                ClientId = clientId,
                ProductId = validated.ProductId,
                LicenseId = validated.LicenseId,
                GrantRefDigestSha256 = validated.GrantRefDigestSha256!,
                SubjectRefDigestSha256 = subjectRefDigest!,
                ContractVersion = 3,
                State = "issued",
                IssuedAtUtc = issuedAt.UtcDateTime,
                ExpiresAtUtc = expiresAt.UtcDateTime
            });
        }
        if (validated.GrantRefDigestSha256 != null)
        {
            db.DistributionGrantOwnerships.Add(new DistributionGrantOwnership
            {
                ProductId = validated.ProductId,
                GrantRefDigestSha256 = validated.GrantRefDigestSha256,
                ClientId = clientId,
                Source = validated.ContractVersion == 3 ? "issue_v3" : "issue_v2",
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
    /// decision. See DevBrain DOC-324 and DOC-327.
    /// </remarks>
    public async Task<DistributionOperationResult<DistributionInstallationBindingResponse>> FinalizeAsync(
        string clientId,
        string exactPayloadDigest,
        DistributionInstallationFinalizeRequest request,
        CancellationToken cancellationToken = default)
    {
        var validated = ValidateFinalizeRequest(request);
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
        if (entitlement.GrantRefDigestSha256 != null
            && !string.Equals(entitlement.GrantRefDigestSha256, grantRefDigest, StringComparison.Ordinal))
        {
            throw Conflict("grant_ownership_mismatch");
        }
        await EnsureGrantOwnershipForFinalizeAsync(
            db, clientId, validated.ProductId, grantRefDigest,
            entitlement.GrantRefDigestSha256 != null, now, cancellationToken);

        await ProductHardwareSeatLockAuthority.AcquireAsync(
            db, validated.ProductId, validated.HardwareId, cancellationToken);
        await AcquireLicenseSeatLockAsync(db, entitlement.LicenseId, cancellationToken);

        var license = await db.Licenses
            .Include(candidate => candidate.Seats)
            .Include(candidate => candidate.Product)
            .Include(candidate => candidate.Type)
            .SingleOrDefaultAsync(candidate =>
                candidate.Id == entitlement.LicenseId && candidate.ProductId == validated.ProductId,
                cancellationToken);
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
                string.Equals(hardwareId, validated.HardwareId, StringComparison.OrdinalIgnoreCase)))
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

        var seat = await EnsureInitialSeatAsync(
            db, license, validated.HardwareId, validated.Version, clientId, now, cancellationToken);

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
                    await db.SaveChangesAsync(cancellationToken);
                    if (transaction != null)
                        await transaction.CommitAsync(cancellationToken);
                    return new(existingResponse, true);
                }
                catch (Exception exception) when (IsRetryableWriteFailure(exception, db))
                {
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
            if (validated.LicenseReplacement != null || validated.LicenseReplacementCandidates.Count > 0)
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
            LicenseReplacementValidated? replacement = validated.LicenseReplacement;
            var proofs = validated.LicenseReplacementCandidates.Count > 0
                ? validated.LicenseReplacementCandidates
                : replacement == null ? [] : [replacement];
            var isSameLicenseSeatTransition = false;
            DistributionInstallationBinding? recoverySource = null;
            var hasActiveHardwareAuthority = hardwareBindings.Any(candidate => candidate.State == "active");
            var hasSecurityTerminalHardwareAuthority = hardwareBindings.Any(candidate =>
                !RuntimeAuthorityTransitionResolver.IsRecoverableBinding(
                    candidate.State, candidate.InvalidationReason));
            if (!hasActiveHardwareAuthority
                && !hasSecurityTerminalHardwareAuthority
                && replacement == null
                && entitlement.ContractVersion == 3
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
                            proofs.Count > 0
                                ? proofs.Count(proof =>
                                    proof.SourceBindingId == candidate.Id
                                    && proof.SourceLicenseId == candidate.LicenseId
                                    && proof.SourceSubjectRefDigestSha256 == candidate.SubjectRefDigestSha256) == 1
                                : candidate.LicenseId == entitlement.LicenseId
                                    && candidate.LicenseSeatId == seat.Id
                                    && candidate.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256))
                        .ToList());
                if (bindingDecision.Kind == RuntimeAuthorityBindingDecisionKind.RejectAmbiguous)
                    throw Conflict("binding_conflict", "replacement_hardware_ambiguous");
                recoverySource = bindingDecision.BindingId.HasValue
                    ? hardwareBindings.Single(candidate => candidate.Id == bindingDecision.BindingId.Value)
                    : null;
            }
            var isExactActiveAuthorityRecovery = recoverySource is
                {
                    State: "active"
                }
                && !hasSecurityTerminalHardwareAuthority
                && recoverySource.InvalidatedAtUtc == null
                && recoverySource.InvalidationReason == null
                && recoverySource.ProductId == validated.ProductId
                && recoverySource.LicenseId == entitlement.LicenseId
                && recoverySource.LicenseSeatId == seat.Id
                && string.Equals(
                    recoverySource.SubjectRefDigestSha256,
                    entitlement.SubjectRefDigestSha256,
                    StringComparison.Ordinal)
                && string.Equals(recoverySource.HardwareIdHash, hardwareIdHash, StringComparison.Ordinal);
            if (recoverySource != null
                && validated.LicenseReplacementCandidates.Count > 0
                && !isSameLicenseSeatTransition
                && !isExactActiveAuthorityRecovery)
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
            if (recoverySource != null)
            {
                if (!validated.AllowSameAuthorityRecovery)
                    throw Conflict("binding_conflict", "replacement_authority_missing");
                if (validated.LicenseReplacementCandidates.Count > 0
                    && replacement == null
                    && !isSameLicenseSeatTransition
                    && !isExactActiveAuthorityRecovery)
                    throw Conflict("binding_conflict", "replacement_candidate_none");
                if (replacement is { } exactReplacement
                    && exactReplacement.SourceBindingId != recoverySource.Id)
                    throw Conflict("binding_conflict", "replacement_source_binding_mismatch");
                var recovery = await RecoverSameAuthorityInstallationAsync(
                    db, clientId, recoverySource.Id,
                    isExactActiveAuthorityRecovery && validated.LicenseReplacementCandidates.Count > 0,
                    replacement,
                    validated, entitlement, seat.Id,
                    grantRefDigest, hardwareIdHash, binaryMap, now, cancellationToken);
                binding = recovery.Binding;
                supersededEnrollments = recovery.Enrollments;
            }
            else
            {
                if (validated.LicenseReplacement != null || validated.LicenseReplacementCandidates.Count > 0)
                    throw Conflict("binding_conflict", "replacement_candidate_none");
                if (hardwareBindings.Count > 0)
                    throw Conflict("binding_conflict", "replacement_authority_missing");
                binding = CreateBinding(
                    validated, entitlement, seat.Id, grantRefDigest, hardwareIdHash, binaryMap, now,
                    supersededBindingId: null, initialSecurityEpoch: 1);
                db.DistributionInstallationBindings.Add(binding);
            }
        }
        var response = ToResponse(binding);
        if (entitlement.ContractVersion == 3)
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
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
            return new(response, false);
        }
        catch (Exception exception) when (IsRetryableWriteFailure(exception, db))
        {
            await TryRollbackAsync(transaction, cancellationToken);
            return new(
                await ReloadConcurrentAsync<DistributionInstallationBindingResponse>(
                    clientId, validated.RequestId, FinalizeOperation, exactPayloadDigest, cancellationToken),
                true);
        }
    }

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

        var binding = await db.DistributionInstallationBindings
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

        var invalidatedAt = now.UtcDateTime;
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
                || payload.Schema != IssueResponseSchema
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
            if (payload.ContractVersion == 3)
            {
                var persisted = await db.DistributionEntitlements.AsNoTracking()
                    .SingleOrDefaultAsync(row => row.Id == entitlementId, cancellationToken);
                if (persisted == null
                    || persisted.ContractVersion != 3
                    || !string.Equals(persisted.ClientId, expectedClientId, StringComparison.Ordinal)
                    || persisted.ProductId != productId
                    || persisted.LicenseId != licenseId
                    || !string.Equals(persisted.GrantRefDigestSha256, payload.GrantRefDigestSha256, StringComparison.Ordinal)
                    || !string.Equals(persisted.SubjectRefDigestSha256, payload.SubjectRefDigestSha256, StringComparison.Ordinal)
                    || persisted.ExpiresAtUtc != ToPostgreSqlTimestampPrecision(expiresAt).UtcDateTime
                    || !string.Equals(persisted.State, "issued", StringComparison.Ordinal))
                    throw Reject("entitlement_ineligible");
            }
            return new(entitlementId, licenseId, payload.GrantRefDigestSha256, payload.SubjectRefDigestSha256, payload.ContractVersion);
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

    private static IssueValidated ValidateIssueRequest(DistributionEntitlementIssueRequest request)
    {
        if (request.ExtensionData is { Count: > 0 }
            || !TryCanonicalUuid(request.RequestId, out _)
            || !TryCanonicalUuid(request.ProductId, out var productId)
            || !TryCanonicalUuid(request.SoftLicenceLicenseId, out var licenseId))
        {
            throw Invalid();
        }
        if (request.Schema == IssueSchema && request.GrantRefDigestSha256 == null && request.SubjectRef == null)
            return new(request.RequestId!, productId, licenseId, IssueOperation, null, null, 1);
        if (request.Schema == IssueV2Schema && IsLowerSha256(request.GrantRefDigestSha256) && request.SubjectRef == null)
            return new(request.RequestId!, productId, licenseId, IssueV2Operation, request.GrantRefDigestSha256, null, 2);
        if (request.Schema == IssueV3Schema
            && IsLowerSha256(request.GrantRefDigestSha256)
            && IsCanonicalSubjectRef(request.SubjectRef))
            return new(request.RequestId!, productId, licenseId, IssueV3Operation, request.GrantRefDigestSha256, request.SubjectRef, 3);
        throw Invalid();
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
                && !request.LicenseReplacementCandidatesPresent =>
                new FinalizeReplacementAuthority(false, null, []),
            FinalizeV2Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true
                && !request.LicenseReplacementPresent
                && !request.LicenseReplacementCandidatesPresent => new FinalizeReplacementAuthority(true, null, []),
            FinalizeV3Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true
                && request.LicenseReplacementPresent
                && !request.LicenseReplacementCandidatesPresent =>
                new FinalizeReplacementAuthority(true, ValidateLicenseReplacement(request.LicenseReplacement), []),
            FinalizeV4Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true
                && !request.LicenseReplacementPresent
                && request.LicenseReplacementCandidatesPresent =>
                new FinalizeReplacementAuthority(true, null, ValidateLicenseReplacementCandidates(request.LicenseReplacementCandidates)),
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
            replacementAuthority.LicenseReplacementCandidates);
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

    private static async Task<LicenseSeat> EnsureInitialSeatAsync(
        LicenseDbContext db,
        License license,
        string hardwareId,
        string version,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
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

        var activeSeatCount = license.Seats.Count(candidate => candidate.IsActive);
        if (activeSeatCount >= license.MaxSeats)
            throw Reject("seat_limit_reached");

        var maxActivationsPerDay = license.Type?.MaxActivationsPerDay ?? 0;
        if (maxActivationsPerDay > 0)
        {
            var dayStart = now.UtcDateTime.Date;
            var activationsToday = await db.LicenseSeats.AsNoTracking().CountAsync(candidate =>
                candidate.LicenseId == license.Id && candidate.FirstActivatedAt >= dayStart,
                cancellationToken);
            if (activationsToday >= maxActivationsPerDay)
                throw Reject("activation_rate_limited");
        }

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
        && (entitlement.ContractVersion != 3
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
        if (db.Database.IsNpgsql())
        {
            // Runtime operations take the global authority lock before the binding lock.
            // The exclusive form prevents an old enrollment from racing the rotation.
            await db.Database.ExecuteSqlRawAsync(
                "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)", cancellationToken);
        }

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
        if (entitlement.ContractVersion != 3 || entitlement.SubjectRefDigestSha256 is not { Length: 64 })
            return "cross_generation_candidate_entitlement_invalid";
        if (previousEntitlement is not
            {
                ContractVersion: 3,
                State: "finalized",
                SubjectRefDigestSha256.Length: 64
            })
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
        if (previousGrantOwner == null || previousGrantOwner.ClientId != clientId)
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
    /// Resolves the unique previous Runtime authority after the same license was explicitly
    /// unlinked from one seat and activated on another. Historical replacement proofs belong
    /// to cross-license renewal and therefore cannot select or veto this same-license path.
    /// The selected rows are revalidated under authority and row locks before mutation.
    /// See DevBrain DOC-324.
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
    /// enrollment whose reason is <c>authority_ineligible</c>. It is used only for the exact
    /// active-binding recovery described by DOC-327.
    /// </param>
    /// <param name="replacement">The optional exact cross-license replacement proof.</param>
    /// <param name="request">The validated fresh finalize request.</param>
    /// <param name="entitlement">The authoritative target entitlement.</param>
    /// <param name="seatId">The authoritative active target seat.</param>
    /// <param name="grantRefDigestSha256">The exact target grant digest.</param>
    /// <param name="hardwareIdHash">The exact target hardware digest.</param>
    /// <param name="binaries">The validated approved-binary evidence keyed by canonical component code.</param>
    /// <param name="now">The authoritative operation time.</param>
    /// <param name="cancellationToken">Cancels the operation before commit.</param>
    /// <returns>The fresh successor and any live source enrollments terminalized by the transition.</returns>
    /// <exception cref="DistributionOperationException">
    /// Thrown when ownership, history, security, freshness or exact-authority checks fail closed.
    /// </exception>
    private static async Task<CrossGenerationRotation> RecoverSameAuthorityInstallationAsync(
        LicenseDbContext db,
        string clientId,
        Guid sourceBindingId,
        bool requireExactRecoverableEnrollment,
        LicenseReplacementValidated? replacement,
        FinalizeValidated request,
        EntitlementIdentity entitlement,
        Guid seatId,
        string grantRefDigestSha256,
        string hardwareIdHash,
        IReadOnlyDictionary<string, string> binaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (db.Database.IsNpgsql())
        {
            // Runtime operations use the same global authority lock. Taking it exclusively
            // prevents credentials from being minted while the old identity is superseded.
            await db.Database.ExecuteSqlRawAsync(
                "SELECT pg_catalog.pg_advisory_xact_lock(999831, 1)", cancellationToken);
        }

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

        var sourceLicense = replacement == null
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

        var sameAuthority = entitlement.ContractVersion == 3
            && entitlement.SubjectRefDigestSha256 is { Length: 64 }
            && previousEntitlement is
            {
                ContractVersion: 3,
                State: "finalized",
                SubjectRefDigestSha256.Length: 64
            }
            && RuntimeAuthorityTransitionResolver.IsRecoverableBinding(source.State, source.InvalidationReason)
            && source.ProductId == request.ProductId
            && (exactSameLicenseAuthority || exactSameLicenseSeatTransition || exactRenewalAuthority)
            && source.InstallationId != request.InstallationId
            && (source.HardwareIdHash == hardwareIdHash || exactSameLicenseSeatTransition)
            && previousEntitlement.Id == source.EntitlementId
            && previousEntitlement.ClientId == clientId
            && previousEntitlement.ProductId == source.ProductId
            && previousEntitlement.LicenseId == source.LicenseId
            && previousEntitlement.GrantRefDigestSha256 == source.GrantRefDigestSha256
            && previousEntitlement.SubjectRefDigestSha256 == source.SubjectRefDigestSha256
            && previousGrantOwner != null
            && previousGrantOwner.ClientId == clientId
            && finalizeOwners.Count == 1
            && finalizeOwners[0] == clientId
            && source.GrantRefDigestSha256 == Sha256(source.GrantRef)
            && source.GrantRefDigestSha256 != grantRefDigestSha256
            && source.HandoffIssuedAtUtc.HasValue
            && request.HandoffIssuedAtUtc.UtcDateTime > source.HandoffIssuedAtUtc.Value
            && !IsVersionBelow(request.Version, source.Version);
        if (!sameAuthority)
            throw Conflict("binding_conflict", replacement == null
                ? "same_authority_mismatch"
                : "replacement_source_authority_mismatch");

        if (await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(
                incident => incident.BindingId == source.Id && incident.State == "OPEN",
                cancellationToken))
        {
            throw Conflict("binding_conflict", "replacement_source_incident");
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
        var enrollmentDecision = RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
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
        var isExactAuthorityIneligibleTerminal =
            enrollmentDecision == RuntimeAuthorityEnrollmentDecision.UseBusinessTerminal
            && enrollments.Count == 1
            && string.Equals(
                enrollments[0].InvalidationReason,
                "authority_ineligible",
                StringComparison.Ordinal);
        if (requireExactRecoverableEnrollment
            && !isExactActiveEnrollment
            && !isExactAuthorityIneligibleTerminal)
        {
            throw Conflict("binding_conflict", "same_authority_active_enrollment_mismatch");
        }

        var sourceEnrollment = enrollmentDecision == RuntimeAuthorityEnrollmentDecision.UseActive
            ? enrollments.Single(candidate => candidate.State == RuntimeAuthorityTransitionResolver.ActiveState)
            : enrollments.Single();
        var enrollmentMatchesAuthority = string.Equals(sourceEnrollment.ClientId, clientId, StringComparison.Ordinal)
            && sourceEnrollment.BindingId == source.Id
            && sourceEnrollment.ProductId == source.ProductId
            && sourceEnrollment.LicenseId == source.LicenseId
            && sourceEnrollment.LicenseSeatId == source.LicenseSeatId
            && string.Equals(sourceEnrollment.InstallationId, source.InstallationId, StringComparison.Ordinal)
            && string.Equals(sourceEnrollment.HardwareIdHash, source.HardwareIdHash, StringComparison.Ordinal)
            && string.Equals(
                sourceEnrollment.SubjectRefDigestSha256,
                source.SubjectRefDigestSha256,
                StringComparison.Ordinal)
            && string.Equals(
                sourceEnrollment.HandoffDigestSha256,
                source.HandoffDigestSha256,
                StringComparison.Ordinal)
            && string.Equals(sourceEnrollment.ReleaseVersion, source.Version, StringComparison.Ordinal)
            && string.Equals(
                sourceEnrollment.ProtocolVersion,
                RuntimeEnrollmentService.ProtocolVersion,
                StringComparison.Ordinal)
            && sourceEnrollment.Epoch == 1
            && sourceEnrollment.SecurityEpoch >= 1;
        if (!enrollmentMatchesAuthority)
            throw Conflict("binding_conflict");

        var initialSecurityEpoch = checked(enrollments.Max(candidate => candidate.SecurityEpoch) + 1);
        IReadOnlyList<RuntimeEnrollment> enrollmentsToInvalidate =
            enrollmentDecision == RuntimeAuthorityEnrollmentDecision.UseActive
                ? [sourceEnrollment]
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

    private static async Task EnsureGrantOwnershipForFinalizeAsync(
        LicenseDbContext db,
        string clientId,
        Guid productId,
        string grantRefDigestSha256,
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
            if (!string.Equals(owner.ClientId, clientId, StringComparison.Ordinal))
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
            // acquiring the lock and observe the preceding finalize/invalidation commit.
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
        int ContractVersion = 1);

    internal sealed record EntitlementIdentity(
        Guid EntitlementId,
        Guid LicenseId,
        string? GrantRefDigestSha256,
        string? SubjectRefDigestSha256,
        int ContractVersion);
    private sealed record IssueValidated(
        string RequestId,
        Guid ProductId,
        Guid LicenseId,
        string Operation,
        string? GrantRefDigestSha256,
        string? SubjectRef,
        int ContractVersion);
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
        IReadOnlyList<LicenseReplacementValidated> LicenseReplacementCandidates);
    private sealed record FinalizeReplacementAuthority(
        bool AllowSameAuthorityRecovery,
        LicenseReplacementValidated? LicenseReplacement,
        IReadOnlyList<LicenseReplacementValidated> LicenseReplacementCandidates);
    private sealed record LicenseReplacementValidated(
        Guid SourceBindingId,
        Guid SourceLicenseId,
        string SourceSubjectRefDigestSha256);
    private sealed record InvalidationValidated(
        string RequestId,
        Guid ProductId,
        Guid? BindingId,
        string GrantRefDigestSha256,
        string Reason,
        DateTimeOffset OccurredAtUtc,
        long Epoch);
}

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

public sealed class DistributionOperationException(string errorCode, int statusCode)
    : Exception(errorCode)
{
    public string ErrorCode { get; } = errorCode;
    public int StatusCode { get; } = statusCode;
}

public sealed class DistributionInstallationBindingService : IDistributionInstallationBindingService
{
    public const string IssueSchema = "distribution-entitlement-issue-v1";
    public const string IssueV2Schema = "distribution-entitlement-issue-v2";
    public const string IssueV3Schema = "distribution-entitlement-issue-v3";
    public const string IssueResponseSchema = "distribution-entitlement-v1";
    public const string FinalizeSchema = "distribution-installation-finalize-v1";
    public const string FinalizeV2Schema = "distribution-installation-finalize-v2";
    public const string BindingResponseSchema = "distribution-installation-binding-v1";
    public const string InvalidationSchema = "distribution-installation-invalidation-v1";
    public const string InvalidationResponseSchema = "distribution-installation-invalidation-result-v1";
    private const string IssueOperation = "issue_entitlement";
    private const string IssueV2Operation = "issue_entitlement_v2";
    private const string IssueV3Operation = "issue_entitlement_v3";
    private const string FinalizeOperation = "finalize_binding";
    private const string InvalidateOperation = "invalidate_binding";
    private const string EntitlementPurpose = "SoftLicence.DistributionEntitlement.v1";
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

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
            var rotation = await RotateCrossGenerationBindingAsync(
                db, clientId, validated, entitlement, seat.Id, grantRefDigest,
                hardwareIdHash, binaryMap, now, cancellationToken);
            binding = rotation.Binding;
            supersededEnrollments = rotation.Enrollments;
        }
        else
        {
            var activeHardwareBindings = await db.DistributionInstallationBindings.AsNoTracking()
                .Where(candidate => candidate.ProductId == validated.ProductId
                    && candidate.HardwareIdHash == hardwareIdHash
                    && candidate.State == "active")
                .OrderBy(candidate => candidate.Id)
                .Take(2)
                .ToListAsync(cancellationToken);
            if (activeHardwareBindings.Count > 1)
                throw Conflict("binding_conflict");
            if (activeHardwareBindings.Count == 1)
            {
                if (!validated.AllowSameAuthorityRecovery)
                    throw Conflict("binding_conflict");
                var recovery = await RecoverSameAuthorityInstallationAsync(
                    db, clientId, activeHardwareBindings[0].Id, validated, entitlement, seat.Id,
                    grantRefDigest, hardwareIdHash, binaryMap, now, cancellationToken);
                binding = recovery.Binding;
                supersededEnrollments = recovery.Enrollments;
            }
            else
            {
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

    private async Task<EntitlementIdentity> ReadEntitlementAsync(
        LicenseDbContext db,
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
            var json = _entitlementProtector.Unprotect(entitlementRef);
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
        var allowSameAuthorityRecovery = request.Schema switch
        {
            FinalizeSchema when !request.AllowSameAuthorityRecoveryPresent => false,
            FinalizeV2Schema when request.AllowSameAuthorityRecoveryPresent
                && request.AllowSameAuthorityRecovery == true => true,
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
            allowSameAuthorityRecovery);
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

        var sameAuthority = entitlement.ContractVersion == 3
            && entitlement.SubjectRefDigestSha256 is { Length: 64 }
            && previousEntitlement is
            {
                ContractVersion: 3,
                State: "finalized",
                SubjectRefDigestSha256.Length: 64
            }
            && binding.State == "active"
            && binding.ProductId == request.ProductId
            && binding.LicenseId == entitlement.LicenseId
            && binding.LicenseSeatId == seatId
            && binding.HardwareIdHash == hardwareIdHash
            && binding.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256
            && previousEntitlement.Id == binding.EntitlementId
            && previousEntitlement.ClientId == clientId
            && previousEntitlement.ProductId == binding.ProductId
            && previousEntitlement.LicenseId == binding.LicenseId
            && previousEntitlement.GrantRefDigestSha256 == binding.GrantRefDigestSha256
            && previousEntitlement.SubjectRefDigestSha256 == binding.SubjectRefDigestSha256
            && previousGrantOwner != null
            && previousGrantOwner.ClientId == clientId
            && finalizeOwners.Count == 1
            && finalizeOwners[0] == clientId
            && binding.GrantRefDigestSha256 == Sha256(binding.GrantRef)
            && binding.GrantRefDigestSha256 != grantRefDigestSha256
            && binding.HandoffIssuedAtUtc.HasValue
            && request.HandoffIssuedAtUtc.UtcDateTime > binding.HandoffIssuedAtUtc.Value
            && !IsVersionBelow(request.Version, binding.Version);
        if (!sameAuthority)
            throw Conflict("binding_conflict");

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

    private static async Task<CrossGenerationRotation> RecoverSameAuthorityInstallationAsync(
        LicenseDbContext db,
        string clientId,
        Guid sourceBindingId,
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

        var sameAuthority = entitlement.ContractVersion == 3
            && entitlement.SubjectRefDigestSha256 is { Length: 64 }
            && previousEntitlement is
            {
                ContractVersion: 3,
                State: "finalized",
                SubjectRefDigestSha256.Length: 64
            }
            && source.State == "active"
            && source.ProductId == request.ProductId
            && source.LicenseId == entitlement.LicenseId
            && source.LicenseSeatId == seatId
            && source.InstallationId != request.InstallationId
            && source.HardwareIdHash == hardwareIdHash
            && source.SubjectRefDigestSha256 == entitlement.SubjectRefDigestSha256
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
            throw Conflict("binding_conflict");

        if (await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(
                incident => incident.BindingId == source.Id && incident.State == "OPEN",
                cancellationToken))
        {
            throw Conflict("binding_conflict");
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
        var liveEnrollments = enrollments.Where(candidate => candidate.State is "PENDING" or "ACTIVE").ToList();
        var activeEnrollment = liveEnrollments.Count == 1
            && string.Equals(liveEnrollments[0].State, "ACTIVE", StringComparison.Ordinal)
            ? liveEnrollments[0]
            : null;
        // A never-consumed challenge that expired before activation cannot carry Runtime authority.
        // Its exact terminal row is preserved as forensic evidence; every other terminal history
        // remains ineligible so recovery cannot collapse ambiguous or previously-used identities.
        var abandonedEnrollment = enrollments.Count == 1
            && string.Equals(enrollments[0].State, "INVALIDATED", StringComparison.Ordinal)
            && string.Equals(enrollments[0].InvalidationReason, "challenge_expired", StringComparison.Ordinal)
            && enrollments[0].ActivatedAtUtc == null
            && enrollments[0].ChallengeConsumedAtUtc == null
            && enrollments[0].InvalidatedAtUtc.HasValue
            && enrollments[0].ChallengeExpiresAtUtc <= now.UtcDateTime
            && enrollments[0].InvalidatedAtUtc.GetValueOrDefault() <= now.UtcDateTime
            && enrollments[0].InvalidatedAtUtc.GetValueOrDefault() >= enrollments[0].ChallengeExpiresAtUtc
            ? enrollments[0]
            : null;
        if (activeEnrollment == null && abandonedEnrollment == null)
            throw Conflict("binding_conflict");

        var sourceEnrollment = activeEnrollment ?? abandonedEnrollment!;
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
        IReadOnlyList<RuntimeEnrollment> enrollmentsToInvalidate = activeEnrollment == null
            ? Array.Empty<RuntimeEnrollment>()
            : [activeEnrollment];
        foreach (var enrollment in enrollmentsToInvalidate)
        {
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = now.UtcDateTime;
            enrollment.InvalidationReason = "binding_superseded";
        }
        source.State = "invalidated";
        source.InvalidatedAtUtc = now.UtcDateTime;
        source.InvalidationReason = "installation_superseded";

        // Free the active-HWID uniqueness slot before inserting the successor in this transaction.
        await db.SaveChangesAsync(cancellationToken);

        var successor = CreateBinding(
            request, entitlement, seatId, grantRefDigestSha256, hardwareIdHash, binaries, now,
            source.Id, initialSecurityEpoch);
        db.DistributionInstallationBindings.Add(successor);
        return new CrossGenerationRotation(successor, enrollmentsToInvalidate);
    }

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

    private sealed record EntitlementIdentity(
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
        bool AllowSameAuthorityRecovery);
    private sealed record InvalidationValidated(
        string RequestId,
        Guid ProductId,
        Guid? BindingId,
        string GrantRefDigestSha256,
        string Reason,
        DateTimeOffset OccurredAtUtc,
        long Epoch);
}

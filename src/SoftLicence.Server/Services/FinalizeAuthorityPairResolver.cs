using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>
/// Resolves, at Finalize time, whether a presented hardware identifier and a grant digest designate the
/// same machine through one server-authenticated alias pair (TKT-001296).
/// </summary>
public interface IFinalizeAuthorityPairResolver
{
    /// <summary>
    /// Evaluates one exact request under the same commercial and ban locks as the distribution preflight.
    /// Direct equality uses current target distribution policy. Alias matches additionally require one
    /// current ACTIVE assignment for the authenticated historical binding and resolved seat.
    /// Contract (explicit, accepted in review): the evaluation is deterministic and persists nothing on the
    /// provider. <c>requestId</c> is a correlation echo and <c>payloadDigestSha256</c> is the SHA-256 of the
    /// exact authenticated body, echoed so the caller can prove which payload produced which decision; a
    /// replay with a divergent payload therefore yields a visibly different binding. The durable, idempotent
    /// record of the decision belongs to the Website grant and is written only after the atomic Finalize
    /// succeeded with the same canonical digest. A concurrent revocation or ban committed before the locks
    /// are taken wins here, and the atomic Finalize re-checks both anyway.
    /// </summary>
    /// <param name="clientId">Authenticated S2S client identity.</param>
    /// <param name="payloadDigestSha256">Lowercase SHA-256 of the exact authenticated request bytes.</param>
    /// <param name="request">Exact deserialized request.</param>
    /// <param name="cancellationToken">Cancels relational reads.</param>
    /// <returns>A closed digest-only decision.</returns>
    Task<FinalizeAuthorityPairResponse> ResolveAsync(
        string clientId,
        string payloadDigestSha256,
        FinalizeAuthorityPairRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// PostgreSQL-backed pair resolver. Direction A (submitted legacy, expected canonical stable) and direction B
/// (submitted canonical stable, expected legacy) are both verified against the complete alias authority graph
/// of the same product and licence; a direct equality is verified without any alias.
/// </summary>
public sealed partial class FinalizeAuthorityPairResolver : IFinalizeAuthorityPairResolver
{
    /// <summary>Closed request schema.</summary>
    public const string RequestSchema = "distribution-finalize-authority-pair-v1";

    /// <summary>Closed response schema.</summary>
    public const string ResponseSchema = "distribution-finalize-authority-resolution-v1";

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IOptions<HardwareAuthorityAliasOptions> _aliasOptions;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<FinalizeAuthorityPairResolver> _logger;

    /// <summary>Creates the resolver over the shared licence database factory.</summary>
    public FinalizeAuthorityPairResolver(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IOptions<HardwareAuthorityAliasOptions> aliasOptions,
        ILoggerFactory loggerFactory,
        ILogger<FinalizeAuthorityPairResolver> logger)
    {
        _dbFactory = dbFactory;
        _aliasOptions = aliasOptions;
        _loggerFactory = loggerFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<FinalizeAuthorityPairResponse> ResolveAsync(
        string clientId,
        string payloadDigestSha256,
        FinalizeAuthorityPairRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.ExtensionData is { Count: > 0 }
            || !Sha256Pattern().IsMatch(payloadDigestSha256 ?? string.Empty)
            || !string.Equals(request.Schema, RequestSchema, StringComparison.Ordinal)
            || !TryCanonicalUuid(request.RequestId, out var requestId)
            || !TryCanonicalUuid(request.ProductId, out var productIdText)
            || !TryCanonicalUuid(request.SoftLicenceLicenseId, out var licenseIdText)
            || !Sha256Pattern().IsMatch(request.GrantRefDigestSha256 ?? string.Empty)
            || !Sha256Pattern().IsMatch(request.ExpectedHardwareIdHash ?? string.Empty)
            || !HardwareAuthorityAliasResolver.IsCanonicalHardwareId(request.SubmittedHardwareId)
            || string.IsNullOrWhiteSpace(clientId) || clientId.Length > 64)
            throw new DistributionOperationException("invalid_request", StatusCodes.Status400BadRequest);
        var productId = Guid.ParseExact(productIdText, "D");
        var licenseId = Guid.ParseExact(licenseIdText, "D");
        var submittedHardwareId = request.SubmittedHardwareId!;
        var submittedHash = HardwareAuthorityAliasResolver.Sha256(submittedHardwareId);
        var expectedHash = request.ExpectedHardwareIdHash!;
        var grantRefDigest = request.GrantRefDigestSha256!;

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(
                db.Database.IsNpgsql() ? System.Data.IsolationLevel.ReadCommitted
                    : System.Data.IsolationLevel.Serializable,
                cancellationToken)
            : null;
        // Same lock order as the preflight and Finalize: commercial rows first, then the hardware digests,
        // so a ban or revocation writer that committed before these locks is observed below.
        await RuntimeDistributionPreflightService.AcquireCommercialAuthorityReadLocksAsync(
            db, clientId, productId, licenseId, grantRefDigest, cancellationToken);
        if (db.Database.IsNpgsql())
        {
            if (!string.Equals(submittedHash, expectedHash, StringComparison.Ordinal))
                await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
            await SecurityService.AcquireHardwareBanDigestMutationAsync(db, submittedHash);
            if (!string.Equals(submittedHash, expectedHash, StringComparison.Ordinal))
                await SecurityService.AcquireHardwareBanDigestMutationAsync(db, expectedHash);
        }
        var now = (await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken)).UtcDateTime;
        var entitlement = await db.DistributionEntitlements.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ClientId == clientId && candidate.ProductId == productId
            && candidate.LicenseId == licenseId
            && candidate.GrantRefDigestSha256 == grantRefDigest
            && (candidate.State == "issued" || candidate.State == "finalized")
            && candidate.ExpiresAtUtc > now,
            cancellationToken);
        var license = await db.Licenses.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.Id == licenseId && candidate.ProductId == productId,
            cancellationToken);
        FinalizeAuthorityPairResponse response;
        if (entitlement is null || license is null || !license.IsActive || license.RevokedAt is not null
            || (license.ExpirationDate is DateTime expiration && now > expiration))
        {
            response = Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement?.Id,
                grantRefDigest, submittedHash, expectedHash, "commercial_authority_invalid", null, null, null);
        }
        else if (string.Equals(submittedHash, expectedHash, StringComparison.Ordinal))
        {
            response = await HardwareAuthorityAliasResolver.HasActiveHardwareBanAsync(
                    db, productId, submittedHardwareId, submittedHardwareId, now, cancellationToken)
                ? Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement.Id,
                    grantRefDigest, submittedHash, expectedHash, "hardware_banned", null, null, null)
                : new FinalizeAuthorityPairResponse(ResponseSchema, requestId, payloadDigestSha256!, productId, licenseId,
                    entitlement.Id, grantRefDigest, "matched", submittedHash, expectedHash,
                    submittedHash, "direct", null, null, null, null);
        }
        else
        {
            var resolver = new HardwareAuthorityAliasResolver(
                db, _aliasOptions, _loggerFactory.CreateLogger<HardwareAuthorityAliasResolver>());
            // Direction A: the Desktop presents the legacy member; the grant froze the canonical stable digest.
            var legacyDirection = await resolver.ResolveAsync(
                db, productId, licenseId, submittedHardwareId,
                HardwareAuthorityResolutionIntent.Finalize, cancellationToken);
            if (legacyDirection.Status == HardwareAuthorityResolutionStatus.Resolved
                && string.Equals(HardwareAuthorityAliasResolver.Sha256(legacyDirection.EffectiveHardwareId),
                    expectedHash, StringComparison.Ordinal))
            {
                response = !await HasCurrentAliasAssignmentAsync(
                        db, legacyDirection, licenseId, now, cancellationToken)
                    ? Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement.Id,
                        grantRefDigest, submittedHash, expectedHash, "commercial_authority_invalid",
                        legacyDirection.AliasId, legacyDirection.BindingId, legacyDirection.LicenseSeatId)
                    : await HardwareAuthorityAliasResolver.HasActiveHardwareBanAsync(
                        db, productId, submittedHardwareId, legacyDirection.EffectiveHardwareId, now, cancellationToken)
                    ? Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement.Id,
                        grantRefDigest, submittedHash, expectedHash, "hardware_banned",
                        legacyDirection.AliasId, legacyDirection.BindingId, legacyDirection.LicenseSeatId)
                    : new FinalizeAuthorityPairResponse(ResponseSchema, requestId, payloadDigestSha256!, productId, licenseId,
                        entitlement.Id, grantRefDigest, "alias-matched", submittedHash,
                        expectedHash, expectedHash, "stable-expected-legacy-submitted",
                        legacyDirection.AliasId, legacyDirection.BindingId, legacyDirection.LicenseSeatId, null);
            }
            else if (legacyDirection.Status == HardwareAuthorityResolutionStatus.Refused)
            {
                response = Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement.Id,
                    grantRefDigest, submittedHash, expectedHash,
                    await ClassifyAliasRefusalAsync(db, legacyDirection, expectedHash, canonicalExpected: true, cancellationToken),
                    legacyDirection.AliasId, legacyDirection.BindingId, legacyDirection.LicenseSeatId);
            }
            else
            {
                // Direction B: the Desktop presents the canonical stable member (marker kept); the grant froze
                // the legacy digest, which happens for grants issued before the server recognized the machine.
                var stableDirection = await resolver.ResolveByCanonicalAsync(
                    db, productId, licenseId, submittedHardwareId, expectedHash,
                    HardwareAuthorityResolutionIntent.Finalize, cancellationToken);
                if (stableDirection.Status == HardwareAuthorityResolutionStatus.Resolved)
                {
                    response = !await HasCurrentAliasAssignmentAsync(
                            db, stableDirection, licenseId, now, cancellationToken)
                        ? Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement.Id,
                            grantRefDigest, submittedHash, expectedHash, "commercial_authority_invalid",
                            stableDirection.AliasId, stableDirection.BindingId, stableDirection.LicenseSeatId)
                        : await HardwareAuthorityAliasResolver.HasActiveHardwareBanAsync(
                            db, productId, submittedHardwareId, stableDirection.EffectiveHardwareId, now, cancellationToken)
                        ? Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement.Id,
                            grantRefDigest, submittedHash, expectedHash, "hardware_banned",
                            stableDirection.AliasId, stableDirection.BindingId, stableDirection.LicenseSeatId)
                        : new FinalizeAuthorityPairResponse(ResponseSchema, requestId, payloadDigestSha256!, productId, licenseId,
                            entitlement.Id, grantRefDigest, "alias-matched", submittedHash,
                            expectedHash, submittedHash, "legacy-expected-stable-submitted",
                            stableDirection.AliasId, stableDirection.BindingId, stableDirection.LicenseSeatId, null);
                }
                else if (stableDirection.Status == HardwareAuthorityResolutionStatus.Refused)
                {
                    response = Refused(requestId, payloadDigestSha256!, productId, licenseId, entitlement.Id,
                        grantRefDigest, submittedHash, expectedHash,
                        await ClassifyAliasRefusalAsync(db, stableDirection, expectedHash, canonicalExpected: false, cancellationToken),
                        stableDirection.AliasId, stableDirection.BindingId, stableDirection.LicenseSeatId);
                }
                else
                {
                    response = new FinalizeAuthorityPairResponse(ResponseSchema, requestId, payloadDigestSha256!, productId, licenseId,
                        entitlement.Id, grantRefDigest, "mismatch", submittedHash,
                        expectedHash, null, "none", null, null, null, null);
                }
            }
        }
        if (transaction is not null) await transaction.CommitAsync(cancellationToken);
        // Diagnostic HWID volontaire (TKT-001277/TKT-001296) : identifiants en clair pendant l'analyse.
        _logger.LogWarning(
            "HWID_DIAGNOSIS finalize-pair requestId={RequestId} payloadDigest={PayloadDigest} clientId={ClientId} productId={ProductId} licenseId={LicenseId} submitted={Submitted} submittedHash={SubmittedHash} expectedHash={ExpectedHash} outcome={Outcome} direction={Direction} canonicalEffectiveHash={CanonicalEffectiveHash} aliasId={AliasId} bindingId={BindingId} seatId={SeatId} refusalReason={RefusalReason} serverVersion={ServerVersion}",
            requestId, payloadDigestSha256, clientId, productId, licenseId, submittedHardwareId, submittedHash, expectedHash,
            response.Outcome, response.PairMatchedDirection, response.CanonicalEffectiveHardwareIdHash,
            response.AliasId, response.BindingId, response.LicenseSeatId, response.RefusalReason,
            typeof(FinalizeAuthorityPairResolver).Assembly.GetName().Version);
        return response;
    }

    /// <summary>Refines only a refused, intact historical graph whose current assignment changed; the requested opposite digest must still be the exact server alias member.</summary>
    /// <remarks>The witness is produced after source validation, never by a request. This method cannot resolve an alias, return hardware, or relax commercial or structural refusals.</remarks>
    private static async Task<string> ClassifyAliasRefusalAsync(
        LicenseDbContext db, HardwareAuthorityResolution resolution, string expectedDigest,
        bool canonicalExpected, CancellationToken cancellationToken)
    {
        if (resolution.Refused
            && resolution.RefusalReason == HardwareAuthorityRefusalReason.AuthorityGraphDiverged
            && resolution.CommercialAssignmentOnlyRefusal
            && await db.HardwareAuthorityAliases.AsNoTracking().AnyAsync(alias =>
                alias.Id == resolution.AliasId && alias.BindingId == resolution.BindingId
                && alias.LicenseSeatId == resolution.LicenseSeatId && alias.IsActive && alias.DisabledAtUtc == null
                && (canonicalExpected ? alias.CanonicalHardwareIdSha256 : alias.LegacyHardwareIdSha256) == expectedDigest,
                cancellationToken))
            return "commercial_authority_invalid";
        return resolution.RefusalReason?.ToString() ?? "alias_refused";
    }

    /// <summary>
    /// Rechecks alias based grants against the independent current assignment. The alias remains signed
    /// historical proof; copied enrollment licence, seat, and hardware values never grant access.
    /// </summary>
    /// <param name="db">Transaction holding distribution, commercial barrier, and hardware locks.</param>
    /// <param name="resolution">Authenticated alias result identifying the historical binding and seat.</param>
    /// <param name="licenseId">Current distribution licence that the assignment must match exactly.</param>
    /// <param name="now">Provider time sampled after every decisive lock wait.</param>
    /// <param name="cancellationToken">Cancels relational reads without converting failure to denial.</param>
    /// <returns><see langword="true"/> only when one current assignment matches the resolved seat and policy.</returns>
    /// <exception cref="DistributionOperationException">The assignment relation is missing, ambiguous, or unavailable.</exception>
    private static async Task<bool> HasCurrentAliasAssignmentAsync(
        LicenseDbContext db,
        HardwareAuthorityResolution resolution,
        Guid licenseId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        if (resolution.BindingId is not Guid bindingId || resolution.LicenseSeatId is not Guid seatId)
            return false;
        var enrollments = await db.RuntimeEnrollments.AsNoTracking()
            .Where(candidate => candidate.BindingId == bindingId)
            .Take(2).ToListAsync(cancellationToken);
        if (enrollments.Count != 1)
            throw new DistributionOperationException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                enrollments.Count == 0 ? "assignment_enrollment_missing" : "assignment_enrollment_ambiguous");
        try
        {
            var assessment = await RuntimeCommercialEligibilityValidator.AssessAsync(
                db, enrollments[0], new Dictionary<string, string>(StringComparer.Ordinal),
                new DateTimeOffset(now, TimeSpan.Zero), null,
                RuntimeCommercialEligibilityValidator.HardwareBanAssessmentMode.DeferToCaller,
                cancellationToken);
            var assignment = assessment.Assignment;
            if (assignment is null) return false;
            return assignment.LicenseId == licenseId && assignment.SeatId == seatId
                && HardwareAuthorityAliasResolver.IsCanonicalHardwareId(resolution.EffectiveHardwareId)
                && HardwareAuthorityAliasResolver.IsCanonicalHardwareId(assignment.HardwareId)
                && string.Equals(
                    resolution.EffectiveHardwareId, assignment.HardwareId, StringComparison.Ordinal);
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
        {
            return false;
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.StatusCode == StatusCodes.Status503ServiceUnavailable)
        {
            throw new DistributionOperationException(
                "authority_unavailable", StatusCodes.Status503ServiceUnavailable, exception.DiagnosticCode);
        }
    }

    private static FinalizeAuthorityPairResponse Refused(
        string requestId, string payloadDigestSha256, Guid productId, Guid licenseId, Guid? entitlementId,
        string grantRefDigestSha256, string submittedHash, string expectedHash, string reason,
        Guid? aliasId, Guid? bindingId, Guid? seatId) =>
        new(ResponseSchema, requestId, payloadDigestSha256, productId, licenseId, entitlementId,
            grantRefDigestSha256, "refused", submittedHash, expectedHash, null, "none",
            aliasId, bindingId, seatId, reason);

    private static bool TryCanonicalUuid(string? value, out string canonical)
    {
        canonical = string.Empty;
        if (value is null || value.Length != 36 || !Guid.TryParseExact(value, "D", out var parsed)) return false;
        canonical = parsed.ToString("D");
        return string.Equals(canonical, value, StringComparison.Ordinal);
    }

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256Pattern();
}

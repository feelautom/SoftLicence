using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Evaluates machine eligibility before Website may expose payload authority.</summary>
public interface IRuntimeDistributionPreflightService
{
    /// <summary>
    /// Evaluates an authenticated authority request, derives identity only for an unknown install,
    /// verifies the exact commercial entitlement, and commits a privacy-bounded decision record.
    /// </summary>
    /// <param name="clientId">Exact authenticated S2S principal; never accepted from the body.</param>
    /// <param name="payloadDigestSha256">Lowercase digest of the authenticated exact request bytes.</param>
    /// <param name="request">Closed request already authenticated by the controller.</param>
    /// <param name="cancellationToken">Cancels database access without converting cancellation to a refusal.</param>
    /// <returns>An accepted opaque digest after the decision record is durable.</returns>
    /// <exception cref="DistributionOperationException">The contract, commercial authority, hardware authority, or provider state fails closed.</exception>
    Task<RuntimeDistributionPreflightResponse> EvaluateAsync(
        string clientId,
        string payloadDigestSha256,
        RuntimeDistributionPreflightRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Keeps the canonical hardware algorithm and ban lookup inside SoftLicence.</summary>
public sealed partial class RuntimeDistributionPreflightService : IRuntimeDistributionPreflightService
{
    /// <summary>Exact request schema accepted across the authenticated Website boundary.</summary>
    internal const string RequestSchema = "runtime-distribution-hardware-authority";
    /// <summary>Exact response schema returned without raw or reusable hardware identifiers.</summary>
    internal const string ResponseSchema = "runtime-distribution-hardware-authority-result";
    /// <summary>Creates isolated contexts so raw observations never outlive the active evaluation.</summary>
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    /// <summary>Writes privacy-bounded operational evidence after authentication.</summary>
    private readonly ILogger<RuntimeDistributionPreflightService> _logger;
    /// <summary>Stores the machine evidence reported with an unknown installation (TKT-001277).</summary>
    private readonly MachineIdentityObservationService _machineIdentityObservations;

    /// <summary>Creates the provider authority over the shared relational decision boundary.</summary>
    /// <param name="dbFactory">Factory for isolated decision contexts.</param>
    /// <param name="logger">Logger for decisions and diagnostics.</param>
    /// <param name="machineIdentityObservations">Evidence store; a private instance is created when omitted (tests).</param>
    public RuntimeDistributionPreflightService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<RuntimeDistributionPreflightService> logger,
        MachineIdentityObservationService? machineIdentityObservations = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _machineIdentityObservations = machineIdentityObservations ?? new MachineIdentityObservationService(
            dbFactory, Microsoft.Extensions.Logging.Abstractions.NullLogger<MachineIdentityObservationService>.Instance);
    }

    /// <summary>
    /// Serializes one authenticated logical request, reuses exact replays, verifies entitlement and
    /// machine authority, and commits the decision atomically with any eligible paid auto-unban.
    /// </summary>
    /// <remarks>
    /// Raw observations remain request-local. PostgreSQL uses a request lock, commercial graph locks,
    /// the item-2 shared barrier for a known enrollment, and canonical hardware-ban locks. Accepted
    /// replays recheck current authority before returning frozen bytes; refused replays stay inert.
    /// A paid allowlisted ban causes one side-effect-free read pass to roll back and one mutation pass
    /// to recompute authority after acquiring exclusive global authority first. A registry write failure
    /// prevents success and divergent request reuse is rejected.
    /// </remarks>
    public async Task<RuntimeDistributionPreflightResponse> EvaluateAsync(
        string clientId,
        string payloadDigestSha256,
        RuntimeDistributionPreflightRequest request,
        CancellationToken cancellationToken)
    {
        var response = await EvaluatePassAsync(
            clientId, payloadDigestSha256, request, mutationPass: false, cancellationToken);
        if (response is not null) return response;

        return await EvaluatePassAsync(
                clientId, payloadDigestSha256, request, mutationPass: true, cancellationToken)
            ?? throw ServiceUnavailable("auto_unban_restart_exhausted");
    }

    /// <summary>
    /// Evaluates one bounded preflight pass. The read pass returns <see langword="null"/> only when
    /// paid auto-unban is required; its transaction is rolled back before the caller starts the sole
    /// mutation pass with exclusive global authority. No entity, timestamp, or classification crosses
    /// that restart boundary.
    /// </summary>
    /// <param name="clientId">Exact authenticated S2S principal.</param>
    /// <param name="payloadDigestSha256">Digest of the authenticated exact request bytes.</param>
    /// <param name="request">Closed authenticated request.</param>
    /// <param name="mutationPass">Whether exclusive global authority must precede every narrower lock.</param>
    /// <param name="cancellationToken">Cancels database access without granting authority.</param>
    /// <returns>The completed response, or null after a side-effect-free PostgreSQL restart request.</returns>
    private async Task<RuntimeDistributionPreflightResponse?> EvaluatePassAsync(
        string clientId,
        string payloadDigestSha256,
        RuntimeDistributionPreflightRequest request,
        bool mutationPass,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.ExtensionData is { Count: > 0 }
            || !string.Equals(request.Schema, RequestSchema, StringComparison.Ordinal)
            || !TryCanonicalUuid(request.RequestId, out var requestId)
            || !TryCanonicalUuid(request.ProductId, out var productIdText)
            || !TryCanonicalUuid(request.SoftLicenceLicenseId, out var licenseIdText)
            || !Sha256Pattern().IsMatch(request.GrantRefDigestSha256 ?? string.Empty)
            || !Sha256Pattern().IsMatch(payloadDigestSha256)
            || string.IsNullOrWhiteSpace(clientId) || clientId.Length > 64)
            throw InvalidRequest();

        var productId = Guid.ParseExact(productIdText, "D");
        var licenseId = Guid.ParseExact(licenseIdText, "D");
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(
                db.Database.IsNpgsql() ? System.Data.IsolationLevel.ReadCommitted
                    : System.Data.IsolationLevel.Serializable,
                cancellationToken)
            : null;
        if (mutationPass)
            await SecurityService.AcquireHardwareBanGlobalMutationAsync(db);
        if (db.Database.IsNpgsql())
        {
            var replayLock = $"runtime-distribution-preflight:{clientId}:{requestId}";
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtextextended({replayLock}, 0))", cancellationToken);
        }
        var replay = await db.RuntimeDistributionHardwareDecisions.SingleOrDefaultAsync(
            candidate => candidate.ClientId == clientId && candidate.RequestId == requestId,
            cancellationToken);
        if (replay is not null)
        {
            if (!string.Equals(replay.PayloadDigestSha256, payloadDigestSha256, StringComparison.Ordinal))
            {
                _logger.LogWarning(
                    "Runtime distribution preflight rejected divergent replay for client {ClientId}, request {RequestId}, audit {AuditId}.",
                    clientId, requestId, replay.Id);
                throw InvalidRequest();
            }
            if (replay.Outcome == "refused")
            {
                replay.AttemptCount++;
                replay.LastSeenAtUtc = await ReadDatabaseClockAsync(db, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
                if (transaction is not null) await transaction.CommitAsync(cancellationToken);
                LogDecision(replay, replay: true);
                throw Denial(replay.ReasonCode);
            }
        }

        await AcquireCommercialAuthorityReadLocksAsync(
            db, clientId, productId, licenseId, request.GrantRefDigestSha256!, cancellationToken);
        var requestedAuthorityMode = request.HardwareIdHash is null ? "server-derived" : "digest-revalidation";

        string hardwareIdHash;
        string authorityMode;
        string? installationIdHash = null;
        IReadOnlyCollection<string?> hardwareCandidates;
        RuntimeEnrollment? knownEnrollment = null;
        Action? emitHardwareDiagnosis = null;
        string? identityRefusal = null;
        if (request.HardwareIdHash is not null)
        {
            if (request.HardwareEvidence is not null || request.InstallationId is not null
                || request.KeyThumbprint is not null
                || !Sha256Pattern().IsMatch(request.HardwareIdHash))
                throw InvalidRequest();
            hardwareIdHash = request.HardwareIdHash;
            authorityMode = "digest-revalidation";
            await SecurityService.AcquireHardwareBanDigestMutationAsync(db, hardwareIdHash);
            hardwareCandidates = [];
        }
        else if (!TryCanonicalUuid(request.InstallationId, out var installationId)
            || request.KeyThumbprint is null
            || !ThumbprintPattern().IsMatch(request.KeyThumbprint))
        {
            throw InvalidRequest();
        }
        else
        {
            installationIdHash = Sha256Lower(installationId);
            var installationExists = await db.RuntimeEnrollments.AsNoTracking().AnyAsync(
                candidate => candidate.ProductId == productId && candidate.InstallationId == installationId,
                cancellationToken);
            var known = await db.RuntimeEnrollments.AsNoTracking().SingleOrDefaultAsync(
                candidate => candidate.ProductId == productId && candidate.InstallationId == installationId
                    && candidate.KeyThumbprint == request.KeyThumbprint && candidate.State == "ACTIVE",
                cancellationToken);
            if (installationExists && known is null)
            {
                var mismatchNow = await ReadDatabaseClockAsync(db, cancellationToken);
                var mismatchLicense = await db.Licenses.Include(candidate => candidate.Type)
                    .SingleOrDefaultAsync(candidate => candidate.Id == licenseId && candidate.ProductId == productId,
                        cancellationToken);
                var mismatchActive = mismatchLicense?.IsActive == true;
                var mismatchRevoked = mismatchLicense?.RevokedAt is not null;
                var mismatchExpired = mismatchLicense?.ExpirationDate is DateTime mismatchExpiry
                    && mismatchNow > mismatchExpiry;
                return await RefuseAsync(db, transaction, replay, clientId, requestId, payloadDigestSha256,
                    productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash,
                    "known-enrollment", "installation_key_mismatch", [], mismatchActive, mismatchRevoked,
                    mismatchExpired, mismatchLicense is not null
                        && SecurityService.IsPaidLicenseEligibleForAutoUnban(mismatchLicense, mismatchNow),
                    cancellationToken);
            }
            if (known is not null)
            {
                if (request.HardwareEvidence is not null) throw InvalidRequest();
                if (db.Database.IsNpgsql())
                {
                    // Match item-2's enrollment-row -> commercial-barrier order. A writer that already
                    // changed identity wins, commits its deferred trigger, and is observed by the reread.
                    await db.Database.ExecuteSqlInterpolatedAsync(
                        $"SELECT 1 FROM \"RuntimeEnrollments\" WHERE \"Id\" = {known.Id} FOR SHARE",
                        cancellationToken);
                    await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
                    known = await db.RuntimeEnrollments.AsNoTracking().SingleOrDefaultAsync(
                        candidate => candidate.Id == known.Id && candidate.ProductId == productId
                            && candidate.InstallationId == installationId
                            && candidate.KeyThumbprint == request.KeyThumbprint && candidate.State == "ACTIVE",
                        cancellationToken);
                    if (known is null)
                    {
                        var changedNow = await ReadDatabaseClockAsync(db, cancellationToken);
                        var changedLicense = await db.Licenses.Include(candidate => candidate.Type)
                            .SingleOrDefaultAsync(candidate => candidate.Id == licenseId
                                && candidate.ProductId == productId, cancellationToken);
                        var changedActive = changedLicense?.IsActive == true;
                        var changedRevoked = changedLicense?.RevokedAt is not null;
                        var changedExpired = changedLicense?.ExpirationDate is DateTime changedExpiry
                            && changedNow > changedExpiry;
                        return await RefuseAsync(db, transaction, replay, clientId, requestId,
                            payloadDigestSha256, productId, licenseId, request.GrantRefDigestSha256!, request,
                            installationIdHash, "known-enrollment", "identity_authority_changed", [],
                            changedActive, changedRevoked, changedExpired, changedLicense is not null
                                && SecurityService.IsPaidLicenseEligibleForAutoUnban(changedLicense, changedNow),
                            cancellationToken);
                    }
                }
                var assignments = await db.EnrollmentLicenseAssignments.AsNoTracking()
                    .Where(candidate => candidate.EnrollmentId == known.Id && candidate.State == "ACTIVE")
                    .Take(2).ToListAsync(cancellationToken);
                if (assignments.Count > 1) throw ServiceUnavailable("assignment_duplicate_active");
                if (assignments.Count == 0)
                {
                    var quarantined = await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
                        .AnyAsync(candidate => candidate.EnrollmentId == known.Id, cancellationToken);
                    return await RefuseAsync(db, transaction, replay, clientId, requestId, payloadDigestSha256,
                        productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash,
                        "known-enrollment", quarantined ? "assignment_quarantined" : "assignment_missing",
                        [], false, false, false, false, cancellationToken);
                }
                var seatHardware = await db.LicenseSeats.AsNoTracking()
                    .Where(candidate => candidate.Id == assignments[0].LicenseSeatId)
                    .Select(candidate => candidate.HardwareId).SingleOrDefaultAsync(cancellationToken);
                if (string.IsNullOrWhiteSpace(seatHardware)) throw ServiceUnavailable("assignment_relation_missing");
                hardwareIdHash = Sha256Lower(seatHardware);
                authorityMode = "known-enrollment";
                knownEnrollment = known;
                await SecurityService.AcquireHardwareBanDigestMutationAsync(db, hardwareIdHash);
                hardwareCandidates = [];
            }
            else
            {
                // TKT-001277 lot 2c: the identifier is derived from the system UUID only, with the exact SDK rule.
                // The WebSetup sends observations and never an identifier; a refused UUID is refused with its
                // support code after the commercial checks below, and the evidence is stored for investigation.
                var evidence = ValidateEvidence(request.HardwareEvidence);
                var identity = MachineIdentity.FromUuid(evidence.SystemUuid);
                authorityMode = "server-derived";
                identityRefusal = identity.RefusalCode;
                // TKT-001277 review M1: a UUID the WebSetup could not read is reported as unreadable (AR-02), like the
                // SDK does, instead of absent (AR-01). The unsigned indicator only chooses between two refusals, and the
                // same final classification feeds the response, the stored observation and the diagnosis log.
                if (identityRefusal == MachineIdentity.RefusalUuidAbsent && ReportsUnreadableUuid(evidence.MachineEvidence))
                    identityRefusal = MachineIdentity.RefusalUuidUnreadable;
                await _machineIdentityObservations.ObserveDerivedAsync(
                    productId, evidence.SystemUuid, evidence.MachineEvidence, "PREFLIGHT", cancellationToken,
                    identityRefusal);
                hardwareIdHash = identity.IsAccepted ? Sha256Lower(identity.HardwareId!) : string.Empty;
                // Diagnostic volontaire (TKT-001277/TKT-001294) : identifiants produit/licence/installation pour
                // dedupliquer par client ; son retrait est une decision explicite, pas un nettoyage.
                emitHardwareDiagnosis = () => _logger.LogWarning(
                    "HWID_DIAGNOSIS preflight requestId={RequestId} productId={ProductId} licenseId={LicenseId} installationId={InstallationId} systemUuid={SystemUuid} hardwareId={HardwareId} hardwareIdHash={HardwareIdHash} refusal={Refusal} serverVersion={ServerVersion}",
                    requestId, productId, licenseId, request.InstallationId, identity.CanonicalUuid, identity.HardwareId,
                    hardwareIdHash, identityRefusal, typeof(RuntimeDistributionPreflightService).Assembly.GetName().Version);
                hardwareCandidates = identity.IsAccepted ? [identity.HardwareId] : [];
                if (identity.IsAccepted)
                    await SecurityService.AcquireHardwareBanMutationsAsync(db, [identity.HardwareId!]);
            }
        }

        var now = await ReadDatabaseClockAsync(db, cancellationToken);
        var entitlement = await db.DistributionEntitlements.AsNoTracking().SingleOrDefaultAsync(candidate =>
            candidate.ClientId == clientId && candidate.ProductId == productId
            && candidate.LicenseId == licenseId
            && candidate.GrantRefDigestSha256 == request.GrantRefDigestSha256
            && (candidate.State == "issued" || candidate.State == "finalized")
            && candidate.ExpiresAtUtc > now,
            cancellationToken);
        var license = await db.Licenses.Include(candidate => candidate.Type).SingleOrDefaultAsync(candidate =>
            candidate.Id == licenseId && candidate.ProductId == productId,
            cancellationToken);
        var licenseActive = license?.IsActive == true;
        var licenseRevoked = license?.RevokedAt is not null;
        var licenseExpired = license?.ExpirationDate is DateTime expiration && now > expiration;
        var paidAutoUnbanEligible = license is not null
            && SecurityService.IsPaidLicenseEligibleForAutoUnban(license, now);
        if (entitlement is null || license is null || !licenseActive || licenseRevoked || licenseExpired)
        {
            emitHardwareDiagnosis?.Invoke();
            return await RefuseAsync(db, transaction, replay, clientId, requestId, payloadDigestSha256,
                productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash, requestedAuthorityMode,
                "commercial_authority_invalid", [], licenseActive, licenseRevoked, licenseExpired,
                paidAutoUnbanEligible, cancellationToken);
        }

        if (identityRefusal is not null)
        {
            emitHardwareDiagnosis?.Invoke();
            return await RefuseAsync(db, transaction, replay, clientId, requestId, payloadDigestSha256,
                productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash, authorityMode,
                identityRefusal, [], licenseActive, licenseRevoked, licenseExpired,
                paidAutoUnbanEligible, cancellationToken);
        }

        if (knownEnrollment is not null)
        {
            try
            {
                var approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
                    db, knownEnrollment, cancellationToken);
                var assessment = await RuntimeCommercialEligibilityValidator.AssessAsync(
                    db, knownEnrollment, approved.Binaries, new DateTimeOffset(now, TimeSpan.Zero),
                    null, RuntimeCommercialEligibilityValidator.HardwareBanAssessmentMode.DeferToCaller,
                    cancellationToken);
                var assignment = assessment.Assignment;
                if (assignment is null)
                    throw new RuntimeEnrollmentException(
                        "authority_ineligible", StatusCodes.Status422UnprocessableEntity,
                        assessment.DenialReason ?? "commercial_authority_ineligible");
                if (assignment.LicenseId != licenseId
                    || !string.Equals(hardwareIdHash, Sha256Lower(assignment.HardwareId), StringComparison.Ordinal))
                    return await RefuseAsync(db, transaction, replay, clientId, requestId, payloadDigestSha256,
                        productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash, authorityMode,
                        "assignment_scope_mismatch", [], licenseActive, licenseRevoked, licenseExpired,
                        paidAutoUnbanEligible, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception) when (
                exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            {
                return await RefuseAsync(db, transaction, replay, clientId, requestId, payloadDigestSha256,
                    productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash, authorityMode,
                    exception.DiagnosticCode ?? "commercial_authority_ineligible", [], licenseActive, licenseRevoked, licenseExpired,
                    paidAutoUnbanEligible, cancellationToken);
            }
            catch (RuntimeEnrollmentException exception) when (
                exception.StatusCode == StatusCodes.Status503ServiceUnavailable)
            {
                throw ServiceUnavailable(exception.DiagnosticCode ?? "commercial_authority_unavailable");
            }
        }

        var activeBans = request.HardwareIdHash is not null || knownEnrollment is not null
            ? await LoadBansByDigestAsync(db, hardwareIdHash, productId, now, cancellationToken)
            : await LoadBansByHardwareIdsAsync(db, hardwareCandidates, productId, now, cancellationToken);

        var categories = activeBans.Select(candidate => candidate.BanCategory ?? BannedHardwareId.Categories.Manual)
            .Distinct(StringComparer.Ordinal).OrderBy(candidate => candidate, StringComparer.Ordinal).ToArray();
        if (activeBans.Count > 0 && (!paidAutoUnbanEligible
            || !SecurityService.AreAllHardwareBansAutoUnbannable(activeBans)))
        {
            emitHardwareDiagnosis?.Invoke();
            return await RefuseAsync(db, transaction, replay, clientId, requestId, payloadDigestSha256,
                productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash,
                authorityMode, "hardware_banned", categories, licenseActive, licenseRevoked,
                licenseExpired, paidAutoUnbanEligible, cancellationToken, hardwareIdHash);
        }

        if (replay is not null)
        {
            if (replay.HardwareIdHash is null
                || !string.Equals(replay.HardwareIdHash, hardwareIdHash, StringComparison.Ordinal)
                || !string.Equals(replay.AuthorityMode, authorityMode, StringComparison.Ordinal))
            {
                emitHardwareDiagnosis?.Invoke();
                throw NotEligible("replay_authority_changed");
            }
        }

        if (activeBans.Count > 0 && !mutationPass && db.Database.IsNpgsql())
        {
            if (transaction is not null) await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        emitHardwareDiagnosis?.Invoke();
        if (replay is not null)
        {
            // A paid allowlisted ban is current commercial policy, not frozen replay evidence.
            // Apply the same atomic auto-unban as a new accepted decision after scope equality is proved.
            foreach (var ban in activeBans) ban.IsActive = false;
            replay.AttemptCount++;
            replay.LastSeenAtUtc = now;
            await db.SaveChangesAsync(cancellationToken);
            if (transaction is not null) await transaction.CommitAsync(cancellationToken);
            LogDecision(replay, replay: true);
            return Accepted(requestId, replay.HardwareIdHash!, replay.AuthorityMode);
        }

        foreach (var ban in activeBans) ban.IsActive = false;
        var outcome = activeBans.Count == 0 ? "accepted" : "auto-unbanned";
        db.RuntimeDistributionHardwareDecisions.Add(BuildDecision(clientId, requestId, payloadDigestSha256,
            productId, licenseId, request.GrantRefDigestSha256!, request, hardwareIdHash,
            installationIdHash, authorityMode, outcome, outcome == "accepted" ? "eligible" : "paid_auto_unban",
            categories, licenseActive, licenseRevoked, licenseExpired, paidAutoUnbanEligible,
            activeBans.Count, now));
        await db.SaveChangesAsync(cancellationToken);
        if (transaction is not null) await transaction.CommitAsync(cancellationToken);
        LogDecision(db.RuntimeDistributionHardwareDecisions.Local.Single(), replay: false);
        return Accepted(requestId, hardwareIdHash, authorityMode);
    }

    /// <summary>
    /// Holds shared PostgreSQL row locks for the submitted licence, its type, and matching entitlement
    /// until the decision commits. Concurrent revoke, type-policy, or entitlement mutations must complete
    /// first or wait, so paid auto-unban cannot authorize from commercial facts changed mid-transaction.
    /// </summary>
    internal static async Task AcquireCommercialAuthorityReadLocksAsync(
        LicenseDbContext db, string clientId, Guid productId, Guid licenseId,
        string grantRefDigestSha256, CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql()) return;
        await db.Database.ExecuteSqlRawAsync(
            "SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';",
            cancellationToken);
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT 1 FROM \"Licenses\" WHERE \"Id\" = {licenseId} FOR SHARE",
            cancellationToken);
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT 1 FROM \"LicenseTypes\" AS type_row INNER JOIN \"Licenses\" AS license_row ON license_row.\"LicenseTypeId\" = type_row.\"Id\" WHERE license_row.\"Id\" = {licenseId} FOR SHARE OF type_row",
            cancellationToken);
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT 1 FROM \"DistributionEntitlements\" WHERE \"ClientId\" = {clientId} AND \"ProductId\" = {productId} AND \"LicenseId\" = {licenseId} AND \"GrantRefDigestSha256\" = {grantRefDigestSha256} FOR SHARE",
            cancellationToken);
    }

    /// <summary>
    /// Reads live product-compatible bans after the caller has acquired the irreversible digest lock
    /// and sampled fresh provider time. Every ban writer takes the same lock before mutation.
    /// </summary>
    /// <param name="db">Transaction that already owns the canonical hardware digest lock.</param>
    /// <param name="hardwareIdHash">Lowercase SHA-256 digest selected by the preflight mode.</param>
    /// <param name="productId">Product scope; global bans also apply.</param>
    /// <param name="now">Provider time sampled after lock acquisition.</param>
    /// <param name="cancellationToken">Cancels the database read.</param>
    /// <returns>Tracked active bans whose canonical hardware digest matches exactly.</returns>
    private static async Task<List<BannedHardwareId>> LoadBansByDigestAsync(
        LicenseDbContext db, string hardwareIdHash, Guid productId, DateTime now,
        CancellationToken cancellationToken)
    {
        var lockedCandidates = await db.BannedHardwareIds.Where(ban => ban.IsActive
            && (ban.ProductId == null || ban.ProductId == productId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now)).ToListAsync(cancellationToken);
        return lockedCandidates.Where(candidate => string.Equals(
            Sha256Lower(candidate.HardwareId.ToUpperInvariant()), hardwareIdHash,
            StringComparison.Ordinal)).ToList();
    }

    /// <summary>
    /// Reads tracked live bans after the caller has locked each exact canonical candidate in ordinal
    /// order and sampled fresh provider time. The caller's deterministic order prevents deadlocks.
    /// </summary>
    /// <param name="db">Transaction holding every candidate hardware lock.</param>
    /// <param name="hardwareIds">Canonical legacy and stable candidates; null values are ignored.</param>
    /// <param name="productId">Product scope; global bans also apply.</param>
    /// <param name="now">Provider time sampled after lock acquisition.</param>
    /// <param name="cancellationToken">Cancels the database read.</param>
    /// <returns>Tracked active bans matching one exact candidate.</returns>
    private static async Task<List<BannedHardwareId>> LoadBansByHardwareIdsAsync(
        LicenseDbContext db, IEnumerable<string?> hardwareIds, Guid productId, DateTime now,
        CancellationToken cancellationToken)
    {
        var candidates = hardwareIds.Where(value => value is not null).Select(value => value!.ToUpperInvariant())
            .ToHashSet(StringComparer.Ordinal);
        var rows = await db.BannedHardwareIds.Where(ban => ban.IsActive
            && (ban.ProductId == null || ban.ProductId == productId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now)).ToListAsync(cancellationToken);
        return rows.Where(ban => candidates.Contains(ban.HardwareId.ToUpperInvariant())).ToList();
    }

    /// <summary>
    /// Commits a privacy-bounded refusal in the caller transaction, logs its audit reference, and then
    /// throws the opaque public denial. An accepted replay denial changes no frozen decision or attempt
    /// count. Persistence failure propagates instead of losing evidence.
    /// </summary>
    /// <param name="db">Decision transaction.</param>
    /// <param name="transaction">Relational transaction to commit after a new refusal is durable.</param>
    /// <param name="replay">Existing accepted decision, which must remain immutable on current denial.</param>
    /// <param name="clientId">Authenticated S2S principal.</param>
    /// <param name="requestId">Canonical idempotency identifier.</param>
    /// <param name="payloadDigestSha256">Digest of exact authenticated request bytes.</param>
    /// <param name="productId">Validated product scope.</param>
    /// <param name="licenseId">Requested distribution licence.</param>
    /// <param name="grantRefDigestSha256">Authenticated grant reference digest.</param>
    /// <param name="request">Validated request used only for bounded audit fields.</param>
    /// <param name="installationIdHash">Optional irreversible installation correlation.</param>
    /// <param name="authorityMode">Closed evaluated authority mode.</param>
    /// <param name="reasonCode">Bounded internal refusal reason.</param>
    /// <param name="categories">Current matching ban categories.</param>
    /// <param name="licenseActive">Frozen licence-active observation.</param>
    /// <param name="licenseRevoked">Frozen licence-revoked observation.</param>
    /// <param name="licenseExpired">Frozen licence-expired observation.</param>
    /// <param name="paidAutoUnbanEligible">Frozen paid-policy observation.</param>
    /// <param name="cancellationToken">Cancels persistence without returning authority.</param>
    /// <param name="hardwareIdHash">Optional irreversible hardware correlation.</param>
    /// <returns>This method never returns; its task type permits use in return expressions.</returns>
    /// <exception cref="DistributionOperationException">Always throws the bounded public denial after required persistence.</exception>
    private async Task<RuntimeDistributionPreflightResponse> RefuseAsync(
        LicenseDbContext db, Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction? transaction,
        RuntimeDistributionHardwareDecision? replay,
        string clientId, string requestId, string payloadDigestSha256, Guid productId, Guid licenseId,
        string grantRefDigestSha256, RuntimeDistributionPreflightRequest request, string? installationIdHash,
        string authorityMode, string reasonCode, IReadOnlyCollection<string> categories,
        bool licenseActive, bool licenseRevoked, bool licenseExpired, bool paidAutoUnbanEligible,
        CancellationToken cancellationToken, string? hardwareIdHash = null)
    {
        if (replay is not null)
            throw Denial(reasonCode);
        db.RuntimeDistributionHardwareDecisions.Add(BuildDecision(clientId, requestId, payloadDigestSha256,
            productId, licenseId, grantRefDigestSha256, request, hardwareIdHash, installationIdHash,
            authorityMode, "refused", reasonCode, categories, licenseActive, licenseRevoked,
            licenseExpired, paidAutoUnbanEligible, 0, await ReadDatabaseClockAsync(db, cancellationToken)));
        await db.SaveChangesAsync(cancellationToken);
        if (transaction is not null) await transaction.CommitAsync(cancellationToken);
        LogDecision(db.RuntimeDistributionHardwareDecisions.Local.Single(), replay: false);
        throw Denial(reasonCode);
    }

    /// <summary>Reads provider time after all decisive waits so expiry policy never uses a stale client clock.</summary>
    /// <param name="db">Current authority context.</param>
    /// <param name="cancellationToken">Cancels the provider query.</param>
    /// <returns>PostgreSQL clock time, or process UTC for the nonrelational unit-test provider.</returns>
    private static async Task<DateTime> ReadDatabaseClockAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken) => db.Database.IsNpgsql()
            ? await db.Database.SqlQueryRaw<DateTime>(
                "SELECT pg_catalog.clock_timestamp() AS \"Value\"").SingleAsync(cancellationToken)
            : DateTime.UtcNow;

    /// <summary>
    /// Creates one first-seen decision row with irreversible correlations and frozen commercial facts;
    /// raw machine observations, reusable HWIDs, credentials, and customer data are deliberately omitted.
    /// </summary>
    private static RuntimeDistributionHardwareDecision BuildDecision(
        string clientId, string requestId, string payloadDigestSha256, Guid productId, Guid licenseId,
        string grantRefDigestSha256, RuntimeDistributionPreflightRequest request, string? hardwareIdHash,
        string? installationIdHash, string authorityMode, string outcome, string reasonCode,
        IReadOnlyCollection<string> categories, bool licenseActive, bool licenseRevoked,
        bool licenseExpired, bool paidAutoUnbanEligible, int autoUnbannedCount, DateTime now) => new()
    {
        Id = Guid.NewGuid(), ClientId = clientId, RequestId = requestId,
        PayloadDigestSha256 = payloadDigestSha256, ProductId = productId, LicenseId = licenseId,
        GrantRefDigestSha256 = grantRefDigestSha256, HardwareIdHash = hardwareIdHash,
        InstallationIdHash = installationIdHash, KeyThumbprint = request.KeyThumbprint,
        AuthorityMode = authorityMode, Outcome = outcome, ReasonCode = reasonCode,
        BanCategoriesJson = JsonSerializer.Serialize(categories), LicenseActive = licenseActive,
        LicenseRevoked = licenseRevoked, LicenseExpired = licenseExpired,
        PaidAutoUnbanEligible = paidAutoUnbanEligible,
        AutoUnbannedCount = autoUnbannedCount, AttemptCount = 1,
        CreatedAtUtc = now, LastSeenAtUtc = now
    };

    /// <summary>
    /// Emits one structured post-commit operational event keyed by audit/request identifiers. The event
    /// contains only the same bounded decision metadata as the registry and never raw machine evidence.
    /// </summary>
    private void LogDecision(RuntimeDistributionHardwareDecision decision, bool replay) =>
        _logger.LogInformation(
            "Runtime distribution preflight decision {AuditId}: client {ClientId}, request {RequestId}, product {ProductId}, licence {LicenseId}, mode {AuthorityMode}, outcome {Outcome}, reason {ReasonCode}, categories {BanCategories}, auto-unbanned {AutoUnbannedCount}, attempt {AttemptCount}, replay {Replay}.",
            decision.Id, decision.ClientId, decision.RequestId, decision.ProductId, decision.LicenseId,
            decision.AuthorityMode, decision.Outcome, decision.ReasonCode, decision.BanCategoriesJson,
            decision.AutoUnbannedCount, decision.AttemptCount, replay);

    /// <summary>
    /// Admits only the closed UUID evidence shape. A missing or malformed UUID is not a contract error: it is a
    /// machine refusal decided by <see cref="MachineIdentity.FromUuid"/>. Only an unknown member, a missing evidence
    /// object, or a UUID longer than the stored bound is rejected as an invalid request.
    /// </summary>
    /// <summary>
    /// Returns whether the WebSetup observations state that the UUID read itself failed
    /// (<c>"systemUuidRead": "error"</c>, exact ordinal value). Used only to pick AR-02 over AR-01 for an already
    /// refused machine; it can never turn a refusal into an acceptance.
    /// </summary>
    /// <param name="machineEvidence">Unsigned observation object, or null.</param>
    /// <returns><see langword="true"/> for an explicit read error.</returns>
    internal static bool ReportsUnreadableUuid(JsonElement? machineEvidence) =>
        machineEvidence is { ValueKind: JsonValueKind.Object } evidence
        && evidence.TryGetProperty("systemUuidRead", out var status)
        && status.ValueKind == JsonValueKind.String
        && string.Equals(status.GetString(), "error", StringComparison.Ordinal);

    private static RuntimeDistributionHardwareEvidence ValidateEvidence(
        RuntimeDistributionHardwareEvidence? evidence)
    {
        if (evidence is null || evidence.ExtensionData is { Count: > 0 }
            || evidence.SystemUuid is { Length: > MachineIdentityObservationService.MaxSystemUuidLength })
            throw InvalidRequest();
        return evidence;
    }

    /// <summary>Creates the irreversible lowercase digest allowed to cross back into Website storage.</summary>
    private static string Sha256Lower(string value)
    {
        using var sha256 = SHA256.Create();
        return Convert.ToHexString(sha256.ComputeHash(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    /// <summary>Builds the closed accepted response without raw observations or a reusable HWID.</summary>
    private static RuntimeDistributionPreflightResponse Accepted(
        string requestId,
        string hardwareIdHash,
        string authorityMode) => new(
            ResponseSchema, requestId, "accepted", hardwareIdHash, authorityMode);

    /// <summary>Creates the bounded caller-error refusal used for malformed contracts.</summary>
    private static DistributionOperationException InvalidRequest() =>
        new("invalid_request", StatusCodes.Status400BadRequest);

    /// <summary>Creates the indistinguishable refusal used for a banned or mismatched installation.</summary>
    private static DistributionOperationException NotEligible(string? reasonCode = null) =>
        new("not_eligible", StatusCodes.Status403Forbidden, reasonCode);

    /// <summary>Public error code of a machine refused by the UUID rule (TKT-001277).</summary>
    internal const string DeviceRefusedErrorCode = "device_refused";

    /// <summary>
    /// Maps an internal refusal reason to its public denial. UUID refusals become <c>device_refused</c> carrying only
    /// the customer support code (AR-xx) so the WebSetup can show "Appareil refusé (code AR-xx)"; every other reason
    /// keeps the indistinguishable <c>not_eligible</c> denial.
    /// </summary>
    /// <param name="reasonCode">Internal refusal reason recorded in the decision.</param>
    /// <returns>The public exception to throw.</returns>
    private static DistributionOperationException Denial(string? reasonCode)
    {
        var supportCode = MachineIdentity.ToSupportCode(reasonCode);
        return supportCode is not null && !string.Equals(supportCode, "AR-00", StringComparison.Ordinal)
            ? new DistributionOperationException(DeviceRefusedErrorCode, StatusCodes.Status403Forbidden, supportCode)
            : NotEligible(reasonCode);
    }

    /// <summary>Creates a fail-closed response for malformed provider-owned enrollment state.</summary>
    private static DistributionOperationException ServiceUnavailable() =>
        new("service_unavailable", StatusCodes.Status503ServiceUnavailable);

    /// <summary>Preserves one bounded internal infrastructure diagnostic without changing the public 503.</summary>
    /// <param name="diagnosticCode">Internal closed reason that contains no credential or hardware value.</param>
    /// <returns>A public service-unavailable exception with the bounded internal reason.</returns>
    private static DistributionOperationException ServiceUnavailable(string diagnosticCode) =>
        new("service_unavailable", StatusCodes.Status503ServiceUnavailable, diagnosticCode);

    /// <summary>Accepts only lowercase canonical D-format UUID spelling without normalization.</summary>
    private static bool TryCanonicalUuid(string? value, out string canonical)
    {
        canonical = string.Empty;
        if (!Guid.TryParseExact(value, "D", out var parsed)) return false;
        canonical = parsed.ToString("D");
        return string.Equals(value, canonical, StringComparison.Ordinal);
    }

    /// <summary>Matches an exact unpadded base64url SHA-256 key thumbprint.</summary>
    [GeneratedRegex("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex ThumbprintPattern();

    /// <summary>Matches the only hardware digest representation accepted across services.</summary>
    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();
}

using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
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
    /// <summary>Creates the provider authority over the shared relational decision boundary.</summary>
    public RuntimeDistributionPreflightService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<RuntimeDistributionPreflightService> logger,
        IOptions<HardwareAuthorityAliasOptions>? aliasOptions = null,
        ILoggerFactory? loggerFactory = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _aliasOptions = aliasOptions ?? Options.Create(new HardwareAuthorityAliasOptions());
        _loggerFactory = loggerFactory ?? Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
    }

    private readonly IOptions<HardwareAuthorityAliasOptions> _aliasOptions;
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>
    /// Serializes one authenticated logical request, reuses exact replays, verifies entitlement and
    /// machine authority, and commits the decision atomically with any eligible paid auto-unban.
    /// </summary>
    /// <remarks>
    /// Raw observations remain request-local. PostgreSQL uses a request lock plus canonical hardware-ban
    /// locks; a registry write failure prevents success. Divergent request reuse is rejected.
    /// </remarks>
    public async Task<RuntimeDistributionPreflightResponse> EvaluateAsync(
        string clientId,
        string payloadDigestSha256,
        RuntimeDistributionPreflightRequest request,
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
            replay.AttemptCount++;
            replay.LastSeenAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            if (transaction is not null) await transaction.CommitAsync(cancellationToken);
            LogDecision(replay, replay: true);
            if (replay.Outcome == "refused") throw NotEligible(replay.ReasonCode);
            if (replay.HardwareIdHash is null) throw ServiceUnavailable();
            return Accepted(requestId, replay.HardwareIdHash, replay.AuthorityMode);
        }

        var now = DateTime.UtcNow;
        await AcquireCommercialAuthorityReadLocksAsync(
            db, clientId, productId, licenseId, request.GrantRefDigestSha256!, cancellationToken);
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
        var requestedAuthorityMode = request.HardwareIdHash is null ? "server-derived" : "digest-revalidation";

        if (entitlement is null || license is null || !licenseActive || licenseRevoked || licenseExpired)
            return await RefuseAsync(db, transaction, clientId, requestId, payloadDigestSha256,
                productId, licenseId, request.GrantRefDigestSha256!, request, null, requestedAuthorityMode,
                "commercial_authority_invalid", [], licenseActive, licenseRevoked, licenseExpired,
                paidAutoUnbanEligible, cancellationToken);

        string hardwareIdHash;
        string authorityMode;
        string? installationIdHash = null;
        List<BannedHardwareId> activeBans;
        if (request.HardwareIdHash is not null)
        {
            if (request.HardwareEvidence is not null || request.InstallationId is not null
                || request.KeyThumbprint is not null
                || !Sha256Pattern().IsMatch(request.HardwareIdHash))
                throw InvalidRequest();
            hardwareIdHash = request.HardwareIdHash;
            authorityMode = "digest-revalidation";
            activeBans = await FindBansByDigestAsync(db, hardwareIdHash, productId, now, cancellationToken);
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
                return await RefuseAsync(db, transaction, clientId, requestId, payloadDigestSha256,
                    productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash,
                    "known-enrollment", "installation_key_mismatch", [], licenseActive, licenseRevoked,
                    licenseExpired, paidAutoUnbanEligible, cancellationToken);
            if (known is not null)
            {
                if (request.HardwareEvidence is not null) throw InvalidRequest();
                if (!Sha256Pattern().IsMatch(known.HardwareIdHash)) throw ServiceUnavailable();
                hardwareIdHash = known.HardwareIdHash;
                authorityMode = "known-enrollment";
                activeBans = await FindBansByDigestAsync(db, hardwareIdHash, productId, now, cancellationToken);
            }
            else
            {
                var evidence = ValidateEvidence(request.HardwareEvidence);
                var legacyHardwareId = ComputeHardwareId(evidence, evidence.LegacyDiskId!);
                var stableHardwareId = IsMissing(evidence.StableDiskId)
                    ? null : ComputeHardwareId(evidence, evidence.StableDiskId!);
                hardwareIdHash = Sha256Lower(legacyHardwareId);
                authorityMode = "server-derived";
                // TKT-001296: a machine the server no longer recognizes by installation and key may still be
                // known through the authenticated alias created by its signed migration. When the complete
                // alias graph proves that the legacy candidate maps to this exact stable candidate, the stable
                // digest is chosen so a Desktop that kept its stable marker matches at Finalize. Every
                // compatibility refusal keeps the historical legacy choice and is only diagnosed: no client
                // that is tolerated today becomes blocked here. Bans on both candidates are verified below.
                var recognition = "no-alias";
                Guid? recognizedAliasId = null;
                if (stableHardwareId is not null
                    && !string.Equals(legacyHardwareId, stableHardwareId, StringComparison.Ordinal))
                {
                    var resolver = new HardwareAuthorityAliasResolver(
                        db, _aliasOptions, _loggerFactory.CreateLogger<HardwareAuthorityAliasResolver>());
                    var recognized = await resolver.ResolveAsync(
                        db, productId, licenseId, legacyHardwareId,
                        HardwareAuthorityResolutionIntent.DistributionPreflight, cancellationToken);
                    if (recognized.Status == HardwareAuthorityResolutionStatus.Resolved
                        && string.Equals(recognized.EffectiveHardwareId, stableHardwareId, StringComparison.Ordinal))
                    {
                        hardwareIdHash = Sha256Lower(stableHardwareId);
                        // Contract TKT-001296: the accepted mode names the recognition so Website and WebSetup
                        // can tell a recognized machine from a plain server derivation. Website must tolerate
                        // this mode before this server version is deployed.
                        authorityMode = "alias-recognized";
                        recognition = "alias-recognized";
                        recognizedAliasId = recognized.AliasId;
                    }
                    else if (recognized.Status == HardwareAuthorityResolutionStatus.Refused)
                    {
                        recognition = "compat-refused:" + recognized.RefusalReason;
                        recognizedAliasId = recognized.AliasId;
                    }
                }
                // Diagnostic HWID volontaire (TKT-001277/TKT-001294) : conserve tant que les cas d'incoherence
                // d'autorite materielle sont analyses ; son retrait est une decision explicite, pas un nettoyage.
                // Les identifiants produit/licence/installation permettent de dedupliquer par client, pas par ligne.
                _logger.LogWarning(
                    "HWID_DIAGNOSIS preflight requestId={RequestId} productId={ProductId} licenseId={LicenseId} installationId={InstallationId} CpuId={CpuId} MotherboardId={MotherboardId} BiosId={BiosId} LegacyDiskId={LegacyDiskId} StableDiskId={StableDiskId} MachineName={MachineName} LegacyHardwareId={LegacyHardwareId} StableHardwareId={StableHardwareId} hardwareIdHash={HardwareIdHash} recognition={Recognition} recognizedAliasId={RecognizedAliasId} serverVersion={ServerVersion}",
                    requestId, productId, licenseId, request.InstallationId, evidence.CpuId, evidence.MotherboardId, evidence.BiosId,
                    evidence.LegacyDiskId, evidence.StableDiskId, evidence.MachineName,
                    legacyHardwareId, stableHardwareId, hardwareIdHash, recognition, recognizedAliasId,
                    typeof(RuntimeDistributionPreflightService).Assembly.GetName().Version);
                activeBans = await FindBansByHardwareIdsAsync(
                    db, [legacyHardwareId, stableHardwareId], productId, now, cancellationToken);
            }
        }

        var categories = activeBans.Select(candidate => candidate.BanCategory ?? BannedHardwareId.Categories.Manual)
            .Distinct(StringComparer.Ordinal).OrderBy(candidate => candidate, StringComparer.Ordinal).ToArray();
        if (activeBans.Count > 0 && (!paidAutoUnbanEligible
            || !SecurityService.AreAllHardwareBansAutoUnbannable(activeBans)))
            return await RefuseAsync(db, transaction, clientId, requestId, payloadDigestSha256,
                productId, licenseId, request.GrantRefDigestSha256!, request, installationIdHash,
                authorityMode, "hardware_banned", categories, licenseActive, licenseRevoked,
                licenseExpired, paidAutoUnbanEligible, cancellationToken, hardwareIdHash);

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
    /// Locks one irreversible digest before reading live product-compatible bans. Every ban writer takes
    /// the same digest lock before mutation, including creation when no matching row exists yet.
    /// </summary>
    private static async Task<List<BannedHardwareId>> FindBansByDigestAsync(
        LicenseDbContext db, string hardwareIdHash, Guid productId, DateTime now,
        CancellationToken cancellationToken)
    {
        await SecurityService.AcquireHardwareBanDigestMutationAsync(db, hardwareIdHash);
        var lockedCandidates = await db.BannedHardwareIds.Where(ban => ban.IsActive
            && (ban.ProductId == null || ban.ProductId == productId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now)).ToListAsync(cancellationToken);
        return lockedCandidates.Where(candidate => string.Equals(
            Sha256Lower(candidate.HardwareId.ToUpperInvariant()), hardwareIdHash,
            StringComparison.Ordinal)).ToList();
    }

    /// <summary>
    /// Locks each exact canonical candidate in ordinal order, then returns tracked live bans applicable
    /// to the product. The deterministic order prevents deadlocks for legacy/stable dual identity.
    /// </summary>
    private static async Task<List<BannedHardwareId>> FindBansByHardwareIdsAsync(
        LicenseDbContext db, IEnumerable<string?> hardwareIds, Guid productId, DateTime now,
        CancellationToken cancellationToken)
    {
        var candidates = hardwareIds.Where(value => value is not null).Select(value => value!.ToUpperInvariant())
            .ToHashSet(StringComparer.Ordinal);
        await SecurityService.AcquireHardwareBanMutationsAsync(db, candidates);
        var rows = await db.BannedHardwareIds.Where(ban => ban.IsActive
            && (ban.ProductId == null || ban.ProductId == productId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now)).ToListAsync(cancellationToken);
        return rows.Where(ban => candidates.Contains(ban.HardwareId.ToUpperInvariant())).ToList();
    }

    /// <summary>
    /// Commits a privacy-bounded refusal in the caller transaction, logs its audit reference, and then
    /// throws the opaque public denial. Persistence failure propagates instead of losing evidence.
    /// </summary>
    private async Task<RuntimeDistributionPreflightResponse> RefuseAsync(
        LicenseDbContext db, Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction? transaction,
        string clientId, string requestId, string payloadDigestSha256, Guid productId, Guid licenseId,
        string grantRefDigestSha256, RuntimeDistributionPreflightRequest request, string? installationIdHash,
        string authorityMode, string reasonCode, IReadOnlyCollection<string> categories,
        bool licenseActive, bool licenseRevoked, bool licenseExpired, bool paidAutoUnbanEligible,
        CancellationToken cancellationToken, string? hardwareIdHash = null)
    {
        db.RuntimeDistributionHardwareDecisions.Add(BuildDecision(clientId, requestId, payloadDigestSha256,
            productId, licenseId, grantRefDigestSha256, request, hardwareIdHash, installationIdHash,
            authorityMode, "refused", reasonCode, categories, licenseActive, licenseRevoked,
            licenseExpired, paidAutoUnbanEligible, 0, DateTime.UtcNow));
        await db.SaveChangesAsync(cancellationToken);
        if (transaction is not null) await transaction.CommitAsync(cancellationToken);
        LogDecision(db.RuntimeDistributionHardwareDecisions.Local.Single(), replay: false);
        throw NotEligible(reasonCode);
    }

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
    /// Admits only the closed six-observation shape with bounded, pre-trimmed values. The returned
    /// object remains request-local and is never attached to an entity or logger.
    /// </summary>
    private static RuntimeDistributionHardwareEvidence ValidateEvidence(
        RuntimeDistributionHardwareEvidence? evidence)
    {
        if (evidence is null || evidence.ExtensionData is { Count: > 0 }
            || !ValidObservation(evidence.CpuId) || IsMissing(evidence.CpuId)
            || !ValidObservation(evidence.MotherboardId) || IsMissing(evidence.MotherboardId)
            || !ValidObservation(evidence.BiosId) || IsMissing(evidence.BiosId)
            || !ValidObservation(evidence.LegacyDiskId) || IsMissing(evidence.LegacyDiskId)
            || !ValidObservation(evidence.MachineName)
            || (evidence.StableDiskId is not null && !ValidObservation(evidence.StableDiskId)))
            throw InvalidRequest();
        return evidence;
    }

    /// <summary>Reports whether one observation is bounded, trimmed, non-empty, and control-free.</summary>
    private static bool ValidObservation(string? value) =>
        value is { Length: >= 1 and <= 256 }
        && string.Equals(value, value.Trim(), StringComparison.Ordinal)
        && !value.Any(char.IsControl);

    /// <summary>
    /// Recognizes the SDK's explicit missing-value sentinels. Applied to every WMI-derived
    /// component (CPU/motherboard/BIOS/disk) so a failed local read is refused up front instead
    /// of silently becoming part of the authoritative hardware identity. MachineName is exempt:
    /// it is never WMI-derived (Environment.MachineName), so it cannot legitimately produce these
    /// sentinels, and a machine literally named "UNKNOWN" must not be refused.
    /// </summary>
    private static bool IsMissing(string? value) => string.IsNullOrWhiteSpace(value)
        || string.Equals(value, "UNKNOWN", StringComparison.Ordinal)
        || string.Equals(value, "NON-WINDOWS", StringComparison.Ordinal);

    /// <summary>
    /// Reproduces the pinned SDK five-component identity and returns its first sixteen uppercase
    /// SHA-256 hexadecimal characters; no client-supplied final HWID is accepted.
    /// </summary>
    private static string ComputeHardwareId(RuntimeDistributionHardwareEvidence evidence, string diskId)
    {
        var raw = string.Concat(evidence.CpuId, evidence.MotherboardId, evidence.BiosId,
            diskId, evidence.MachineName);
        using var sha256 = SHA256.Create();
        return Convert.ToHexString(sha256.ComputeHash(Encoding.UTF8.GetBytes(raw)))[..16];
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

    /// <summary>Creates a fail-closed response for malformed provider-owned enrollment state.</summary>
    private static DistributionOperationException ServiceUnavailable() =>
        new("service_unavailable", StatusCodes.Status503ServiceUnavailable);

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

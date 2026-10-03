using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Resolves legacy identifiers only through server-owned relationships established by signed Runtime migrations.
/// </summary>
public interface IHardwareAuthorityAliasResolver
{
    /// <summary>
    /// Resolves a submitted identifier inside one product and license boundary.
    /// </summary>
    /// <param name="productId">Product boundary selected by the validated application request.</param>
    /// <param name="licenseId">License boundary selected by the validated license key.</param>
    /// <param name="submittedHardwareId">Exact client-supplied hardware identifier.</param>
    /// <param name="intent">Operation intent that determines whether an inactive canonical seat may still identify authority.</param>
    /// <param name="cancellationToken">Request cancellation token.</param>
    /// <returns>A direct, resolved, or fail-closed result. A refused result must never be treated as a new submitted machine.</returns>
    Task<HardwareAuthorityResolution> ResolveAsync(
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves a submitted identifier inside the caller's existing authority transaction.
    /// </summary>
    /// <param name="authorityDb">Database context whose active transaction and locks own the consuming mutation.</param>
    /// <param name="productId">Product boundary selected by the validated application request.</param>
    /// <param name="licenseId">License boundary selected by the validated license key.</param>
    /// <param name="submittedHardwareId">Exact client-supplied hardware identifier.</param>
    /// <param name="intent">Operation intent that determines whether an inactive canonical seat may still identify authority.</param>
    /// <param name="cancellationToken">Request cancellation token.</param>
    /// <returns>A direct, resolved, or fail-closed result evaluated in the supplied transaction.</returns>
    Task<HardwareAuthorityResolution> ResolveAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default);

}

/// <summary>
/// Resolves a canonical Finalize identifier back to one server-authenticated historical source.
/// This compatibility lookup is internal to Finalize and never grants commercial eligibility.
/// </summary>
internal interface ICanonicalFinalizeHardwareAuthorityResolver
{
    /// <summary>
    /// Resolves one canonical hardware identifier to an exact alias source when the server graph
    /// proves the alias references and immutable Runtime evidence. Unknown, ambiguous, disabled,
    /// or structurally broken reverse graphs retain the historical direct-identity behavior.
    /// </summary>
    /// <param name="authorityDb">Database context whose transaction owns the Finalize decision.</param>
    /// <param name="productId">Exact product boundary.</param>
    /// <param name="licenseId">Exact target licence boundary.</param>
    /// <param name="submittedCanonicalHardwareId">Canonical identifier submitted to Finalize.</param>
    /// <param name="cancellationToken">Cancels the database reads.</param>
    /// <returns>An authenticated source resolution, or <c>NoAlias</c> when reverse compatibility must not alter existing behavior.</returns>
    Task<HardwareAuthorityResolution> ResolveFinalizeSourceByCanonicalAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedCanonicalHardwareId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Identifies whether alias resolution is locating authority for activation, status, or an active-seat mutation.
/// </summary>
public enum HardwareAuthorityResolutionIntent
{
    /// <summary>Allows an inactive canonical seat so activation can reactivate the same seat under normal quota policy.</summary>
    Activation,

    /// <summary>Allows an inactive canonical seat so status can report HARDWARE_NOT_ACTIVATED for the proven authority.</summary>
    StatusCheck,

    /// <summary>
    /// TKT-001296: distribution preflight of a machine the server no longer recognizes by installation
    /// and key. Shares the version-terminal Finalize tolerance only; a disabled alias, an inactive
    /// backfill and every seat-transition case are refused here and mapped to legacy by the preflight.
    /// </summary>
    DistributionPreflight,

    /// <summary>Requires the canonical seat to be active before a deactivation mutation can target it.</summary>
    Deactivation,

    /// <summary>
    /// Allows Finalize to identify one authenticated, recoverable same-license seat transition.
    /// The result remains refused until the transaction-scoped Finalize validator proves the successor graph.
    /// </summary>
    Finalize
}

/// <summary>
/// Describes the result of a license-scoped hardware authority lookup without exposing alias digests.
/// </summary>
/// <param name="SubmittedHardwareId">Exact identifier received from the client.</param>
/// <param name="EffectiveHardwareId">Identifier that owns the seat and must be used for signing and enforcement.</param>
/// <param name="AliasId">Server alias identifier when compatibility resolution occurred.</param>
/// <param name="BindingId">Authenticated Runtime binding that proves the resolved authority.</param>
/// <param name="LicenseSeatId">Canonical seat owned by the resolved authority.</param>
/// <param name="RefusalReason">Bounded internal reason for a known alias refusal.</param>
public sealed record HardwareAuthorityResolution(
    string SubmittedHardwareId,
    string EffectiveHardwareId,
    Guid? AliasId,
    HardwareAuthorityResolutionStatus Status,
    Guid? BindingId = null,
    Guid? LicenseSeatId = null,
    HardwareAuthorityRefusalReason? RefusalReason = null)
{
    /// <summary>Gets whether a server-authenticated compatibility alias was used.</summary>
    public bool UsedAlias => Status == HardwareAuthorityResolutionStatus.Resolved;

    /// <summary>Gets whether a known alias was refused and must never fall back to a new legacy seat.</summary>
    public bool Refused => Status == HardwareAuthorityResolutionStatus.Refused;

    /// <summary>Internal diagnostic witness only: exact historical authority survived, but its current assignment changed. Never grants resolution or exposes a canonical digest.</summary>
    internal bool CommercialAssignmentOnlyRefusal { get; init; }
}

/// <summary>
/// Classifies known alias refusals without exposing hardware identifiers, digests, or client payloads.
/// </summary>
public enum HardwareAuthorityRefusalReason
{
    /// <summary>More than one alias matched a license-scoped legacy digest.</summary>
    AmbiguousAlias,

    /// <summary>The exact alias or product compatibility policy is disabled.</summary>
    AliasUnavailable,

    /// <summary>One or more required relational authority rows are missing.</summary>
    AuthorityGraphMissing,

    /// <summary>The persisted authority graph violates an identity, epoch, state, or eligibility invariant.</summary>
    AuthorityGraphDiverged,

    /// <summary>
    /// A signed alias proves one recoverable historical V2 authority. The current server graph
    /// separately proves one active legacy transition seat before Finalize may consume this refusal.
    /// </summary>
    SameLicenseSeatTransitionRequired
}

/// <summary>
/// Separates unknown direct identities from resolved aliases and known aliases that failed authority validation.
/// </summary>
public enum HardwareAuthorityResolutionStatus
{
    /// <summary>No server-side alias exists, so the submitted identity remains a direct authority candidate.</summary>
    NoAlias,

    /// <summary>A single active alias passed every live server authority check.</summary>
    Resolved,

    /// <summary>A known alias was disabled, policy-blocked, ambiguous, rolled back, or divergent and must fail closed.</summary>
    Refused
}

/// <summary>
/// Configures the bounded legacy alias compatibility window.
/// </summary>
public sealed class HardwareAuthorityAliasOptions
{
    /// <summary>Gets or sets the exact fallback mode, either <c>enabled</c> or <c>off</c>.</summary>
    public string DefaultMode { get; set; } = "enabled";

    /// <summary>Gets or sets exact product-specific overrides, evaluated before the fallback mode.</summary>
    public List<HardwareAuthorityAliasProductOptions> Products { get; set; } = [];
}

/// <summary>
/// Selects the compatibility mode for one canonical product identifier.
/// </summary>
public sealed class HardwareAuthorityAliasProductOptions
{
    /// <summary>Gets or sets the canonical lowercase UUID product identifier.</summary>
    public string ProductId { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact mode, either <c>enabled</c> or <c>off</c>.</summary>
    public string Mode { get; set; } = "off";
}

/// <summary>
/// Rejects ambiguous compatibility modes at startup.
/// </summary>
public sealed class HardwareAuthorityAliasOptionsValidator : IValidateOptions<HardwareAuthorityAliasOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, HardwareAuthorityAliasOptions options)
    {
        if (options.DefaultMode is not ("enabled" or "off"))
            return ValidateOptionsResult.Fail("Hardware authority alias default mode must be exactly 'enabled' or 'off'.");

        var productIds = new HashSet<Guid>();
        foreach (var product in options.Products)
        {
            if (!Guid.TryParseExact(product.ProductId, "D", out var productId)
                || product.ProductId != productId.ToString("D")
                || product.Mode is not ("enabled" or "off")
                || !productIds.Add(productId))
            {
                return ValidateOptionsResult.Fail("Hardware authority alias product policies require unique canonical lowercase UUIDs and exact modes.");
            }
        }

        return ValidateOptionsResult.Success;
    }
}

/// <summary>
/// PostgreSQL-backed alias resolver that compares canonical SHA-256 digests through an indexed equality predicate.
/// </summary>
/// <param name="db">Scoped database context used by read-only compatibility consumers.</param>
/// <param name="options">Product-scoped alias compatibility policy.</param>
/// <param name="migrationCrypto">Server receipt authenticator; missing evidence never relaxes eligibility.</param>
/// <param name="logger">Bounded security telemetry sink. Security refusals never record hardware identifiers or digests; the deliberate HWID_DIAGNOSIS lines (TKT-001277/TKT-001294) do, on purpose, until the hardware-authority investigation ends.</param>
public sealed class HardwareAuthorityAliasResolver(
    LicenseDbContext db,
    IOptions<HardwareAuthorityAliasOptions> options,
    ILogger<HardwareAuthorityAliasResolver> logger,
    IRuntimeEnrollmentCryptoService? migrationCrypto = null) :
    IHardwareAuthorityAliasResolver,
    ICanonicalFinalizeHardwareAuthorityResolver
{
    private static readonly TimeSpan ObservationInterval = TimeSpan.FromHours(1);

    /// <inheritdoc />
    public async Task<HardwareAuthorityResolution> ResolveAsync(
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default) =>
        await ResolveCoreAsync(
            db,
            productId,
            licenseId,
            submittedHardwareId,
            intent,
            cancellationToken);

    /// <inheritdoc />
    public async Task<HardwareAuthorityResolution> ResolveAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default) =>
        await ResolveCoreAsync(
            authorityDb,
            productId,
            licenseId,
            submittedHardwareId,
            intent,
            cancellationToken);

    /// <summary>
    /// Evaluates one alias against its complete authority graph. Exact seat-release terminals
    /// preserve the proven hardware mapping for later licensing operations, never Runtime rights.
    /// Revocation, disabled aliases and divergent ownership or generations remain refused.
    /// </summary>
    /// <param name="authorityDb">Context that owns either the request scope or the consuming transaction.</param>
    /// <param name="productId">Exact product authority boundary.</param>
    /// <param name="licenseId">Exact licence authority boundary.</param>
    /// <param name="submittedHardwareId">Canonical submitted identifier, preserved byte-for-byte.</param>
    /// <param name="intent">Seat-state requirement for the consuming operation.</param>
    /// <param name="cancellationToken">Cancels relational reads and bounded telemetry persistence.</param>
    /// <returns>A fail-closed authority resolution without exposing hardware digests.</returns>
    private async Task<HardwareAuthorityResolution> ResolveCoreAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken)
    {
        var resolution = await ResolveUnloggedAsync(
            authorityDb, productId, licenseId, submittedHardwareId, intent, cancellationToken);
        // Diagnostic HWID volontaire (TKT-001277/TKT-001294) : une ligne par resolution, avec les identifiants
        // en clair, pour reconstituer submitted/effective/canonical par intention et par licence. Les cas
        // CAS-03/CAS-04 (journal "legacy" avec siege stable) ne pouvaient pas etre expliques sans cette trace.
        // Son retrait est une decision explicite, pas un nettoyage.
        logger.LogWarning(
            "HWID_DIAGNOSIS alias-resolution intent={Intent} productId={ProductId} licenseId={LicenseId} submitted={Submitted} effective={Effective} status={Status} aliasId={AliasId} bindingId={BindingId} seatId={SeatId} refusalReason={RefusalReason} serverVersion={ServerVersion}",
            intent, productId, licenseId, resolution.SubmittedHardwareId, resolution.EffectiveHardwareId,
            resolution.Status, resolution.AliasId, resolution.BindingId, resolution.LicenseSeatId, resolution.RefusalReason,
            typeof(HardwareAuthorityAliasResolver).Assembly.GetName().Version);
        return resolution;
    }

    private async Task<HardwareAuthorityResolution> ResolveUnloggedAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken)
    {
        if (!IsCanonicalHardwareId(submittedHardwareId))
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, null, HardwareAuthorityResolutionStatus.NoAlias);

        var legacyDigest = Sha256(submittedHardwareId);
        var aliases = await authorityDb.HardwareAuthorityAliases
            .AsNoTracking()
            .Include(candidate => candidate.Product)
            .Include(candidate => candidate.License)
            .Include(candidate => candidate.LicenseSeat)
            .Include(candidate => candidate.RuntimeEnrollment)
            .Include(candidate => candidate.Binding)
            .Where(candidate =>
                candidate.LicenseId == licenseId
                && candidate.LegacyHardwareIdSha256 == legacyDigest)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (aliases.Count == 0)
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, null, HardwareAuthorityResolutionStatus.NoAlias);
        if (aliases.Count != 1)
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, null, HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.AmbiguousAlias);

        var alias = aliases[0];
        return await EvaluateAliasAsync(
            authorityDb, alias, productId, licenseId, submittedHardwareId, intent, cancellationToken);
    }

    /// <summary>
    /// TKT-001296, reverse direction: resolves a submitted canonical (stable) identifier against the one alias
    /// of this licence whose legacy digest equals the expected digest. Same authority graph, epoch,
    /// eligibility and ban semantics as the legacy direction; without exactly that pair the result is NoAlias.
    /// Concrete-only on purpose so existing test doubles of the interface stay untouched.
    /// </summary>
    public async Task<HardwareAuthorityResolution> ResolveByCanonicalAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedCanonicalHardwareId,
        string expectedLegacyHardwareIdSha256,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default)
    {
        if (!IsCanonicalHardwareId(submittedCanonicalHardwareId)
            || string.IsNullOrEmpty(expectedLegacyHardwareIdSha256) || expectedLegacyHardwareIdSha256.Length != 64)
            return new HardwareAuthorityResolution(
                submittedCanonicalHardwareId, submittedCanonicalHardwareId, null, HardwareAuthorityResolutionStatus.NoAlias);
        var canonicalDigest = Sha256(submittedCanonicalHardwareId);
        var aliases = await authorityDb.HardwareAuthorityAliases
            .AsNoTracking()
            .Include(candidate => candidate.Product)
            .Include(candidate => candidate.License)
            .Include(candidate => candidate.LicenseSeat)
            .Include(candidate => candidate.RuntimeEnrollment)
            .Include(candidate => candidate.Binding)
            .Where(candidate =>
                candidate.LicenseId == licenseId
                && candidate.CanonicalHardwareIdSha256 == canonicalDigest
                && candidate.LegacyHardwareIdSha256 == expectedLegacyHardwareIdSha256)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (aliases.Count == 0)
            return new HardwareAuthorityResolution(
                submittedCanonicalHardwareId, submittedCanonicalHardwareId, null, HardwareAuthorityResolutionStatus.NoAlias);
        if (aliases.Count != 1)
            return new HardwareAuthorityResolution(
                submittedCanonicalHardwareId, submittedCanonicalHardwareId, null, HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.AmbiguousAlias);
        // The submitted identifier is the canonical member itself: the graph evaluation compares it to the seat.
        var resolution = await EvaluateAliasAsync(
            authorityDb, aliases[0], productId, licenseId, submittedCanonicalHardwareId, intent, cancellationToken);
        logger.LogWarning(
            "HWID_DIAGNOSIS alias-resolution direction=canonical intent={Intent} productId={ProductId} licenseId={LicenseId} submitted={Submitted} expectedLegacyHash={ExpectedLegacyHash} effective={Effective} status={Status} aliasId={AliasId} refusalReason={RefusalReason}",
            intent, productId, licenseId, submittedCanonicalHardwareId, expectedLegacyHardwareIdSha256,
            resolution.EffectiveHardwareId, resolution.Status, resolution.AliasId, resolution.RefusalReason);
        return resolution;
    }

    /// <inheritdoc />
    public async Task<HardwareAuthorityResolution> ResolveFinalizeSourceByCanonicalAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedCanonicalHardwareId,
        CancellationToken cancellationToken = default)
    {
        if (!IsCanonicalHardwareId(submittedCanonicalHardwareId))
            return NoAlias(submittedCanonicalHardwareId);

        var canonicalDigest = Sha256(submittedCanonicalHardwareId);
        var aliases = await authorityDb.HardwareAuthorityAliases
            .AsNoTracking()
            .Include(candidate => candidate.Product)
            .Include(candidate => candidate.License)
            .Include(candidate => candidate.LicenseSeat)
            .Include(candidate => candidate.RuntimeEnrollment)
            .Include(candidate => candidate.Binding)
            .Where(candidate =>
                candidate.ProductId == productId
                && candidate.LicenseId == licenseId
                && candidate.CanonicalHardwareIdSha256 == canonicalDigest)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (aliases.Count != 1)
            return NoAlias(submittedCanonicalHardwareId);

        var alias = aliases[0];
        var sourceShape = EvaluateAuthenticatedSourceShape(alias, productId, licenseId, canonicalDigest);
        if (!sourceShape.StableAuthorityGraph && !sourceShape.ImmutableLegacyRuntimeEvidence)
            return NoAlias(submittedCanonicalHardwareId);

        var resolution = await EvaluateAliasAsync(
            authorityDb,
            alias,
            productId,
            licenseId,
            submittedCanonicalHardwareId,
            HardwareAuthorityResolutionIntent.Finalize,
            cancellationToken);
        if (!resolution.Refused
            || resolution.RefusalReason == HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired)
        {
            return resolution;
        }

        if (resolution.RefusalReason != HardwareAuthorityRefusalReason.AuthorityGraphDiverged)
            return NoAlias(submittedCanonicalHardwareId);

        if (!IsAuthenticatedFinalizeTerminalSource(alias))
            return NoAlias(submittedCanonicalHardwareId);

        // Coherent business terminals remain recoverable historical proof. Security terminals and
        // invalid future chronology are authenticated sources but never grants: Finalize loads them
        // only so its existing recovery classifier can retain the precise closed conflict.
        return resolution with
        {
            Status = HardwareAuthorityResolutionStatus.Resolved,
            RefusalReason = null
        };
    }

    /// <summary>
    /// Evaluates one loaded alias against its complete authority graph for the submitted identifier.
    /// Shared by the legacy and canonical directions so both apply exactly the same invariants.
    /// </summary>
    private async Task<HardwareAuthorityResolution> EvaluateAliasAsync(
        LicenseDbContext authorityDb,
        HardwareAuthorityAlias alias,
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken)
    {
        if (!IsEnabledForProduct(productId))
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, alias.Id, HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.AliasUnavailable);

        var inactiveBackfillMayReconcile = (!alias.IsActive || alias.DisabledAtUtc.HasValue)
            && intent == HardwareAuthorityResolutionIntent.Finalize
            && await HasExactInactiveBackfillProvenanceAsync(authorityDb, alias, cancellationToken);
        if ((!alias.IsActive || alias.DisabledAtUtc.HasValue) && !inactiveBackfillMayReconcile)
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, alias.Id, HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.AliasUnavailable);

        if (alias.Product == null
            || alias.License == null
            || alias.LicenseSeat == null
            || alias.RuntimeEnrollment == null
            || alias.Binding == null)
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, alias.Id, HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.AuthorityGraphMissing);

        var now = DateTime.UtcNow;
        var seat = alias.LicenseSeat;
        var license = alias.License;
        var enrollment = alias.RuntimeEnrollment;
        var binding = alias.Binding;
        var canonicalDigest = IsCanonicalHardwareId(seat.HardwareId) ? Sha256(seat.HardwareId) : string.Empty;
        var sourceShape = EvaluateAuthenticatedSourceShape(alias, productId, licenseId, canonicalDigest);
        var stableAuthorityGraph = sourceShape.StableAuthorityGraph;
        var immutableLegacyRuntimeEvidence = sourceShape.ImmutableLegacyRuntimeEvidence;
        var exactAuthenticatedRuntimeEvidence = stableAuthorityGraph || immutableLegacyRuntimeEvidence;
        var currentAssignments = await authorityDb.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(candidate => candidate.EnrollmentId == enrollment.Id && candidate.State == "ACTIVE")
            .Take(2)
            .ToListAsync(cancellationToken);
        var currentAssignmentMatches = currentAssignments.Count == 1
            && currentAssignments[0].LicenseId == licenseId
            && currentAssignments[0].LicenseSeatId == seat.Id;
        var currentAuthorityGraph = currentAssignmentMatches
            && (stableAuthorityGraph || immutableLegacyRuntimeEvidence);
        var licenseIsEligible = license.IsActive
            && license.RevokedAt == null
            && (!license.ExpirationDate.HasValue || license.ExpirationDate.Value > now);
        // A business seat release revokes execution rights, not the previously signed hardware
        // correspondence. Reusing that correspondence must never reactivate the terminal enrollment.
        var releasedHardwareProof = enrollment.InvalidationReason == SeatRuntimeReleaseAuthority.Reason
            && RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(binding, [enrollment], now)
            && binding.InvalidatedAtUtc.GetValueOrDefault() >= alias.CreatedAtUtc;
        // Finalize must retain its existing atomic seat-transition path when a prior client
        // already occupied a separate legacy seat after the canonical seat was released.
        var releasedSeatTransitionRequired = releasedHardwareProof
            && intent == HardwareAuthorityResolutionIntent.Finalize && !seat.IsActive
            && await authorityDb.LicenseSeats.AsNoTracking().AnyAsync(candidate =>
                candidate.LicenseId == licenseId && candidate.Id != seat.Id
                && candidate.HardwareId == submittedHardwareId && candidate.IsActive, cancellationToken);
        // A forced minimum-version refusal terminates execution, not the signed hardware lineage.
        // Historical rows used the broad authority_ineligible reason, so Finalize may reuse that
        // lineage only after the complete current provider graph proves version-only ineligibility.
        var versionTerminalCandidate = IsFinalizeLike(intent)
            && exactAuthenticatedRuntimeEvidence
            && enrollment.State == RuntimeAuthorityTransitionResolver.InvalidatedState
            && enrollment.InvalidationReason is "authority_ineligible" or "version_ineligible"
            && enrollment.InvalidatedAtUtc.HasValue
            && enrollment.InvalidatedAtUtc >= enrollment.CreatedAtUtc
            && enrollment.InvalidatedAtUtc <= now
            && (!enrollment.ActivatedAtUtc.HasValue
                || enrollment.InvalidatedAtUtc >= enrollment.ActivatedAtUtc)
            && binding.State == "active"
            && binding.InvalidationReason == null
            && seat.IsActive;
        var versionTerminalAuthorityProof = versionTerminalCandidate
            && await RuntimeBindingEligibilityEvaluator.EvaluateAsync(
                authorityDb,
                binding,
                now,
                allowIneligibleSourceLicense: false,
                cancellationToken, migrationCrypto) == RuntimeBindingEligibility.VersionIneligible;
        // TKT-001492: ending the exact commercial assignment preserves identity evidence only.
        // Activation retains quota/MaxSeats; StatusCheck only locates the inactive seat, never grants rights.
        var releasedCommercialAssignmentProof = (intent is HardwareAuthorityResolutionIntent.Activation or HardwareAuthorityResolutionIntent.StatusCheck)
            && exactAuthenticatedRuntimeEvidence
            && currentAssignments.Count == 0
            && enrollment.State == "ACTIVE" && enrollment.InvalidationReason == null && enrollment.InvalidatedAtUtc == null
            && binding.State == "active" && binding.InvalidationReason == null && binding.InvalidatedAtUtc == null
            && !seat.IsActive
            && (!seat.UnlinkedAt.HasValue || (seat.UnlinkedAt >= alias.CreatedAtUtc && seat.UnlinkedAt <= now))
            && await HasExactReleasedAssignmentAsync(authorityDb, alias, now, cancellationToken);
        var authorityIsCurrent = !releasedSeatTransitionRequired
            && licenseIsEligible
            && (intent != HardwareAuthorityResolutionIntent.Deactivation || seat.IsActive)
            && ((currentAuthorityGraph && enrollment.State == "ACTIVE" && binding.State == "active")
                || (exactAuthenticatedRuntimeEvidence && (releasedHardwareProof || versionTerminalAuthorityProof))
                || releasedCommercialAssignmentProof);
        if (!authorityIsCurrent)
        {
            var refusalReason = HardwareAuthorityRefusalReason.AuthorityGraphDiverged;
            if (intent == HardwareAuthorityResolutionIntent.Finalize
                && exactAuthenticatedRuntimeEvidence
                && licenseIsEligible
                && !seat.IsActive
                && seat.UnlinkedAt.HasValue
                && (releasedHardwareProof || (RuntimeAuthorityTransitionResolver.IsRecoverableBinding(
                    binding.State, binding.InvalidationReason)
                && RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
                    [new RuntimeAuthorityEnrollmentSnapshot(
                        enrollment.State,
                        enrollment.InvalidationReason,
                        enrollment.ChallengeExpiresAtUtc,
                        enrollment.ChallengeConsumedAtUtc,
                        enrollment.ActivatedAtUtc,
                        enrollment.InvalidatedAtUtc)],
                    now) == RuntimeAuthorityEnrollmentDecision.UseBusinessTerminal)))
            {
                var activeSubmittedSeats = await authorityDb.LicenseSeats
                    .AsNoTracking()
                    .Where(candidate => candidate.LicenseId == licenseId
                        && candidate.HardwareId == submittedHardwareId
                        && candidate.IsActive)
                    .Take(2)
                    .Select(candidate => candidate.Id)
                    .ToListAsync(cancellationToken);
                if (activeSubmittedSeats.Count == 1 && activeSubmittedSeats[0] != seat.Id)
                    refusalReason = HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired;
            }
            // TEMP-FAIL-OPEN(TKT-001262): TEMPORARY observation branch, never leave as is. The intended
            // rule is fail-closed, but the alias/graph authority is known to be buggy (Finalize rotates
            // the binding without repointing the alias, SUP-000040). Franck's directive (2026-09-21):
            // no known HWID alias/graph divergence blocks a legitimate client; accept and log
            // exhaustively. This branch covers exactly that case: an active alias of the same
            // product, licence and active canonical seat of the same machine. Keep this
            // branch even after the durable fix (atomic alias repointing on rotation) during an
            // observation phase; restoring fail-closed requires conclusive telemetry AND Franck's
            // explicit approval. Certain business refusals stay: ineligible licence, active explicit
            // HWID ban on the submitted or canonical identifier (checked here; the distribution
            // preflight also checks HWID bans before any grant or download), component bans
            // (enforced only by Finalize binary evidence and Runtime validation, once binaries are
            // known) and the real seat quota (enforced by the callers).
            if (refusalReason == HardwareAuthorityRefusalReason.AuthorityGraphDiverged)
            {
                var sameMachineSeat = alias.IsActive
                    && !alias.DisabledAtUtc.HasValue
                    && alias.ProductId == productId
                    && alias.Product.Id == productId
                    && alias.LicenseId == licenseId
                    && license.Id == licenseId
                    && license.ProductId == productId
                    && seat.Id == alias.LicenseSeatId
                    && seat.LicenseId == licenseId
                    && seat.IsActive
                    && canonicalDigest.Length == 64
                    && canonicalDigest == alias.CanonicalHardwareIdSha256
                    && !releasedSeatTransitionRequired;
                if (!licenseIsEligible)
                {
                    logger.LogWarning(
                        "Hardware authority alias {AliasId} kept its refusal for intent {Intent}: licence {LicenseId} is not eligible.",
                        alias.Id, intent, licenseId);
                }
                else if (await HasActiveHardwareBanAsync(
                             authorityDb, productId, submittedHardwareId, seat.HardwareId, now, cancellationToken))
                {
                    logger.LogWarning(
                        "Hardware authority alias {AliasId} kept its refusal for intent {Intent}: an active explicit hardware ban matches licence {LicenseId}, seat {LicenseSeatId}.",
                        alias.Id, intent, licenseId, seat.Id);
                }
                else if (!sameMachineSeat)
                {
                    // Out of the SUP-000040 scope: the alias no longer designates one active seat of
                    // this same machine and licence. The historical refusal is kept (listed in the
                    // divergence matrix of docs-internal/sup-000040-alias-successor-report.md).
                    logger.LogWarning(
                        "Hardware authority alias {AliasId} kept its refusal for intent {Intent}: seat {LicenseSeatId} no longer matches this alias (seat active {SeatActive}, same machine {SameMachine}, released seat transition {ReleasedSeatTransition}).",
                        alias.Id,
                        intent,
                        seat.Id,
                        seat.IsActive,
                        canonicalDigest.Length == 64 && canonicalDigest == alias.CanonicalHardwareIdSha256,
                        releasedSeatTransitionRequired);
                }
                else
                {
                    var activeCandidates = authorityDb.DistributionInstallationBindings
                        .AsNoTracking()
                        .Where(candidate => candidate.ProductId == productId
                            && candidate.LicenseId == licenseId
                            && candidate.LicenseSeatId == seat.Id
                            && candidate.HardwareIdHash == canonicalDigest
                            && candidate.State == "active");
                    var activeCandidateCount = await activeCandidates.CountAsync(cancellationToken);
                    var candidates = await activeCandidates
                        .OrderBy(candidate => candidate.Id)
                        .Take(2)
                        .Select(candidate => new { candidate.Id, candidate.SupersededBindingId, candidate.Version })
                        .ToListAsync(cancellationToken);
                    // Only a unique active binding is reported as current. With none or several, no
                    // binding is claimed: the seat mapping stays usable and each caller applies its
                    // own binding rules, instead of receiving the stale alias binding as current.
                    var successor = activeCandidateCount == 1 ? candidates[0] : null;
                    const int maxLoggedEnrollments = 3;
                    var successorEnrollmentQuery = authorityDb.RuntimeEnrollments.AsNoTracking()
                        .Where(candidate => successor != null && candidate.BindingId == successor.Id);
                    var successorEnrollmentCount = successor == null
                        ? 0
                        : await successorEnrollmentQuery.CountAsync(cancellationToken);
                    var successorEnrollments = successor == null
                        ? []
                        : await successorEnrollmentQuery
                            .OrderBy(candidate => candidate.Id)
                            .Take(maxLoggedEnrollments)
                            .Select(candidate => new
                            {
                                candidate.Id,
                                candidate.State,
                                candidate.InvalidationReason,
                                candidate.SecurityEpoch,
                                candidate.AuthorityEpoch
                            })
                            .ToListAsync(cancellationToken);
                    // Every fact needed by the durable fix is logged: internal UUIDs, states, reasons,
                    // epochs, counts, intent and the ambient request correlation. No HWID or digest.
                    logger.LogWarning(
                        "TEMP-FAIL-OPEN(TKT-001262) Hardware authority alias {AliasId} tolerated AuthorityGraphDiverged for intent {Intent}, correlation {CorrelationId}: product {ProductId}, licence {LicenseId}, seat {LicenseSeatId}, alias binding {AliasBindingId} (state {AliasBindingState}, reason {AliasBindingReason}), alias enrollment {AliasEnrollmentId} (state {AliasEnrollmentState}, reason {AliasEnrollmentReason}, security epoch {EnrollmentSecurityEpoch}/{AliasSecurityEpoch}, authority epoch {EnrollmentAuthorityEpoch}/{AliasAuthorityEpoch}), stable graph {StableAuthorityGraph}, active binding candidates {ActiveBindingCount} (exact), successor binding {SuccessorBindingId} (supersedes {SuccessorSupersedes}, version {SuccessorVersion}), successor enrollments {SuccessorEnrollmentCount} (exact) listed {SuccessorEnrollments} truncated {SuccessorEnrollmentsTruncated}, resolved binding {ResolvedBindingId}.",
                        alias.Id,
                        intent,
                        System.Diagnostics.Activity.Current?.Id ?? "none",
                        productId,
                        licenseId,
                        seat.Id,
                        binding.Id,
                        binding.State,
                        binding.InvalidationReason ?? "none",
                        enrollment.Id,
                        enrollment.State,
                        enrollment.InvalidationReason ?? "none",
                        enrollment.SecurityEpoch,
                        alias.SecurityEpoch,
                        enrollment.AuthorityEpoch,
                        alias.AuthorityEpoch,
                        stableAuthorityGraph,
                        activeCandidateCount,
                        successor?.Id.ToString() ?? "none",
                        successor?.SupersededBindingId?.ToString() ?? "none",
                        successor?.Version ?? "none",
                        successorEnrollmentCount,
                        successorEnrollments.Count == 0
                            ? "none"
                            : string.Join(',', successorEnrollments.Select(item =>
                                item.Id + ":" + item.State + "/" + (item.InvalidationReason ?? "none")
                                + "@" + item.SecurityEpoch + "/" + item.AuthorityEpoch)),
                        successorEnrollmentCount > successorEnrollments.Count,
                        successor?.Id.ToString() ?? "none");
                    return new HardwareAuthorityResolution(
                        submittedHardwareId,
                        seat.HardwareId,
                        alias.Id,
                        HardwareAuthorityResolutionStatus.Resolved,
                        successor?.Id,
                        seat.Id);
                }
            }
            logger.LogWarning(
                "Hardware authority alias {AliasId} was refused with reason {RefusalReason}.",
                alias.Id,
                refusalReason);
            return new HardwareAuthorityResolution(
                submittedHardwareId,
                refusalReason == HardwareAuthorityRefusalReason.SameLicenseSeatTransitionRequired
                    ? seat.HardwareId
                    : submittedHardwareId,
                alias.Id,
                HardwareAuthorityResolutionStatus.Refused,
                binding.Id, seat.Id, refusalReason)
            {
                CommercialAssignmentOnlyRefusal = refusalReason == HardwareAuthorityRefusalReason.AuthorityGraphDiverged
                    && intent == HardwareAuthorityResolutionIntent.Finalize
                    && exactAuthenticatedRuntimeEvidence && licenseIsEligible
                    && alias.IsActive && alias.DisabledAtUtc == null
                    && enrollment.State == "ACTIVE" && enrollment.InvalidatedAtUtc == null
                    && enrollment.InvalidationReason == null
                    && binding.State == "active" && binding.InvalidatedAtUtc == null
                    && binding.InvalidationReason == null
                    && enrollment.ProtocolVersion == RuntimeEnrollmentService.ProtocolVersion
                    && enrollment.Epoch == 1
                    && string.Equals(enrollment.HandoffDigestSha256, binding.HandoffDigestSha256, StringComparison.Ordinal)
                    && string.Equals(enrollment.SubjectRefDigestSha256, binding.SubjectRefDigestSha256, StringComparison.Ordinal)
                    && string.Equals(enrollment.ReleaseVersion, binding.Version, StringComparison.Ordinal)
                    && currentAssignments.Count == 1 && !currentAssignmentMatches
            };
        }

        var observationCutoff = now - ObservationInterval;
        var observationUpdated = await authorityDb.HardwareAuthorityAliases
            .Where(candidate => candidate.Id == alias.Id
                && candidate.IsActive
                && (!candidate.LastObservedAtUtc.HasValue || candidate.LastObservedAtUtc <= observationCutoff))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(candidate => candidate.LastObservedAtUtc, now)
                .SetProperty(
                    candidate => candidate.ObservationCount,
                    candidate => candidate.ObservationCount < long.MaxValue
                        ? candidate.ObservationCount + 1
                        : candidate.ObservationCount),
                cancellationToken);
        if (observationUpdated == 1)
        {
            logger.LogInformation(
                "Authenticated hardware authority alias {AliasId} used for product {ProductId}, license {LicenseId}, seat {LicenseSeatId}.",
                alias.Id,
                productId,
                licenseId,
                seat.Id);
        }
        if (versionTerminalAuthorityProof)
        {
            logger.LogInformation(
                "Authenticated hardware authority alias {AliasId} recovered a version-terminal Runtime lineage for Finalize.",
                alias.Id);
        }

        return new HardwareAuthorityResolution(
            submittedHardwareId,
            seat.HardwareId,
            alias.Id,
            HardwareAuthorityResolutionStatus.Resolved,
            binding.Id,
            seat.Id);
    }

    /// <summary>
    /// Recognizes only the latest exact seat-release assignment as historical machine evidence.
    /// It grants no commercial right and never changes an enrollment, assignment or seat. A later
    /// different assignment, quarantine, active seat owner or incoherent chronology fails closed.
    /// </summary>
    /// <param name="db">Caller context owning the activation transaction or read-only commercial status evaluation.</param>
    /// <param name="alias">Alias whose complete product, license, seat and Runtime graph already matched.</param>
    /// <param name="nowUtc">UTC observation time bounding the persisted release evidence.</param>
    /// <param name="cancellationToken">Cancels the evidence reads before any activation mutation.</param>
    /// <returns>True only for a latest ENDED seat_released record in the exact authenticated scope.</returns>
    private static async Task<bool> HasExactReleasedAssignmentAsync(
        LicenseDbContext db, HardwareAuthorityAlias alias, DateTime nowUtc, CancellationToken cancellationToken)
    {
        var latest = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == alias.RuntimeEnrollmentId)
            .OrderByDescending(row => row.Revision)
            .FirstOrDefaultAsync(cancellationToken);
        if (latest == null || latest.State != "ENDED" || latest.EndReason != "seat_released"
            || latest.LicenseId != alias.LicenseId || latest.LicenseSeatId != alias.LicenseSeatId
            || latest.Revision < 1 || !latest.EndedAtUtc.HasValue
            || latest.EndedAtUtc < latest.ActivatedAtUtc || latest.EndedAtUtc < alias.CreatedAtUtc
            || latest.EndedAtUtc > nowUtc)
            return false;
        if (await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking()
            .AnyAsync(row => row.EnrollmentId == alias.RuntimeEnrollmentId, cancellationToken))
            return false;
        return !await db.EnrollmentLicenseAssignments.AsNoTracking()
            .AnyAsync(row => row.LicenseSeatId == alias.LicenseSeatId && row.State == "ACTIVE", cancellationToken);
    }

    /// <summary>
    /// Evaluates immutable server-owned alias references and the binding's licensing HWID evidence.
    /// The retained Runtime enrollment HWID is deliberately excluded from identity. State and
    /// commercial eligibility remain caller-owned so historical proof cannot authorize mixed data.
    /// </summary>
    /// <param name="alias">Loaded alias and related authority rows.</param>
    /// <param name="productId">Exact product boundary.</param>
    /// <param name="licenseId">Exact licence boundary.</param>
    /// <param name="canonicalDigest">SHA-256 digest of the canonical submitted identifier.</param>
    /// <returns>Whether the binding carries canonical or exact immutable legacy licensing evidence.</returns>
    private static AuthenticatedSourceShape EvaluateAuthenticatedSourceShape(
        HardwareAuthorityAlias alias,
        Guid productId,
        Guid licenseId,
        string canonicalDigest)
    {
        if (alias.Product == null
            || alias.License == null
            || alias.LicenseSeat == null
            || alias.RuntimeEnrollment == null
            || alias.Binding == null)
        {
            return default;
        }

        var license = alias.License;
        var seat = alias.LicenseSeat;
        var enrollment = alias.RuntimeEnrollment;
        var binding = alias.Binding;
        var coherentAliasReferences = alias.ProductId == productId
            && alias.Product.Id == productId
            && alias.LicenseId == licenseId
            && license.Id == licenseId
            && license.ProductId == productId
            && seat.Id == alias.LicenseSeatId
            && seat.LicenseId == licenseId
            && canonicalDigest == alias.CanonicalHardwareIdSha256
            && enrollment.Id == alias.RuntimeEnrollmentId
            && enrollment.BindingId == alias.BindingId
            && enrollment.ProductId == productId
            && enrollment.LicenseId == licenseId
            && enrollment.LicenseSeatId == seat.Id
            // Alias epochs are minimum authenticated generations. Monotonic progress is valid
            // while rollback and every authority or identity divergence remain fail-closed.
            && enrollment.SecurityEpoch >= alias.SecurityEpoch
            && enrollment.AuthorityEpoch >= alias.AuthorityEpoch
            && binding.Id == alias.BindingId
            && binding.ProductId == productId
            && binding.LicenseId == licenseId
            && binding.LicenseSeatId == seat.Id
            && binding.InstallationId == enrollment.InstallationId;
        return new AuthenticatedSourceShape(
            coherentAliasReferences
                && binding.HardwareIdHash == alias.CanonicalHardwareIdSha256,
            coherentAliasReferences
                && binding.HardwareIdHash == alias.LegacyHardwareIdSha256);
    }

    /// <summary>
    /// Creates the historical no-alias result used when reverse lookup must preserve direct
    /// canonical compatibility instead of introducing a new refusal.
    /// </summary>
    /// <param name="submittedHardwareId">Exact canonical identifier received by Finalize.</param>
    /// <returns>A direct-identity result with no alias authority.</returns>
    private static HardwareAuthorityResolution NoAlias(string submittedHardwareId) =>
        new(submittedHardwareId, submittedHardwareId, null, HardwareAuthorityResolutionStatus.NoAlias);

    /// <summary>
    /// Restricts reverse-source recovery to a coherent released generation or to the two explicit
    /// terminal classes that Finalize must rediscover in order to preserve its closed conflict.
    /// Other state or commercial divergences retain the historical direct-canonical behavior.
    /// </summary>
    /// <param name="alias">Exact alias whose structural source shape already passed.</param>
    /// <returns><see langword="true"/> only for coherent release, security terminal, or invalid future business-terminal chronology.</returns>
    private static bool IsAuthenticatedFinalizeTerminalSource(HardwareAuthorityAlias alias)
    {
        var enrollment = alias.RuntimeEnrollment!;
        var binding = alias.Binding!;
        if (RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
                binding,
                [enrollment],
                DateTime.UtcNow))
        {
            return true;
        }

        var decision = RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
            [new RuntimeAuthorityEnrollmentSnapshot(
                enrollment.State,
                enrollment.InvalidationReason,
                enrollment.ChallengeExpiresAtUtc,
                enrollment.ChallengeConsumedAtUtc,
                enrollment.ActivatedAtUtc,
                enrollment.InvalidatedAtUtc)],
            DateTime.UtcNow);
        if (decision == RuntimeAuthorityEnrollmentDecision.RejectSecurity)
            return true;

        return binding.InvalidationReason == SeatRuntimeReleaseAuthority.Reason
            && binding.InvalidatedAtUtc.HasValue
            && enrollment.State == RuntimeAuthorityTransitionResolver.InvalidatedState
            && enrollment.InvalidationReason is "authority_ineligible" or "version_ineligible"
            && enrollment.InvalidatedAtUtc > binding.InvalidatedAtUtc;
    }

    /// <summary>
    /// Describes the two exact copied Runtime evidence shapes accepted by signed alias provenance.
    /// </summary>
    /// <param name="StableAuthorityGraph">Both Runtime copies contain the canonical alias digest.</param>
    /// <param name="ImmutableLegacyRuntimeEvidence">Both Runtime copies retain the legacy alias digest.</param>
    private readonly record struct AuthenticatedSourceShape(
        bool StableAuthorityGraph,
        bool ImmutableLegacyRuntimeEvidence);

    /// <summary>
    /// Keeps explicit security decisions blocking inside the TEMP-FAIL-OPEN(TKT-001262) branch: an
    /// active, unexpired hardware ban on either the submitted or the canonical identifier, scoped to
    /// this product or global, refuses the tolerance. Comparison follows the existing ban semantics
    /// (upper-invariant identifier match).
    /// </summary>
    /// <param name="authorityDb">Context of the consuming operation.</param>
    /// <param name="productId">Exact product scope.</param>
    /// <param name="submittedHardwareId">Identifier presented by the caller.</param>
    /// <param name="canonicalHardwareId">Identifier stored on the canonical seat.</param>
    /// <param name="now">Decision time used for ban expiry.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns><see langword="true"/> when any matching active ban exists.</returns>
    /// <summary>
    /// TKT-001296: the distribution preflight mirrors exactly one Finalize tolerance, the version-terminal
    /// lineage (a machine blocked by a forced update is still the same machine). The inactive-backfill
    /// reconciliation and the seat-transition paths stay Finalize-only: at preflight a disabled alias
    /// means legacy plus diagnostic, never a recognized stable identity.
    /// </summary>
    private static bool IsFinalizeLike(HardwareAuthorityResolutionIntent intent) =>
        intent is HardwareAuthorityResolutionIntent.Finalize or HardwareAuthorityResolutionIntent.DistributionPreflight;

    internal static async Task<bool> HasActiveHardwareBanAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        string submittedHardwareId,
        string canonicalHardwareId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var submitted = submittedHardwareId.ToUpperInvariant();
        var canonical = canonicalHardwareId.ToUpperInvariant();
        return await authorityDb.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
            ban.IsActive
            && (ban.ProductId == null || ban.ProductId == productId)
            && (ban.ExpiresAt == null || ban.ExpiresAt > now)
            && (ban.HardwareId.ToUpper() == submitted || ban.HardwareId.ToUpper() == canonical),
            cancellationToken);
    }

    /// <summary>
    /// Proves that an inactive alias was created by the historical migration backfill rather than
    /// disabled later by an operator or security workflow. Every persisted identity is compared
    /// exactly; malformed, incomplete, duplicated, or rewritten history fails closed.
    /// </summary>
    /// <param name="authorityDb">Database context that owns the Finalize authority transaction.</param>
    /// <param name="alias">Inactive alias whose server-owned provenance must be established.</param>
    /// <param name="cancellationToken">Cancels the single bounded history lookup.</param>
    /// <returns><see langword="true"/> only for the exact row shape emitted by the original backfill.</returns>
    private static async Task<bool> HasExactInactiveBackfillProvenanceAsync(
        LicenseDbContext authorityDb,
        HardwareAuthorityAlias alias,
        CancellationToken cancellationToken)
    {
        if (alias.IsActive
            || !alias.DisabledAtUtc.HasValue
            || !string.Equals(
                alias.DisabledReason,
                HardwareAuthorityAlias.BackfillAuthorityInvalidReason,
                StringComparison.Ordinal)
            || alias.MigrationRequestId.HasValue)
        {
            return false;
        }

        var histories = await authorityDb.LicenseHistories
            .AsNoTracking()
            .Where(candidate => candidate.Id == alias.Id
                && candidate.LicenseId == alias.LicenseId
                && candidate.Action == "HWID_V2_MIGRATED")
            .Take(2)
            .Select(candidate => new
            {
                candidate.Timestamp,
                candidate.Details
            })
            .ToListAsync(cancellationToken);
        if (histories.Count != 1
            || histories[0].Timestamp != alias.CreatedAtUtc
            || histories[0].Details is not { Length: > 0 } details)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(details);
            var root = document.RootElement;
            return root.ValueKind == JsonValueKind.Object
                && HasSingleExactString(root, "schema", RuntimeEnrollmentService.HardwareAuthorityMigrationSchema)
                && HasSingleExactString(root, "enrollmentId", alias.RuntimeEnrollmentId.ToString("D"))
                && HasSingleExactString(root, "bindingId", alias.BindingId.ToString("D"))
                && HasSingleExactString(root, "seatId", alias.LicenseSeatId.ToString("D"))
                && HasSingleExactString(root, "legacyHardwareIdSha256", alias.LegacyHardwareIdSha256)
                && HasSingleExactString(root, "hardwareIdV2Sha256", alias.CanonicalHardwareIdSha256);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Compares one required JSON string without trimming, case folding, coercion, or normalization.
    /// </summary>
    private static bool HasSingleExactString(JsonElement root, string propertyName, string expected)
    {
        JsonElement? match = null;
        foreach (var property in root.EnumerateObject())
        {
            if (!property.NameEquals(propertyName))
                continue;
            if (match.HasValue)
                return false;
            match = property.Value;
        }

        return match is { ValueKind: JsonValueKind.String } value
            && string.Equals(value.GetString(), expected, StringComparison.Ordinal);
    }

    /// <summary>
    /// Resolves an exact product override before applying the explicit default compatibility mode.
    /// </summary>
    /// <param name="productId">Product security boundary for the submitted request.</param>
    /// <returns><see langword="true"/> only while legacy alias compatibility is explicitly enabled for the product.</returns>
    private bool IsEnabledForProduct(Guid productId)
    {
        var productPolicy = options.Value.Products.SingleOrDefault(candidate =>
            string.Equals(candidate.ProductId, productId.ToString("D"), StringComparison.Ordinal));
        return (productPolicy?.Mode ?? options.Value.DefaultMode) == "enabled";
    }

    /// <summary>
    /// Tests the exact uppercase 16-character ASCII hexadecimal authority contract.
    /// </summary>
    /// <param name="value">Untrusted identifier to validate without rewriting.</param>
    /// <returns><see langword="true"/> only for the canonical wire representation.</returns>
    internal static bool IsCanonicalHardwareId(string? value) =>
        value is { Length: 16 }
        && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    /// <summary>
    /// Hashes an already validated canonical identifier without case or whitespace rewriting.
    /// </summary>
    /// <param name="value">Canonical identifier whose exact UTF-8 bytes form the digest input.</param>
    /// <returns>A lowercase 64-character SHA-256 hexadecimal digest suitable for indexed persistence.</returns>
    internal static string Sha256(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

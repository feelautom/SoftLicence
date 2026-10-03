using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Outcome of <see cref="MachineIdentityObservationService.ObserveAsync"/>.
/// </summary>
/// <param name="Applies">Whether the request carried a UUID or machine evidence; <c>false</c> leaves the request flow untouched.</param>
/// <param name="RefusalCode">The stable <c>UUID_*</c> refusal code, or <c>null</c> when the machine identity is acceptable.</param>
public sealed record MachineIdentityObservationOutcome(bool Applies, string? RefusalCode)
{
    /// <summary>Gets the outcome for a request that carried neither UUID nor evidence.</summary>
    public static MachineIdentityObservationOutcome NotApplicable { get; } = new(false, null);

    /// <summary>Gets whether the request must be refused with the public "device refused" message.</summary>
    public bool IsRefused => RefusalCode is not null;

    /// <summary>
    /// Gets the short support code shown to the customer with "device refused" (for example <c>AR-04</c>), or
    /// <c>null</c> when not refused. Single mapping owned by the SDK (<see cref="MachineIdentity.ToSupportCode"/>).
    /// </summary>
    public string? SupportCode => MachineIdentity.ToSupportCode(RefusalCode);
}

/// <summary>
/// Server side of the UUID machine identity (TKT-001277 lot 2a). Applies the same rule as the SDK
/// (<see cref="MachineIdentity.FromUuid"/>) to the UUID reported by a client, refuses only the decided
/// classes (absent, unreadable, malformed, known generic, identifier not derived from the UUID), and stores the
/// reported evidence for investigation.
/// </summary>
/// <remarks>
/// <para>
/// A request that carries either field must carry a valid UUID; a missing one is
/// <see cref="MachineIdentity.RefusalUuidAbsent"/>.
/// </para>
/// <para>
/// The submitted identifier must be the one derived from the submitted UUID. The SDK always derives it the same
/// way, so a difference means a modified or faulty client and is refused as
/// <see cref="MachineIdentity.RefusalIdentifierMismatch"/>.
/// </para>
/// <para>
/// Storage is fail-open: any persistence failure is logged and never changes the licensing decision. String
/// contract: <c>HardwareId</c> arrives already validated as 16 uppercase ASCII hexadecimal characters,
/// <c>EvidenceSha256</c> is produced here in lowercase hexadecimal, so the unique key compares canonical values
/// ordinally in PostgreSQL. The raw UUID and the evidence JSON are opaque evidence and are stored unmodified.
/// </para>
/// </remarks>
public sealed class MachineIdentityObservationService
{
    /// <summary>Maximum stored length of the raw UUID; longer values are refused as malformed and not stored.</summary>
    public const int MaxSystemUuidLength = 128;

    /// <summary>Maximum stored length of the evidence JSON text; larger objects are dropped and logged.</summary>
    public const int MaxEvidenceJsonLength = 16 * 1024;

    private const int MaxAppVersionLength = 64;

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<MachineIdentityObservationService> _logger;

    /// <summary>Creates the service.</summary>
    /// <param name="dbFactory">Factory for a private context, so storage never joins the caller's transaction.</param>
    /// <param name="logger">Logger for refusals, mismatches and storage failures.</param>
    public MachineIdentityObservationService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<MachineIdentityObservationService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    /// <summary>
    /// Evaluates the UUID reported with one activation, check or trial request and records the evidence.
    /// </summary>
    /// <param name="productId">Product resolved by the endpoint.</param>
    /// <param name="hardwareId">Submitted identifier, already validated as canonical by the endpoint.</param>
    /// <param name="systemUuid">Raw <c>SystemUuid</c> field, or <c>null</c>.</param>
    /// <param name="evidence">Raw <c>MachineEvidence</c> field, or <c>null</c>.</param>
    /// <param name="endpoint">Endpoint label: <c>ACTIVATE</c>, <c>CHECK</c> or <c>TRIAL</c>.</param>
    /// <param name="appVersion">Client application version, or <c>null</c>.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns><see cref="MachineIdentityObservationOutcome.NotApplicable"/> for legacy clients, otherwise the decision.</returns>
    public async Task<MachineIdentityObservationOutcome> ObserveAsync(
        Guid productId,
        string hardwareId,
        string? systemUuid,
        JsonElement? evidence,
        string endpoint,
        string? appVersion,
        CancellationToken cancellationToken)
    {
        // LEGACY-EXPIRY(TKT-001430, 2026-12-31): a request without UUID or evidence keeps the pre-UUID behaviour for outdated clients.
        // Remove by 31/12/2026: make SystemUuid mandatory and refuse its absence with AR-01 (UUID_ABSENT).
        if (systemUuid is null && evidence is null)
            return MachineIdentityObservationOutcome.NotApplicable;

        var uuidStorable = systemUuid is not null && systemUuid.Length <= MaxSystemUuidLength;
        var identity = systemUuid is not null && !uuidStorable
            ? null
            : MachineIdentity.FromUuid(systemUuid);
        var refusalCode = identity is null ? MachineIdentity.RefusalUuidInvalidFormat : identity.RefusalCode;
        if (refusalCode is null && !string.Equals(identity!.HardwareId, hardwareId, StringComparison.Ordinal))
            refusalCode = MachineIdentity.RefusalIdentifierMismatch;

        if (refusalCode is not null)
        {
            _logger.LogWarning(
                "MACHINE_IDENTITY_REFUSED endpoint={Endpoint} productId={ProductId} hardwareId={HardwareId} reason={RefusalCode} supportCode={SupportCode}",
                endpoint, productId, hardwareId, refusalCode, MachineIdentity.ToSupportCode(refusalCode));
        }

        var evidenceJson = ReadEvidenceJson(evidence, endpoint, productId, hardwareId);
        var row = new MachineEvidenceObservation
        {
            ProductId = productId,
            HardwareId = hardwareId,
            SystemUuidRaw = uuidStorable ? systemUuid : null,
            SystemUuidCanonical = identity?.CanonicalUuid,
            DerivedHardwareId = identity?.HardwareId,
            RefusalCode = refusalCode,
            EvidenceJson = evidenceJson,
            EvidenceSha256 = Digest(uuidStorable ? systemUuid : null, evidenceJson),
            LastEndpoint = endpoint,
            LastAppVersion = Truncate(appVersion, MaxAppVersionLength),
        };

        try
        {
            await StoreAsync(row, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogWarning(exception,
                "MACHINE_EVIDENCE_STORE_FAILED endpoint={Endpoint} productId={ProductId} hardwareId={HardwareId}",
                endpoint, productId, hardwareId);
        }

        return new MachineIdentityObservationOutcome(true, refusalCode);
    }

    /// <summary>
    /// Records the evidence of a WebSetup preflight, where no client identifier exists: the stored identifier is
    /// the one the server derives from the UUID, or empty when the UUID is refused. Never throws for storage
    /// failures and never decides anything; the preflight applies <see cref="MachineIdentity.FromUuid"/> itself.
    /// </summary>
    /// <param name="productId">Product of the preflight.</param>
    /// <param name="systemUuid">Raw UUID sent by the WebSetup, or <c>null</c>.</param>
    /// <param name="evidence">Raw machine evidence object, or <c>null</c>.</param>
    /// <param name="endpoint">Endpoint label, <c>PREFLIGHT</c>.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <param name="finalRefusalCode">
    /// Refusal code the caller finally applies when it refines the UUID rule (AR-02 for a reported read failure,
    /// TKT-001277 review M1); null keeps the code of <see cref="MachineIdentity.FromUuid"/>. It is only honoured for
    /// a UUID the rule already refused, so it can never record an accepted machine as refused or the reverse.
    /// </param>
    /// <returns>A task that completes when the evidence was stored or its failure logged.</returns>
    public async Task ObserveDerivedAsync(
        Guid productId,
        string? systemUuid,
        JsonElement? evidence,
        string endpoint,
        CancellationToken cancellationToken,
        string? finalRefusalCode = null)
    {
        var uuidStorable = systemUuid is not null && systemUuid.Length <= MaxSystemUuidLength;
        var identity = MachineIdentity.FromUuid(uuidStorable ? systemUuid : null);
        var refusalCode = identity.RefusalCode is not null && finalRefusalCode is not null
            ? finalRefusalCode
            : identity.RefusalCode;
        var derived = identity.HardwareId ?? string.Empty;
        var evidenceJson = ReadEvidenceJson(evidence, endpoint, productId, derived);
        var row = new MachineEvidenceObservation
        {
            ProductId = productId,
            HardwareId = derived,
            SystemUuidRaw = uuidStorable ? systemUuid : null,
            SystemUuidCanonical = identity.CanonicalUuid,
            DerivedHardwareId = identity.HardwareId,
            RefusalCode = refusalCode,
            EvidenceJson = evidenceJson,
            EvidenceSha256 = Digest(uuidStorable ? systemUuid : null, evidenceJson),
            LastEndpoint = endpoint,
        };
        if (refusalCode is not null)
        {
            _logger.LogWarning(
                "MACHINE_IDENTITY_REFUSED endpoint={Endpoint} productId={ProductId} reason={RefusalCode} supportCode={SupportCode}",
                endpoint, productId, refusalCode, MachineIdentity.ToSupportCode(refusalCode));
        }

        try
        {
            await StoreAsync(row, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogWarning(exception,
                "MACHINE_EVIDENCE_STORE_FAILED endpoint={Endpoint} productId={ProductId} hardwareId={HardwareId}",
                endpoint, productId, derived);
        }
    }

    /// <summary>Inserts the observation or advances the identical existing row; retries once after a concurrent insert.</summary>
    private async Task StoreAsync(MachineEvidenceObservation row, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var now = DateTime.UtcNow;
            var existing = await db.MachineEvidenceObservations.SingleOrDefaultAsync(candidate =>
                candidate.ProductId == row.ProductId
                && candidate.HardwareId == row.HardwareId
                && candidate.EvidenceSha256 == row.EvidenceSha256,
                cancellationToken);
            if (existing is not null)
            {
                existing.LastSeenAtUtc = now;
                existing.ObservationCount++;
                existing.LastEndpoint = row.LastEndpoint;
                existing.LastAppVersion = row.LastAppVersion;
                await db.SaveChangesAsync(cancellationToken);
                return;
            }

            row.FirstSeenAtUtc = now;
            row.LastSeenAtUtc = now;
            row.ObservationCount = 1;
            db.MachineEvidenceObservations.Add(row);
            try
            {
                await db.SaveChangesAsync(cancellationToken);
                return;
            }
            catch (DbUpdateException) when (attempt == 0)
            {
                // A concurrent identical report inserted the row first; the next pass updates it.
                row.Id = Guid.NewGuid();
            }
        }
    }

    /// <summary>Returns the evidence object text unchanged, or <c>null</c> when absent, not an object, or oversized.</summary>
    private string? ReadEvidenceJson(JsonElement? evidence, string endpoint, Guid productId, string hardwareId)
    {
        if (evidence is not JsonElement element || element.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;

        string? rejection = null;
        string? text = null;
        if (element.ValueKind != JsonValueKind.Object)
            rejection = "not_an_object";
        else
        {
            text = element.GetRawText();
            if (text.Length > MaxEvidenceJsonLength)
            {
                rejection = "too_large";
                text = null;
            }
        }

        if (rejection is not null)
        {
            _logger.LogWarning(
                "MACHINE_EVIDENCE_DROPPED endpoint={Endpoint} productId={ProductId} hardwareId={HardwareId} reason={Reason}",
                endpoint, productId, hardwareId, rejection);
        }
        return text;
    }

    /// <summary>Lowercase SHA-256 over the raw UUID and evidence text, with explicit markers for absent values.</summary>
    private static string Digest(string? systemUuidRaw, string? evidenceJson)
    {
        var material = (systemUuidRaw is null ? "\u0000uuid-absent" : "uuid:" + systemUuidRaw)
            + "\n"
            + (evidenceJson is null ? "\u0000evidence-absent" : "evidence:" + evidenceJson);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    /// <summary>Truncates to <paramref name="maxLength"/> characters.</summary>
    private static string? Truncate(string? value, int maxLength) =>
        value is null || value.Length <= maxLength ? value : value[..maxLength];
}

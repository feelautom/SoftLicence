using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public enum ApprovedBinaryVerdict
{
    Approved,
    Mismatch,
    BaselineMissing,
    EvidenceInvalidOrUntrusted
}

public sealed record ApprovedBinaryArtifact(string Key, string Sha256);

public sealed record ApprovedBinaryVerificationResult(
    ApprovedBinaryVerdict Verdict,
    IReadOnlyList<ApprovedBinaryArtifact> Artifacts,
    IReadOnlyDictionary<string, string> Mismatches,
    string? ErrorCode = null,
    bool Idempotent = false,
    string? Source = null,
    string? RegistrationId = null,
    Guid? BaselineId = null,
    string? ManifestDigestSha256 = null,
    string? BaselineDigestSha256 = null);

public sealed class ApprovedBinaryService
{
    public const string ReleaseSource = "release";
    public const string AdminSource = "admin";
    public static readonly Guid TiaConnectLegacyAdoptionProductId =
        Guid.Parse("808648bc-a4b9-4f71-bcb1-b7c7e67ca98e");
    public const string TiaConnectLegacyAdoptionVersion = "2.3.62";

    private static readonly string[] RequiredKeys = ["FP_EXE", "FP_DLL", "FP_CORE"];
    private static readonly HashSet<string> RequiredKeySet = new(RequiredKeys, StringComparer.Ordinal);
    private static readonly Regex VersionPattern = new(
        "^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex RegistrationKeyPattern = new(
        "^[!-~]{1,128}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<ApprovedBinaryService> _logger;

    public ApprovedBinaryService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        ILogger<ApprovedBinaryService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<(bool ProductExists, ApprovedBinaryVerificationResult Result)> RegisterReleaseBaselineAsync(
        Guid productId,
        string? version,
        string? registrationId,
        string? manifestDigestSha256,
        IReadOnlyCollection<ApprovedBinaryArtifact>? artifacts,
        CancellationToken cancellationToken = default)
    {
        var normalizedVersion = NormalizeVersion(version);
        if (normalizedVersion == null)
            return (true, Invalid("invalid_version"));

        if (!IsValidRegistrationKey(registrationId))
            return (true, Invalid("invalid_registration_id"));

        if (!IsCanonicalSha256(manifestDigestSha256))
            return (true, Invalid("invalid_manifest_digest"));

        var normalization = NormalizeArtifacts(artifacts, requireCompleteSet: true);
        if (normalization.ErrorCode != null)
            return (true, Invalid(normalization.ErrorCode));

        var baselineDigest = ComputeBaselineDigestSha256(normalization.Artifacts);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        if (!await db.Products.AsNoTracking().AnyAsync(product => product.Id == productId, cancellationToken))
            return (false, Missing());

        IDbContextTransaction? transaction = null;
        if (db.Database.IsRelational())
            transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        await using (transaction)
        {
            var keyRegistration = await LoadRegistrationByKeyAsync(db, registrationId!, cancellationToken);
            if (keyRegistration != null)
            {
                var result = EvaluateRegistrationRequest(
                    keyRegistration,
                    productId,
                    normalizedVersion,
                    registrationId!,
                    manifestDigestSha256!,
                    baselineDigest,
                    normalization.Artifacts);
                if (transaction != null)
                    await transaction.RollbackAsync(cancellationToken);
                return (true, result);
            }

            var versionRegistration = await LoadRegistrationAsync(db, productId, normalizedVersion, cancellationToken);
            if (versionRegistration != null)
            {
                if (transaction != null)
                    await transaction.RollbackAsync(cancellationToken);
                return (true, Conflict("baseline_registration_conflict"));
            }

            if (await db.ApprovedBinaries.AsNoTracking().AnyAsync(
                    row => row.ProductId == productId && row.Version == normalizedVersion,
                    cancellationToken))
            {
                if (transaction != null)
                    await transaction.RollbackAsync(cancellationToken);
                return (true, Conflict("baseline_not_authoritative"));
            }

            var registration = new ApprovedBinaryRegistration
            {
                ProductId = productId,
                Version = normalizedVersion,
                RegistrationKey = registrationId!,
                ManifestDigestSha256 = manifestDigestSha256!,
                BaselineDigestSha256 = baselineDigest,
                Source = ReleaseSource,
                RegisteredAtUtc = DateTime.UtcNow
            };
            db.ApprovedBinaryRegistrations.Add(registration);
            foreach (var artifact in normalization.Artifacts)
            {
                db.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = productId,
                    ApprovedBinaryRegistrationId = registration.Id,
                    Version = normalizedVersion,
                    Key = artifact.Key,
                    Hash = artifact.Sha256,
                    Source = ReleaseSource,
                    ApprovedAt = registration.RegisteredAtUtc,
                    ApprovedBy = "release-api"
                });
            }

            try
            {
                await db.SaveChangesAsync(cancellationToken);
                if (transaction != null)
                    await transaction.CommitAsync(cancellationToken);
            }
            catch (DbUpdateException ex)
            {
                if (transaction != null)
                    await transaction.RollbackAsync(cancellationToken);
                _logger.LogWarning(ex,
                    "Concurrent ApprovedBinaries registration detected for product {ProductId} version {Version}",
                    productId,
                    normalizedVersion);
                return await ClassifyConcurrentRegistrationAsync(
                    productId,
                    normalizedVersion,
                    registrationId!,
                    manifestDigestSha256!,
                    baselineDigest,
                    normalization.Artifacts,
                    cancellationToken);
            }

            return (true, BuildApproved(registration, normalization.Artifacts, idempotent: false));
        }
    }

    /// <summary>
    /// Adopts only the pre-registration T-IA Connect 2.3.62 release rows. The operation deliberately
    /// cannot serve as a generic migration: product, version, row count, provenance, keys and hashes
    /// must all match the caller's canonical evidence before any row is linked (DOC-264).
    /// </summary>
    public async Task<(bool ProductExists, ApprovedBinaryVerificationResult Result)> AdoptTiaConnect2362LegacyBaselineAsync(
        Guid productId,
        string? version,
        string? registrationId,
        string? manifestDigestSha256,
        IReadOnlyCollection<ApprovedBinaryArtifact>? artifacts,
        CancellationToken cancellationToken = default)
    {
        if (productId != TiaConnectLegacyAdoptionProductId
            || !string.Equals(version, TiaConnectLegacyAdoptionVersion, StringComparison.Ordinal))
            return (true, Invalid("legacy_adoption_not_allowed"));
        if (!IsValidRegistrationKey(registrationId))
            return (true, Invalid("invalid_registration_id"));
        if (!IsCanonicalSha256(manifestDigestSha256))
            return (true, Invalid("invalid_manifest_digest"));

        var normalization = NormalizeCanonicalArtifacts(artifacts);
        if (normalization.ErrorCode != null)
            return (true, Invalid(normalization.ErrorCode));

        var baselineDigest = ComputeBaselineDigestSha256(normalization.Artifacts);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        if (!await db.Products.AsNoTracking().AnyAsync(product => product.Id == productId, cancellationToken))
            return (false, Missing());

        IDbContextTransaction? transaction = null;
        if (db.Database.IsRelational())
            transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        await using (transaction)
        {
            try
            {
                var existing = await LoadRegistrationAsync(db, productId, version!, cancellationToken);
                if (existing != null)
                {
                    if (transaction != null)
                        await transaction.RollbackAsync(cancellationToken);
                    return (true, EvaluateRegistrationRequest(existing, productId, version!, registrationId!,
                        manifestDigestSha256!, baselineDigest, normalization.Artifacts));
                }

                var rows = await db.ApprovedBinaries
                    .Where(row => row.ProductId == productId && row.Version == version)
                    .OrderBy(row => row.Key)
                    .ToListAsync(cancellationToken);
                if (rows.Count != RequiredKeys.Length
                    || rows.Any(row => row.ApprovedBinaryRegistrationId != null
                        || !string.Equals(row.Source, ReleaseSource, StringComparison.Ordinal)))
                    return await RollbackConflictAsync(transaction, "legacy_baseline_not_adoptable", cancellationToken);

                var persisted = NormalizeCanonicalArtifacts(rows
                    .Select(row => new ApprovedBinaryArtifact(row.Key, row.Hash))
                    .ToList());
                if (persisted.ErrorCode != null || !persisted.Artifacts.SequenceEqual(normalization.Artifacts))
                    return await RollbackConflictAsync(transaction, "legacy_baseline_mismatch", cancellationToken);

                var registration = new ApprovedBinaryRegistration
                {
                    ProductId = productId,
                    Version = version!,
                    RegistrationKey = registrationId!,
                    ManifestDigestSha256 = manifestDigestSha256!,
                    BaselineDigestSha256 = baselineDigest,
                    Source = ReleaseSource,
                    RegisteredAtUtc = DateTime.UtcNow
                };
                db.ApprovedBinaryRegistrations.Add(registration);
                foreach (var row in rows)
                    row.ApprovedBinaryRegistrationId = registration.Id;

                await db.SaveChangesAsync(cancellationToken);
                if (transaction != null)
                    await transaction.CommitAsync(cancellationToken);
                return (true, BuildApproved(registration, normalization.Artifacts, idempotent: false));
            }
            catch (Exception ex) when (IsRelationalWriteConflict(ex))
            {
                if (transaction != null)
                    await transaction.RollbackAsync(cancellationToken);
                _logger.LogWarning(ex,
                    "Concurrent bounded legacy ApprovedBinaries adoption detected for product {ProductId} version {Version}",
                    productId,
                    version);
                return await ClassifyConcurrentRegistrationAsync(productId, version!, registrationId!,
                    manifestDigestSha256!, baselineDigest, normalization.Artifacts, cancellationToken);
            }
        }
    }

    public async Task<(bool ProductExists, ApprovedBinaryVerificationResult Result)> GetAuthoritativeBaselineAsync(
        Guid productId,
        string? version,
        CancellationToken cancellationToken = default)
    {
        var normalizedVersion = NormalizeVersion(version);
        if (normalizedVersion == null)
            return (true, Invalid("invalid_version"));

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        if (!await db.Products.AsNoTracking().AnyAsync(product => product.Id == productId, cancellationToken))
            return (false, Missing());

        var registration = await LoadRegistrationAsync(db, productId, normalizedVersion, cancellationToken);
        if (registration != null)
            return (true, EvaluatePersistedRegistration(registration));

        var rows = await LoadVersionRowsAsync(db, productId, normalizedVersion, cancellationToken);
        if (rows.Count == 0)
            return (true, Missing());
        return (true, rows.All(row => row.Source == ReleaseSource)
            ? Conflict("baseline_registration_missing")
            : Conflict("baseline_source_conflict"));
    }

    public async Task<ApprovedBinaryVerificationResult> EvaluateTelemetryEvidenceAsync(
        Guid productId,
        string? version,
        IReadOnlyDictionary<string, string>? properties,
        CancellationToken cancellationToken = default)
    {
        var normalizedVersion = NormalizeVersion(version);
        if (normalizedVersion == null)
            return Invalid("invalid_version");

        var evidence = NormalizeTelemetryArtifacts(properties);
        if (evidence.ErrorCode != null)
            return Invalid(evidence.ErrorCode);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var registration = await LoadRegistrationAsync(db, productId, normalizedVersion, cancellationToken);
        if (registration == null)
            return Missing();
        var baseline = EvaluatePersistedRegistration(registration);
        if (baseline.Verdict != ApprovedBinaryVerdict.Approved)
            return Missing();

        var baselineMap = baseline.Artifacts.ToDictionary(artifact => artifact.Key, artifact => artifact.Sha256, StringComparer.Ordinal);
        var evidenceMap = evidence.Artifacts.ToDictionary(artifact => artifact.Key, artifact => artifact.Sha256, StringComparer.Ordinal);
        var mismatches = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, expectedHash) in baselineMap)
        {
            if (evidenceMap.TryGetValue(key, out var reportedHash)
                && !string.Equals(expectedHash, reportedHash, StringComparison.Ordinal))
                mismatches[key] = reportedHash;
        }

        if (mismatches.Count > 0)
            return new ApprovedBinaryVerificationResult(ApprovedBinaryVerdict.Mismatch, evidence.Artifacts, mismatches);
        if (RequiredKeys.Any(key => !evidenceMap.ContainsKey(key)))
            return Invalid("required_key_missing");
        return new ApprovedBinaryVerificationResult(ApprovedBinaryVerdict.Approved, evidence.Artifacts, EmptyMismatches());
    }

    public static string? NormalizeSha256(string? value)
    {
        var trimmed = value?.Trim();
        if (trimmed is not { Length: 64 })
            return null;
        foreach (var character in trimmed)
        {
            if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f')
                || (character >= 'A' && character <= 'F')))
                return null;
        }
        return trimmed.ToLowerInvariant();
    }

    public static bool IsCanonicalSha256(string? value)
    {
        if (value is not { Length: 64 })
            return false;
        return value.All(character => (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f'));
    }

    public static string? NormalizeVersion(string? version)
    {
        var trimmed = version?.Trim();
        return trimmed != null && VersionPattern.IsMatch(trimmed) ? trimmed : null;
    }

    public static bool IsValidRegistrationKey(string? registrationKey) =>
        registrationKey != null && RegistrationKeyPattern.IsMatch(registrationKey);

    public static string ComputeBaselineDigestSha256(IReadOnlyList<ApprovedBinaryArtifact> artifacts)
    {
        var canonical = string.Join('\n', artifacts.Select(artifact => $"{artifact.Key}:{artifact.Sha256}"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private async Task<(bool ProductExists, ApprovedBinaryVerificationResult Result)> ClassifyConcurrentRegistrationAsync(
        Guid productId,
        string version,
        string registrationId,
        string manifestDigest,
        string baselineDigest,
        IReadOnlyList<ApprovedBinaryArtifact> artifacts,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var keyRegistration = await LoadRegistrationByKeyAsync(db, registrationId, cancellationToken);
        if (keyRegistration != null)
            return (true, EvaluateRegistrationRequest(keyRegistration, productId, version, registrationId,
                manifestDigest, baselineDigest, artifacts));
        return (true, Conflict("baseline_registration_conflict"));
    }

    private static ApprovedBinaryVerificationResult EvaluateRegistrationRequest(
        ApprovedBinaryRegistration registration,
        Guid productId,
        string version,
        string registrationId,
        string manifestDigest,
        string baselineDigest,
        IReadOnlyList<ApprovedBinaryArtifact> artifacts)
    {
        if (registration.ProductId != productId
            || !string.Equals(registration.Version, version, StringComparison.Ordinal)
            || !string.Equals(registration.RegistrationKey, registrationId, StringComparison.Ordinal)
            || !string.Equals(registration.ManifestDigestSha256, manifestDigest, StringComparison.Ordinal)
            || !string.Equals(registration.BaselineDigestSha256, baselineDigest, StringComparison.Ordinal))
            return Conflict("registration_id_conflict");

        var persisted = EvaluatePersistedRegistration(registration);
        if (persisted.Verdict != ApprovedBinaryVerdict.Approved)
            return Conflict("baseline_not_authoritative");
        return persisted.Artifacts.SequenceEqual(artifacts)
            ? persisted with { Idempotent = true }
            : Conflict("registration_id_conflict");
    }

    private static ApprovedBinaryVerificationResult EvaluatePersistedRegistration(ApprovedBinaryRegistration registration)
    {
        if (registration.Source != ReleaseSource
            || registration.Artifacts.Count != RequiredKeys.Length
            || registration.Artifacts.Any(row => row.Source != ReleaseSource
                || row.ProductId != registration.ProductId
                || !string.Equals(row.Version, registration.Version, StringComparison.Ordinal)
                || row.ApprovedBinaryRegistrationId != registration.Id))
            return Conflict("baseline_not_authoritative");

        var normalization = NormalizeArtifacts(
            registration.Artifacts.Select(row => new ApprovedBinaryArtifact(row.Key, row.Hash)).ToList(),
            requireCompleteSet: true);
        if (normalization.ErrorCode != null)
            return Conflict("baseline_not_authoritative");
        if (!string.Equals(ComputeBaselineDigestSha256(normalization.Artifacts),
                registration.BaselineDigestSha256,
                StringComparison.Ordinal))
            return Conflict("baseline_not_authoritative");
        return BuildApproved(registration, normalization.Artifacts, idempotent: false);
    }

    private static ApprovedBinaryVerificationResult BuildApproved(
        ApprovedBinaryRegistration registration,
        IReadOnlyList<ApprovedBinaryArtifact> artifacts,
        bool idempotent) => new(
            ApprovedBinaryVerdict.Approved,
            artifacts,
            EmptyMismatches(),
            Idempotent: idempotent,
            Source: registration.Source,
            RegistrationId: registration.RegistrationKey,
            BaselineId: registration.Id,
            ManifestDigestSha256: registration.ManifestDigestSha256,
            BaselineDigestSha256: registration.BaselineDigestSha256);

    private static (IReadOnlyList<ApprovedBinaryArtifact> Artifacts, string? ErrorCode) NormalizeTelemetryArtifacts(
        IReadOnlyDictionary<string, string>? properties)
    {
        if (properties == null)
            return ([], "required_key_missing");
        var candidates = new List<ApprovedBinaryArtifact>();
        foreach (var (key, hash) in properties)
        {
            if (RequiredKeySet.Contains(key))
                candidates.Add(new ApprovedBinaryArtifact(key, hash));
            else if (RequiredKeys.Contains(key, StringComparer.OrdinalIgnoreCase))
                return ([], "non_canonical_key");
        }
        return NormalizeArtifacts(candidates, requireCompleteSet: false);
    }

    private static (IReadOnlyList<ApprovedBinaryArtifact> Artifacts, string? ErrorCode) NormalizeArtifacts(
        IReadOnlyCollection<ApprovedBinaryArtifact>? artifacts,
        bool requireCompleteSet)
    {
        if (artifacts == null)
            return ([], "invalid_payload");
        var normalized = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var artifact in artifacts)
        {
            if (!RequiredKeySet.Contains(artifact.Key))
                return ([], "invalid_key");
            if (!normalized.TryAdd(artifact.Key, string.Empty))
                return ([], "duplicate_key");
            var hash = NormalizeSha256(artifact.Sha256);
            if (hash == null)
                return ([], "invalid_hash");
            normalized[artifact.Key] = hash;
        }
        if (requireCompleteSet && RequiredKeys.Any(key => !normalized.ContainsKey(key)))
            return ([], "required_key_missing");
        var ordered = RequiredKeys
            .Where(normalized.ContainsKey)
            .Select(key => new ApprovedBinaryArtifact(key, normalized[key]))
            .ToList();
        return (ordered, null);
    }

    private static (IReadOnlyList<ApprovedBinaryArtifact> Artifacts, string? ErrorCode) NormalizeCanonicalArtifacts(
        IReadOnlyCollection<ApprovedBinaryArtifact>? artifacts)
    {
        var normalized = NormalizeArtifacts(artifacts, requireCompleteSet: true);
        if (normalized.ErrorCode != null)
            return normalized;
        if (artifacts!.Count != RequiredKeys.Length)
            return ([], "invalid_payload");
        var exact = artifacts.ToDictionary(artifact => artifact.Key, artifact => artifact.Sha256, StringComparer.Ordinal);
        if (normalized.Artifacts.Any(artifact => !exact.TryGetValue(artifact.Key, out var supplied)
                || !string.Equals(supplied, artifact.Sha256, StringComparison.Ordinal)))
            return ([], "non_canonical_hash");
        return normalized;
    }

    private static async Task<(bool ProductExists, ApprovedBinaryVerificationResult Result)> RollbackConflictAsync(
        IDbContextTransaction? transaction,
        string errorCode,
        CancellationToken cancellationToken)
    {
        if (transaction != null)
            await transaction.RollbackAsync(cancellationToken);
        return (true, Conflict(errorCode));
    }

    private static bool IsRelationalWriteConflict(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is PostgresException postgres
                && postgres.SqlState is PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.UniqueViolation)
                return true;
        }
        return false;
    }

    private static Task<ApprovedBinaryRegistration?> LoadRegistrationByKeyAsync(
        LicenseDbContext db,
        string registrationId,
        CancellationToken cancellationToken) =>
        db.ApprovedBinaryRegistrations.AsNoTracking()
            .Include(registration => registration.Artifacts)
            .SingleOrDefaultAsync(registration => registration.RegistrationKey == registrationId, cancellationToken);

    private static Task<ApprovedBinaryRegistration?> LoadRegistrationAsync(
        LicenseDbContext db,
        Guid productId,
        string version,
        CancellationToken cancellationToken) =>
        db.ApprovedBinaryRegistrations.AsNoTracking()
            .Include(registration => registration.Artifacts)
            .SingleOrDefaultAsync(
                registration => registration.ProductId == productId && registration.Version == version,
                cancellationToken);

    private static Task<List<ApprovedBinary>> LoadVersionRowsAsync(
        LicenseDbContext db,
        Guid productId,
        string version,
        CancellationToken cancellationToken) =>
        db.ApprovedBinaries.AsNoTracking()
            .Where(row => row.ProductId == productId && row.Version == version)
            .ToListAsync(cancellationToken);

    private static ApprovedBinaryVerificationResult Invalid(string errorCode) =>
        new(ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted, [], EmptyMismatches(), errorCode);

    private static ApprovedBinaryVerificationResult Missing() =>
        new(ApprovedBinaryVerdict.BaselineMissing, [], EmptyMismatches(), "baseline_missing");

    private static ApprovedBinaryVerificationResult Conflict(string errorCode) =>
        new(ApprovedBinaryVerdict.BaselineMissing, [], EmptyMismatches(), errorCode);

    private static IReadOnlyDictionary<string, string> EmptyMismatches() =>
        new Dictionary<string, string>(StringComparer.Ordinal);
}

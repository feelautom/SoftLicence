using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services.SecurityLocks;

namespace SoftLicence.Server.Services;

public sealed partial class RuntimeEnrollmentService
{
    /// <summary>Exact request path bound into the lock report proof.</summary>
    public const string SecurityLockReportPath = "/api/security/lock-report";

    /// <summary>
    /// Processes one authenticated security lock report and returns a signed verdict (TKT-001177). Security
    /// contract: the same enrollment proof, authority lease, quota and binding checks as a critical canary apply;
    /// the proof payload uses its own prefix and path so a canary proof can never be replayed here; the verdict
    /// is computed server-side only (client mode is informational) and ENFORCE bans the hardware in the same
    /// transaction; hardware that already has a live ban receives a signed BAN without the authority check (which
    /// would otherwise reject it first); a replayed JTI returns the stored verdict, any other reuse is a conflict.
    /// </summary>
    /// <param name="routeEnrollmentId">Enrollment from the authenticated header.</param>
    /// <param name="exactBodyDigest">Lower-case SHA-256 of the exact request body.</param>
    /// <param name="request">Deserialized request.</param>
    /// <param name="proof">Proof headers.</param>
    /// <param name="clientAddress">Client address for quotas.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The signed verdict and its exact JSON bytes.</returns>
    public async Task<RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>> ProcessSecurityLockReportAsync(
        Guid routeEnrollmentId,
        string exactBodyDigest,
        SecurityLockReportRequest request,
        RuntimeProofHeaders proof,
        IPAddress? clientAddress,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        if (_canaryAck == null)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        if (!LowerSha256Pattern.IsMatch(exactBodyDigest))
            throw Invalid();
        SecurityLockValidatedReport report;
        try
        {
            report = SecurityLockReportValidator.Validate(request, DateTimeOffset.UtcNow);
        }
        catch (SecurityLockReportValidationException exception)
        {
            throw new RuntimeEnrollmentException(exception.ErrorCode, StatusCodes.Status400BadRequest);
        }

        var validatedProof = ValidateProofHeaders(proof);
        var preflight = await LoadProofPreflightAsync(routeEnrollmentId, cancellationToken);
        VerifySecurityLockReportProof(preflight, report.ReportId, exactBodyDigest, validatedProof);

        var result = await ExecuteWithRetriesAsync(async () =>
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);

            var now = await DatabaseNowAsync(db, cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("lock-report-binding", preflight.BindingId.ToString("D"), 60),
                 ("lock-report-credential", preflight.EnrollmentId.ToString("D"), 30),
                 ("lock-report-ip", PseudonymizeAddress(clientAddress), 30),
                 ("lock-report-global", "all", 600)], cancellationToken);
            ValidateProofTime(validatedProof.SentAtUtc, now);
            if (Sha256(report.HardwareId) != enrollment.HardwareIdHash
                || !string.Equals(report.AppVersion, enrollment.ReleaseVersion, StringComparison.Ordinal))
                throw Reject("lock_report_binding_mismatch");

            // Historical bans may be stored in any case (same rule as every other ban lookup); the report value is
            // already the validated canonical upper-case form, so only the column side is folded.
            var hardwareBanned = await db.BannedHardwareIds.AsNoTracking().AnyAsync(ban =>
                ban.HardwareId.ToUpper() == report.HardwareId && ban.IsActive
                && (ban.ProductId == null || ban.ProductId == enrollment.ProductId)
                && (ban.ExpiresAt == null || ban.ExpiresAt > now.UtcDateTime), cancellationToken);
            // A banned hardware makes the enrollment authority ineligible, which would reject the report before any
            // verdict and leave the client without its signed BAN. The proof is already verified and BAN is the most
            // restrictive verdict, so banned hardware skips the authority check and always receives BAN below.
            if (!hardwareBanned)
            {
                try
                {
                    await ValidateEnrollmentAuthorityAsync(db, enrollment, now, cancellationToken);
                }
                catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
                {
                    await CommitInvalidationAsync(db, lease, enrollment, exception, now, cancellationToken);
                    throw;
                }
                if (enrollment.State != "ACTIVE")
                    throw Reject("enrollment_inactive");
            }

            var jti = validatedProof.Jti.ToString("D");
            var existingNonce = await db.SecurityLockReportNonces.AsNoTracking()
                .SingleOrDefaultAsync(nonce => nonce.EnrollmentId == enrollment.Id && nonce.Jti == jti, cancellationToken);
            if (existingNonce != null)
            {
                if (!string.Equals(existingNonce.ReportId, report.ReportId, StringComparison.Ordinal)
                    || !string.Equals(existingNonce.BodyDigestSha256, exactBodyDigest, StringComparison.Ordinal))
                    throw Conflict("proof_replay");
                var stored = JsonSerializer.Deserialize<SecurityLockVerdictResponse>(existingNonce.ResponseJson, JsonOptions)
                    ?? throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>(
                    stored, true, Encoding.UTF8.GetBytes(existingNonce.ResponseJson));
            }

            var configuredMode = await db.SecurityLockEnforcementPolicies.AsNoTracking()
                .Where(policy => policy.ProductId == enrollment.ProductId && policy.Cause == report.Cause)
                .Select(policy => policy.Mode)
                .SingleOrDefaultAsync(cancellationToken);
            var effectiveMode = SecurityLockVerdictPolicy.ResolveEffectiveMode(report.Level, configuredMode);
            var row = await db.SecurityLockReports
                .SingleOrDefaultAsync(existing => existing.EnrollmentId == enrollment.Id && existing.LockId == report.LockId,
                    cancellationToken);
            if (row != null && (!string.Equals(row.Cause, report.Cause, StringComparison.Ordinal)
                                || !string.Equals(row.EvidenceDigestSha256, report.EvidenceDigestSha256, StringComparison.Ordinal)))
                throw Conflict("lock_id_conflict");
            var openCriticalIncident = await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(incident =>
                incident.BindingId == enrollment.BindingId && incident.State == "OPEN", cancellationToken);

            var decision = SecurityLockVerdictPolicy.Decide(new SecurityLockDecisionInput(
                report.Cause, report.Level, effectiveMode, row?.AdminDecision, hardwareBanned, openCriticalIncident));

            var isNewLock = row == null;
            if (row == null)
            {
                row = new SecurityLockReport
                {
                    ProductId = enrollment.ProductId,
                    EnrollmentId = enrollment.Id,
                    BindingId = enrollment.BindingId,
                    InstallationId = enrollment.InstallationId,
                    HardwareId = report.HardwareId,
                    AppVersion = report.AppVersion,
                    LockId = report.LockId,
                    Cause = report.Cause,
                    Level = report.Level,
                    EvidenceDigestSha256 = report.EvidenceDigestSha256,
                    FirstSeenUtc = report.FirstSeenUtc.UtcDateTime,
                    FirstReportedUtc = now.UtcDateTime
                };
                db.SecurityLockReports.Add(row);
            }
            row.ClientMode = report.ClientMode;
            row.EffectiveMode = effectiveMode;
            row.LastReportedUtc = now.UtcDateTime;
            row.ReportCount += 1;
            row.State = decision.State;
            row.LastVerdict = decision.Verdict;

            if (string.Equals(decision.Verdict, SecurityLockVerdicts.Ban, StringComparison.Ordinal) && !hardwareBanned)
            {
                await SecurityLockBans.StagePermanentBanAsync(db, report.HardwareId, enrollment.ProductId,
                    "security-lock:" + report.Cause + ":" + report.LockId,
                    SecurityLockVerdictPolicy.BanCategoryFor(report.Level), now.UtcDateTime, cancellationToken);
            }

            var verdict = _canaryAck.CreateSecurityLockVerdict(enrollment.Id, report, decision.Verdict, now);
            var verdictJson = JsonSerializer.Serialize(verdict, JsonOptions);
            db.SecurityLockReportNonces.Add(new SecurityLockReportNonce
            {
                EnrollmentId = enrollment.Id,
                Jti = jti,
                ReportId = report.ReportId,
                BodyDigestSha256 = exactBodyDigest,
                ResponseJson = verdictJson,
                ExpiresAtUtc = now.AddHours(_options.ProofNonceRetentionHours).UtcDateTime
            });
            var newBan = string.Equals(decision.Verdict, SecurityLockVerdicts.Ban, StringComparison.Ordinal) && !hardwareBanned;
            if (newBan || (isNewLock && SecurityLockAlertPolicy.ShouldAlertNewLock(report.Cause, report.Level, decision.Verdict)))
            {
                await SecurityLockAlertOutboxProcessor.StageAsync(
                    db, row, newBan, clientAddress?.ToString(), now.UtcDateTime, cancellationToken);
            }
            enrollment.AuthorityEpoch = lease.AuthorityEpoch;
            await db.SaveChangesAsync(cancellationToken);
            await lease.CommitAsync(cancellationToken);
            return new RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>(
                verdict, false, Encoding.UTF8.GetBytes(verdictJson));
        }, cancellationToken);
        return result;
    }

    /// <summary>
    /// Canonical payload signed by the enrollment key for a lock report. Its own prefix and exact path make it
    /// unusable as a canary, capability or confirmation proof, and vice versa.
    /// </summary>
    /// <param name="enrollmentId">Enrollment.</param>
    /// <param name="epoch">Enrollment epoch.</param>
    /// <param name="audience">Canary audience reused for lock reports.</param>
    /// <param name="timestamp">Proof timestamp.</param>
    /// <param name="jti">Proof JTI.</param>
    /// <param name="reportId">Report identifier.</param>
    /// <param name="bodyDigest">Lower-case SHA-256 of the exact body.</param>
    public static string BuildSecurityLockReportProofPayload(
        Guid enrollmentId,
        int epoch,
        string audience,
        string timestamp,
        string jti,
        string reportId,
        string bodyDigest) => string.Join('\n',
            "security-lock-report-proof-v1", "PS256", enrollmentId.ToString("D"),
            epoch.ToString(CultureInfo.InvariantCulture), "POST", SecurityLockReportPath, audience,
            timestamp, jti, reportId, bodyDigest);

    private void VerifySecurityLockReportProof(
        ProofPreflight enrollment,
        string reportId,
        string bodyDigest,
        ProofValidated proof)
    {
        var payload = BuildSecurityLockReportProofPayload(
            enrollment.EnrollmentId, enrollment.Epoch, _options.CanaryAudience,
            proof.Timestamp, proof.Jti.ToString("D"), reportId, bodyDigest);
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
}

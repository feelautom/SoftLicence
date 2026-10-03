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
    /// contract: enrolled proof, key registry, release identity, authority lease and quota checks apply;
    /// its distinct prefix and path prevent cross-workflow proof replay. Commercial denial accepts the
    /// security evidence but keeps the lock; ENFORCE can ban only hardware linked to the assignment or
    /// authenticated alias. A live ban remains BAN. Exact JTI replay returns frozen bytes only while their
    /// verdict is at least as restrictive as today's policy.
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
            report = SecurityLockReportValidator.ValidateStructure(request);
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
            // A report may atomically create a permanent hardware ban. Own the global mutation side
            // before enrollment, hardware, assignment and report locks so the later protected-table
            // trigger is reentrant instead of a shared-to-exclusive upgrade.
            await using var lease = await _authority.AcquireMutationAsync(
                db, preflight.BindingId, cancellationToken);
            await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
            var enrollment = await LoadEnrollmentForUpdateAsync(db, routeEnrollmentId, cancellationToken);
            EnsurePreflightUnchanged(enrollment, preflight);

            // Ban writers use the same advisory key. Keep the policy read and any new ban in this transaction.
            await SecurityService.AcquireHardwareBanMutationAsync(db, report.HardwareId);
            // Hold the shared half of the assignment writer's commit barrier through
            // assessment, first-receipt capture and the signed decision.
            await db.Database.ExecuteSqlRawAsync(
                "SELECT pg_catalog.pg_advisory_xact_lock_shared(1312, 1)", cancellationToken);
            // The hardware advisory lock precedes this row lock in both Runtime and admin BAN.
            // A concurrent admin decision is visible before the signed policy is recomputed.
            var row = await db.SecurityLockReports.FromSqlInterpolated($"""
                SELECT * FROM public."SecurityLockReports"
                WHERE "EnrollmentId" = {enrollment.Id} AND "LockId" = {report.LockId}
                FOR UPDATE
                """).SingleOrDefaultAsync(cancellationToken);
            // Every timestamp and authority decision below uses provider time sampled after global,
            // enrollment, hardware, assignment-barrier and report-row waits.
            var now = await DatabaseNowAsync(db, cancellationToken);
            try
            {
                SecurityLockReportValidator.ValidateTime(report, now);
            }
            catch (SecurityLockReportValidationException exception)
            {
                throw new RuntimeEnrollmentException(exception.ErrorCode, StatusCodes.Status400BadRequest);
            }
            ValidateProofTime(validatedProof.SentAtUtc, now);
            var approved = await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "ACTIVE", false, null, cancellationToken);
            if (!string.Equals(report.AppVersion, enrollment.ReleaseVersion, StringComparison.Ordinal))
                throw Reject("lock_report_binding_mismatch");
            // LockId is an immutable report identity. A new proof cannot upgrade a prior UNLINKED observation.
            if (row != null && (!string.Equals(row.HardwareId, report.HardwareId, StringComparison.Ordinal)
                                || !string.Equals(row.AppVersion, report.AppVersion, StringComparison.Ordinal)
                                || !string.Equals(row.Cause, report.Cause, StringComparison.Ordinal)
                                || row.Level != report.Level
                                || !string.Equals(row.EvidenceDigestSha256, report.EvidenceDigestSha256, StringComparison.Ordinal)
                                // Compare at PostgreSQL's exact microsecond storage precision.
                                || row.FirstSeenUtc != new DateTime(
                                    report.FirstSeenUtc.UtcDateTime.Ticks / 10 * 10, DateTimeKind.Utc)
                                || row.ProductId != enrollment.ProductId
                                || row.BindingId != enrollment.BindingId
                                || !string.Equals(row.InstallationId, enrollment.InstallationId, StringComparison.Ordinal)))
                throw Conflict("lock_id_conflict");
            var commercial = await RuntimeCommercialEligibilityValidator.AssessAsync(
                db, enrollment, approved.Binaries, now, report.HardwareId, cancellationToken);
            var hardwareBanned = commercial.ReportHardwareBanned;
            var configuredMode = await db.SecurityLockEnforcementPolicies.AsNoTracking()
                .Where(policy => policy.ProductId == enrollment.ProductId && policy.Cause == report.Cause)
                .Select(policy => policy.Mode)
                .SingleOrDefaultAsync(cancellationToken);
            var effectiveMode = SecurityLockVerdictPolicy.ResolveEffectiveMode(report.Level, configuredMode);
            var openCriticalIncident = await db.RuntimeCriticalIncidents.AsNoTracking().AnyAsync(incident =>
                incident.BindingId == enrollment.BindingId && incident.State == "OPEN", cancellationToken);
            await ReserveQuotasAsync(db, now,
                [("lock-report-binding", preflight.BindingId.ToString("D"), 60),
                 ("lock-report-credential", preflight.EnrollmentId.ToString("D"), 30),
                 ("lock-report-ip", PseudonymizeAddress(clientAddress), 30),
                 ("lock-report-global", "all", 600)], cancellationToken);
            var currentDecision = SecurityLockVerdictPolicy.ApplyAuthorityBoundary(
                SecurityLockVerdictPolicy.Decide(new SecurityLockDecisionInput(
                    report.Cause, report.Level, effectiveMode, row?.AdminDecision, hardwareBanned, openCriticalIncident)),
                commercial.IsEligible, commercial.ReportHardwareLinked, hardwareBanned);
            if (row is not null && currentDecision.Verdict == SecurityLockVerdicts.Ban && !hardwareBanned
                && row.LinkStatus is not (SecurityLockReportLinkStatuses.VerifiedSeat
                    or SecurityLockReportLinkStatuses.VerifiedAlias))
                currentDecision = new SecurityLockDecision(SecurityLockVerdicts.Maintain,
                    SecurityLockReportStates.Open);

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
                if (!SecurityLockVerdictPolicy.ReplayRemainsSafe(stored.Verdict, currentDecision.Verdict))
                    throw Conflict("stale_verdict");
                await lease.CommitAsync(cancellationToken);
                return new RuntimeEnrollmentOperationResult<SecurityLockVerdictResponse>(
                    stored, true, Encoding.UTF8.GetBytes(existingNonce.ResponseJson));
            }

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
                    FirstReportedUtc = now.UtcDateTime,
                    ClientMode = report.ClientMode,
                    EffectiveMode = effectiveMode,
                    LastReportedUtc = now.UtcDateTime,
                    State = SecurityLockReportStates.Open,
                    LastVerdict = SecurityLockVerdicts.Maintain
                };
                db.SecurityLockReports.Add(row);
                // The BEFORE INSERT trigger captures the immutable server link. This first flush
                // remains inside the authority transaction; failure rolls back report and proof.
                await db.SaveChangesAsync(cancellationToken);
                await db.Entry(row).ReloadAsync(cancellationToken);
            }
            var linkAtDecision = isNewLock
                ? row.LinkStatus is SecurityLockReportLinkStatuses.VerifiedSeat
                    or SecurityLockReportLinkStatuses.VerifiedAlias
                : commercial.ReportHardwareLinked;
            var decision = SecurityLockVerdictPolicy.ApplyAuthorityBoundary(
                SecurityLockVerdictPolicy.Decide(new SecurityLockDecisionInput(
                    report.Cause, report.Level, effectiveMode, row.AdminDecision,
                    hardwareBanned, openCriticalIncident)),
                commercial.IsEligible, linkAtDecision, hardwareBanned);
            // A legacy or originally unlinked lock cannot gain an irreversible ban merely
            // because a mutable seat later acquired the reported identifier.
            if (decision.Verdict == SecurityLockVerdicts.Ban && !hardwareBanned
                && row.LinkStatus is not (SecurityLockReportLinkStatuses.VerifiedSeat
                    or SecurityLockReportLinkStatuses.VerifiedAlias))
                decision = new SecurityLockDecision(SecurityLockVerdicts.Maintain, SecurityLockReportStates.Open);
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
            // Security evidence and commercial policy do not create a new enrollment lineage. The mutation
            // lease still serializes protected authority and ban writes, but its global epoch remains audit data.
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

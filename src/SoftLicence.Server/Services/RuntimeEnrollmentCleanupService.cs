using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed class RuntimeEnrollmentCleanupService(
    IDbContextFactory<LicenseDbContext> dbFactory,
    IOptions<RuntimeEnrollmentOptions> options,
    TimeProvider timeProvider,
    ILogger<RuntimeEnrollmentCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.Value.Mode != "enabled")
            return;

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1), timeProvider);
        do
        {
            try
            {
                await CleanupAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Runtime enrollment retention cleanup failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        if (!db.Database.IsNpgsql())
            return;

        await db.Database.ExecuteSqlRawAsync("""
            WITH expired_sessions AS MATERIALIZED (
                SELECT "EnrollmentId", "SessionId"
                FROM public."RuntimeMilestoneSessions"
                WHERE "ExpiresAtUtc" <= clock_timestamp()
            ), deleted_proofs AS (
                DELETE FROM public."RuntimeEnrollmentProofNonces" proof
                USING public."RuntimeMilestones" milestone, expired_sessions expired
                WHERE proof."EnrollmentId" = milestone."EnrollmentId"
                  AND proof."Jti" = milestone."Jti"
                  AND milestone."EnrollmentId" = expired."EnrollmentId"
                  AND milestone."SessionId" = expired."SessionId"
                RETURNING proof."EnrollmentId"
            )
            DELETE FROM public."RuntimeMilestoneSessions" session
            USING expired_sessions expired
            WHERE session."EnrollmentId" = expired."EnrollmentId"
              AND session."SessionId" = expired."SessionId";
            DELETE FROM public."RuntimeCanaryProofNonces"
            WHERE "ExpiresAtUtc" < clock_timestamp();
            DELETE FROM public."RuntimeEnrollmentProofNonces"
            WHERE "ExpiresAtUtc" < clock_timestamp();
            DELETE FROM public."RuntimeEnrollmentQuotas"
            WHERE "ExpiresAtUtc" < clock_timestamp();
            DELETE FROM public."RuntimeEnrollmentCredentialMutexes"
            WHERE "ExpiresAtUtc" < clock_timestamp();
            UPDATE public."RuntimeCriticalRecoveryReceipts"
            SET "ExactResponseBody" = NULL,
                "DeliveryPurgedAtUtc" = clock_timestamp()
            WHERE "ExactResponseBody" IS NOT NULL
              AND "ExpiresAtUtc" <= clock_timestamp();
            UPDATE public."DistributionLicenseBootstrapCapabilities"
            SET "State" = 'EXPIRED'
            WHERE "State" = 'ISSUED' AND "ExpiresAtUtc" <= clock_timestamp();
            UPDATE public."DistributionLicenseBootstrapAuthorizations"
            SET "State" = 'EXPIRED'
            WHERE "State" = 'ISSUED' AND "ExpiresAtUtc" <= clock_timestamp();
            UPDATE public."DistributionLicenseBootstrapAuthorizations"
            SET "ResponseCiphertext" = NULL,
                "ResponseKeyId" = NULL,
                "ResponseCiphertextLength" = NULL,
                "ResponsePlaintextLength" = NULL
            WHERE ("ResponseCiphertext" IS NOT NULL
                OR "ResponseKeyId" IS NOT NULL
                OR "ResponseCiphertextLength" IS NOT NULL
                OR "ResponsePlaintextLength" IS NOT NULL)
              AND "ExpiresAtUtc" <= clock_timestamp();
            UPDATE public."DistributionLicenseBootstrapRequests"
            SET "ExactResponseCiphertext" = ''::bytea,
                "ResponseKeyId" = 'purged'
            WHERE pg_catalog.octet_length("ExactResponseCiphertext") > 0
              AND "ExpiresAtUtc" <= clock_timestamp();
            UPDATE public."RuntimeEnrollments"
            SET "State" = 'INVALIDATED',
                "InvalidatedAtUtc" = clock_timestamp(),
                "InvalidationReason" = 'challenge_expired'
            WHERE "State" = 'PENDING'
              AND "ChallengeExpiresAtUtc" <= clock_timestamp();
            """, cancellationToken);
    }
}

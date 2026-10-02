using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services.SecurityLocks;

namespace SoftLicence.Server.Services;

/// <summary>
/// Persists and delivers security-lock alerts independently for each configured channel. Provider calls are never
/// made in the verdict transaction, while the delivery intent is committed atomically with that verdict.
/// </summary>
public sealed class SecurityLockAlertOutboxProcessor(
    IDbContextFactory<LicenseDbContext> dbFactory,
    IHttpClientFactory httpClientFactory,
    IServiceScopeFactory scopeFactory,
    IOptions<SmtpSettings> smtpOptions,
    GeoIpService geoIp,
    TimeProvider timeProvider,
    ILogger<SecurityLockAlertOutboxProcessor> logger)
{
    private const int MaximumAttempts = 6;
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Adds one email delivery and one row per matching webhook to the caller's current transaction.
    /// </summary>
    internal static async Task StageAsync(
        LicenseDbContext db,
        SecurityLockReport report,
        bool newBan,
        string? clientIp,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        var trigger = newBan
            ? NotificationService.Triggers.SecurityLockBanned
            : NotificationService.Triggers.SecurityLockReported;
        var deliveries = new List<SecurityLockAlertDelivery>
        {
            Create(report.Id, "EMAIL", "ADMIN", trigger, newBan, clientIp, nowUtc)
        };
        var candidates = await db.Webhooks.AsNoTracking()
            .Where(webhook => webhook.IsEnabled && webhook.EnabledEvents.Contains(trigger))
            .Select(webhook => new { webhook.Url, webhook.EnabledEvents })
            .ToListAsync(cancellationToken);
        foreach (var target in candidates
                     .Where(candidate => candidate.Url.Length is > 0 and <= 2048
                         && candidate.EnabledEvents.Split(',', StringSplitOptions.RemoveEmptyEntries)
                             .Select(value => value.Trim()).Contains(trigger, StringComparer.Ordinal))
                     .Select(candidate => candidate.Url).Distinct(StringComparer.Ordinal))
        {
            // EnabledEvents is legacy CSV; the exact ordinal check prevents prefix/suffix subscriptions.
            deliveries.Add(Create(report.Id, "WEBHOOK", target, trigger, newBan, clientIp, nowUtc));
        }
        db.SecurityLockAlertDeliveries.AddRange(deliveries);
    }

    /// <summary>Claims and processes up to <paramref name="maximumCount"/> due deliveries.</summary>
    public async Task<int> ProcessPendingAsync(int maximumCount = 20, CancellationToken cancellationToken = default)
    {
        maximumCount = Math.Clamp(maximumCount, 1, 100);
        var processed = 0;
        for (; processed < maximumCount; processed++)
        {
            var claimed = await ClaimNextAsync(cancellationToken);
            if (claimed == null) break;
            await ProcessClaimedAsync(claimed.Value.Id, claimed.Value.LeaseToken, cancellationToken);
        }
        return processed;
    }

    private static SecurityLockAlertDelivery Create(
        Guid reportId, string channel, string target, string trigger, bool newBan, string? clientIp, DateTime nowUtc) => new()
    {
        SecurityLockReportId = reportId,
        Channel = channel,
        Target = target,
        TargetDigestSha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(target))),
        Trigger = trigger,
        NewBan = newBan,
        ClientIp = clientIp,
        State = SecurityLockAlertDeliveryStates.Pending,
        NextAttemptUtc = nowUtc,
        CreatedAtUtc = nowUtc,
        UpdatedAtUtc = nowUtc
    };

    private async Task<(Guid Id, Guid LeaseToken)?> ClaimNextAsync(CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);

        // SMTP has no idempotency key. A process death after SendAsync may have delivered the message, so an expired
        // email lease is exposed as UNKNOWN for manual review instead of risking duplicate mail.
        await db.SecurityLockAlertDeliveries
            .Where(delivery => delivery.State == SecurityLockAlertDeliveryStates.Processing
                && delivery.Channel == "EMAIL" && delivery.LeaseExpiresUtc <= now)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(delivery => delivery.State, SecurityLockAlertDeliveryStates.Unknown)
                .SetProperty(delivery => delivery.LeaseToken, (Guid?)null)
                .SetProperty(delivery => delivery.LeaseExpiresUtc, (DateTime?)null)
                .SetProperty(delivery => delivery.LastError, "smtp_outcome_unknown_after_worker_interruption")
                .SetProperty(delivery => delivery.UpdatedAtUtc, now), cancellationToken);

        var candidateIds = await db.SecurityLockAlertDeliveries.AsNoTracking()
            .Where(delivery => (delivery.State == SecurityLockAlertDeliveryStates.Pending
                                && delivery.NextAttemptUtc <= now)
                || (delivery.State == SecurityLockAlertDeliveryStates.Processing
                    && delivery.Channel == "WEBHOOK" && delivery.LeaseExpiresUtc <= now))
            .OrderBy(delivery => delivery.NextAttemptUtc)
            .ThenBy(delivery => delivery.CreatedAtUtc)
            .Select(delivery => delivery.Id)
            .Take(10)
            .ToListAsync(cancellationToken);
        foreach (var candidateId in candidateIds)
        {
            var leaseToken = Guid.NewGuid();
            var affected = await db.SecurityLockAlertDeliveries
                .Where(delivery => delivery.Id == candidateId
                    && ((delivery.State == SecurityLockAlertDeliveryStates.Pending && delivery.NextAttemptUtc <= now)
                        || (delivery.State == SecurityLockAlertDeliveryStates.Processing
                            && delivery.Channel == "WEBHOOK" && delivery.LeaseExpiresUtc <= now)))
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(delivery => delivery.State, SecurityLockAlertDeliveryStates.Processing)
                    .SetProperty(delivery => delivery.LeaseToken, leaseToken)
                    .SetProperty(delivery => delivery.LeaseExpiresUtc, now.Add(LeaseDuration))
                    .SetProperty(delivery => delivery.AttemptCount, delivery => delivery.AttemptCount + 1)
                    .SetProperty(delivery => delivery.UpdatedAtUtc, now), cancellationToken);
            if (affected == 1) return (candidateId, leaseToken);
        }
        return null;
    }

    private async Task ProcessClaimedAsync(Guid id, Guid leaseToken, CancellationToken cancellationToken)
    {
        try
        {
            await PreparePayloadAsync(id, leaseToken, cancellationToken);
            await using var readDb = await dbFactory.CreateDbContextAsync(cancellationToken);
            var delivery = await readDb.SecurityLockAlertDeliveries.AsNoTracking()
                .SingleOrDefaultAsync(row => row.Id == id && row.LeaseToken == leaseToken
                    && row.State == SecurityLockAlertDeliveryStates.Processing, cancellationToken);
            if (delivery == null) return;

            if (delivery.Channel == "EMAIL")
            {
                if (!IsSmtpConfigured(smtpOptions.Value))
                {
                    await CompleteAsync(id, leaseToken, SecurityLockAlertDeliveryStates.Skipped,
                        "smtp_not_configured", cancellationToken);
                    return;
                }
                try
                {
                    using var scope = scopeFactory.CreateScope();
                    var email = scope.ServiceProvider.GetRequiredService<EmailService>();
                    await email.SendSecurityLockAlertEmailAsync(delivery.Title!, delivery.Message!);
                    await CompleteAsync(id, leaseToken, SecurityLockAlertDeliveryStates.Sent, null, cancellationToken);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    // MailKit cannot prove whether a transport failure occurred before or after server acceptance.
                    await CompleteAsync(id, leaseToken, SecurityLockAlertDeliveryStates.Unknown,
                        Diagnostic("smtp_outcome_unknown", exception), cancellationToken);
                }
                return;
            }

            await SendWebhookAsync(delivery, leaseToken, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Security-lock alert preparation failed for delivery {DeliveryId}", id);
            await RetryAsync(id, leaseToken, Diagnostic("preparation_failed", exception), cancellationToken);
        }
    }

    private async Task PreparePayloadAsync(Guid id, Guid leaseToken, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var delivery = await db.SecurityLockAlertDeliveries
            .SingleAsync(row => row.Id == id && row.LeaseToken == leaseToken, cancellationToken);
        if (delivery.Title != null && delivery.Message != null) return;
        var row = await db.SecurityLockReports.AsNoTracking().SingleAsync(report => report.Id == delivery.SecurityLockReportId, cancellationToken);
        var product = await db.Products.AsNoTracking().Where(product => product.Id == row.ProductId)
            .Select(product => product.Name).SingleOrDefaultAsync(cancellationToken);
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .Where(candidate => candidate.Id == row.BindingId)
            .Select(candidate => new { candidate.LicenseId, candidate.LicenseSeatId })
            .SingleOrDefaultAsync(cancellationToken);
        var license = binding == null ? null : await db.Licenses.AsNoTracking()
            .Where(candidate => candidate.Id == binding.LicenseId)
            .Select(candidate => new { candidate.CustomerName, candidate.CustomerEmail, candidate.LicenseKey })
            .SingleOrDefaultAsync(cancellationToken);
        var machine = binding == null ? null : await db.LicenseSeats.AsNoTracking()
            .Where(seat => seat.Id == binding.LicenseSeatId)
            .Select(seat => seat.MachineName).SingleOrDefaultAsync(cancellationToken);
        var otherLocks = await db.SecurityLockReports.AsNoTracking()
            .CountAsync(candidate => candidate.HardwareId == row.HardwareId && candidate.Id != row.Id, cancellationToken);
        var openIncident = await db.RuntimeCriticalIncidents.AsNoTracking()
            .AnyAsync(incident => incident.BindingId == row.BindingId && incident.State == "OPEN", cancellationToken);
        var since = delivery.CreatedAtUtc.AddHours(-24);
        var telemetry = await db.TelemetryRecords.AsNoTracking()
            .Where(record => record.ProductId == row.ProductId && record.Timestamp >= since
                && record.Timestamp <= delivery.CreatedAtUtc && record.HardwareId.ToUpper() == row.HardwareId)
            .GroupBy(record => record.EventName)
            .Select(group => new { Event = group.Key, Count = group.Count() })
            .ToListAsync(cancellationToken);
        var topEvents = string.Join(", ", telemetry.OrderByDescending(item => item.Count)
            .ThenBy(item => item.Event, StringComparer.Ordinal).Take(5)
            .Select(item => item.Event + " ×" + item.Count.ToString(CultureInfo.InvariantCulture)));
        string? country = null;
        if (!string.IsNullOrEmpty(delivery.ClientIp))
        {
            var location = await geoIp.GetGeoInfoAsync(delivery.ClientIp);
            country = location.Country + (string.IsNullOrEmpty(location.City) || location.City == "Unknown"
                ? string.Empty : ", " + location.City);
        }
        delivery.Title = delivery.NewBan
            ? "Verrou de sécurité : matériel banni"
            : "Verrou de sécurité niveau " + row.Level.ToString(CultureInfo.InvariantCulture) + " : " + row.Cause;
        delivery.Message = SecurityLockAlertPolicy.BuildDossier(new SecurityLockDossier(
            product ?? row.ProductId.ToString("D"), license?.CustomerName, license?.CustomerEmail,
            SecurityLockAlertPolicy.MaskLicenseKey(license?.LicenseKey), machine, row.HardwareId, row.AppVersion,
            row.InstallationId, row.EnrollmentId, row.LockId, row.Cause, row.Level, row.EffectiveMode, row.ClientMode,
            row.LastVerdict, row.State, row.FirstSeenUtc, row.FirstReportedUtc, row.ReportCount, otherLocks,
            openIncident, row.EvidenceDigestSha256, delivery.ClientIp, country,
            telemetry.Sum(item => item.Count), topEvents));
        delivery.UpdatedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task SendWebhookAsync(
        SecurityLockAlertDelivery delivery, Guid leaseToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, delivery.Target);
        request.Headers.TryAddWithoutValidation("Idempotency-Key", "security-lock-alert/" + delivery.Id.ToString("D"));
        if (delivery.Target.Contains("ntfy", StringComparison.OrdinalIgnoreCase))
        {
            var uri = new UriBuilder(delivery.Target);
            var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
            query["title"] = delivery.Title;
            query["tags"] = delivery.NewBan ? "no_entry" : "lock";
            query["priority"] = "4";
            uri.Query = query.ToString();
            request.RequestUri = uri.Uri;
            request.Content = new StringContent(delivery.Message!);
        }
        else
        {
            request.Content = JsonContent.Create(new
            {
                trigger = delivery.Trigger,
                title = delivery.Title,
                message = delivery.Message,
                timestamp = delivery.CreatedAtUtc,
                deliveryId = delivery.Id
            });
        }

        try
        {
            using var response = await httpClientFactory.CreateClient().SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                await CompleteAsync(delivery.Id, leaseToken, SecurityLockAlertDeliveryStates.Sent, null, cancellationToken);
                return;
            }
            var status = (int)response.StatusCode;
            var diagnostic = "http_status_" + status.ToString(CultureInfo.InvariantCulture);
            if (status is 408 or 425 or 429 || status >= 500)
                await RetryAsync(delivery.Id, leaseToken, diagnostic, cancellationToken);
            else
                await CompleteAsync(delivery.Id, leaseToken, SecurityLockAlertDeliveryStates.Failed, diagnostic, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            // The remote endpoint may have accepted the body before the connection failed. Keep the ambiguity visible;
            // operators may replay manually using the stable delivery id instead of receiving silent duplicates.
            await CompleteAsync(delivery.Id, leaseToken, SecurityLockAlertDeliveryStates.Unknown,
                Diagnostic("webhook_outcome_unknown", exception), cancellationToken);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            await CompleteAsync(delivery.Id, leaseToken, SecurityLockAlertDeliveryStates.Unknown,
                Diagnostic("webhook_timeout_outcome_unknown", exception), cancellationToken);
        }
    }

    private async Task RetryAsync(Guid id, Guid leaseToken, string diagnostic, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var delivery = await db.SecurityLockAlertDeliveries.SingleOrDefaultAsync(
            row => row.Id == id && row.LeaseToken == leaseToken, cancellationToken);
        if (delivery == null) return;
        var terminal = delivery.AttemptCount >= MaximumAttempts;
        delivery.State = terminal ? SecurityLockAlertDeliveryStates.Failed : SecurityLockAlertDeliveryStates.Pending;
        delivery.NextAttemptUtc = timeProvider.GetUtcNow().UtcDateTime.AddSeconds(Math.Min(900, 15 * (1 << Math.Min(5, delivery.AttemptCount - 1))));
        delivery.LeaseToken = null;
        delivery.LeaseExpiresUtc = null;
        delivery.LastError = terminal ? "retry_exhausted:" + diagnostic : diagnostic;
        delivery.UpdatedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
        logger.LogWarning("Security-lock alert {DeliveryId} is {State} after attempt {AttemptCount}: {Diagnostic}",
            id, delivery.State, delivery.AttemptCount, delivery.LastError);
    }

    private async Task CompleteAsync(
        Guid id, Guid leaseToken, string state, string? diagnostic, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var affected = await db.SecurityLockAlertDeliveries
            .Where(row => row.Id == id && row.LeaseToken == leaseToken
                && row.State == SecurityLockAlertDeliveryStates.Processing)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.State, state)
                .SetProperty(row => row.LeaseToken, (Guid?)null)
                .SetProperty(row => row.LeaseExpiresUtc, (DateTime?)null)
                .SetProperty(row => row.LastError, diagnostic)
                .SetProperty(row => row.UpdatedAtUtc, now)
                .SetProperty(row => row.SentAtUtc,
                    state == SecurityLockAlertDeliveryStates.Sent ? now : (DateTime?)null), cancellationToken);
        if (affected == 1 && state is SecurityLockAlertDeliveryStates.Failed or SecurityLockAlertDeliveryStates.Unknown)
            logger.LogError("Security-lock alert {DeliveryId} reached {State}: {Diagnostic}", id, state, diagnostic);
    }

    private static bool IsSmtpConfigured(SmtpSettings settings)
    {
        var host = settings.Host?.Trim('"', '\'', ' ', '\t');
        var user = settings.Username?.Trim('"', '\'', ' ', '\t');
        var from = settings.FromEmail?.Trim('"', '\'', ' ', '\t');
        return !string.IsNullOrEmpty(host) && host != "localhost"
            && (!string.IsNullOrEmpty(user) || !string.IsNullOrEmpty(from));
    }

    private static string Diagnostic(string prefix, Exception exception)
    {
        var value = prefix + ":" + exception.GetType().Name;
        return value.Length <= 500 ? value : value[..500];
    }
}

/// <summary>Continuously drains the durable security-lock alert outbox.</summary>
public sealed class SecurityLockAlertOutboxWorker(
    SecurityLockAlertOutboxProcessor processor,
    ILogger<SecurityLockAlertOutboxWorker> logger) : BackgroundService
{
    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var processed = await processor.ProcessPendingAsync(cancellationToken: stoppingToken);
                if (processed == 0) await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Security-lock alert outbox cycle failed");
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }
    }
}

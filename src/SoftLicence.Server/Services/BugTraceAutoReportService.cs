using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>
/// Accepts identified automatic reports into a durable, report-only outbox and relays them to BugTrace.
/// </summary>
public interface IBugTraceAutoReportService
{
    /// <summary>
    /// Validates the closed request envelope, resolves the active license, and durably accepts one report.
    /// </summary>
    /// <param name="request">The untrusted Desktop report envelope.</param>
    /// <param name="cancellationToken">Cancels validation or the durable database write.</param>
    /// <returns>An accepted idempotent result or a stable failure code.</returns>
    Task<BugTraceAutoReportEnqueueResult> EnqueueAsync(
        BugTraceAutoReportRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Relays a bounded batch of accepted reports and persists delivery or retry state.
    /// </summary>
    /// <param name="cancellationToken">Cancels the current bounded relay batch.</param>
    /// <returns>The number of outbox records examined.</returns>
    Task<int> ProcessPendingAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Represents the report-only acceptance result without exposing license or hardware identifiers.
/// </summary>
public sealed record BugTraceAutoReportEnqueueResult(
    bool Accepted,
    bool Duplicate,
    string ReportId,
    string? TicketNumber,
    string? ErrorCode)
{
    /// <summary>Creates a stable rejected result.</summary>
    public static BugTraceAutoReportEnqueueResult Reject(string errorCode) =>
        new(false, false, string.Empty, null, errorCode);
}

/// <summary>
/// Implements the identified auto-report trust boundary. License recognition is mandatory, while a
/// hardware mismatch is recorded as metadata and tolerated only inside this service.
/// </summary>
public sealed partial class BugTraceAutoReportService : IBugTraceAutoReportService
{
    public const string Schema = "bugtrace-auto-report-v1";

    private const string OutboxPrefix = "BugTraceAutoReportOutbox_v1_";
    private const string ReceiptPrefix = "BugTraceAutoReportReceipt_v1_";
    private const string FingerprintPrefix = "BugTraceAutoReportFingerprint_v1_";
    private const int MaximumBatchSize = 20;
    private const int MaximumAttempts = 5;
    private const int MaximumLicenseKeyLength = 512;
    private const int MaximumHardwareIdLength = 256;
    private const int MaximumAppVersionLength = 64;
    private const int MaximumErrorTypeLength = 256;
    private const int MaximumErrorSourceLength = 256;
    private const int MaximumMessageLength = 4096;
    private const int MaximumStackTraceLength = 32768;
    private static readonly TimeSpan FingerprintRetention = TimeSpan.FromHours(24);
    private static readonly TimeSpan ReceiptRetention = TimeSpan.FromDays(7);
    private static readonly JsonSerializerOptions StoreJsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IBugTraceProxyService _bugTrace;
    private readonly IMemoryCache _cache;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<BugTraceAutoReportService> _logger;
    private readonly SemaphoreSlim _enqueueGate = new(1, 1);
    private readonly SemaphoreSlim _processGate = new(1, 1);

    /// <summary>
    /// Creates the singleton report boundary from database, upstream, rate-limit, clock, and logging authorities.
    /// </summary>
    public BugTraceAutoReportService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IBugTraceProxyService bugTrace,
        IMemoryCache cache,
        TimeProvider timeProvider,
        ILogger<BugTraceAutoReportService> logger)
    {
        _dbFactory = dbFactory;
        _bugTrace = bugTrace;
        _cache = cache;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<BugTraceAutoReportEnqueueResult> EnqueueAsync(
        BugTraceAutoReportRequest request,
        CancellationToken cancellationToken = default)
    {
        var validationError = ValidateEnvelope(request, out var reportId);
        if (validationError is not null)
            return BugTraceAutoReportEnqueueResult.Reject(validationError);
        var serverFingerprint = ComputeDiagnosticFingerprint(request.Report.ErrorType, request.Report.Message);
        if (!string.Equals(request.Report.Fingerprint, serverFingerprint, StringComparison.Ordinal))
            return BugTraceAutoReportEnqueueResult.Reject("fingerprint_mismatch");
        if (!_bugTrace.IsConfigured)
            return BugTraceAutoReportEnqueueResult.Reject("bugtrace_unavailable");
        if (!string.Equals(request.ProjectId, _bugTrace.ExpectedProjectId, StringComparison.OrdinalIgnoreCase))
            return BugTraceAutoReportEnqueueResult.Reject("project_invalid");

        var normalizedLicenseKey = request.LicenseKey.Trim().ToUpperInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var license = await db.Licenses.AsNoTracking()
            .Include(item => item.Product)
            .SingleOrDefaultAsync(item => item.LicenseKey == normalizedLicenseKey, cancellationToken);
        if (license is null)
            return BugTraceAutoReportEnqueueResult.Reject("license_invalid");
        if (!license.IsActive)
            return BugTraceAutoReportEnqueueResult.Reject("license_revoked");
        if (license.ExpirationDate is { } expirationDate && expirationDate <= _timeProvider.GetUtcNow().UtcDateTime)
            return BugTraceAutoReportEnqueueResult.Reject("license_expired");

        var hardwareMatches = string.IsNullOrWhiteSpace(license.HardwareId)
            || string.Equals(license.HardwareId, request.HardwareId, StringComparison.OrdinalIgnoreCase);
        var ticket = BuildServerOwnedTicket(request, license, hardwareMatches);
        var binding = ComputeBinding(request, license.Id);
        var outboxKey = ReportKey(OutboxPrefix, license.Id, reportId);
        var receiptKey = ReportKey(ReceiptPrefix, license.Id, reportId);
        var fingerprintKey = FingerprintKey(license.Id, serverFingerprint);
        var now = _timeProvider.GetUtcNow();

        await _enqueueGate.WaitAsync(cancellationToken);
        try
        {
            var existing = await ReadStoredAsync(db, [outboxKey, receiptKey], cancellationToken);
            if (existing is not null)
            {
                if (!string.Equals(existing.Binding, binding, StringComparison.Ordinal))
                    return BugTraceAutoReportEnqueueResult.Reject("report_id_conflict");
                return Accepted(existing, duplicate: true);
            }

            var existingFingerprint = await db.SystemSettings
                .SingleOrDefaultAsync(item => item.Key == fingerprintKey, cancellationToken);
            if (existingFingerprint is not null
                && TryReadFingerprint(existingFingerprint.Value, out var fingerprint)
                && fingerprint.ExpiresAtUtc > now)
            {
                var duplicate = await ReadStoredAsync(db, fingerprint.OutboxKey, cancellationToken);
                if (duplicate is not null)
                    return Accepted(duplicate, duplicate: true);
            }

            // Retries and duplicates do not consume the burst budget. The counter applies only after
            // authoritative license resolution and immediately before a new durable acceptance.
            var rateLimitKey = $"bugtrace-auto-report:{license.Id:N}";
            if (IsRateLimited(rateLimitKey))
                return BugTraceAutoReportEnqueueResult.Reject("rate_limited");

            var stored = new StoredAutoReport(
                binding,
                license.Id,
                reportId,
                serverFingerprint,
                "pending",
                0,
                null,
                now,
                ticket);
            db.SystemSettings.Add(new SystemSetting
            {
                Key = outboxKey,
                Value = JsonSerializer.Serialize(stored, StoreJsonOptions),
                LastUpdated = now.UtcDateTime
            });
            var fingerprintValue = JsonSerializer.Serialize(
                new StoredFingerprint(outboxKey, now + FingerprintRetention),
                StoreJsonOptions);
            if (existingFingerprint is null)
            {
                db.SystemSettings.Add(new SystemSetting
                {
                    Key = fingerprintKey,
                    Value = fingerprintValue,
                    LastUpdated = now.UtcDateTime
                });
            }
            else
            {
                existingFingerprint.Value = fingerprintValue;
                existingFingerprint.LastUpdated = now.UtcDateTime;
            }
            await db.SaveChangesAsync(cancellationToken);

            TagAuditContext(hardwareMatches);
            return Accepted(stored, duplicate: false);
        }
        catch (DbUpdateException)
        {
            // A concurrent identical request may win the unique-key race. Reread the report ID and
            // preserve idempotence; a different binding remains a typed conflict.
            db.ChangeTracker.Clear();
            var existing = await ReadStoredAsync(db, [outboxKey, receiptKey], cancellationToken);
            if (existing is not null && string.Equals(existing.Binding, binding, StringComparison.Ordinal))
                return Accepted(existing, duplicate: true);
            return BugTraceAutoReportEnqueueResult.Reject("report_id_conflict");
        }
        finally
        {
            _enqueueGate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<int> ProcessPendingAsync(CancellationToken cancellationToken = default)
    {
        if (!await _processGate.WaitAsync(0, cancellationToken))
            return 0;

        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var now = _timeProvider.GetUtcNow();
            await CleanupStaleStateAsync(db, now, cancellationToken);
            var candidates = await db.SystemSettings
                .Where(item => item.Key.StartsWith(OutboxPrefix))
                .OrderBy(item => item.LastUpdated)
                .Take(MaximumBatchSize)
                .ToListAsync(cancellationToken);
            var examined = 0;

            foreach (var setting in candidates)
            {
                var stored = TryReadStored(setting.Value);
                if (stored is null
                    || !string.Equals(stored.Status, "pending", StringComparison.Ordinal)
                    || stored.NextAttemptUtc > now)
                {
                    continue;
                }

                examined++;
                try
                {
                    // The durable report ID is the cross-repository operation identity. Reusing it unchanged
                    // lets BugTrace replay its receipt after either an ambiguous response or a local save failure.
                    var upstream = await _bugTrace.SubmitTicketAsync(
                        stored.Ticket,
                        stored.ReportId,
                        cancellationToken);
                    var ticketNumber = upstream.TryGetProperty("ticketNumber", out var ticketProperty)
                        ? ticketProperty.GetString()
                        : null;
                    stored = stored with { Status = "delivered", TicketNumber = ticketNumber };
                    _logger.LogInformation("Delivered identified BugTrace auto-report to provider");
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    var attempts = stored.Attempts + 1;
                    stored = stored with
                    {
                        Status = attempts >= MaximumAttempts ? "failed" : "pending",
                        Attempts = attempts,
                        NextAttemptUtc = now + RetryDelay(attempts)
                    };
                    // Do not attach the exception: provider or transport messages are not an authority for
                    // safe log content and could echo the idempotency header or diagnostic payload.
                    _logger.LogWarning(
                        "BugTrace auto-report relay failed; attempt={Attempt} terminal={Terminal} failureType={FailureType}",
                        attempts,
                        attempts >= MaximumAttempts,
                        exception.GetType().Name);
                }

                if (string.Equals(stored.Status, "pending", StringComparison.Ordinal))
                {
                    setting.Value = JsonSerializer.Serialize(stored, StoreJsonOptions);
                    setting.LastUpdated = now.UtcDateTime;
                }
                else
                {
                    // Terminal records leave the outbox prefix so old receipts cannot starve pending work.
                    var receiptKey = ReportKey(ReceiptPrefix, stored.LicenseId, stored.ReportId);
                    db.SystemSettings.Remove(setting);
                    db.SystemSettings.Add(new SystemSetting
                    {
                        Key = receiptKey,
                        Value = JsonSerializer.Serialize(stored, StoreJsonOptions),
                        LastUpdated = now.UtcDateTime
                    });
                    var fingerprintKey = FingerprintKey(stored.LicenseId, stored.Fingerprint);
                    var fingerprint = await db.SystemSettings
                        .SingleOrDefaultAsync(item => item.Key == fingerprintKey, cancellationToken);
                    if (fingerprint is not null)
                    {
                        fingerprint.Value = JsonSerializer.Serialize(
                            new StoredFingerprint(receiptKey, now + FingerprintRetention),
                            StoreJsonOptions);
                        fingerprint.LastUpdated = now.UtcDateTime;
                    }
                }
                await db.SaveChangesAsync(cancellationToken);
            }

            return examined;
        }
        finally
        {
            _processGate.Release();
        }
    }

    /// <summary>Bounds durable state growth without removing pending reports.</summary>
    private static async Task CleanupStaleStateAsync(
        LicenseDbContext db,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var receiptCutoff = (now - ReceiptRetention).UtcDateTime;
        var fingerprintCutoff = (now - FingerprintRetention).UtcDateTime;
        var stale = await db.SystemSettings
            .Where(item =>
                item.Key.StartsWith(ReceiptPrefix) && item.LastUpdated < receiptCutoff
                || item.Key.StartsWith(FingerprintPrefix) && item.LastUpdated < fingerprintCutoff)
            .OrderBy(item => item.LastUpdated)
            .Take(MaximumBatchSize)
            .ToListAsync(cancellationToken);
        if (stale.Count == 0)
            return;
        db.SystemSettings.RemoveRange(stale);
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>Validates all client-controlled strings before they cross the durable boundary.</summary>
    private static string? ValidateEnvelope(BugTraceAutoReportRequest? request, out string reportId)
    {
        reportId = string.Empty;
        if (request is null)
            return "request_required";
        if (!string.Equals(request.Schema, Schema, StringComparison.Ordinal))
            return "schema_invalid";
        if (request.ExtensionData is { Count: > 0 } || request.Report?.ExtensionData is { Count: > 0 })
            return "unexpected_field";
        if (!Guid.TryParseExact(request.ReportId, "D", out var parsedReportId))
            return "report_id_invalid";
        reportId = parsedReportId.ToString("D", CultureInfo.InvariantCulture);
        if (!string.Equals(reportId, request.ReportId, StringComparison.Ordinal))
            return "report_id_invalid";
        if (string.IsNullOrWhiteSpace(request.LicenseKey) || request.LicenseKey.Length > MaximumLicenseKeyLength)
            return "license_required";
        if (!IsBoundedAscii(request.HardwareId, 1, MaximumHardwareIdLength)
            || string.Equals(request.HardwareId, "unknown", StringComparison.OrdinalIgnoreCase))
            return "hardware_id_invalid";
        if (string.IsNullOrWhiteSpace(request.ProjectId) || request.ProjectId.Length > 64)
            return "project_invalid";
        if (request.Report is null)
            return "report_required";
        if (!string.Equals(request.Report.Kind, "crash", StringComparison.Ordinal)
            && !string.Equals(request.Report.Kind, "error", StringComparison.Ordinal))
            return "report_kind_invalid";
        if (!IsBoundedAscii(request.Report.AppVersion, 1, MaximumAppVersionLength))
            return "app_version_invalid";
        if (!IsBoundedText(request.Report.ErrorType, 1, MaximumErrorTypeLength, allowLineBreaks: false))
            return "error_type_invalid";
        if (!IsBoundedText(request.Report.ErrorSource, 1, MaximumErrorSourceLength, allowLineBreaks: false))
            return "error_source_invalid";
        if (!IsBoundedText(request.Report.Message, 0, MaximumMessageLength, allowLineBreaks: true))
            return "message_invalid";
        if (request.Report.StackTrace is not null
            && !IsBoundedText(request.Report.StackTrace, 0, MaximumStackTraceLength, allowLineBreaks: true))
            return "stack_trace_invalid";
        if (!LowercaseSha256Regex().IsMatch(request.Report.Fingerprint))
            return "fingerprint_invalid";
        return null;
    }

    /// <summary>Builds the only BugTrace ticket shape allowed for the report-only capability.</summary>
    private static BugTraceTicketBody BuildServerOwnedTicket(
        BugTraceAutoReportRequest request,
        License license,
        bool hardwareMatches)
    {
        var kindLabel = string.Equals(request.Report.Kind, "crash", StringComparison.Ordinal) ? "Crash" : "Error";
        var title = $"[Auto][{kindLabel}] {request.Report.ErrorType} in {request.Report.ErrorSource}";
        if (title.Length > 200)
            title = title[..200];

        var description = new StringBuilder()
            .AppendLine($"**Error source:** {request.Report.ErrorSource}")
            .AppendLine($"**Exception:** {request.Report.ErrorType}")
            .AppendLine($"**Message:** {request.Report.Message}")
            .AppendLine()
            .AppendLine("### Server-associated context")
            .AppendLine($"- License ID: `{license.Id:D}`")
            .AppendLine($"- Product ID: `{license.ProductId:D}`")
            .AppendLine($"- Product: {license.Product?.Name ?? "unknown"}")
            .AppendLine($"- Hardware binding: {(hardwareMatches ? "match" : "mismatch-tolerated-for-report-only")}")
            .AppendLine($"- Report ID: `{request.ReportId}`")
            .AppendLine($"- Fingerprint: `{request.Report.Fingerprint}`");
        if (!string.IsNullOrEmpty(request.Report.StackTrace))
            description.AppendLine().AppendLine("### Stack trace").AppendLine("```").AppendLine(request.Report.StackTrace).AppendLine("```");

        return new BugTraceTicketBody
        {
            Title = title,
            Description = description.ToString(),
            Version = request.Report.AppVersion,
            Type = "BUG",
            Priority = string.Equals(request.Report.Kind, "crash", StringComparison.Ordinal) ? "CRITICAL" : "HIGH",
            ReporterEmail = license.CustomerEmail,
            Tags =
            [
                "t-ia-connect",
                "auto-report",
                string.Equals(request.Report.Kind, "crash", StringComparison.Ordinal) ? "crash" : "error-500",
                "source:softlicence-report-only",
                hardwareMatches ? "hardware:match" : "hardware:mismatch-tolerated"
            ]
        };
    }

    /// <summary>Computes an exact binding for report-ID replay protection.</summary>
    private static string ComputeBinding(BugTraceAutoReportRequest request, Guid licenseId)
    {
        var canonical = string.Join('\n',
            Schema,
            licenseId.ToString("D", CultureInfo.InvariantCulture),
            request.ReportId,
            request.HardwareId,
            request.Report.Kind,
            request.Report.AppVersion,
            request.Report.ErrorType,
            request.Report.ErrorSource,
            request.Report.Message,
            request.Report.StackTrace ?? string.Empty,
            request.Report.Fingerprint);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    /// <summary>Derives the authoritative deduplication fingerprint from the exact bounded report fields.</summary>
    private static string ComputeDiagnosticFingerprint(string errorType, string message)
    {
        var canonical = errorType + "|" + message;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    /// <summary>Applies an additional per-license burst limit after authoritative license resolution.</summary>
    private bool IsRateLimited(string key)
    {
        if (!_cache.TryGetValue<int>(key, out var count))
        {
            _cache.Set(key, 1, TimeSpan.FromMinutes(10));
            return false;
        }
        if (count >= 3)
            return true;
        _cache.Set(key, count + 1, TimeSpan.FromMinutes(10));
        return false;
    }

    /// <summary>Records acceptance policy outcome without any report, licence, or hardware identity.</summary>
    private void TagAuditContext(bool hardwareMatches)
    {
        // The report-only path never stores the raw key or submitted HWID in request audit context.
        _logger.LogInformation(
            "Accepted identified BugTrace auto-report; hardwareMatch={HardwareMatch}",
            hardwareMatches);
    }

    /// <summary>Reads one durable outbox record and fails closed on malformed state.</summary>
    private static async Task<StoredAutoReport?> ReadStoredAsync(
        LicenseDbContext db,
        IReadOnlyCollection<string> keys,
        CancellationToken cancellationToken)
    {
        var value = await db.SystemSettings.AsNoTracking()
            .Where(item => keys.Contains(item.Key))
            .Select(item => item.Value)
            .FirstOrDefaultAsync(cancellationToken);
        return value is null ? null : TryReadStored(value);
    }

    /// <summary>Reads one durable record referenced by a server-owned fingerprint pointer.</summary>
    private static Task<StoredAutoReport?> ReadStoredAsync(
        LicenseDbContext db,
        string key,
        CancellationToken cancellationToken) => ReadStoredAsync(db, [key], cancellationToken);

    /// <summary>Deserializes internal state without accepting a null or incomplete payload.</summary>
    private static StoredAutoReport? TryReadStored(string value)
    {
        try
        {
            var stored = JsonSerializer.Deserialize<StoredAutoReport>(value, StoreJsonOptions);
            return stored?.Ticket is null ? null : stored;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Deserializes the bounded fingerprint pointer used for 24-hour server deduplication.</summary>
    private static bool TryReadFingerprint(string value, out StoredFingerprint fingerprint)
    {
        try
        {
            fingerprint = JsonSerializer.Deserialize<StoredFingerprint>(value, StoreJsonOptions)!;
            return fingerprint is not null && !string.IsNullOrWhiteSpace(fingerprint.OutboxKey);
        }
        catch (JsonException)
        {
            fingerprint = null!;
            return false;
        }
    }

    /// <summary>Creates the stable response returned for new and idempotent acceptance.</summary>
    private static BugTraceAutoReportEnqueueResult Accepted(StoredAutoReport stored, bool duplicate) =>
        new(true, duplicate, stored.ReportId, stored.TicketNumber, null);

    /// <summary>Returns the bounded retry delay for the durable relay worker.</summary>
    private static TimeSpan RetryDelay(int attempt) => TimeSpan.FromSeconds(Math.Min(300, 5 * (1 << Math.Min(attempt, 5))));

    /// <summary>Builds a canonical outbox primary key from server-owned license identity and report UUID.</summary>
    private static string ReportKey(string prefix, Guid licenseId, string reportId) =>
        prefix + licenseId.ToString("N", CultureInfo.InvariantCulture) + "_" + reportId.Replace("-", string.Empty);

    /// <summary>Builds a canonical fingerprint key from server-owned license identity and lowercase SHA-256.</summary>
    private static string FingerprintKey(Guid licenseId, string fingerprint) =>
        FingerprintPrefix + licenseId.ToString("N", CultureInfo.InvariantCulture) + "_" + fingerprint;

    /// <summary>Validates bounded printable ASCII machine identifiers without normalization.</summary>
    private static bool IsBoundedAscii(string? value, int minimum, int maximum) =>
        value is not null
        && value.Length >= minimum
        && value.Length <= maximum
        && value.All(character => character is >= (char)0x20 and <= (char)0x7e);

    /// <summary>Validates bounded diagnostic text and rejects control characters other than line breaks.</summary>
    private static bool IsBoundedText(string? value, int minimum, int maximum, bool allowLineBreaks)
    {
        if (value is null || value.Length < minimum || value.Length > maximum)
            return false;
        return value.All(character =>
            character >= 0x20 || (allowLineBreaks && (character == '\r' || character == '\n' || character == '\t')));
    }

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex LowercaseSha256Regex();

    private sealed record StoredFingerprint(string OutboxKey, DateTimeOffset ExpiresAtUtc);

    private sealed record StoredAutoReport(
        string Binding,
        Guid LicenseId,
        string ReportId,
        string Fingerprint,
        string Status,
        int Attempts,
        string? TicketNumber,
        DateTimeOffset NextAttemptUtc,
        BugTraceTicketBody Ticket);
}

/// <summary>
/// Periodically drains the durable report-only outbox without extending Desktop request latency.
/// </summary>
public sealed class BugTraceAutoReportOutboxWorker(
    IBugTraceAutoReportService autoReports,
    ILogger<BugTraceAutoReportOutboxWorker> logger) : BackgroundService
{
    /// <summary>
    /// Processes bounded batches until shutdown; transient failures retain type-only diagnostics without terminating the host.
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await autoReports.ProcessPendingAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // Persistence exceptions can contain durable keys or provider receipts; retain only the
                // failure class so the hosted loop remains observable without exporting stored identity.
                logger.LogError(
                    "BugTrace auto-report outbox processing failed; failureType={FailureType}",
                    exception.GetType().Name);
            }

            if (!await timer.WaitForNextTickAsync(stoppingToken))
                break;
        }
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SoftLicence.Server.Services;

public sealed class TelemetryRawSampleAnalyticsService
{
    private const int DefaultTake = 25;
    private const int MaxTake = 50;
    private const int MaxDiagnosticItems = 20;
    private const int MaxDiagnosticMessageLength = 256;
    private const int MaxDiagnosticLabelLength = 80;
    private const int MaxDiagnosticSanitizationInputLength = 4096;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private static readonly Regex SecretAssignmentRegex = new(
        """\b(password|passwd|token|secret|api[-_ ]?key|license[-_ ]?key|authorization|cookie)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|\S+)""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex EmailRegex = new(
        @"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex UrlRegex = new(
        """\bhttps?://[^\s"']+""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex WindowsPathRegex = new(
        """(?:\b[A-Z]:\\|\\\\)[^\s"']+""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Ipv4Regex = new(
        @"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Ipv6CandidateRegex = new(
        @"(?<![A-F0-9:])\[?(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}\]?(?![A-F0-9:])",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    public TelemetryRawSampleAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    public async Task<TelemetryRawSampleResponse> GetRawSampleForProductIdAsync(
        Guid productId,
        TelemetryAnalyticsPeriod period,
        string? hardwareId,
        string? eventName,
        string? eventFamily,
        string? version,
        string? type,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);

        hardwareId = Normalize(hardwareId);
        eventName = Normalize(eventName);
        eventFamily = Normalize(eventFamily);
        version = Normalize(version);
        type = Normalize(type);

        var cacheKey = string.Join(':',
            "telemetry-raw-sample",
            productId.ToString("N"),
            period.CacheKey,
            hardwareId?.ToLowerInvariant() ?? "",
            eventName?.ToLowerInvariant() ?? "",
            eventFamily?.ToLowerInvariant() ?? "",
            version?.ToLowerInvariant() ?? "",
            type?.ToLowerInvariant() ?? "",
            take);

        if (_cache.TryGetValue(cacheKey, out TelemetryRawSampleResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var query = db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.Timestamp >= period.FromUtc && r.Timestamp < period.ToUtc);

        query = ApplyHardwareIdFilter(query, hardwareId);

        if (eventName != null)
            query = query.Where(r => r.EventName == eventName);

        if (version != null)
            query = query.Where(r => r.Version == version);

        if (type != null && Enum.TryParse<TelemetryType>(type, ignoreCase: true, out var parsedType))
            query = query.Where(r => r.Type == parsedType);

        var rows = await query
            .OrderByDescending(r => r.Timestamp)
            .Select(r => new RawTelemetryRow(
                r.Timestamp,
                r.HardwareId,
                r.ClientIp,
                r.AppName,
                r.Version,
                r.EventName,
                r.Type,
                r.EventData != null ? r.EventData.PropertiesJson : null,
                r.ErrorData != null ? r.ErrorData.ErrorType : null,
                r.DiagnosticData != null ? r.DiagnosticData.Id : null,
                r.DiagnosticData != null ? r.DiagnosticData.Score : null))
            .Take(500)
            .ToListAsync(cancellationToken);

        if (eventFamily != null)
        {
            rows = rows
                .Where(r => string.Equals(TelemetrySchemaRegistry.ClassifyFamily(r.EventName), eventFamily, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        var selectedRows = rows.Take(take).ToList();
        var diagnosticIds = selectedRows
            .Where(r => r.DiagnosticId.HasValue)
            .Select(r => r.DiagnosticId!.Value)
            .Distinct()
            .ToList();
        var diagnosticRows = diagnosticIds.Count == 0
            ? new List<RawDiagnosticRow>()
            : await db.TelemetryDiagnostics
                .AsNoTracking()
                .AsSplitQuery()
                .Where(d => diagnosticIds.Contains(d.Id))
                .Select(d => new RawDiagnosticRow
                {
                    Id = d.Id,
                    Score = d.Score,
                    ResultsTotal = d.Results.Count,
                    PortsTotal = d.Ports.Count,
                    Results = d.Results
                        .OrderBy(r => r.Id)
                        .Take(MaxDiagnosticItems)
                        .Select(r => new RawDiagnosticResultRow
                        {
                            ModuleName = r.ModuleName,
                            Success = r.Success,
                            Severity = r.Severity,
                            Message = r.Message
                        })
                        .ToList(),
                    Ports = d.Ports
                        .OrderBy(p => p.Id)
                        .Take(MaxDiagnosticItems)
                        .Select(p => new RawDiagnosticPortRow
                        {
                            Name = p.Name,
                            ExternalPort = p.ExternalPort,
                            Protocol = p.Protocol
                        })
                        .ToList()
                })
                .ToListAsync(cancellationToken);
        var diagnosticsById = diagnosticRows.ToDictionary(d => d.Id);

        var records = selectedRows
            .Select(r => new TelemetryRawSampleRecord
            {
                TimestampUtc = r.Timestamp,
                HardwareId = r.HardwareId,
                ClientIp = r.ClientIp,
                AppName = r.AppName,
                Version = r.Version,
                EventName = r.EventName,
                Type = r.Type.ToString(),
                Family = TelemetrySchemaRegistry.ClassifyFamily(r.EventName),
                PropertyKeys = TelemetrySchemaRegistry.ParseKeys(r.PropertiesJson),
                Properties = TelemetrySchemaRegistry.ParseProperties(r.PropertiesJson),
                ErrorType = r.ErrorType,
                DiagnosticScore = r.DiagnosticScore,
                Diagnostic = BuildDiagnostic(r.DiagnosticId, diagnosticsById)
            })
            .ToList();

        var now = DateTime.UtcNow;
        var response = new TelemetryRawSampleResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Days = period.Days,
            FromUtc = period.FromUtc,
            ToUtc = period.ToUtc,
            PeriodMode = period.Mode,
            RecordsMatched = rows.Count,
            RecordsReturned = records.Count,
            Records = records
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    private static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static IQueryable<TelemetryRecord> ApplyHardwareIdFilter(IQueryable<TelemetryRecord> query, string? hardwareId)
    {
        if (hardwareId == null)
            return query;

        var normalized = hardwareId.ToUpperInvariant();
        if (normalized.Length < 6)
            return query.Where(r => r.HardwareId.ToUpper() == normalized);

        var prefix = normalized[..Math.Min(8, normalized.Length)];
        return query.Where(r =>
            r.HardwareId.ToUpper() == normalized
            || r.HardwareId.ToUpper().Contains(normalized)
            || r.HardwareId.ToUpper().StartsWith(prefix));
    }

    private static TelemetryRawSampleDiagnostic BuildDiagnostic(
        Guid? diagnosticId,
        IReadOnlyDictionary<Guid, RawDiagnosticRow> diagnosticsById)
    {
        if (!diagnosticId.HasValue || !diagnosticsById.TryGetValue(diagnosticId.Value, out var row))
            return new TelemetryRawSampleDiagnostic { State = "absent" };

        var hasItems = row.ResultsTotal > 0 || row.PortsTotal > 0;
        var isTruncated = row.ResultsTotal > MaxDiagnosticItems || row.PortsTotal > MaxDiagnosticItems;
        return new TelemetryRawSampleDiagnostic
        {
            State = isTruncated ? "truncated" : hasItems ? "available" : "legacy-empty",
            Score = row.Score,
            ResultsTotal = row.ResultsTotal,
            ResultsReturned = row.Results.Count,
            PortsTotal = row.PortsTotal,
            PortsReturned = row.Ports.Count,
            Results = row.Results.Select(result =>
            {
                var message = SanitizeDiagnosticText(result.Message, MaxDiagnosticMessageLength);
                return new TelemetryRawSampleDiagnosticResult
                {
                    ModuleName = SanitizeDiagnosticText(result.ModuleName, MaxDiagnosticLabelLength).Value,
                    Success = result.Success,
                    Severity = SanitizeDiagnosticText(result.Severity, MaxDiagnosticLabelLength).Value,
                    Message = message.Value,
                    MessageTruncated = message.Truncated
                };
            }).ToList(),
            Ports = row.Ports.Select(port => new TelemetryRawSampleDiagnosticPort
            {
                Name = SanitizeDiagnosticText(port.Name, MaxDiagnosticLabelLength).Value,
                ExternalPort = port.ExternalPort,
                Protocol = SanitizeDiagnosticText(port.Protocol, MaxDiagnosticLabelLength).Value
            }).ToList()
        };
    }

    private static SanitizedText SanitizeDiagnosticText(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return new SanitizedText(null, false);

        var inputWasTruncated = value.Length > maxLength;
        var boundedInput = value.Length > MaxDiagnosticSanitizationInputLength
            ? value[..MaxDiagnosticSanitizationInputLength]
            : value;
        var normalized = new string(boundedInput
            .Select(character => char.IsControl(character) ? ' ' : character)
            .ToArray())
            .Trim();
        normalized = SecretAssignmentRegex.Replace(normalized, "$1=[REDACTED]");
        normalized = EmailRegex.Replace(normalized, "[REDACTED_EMAIL]");
        normalized = UrlRegex.Replace(normalized, "[REDACTED_URL]");
        normalized = WindowsPathRegex.Replace(normalized, "[REDACTED_PATH]");
        normalized = Ipv4Regex.Replace(normalized, "[REDACTED_IP]");
        normalized = Ipv6CandidateRegex.Replace(normalized, match =>
        {
            var candidate = match.Value.Trim('[', ']');
            return IPAddress.TryParse(candidate, out var address)
                && address.AddressFamily == AddressFamily.InterNetworkV6
                    ? "[REDACTED_IP]"
                    : match.Value;
        });

        if (normalized.Length <= maxLength)
            return new SanitizedText(normalized, inputWasTruncated);

        return new SanitizedText(normalized[..maxLength], true);
    }

    private sealed record RawTelemetryRow(
        DateTime Timestamp,
        string HardwareId,
        string? ClientIp,
        string AppName,
        string? Version,
        string EventName,
        TelemetryType Type,
        string? PropertiesJson,
        string? ErrorType,
        Guid? DiagnosticId,
        int? DiagnosticScore);

    private sealed class RawDiagnosticRow
    {
        public Guid Id { get; set; }
        public int Score { get; set; }
        public int ResultsTotal { get; set; }
        public int PortsTotal { get; set; }
        public List<RawDiagnosticResultRow> Results { get; set; } = new();
        public List<RawDiagnosticPortRow> Ports { get; set; } = new();
    }

    private sealed class RawDiagnosticResultRow
    {
        public string? ModuleName { get; set; }
        public bool Success { get; set; }
        public string? Severity { get; set; }
        public string? Message { get; set; }
    }

    private sealed class RawDiagnosticPortRow
    {
        public string? Name { get; set; }
        public int ExternalPort { get; set; }
        public string? Protocol { get; set; }
    }

    private sealed record SanitizedText(string? Value, bool Truncated);
}

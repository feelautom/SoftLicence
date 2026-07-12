namespace SoftLicence.Server.Models;

public sealed class TelemetrySchemaSummaryResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public int RecordsAnalyzed { get; set; }
    public int EventsWithProperties { get; set; }
    public List<TelemetryPropertyKeySummary> CommonKeys { get; set; } = new();
    public List<TelemetryEventSchemaSummary> Events { get; set; } = new();
}

public sealed class TelemetryOverviewResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public int RecordsAnalyzed { get; set; }
    public int UniqueDevices { get; set; }
    public int UniqueClientIps { get; set; }
    public DateTime? FirstActivityUtc { get; set; }
    public DateTime? LastActivityUtc { get; set; }
    public List<TelemetryToolCount> TypeCounts { get; set; } = new();
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> EventFamilies { get; set; } = new();
    public List<TelemetryToolCount> TopVersions { get; set; } = new();
    public List<TelemetryToolCount> TopApps { get; set; } = new();
    public List<TelemetryDailyCount> DailyActivity { get; set; } = new();
}

public sealed class TelemetryDevicesResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public int RecordsAnalyzed { get; set; }
    public int TotalDevices { get; set; }
    public int DevicesReturned { get; set; }
    public List<TelemetryDeviceSummary> Devices { get; set; } = new();
}

public sealed class TelemetryDeviceSummary
{
    public string HardwareId { get; set; } = "";
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int EventCount { get; set; }
    public string? LastVersion { get; set; }
    public string? LastClientIp { get; set; }
    public string? AppName { get; set; }
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> EventFamilies { get; set; } = new();
}

public sealed class TelemetryDailyCount
{
    public DateTime DateUtc { get; set; }
    public int Count { get; set; }
}

public sealed class TelemetryPropertyKeySummary
{
    public string Key { get; set; } = "";
    public int Count { get; set; }
    public double Percentage { get; set; }
}

public sealed class TelemetryEventSchemaSummary
{
    public string EventName { get; set; } = "";
    public string Family { get; set; } = "";
    public int Count { get; set; }
    public int EventsWithProperties { get; set; }
    public int SchemaVariants { get; set; }
    public double TopSchemaPercentage { get; set; }
    public int KeyCount { get; set; }
    public List<string> CommonKeys { get; set; } = new();
    public List<string> SpecificKeys { get; set; } = new();
    public List<TelemetrySchemaVariantSummary> TopSchemas { get; set; } = new();
}

public sealed class TelemetrySchemaVariantSummary
{
    public int Count { get; set; }
    public double Percentage { get; set; }
    public List<string> Keys { get; set; } = new();
}

public sealed class TelemetryToolUsageSummaryResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public int RecordsAnalyzed { get; set; }
    public int ToolCallEvents { get; set; }
    public List<TelemetryToolChannelSummary> Channels { get; set; } = new();
    public List<TelemetryToolCount> TopTools { get; set; } = new();
    public List<TelemetryToolCount> TopProviders { get; set; } = new();
    public List<TelemetryToolCount> TopModels { get; set; } = new();
    public List<TelemetryToolCount> RequestSources { get; set; } = new();
    public List<TelemetryQuotaPeak> QuotaPeaks { get; set; } = new();
}

public sealed class TelemetryToolChannelSummary
{
    public string Channel { get; set; } = "";
    public int Count { get; set; }
    public double Percentage { get; set; }
}

public sealed class TelemetryToolCount
{
    public string Name { get; set; } = "";
    public int Count { get; set; }
}

public sealed class TelemetryQuotaPeak
{
    public string QuotaKey { get; set; } = "";
    public int PeakUsed { get; set; }
    public int? Limit { get; set; }
    public double? PeakPercentage { get; set; }
}

public sealed class TelemetryQuotaSummaryResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public int RecordsAnalyzed { get; set; }
    public int RecordsWithQuota { get; set; }
    public List<TelemetryQuotaMetric> Quotas { get; set; } = new();
    public List<TelemetryToolChannelSummary> Channels { get; set; } = new();
    public List<TelemetryToolCount> RequestSources { get; set; } = new();
}

public sealed class TelemetryQuotaMetric
{
    public string QuotaKey { get; set; } = "";
    public int Samples { get; set; }
    public int PeakUsed { get; set; }
    public int? Limit { get; set; }
    public double? PeakPercentage { get; set; }
    public double AverageUsed { get; set; }
}

public sealed class TelemetryCertPinningSummaryResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public int RecordsAnalyzed { get; set; }
    public int Incidents { get; set; }
    public int Failures { get; set; }
    public int Recoveries { get; set; }
    public int SuppressedFailures { get; set; }
    public int UniqueDevices { get; set; }
    public List<TelemetryToolCount> EventNames { get; set; } = new();
    public List<TelemetryToolCount> Hosts { get; set; } = new();
    public List<TelemetryToolCount> FailureReasons { get; set; } = new();
    public List<TelemetryToolCount> Versions { get; set; } = new();
}

public sealed class TelemetryActivationFunnelResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public int LicensesCreated { get; set; }
    public int LicensesActivated { get; set; }
    public int LicensesCreatedAndNeverActivated { get; set; }
    public int ActivationAttempts { get; set; }
    public int ActivationSuccesses { get; set; }
    public int ActivationFailures { get; set; }
    public double ActivationSuccessRate { get; set; }
    public int TrialRequests { get; set; }
    public int TrialSuccesses { get; set; }
    public int TrialFailures { get; set; }
    public int CheckRequests { get; set; }
    public int UniqueActivationDevices { get; set; }
    public int UniqueActivationIps { get; set; }
    public List<TelemetryToolCount> FailureStatuses { get; set; } = new();
    public List<TelemetryActivationFunnelDay> DailyFunnel { get; set; } = new();
}

public sealed class TelemetryActivationFunnelDay
{
    public DateTime DateUtc { get; set; }
    public int LicensesCreated { get; set; }
    public int LicensesActivated { get; set; }
    public int ActivationAttempts { get; set; }
    public int ActivationSuccesses { get; set; }
    public int ActivationFailures { get; set; }
    public int TrialRequests { get; set; }
}

public sealed class TelemetryActivationFailuresResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime FromUtc { get; set; }
    public DateTime ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public string? HardwareId { get; set; }
    public string? Status { get; set; }
    public int RecordsMatched { get; set; }
    public int RecordsReturned { get; set; }
    public List<TelemetryToolCount> FailureStatuses { get; set; } = new();
    public List<TelemetryToolCount> HardwareIds { get; set; } = new();
    public List<TelemetryToolCount> ClientVersions { get; set; } = new();
    public List<TelemetryActivationFailureRecord> Failures { get; set; } = new();
}

public sealed class TelemetryActivationFailureRecord
{
    public DateTime TimestampUtc { get; set; }
    public string HardwareId { get; set; } = "";
    public string? CustomerEmail { get; set; }
    public string? ClientIp { get; set; }
    public int StatusCode { get; set; }
    public string Status { get; set; } = "";
    public string? FailureReason { get; set; }
    public string? ClientVersion { get; set; }
}

public sealed class TelemetryMachineProfileResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public string HardwareId { get; set; } = "";
    public int RecordsAnalyzed { get; set; }
    public int RealActivityEvents { get; set; }
    public int SystemNoiseEvents { get; set; }
    public DateTime? FirstActivityUtc { get; set; }
    public DateTime? LastActivityUtc { get; set; }
    public List<TelemetryToolCount> TypeCounts { get; set; } = new();
    public List<TelemetryToolCount> EventFamilies { get; set; } = new();
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> Versions { get; set; } = new();
    public List<TelemetryToolCount> Apps { get; set; } = new();
    public List<TelemetryMachineProfileRecord> RecentRecords { get; set; } = new();
}

public sealed class TelemetryMachineProfileRecord
{
    public DateTime TimestampUtc { get; set; }
    public string Type { get; set; } = "";
    public string EventName { get; set; } = "";
    public string Family { get; set; } = "";
    public string AppName { get; set; } = "";
    public string? Version { get; set; }
    public List<string> PropertyKeys { get; set; } = new();
    public string? ErrorType { get; set; }
    public int? DiagnosticScore { get; set; }
}

public sealed class TelemetrySupportProfileResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public TelemetrySupportProfileQuery Query { get; set; } = new();
    public int CandidateCount { get; set; }
    public bool IsAmbiguous { get; set; }
    public TelemetrySupportCandidate? SelectedCandidate { get; set; }
    public List<TelemetrySupportCandidate> Candidates { get; set; } = new();
    public TelemetryMachineProfileResponse? MachineProfile { get; set; }
    public TelemetrySupportQuotaSummary? Quotas { get; set; }
    public List<TelemetryInsightItem> Insights { get; set; } = new();
}

public sealed class TelemetrySupportProfileQuery
{
    public bool HasHardwareId { get; set; }
    public int? HardwareIdLength { get; set; }
    public bool HardwareIdPartialLookupEnabled { get; set; }
    public bool HasEmail { get; set; }
    public bool HasEmailFragment { get; set; }
    public bool HasLicenseFragment { get; set; }
    public bool HasClientIp { get; set; }
    public int? EmailFragmentLength { get; set; }
    public int? LicenseFragmentLength { get; set; }
}

public sealed class TelemetrySupportCandidate
{
    public string MatchType { get; set; } = "";
    public Guid? LicenseId { get; set; }
    public string? ProductName { get; set; }
    public string? CustomerName { get; set; }
    public string? CustomerEmail { get; set; }
    public string? CustomerEmailRedacted { get; set; }
    public string? LicenseKeyRedacted { get; set; }
    public string? LicenseKeyFirstSegment { get; set; }
    public string? LicenseStatus { get; set; }
    public string? LicenseTypeSlug { get; set; }
    public string? LicenseTypeName { get; set; }
    public int? LicenseValidityDays { get; set; }
    public int? LicenseTypeDefaultDurationDays { get; set; }
    public string? LicenseEdition { get; set; }
    public int? MaxSeats { get; set; }
    public DateTime? ActivationDateUtc { get; set; }
    public DateTime? ExpirationDateUtc { get; set; }
    public string? HardwareId { get; set; }
    public DateTime? SeatFirstActivatedAtUtc { get; set; }
    public DateTime? SeatLastCheckInAtUtc { get; set; }
    public int TelemetryRecords { get; set; }
    public DateTime? FirstTelemetryUtc { get; set; }
    public DateTime? LastTelemetryUtc { get; set; }
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> Versions { get; set; } = new();
    public List<TelemetryToolCount> ClientIps { get; set; } = new();
}

public sealed class TelemetrySupportQuotaSummary
{
    public int RecordsAnalyzed { get; set; }
    public int RecordsWithQuota { get; set; }
    public bool HasSaturatedQuota { get; set; }
    public List<TelemetrySupportQuotaMetric> Quotas { get; set; } = new();
    public List<TelemetrySupportUsageMetric> Usage { get; set; } = new();
    public List<TelemetryToolChannelSummary> Channels { get; set; } = new();
    public List<TelemetryToolCount> RequestSources { get; set; } = new();
}

public sealed class CustomerLicenseTimelineResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime FromUtc { get; set; }
    public DateTime ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public CustomerLicenseTimelineQuery Query { get; set; } = new();
    public CustomerLicenseTimelineSummary Summary { get; set; } = new();
    public List<CustomerLicenseTimelineCandidate> Candidates { get; set; } = new();
    public List<CustomerLicenseTimelineLicense> Licenses { get; set; } = new();
    public List<CustomerLicenseTimelineHardwareId> HardwareIds { get; set; } = new();
    public List<CustomerLicenseTimelineItem> Timeline { get; set; } = new();
    public int TimelineTotal { get; set; }
    public int TimelineReturned { get; set; }
    public int OmittedRecords { get; set; }
    public bool HasMore { get; set; }
}

public sealed class CustomerLicenseTimelineQuery
{
    public bool HasEmail { get; set; }
    public bool HasEmailFragment { get; set; }
    public bool HasHardwareId { get; set; }
    public bool HasLicenseId { get; set; }
    public bool HasLicenseFragment { get; set; }
    public bool IncludeAccessLogs { get; set; }
    public bool IncludeNoise { get; set; }
    public bool IncludeProperties { get; set; }
    public bool ImportantOnly { get; set; }
    public string Mode { get; set; } = "timeline";
    public int TakeTimeline { get; set; }
    public int Offset { get; set; }
}

public sealed class CustomerLicenseTimelineSummary
{
    public int CandidateCount { get; set; }
    public bool IsAmbiguous { get; set; }
    public int LicenseCount { get; set; }
    public int HardwareIdCount { get; set; }
    public int ActiveSeatCount { get; set; }
    public int TelemetryRecords { get; set; }
    public int AccessLogRecords { get; set; }
    public int LicenseEvents { get; set; }
    public int SeatEvents { get; set; }
    public int RealActivityEvents { get; set; }
    public int SystemNoiseEvents { get; set; }
    public int DiagnosticEvents { get; set; }
    public int ErrorEvents { get; set; }
    public DateTime? FirstEventUtc { get; set; }
    public DateTime? LastEventUtc { get; set; }
    public bool UpdateRevokeLicenseSeen { get; set; }
    public bool ServerSeatUnlinkTraceSeen { get; set; }
    public bool LicenseDeactivationTraceSeen { get; set; }
    public string ServerDeactivationVerdict { get; set; } = "not_evaluated";
    public List<string> VerdictCodes { get; set; } = new();
    public List<string> Notes { get; set; } = new();
}

public sealed class CustomerLicenseTimelineCandidate
{
    public Guid? LicenseId { get; set; }
    public string MatchType { get; set; } = "";
    public string? ProductName { get; set; }
    public string? CustomerName { get; set; }
    public string? CustomerEmail { get; set; }
    public string? CustomerEmailRedacted { get; set; }
    public string? LicenseKeyRedacted { get; set; }
    public string? LicenseKeyFirstSegment { get; set; }
    public string? LicenseStatus { get; set; }
    public string? HardwareId { get; set; }
}

public sealed class CustomerLicenseTimelineLicense
{
    public Guid LicenseId { get; set; }
    public Guid ProductId { get; set; }
    public string? ProductName { get; set; }
    public string? CustomerName { get; set; }
    public string? CustomerEmail { get; set; }
    public string? CustomerEmailRedacted { get; set; }
    public string? LicenseKeyRedacted { get; set; }
    public string? LicenseKeyFirstSegment { get; set; }
    public string LicenseStatus { get; set; } = "";
    public string? LicenseTypeSlug { get; set; }
    public string? LicenseTypeName { get; set; }
    public string? LicenseEdition { get; set; }
    public DateTime CreationDateUtc { get; set; }
    public DateTime? ActivationDateUtc { get; set; }
    public DateTime? ExpirationDateUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public int MaxSeats { get; set; }
    public int ActiveSeats { get; set; }
    public int TotalSeats { get; set; }
    public List<string> HardwareIds { get; set; } = new();
}

public sealed class CustomerLicenseTimelineHardwareId
{
    public string HardwareId { get; set; } = "";
    public string HardwareIdRedacted { get; set; } = "";
    public int TelemetryRecords { get; set; }
    public int RealActivityEvents { get; set; }
    public int SystemNoiseEvents { get; set; }
    public DateTime? FirstTelemetryUtc { get; set; }
    public DateTime? LastTelemetryUtc { get; set; }
    public bool IsCurrentActiveSeat { get; set; }
    public DateTime? SeatFirstActivatedAtUtc { get; set; }
    public DateTime? SeatLastCheckInAtUtc { get; set; }
    public DateTime? SeatDeactivatedAtUtc { get; set; }
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> Versions { get; set; } = new();
    public List<TelemetryToolCount> ClientIps { get; set; } = new();
    public List<TelemetryToolCount> Environment { get; set; } = new();
    public List<CustomerLicenseTimelineItem> RecentSignificantEvents { get; set; } = new();
}

public sealed class CustomerLicenseTimelineItem
{
    public DateTime TimestampUtc { get; set; }
    public string Source { get; set; } = "";
    public string? HardwareId { get; set; }
    public string? HardwareIdRedacted { get; set; }
    public Guid? LicenseId { get; set; }
    public string? EventName { get; set; }
    public string? Action { get; set; }
    public string Category { get; set; } = "usage";
    public string Severity { get; set; } = "info";
    public string Result { get; set; } = "observed";
    public string? ReasonCode { get; set; }
    public string? ClientIp { get; set; }
    public string? AppVersion { get; set; }
    public Dictionary<string, string> ShortProperties { get; set; } = new();
    public string? CorrelationId { get; set; }
    public string? SessionCorrelationId { get; set; }
}

public sealed class TelemetrySupportQuotaMetric
{
    public string QuotaKey { get; set; } = "";
    public int Samples { get; set; }
    public int LastUsed { get; set; }
    public int? LastLimit { get; set; }
    public double? LastPercentage { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public int PeakUsed { get; set; }
    public int? PeakLimit { get; set; }
    public double? PeakPercentage { get; set; }
    public double AverageUsed { get; set; }
    public bool IsSaturated { get; set; }
}

public sealed class TelemetrySupportUsageMetric
{
    public string UsageKey { get; set; } = "";
    public string Channel { get; set; } = "";
    public int Samples { get; set; }
    public double LastValue { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public double PeakValue { get; set; }
    public double? PercentageOfPeakTotal { get; set; }
}

public sealed class SecurityBanAuditResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public SecurityBanAuditQuery Query { get; set; } = new();
    public int RecordsMatched { get; set; }
    public int RecordsReturned { get; set; }
    public List<SecurityBanAuditItem> Bans { get; set; } = new();
}

public sealed class SecurityBanAuditQuery
{
    public bool HasHardwareId { get; set; }
    public bool HasComponentHash { get; set; }
    public bool HasComponentType { get; set; }
    public bool HasClientIp { get; set; }
    public bool HasEmailFragment { get; set; }
    public bool HasLicenseFragment { get; set; }
    public bool IncludeInactive { get; set; }
    public int Take { get; set; }
}

public sealed class SecurityBanAuditItem
{
    public Guid BanId { get; set; }
    public string TargetType { get; set; } = "";
    public bool IsActive { get; set; }
    public Guid? ProductId { get; set; }
    public string? ProductName { get; set; }
    public DateTime BannedAtUtc { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public string? HardwareId { get; set; }
    public string? ComponentType { get; set; }
    public string? ComponentHash { get; set; }
    public string? ComponentHashRedacted { get; set; }
    public string? ComponentMatchType { get; set; }
    public string ComponentMatchStrength { get; set; } = "unknown";
    public string ComponentMatchSummary { get; set; } = "";
    public bool IsWeakComponentCorrelation { get; set; }
    public string? BanCategory { get; set; }
    public string Reason { get; set; } = "";
    public string MatchType { get; set; } = "";
    public bool SourceEventAvailable { get; set; }
    public string SourceEventStatus { get; set; } = "not_checked";
}

public sealed class SecurityBanDetailsResponse
{
    public SecurityBanAuditItem? Ban { get; set; }
    public SecurityBanSourceEvent? SourceEvent { get; set; }
}

public sealed class SecurityBanSourceEvent
{
    public bool Found { get; set; }
    public string Status { get; set; } = "";
    public string SearchStrategy { get; set; } = "";
    public string CorrelationConfidence { get; set; } = "unavailable";
    public double? TimeDeltaSeconds { get; set; }
    public Guid? TelemetryRecordId { get; set; }
    public DateTime? TimestampUtc { get; set; }
    public string? HardwareId { get; set; }
    public string? EventName { get; set; }
    public string? Type { get; set; }
    public string? Version { get; set; }
    public List<string> PropertyKeys { get; set; } = new();
}

public sealed class LicenseHardwareVerificationResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public string HardwareId { get; set; } = "";
    public string Status { get; set; } = "Unknown";
    public string ReasonCode { get; set; } = "unknown";
    public Guid? ProductId { get; set; }
    public string? ProductName { get; set; }
    public Guid? LicenseId { get; set; }
    public Guid? UserId { get; set; }
    public string? LicenseType { get; set; }
    public string? LicenseTypeName { get; set; }
    public string? LicenseTypeLabel { get; set; }
    public string? CustomerEmail { get; set; }
    public string? CustomerEmailRedacted { get; set; }
    public string? Company { get; set; }
    public DateTime? ActivationDateUtc { get; set; }
    public DateTime? ExpirationDateUtc { get; set; }
    public bool SourceAuthoritative { get; set; } = true;
    public string Source { get; set; } = "SoftLicence.Licenses";
}

public sealed class SecurityCaseContext
{
    public string SecurityCaseId { get; set; } = "";
    public string Trigger { get; set; } = "";
    public Guid? ProductId { get; set; }
    public string? HardwareId { get; set; }
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public int LicenseCount { get; set; }
    public int DistinctEmailCount { get; set; }
    public int ActiveLicenseCount { get; set; }
    public int ExpiredLicenseCount { get; set; }
    public int RevokedLicenseCount { get; set; }
    public int RecentActivationCount { get; set; }
    public int RecentActivationFailureCount { get; set; }
    public List<string> EmailsRedacted { get; set; } = new();
    public List<string> LicenseKeysRedacted { get; set; } = new();
}

public sealed class TelemetryRawSampleResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime FromUtc { get; set; }
    public DateTime ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public int RecordsMatched { get; set; }
    public int RecordsReturned { get; set; }
    public List<TelemetryRawSampleRecord> Records { get; set; } = new();
}

public sealed class TelemetryRawSampleRecord
{
    public DateTime TimestampUtc { get; set; }
    public string HardwareId { get; set; } = "";
    public string? ClientIp { get; set; }
    public string AppName { get; set; } = "";
    public string? Version { get; set; }
    public string EventName { get; set; } = "";
    public string Type { get; set; } = "";
    public string Family { get; set; } = "";
    public List<string> PropertyKeys { get; set; } = new();
    public Dictionary<string, string> Properties { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public string? ErrorType { get; set; }
    public int? DiagnosticScore { get; set; }
}

public sealed class TelemetryInsightsResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime FromUtc { get; set; }
    public DateTime ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public int RecordsAnalyzed { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int OpportunityCount { get; set; }
    public List<TelemetryInsightItem> Insights { get; set; } = new();
}

public sealed class TelemetryInsightItem
{
    public string Severity { get; set; } = "";
    public string Category { get; set; } = "";
    public string Title { get; set; } = "";
    public string Summary { get; set; } = "";
    public int Count { get; set; }
    public double? Score { get; set; }
    public DateTime? FirstSeenUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public List<TelemetryToolCount> Breakdown { get; set; } = new();
}

public sealed class TelemetryVersionHealthResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public int RecordsAnalyzed { get; set; }
    public int ErrorRecords { get; set; }
    public int UniqueDevices { get; set; }
    public List<TelemetryVersionHealthSummary> Versions { get; set; } = new();
    public List<TelemetryToolCount> TopErrorTypes { get; set; } = new();
    public List<TelemetryToolCount> TopErrorEvents { get; set; } = new();
    public List<TelemetryDailyCount> DailyErrors { get; set; } = new();
}

public sealed class TelemetryVersionHealthSummary
{
    public string Version { get; set; } = "";
    public int Records { get; set; }
    public int Events { get; set; }
    public int Diagnostics { get; set; }
    public int Errors { get; set; }
    public int UniqueDevices { get; set; }
    public double ErrorRate { get; set; }
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> ErrorTypes { get; set; } = new();
    public List<TelemetryToolCount> ErrorEvents { get; set; } = new();
}

public sealed class TelemetryStartupHealthResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public int StartupEvents { get; set; }
    public int UniqueDevices { get; set; }
    public List<TelemetryToolCount> OverallStatuses { get; set; } = new();
    public List<TelemetryToolCount> SelectedTiaVersions { get; set; } = new();
    public List<TelemetryToolCount> LicenseEditions { get; set; } = new();
    public TelemetryStartupFlagSummary Flags { get; set; } = new();
    public TelemetryStartupCheckTotals CheckTotals { get; set; } = new();
    public List<TelemetryToolCount> FailedChecks { get; set; } = new();
    public List<TelemetryToolCount> WarningChecks { get; set; } = new();
}

public sealed class TelemetryStartupFlagSummary
{
    public int AdminTrue { get; set; }
    public int AdminFalse { get; set; }
    public int VmTrue { get; set; }
    public int SandboxTrue { get; set; }
    public int FingerprintSamples { get; set; }
}

public sealed class TelemetryStartupCheckTotals
{
    public int PassCount { get; set; }
    public int WarningCount { get; set; }
    public int FailCount { get; set; }
}

public sealed class LicenseDurationMigrationImpactResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public string LicenseType { get; set; } = "";
    public int CurrentDurationDays { get; set; }
    public int TargetDurationDays { get; set; }
    public string CandidateDefinition { get; set; } = "";
    public string ActivationDateSource { get; set; } = "";
    public List<int> ActivityWindowsDays { get; set; } = new();
    public LicenseDurationMigrationImpactSummary Summary { get; set; } = new();
    public List<LicenseDurationMigrationWindowActivity> WindowActivity { get; set; } = new();
    public List<LicenseDurationMigrationDaysRemaining> ByDaysRemaining { get; set; } = new();
    public List<LicenseDurationMigrationTopEvent> TopEvents { get; set; } = new();
    public LicenseDurationMigrationRecommendedSegments RecommendedSegments { get; set; } = new();
    public List<LicenseDurationMigrationSample> Samples { get; set; } = new();
}

public sealed class LicenseDurationMigrationImpactSummary
{
    public int TotalCandidates { get; set; }
    public int DeliveredNotActivated { get; set; }
    public int Active1d { get; set; }
    public int Active3d { get; set; }
    public int Active7d { get; set; }
    public int Inactive7d { get; set; }
    public int ProfessionalActive7d { get; set; }
    public int PersonalActive7d { get; set; }
    public int UnknownSegmentActive7d { get; set; }
}

public sealed class LicenseDurationMigrationWindowActivity
{
    public int WindowDays { get; set; }
    public int ActiveCandidates { get; set; }
    public int InactiveCandidates { get; set; }
}

public sealed class LicenseDurationMigrationDaysRemaining
{
    public int DaysRemaining { get; set; }
    public int Total { get; set; }
    public int Active7d { get; set; }
}

public sealed class LicenseDurationMigrationTopEvent
{
    public string EventName { get; set; } = "";
    public int Count { get; set; }
    public int HardwareIds { get; set; }
}

public sealed class LicenseDurationMigrationRecommendedSegments
{
    public string EmailPriorityHigh { get; set; } = "active1d or active3d";
    public string EmailPriorityMedium { get; set; } = "active7d";
    public string IgnoreImmediate { get; set; } = "Delivered without hardwareId";
}

public sealed class LicenseDurationMigrationSample
{
    public Guid LicenseId { get; set; }
    public string CustomerEmailRedacted { get; set; } = "";
    public string LicenseKeyRedacted { get; set; } = "";
    public string HardwareIdRedacted { get; set; } = "";
    public DateTime? ActivationDateUtc { get; set; }
    public DateTime? ExpirationDateUtc { get; set; }
    public int ActivationAgeDays { get; set; }
    public int DaysRemaining { get; set; }
    public DateTime? LastTelemetryUtc { get; set; }
    public string ActivitySegment { get; set; } = "";
    public string UserSegment { get; set; } = "";
}

public sealed class FreemiumActivityRankingResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public string LicenseType { get; set; } = "";
    public List<string> LicenseTypes { get; set; } = new();
    public string StatusFilter { get; set; } = "active";
    public int TelemetryDays { get; set; }
    public int? ActivationAgeMinDays { get; set; }
    public int? ActivationAgeMaxDays { get; set; }
    public FreemiumActivityRankingSummary Summary { get; set; } = new();
    public List<TelemetryToolCount> TopSegments { get; set; } = new();
    public List<TelemetryToolCount> TopEventFamilies { get; set; } = new();
    public List<FreemiumActivityRankingItem> Rankings { get; set; } = new();
}

public sealed class FreemiumActivityRankingSummary
{
    public int TotalLicensesInFilter { get; set; }
    public int RankedMachines { get; set; }
    public int ActiveTelemetry1d { get; set; }
    public int ActiveTelemetry3d { get; set; }
    public int ActiveTelemetry7d { get; set; }
    public int QuotaLimitedMachines { get; set; }
    public int MachinesWithNegativeSignals { get; set; }
}

public sealed class FreemiumActivityRankingItem
{
    public int Rank { get; set; }
    public Guid LicenseId { get; set; }
    public string LicenseTypeSlug { get; set; } = "";
    public string LicenseTypeName { get; set; } = "";
    public string LicenseStatus { get; set; } = "";
    public string CustomerEmail { get; set; } = "";
    public string CustomerEmailRedacted { get; set; } = "";
    public string LicenseKeyRedacted { get; set; } = "";
    public string HardwareIdRedacted { get; set; } = "";
    public string HardwareIdHash { get; set; } = "";
    public DateTime? ActivationDateUtc { get; set; }
    public int? ActivationAgeDays { get; set; }
    public DateTime? ExpirationDateUtc { get; set; }
    public int? DaysRemaining { get; set; }
    public DateTime? LastTelemetryUtc { get; set; }
    public int TotalEvents { get; set; }
    public int ProductiveEvents { get; set; }
    public int McpCopilotEvents { get; set; }
    public double Score { get; set; }
    public string UserSegment { get; set; } = "unknown";
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> TopEventFamilies { get; set; } = new();
    public List<string> QuotaFlags { get; set; } = new();
    public List<string> NegativeFlags { get; set; } = new();
    public List<FreemiumActivityRecentEvent> RecentEvents { get; set; } = new();
}

public sealed class FreemiumActivityRecentEvent
{
    public DateTime TimestampUtc { get; set; }
    public string EventName { get; set; } = "";
    public string Family { get; set; } = "";
}

public sealed class LicenseTypesAnalyticsResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int TotalTypes { get; set; }
    public int TotalLicenses { get; set; }
    public int ActiveLicenses { get; set; }
    public List<LicenseTypeAnalyticsItem> LicenseTypes { get; set; } = new();
}

public sealed class LicenseTypeAnalyticsItem
{
    public Guid LicenseTypeId { get; set; }
    public string Slug { get; set; } = "";
    public string Name { get; set; } = "";
    public bool IsFree { get; set; }
    public int DefaultDurationDays { get; set; }
    public int TotalLicenses { get; set; }
    public int ActiveLicenses { get; set; }
    public int ExpiredLicenses { get; set; }
    public int RevokedLicenses { get; set; }
}

public sealed class RecentLicenseOnboardingMetricsResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public string LicenseTypeFilter { get; set; } = "paid";
    public string StatusFilter { get; set; } = "active";
    public int? ActivationAgeMaxDays { get; set; }
    public int TotalLicensesMatched { get; set; }
    public int LicensesReturned { get; set; }
    public RecentLicenseOnboardingMetricsSummary Summary { get; set; } = new();
    public List<TelemetryToolCount> OnboardingSegments { get; set; } = new();
    public List<TelemetryToolCount> DetectedPaths { get; set; } = new();
    public List<RecentLicenseOnboardingMetricItem> Licenses { get; set; } = new();
}

public sealed class RecentLicenseOnboardingMetricsSummary
{
    public int WithTelemetry { get; set; }
    public int WithProductiveEvent { get; set; }
    public int WithMcpEvents { get; set; }
    public int WithCopilotEvents { get; set; }
    public double? MedianMinutesToFirstProductiveEvent { get; set; }
}

public sealed class RecentLicenseOnboardingMetricItem
{
    public Guid LicenseId { get; set; }
    public string LicenseTypeSlug { get; set; } = "";
    public string LicenseTypeName { get; set; } = "";
    public string LicenseStatus { get; set; } = "";
    public string CustomerEmailRedacted { get; set; } = "";
    public DateTime? ActivationDateUtc { get; set; }
    public DateTime OnboardingStartUtc { get; set; }
    public string ActivationDateSource { get; set; } = "";
    public DateTime? ExpirationDateUtc { get; set; }
    public string HardwareIdRedacted { get; set; } = "";
    public string HardwareIdHash { get; set; } = "";
    public List<string> HardwareIdsRedacted { get; set; } = new();
    public List<string> HardwareIdHashes { get; set; } = new();
    public DateTime? FirstTelemetryUtc { get; set; }
    public DateTime? FirstWizardOpenedUtc { get; set; }
    public DateTime? FirstWizardCompletedUtc { get; set; }
    public DateTime? FirstWizardMcpToolSelectedUtc { get; set; }
    public DateTime? FirstCopilotChatUtc { get; set; }
    public DateTime? FirstCopilotChatSuccessUtc { get; set; }
    public DateTime? FirstMcpToolCallUtc { get; set; }
    public DateTime? FirstProductiveEventUtc { get; set; }
    public DateTime? FirstBlockExportUtc { get; set; }
    public DateTime? FirstProjectOpenUtc { get; set; }
    public DateTime? LastTelemetryUtc { get; set; }
    public double? MinutesActivationToWizardCompleted { get; set; }
    public double? MinutesActivationToMcpSelected { get; set; }
    public double? MinutesActivationToCopilotChat { get; set; }
    public double? MinutesActivationToCopilotChatSuccess { get; set; }
    public double? MinutesActivationToMcpToolCall { get; set; }
    public double? MinutesActivationToProductiveEvent { get; set; }
    public double? MinutesActivationToLastTelemetry { get; set; }
    public int TotalEvents { get; set; }
    public int ProductiveEvents { get; set; }
    public int McpEvents { get; set; }
    public int CopilotEvents { get; set; }
    public string OnboardingSegment { get; set; } = "stuck";
    public string DetectedPath { get; set; } = "unknown";
    public List<string> NegativeFlags { get; set; } = new();
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
}

public sealed class LicenseUsageScoringResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public string LicenseTypeFilter { get; set; } = "paid";
    public string StatusFilter { get; set; } = "active";
    public int ActivityWindowDays { get; set; }
    public int? ActivationAgeMaxDays { get; set; }
    public bool IncludeInactive { get; set; }
    public string SortBy { get; set; } = "score";
    public double? MinScore { get; set; }
    public int TotalLicensesMatched { get; set; }
    public int LicensesReturned { get; set; }
    public LicenseUsageScoringSummary Summary { get; set; } = new();
    public List<TelemetryToolCount> Classifications { get; set; } = new();
    public List<TelemetryToolCount> DetectedPaths { get; set; } = new();
    public List<LicenseUsageScoreItem> Licenses { get; set; } = new();
}

public sealed class LicenseUsageScoringSummary
{
    public int WithRecentTelemetry { get; set; }
    public int WithProductiveEvents { get; set; }
    public int WithMcpOrCopilot { get; set; }
    public int AtRiskOrDormant { get; set; }
    public int HighConversionPotential { get; set; }
    public int EngagedSubscribers { get; set; }
}

public sealed class LicenseUsageScoreItem
{
    public Guid LicenseId { get; set; }
    public string LicenseKind { get; set; } = "unknown";
    public string LicenseTypeSlug { get; set; } = "";
    public string LicenseTypeName { get; set; } = "";
    public string LicenseStatus { get; set; } = "";
    public string CustomerEmailRedacted { get; set; } = "";
    public DateTime CreationDateUtc { get; set; }
    public DateTime? ActivationDateUtc { get; set; }
    public DateTime OnboardingStartUtc { get; set; }
    public string ActivationDateSource { get; set; } = "";
    public DateTime? ExpirationDateUtc { get; set; }
    public string HardwareIdRedacted { get; set; } = "";
    public string HardwareIdHash { get; set; } = "";
    public DateTime? FirstTelemetryUtc { get; set; }
    public DateTime? LastSeenAtUtc { get; set; }
    public int? DaysSinceLastSeen { get; set; }
    public int DaysActive { get; set; }
    public int ActiveDaysInWindow { get; set; }
    public int TotalEvents { get; set; }
    public int RecentEvents { get; set; }
    public int ProductiveEvents { get; set; }
    public int RecentProductiveEvents { get; set; }
    public int McpEvents { get; set; }
    public int CopilotEvents { get; set; }
    public int WizardEvents { get; set; }
    public int ProjectEvents { get; set; }
    public int BlockEvents { get; set; }
    public int ExportEvents { get; set; }
    public int NegativeEvents { get; set; }
    public bool OnboardingCompleted { get; set; }
    public bool ReturnedAfterFirstSession { get; set; }
    public double? MinutesToFirstProductiveEvent { get; set; }
    public string DetectedPath { get; set; } = "unknown";
    public string OnboardingSegment { get; set; } = "unknown";
    public double UsageScore { get; set; }
    public double ConversionPotentialScore { get; set; }
    public double RetentionConfidenceScore { get; set; }
    public double ChurnRiskScore { get; set; }
    public string Classification { get; set; } = "unknown";
    public List<string> ReasonCodes { get; set; } = new();
    public List<LicenseUsageScoreBreakdownItem> ScoreBreakdown { get; set; } = new();
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
}

public sealed class LicenseUsageScoreBreakdownItem
{
    public string Score { get; set; } = "";
    public string Code { get; set; } = "";
    public double Points { get; set; }
}

public sealed class TelemetryLicenseHardwareAuditResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime FromUtc { get; set; }
    public DateTime ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public List<int> ActivityWindowsDays { get; set; } = new();
    public TelemetryLicenseHardwareAuditSummary Summary { get; set; } = new();
    public List<TelemetryLicenseHardwareAuditWindow> WindowActivity { get; set; } = new();
    public List<TelemetryToolCount> ClassificationCounts { get; set; } = new();
    public List<TelemetryLicenseHardwareAuditItem> Anomalies { get; set; } = new();
}

public sealed class TelemetryLicenseHardwareAuditSummary
{
    public int TelemetryRecords { get; set; }
    public int TelemetryMachines { get; set; }
    public int TelemetryWithoutHardwareId { get; set; }
    public int LicenseBoundMachines { get; set; }
    public int MachinesWithActiveValidLicense { get; set; }
    public int MachinesWithActiveFreemium { get; set; }
    public int MachinesWithActivePaid { get; set; }
    public int MachinesWithExpiredLicense { get; set; }
    public int MachinesWithRevokedLicense { get; set; }
    public int MachinesWithoutLicense { get; set; }
    public int MachinesWithMultipleLicenses { get; set; }
    public bool BlockingMismatchDetected { get; set; }
}

public sealed class TelemetryLicenseHardwareAuditWindow
{
    public int WindowDays { get; set; }
    public int TelemetryMachines { get; set; }
    public int MachinesWithActiveValidLicense { get; set; }
    public int MachinesWithoutActiveValidLicense { get; set; }
}

public sealed class TelemetryLicenseHardwareAuditItem
{
    public string HardwareIdRedacted { get; set; } = "";
    public string HardwareIdHash { get; set; } = "";
    public string Classification { get; set; } = "";
    public int LicenseCount { get; set; }
    public string? LicenseTypeSlug { get; set; }
    public string? LicenseTypeName { get; set; }
    public string LicenseStatus { get; set; } = "";
    public string CustomerEmailRedacted { get; set; } = "";
    public string LicenseKeyRedacted { get; set; } = "";
    public DateTime? LastTelemetryUtc { get; set; }
    public string? LastVersion { get; set; }
    public string? LastEventName { get; set; }
    public int EventCount { get; set; }
}

public sealed class FreemiumAbuseRiskResponse
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Cached { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public int Days { get; set; }
    public DateTime FromUtc { get; set; }
    public DateTime ToUtc { get; set; }
    public string PeriodMode { get; set; } = "rolling";
    public string LicenseType { get; set; } = "";
    public FreemiumAbuseRiskSummary Summary { get; set; } = new();
    public List<TelemetryToolCount> RiskBands { get; set; } = new();
    public List<FreemiumAbuseRiskGroup> Groups { get; set; } = new();
}

public sealed class FreemiumAbuseRiskSummary
{
    public int GroupsAnalyzed { get; set; }
    public int GroupsReturned { get; set; }
    public int HighRiskGroups { get; set; }
    public int MediumRiskGroups { get; set; }
    public int EnterpriseFreemiumGroups { get; set; }
    public int SecuritySignalGroups { get; set; }
    public int TotalLicenses { get; set; }
    public int TotalHardwareIds { get; set; }
    public int TotalEmails { get; set; }
    public int TotalTelemetryEvents { get; set; }
}

public sealed class FreemiumAbuseRiskGroup
{
    public int Rank { get; set; }
    public string GroupKey { get; set; } = "";
    public string GroupType { get; set; } = "";
    public string? EmailDomain { get; set; }
    public string RiskBand { get; set; } = "low";
    public string Classification { get; set; } = "solo_or_low_usage";
    public int PolicyLevel { get; set; } = 1;
    public string RecommendedAction { get; set; } = "observe";
    public string ReviewCategory { get; set; } = "commercial_review";
    public string DeduplicationKey { get; set; } = "";
    public string DeduplicationWindow { get; set; } = "7d";
    public double Score { get; set; }
    public List<FreemiumAbuseRiskSignal> Signals { get; set; } = new();
    public int LicenseCount { get; set; }
    public int ActiveLicenses { get; set; }
    public int ExpiredLicenses { get; set; }
    public int RevokedLicenses { get; set; }
    public int EmailCount { get; set; }
    public int HardwareIdCount { get; set; }
    public int ClientIpCount { get; set; }
    public int TelemetryEvents { get; set; }
    public int ProductiveEvents { get; set; }
    public int McpCopilotEvents { get; set; }
    public DateTime? FirstActivationUtc { get; set; }
    public DateTime? LastActivationUtc { get; set; }
    public DateTime? LastTelemetryUtc { get; set; }
    public List<string> EmailsRedacted { get; set; } = new();
    public List<string> CustomerNameHashes { get; set; } = new();
    public List<string> HardwareIdsRedacted { get; set; } = new();
    public List<string> HardwareIdHashes { get; set; } = new();
    public List<string> ClientIpsRedacted { get; set; } = new();
    public List<string> Versions { get; set; } = new();
    public List<TelemetryToolCount> TopEvents { get; set; } = new();
    public List<TelemetryToolCount> TopEventFamilies { get; set; } = new();
    public List<FreemiumAbuseQuotaPeak> QuotaPeaks { get; set; } = new();
}

public sealed class FreemiumAbuseRiskSignal
{
    public string Code { get; set; } = "";
    public double Points { get; set; }
    public string Detail { get; set; } = "";
}

public sealed class FreemiumAbuseQuotaPeak
{
    public string QuotaKey { get; set; } = "";
    public int PeakUsed { get; set; }
    public int? Limit { get; set; }
    public double? PeakPercentage { get; set; }
}

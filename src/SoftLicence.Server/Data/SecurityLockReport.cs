using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// One security lock reported by an authenticated installation (TKT-001177). Identifiers are stored in their
/// canonical form only (lock id and digests lower-case hex, cause upper-case ASCII), so ordinal equality in SQL
/// matches the validator; the unique key is the enrollment plus the client lock identifier.
/// </summary>
public sealed class SecurityLockReport
{
    /// <summary>Row identifier.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Product of the enrollment.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Authenticated enrollment.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Navigation to the enrollment.</summary>
    public RuntimeEnrollment? Enrollment { get; set; }
    /// <summary>Distribution binding of the enrollment.</summary>
    public Guid BindingId { get; set; }
    /// <summary>Installation identifier of the enrollment.</summary>
    [MaxLength(36)]
    public string InstallationId { get; set; } = string.Empty;
    /// <summary>Upper-case hardware identifier reported (validated against the enrollment hash).</summary>
    [MaxLength(128)]
    public string HardwareId { get; set; } = string.Empty;
    /// <summary>Release version reported.</summary>
    [MaxLength(64)]
    public string AppVersion { get; set; } = string.Empty;
    /// <summary>Client lock identifier (32 lower-case hex).</summary>
    [MaxLength(32)]
    public string LockId { get; set; } = string.Empty;
    /// <summary>Catalogued cause.</summary>
    [MaxLength(64)]
    public string Cause { get; set; } = string.Empty;
    /// <summary>Catalogued level 0..5.</summary>
    public int Level { get; set; }
    /// <summary>Mode claimed by the client (informational).</summary>
    [MaxLength(16)]
    public string ClientMode { get; set; } = string.Empty;
    /// <summary>Mode applied by the server when the verdict was computed.</summary>
    [MaxLength(16)]
    public string EffectiveMode { get; set; } = string.Empty;
    /// <summary>SHA-256 of the client evidence (64 lower-case hex).</summary>
    [MaxLength(64)]
    public string EvidenceDigestSha256 { get; set; } = string.Empty;
    /// <summary>First local detection reported by the client.</summary>
    public DateTime FirstSeenUtc { get; set; }
    /// <summary>First time the server received this lock.</summary>
    public DateTime FirstReportedUtc { get; set; }
    /// <summary>Latest report time.</summary>
    public DateTime LastReportedUtc { get; set; }
    /// <summary>Number of reports received for this lock.</summary>
    public int ReportCount { get; set; }
    /// <summary>OPEN, RELEASED or BANNED.</summary>
    [MaxLength(16)]
    public string State { get; set; } = string.Empty;
    /// <summary>Latest verdict returned (MAINTAIN, RELEASE, BAN).</summary>
    [MaxLength(16)]
    public string LastVerdict { get; set; } = string.Empty;
    /// <summary>Admin decision (RELEASE or BAN), if any.</summary>
    [MaxLength(16)]
    public string? AdminDecision { get; set; }
    /// <summary>Admin decision time.</summary>
    public DateTime? AdminDecisionAtUtc { get; set; }
    /// <summary>Admin identity recorded with the decision.</summary>
    [MaxLength(100)]
    public string? AdminDecisionBy { get; set; }
    /// <summary>Free-text reason recorded with the decision.</summary>
    [MaxLength(500)]
    public string? AdminDecisionReason { get; set; }
}

/// <summary>
/// One-use proof nonce of a lock report. A replay with the same JTI and the same report/body returns the stored
/// signed verdict; any other reuse is a conflict.
/// </summary>
public sealed class SecurityLockReportNonce
{
    /// <summary>Authenticated enrollment.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Proof JTI (canonical UUID).</summary>
    [MaxLength(36)]
    public string Jti { get; set; } = string.Empty;
    /// <summary>Report identifier bound to the proof.</summary>
    [MaxLength(36)]
    public string ReportId { get; set; } = string.Empty;
    /// <summary>SHA-256 of the exact request body.</summary>
    [MaxLength(64)]
    public string BodyDigestSha256 { get; set; } = string.Empty;
    /// <summary>Exact signed verdict JSON returned the first time.</summary>
    public string ResponseJson { get; set; } = string.Empty;
    /// <summary>Retention deadline.</summary>
    public DateTime ExpiresAtUtc { get; set; }
}

/// <summary>
/// Server-side enforcement mode of one irreversible-candidate cause for one product (TKT-001177 buffer zone).
/// Absent rows mean REVIEW; ENFORCE is only ever set explicitly by an administrator.
/// </summary>
public sealed class SecurityLockEnforcementPolicy
{
    /// <summary>Product.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Catalogued level-4 or level-5 cause.</summary>
    [MaxLength(64)]
    public string Cause { get; set; } = string.Empty;
    /// <summary>SHADOW, REVIEW or ENFORCE.</summary>
    [MaxLength(16)]
    public string Mode { get; set; } = string.Empty;
    /// <summary>Last change time.</summary>
    public DateTime UpdatedAtUtc { get; set; }
    /// <summary>Administrator who made the last change.</summary>
    [MaxLength(100)]
    public string UpdatedBy { get; set; } = string.Empty;
}

/// <summary>
/// Durable, per-channel delivery of one committed security-lock alert. The row is created in the same transaction
/// as the lock verdict; provider calls are performed later by a leased worker.
/// </summary>
public sealed class SecurityLockAlertDelivery
{
    /// <summary>Stable delivery identifier, also used as the webhook idempotency key.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Security-lock report that caused the alert.</summary>
    public Guid SecurityLockReportId { get; set; }
    /// <summary>Navigation to the report.</summary>
    public SecurityLockReport? SecurityLockReport { get; set; }
    /// <summary>EMAIL or WEBHOOK.</summary>
    [MaxLength(16)]
    public string Channel { get; set; } = string.Empty;
    /// <summary>Frozen webhook URL, or the non-secret logical target ADMIN for email.</summary>
    [MaxLength(2048)]
    public string Target { get; set; } = string.Empty;
    /// <summary>Lower-case SHA-256 of <see cref="Target"/>, used by the bounded uniqueness index.</summary>
    [MaxLength(64)]
    public string TargetDigestSha256 { get; set; } = string.Empty;
    /// <summary>Notification trigger used to select subscriptions and render the provider request.</summary>
    [MaxLength(64)]
    public string Trigger { get; set; } = string.Empty;
    /// <summary>Whether the triggering verdict created a permanent ban.</summary>
    public bool NewBan { get; set; }
    /// <summary>Client address used only for the redacted administrative dossier.</summary>
    [MaxLength(64)]
    public string? ClientIp { get; set; }
    /// <summary>Frozen title prepared before the first provider call.</summary>
    [MaxLength(300)]
    public string? Title { get; set; }
    /// <summary>Frozen plain-text dossier prepared before the first provider call.</summary>
    public string? Message { get; set; }
    /// <summary>PENDING, PROCESSING, SENT, SKIPPED, FAILED or UNKNOWN.</summary>
    [MaxLength(16)]
    public string State { get; set; } = SecurityLockAlertDeliveryStates.Pending;
    /// <summary>Number of provider calls started.</summary>
    public int AttemptCount { get; set; }
    /// <summary>Earliest time at which a retry may be claimed.</summary>
    public DateTime NextAttemptUtc { get; set; }
    /// <summary>Opaque ownership token of the current worker lease.</summary>
    public Guid? LeaseToken { get; set; }
    /// <summary>Lease deadline; an expired SMTP lease becomes UNKNOWN rather than being sent twice.</summary>
    public DateTime? LeaseExpiresUtc { get; set; }
    /// <summary>Bounded operational diagnostic with no dossier or credential content.</summary>
    [MaxLength(500)]
    public string? LastError { get; set; }
    /// <summary>Creation time.</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Last state transition time.</summary>
    public DateTime UpdatedAtUtc { get; set; }
    /// <summary>Successful provider completion time.</summary>
    public DateTime? SentAtUtc { get; set; }
}

/// <summary>Canonical security-lock alert delivery states.</summary>
public static class SecurityLockAlertDeliveryStates
{
    public const string Pending = "PENDING";
    public const string Processing = "PROCESSING";
    public const string Sent = "SENT";
    public const string Skipped = "SKIPPED";
    public const string Failed = "FAILED";
    public const string Unknown = "UNKNOWN";
}

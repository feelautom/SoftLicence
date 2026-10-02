namespace SoftLicence.Server.Data;

/// <summary>
/// Stores the authoritative server projection for one privacy-safe Recovery telemetry run.
/// </summary>
public sealed class RecoveryTelemetryRun
{
    /// <summary>Gets or sets the database identity.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Gets or sets the product that owns the run.</summary>
    public Guid ProductId { get; set; }

    /// <summary>Gets or sets the opaque client-generated Recovery run identifier.</summary>
    public Guid RecoveryRunId { get; set; }

    /// <summary>Gets or sets the last durably accepted sequence number.</summary>
    public int LastSequence { get; set; }

    /// <summary>Gets or sets the last accepted closed stage.</summary>
    public string LastStage { get; set; } = string.Empty;

    /// <summary>Gets or sets the last accepted closed outcome.</summary>
    public string LastOutcome { get; set; } = string.Empty;

    /// <summary>Gets or sets whether the run has accepted its unique terminal event.</summary>
    public bool IsTerminal { get; set; }

    /// <summary>Gets or sets the derived status: incomplete, completed, failed, or cancelled.</summary>
    public string Status { get; set; } = RecoveryTelemetryStatuses.Incomplete;

    /// <summary>Gets or sets the last closed error code, if the current state carries one.</summary>
    public string? ErrorCode { get; set; }

    /// <summary>Gets or sets the source application version when supplied by an accepted event.</summary>
    public string? SourceVersion { get; set; }

    /// <summary>Gets or sets the target application version when supplied by an accepted event.</summary>
    public string? TargetVersion { get; set; }

    /// <summary>Gets or sets the independently verified restored version.</summary>
    public string? VerifiedRestoredVersion { get; set; }

    /// <summary>Gets or sets the authoritative server receipt time for the first event.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Gets or sets the authoritative server receipt time for the latest event.</summary>
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>Gets or sets the owning product navigation.</summary>
    public Product Product { get; set; } = null!;

    /// <summary>Gets or sets the ordered events belonging to this run.</summary>
    public ICollection<RecoveryTelemetryEvent> Events { get; set; } = new List<RecoveryTelemetryEvent>();
}

/// <summary>
/// Stores one immutable accepted Recovery v1 event without customer or machine identity.
/// </summary>
public sealed class RecoveryTelemetryEvent
{
    /// <summary>Gets or sets the database identity.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Gets or sets the owning product identity.</summary>
    public Guid ProductId { get; set; }
    /// <summary>Gets or sets the owning run database identity.</summary>
    public Guid RunId { get; set; }
    /// <summary>Gets or sets the opaque Recovery run identifier.</summary>
    public Guid RecoveryRunId { get; set; }
    /// <summary>Gets or sets the opaque event identifier.</summary>
    public Guid EventId { get; set; }
    /// <summary>Gets or sets the monotonic sequence within the run.</summary>
    public int Sequence { get; set; }
    /// <summary>Gets or sets the SHA-256 of the exact canonical request bytes.</summary>
    public string PayloadSha256 { get; set; } = string.Empty;
    /// <summary>Gets or sets the exact client occurrence time parsed from the canonical timestamp.</summary>
    public DateTime OccurredAtUtc { get; set; }
    /// <summary>Gets or sets the authoritative server receipt time.</summary>
    public DateTime ReceivedAtUtc { get; set; }
    /// <summary>Gets or sets the canonical three-component client version.</summary>
    public string ClientVersion { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed process role.</summary>
    public string ProcessRole { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed stage.</summary>
    public string Stage { get; set; } = string.Empty;
    /// <summary>Gets or sets the closed outcome.</summary>
    public string Outcome { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional source version.</summary>
    public string? SourceVersion { get; set; }
    /// <summary>Gets or sets the optional target version.</summary>
    public string? TargetVersion { get; set; }
    /// <summary>Gets or sets the verified restored version only for successful verification.</summary>
    public string? VerifiedRestoredVersion { get; set; }
    /// <summary>Gets or sets an optional result duration in milliseconds.</summary>
    public int? DurationMs { get; set; }
    /// <summary>Gets or sets the closed error code for failed or cancelled outcomes.</summary>
    public string? ErrorCode { get; set; }
    /// <summary>Gets or sets the allowlisted MSI exit code when applicable.</summary>
    public int? MsiExitCode { get; set; }
    /// <summary>Gets or sets whether this event is the run terminal.</summary>
    public bool IsTerminal { get; set; }
    /// <summary>Gets or sets the owning run navigation.</summary>
    public RecoveryTelemetryRun Run { get; set; } = null!;
}

/// <summary>
/// Stores a bounded closed rejection without retaining the request body or invalid identifier candidates.
/// </summary>
public sealed class RecoveryTelemetryRejection
{
    /// <summary>Gets or sets the database identity.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Gets or sets the resolved product identity when exact resolution succeeded.</summary>
    public Guid? ProductId { get; set; }
    /// <summary>Gets or sets a run ID only when it passed canonical validation.</summary>
    public Guid? RecoveryRunId { get; set; }
    /// <summary>Gets or sets an event ID only when it passed canonical validation.</summary>
    public Guid? EventId { get; set; }
    /// <summary>Gets or sets the closed rejection code.</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Gets or sets the server correlation identifier returned to the caller.</summary>
    public Guid CorrelationId { get; set; }
    /// <summary>Gets or sets the authoritative server rejection time.</summary>
    public DateTime ReceivedAtUtc { get; set; }
    /// <summary>Gets or sets the resolved product navigation.</summary>
    public Product? Product { get; set; }
}

/// <summary>Defines the only derived Recovery run status strings persisted and returned by analytics.</summary>
public static class RecoveryTelemetryStatuses
{
    /// <summary>Represents a run with no accepted terminal.</summary>
    public const string Incomplete = "incomplete";
    /// <summary>Represents a verified and committed completed run.</summary>
    public const string Completed = "completed";
    /// <summary>Represents a technical failure terminal.</summary>
    public const string Failed = "failed";
    /// <summary>Represents an explicit user or UAC cancellation terminal.</summary>
    public const string Cancelled = "cancelled";
}

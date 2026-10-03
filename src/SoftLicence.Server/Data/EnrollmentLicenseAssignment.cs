using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

/// <summary>
/// Records the commercial right attached to one cryptographic Runtime enrollment.
/// Hardware identity remains exclusively in licensing and is never copied here.
/// </summary>
public sealed class EnrollmentLicenseAssignment
{
    /// <summary>Stable row identity; the initial backfill uses the enrollment ID.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Cryptographic enrollment receiving this commercial right.</summary>
    public Guid EnrollmentId { get; set; }
    /// <summary>Commercial license selected independently of the enrollment's legacy copy.</summary>
    public Guid LicenseId { get; set; }
    /// <summary>Seat that must belong to <see cref="LicenseId"/>.</summary>
    public Guid LicenseSeatId { get; set; }

    /// <summary>Exact ACTIVE or ENDED lifecycle code; only ACTIVE may grant a right.</summary>
    [MaxLength(16)]
    public string State { get; set; } = "ACTIVE";

    /// <summary>UTC instant at which the commercial assignment began.</summary>
    public DateTime ActivatedAtUtc { get; set; }
    /// <summary>UTC termination instant, required for ENDED rows and absent for ACTIVE rows.</summary>
    public DateTime? EndedAtUtc { get; set; }
    /// <summary>Monotonic positive history number within one enrollment.</summary>
    public int Revision { get; set; } = 1;

    /// <summary>Bounded termination reason, required only after the assignment ends.</summary>
    [MaxLength(64)]
    public string? EndReason { get; set; }
}

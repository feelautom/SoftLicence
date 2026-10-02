using System.Globalization;
using System.Text;

namespace SoftLicence.Server.Services.SecurityLocks;

/// <summary>Facts gathered for one lock alert (identifiers and states only, never evidence content).</summary>
public sealed record SecurityLockDossier(
    string Product,
    string? CustomerName,
    string? CustomerEmail,
    string? MaskedLicenseKey,
    string? MachineName,
    string HardwareId,
    string AppVersion,
    string InstallationId,
    Guid EnrollmentId,
    string LockId,
    string Cause,
    int Level,
    string EffectiveMode,
    string ClientMode,
    string LastVerdict,
    string State,
    DateTime FirstSeenUtc,
    DateTime FirstReportedUtc,
    int ReportCount,
    int OtherLocksOnHardware,
    bool OpenCriticalIncident,
    string EvidenceDigestSha256,
    string? ClientIp = null,
    string? Country = null,
    int TelemetryLast24h = 0,
    string? TelemetryTopEvents = null);

/// <summary>
/// Alert rules of TKT-001177 (owner decision: level 3 and above raise a big alert with the full dossier). A legacy
/// marker released automatically on a clean record is not alerted, because every machine migrating from the old
/// 72-hour marker produces one and it needs no admin action.
/// </summary>
public static class SecurityLockAlertPolicy
{
    /// <summary>Whether a newly reported lock raises an alert.</summary>
    /// <param name="cause">Catalogued cause.</param>
    /// <param name="level">Catalogued level.</param>
    /// <param name="verdict">Verdict just returned.</param>
    public static bool ShouldAlertNewLock(string cause, int level, string verdict)
    {
        if (level < 3) return false;
        return !(string.Equals(cause, "LEGACY_MARKER", StringComparison.Ordinal)
                 && string.Equals(verdict, SecurityLockVerdicts.Release, StringComparison.Ordinal));
    }

    /// <summary>
    /// Masks a licence key so that the alert identifies it without disclosing it: only the first and last four
    /// characters are kept, and short keys are fully masked.
    /// </summary>
    /// <param name="licenseKey">Stored licence key, or null.</param>
    public static string? MaskLicenseKey(string? licenseKey)
    {
        if (string.IsNullOrEmpty(licenseKey)) return null;
        return licenseKey.Length <= 8 ? "****" : licenseKey[..4] + "…" + licenseKey[^4..];
    }

    /// <summary>Builds the French dossier text sent to the webhooks.</summary>
    /// <param name="d">Dossier facts.</param>
    public static string BuildDossier(SecurityLockDossier d)
    {
        static string Utc(DateTime value) => value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        var sb = new StringBuilder(1024);
        sb.Append("Produit : ").AppendLine(d.Product);
        sb.Append("Client : ").Append(string.IsNullOrWhiteSpace(d.CustomerName) ? "?" : d.CustomerName)
            .Append(" <").Append(string.IsNullOrWhiteSpace(d.CustomerEmail) ? "?" : d.CustomerEmail).AppendLine(">");
        sb.Append("Licence : ").AppendLine(d.MaskedLicenseKey ?? "?");
        sb.Append("Machine : ").AppendLine(string.IsNullOrWhiteSpace(d.MachineName) ? "?" : d.MachineName);
        sb.Append("HWID : ").AppendLine(d.HardwareId);
        sb.Append("Version : ").AppendLine(d.AppVersion);
        sb.Append("Installation : ").Append(d.InstallationId).Append(" / enrôlement : ").AppendLine(d.EnrollmentId.ToString("D"));
        sb.Append("Verrou : ").AppendLine(d.LockId);
        sb.Append("Cause : ").Append(d.Cause).Append(" (niveau ").Append(d.Level.ToString(CultureInfo.InvariantCulture)).AppendLine(")");
        sb.Append("Mode serveur : ").Append(d.EffectiveMode).Append(" (client : ").Append(d.ClientMode).AppendLine(")");
        sb.Append("Verdict : ").Append(d.LastVerdict).Append(", état ").AppendLine(d.State);
        sb.Append("Première détection : ").Append(Utc(d.FirstSeenUtc)).Append(" ; premier rapport : ").AppendLine(Utc(d.FirstReportedUtc));
        sb.Append("Rapports reçus : ").AppendLine(d.ReportCount.ToString(CultureInfo.InvariantCulture));
        sb.Append("Autres verrous sur ce matériel : ").AppendLine(d.OtherLocksOnHardware.ToString(CultureInfo.InvariantCulture));
        sb.Append("Incident critique ouvert : ").AppendLine(d.OpenCriticalIncident ? "oui" : "non");
        sb.Append("IP : ").Append(string.IsNullOrWhiteSpace(d.ClientIp) ? "?" : d.ClientIp)
            .Append(" (").Append(string.IsNullOrWhiteSpace(d.Country) ? "pays inconnu" : d.Country).AppendLine(")");
        sb.Append("Télémétrie 24 h : ").Append(d.TelemetryLast24h.ToString(CultureInfo.InvariantCulture)).Append(" événement(s)")
            .AppendLine(string.IsNullOrWhiteSpace(d.TelemetryTopEvents) ? string.Empty : " (" + d.TelemetryTopEvents + ")");
        sb.Append("Empreinte de la preuve : ").AppendLine(d.EvidenceDigestSha256);
        sb.Append("Action : page admin « Verrous » /security-locks, référence ").Append(d.LockId).Append(" (relâcher ou bannir).");
        return sb.ToString();
    }
}

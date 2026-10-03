using System.Globalization;

namespace SoftLicence.Server.Services;

/// <summary>Enforces the configured TIAConnect minimum independently of telemetry and commercial tier.</summary>
public static class LegacyMinimumVersionPolicy
{
    /// <summary>Identifies the server-resolved product without trusting request spelling or ambient culture.</summary>
    public static bool AppliesTo(string productName) =>
        string.Equals(productName, "TIAConnect", StringComparison.OrdinalIgnoreCase);

    /// <summary>Returns a stable refusal reason, or null when this policy permits the declared version.</summary>
    /// <remarks>No configured minimum disables the policy. A malformed configured minimum fails closed.
    /// A declaration is compatibility evidence only, never binary attestation or authority to lift a ban.</remarks>
    public static string? Evaluate(string productName, string? current, string? minimum)
    {
        if (!AppliesTo(productName) || string.IsNullOrWhiteSpace(minimum)) return null;
        if (!TryParse(minimum, out var required)) return "MINIMUM_VERSION_CONFIGURATION_INVALID";
        if (string.IsNullOrWhiteSpace(current)) return "APP_VERSION_REQUIRED";
        if (!TryParse(current, out var declared)) return "APP_VERSION_INVALID";
        return declared!.CompareTo(required) < 0 ? "APP_VERSION_BELOW_MINIMUM" : null;
    }

    /// <summary>Describes only validated numeric data; malformed client input is never echoed to structured logs.</summary>
    internal static string DescribeForDiagnostics(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "missing" : TryParse(value, out var version) ? version!.ToString() : "invalid";

    /// <summary>Parses at most 64 characters containing two to four ASCII numeric components, padding omitted components with zero.</summary>
    /// <remarks>Outer whitespace is accepted; signs, suffixes, internal whitespace and integer overflow are rejected.</remarks>
    private static bool TryParse(string value, out Version? version)
    {
        version = null;
        if (value.Length > 64) return false;
        var parts = value.Trim().Split('.');
        if (parts.Length is < 2 or > 4) return false;
        var numbers = new int[4];
        for (var i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length == 0 || parts[i].Any(c => c is < '0' or > '9')
                || !int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
                return false;
        }
        version = new Version(numbers[0], numbers[1], numbers[2], numbers[3]);
        return true;
    }
}

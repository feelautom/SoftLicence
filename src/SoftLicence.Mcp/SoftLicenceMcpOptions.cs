namespace SoftLicence.Mcp;

public sealed class SoftLicenceMcpOptions
{
    public string? SoftLicenceBaseUrl { get; set; }
    public string? SoftLicenceApiKey { get; set; }
    public string? SoftLicenceAdminSecret { get; set; }
    public string? SOFTLICENCE_BASE_URL { get; set; }
    public string? SOFTLICENCE_API_KEY { get; set; }
    public string? SOFTLICENCE_ADMIN_SECRET { get; set; }
    public string? ResultDirectory { get; set; }
    public int MaxInlineResultCharacters { get; set; } = 131_072;
    public int ResultChunkCharacters { get; set; } = 32_768;
    public int ResultTtlMinutes { get; set; } = 60;
    public long ResultMaxTotalBytes { get; set; } = 100 * 1024 * 1024;
    /// <summary>
    /// HTTP mode only (TKT-001169): comma-separated networks allowed to call /mcp, from
    /// SOFTLICENCE_MCP_ALLOWED_CIDRS. Defaults to the WireGuard VPN.
    /// </summary>
    public string AllowedCidrs { get; set; } = "10.10.0.0/24";
    /// <summary>Requested per-response transport bound; runtime clamps it to the safe 1 KiB..16 MiB range.</summary>
    public int AnalyticsResponseMaxBytes { get; set; } = 16 * 1024 * 1024;

    public string GetBaseUrl()
    {
        var value = FirstNonEmpty(SoftLicenceBaseUrl, SOFTLICENCE_BASE_URL);
        if (value == null)
            throw new InvalidOperationException("Missing SOFTLICENCE_BASE_URL.");

        return value.Trim().TrimEnd('/');
    }

    public string GetApiKey()
    {
        var value = FirstNonEmpty(SoftLicenceApiKey, SOFTLICENCE_API_KEY);
        if (value == null)
            throw new InvalidOperationException("Missing SOFTLICENCE_API_KEY.");

        return value.Trim();
    }

    public string GetAdminSecret()
    {
        if (!TryGetAdminSecret(out var value, out var errorCode, out var errorMessage))
            throw new InvalidOperationException($"{errorCode}: {errorMessage}");

        return value;
    }

    public bool TryGetAdminSecret(out string value, out string errorCode, out string errorMessage) =>
        ValidateAdminSecret(
            SoftLicenceAdminSecret ?? SOFTLICENCE_ADMIN_SECRET,
            "Missing SOFTLICENCE_ADMIN_SECRET.",
            out value,
            out errorCode,
            out errorMessage);

    /// <summary>
    /// Validates an admin secret candidate, shared by stdio (environment) and HTTP (request header)
    /// credentials. The secret is exact printable ASCII; it is never trimmed or echoed in messages.
    /// </summary>
    /// <param name="candidate">Raw secret, or null when absent.</param>
    /// <param name="missingMessage">Message returned when the secret is absent.</param>
    /// <param name="value">Validated secret, or empty on failure.</param>
    /// <param name="errorCode">Stable refusal code, or empty on success.</param>
    /// <param name="errorMessage">Human-readable refusal, or empty on success.</param>
    public static bool ValidateAdminSecret(
        string? candidate,
        string missingMessage,
        out string value,
        out string errorCode,
        out string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            value = string.Empty;
            errorCode = "write_credentials_missing";
            errorMessage = missingMessage;
            return false;
        }

        if (candidate != candidate.Trim()
            || candidate.Any(character => character is < ' ' or > '~'))
        {
            value = string.Empty;
            errorCode = "write_credentials_invalid";
            errorMessage = "The admin secret must be exact printable ASCII without surrounding whitespace or control characters.";
            return false;
        }

        value = candidate;
        errorCode = string.Empty;
        errorMessage = string.Empty;
        return true;
    }

    public string GetResultDirectory()
    {
        var root = !string.IsNullOrWhiteSpace(ResultDirectory)
            ? Path.GetFullPath(ResultDirectory.Trim())
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FeelAutomCorp",
                "SoftLicence",
                "McpResults");

        return Path.Combine(root, $"session-{Environment.ProcessId}");
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    }
}

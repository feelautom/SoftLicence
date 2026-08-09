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

    public bool TryGetAdminSecret(out string value, out string errorCode, out string errorMessage)
    {
        var candidate = SoftLicenceAdminSecret ?? SOFTLICENCE_ADMIN_SECRET;
        if (string.IsNullOrWhiteSpace(candidate))
        {
            value = string.Empty;
            errorCode = "write_credentials_missing";
            errorMessage = "Missing SOFTLICENCE_ADMIN_SECRET.";
            return false;
        }

        if (candidate != candidate.Trim()
            || candidate.Any(character => character is < ' ' or > '~'))
        {
            value = string.Empty;
            errorCode = "write_credentials_invalid";
            errorMessage = "SOFTLICENCE_ADMIN_SECRET must be exact printable ASCII without surrounding whitespace or control characters.";
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

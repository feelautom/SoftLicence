namespace SoftLicence.Mcp;

public sealed class SoftLicenceMcpOptions
{
    public string? SoftLicenceBaseUrl { get; set; }
    public string? SoftLicenceApiKey { get; set; }
    public string? SoftLicenceAdminSecret { get; set; }
    public string? SOFTLICENCE_BASE_URL { get; set; }
    public string? SOFTLICENCE_API_KEY { get; set; }
    public string? SOFTLICENCE_ADMIN_SECRET { get; set; }

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
        var value = FirstNonEmpty(SoftLicenceAdminSecret, SOFTLICENCE_ADMIN_SECRET);
        if (value == null)
            throw new InvalidOperationException("write_credentials_missing: Missing SOFTLICENCE_ADMIN_SECRET.");

        return value.Trim();
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    }
}

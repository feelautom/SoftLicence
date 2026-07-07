using System.Text.Json;

namespace SoftLicence.Server.Services;

public static class TelemetrySchemaRegistry
{
    private const int MaxPropertyValueLength = 512;
    private static readonly StringComparer KeyComparer = StringComparer.OrdinalIgnoreCase;

    public static readonly HashSet<string> CommonKeys = new(KeyComparer)
    {
        "OS",
        "Culture",
        "AppVersion",
        "IsInteractive",
        "RequestSource",
        "GDI_Objects",
        "Usage_Total",
        "Usage_Api",
        "Usage_Mcp",
        "Usage_Copilot",
        "Usage_Reads",
        "Usage_Writes",
        "Usage_SessionMinutes",
        "Quota_Api_Hourly",
        "Quota_Api_Daily",
        "Quota_Mcp_Hourly",
        "Quota_Mcp_Daily",
        "Quota_Copilot_Hourly",
        "Quota_Copilot_Daily"
    };

    public static readonly HashSet<string> SensitiveKeys = new(KeyComparer)
    {
        "Key",
        "LicenseKey",
        "Token",
        "Secret",
        "Password",
        "PrivateKey",
        "ApiSecret",
        "Authorization",
        "Bearer",
        "Cookie"
    };

    private static readonly string[] SensitiveKeyFragments =
    {
        "LicenseKey",
        "Token",
        "Secret",
        "Password",
        "PrivateKey",
        "ApiSecret",
        "Authorization",
        "Bearer",
        "Cookie"
    };

    public static string ClassifyFamily(string eventName)
    {
        if (eventName.StartsWith("Update_", StringComparison.OrdinalIgnoreCase))
            return "update";
        if (eventName.StartsWith("Startup_", StringComparison.OrdinalIgnoreCase))
            return "startup";
        if (eventName.StartsWith("Mcp_", StringComparison.OrdinalIgnoreCase))
            return "mcp";
        if (eventName.StartsWith("Copilot_", StringComparison.OrdinalIgnoreCase))
            return "copilot";
        if (eventName.StartsWith("Wizard_", StringComparison.OrdinalIgnoreCase))
            return "wizard";
        if (eventName.StartsWith("UI_", StringComparison.OrdinalIgnoreCase))
            return "ui";
        if (eventName.StartsWith("Block", StringComparison.OrdinalIgnoreCase))
            return "block";
        if (eventName.StartsWith("Compile_", StringComparison.OrdinalIgnoreCase))
            return "compile";
        if (eventName.StartsWith("API_", StringComparison.OrdinalIgnoreCase))
            return "api";
        if (eventName.StartsWith("License", StringComparison.OrdinalIgnoreCase))
            return "license";
        if (eventName.Contains("CertPinning", StringComparison.OrdinalIgnoreCase))
            return "cert-pinning";

        return "other";
    }

    public static bool IsSystemNoiseEvent(string? eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName))
            return false;

        var family = ClassifyFamily(eventName);
        return family is "update" or "startup";
    }

    public static bool IsRealUserActivityEvent(string? eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName))
            return false;

        var family = ClassifyFamily(eventName);
        return family is not ("update" or "startup" or "ui" or "wizard");
    }

    public static List<string> ParseKeys(string? propertiesJson)
    {
        if (string.IsNullOrWhiteSpace(propertiesJson))
            return new List<string>();

        try
        {
            using var doc = JsonDocument.Parse(propertiesJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return new List<string>();

            return doc.RootElement.EnumerateObject()
                .Select(p => p.Name)
                .Where(k => !IsSensitiveKey(k))
                .Distinct(KeyComparer)
                .OrderBy(k => k, KeyComparer)
                .ToList();
        }
        catch (JsonException)
        {
            return new List<string>();
        }
    }

    public static Dictionary<string, string> ParseProperties(string? propertiesJson)
    {
        if (string.IsNullOrWhiteSpace(propertiesJson))
            return new Dictionary<string, string>(KeyComparer);

        try
        {
            using var doc = JsonDocument.Parse(propertiesJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return new Dictionary<string, string>(KeyComparer);

            var result = new Dictionary<string, string>(KeyComparer);
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                if (IsSensitiveKey(property.Name))
                    continue;

                result[property.Name] = RedactValue(property.Value);
            }

            return result;
        }
        catch (JsonException)
        {
            return new Dictionary<string, string>(KeyComparer);
        }
    }

    public static bool IsSensitiveKey(string key)
    {
        if (SensitiveKeys.Contains(key))
            return true;

        return SensitiveKeyFragments.Any(fragment =>
            key.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private static string RedactValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => Truncate(element.GetString() ?? ""),
            JsonValueKind.Object => SerializeRedactedObject(element),
            JsonValueKind.Array => SerializeRedactedArray(element),
            _ => Truncate(element.ToString())
        };
    }

    private static string SerializeRedactedObject(JsonElement element)
    {
        var values = new Dictionary<string, object?>(KeyComparer);
        foreach (var property in element.EnumerateObject())
        {
            if (IsSensitiveKey(property.Name))
                continue;

            values[property.Name] = ToRedactedObject(property.Value);
        }

        return Truncate(JsonSerializer.Serialize(values));
    }

    private static string SerializeRedactedArray(JsonElement element)
    {
        var values = element.EnumerateArray()
            .Take(20)
            .Select(ToRedactedObject)
            .ToList();

        return Truncate(JsonSerializer.Serialize(values));
    }

    private static object? ToRedactedObject(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => element.EnumerateObject()
                .Where(p => !IsSensitiveKey(p.Name))
                .ToDictionary(p => p.Name, p => ToRedactedObject(p.Value), KeyComparer),
            JsonValueKind.Array => element.EnumerateArray()
                .Take(20)
                .Select(ToRedactedObject)
                .ToList(),
            JsonValueKind.String => Truncate(element.GetString() ?? ""),
            JsonValueKind.Number => element.TryGetInt64(out var longValue)
                ? longValue
                : element.TryGetDouble(out var doubleValue) ? doubleValue : element.ToString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => Truncate(element.ToString())
        };
    }

    private static string Truncate(string value)
    {
        return value.Length <= MaxPropertyValueLength
            ? value
            : value[..MaxPropertyValueLength];
    }
}

using System.Text.Json;
using SoftLicence.SDK;

var keys = LicenseService.GenerateKeys();
const string hardwareId = "SDK-COMPAT-HWID-20260728";
var model = new LicenseModel
{
    Id = Guid.Parse("11111111-1111-4111-8111-111111111111"),
    LicenseKey = "TEST-COMPAT-ONLY",
    CustomerName = "Franck – 測試",
    CustomerEmail = "compat@example.invalid",
    TypeSlug = "STANDARD",
    Reference = "plugin:mcp-tools:pluginVersion=β-1:allowedFeatures=read,write",
    CreationDate = new DateTime(2026, 7, 28, 0, 0, 0, DateTimeKind.Utc),
    ExpirationDate = new DateTime(2030, 7, 28, 0, 0, 0, DateTimeKind.Utc),
    HardwareId = hardwareId,
    PluginId = "mcp-tools",
    PluginVersion = "β-1",
    AllowedFeatures = ["read", "write"],
    Features = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["unicodeLabel"] = "électricité-測試",
        ["pluginVersion"] = "β-1"
    }
};
var licenseFile = LicenseService.GenerateLicense(model, keys.PrivateKey);
Console.Out.Write(JsonSerializer.Serialize(new
{
    licenseFile,
    publicKey = keys.PublicKey,
    hardwareId
}));

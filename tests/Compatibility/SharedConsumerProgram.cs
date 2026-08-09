using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;

var inputJson = await Console.In.ReadToEndAsync();
var input = JsonSerializer.Deserialize<Input>(inputJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
    ?? throw new InvalidDataException("Compatibility input missing.");
var validation = LicenseService.ValidateLicense(input.LicenseFile, input.PublicKey, input.HardwareId);
if (!validation.IsValid || validation.License == null)
{
    Console.Error.WriteLine($"License validation failed: {validation.ErrorMessage}");
    return 2;
}
var license = validation.License;
var type = license.GetType();
Console.Out.Write(JsonSerializer.Serialize(new
{
    licenseFileSha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(input.LicenseFile))),
    license.CustomerName,
    unicodeLabel = license.Features["unicodeLabel"],
    pluginId = type.GetProperty("PluginId")?.GetValue(license),
    pluginVersion = type.GetProperty("PluginVersion")?.GetValue(license),
    allowedFeatures = type.GetProperty("AllowedFeatures")?.GetValue(license)
}));
return 0;

internal sealed record Input(string LicenseFile, string PublicKey, string HardwareId);

using System.Reflection;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

public class LicenseFileContractTests
{
    private const string ContractFixturePublicKeyXml =
        "<RSAKeyValue><Modulus>6K5AqQclKeiokegoNC8s5uwmxWQ03rK+tWHRR7hI3NSUuvgUY+PYkRg4tMGRFLtoCUTeaO/hBOydhMqcECpbJMIz1TEiTYk+JPSJ2IXofhRdTx0C9p4vnlGXws58C1XcnVRJTzba5vgB0U7JI02L1dteaVs+ftTjbMKjf+jd9jWTgDYsnctnayld87UR2oVovDyKflzKJfxePWt+PQpJ/pV5R2LR+CIkUlWfrdlF43ai3fHEPRi/vXzWQWtmgR2ynVfnSbQkBL0G553cFg7sINutnsmYtVeO0a5Bn7ZlKg0gOTG3HJ/f//6/N57D4ye8v8csLJMqBGRXDYja7+GJKGzRErIzYxZhEtSbnT9I67yWPSaOJjaAXoIRBua0QeG+sJu4OeScCmtAsoUA7sehus8du1ymOIK2jrrORJ/ROUghqT6HkZ6fV7WLM7dAojCXS/na3/IZ89SJoS1nuOQ3Sm4my5KVqwVJ20N2NBXdYaCD4z1U7UtxAIBXrR4wjTJ1tUF4ibz/ZPKVTq23Thg2A+nYLRx0chp5AvMOEHgrkDrBQB8UQ1F0qBP5LzSyomn3LZagl3g1TE2P26bp/gWQ3rI7gZRp3IBL3e7b+OJH0jM7eqIXulDOU6PuMAn0y9APJSvq//eOcMKx1pOpkOsKG6JBk5TIwtHm5mPN1C9vRJk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    private const string ContractFixtureLicenseFile =
        "eyJJZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsIkxpY2Vuc2VLZXkiOiJURVNULUxJQ0VOU0UtMDAwMSIsIkN1c3RvbWVyTmFtZSI6IkZpeHR1cmUgVXNlciIsIkN1c3RvbWVyRW1haWwiOiJmaXh0dXJlQGV4YW1wbGUuaW52YWxpZCIsIlR5cGVTbHVnIjoiVElBLUNPTlRSQUNULUZJWFRVUkUiLCJSZWZlcmVuY2UiOm51bGwsIkNyZWF0aW9uRGF0ZSI6IjIwMjYtMDYtMjJUMTI6MDA6MDBaIiwiRXhwaXJhdGlvbkRhdGUiOiIyMDk5LTEyLTMxVDIzOjU5OjU5WiIsIkhhcmR3YXJlSWQiOiJBQkNERUYxMjM0NTY3ODkwIiwiRmVhdHVyZXMiOnsiZWRpdGlvbiI6IkVOVEVSUFJJU0UiLCJoYXNBaSI6InRydWUiLCJoYXNBcGkiOiJ0cnVlIiwiaGFzTWNwIjoidHJ1ZSIsIm1heE1ham9yVmVyc2lvbiI6IjIiLCJ2ZXJzaW9uIjoiMiJ9LCJTaWduYXR1cmUiOiIzVU1Ub2NHeUhzSTdHUTVpalVTRjBSaEJQUXRvOGhaMmRhZVhCb0dGZTZDdlpTQnM1ZTUrWEhKbG53M3BIQXlCeGxVcGREcFZ2RU9GMEZTSkVoeU5mbDZPYTJwUTJpVVdzdjRCTW84ZDNvMlVKSTZUV3h4SkUra0k0NWxQQ0d5YUVSY0RId0JITml3UzVSdlJ1bFRPREVvdW9DMXNkcFhrWHl4UFVHZnFDM05yVC9iZFdzUktGVklDWU1YVzBUUzdNZ0ZiSzVTT0xMNUw5cnNhclltNFI4Q2JxS29XTFhFT3piNEJEM2JaUEV1bHFobDVHeVlRT1ZtbVdVUnhuM2VsaHZMck5saWFSbEZCSkEzcy8vUGpUdWNCWXpIQW1RR0JRZHovNVFkT1NRUytYbDJKem1IMVVGZ1NVVmt2alBOMy9JVmx3WmZ4ZFRvdGYyYVdFdzJ4MEFpTmxMNFFXcjVQY3IxcExpWSt3LzJGbXMrQ2FvOExGdGI4d2p2ak1XeEh5WEZ6ZlhPVmJYaGV0QThYRGZmS1oxM01pV2JOUy9OUVR6M3NScXVmRVVMWmZTWlZmTkFROTVadkZuT2tzSUJCSExFbFExcXZjTFBUVTNndm9NbTdQa01tRnJxYmJ4Z3lTU29BWGUwWlJLNVR1QnZwN0VLMWY0MmVTNzFkeTlFK253cldUUkZEZmZHZGJIWHE2LytSR09uQkFjVmVCSzBsclBJMHdZK3NhSkxRdDFNMndlcDllWTU5NVFSOGxlSGoxVjJsVUZtdDZNaTNMUE5IcXNMZ1J4M0lSN1lKbFlnc1MxWjE3RC93d0FTeEZBUGlRTU5QTEpMNlZXY3BjSHZWNVE4eFRjT3g1aUoySW4rb3Y0MkdJb0h0VEh0Ukc5ZW1TeE9HVVVkbm1zRT0iLCJJc0V4cGlyZWQiOmZhbHNlfQ==";

    private const string ContractFixtureSignedJson =
        "{\"Id\":\"11111111-2222-3333-4444-555555555555\",\"LicenseKey\":\"TEST-LICENSE-0001\",\"CustomerName\":\"Fixture User\",\"CustomerEmail\":\"fixture@example.invalid\",\"TypeSlug\":\"TIA-CONTRACT-FIXTURE\",\"Reference\":null,\"CreationDate\":\"2026-06-22T12:00:00Z\",\"ExpirationDate\":\"2099-12-31T23:59:59Z\",\"HardwareId\":\"ABCDEF1234567890\",\"Features\":{\"edition\":\"ENTERPRISE\",\"hasAi\":\"true\",\"hasApi\":\"true\",\"hasMcp\":\"true\",\"maxMajorVersion\":\"2\",\"version\":\"2\"},\"Signature\":\"\",\"IsExpired\":false}";

    private static readonly string[] SignedLicenseModelProperties =
    {
        "Id",
        "LicenseKey",
        "CustomerName",
        "CustomerEmail",
        "TypeSlug",
        "PluginId",
        "PluginVersion",
        "MinAppVersion",
        "AllowedFeatures",
        "Reference",
        "CreationDate",
        "ExpirationDate",
        "HardwareId",
        "Features",
        "Signature",
        "IsExpired"
    };

    private static readonly string[] StandardLicenseSignedJsonProperties =
    {
        "Id",
        "LicenseKey",
        "CustomerName",
        "CustomerEmail",
        "TypeSlug",
        "Reference",
        "CreationDate",
        "ExpirationDate",
        "HardwareId",
        "Features",
        "Signature",
        "IsExpired"
    };

    [Fact]
    public void ContractFixture_ShouldValidateWithOnlyPublicKey()
    {
        var result = LicenseService.ValidateLicense(
            ContractFixtureLicenseFile,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890");

        Assert.True(result.IsValid);
        Assert.NotNull(result.License);
        Assert.Equal("TIA-CONTRACT-FIXTURE", result.License.TypeSlug);
        Assert.Equal("ENTERPRISE", result.License.Features["edition"]);
    }

    [Fact]
    public void ContractFixture_ShouldDocumentExactSignedBytes()
    {
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(ContractFixtureLicenseFile));
        var model = JsonSerializer.Deserialize<LicenseModel>(finalJson)!;

        Assert.False(string.IsNullOrEmpty(model.Signature));

        model.Signature = string.Empty;
        var signedJson = JsonSerializer.Serialize(model);
        var signedBytes = Encoding.UTF8.GetBytes(signedJson);

        Assert.Equal(ContractFixtureSignedJson, signedJson);
        Assert.Equal(ContractFixtureSignedJson, Encoding.UTF8.GetString(signedBytes));
    }

    [Fact]
    public void LicenseModel_PublicSignedProperties_ShouldRequireExplicitContractReview()
    {
        // LicenseModel is the signed transport contract. Adding a public serialized property
        // changes signed bytes for every generated license unless the property is explicitly
        // ignored when absent. This list is intentionally strict.
        var properties = typeof(LicenseModel)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(property => property.GetIndexParameters().Length == 0)
            .Select(property => property.Name)
            .ToArray();

        Assert.Equal(SignedLicenseModelProperties, properties);
    }

    [Fact]
    public void StandardLicense_SignedJson_ShouldKeepLegacyNullableFieldsAndNoPluginNulls()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            LicenseKey = "STANDARD-CONTRACT-0001",
            CustomerName = "Standard User",
            CustomerEmail = "standard@example.invalid",
            TypeSlug = "TIA-STANDARD",
            Reference = null,
            CreationDate = new DateTime(2026, 07, 05, 12, 30, 00, DateTimeKind.Utc),
            ExpirationDate = null,
            HardwareId = "STANDARD-HWID",
            Features = new Dictionary<string, string>
            {
                ["edition"] = "PRO",
                ["hasApi"] = "true"
            }
        };

        var licenseFile = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(licenseFile));
        using var document = JsonDocument.Parse(finalJson);

        var propertyNames = document.RootElement
            .EnumerateObject()
            .Select(property => property.Name)
            .ToArray();

        Assert.Equal(StandardLicenseSignedJsonProperties, propertyNames);
        Assert.True(document.RootElement.GetProperty("Reference").ValueKind == JsonValueKind.Null);
        Assert.True(document.RootElement.GetProperty("ExpirationDate").ValueKind == JsonValueKind.Null);
        Assert.False(finalJson.Contains("PluginId", StringComparison.Ordinal));
        Assert.False(finalJson.Contains("PluginVersion", StringComparison.Ordinal));
        Assert.False(finalJson.Contains("MinAppVersion", StringComparison.Ordinal));
        Assert.False(finalJson.Contains("AllowedFeatures", StringComparison.Ordinal));
    }
}

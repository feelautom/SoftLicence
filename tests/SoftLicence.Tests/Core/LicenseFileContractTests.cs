using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
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
    public void ContractFixture_BeforeExpiration_ShouldRemainValid()
    {
        var result = LicenseService.ValidateLicenseDetailed(
            ContractFixtureLicenseFile,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890",
            new DateTime(2099, 12, 31, 23, 59, 58, DateTimeKind.Utc));

        Assert.True(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.None, result.ErrorCode);
    }

    [Fact]
    public void ContractFixture_AtExactExpiration_ShouldRemainValid()
    {
        var expiration = new DateTime(2099, 12, 31, 23, 59, 59, DateTimeKind.Utc);

        var result = LicenseService.ValidateLicenseDetailed(
            ContractFixtureLicenseFile,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890",
            expiration);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.None, result.ErrorCode);
    }

    [Fact]
    public void ContractFixture_OneTickAfterExpiration_ShouldReturnExpired()
    {
        var expiration = new DateTime(2099, 12, 31, 23, 59, 59, DateTimeKind.Utc);

        var result = LicenseService.ValidateLicenseDetailed(
            ContractFixtureLicenseFile,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890",
            expiration.AddTicks(1));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.Expired, result.ErrorCode);
        Assert.Equal("Licence expirée.", result.ErrorMessage);
    }

    [Fact]
    public void ContractFixture_WithTamperedExpirationSnapshot_ShouldReturnInvalidSignature()
    {
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(ContractFixtureLicenseFile));
        var tamperedJson = finalJson.Replace("\"IsExpired\":false", "\"IsExpired\":true", StringComparison.Ordinal);
        var tamperedLicense = Convert.ToBase64String(Encoding.UTF8.GetBytes(tamperedJson));

        var result = LicenseService.ValidateLicenseDetailed(
            tamperedLicense,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890",
            new DateTime(2099, 12, 31, 23, 59, 58, DateTimeKind.Utc));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidSignature, result.ErrorCode);
    }

    [Fact]
    public void ContractFixture_WithTamperedExpirationDate_ShouldReturnInvalidSignature()
    {
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(ContractFixtureLicenseFile));
        var tamperedJson = finalJson.Replace(
            "2099-12-31T23:59:59Z",
            "2098-12-31T23:59:59Z",
            StringComparison.Ordinal);
        var tamperedLicense = Convert.ToBase64String(Encoding.UTF8.GetBytes(tamperedJson));

        var result = LicenseService.ValidateLicenseDetailed(
            tamperedLicense,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890",
            new DateTime(2098, 12, 31, 23, 59, 58, DateTimeKind.Utc));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidSignature, result.ErrorCode);
    }

    [Fact]
    public void ContractFixture_WithInvalidSignatureAfterExpiration_ShouldKeepInvalidSignaturePriority()
    {
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(ContractFixtureLicenseFile));
        var signature = ExtractRawJsonStringValue(finalJson, "Signature");
        var replacementFirstCharacter = signature[0] == 'A' ? 'B' : 'A';
        var tamperedSignature = replacementFirstCharacter + signature[1..];
        var tamperedJson = ReplaceRawJsonStringValue(finalJson, "Signature", tamperedSignature);
        var tamperedLicense = Convert.ToBase64String(Encoding.UTF8.GetBytes(tamperedJson));

        var result = LicenseService.ValidateLicenseDetailed(
            tamperedLicense,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890",
            new DateTime(2100, 01, 01, 00, 00, 00, DateTimeKind.Utc));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidSignature, result.ErrorCode);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("non-boolean")]
    public void ContractFixture_WithInvalidExpirationSnapshotContract_ShouldReturnInvalidFormat(string variant)
    {
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(ContractFixtureLicenseFile));
        var invalidJson = variant switch
        {
            "missing" => finalJson.Replace(",\"IsExpired\":false", string.Empty, StringComparison.Ordinal),
            "duplicate" => finalJson.Replace(
                "\"IsExpired\":false",
                "\"IsExpired\":false,\"IsExpired\":false",
                StringComparison.Ordinal),
            "non-boolean" => finalJson.Replace(
                "\"IsExpired\":false",
                "\"IsExpired\":\"false\"",
                StringComparison.Ordinal),
            _ => throw new InvalidOperationException("Unknown test variant.")
        };
        var invalidLicense = Convert.ToBase64String(Encoding.UTF8.GetBytes(invalidJson));

        var result = LicenseService.ValidateLicenseDetailed(
            invalidLicense,
            ContractFixturePublicKeyXml,
            "ABCDEF1234567890",
            new DateTime(2099, 12, 31, 23, 59, 58, DateTimeKind.Utc));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidFormat, result.ErrorCode);
        Assert.Equal("Format de licence invalide.", result.ErrorMessage);
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

    [Fact]
    public void GeneratedLicense_WithNonAsciiJson_ShouldVerifyAgainstFinalJsonBytes()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            Id = Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"),
            LicenseKey = "UNICODE-CONTRACT-0001",
            CustomerName = "Marko Jelov\u010dan <native> \"quoted\" \\ path & emoji \ud83d\ude00\nnext\tcell",
            CustomerEmail = "marko@example.invalid",
            TypeSlug = "TIA-UNICODE",
            CreationDate = new DateTime(2026, 07, 14, 12, 00, 00, DateTimeKind.Utc),
            ExpirationDate = new DateTime(2099, 12, 31, 23, 59, 59, DateTimeKind.Utc),
            HardwareId = "AF880A3C383020D7",
            Features = new Dictionary<string, string>
            {
                ["edition"] = "PRO",
                ["escaped"] = "line1\nline2\t\\\"<&> \ud83d\ude00"
            }
        };

        var licenseFile = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(licenseFile));
        using var document = JsonDocument.Parse(finalJson);
        var signature = document.RootElement.GetProperty("Signature").GetString();
        var signedJsonFromFinalFile = RewriteRootSignatureAsEmpty(document);

        Assert.Equal("Marko Jelov\u010dan <native> \"quoted\" \\ path & emoji \ud83d\ude00\nnext\tcell", document.RootElement.GetProperty("CustomerName").GetString());
        Assert.Contains("\\u003Cnative\\u003E", finalJson);
        Assert.Contains("\\u010D", finalJson);
        Assert.Contains("\\uD83D\\uDE00", finalJson);
        Assert.Contains("\\u0026", finalJson);
        Assert.Contains("\\n", finalJson);
        Assert.Contains("\\t", finalJson);
        Assert.True(VerifySignature(signedJsonFromFinalFile, signature!, keys.PublicKey));

        var managedResult = LicenseService.ValidateLicense(licenseFile, keys.PublicKey, "AF880A3C383020D7");
        Assert.True(managedResult.IsValid);
    }

    [Fact]
    public void GeneratedLicense_WithPlusInSignature_ShouldKeepSignatureAsRawBase64()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            Id = Guid.Parse("cccccccc-dddd-eeee-ffff-000000000001"),
            LicenseKey = "PLUS-SIGNATURE-CONTRACT-0001",
            CustomerName = "Marko Jelov\u010dan",
            CustomerEmail = "marko@example.invalid",
            TypeSlug = "TIA-CONNECT-PRO",
            CreationDate = new DateTime(2026, 07, 14, 12, 29, 00, DateTimeKind.Utc),
            ExpirationDate = new DateTime(2099, 12, 31, 23, 59, 59, DateTimeKind.Utc),
            HardwareId = "AF880A3C383020D7",
            Features = new Dictionary<string, string>
            {
                ["edition"] = "PRO"
            }
        };

        string? licenseFile = null;
        string? finalJson = null;
        string? rawSignature = null;

        for (var attempt = 0; attempt < 32; attempt++)
        {
            model.Reference = "force-plus-signature-" + attempt.ToString("D2");
            licenseFile = LicenseService.GenerateLicense(model, keys.PrivateKey);
            finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(licenseFile));
            rawSignature = ExtractRawJsonStringValue(finalJson, "Signature");

            if (rawSignature.Contains('+', StringComparison.Ordinal) &&
                rawSignature.Contains('/', StringComparison.Ordinal) &&
                rawSignature.Contains('=', StringComparison.Ordinal))
            {
                break;
            }
        }

        Assert.NotNull(licenseFile);
        Assert.NotNull(finalJson);
        Assert.NotNull(rawSignature);
        Assert.True(rawSignature.Contains('+', StringComparison.Ordinal));
        Assert.True(rawSignature.Contains('/', StringComparison.Ordinal));
        Assert.True(rawSignature.Contains('=', StringComparison.Ordinal));
        Assert.DoesNotContain("\\u002B", rawSignature);
        Assert.DoesNotContain("\\u002B", finalJson);
        Assert.Contains("Marko Jelov\\u010Dan", finalJson);

        var signedJsonFromFinalFile = ReplaceRawJsonStringValue(finalJson, "Signature", string.Empty);
        Assert.True(VerifySignature(signedJsonFromFinalFile, rawSignature, keys.PublicKey));

        var managedResult = LicenseService.ValidateLicense(licenseFile, keys.PublicKey, "AF880A3C383020D7");
        Assert.True(managedResult.IsValid);
    }

    [Fact]
    public void GeneratedLicense_WithReservedSignatureFeature_ShouldFailBeforeSigning()
    {
        var model = new LicenseModel
        {
            Features = new Dictionary<string, string>
            {
                ["Signature"] = "reserved"
            },
            Signature = "unchanged"
        };

        var exception = Assert.Throws<InvalidOperationException>(() =>
            LicenseService.GenerateLicense(model, "not-used"));

        Assert.Equal("La clé de feature 'Signature' est réservée au contrat de licence signé.", exception.Message);
        Assert.Equal("unchanged", model.Signature);
    }

    [Fact]
    public void FinalLicenseJson_ShouldReplaceOnlyRootSignatureProperty()
    {
        const string signedJson = "{\"Features\":{\"Signature\":\"\"},\"Signature\":\"\",\"IsExpired\":false}";
        const string signature = "A+/=";
        var method = typeof(LicenseService).GetMethod(
            "BuildFinalLicenseJson",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        var finalJson = (string)method.Invoke(null, new object[] { signedJson, signature })!;

        Assert.Equal("{\"Features\":{\"Signature\":\"\"},\"Signature\":\"A+/=\",\"IsExpired\":false}", finalJson);
    }

    [Fact]
    public void LegacyRelaxedJson_WithUnicode_ShouldRemainManagedCompatibleButNotExactByteCompatible()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            Id = Guid.Parse("dddddddd-eeee-ffff-0000-000000000001"),
            LicenseKey = "LEGACY-UNICODE-CONTRACT-0001",
            CustomerName = "Marko Jelov\u010dan <legacy>",
            CustomerEmail = "legacy@example.invalid",
            TypeSlug = "TIA-LEGACY-UNICODE",
            CreationDate = new DateTime(2026, 07, 13, 12, 00, 00, DateTimeKind.Utc),
            ExpirationDate = new DateTime(2099, 12, 31, 23, 59, 59, DateTimeKind.Utc),
            HardwareId = "LEGACY-HWID",
            Features = new Dictionary<string, string>
            {
                ["edition"] = "PRO"
            }
        };

        model.Signature = string.Empty;
        var signedJson = JsonSerializer.Serialize(model);
        using (var rsa = RSA.Create())
        {
            rsa.FromXmlString(keys.PrivateKey);
            model.Signature = Convert.ToBase64String(rsa.SignData(
                Encoding.UTF8.GetBytes(signedJson),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1));
        }

        var legacyFinalJson = JsonSerializer.Serialize(model, new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        var legacyLicense = Convert.ToBase64String(Encoding.UTF8.GetBytes(legacyFinalJson));
        var nativeStyleSignedJson = ReplaceRawJsonStringValue(legacyFinalJson, "Signature", string.Empty);

        var managedResult = LicenseService.ValidateLicense(legacyLicense, keys.PublicKey, "LEGACY-HWID");

        Assert.True(managedResult.IsValid);
        Assert.NotEqual(signedJson, nativeStyleSignedJson);
        Assert.False(VerifySignature(nativeStyleSignedJson, model.Signature, keys.PublicKey));
    }

    [Fact]
    public void GeneratedLicense_WithReorderedProperties_ShouldRemainManagedCompatibleButNotExactByteCompatible()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            Id = Guid.Parse("eeeeeeee-ffff-0000-1111-000000000001"),
            LicenseKey = "REORDERED-CONTRACT-0001",
            CustomerName = "Reordered Contract",
            CustomerEmail = "reordered@example.invalid",
            TypeSlug = "TIA-REORDERED",
            CreationDate = new DateTime(2026, 07, 15, 12, 00, 00, DateTimeKind.Utc),
            ExpirationDate = new DateTime(2099, 12, 31, 23, 59, 59, DateTimeKind.Utc),
            HardwareId = "REORDERED-HWID",
            Features = new Dictionary<string, string>
            {
                ["edition"] = "PRO"
            }
        };

        var licenseFile = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(licenseFile));
        using var document = JsonDocument.Parse(finalJson);
        var properties = document.RootElement.EnumerateObject().Reverse().ToArray();
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var property in properties)
            {
                property.WriteTo(writer);
            }
            writer.WriteEndObject();
        }

        var reorderedJson = Encoding.UTF8.GetString(stream.ToArray());
        var reorderedLicense = Convert.ToBase64String(stream.ToArray());
        var signature = document.RootElement.GetProperty("Signature").GetString()!;
        var nativeStyleSignedJson = ReplaceRawJsonStringValue(reorderedJson, "Signature", string.Empty);

        var managedResult = LicenseService.ValidateLicense(reorderedLicense, keys.PublicKey, "REORDERED-HWID");

        Assert.True(managedResult.IsValid);
        Assert.False(VerifySignature(nativeStyleSignedJson, signature, keys.PublicKey));
    }

    private static string RewriteRootSignatureAsEmpty(JsonDocument document)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.NameEquals("Signature"))
                {
                    writer.WriteString(property.Name, string.Empty);
                    continue;
                }

                property.WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string ExtractRawJsonStringValue(string json, string propertyName)
    {
        var marker = "\"" + propertyName + "\":\"";
        var valueStart = json.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(valueStart >= 0, $"Property {propertyName} was not found.");
        valueStart += marker.Length;

        var valueEnd = json.IndexOf('"', valueStart);
        Assert.True(valueEnd >= 0, $"Property {propertyName} string value was not terminated.");
        return json[valueStart..valueEnd];
    }

    private static string ReplaceRawJsonStringValue(string json, string propertyName, string replacementValue)
    {
        var marker = "\"" + propertyName + "\":\"";
        var valueStart = json.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(valueStart >= 0, $"Property {propertyName} was not found.");
        valueStart += marker.Length;

        var valueEnd = json.IndexOf('"', valueStart);
        Assert.True(valueEnd >= 0, $"Property {propertyName} string value was not terminated.");
        return string.Concat(json.AsSpan(0, valueStart), replacementValue, json.AsSpan(valueEnd));
    }

    private static bool VerifySignature(string signedJson, string signature, string publicKeyXml)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(publicKeyXml);
        return rsa.VerifyData(
            Encoding.UTF8.GetBytes(signedJson),
            Convert.FromBase64String(signature),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
    }
}

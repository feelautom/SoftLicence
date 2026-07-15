using System.Net;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

/// <summary>
/// Mock HttpMessageHandler for testing CheckOnlineStatusAsync without network.
/// </summary>
internal class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

    public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
    {
        _handler = handler;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(_handler(request));
    }
}

/// <summary>
/// Mock that throws on send, simulating a network error.
/// </summary>
internal class ThrowingHttpMessageHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        throw new HttpRequestException("Simulated network failure");
    }
}

public class LicenseServiceTests
{
    [Fact]
    public void GenerateKeys_ShouldReturnValidRsaKeys()
    {
        // Act
        var keys = LicenseService.GenerateKeys();

        // Assert
        Assert.Contains("<RSAKeyValue>", keys.PrivateKey);
        Assert.Contains("<P>", keys.PrivateKey); 
        Assert.Contains("<RSAKeyValue>", keys.PublicKey);
        Assert.DoesNotContain("<P>", keys.PublicKey);
    }

    [Fact]
    public void GenerateAndValidate_ShouldReturnValid_WhenDataIsCorrect()
    {
        // Arrange
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "TEST-KEY-123",
            CustomerName = "John Doe",
            CustomerEmail = "john@example.com",
            TypeSlug = "PRO",
            HardwareId = "HW-001",
            CreationDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddDays(30)
        };

        // Act
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var result = LicenseService.ValidateLicense(licenseString, keys.PublicKey, "HW-001");

        // Assert
        Assert.True(result.IsValid);
        Assert.NotNull(result.License);
        Assert.Equal("TEST-KEY-123", result.License.LicenseKey);
        Assert.Equal("PRO", result.License.TypeSlug);
    }

    [Fact]
    public void GenerateLicense_StandardLicense_ShouldRemainCompatibleWithLegacyModel()
    {
        // Arrange
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "STANDARD-KEY",
            CustomerName = "Jane Doe",
            CustomerEmail = "jane@example.com",
            TypeSlug = "PRO",
            HardwareId = "HW-LEGACY",
            CreationDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddDays(30)
        };

        // Act
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(licenseString));
        var legacyValid = ValidateWithLegacyModel(licenseString, keys.PublicKey);

        // Assert
        Assert.DoesNotContain("PluginId", finalJson);
        Assert.DoesNotContain("PluginVersion", finalJson);
        Assert.DoesNotContain("MinAppVersion", finalJson);
        Assert.DoesNotContain("AllowedFeatures", finalJson);
        Assert.True(legacyValid);
    }

    [Fact]
    public void GenerateLicense_PluginLicense_ShouldIncludePluginContractFields()
    {
        // Arrange
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "PLUGIN-KEY",
            CustomerName = "Plugin User",
            CustomerEmail = "plugin@example.com",
            TypeSlug = "PLUGIN",
            PluginId = "com.YOUR_APP_NAME.dnd",
            PluginVersion = "1.0.0",
            MinAppVersion = "1.1.70",
            AllowedFeatures = new[] { "*" },
            HardwareId = "HW-PLUGIN",
            CreationDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddDays(30)
        };

        // Act
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(licenseString));
        var result = LicenseService.ValidateLicense(licenseString, keys.PublicKey, "HW-PLUGIN");

        // Assert
        Assert.Contains("\"PluginId\":\"com.YOUR_APP_NAME.dnd\"", finalJson);
        Assert.Contains("\"PluginVersion\":\"1.0.0\"", finalJson);
        Assert.Contains("\"MinAppVersion\":\"1.1.70\"", finalJson);
        Assert.Contains("\"AllowedFeatures\":[\"*\"]", finalJson);
        Assert.True(result.IsValid);
        Assert.Equal("com.YOUR_APP_NAME.dnd", result.License!.PluginId);
    }

    [Fact]
    public void ValidateLicense_ShouldReturnExpired_WhenLicenseIsPastDate()
    {
        // Arrange
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "EXPIRED-KEY",
            ExpirationDate = DateTime.UtcNow.AddDays(-1)
        };

        // Act
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var result = LicenseService.ValidateLicense(licenseString, keys.PublicKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal("Licence expirée.", result.ErrorMessage);
    }

    [Fact]
    public void ValidateLicenseDetailed_WithoutExpiration_ShouldRemainValidAtAnyControlledInstant()
    {
        var keys = LicenseService.GenerateKeys();
        var licenseString = LicenseService.GenerateLicense(
            new LicenseModel
            {
                LicenseKey = "NO-EXPIRATION",
                ExpirationDate = null
            },
            keys.PrivateKey);

        var result = LicenseService.ValidateLicenseDetailed(
            licenseString,
            keys.PublicKey,
            currentHardwareId: null,
            utcNow: DateTime.MaxValue);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.None, result.ErrorCode);
    }

    [Fact]
    public void ValidateLicenseDetailed_WithFutureExpiration_ShouldRemainValid()
    {
        var keys = LicenseService.GenerateKeys();
        var expiration = new DateTime(2099, 01, 01, 00, 00, 00, DateTimeKind.Utc);
        var licenseString = LicenseService.GenerateLicense(
            new LicenseModel
            {
                LicenseKey = "FUTURE-EXPIRATION",
                ExpirationDate = expiration
            },
            keys.PrivateKey);

        var result = LicenseService.ValidateLicenseDetailed(
            licenseString,
            keys.PublicKey,
            currentHardwareId: null,
            utcNow: expiration.AddTicks(-1));

        Assert.True(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.None, result.ErrorCode);
    }

    [Fact]
    public void ValidateLicenseDetailed_WithHistoricallySignedTrueSnapshot_ShouldReturnExpired()
    {
        var keys = LicenseService.GenerateKeys();
        var expiration = new DateTime(2000, 01, 01, 00, 00, 00, DateTimeKind.Utc);
        var licenseString = LicenseService.GenerateLicense(
            new LicenseModel
            {
                LicenseKey = "SIGNED-AS-EXPIRED",
                ExpirationDate = expiration
            },
            keys.PrivateKey);
        var finalJson = Encoding.UTF8.GetString(Convert.FromBase64String(licenseString));

        var result = LicenseService.ValidateLicenseDetailed(
            licenseString,
            keys.PublicKey,
            currentHardwareId: null,
            utcNow: expiration.AddTicks(1));

        Assert.Contains("\"IsExpired\":true", finalJson, StringComparison.Ordinal);
        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.Expired, result.ErrorCode);
    }

    [Fact]
    public void ValidateLicense_ShouldReturnInvalid_WhenHardwareMismatch()
    {
        // Arrange
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "HW-KEY",
            HardwareId = "PC-A"
        };

        // Act
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var result = LicenseService.ValidateLicense(licenseString, keys.PublicKey, "PC-B");

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal("Cette licence n'est pas valide pour cette machine.", result.ErrorMessage);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateLicenseDetailed_BoundLicenseWithoutUsableCurrentHardwareId_ShouldFailClosed(string? currentHardwareId)
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "BOUND-HWID-REQUIRED",
            HardwareId = "HW-BOUND"
        };
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);

        var detailed = LicenseService.ValidateLicenseDetailed(licenseString, keys.PublicKey, currentHardwareId);
        var legacy = LicenseService.ValidateLicense(licenseString, keys.PublicKey, currentHardwareId);

        Assert.False(detailed.IsValid);
        Assert.Equal(LicenseValidationErrorCode.HardwareIdRequired, detailed.ErrorCode);
        Assert.Equal("Un hardware ID courant est requis pour valider cette licence.", detailed.ErrorMessage);
        Assert.Equal(detailed.IsValid, legacy.IsValid);
        Assert.Equal(detailed.License!.LicenseKey, legacy.License!.LicenseKey);
        Assert.Equal(detailed.ErrorMessage, legacy.ErrorMessage);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ValidateLicenseDetailed_UnboundLicenseWithoutCurrentHardwareId_ShouldRemainValid(string? signedHardwareId)
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "UNBOUND-COMPATIBILITY",
            HardwareId = signedHardwareId!
        };
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);

        var result = LicenseService.ValidateLicenseDetailed(licenseString, keys.PublicKey);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.None, result.ErrorCode);
    }

    [Fact]
    public void ValidateLicenseDetailed_UnboundLicense_ShouldIgnoreCurrentHardwareId()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "UNBOUND-ANY-MACHINE",
            HardwareId = string.Empty
        };
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);

        var whitespaceResult = LicenseService.ValidateLicenseDetailed(licenseString, keys.PublicKey, "   ");
        var otherMachineResult = LicenseService.ValidateLicenseDetailed(licenseString, keys.PublicKey, "HW-OTHER");

        Assert.True(whitespaceResult.IsValid);
        Assert.True(otherMachineResult.IsValid);
    }

    [Fact]
    public void ValidateLicenseDetailed_WhitespaceSignedHardwareId_ShouldRejectInvalidContract()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "INVALID-WHITESPACE-BINDING",
            HardwareId = "   "
        };
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);

        var result = LicenseService.ValidateLicenseDetailed(licenseString, keys.PublicKey, "   ");

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidHardwareBinding, result.ErrorCode);
    }

    [Fact]
    public void ValidateLicenseDetailed_HardwareIdComparison_ShouldRemainOrdinal()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "ORDINAL-HWID",
            HardwareId = "HW-CASE"
        };
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);

        var exact = LicenseService.ValidateLicenseDetailed(licenseString, keys.PublicKey, "HW-CASE");
        var differentCase = LicenseService.ValidateLicenseDetailed(licenseString, keys.PublicKey, "hw-case");

        Assert.True(exact.IsValid);
        Assert.Equal(LicenseValidationErrorCode.None, exact.ErrorCode);
        Assert.False(differentCase.IsValid);
        Assert.Equal(LicenseValidationErrorCode.HardwareIdMismatch, differentCase.ErrorCode);
    }

    [Fact]
    public void ValidateLicense_HistoricalSignature_ShouldRemainOptionalAndBinaryCompatible()
    {
        var method = typeof(LicenseService).GetMethod(
            nameof(LicenseService.ValidateLicense),
            new[] { typeof(string), typeof(string), typeof(string) });

        Assert.NotNull(method);
        var parameters = method.GetParameters();
        Assert.Equal(3, parameters.Length);
        Assert.True(parameters[2].IsOptional);
        Assert.Null(parameters[2].DefaultValue);
    }

    [Fact]
    public void ValidateLicenseDetailed_InvalidInput_ShouldReturnTypedErrorWithoutPayload()
    {
        const string invalidPayload = "not-a-license-payload";

        var result = LicenseService.ValidateLicenseDetailed(invalidPayload, "not-used");

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidFormat, result.ErrorCode);
        Assert.Equal("Format de licence invalide.", result.ErrorMessage);
        Assert.DoesNotContain(invalidPayload, result.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateLicenseDetailed_InvalidJson_ShouldNotExposeDecodedPayload()
    {
        const string sensitiveMarker = "SENSITIVE-JSON-MARKER";
        var invalidJson = $"{{\"marker\":\"{sensitiveMarker}\"";
        var licenseString = Convert.ToBase64String(Encoding.UTF8.GetBytes(invalidJson));

        var result = LicenseService.ValidateLicenseDetailed(licenseString, "not-used");

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidFormat, result.ErrorCode);
        Assert.Equal("Format de licence invalide.", result.ErrorMessage);
        Assert.DoesNotContain(sensitiveMarker, result.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateLicenseDetailed_CryptographicallyInvalidSignature_ShouldReturnInvalidSignature()
    {
        var keys = LicenseService.GenerateKeys();
        var licenseString = LicenseService.GenerateLicense(
            new LicenseModel { LicenseKey = "INVALID-SIGNATURE-BYTES" },
            keys.PrivateKey);
        var model = JsonSerializer.Deserialize<LicenseModel>(
            Encoding.UTF8.GetString(Convert.FromBase64String(licenseString)))!;
        model.Signature = Convert.ToBase64String(new byte[] { 1, 2, 3 });
        var alteredLicense = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(model)));

        var result = LicenseService.ValidateLicenseDetailed(alteredLicense, keys.PublicKey);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseValidationErrorCode.InvalidSignature, result.ErrorCode);
        Assert.Equal("Signature invalide. La licence a été altérée.", result.ErrorMessage);
    }

    [Fact]
    public void ValidateLicense_ShouldReturnInvalid_WhenSignatureIsTampered()
    {
        // Arrange
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel { LicenseKey = "VALID-KEY" };
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);

        // Decode from Base64
        var jsonBytes = Convert.FromBase64String(licenseString);
        var json = System.Text.Encoding.UTF8.GetString(jsonBytes);
        
        // Tamper with the JSON content (change one character in the LicenseKey)
        var tamperedJson = json.Replace("VALID-KEY", "TAMO-KEY");
        var tamperedString = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(tamperedJson));

        // Act
        var result = LicenseService.ValidateLicense(tamperedString, keys.PublicKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal("Signature invalide. La licence a été altérée.", result.ErrorMessage);
    }

    // ── CheckOnlineStatusAsync tests ──

    [Fact]
    public async Task CheckOnline_ShouldReturnValid_When200()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"status\":\"VALID\"}", Encoding.UTF8, "application/json")
            });
        using var client = new HttpClient(handler);

        // Act
        var result = await LicenseService.CheckOnlineStatusAsync(client, "http://localhost", "TestApp", "KEY-123", "HW-001");

        // Assert
        Assert.Equal("VALID", result);
    }

    [Fact]
    public async Task CheckOnline_ShouldReturnNotFound_When404()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.NotFound));
        using var client = new HttpClient(handler);

        // Act
        var result = await LicenseService.CheckOnlineStatusAsync(client, "http://localhost", "TestApp", "KEY-123", "HW-001");

        // Assert
        Assert.Equal("NOT_FOUND", result);
    }

    [Fact]
    public async Task CheckOnline_ShouldReturnServerError_When500()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var client = new HttpClient(handler);

        // Act
        var result = await LicenseService.CheckOnlineStatusAsync(client, "http://localhost", "TestApp", "KEY-123", "HW-001");

        // Assert
        Assert.Equal("SERVER_ERROR", result);
    }

    [Fact]
    public async Task CheckOnline_ShouldReturnNetworkError_OnException()
    {
        // Arrange
        var handler = new ThrowingHttpMessageHandler();
        using var client = new HttpClient(handler);

        // Act
        var result = await LicenseService.CheckOnlineStatusAsync(client, "http://localhost", "TestApp", "KEY-123", "HW-001");

        // Assert
        Assert.Equal("NETWORK_ERROR", result);
    }

    [Fact]
    public async Task CheckOnline_ShouldReturnRevoked_When200()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"status\":\"REVOKED\"}", Encoding.UTF8, "application/json")
            });
        using var client = new HttpClient(handler);

        // Act
        var result = await LicenseService.CheckOnlineStatusAsync(client, "http://localhost", "TestApp", "KEY-123", "HW-001");

        // Assert
        Assert.Equal("REVOKED", result);
    }

    private static bool ValidateWithLegacyModel(string licenseString, string publicKeyXml)
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(licenseString));
        var model = JsonSerializer.Deserialize<LegacyLicenseModel>(json);
        if (model == null || string.IsNullOrEmpty(model.Signature))
            return false;

        var signature = model.Signature;
        model.Signature = string.Empty;
        var signedJson = JsonSerializer.Serialize(model);

        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.FromXmlString(publicKeyXml);
        return rsa.VerifyData(
            Encoding.UTF8.GetBytes(signedJson),
            Convert.FromBase64String(signature),
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
    }

    private sealed class LegacyLicenseModel
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string LicenseKey { get; set; } = string.Empty;
        public string CustomerName { get; set; } = string.Empty;
        public string CustomerEmail { get; set; } = string.Empty;
        public string TypeSlug { get; set; } = "STANDARD";
        public string? Reference { get; set; }
        public DateTime CreationDate { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string HardwareId { get; set; } = string.Empty;
        public Dictionary<string, string> Features { get; set; } = new();
        public string Signature { get; set; } = string.Empty;
        public bool IsExpired => ExpirationDate.HasValue && DateTime.UtcNow > ExpirationDate.Value;
    }
}

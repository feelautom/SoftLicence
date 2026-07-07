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

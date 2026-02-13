using SoftLicence.Core;
using Xunit;

namespace SoftLicence.Tests.Core;

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
}
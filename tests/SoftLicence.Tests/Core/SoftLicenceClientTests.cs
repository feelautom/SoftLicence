using System.Net;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

public class SoftLicenceClientTests
{
    private const string ServerUrl = "http://localhost:5200";

    private static SoftLicenceClient CreateClient(HttpMessageHandler handler, string? publicKeyXml = null)
    {
        var httpClient = new HttpClient(handler);
        return new SoftLicenceClient(ServerUrl, publicKeyXml, httpClient);
    }

    // ── ActivateAsync ──

    [Fact]
    public async Task ActivateAsync_ShouldReturnSuccess_When200()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"LicenseFile\":\"abc\"}", Encoding.UTF8, "application/json")
            });

        var client = CreateClient(handler);
        var result = await client.ActivateAsync("KEY-123", "TestApp");

        Assert.True(result.Success);
        Assert.Equal("abc", result.LicenseFile);
        Assert.Equal(ActivationErrorCode.None, result.ErrorCode);
    }

    [Fact]
    public async Task ActivateAsync_ShouldSendAppId_WhenProvided()
    {
        string? capturedPayload = null;
        var handler = new MockHttpMessageHandler(request =>
        {
            capturedPayload = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"LicenseFile\":\"abc\"}", Encoding.UTF8, "application/json")
            };
        });

        var client = CreateClient(handler);
        await client.ActivateAsync("KEY-123", "TestApp", "APP-GUID-123");

        Assert.NotNull(capturedPayload);
        Assert.Contains("\"AppId\":\"APP-GUID-123\"", capturedPayload);
    }

    [Fact]
    public async Task ActivateAsync_ShouldSendStableHardwareIdAsSecondaryObservationSignal()
    {
        using var readerOverride = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-1",
                "Win32_BaseBoard" => "MB-1",
                "Win32_BIOS" => "BIOS-1",
                "Win32_DiskDrive" when whereClause == "Index=0" => "SYSTEM-DISK",
                "Win32_DiskDrive" => "LEGACY-DISK",
                _ => "UNKNOWN"
            });

        string? capturedPayload = null;
        var handler = new MockHttpMessageHandler(request =>
        {
            capturedPayload = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"LicenseFile\":\"abc\"}", Encoding.UTF8, "application/json")
            };
        });

        var client = CreateClient(handler);
        await client.ActivateAsync("KEY-123", "TestApp");

        Assert.NotNull(capturedPayload);
        using var doc = JsonDocument.Parse(capturedPayload);
        var root = doc.RootElement;

        Assert.Equal(HardwareInfo.GetHardwareId(), root.GetProperty("HardwareId").GetString());
        Assert.Equal(HardwareInfo.GetStableHardwareId(), root.GetProperty("HardwareIdV2").GetString());
        Assert.True(root.GetProperty("HardwareIdV2Differs").GetBoolean());
        Assert.Equal("legacy-wmi-first-disk", root.GetProperty("HardwareIdAlgorithm").GetString());
        Assert.Equal("v2-wmi-disk-index-0", root.GetProperty("HardwareIdV2Algorithm").GetString());
        Assert.Equal("1.1.11", root.GetProperty("SdkVersion").GetString());
    }

    [Fact]
    public async Task ActivateAsync_ShouldReturnFail_When400()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("Invalid license key", Encoding.UTF8, "text/plain")
            });

        var client = CreateClient(handler);
        var result = await client.ActivateAsync("BAD-KEY", "TestApp");

        Assert.False(result.Success);
        Assert.NotEqual(ActivationErrorCode.None, result.ErrorCode);
        Assert.NotNull(result.ErrorMessage);
    }

    [Fact]
    public async Task ActivateAsync_ShouldReturnServerError_When500()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("Internal error", Encoding.UTF8, "text/plain")
            });

        var client = CreateClient(handler);
        var result = await client.ActivateAsync("KEY-123", "TestApp");

        Assert.False(result.Success);
        Assert.Equal(ActivationErrorCode.ServerError, result.ErrorCode);
    }

    [Fact]
    public async Task ActivateAsync_ShouldReturnNetworkError_OnException()
    {
        var handler = new ThrowingHttpMessageHandler();
        var client = CreateClient(handler);
        var result = await client.ActivateAsync("KEY-123", "TestApp");

        Assert.False(result.Success);
        Assert.Equal(ActivationErrorCode.NetworkError, result.ErrorCode);
    }

    // ── RequestTrialAsync ──

    [Fact]
    public async Task RequestTrialAsync_ShouldReturnSuccess_When200()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"LicenseFile\":\"trial\"}", Encoding.UTF8, "application/json")
            });

        var client = CreateClient(handler);
        var result = await client.RequestTrialAsync("TestApp", "TRIAL");

        Assert.True(result.Success);
        Assert.Equal("trial", result.LicenseFile);
    }

    [Fact]
    public async Task RequestTrialAsync_ShouldReturnFail_When400()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("Product not found", Encoding.UTF8, "text/plain")
            });

        var client = CreateClient(handler);
        var result = await client.RequestTrialAsync("TestApp", "TRIAL");

        Assert.False(result.Success);
    }

    [Fact]
    public async Task RequestTrialAsync_ShouldReturnNetworkError_OnException()
    {
        var handler = new ThrowingHttpMessageHandler();
        var client = CreateClient(handler);
        var result = await client.RequestTrialAsync("TestApp", "TRIAL");

        Assert.False(result.Success);
        Assert.Equal(ActivationErrorCode.NetworkError, result.ErrorCode);
    }

    // ── CheckStatusAsync ──

    [Fact]
    public async Task CheckStatusAsync_ShouldReturnValid_When200()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"Status\":\"VALID\"}", Encoding.UTF8, "application/json")
            });

        var client = CreateClient(handler);
        var result = await client.CheckStatusAsync("KEY-123", "TestApp");

        Assert.True(result.Success);
        Assert.Equal("VALID", result.Status);
    }

    [Fact]
    public async Task CheckStatusAsync_ShouldSendAppVersion_WhenProvided()
    {
        string? capturedPayload = null;
        var handler = new MockHttpMessageHandler(request =>
        {
            capturedPayload = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"Status\":\"VALID\"}", Encoding.UTF8, "application/json")
            };
        });

        var client = CreateClient(handler);
        await client.CheckStatusAsync("KEY-123", "TestApp", appId: "APP-GUID-123", appVersion: "1.1.91");

        Assert.NotNull(capturedPayload);
        Assert.Contains("\"AppId\":\"APP-GUID-123\"", capturedPayload);
        Assert.Contains("\"AppVersion\":\"1.1.91\"", capturedPayload);
    }

    [Fact]
    public async Task CheckStatusAsync_ShouldOmitStableHardwareId_WhenIndexZeroIsUnavailable()
    {
        using var _ = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
            className switch
            {
                "Win32_Processor" => "CPU-1",
                "Win32_BaseBoard" => "MB-1",
                "Win32_BIOS" => "BIOS-1",
                "Win32_DiskDrive" when whereClause == "Index=0" => "",
                "Win32_DiskDrive" => "LEGACY-DISK",
                _ => "UNKNOWN"
            });

        string? capturedPayload = null;
        var handler = new MockHttpMessageHandler(request =>
        {
            capturedPayload = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"Status\":\"VALID\"}", Encoding.UTF8, "application/json")
            };
        });

        var client = CreateClient(handler);
        await client.CheckStatusAsync("KEY-123", "TestApp");

        Assert.NotNull(capturedPayload);
        using var doc = JsonDocument.Parse(capturedPayload);
        var root = doc.RootElement;

        Assert.Equal(HardwareInfo.GetHardwareId(), root.GetProperty("HardwareId").GetString());
        Assert.False(root.TryGetProperty("HardwareIdV2", out var hardwareIdV2Property));
        Assert.False(root.TryGetProperty("HardwareIdV2Differs", out var hardwareIdV2DiffersProperty));
        Assert.False(root.TryGetProperty("HardwareIdV2Algorithm", out var hardwareIdV2AlgorithmProperty));
        Assert.Equal("1.1.11", root.GetProperty("SdkVersion").GetString());
    }

    [Fact]
    public async Task CheckStatusAsync_ShouldReturnServerMessage_WhenStatusContainsErrorMessage()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"status\":\"FREEMIUM_HWID_ALREADY_CONSUMED\",\"errorMessage\":\"Freemium access has already been used on this machine.\"}",
                    Encoding.UTF8,
                    "application/json")
            });

        var client = CreateClient(handler);
        var result = await client.CheckStatusAsync("KEY-123", "TestApp");

        Assert.True(result.Success);
        Assert.Equal("FREEMIUM_HWID_ALREADY_CONSUMED", result.Status);
        Assert.Equal("Freemium access has already been used on this machine.", result.ErrorMessage);
    }

    [Fact]
    public async Task CheckStatusAsync_ShouldReturnNotFound_When404()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.NotFound));

        var client = CreateClient(handler);
        var result = await client.CheckStatusAsync("KEY-123", "TestApp");

        Assert.True(result.Success);
        Assert.Equal("NOT_FOUND", result.Status);
    }

    [Fact]
    public async Task CheckStatusAsync_ShouldReturnServerError_When500()
    {
        var handler = new MockHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("Internal error", Encoding.UTF8, "text/plain")
            });

        var client = CreateClient(handler);
        var result = await client.CheckStatusAsync("KEY-123", "TestApp");

        Assert.False(result.Success);
        Assert.Equal(StatusErrorCode.ServerError, result.ErrorCode);
    }

    [Fact]
    public async Task CheckStatusAsync_ShouldReturnNetworkError_OnException()
    {
        var handler = new ThrowingHttpMessageHandler();
        var client = CreateClient(handler);
        var result = await client.CheckStatusAsync("KEY-123", "TestApp");

        Assert.False(result.Success);
        Assert.Equal(StatusErrorCode.NetworkError, result.ErrorCode);
    }

    // ── ValidateLocal ──

    [Fact]
    public void ValidateLocal_ShouldValidate_WhenPublicKeyProvided()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "LOCAL-TEST",
            CustomerName = "Test User",
            HardwareId = "HW-LOCAL",
            CreationDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddDays(30)
        };

        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var client = new SoftLicenceClient(ServerUrl, keys.PublicKey);
        var result = client.ValidateLocal(licenseString, "HW-LOCAL");

        Assert.True(result.IsValid);
        Assert.NotNull(result.License);
        Assert.Equal("LOCAL-TEST", result.License.LicenseKey);
    }

    [Fact]
    public async Task ValidateLocalAsync_ShouldValidateCorrectly()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "ASYNC-TEST",
            HardwareId = "HW-ASYNC"
        };

        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var client = new SoftLicenceClient(ServerUrl, keys.PublicKey);
        var result = await client.ValidateLocalAsync(licenseString, "HW-ASYNC");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void ValidateForCurrentMachine_ShouldUseCurrentHwid()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "CURRENT-TEST",
            HardwareId = HardwareInfo.GetHardwareId()
        };

        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var client = new SoftLicenceClient(ServerUrl, keys.PublicKey);
        var result = client.ValidateForCurrentMachine(licenseString);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void ValidateLocal_ShouldThrow_WhenNoPublicKey()
    {
        var client = new SoftLicenceClient(ServerUrl);

        Assert.Throws<InvalidOperationException>(() =>
            client.ValidateLocal("some-license-data", "HW-001"));
    }
}

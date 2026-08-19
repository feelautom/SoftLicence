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
        Assert.Equal("1.1.14", root.GetProperty("SdkVersion").GetString());
    }

    [Fact]
    public async Task ActivateAsync_WithExplicitAuthority_SendsAuthorityAsPrimaryIdentity()
    {
        using var readerOverride = HardwareInfo.UseWmiPropertyReaderForTests((_, _, _) =>
            throw new InvalidOperationException("Optional component collection is unavailable."));
        string? capturedPayload = null;
        var handler = new MockHttpMessageHandler(request =>
        {
            capturedPayload = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"LicenseFile\":\"abc\"}", Encoding.UTF8, "application/json")
            };
        });

        await CreateClient(handler).ActivateAsync(
            "KEY-123", "TestApp", null, "2.3.394", null, null, "A6D3ABCD1234EF90");

        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.Equal("A6D3ABCD1234EF90", document.RootElement.GetProperty("HardwareId").GetString());
        Assert.Equal("1.1.14", document.RootElement.GetProperty("SdkVersion").GetString());
        Assert.False(document.RootElement.TryGetProperty("HardwareIdV2", out _));
        Assert.False(document.RootElement.TryGetProperty("HardwareIdAlgorithm", out _));
        Assert.False(document.RootElement.TryGetProperty("HardwareIdV2Algorithm", out _));
        Assert.False(document.RootElement.TryGetProperty("ComponentFingerprints", out _));
    }

    [Fact]
    public async Task ActivateAsync_WithExplicitAuthority_PreservesOptionalComponentFingerprints()
    {
        var legacyDiskReadCount = 0;
        var stableDiskReadCount = 0;
        using var readerOverride = HardwareInfo.UseWmiPropertyReaderForTests((className, propertyName, whereClause) =>
        {
            if (className == "Win32_DiskDrive")
            {
                if (whereClause == null)
                    Interlocked.Increment(ref legacyDiskReadCount);
                else if (whereClause == "Index=0")
                    Interlocked.Increment(ref stableDiskReadCount);
            }
            return $"{className}:{propertyName}";
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

        await CreateClient(handler).ActivateAsync(
            "KEY-123", "TestApp", null, null, null, null, "A6D3ABCD1234EF90");

        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.True(document.RootElement.TryGetProperty("ComponentFingerprints", out var fingerprints));
        Assert.True(fingerprints.EnumerateObject().Any());
        Assert.Equal(1, legacyDiskReadCount);
        Assert.Equal(0, stableDiskReadCount);
        Assert.False(document.RootElement.TryGetProperty("HardwareIdV2", out _));
        Assert.False(document.RootElement.TryGetProperty("HardwareIdAlgorithm", out _));
    }

    [Theory]
    [InlineData("a6d3abcd1234ef90")]
    [InlineData("A6D3ABCD1234EF9")]
    [InlineData("A6D3ABCD1234EF9Z")]
    [InlineData(" A6D3ABCD1234EF90")]
    public async Task ActivateAsync_WithNonCanonicalExplicitAuthority_RejectsBeforeNetwork(string hardwareId)
    {
        var handler = new MockHttpMessageHandler(_ => throw new InvalidOperationException("No request expected."));
        var client = CreateClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => client.ActivateAsync(
            "KEY-123", "TestApp", null, null, null, null, hardwareId));
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
        Assert.True(result.UsedLegacyErrorFallback);
    }

    [Fact]
    public async Task ActivateAsync_ShouldMapStructuredCodeExactly_RegardlessOfLocalizedMessage()
    {
        var handler = new MockHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("{\"message\":\"Cette traduction ne contient aucun mot-clé historique.\"}", Encoding.UTF8, "application/json")
            };
            response.Headers.Add("X-SoftLicence-Error-Code", "LICENSE_EXPIRED");
            response.Headers.Add("X-SoftLicence-Correlation-Id", "corr-safe-123");
            return response;
        });

        var result = await CreateClient(handler).ActivateAsync("KEY-123", "TestApp");

        Assert.Equal(ActivationErrorCode.LicenseExpired, result.ErrorCode);
        Assert.Equal("LICENSE_EXPIRED", result.ServerErrorCode);
        Assert.Equal("corr-safe-123", result.CorrelationId);
        Assert.Equal("Cette traduction ne contient aucun mot-clé historique.", result.ErrorMessage);
        Assert.False(result.UsedLegacyErrorFallback);
    }

    [Theory]
    [InlineData("license_expired")]
    [InlineData("UNKNOWN_FUTURE_CODE")]
    public async Task ActivateAsync_ShouldFailClosed_WhenStructuredCodeIsNotCanonical(string serverCode)
    {
        var handler = new MockHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("expired", Encoding.UTF8, "text/plain")
            };
            response.Headers.Add("X-SoftLicence-Error-Code", serverCode);
            return response;
        });

        var result = await CreateClient(handler).ActivateAsync("KEY-123", "TestApp");

        Assert.Equal(ActivationErrorCode.ServerError, result.ErrorCode);
        Assert.Equal(serverCode, result.ServerErrorCode);
        Assert.False(result.UsedLegacyErrorFallback);
    }

    [Fact]
    public async Task ActivateAsync_ShouldFailClosed_WhenStructuredCodeHeaderIsDuplicated()
    {
        var handler = new MockHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("expired", Encoding.UTF8, "text/plain")
            };
            response.Headers.TryAddWithoutValidation("X-SoftLicence-Error-Code", new[] { "LICENSE_EXPIRED", "INVALID_LICENSE_KEY" });
            return response;
        });

        var result = await CreateClient(handler).ActivateAsync("KEY-123", "TestApp");

        Assert.Equal(ActivationErrorCode.ServerError, result.ErrorCode);
        Assert.Null(result.ServerErrorCode);
        Assert.False(result.UsedLegacyErrorFallback);
    }

    [Fact]
    public async Task ActivateAsync_ShouldHonorStructuredFailureReturnedWithLegacyHttp200()
    {
        var handler = new MockHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"isSuccess\":false,\"errorCode\":\"BANNED\",\"message\":\"Access denied by server\",\"correlationId\":\"opaque\",\"contractVersion\":1}", Encoding.UTF8, "application/json")
            };
            response.Headers.Add("X-SoftLicence-Error-Code", "BANNED");
            response.Headers.Add("X-SoftLicence-Correlation-Id", "opaque");
            return response;
        });

        var result = await CreateClient(handler).ActivateAsync("KEY-123", "TestApp");

        Assert.False(result.Success);
        Assert.Equal(ActivationErrorCode.LicenseDisabled, result.ErrorCode);
        Assert.Equal("opaque", result.CorrelationId);
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
        Assert.Equal("1.1.14", root.GetProperty("SdkVersion").GetString());
    }

    [Fact]
    public async Task CheckStatusAsync_WithExplicitAuthority_SendsAuthorityAsPrimaryIdentity()
    {
        var diskReadCount = 0;
        using var readerOverride = HardwareInfo.UseWmiPropertyReaderForTests((_, _, _) =>
        {
            Interlocked.Increment(ref diskReadCount);
            throw new InvalidOperationException("Optional component collection is unavailable.");
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

        await CreateClient(handler).CheckStatusAsync(
            "KEY-123", "TestApp", null, "2.3.394", "A6D3ABCD1234EF90");

        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.Equal("A6D3ABCD1234EF90", document.RootElement.GetProperty("HardwareId").GetString());
        Assert.Equal("1.1.14", document.RootElement.GetProperty("SdkVersion").GetString());
        Assert.Equal(1, diskReadCount);
        Assert.False(document.RootElement.TryGetProperty("HardwareIdV2", out _));
        Assert.False(document.RootElement.TryGetProperty("HardwareIdAlgorithm", out _));
        Assert.False(document.RootElement.TryGetProperty("HardwareIdV2Algorithm", out _));
        Assert.False(document.RootElement.TryGetProperty("ComponentFingerprints", out _));
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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateLocal_ShouldThrow_WhenHardwareIdIsMissingOrWhitespace(string? hardwareId)
    {
        var keys = LicenseService.GenerateKeys();
        var client = new SoftLicenceClient(ServerUrl, keys.PublicKey);

        var exception = Assert.Throws<ArgumentException>(() =>
            client.ValidateLocal("not-used", hardwareId!));

        Assert.Equal("hardwareId", exception.ParamName);
    }

    [Fact]
    public void ValidateLocal_UnboundLicenseWithExplicitHardwareId_ShouldRemainValid()
    {
        var keys = LicenseService.GenerateKeys();
        var model = new LicenseModel
        {
            LicenseKey = "LOCAL-UNBOUND",
            HardwareId = string.Empty
        };
        var licenseString = LicenseService.GenerateLicense(model, keys.PrivateKey);
        var client = new SoftLicenceClient(ServerUrl, keys.PublicKey);

        var result = client.ValidateLocal(licenseString, "HW-CURRENT");

        Assert.True(result.IsValid);
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

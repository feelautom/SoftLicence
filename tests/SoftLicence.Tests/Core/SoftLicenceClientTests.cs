using System.Net;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Core;

[Collection(MachineIdentityReadersCollection.Name)]
public class SoftLicenceClientTests : IDisposable
{
    private const string ServerUrl = "http://localhost:5200";
    private const string TestUuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";

    private readonly IDisposable _wmi = UseUuid(TestUuid);
    private readonly IDisposable _registry = MachineIdentity.UseRegistryValueReaderForTests((_, _, _) => MachineEvidenceValue.Unsupported());

    /// <summary>Restores the real machine readers after each test.</summary>
    public void Dispose()
    {
        _registry.Dispose();
        _wmi.Dispose();
    }

    /// <summary>Simulates a machine whose system UUID is <paramref name="uuid"/> (<c>null</c>: no UUID instance).</summary>
    private static IDisposable UseUuid(string? uuid) =>
        MachineIdentity.UseWmiQueryReaderForTests((className, properties) =>
        {
            if (className == "Win32_ComputerSystemProduct")
                return uuid is null
                    ? WmiQueryResult.Success(Array.Empty<IReadOnlyDictionary<string, string?>>())
                    : WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[] { new Dictionary<string, string?> { ["UUID"] = uuid } });
            return WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
            {
                properties.ToDictionary(property => property, property => (string?)(className + "." + property))
            });
        });

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
    public async Task ActivateAsync_SendsUuidDerivedIdentifier_SystemUuid_AndEvidence()
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

        await CreateClient(handler).ActivateAsync("KEY-123", "TestApp");

        using var doc = JsonDocument.Parse(capturedPayload!);
        var root = doc.RootElement;
        Assert.Equal(MachineIdentity.FromUuid(TestUuid).HardwareId, root.GetProperty("HardwareId").GetString());
        Assert.Equal(TestUuid, root.GetProperty("SystemUuid").GetString());
        var evidence = root.GetProperty("MachineEvidence");
        Assert.Equal("Present", evidence.GetProperty("SystemUuid").GetProperty("Status").GetString());
        Assert.Equal("Win32_BIOS.SerialNumber", evidence.GetProperty("BiosSerial").GetProperty("Value").GetString());
        Assert.Equal("2.0.0", root.GetProperty("SdkVersion").GetString());
        Assert.False(root.TryGetProperty("HardwareIdV2", out _));
        Assert.False(root.TryGetProperty("HardwareIdAlgorithm", out _));
        Assert.False(root.TryGetProperty("ComponentFingerprints", out _));
    }

    [Fact]
    public async Task ActivateAsync_RefusedUuid_FailsLocallyWithSupportCode_WithoutNetwork()
    {
        using var _ = UseUuid("03000200-0400-0500-0006-000700080009");
        var handler = new MockHttpMessageHandler(_ => throw new InvalidOperationException("No request expected."));

        var result = await CreateClient(handler).ActivateAsync("KEY-123", "TestApp");

        Assert.False(result.Success);
        Assert.Equal(ActivationErrorCode.DeviceRefused, result.ErrorCode);
        Assert.Equal("Device refused (code AR-04).", result.ErrorMessage);
        Assert.Equal("DEVICE_REFUSED", result.ServerErrorCode);
    }

    [Fact]
    public async Task ActivateAsync_ServerDeviceRefused_MapsToDeviceRefused()
    {
        var handler = new MockHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"isSuccess\":false,\"errorCode\":\"DEVICE_REFUSED\",\"message\":\"Appareil refusé (code AR-05).\"}", Encoding.UTF8, "application/json")
            };
            response.Headers.Add("X-SoftLicence-Error-Code", "DEVICE_REFUSED");
            return response;
        });

        var result = await CreateClient(handler).ActivateAsync("KEY-123", "TestApp");

        Assert.Equal(ActivationErrorCode.DeviceRefused, result.ErrorCode);
        Assert.Equal("Appareil refusé (code AR-05).", result.ErrorMessage);
    }

    /// <summary>
    /// TKT-001277 lot 5: a held identifier that is not derived from this machine's UUID is a pre-UUID seat identifier;
    /// neither the UUID nor the evidence is sent, so the server does not refuse it as not derived (AR-05).
    /// </summary>
    [Fact]
    public async Task ActivateAsync_WithPreUuidAuthority_SendsNeitherUuidNorEvidence()
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

        await CreateClient(handler).ActivateAsync(
            "KEY-123", "TestApp", null, "2.3.394", null, null, "A6D3ABCD1234EF90");

        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.Equal("A6D3ABCD1234EF90", document.RootElement.GetProperty("HardwareId").GetString());
        Assert.False(document.RootElement.TryGetProperty("SystemUuid", out _));
        Assert.False(document.RootElement.TryGetProperty("MachineEvidence", out _));
        Assert.Equal("2.0.0", document.RootElement.GetProperty("SdkVersion").GetString());
        Assert.False(document.RootElement.TryGetProperty("ComponentFingerprints", out _));
    }

    /// <summary>A held identifier equal to the one derived from this machine's UUID is sent with the UUID and evidence.</summary>
    [Fact]
    public async Task ActivateAsync_WithUuidDerivedAuthority_SendsUuidAndEvidence()
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
        var derived = MachineIdentity.FromUuid(TestUuid).HardwareId!;

        await CreateClient(handler).ActivateAsync("KEY-123", "TestApp", null, null, null, null, derived);

        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.Equal(derived, document.RootElement.GetProperty("HardwareId").GetString());
        Assert.Equal(TestUuid, document.RootElement.GetProperty("SystemUuid").GetString());
        Assert.True(document.RootElement.TryGetProperty("MachineEvidence", out _));
    }

    [Fact]
    public async Task ActivateReplacingHardwareIdAsync_SendsCurrentIdentity_AndPreviousIdentifier()
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

        var result = await CreateClient(handler).ActivateReplacingHardwareIdAsync("KEY-123", "TestApp", "0123456789ABCDEF");

        Assert.True(result.Success);
        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.Equal(MachineIdentity.FromUuid(TestUuid).HardwareId, document.RootElement.GetProperty("HardwareId").GetString());
        Assert.Equal("0123456789ABCDEF", document.RootElement.GetProperty("PreviousHardwareId").GetString());
        Assert.Equal(TestUuid, document.RootElement.GetProperty("SystemUuid").GetString());
    }

    [Theory]
    [InlineData("0123456789abcdef")]
    [InlineData("0123456789ABCDE")]
    [InlineData(" 0123456789ABCDEF")]
    public async Task ActivateReplacingHardwareIdAsync_NonCanonicalPrevious_RejectsBeforeNetwork(string previous)
    {
        var handler = new MockHttpMessageHandler(_ => throw new InvalidOperationException("No request expected."));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            CreateClient(handler).ActivateReplacingHardwareIdAsync("KEY-123", "TestApp", previous));
    }

    [Fact]
    public async Task ActivateAsync_ServerQuotaExhaustedOnSwitch_MapsToMaxActivationsReached()
    {
        var handler = new MockHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("Limite de déliements quotidiens atteinte (3/jour). Réessayez demain.")
            };
            response.Headers.Add("X-SoftLicence-Error-Code", "MAX_DAILY_DEACTIVATIONS_REACHED");
            return response;
        });

        var result = await CreateClient(handler).ActivateReplacingHardwareIdAsync("KEY-123", "TestApp", "0123456789ABCDEF");

        Assert.Equal(ActivationErrorCode.MaxActivationsReached, result.ErrorCode);
    }

    [Fact]
    public async Task ActivateAsync_WithExplicitAuthority_WithoutUuid_SendsNoUuid()
    {
        using var noUuid = UseUuid(null);
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
        Assert.False(document.RootElement.TryGetProperty("SystemUuid", out _));
        Assert.False(document.RootElement.TryGetProperty("MachineEvidence", out _));
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

    /// <summary>SDK 2 classifies the stable HTTP200 header for activation and trial without falling back to text.</summary>
    [Theory]
    [InlineData(false, "APP_VERSION_REQUIRED")]
    [InlineData(false, "APP_VERSION_INVALID")]
    [InlineData(false, "APP_VERSION_BELOW_MINIMUM")]
    [InlineData(true, "APP_VERSION_REQUIRED")]
    [InlineData(true, "APP_VERSION_INVALID")]
    [InlineData(true, "APP_VERSION_BELOW_MINIMUM")]
    public async Task Tkt1469_ActivationAndTrial_UpdateRequired_IsVersionNotAllowed(bool trial, string reason)
    {
        // The paired PostgreSQL HTTP matrix verifies that the provider actually emits this envelope/header.
        var handler = new MockHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { isSuccess = false,
                    status = "UPDATE_REQUIRED", errorCode = "UPDATE_REQUIRED", reasonCode = reason,
                    message = "Update required by server", contractVersion = 1 }), Encoding.UTF8, "application/json")
            };
            response.Headers.Add("X-SoftLicence-Error-Code", "UPDATE_REQUIRED");
            response.Headers.Add("X-SoftLicence-Correlation-Id", "tkt1469-synthetic");
            return response;
        });
        var client = CreateClient(handler);
        var result = trial ? await client.RequestTrialAsync("TIAConnect", appVersion: "2.1.357")
            : await client.ActivateAsync("KEY-SYNTHETIC", "TIAConnect", appVersion: "2.1.357");
        Assert.False(result.Success);
        Assert.Equal(ActivationErrorCode.VersionNotAllowed, result.ErrorCode);
        Assert.Equal("UPDATE_REQUIRED", result.ServerErrorCode);
        Assert.Equal("tkt1469-synthetic", result.CorrelationId);
        Assert.False(result.UsedLegacyErrorFallback);
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
    public async Task CheckStatusAsync_SendsUuidDerivedIdentifier_AndSystemUuid()
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

        await CreateClient(handler).CheckStatusAsync("KEY-123", "TestApp");

        using var doc = JsonDocument.Parse(capturedPayload!);
        var root = doc.RootElement;
        Assert.Equal(MachineIdentity.FromUuid(TestUuid).HardwareId, root.GetProperty("HardwareId").GetString());
        Assert.Equal(TestUuid, root.GetProperty("SystemUuid").GetString());
        Assert.True(root.TryGetProperty("MachineEvidence", out _));
        Assert.Equal("2.0.0", root.GetProperty("SdkVersion").GetString());
        Assert.False(root.TryGetProperty("HardwareIdV2", out _));
    }

    [Fact]
    public async Task CheckStatusAsync_MissingUuid_FailsLocallyWithAr01_WithoutNetwork()
    {
        using var _ = UseUuid(null);
        var handler = new MockHttpMessageHandler(_ => throw new InvalidOperationException("No request expected."));

        var result = await CreateClient(handler).CheckStatusAsync("KEY-123", "TestApp");

        Assert.False(result.Success);
        Assert.Equal(StatusErrorCode.DeviceRefused, result.ErrorCode);
        Assert.Equal("Device refused (code AR-01).", result.ErrorMessage);
    }

    [Fact]
    public async Task CheckStatusAsync_WithPreUuidAuthority_SendsNeitherUuidNorEvidence()
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

        await CreateClient(handler).CheckStatusAsync(
            "KEY-123", "TestApp", null, "2.3.394", "A6D3ABCD1234EF90");

        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.Equal("A6D3ABCD1234EF90", document.RootElement.GetProperty("HardwareId").GetString());
        Assert.False(document.RootElement.TryGetProperty("SystemUuid", out _));
        Assert.False(document.RootElement.TryGetProperty("MachineEvidence", out _));
        Assert.False(document.RootElement.TryGetProperty("ComponentFingerprints", out _));
    }

    /// <summary>After the switch the held identifier is the UUID-derived one and the check carries the UUID.</summary>
    [Fact]
    public async Task CheckStatusAsync_WithUuidDerivedAuthority_SendsUuid()
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
        var derived = MachineIdentity.FromUuid(TestUuid).HardwareId!;

        await CreateClient(handler).CheckStatusAsync("KEY-123", "TestApp", null, null, derived);

        using var document = JsonDocument.Parse(capturedPayload!);
        Assert.Equal(TestUuid, document.RootElement.GetProperty("SystemUuid").GetString());
        Assert.True(document.RootElement.TryGetProperty("MachineEvidence", out _));
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
    public void ValidateForCurrentMachine_RefusedUuid_ReturnsInvalidWithSupportCode()
    {
        var keys = LicenseService.GenerateKeys();
        var licenseString = LicenseService.GenerateLicense(
            new LicenseModel { LicenseKey = "CURRENT-TEST", HardwareId = MachineIdentity.FromUuid(TestUuid).HardwareId! },
            keys.PrivateKey);
        using var _ = UseUuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");

        var result = new SoftLicenceClient(ServerUrl, keys.PublicKey).ValidateForCurrentMachine(licenseString);

        Assert.False(result.IsValid);
        Assert.Equal("Device refused (code AR-04).", result.ErrorMessage);
    }

    [Fact]
    public void ValidateLocal_ShouldThrow_WhenNoPublicKey()
    {
        var client = new SoftLicenceClient(ServerUrl);

        Assert.Throws<InvalidOperationException>(() =>
            client.ValidateLocal("some-license-data", "HW-001"));
    }
}

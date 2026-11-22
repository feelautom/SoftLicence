using System.Net;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests;

/// <summary>Exercises actual SDK parsing rather than reflecting the private code mapping.</summary>
public sealed class VirtualMachinePolicySdkTests
{
    /// <summary>The SDK retains the exact server cause and message without falling back to text heuristics.</summary>
    [Theory]
    [InlineData(VirtualMachinePolicy.VirtualMachineCode, ActivationErrorCode.DeviceRefused)]
    [InlineData(VirtualMachinePolicy.EvidenceRequiredCode, ActivationErrorCode.VersionNotAllowed)]
    public async Task Tkt1550_SdkPreservesStructuredPolicyRefusal(string code, ActivationErrorCode expected)
    {
        using var http = new HttpClient(new PolicyHandler(code));
        var client = new SoftLicenceClient("http://localhost:5200", null, http);
        var result = await client.ActivateAsync("KEY", "TestApp", null, "2.3.924", null, null, "A155000000000001");
        Assert.False(result.Success);
        Assert.Equal(expected, result.ErrorCode);
        Assert.Equal(code, result.ServerErrorCode);
        Assert.Equal(VirtualMachinePolicy.Message(code), result.ErrorMessage);
        Assert.Null(result.LicenseFile);
        Assert.False(result.UsedLegacyErrorFallback);
    }

    /// <summary>Returns the frozen HTTP200 activation business-refusal contract.</summary>
    private sealed class PolicyHandler(string code) : HttpMessageHandler
    {
        /// <summary>Creates one local policy response with structured fields and the canonical header; no network call occurs.</summary>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent(JsonSerializer.Serialize(new { isSuccess = false, errorCode = code,
                    message = VirtualMachinePolicy.Message(code), errorMessage = VirtualMachinePolicy.Message(code),
                    correlationId = "tkt1550-sdk", contractVersion = 1 }), Encoding.UTF8, "application/json") };
            response.Headers.Add("X-SoftLicence-Error-Code", code);
            return Task.FromResult(response);
        }
    }
}

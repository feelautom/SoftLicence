using System.Reflection;
using System.Text.Json;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Locks the additive issue-v4 wire contract without changing legacy response bytes.</summary>
public sealed class Tkt000686DistributionEntitlementContractTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Theory]
    [InlineData("distribution-entitlement-issue-v1")]
    [InlineData("distribution-entitlement-issue-v2")]
    [InlineData("distribution-entitlement-issue-v3")]
    public void LegacyIssue_ExplicitNullAuthorityGeneration_IsRejected(string schema)
    {
        var request = Request(schema, "null");

        AssertInvalid(request);
    }

    [Theory]
    [InlineData("018F6FD4-8F31-4CC2-8D19-9E79C8B87A01")]
    [InlineData("{018f6fd4-8f31-4cc2-8d19-9e79c8b87a01}")]
    [InlineData("018f6fd48f314cc28d199e79c8b87a01")]
    public void IssueV4_NonCanonicalAuthorityGeneration_IsRejected(string value)
    {
        var request = Request(DistributionInstallationBindingService.IssueV4Schema,
            JsonSerializer.Serialize(value));

        AssertInvalid(request);
    }

    [Fact]
    public void IssueV4_CanonicalAuthorityGeneration_IsAccepted()
    {
        var request = Request(DistributionInstallationBindingService.IssueV4Schema,
            "\"018f6fd4-8f31-4cc2-8d19-9e79c8b87a01\"");

        AssertValid(request);
    }

    [Fact]
    public void LegacyResponse_NullGeneration_PreservesExactV1Json()
    {
        var response = new DistributionEntitlementIssueResponse(
            DistributionInstallationBindingService.IssueResponseSchema, "opaque", "2026-08-26T12:00:00.0000000Z");

        Assert.Equal(
            "{\"schema\":\"distribution-entitlement-v1\",\"entitlementRef\":\"opaque\",\"expiresAtUtc\":\"2026-08-26T12:00:00.0000000Z\"}",
            JsonSerializer.Serialize(response, WebJson));
    }

    [Fact]
    public void V4Response_ContainsExactProviderGeneration()
    {
        const string generation = "018f6fd4-8f31-4cc2-8d19-9e79c8b87a01";
        var response = new DistributionEntitlementIssueResponse(
            DistributionInstallationBindingService.IssueV2ResponseSchema, "opaque",
            "2026-08-26T12:00:00.0000000Z", generation);

        Assert.Equal(generation, JsonDocument.Parse(JsonSerializer.Serialize(response, WebJson))
            .RootElement.GetProperty("authorityGenerationId").GetString());
    }

    /// <summary>Creates one exact request and preserves JSON member presence through deserialization.</summary>
    private static DistributionEntitlementIssueRequest Request(string schema, string authorityJson)
    {
        var grant = schema == DistributionInstallationBindingService.IssueSchema ? "null" : $"\"{new string('a', 64)}\"";
        var subject = schema is DistributionInstallationBindingService.IssueV3Schema
            or DistributionInstallationBindingService.IssueV4Schema ? $"\"{new string('A', 43)}\"" : "null";
        return JsonSerializer.Deserialize<DistributionEntitlementIssueRequest>($$"""
            {"schema":"{{schema}}","requestId":"018f6fd4-8f31-4cc2-8d19-9e79c8b87a02","productId":"018f6fd4-8f31-4cc2-8d19-9e79c8b87a03","softLicenceLicenseId":"018f6fd4-8f31-4cc2-8d19-9e79c8b87a04","grantRefDigestSha256":{{grant}},"subjectRef":{{subject}},"authorityGenerationId":{{authorityJson}}}
            """, WebJson)!;
    }

    /// <summary>Invokes the production shape validator and requires its stable invalid-request classification.</summary>
    private static void AssertInvalid(DistributionEntitlementIssueRequest request)
    {
        var error = Assert.Throws<TargetInvocationException>(() => Validator().Invoke(null, [request]));
        Assert.IsType<DistributionOperationException>(error.InnerException);
    }

    /// <summary>Invokes the production shape validator and requires successful exact parsing.</summary>
    private static void AssertValid(DistributionEntitlementIssueRequest request) =>
        Assert.NotNull(Validator().Invoke(null, [request]));

    /// <summary>Returns the private production validator used at the authenticated HTTP boundary.</summary>
    private static MethodInfo Validator() => typeof(DistributionInstallationBindingService).GetMethod(
        "ValidateIssueRequest", BindingFlags.Static | BindingFlags.NonPublic)!;
}

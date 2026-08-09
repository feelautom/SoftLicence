using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Reflection;
using System.Globalization;
using Microsoft.AspNetCore.Http;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentServiceTests
{
    [Fact]
    public void PrepareResponseV1_SerializationRemainsExactWithoutSecurityEpoch()
    {
        var response = new RuntimeEnrollmentPrepareResponse(
            RuntimeEnrollmentService.PrepareResponseSchema,
            RuntimeEnrollmentService.ProtocolVersion,
            "pending",
            "55555555-5555-4555-8555-555555555555",
            1,
            "challenge",
            "2026-08-04T08:00:00.0000000Z",
            "https://runtime.example.test");

        Assert.Equal(
            "{\"schema\":\"runtime-enrollment-prepare-response-v1\",\"protocolVersion\":\"runtime-enrollment-v1\",\"status\":\"pending\",\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"epoch\":1,\"challenge\":\"challenge\",\"expiresAtUtc\":\"2026-08-04T08:00:00.0000000Z\",\"confirmAudience\":\"https://runtime.example.test\"}",
            JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }

    [Fact]
    public void PrepareResponseV2_SerializationCarriesAuthoritativeSecurityEpoch()
    {
        var response = new RuntimeEnrollmentPrepareResponse(
            RuntimeEnrollmentService.PrepareV2ResponseSchema,
            RuntimeEnrollmentService.ProtocolVersion,
            "pending",
            "55555555-5555-4555-8555-555555555555",
            1,
            "challenge",
            "2026-08-04T08:00:00.0000000Z",
            "https://runtime.example.test")
        {
            SecurityEpoch = 5
        };

        Assert.Equal(
            "{\"schema\":\"runtime-enrollment-prepare-response-v2\",\"protocolVersion\":\"runtime-enrollment-v1\",\"status\":\"pending\",\"enrollmentId\":\"55555555-5555-4555-8555-555555555555\",\"epoch\":1,\"challenge\":\"challenge\",\"expiresAtUtc\":\"2026-08-04T08:00:00.0000000Z\",\"confirmAudience\":\"https://runtime.example.test\",\"securityEpoch\":5}",
            JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }

    [Theory]
    [InlineData("runtime-enrollment-refresh-v1", null, "runtime-enrollment-refresh-response-v1", null)]
    [InlineData("runtime-enrollment-refresh-v2", 5, "runtime-enrollment-refresh-response-v2", 5)]
    public void RefreshResponse_SerializationPreservesVersionedExactShape(
        string requestSchema,
        int? expectedSecurityEpoch,
        string responseSchema,
        int? securityEpoch)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateRefresh", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidRefreshRequest(requestSchema, expectedSecurityEpoch);

        var validated = validate.Invoke(null, [request, new string('d', 64)]);
        var response = new RuntimeEnrollmentPrepareResponse(
            responseSchema,
            RuntimeEnrollmentService.ProtocolVersion,
            "pending",
            request.EnrollmentId!,
            1,
            "challenge",
            "2026-08-04T08:00:00.0000000Z",
            "https://runtime.example.test")
        {
            SecurityEpoch = securityEpoch
        };

        Assert.NotNull(validated);
        var expectedSuffix = securityEpoch.HasValue ? ",\"securityEpoch\":5}" : "}";
        Assert.EndsWith(expectedSuffix,
            JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Runtime-enrollment-refresh-v2", 5)]
    [InlineData("runtime-enrollment-refresh-v3", 5)]
    [InlineData("runtime-enrollment-refresh-v2", null)]
    [InlineData("runtime-enrollment-refresh-v2", 0)]
    [InlineData("runtime-enrollment-refresh-v1", 1)]
    public void RefreshValidation_RejectsNearMissAndHybridVersionContracts(
        string schema,
        int? expectedSecurityEpoch)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateRefresh", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidRefreshRequest(schema, expectedSecurityEpoch);

        var thrown = Assert.Throws<TargetInvocationException>(() =>
            validate.Invoke(null, [request, new string('d', 64)]));

        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    private static RuntimeEnrollmentRefreshRequest ValidRefreshRequest(
        string schema,
        int? expectedSecurityEpoch) => new()
    {
        Schema = schema,
        RequestId = "11111111-1111-4111-8111-111111111111",
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        ProductId = "22222222-2222-4222-8222-222222222222",
        BindingId = "33333333-3333-4333-8333-333333333333",
        EnrollmentId = "44444444-4444-4444-8444-444444444444",
        ExpectedChallengeDigestSha256 = new string('a', 64),
        ExpectedSecurityEpoch = expectedSecurityEpoch
    };

    [Fact]
    public void ReinstallAuthorityLegacyV2_ValidationPreservesExactSignedReferences()
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateReinstallAuthority", BindingFlags.NonPublic | BindingFlags.Static)!;
        var build = typeof(RuntimeEnrollmentService).GetMethod(
            "BuildReinstallProofPayload", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidLegacyV2ReinstallRequest();

        var validated = validate.Invoke(null, [request]);
        var payload = Assert.IsType<string>(build.Invoke(null, [validated]));

        Assert.Equal(string.Join('\n',
            "distribution-reinstall-proof-v2",
            request.BootstrapId,
            request.RequestId,
            request.InstallationId,
            request.EnrollmentId,
            request.ReleaseVersion,
            request.KeyThumbprint,
            "3",
            request.GrantRef,
            request.SubjectRef,
            request.Challenge), payload);
    }

    [Theory]
    [InlineData("subject-length")]
    [InlineData("subject-character")]
    [InlineData("grant-uppercase")]
    [InlineData("v1-extra-fields")]
    public void ReinstallAuthorityValidation_RejectsNonCanonicalOrCrossSchemaReferences(string mutation)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateReinstallAuthority", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = ValidLegacyV2ReinstallRequest();
        switch (mutation)
        {
            case "subject-length": request.SubjectRef += "A"; break;
            case "subject-character": request.SubjectRef = new string('A', 42) + "+"; break;
            case "grant-uppercase": request.GrantRef = request.GrantRef!.ToUpperInvariant(); break;
            case "v1-extra-fields": request.Schema = RuntimeEnrollmentService.ReinstallAuthoritySchema; break;
        }

        var thrown = Assert.Throws<TargetInvocationException>(() => validate.Invoke(null, [request]));

        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    [Fact]
    public void BuildProofPayload_UsesFrozenLineOrderWithoutTrailingNewline()
    {
        var id = Guid.Parse("11111111-1111-4111-8111-111111111111");

        var payload = RuntimeEnrollmentService.BuildProofPayload(
            "capability", id, 1,
            "/api/v1/runtime-enrollments/11111111-1111-4111-8111-111111111111/capabilities",
            "https://broker.example.test", "2026-07-19T00:00:00.0000000Z",
            "22222222-2222-4222-8222-222222222222", "-", new string('a', 64));

        Assert.Equal(12, payload.Split('\n').Length);
        Assert.StartsWith("runtime-enrollment-proof-v1\nPS256\ncapability\n", payload, StringComparison.Ordinal);
        Assert.EndsWith(new string('a', 64), payload, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", payload, StringComparison.Ordinal);
    }

    [Fact]
    public void SignCapability_ProducesVerifiablePs256TokenWithBoundCnf()
    {
        using var rsa = RSA.Create(3072);
        using var service = new RuntimeEnrollmentCryptoService(Options.Create(OptionsFor(rsa)));
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var issued = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        var token = service.SignCapability(enrollmentId, 1, 7,
            "44444444-4444-4444-8444-444444444444", "2.2.844",
            "77777777-7777-4777-8777-777777777777",
            CapabilityBinaries(), "https://broker.example.test",
            ["runtime.execute"], new string('a', 64), issued,
            "22222222-2222-4222-8222-222222222222");

        var segments = token.Split('.');
        Assert.Equal(3, segments.Length);
        using var header = JsonDocument.Parse(Decode(segments[0]));
        using var payload = JsonDocument.Parse(Decode(segments[1]));
        Assert.Equal("PS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("runtime-2026-01", header.RootElement.GetProperty("kid").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(enrollmentId.ToString("D"), payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal(7, payload.RootElement.GetProperty("security_epoch").GetInt32());
        Assert.Equal("2.2.844", payload.RootElement.GetProperty("release_version").GetString());
        Assert.Equal(new string('c', 64), payload.RootElement.GetProperty("binaries").GetProperty("FP_CORE").GetString());
        Assert.Equal(issued.ToUnixTimeSeconds() + 120, payload.RootElement.GetProperty("exp").GetInt64());
        Assert.Equal(new string('a', 64), payload.RootElement.GetProperty("cnf").GetProperty("spki_sha256").GetString());
        Assert.True(rsa.VerifyData(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), Decode(segments[2]),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        var rejected = Assert.Throws<RuntimeEnrollmentException>(() => service.SignCapability(
            enrollmentId, 1, 7, null!, "2.2.844",
            "77777777-7777-4777-8777-777777777777", CapabilityBinaries(),
            "https://broker.example.test", ["runtime.execute"], new string('a', 64), issued,
            "33333333-3333-4333-8333-333333333333"));
        Assert.Equal("authority_unavailable", rejected.ErrorCode);
    }

    [Fact]
    public void SignLegacyCapability_ProducesExactHistoricalClaimSet()
    {
        using var rsa = RSA.Create(3072);
        using var service = new RuntimeEnrollmentCryptoService(Options.Create(OptionsFor(rsa)));
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");

        var token = service.SignLegacyCapability(
            enrollmentId, 1, 3, "https://broker.example.test", ["runtime.execute"],
            new string('a', 64), DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
            "22222222-2222-4222-8222-222222222222");

        var segments = token.Split('.');
        using var payload = JsonDocument.Parse(Decode(segments[1]));
        Assert.Equal(
            ["iss", "aud", "sub", "jti", "iat", "nbf", "exp", "epoch", "security_epoch", "scope", "cnf"],
            payload.RootElement.EnumerateObject().Select(property => property.Name).ToArray());
        Assert.False(payload.RootElement.TryGetProperty("installation_id", out _));
        Assert.False(payload.RootElement.TryGetProperty("release_version", out _));
        Assert.False(payload.RootElement.TryGetProperty("session_id", out _));
        Assert.False(payload.RootElement.TryGetProperty("binaries", out _));
        Assert.True(rsa.VerifyData(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), Decode(segments[2]),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Fact]
    public void CapabilityValidation_AcceptsHistoricalShapeButRejectsMixedShape()
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateCapability", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var request = LegacyCapabilityRequest(enrollmentId);

        Assert.NotNull(method.Invoke(null, [enrollmentId, request, ValidProofHeaders(), new string('b', 64)]));

        request.SessionId = "22222222-2222-4222-8222-222222222222";
        var thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [enrollmentId, request, ValidProofHeaders(), new string('b', 64)]));
        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);

        request = LegacyCapabilityRequest(enrollmentId);
        request.InstallationId = null;
        thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [enrollmentId, request, ValidProofHeaders(), new string('b', 64)]));
        invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    [Theory]
    [InlineData("2.2.916", "2.2.916", true)]
    [InlineData("2.2.915", "2.2.915", false)]
    [InlineData("2.2.916", "2.2.915", false)]
    public void LegacyCapabilityBinding_IsRestrictedToExactAuthoritativeRelease(
        string enrollmentVersion, string bindingVersion, bool accepted)
    {
        var validate = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateCapability", BindingFlags.NonPublic | BindingFlags.Static)!;
        var validateBinding = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateCapabilityBinding", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var bindingId = Guid.Parse("33333333-3333-4333-8333-333333333333");
        const string installationId = "44444444-4444-4444-8444-444444444444";
        var capability = validate.Invoke(null,
            [enrollmentId, LegacyCapabilityRequest(enrollmentId), ValidProofHeaders(), new string('b', 64)]);
        var enrollment = new RuntimeEnrollment
        {
            Id = enrollmentId,
            BindingId = bindingId,
            InstallationId = installationId,
            ReleaseVersion = enrollmentVersion
        };
        var binding = new DistributionInstallationBinding
        {
            Id = bindingId,
            InstallationId = installationId,
            Version = bindingVersion
        };

        if (accepted)
        {
            validateBinding.Invoke(null, [enrollment, binding, capability]);
            return;
        }

        var thrown = Assert.Throws<TargetInvocationException>(() =>
            validateBinding.Invoke(null, [enrollment, binding, capability]));
        var rejected = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status409Conflict, rejected.StatusCode);
        Assert.Equal("capability_binding_mismatch", rejected.ErrorCode);
    }

    private static List<RuntimeEnrollmentBinaryEvidenceRequest> CapabilityBinaries() =>
    [
        new() { Key = "FP_CORE", Sha256 = new string('c', 64) },
        new() { Key = "FP_DLL", Sha256 = new string('d', 64) },
        new() { Key = "FP_EXE", Sha256 = new string('e', 64) }
    ];

    private static RuntimeEnrollmentCapabilityRequest LegacyCapabilityRequest(Guid enrollmentId) => new()
    {
        Schema = RuntimeEnrollmentService.CapabilitySchema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        EnrollmentId = enrollmentId.ToString("D"),
        Epoch = 1,
        SecurityEpoch = 1,
        Audience = "https://broker.example.test",
        Scope = ["runtime.execute"]
    };

    private static RuntimeReinstallAuthorityRequest ValidLegacyV2ReinstallRequest() => new()
    {
        Schema = RuntimeEnrollmentService.ReinstallAuthorityLegacyV2Schema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        RequestId = "11111111-1111-4111-8111-111111111111",
        ProductId = "22222222-2222-4222-8222-222222222222",
        BootstrapId = "33333333-3333-4333-8333-333333333333",
        InstallationId = "44444444-4444-4444-8444-444444444444",
        EnrollmentId = "55555555-5555-4555-8555-555555555555",
        ReleaseVersion = "2.3.7",
        KeyThumbprint = new string('A', 43),
        SecurityEpoch = 3,
        GrantRef = "abcdefab-cdef-4abc-8def-abcdefabcdef",
        SubjectRef = new string('A', 43),
        Challenge = new string('B', 86),
        Signature = new string('C', 512)
    };

    [Fact]
    public void EncryptionOwnerType_AllowsCriticalRecoveryClientRefetchResponse()
    {
        var allowlist = typeof(RuntimeEnrollmentCryptoService).GetMethod(
            "IsOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var mapping = typeof(RuntimeEnrollmentService).GetMethod(
            "ProofResponseOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ownerType = Assert.IsType<string>(mapping.Invoke(null, ["critical-recovery-refetch"]));

        Assert.Equal("recovery-refetch-response", ownerType);
        Assert.True(ownerType.Length <= 32);
        Assert.True((bool)allowlist.Invoke(null, [ownerType])!);
        Assert.False((bool)allowlist.Invoke(null, ["critical-recovery-refetch-response"])!);
    }

    [Fact]
    public void EncryptionOwnerType_AllowsMilestoneResponse()
    {
        var allowlist = typeof(RuntimeEnrollmentCryptoService).GetMethod(
            "IsOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var mapping = typeof(RuntimeEnrollmentService).GetMethod(
            "ProofResponseOwnerType", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ownerType = Assert.IsType<string>(mapping.Invoke(null, ["milestone"]));

        Assert.Equal("milestone-response", ownerType);
        Assert.True((bool)allowlist.Invoke(null, [ownerType])!);
    }

    [Theory]
    [InlineData("bootstrap_entered")]
    [InlineData("integrity_denied")]
    [InlineData("mcp_invocation_requested")]
    [InlineData("tia_operation_failed")]
    public void MilestoneValidation_AcceptsExactAllowlistedCodes(string code)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateMilestone", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var request = MilestoneRequest(enrollmentId, code);

        var result = method.Invoke(null,
            [enrollmentId, request, ValidProofHeaders(), new string('a', 64)]);

        Assert.NotNull(result);
    }

    [Theory]
    [InlineData("Bootstrap_entered")]
    [InlineData("bootstrap-entered")]
    [InlineData("server_verified")]
    [InlineData("")]
    public void MilestoneValidation_RejectsNonAllowlistedCodes(string code)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateMilestone", BindingFlags.NonPublic | BindingFlags.Static)!;
        var enrollmentId = Guid.Parse("11111111-1111-4111-8111-111111111111");

        var thrown = Assert.Throws<TargetInvocationException>(() => method.Invoke(null,
            [enrollmentId, MilestoneRequest(enrollmentId, code), ValidProofHeaders(), new string('a', 64)]));

        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal("invalid_request", invalid.ErrorCode);
        Assert.Equal(400, invalid.StatusCode);
    }

    [Fact]
    public void MilestoneAuthorization_AllowsConfiguredScopeAtDifferentCapabilityAudience()
    {
        var productId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var options = new RuntimeEnrollmentOptions
        {
            ConfirmAudience = "https://runtime.example.test",
            Products =
            [
                new()
                {
                    ProductId = productId.ToString("D"),
                    Capabilities =
                    [
                        new()
                        {
                            Audience = "https://broker.example.test",
                            Scopes = ["milestone:write", "runtime.execute"]
                        }
                    ]
                }
            ]
        };
        var service = new RuntimeEnrollmentService(
            null!, null!, null!, null!, Options.Create(options));
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidateMilestoneAuthorization", BindingFlags.NonPublic | BindingFlags.Instance)!;

        method.Invoke(service, [productId]);

        options.Products[0].Capabilities[0].Scopes = ["runtime.execute"];
        var denied = Assert.Throws<TargetInvocationException>(() => method.Invoke(service, [productId]));
        Assert.Equal("capability_not_allowed",
            Assert.IsType<RuntimeEnrollmentException>(denied.InnerException).ErrorCode);
    }

    [Fact]
    public void MilestoneSession_AtAbsoluteExpiry_IsRejected()
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "EnsureMilestoneSessionActive", BindingFlags.NonPublic | BindingFlags.Static)!;
        var now = DateTimeOffset.Parse("2026-07-20T10:00:00Z", CultureInfo.InvariantCulture);
        var session = new RuntimeMilestoneSession
        {
            ExpiresAtUtc = now.UtcDateTime
        };

        var thrown = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, [session, now]));

        var expired = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal("session_expired", expired.ErrorCode);
        Assert.Equal(409, expired.StatusCode);
    }

    [Fact]
    public async Task EnabledAuthority_WithNonPostgreSqlProvider_FailsClosed()
    {
        var factory = new InMemoryFactory();
        var authority = new RuntimeEnrollmentAuthorityService(
            factory, Options.Create(new RuntimeEnrollmentOptions { Mode = "enabled" }));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => authority.ValidateInfrastructureAsync());

        Assert.Equal("Runtime enrollment enabled infrastructure validation failed.", exception.Message);
    }

    [Theory]
    [InlineData("2.10.0", "2.9.0", false)]
    [InlineData("2.9.0", "2.10.0", true)]
    [InlineData("2.2.0-alpha.9", "2.2.0-alpha.10", true)]
    [InlineData("2.2.0-rc.1", "2.2.0", true)]
    [InlineData("2.2.0+build.7", "2.2.0+build.8", false)]
    [InlineData("2.2.0-01", "2.2.0", true)]
    public void MinimumVersion_UsesSemVerPrecedence(string current, string minimum, bool expectedBelow)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "IsVersionBelow", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal(expectedBelow, (bool)method.Invoke(null, [current, minimum])!);
    }

    [Theory]
    [InlineData("2.10.0", "2.*", true)]
    [InlineData("2.10.0-rc.1+build.7", "2.10.*", true)]
    [InlineData("2.10.0+build.7", "2.10.0+build.7", true)]
    [InlineData("2.10.0+build.8", "2.10.0+build.7", false)]
    [InlineData("2.10.0-01", "2.*", false)]
    public void AllowedVersion_RequiresValidSemVerAndCanonicalMask(
        string version, string mask, bool expectedAllowed)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "IsVersionAllowed", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal(expectedAllowed, (bool)method.Invoke(null, [version, mask])!);
    }

    [Fact]
    public void PrepareValidation_RejectsNonCanonicalSemVerBeforeOpenVersionPolicies()
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidatePrepare", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = new RuntimeEnrollmentPrepareRequest
        {
            Schema = RuntimeEnrollmentService.PrepareSchema,
            RequestId = "11111111-1111-4111-8111-111111111111",
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = "22222222-2222-4222-8222-222222222222",
            BindingId = "33333333-3333-4333-8333-333333333333",
            HandoffDigestSha256 = new string('a', 64),
            InstallationId = "44444444-4444-4444-8444-444444444444",
            ReleaseVersion = "2.2.0-01",
            Epoch = 1,
            Key = new RuntimeEnrollmentKeyRequest()
        };

        var thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [request, new string('b', 64)]));
        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(400, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    [Theory]
    [InlineData("runtime-enrollment-prepare-v1", true)]
    [InlineData("runtime-enrollment-prepare-v2", true)]
    [InlineData("Runtime-enrollment-prepare-v2", false)]
    [InlineData("runtime-enrollment-prepare-v3", false)]
    public void PrepareValidation_AcceptsOnlyExactVersionedSchemas(string schema, bool accepted)
    {
        var method = typeof(RuntimeEnrollmentService).GetMethod(
            "ValidatePrepare", BindingFlags.NonPublic | BindingFlags.Static)!;
        var request = new RuntimeEnrollmentPrepareRequest
        {
            Schema = schema,
            RequestId = "11111111-1111-4111-8111-111111111111",
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            ProductId = "22222222-2222-4222-8222-222222222222",
            BindingId = "33333333-3333-4333-8333-333333333333",
            HandoffDigestSha256 = new string('a', 64),
            InstallationId = "44444444-4444-4444-8444-444444444444",
            ReleaseVersion = "2.2.844",
            Epoch = 1,
            Key = new RuntimeEnrollmentKeyRequest()
        };

        if (accepted)
        {
            Assert.NotNull(method.Invoke(null, [request, new string('b', 64)]));
            return;
        }

        var thrown = Assert.Throws<TargetInvocationException>(() =>
            method.Invoke(null, [request, new string('b', 64)]));
        var invalid = Assert.IsType<RuntimeEnrollmentException>(thrown.InnerException);
        Assert.Equal(StatusCodes.Status400BadRequest, invalid.StatusCode);
        Assert.Equal("invalid_request", invalid.ErrorCode);
    }

    private static RuntimeEnrollmentOptions OptionsFor(RSA rsa) => new()
    {
        Mode = "enabled",
        Issuer = "https://runtime.example.test",
        CapabilityTtlSeconds = 120,
        CapabilitySigning = new RuntimeCapabilitySigningOptions
        {
            ActiveKeyId = "runtime-2026-01",
            Keys =
            [
                new RuntimeCapabilitySigningKeyOptions
                {
                    KeyId = "runtime-2026-01",
                    Role = "active",
                    PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
                    PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem()
                }
            ]
        },
        Encryption = new RuntimeEncryptionOptions { Keys = [] }
    };

    private static RuntimeMilestoneRequest MilestoneRequest(Guid enrollmentId, string code) => new()
    {
        Schema = RuntimeEnrollmentService.MilestoneSchema,
        ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
        EnrollmentId = enrollmentId.ToString("D"),
        Epoch = 1,
        SecurityEpoch = 1,
        SessionId = "22222222-2222-4222-8222-222222222222",
        Sequence = 1,
        EventId = "33333333-3333-4333-8333-333333333333",
        Code = code,
        OccurredAtUtc = "2026-07-20T10:00:00.0000000Z"
    };

    private static RuntimeProofHeaders ValidProofHeaders() => new(
        "2026-07-20T10:00:00.0000000Z",
        "44444444-4444-4444-8444-444444444444",
        new string('A', 512));

    private static byte[] Decode(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        return Convert.FromBase64String(base64);
    }

    private sealed class InMemoryFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options =
            new DbContextOptionsBuilder<LicenseDbContext>()
                .UseInMemoryDatabase("runtime-provider-gate-" + Guid.NewGuid().ToString("N"))
                .Options;

        public LicenseDbContext CreateDbContext() => new(_options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

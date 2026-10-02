using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class DistributionInstallationBindingsControllerTests
{
    [Fact]
    public async Task RuntimePreflight_AuthenticatesExactBodyAndReturnsOpaqueAuthority()
    {
        const string body = "{\"schema\":\"runtime-distribution-hardware-authority\",\"requestId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"softLicenceLicenseId\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\",\"grantRefDigestSha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"installationId\":null,\"keyThumbprint\":null,\"hardwareEvidence\":null,\"hardwareIdHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                "12345678-1234-4234-9234-1234567890ab",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var preflight = new Mock<IRuntimeDistributionPreflightService>();
        var response = new RuntimeDistributionPreflightResponse(
            "runtime-distribution-hardware-authority-result",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "accepted", new string('a', 64),
            "digest-revalidation");
        preflight.Setup(service => service.EvaluateAsync(
                "tia-connect-website",
                It.Is<string>(digest => digest.Length == 64),
                It.Is<RuntimeDistributionPreflightRequest>(request =>
                    request.HardwareIdHash == new string('a', 64)),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
        var controller = CreateController(authentication.Object,
            Mock.Of<IDistributionInstallationBindingService>(), body, preflight.Object);

        var result = Assert.IsType<OkObjectResult>(
            await controller.RuntimePreflight(CancellationToken.None));

        Assert.Equal(response, result.Value);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
    }

    /// <summary>TKT-001296: the pair route authenticates the exact bytes and relays the closed digest-only decision.</summary>
    [Fact]
    public async Task FinalizeAuthorityPair_AuthenticatesExactBodyAndReturnsClosedDecision()
    {
        var body = "{\"schema\":\"distribution-finalize-authority-pair-v1\",\"requestId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"softLicenceLicenseId\":\"22345678-1234-4234-9234-1234567890ab\",\"grantRefDigestSha256\":\"" + new string('b', 64) + "\",\"submittedHardwareId\":\"A00272B768FFD6AF\",\"expectedHardwareIdHash\":\"" + new string('c', 64) + "\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                "12345678-1234-4234-9234-1234567890ab",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var pairs = new Mock<IFinalizeAuthorityPairResolver>();
        var response = new FinalizeAuthorityPairResponse(
            "distribution-finalize-authority-resolution-v1", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", new string('d', 64),
            Guid.Parse("12345678-1234-4234-9234-1234567890ab"),
            Guid.Parse("22345678-1234-4234-9234-1234567890ab"),
            Guid.Parse("32345678-1234-4234-9234-1234567890ab"), new string('b', 64),
            "alias-matched", new string('a', 64), new string('c', 64), new string('c', 64),
            "stable-expected-legacy-submitted", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), null);
        pairs.Setup(service => service.ResolveAsync(
                "tia-connect-website",
                It.Is<string>(digest => digest.Length == 64),
                It.Is<FinalizeAuthorityPairRequest>(request =>
                    request.SubmittedHardwareId == "A00272B768FFD6AF" && request.ExpectedHardwareIdHash == new string('c', 64)),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
        var controller = CreateController(authentication.Object,
            Mock.Of<IDistributionInstallationBindingService>(), body, finalizeAuthorityPairs: pairs.Object);

        var result = Assert.IsType<OkObjectResult>(
            await controller.FinalizeAuthorityPair(CancellationToken.None));

        Assert.Equal(response, result.Value);
        Assert.Equal("no-store, max-age=0", controller.Response.Headers.CacheControl);
    }

    [Fact]
    public async Task FinalizeAuthorityPair_WithoutRegisteredResolver_IsUnavailableNotCrashed()
    {
        var controller = CreateController(Mock.Of<IDistributionS2SAuthenticationService>(),
            Mock.Of<IDistributionInstallationBindingService>(), "{}");

        var result = Assert.IsType<ObjectResult>(await controller.FinalizeAuthorityPair(CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
    }

    [Fact]
    public async Task IssueEntitlement_PassesExactBodyToAuthenticationAndReturnsCreated()
    {
        const string body = "{\"schema\":\"distribution-entitlement-issue-v1\",\"requestId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"softLicenceLicenseId\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                "12345678-1234-4234-9234-1234567890ab",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.IssueEntitlementAsync(
                "tia-connect-website",
                It.Is<string>(digest => digest.Length == 64),
                It.IsAny<DistributionEntitlementIssueRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionEntitlementIssueResponse>(
                new("distribution-entitlement-v1", "opaque-reference", "2026-07-18T20:30:00.0000000Z"),
                false));
        var controller = CreateController(authentication.Object, bindings.Object, body);
        controller.Request.ContentType = "application/json; charset=utf-8";

        var result = await controller.IssueEntitlement(CancellationToken.None);

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status201Created, objectResult.StatusCode);
    }

    [Fact]
    public async Task Finalize_ReplayFailure_ReturnsOnlyStablePseudonymousError()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionS2SAuthenticationException("replay_rejected", StatusCodes.Status409Conflict));
        var controller = CreateController(authentication.Object, Mock.Of<IDistributionInstallationBindingService>(), body);

        var result = await controller.FinalizeInstallation(CancellationToken.None);

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, objectResult.StatusCode);
        Assert.Equal(new DistributionApiError("replay_rejected"), objectResult.Value);
    }

    [Fact]
    public async Task ResolveRuntimeSource_PassesExactAuthenticatedRequestAndReturnsBoundedAuthority()
    {
        const string body = "{\"schema\":\"distribution-runtime-source-resolution-v1\",\"requestId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"targetLicenseId\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\",\"hardwareId\":\"EXACT-HWID\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                "12345678-1234-4234-9234-1234567890ab",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.ResolveRuntimeSourceAsync(
                "tia-connect-website",
                It.Is<DistributionRuntimeSourceResolutionRequest>(request => request.HardwareId == "EXACT-HWID"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionRuntimeSourceResolutionResponse(
                "distribution-runtime-source-resolution-result-v1",
                "source",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "legacy"));
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = Assert.IsType<OkObjectResult>(
            await controller.ResolveRuntimeSource(CancellationToken.None));

        Assert.Equal(new DistributionRuntimeSourceResolutionResponse(
            "distribution-runtime-source-resolution-result-v1",
            "source",
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "legacy"), result.Value);
    }

    [Fact]
    public async Task Finalize_AuthorityConflict_ReturnsAllowlistedInternalReasonWithoutSensitiveContext()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.FinalizeAsync(
                "tia-connect-website", It.IsAny<string>(), It.IsAny<DistributionInstallationFinalizeRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionOperationException(
                "binding_conflict", StatusCodes.Status409Conflict, "cross_generation_grant_owner_mismatch"));
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = Assert.IsType<ObjectResult>(
            await controller.FinalizeInstallation(CancellationToken.None));

        Assert.Equal(StatusCodes.Status409Conflict, result.StatusCode);
        Assert.Equal(new DistributionApiError("binding_conflict", "cross_generation_grant_owner_mismatch"), result.Value);
    }

    [Theory]
    [InlineData("alias_resolution_ambiguous")]
    [InlineData("alias_resolution_unavailable")]
    [InlineData("authority_graph_missing")]
    [InlineData("authority_graph_diverged")]
    [InlineData("alias_reconciliation_identity_missing")]
    [InlineData("canonical_seat_cardinality_mismatch")]
    [InlineData("recovery_source_missing")]
    [InlineData("recovery_source_binding_mismatch")]
    public async Task Finalize_HardwareAuthorityRefusal_ReturnsExactCompatible422(string reasonCode)
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.FinalizeAsync(
                "tia-connect-website", It.IsAny<string>(), It.IsAny<DistributionInstallationFinalizeRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DistributionOperationException(
                "hardware_authority_refused", StatusCodes.Status422UnprocessableEntity, reasonCode));
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = Assert.IsType<ObjectResult>(
            await controller.FinalizeInstallation(CancellationToken.None));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, result.StatusCode);
        Assert.Equal(new DistributionApiError("hardware_authority_refused", reasonCode), result.Value);
        Assert.Equal(
            $"{{\"error\":\"hardware_authority_refused\",\"reasonCode\":\"{reasonCode}\"}}",
            JsonSerializer.Serialize(result.Value, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }

    [Fact]
    public async Task Finalize_DuplicateProductId_IsRejectedBeforeAuthentication()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"productId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        var controller = CreateController(authentication.Object, Mock.Of<IDistributionInstallationBindingService>(), body);

        var result = await controller.FinalizeInstallation(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        authentication.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("application/jsonp")]
    [InlineData("application/jsonmalformed")]
    [InlineData("application/json; charset=")]
    public async Task IssueEntitlement_JsonLikeButInvalidMediaType_IsRejectedBeforeAuthentication(string contentType)
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\"}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        var controller = CreateController(authentication.Object, Mock.Of<IDistributionInstallationBindingService>(), body);
        controller.Request.ContentType = contentType;

        var result = await controller.IssueEntitlement(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        authentication.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Finalize_NestedDuplicateProperty_ConsumesAuthenticationNonceBeforeBadRequest()
    {
        const string body = "{\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"release\":{\"version\":\"2.2.844\",\"version\":\"2.2.845\"}}";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = await controller.FinalizeInstallation(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        authentication.Verify(service => service.AuthenticateAndReserveNonceAsync(
            It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(),
            "12345678-1234-4234-9234-1234567890ab", It.IsAny<CancellationToken>()), Times.Once);
        bindings.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"legacyLicenseReplacement\":{},\"legacyLicenseReplacement\":{}}")]
    [InlineData("{\"productId\":\"12345678-1234-4234-9234-1234567890ab\",\"legacyLicenseReplacement\":{\"sourceLicenseId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"sourceLicenseId\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\"}}")]
    public async Task FinalizeV5_DuplicateOuterOrProofMember_IsRejectedAfterNonceReservation(string body)
    {
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = await controller.FinalizeInstallation(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        authentication.Verify(service => service.AuthenticateAndReserveNonceAsync(
            It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(),
            "12345678-1234-4234-9234-1234567890ab", It.IsAny<CancellationToken>()), Times.Once);
        bindings.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Proves the controller authenticates the exact request bytes and forwards the closed seat-release reason
    /// without normalization before returning the created invalidation result.
    /// </summary>
    [Fact]
    public async Task Invalidate_PassesExactBodyAfterAuthenticationAndReturnsCreated()
    {
        var grantDigest = new string('a', 64);
        var body = $$"""{"schema":"distribution-installation-invalidation-v1","requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","productId":"12345678-1234-4234-9234-1234567890ab","bindingId":null,"grantRefDigestSha256":"{{grantDigest}}","reason":"seat_released","occurredAtUtc":"2026-07-18T18:20:00.0000000Z","epoch":1}""";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(),
                It.Is<ReadOnlyMemory<byte>>(bytes => Encoding.UTF8.GetString(bytes.ToArray()) == body),
                "12345678-1234-4234-9234-1234567890ab",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.Setup(service => service.InvalidateAsync(
                "tia-connect-website", It.Is<string>(digest => digest.Length == 64),
                It.IsAny<DistributionInstallationInvalidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionInstallationInvalidationResponse>(
                new("distribution-installation-invalidation-result-v1", null, "invalidated", grantDigest,
                    "seat_released", "2026-07-18T18:20:00.0000000Z", 1, "2026-07-18T18:30:00.0000000Z"), false));
        var controller = CreateController(authentication.Object, bindings.Object, body);

        var result = await controller.InvalidateInstallation(CancellationToken.None);

        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status201Created, objectResult.StatusCode);
        bindings.Verify(service => service.InvalidateAsync(
            "tia-connect-website", It.IsAny<string>(),
            It.Is<DistributionInstallationInvalidationRequest>(request => request.Reason == "seat_released"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Invalidate_ExactReplayReturnsOk_AndChangedPayloadConflictRemainsStable()
    {
        var grantDigest = new string('a', 64);
        var body = $$"""{"schema":"distribution-installation-invalidation-v1","requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","productId":"12345678-1234-4234-9234-1234567890ab","bindingId":null,"grantRefDigestSha256":"{{grantDigest}}","reason":"grant_revoked","occurredAtUtc":"2026-07-18T18:20:00.0000000Z","epoch":1}""";
        var authentication = new Mock<IDistributionS2SAuthenticationService>();
        authentication.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(),
                "12345678-1234-4234-9234-1234567890ab", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal("tia-connect-website", "key-id"));
        var response = new DistributionInstallationInvalidationResponse(
            "distribution-installation-invalidation-result-v1", null, "invalidated", grantDigest,
            "grant_revoked", "2026-07-18T18:20:00.0000000Z", 1, "2026-07-18T18:30:00.0000000Z");
        var bindings = new Mock<IDistributionInstallationBindingService>();
        bindings.SetupSequence(service => service.InvalidateAsync(
                "tia-connect-website", It.IsAny<string>(), It.IsAny<DistributionInstallationInvalidationRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionOperationResult<DistributionInstallationInvalidationResponse>(response, true))
            .ThrowsAsync(new DistributionOperationException("idempotency_conflict", StatusCodes.Status409Conflict));

        var replayController = CreateController(authentication.Object, bindings.Object, body);
        var replay = Assert.IsType<ObjectResult>(await replayController.InvalidateInstallation(CancellationToken.None));
        Assert.Equal(StatusCodes.Status200OK, replay.StatusCode);
        Assert.Equal(response, replay.Value);

        var changedController = CreateController(authentication.Object, bindings.Object, body.Replace("grant_revoked", "fraud_flagged", StringComparison.Ordinal));
        var changed = Assert.IsType<ObjectResult>(await changedController.InvalidateInstallation(CancellationToken.None));
        Assert.Equal(StatusCodes.Status409Conflict, changed.StatusCode);
        Assert.Equal(new DistributionApiError("idempotency_conflict"), changed.Value);
    }

    private static DistributionInstallationBindingsController CreateController(
        IDistributionS2SAuthenticationService authentication,
        IDistributionInstallationBindingService bindings,
        string body,
        IRuntimeDistributionPreflightService? preflight = null,
        IFinalizeAuthorityPairResolver? finalizeAuthorityPairs = null)
    {
        var controller = new DistributionInstallationBindingsController(
            authentication, bindings, preflight ?? Mock.Of<IRuntimeDistributionPreflightService>(),
            NullLogger<DistributionInstallationBindingsController>.Instance, finalizeAuthorityPairs);
        var context = new DefaultHttpContext();
        var bytes = Encoding.UTF8.GetBytes(body);
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;
        context.Request.ContentType = "application/json";
        controller.ControllerContext = new ControllerContext { HttpContext = context };
        return controller;
    }
}

/// <summary>Exercises provider-owned hardware derivation, ban refusal, and stored-state failures.</summary>
public sealed class RuntimeDistributionPreflightServiceTests
{
    /// <summary>Canonical isolated product scope shared by each provider decision fixture.</summary>
    private static readonly Guid ProductId = Guid.Parse("12345678-1234-4234-9234-1234567890ab");
    private static readonly Guid LicenseId = Guid.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private const string ClientId = "tia-connect-website";
    private static readonly string GrantDigest = new('c', 64);
    private static readonly string PayloadDigest = new('d', 64);

    [Fact]
    public async Task UnknownInstallation_DerivesLegacyDigestWithoutPersistingRawEvidence()
    {
        var fixture = CreateFixture();
        var response = await EvaluateAsync(fixture, Request(Evidence()));

        Assert.Equal("server-derived", response.AuthorityMode);
        Assert.Matches("^[0-9a-f]{64}$", response.HardwareIdHash);
        await using var db = await fixture.Factory.CreateDbContextAsync();
        Assert.Empty(await db.HardwareFingerprints.ToListAsync());
    }

    [Fact]
    public async Task DigestRevalidation_WithLiveBan_IsRefused()
    {
        var fixture = CreateFixture();
        const string hardwareId = "0123456789ABCDEF";
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = ProductId,
                Reason = "test",
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, DigestRequest(Sha256Lower(hardwareId))));
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
    }

    [Fact]
    public async Task DigestRevalidation_WithoutBanReturnsSameOpaqueDigest()
    {
        var fixture = CreateFixture();
        var hardwareIdHash = Sha256Lower("0123456789ABCDEF");

        var response = await EvaluateAsync(fixture, DigestRequest(hardwareIdHash));

        Assert.Equal("digest-revalidation", response.AuthorityMode);
        Assert.Equal(hardwareIdHash, response.HardwareIdHash);
    }

    [Theory]
    [InlineData(BannedHardwareId.Categories.OutdatedVersion)]
    [InlineData(BannedHardwareId.Categories.QuotaAbuse)]
    public async Task PaidLicense_WithAllowlistedBan_AutoUnbansAndAudits(string category)
    {
        var fixture = CreateFixture();
        const string hardwareId = "0123456789ABCDEF";
        await AddBanAsync(fixture, hardwareId, category);

        var response = await EvaluateAsync(fixture, DigestRequest(Sha256Lower(hardwareId)));

        Assert.Equal("accepted", response.Decision);
        await using var db = await fixture.Factory.CreateDbContextAsync();
        Assert.False((await db.BannedHardwareIds.SingleAsync()).IsActive);
        var decision = await db.RuntimeDistributionHardwareDecisions.SingleAsync();
        Assert.Equal("auto-unbanned", decision.Outcome);
        Assert.Equal(1, decision.AutoUnbannedCount);
        Assert.True(decision.PaidAutoUnbanEligible);
        Assert.Equal($"[\"{category}\"]", decision.BanCategoriesJson);
    }

    [Theory]
    [InlineData(BannedHardwareId.Categories.Piracy)]
    [InlineData(BannedHardwareId.Categories.Debugger)]
    [InlineData(BannedHardwareId.Categories.Manual)]
    [InlineData(BannedHardwareId.Categories.DevCanaryQuarantine)]
    public async Task PaidLicense_WithNonAllowlistedBan_RefusesWithoutMutation(string category)
    {
        var fixture = CreateFixture();
        const string hardwareId = "0123456789ABCDEF";
        await AddBanAsync(fixture, hardwareId, category);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, DigestRequest(Sha256Lower(hardwareId))));

        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
        await using var db = await fixture.Factory.CreateDbContextAsync();
        Assert.True((await db.BannedHardwareIds.SingleAsync()).IsActive);
        Assert.Equal("refused", (await db.RuntimeDistributionHardwareDecisions.SingleAsync()).Outcome);
    }

    [Fact]
    public async Task PaidLicense_WithMixedAllowlistedAndPermanentBans_RefusesAtomically()
    {
        var fixture = CreateFixture();
        const string hardwareId = "0123456789ABCDEF";
        await AddBanAsync(fixture, hardwareId, BannedHardwareId.Categories.OutdatedVersion);
        await AddBanAsync(fixture, hardwareId, BannedHardwareId.Categories.Piracy);

        await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, DigestRequest(Sha256Lower(hardwareId))));

        await using var db = await fixture.Factory.CreateDbContextAsync();
        Assert.All(await db.BannedHardwareIds.ToListAsync(), ban => Assert.True(ban.IsActive));
    }

    [Theory]
    [InlineData("free")]
    [InlineData("expired")]
    [InlineData("revoked")]
    public async Task IneligibleLicense_DoesNotAutoUnbanTemporaryCategory(string state)
    {
        var fixture = CreateFixture();
        const string hardwareId = "0123456789ABCDEF";
        await AddBanAsync(fixture, hardwareId, BannedHardwareId.Categories.OutdatedVersion);
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.Include(item => item.Type).SingleAsync();
            if (state == "free") license.Type!.IsFree = true;
            if (state == "expired") license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
            if (state == "revoked") license.RevokedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }

        await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, DigestRequest(Sha256Lower(hardwareId))));

        await using var verification = await fixture.Factory.CreateDbContextAsync();
        Assert.True((await verification.BannedHardwareIds.SingleAsync()).IsActive);
        Assert.False((await verification.RuntimeDistributionHardwareDecisions.SingleAsync())
            .PaidAutoUnbanEligible);
    }

    [Theory]
    [InlineData("inactive")]
    [InlineData("expired")]
    [InlineData("revoked")]
    public async Task InvalidCommercialAuthority_RefusesEvenWithoutHardwareBan(string state)
    {
        var fixture = CreateFixture();
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            var license = await db.Licenses.SingleAsync();
            if (state == "inactive") license.IsActive = false;
            if (state == "expired") license.ExpirationDate = DateTime.UtcNow.AddMinutes(-1);
            if (state == "revoked") license.RevokedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }

        await Assert.ThrowsAsync<DistributionOperationException>(() => EvaluateAsync(
            fixture, DigestRequest(Sha256Lower("0123456789ABCDEF"))));

        await using var verification = await fixture.Factory.CreateDbContextAsync();
        var decision = await verification.RuntimeDistributionHardwareDecisions.SingleAsync();
        Assert.Equal("commercial_authority_invalid", decision.ReasonCode);
        Assert.Equal("refused", decision.Outcome);
    }

    [Fact]
    public async Task ExactReplay_ReusesDecisionAndIncrementsAttemptCounter()
    {
        var fixture = CreateFixture();
        var request = DigestRequest(Sha256Lower("0123456789ABCDEF"));

        var first = await EvaluateAsync(fixture, request);
        var replay = await EvaluateAsync(fixture, request);

        Assert.Equal(first, replay);
        await using var db = await fixture.Factory.CreateDbContextAsync();
        var decision = await db.RuntimeDistributionHardwareDecisions.SingleAsync();
        Assert.Equal(2, decision.AttemptCount);
        Assert.True(decision.LastSeenAtUtc >= decision.CreatedAtUtc);
    }

    [Fact]
    public async Task DivergentReplay_IsRejectedWithoutReplacingOriginalDecision()
    {
        var fixture = CreateFixture();
        var request = DigestRequest(Sha256Lower("0123456789ABCDEF"));
        await EvaluateAsync(fixture, request);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, request, new string('f', 64)));

        Assert.Equal(StatusCodes.Status400BadRequest, exception.StatusCode);
        await using var db = await fixture.Factory.CreateDbContextAsync();
        Assert.Equal(PayloadDigest, (await db.RuntimeDistributionHardwareDecisions.SingleAsync())
            .PayloadDigestSha256);
    }

    [Fact]
    public async Task AcceptedDecision_WhenRegistryWriteFails_DoesNotReturnAuthority()
    {
        var fixture = CreateFixture(failDecisionWrites: true);

        await Assert.ThrowsAsync<DbUpdateException>(() => EvaluateAsync(
            fixture, DigestRequest(Sha256Lower("0123456789ABCDEF"))));

        await using var db = await fixture.Factory.CreateDbContextAsync();
        Assert.Empty(await db.RuntimeDistributionHardwareDecisions.ToListAsync());
    }

    [Fact]
    public async Task UnknownInstallation_WithBannedDerivedHardware_IsRefused()
    {
        var fixture = CreateFixture();
        var hardwareId = ComputeHardwareId(Evidence(), "DISK-LEGACY");
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = ProductId,
                Reason = "test",
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, Request(Evidence())));
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
    }

    [Fact]
    public async Task UnknownInstallation_WithBannedStableHardware_IsRefused()
    {
        var fixture = CreateFixture();
        var hardwareId = ComputeHardwareId(Evidence(), "DISK-STABLE");
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = ProductId,
                Reason = "test",
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, Request(Evidence())));
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
    }

    [Fact]
    public async Task KnownInstallation_UsesEnrolledDigestWithoutHardwareEvidence()
    {
        var fixture = CreateFixture();
        var request = Request(null);
        var enrolledDigest = new string('a', 64);
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                BindingId = Guid.NewGuid(),
                ProductId = ProductId,
                InstallationId = request.InstallationId!,
                KeyThumbprint = request.KeyThumbprint!,
                HardwareIdHash = enrolledDigest,
                State = "ACTIVE"
            });
            await db.SaveChangesAsync();
        }

        var response = await EvaluateAsync(fixture, request);
        Assert.Equal("known-enrollment", response.AuthorityMode);
        Assert.Equal(enrolledDigest, response.HardwareIdHash);
    }

    [Fact]
    public async Task KnownInstallation_WithWrongKeyThumbprint_IsRefused()
    {
        var fixture = CreateFixture();
        var request = Request(null);
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                BindingId = Guid.NewGuid(),
                ProductId = ProductId,
                InstallationId = request.InstallationId!,
                KeyThumbprint = new string('B', 43),
                HardwareIdHash = new string('a', 64),
                State = "ACTIVE"
            });
            await db.SaveChangesAsync();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, request));
        Assert.Equal(StatusCodes.Status403Forbidden, exception.StatusCode);
    }

    [Fact]
    public async Task KnownInstallation_WithMalformedStoredDigest_FailsClosed()
    {
        var fixture = CreateFixture();
        var request = Request(null);
        await using (var db = await fixture.Factory.CreateDbContextAsync())
        {
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                BindingId = Guid.NewGuid(),
                ProductId = ProductId,
                InstallationId = request.InstallationId!,
                KeyThumbprint = request.KeyThumbprint!,
                HardwareIdHash = "malformed",
                State = "ACTIVE"
            });
            await db.SaveChangesAsync();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            EvaluateAsync(fixture, request));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, exception.StatusCode);
    }

    /// <summary>Builds one canonical authority request with optional fresh-install observations.</summary>
    private static RuntimeDistributionPreflightRequest Request(
        RuntimeDistributionHardwareEvidence? evidence) => new()
        {
            Schema = "runtime-distribution-hardware-authority",
            RequestId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProductId = ProductId.ToString("D"),
            SoftLicenceLicenseId = LicenseId.ToString("D"),
            GrantRefDigestSha256 = GrantDigest,
            InstallationId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            KeyThumbprint = new string('A', 43),
            HardwareEvidence = evidence
        };

    /// <summary>Builds the closed digest-only request used immediately before payload admission.</summary>
    private static RuntimeDistributionPreflightRequest DigestRequest(string hardwareIdHash) => new()
    {
        Schema = "runtime-distribution-hardware-authority",
        RequestId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ProductId = ProductId.ToString("D"),
        SoftLicenceLicenseId = LicenseId.ToString("D"),
        GrantRefDigestSha256 = GrantDigest,
        HardwareIdHash = hardwareIdHash
    };

    /// <summary>Returns deterministic observations shared by derivation and ban fixtures.</summary>
    private static RuntimeDistributionHardwareEvidence Evidence() => new()
    {
        CpuId = "CPU",
        MotherboardId = "BOARD",
        BiosId = "BIOS",
        LegacyDiskId = "DISK-LEGACY",
        StableDiskId = "DISK-STABLE",
        MachineName = "HOST"
    };

    /// <summary>Mirrors the pinned SDK identity solely to arrange a known banned fixture.</summary>
    private static string ComputeHardwareId(RuntimeDistributionHardwareEvidence evidence, string disk)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Concat(evidence.CpuId, evidence.MotherboardId, evidence.BiosId, disk,
                evidence.MachineName)));
        return Convert.ToHexString(bytes)[..16];
    }

    /// <summary>Creates the exact lowercase digest that the Website is permitted to persist.</summary>
    private static string Sha256Lower(string value) => Convert.ToHexString(
        System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    /// <summary>Adds one exact live ban to the isolated product scope.</summary>
    private static async Task AddBanAsync(Fixture fixture, string hardwareId, string category)
    {
        await using var db = await fixture.Factory.CreateDbContextAsync();
        db.BannedHardwareIds.Add(new BannedHardwareId
        {
            HardwareId = hardwareId, ProductId = ProductId, Reason = "test",
            BanCategory = category, IsActive = true
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Creates an isolated in-memory provider service without external persistence or network calls.</summary>
    private static Fixture CreateFixture(bool failDecisionWrites = false)
    {
        var builder = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"));
        if (failDecisionWrites) builder.AddInterceptors(new DecisionWriteFailureInterceptor());
        var options = builder.Options;
        var factory = new TestDbContextFactory(options);
        using (var db = factory.CreateDbContext())
        {
            var typeId = Guid.NewGuid();
            db.Products.Add(new Product
            {
                Id = ProductId, Name = "T-IA Connect", PrivateKeyXml = "test", PublicKeyXml = "test"
            });
            db.LicenseTypes.Add(new LicenseType
            {
                Id = typeId, ProductId = ProductId, Name = "Professional", Slug = "PRO", IsFree = false
            });
            db.Licenses.Add(new License
            {
                Id = LicenseId, ProductId = ProductId, LicenseTypeId = typeId,
                LicenseKey = "TEST-ONLY", IsActive = true
            });
            db.DistributionEntitlements.Add(new DistributionEntitlement
            {
                Id = Guid.NewGuid(), ClientId = ClientId, ProductId = ProductId,
                LicenseId = LicenseId, GrantRefDigestSha256 = GrantDigest,
                SubjectRefDigestSha256 = new string('e', 64), ContractVersion = 3,
                State = "issued", IssuedAtUtc = DateTime.UtcNow.AddMinutes(-1),
                ExpiresAtUtc = DateTime.UtcNow.AddHours(1)
            });
            db.SaveChanges();
        }
        return new Fixture(factory, new RuntimeDistributionPreflightService(
            factory, Mock.Of<ILogger<RuntimeDistributionPreflightService>>()));
    }

    /// <summary>Evaluates one authenticated request with stable provider boundary inputs.</summary>
    private static Task<RuntimeDistributionPreflightResponse> EvaluateAsync(
        Fixture fixture, RuntimeDistributionPreflightRequest request, string? payloadDigest = null) =>
        fixture.Service.EvaluateAsync(ClientId, payloadDigest ?? PayloadDigest, request, CancellationToken.None);

    /// <summary>Groups the isolated database factory with the service under test.</summary>
    /// <param name="Factory">Factory sharing the test's isolated in-memory database.</param>
    /// <param name="Service">Concrete provider authority evaluated by the test.</param>
    private sealed record Fixture(
        TestDbContextFactory Factory,
        RuntimeDistributionPreflightService Service);

    /// <summary>Creates contexts over one isolated in-memory database for each test.</summary>
    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);

        /// <inheritdoc />
        public Task<LicenseDbContext> CreateDbContextAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>Simulates durable registry failure without affecting commercial fixture seeding.</summary>
    private sealed class DecisionWriteFailureInterceptor : SaveChangesInterceptor
    {
        /// <inheritdoc />
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (eventData.Context?.ChangeTracker.Entries<RuntimeDistributionHardwareDecision>()
                .Any(entry => entry.State == EntityState.Added) == true)
                throw new DbUpdateException("Synthetic registry failure.");
            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }
}

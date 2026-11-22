using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002919 boundary tests without a database: dedicated relink identity and its client links at startup, strict
/// request parsing, and the controller's fail-closed answers before any relink work.
/// </summary>
public sealed class RuntimeAccountRelinkContractTests
{
    private const string ProductId = "12345678-1234-4234-9234-1234567890ab";
    private const string RelinkClientId = "website-account-relink";
    private const string DistributionClientId = "website-step1";

    /// <summary>The relink right shared with any other right on the same identity fails startup validation.</summary>
    [Fact]
    public void Options_AccountRelinkSharedWithOtherRight_FailsValidation()
    {
        var result = Validate(client => client.AllowRuntimeRecovery = true);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, failure => failure.Contains("Runtime account relink requires one dedicated client identity"));
    }

    /// <summary>The relink right without any linked distribution client fails startup validation.</summary>
    [Fact]
    public void Options_AccountRelinkWithoutLinkedClients_FailsValidation()
    {
        var result = Validate(client => client.AccountRelinkForClientIds = []);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, failure => failure.Contains("non-empty AccountRelinkForClientIds"));
    }

    /// <summary>Linked clients on an identity without the relink right fail startup validation.</summary>
    [Fact]
    public void Options_LinkedClientsWithoutAccountRelink_FailsValidation()
    {
        var result = Validate(client =>
        {
            client.AllowRuntimeAccountRelink = false;
            client.AllowRuntimeRecovery = true;
        });

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, failure => failure.Contains("allowed only with AllowRuntimeAccountRelink"));
    }

    /// <summary>The identity cannot list itself, and a key rotation cannot widen the linked clients.</summary>
    [Theory]
    [InlineData("self")]
    [InlineData("rotation")]
    [InlineData("non-canonical")]
    public void Options_InvalidLinkedClients_FailValidation(string mutation)
    {
        using var rsa = RSA.Create(2048);
        var first = Client(rsa);
        var second = Client(rsa);
        second.KeyId = "account-relink-2026-11";
        if (mutation == "self")
            first.AccountRelinkForClientIds = [DistributionClientId, RelinkClientId];
        if (mutation == "rotation")
            second.AccountRelinkForClientIds = [DistributionClientId, "another-client"];
        if (mutation == "non-canonical")
            first.AccountRelinkForClientIds = ["Website-Step1"];

        var result = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            Clients = mutation == "rotation" ? [first, second, DistributionClient(rsa)] : [first, DistributionClient(rsa)]
        });

        Assert.True(result.Failed);
    }

    /// <summary>A linked client that no configured S2S identity carries fails startup validation (typo at deployment).</summary>
    [Fact]
    public void Options_LinkedClientNotConfigured_FailsValidation()
    {
        using var rsa = RSA.Create(2048);
        var result = new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions { Clients = [Client(rsa)] });

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, failure => failure.Contains("must name configured Distribution S2S clients"));
    }

    /// <summary>A dedicated identity linked to one distribution client is valid.</summary>
    [Fact]
    public void Options_DedicatedAccountRelinkIdentity_IsValid()
    {
        Assert.False(Validate(_ => { }).Failed);
    }

    /// <summary>Unknown properties, non-canonical identifiers and a missing proof are told apart by the parser.</summary>
    [Fact]
    public void Parse_IsStrict_AndLeavesProofFailuresToTheService()
    {
        Assert.NotNull(RuntimeAccountRelinkContract.Parse(Body()));
        var withoutProof = RuntimeAccountRelinkContract.Parse(Body(body => body.Remove("installationProof")));
        Assert.NotNull(withoutProof);
        Assert.Null(withoutProof.Proof);
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["unexpected"] = 1)));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["productId"] = ProductId.ToUpperInvariant())));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["hardwareId"] = "a00272b768ffd6af")));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["securityEpoch"] = 0)));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["installationSubjectRefDigestSha256"] = new string('A', 64))));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["schema"] = "softlicence.runtime-account-relink.request.v2")));
    }

    /// <summary>
    /// TKT-003350: <c>ownerSubjectId</c> stays a mandatory property but may be an explicit JSON null; an absent
    /// property, an empty string, the nil UUID, a non-canonical spelling or another JSON type is still refused.
    /// </summary>
    [Fact]
    public void Parse_OwnerSubjectId_AcceptsExplicitNull_RefusesEverythingElse()
    {
        var withoutOwner = RuntimeAccountRelinkContract.Parse(Body(body => body["ownerSubjectId"] = null));
        Assert.NotNull(withoutOwner);
        Assert.Null(withoutOwner.OwnerSubjectId);
        Assert.Equal(Guid.Parse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), RuntimeAccountRelinkContract.Parse(Body())!.OwnerSubjectId);
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body.Remove("ownerSubjectId"))));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["ownerSubjectId"] = "")));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["ownerSubjectId"] = Guid.Empty.ToString("D"))));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["ownerSubjectId"] = "EEEEEEEE-EEEE-4EEE-8EEE-EEEEEEEEEEEE")));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["ownerSubjectId"] = 0)));
    }

    /// <summary>
    /// TKT-003753: <c>ownerAttestation</c> is optional; when present it must be exactly
    /// <c>website_same_account_v1</c> with a null <c>ownerSubjectId</c>. JSON null, another value, a different case,
    /// another JSON type or an attestation beside an owner is refused (400); the body digest covers the field.
    /// </summary>
    [Fact]
    public void Parse_OwnerAttestation_OnlyFrozenValue_OnlyWithoutOwner()
    {
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body())!.OwnerAttestation);
        var attested = RuntimeAccountRelinkContract.Parse(Body(body =>
        {
            body["ownerSubjectId"] = null;
            body["ownerAttestation"] = "website_same_account_v1";
        }));
        Assert.NotNull(attested);
        Assert.Equal(RuntimeAccountRelinkContract.WebsiteSameAccountAttestation, attested.OwnerAttestation);
        Assert.Null(attested.OwnerSubjectId);
        Assert.NotEqual(RuntimeAccountRelinkContract.Parse(Body(body => body["ownerSubjectId"] = null))!.BodyDigestSha256,
            attested.BodyDigestSha256);
        foreach (var value in new JsonNode?[] { null, "website_same_account_v2", "WEBSITE_SAME_ACCOUNT_V1", " website_same_account_v1", 1, true })
            Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body =>
            {
                body["ownerSubjectId"] = null;
                body["ownerAttestation"] = value?.DeepClone();
            })));
        Assert.Null(RuntimeAccountRelinkContract.Parse(Body(body => body["ownerAttestation"] = "website_same_account_v1")));
    }

    /// <summary>An authenticated identity without the relink right receives the exact 403 and the service is never called.</summary>
    [Fact]
    public async Task AccountRelink_PrincipalWithoutRight_Returns403()
    {
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);
        var s2s = new Mock<IDistributionS2SAuthenticationService>();
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(DistributionClientId, "site-key", AllowRuntimeRecovery: true));

        var (status, body) = await InvokeAsync(s2s.Object, runtime.Object, "enabled", Body());

        Assert.Equal(StatusCodes.Status403Forbidden, status);
        Assert.Equal("{\"error\":\"account_relink_not_authorized\"}", body);
    }

    /// <summary>A malformed body is 400 before authentication, so no S2S nonce is consumed.</summary>
    [Fact]
    public async Task AccountRelink_InvalidBody_Returns400_WithoutAuthentication()
    {
        var s2s = new Mock<IDistributionS2SAuthenticationService>(MockBehavior.Strict);
        var runtime = new Mock<IRuntimeEnrollmentService>(MockBehavior.Strict);

        var (status, body) = await InvokeAsync(s2s.Object, runtime.Object, "enabled", Body(json => json["extra"] = true));

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Equal("{\"error\":\"invalid_request\"}", body);
    }

    /// <summary>Runtime enrollment disabled: 503 provider_unavailable before reading anything.</summary>
    [Fact]
    public async Task AccountRelink_RuntimeDisabled_Returns503()
    {
        var (status, body) = await InvokeAsync(
            Mock.Of<IDistributionS2SAuthenticationService>(MockBehavior.Strict),
            Mock.Of<IRuntimeEnrollmentService>(MockBehavior.Strict), "off", Body());

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, status);
        Assert.Equal("{\"error\":\"provider_unavailable\"}", body);
    }

    /// <summary>Service refusals leave only the public code; the server diagnostic never reaches the body.</summary>
    [Fact]
    public async Task AccountRelink_ServiceRefusal_ReturnsOnlyPublicCode()
    {
        var s2s = new Mock<IDistributionS2SAuthenticationService>();
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(RelinkClientId, "account-relink-2026-10",
                AllowRuntimeAccountRelink: true, AccountRelinkForClientIds: [DistributionClientId]));
        var runtime = new Mock<IRuntimeEnrollmentService>();
        runtime.Setup(service => service.RelinkAccountAsync(
                It.IsAny<DistributionS2SPrincipal>(), It.IsAny<RuntimeAccountRelinkCommand>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RuntimeEnrollmentException("authority_ineligible", StatusCodes.Status422UnprocessableEntity, "seat_not_released"));

        var (status, body) = await InvokeAsync(s2s.Object, runtime.Object, "enabled", Body());

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, status);
        Assert.Equal("{\"error\":\"authority_ineligible\"}", body);
    }

    /// <summary>
    /// TKT-004085 (review 2498): a named 409 assignment refusal keeps the exact relink body <c>{"error":"code"}</c>, and
    /// only <c>seat_assignment_busy</c> adds <c>Retry-After: 5</c>; the bounded reason never reaches the body.
    /// </summary>
    [Theory]
    [InlineData(AssignmentRefusals.BusyCode, "concurrent_seat_claimant", "5")]
    [InlineData(AssignmentRefusals.ReconciliationRequiredCode, "seat_release_assignment_missing", null)]
    public async Task AccountRelink_NamedAssignmentRefusal_KeepsExactBodyAndRetryAfterOnlyWhenBusy(
        string code, string reason, string? retryAfter)
    {
        var s2s = new Mock<IDistributionS2SAuthenticationService>();
        s2s.Setup(service => service.AuthenticateAndReserveNonceAsync(
                It.IsAny<HttpContext>(), It.IsAny<ReadOnlyMemory<byte>>(), ProductId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DistributionS2SPrincipal(RelinkClientId, "account-relink-2026-10",
                AllowRuntimeAccountRelink: true, AccountRelinkForClientIds: [DistributionClientId]));
        var runtime = new Mock<IRuntimeEnrollmentService>();
        runtime.Setup(service => service.RelinkAccountAsync(
                It.IsAny<DistributionS2SPrincipal>(), It.IsAny<RuntimeAccountRelinkCommand>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RuntimeEnrollmentException(code, StatusCodes.Status409Conflict, reason));

        var (status, body, headers) = await InvokeWithHeadersAsync(s2s.Object, runtime.Object, "enabled", Body());

        Assert.Equal(StatusCodes.Status409Conflict, status);
        Assert.Equal("{\"error\":\"" + code + "\"}", body);
        if (retryAfter is null)
            Assert.False(headers.ContainsKey("Retry-After"));
        else
            Assert.Equal(retryAfter, headers.RetryAfter.ToString());
    }

    /// <summary>Validates options holding one dedicated relink identity after <paramref name="mutate"/>.</summary>
    private static ValidateOptionsResult Validate(Action<DistributionS2SClientOptions> mutate)
    {
        using var rsa = RSA.Create(2048);
        var client = Client(rsa);
        mutate(client);
        return new DistributionS2SOptionsValidator().Validate(null, new DistributionS2SOptions
        {
            Clients = [client, DistributionClient(rsa)]
        });
    }

    /// <summary>One valid dedicated relink identity key entry linked to the distribution client.</summary>
    private static DistributionS2SClientOptions Client(RSA rsa) => new()
    {
        ClientId = RelinkClientId,
        KeyId = "account-relink-2026-10",
        PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
        AllowRuntimeAccountRelink = true,
        AccountRelinkForClientIds = [DistributionClientId],
        ProductIds = [ProductId],
        AllowedCidrs = ["127.0.0.1/32"]
    };

    /// <summary>The distribution client the relink identity is linked to, configured with its own right.</summary>
    private static DistributionS2SClientOptions DistributionClient(RSA rsa) => new()
    {
        ClientId = DistributionClientId,
        KeyId = "website-step1-2026-10",
        PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
        AllowRuntimeRecovery = true,
        ProductIds = [ProductId],
        AllowedCidrs = ["127.0.0.1/32"]
    };

    /// <summary>A syntactically valid request body, optionally altered; the proof is well formed but not verified here.</summary>
    private static byte[] Body(Action<JsonObject>? mutate = null)
    {
        var body = new JsonObject
        {
            ["schema"] = RuntimeAccountRelinkContract.RequestSchema,
            ["requestId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ["productId"] = ProductId,
            ["enrollmentId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ["installationId"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            ["licenseId"] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            ["hardwareId"] = "A00272B768FFD6AF",
            ["releaseVersion"] = "2.5.626",
            ["securityEpoch"] = 1,
            ["installationSubjectRefDigestSha256"] = new string('a', 64),
            ["ownerSubjectId"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            ["installationProof"] = new JsonObject
            {
                ["timestamp"] = "2026-11-03T07:00:00.0000000Z",
                ["jti"] = "ffffffff-ffff-4fff-8fff-ffffffffffff",
                ["signature"] = new string('A', 512)
            }
        };
        mutate?.Invoke(body);
        return Encoding.UTF8.GetBytes(body.ToJsonString());
    }

    /// <summary>Runs the controller action over an HTTPS request carrying <paramref name="body"/>; returns status and body text.</summary>
    private static async Task<(int Status, string Body)> InvokeAsync(
        IDistributionS2SAuthenticationService s2s, IRuntimeEnrollmentService runtime, string mode, byte[] body)
    {
        var (status, text, _) = await InvokeWithHeadersAsync(s2s, runtime, mode, body);
        return (status, text);
    }

    /// <summary>
    /// Runs the controller action like <see cref="InvokeAsync"/> and also returns the response headers the action
    /// set on the HTTP context (for example <c>Retry-After</c>).
    /// </summary>
    private static async Task<(int Status, string Body, IHeaderDictionary Headers)> InvokeWithHeadersAsync(
        IDistributionS2SAuthenticationService s2s, IRuntimeEnrollmentService runtime, string mode, byte[] body)
    {
        var controller = new RuntimeAccountRelinksController(s2s, runtime,
            Options.Create(new RuntimeEnrollmentOptions { Mode = mode }));
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Scheme = "https";
        context.Request.Path = RuntimeAccountRelinkContract.Path;
        context.Request.ContentType = "application/json; charset=utf-8";
        context.Request.ContentLength = body.Length;
        context.Request.Body = new MemoryStream(body);
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var result = Assert.IsType<FileContentResult>(await controller.Relink(CancellationToken.None));
        return (context.Response.StatusCode, Encoding.UTF8.GetString(result.FileContents), context.Response.Headers);
    }
}

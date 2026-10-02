using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Exposes the TKT-000672 producer only when the test assembly is explicitly registered as an MVC application part.
/// The production server does not reference or discover this controller.
/// </summary>
[ApiController]
internal sealed class Tkt000672SourceCAuthorityController : ControllerBase
{
    /// <summary>Gets the exact test-assembly-only POST route, absent from production application parts.</summary>
    internal const string Route = "/api/internal/test/v1/runtime-enrollment-source-c-authority";
    private readonly Tkt000672SourceCAuthorityHarness harness;
    private readonly Tkt000672SourceCAuthorityGate gate;
    private readonly IWebHostEnvironment hostEnvironment;
    private readonly ITkt000672SourceCAuthorityAuthorization authorization;

    /// <summary>Creates the test-only transport boundary over an explicitly registered harness and gate.</summary>
    /// <param name="harness">Bounded real-flow composition.</param>
    /// <param name="gate">Default-off capability configuration registered by the test host.</param>
    /// <param name="hostEnvironment">Authoritative ASP.NET host environment.</param>
    /// <param name="authorization">Authenticated S2S principal authorization boundary.</param>
    public Tkt000672SourceCAuthorityController(
        Tkt000672SourceCAuthorityHarness harness,
        Tkt000672SourceCAuthorityGate gate,
        IWebHostEnvironment hostEnvironment,
        ITkt000672SourceCAuthorityAuthorization authorization)
    {
        this.harness = harness;
        this.gate = gate;
        this.hostEnvironment = hostEnvironment;
        this.authorization = authorization;
    }

    /// <summary>
    /// Reads at most 16,385 bytes, validates the closed request before dispatch, then returns exact JSON bytes.
    /// No rejected value, raw tuple, provider value, credential, or signature input is logged or echoed.
    /// </summary>
    /// <param name="cancellationToken">Request cancellation propagated through all real flows.</param>
    /// <returns>A metadata-only signed manifest or a stable closed refusal.</returns>
    [HttpPost(Route)]
    public async Task<IActionResult> Produce(CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
        if (!gate.Enabled)
            return Refusal(StatusCodes.Status404NotFound, "CAPABILITY_DISABLED", "capability");
        if (!string.Equals(hostEnvironment.EnvironmentName, "Development", StringComparison.Ordinal))
            return Refusal(StatusCodes.Status404NotFound, "NON_PRODUCTION_GATE_REQUIRED", "environment");
        var access = await authorization.AuthorizeAsync(HttpContext, gate, cancellationToken);
        if (!access.IsAuthenticated)
            return Refusal(StatusCodes.Status401Unauthorized, "SERVICE_AUTHENTICATION_REQUIRED", "client");
        if (!access.IsAuthorized)
            return Refusal(StatusCodes.Status403Forbidden, "PERMISSION_REQUIRED", "permission");
        if (!string.Equals(Request.ContentType, "application/json", StringComparison.Ordinal))
            return Refusal(StatusCodes.Status415UnsupportedMediaType, "CONTENT_TYPE_INVALID", "contentType");
        var body = await ReadBoundedBodyAsync(cancellationToken);
        if (body is null)
            return Refusal(StatusCodes.Status413PayloadTooLarge, "REQUEST_SIZE_INVALID", "request");
        var parsed = Tkt000672SourceCAuthorityContract.ParseRequest(body);
        if (!parsed.Ok)
            return Refusal(StatusCodes.Status400BadRequest, parsed.Reason!, parsed.Field!);
        var result = await harness.RunAsync(parsed.Request!, cancellationToken);
        if (!result.Ok)
        {
            var status = result.Reason switch
            {
                _ => StatusCodes.Status409Conflict
            };
            return Refusal(status, result.Reason!, result.Field!);
        }
        return File(JsonSerializer.SerializeToUtf8Bytes(result.Response, SerializerOptions), "application/json");
    }

    /// <summary>Gets the deterministic compact response serializer used for exact HTTP bytes.</summary>
    private static JsonSerializerOptions SerializerOptions { get; } = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false
    };

    /// <summary>Reads at most one byte beyond the request limit so overflow fails before parsing.</summary>
    private async Task<byte[]?> ReadBoundedBodyAsync(CancellationToken cancellationToken)
    {
        var limit = Tkt000672SourceCAuthorityContract.RequestUtf8Limit;
        var buffer = new byte[limit + 1];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = await Request.Body.ReadAsync(buffer.AsMemory(count, buffer.Length - count), cancellationToken);
            if (read == 0) break;
            count += read;
        }
        if (count > limit) return null;
        return buffer[..count];
    }

    /// <summary>Creates one stable metadata-only HTTP refusal without echoing caller values.</summary>
    private ObjectResult Refusal(int status, string reason, string field) =>
        StatusCode(status, new Tkt000672Refusal(reason, field));
}

/// <summary>Authorizes an already authenticated test-host S2S principal without consulting request headers.</summary>
internal interface ITkt000672SourceCAuthorityAuthorization
{
    /// <summary>
    /// Evaluates the authoritative host principal and exact permission before the controller reads the body.
    /// </summary>
    /// <param name="context">Current ASP.NET request context containing the authenticated principal.</param>
    /// <param name="gate">Closed expected client and permission configuration.</param>
    /// <param name="cancellationToken">Cancellation observed before authorization work.</param>
    /// <returns>Only the two closed authentication and authorization decisions.</returns>
    ValueTask<Tkt000672AuthorizationDecision> AuthorizeAsync(
        HttpContext context, Tkt000672SourceCAuthorityGate gate, CancellationToken cancellationToken);
}

/// <summary>Closed authorization decision that contains no caller-controlled identity value.</summary>
internal sealed record Tkt000672AuthorizationDecision(bool IsAuthenticated, bool IsAuthorized);

/// <summary>Uses only the authenticated ClaimsPrincipal established by the explicitly registered test host.</summary>
internal sealed class Tkt000672ClaimsAuthorization : ITkt000672SourceCAuthorityAuthorization
{
    /// <summary>Gets the exact authenticated service-client claim type.</summary>
    internal const string ClientIdClaim = "client_id";
    /// <summary>Gets the repeatable exact permission claim type.</summary>
    internal const string PermissionClaim = "permission";

    /// <inheritdoc />
    public ValueTask<Tkt000672AuthorizationDecision> AuthorizeAsync(
        HttpContext context, Tkt000672SourceCAuthorityGate gate, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var principal = context.User;
        var authenticated = principal.Identity?.IsAuthenticated == true
            && principal.FindAll(ClientIdClaim).Count() == 1
            && string.Equals(principal.FindFirst(ClientIdClaim)?.Value, gate.AuthorizedClientId,
                StringComparison.Ordinal);
        var permitted = authenticated && principal.FindAll(PermissionClaim)
            .Any(claim => string.Equals(claim.Value, gate.RequiredPermission, StringComparison.Ordinal));
        return ValueTask.FromResult(new Tkt000672AuthorizationDecision(authenticated, permitted));
    }
}

/// <summary>Closed stable HTTP refusal containing no caller-supplied values.</summary>
internal sealed record Tkt000672Refusal(
    [property: System.Text.Json.Serialization.JsonPropertyName("reason")] string Reason,
    [property: System.Text.Json.Serialization.JsonPropertyName("field")] string Field);

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// TKT-002919 transport boundary of the account relink: exact bytes, S2S authentication with its nonce, the
/// dedicated <c>AllowRuntimeAccountRelink</c> right, then the service. Every answer is an exact JSON body with
/// <c>no-store</c>; refusals are <c>{"error":"code"}</c> only.
/// </summary>
[ApiController]
public sealed class RuntimeAccountRelinksController : ControllerBase
{
    private const string JsonContentType = "application/json; charset=utf-8";
    private readonly IDistributionS2SAuthenticationService s2s;
    private readonly IRuntimeEnrollmentService runtime;
    private readonly RuntimeEnrollmentOptions options;

    /// <summary>Creates the boundary; it owns no seat decision.</summary>
    /// <param name="s2s">Exact-bytes S2S authentication and nonce reservation.</param>
    /// <param name="runtime">Runtime enrollment service performing the relink.</param>
    /// <param name="options">Runtime enrollment mode; the route answers 503 when it is not enabled.</param>
    public RuntimeAccountRelinksController(
        IDistributionS2SAuthenticationService s2s,
        IRuntimeEnrollmentService runtime,
        IOptions<RuntimeEnrollmentOptions> options)
    {
        this.s2s = s2s;
        this.runtime = runtime;
        this.options = options.Value;
    }

    /// <summary>
    /// Relinks the installation of the account signed in inside the application, or replays the frozen answer.
    /// </summary>
    /// <remarks>
    /// The body is parsed before authentication only to learn the product scope the S2S signature is checked
    /// against, as the other internal routes do; a malformed body is 400 <c>invalid_request</c> without nonce.
    /// An identity without the right, including when no relink identity is configured at all, receives 403
    /// <c>account_relink_not_authorized</c> (fail closed, decision of 31/10/2026).
    /// </remarks>
    /// <param name="cancellationToken">Cancels reading, authentication or the relink transaction.</param>
    /// <returns>The exact contract response.</returns>
    [HttpPost(RuntimeAccountRelinkContract.Path)]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> Relink(CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
        if (options.Mode != "enabled")
            return Error(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
        try
        {
            if (!string.Equals(Request.Path.Value, RuntimeAccountRelinkContract.Path, StringComparison.Ordinal)
                || Request.QueryString.HasValue
                || Request.Headers.ContainsKey("Transfer-Encoding")
                || !string.Equals(Request.ContentType, JsonContentType, StringComparison.Ordinal))
                return Error(StatusCodes.Status400BadRequest, "invalid_request");
            var body = await ReadBodyAsync(cancellationToken);
            if (body is null)
                return Error(StatusCodes.Status400BadRequest, "invalid_request");
            var command = RuntimeAccountRelinkContract.Parse(body);
            if (command is null)
                return Error(StatusCodes.Status400BadRequest, "invalid_request");
            var principal = await s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, body, command.ProductId.ToString("D"), cancellationToken);
            if (!principal.AllowRuntimeAccountRelink)
                return Error(StatusCodes.Status403Forbidden, "account_relink_not_authorized");
            var result = await runtime.RelinkAccountAsync(principal, command, cancellationToken);
            Response.StatusCode = StatusCodes.Status200OK;
            return File(result.ExactBody, JsonContentType);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return Error(exception.StatusCode, exception.ErrorCode);
        }
        catch (RuntimeEnrollmentException exception)
        {
            // Only the closed public code leaves the server; the diagnostic stays internal and the body stays the exact
            // {"error":"code"} the website parses. TKT-004085: a seat_assignment_busy refusal also carries Retry-After.
            AssignmentRefusals.ApplyRetryAfter(Response, exception.ErrorCode);
            return Error(exception.StatusCode, exception.ErrorCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Error(StatusCodes.Status503ServiceUnavailable, "provider_unavailable");
        }
    }

    /// <summary>
    /// Reads at most <see cref="RuntimeAccountRelinkContract.MaximumRequestBytes"/> bytes without trusting
    /// Content-Length; returns null for an empty or oversized body.
    /// </summary>
    private async Task<byte[]?> ReadBodyAsync(CancellationToken cancellationToken)
    {
        if (Request.ContentLength is > RuntimeAccountRelinkContract.MaximumRequestBytes)
            return null;
        await using var stream = new MemoryStream();
        var buffer = new byte[1024];
        while (true)
        {
            var read = await Request.Body.ReadAsync(buffer, cancellationToken);
            if (read == 0)
                break;
            if (stream.Length + read > RuntimeAccountRelinkContract.MaximumRequestBytes)
                return null;
            await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        return stream.Length == 0 ? null : stream.ToArray();
    }

    /// <summary>Exact refusal body <c>{"error":"code"}</c> with its status.</summary>
    private IActionResult Error(int statusCode, string errorCode)
    {
        Response.StatusCode = statusCode;
        return File(RuntimeAccountRelinkContract.ErrorBody(errorCode), JsonContentType);
    }
}

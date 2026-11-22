using System.Text.Json;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Middlewares;

/// <summary>
/// Last-resort handler for exceptions that escape an <c>/api</c> action (TKT-004085). Before it, such an exception gave
/// an empty HTTP 500 in production (and the developer page, with database text, in Development): the client could not
/// tell a licence state from an outage. It writes a bounded JSON body with a correlation reference instead.
/// </summary>
/// <remarks>
/// <para>
/// Classification, first match wins: a refusal of the PostgreSQL assignment trigger becomes its named 409
/// (<see cref="AssignmentRefusals"/>); a <see cref="DistributionOperationException"/> or
/// <see cref="RuntimeEnrollmentException"/> keeps its own code and status; anything else is 500
/// <c>internal_error</c>. The exception text, type and stack are logged with the correlation identifier and never
/// written to the response.
/// </para>
/// <para>
/// Body shape: server-to-server routes under <c>/api/internal</c> receive only <c>{"error"}</c> or
/// <c>{"error","reasonCode"}</c>, the only error shapes the website's strict parsers accept; public routes also receive
/// <c>message</c> (named codes only) and <c>correlationId</c>. Requests outside <c>/api</c>, cancelled requests and
/// responses already started are left to the framework unchanged.
/// </para>
/// <para>
/// Registered after <see cref="AuditMiddleware"/>, so the audit log records the final status written here.
/// </para>
/// </remarks>
public sealed class ApiExceptionSafetyNetMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ApiExceptionSafetyNetMiddleware> _logger;

    /// <summary>Creates the middleware around the authorization, routing and controller pipeline.</summary>
    /// <param name="next">The downstream pipeline.</param>
    /// <param name="logger">Receives the original exception with the correlation identifier.</param>
    public ApiExceptionSafetyNetMiddleware(RequestDelegate next, ILogger<ApiExceptionSafetyNetMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    /// <summary>
    /// Runs the downstream pipeline and converts an escaping exception of an <c>/api</c> request into a JSON error.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <exception cref="Exception">
    /// Rethrown unchanged when the request is outside <c>/api</c>, was aborted by the client, or the response has
    /// already started (headers sent: a body can no longer be written safely).
    /// </exception>
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception exception) when (ShouldHandle(context, exception))
        {
            await WriteErrorAsync(context, exception);
        }
    }

    /// <summary>Returns whether this middleware owns the response for <paramref name="exception"/>.</summary>
    /// <param name="context">The current request.</param>
    /// <param name="exception">The escaping exception.</param>
    private static bool ShouldHandle(HttpContext context, Exception exception) =>
        context.Request.Path.StartsWithSegments("/api")
        && !context.Response.HasStarted
        && !(exception is OperationCanceledException && context.RequestAborted.IsCancellationRequested);

    /// <summary>
    /// Classifies the exception, logs it once with the correlation identifier, and writes the bounded JSON body.
    /// </summary>
    /// <param name="context">The current request; its response is cleared first.</param>
    /// <param name="exception">The escaping exception.</param>
    private async Task WriteErrorAsync(HttpContext context, Exception exception)
    {
        string error;
        int status;
        string? reason = null;
        if (AssignmentRefusals.TryTranslate(exception, out var assignmentRefusal))
        {
            (error, status, reason) = (assignmentRefusal.ErrorCode, assignmentRefusal.StatusCode, assignmentRefusal.ReasonCode);
        }
        else if (exception is DistributionOperationException distribution)
        {
            (error, status) = (distribution.ErrorCode, distribution.StatusCode);
            // Only named assignment codes and assignment-state reasons (TKT-004106) are published; other diagnostics
            // stay server-side. Same rule as every controller, through AssignmentRefusals.PublicReasonCode.
            reason = AssignmentRefusals.PublicReasonCode(distribution.ErrorCode, distribution.ReasonCode);
        }
        else if (exception is RuntimeEnrollmentException runtime)
        {
            (error, status) = (runtime.ErrorCode, runtime.StatusCode);
            reason = AssignmentRefusals.PublicReasonCode(runtime.ErrorCode, runtime.DiagnosticCode);
        }
        else
        {
            (error, status) = ("internal_error", StatusCodes.Status500InternalServerError);
        }

        var correlationId = context.TraceIdentifier;
        if (status >= StatusCodes.Status500InternalServerError)
            _logger.LogError(exception, "API_UNHANDLED_EXCEPTION Path={Path} Code={Code} CorrelationId={CorrelationId}",
                context.Request.Path.Value, error, correlationId);
        else
            _logger.LogWarning(exception, "API_NAMED_REFUSAL Path={Path} Code={Code} Reason={Reason} CorrelationId={CorrelationId}",
                context.Request.Path.Value, error, reason, correlationId);

        context.Response.Clear();
        context.Response.StatusCode = status;
        context.Response.Headers.CacheControl = "no-store, max-age=0";
        AssignmentRefusals.ApplyRetryAfter(context.Response, error);
        context.Response.ContentType = "application/json; charset=utf-8";
        await context.Response.WriteAsync(JsonSerializer.Serialize(
            BuildBody(context.Request.Path.StartsWithSegments("/api/internal"), error, reason, correlationId)));
    }

    /// <summary>
    /// Builds the JSON body; properties are added only when they have a value so that the server-to-server shape stays
    /// exactly <c>{"error"}</c> or <c>{"error","reasonCode"}</c>.
    /// </summary>
    /// <param name="internalRoute">True for <c>/api/internal</c> server-to-server routes.</param>
    /// <param name="error">Public error code.</param>
    /// <param name="reason">Bounded public reason, or null.</param>
    /// <param name="correlationId">Request trace identifier, written only on public routes.</param>
    private static Dictionary<string, string> BuildBody(bool internalRoute, string error, string? reason, string correlationId)
    {
        var body = new Dictionary<string, string>(StringComparer.Ordinal) { ["error"] = error };
        if (reason != null)
            body["reasonCode"] = reason;
        if (internalRoute)
            return body;
        if (AssignmentRefusals.MessageFor(error) is { } message)
            body["message"] = message;
        body["correlationId"] = correlationId;
        return body;
    }
}

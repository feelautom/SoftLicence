using SoftLicence.Server.Models;

namespace SoftLicence.Server.Middlewares;

/// <summary>
/// Keeps transport-generated failures on the dedicated Recovery endpoint inside its bounded privacy-safe response envelope.
/// </summary>
public sealed class RecoveryTelemetryResponseEnvelopeMiddleware
{
    private const string RecoveryPath = "/api/telemetry/recovery/v1/events";
    private readonly RequestDelegate next;

    /// <summary>Creates the middleware around the downstream routing, throttling, and controller pipeline.</summary>
    public RecoveryTelemetryResponseEnvelopeMiddleware(RequestDelegate next)
    {
        this.next = next;
    }

    /// <summary>
    /// Captures only the exact Recovery route so automatic 415, 429, and 5xx responses cannot expose another response schema or internal details.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.Equals(RecoveryPath, StringComparison.Ordinal))
        {
            await next(context);
            return;
        }

        var originalBody = context.Response.Body;
        await using var capturedBody = new MemoryStream(capacity: 512);
        context.Response.Body = capturedBody;
        try
        {
            try
            {
                await next(context);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                await WriteClosedFailureAsync(context, originalBody, StatusCodes.Status500InternalServerError);
                return;
            }

            if (RequiresClosedTransportEnvelope(context.Response.StatusCode))
            {
                await WriteClosedFailureAsync(context, originalBody, context.Response.StatusCode);
                return;
            }

            context.Response.Body = originalBody;
            capturedBody.Position = 0;
            await capturedBody.CopyToAsync(originalBody, context.RequestAborted);
        }
        finally
        {
            context.Response.Body = originalBody;
        }
    }

    /// <summary>Returns whether a status can originate outside the Recovery controller's own closed response handling.</summary>
    private static bool RequiresClosedTransportEnvelope(int statusCode) =>
        statusCode == StatusCodes.Status415UnsupportedMediaType
        || statusCode == StatusCodes.Status429TooManyRequests
        || statusCode >= StatusCodes.Status500InternalServerError;

    /// <summary>Discards every captured downstream byte and writes the two-field frozen envelope with no-store semantics.</summary>
    private static async Task WriteClosedFailureAsync(HttpContext context, Stream originalBody, int statusCode)
    {
        context.Response.Body = originalBody;
        context.Response.Clear();
        context.Response.StatusCode = statusCode;
        context.Response.Headers.CacheControl = "no-store, max-age=0";
        context.Response.Headers.Pragma = "no-cache";
        await context.Response.WriteAsJsonAsync(
            new RecoveryTelemetryResponse(RecoveryTelemetryCodes.InvalidFieldValue, Guid.NewGuid()),
            context.RequestAborted);
    }
}

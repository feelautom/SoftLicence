using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Exposes the dedicated strict Recovery v1 ingestion boundary without generic telemetry enrichment or payload logging.
/// </summary>
[ApiController]
[Route("api/telemetry/recovery/v1/events")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("TelemetryAPI")]
public sealed class RecoveryTelemetryController : ControllerBase
{
    private readonly RecoveryTelemetryService service;

    /// <summary>Creates the controller with its scoped transactional ingestion service.</summary>
    public RecoveryTelemetryController(RecoveryTelemetryService service)
    {
        this.service = service;
    }

    /// <summary>
    /// Reads at most 4,097 bytes, strictly parses the body, and returns only a closed code plus server correlation ID.
    /// </summary>
    /// <param name="cancellationToken">Cancels request processing before a database commit.</param>
    [HttpPost]
    [Consumes("application/json")]
    [Produces("application/json")]
    public async Task<IActionResult> Post(CancellationToken cancellationToken)
    {
        var correlationId = Guid.NewGuid();
        if (Request.ContentLength > RecoveryTelemetryParser.MaximumBodyBytes)
            return await RejectAsync(new(null, RecoveryTelemetryCodes.PayloadTooLarge, null, null, null), correlationId,
                StatusCodes.Status413PayloadTooLarge, cancellationToken);

        var body = await ReadBoundedBodyAsync(Request.Body, RecoveryTelemetryParser.MaximumBodyBytes + 1, cancellationToken);
        var parsed = RecoveryTelemetryParser.Parse(body);
        if (!parsed.IsSuccess)
        {
            var status = parsed.RejectionCode == RecoveryTelemetryCodes.PayloadTooLarge
                ? StatusCodes.Status413PayloadTooLarge
                : StatusCodes.Status400BadRequest;
            return await RejectAsync(parsed, correlationId, status, cancellationToken);
        }

        var result = await service.IngestAsync(parsed.Envelope!, body, correlationId, cancellationToken);
        return StatusCode(result.StatusCode, new RecoveryTelemetryResponse(result.Code, correlationId));
    }

    /// <summary>Persists only validated identifiers and returns the same closed rejection code to the caller.</summary>
    private async Task<IActionResult> RejectAsync(
        RecoveryTelemetryParseResult parsed,
        Guid correlationId,
        int statusCode,
        CancellationToken cancellationToken)
    {
        var productId = await service.ResolveProductIdAsync(parsed.ProductCode, cancellationToken);
        await service.RecordRejectionAsync(productId, parsed.RecoveryRunId, parsed.EventId,
            parsed.RejectionCode!, correlationId, cancellationToken);
        return StatusCode(statusCode, new RecoveryTelemetryResponse(parsed.RejectionCode!, correlationId));
    }

    /// <summary>Reads no more than the supplied bound so an oversized or endless body cannot consume unbounded memory.</summary>
    private static async Task<byte[]> ReadBoundedBodyAsync(Stream body, int maximumBytes, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(capacity: maximumBytes);
        var chunk = new byte[1024];
        while (buffer.Length < maximumBytes)
        {
            var remaining = maximumBytes - (int)buffer.Length;
            var read = await body.ReadAsync(chunk.AsMemory(0, Math.Min(chunk.Length, remaining)), cancellationToken);
            if (read == 0)
                break;
            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }
        return buffer.ToArray();
    }
}

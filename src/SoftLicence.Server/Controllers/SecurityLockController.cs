using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Authenticated security lock reports (TKT-001177). Transport rules mirror the critical canary endpoint:
/// exact target, bounded strict UTF-8 JSON body, exact field set, singleton proof headers, no caching.
/// </summary>
[ApiController]
[Route("api/security")]
[EnableRateLimiting("TelemetryAPI")]
public sealed class SecurityLockController : ControllerBase
{
    private const int MaximumBodyBytes = 4096;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly string[] RequestFields =
    [
        "schema", "reportId", "sentAtUtc", "hardwareId", "appVersion", "lockId", "cause", "level", "mode",
        "evidenceDigestSha256", "firstSeenUtc"
    ];
    private static readonly JsonSerializerOptions RequestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false
    };

    private readonly ILogger<SecurityLockController> _logger;
    private readonly IRuntimeEnrollmentService? _runtimeEnrollments;

    /// <summary>Creates the controller.</summary>
    /// <param name="logger">Logger.</param>
    /// <param name="runtimeEnrollments">Runtime enrollment authority; absent means unavailable.</param>
    public SecurityLockController(ILogger<SecurityLockController> logger, IRuntimeEnrollmentService? runtimeEnrollments = null)
    {
        _logger = logger;
        _runtimeEnrollments = runtimeEnrollments;
    }

    /// <summary>
    /// Receives one lock report and returns the exact signed verdict bytes. Failures never return a verdict, so
    /// the client keeps its lock (fail-closed) and retries later.
    /// </summary>
    /// <param name="cancellationToken">Cancellation.</param>
    [HttpPost("lock-report")]
    public async Task<IActionResult> Report(CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
        if (_runtimeEnrollments == null)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "authority_unavailable" });
        try
        {
            EnsureExactTarget();
            var body = await ReadStrictBodyAsync(Request, cancellationToken);
            using var document = JsonDocument.Parse(body);
            if (!TryDeserialize(document.RootElement, out var request))
                return BadRequest(new { error = "invalid_request" });
            if (!Guid.TryParseExact(ReadSingletonHeader("X-Runtime-Enrollment-Id"), "D", out var enrollmentId)
                || !string.Equals(enrollmentId.ToString("D"), Request.Headers["X-Runtime-Enrollment-Id"][0], StringComparison.Ordinal))
                throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
            var proof = new RuntimeProofHeaders(
                ReadSingletonHeader("X-Runtime-Enrollment-Timestamp"),
                ReadSingletonHeader("X-Runtime-Enrollment-Jti"),
                ReadSingletonHeader("X-Runtime-Enrollment-Signature"));
            var result = await _runtimeEnrollments.ProcessSecurityLockReportAsync(
                enrollmentId, Convert.ToHexStringLower(SHA256.HashData(body.Span)), request!, proof,
                HttpContext.Connection.RemoteIpAddress, cancellationToken);
            return File(result.ExactResponseBody, "application/json");
        }
        catch (TransportException exception)
        {
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException)
        {
            return BadRequest(new { error = "invalid_request" });
        }
        catch (RuntimeEnrollmentException exception)
        {
            _logger.LogWarning("Security lock report rejected: {ErrorCode}", exception.ErrorCode);
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
    }

    private void EnsureExactTarget()
    {
        if (!string.Equals(Request.Method, HttpMethods.Post, StringComparison.Ordinal)
            || !string.Equals(Request.Path.Value, RuntimeEnrollmentService.SecurityLockReportPath, StringComparison.Ordinal)
            || Request.QueryString.HasValue
            || Request.Headers.ContainsKey("Transfer-Encoding")
            || Request.Headers.ContainsKey("Content-Encoding"))
            throw new TransportException(StatusCodes.Status400BadRequest, "invalid_request");
    }

    private static async Task<ReadOnlyMemory<byte>> ReadStrictBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.ContentLength is null or <= 0)
            throw new TransportException(StatusCodes.Status400BadRequest, "invalid_request");
        if (request.ContentLength > MaximumBodyBytes)
            throw new TransportException(StatusCodes.Status413PayloadTooLarge, "payload_too_large");
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType)
            || !string.Equals(mediaType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
            || mediaType.Parameters.Count > 1
            || mediaType.Parameters.Any(parameter =>
                !string.Equals(parameter.Name, "charset", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(parameter.Value?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase)))
            throw new TransportException(StatusCodes.Status415UnsupportedMediaType, "unsupported_media_type");

        var bytes = new byte[checked((int)request.ContentLength.Value)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = await request.Body.ReadAsync(bytes.AsMemory(offset), cancellationToken);
            if (read == 0)
                throw new TransportException(StatusCodes.Status400BadRequest, "invalid_request");
            offset += read;
        }
        if (await request.Body.ReadAsync(new byte[1], cancellationToken) != 0
            || bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble))
            throw new TransportException(StatusCodes.Status400BadRequest, "invalid_request");
        _ = StrictUtf8.GetString(bytes);
        return bytes;
    }

    private static bool TryDeserialize(JsonElement payload, out SecurityLockReportRequest? request)
    {
        request = null;
        if (payload.ValueKind != JsonValueKind.Object)
            return false;
        var names = payload.EnumerateObject().Select(property => property.Name).ToList();
        if (names.Count != RequestFields.Length
            || names.Distinct(StringComparer.Ordinal).Count() != RequestFields.Length
            || RequestFields.Any(field => !names.Contains(field, StringComparer.Ordinal)))
            return false;
        try
        {
            request = payload.Deserialize<SecurityLockReportRequest>(RequestJsonOptions);
            return request != null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private string ReadSingletonHeader(string name)
    {
        if (!Request.Headers.TryGetValue(name, out var values) || values.Count != 1)
            throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
        var value = values[0] ?? string.Empty;
        if (value.Length == 0 || value.Contains(',') || value.Any(char.IsControl))
            throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
        return value;
    }

    private sealed class TransportException(int statusCode, string errorCode) : Exception(errorCode)
    {
        public int StatusCode { get; } = statusCode;
        public string ErrorCode { get; } = errorCode;
    }
}

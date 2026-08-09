using System.Text;
using System.Text.Json;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Middlewares;

public sealed class TelemetryRejectionCaptureMiddleware
{
    public const int MaximumCapturedBytes = 64 * 1024;
    private static readonly string[] RequiredFields = ["hardwareId", "appName", "eventName"];
    private readonly RequestDelegate _next;
    private readonly ILogger<TelemetryRejectionCaptureMiddleware> _logger;

    public TelemetryRejectionCaptureMiddleware(RequestDelegate next, ILogger<TelemetryRejectionCaptureMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, TelemetryRejectionService rejectionService)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.Path.StartsWithSegments("/api/telemetry"))
        {
            await _next(context);
            return;
        }

        var oversized = context.Request.ContentLength > MaximumCapturedBytes;
        string? body = null;
        if (!oversized)
        {
            context.Request.EnableBuffering();
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, false, 4096, leaveOpen: true);
            var buffer = new char[MaximumCapturedBytes + 1];
            var read = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
            oversized = read > MaximumCapturedBytes;
            if (!oversized) body = new string(buffer, 0, read);
            context.Request.Body.Position = 0;
        }

        await _next(context);
        if (context.Response.StatusCode != StatusCodes.Status400BadRequest) return;

        try
        {
            var parsed = Parse(body, oversized);
            var forwarded = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var ip = !string.IsNullOrWhiteSpace(forwarded)
                ? forwarded.Split(',')[0].Trim()
                : context.Connection.RemoteIpAddress?.ToString();
            await rejectionService.RecordAsync(new TelemetryRejectionCandidate(
                context.Request.Path.Value ?? "/api/telemetry",
                parsed.ValidationCode,
                parsed.InvalidFields,
                parsed.AppName,
                parsed.Version,
                parsed.EventName,
                parsed.HardwareId,
                ip,
                context.Request.Headers.UserAgent.FirstOrDefault(),
                context.TraceIdentifier),
                context.RequestAborted);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist sanitized telemetry rejection {CorrelationId}", context.TraceIdentifier);
        }
    }

    public static ParsedTelemetryRejection Parse(string? body, bool oversized)
    {
        if (oversized) return new("PayloadTooLarge", ["body"], null, null, null, null);
        if (string.IsNullOrWhiteSpace(body)) return new("EmptyBody", ["body"], null, null, null, null);
        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return new("InvalidRootType", ["body"], null, null, null, null);
            var root = document.RootElement;
            var invalid = new List<string>();
            foreach (var field in RequiredFields)
            {
                if (!TryGetProperty(root, field, out var value)) invalid.Add(field + ":missing");
                else if (value.ValueKind != JsonValueKind.String) invalid.Add(field + ":type");
                else if (string.IsNullOrWhiteSpace(value.GetString())) invalid.Add(field + ":empty");
            }
            return new(invalid.Count == 0 ? "ModelValidationFailed" : "InvalidFields", invalid,
                SafeString(root, "appName"), SafeString(root, "version"), SafeString(root, "eventName"), SafeString(root, "hardwareId"));
        }
        catch (JsonException)
        {
            return new("MalformedJson", ["body"], null, null, null, null);
        }
    }

    private static bool TryGetProperty(JsonElement root, string name, out JsonElement value)
    {
        foreach (var property in root.EnumerateObject())
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)) { value = property.Value; return true; }
        value = default;
        return false;
    }

    private static string? SafeString(JsonElement root, string name)
    {
        return TryGetProperty(root, name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }
}

public sealed record ParsedTelemetryRejection(
    string ValidationCode,
    IReadOnlyCollection<string> InvalidFields,
    string? AppName,
    string? Version,
    string? EventName,
    string? HardwareId);

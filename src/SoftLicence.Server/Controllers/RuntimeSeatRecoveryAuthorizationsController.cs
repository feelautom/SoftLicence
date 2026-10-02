using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>Exposes authenticated authorization, key proof, activation, and exact readback surfaces.</summary>
[ApiController]
public sealed class RuntimeSeatRecoveryAuthorizationsController : ControllerBase
{
    private const int MaximumRequestBytes = 4096;
    private readonly IDistributionS2SAuthenticationService s2s;
    private readonly IRuntimeSeatRecoveryAuthorizationService authorizations;
    private readonly RuntimeEnrollmentOptions options;

    /// <summary>Creates the transport boundary without taking ownership of provider seat decisions.</summary>
    public RuntimeSeatRecoveryAuthorizationsController(
        IDistributionS2SAuthenticationService s2s,
        IRuntimeSeatRecoveryAuthorizationService authorizations,
        IOptions<RuntimeEnrollmentOptions> options)
    {
        this.s2s = s2s;
        this.authorizations = authorizations;
        this.options = options.Value;
    }

    /// <summary>Authenticates exact bytes, then atomically authorizes or replays one provider recovery result.</summary>
    [HttpPost("/api/internal/v1/runtime-seat-recovery-authorizations")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> Authorize(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (options.Mode != "enabled") return Exact(Transport(503, "provider_unavailable"));
        try
        {
            EnsureTransport("/api/internal/v1/runtime-seat-recovery-authorizations");
            var body = await ReadBodyAsync(cancellationToken);
            var parsed = RuntimeSeatRecoveryContractCodec.ParseAuthorizationRequest(body.Span);
            if (!parsed.IsSuccess) return Exact(Transport(400, "invalid_request"));
            var principal = await s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, body, parsed.Request!.ProductId, cancellationToken);
            if (!principal.AllowRuntimeRecovery) return Exact(Transport(403, "recovery_not_authorized"));
            return Exact(await authorizations.AuthorizeAsync(principal.ClientId, parsed, cancellationToken));
        }
        catch (RuntimeSeatRecoveryTransportException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (DistributionS2SAuthenticationException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(503, "provider_unavailable")); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(500, "internal_error")); }
    }

    /// <summary>Authenticates one exact tuple and returns a complete current snapshot without provider mutation.</summary>
    [HttpPost("/api/internal/v1/runtime-seat-recovery-authorizations/current-readback")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> CurrentReadback(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (options.Mode != "enabled") return Exact(Transport(503, "provider_unavailable"));
        try
        {
            EnsureTransport("/api/internal/v1/runtime-seat-recovery-authorizations/current-readback");
            var body = await ReadBodyAsync(cancellationToken);
            var parsed = RuntimeSeatRecoveryContractCodec.ParseCurrentReadbackRequest(body.Span);
            if (!parsed.IsSuccess) return Exact(Transport(400, "invalid_request"));
            var principal = await s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, body, parsed.Request!.ProductId, cancellationToken);
            if (!principal.AllowRuntimeRecovery) return Exact(Transport(403, "recovery_not_authorized"));
            return Exact(await authorizations.ReadCurrentAsync(principal.ClientId, parsed.Request, cancellationToken));
        }
        catch (RuntimeSeatRecoveryTransportException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (DistributionS2SAuthenticationException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(503, "provider_unavailable")); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(500, "internal_error")); }
    }

    /// <summary>Authenticates and freezes one provider-protected W10 key preparation.</summary>
    [HttpPost("/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/key-preparations")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> PrepareKey(string requestId, CancellationToken cancellationToken)
    {
        SetNoStore();
        if (options.Mode != "enabled") return Exact(Transport(503, "provider_unavailable"));
        try
        {
            EnsureTransport($"/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/key-preparations");
            var body = await ReadBodyAsync(cancellationToken);
            var parsed = RuntimeSeatRecoveryContractCodec.ParseKeyPreparationRequest(body.Span);
            if (!parsed.IsSuccess) return Exact(Transport(400, "invalid_request"));
            var principal = await s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, body, parsed.Request!.ProductId, cancellationToken);
            if (!principal.AllowRuntimeRecovery) return Exact(Transport(403, "recovery_not_authorized"));
            return Exact(await authorizations.PrepareKeyAsync(principal.ClientId, requestId, parsed, cancellationToken));
        }
        catch (RuntimeSeatRecoveryTransportException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (DistributionS2SAuthenticationException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(503, "provider_unavailable")); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(500, "internal_error")); }
    }

    /// <summary>Verifies one raw W10 PS256 statement and freezes a PROVED receipt without activation.</summary>
    [HttpPost("/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/key-confirmations")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> ConfirmKey(string requestId, CancellationToken cancellationToken)
    {
        SetNoStore();
        if (options.Mode != "enabled") return Exact(Transport(503, "provider_unavailable"));
        try
        {
            EnsureTransport($"/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/key-confirmations");
            var body = await ReadBodyAsync(cancellationToken);
            var parsed = RuntimeSeatRecoveryContractCodec.ParseKeyConfirmationRequest(body.Span);
            if (!parsed.IsSuccess) return Exact(Transport(400, "invalid_request"));
            var principal = await s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, body, parsed.Request!.ProductId, cancellationToken);
            if (!principal.AllowRuntimeRecovery) return Exact(Transport(403, "recovery_not_authorized"));
            return Exact(await authorizations.ConfirmKeyAsync(principal.ClientId, requestId, parsed, cancellationToken));
        }
        catch (RuntimeSeatRecoveryTransportException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (DistributionS2SAuthenticationException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(503, "provider_unavailable")); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(500, "internal_error")); }
    }

    /// <summary>Consumes one exact PROVED receipt and atomically freezes the three recovery transitions.</summary>
    [HttpPost("/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/activations")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> Activate(string requestId, CancellationToken cancellationToken)
    {
        SetNoStore();
        if (options.Mode != "enabled") return Exact(Transport(503, "provider_unavailable"));
        try
        {
            EnsureTransport($"/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/activations");
            var body = await ReadBodyAsync(cancellationToken);
            var parsed = RuntimeSeatRecoveryContractCodec.ParseActivationRequest(body.Span);
            if (!parsed.IsSuccess) return Exact(Transport(400, "invalid_request"));
            var principal = await s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, body, parsed.Request!.ProductId, cancellationToken);
            if (!principal.AllowRuntimeRecovery) return Exact(Transport(403, "recovery_not_authorized"));
            return Exact(await authorizations.ActivateAsync(principal.ClientId, requestId, parsed, cancellationToken));
        }
        catch (RuntimeSeatRecoveryTransportException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (DistributionS2SAuthenticationException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(503, "provider_unavailable")); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(500, "internal_error")); }
    }

    /// <summary>Returns the exact stored activation terminal without rerunning any provider decision.</summary>
    [HttpPost("/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/activation-readback")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> ActivationReadback(string requestId, CancellationToken cancellationToken)
    {
        SetNoStore();
        if (options.Mode != "enabled") return Exact(Transport(503, "provider_unavailable"));
        try
        {
            EnsureTransport($"/api/internal/v1/runtime-seat-recovery-authorizations/{requestId}/activation-readback");
            var body = await ReadBodyAsync(cancellationToken);
            var parsed = RuntimeSeatRecoveryContractCodec.ParseActivationReadbackRequest(body.Span);
            if (!parsed.IsSuccess) return Exact(Transport(400, "invalid_request"));
            var principal = await s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, body, parsed.Request!.ProductId, cancellationToken);
            if (!principal.AllowRuntimeRecovery) return Exact(Transport(403, "recovery_not_authorized"));
            return Exact(await authorizations.ReadActivationAsync(
                principal.ClientId, requestId, parsed.Request, cancellationToken));
        }
        catch (RuntimeSeatRecoveryTransportException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (DistributionS2SAuthenticationException exception) { return Exact(Transport(exception.StatusCode, exception.ErrorCode)); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(503, "provider_unavailable")); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { return Exact(Transport(500, "internal_error")); }
    }

    /// <summary>Rejects query, transfer encoding, non-exact target, and non-exact UTF-8 JSON media type.</summary>
    private void EnsureTransport(string expectedPath)
    {
        if (!string.Equals(Request.Path.Value, expectedPath, StringComparison.Ordinal)
            || Request.QueryString.HasValue || Request.Headers.ContainsKey("Transfer-Encoding"))
            throw new RuntimeSeatRecoveryTransportException("invalid_request", 400);
        if (!string.Equals(Request.ContentType, "application/json; charset=utf-8", StringComparison.Ordinal))
            throw new RuntimeSeatRecoveryTransportException("unsupported_media_type", 415);
    }

    /// <summary>Reads at most 4096 bytes before parsing and never trusts Content-Length alone.</summary>
    private async Task<ReadOnlyMemory<byte>> ReadBodyAsync(CancellationToken cancellationToken)
    {
        if (Request.ContentLength is > MaximumRequestBytes)
            throw new RuntimeSeatRecoveryTransportException("payload_too_large", 413);
        await using var stream = new MemoryStream();
        var buffer = new byte[1024];
        while (true)
        {
            var read = await Request.Body.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            if (stream.Length + read > MaximumRequestBytes)
                throw new RuntimeSeatRecoveryTransportException("payload_too_large", 413);
            await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        return stream.ToArray();
    }

    /// <summary>Returns exact bytes with the caller-selected terminal status and media type.</summary>
    private IActionResult Exact(RuntimeSeatRecoveryHttpResult result)
    {
        Response.StatusCode = result.StatusCode;
        return File(result.ExactBodyUtf8, result.ContentType);
    }

    /// <summary>Builds the closed transport envelope without creating a business ledger row.</summary>
    private static RuntimeSeatRecoveryHttpResult Transport(int status, string errorCode) => new(
        status, "application/json; charset=utf-8", Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"runtime-seat-recovery-transport-error-v1\",\"contractVersion\":1,\"errorCode\":\"{errorCode}\"}}"));

    /// <summary>Applies sensitive-response caching policy even when MVC returns an error.</summary>
    private void SetNoStore()
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
    }
}

/// <summary>Represents one closed transport rejection before provider business identity is persisted.</summary>
internal sealed class RuntimeSeatRecoveryTransportException : Exception
{
    /// <summary>Creates a bounded error with exact code and HTTP status.</summary>
    internal RuntimeSeatRecoveryTransportException(string errorCode, int statusCode) : base(errorCode)
    {
        ErrorCode = errorCode;
        StatusCode = statusCode;
    }

    /// <summary>Gets the exact public transport code.</summary>
    internal string ErrorCode { get; }
    /// <summary>Gets the exact associated HTTP status.</summary>
    internal int StatusCode { get; }
}

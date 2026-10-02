using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace SoftLicence.Server.Services;

/// <summary>A public-safe support failure. It never carries upstream bodies, credentials, or inner exceptions.</summary>
public sealed class BugTraceSupportException(int status, string code, int? retryAfterSeconds = null) : Exception(code)
{
    /// <summary>Gets the allowlisted HTTP status to return to the Desktop.</summary>
    public int Status { get; } = status;
    /// <summary>Gets a server-selected machine code, never provider prose.</summary>
    public string Code { get; } = code;
    /// <summary>Gets bounded retry guidance in seconds when the failure is throttling.</summary>
    public int? RetryAfterSeconds { get; } = retryAfterSeconds;
}

/// <summary>Implements bounded SUP transport separately from the legacy and durable auto-report contracts.</summary>
public sealed partial class BugTraceProxyService
{
    /// <summary>Caps each customer-visible JSON response at 2 MiB, including full conversations.</summary>
    private const int SupportJsonLimit = 2 * 1024 * 1024;
    /// <summary>Caps binary downloads at the provider's maximum single ZIP size, 40 MiB.</summary>
    private const int SupportDownloadLimit = 40 * 1024 * 1024;

    /// <summary>Uses only the dedicated support credential; missing configuration fails before any provider request.</summary>
    private HttpClient CreateSupportClient()
    {
        if (string.IsNullOrEmpty(_supportProjectToken))
            throw new BugTraceSupportException(503, "support_not_configured");
        var client = _httpClientFactory.CreateClient("BugTrace");
        client.DefaultRequestHeaders.Remove("X-Project-Token");
        client.DefaultRequestHeaders.Add("X-Project-Token", _supportProjectToken);
        return client;
    }

    /// <summary>Creates or replays a SUP with the exact opaque provider idempotency header and a bounded receipt.</summary>
    /// <inheritdoc cref="IBugTraceProxyService.CreateSupportCaseAsync"/>
    public Task<JsonElement> CreateSupportCaseAsync(object body, string idempotencyKey, CancellationToken ct = default) =>
        SupportJsonAsync(HttpMethod.Post, "/api/support-cases", body, idempotencyKey, ct);

    /// <summary>Reads one explicit owner-filtered page; offset prevents older owned cases being mistaken for foreign cases.</summary>
    /// <inheritdoc cref="IBugTraceProxyService.ListSupportCasesAsync"/>
    public Task<JsonElement> ListSupportCasesAsync(string reporterEmail, int limit, CancellationToken ct = default, int offset = 0) =>
        SupportJsonAsync(HttpMethod.Get, $"/api/support-cases?reporterEmail={Uri.EscapeDataString(reporterEmail)}&limit={limit}&offset={offset}", null, null, ct);

    /// <summary>Reads a bounded public conversation; callers must establish ownership before this operation.</summary>
    /// <inheritdoc cref="IBugTraceProxyService.GetSupportCaseAsync"/>
    public Task<JsonElement> GetSupportCaseAsync(string supportNumber, CancellationToken ct = default) =>
        SupportJsonAsync(HttpMethod.Get, $"/api/support-cases/{Uri.EscapeDataString(supportNumber)}", null, null, ct);

    /// <summary>Relays a customer message once; provider binding controls any attached staged files.</summary>
    /// <inheritdoc cref="IBugTraceProxyService.AddSupportCaseMessageAsync"/>
    public Task<JsonElement> AddSupportCaseMessageAsync(string supportNumber, object body, CancellationToken ct = default) =>
        SupportJsonAsync(HttpMethod.Post, $"/api/support-cases/{Uri.EscapeDataString(supportNumber)}/messages", body, null, ct);

    /// <summary>Resolves an already-authorized case through the provider's dedicated PATCH contract.</summary>
    /// <inheritdoc cref="IBugTraceProxyService.ResolveSupportCaseAsync"/>
    public Task<JsonElement> ResolveSupportCaseAsync(string supportNumber, CancellationToken ct = default) =>
        SupportJsonAsync(HttpMethod.Patch, $"/api/support-cases/{Uri.EscapeDataString(supportNumber)}/resolve", null, null, ct);

    /// <summary>Stages one owner-bound multipart file with exact idempotency; scanning and durable binding remain provider-owned.</summary>
    /// <inheritdoc cref="IBugTraceProxyService.StageSupportAttachmentAsync"/>
    public async Task<JsonElement> StageSupportAttachmentAsync(IFormFile file, string reporterEmail, string idempotencyKey, CancellationToken ct = default)
    {
        using var form = new MultipartFormDataContent();
        await using var stream = file.OpenReadStream();
        using var content = new StreamContent(stream);
        if (!string.IsNullOrEmpty(file.ContentType))
        {
            if (!MediaTypeHeaderValue.TryParse(file.ContentType, out var mediaType))
                throw new BugTraceSupportException(400, "attachment_media_type_invalid");
            content.Headers.ContentType = mediaType;
        }
        form.Add(new StringContent(reporterEmail), "reporterEmail");
        form.Add(content, "file", file.FileName);
        using var request = new HttpRequestMessage(HttpMethod.Post, _baseUrl + "/api/support-cases/attachments") { Content = form };
        request.Headers.Add("Idempotency-Key", idempotencyKey);
        return await ReadSupportJsonAsync(request, ct);
    }

    /// <summary>Downloads a bounded authorized file. Only a neutralized basename is returned for Content-Disposition.</summary>
    /// <inheritdoc cref="IBugTraceProxyService.DownloadSupportAttachmentAsync"/>
    public async Task<(byte[] Content, string ContentType, string FileName)> DownloadSupportAttachmentAsync(string supportNumber, string attachmentId, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"{_baseUrl}/api/support-cases/{Uri.EscapeDataString(supportNumber)}/attachments/{Uri.EscapeDataString(attachmentId)}");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(40));
        try
        {
            using var response = await CreateSupportClient().SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            ValidateSupportResponse(response);
            var bytes = await ReadSupportBytesAsync(response.Content, SupportDownloadLimit, deadline.Token);
            var name = response.Content.Headers.ContentDisposition?.FileNameStar
                ?? response.Content.Headers.ContentDisposition?.FileName?.Trim('"') ?? "attachment";
            name = name.Replace('\\', '/').Split('/').Last();
            // Treat both slash styles and Windows alternate-stream punctuation as unsafe even
            // on Linux; callback performs only the documented basename character filter.
            name = new string(name.Where(c => !char.IsControl(c) && !"<>:\"|?*".Contains(c)).Take(180).ToArray()).TrimEnd(' ', '.');
            var mediaType = response.Content.Headers.ContentType?.MediaType;
            var safeType = mediaType is "application/pdf" or "application/zip" or "image/png" or "image/jpeg" or "text/plain"
                ? mediaType : "application/octet-stream";
            return (bytes, safeType, string.IsNullOrWhiteSpace(name) ? "attachment" : name);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new BugTraceSupportException(504, "support_timeout"); }
        catch (HttpRequestException) { throw new BugTraceSupportException(502, "support_unavailable"); }
        catch (IOException) { throw new BugTraceSupportException(502, "support_unavailable"); }
    }

    /// <summary>Owns request lifetime and exact serialization; neither redirects nor automatic retries are introduced.</summary>
    /// <remarks>Method and relative path are server-selected. Optional body is serialized once; optional key is forwarded exactly. Request/content are disposed after bounded JSON completion. Failures and caller cancellation propagate from ReadSupportJsonAsync; no retries or rollback.</remarks>
    private async Task<JsonElement> SupportJsonAsync(HttpMethod method, string path, object? body, string? key, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, _baseUrl + path);
        if (body != null) request.Content = JsonContent.Create(body);
        if (key != null) request.Headers.Add("Idempotency-Key", key);
        return await ReadSupportJsonAsync(request, ct);
    }

    /// <summary>Applies a 40-second deadline covering headers and body, then parses only a bounded JSON object.</summary>
    /// <param name="request">Caller-owned request; this method owns the response and linked deadline, not the request.</param>
    /// <param name="ct">Caller cancellation, which propagates unchanged.</param>
    /// <returns>A cloned object detached from the disposed JSON document; maximum 2 MiB and depth 32.</returns>
    /// <remarks>Provider error bodies are never read. Invalid shape/JSON, excess bytes or transport failure become safe 502; internal deadline becomes 504. Provider mutations may have completed before either failure.</remarks>
    private async Task<JsonElement> ReadSupportJsonAsync(HttpRequestMessage request, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(40));
        try
        {
            using var response = await CreateSupportClient().SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            ValidateSupportResponse(response);
            var bytes = await ReadSupportBytesAsync(response.Content, SupportJsonLimit, deadline.Token);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new BugTraceSupportException(502, "support_invalid_response");
            return document.RootElement.Clone();
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new BugTraceSupportException(504, "support_timeout"); }
        catch (HttpRequestException) { throw new BugTraceSupportException(502, "support_unavailable"); }
        catch (IOException) { throw new BugTraceSupportException(502, "support_unavailable"); }
        catch (JsonException) { throw new BugTraceSupportException(502, "support_invalid_response"); }
    }

    /// <summary>Projects statuses without reading or logging error bodies; redirects fail closed with no credential forwarding.</summary>
    /// <remarks>Every 2xx proceeds to bounded body validation. Only 400/403/404/409/413/415/422/429/503 are preserved; all other failures including redirects map to 502. Retry guidance is emitted only for 429 and clamped to 1–600 seconds, default 60. Does not dispose or consume the caller-owned response.</remarks>
    private static void ValidateSupportResponse(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return;
        var status = (int)response.StatusCode;
        var code = status switch
        {
            400 => "support_request_rejected", 403 => "support_access_denied", 404 => "support_not_found",
            409 => "support_conflict", 413 => "attachment_too_large", 415 => "attachment_type_rejected",
            422 => "support_content_rejected", 429 => "rate_limited", 503 => "support_unavailable",
            _ => "support_upstream_error"
        };
        if (status is not (400 or 403 or 404 or 409 or 413 or 415 or 422 or 429 or 503)) status = 502;
        int? retry = status == 429 ? (int)Math.Clamp(Math.Ceiling(response.Headers.RetryAfter?.Delta?.TotalSeconds ?? 60), 1, 600) : null;
        throw new BugTraceSupportException(status, code, retry);
    }

    /// <summary>Rejects declared oversized bodies without reading, and unknown lengths after at most limit plus one bytes.</summary>
    /// <param name="content">Response content; its opened stream is disposed here, with content lifetime owned by the caller.</param>
    /// <param name="limit">Positive server-selected byte bound, currently 2 MiB JSON or 40 MiB download.</param>
    /// <param name="ct">Deadline/caller token observed on stream reads.</param>
    /// <returns>Owned complete bytes only; partial output is discarded on failure.</returns>
    /// <exception cref="BugTraceSupportException">Safe 502 when declared or observed content exceeds the byte bound.</exception>
    /// <remarks>I/O and cancellation propagate for the public transport layer to classify; no filesystem writes. Chunking uses at most 8192 temporary bytes per read.</remarks>
    private static async Task<byte[]> ReadSupportBytesAsync(HttpContent content, int limit, CancellationToken ct)
    {
        if (content.Headers.ContentLength > limit) throw new BugTraceSupportException(502, "support_response_too_large");
        await using var stream = await content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, limit + 1 - (int)output.Length)), ct);
            if (read == 0) return output.ToArray();
            if (output.Length + read > limit) throw new BugTraceSupportException(502, "support_response_too_large");
            output.Write(buffer, 0, read);
        }
    }
}

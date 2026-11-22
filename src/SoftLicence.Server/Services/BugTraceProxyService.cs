using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace SoftLicence.Server.Services;

/// <summary>Separates credential-owning transport from caller-owned licence/product/customer authorization.</summary>
/// <remarks>SUP methods require caller validation of canonical references, reporter, request bounds and quotas; they never establish ownership. Real SUP transport returns detached public JSON up to2MiB or owned binary bytes up to40MiB, uses40s deadlines, never retries and maps errors without provider bodies. Caller cancellation propagates; provider mutations can survive ambiguous responses. T-IA methods use a separately verified authority; ordinary legacy methods retain the internal credential.</remarks>
public interface IBugTraceProxyService
{
    /// <summary>Gets the project identifier enforced by the server-side provider configuration.</summary>
    string ExpectedProjectId { get; }
    /// <summary>Gets whether every required server-side provider setting is present.</summary>
    bool IsConfigured { get; }
    /// <summary>Gets whether the dedicated T-IA ticket authority is syntactically configured.</summary>
    /// <remarks>The default is deliberately false so substitutes cannot inherit legacy authority implicitly.</remarks>
    bool IsTiaConfigured => false;

    /// <summary>Verifies that the dedicated T-IA credential resolves to the configured provider project.</summary>
    /// <remarks>Implementations may cache only a successful exact match. The default fails closed and never consults legacy authority.</remarks>
    /// <exception cref="BugTraceTiaAuthorityException">The configuration or provider-owned identity cannot be trusted.</exception>
    /// <param name="ct">Cancels provider identity verification; cancellation is not converted to an authority failure.</param>
    /// <returns>A task that completes only after the exact project identity has been trusted.</returns>
    Task VerifyTiaAuthorityAsync(CancellationToken ct = default) =>
        throw new NotSupportedException("The BugTrace proxy does not support T-IA authority verification.");
    /// <summary>Submits a regular authenticated ticket without auto-report idempotency semantics.</summary>
    Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default);

    /// <summary>
    /// Submits a legacy internal ticket with a canonical report identifier as the provider idempotency key.
    /// </summary>
    /// <remarks>
    /// This compatibility overload always retains legacy authority. Desktop automatic reports must use
    /// <see cref="SubmitTiaTicketAsync(object, string, CancellationToken)"/> explicitly. The default fails closed.
    /// </remarks>
    /// <param name="ticketBody">The server-owned BugTrace ticket projection.</param>
    /// <param name="idempotencyKey">The exact lowercase canonical report UUID; it is never normalized.</param>
    /// <param name="ct">Cancels the outbound provider request.</param>
    /// <returns>The provider ticket receipt.</returns>
    Task<JsonElement> SubmitTicketAsync(
        object ticketBody,
        string idempotencyKey,
        CancellationToken ct = default) =>
        throw new NotSupportedException("The BugTrace proxy does not support idempotent ticket submission.");

    /// <summary>Submits a T-IA Desktop ticket through the dedicated, provider-verified authority.</summary>
    Task<JsonElement> SubmitTiaTicketAsync(object ticketBody, CancellationToken ct = default) =>
        throw new NotSupportedException("The BugTrace proxy does not support T-IA ticket submission.");

    /// <summary>Submits an idempotent T-IA automatic report through the dedicated, provider-verified authority.</summary>
    /// <remarks>The default fails closed so no substitute can route T-IA traffic through a legacy idempotent implementation.</remarks>
    Task<JsonElement> SubmitTiaTicketAsync(
        object ticketBody,
        string idempotencyKey,
        CancellationToken ct = default) =>
        throw new NotSupportedException("The BugTrace proxy does not support idempotent T-IA ticket submission.");

    /// <summary>Adds a comment through the dedicated, provider-verified T-IA authority.</summary>
    Task<JsonElement> AddTiaCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default) =>
        throw new NotSupportedException("The BugTrace proxy does not support T-IA ticket comments.");

    /// <summary>Lists tickets through the dedicated, provider-verified T-IA authority.</summary>
    Task<JsonElement> GetTiaTicketsByEmailAsync(string email, CancellationToken ct = default) =>
        throw new NotSupportedException("The BugTrace proxy does not support T-IA ticket listing.");

    /// <summary>Lists comments through the dedicated, provider-verified T-IA authority.</summary>
    Task<JsonElement> GetTiaTicketCommentsAsync(string ticketNumber, CancellationToken ct = default) =>
        throw new NotSupportedException("The BugTrace proxy does not support T-IA ticket comment listing.");

    /// <summary>Adds an authenticated comment to an existing provider ticket.</summary>
    Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default);
    /// <summary>Gets authenticated ticket projections for an email address.</summary>
    Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default);
    /// <summary>Gets authenticated comment projections for an existing provider ticket.</summary>
    Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default);
    /// <summary>Creates or replays one customer case using an exact provider key.</summary>
    /// <remarks>Caller supplies server-projected reporter/source, title240/description50000 and up to5 staged UUIDs. Exact printable ASCII key16–128 is forwarded unchanged. Returns create/replay receipt;409 preserves provider conflict. Creation may commit before timeout/cancellation; reuse the same key after ambiguity.</remarks>
    /// <exception cref="BugTraceSupportException">Bounded400/403/404/409/413/415/422/429/503; malformed/oversized/transport failures502; internal deadline504. Error bodies are not exposed.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation; no rollback guarantee.</exception>
    /// <param name="body">Server-owned customer projection; no raw client authority fields.</param>
    /// <param name="idempotencyKey">Exact previously validated printable ASCII replay key, length 16–128.</param>
    /// <param name="ct">Cancels headers and body reads; cancellation propagates and does not roll back provider mutations.</param>
    /// <returns>Detached bounded public JSON object owned by the caller.</returns>
    Task<JsonElement> CreateSupportCaseAsync(object body, string idempotencyKey, CancellationToken ct = default);
    /// <summary>Reads one bounded owner-filtered page at the explicit provider offset.</summary>
    /// <remarks>Reporter is the server-authorized licence email; caller bounds limit1–200 and offset0–100000. Returns one public page, not an ownership proof or complete history. URI encoding preserves supplied email; no mutation.</remarks>
    /// <exception cref="BugTraceSupportException">Bounded400/403/404/409/413/415/422/429/503; malformed/oversized/transport failures502; internal deadline504. Error bodies are not exposed.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation; no rollback guarantee.</exception>
    /// <param name="reporterEmail">Authoritative licence customer email; URI encoded without normalization.</param>
    /// <param name="limit">Page size from 1 through 200 inclusive.</param>
    /// <param name="offset">Zero-based offset from 0 through 100000 inclusive.</param>
    /// <param name="ct">Cancels headers and body reads; cancellation propagates and does not roll back provider mutations.</param>
    /// <returns>Detached bounded public JSON object owned by the caller.</returns>
    Task<JsonElement> ListSupportCasesAsync(string reporterEmail, int limit, CancellationToken ct = default, int offset = 0);
    /// <summary>Reads public case details after caller ownership validation.</summary>
    /// <remarks>Caller first proves ownership of exact SUP-######. Returns provider public conversation bounded2MiB; oversized history fails closed. No mutation.</remarks>
    /// <exception cref="BugTraceSupportException">Bounded400/403/404/409/413/415/422/429/503; malformed/oversized/transport failures502; internal deadline504. Error bodies are not exposed.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation; no rollback guarantee.</exception>
    /// <param name="supportNumber">Exact canonical SUP reference already authorized by the caller.</param>
    /// <param name="ct">Cancels headers and body reads; cancellation propagates and does not roll back provider mutations.</param>
    /// <returns>Detached bounded public JSON object owned by the caller.</returns>
    Task<JsonElement> GetSupportCaseAsync(string supportNumber, CancellationToken ct = default);
    /// <summary>Posts customer content after caller ownership validation.</summary>
    /// <remarks>Caller proves ownership and supplies content1–50000 UTF-16 units with up to5 staged UUIDs. Provider owns attachment binding. Returns message receipt; no replay key or automatic retry, so read back after ambiguity before resending.</remarks>
    /// <exception cref="BugTraceSupportException">Bounded400/403/404/409/413/415/422/429/503; malformed/oversized/transport failures502; internal deadline504. Error bodies are not exposed.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation; no rollback guarantee.</exception>
    /// <param name="supportNumber">Exact canonical SUP reference already authorized by the caller.</param>
    /// <param name="body">Server-owned message projection with validated content and attachment identifiers.</param>
    /// <param name="ct">Cancels headers and body reads; cancellation propagates and does not roll back provider mutations.</param>
    /// <returns>Detached bounded public JSON object owned by the caller.</returns>
    Task<JsonElement> AddSupportCaseMessageAsync(string supportNumber, object body, CancellationToken ct = default);
    /// <summary>Resolves a customer-owned case through the provider lifecycle.</summary>
    /// <remarks>Caller proves canonical SUP ownership before provider PATCH. Returns lifecycle projection;409 means invalid transition. Cancellation does not undo committed resolution.</remarks>
    /// <exception cref="BugTraceSupportException">Bounded400/403/404/409/413/415/422/429/503; malformed/oversized/transport failures502; internal deadline504. Error bodies are not exposed.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation; no rollback guarantee.</exception>
    /// <param name="supportNumber">Exact canonical SUP reference already authorized by the caller.</param>
    /// <param name="ct">Cancels headers and body reads; cancellation propagates and does not roll back provider mutations.</param>
    /// <returns>Detached bounded public JSON object owned by the caller.</returns>
    Task<JsonElement> ResolveSupportCaseAsync(string supportNumber, CancellationToken ct = default);
    /// <summary>Stages one multipart file bound to the authenticated customer.</summary>
    /// <remarks>Caller authorizes reporter and validates nonempty file up to40MiB, safe basename and exact replay key. Opens/disposes its own stream/multipart container, not the IFormFile owner. Returns staged receipt; provider owns scan, TTL, type/size and reporter/project binding, not yet case attachment.</remarks>
    /// <exception cref="BugTraceSupportException">Bounded400/403/404/409/413/415/422/429/503; malformed/oversized/transport failures502; internal deadline504. Error bodies are not exposed.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation; no rollback guarantee.</exception>
    /// <param name="file">Validated request-owned file; transport disposes only the stream it opens.</param>
    /// <param name="reporterEmail">Authoritative licence customer email, not a client-selected owner.</param>
    /// <param name="idempotencyKey">Exact validated replay key; reuse after ambiguous staging responses.</param>
    /// <param name="ct">Cancels headers and body reads; cancellation propagates and does not roll back provider mutations.</param>
    /// <returns>Detached bounded public JSON object owned by the caller.</returns>
    Task<JsonElement> StageSupportAttachmentAsync(IFormFile file, string reporterEmail, string idempotencyKey, CancellationToken ct = default);
    /// <summary>Downloads bounded bytes from a customer-owned case.</summary>
    /// <remarks>Caller proves canonical SUP ownership and lowercase D-form attachment UUID; provider binds UUID to case. Returns caller-owned array up to40MiB, MIME allowlist and neutralized basename; no filesystem write. Partial bytes discarded on failure.</remarks>
    /// <exception cref="BugTraceSupportException">Bounded400/403/404/409/413/415/422/429/503; malformed/oversized/transport failures502; internal deadline504. Error bodies are not exposed.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation; no rollback guarantee.</exception>
    /// <param name="supportNumber">Exact canonical SUP reference already authorized by the caller.</param>
    /// <param name="attachmentId">Exact lowercase D-form UUID; provider verifies attachment-to-case binding.</param>
    /// <param name="ct">Cancels headers and body reads; cancellation propagates and does not roll back provider mutations.</param>
    /// <returns>Caller-owned bounded bytes, safe media type and neutralized basename; no file is written.</returns>
    Task<(byte[] Content, string ContentType, string FileName)> DownloadSupportAttachmentAsync(string supportNumber, string attachmentId, CancellationToken ct = default);
}

/// <summary>Identifies a stable, non-secret reason why the dedicated T-IA authority cannot be trusted.</summary>
public enum BugTraceTiaAuthorityFailureReason
{
    /// <summary>The server-held base URL, token, or expected project identifier is missing or malformed.</summary>
    ConfigurationInvalid,
    /// <summary>The provider rejected the dedicated credential.</summary>
    IdentityRejected,
    /// <summary>The provider credential resolves to a project other than the configured project.</summary>
    IdentityMismatch,
    /// <summary>The provider identity response or its transport could not be validated.</summary>
    IdentityUnavailable
}

/// <summary>Represents a fail-closed T-IA authority configuration or provider-identity verification failure.</summary>
public sealed class BugTraceTiaAuthorityException : Exception
{
    /// <summary>Initializes a safe authority failure without provider response content or credentials.</summary>
    public BugTraceTiaAuthorityException(
        BugTraceTiaAuthorityFailureReason reason,
        Exception? innerException = null)
        : base("The BugTrace T-IA authority is unavailable.", innerException)
    {
        Reason = reason;
    }

    /// <summary>Gets a stable, non-secret diagnostic category intended for server-side tests and metrics.</summary>
    public BugTraceTiaAuthorityFailureReason Reason { get; }
}

/// <summary>Owns server-only project credentials and separates legacy, verified T-IA Ticket, and bounded SUP transport.</summary>
public sealed partial class BugTraceProxyService : IBugTraceProxyService
{
    private const int MaxLoggedBodyLength = 2000;
    private const int MaxLoggedBodyBytes = 8 * 1024;
    private const int MaxIdentityBodyBytes = 4 * 1024;
    private const int MaxTicketResponseBodyBytes = 2 * 1024 * 1024;
    private const string Redacted = "<redacted>";
    private const string OversizedBody = "<omitted:oversized>";
    private static readonly Regex SensitiveJsonPropertyRegex = new(
        """(?i)("(?:[^"]*(?:token|secret|password|authorization|apikey|apiKey|accessToken|refreshToken|licenseKey|x-project-token|idempotency|bearer)[^"]*)"\s*:\s*)("[^"]*"|[^\s,}\]]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SensitiveAssignmentRegex = new(
        """(?i)\b([a-z0-9_.-]*(?:token|secret|password|authorization|apikey|apiKey|accessToken|refreshToken|licenseKey|x-project-token|idempotency|bearer)[a-z0-9_.-]*)(\s*[=:]\s*)([^\s,;}\]]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex BearerRegex = new(
        """(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex ProjectTokenRegex = new(
        """\bBT-TKN-[0-9A-Fa-f]{48}\b""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex EmailRegex = new(
        """\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<BugTraceProxyService> _logger;
    private readonly string _baseUrl;
    // Token stocke en memoire uniquement -- jamais logue, jamais retourne au client
    private readonly string _projectToken;
    /// <summary>Dedicated T-IA ticket authority; never falls back to the legacy technical-report token.</summary>
    private readonly string _tiaProjectToken;
    /// <summary>Dedicated TIA support authority; never falls back to the legacy report project's token.</summary>
    private readonly string _supportProjectToken;
    private readonly string _projectId;
    private readonly SemaphoreSlim _tiaIdentityGate = new(1, 1);
    private bool _tiaIdentityVerified;

    /// <summary>Captures server configuration and the named-client factory without contacting the provider or loading client-supplied authority.</summary>
    /// <remarks>Missing settings remain empty and make IsConfigured false; callers must fail closed. Only base URL trailing slashes are removed. Configuration is captured for the singleton lifetime.</remarks>
    public BugTraceProxyService(
        IHttpClientFactory httpClientFactory,
        ILogger<BugTraceProxyService> logger,
        IConfiguration config)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _baseUrl = (config["BUGTRACE_BASE_URL"] ?? string.Empty).TrimEnd('/');
        _projectToken = config["BUGTRACE_PROJECT_TOKEN"] ?? string.Empty;
        _tiaProjectToken = config["BUGTRACE_TIA_PROJECT_TOKEN"] ?? string.Empty;
        _supportProjectToken = config["BUGTRACE_SUPPORT_PROJECT_TOKEN"] ?? string.Empty;
        _projectId = config["BUGTRACE_PROJECT_ID"] ?? string.Empty;
    }

    /// <inheritdoc />
    public string ExpectedProjectId => _projectId;

    /// <inheritdoc />
    public bool IsConfigured =>
        !string.IsNullOrEmpty(_baseUrl) &&
        !string.IsNullOrEmpty(_projectToken) &&
        !string.IsNullOrEmpty(_projectId);

    /// <inheritdoc />
    public bool IsTiaConfigured =>
        IsValidBaseUrl(_baseUrl) &&
        Regex.IsMatch(_tiaProjectToken, "^BT-TKN-[0-9a-f]{48}$", RegexOptions.CultureInvariant) &&
        Guid.TryParseExact(_projectId, "D", out var parsedProjectId) &&
        string.Equals(parsedProjectId.ToString("D"), _projectId, StringComparison.Ordinal);

    /// <summary>Creates the redirect-free, cookie-free transport used only for BugTrace relay calls.</summary>
    internal static HttpMessageHandler CreateHttpMessageHandler() => new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = DecompressionMethods.None
    };

    // Cree un client HTTP avec le token BugTrace injecte cote serveur.
    // Le token n'est jamais transmis au client appelant ni dans les logs.
    /// <summary>Obtains a factory-managed BugTrace client and replaces its project-token header with server-held configuration; callers never supply that authority.</summary>
    /// <returns>A named client whose handler lifetime belongs to the factory; neither token nor response content is logged here.</returns>
    private HttpClient CreateClient(string projectToken)
    {
        var client = _httpClientFactory.CreateClient("BugTrace");
        client.DefaultRequestHeaders.Remove("X-Project-Token");
        client.DefaultRequestHeaders.Add("X-Project-Token", projectToken);
        return client;
    }

    /// <summary>Creates a client carrying only the legacy internal technical-report authority.</summary>
    private HttpClient CreateClient() => CreateClient(_projectToken);

    /// <inheritdoc />
    public async Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default) =>
        await SubmitTicketCoreAsync(ticketBody, idempotencyKey: null, _projectToken, boundedResponse: false, ct);

    /// <inheritdoc />
    public async Task<JsonElement> SubmitTicketAsync(
        object ticketBody,
        string idempotencyKey,
        CancellationToken ct = default)
    {
        if (!Guid.TryParseExact(idempotencyKey, "D", out var parsed)
            || !string.Equals(parsed.ToString("D"), idempotencyKey, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The idempotency key must be an exact lowercase canonical report UUID.",
                nameof(idempotencyKey));
        }

        return await SubmitTicketCoreAsync(
            ticketBody,
            idempotencyKey,
            _projectToken,
            boundedResponse: false,
            ct);
    }

    /// <inheritdoc />
    public async Task<JsonElement> SubmitTiaTicketAsync(object ticketBody, CancellationToken ct = default) =>
        await SubmitTiaTicketCoreAsync(ticketBody, idempotencyKey: null, ct);

    /// <inheritdoc />
    public async Task<JsonElement> SubmitTiaTicketAsync(
        object ticketBody,
        string idempotencyKey,
        CancellationToken ct = default)
    {
        if (!Guid.TryParseExact(idempotencyKey, "D", out var parsed)
            || !string.Equals(parsed.ToString("D"), idempotencyKey, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The idempotency key must be an exact lowercase canonical report UUID.",
                nameof(idempotencyKey));
        }

        return await SubmitTiaTicketCoreAsync(ticketBody, idempotencyKey, ct);
    }

    /// <summary>Verifies the configured provider project before relaying a T-IA ticket mutation.</summary>
    private async Task<JsonElement> SubmitTiaTicketCoreAsync(
        object ticketBody,
        string? idempotencyKey,
        CancellationToken ct)
    {
        await VerifyTiaAuthorityAsync(ct);
        return await SubmitTicketCoreAsync(ticketBody, idempotencyKey, _tiaProjectToken, boundedResponse: true, ct);
    }

    /// <summary>Relays a legacy or T-IA ticket while forwarding an optional canonical idempotency key unchanged.</summary>
    private async Task<JsonElement> SubmitTicketCoreAsync(
        object ticketBody,
        string? idempotencyKey,
        string projectToken,
        bool boundedResponse,
        CancellationToken ct)
    {
        var client = CreateClient(projectToken);
        _logger.LogInformation("BugTrace proxy: relaying ticket submission");

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/api/external/tickets")
        {
            Content = JsonContent.Create(ticketBody)
        };
        if (idempotencyKey is not null)
            request.Headers.Add("Idempotency-Key", idempotencyKey);

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        await EnsureBugTraceSuccessAsync(response, "submit_ticket", ct);
        return boundedResponse
            ? await ReadBoundedTicketJsonAsync(response.Content, projectToken, ct)
            : await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    /// <inheritdoc />
    public async Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default)
    {
        var client = CreateClient();
        _logger.LogInformation("BugTrace proxy: relaying comment to ticket {TicketNumber}", ticketNumber);

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"{_baseUrl}/api/external/tickets/{ticketNumber}/comments")
        {
            Content = JsonContent.Create(commentBody)
        };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        await EnsureBugTraceSuccessAsync(response, "add_comment", ct);
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    /// <inheritdoc />
    public async Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default)
    {
        var client = CreateClient();
        _logger.LogInformation("BugTrace proxy: relaying ticket list request (email redacted)");

        using var response = await client.GetAsync(
            $"{_baseUrl}/api/external/tickets/email/{Uri.EscapeDataString(email)}",
            HttpCompletionOption.ResponseHeadersRead,
            ct);
        await EnsureBugTraceSuccessAsync(response, "get_tickets_by_email", ct);
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    /// <inheritdoc />
    public async Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default)
    {
        var client = CreateClient();
        _logger.LogInformation("BugTrace proxy: relaying comments request for ticket {TicketNumber}", ticketNumber);

        using var response = await client.GetAsync(
            $"{_baseUrl}/api/external/tickets/{ticketNumber}/comments",
            HttpCompletionOption.ResponseHeadersRead,
            ct);
        await EnsureBugTraceSuccessAsync(response, "get_ticket_comments", ct);
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    /// <inheritdoc />
    public async Task<JsonElement> AddTiaCommentAsync(
        string ticketNumber,
        object commentBody,
        CancellationToken ct = default)
    {
        await VerifyTiaAuthorityAsync(ct);
        var client = CreateClient(_tiaProjectToken);
        _logger.LogInformation("BugTrace proxy: relaying T-IA comment to ticket {TicketNumber}", ticketNumber);

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"{_baseUrl}/api/external/tickets/{ticketNumber}/comments")
        {
            Content = JsonContent.Create(commentBody)
        };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        await EnsureBugTraceSuccessAsync(response, "add_tia_comment", ct);
        return await ReadBoundedTicketJsonAsync(response.Content, _tiaProjectToken, ct);
    }

    /// <inheritdoc />
    public async Task<JsonElement> GetTiaTicketsByEmailAsync(string email, CancellationToken ct = default)
    {
        await VerifyTiaAuthorityAsync(ct);
        var client = CreateClient(_tiaProjectToken);
        _logger.LogInformation("BugTrace proxy: relaying T-IA ticket list request (email redacted)");

        using var response = await client.GetAsync(
            $"{_baseUrl}/api/external/tickets/email/{Uri.EscapeDataString(email)}",
            HttpCompletionOption.ResponseHeadersRead,
            ct);
        await EnsureBugTraceSuccessAsync(response, "get_tia_tickets_by_email", ct);
        return await ReadBoundedTicketJsonAsync(response.Content, _tiaProjectToken, ct);
    }

    /// <inheritdoc />
    public async Task<JsonElement> GetTiaTicketCommentsAsync(string ticketNumber, CancellationToken ct = default)
    {
        await VerifyTiaAuthorityAsync(ct);
        var client = CreateClient(_tiaProjectToken);
        _logger.LogInformation("BugTrace proxy: relaying T-IA comments request for ticket {TicketNumber}", ticketNumber);

        using var response = await client.GetAsync(
            $"{_baseUrl}/api/external/tickets/{ticketNumber}/comments",
            HttpCompletionOption.ResponseHeadersRead,
            ct);
        await EnsureBugTraceSuccessAsync(response, "get_tia_ticket_comments", ct);
        return await ReadBoundedTicketJsonAsync(response.Content, _tiaProjectToken, ct);
    }

    /// <summary>Verifies that the dedicated opaque T-IA token selects the exact configured provider project.</summary>
    /// <remarks>Only a successful exact match is cached. Concurrent callers share one verification gate; failures never enable later calls or fall back to legacy authority.</remarks>
    /// <param name="ct">Cancels the gate wait, provider request, or bounded response read.</param>
    /// <returns>A task that completes only when the dedicated authority is trusted.</returns>
    /// <exception cref="OperationCanceledException">The caller canceled verification.</exception>
    /// <exception cref="BugTraceTiaAuthorityException">Configuration is invalid, identity is rejected or mismatched, or identity transport cannot be validated.</exception>
    public async Task VerifyTiaAuthorityAsync(CancellationToken ct = default)
    {
        if (Volatile.Read(ref _tiaIdentityVerified))
            return;
        if (!IsTiaConfigured)
            throw new BugTraceTiaAuthorityException(BugTraceTiaAuthorityFailureReason.ConfigurationInvalid);

        await _tiaIdentityGate.WaitAsync(ct);
        try
        {
            if (Volatile.Read(ref _tiaIdentityVerified))
                return;

            var client = CreateClient(_tiaProjectToken);
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}/api/external/tickets/project");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "BugTrace T-IA project identity verification was rejected: status={StatusCode}",
                    (int)response.StatusCode);
                throw new BugTraceTiaAuthorityException(BugTraceTiaAuthorityFailureReason.IdentityRejected);
            }

            var identity = await ReadBoundedIdentityAsync(response.Content, ct);
            if (!identity.TryGetProperty("projectId", out var projectIdProperty)
                || projectIdProperty.ValueKind != JsonValueKind.String
                || !string.Equals(projectIdProperty.GetString(), _projectId, StringComparison.Ordinal))
            {
                throw new BugTraceTiaAuthorityException(BugTraceTiaAuthorityFailureReason.IdentityMismatch);
            }

            Volatile.Write(ref _tiaIdentityVerified, true);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (BugTraceTiaAuthorityException)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or NotSupportedException or IOException or OperationCanceledException)
        {
            throw new BugTraceTiaAuthorityException(
                BugTraceTiaAuthorityFailureReason.IdentityUnavailable,
                exception);
        }
        finally
        {
            _tiaIdentityGate.Release();
        }
    }

    /// <summary>Reads and detaches a small identity document; oversized or trailing content fails closed.</summary>
    private static async Task<JsonElement> ReadBoundedIdentityAsync(HttpContent? content, CancellationToken ct)
    {
        if (content is null || content.Headers.ContentLength is > MaxIdentityBodyBytes)
            throw new JsonException("The BugTrace project identity response is missing or oversized.");

        await using var stream = await content.ReadAsStreamAsync(ct);
        var buffer = new byte[MaxIdentityBodyBytes + 1];
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), ct);
            if (read == 0)
                break;
            totalRead += read;
        }
        if (totalRead == 0 || totalRead > MaxIdentityBodyBytes)
            throw new JsonException("The BugTrace project identity response is missing or oversized.");

        using var document = JsonDocument.Parse(buffer.AsMemory(0, totalRead));
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new JsonException("The BugTrace project identity response must be an object.");
        return document.RootElement.Clone();
    }

    /// <summary>Reads a detached ticket response within a fixed bound and never includes provider content in failures.</summary>
    private static async Task<JsonElement> ReadBoundedTicketJsonAsync(
        HttpContent? content,
        string forbiddenCredential,
        CancellationToken ct)
    {
        if (content is null || content.Headers.ContentLength is > MaxTicketResponseBodyBytes)
            throw new HttpRequestException("The BugTrace ticket response is missing or oversized.");

        await using var stream = await content.ReadAsStreamAsync(ct);
        var buffer = new byte[MaxTicketResponseBodyBytes + 1];
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), ct);
            if (read == 0)
                break;
            totalRead += read;
        }
        if (totalRead == 0 || totalRead > MaxTicketResponseBodyBytes)
            throw new HttpRequestException("The BugTrace ticket response is missing or oversized.");

        var responseText = Encoding.UTF8.GetString(buffer, 0, totalRead);
        if (!string.IsNullOrEmpty(forbiddenCredential)
            && responseText.Contains(forbiddenCredential, StringComparison.Ordinal))
        {
            throw new HttpRequestException("The BugTrace ticket response contained forbidden credential material.");
        }

        try
        {
            using var document = JsonDocument.Parse(responseText);
            if (JsonContainsCredential(document.RootElement, forbiddenCredential))
                throw new HttpRequestException("The BugTrace ticket response contained forbidden credential material.");
            return document.RootElement.Clone();
        }
        catch (JsonException exception)
        {
            throw new HttpRequestException("The BugTrace ticket response is malformed.", exception);
        }
    }

    /// <summary>Finds an exact credential substring after JSON escape decoding, including property names.</summary>
    private static bool JsonContainsCredential(JsonElement element, string credential)
    {
        if (string.IsNullOrEmpty(credential))
            return false;

        return element.ValueKind switch
        {
            JsonValueKind.Object => element.EnumerateObject().Any(property =>
                property.Name.Contains(credential, StringComparison.Ordinal) ||
                JsonContainsCredential(property.Value, credential)),
            JsonValueKind.Array => element.EnumerateArray().Any(item => JsonContainsCredential(item, credential)),
            JsonValueKind.String => element.GetString()?.Contains(credential, StringComparison.Ordinal) == true,
            _ => false
        };
    }

    /// <summary>Accepts only a credential-free HTTP(S) origin or base path without query or fragment state.</summary>
    private static bool IsValidBaseUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Query) &&
        string.IsNullOrEmpty(uri.Fragment);

    /// <summary>Rejects non-success responses after capturing only a bounded, sanitized diagnostic prefix.</summary>
    private async Task EnsureBugTraceSuccessAsync(
        HttpResponseMessage response,
        string operation,
        CancellationToken ct)
    {
        if (response.IsSuccessStatusCode)
            return;

        var rawBody = await ReadBoundedBodyForLogAsync(response.Content, ct);
        var sanitizedBody = SanitizeForLog(rawBody);
        var statusCode = (int)response.StatusCode;

        if (statusCode >= 500)
        {
            _logger.LogError(
                "BugTrace upstream error during {Operation}: status={StatusCode} body={Body}",
                operation,
                statusCode,
                sanitizedBody);
        }
        else
        {
            _logger.LogWarning(
                "BugTrace upstream rejected {Operation}: status={StatusCode} body={Body}",
                operation,
                statusCode,
                sanitizedBody);
        }

        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Reads at most one fixed UTF-8 prefix for logging and skips known oversized bodies entirely.
    /// </summary>
    private static async Task<string> ReadBoundedBodyForLogAsync(
        HttpContent? content,
        CancellationToken ct)
    {
        if (content is null)
            return string.Empty;
        if (content.Headers.ContentLength is > MaxLoggedBodyBytes)
            return OversizedBody;

        await using var stream = await content.ReadAsStreamAsync(ct);
        var buffer = new byte[MaxLoggedBodyBytes + 1];
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), ct);
            if (read == 0)
                break;
            totalRead += read;
        }

        var capturedBytes = Math.Min(totalRead, MaxLoggedBodyBytes);
        var prefix = Encoding.UTF8.GetString(buffer, 0, capturedBytes);
        return totalRead > MaxLoggedBodyBytes
            ? prefix + "...<truncated>"
            : prefix;
    }

    /// <summary>Redacts known credential and identity shapes from an already bounded diagnostic prefix.</summary>
    private static string SanitizeForLog(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return "";

        var sanitized = body;
        sanitized = SensitiveJsonPropertyRegex.Replace(sanitized, match => $"{match.Groups[1].Value}\"{Redacted}\"");
        sanitized = SensitiveAssignmentRegex.Replace(sanitized, match => $"{match.Groups[1].Value}{match.Groups[2].Value}{Redacted}");
        sanitized = BearerRegex.Replace(sanitized, $"Bearer {Redacted}");
        sanitized = ProjectTokenRegex.Replace(sanitized, Redacted);
        sanitized = EmailRegex.Replace(sanitized, RedactEmailMatch);
        sanitized = sanitized.Replace("\r", "\\r").Replace("\n", "\\n");

        return sanitized.Length <= MaxLoggedBodyLength
            ? sanitized
            : sanitized[..MaxLoggedBodyLength] + "...<truncated>";
    }

    private static string RedactEmailMatch(Match match)
    {
        var email = match.Value;
        var parts = email.Split('@', 2);
        if (parts.Length != 2 || parts[0].Length == 0)
            return Redacted;

        var prefix = parts[0].Length == 1 ? parts[0] : parts[0][..Math.Min(2, parts[0].Length)];
        return $"{prefix}***@{parts[1]}";
    }
}

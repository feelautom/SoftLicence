using System.Net.Http.Json;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace SoftLicence.Server.Services;

public interface IBugTraceProxyService
{
    string ExpectedProjectId { get; }
    bool IsConfigured { get; }
    Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default);
    Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default);
    Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default);
    Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default);
}

public sealed class BugTraceProxyService : IBugTraceProxyService
{
    private const int MaxLoggedBodyLength = 2000;
    private const string Redacted = "<redacted>";
    private static readonly Regex SensitiveJsonPropertyRegex = new(
        """(?i)("(?:[^"]*(?:token|secret|password|authorization|apikey|apiKey|accessToken|refreshToken|licenseKey|x-project-token|bearer)[^"]*)"\s*:\s*)("[^"]*"|[^\s,}\]]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SensitiveAssignmentRegex = new(
        """(?i)\b([a-z0-9_.-]*(?:token|secret|password|authorization|apikey|apiKey|accessToken|refreshToken|licenseKey|x-project-token|bearer)[a-z0-9_.-]*)(\s*[=:]\s*)([^\s,;}\]]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex BearerRegex = new(
        """(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex EmailRegex = new(
        """\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<BugTraceProxyService> _logger;
    private readonly string _baseUrl;
    // Token stocke en memoire uniquement -- jamais logue, jamais retourne au client
    private readonly string _projectToken;
    private readonly string _projectId;

    public BugTraceProxyService(
        IHttpClientFactory httpClientFactory,
        ILogger<BugTraceProxyService> logger,
        IConfiguration config)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _baseUrl = (config["BUGTRACE_BASE_URL"] ?? string.Empty).TrimEnd('/');
        _projectToken = config["BUGTRACE_PROJECT_TOKEN"] ?? string.Empty;
        _projectId = config["BUGTRACE_PROJECT_ID"] ?? string.Empty;
    }

    public string ExpectedProjectId => _projectId;

    public bool IsConfigured =>
        !string.IsNullOrEmpty(_baseUrl) &&
        !string.IsNullOrEmpty(_projectToken) &&
        !string.IsNullOrEmpty(_projectId);

    // Cree un client HTTP avec le token BugTrace injecte cote serveur.
    // Le token n'est jamais transmis au client appelant ni dans les logs.
    private HttpClient CreateClient()
    {
        var client = _httpClientFactory.CreateClient("BugTrace");
        client.DefaultRequestHeaders.Remove("X-Project-Token");
        client.DefaultRequestHeaders.Add("X-Project-Token", _projectToken);
        return client;
    }

    public async Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default)
    {
        var client = CreateClient();
        _logger.LogInformation("BugTrace proxy: relaying ticket submission to {BaseUrl}/api/external/tickets", _baseUrl);

        var response = await client.PostAsJsonAsync($"{_baseUrl}/api/external/tickets", ticketBody, ct);
        await EnsureBugTraceSuccessAsync(response, "submit_ticket", ct);
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    public async Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default)
    {
        var client = CreateClient();
        _logger.LogInformation("BugTrace proxy: relaying comment to ticket {TicketNumber}", ticketNumber);

        var response = await client.PostAsJsonAsync(
            $"{_baseUrl}/api/external/tickets/{ticketNumber}/comments", commentBody, ct);
        await EnsureBugTraceSuccessAsync(response, "add_comment", ct);
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    public async Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default)
    {
        var client = CreateClient();
        _logger.LogInformation("BugTrace proxy: relaying ticket list request (email redacted)");

        var response = await client.GetAsync(
            $"{_baseUrl}/api/external/tickets/email/{Uri.EscapeDataString(email)}", ct);
        await EnsureBugTraceSuccessAsync(response, "get_tickets_by_email", ct);
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    public async Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default)
    {
        var client = CreateClient();
        _logger.LogInformation("BugTrace proxy: relaying comments request for ticket {TicketNumber}", ticketNumber);

        var response = await client.GetAsync(
            $"{_baseUrl}/api/external/tickets/{ticketNumber}/comments", ct);
        await EnsureBugTraceSuccessAsync(response, "get_ticket_comments", ct);
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    private async Task EnsureBugTraceSuccessAsync(
        HttpResponseMessage response,
        string operation,
        CancellationToken ct)
    {
        if (response.IsSuccessStatusCode)
            return;

        var rawBody = response.Content == null
            ? string.Empty
            : await response.Content.ReadAsStringAsync(ct);
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

    private static string SanitizeForLog(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return "";

        var sanitized = body;
        sanitized = SensitiveJsonPropertyRegex.Replace(sanitized, match => $"{match.Groups[1].Value}\"{Redacted}\"");
        sanitized = SensitiveAssignmentRegex.Replace(sanitized, match => $"{match.Groups[1].Value}{match.Groups[2].Value}{Redacted}");
        sanitized = BearerRegex.Replace(sanitized, $"Bearer {Redacted}");
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

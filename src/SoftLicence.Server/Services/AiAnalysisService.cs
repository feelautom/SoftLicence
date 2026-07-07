using System.Text;
using System.Text.Json;

namespace SoftLicence.Server.Services;

public class AiAnalysisService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;

    public AiAnalysisService(IHttpClientFactory httpClientFactory, IConfiguration config)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
    }

    private string? ApiKey => _config["DEEPSEEK_API_KEY"];
    public bool IsConfigured => !string.IsNullOrEmpty(ApiKey);

    public async Task<string> AnalyzeAsync(string prompt)
    {
        var apiKey = ApiKey;
        if (string.IsNullOrEmpty(apiKey))
            throw new InvalidOperationException("Clé API DeepSeek non configurée (variable DEEPSEEK_API_KEY).");

        var client = _httpClientFactory.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.deepseek.com/chat/completions");
        request.Headers.Add("Authorization", $"Bearer {apiKey}");

        var body = new
        {
            model = "deepseek-chat",
            max_tokens = 2048,
            messages = new[]
            {
                new { role = "system", content = "Tu es un expert en analyse de télémétrie logicielle et gestion de licences SaaS. Tu réponds toujours en français avec un rapport structuré, factuel et orienté action." },
                new { role = "user", content = prompt }
            }
        };

        request.Content = new StringContent(
            JsonSerializer.Serialize(body),
            Encoding.UTF8,
            "application/json");

        var response = await client.SendAsync(request);
        var responseJson = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new Exception($"Erreur API DeepSeek ({(int)response.StatusCode}): {responseJson}");

        var json = JsonSerializer.Deserialize<JsonElement>(responseJson);
        return json.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString()
               ?? "Aucune réponse reçue.";
    }
}

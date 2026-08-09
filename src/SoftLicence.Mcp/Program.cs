using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SoftLicence.Mcp;

var builder = Host.CreateApplicationBuilder(args);

builder.Logging.ClearProviders();

builder.Services.Configure<SoftLicenceMcpOptions>(options =>
{
    options.SoftLicenceBaseUrl = builder.Configuration["SoftLicenceBaseUrl"];
    options.SoftLicenceApiKey = builder.Configuration["SoftLicenceApiKey"];
    options.SoftLicenceAdminSecret = builder.Configuration["SoftLicenceAdminSecret"];
    options.SOFTLICENCE_BASE_URL = builder.Configuration["SOFTLICENCE_BASE_URL"];
    options.SOFTLICENCE_API_KEY = builder.Configuration["SOFTLICENCE_API_KEY"];
    options.SOFTLICENCE_ADMIN_SECRET = builder.Configuration["SOFTLICENCE_ADMIN_SECRET"];
    options.ResultDirectory = builder.Configuration["SoftLicenceMcpResultDirectory"]
        ?? builder.Configuration["SOFTLICENCE_MCP_RESULT_DIRECTORY"];
    options.MaxInlineResultCharacters = builder.Configuration.GetValue<int?>("SoftLicenceMcpMaxInlineResultCharacters")
        ?? builder.Configuration.GetValue<int?>("SOFTLICENCE_MCP_MAX_INLINE_RESULT_CHARACTERS")
        ?? options.MaxInlineResultCharacters;
    options.ResultChunkCharacters = builder.Configuration.GetValue<int?>("SoftLicenceMcpResultChunkCharacters")
        ?? builder.Configuration.GetValue<int?>("SOFTLICENCE_MCP_RESULT_CHUNK_CHARACTERS")
        ?? options.ResultChunkCharacters;
    options.ResultTtlMinutes = builder.Configuration.GetValue<int?>("SoftLicenceMcpResultTtlMinutes")
        ?? builder.Configuration.GetValue<int?>("SOFTLICENCE_MCP_RESULT_TTL_MINUTES")
        ?? options.ResultTtlMinutes;
    options.ResultMaxTotalBytes = builder.Configuration.GetValue<long?>("SoftLicenceMcpResultMaxTotalBytes")
        ?? builder.Configuration.GetValue<long?>("SOFTLICENCE_MCP_RESULT_MAX_TOTAL_BYTES")
        ?? options.ResultMaxTotalBytes;
});

builder.Services.AddSingleton<HttpClient>();
builder.Services.AddSingleton<McpResultStore>();
builder.Services.AddTransient<SoftLicenceAnalyticsClient>();

builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<SoftLicenceAnalyticsTools>();

await builder.Build().RunAsync();

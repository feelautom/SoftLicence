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
    options.SOFTLICENCE_BASE_URL = builder.Configuration["SOFTLICENCE_BASE_URL"];
    options.SOFTLICENCE_API_KEY = builder.Configuration["SOFTLICENCE_API_KEY"];
});

builder.Services.AddSingleton<HttpClient>();
builder.Services.AddTransient<SoftLicenceAnalyticsClient>();

builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<SoftLicenceAnalyticsTools>();

await builder.Build().RunAsync();

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
});

builder.Services.AddSingleton<HttpClient>();
builder.Services.AddTransient<SoftLicenceAnalyticsClient>();

builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<SoftLicenceAnalyticsTools>();

await builder.Build().RunAsync();

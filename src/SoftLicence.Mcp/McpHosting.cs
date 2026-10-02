using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SoftLicence.Mcp;

/// <summary>
/// Builds the SoftLicence MCP in one of two modes sharing the same tools:
/// stdio (local executable, credentials from the environment) and HTTP (TKT-001169: VPN-only
/// container at /mcp, credentials from each caller's request headers, access gate in front).
/// </summary>
public static class McpHosting
{
    /// <summary>Configuration key selecting the transport; "http" enables the online mode.</summary>
    public const string TransportSetting = "SOFTLICENCE_MCP_TRANSPORT";

    /// <summary>Route of the online MCP endpoint.</summary>
    public const string McpRoute = "/mcp";

    /// <summary>Returns whether the configuration or the command line selects the HTTP mode.</summary>
    public static bool IsHttpMode(IConfiguration configuration, string[] args) =>
        args.Contains("--http", StringComparer.Ordinal)
        || string.Equals(configuration[TransportSetting], "http", StringComparison.OrdinalIgnoreCase);

    /// <summary>Binds <see cref="SoftLicenceMcpOptions"/> from configuration (both naming styles).</summary>
    public static void ConfigureOptions(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<SoftLicenceMcpOptions>(options =>
        {
            options.SoftLicenceBaseUrl = configuration["SoftLicenceBaseUrl"];
            options.SoftLicenceApiKey = configuration["SoftLicenceApiKey"];
            options.SoftLicenceAdminSecret = configuration["SoftLicenceAdminSecret"];
            options.SOFTLICENCE_BASE_URL = configuration["SOFTLICENCE_BASE_URL"];
            options.SOFTLICENCE_API_KEY = configuration["SOFTLICENCE_API_KEY"];
            options.SOFTLICENCE_ADMIN_SECRET = configuration["SOFTLICENCE_ADMIN_SECRET"];
            options.ResultDirectory = configuration["SoftLicenceMcpResultDirectory"]
                ?? configuration["SOFTLICENCE_MCP_RESULT_DIRECTORY"];
            options.MaxInlineResultCharacters = configuration.GetValue<int?>("SoftLicenceMcpMaxInlineResultCharacters")
                ?? configuration.GetValue<int?>("SOFTLICENCE_MCP_MAX_INLINE_RESULT_CHARACTERS")
                ?? options.MaxInlineResultCharacters;
            options.ResultChunkCharacters = configuration.GetValue<int?>("SoftLicenceMcpResultChunkCharacters")
                ?? configuration.GetValue<int?>("SOFTLICENCE_MCP_RESULT_CHUNK_CHARACTERS")
                ?? options.ResultChunkCharacters;
            options.ResultTtlMinutes = configuration.GetValue<int?>("SoftLicenceMcpResultTtlMinutes")
                ?? configuration.GetValue<int?>("SOFTLICENCE_MCP_RESULT_TTL_MINUTES")
                ?? options.ResultTtlMinutes;
            options.ResultMaxTotalBytes = configuration.GetValue<long?>("SoftLicenceMcpResultMaxTotalBytes")
                ?? configuration.GetValue<long?>("SOFTLICENCE_MCP_RESULT_MAX_TOTAL_BYTES")
                ?? options.ResultMaxTotalBytes;
            options.AllowedCidrs = configuration["SOFTLICENCE_MCP_ALLOWED_CIDRS"] ?? options.AllowedCidrs;
        });
    }

    /// <summary>Runs the historical local stdio server (credentials from the environment).</summary>
    public static async Task RunStdioAsync(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Logging.ClearProviders();
        ConfigureOptions(builder.Services, builder.Configuration);

        builder.Services.AddSingleton<HttpClient>();
        builder.Services.AddSingleton<McpResultStore>();
        builder.Services.AddTransient<SoftLicenceAnalyticsClient>();

        builder.Services
            .AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<SoftLicenceAnalyticsTools>()
            // Expose the real cause of expected tool failures instead of the SDK's generic message.
            .WithRequestFilters(filters => filters.AddCallToolFilter(McpToolErrorFilter.Wrap));

        await builder.Build().RunAsync();
    }

    /// <summary>
    /// Builds the online HTTP server. Stateless Streamable HTTP; every /mcp request passes the
    /// <see cref="McpHttpAccessGate"/> (VPN network, then analytics key verified by SoftLicence).
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <param name="configureBuilder">Test hook applied before the application is built.</param>
    public static WebApplication BuildHttpApp(string[] args, Action<WebApplicationBuilder>? configureBuilder = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        ConfigureOptions(builder.Services, builder.Configuration);

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(provider => new HttpClient(
            new ForwardedClientIpHandler(provider.GetRequiredService<IHttpContextAccessor>())
            {
                InnerHandler = new SocketsHttpHandler(),
            }));
        builder.Services.AddSingleton(provider =>
        {
            var accessor = provider.GetRequiredService<IHttpContextAccessor>();
            return new McpResultStore(
                provider.GetRequiredService<IOptions<SoftLicenceMcpOptions>>(),
                () => HttpRequestCallerCredentials.GetKeyFingerprint(accessor.HttpContext));
        });
        builder.Services.AddScoped<ISoftLicenceCallerCredentials, HttpRequestCallerCredentials>();
        builder.Services.AddTransient<SoftLicenceAnalyticsClient>();
        builder.Services.AddSingleton<McpHttpAccessGate>();

        builder.Services
            .AddMcpServer()
            .WithHttpTransport(options => options.Stateless = true)
            .WithTools<SoftLicenceAnalyticsTools>()
            .WithRequestFilters(filters => filters.AddCallToolFilter(McpToolErrorFilter.Wrap));

        configureBuilder?.Invoke(builder);

        var app = builder.Build();
        // Fail at startup, not at the first request, when the allowed networks are misconfigured.
        var gate = app.Services.GetRequiredService<McpHttpAccessGate>();

        app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
        app.UseWhen(
            context => context.Request.Path.StartsWithSegments(McpRoute),
            branch => branch.Use((context, next) => gate.InvokeAsync(context, next)));
        app.MapMcp(McpRoute);
        return app;
    }
}

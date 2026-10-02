using Microsoft.Extensions.Configuration;
using SoftLicence.Mcp;

// Local executable: stdio (default). Online VPN-only container: SOFTLICENCE_MCP_TRANSPORT=http (TKT-001169).
var configuration = new ConfigurationBuilder().AddEnvironmentVariables().AddCommandLine(args).Build();

if (McpHosting.IsHttpMode(configuration, args))
{
    await McpHosting.BuildHttpApp(args).RunAsync();
}
else
{
    await McpHosting.RunStdioAsync(args);
}

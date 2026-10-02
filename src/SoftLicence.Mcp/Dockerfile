# Online SoftLicence MCP (TKT-001169): Streamable HTTP at /mcp, VPN-only.
# Build from the repository root:  docker build -f src/SoftLicence.Mcp/Dockerfile -t softlicence-mcp:<tag> .
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["src/SoftLicence.Mcp/SoftLicence.Mcp.csproj", "SoftLicence.Mcp/"]
RUN dotnet restore "SoftLicence.Mcp/SoftLicence.Mcp.csproj"
COPY src/SoftLicence.Mcp/ SoftLicence.Mcp/
# Drop host build outputs (Windows NuGet paths in obj/ break the Linux restore), then restore cleanly.
RUN rm -rf SoftLicence.Mcp/bin SoftLicence.Mcp/obj \
    && dotnet publish "SoftLicence.Mcp/SoftLicence.Mcp.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# Result artifacts live in a dedicated writable folder owned by the non-root 'app' user (uid 1654).
RUN mkdir -p /app/mcp-results && chown -R 1654:1654 /app/mcp-results
USER 1654

ENV SOFTLICENCE_MCP_TRANSPORT=http \
    ASPNETCORE_URLS=http://0.0.0.0:8080 \
    SOFTLICENCE_MCP_RESULT_DIRECTORY=/app/mcp-results
EXPOSE 8080
ENTRYPOINT ["dotnet", "SoftLicence.Mcp.dll"]

using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Models;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies that every transport-generated Recovery failure remains in the bounded closed response envelope.</summary>
public sealed class RecoveryTelemetryEnvelopeTests
{
    /// <summary>Proves the real routing and consumes pipeline rewrites automatic 415 output to the Recovery envelope.</summary>
    [Fact]
    public async Task RealPipeline_UnsupportedMediaType_UsesRecoveryEnvelope()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();
        using var content = new StringContent("{}", Encoding.UTF8, "text/plain");

        using var response = await client.PostAsync("/api/telemetry/recovery/v1/events", content);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(StatusCodes.Status415UnsupportedMediaType, (int)response.StatusCode);
        using var json = JsonDocument.Parse(body);
        Assert.Equal(RecoveryTelemetryCodes.InvalidFieldValue, json.RootElement.GetProperty("code").GetString());
        Assert.True(Guid.TryParseExact(json.RootElement.GetProperty("correlationId").GetString(), "D", out _));
        Assert.Equal(2, json.RootElement.EnumerateObject().Count());
    }

    /// <summary>Proves the real controller pipeline keeps oversized bodies inside the same bounded envelope.</summary>
    [Fact]
    public async Task RealPipeline_OversizedBody_UsesRecoveryEnvelope()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();
        using var content = new ByteArrayContent(Enumerable.Repeat((byte)'x', 4097).ToArray());
        content.Headers.ContentType = new("application/json");

        using var response = await client.PostAsync("/api/telemetry/recovery/v1/events", content);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, (int)response.StatusCode);
        Assert.Equal(RecoveryTelemetryCodes.PayloadTooLarge, json.RootElement.GetProperty("code").GetString());
        Assert.True(Guid.TryParseExact(json.RootElement.GetProperty("correlationId").GetString(), "D", out _));
        Assert.Equal(2, json.RootElement.EnumerateObject().Count());
    }

    /// <summary>Proves automatic 415, throttling, and downstream 5xx bodies are replaced without retaining leaked details.</summary>
    [Theory]
    [InlineData(StatusCodes.Status415UnsupportedMediaType)]
    [InlineData(StatusCodes.Status429TooManyRequests)]
    [InlineData(StatusCodes.Status500InternalServerError)]
    [InlineData(StatusCodes.Status503ServiceUnavailable)]
    public async Task TransportFailure_IsRewrittenAsBoundedRecoveryEnvelope(int statusCode)
    {
        var context = CreateContext();
        var middleware = new RecoveryTelemetryResponseEnvelopeMiddleware(async httpContext =>
        {
            httpContext.Response.StatusCode = statusCode;
            await httpContext.Response.WriteAsync("SENSITIVE_INTERNAL_DETAIL");
        });

        await middleware.InvokeAsync(context);

        Assert.Equal(statusCode, context.Response.StatusCode);
        var body = ReadBody(context);
        Assert.DoesNotContain("SENSITIVE_INTERNAL_DETAIL", body, StringComparison.Ordinal);
        Assert.True(Encoding.UTF8.GetByteCount(body) <= 256);
        using var json = JsonDocument.Parse(body);
        Assert.Equal(RecoveryTelemetryCodes.InvalidFieldValue, json.RootElement.GetProperty("code").GetString());
        Assert.True(Guid.TryParseExact(json.RootElement.GetProperty("correlationId").GetString(), "D", out _));
        Assert.Equal(2, json.RootElement.EnumerateObject().Count());
    }

    /// <summary>Proves an uncaught exception is converted to a closed 500 envelope without exception text.</summary>
    [Fact]
    public async Task UncaughtException_IsRewrittenWithoutDetails()
    {
        var context = CreateContext();
        var middleware = new RecoveryTelemetryResponseEnvelopeMiddleware(_ =>
            throw new InvalidOperationException("SENSITIVE_EXCEPTION_DETAIL"));

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status500InternalServerError, context.Response.StatusCode);
        Assert.DoesNotContain("SENSITIVE_EXCEPTION_DETAIL", ReadBody(context), StringComparison.Ordinal);
    }

    /// <summary>Creates one isolated Recovery request with a readable response stream.</summary>
    private static DefaultHttpContext CreateContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/telemetry/recovery/v1/events";
        context.Response.Body = new MemoryStream();
        return context;
    }

    /// <summary>Creates a real server pipeline with an isolated non-relational store used only before persistence semantics matter.</summary>
    private static WebApplicationFactory<Program> CreateFactory() =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase($"recovery-envelope-{Guid.NewGuid():N}"));
            });
        });

    /// <summary>Returns the complete UTF-8 response body without changing its retained bytes.</summary>
    private static string ReadBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return new StreamReader(context.Response.Body, Encoding.UTF8, false, leaveOpen: true).ReadToEnd();
    }
}

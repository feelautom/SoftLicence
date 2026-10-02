using System.Security.Cryptography;
using System.Text;
using SoftLicence.Server.Services;
using Xunit;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;

namespace SoftLicence.Tests;

/// <summary>Protects the exact digest join against whitespace repair and neighboring-machine guesses.</summary>
public sealed class PreflightDiagnosticIdentityTests
{
    /// <summary>The digest algorithm matches preflight authority and collapses casing aliases only.</summary>
    [Fact]
    public void Resolve_MatchesExactDigestOnly()
    {
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("MACHINE-A"))).ToLowerInvariant();
        Assert.Equal("MACHINE-A", PreflightDiagnosticIdentity.Resolve(digest, ["machine-a", "MACHINE-A", "MACHINE-B"]));
        Assert.Null(PreflightDiagnosticIdentity.Resolve(digest, [" MACHINE-A", "MACHINE-B"]));
        Assert.Null(PreflightDiagnosticIdentity.Resolve(digest, []));
        Assert.Null(PreflightDiagnosticIdentity.Resolve(digest.ToUpperInvariant(), ["MACHINE-A"]));
    }

    /// <summary>Exercises authenticated HTTP lookup against persisted, product-scoped decision/seat rows.</summary>
    [Theory]
    [InlineData("exact", 200, "resolved")]
    [InlineData("other-license", 200, "not_found")]
    [InlineData("cross-product", 409, null)]
    [InlineData("wrong-grant", 409, null)]
    [InlineData("no-auth", 401, null)]
    public async Task HttpLookup_RequiresExactAuthority(string scenario, int expected, string? state)
    {
        var database = Guid.NewGuid().ToString();
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "synthetic-admin-secret");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(database));
            });
        });
        const string key = "sla_synthetic_preflight_test";
        var requestId = Guid.NewGuid().ToString();
        var grant = new string('b', 64);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var product = new Product { Id = Guid.NewGuid(), Name = "DiagnosticTest", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "synthetic" };
            var license = new License { Id = Guid.NewGuid(), ProductId = product.Id, LicenseKey = "SYNTHETIC" };
            db.Products.Add(product);
            db.Licenses.Add(license);
            db.LicenseSeats.Add(new LicenseSeat { LicenseId = license.Id, HardwareId = "MACHINE-A" });
            db.AnalyticsApiKeys.Add(new AnalyticsApiKey { ProductId = product.Id, Name = "test",
                Prefix = AnalyticsApiKeyAuthService.BuildPrefix(key), KeyHash = AnalyticsApiKeyAuthService.ComputeKeyHash(key),
                Scopes = AnalyticsApiKeyScopes.TelemetryRead, IsActive = true });
            db.RuntimeDistributionHardwareDecisions.Add(new RuntimeDistributionHardwareDecision {
                ClientId = "test", RequestId = requestId, ProductId = scenario == "cross-product" ? Guid.NewGuid() : product.Id,
                LicenseId = scenario == "other-license" ? Guid.NewGuid() : license.Id,
                GrantRefDigestSha256 = grant, PayloadDigestSha256 = new string('a', 64),
                HardwareIdHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("MACHINE-A"))).ToLowerInvariant(),
                Outcome = "accepted", ReasonCode = "eligible", AuthorityMode = "server-derived", BanCategoriesJson = "[]" });
            await db.SaveChangesAsync();
        }
        var client = factory.CreateClient();
        if (scenario != "no-auth") client.DefaultRequestHeaders.Add("X-Analytics-Key", key);
        var response = await client.GetAsync($"/api/analytics/support/runtime-distribution-hardware-identity?requestId={requestId}&grantRefDigestSha256={(scenario == "wrong-grant" ? new string('c', 64) : grant)}");
        Assert.Equal((HttpStatusCode)expected, response.StatusCode);
        if (state is not null)
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(state, body.RootElement.GetProperty("status").GetString());
            Assert.Equal(state == "resolved" ? "MACHINE-A" : null, body.RootElement.GetProperty("hardwareId").GetString());
        }
    }
}

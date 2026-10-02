using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises the customer boundary with synthetic identities and no provider network access.</summary>
public sealed class BugTraceSupportCaseTests
{
    /// <summary>Tests family-wide redaction without broadening the adjacent route classification.</summary>
    [Theory]
    [InlineData("/api/bugtrace/support-cases", true)]
    [InlineData("/API/BUGTRACE/SUPPORT-CASES/", true)]
    [InlineData("/api/bugtrace/support-cases/attachments", true)]
    [InlineData("/api/bugtrace/support-cases/SUP-000123/messages", true)]
    [InlineData("/api/bugtrace/support-cases-extra", false)]
    public void Redaction_CoversOnlySupportFamily(string path, bool expected)
    {
        var method = typeof(AuditMiddleware).GetMethod("IsBugTraceSensitiveReportPath", BindingFlags.NonPublic | BindingFlags.Static)!;
        Assert.Equal(expected, method.Invoke(null, [path]));
    }

    /// <summary>A licence from another product cannot acquire this project's support authority.</summary>
    [Fact]
    public async Task Create_WrongLicenseProduct_IsForbidden()
    {
        using var factory = CreateFactory(Guid.NewGuid());
        await SeedAsync(factory, Guid.NewGuid());
        using var request = CreateRequest();
        using var response = await factory.CreateClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>A rejected JSON request must persist no raw key, hardware or human message.</summary>
    [Fact]
    public async Task RejectedJson_AuditBodyIsRedacted()
    {
        using var factory = CreateFactory(Guid.NewGuid());
        using var request = CreateRequest();
        using var response = await factory.CreateClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var log = await ReadLogAsync(factory);
        Assert.Equal("[REDACTED]", log.RequestBody);
        Assert.True(string.IsNullOrEmpty(log.LicenseKey));
        Assert.True(string.IsNullOrEmpty(log.HardwareId));
    }

    /// <summary>Provider replay must not spend another create quota slot for the same exact request.</summary>
    [Fact]
    public async Task IdenticalCreateReplay_DoesNotExhaustCreationQuota()
    {
        var product = Guid.NewGuid();
        using var factory = CreateFactory(product);
        await SeedAsync(factory, product);
        for (var i = 0; i < 4; i++)
        {
            using var request = CreateRequest();
            using var response = await factory.CreateClient().SendAsync(request);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        }
    }

    /// <summary>The owner retains access when the exact case is on the second provider page.</summary>
    [Fact]
    public async Task OwnedCaseAfterFirst200_RemainsReadable()
    {
        var product = Guid.NewGuid();
        var proxy = new FakeBugTraceProxyService
        {
            SupportPage = page => System.Text.Json.JsonSerializer.SerializeToElement(new
            {
                total = 201, limit = 200, offset = page * 200,
                items = page == 0
                    ? Enumerable.Range(1000, 200).Select(i => new { supportNumber = $"SUP-{i:000000}", reporterEmail = "synthetic@example.invalid" }).ToArray()
                    : new[] { new { supportNumber = "SUP-000123", reporterEmail = "synthetic@example.invalid" } }
            })
        };
        using var factory = CreateFactory(product, proxy);
        await SeedAsync(factory, product);
        using var response = await factory.CreateClient().PostAsJsonAsync("/api/bugtrace/support-cases/SUP-000123/detail", new
        {
            licenseKey = "SUP871-SYNTHETIC", hardwareId = "CURRENT-SYNTHETIC",
            projectId = "9f3c8fea-8740-42af-be83-6f527c6d102a"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, proxy.QueriedSupportEmails.Count);
    }

    /// <summary>A provider filter bug cannot authorize a record bearing a different reporter.</summary>
    [Fact]
    public async Task ProviderReturnsForeignReporter_IsForbidden()
    {
        var product = Guid.NewGuid();
        var proxy = new FakeBugTraceProxyService { SupportPage = _ => System.Text.Json.JsonSerializer.SerializeToElement(new
        { total = 1, limit = 200, offset = 0, items = new[] { new { supportNumber = "SUP-000123", reporterEmail = "foreign@example.invalid" } } }) };
        using var factory = CreateFactory(product, proxy);
        await SeedAsync(factory, product);
        using var response = await factory.CreateClient().PostAsJsonAsync("/api/bugtrace/support-cases/SUP-000123/detail", new
        { licenseKey = "SUP871-SYNTHETIC", hardwareId = "CURRENT-SYNTHETIC", projectId = proxy.ExpectedProjectId });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>Rejects every nonnumeric pagination kind before an otherwise matching owner can acquire access.</summary>
    [Theory]
    [InlineData("total", "\"1\"")]
    [InlineData("total", "null")]
    [InlineData("total", "{}")]
    [InlineData("total", "[]")]
    [InlineData("total", "true")]
    [InlineData("offset", "\"0\"")]
    [InlineData("offset", "null")]
    [InlineData("offset", "{}")]
    [InlineData("offset", "[]")]
    [InlineData("offset", "false")]
    public async Task PostAudit_MalformedPaginationScalarIsRejected(string field, string json)
    {
        var product = Guid.NewGuid();
        var page = System.Text.Json.Nodes.JsonNode.Parse("""
            {"total":1,"offset":0,"items":[{"supportNumber":"SUP-000123","reporterEmail":"synthetic@example.invalid"}]}
            """)!;
        page[field] = System.Text.Json.Nodes.JsonNode.Parse(json);
        var proxy = new FakeBugTraceProxyService
        {
            SupportPage = _ => System.Text.Json.JsonSerializer.SerializeToElement(page)
        };
        using var factory = CreateFactory(product, proxy);
        await SeedAsync(factory, product);
        using var response = await factory.CreateClient().PostAsJsonAsync("/api/bugtrace/support-cases/SUP-000123/detail", new
        {
            licenseKey = "SUP871-SYNTHETIC", hardwareId = "CURRENT-SYNTHETIC", projectId = proxy.ExpectedProjectId
        });
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal("{\"error\":\"support_invalid_response\"}", await response.Content.ReadAsStringAsync());
    }

    /// <summary>Private addresses receive the same SUP abuse limit as public addresses before licence lookup.</summary>
    [Fact]
    public async Task PostAudit_PrivateIpCannotBypassSupportThrottle()
    {
        using var factory = CreateFactory(Guid.NewGuid());
        for (var attempt = 0; attempt < 31; attempt++)
        {
            var response = await factory.Server.SendAsync(context =>
            {
                // Inject a trusted transport address, never an untrusted forwarding header.
                context.Connection.RemoteIpAddress = IPAddress.Loopback;
                context.Request.Method = "POST";
                context.Request.Path = "/api/bugtrace/support-cases";
                context.Request.ContentType = "application/json";
                context.Request.ContentLength = 2;
                context.Request.Body = new MemoryStream("{}"u8.ToArray());
            });
            Assert.Equal(attempt == 30 ? 429 : 400, response.Response.StatusCode);
        }
    }

    /// <summary>The proxy accepts the provider's documented maximum human text rather than silently narrowing it.</summary>
    [Fact]
    public async Task PostAudit_ProviderTextLimitsRemainUsable()
    {
        var product = Guid.NewGuid();
        using var factory = CreateFactory(product);
        await SeedAsync(factory, product);
        using var request = CreateRequest();
        request.Content = JsonContent.Create(new { licenseKey = "SUP871-SYNTHETIC", hardwareId = "CURRENT-SYNTHETIC",
            projectId = "9f3c8fea-8740-42af-be83-6f527c6d102a", reporterEmail = "synthetic@example.invalid",
            supportCase = new { title = new string('x', 240), description = new string('y', 50000) } });
        using var response = await factory.CreateClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>A null provider list item must yield a safe protocol failure instead of an uncaught exception.</summary>
    [Fact]
    public async Task PostAudit_MalformedOwnerPageFailsSafely()
    {
        var product = Guid.NewGuid();
        var proxy = new FakeBugTraceProxyService { SupportPage = _ => System.Text.Json.JsonSerializer.SerializeToElement(new
        { total = 1, limit = 200, offset = 0, items = new object?[] { null } }) };
        using var factory = CreateFactory(product, proxy);
        await SeedAsync(factory, product);
        using var response = await factory.CreateClient().PostAsJsonAsync("/api/bugtrace/support-cases/SUP-000123/detail", new
        { licenseKey = "SUP871-SYNTHETIC", hardwareId = "CURRENT-SYNTHETIC", projectId = proxy.ExpectedProjectId });
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    /// <summary>Simultaneous distinct creates cannot overrun the atomic per-licence allowance.</summary>
    [Fact]
    public async Task Quota_ConcurrentAdmissionAllowsExactlyThreeDistinctCreates()
    {
        var quota = new BugTraceSupportQuota();
        var license = Guid.NewGuid();
        var admitted = 0;
        await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Task.Run(() =>
        {
            try { quota.Admit(license, "create", 3, $"synthetic-key-{i:0000}", "body"); Interlocked.Increment(ref admitted); }
            catch (BugTraceSupportException failure) { Assert.Equal(429, failure.Status); }
        })));
        Assert.Equal(3, admitted);
    }

    /// <summary>Idempotency keys are exact and cannot authorize a different body.</summary>
    [Fact]
    public void Quota_ChangedReplayConflicts()
    {
        var quota = new BugTraceSupportQuota();
        var license = Guid.NewGuid();
        quota.Admit(license, "create", 3, "Exact-Key-0000001", "original");
        var failure = Assert.Throws<BugTraceSupportException>(() => quota.Admit(license, "create", 3, "Exact-Key-0000001", "changed"));
        Assert.Equal(409, failure.Status);
        quota.Admit(license, "create", 3, "exact-key-0000001", "changed");
    }

    /// <summary>Absent or malformed product configuration disables SUP without borrowing client authority.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("malformed")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public async Task InvalidProductConfiguration_FailsClosed(string? value)
    {
        using var factory = CreateFactory(Guid.NewGuid()).WithWebHostBuilder(builder => builder.UseSetting("BUGTRACE_SUPPORT_PRODUCT_ID", value));
        using var request = CreateRequest();
        using var response = await factory.CreateClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    /// <summary>Rejected multipart and unmatched nested requests persist no human content or identity.</summary>
    [Theory]
    [InlineData("/api/bugtrace/support-cases/attachments")]
    [InlineData("/api/bugtrace/support-cases/unknown/deep/path/")]
    public async Task MultipartRefusal_IsCompletelyRedacted(string path)
    {
        using var factory = CreateFactory(Guid.NewGuid());
        using var form = CreateMultipart();
        using var response = await factory.CreateClient().PostAsync(path, form);
        Assert.False(response.IsSuccessStatusCode);
        var log = await ReadLogAsync(factory, path);
        Assert.Equal("[REDACTED]", log.RequestBody);
        Assert.True(string.IsNullOrEmpty(log.LicenseKey));
        Assert.True(string.IsNullOrEmpty(log.HardwareId));
    }

    /// <summary>Exercises all seven SUP routes with synthetic provider bytes and proves foreign-case refusal.</summary>
    [Fact]
    public async Task LocalLifecycle_CreateUploadListDetailMessageResolveDownloadAndRefusal()
    {
        var product = Guid.NewGuid();
        using var factory = CreateFactory(product);
        await SeedAsync(factory, product);
        using var client = factory.CreateClient();
        using var upload = new HttpRequestMessage(HttpMethod.Post, "/api/bugtrace/support-cases/attachments") { Content = CreateMultipart() };
        upload.Headers.Add("Idempotency-Key", "synthetic-upload-0001");
        using var staged = await client.SendAsync(upload);
        Assert.Equal(HttpStatusCode.Created, staged.StatusCode);
        using var create = CreateRequest();
        using var created = await client.SendAsync(create);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var identity = new { licenseKey = "SUP871-SYNTHETIC", hardwareId = "CURRENT-SYNTHETIC", projectId = "9f3c8fea-8740-42af-be83-6f527c6d102a", reporterEmail = "synthetic@example.invalid", content = "Synthetic reply" };
        foreach (var suffix in new[] { "list", "SUP-000123/detail", "SUP-000123/messages", "SUP-000123/resolve", "SUP-000123/attachments/07c8f639-14b5-4e61-bc3a-6c3bc3bed431/download" })
        {
            using var response = await client.PostAsJsonAsync("/api/bugtrace/support-cases/" + suffix, identity);
            Assert.True(response.IsSuccessStatusCode, $"{suffix}: {response.StatusCode}");
            if (suffix.EndsWith("download", StringComparison.Ordinal))
            {
                Assert.Equal("synthetic attachment", await response.Content.ReadAsStringAsync());
                Assert.True(response.Headers.CacheControl!.NoStore);
            }
        }
        using var foreign = await client.PostAsJsonAsync("/api/bugtrace/support-cases/SUP-999999/detail", identity);
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
    }

    /// <summary>Builds a small attachment with synthetic sensitive markers and no filesystem input.</summary>
    private static MultipartFormDataContent CreateMultipart()
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent("SUP871-SYNTHETIC"), "licenseKey");
        form.Add(new StringContent("CURRENT-SYNTHETIC"), "hardwareId");
        form.Add(new StringContent("9f3c8fea-8740-42af-be83-6f527c6d102a"), "projectId");
        form.Add(new StringContent("synthetic@example.invalid"), "reporterEmail");
        form.Add(new StringContent("Private synthetic attachment"), "file", "synthetic.txt");
        return form;
    }

    /// <summary>Owns one isolated in-memory application; provider calls use an explicit synthetic fake.</summary>
    private static WebApplicationFactory<Program> CreateFactory(Guid productId, FakeBugTraceProxyService? proxy = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "CHANGE_ME_RANDOM_SECRET");
            builder.UseSetting("BUGTRACE_SUPPORT_PRODUCT_ID", productId.ToString("D"));
            var name = Guid.NewGuid().ToString("N");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(name));
                services.RemoveAll<IBugTraceProxyService>();
                services.AddSingleton<IBugTraceProxyService>(proxy ?? new FakeBugTraceProxyService());
            });
        });

    /// <summary>Seeds no real credentials; product linkage is the only variable under test.</summary>
    private static async Task SeedAsync(WebApplicationFactory<Program> factory, Guid productId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        db.Licenses.Add(new License { LicenseKey = "SUP871-SYNTHETIC", ProductId = productId,
            CustomerEmail = "synthetic@example.invalid", IsActive = true, HardwareId = "OLD-SYNTHETIC" });
        await db.SaveChangesAsync();
    }

    /// <summary>Returns an owned JSON request with stable identity and provider idempotency key.</summary>
    private static HttpRequestMessage CreateRequest()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/bugtrace/support-cases")
        {
            Content = JsonContent.Create(new { licenseKey = "SUP871-SYNTHETIC", hardwareId = "CURRENT-SYNTHETIC",
                projectId = "9f3c8fea-8740-42af-be83-6f527c6d102a", reporterEmail = "synthetic@example.invalid",
                supportCase = new { title = "Synthetic", description = "Private synthetic message" } })
        };
        request.Headers.Add("Idempotency-Key", "support-871-synthetic-0001");
        return request;
    }

    /// <summary>Waits for asynchronous middleware persistence in this fixture only.</summary>
    private static async Task<AccessLog> ReadLogAsync(WebApplicationFactory<Program> factory, string path = "/api/bugtrace/support-cases")
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var log = await db.AccessLogs.FirstOrDefaultAsync(item => item.Path == path);
            if (log != null) return log;
            await Task.Delay(100);
        }
        throw new TimeoutException("Synthetic audit record missing.");
    }
}

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace SoftLicence.Tests.Server;

// ---------------------------------------------------------------------------
// Fake IBugTraceProxyService pour les tests d'integration
// ---------------------------------------------------------------------------
internal sealed class FakeBugTraceProxyService : IBugTraceProxyService
{
    public string ExpectedProjectId { get; set; } = "9f3c8fea-8740-42af-be83-6f527c6d102a";
    public bool IsConfigured { get; set; } = true;

    public List<object> SubmittedTickets { get; } = new();
    public List<(string TicketNumber, object Body)> AddedComments { get; } = new();
    public List<string> QueriedEmails { get; } = new();

    public Task<JsonElement> SubmitTicketAsync(object ticketBody, CancellationToken ct = default)
    {
        SubmittedTickets.Add(ticketBody);
        var json = JsonSerializer.Serialize(new { ticketNumber = "BT-00042", id = "fake-id-001" });
        return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
    }

    public Task<JsonElement> AddCommentAsync(string ticketNumber, object commentBody, CancellationToken ct = default)
    {
        AddedComments.Add((ticketNumber, commentBody));
        var json = JsonSerializer.Serialize(new { id = "comment-id-001", ticketNumber });
        return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
    }

    public Task<JsonElement> GetTicketsByEmailAsync(string email, CancellationToken ct = default)
    {
        QueriedEmails.Add(email);
        var json = JsonSerializer.Serialize(new[] { new { ticketNumber = "BT-00042", title = "Test" } });
        return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
    }

    public List<string> QueriedCommentTickets { get; } = new();

    public Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default)
    {
        QueriedCommentTickets.Add(ticketNumber);
        var json = JsonSerializer.Serialize(new[] { new { id = "cmt-001", content = "Réponse du support", authorName = "Support" } });
        return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
    }
}

// ---------------------------------------------------------------------------
// Fixture d'integration BugTrace
// ---------------------------------------------------------------------------
public class BugTraceProxyTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string ValidProjectId = "9f3c8fea-8740-42af-be83-6f527c6d102a";
    private const string WrongProjectId = "00000000-0000-0000-0000-000000000000";
    private const string FakeLicenseKey = "BTTEST-LICENSE-KEY-001";
    private const string FakeHwid = "HWID-BT-TEST-001";
    private const string FakeEmail = "bt.user@example.com";

    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();
    private readonly FakeBugTraceProxyService _fakeBugTrace = new();

    public BugTraceProxyTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "CHANGE_ME_RANDOM_SECRET");
            builder.UseSetting("AdminSettings:AllowedIps", "");
            builder.ConfigureServices(services =>
            {
                // Base de donnees en memoire
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase(_dbName));

                // Injecter le faux service BugTrace pour isoler les tests du reseau
                services.RemoveAll<IBugTraceProxyService>();
                services.AddSingleton<IBugTraceProxyService>(_fakeBugTrace);
            });
        });
    }

    private HttpClient CreateClient() => _factory.CreateClient();

    private async Task SeedLicenseAsync(string licenseKey, string? hwid = null, string? email = null, bool isActive = true)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var encryption = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

        var product = await db.Products.FirstOrDefaultAsync(p => p.Name == "BtTestProduct");
        if (product == null)
        {
            var keys = LicenseService.GenerateKeys();
            product = new Product
            {
                Id = Guid.NewGuid(),
                Name = "BtTestProduct",
                PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
                PublicKeyXml = keys.PublicKey,
                ApiSecret = "CHANGE_ME_RANDOM_SECRET"
            };
            db.Products.Add(product);
        }

        var licenseType = await db.LicenseTypes.FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug == "STANDARD");
        if (licenseType == null)
        {
            licenseType = new LicenseType
            {
                Id = Guid.NewGuid(),
                Name = "Standard",
                Slug = "STANDARD",
                ProductId = product.Id
            };
            db.LicenseTypes.Add(licenseType);
        }

        var normalizedLicenseKey = licenseKey.ToUpperInvariant();
        var existingLicense = await db.Licenses.FirstOrDefaultAsync(l => l.LicenseKey == normalizedLicenseKey);
        if (existingLicense != null)
        {
            existingLicense.HardwareId = hwid;
            existingLicense.CustomerEmail = email ?? FakeEmail;
            existingLicense.IsActive = isActive;
            await db.SaveChangesAsync();
            return;
        }

        db.Licenses.Add(new License
        {
            LicenseKey = normalizedLicenseKey,
            ProductId = product.Id,
            LicenseTypeId = licenseType.Id,
            HardwareId = hwid,
            CustomerName = "BT Test User",
            CustomerEmail = email ?? FakeEmail,
            IsActive = isActive,
            MaxSeats = 1
        });

        await db.SaveChangesAsync();
    }

    // -------------------------------------------------------------------------
    // 1. Token BugTrace jamais expose dans les reponses
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Submit_ResponseBody_NeverContainsBugTraceToken()
    {
        var client = CreateClient();
        var payload = new
        {
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticket = new { title = "Test", description = "Desc", type = "BUG", priority = "NORMAL" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        var body = await response.Content.ReadAsStringAsync();

        // Le token ne doit jamais apparaitre dans une reponse HTTP, quelle que soit sa valeur
        Assert.DoesNotContain("BT-TKN-", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("X-Project-Token", body, StringComparison.OrdinalIgnoreCase);
        // La reponse doit contenir le numero de ticket retourne par BugTrace
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("BT-00042", body);
    }

    // -------------------------------------------------------------------------
    // 2. projectId invalide -> 400
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Submit_WithInvalidProjectId_ShouldReturn400()
    {
        var client = CreateClient();
        var payload = new
        {
            hardwareId = FakeHwid,
            projectId = WrongProjectId,
            ticket = new { title = "Test", description = "Desc" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("projectId", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Comment_WithInvalidProjectId_ShouldReturn400()
    {
        var client = CreateClient();
        var payload = new
        {
            hardwareId = FakeHwid,
            projectId = WrongProjectId,
            ticketNumber = "BT-00042",
            content = "Hello"
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/comment", payload);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task GetTickets_WithInvalidProjectId_ShouldReturn400()
    {
        var client = CreateClient();
        var response = await client.GetAsync(
            $"/api/bugtrace/tickets?email={FakeEmail}&projectId={WrongProjectId}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // -------------------------------------------------------------------------
    // 3. Submit relaie correctement vers BugTrace
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Submit_WithValidHardwareId_ShouldRelayTicketToBugTrace()
    {
        _fakeBugTrace.SubmittedTickets.Clear();
        var client = CreateClient();
        var payload = new
        {
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticket = new
            {
                title = "Crash au demarrage",
                description = "L'application plante au lancement.",
                version = "2.1.900",
                type = "BUG",
                priority = "HIGH",
                reporterEmail = FakeEmail,
                tags = new[] { "t-ia-connect" }
            }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(result.TryGetProperty("ticketNumber", out var tn));
        Assert.Equal("BT-00042", tn.GetString());

        // Le ticket a bien ete transmis au service proxy
        Assert.Single(_fakeBugTrace.SubmittedTickets);
    }

    [Fact]
    public async Task Submit_WithValidLicenseKey_ShouldRelayTicketToBugTrace()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.SubmittedTickets.Clear();

        var client = CreateClient();
        var payload = new
        {
            licenseKey = FakeLicenseKey,
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticket = new { title = "Bug", description = "Details", type = "BUG", priority = "NORMAL" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.SubmittedTickets);
    }

    // -------------------------------------------------------------------------
    // 4. Comment relaie correctement vers BugTrace
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Comment_WithValidLicenseKey_ShouldRelayCommentToBugTrace()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.AddedComments.Clear();
        _fakeBugTrace.QueriedEmails.Clear();
        var client = CreateClient();
        var payload = new
        {
            licenseKey = FakeLicenseKey,
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticketNumber = "BT-00042",
            content = "Voici les logs supplementaires.",
            authorName = "Test User",
            authorEmail = FakeEmail
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/comment", payload);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.Single(_fakeBugTrace.QueriedEmails);
        Assert.Equal(FakeEmail, _fakeBugTrace.QueriedEmails[0]);
        Assert.Single(_fakeBugTrace.AddedComments);
        Assert.Equal("BT-00042", _fakeBugTrace.AddedComments[0].TicketNumber);
    }

    [Fact]
    public async Task Comment_WithoutLicenseKey_ShouldReturn400()
    {
        var client = CreateClient();
        var payload = new
        {
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticketNumber = "BT-00042",
            content = "Voici les logs supplementaires."
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/comment", payload);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Comment_WhenTicketDoesNotBelongToLicense_ShouldReturn403()
    {
        await SeedLicenseAsync(FakeLicenseKey + "3", hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.AddedComments.Clear();
        var client = CreateClient();
        var payload = new
        {
            licenseKey = FakeLicenseKey + "3",
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticketNumber = "BT-99999",
            content = "Tentative commentaire autre ticket."
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/comment", payload);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(_fakeBugTrace.AddedComments);
    }

    // -------------------------------------------------------------------------
    // 5. Lecture tickets relaie correctement vers BugTrace
    // -------------------------------------------------------------------------
    [Fact]
    public async Task GetTickets_WithValidEmail_ShouldRelayToBugTrace()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.QueriedEmails.Clear();
        var client = CreateClient();

        var response = await client.GetAsync(
            $"/api/bugtrace/tickets?email={FakeEmail}&licenseKey={FakeLicenseKey}&hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.QueriedEmails);
        Assert.Equal(FakeEmail, _fakeBugTrace.QueriedEmails[0]);
    }

    [Fact]
    public async Task PostTickets_WithValidEmail_ShouldRelayToBugTrace()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.QueriedEmails.Clear();
        var client = CreateClient();

        var payload = new
        {
            email = FakeEmail,
            licenseKey = FakeLicenseKey,
            hardwareId = FakeHwid,
            projectId = ValidProjectId
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/tickets", payload);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.QueriedEmails);
        Assert.Equal(FakeEmail, _fakeBugTrace.QueriedEmails[0]);
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("BT-00042", result[0].GetProperty("ticketNumber").GetString());
    }

    [Fact]
    public async Task BugTraceProxy_WithValidLicense_ShouldSupportFullTicketLifecycle()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.SubmittedTickets.Clear();
        _fakeBugTrace.QueriedEmails.Clear();
        _fakeBugTrace.QueriedCommentTickets.Clear();
        _fakeBugTrace.AddedComments.Clear();
        var client = CreateClient();

        var submitResponse = await client.PostAsJsonAsync("/api/bugtrace/submit", new
        {
            licenseKey = FakeLicenseKey,
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticket = new { title = "Lifecycle bug", description = "End-to-end proxy check.", type = "BUG", priority = "NORMAL" }
        });
        var submitBody = await submitResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, submitResponse.StatusCode);
        Assert.Contains("BT-00042", submitBody);
        Assert.DoesNotContain("BT-TKN-", submitBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("X-Project-Token", submitBody, StringComparison.OrdinalIgnoreCase);
        Assert.Single(_fakeBugTrace.SubmittedTickets);

        var postTicketsResponse = await client.PostAsJsonAsync("/api/bugtrace/tickets", new
        {
            email = FakeEmail,
            licenseKey = FakeLicenseKey,
            hardwareId = FakeHwid,
            projectId = ValidProjectId
        });
        var postTicketsBody = await postTicketsResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, postTicketsResponse.StatusCode);
        Assert.Contains("BT-00042", postTicketsBody);
        Assert.DoesNotContain("BT-TKN-", postTicketsBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("X-Project-Token", postTicketsBody, StringComparison.OrdinalIgnoreCase);

        var getTicketsResponse = await client.GetAsync(
            $"/api/bugtrace/tickets?email={FakeEmail}&licenseKey={FakeLicenseKey}&hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.OK, getTicketsResponse.StatusCode);

        var commentsResponse = await client.GetAsync(
            $"/api/bugtrace/tickets/BT-00042/comments?licenseKey={FakeLicenseKey}&hardwareId={FakeHwid}&projectId={ValidProjectId}");
        var commentsBody = await commentsResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, commentsResponse.StatusCode);
        Assert.Contains("Réponse du support", commentsBody);
        Assert.DoesNotContain("BT-TKN-", commentsBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("X-Project-Token", commentsBody, StringComparison.OrdinalIgnoreCase);

        var commentResponse = await client.PostAsJsonAsync("/api/bugtrace/comment", new
        {
            licenseKey = FakeLicenseKey,
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticketNumber = "BT-00042",
            content = "Client-side comment through proxy.",
            authorName = "BT Test User",
            authorEmail = FakeEmail
        });
        var commentBody = await commentResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, commentResponse.StatusCode);
        Assert.Contains("comment-id-001", commentBody);
        Assert.DoesNotContain("BT-TKN-", commentBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("X-Project-Token", commentBody, StringComparison.OrdinalIgnoreCase);
        Assert.Single(_fakeBugTrace.AddedComments);
        Assert.Equal("BT-00042", _fakeBugTrace.AddedComments[0].TicketNumber);
        Assert.Contains(_fakeBugTrace.QueriedEmails, email => email == FakeEmail);
        Assert.Contains(_fakeBugTrace.QueriedCommentTickets, ticket => ticket == "BT-00042");
    }

    [Fact]
    public async Task PostTickets_WithInvalidProjectId_ShouldReturn400Not405()
    {
        var client = CreateClient();
        var payload = new
        {
            email = FakeEmail,
            licenseKey = FakeLicenseKey,
            hardwareId = FakeHwid,
            projectId = WrongProjectId
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/tickets", payload);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("projectId", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PostTickets_WithoutLicenseKey_ShouldReturn400Not405()
    {
        var client = CreateClient();
        var payload = new
        {
            email = FakeEmail,
            hardwareId = FakeHwid,
            projectId = ValidProjectId
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/tickets", payload);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("licenseKey", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetTickets_WithEncryptedLicenseKeyAndMatchingEmailHardware_ShouldRelayToBugTrace()
    {
        await SeedLicenseAsync(FakeLicenseKey + "-ENC", hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.QueriedEmails.Clear();
        var client = CreateClient();

        var response = await client.GetAsync(
            $"/api/bugtrace/tickets?email={FakeEmail}&licenseKey=ENC%3Atest-ciphertext&hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.QueriedEmails);
        Assert.Equal(FakeEmail, _fakeBugTrace.QueriedEmails[0]);
    }

    [Fact]
    public async Task GetTickets_WithoutLicenseKey_ShouldReturn400()
    {
        var client = CreateClient();

        var response = await client.GetAsync(
            $"/api/bugtrace/tickets?email={FakeEmail}&hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task GetTickets_WithLicenseKey_EmailMismatch_ShouldReturn403()
    {
        await SeedLicenseAsync(FakeLicenseKey + "2", hwid: FakeHwid, email: FakeEmail);

        var client = CreateClient();
        var response = await client.GetAsync(
            $"/api/bugtrace/tickets?email=autre@example.com&licenseKey={FakeLicenseKey}2&hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("email", body, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // 6. Rate limit basique (controle interne par cle/hwid)
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Submit_WhenInternalRateLimitExceeded_ShouldReturn429()
    {
        // Utiliser un hwid unique pour isoler ce test du rate limiter memoire partage
        var uniqueHwid = $"HWID-RATELIMIT-{Guid.NewGuid()}";
        var client = CreateClient();

        var payload = new
        {
            hardwareId = uniqueHwid,
            projectId = ValidProjectId,
            ticket = new { title = "T", description = "D", type = "BUG", priority = "NORMAL" }
        };

        // Les 3 premieres soumissions doivent passer (limit = 3 par 10 min)
        for (int i = 0; i < 3; i++)
        {
            var r = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
            Assert.NotEqual(HttpStatusCode.TooManyRequests, r.StatusCode);
        }

        // La 4e doit etre bloquee
        var blocked = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.Equal("60", blocked.Headers.RetryAfter?.Delta?.TotalSeconds.ToString("0"));

        var body = await blocked.Content.ReadAsStringAsync();
        Assert.Contains("rate_limited", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("retryAfterSeconds", body, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // 7. Mode degrade : absence de licenseKey acceptee avec hardwareId present
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Submit_WithoutLicenseKey_AndHardwareId_ShouldBeAccepted()
    {
        var client = CreateClient();
        var payload = new
        {
            // licenseKey absent intentionnellement
            hardwareId = "CANARY-HWID-001",
            projectId = ValidProjectId,
            ticket = new { title = "Security alert", description = "Reverse engineering detected.", type = "BUG", priority = "CRITICAL" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Submit_WithoutLicenseKey_AndWithoutHardwareId_ShouldReturn400()
    {
        var client = CreateClient();
        var payload = new
        {
            // Ni licenseKey ni hardwareId -> mode degrade invalide
            projectId = ValidProjectId,
            ticket = new { title = "T", description = "D" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("hardwareId", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Submit_WithoutLicenseKey_AndHardwareIdUnknown_ShouldBeAccepted()
    {
        var client = CreateClient();
        var payload = new
        {
            hardwareId = "unknown",
            projectId = ValidProjectId,
            ticket = new { title = "T", description = "D", type = "BUG", priority = "NORMAL" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -------------------------------------------------------------------------
    // 8. BugTrace non configure -> 503
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Submit_WhenBugTraceNotConfigured_ShouldReturn503()
    {
        var unconfiguredFake = new FakeBugTraceProxyService { IsConfigured = false };
        var localFactory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase(Guid.NewGuid().ToString()));
                services.RemoveAll<IBugTraceProxyService>();
                services.AddSingleton<IBugTraceProxyService>(unconfiguredFake);
            });
        });

        var client = localFactory.CreateClient();
        var payload = new
        {
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticket = new { title = "T", description = "D" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    // -------------------------------------------------------------------------
    // 9. Commentaires d'un ticket (lazy loading)
    // -------------------------------------------------------------------------
    [Fact]
    public async Task GetTicketComments_WithValidLicenseKey_ShouldRelayToBugTrace()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.QueriedEmails.Clear();
        _fakeBugTrace.QueriedCommentTickets.Clear();
        var client = CreateClient();

        var response = await client.GetAsync(
            $"/api/bugtrace/tickets/BT-00042/comments?licenseKey={FakeLicenseKey}&hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.QueriedEmails);
        Assert.Equal(FakeEmail, _fakeBugTrace.QueriedEmails[0]);
        Assert.Single(_fakeBugTrace.QueriedCommentTickets);
        Assert.Equal("BT-00042", _fakeBugTrace.QueriedCommentTickets[0]);
    }

    [Fact]
    public async Task GetTicketComments_WithoutLicenseKey_ShouldReturn400()
    {
        var client = CreateClient();

        var response = await client.GetAsync(
            $"/api/bugtrace/tickets/BT-00042/comments?hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task GetTicketComments_WhenTicketDoesNotBelongToLicense_ShouldReturn403()
    {
        await SeedLicenseAsync(FakeLicenseKey + "4", hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.QueriedCommentTickets.Clear();
        var client = CreateClient();

        var response = await client.GetAsync(
            $"/api/bugtrace/tickets/BT-99999/comments?licenseKey={FakeLicenseKey}4&hardwareId={FakeHwid}&projectId={ValidProjectId}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(_fakeBugTrace.QueriedCommentTickets);
    }

    [Fact]
    public async Task GetTicketComments_WithInvalidProjectId_ShouldReturn400()
    {
        var client = CreateClient();
        var response = await client.GetAsync(
            $"/api/bugtrace/tickets/BT-00042/comments?hardwareId={FakeHwid}&projectId={WrongProjectId}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // -------------------------------------------------------------------------
    // 10. Licence revoquee -> 400
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Submit_WithRevokedLicense_ShouldReturn400()
    {
        var revokedKey = "REVOKED-LICENSE-KEY-001";
        await SeedLicenseAsync(revokedKey, hwid: FakeHwid, email: FakeEmail, isActive: false);

        var client = CreateClient();
        var payload = new
        {
            licenseKey = revokedKey,
            hardwareId = FakeHwid,
            projectId = ValidProjectId,
            ticket = new { title = "T", description = "D", type = "BUG", priority = "NORMAL" }
        };

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", payload);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("revoked", body, StringComparison.OrdinalIgnoreCase);
    }
}

// ---------------------------------------------------------------------------
// Tests unitaires : BugTraceProxyService - token jamais transmis en clair
// ---------------------------------------------------------------------------
public class BugTraceProxyServiceUnitTests
{
    private const string FakeToken = "BT-TKN-SUPER-SECRET-TOKEN";
    private const string FakeBaseUrl = "https://bugtrace.example.com";
    private const string FakeProjectId = "9f3c8fea-8740-42af-be83-6f527c6d102a";

    private (BugTraceProxyService service, List<HttpRequestMessage> capturedRequests, ListLogger<BugTraceProxyService> logger) BuildService(
        HttpResponseMessage response,
        ListLogger<BugTraceProxyService>? logger = null)
    {
        var capturedRequests = new List<HttpRequestMessage>();
        var handler = new MockBugTraceHandler(response, capturedRequests);

        var httpClient = new HttpClient(handler);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient("BugTrace")).Returns(httpClient);

        var configMock = new Mock<IConfiguration>();
        configMock.Setup(c => c["BUGTRACE_BASE_URL"]).Returns(FakeBaseUrl);
        configMock.Setup(c => c["BUGTRACE_PROJECT_TOKEN"]).Returns(FakeToken);
        configMock.Setup(c => c["BUGTRACE_PROJECT_ID"]).Returns(FakeProjectId);

        logger ??= new ListLogger<BugTraceProxyService>();
        var service = new BugTraceProxyService(factoryMock.Object, logger, configMock.Object);
        return (service, capturedRequests, logger);
    }

    [Fact]
    public async Task SubmitTicket_OutboundRequest_ContainsProjectTokenHeader()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { ticketNumber = "BT-00001", id = "abc" })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.SubmitTicketAsync(new { title = "T", description = "D" });

        Assert.Single(requests);
        Assert.True(requests[0].Headers.Contains("X-Project-Token"),
            "L'header X-Project-Token doit etre present dans la requete sortante vers BugTrace");
        Assert.Contains(FakeToken, requests[0].Headers.GetValues("X-Project-Token"));
    }

    [Fact]
    public async Task SubmitTicket_ReturnedJsonElement_DoesNotContainToken()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { ticketNumber = "BT-00001", id = "abc" })
        };
        var (service, _, _) = BuildService(fakeResponse);

        var result = await service.SubmitTicketAsync(new { title = "T", description = "D" });
        var json = result.GetRawText();

        Assert.DoesNotContain(FakeToken, json, StringComparison.Ordinal);
        Assert.DoesNotContain("X-Project-Token", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AddComment_OutboundRequest_ContainsProjectTokenHeader()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { id = "cmt-001" })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.AddCommentAsync("BT-00001", new { content = "hello" });

        Assert.Single(requests);
        Assert.True(requests[0].Headers.Contains("X-Project-Token"));
    }

    [Fact]
    public async Task GetTicketsByEmail_OutboundRequest_ContainsProjectTokenHeader()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new[] { new { ticketNumber = "BT-00001" } })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.GetTicketsByEmailAsync("user@example.com");

        Assert.Single(requests);
        Assert.True(requests[0].Headers.Contains("X-Project-Token"));
    }

    [Fact]
    public async Task GetTicketComments_OutboundRequest_ContainsProjectTokenHeader()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new[] { new { id = "cmt-001", content = "reply" } })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.GetTicketCommentsAsync("BT-00042");

        Assert.Single(requests);
        Assert.True(requests[0].Headers.Contains("X-Project-Token"));
        Assert.Contains($"{FakeBaseUrl}/api/external/tickets/BT-00042/comments",
            requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitTicket_WhenUpstreamReturns400_LogsSanitizedBodyAndThrows()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"message":"Missing required fields: version, title, description, reporterEmail","reporterEmail":"john.doe@example.com"}""")
        };
        var logger = new ListLogger<BugTraceProxyService>();
        var (service, _, _) = BuildService(fakeResponse, logger);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            service.SubmitTicketAsync(new { title = "T" }));

        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("submit_ticket", warning.Message);
        Assert.Contains("Missing required fields", warning.Message);
        Assert.Contains("jo***@example.com", warning.Message);
        Assert.DoesNotContain("john.doe@example.com", warning.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AddComment_WhenUpstreamBodyContainsSecrets_LogsRedactedBody()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("""
            {
              "message":"Forbidden",
              "x-project-token":"BT-TKN-VISIBLE",
              "authorization":"Bearer SHOULD-NOT-LOG",
              "licenseKey":"AAAA-BBBB-CCCC-DDDD",
              "apiKey":"API-SECRET",
              "password":"p@ssw0rd",
              "secret":"hidden",
              "accessToken":"access-value",
              "refreshToken":"refresh-value"
            }
            """)
        };
        var logger = new ListLogger<BugTraceProxyService>();
        var (service, _, _) = BuildService(fakeResponse, logger);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            service.AddCommentAsync("BT-00001", new { content = "hello" }));

        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("add_comment", warning.Message);
        Assert.Contains("<redacted>", warning.Message);
        Assert.DoesNotContain("BT-TKN-VISIBLE", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("SHOULD-NOT-LOG", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("AAAA-BBBB-CCCC-DDDD", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("API-SECRET", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("p@ssw0rd", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hidden", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("access-value", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("refresh-value", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetTicketComments_WhenUpstreamBodyIsLong_TruncatesLoggedBody()
    {
        var longBody = new string('A', 2500);
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(longBody)
        };
        var logger = new ListLogger<BugTraceProxyService>();
        var (service, _, _) = BuildService(fakeResponse, logger);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            service.GetTicketCommentsAsync("BT-00001"));

        var error = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.Contains("get_ticket_comments", error.Message);
        Assert.Contains("<truncated>", error.Message);
        Assert.True(error.Message.Length < 2300);
    }

    [Fact]
    public void IsConfigured_WhenAllEnvVarsMissing_ReturnsFalse()
    {
        var factoryMock = new Mock<IHttpClientFactory>();
        var configMock = new Mock<IConfiguration>();
        configMock.Setup(c => c["BUGTRACE_BASE_URL"]).Returns((string?)null);
        configMock.Setup(c => c["BUGTRACE_PROJECT_TOKEN"]).Returns((string?)null);
        configMock.Setup(c => c["BUGTRACE_PROJECT_ID"]).Returns((string?)null);

        var service = new BugTraceProxyService(factoryMock.Object, Mock.Of<ILogger<BugTraceProxyService>>(), configMock.Object);
        Assert.False(service.IsConfigured);
    }
}

// ---------------------------------------------------------------------------
// Handler HTTP de capture pour les tests unitaires
// ---------------------------------------------------------------------------
internal sealed class MockBugTraceHandler : HttpMessageHandler
{
    private readonly HttpResponseMessage _response;
    private readonly List<HttpRequestMessage> _captured;

    public MockBugTraceHandler(HttpResponseMessage response, List<HttpRequestMessage> captured)
    {
        _response = response;
        _captured = captured;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _captured.Add(request);
        return Task.FromResult(_response);
    }
}

internal sealed class ListLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add((logLevel, formatter(state, exception), exception));
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose()
        {
        }
    }
}

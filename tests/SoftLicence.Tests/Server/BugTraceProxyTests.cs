using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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
/// <summary>Records synthetic provider calls without network access; durable replay and scanning are not simulated.</summary>
internal sealed class FakeBugTraceProxyService : IBugTraceProxyService
{
    /// <summary>Supplies the synthetic configured project boundary; individual tests may replace it to prove rejection.</summary>
    public string ExpectedProjectId { get; set; } = "9f3c8fea-8740-42af-be83-6f527c6d102a";
    /// <summary>Allows one fixture to simulate missing provider configuration without reading real settings.</summary>
    public bool IsConfigured { get; set; } = true;

    /// <summary>Records server-projected synthetic Ticket submissions in fixture memory; no durable or network side effect is simulated.</summary>
    public List<object> SubmittedTickets { get; } = new();
    /// <summary>Records exact synthetic legacy comment projections in fixture-owned memory for routing assertions; no provider mutation occurs.</summary>
    public List<(string TicketNumber, object Body)> AddedComments { get; } = new();
    /// <summary>Records synthetic legacy email lookups in call order; owned by one test fixture and never sent over a network.</summary>
    public List<string> QueriedEmails { get; } = new();
    /// <summary>Records accepted create projections so tests can assert server-owned identity and source.</summary>
    public List<object> CreatedSupportCases { get; } = new();
    /// <summary>Supplies synthetic pages by zero-based offset divided by200, preserving ownership lookup order.</summary>
    public Func<int, System.Text.Json.JsonElement>? SupportPage { get; set; }
    /// <summary>Records owner filters in lookup order; each fixture owns this mutable collection.</summary>
    public List<string> QueriedSupportEmails { get; } = new();

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

    /// <summary>Records the requested legacy reference and returns fixed public comments without provider authorization, cancellation or persistence simulation.</summary>
    public Task<JsonElement> GetTicketCommentsAsync(string ticketNumber, CancellationToken ct = default)
    {
        QueriedCommentTickets.Add(ticketNumber);
        var json = JsonSerializer.Serialize(new[] { new { id = "cmt-001", content = "Réponse du support", authorName = "Support" } });
        return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
    }

    /// <summary>Records one synthetic create and returns a fixed receipt; provider durable replay is not simulated.</summary>
    public Task<JsonElement> CreateSupportCaseAsync(object body, string idempotencyKey, CancellationToken ct = default)
    {
        CreatedSupportCases.Add(body);
        return Json(new { id = "support-id", supportNumber = "SUP-000123", replayed = false });
    }

    /// <summary>Records the authoritative email and returns a synthetic page selected by offset divided by200.</summary>
    public Task<JsonElement> ListSupportCasesAsync(string reporterEmail, int limit, CancellationToken ct = default, int offset = 0)
    {
        QueriedSupportEmails.Add(reporterEmail);
        if (SupportPage != null) return Task.FromResult(SupportPage(offset / 200));
        return Json(new { total = 1, limit, offset, items = new[] { new { supportNumber = "SUP-000123", reporterEmail } } });
    }

    /// <summary>Returns a public synthetic conversation after the controller has checked ownership.</summary>
    public Task<JsonElement> GetSupportCaseAsync(string supportNumber, CancellationToken ct = default) =>
        Json(new { supportNumber, title = "Support", description = "Details", status = "OPEN", messages = Array.Empty<object>() });

    /// <summary>Returns a synthetic customer-message receipt without external persistence.</summary>
    public Task<JsonElement> AddSupportCaseMessageAsync(string supportNumber, object body, CancellationToken ct = default) =>
        Json(new { id = "message-id", supportNumber });

    /// <summary>Returns the fixed resolved projection for an already-authorized synthetic case.</summary>
    public Task<JsonElement> ResolveSupportCaseAsync(string supportNumber, CancellationToken ct = default) =>
        Json(new { supportNumber, status = "RESOLVED" });

    /// <summary>Returns a fixed staged UUID without emulating scanning or durable provider binding.</summary>
    public Task<JsonElement> StageSupportAttachmentAsync(IFormFile file, string reporterEmail, string idempotencyKey, CancellationToken ct = default) =>
        Json(new { id = "07c8f639-14b5-4e61-bc3a-6c3bc3bed431", reporterEmail });

    /// <summary>Returns fixed synthetic file bytes and a safe basename after controller ownership checks.</summary>
    public Task<(byte[] Content, string ContentType, string FileName)> DownloadSupportAttachmentAsync(string supportNumber, string attachmentId, CancellationToken ct = default) =>
        Task.FromResult((System.Text.Encoding.UTF8.GetBytes("synthetic attachment"), "application/octet-stream", "synthetic.txt"));

    /// <summary>Returns a detached synthetic JSON projection for the fake provider response.</summary>
    private static Task<JsonElement> Json(object value) =>
        Task.FromResult(JsonDocument.Parse(JsonSerializer.Serialize(value)).RootElement.Clone());
}

// ---------------------------------------------------------------------------
// Fixture d'integration BugTrace
// ---------------------------------------------------------------------------
/// <summary>Checks legacy and SUP routes against isolated in-memory authority and a non-network provider fake.</summary>
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
    /// <summary>Provides explicit alias outcomes while preserving the controller's relational recheck.</summary>
    private readonly Mock<IHardwareAuthorityAliasResolver> _hardwareAuthorityAliases = new();

    /// <summary>Owns a synthetic product mapping and independent database while preserving explicit alias authority behavior.</summary>
    public BugTraceProxyTests(WebApplicationFactory<Program> factory)
    {
        _hardwareAuthorityAliases
            .Setup(resolver => resolver.ResolveAsync(
                It.IsAny<LicenseDbContext>(),
                It.IsAny<Guid>(),
                It.IsAny<Guid>(),
                It.IsAny<string>(),
                It.IsAny<HardwareAuthorityResolutionIntent>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((LicenseDbContext _, Guid _, Guid _, string hardwareId,
                HardwareAuthorityResolutionIntent _, CancellationToken _) =>
                new HardwareAuthorityResolution(
                    hardwareId,
                    hardwareId,
                    null,
                    HardwareAuthorityResolutionStatus.NoAlias));

        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("BUGTRACE_SUPPORT_PRODUCT_ID", "b0251940-0332-4e3c-81b3-b894b75b04ea");
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
                services.RemoveAll<IHardwareAuthorityAliasResolver>();
                services.AddSingleton(_hardwareAuthorityAliases.Object);
            });
        });
    }

    /// <summary>Creates a client confined to this fixture application without external provider traffic.</summary>
    private HttpClient CreateClient() => _factory.CreateClient();

    /// <summary>Creates one isolated licence authority and returns its stable relational boundary.</summary>
    /// <param name="licenseKey">Synthetic canonical licence key.</param>
    /// <param name="hwid">Optional exact direct hardware authority.</param>
    /// <param name="email">Optional customer identity, defaulting to the fixture identity.</param>
    /// <param name="isActive">Whether the licence may authorize requests.</param>
    /// <returns>The persisted licence and product identifiers.</returns>
    private async Task<(Guid LicenseId, Guid ProductId)> SeedLicenseAsync(
        string licenseKey,
        string? hwid = null,
        string? email = null,
        bool isActive = true)
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
                Id = Guid.Parse("b0251940-0332-4e3c-81b3-b894b75b04ea"),
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
            return (existingLicense.Id, existingLicense.ProductId);
        }

        var license = new License
        {
            LicenseKey = normalizedLicenseKey,
            ProductId = product.Id,
            LicenseTypeId = licenseType.Id,
            HardwareId = hwid,
            CustomerName = "BT Test User",
            CustomerEmail = email ?? FakeEmail,
            IsActive = isActive,
            MaxSeats = 1
        };
        db.Licenses.Add(license);

        await db.SaveChangesAsync();
        return (license.Id, license.ProductId);
    }

    /// <summary>Creates a seat owned by the selected licence for authority-boundary tests.</summary>
    /// <param name="licenseId">Owning licence boundary.</param>
    /// <param name="hardwareId">Exact synthetic seat identifier.</param>
    /// <param name="isActive">Whether the seat can authorize a manual report.</param>
    /// <returns>The persisted seat identifier.</returns>
    private async Task<Guid> SeedSeatAsync(Guid licenseId, string hardwareId, bool isActive = true)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var seat = new LicenseSeat
        {
            LicenseId = licenseId,
            HardwareId = hardwareId,
            IsActive = isActive,
            UnlinkedAt = isActive ? null : DateTime.UtcNow
        };
        db.LicenseSeats.Add(seat);
        await db.SaveChangesAsync();
        return seat.Id;
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

    /// <summary>Proves that an active same-licence seat authorizes relay without alias fallback.</summary>
    [Fact]
    public async Task Submit_WithActiveSameLicenseSeat_ShouldRelayTicketToBugTrace()
    {
        const string submittedHardwareId = "1111222233334444";
        var authority = await SeedLicenseAsync(FakeLicenseKey + "-SEAT", hwid: "AAAABBBBCCCCDDDD");
        await SeedSeatAsync(authority.LicenseId, submittedHardwareId);
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-SEAT", submittedHardwareId);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.SubmittedTickets);
        _hardwareAuthorityAliases.Verify(resolver => resolver.ResolveAsync(
            It.IsAny<LicenseDbContext>(),
            It.IsAny<Guid>(),
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<HardwareAuthorityResolutionIntent>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    /// <summary>Proves that an authenticated alias must resolve to an active same-licence seat.</summary>
    [Fact]
    public async Task Submit_WithAuthorizedAliasForActiveSameLicenseSeat_ShouldRelayTicketToBugTrace()
    {
        const string submittedHardwareId = "1234567890ABCDEF";
        const string effectiveHardwareId = "ABCDEF0123456789";
        var authority = await SeedLicenseAsync(FakeLicenseKey + "-ALIAS", hwid: "2222333344445555");
        var seatId = await SeedSeatAsync(authority.LicenseId, effectiveHardwareId);
        ConfigureAliasResolution(authority, submittedHardwareId, effectiveHardwareId, seatId);
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-ALIAS", submittedHardwareId);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Proves that an adversarial cross-licence resolver result cannot authorize relay.</summary>
    [Fact]
    public async Task Submit_WhenAliasResolvesToForeignLicenseSeat_ShouldReturn400()
    {
        const string submittedHardwareId = "234567890ABCDEF1";
        const string effectiveHardwareId = "BCDEF0123456789A";
        var requested = await SeedLicenseAsync(FakeLicenseKey + "-REQUESTED", hwid: "3333444455556666");
        var foreign = await SeedLicenseAsync(FakeLicenseKey + "-FOREIGN", hwid: "4444555566667777");
        var foreignSeatId = await SeedSeatAsync(foreign.LicenseId, effectiveHardwareId);
        ConfigureAliasResolution(requested, submittedHardwareId, effectiveHardwareId, foreignSeatId);
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-REQUESTED", submittedHardwareId);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Proves that an unknown alias remains a generic fail-closed mismatch.</summary>
    [Fact]
    public async Task Submit_WhenAliasIsUnknown_ShouldReturn400()
    {
        const string submittedHardwareId = "34567890ABCDEF12";
        await SeedLicenseAsync(FakeLicenseKey + "-UNKNOWN", hwid: "5555666677778888");
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-UNKNOWN", submittedHardwareId);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Proves that alias evidence cannot reactivate an inactive seat through support submission.</summary>
    [Fact]
    public async Task Submit_WhenAliasResolvesToInactiveSeat_ShouldReturn400()
    {
        const string submittedHardwareId = "4567890ABCDEF123";
        const string effectiveHardwareId = "CDEF0123456789AB";
        var authority = await SeedLicenseAsync(FakeLicenseKey + "-INACTIVE", hwid: "6666777788889999");
        var seatId = await SeedSeatAsync(authority.LicenseId, effectiveHardwareId, isActive: false);
        ConfigureAliasResolution(authority, submittedHardwareId, effectiveHardwareId, seatId);
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-INACTIVE", submittedHardwareId);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Proves that ambiguous alias evidence is rejected without provider relay.</summary>
    [Fact]
    public async Task Submit_WhenAliasResolutionIsAmbiguous_ShouldReturn400()
    {
        const string submittedHardwareId = "567890ABCDEF1234";
        var authority = await SeedLicenseAsync(FakeLicenseKey + "-AMBIGUOUS", hwid: "777788889999AAAA");
        _hardwareAuthorityAliases
            .Setup(resolver => resolver.ResolveAsync(
                It.IsAny<LicenseDbContext>(),
                authority.ProductId,
                authority.LicenseId,
                submittedHardwareId,
                HardwareAuthorityResolutionIntent.StatusCheck,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new HardwareAuthorityResolution(
                submittedHardwareId,
                submittedHardwareId,
                null,
                HardwareAuthorityResolutionStatus.Refused,
                RefusalReason: HardwareAuthorityRefusalReason.AmbiguousAlias));
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-AMBIGUOUS", submittedHardwareId);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Proves that the legacy unknown sentinel cannot authorize a keyed manual report.</summary>
    [Fact]
    public async Task Submit_WithLicenseKeyAndUnknownHardwareId_ShouldReturn400()
    {
        await SeedLicenseAsync(FakeLicenseKey + "-KEYED-UNKNOWN", hwid: "88889999AAAABBBB");
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-KEYED-UNKNOWN", "unknown");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Proves that omitting hardware authority cannot authorize a keyed manual report.</summary>
    [Fact]
    public async Task Submit_WithLicenseKeyAndMissingHardwareId_ShouldReturn400()
    {
        await SeedLicenseAsync(FakeLicenseKey + "-KEYED-MISSING", hwid: "9999AAAABBBBCCCC");
        _fakeBugTrace.SubmittedTickets.Clear();
        var client = CreateClient();

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", new
        {
            licenseKey = FakeLicenseKey + "-KEYED-MISSING",
            projectId = ValidProjectId,
            ticket = new { title = "Bug", description = "Details", type = "BUG", priority = "NORMAL" }
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Proves that an unbound licence cannot authorize an arbitrary submitted machine.</summary>
    [Fact]
    public async Task Submit_WithUnboundLicenseAndArbitraryHardwareId_ShouldReturn400()
    {
        await SeedLicenseAsync(FakeLicenseKey + "-UNBOUND", hwid: null);
        _fakeBugTrace.SubmittedTickets.Clear();

        var response = await SubmitAsync(FakeLicenseKey + "-UNBOUND", "ABCDEFABCDEFABCD");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Configures an authenticated alias result without persisting any real identifier.</summary>
    /// <param name="authority">Expected product and licence scope.</param>
    /// <param name="submittedHardwareId">Exact synthetic legacy identifier.</param>
    /// <param name="effectiveHardwareId">Exact synthetic canonical seat identifier.</param>
    /// <param name="seatId">Resolver-provided seat identity rechecked by the controller.</param>
    private void ConfigureAliasResolution(
        (Guid LicenseId, Guid ProductId) authority,
        string submittedHardwareId,
        string effectiveHardwareId,
        Guid seatId)
    {
        _hardwareAuthorityAliases
            .Setup(resolver => resolver.ResolveAsync(
                It.IsAny<LicenseDbContext>(),
                authority.ProductId,
                authority.LicenseId,
                submittedHardwareId,
                HardwareAuthorityResolutionIntent.StatusCheck,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new HardwareAuthorityResolution(
                submittedHardwareId,
                effectiveHardwareId,
                Guid.NewGuid(),
                HardwareAuthorityResolutionStatus.Resolved,
                LicenseSeatId: seatId));
    }

    /// <summary>Submits a bounded synthetic manual report through the public HTTP contract.</summary>
    /// <param name="licenseKey">Synthetic licence authority.</param>
    /// <param name="hardwareId">Synthetic direct or legacy machine authority.</param>
    /// <returns>The HTTP response emitted after validation and optional relay.</returns>
    private Task<HttpResponseMessage> SubmitAsync(string licenseKey, string hardwareId)
    {
        var client = CreateClient();
        return client.PostAsJsonAsync("/api/bugtrace/submit", new
        {
            licenseKey,
            hardwareId,
            projectId = ValidProjectId,
            ticket = new { title = "Bug", description = "Details", type = "BUG", priority = "NORMAL" }
        });
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

    /// <summary>Proves desktop clients can authenticate comment reads without exposing the licence key in the URL.</summary>
    [Fact]
    public async Task GetTicketComments_WithLicenseKeyHeader_ShouldRelayToBugTrace()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.QueriedEmails.Clear();
        _fakeBugTrace.QueriedCommentTickets.Clear();
        var client = CreateClient();
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/bugtrace/tickets/BT-00042/comments?hardwareId={FakeHwid}&projectId={ValidProjectId}");
        request.Headers.TryAddWithoutValidation("X-License-Key", $"  {FakeLicenseKey}  ");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(_fakeBugTrace.QueriedEmails);
        Assert.Equal(FakeEmail, _fakeBugTrace.QueriedEmails[0]);
        Assert.Single(_fakeBugTrace.QueriedCommentTickets);
        Assert.Equal("BT-00042", _fakeBugTrace.QueriedCommentTickets[0]);
    }

    /// <summary>Proves ambiguous header and query credentials are rejected before licence or ticket lookup.</summary>
    [Fact]
    public async Task GetTicketComments_WithConflictingLicenseCredentials_ShouldReturn400()
    {
        await SeedLicenseAsync(FakeLicenseKey, hwid: FakeHwid, email: FakeEmail);
        _fakeBugTrace.QueriedEmails.Clear();
        _fakeBugTrace.QueriedCommentTickets.Clear();
        var client = CreateClient();
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/bugtrace/tickets/BT-00042/comments?licenseKey={FakeLicenseKey}&hardwareId={FakeHwid}&projectId={ValidProjectId}");
        request.Headers.TryAddWithoutValidation("X-License-Key", "DIFFERENT-LICENSE-KEY");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Conflicting license credentials", body, StringComparison.Ordinal);
        Assert.Empty(_fakeBugTrace.QueriedEmails);
        Assert.Empty(_fakeBugTrace.QueriedCommentTickets);
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
    /// <summary>Proves a revoked licence cannot use the legacy submission endpoint; the synthetic HTTP fixture must reject before provider submission.</summary>
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

    /// <summary>Proves human support tolerates a changed HWID only after active licence and reporter authorization.</summary>
    [Fact]
    public async Task CreateSupportCase_WithActiveLicenseAndChangedHardware_ShouldSucceed()
    {
        var key = "SUPPORT-MISMATCH-LICENSE-001";
        await SeedLicenseAsync(key, hwid: "OLD-HARDWARE", email: FakeEmail);
        var client = CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/bugtrace/support-cases")
        {
            Content = JsonContent.Create(new
            {
                licenseKey = key,
                hardwareId = "NEW-HARDWARE",
                projectId = ValidProjectId,
                reporterEmail = FakeEmail,
                supportCase = new { title = "Cannot activate", description = "Hardware changed", category = "PROBLEM" }
            })
        };
        request.Headers.Add("Idempotency-Key", "desktop-support-case-regression-0001");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Single(_fakeBugTrace.CreatedSupportCases);
        Assert.Contains("SUP-000123", await response.Content.ReadAsStringAsync());
    }

    /// <summary>Proves the SUP fallback does not widen the legacy manual Ticket hardware boundary.</summary>
    [Fact]
    public async Task LegacyTicketSubmit_WithChangedHardware_RemainsStrict()
    {
        var key = "LEGACY-MISMATCH-LICENSE-001";
        await SeedLicenseAsync(key, hwid: "OLD-HARDWARE", email: FakeEmail);
        var client = CreateClient();

        var response = await client.PostAsJsonAsync("/api/bugtrace/submit", new
        {
            licenseKey = key,
            hardwareId = "NEW-HARDWARE",
            projectId = ValidProjectId,
            ticket = new { title = "Automatic incident", description = "Details", type = "BUG", priority = "NORMAL" }
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("Hardware ID mismatch", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(_fakeBugTrace.SubmittedTickets);
    }

    /// <summary>Rejects a foreign reporter before the synthetic provider can create a case.</summary>
    [Fact]
    public async Task CreateSupportCase_WhenReporterDoesNotMatchLicense_ShouldReturn403()
    {
        var key = "SUPPORT-REPORTER-LICENSE-001";
        await SeedLicenseAsync(key, hwid: FakeHwid, email: FakeEmail);
        var client = CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/bugtrace/support-cases")
        {
            Content = JsonContent.Create(new
            {
                licenseKey = key,
                hardwareId = FakeHwid,
                projectId = ValidProjectId,
                reporterEmail = "attacker@example.com",
                supportCase = new { title = "Test", description = "Test" }
            })
        };
        request.Headers.Add("Idempotency-Key", "desktop-support-case-regression-0002");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>Rejects a canonical reference absent from the authoritative customer history.</summary>
    [Fact]
    public async Task SupportCaseDetail_WhenReferenceIsNotOwned_ShouldReturn403()
    {
        var key = "SUPPORT-OWNERSHIP-LICENSE-001";
        await SeedLicenseAsync(key, hwid: FakeHwid, email: FakeEmail);
        var client = CreateClient();

        var response = await client.PostAsJsonAsync("/api/bugtrace/support-cases/SUP-999999/detail", new
        {
            licenseKey = key,
            hardwareId = FakeHwid,
            projectId = ValidProjectId
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}

// ---------------------------------------------------------------------------
// Tests unitaires : BugTraceProxyService - token jamais transmis en clair
// ---------------------------------------------------------------------------
/// <summary>Exercises provider HTTP projection and safe failure logging with synthetic handlers and configuration; no real provider service is contacted.</summary>
public class BugTraceProxyServiceUnitTests
{
    [Fact]
    public void BugTraceTransport_DisablesRedirectsCookiesAndDecompression()
    {
        using var handler = Assert.IsType<HttpClientHandler>(BugTraceProxyService.CreateHttpMessageHandler());

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
    }

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
        configMock.Setup(c => c["BUGTRACE_SUPPORT_PROJECT_TOKEN"]).Returns(FakeToken);
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
        Assert.False(requests[0].Headers.Contains("Idempotency-Key"));
    }

    [Fact]
    public async Task SubmitTicket_IdempotentAutoReport_ForwardsOpaqueKeyExactly()
    {
        const string reportId = "a1111111-1111-1111-1111-111111111111";
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = JsonContent.Create(new { ticketNumber = "BT-00042", id = "abc" })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.SubmitTicketAsync(new { title = "T", description = "D" }, reportId);

        var request = Assert.Single(requests);
        Assert.Equal([reportId], request.Headers.GetValues("Idempotency-Key"));
    }

    [Fact]
    public async Task SubmitTicket_IdempotentAutoReport_RejectsNonCanonicalKeyWithoutSending()
    {
        const string uppercaseReportId = "A1111111-1111-1111-1111-111111111111";
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = JsonContent.Create(new { ticketNumber = "BT-00042", id = "abc" })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.SubmitTicketAsync(new { title = "T", description = "D" }, uppercaseReportId));

        Assert.Empty(requests);
    }

    [Fact]
    public async Task SubmitTicket_IdempotentAutoReport_UpstreamEchoedKeyIsRedactedFromLogs()
    {
        const string reportId = "c2111111-1111-1111-1111-111111111111";
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent(
                $"{{\"message\":\"provider failure\",\"idempotencyKey\":\"{reportId}\"}} idempotency-key={reportId}")
        };
        var logger = new ListLogger<BugTraceProxyService>();
        var (service, _, _) = BuildService(fakeResponse, logger);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            service.SubmitTicketAsync(new { title = "T", description = "D" }, reportId));

        var error = Assert.Single(logger.Entries, entry => entry.Level == LogLevel.Error);
        Assert.DoesNotContain(reportId, error.Message, StringComparison.Ordinal);
        Assert.Contains("\"idempotencyKey\":\"<redacted>\"", error.Message, StringComparison.Ordinal);
        Assert.Contains("idempotency-key=<redacted>", error.Message, StringComparison.Ordinal);
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

    /// <summary>Checks the dedicated provider create URI and exact opaque header without live provider traffic.</summary>
    [Fact]
    public async Task CreateSupportCase_UsesDedicatedProviderRouteAndIdempotencyHeader()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = JsonContent.Create(new { id = "support-id", supportNumber = "SUP-000123", replayed = false })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.CreateSupportCaseAsync(
            new { title = "Question", description = "Details", reporterEmail = "user@example.com", source = "DESKTOP" },
            "desktop-support-case-contract-0001");

        var request = Assert.Single(requests);
        Assert.Equal($"{FakeBaseUrl}/api/support-cases", request.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Contains(FakeToken, request.Headers.GetValues("X-Project-Token"));
        Assert.Contains("desktop-support-case-contract-0001", request.Headers.GetValues("Idempotency-Key"));
    }

    /// <summary>Checks the encoded owner filter and explicit bounded provider history request.</summary>
    [Fact]
    public async Task ListSupportCases_UsesReporterFilterAndBoundedLimit()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { total = 0, limit = 200, offset = 0, items = Array.Empty<object>() })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.ListSupportCasesAsync("user+support@example.com", 200);

        var request = Assert.Single(requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(
            $"{FakeBaseUrl}/api/support-cases?reporterEmail=user%2Bsupport%40example.com&limit=200&offset=0",
            request.RequestUri!.ToString());
        Assert.Contains(FakeToken, request.Headers.GetValues("X-Project-Token"));
    }

    /// <summary>Checks that client-side resolution uses the provider PATCH lifecycle contract.</summary>
    [Fact]
    public async Task ResolveSupportCase_UsesDedicatedPatchRoute()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { supportNumber = "SUP-000123", status = "RESOLVED" })
        };
        var (service, requests, _) = BuildService(fakeResponse);

        await service.ResolveSupportCaseAsync("SUP-000123");

        var request = Assert.Single(requests);
        Assert.Equal(HttpMethod.Patch, request.Method);
        Assert.Equal($"{FakeBaseUrl}/api/support-cases/SUP-000123/resolve", request.RequestUri!.ToString());
    }

    /// <summary>Checks multipart staging and exact replay header using a synthetic in-memory file.</summary>
    [Fact]
    public async Task StageSupportAttachment_UsesMultipartProviderRouteAndIdempotencyHeader()
    {
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = JsonContent.Create(new { attachment = new { id = Guid.NewGuid(), originalName = "log.txt" } })
        };
        var (service, requests, _) = BuildService(fakeResponse);
        var file = new FormFile(new MemoryStream("diagnostic"u8.ToArray()), 0, 10, "file", "log.txt")
        {
            Headers = new HeaderDictionary(),
            ContentType = "text/plain"
        };

        await service.StageSupportAttachmentAsync(file, "user@example.com", "desktop-support-file-contract-0001");

        var request = Assert.Single(requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"{FakeBaseUrl}/api/support-cases/attachments", request.RequestUri!.ToString());
        Assert.Contains("desktop-support-file-contract-0001", request.Headers.GetValues("Idempotency-Key"));
    }

    /// <summary>Checks bounded download projection preserves safe synthetic bytes, media type and basename.</summary>
    [Fact]
    public async Task DownloadSupportAttachment_PreservesBytesAndProviderFilename()
    {
        var expected = new byte[] { 0x01, 0x02, 0x03 };
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(expected)
        };
        fakeResponse.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pdf");
        fakeResponse.Content.Headers.ContentDisposition = new System.Net.Http.Headers.ContentDispositionHeaderValue("attachment")
        {
            FileNameStar = "report.pdf"
        };
        var (service, requests, _) = BuildService(fakeResponse);

        var result = await service.DownloadSupportAttachmentAsync("SUP-000123", Guid.NewGuid().ToString());

        Assert.Equal(expected, result.Content);
        Assert.Equal("application/pdf", result.ContentType);
        Assert.Equal("report.pdf", result.FileName);
        Assert.Equal(HttpMethod.Get, Assert.Single(requests).Method);
    }

    /// <summary>Proves an upstream legacy rejection throws while bounded log projection redacts sensitive values; a synthetic HTTP handler avoids real provider credentials.</summary>
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
    public async Task GetTicketComments_WhenUpstreamLengthIsUnknown_ReadsOnlyBoundedPrefix()
    {
        var payload = new CountingPayloadStream(1_000_000);
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StreamContent(payload)
        };
        var logger = new ListLogger<BugTraceProxyService>();
        var (service, _, _) = BuildService(fakeResponse, logger);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            service.GetTicketCommentsAsync("BT-00001"));

        var error = Assert.Single(logger.Entries, entry => entry.Level == LogLevel.Error);
        Assert.InRange(payload.BytesRead, 1, 8193);
        Assert.Contains("<truncated>", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetTicketComments_WhenDeclaredBodyIsOversized_DoesNotReadPayload()
    {
        var payload = new CountingPayloadStream(1_000_000);
        var content = new StreamContent(payload);
        content.Headers.ContentLength = 1_000_000;
        var fakeResponse = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = content
        };
        var logger = new ListLogger<BugTraceProxyService>();
        var (service, _, _) = BuildService(fakeResponse, logger);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            service.GetTicketCommentsAsync("BT-00001"));

        var error = Assert.Single(logger.Entries, entry => entry.Level == LogLevel.Error);
        Assert.Equal(0, payload.BytesRead);
        Assert.Contains("<omitted:oversized>", error.Message, StringComparison.Ordinal);
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

    /// <summary>Generates a large non-seekable response while counting bytes requested by the consumer.</summary>
    private sealed class CountingPayloadStream(long length) : Stream
    {
        private long _remaining = length;

        /// <summary>Gets the cumulative bytes requested from the synthetic upstream response.</summary>
        public long BytesRead { get; private set; }
        /// <inheritdoc />
        public override bool CanRead => true;
        /// <inheritdoc />
        public override bool CanSeek => false;
        /// <inheritdoc />
        public override bool CanWrite => false;
        /// <inheritdoc />
        public override long Length => throw new NotSupportedException();
        /// <inheritdoc />
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = (int)Math.Min(count, _remaining);
            buffer.AsSpan(offset, read).Fill((byte)'A');
            _remaining -= read;
            BytesRead += read;
            return read;
        }

        /// <inheritdoc />
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = (int)Math.Min(buffer.Length, _remaining);
            buffer.Span[..read].Fill((byte)'A');
            _remaining -= read;
            BytesRead += read;
            return ValueTask.FromResult(read);
        }

        /// <inheritdoc />
        public override void Flush() => throw new NotSupportedException();
        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        /// <inheritdoc />
        public override void SetLength(long value) => throw new NotSupportedException();
        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
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

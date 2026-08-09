using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;
using SoftLicence.Server.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SoftLicence.Tests.Server;

public class ApiIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public ApiIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", "CHANGE_ME_RANDOM_SECRET");
            builder.UseSetting("AdminSettings:AllowedIps", ""); 
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
            });
        });
    }

    private async Task SeedDataAsync(IServiceProvider services)
    {
        var db = services.GetRequiredService<LicenseDbContext>();
        var encryption = services.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

        if (await db.Products.AnyAsync(p => p.Name == "YOUR_APP_NAME")) return;

        var keys = LicenseService.GenerateKeys();
        var product = new Product 
        { 
            Id = Guid.NewGuid(),
            Name = "YOUR_APP_NAME", 
            PrivateKeyXml = encryption.Encrypt(keys.PrivateKey), 
            PublicKeyXml = keys.PublicKey,
            ApiSecret = "CHANGE_ME_RANDOM_SECRET"
        };
        db.Products.Add(product);

        var trialType = new LicenseType
        {
            Id = Guid.NewGuid(),
            Name = "Trial",
            Slug = "TRIAL",
            DefaultDurationDays = 7,
            IsRecurring = true,
            DefaultMaxSeats = 1,
            ProductId = product.Id
        };
        db.LicenseTypes.Add(trialType);

        await db.SaveChangesAsync();
    }

    private async Task<AccessLog> WaitForActivationLogAsync(string licenseKey, string hardwareId)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);

        while (DateTime.UtcNow < deadline)
        {
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var log = await db.AccessLogs
                .AsNoTracking()
                .Where(l => l.Endpoint == "ACTIVATE"
                    && l.LicenseKey == licenseKey
                    && l.HardwareId == hardwareId)
                .OrderByDescending(l => l.Timestamp)
                .FirstOrDefaultAsync();

            if (log != null)
                return log;

            await Task.Delay(100);
        }

        throw new TimeoutException("Activation audit log was not written.");
    }

    [Fact]
    public async Task PostActivation_WithInvalidKey_ShouldReturnBadRequest()
    {
        var client = _factory.CreateClient();
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedDataAsync(scope.ServiceProvider);
        }

        var request = new { LicenseKey = "INVALID", HardwareId = "HW1", AppName = "YOUR_APP_NAME" };
        var response = await client.PostAsJsonAsync("/api/activation", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PostActivation_WithBannedHardware_ShouldKeepLegacyErrorMessageAliasInStructuredPayload()
    {
        var client = _factory.CreateClient();
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedDataAsync(scope.ServiceProvider);
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            db.BannedHardwareIds.Add(new BannedHardwareId
            {
                HardwareId = "HW-STRUCTURED-COMPAT",
                Reason = "Compatibility test",
                BannedAt = DateTime.UtcNow,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = "YOUR_APP_NAME-FREE-TRIAL",
            HardwareId = "HW-STRUCTURED-COMPAT",
            AppName = "YOUR_APP_NAME"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("BANNED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(payload.GetProperty("message").GetString(), payload.GetProperty("errorMessage").GetString());
        Assert.Equal(1, payload.GetProperty("contractVersion").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(payload.GetProperty("correlationId").GetString()));
    }

    [Fact]
    public async Task PostActivation_WithInvalidKey_ShouldAuditInvalidLicenseKey()
    {
        var client = _factory.CreateClient();
        var licenseKey = $"INVALID-AUDIT-{Guid.NewGuid():N}".ToUpperInvariant();
        var hardwareId = $"HW-AUDIT-{Guid.NewGuid():N}";
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedDataAsync(scope.ServiceProvider);
        }

        var request = new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName = "YOUR_APP_NAME" };
        var response = await client.PostAsJsonAsync("/api/activation", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var log = await WaitForActivationLogAsync(licenseKey, hardwareId);
        Assert.Equal("INVALID_LICENSE_KEY", log.ResultStatus);
        Assert.Equal(400, log.StatusCode);
        Assert.Equal("[REDACTED]", log.RequestBody);
        Assert.Equal("[REDACTED]", log.ErrorDetails);
        Assert.Equal(licenseKey, log.LicenseKey);
        Assert.Equal(hardwareId, log.HardwareId);
        Assert.DoesNotContain(licenseKey, log.RequestBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hardwareId, log.RequestBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(licenseKey, log.ErrorDetails, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hardwareId, log.ErrorDetails, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PostActivation_WithExpiredLicense_ShouldAuditLicenseExpired()
    {
        var client = _factory.CreateClient();
        var licenseKey = $"EXPIRED-AUDIT-{Guid.NewGuid():N}".ToUpperInvariant();
        var hardwareId = $"HW-EXPIRED-{Guid.NewGuid():N}";

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var product = await db.Products.FirstAsync(p => p.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.FirstAsync(t => t.Slug == "TRIAL");

            db.Licenses.Add(new License
            {
                LicenseKey = licenseKey,
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                HardwareId = hardwareId,
                ExpirationDate = DateTime.UtcNow.AddDays(-1),
                CustomerName = "Expired Audit",
                CustomerEmail = "expired-audit@test.local",
                IsActive = true,
                MaxSeats = 1
            });
            await db.SaveChangesAsync();
        }

        var request = new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName = "YOUR_APP_NAME", AppVersion = "2.1.781" };
        var response = await client.PostAsJsonAsync("/api/activation", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(content));

        var log = await WaitForActivationLogAsync(licenseKey, hardwareId);
        Assert.Equal("LICENSE_EXPIRED", log.ResultStatus);
        Assert.Equal(400, log.StatusCode);
    }

    [Fact]
    public async Task PostActivation_WithDisabledLicense_ShouldExposeStructuredCodeWithoutChangingBody()
    {
        var client = _factory.CreateClient();
        var licenseKey = $"DISABLED-{Guid.NewGuid():N}".ToUpperInvariant();
        var hardwareId = $"HW-DISABLED-{Guid.NewGuid():N}";

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var product = await db.Products.FirstAsync(p => p.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.FirstAsync(t => t.Slug == "TRIAL");

            db.Licenses.Add(new License
            {
                LicenseKey = licenseKey,
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                CustomerName = "Disabled",
                CustomerEmail = "disabled@test.local",
                IsActive = false,
                MaxSeats = 1
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName = "YOUR_APP_NAME"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("LICENSE_DISABLED", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        Assert.Equal("1", response.Headers.GetValues("X-SoftLicence-Error-Contract").Single());
        Assert.False(string.IsNullOrWhiteSpace(response.Headers.GetValues("X-SoftLicence-Correlation-Id").Single()));
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("LICENSE_DISABLED", body, StringComparison.OrdinalIgnoreCase);

        var log = await WaitForActivationLogAsync(licenseKey, hardwareId);
        Assert.Equal("LICENSE_DISABLED", log.ResultStatus);
    }

    [Fact]
    public async Task PostActivation_WithInvalidPartner_ShouldExposePartnerInvalidWithoutChangingDisabledBody()
    {
        var client = _factory.CreateClient();
        var licenseKey = $"PARTNER-{Guid.NewGuid():N}".ToUpperInvariant();
        var hardwareId = $"HW-PARTNER-{Guid.NewGuid():N}";

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var product = await db.Products.FirstAsync(p => p.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.FirstAsync(t => t.Slug == "TRIAL");

            db.Licenses.Add(new License
            {
                LicenseKey = licenseKey,
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                CustomerName = "Partner",
                CustomerEmail = "partner@test.local",
                PartnerCode = "MISSING-PARTNER",
                IsActive = true,
                MaxSeats = 1
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName = "YOUR_APP_NAME"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("PARTNER_INVALID", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("PARTNER_INVALID", body, StringComparison.OrdinalIgnoreCase);

        var log = await WaitForActivationLogAsync(licenseKey, hardwareId);
        Assert.Equal("PARTNER_INVALID", log.ResultStatus);
    }

    [Fact]
    public async Task PostActivation_WhenSeatLimitReached_ShouldExposeSeatLimitCode()
    {
        var client = _factory.CreateClient();
        var licenseKey = $"SEAT-LIMIT-{Guid.NewGuid():N}".ToUpperInvariant();
        var firstActivatedAt = DateTime.UtcNow.AddDays(-1);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var product = await db.Products.FirstAsync(p => p.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.FirstAsync(t => t.Slug == "TRIAL");
            var license = new License
            {
                LicenseKey = licenseKey,
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                CustomerName = "Seat Limit",
                CustomerEmail = "seat-limit@test.local",
                HardwareId = "HW-FIRST-SEAT",
                ActivationDate = firstActivatedAt,
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*"
            };

            db.Licenses.Add(license);
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = "HW-FIRST-SEAT",
                FirstActivatedAt = firstActivatedAt,
                LastCheckInAt = firstActivatedAt,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "HW-SECOND-SEAT",
            AppName = "YOUR_APP_NAME"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("SEAT_LIMIT", response.Headers.GetValues("X-SoftLicence-Error-Code").Single());

        var log = await WaitForActivationLogAsync(licenseKey, "HW-SECOND-SEAT");
        Assert.Equal("SEAT_LIMIT", log.ResultStatus);
    }

    [Fact]
    public async Task PostActivation_WithValidLicense_ShouldNotExposeActivationErrorCodeHeader()
    {
        var client = _factory.CreateClient();
        var licenseKey = $"VALID-{Guid.NewGuid():N}".ToUpperInvariant();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var product = await db.Products.FirstAsync(p => p.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.FirstAsync(t => t.Slug == "TRIAL");

            db.Licenses.Add(new License
            {
                LicenseKey = licenseKey,
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                CustomerName = "Valid",
                CustomerEmail = "valid@test.local",
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*"
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "HW-VALID-ACTIVATION",
            AppName = "YOUR_APP_NAME",
            AppVersion = "2.2.640"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("X-SoftLicence-Error-Code"));
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(result.TryGetProperty("licenseFile", out _));
    }

    [Fact]
    public async Task PostActivation_WithAutoTrial_ShouldGenerateNewLicense()
    {
        var client = _factory.CreateClient();
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedDataAsync(scope.ServiceProvider);
        }

        var request = new { LicenseKey = "YOUR_APP_NAME-FREE-TRIAL", HardwareId = "NEW-PC-123", AppName = "YOUR_APP_NAME" };
        var response = await client.PostAsJsonAsync("/api/activation", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(result.TryGetProperty("licenseFile", out _));
    }

    [Fact]
    public async Task AdminRenew_WithSecret_ShouldExtendLicense()
    {
        string licenseKey = "RENEW-ME-KEY";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var prod = await db.Products.FirstAsync(p => p.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.FirstAsync(t => t.Slug == "TRIAL");
            
            db.Licenses.Add(new License {
                LicenseKey = licenseKey,
                ProductId = prod.Id,
                LicenseTypeId = type.Id,
                HardwareId = "HW-RENEW",
                ExpirationDate = DateTime.UtcNow.AddDays(1),
                CustomerName = "Test",
                CustomerEmail = "test@test.com",
                IsActive = true,
                MaxSeats = 1
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        
        var request = new { TransactionId = "STRIPE_SUCCESS_UNIQUE", Reference = "INV-001" };
        var response = await client.PostAsJsonAsync($"/api/admin/licenses/{licenseKey}/renew", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AdminBanHardwareId_WithUnknownOrNonCanonicalCategory_ReturnsBadRequestWithoutMutation()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");

        foreach (var category in new[] { "future_security_category", "Outdated_Version", " outdated_version" })
        {
            var response = await client.PostAsJsonAsync("/api/admin/banned-hwids", new
            {
                HardwareId = "HW-INVALID-CATEGORY-" + Guid.NewGuid().ToString("N"),
                Reason = "operator request",
                BanCategory = category
            });

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("ban_category_invalid", payload.GetProperty("error").GetString());
        }

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.Empty(await db.BannedHardwareIds.ToListAsync());
    }

    [Fact]
    public async Task AdminRevokeAndUnrevoke_ReplayedAfterLostResponse_AreIdempotentAndAuditedOnce()
    {
        var licenseKey = "STATE-REPLAY-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedDataAsync(scope.ServiceProvider);
            var product = await db.Products.SingleAsync(candidate => candidate.Name == "YOUR_APP_NAME");
            var type = await db.LicenseTypes.SingleAsync(candidate => candidate.ProductId == product.Id);
            db.Licenses.Add(new License
            {
                LicenseKey = licenseKey,
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                CustomerName = "State Replay",
                CustomerEmail = "state-replay@example.test",
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*"
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");

        var firstRevoke = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/revoke",
            new { Reason = "operator decision" });
        var replayedRevoke = await client.PostAsJsonAsync(
            $"/api/admin/licenses/{licenseKey}/revoke",
            new { Reason = "operator decision" });
        var firstRestore = await client.PostAsync(
            $"/api/admin/licenses/{licenseKey}/unrevoke",
            content: null);
        var replayedRestore = await client.PostAsync(
            $"/api/admin/licenses/{licenseKey}/unrevoke",
            content: null);

        Assert.Equal(HttpStatusCode.OK, firstRevoke.StatusCode);
        Assert.Equal(HttpStatusCode.OK, replayedRevoke.StatusCode);
        Assert.Equal(HttpStatusCode.OK, firstRestore.StatusCode);
        Assert.Equal(HttpStatusCode.OK, replayedRestore.StatusCode);
        Assert.False((await firstRevoke.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("idempotent").GetBoolean());
        Assert.True((await replayedRevoke.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("idempotent").GetBoolean());
        Assert.False((await firstRestore.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("idempotent").GetBoolean());
        Assert.True((await replayedRestore.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("idempotent").GetBoolean());

        using var verificationScope = _factory.Services.CreateScope();
        var verificationDb = verificationScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var license = await verificationDb.Licenses.SingleAsync(candidate => candidate.LicenseKey == licenseKey);
        Assert.True(license.IsActive);
        Assert.Null(license.RevokedAt);
        Assert.Equal(2, await verificationDb.LicenseHistories.CountAsync(candidate => candidate.LicenseId == license.Id));
    }

    [Fact]
    public async Task PostActivation_WhenLicenseTypeDisablesNewActivations_ShouldRejectUnactivatedLicense()
    {
        var productName = $"NoNewAct-{Guid.NewGuid():N}";
        var licenseKey = $"NO-NEW-ACT-{Guid.NewGuid():N}".ToUpperInvariant();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var (product, type) = await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-FREEMIUM", disableNewActivations: true);

            db.Licenses.Add(new License
            {
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                LicenseKey = licenseKey,
                CustomerName = "Legacy Freemium",
                CustomerEmail = "legacy@example.com",
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*"
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "HW-NEW-ACT-BLOCKED",
            AppName = productName
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("New activations", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PostActivation_WhenLicenseTypeDisablesNewActivations_ShouldAllowExistingSeatRecovery()
    {
        var productName = $"RecoveryAct-{Guid.NewGuid():N}";
        var licenseKey = $"RECOVERY-ACT-{Guid.NewGuid():N}".ToUpperInvariant();
        const string hardwareId = "HW-EXISTING-RECOVERY";

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var (product, type) = await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-FREEMIUM", disableNewActivations: true);
            var license = new License
            {
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                LicenseKey = licenseKey,
                CustomerName = "Existing Freemium",
                CustomerEmail = "existing@example.com",
                HardwareId = hardwareId,
                ActivationDate = DateTime.UtcNow.AddDays(-1),
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*"
            };

            db.Licenses.Add(license);
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = hardwareId,
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddHours(-1),
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName = productName
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AdminFreemiumUnactivatedRevocation_ShouldDryRunAndRevokeOnlyNeverActivatedFreemium()
    {
        var productName = $"FreemiumClose-{Guid.NewGuid():N}";
        var revokeKey = $"REVOKE-FREE-{Guid.NewGuid():N}".ToUpperInvariant();
        var keepActivatedKey = $"KEEP-ACT-{Guid.NewGuid():N}".ToUpperInvariant();
        var keepPaidKey = $"KEEP-PAID-{Guid.NewGuid():N}".ToUpperInvariant();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var (product, freemiumType) = await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-FREEMIUM", isFree: true);
            var paidType = new LicenseType
            {
                ProductId = product.Id,
                Name = "Pro",
                Slug = "TIA-CONNECT-PRO",
                IsFree = false,
                DefaultDurationDays = 365
            };
            db.LicenseTypes.Add(paidType);

            var keepActivated = new License
            {
                ProductId = product.Id,
                LicenseTypeId = freemiumType.Id,
                LicenseKey = keepActivatedKey,
                CustomerName = "Activated",
                CustomerEmail = "activated@example.com",
                HardwareId = "HW-ACTIVATED",
                ActivationDate = DateTime.UtcNow.AddDays(-1),
                IsActive = true,
                MaxSeats = 1,
                AllowedVersions = "*"
            };

            db.Licenses.AddRange(
                new License
                {
                    ProductId = product.Id,
                    LicenseTypeId = freemiumType.Id,
                    LicenseKey = revokeKey,
                    CustomerName = "Never Activated",
                    CustomerEmail = "never@example.com",
                    IsActive = true,
                    MaxSeats = 1,
                    AllowedVersions = "*"
                },
                keepActivated,
                new License
                {
                    ProductId = product.Id,
                    LicenseTypeId = paidType.Id,
                    LicenseKey = keepPaidKey,
                    CustomerName = "Paid",
                    CustomerEmail = "paid@example.com",
                    IsActive = true,
                    MaxSeats = 1,
                    AllowedVersions = "*"
                });
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = keepActivated.Id,
                HardwareId = "HW-ACTIVATED",
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var request = new
        {
            ProductName = productName,
            LicenseTypeSlug = "TIA-CONNECT-FREEMIUM",
            Reason = "Freemium gratuit arrêté - clé non activée avant fermeture"
        };

        var dryRun = await client.PostAsJsonAsync("/api/admin/licenses/freemium-unactivated-revocation/dry-run", request);
        Assert.Equal(HttpStatusCode.OK, dryRun.StatusCode);
        var dryRunJson = await dryRun.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, dryRunJson.GetProperty("count").GetInt32());

        var execute = await client.PostAsJsonAsync("/api/admin/licenses/freemium-unactivated-revocation/execute", request);
        Assert.Equal(HttpStatusCode.OK, execute.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var revoked = await verifyDb.Licenses.SingleAsync(l => l.LicenseKey == revokeKey);
        var keptActivated = await verifyDb.Licenses.SingleAsync(l => l.LicenseKey == keepActivatedKey);
        var keepPaid = await verifyDb.Licenses.SingleAsync(l => l.LicenseKey == keepPaidKey);

        Assert.False(revoked.IsActive);
        Assert.NotNull(revoked.RevokedAt);
        Assert.True(keptActivated.IsActive);
        Assert.True(keepPaid.IsActive);
        Assert.True(await verifyDb.LicenseHistories.AnyAsync(h => h.LicenseId == revoked.Id && h.Action == HistoryActions.Revoked));
    }

    [Fact]
    public async Task AdminCreateLicense_WithPartnerCode_ShouldExtendResellerDemoLicense()
    {
        var productName = $"PartnerSale-{Guid.NewGuid():N}";
        const string partnerCode = "AARONLIU-4M0Q";
        var originalExpiration = DateTime.UtcNow.AddDays(5);
        Guid resellerLicenseId;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var (product, proType) = await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-PRO");
            proType.DefaultDurationDays = 365;

            var resellerType = new LicenseType
            {
                ProductId = product.Id,
                Name = "Reseller",
                Slug = "TIA-RESELLER-EVALDEMO",
                DefaultDurationDays = 30,
                DefaultMaxSeats = 1
            };
            db.LicenseTypes.Add(resellerType);
            db.ResellerPartners.Add(new ResellerPartner
            {
                Code = partnerCode,
                Name = "Aaron Liu",
                ContactEmail = "aaron@example.test"
            });

            var resellerLicense = new License
            {
                ProductId = product.Id,
                LicenseTypeId = resellerType.Id,
                LicenseKey = $"RESELLER-{Guid.NewGuid():N}".ToUpperInvariant(),
                CustomerName = "Aaron Liu",
                CustomerEmail = "aaron@example.test",
                PartnerCode = partnerCode,
                ExpirationDate = originalExpiration,
                IsActive = true,
                MaxSeats = 1
            };
            db.Licenses.Add(resellerLicense);
            await db.SaveChangesAsync();
            resellerLicenseId = resellerLicense.Id;
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var response = await client.PostAsJsonAsync("/api/admin/licenses", new
        {
            ProductName = productName,
            CustomerName = "Final Customer",
            CustomerEmail = "customer@example.test",
            TypeSlug = "TIA-CONNECT-PRO",
            PartnerCode = partnerCode.ToLowerInvariant()
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var updatedResellerLicense = await verifyDb.Licenses
            .Include(l => l.History)
            .SingleAsync(l => l.Id == resellerLicenseId);
        var customerLicense = await verifyDb.Licenses.SingleAsync(l => l.CustomerEmail == "customer@example.test");

        Assert.True(updatedResellerLicense.IsActive);
        Assert.Equal(originalExpiration.AddDays(180), updatedResellerLicense.ExpirationDate);
        Assert.Equal(partnerCode, customerLicense.PartnerCode);
        Assert.Contains(updatedResellerLicense.History, h =>
            h.Action == HistoryActions.Renewed
            && h.Details != null
            && h.Details.Contains("Partner sale auto-renewal", StringComparison.Ordinal)
            && h.Details.Contains("+180 days", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AdminCreateLicense_WhenCreatingResellerDemoLicense_ShouldNotAutoExtendResellerDemoLicense()
    {
        var productName = $"PartnerDemo-{Guid.NewGuid():N}";
        const string partnerCode = "AARONLIU-4M0Q";
        var originalExpiration = DateTime.UtcNow.AddDays(5);
        Guid resellerLicenseId;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var (product, resellerType) = await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-RESELLER-EVALDEMO");
            resellerType.DefaultDurationDays = 30;

            db.ResellerPartners.Add(new ResellerPartner
            {
                Code = partnerCode,
                Name = "Aaron Liu",
                ContactEmail = "aaron@example.test"
            });

            var resellerLicense = new License
            {
                ProductId = product.Id,
                LicenseTypeId = resellerType.Id,
                LicenseKey = $"RESELLER-{Guid.NewGuid():N}".ToUpperInvariant(),
                CustomerName = "Aaron Liu",
                CustomerEmail = "aaron@example.test",
                PartnerCode = partnerCode,
                ExpirationDate = originalExpiration,
                IsActive = true,
                MaxSeats = 1
            };
            db.Licenses.Add(resellerLicense);
            await db.SaveChangesAsync();
            resellerLicenseId = resellerLicense.Id;
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var response = await client.PostAsJsonAsync("/api/admin/licenses", new
        {
            ProductName = productName,
            CustomerName = "Aaron Liu",
            CustomerEmail = "aaron@example.test",
            TypeSlug = "TIA-RESELLER-EVALDEMO",
            PartnerCode = partnerCode
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var updatedResellerLicense = await verifyDb.Licenses
            .Include(l => l.History)
            .SingleAsync(l => l.Id == resellerLicenseId);

        Assert.Equal(originalExpiration, updatedResellerLicense.ExpirationDate);
        Assert.DoesNotContain(updatedResellerLicense.History, h => h.Action == HistoryActions.Renewed);
    }

    [Fact]
    public async Task AdminCreateLicense_WithPartnerCodeButNoResellerDemoLicense_ShouldStillCreateCustomerLicense()
    {
        var productName = $"PartnerNoDemo-{Guid.NewGuid():N}";
        const string partnerCode = "AARONLIU-4M0Q";

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-PRO");
            db.ResellerPartners.Add(new ResellerPartner
            {
                Code = partnerCode,
                Name = "Aaron Liu",
                ContactEmail = "aaron@example.test"
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var response = await client.PostAsJsonAsync("/api/admin/licenses", new
        {
            ProductName = productName,
            CustomerName = "Final Customer",
            CustomerEmail = "customer-no-demo@example.test",
            TypeSlug = "TIA-CONNECT-PRO",
            PartnerCode = partnerCode
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var customerLicense = await verifyDb.Licenses.SingleAsync(l => l.CustomerEmail == "customer-no-demo@example.test");
        Assert.Equal(partnerCode, customerLicense.PartnerCode);
    }

    [Fact]
    public async Task AdminCreateLicense_WithReferenceRetry_ShouldReturnSameProvisionedBatch()
    {
        var productName = $"Provisioning-{Guid.NewGuid():N}";
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-PRO");
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var request = new
        {
            ProductName = productName,
            CustomerName = "Provisioned Customer",
            CustomerEmail = "provisioned@example.test",
            TypeSlug = "TIA-CONNECT-PRO",
            Reference = " ORDER-736 ",
            Quantity = 2,
            DaysValidity = 365,
            MaxSeats = 4
        };

        var firstResponse = await client.PostAsJsonAsync("/api/admin/licenses", request);
        var retryResponse = await client.PostAsJsonAsync("/api/admin/licenses", request);

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, retryResponse.StatusCode);
        var first = await firstResponse.Content.ReadFromJsonAsync<JsonElement>();
        var retry = await retryResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(first.GetProperty("idempotent").GetBoolean());
        Assert.True(retry.GetProperty("idempotent").GetBoolean());
        Assert.Equal(
            first.GetProperty("licenseKeys").EnumerateArray().Select(v => v.GetString()),
            retry.GetProperty("licenseKeys").EnumerateArray().Select(v => v.GetString()));

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        Assert.Equal(2, await verifyDb.Licenses.CountAsync(l => l.CustomerEmail == "provisioned@example.test"));
        var provisioning = await verifyDb.LicenseProvisioningRequests
            .Include(p => p.Licenses)
            .SingleAsync(p => p.Reference == "ORDER-736");
        Assert.Equal(2, provisioning.Licenses.Count);
        Assert.All(provisioning.Licenses, license => Assert.Equal(4, license.MaxSeats));
        Assert.All(provisioning.Licenses, license => Assert.Equal(365, license.ValidityDays));
    }

    [Fact]
    public async Task AdminCreateLicense_WhenReferencePayloadChanges_ShouldReturnConflict()
    {
        var productName = $"ProvisioningConflict-{Guid.NewGuid():N}";
        using (var scope = _factory.Services.CreateScope())
        {
            await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-PRO");
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var firstResponse = await client.PostAsJsonAsync("/api/admin/licenses", new
        {
            ProductName = productName,
            CustomerName = "First Customer",
            CustomerEmail = "first@example.test",
            TypeSlug = "TIA-CONNECT-PRO",
            Reference = "ORDER-CONFLICT",
            MaxSeats = 1
        });
        var conflictResponse = await client.PostAsJsonAsync("/api/admin/licenses", new
        {
            ProductName = productName,
            CustomerName = "Changed Customer",
            CustomerEmail = "changed@example.test",
            TypeSlug = "TIA-CONNECT-PRO",
            Reference = "ORDER-CONFLICT",
            MaxSeats = 2
        });

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, conflictResponse.StatusCode);
        var body = await conflictResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("reference_payload_conflict", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AdminRenew_WithExplicitDaysAndRetry_ShouldApplyOnlyOnce()
    {
        var productName = $"Renewal-{Guid.NewGuid():N}";
        var licenseKey = $"RENEW-{Guid.NewGuid():N}".ToUpperInvariant();
        var initialExpiration = DateTime.UtcNow.AddDays(10);
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var (product, type) = await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-PRO");
            type.IsRecurring = true;
            db.Licenses.Add(new License
            {
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                LicenseKey = licenseKey,
                CustomerName = "Renewed Customer",
                CustomerEmail = "renewed@example.test",
                ExpirationDate = initialExpiration,
                IsActive = true,
                MaxSeats = 1
            });
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var request = new { TransactionId = "TX-736-EXACT", Reference = " INV-736 ", DaysToAdd = 120 };
        var firstResponse = await client.PostAsJsonAsync($"/api/admin/licenses/{licenseKey}/renew", request);
        var retryResponse = await client.PostAsJsonAsync($"/api/admin/licenses/{licenseKey}/renew", request);

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, retryResponse.StatusCode);
        var first = await firstResponse.Content.ReadFromJsonAsync<JsonElement>();
        var retry = await retryResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(first.GetProperty("idempotent").GetBoolean());
        Assert.True(retry.GetProperty("idempotent").GetBoolean());
        Assert.Equal(first.GetProperty("newExpirationDate").GetDateTime(), retry.GetProperty("newExpirationDate").GetDateTime());
        Assert.Equal(120, retry.GetProperty("daysAdded").GetInt32());
        Assert.Equal("INV-736", retry.GetProperty("reference").GetString());

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var persisted = await verifyDb.Licenses.SingleAsync(l => l.LicenseKey == licenseKey);
        Assert.Equal(initialExpiration.AddDays(120), persisted.ExpirationDate);
        Assert.Equal(1, await verifyDb.LicenseRenewals.CountAsync(r => r.TransactionId == "TX-736-EXACT"));
    }

    [Fact]
    public async Task AdminRenew_WhenTransactionBelongsToAnotherLicense_ShouldReturnConflict()
    {
        var productName = $"RenewalConflict-{Guid.NewGuid():N}";
        var firstKey = $"RENEW-A-{Guid.NewGuid():N}".ToUpperInvariant();
        var secondKey = $"RENEW-B-{Guid.NewGuid():N}".ToUpperInvariant();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var (product, type) = await SeedProductAndTypeAsync(scope.ServiceProvider, productName, "TIA-CONNECT-PRO");
            type.IsRecurring = true;
            foreach (var key in new[] { firstKey, secondKey })
            {
                db.Licenses.Add(new License
                {
                    ProductId = product.Id,
                    LicenseTypeId = type.Id,
                    LicenseKey = key,
                    CustomerName = "Renewal Conflict",
                    CustomerEmail = $"{key}@example.test",
                    ExpirationDate = DateTime.UtcNow.AddDays(5),
                    IsActive = true,
                    MaxSeats = 1
                });
            }
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", "CHANGE_ME_RANDOM_SECRET");
        var request = new { TransactionId = "TX-736-SHARED", DaysToAdd = 30 };
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync($"/api/admin/licenses/{firstKey}/renew", request)).StatusCode);
        var conflict = await client.PostAsJsonAsync($"/api/admin/licenses/{secondKey}/renew", request);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
    }

    [Fact]
    public void ProvisioningMigration_ShouldBeDiscoverableByEntityFramework()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=not-used;Username=not-used;Password=not-used")
            .Options;
        using var db = new LicenseDbContext(options);

        Assert.Contains(
            "20260717090000_AddIdempotentLicenseProvisioning",
            db.Database.GetMigrations());
    }

    private async Task<(Product Product, LicenseType Type)> SeedProductAndTypeAsync(
        IServiceProvider services,
        string productName,
        string typeSlug,
        bool disableNewActivations = false,
        bool isFree = false)
    {
        var db = services.GetRequiredService<LicenseDbContext>();
        var encryption = services.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

        var keys = LicenseService.GenerateKeys();
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = productName,
            PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
            PublicKeyXml = keys.PublicKey,
            ApiSecret = "CHANGE_ME_RANDOM_SECRET"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            Name = typeSlug,
            Slug = typeSlug,
            IsFree = isFree,
            DisableNewActivations = disableNewActivations,
            DefaultDurationDays = 7,
            DefaultMaxSeats = 1
        };

        db.Products.Add(product);
        db.LicenseTypes.Add(type);
        await db.SaveChangesAsync();

        return (product, type);
    }
}

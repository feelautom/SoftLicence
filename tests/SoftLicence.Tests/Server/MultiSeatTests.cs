using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using Xunit;
using SoftLicence.Server.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Text.Json;

namespace SoftLicence.Tests.Server;

public class MultiSeatTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string RemovedHardwareStatus = "HARDWARE_NOT_ACTIVATED";
    private const string ProductApiSecret = "secret";

    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public MultiSeatTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", ProductApiSecret);
            builder.UseSetting("AdminSettings:AllowedIps", "");
            builder.ConfigureServices(services =>
            {
                // On force une base unique pour cette série de tests
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
            });
        });
    }

    private async Task<License> CreateLicenseAsync(IServiceProvider services, int maxSeats)
    {
        var db = services.GetRequiredService<LicenseDbContext>();
        var encryption = services.GetRequiredService<SoftLicence.Server.Services.EncryptionService>();

        var prod = new Product { 
            Id = Guid.NewGuid(), 
            Name = "MultiApp", 
            PrivateKeyXml = encryption.Encrypt(LicenseService.GenerateKeys().PrivateKey), 
            PublicKeyXml = "k",
            ApiSecret = ProductApiSecret
        };
        var type = new LicenseType { Id = Guid.NewGuid(), Name = "T", Slug = "T" };
        var license = new License {
            Id = Guid.NewGuid(),
            LicenseKey = Guid.NewGuid().ToString().ToUpper(),
            ProductId = prod.Id,
            LicenseTypeId = type.Id,
            MaxSeats = maxSeats,
            IsActive = true,
            CustomerName = "Test",
            AllowedVersions = "*"
        };
        db.Products.Add(prod);
        db.LicenseTypes.Add(type);
        db.Licenses.Add(license);
        await db.SaveChangesAsync();
        return license;
    }

    [Fact]
    public async Task Activate_ShouldRejectSecondPc_WhenMaxSeatsIsOne()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        
        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
        }

        // PC 1 : OK
        await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "C000000000000001", AppName = "MultiApp" });

        // PC 2 : Rejeté
        var response = await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "C000000000000002", AppName = "MultiApp" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.True(content.Contains("maximum d'activations") || content.Contains("maximum activations"));
    }

    [Fact]
    public async Task Activate_ShouldAllowMultiplePcs_WhenMaxSeatsIsGreater()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        
        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 2);
            licenseKey = lic.LicenseKey;
        }

        var res1 = await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "C000000000000003", AppName = "MultiApp" });
        var res2 = await client.PostAsJsonAsync("/api/activation", new { LicenseKey = licenseKey, HardwareId = "C000000000000004", AppName = "MultiApp" });

        Assert.Equal(HttpStatusCode.OK, res1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, res2.StatusCode);
    }

    [Fact]
    public async Task Activate_WithHardwareIdV2_ShouldCollectObservationWithoutChangingSeatIdentity()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        Guid licenseId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            licenseId = lic.Id;
        }

        var response = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000005",
            HardwareIdV2 = "C000000000000006",
            HardwareIdV2Differs = true,
            HardwareIdAlgorithm = "legacy-wmi-first-disk",
            HardwareIdV2Algorithm = "v2-wmi-disk-index-0",
            SdkVersion = "1.1.11",
            BuildHash = "BUILD-123",
            AppName = "MultiApp",
            AppVersion = "2.3.4"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var license = await verifyDb.Licenses.Include(l => l.Seats).SingleAsync(l => l.Id == licenseId);
        Assert.Equal("C000000000000005", license.HardwareId);
        Assert.Single(license.Seats, s => s.IsActive);
        Assert.Contains(license.Seats, s => s.IsActive && s.HardwareId == "C000000000000005");
        Assert.DoesNotContain(license.Seats, s => s.HardwareId == "C000000000000006");

        var observation = await verifyDb.LicenseHistories.SingleAsync(h =>
            h.LicenseId == licenseId && h.Action == HistoryActions.HardwareIdV2Observed);
        using var details = JsonDocument.Parse(observation.Details!);
        var root = details.RootElement;
        Assert.Equal("ACTIVATE", root.GetProperty("endpoint").GetString());
        Assert.Equal("C000000000000005", root.GetProperty("legacyHardwareId").GetString());
        Assert.Equal("C000000000000006", root.GetProperty("hardwareIdV2").GetString());
        Assert.True(root.GetProperty("hardwareIdV2Differs").GetBoolean());
        Assert.Equal("1.1.11", root.GetProperty("sdkVersion").GetString());
        Assert.Equal("BUILD-123", root.GetProperty("buildHash").GetString());
    }

    [Fact]
    public async Task CheckStatus_WithHardwareIdV2_ShouldNotUseV2ForSeatMatchOrQuota()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        Guid licenseId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            licenseId = lic.Id;

            var setupDb = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            setupDb.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = licenseId,
                HardwareId = "C000000000000005",
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddDays(-1),
                IsActive = true
            });
            lic.HardwareId = "C000000000000005";
            await setupDb.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000007",
            HardwareIdV2 = "C000000000000005",
            HardwareIdV2Differs = true,
            AppName = "MultiApp",
            AppVersion = "2.3.4",
            SdkVersion = "1.1.11"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            var status = json.RootElement.TryGetProperty("status", out var statusProperty)
                ? statusProperty.GetString()
                : json.RootElement.GetProperty("Status").GetString();
            Assert.Equal("HARDWARE_MISMATCH", status);
        }

        var duplicateResponse = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000007",
            HardwareIdV2 = "C000000000000005",
            HardwareIdV2Differs = true,
            AppName = "MultiApp",
            AppVersion = "2.3.4",
            SdkVersion = "1.1.11"
        });
        Assert.Equal(HttpStatusCode.OK, duplicateResponse.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var license = await verifyDb.Licenses.Include(l => l.Seats).SingleAsync(l => l.Id == licenseId);
        Assert.Equal("C000000000000005", license.HardwareId);
        Assert.Single(license.Seats, s => s.IsActive);
        Assert.DoesNotContain(license.Seats, s => s.HardwareId == "C000000000000007");

        var observation = await verifyDb.LicenseHistories.SingleAsync(h =>
            h.LicenseId == licenseId && h.Action == HistoryActions.HardwareIdV2Observed);
        using var details = JsonDocument.Parse(observation.Details!);
        Assert.Equal("CHECK", details.RootElement.GetProperty("endpoint").GetString());
        Assert.Equal("C000000000000007", details.RootElement.GetProperty("legacyHardwareId").GetString());
        Assert.Equal("C000000000000005", details.RootElement.GetProperty("hardwareIdV2").GetString());
    }

    [Fact]
    public async Task UnlinkReactivateUnlink_ShouldNotKeepStaleLegacyHardwareId()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        string appId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            appId = lic.ProductId.ToString();
        }

        var firstActivation = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000008",
            AppName = "MultiApp",
            AppId = appId
        });
        Assert.Equal(HttpStatusCode.OK, firstActivation.StatusCode);

        var clientUnlink = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000008",
            AppName = "MultiApp",
            AppId = appId,
            Source = "settings_button"
        });
        Assert.Equal(HttpStatusCode.OK, clientUnlink.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var license = await db.Licenses.Include(l => l.Seats).SingleAsync(l => l.LicenseKey == licenseKey);
            Assert.Null(license.HardwareId);
            Assert.Null(license.ActivationDate);
            Assert.DoesNotContain(license.Seats, s => s.IsActive);
        }

        var secondActivation = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000009",
            AppName = "MultiApp",
            AppId = appId
        });
        Assert.Equal(HttpStatusCode.OK, secondActivation.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var license = await db.Licenses.Include(l => l.Seats).SingleAsync(l => l.LicenseKey == licenseKey);
            Assert.Equal("C000000000000009", license.HardwareId);
            Assert.Contains(license.Seats, s => s.HardwareId == "C000000000000009" && s.IsActive);
            Assert.Contains(license.Seats, s => s.HardwareId == "C000000000000008" && !s.IsActive);
        }

        client.DefaultRequestHeaders.Add("X-Admin-Secret", ProductApiSecret);
        var adminUnlink = await client.DeleteAsync($"/api/admin/licenses/{licenseKey}/seats/C000000000000009");
        Assert.Equal(HttpStatusCode.OK, adminUnlink.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var license = await db.Licenses.Include(l => l.Seats).SingleAsync(l => l.LicenseKey == licenseKey);
            Assert.Null(license.HardwareId);
            Assert.Null(license.ActivationDate);
            Assert.DoesNotContain(license.Seats, s => s.IsActive);
            Assert.Contains(license.Seats, s => s.HardwareId == "C000000000000009" && !s.IsActive);
        }
    }

    [Fact]
    public async Task Deactivate_WithTrustedSettingsSource_ShouldStoreSourceInHistory()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        string appId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            appId = lic.ProductId.ToString();
        }

        var activation = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000010",
            AppName = "MultiApp",
            AppId = appId
        });
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);

        var unlink = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000010",
            AppName = "MultiApp",
            AppId = appId,
            Source = "settings_button"
        });

        Assert.Equal(HttpStatusCode.OK, unlink.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var db = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var license = await db.Licenses.SingleAsync(l => l.LicenseKey == licenseKey);
        var history = await db.LicenseHistories.SingleAsync(h => h.LicenseId == license.Id && h.Action == HistoryActions.UnlinkedApi);
        var details = Assert.IsType<string>(history.Details);
        Assert.Contains("settings_button", details);
        Assert.DoesNotContain("Reset Code", details, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Deactivate_WithoutSource_ShouldClassifyLegacyUnknown_WhenSeatIsNotRecent()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        string appId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            appId = lic.ProductId.ToString();
        }

        var activation = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000011",
            AppName = "MultiApp",
            AppId = appId
        });
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var license = await db.Licenses.Include(l => l.Seats).SingleAsync(l => l.LicenseKey == licenseKey);
            var seat = Assert.Single(license.Seats, s => s.HardwareId == "C000000000000011" && s.IsActive);
            seat.FirstActivatedAt = DateTime.UtcNow.AddMinutes(-10);
            await db.SaveChangesAsync();
        }

        var unlink = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000011",
            AppName = "MultiApp",
            AppId = appId
        });

        Assert.Equal(HttpStatusCode.OK, unlink.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var verifyLicense = await verifyDb.Licenses.SingleAsync(l => l.LicenseKey == licenseKey);
        var history = await verifyDb.LicenseHistories.SingleAsync(h => h.LicenseId == verifyLicense.Id && h.Action == HistoryActions.UnlinkedApi);
        var details = Assert.IsType<string>(history.Details);
        Assert.Contains("legacy_unknown", details);
        Assert.DoesNotContain("Reset Code", details, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Deactivate_WithoutSource_ShouldRejectImmediatePostActivation()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        string appId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            appId = lic.ProductId.ToString();
        }

        var activation = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000012",
            AppName = "MultiApp",
            AppId = appId
        });
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);

        var unlink = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000012",
            AppName = "MultiApp",
            AppId = appId
        });

        Assert.Equal(HttpStatusCode.BadRequest, unlink.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var db = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var license = await db.Licenses.Include(l => l.Seats).SingleAsync(l => l.LicenseKey == licenseKey);
        Assert.Contains(license.Seats, s => s.HardwareId == "C000000000000012" && s.IsActive);
        Assert.False(await db.LicenseHistories.AnyAsync(h => h.LicenseId == license.Id && h.Action == HistoryActions.UnlinkedApi));
    }

    [Fact]
    public async Task Deactivate_WithTrustedUninstallSource_ShouldAllowImmediatePostActivation()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        string appId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            appId = lic.ProductId.ToString();
        }

        var activation = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000013",
            AppName = "MultiApp",
            AppId = appId
        });
        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);

        var unlink = await client.PostAsJsonAsync("/api/activation/deactivate", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000013",
            AppName = "MultiApp",
            AppId = appId,
            Source = "uninstall"
        });

        Assert.Equal(HttpStatusCode.OK, unlink.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var db = verifyScope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var license = await db.Licenses.Include(l => l.Seats).SingleAsync(l => l.LicenseKey == licenseKey);
        Assert.DoesNotContain(license.Seats, s => s.HardwareId == "C000000000000013" && s.IsActive);
        var history = await db.LicenseHistories.SingleAsync(h => h.LicenseId == license.Id && h.Action == HistoryActions.UnlinkedApi);
        var details = Assert.IsType<string>(history.Details);
        Assert.Contains("uninstall", details);
    }

    [Fact]
    public async Task Check_ShouldReturnHardwareMismatch_WhenLegacyHardwareIdMatchesButActiveSeatDiffers()
    {
        var client = _factory.CreateClient();
        string licenseKey;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;

            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            lic.HardwareId = "C000000000000014";
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = lic.Id,
                HardwareId = "C000000000000015",
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-10),
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000014",
            AppName = "MultiApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("HARDWARE_MISMATCH", json.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task TiaHeartbeatFlow_ShouldReturnTerminalRemovedHardware_WhenActivatedSeatIsRemovedByAdmin()
    {
        var client = _factory.CreateClient();
        string licenseKey;
        string appId;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;
            appId = lic.ProductId.ToString();
        }

        var activation = await client.PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000016",
            AppName = "MultiApp",
            AppId = appId
        });

        Assert.Equal(HttpStatusCode.OK, activation.StatusCode);

        var firstHeartbeat = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000016",
            AppName = "MultiApp",
            AppId = appId
        });

        Assert.Equal(HttpStatusCode.OK, firstHeartbeat.StatusCode);
        using (var json = JsonDocument.Parse(await firstHeartbeat.Content.ReadAsStringAsync()))
        {
            Assert.Equal("VALID", GetString(json.RootElement, "status"));
            Assert.False(string.IsNullOrWhiteSpace(GetString(json.RootElement, "licenseFile")));
        }

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            var license = await db.Licenses
                .Include(l => l.Seats)
                .SingleAsync(l => l.LicenseKey == licenseKey);
            var seat = Assert.Single(license.Seats, s => s.HardwareId == "C000000000000016" && s.IsActive);
            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }

        var secondHeartbeat = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000016",
            AppName = "MultiApp",
            AppId = appId
        });

        Assert.Equal(HttpStatusCode.OK, secondHeartbeat.StatusCode);
        using (var json = JsonDocument.Parse(await secondHeartbeat.Content.ReadAsStringAsync()))
        {
            Assert.Equal(RemovedHardwareStatus, GetString(json.RootElement, "status"));
            Assert.Null(GetString(json.RootElement, "licenseFile"));
        }
    }

    [Fact]
    public async Task Check_ShouldAllowLegacyHardwareId_WhenLicenseHasNoSeatHistory()
    {
        var client = _factory.CreateClient();
        string licenseKey;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;

            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            lic.HardwareId = "C000000000000017";
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000017",
            AppName = "MultiApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("VALID", GetString(json.RootElement, "status"));
        Assert.False(string.IsNullOrWhiteSpace(GetString(json.RootElement, "licenseFile")));
    }

    [Fact]
    public async Task Check_ShouldNotFallbackToLegacyHardwareId_WhenSeatHistoryExists()
    {
        var client = _factory.CreateClient();
        string licenseKey;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;

            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            lic.HardwareId = "C000000000000018";
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = lic.Id,
                HardwareId = "C000000000000018",
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-10),
                IsActive = false,
                UnlinkedAt = DateTime.UtcNow.AddMinutes(-1)
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000018",
            AppName = "MultiApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(RemovedHardwareStatus, GetString(json.RootElement, "status"));
        Assert.Null(GetString(json.RootElement, "licenseFile"));
    }

    [Fact]
    public async Task Check_ShouldReturnValid_WhenLicenseAndSeatAreActive()
    {
        var client = _factory.CreateClient();
        string licenseKey;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;

            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            lic.HardwareId = "C000000000000019";
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = lic.Id,
                HardwareId = "C000000000000019",
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-10),
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000019",
            AppName = "MultiApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("VALID", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.String, json.RootElement.GetProperty("licenseFile").ValueKind);
    }

    [Fact]
    public async Task Check_ShouldReject_WhenCurrentHardwareSeatWasUnlinked()
    {
        var client = _factory.CreateClient();
        string licenseKey;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;

            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            lic.HardwareId = "C000000000000020";
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = lic.Id,
                HardwareId = "C000000000000020",
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-10),
                IsActive = false,
                UnlinkedAt = DateTime.UtcNow.AddMinutes(-1)
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000020",
            AppName = "MultiApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(RemovedHardwareStatus, json.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("licenseFile").ValueKind);
    }

    [Fact]
    public async Task Check_ShouldReject_WhenOtherHardwareIsNotActivated()
    {
        var client = _factory.CreateClient();
        string licenseKey;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 1);
            licenseKey = lic.LicenseKey;

            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            lic.HardwareId = "C000000000000019";
            db.LicenseSeats.Add(new LicenseSeat
            {
                LicenseId = lic.Id,
                HardwareId = "C000000000000019",
                FirstActivatedAt = DateTime.UtcNow.AddDays(-1),
                LastCheckInAt = DateTime.UtcNow.AddMinutes(-10),
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000015",
            AppName = "MultiApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("HARDWARE_MISMATCH", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("licenseFile").ValueKind);
    }

    [Fact]
    public async Task Check_ShouldReject_WhenLicenseIsActiveButAllSeatsWereUnlinked()
    {
        var client = _factory.CreateClient();
        string licenseKey;

        using (var scope = _factory.Services.CreateScope())
        {
            var lic = await CreateLicenseAsync(scope.ServiceProvider, 2);
            licenseKey = lic.LicenseKey;

            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            lic.HardwareId = "C000000000000021";
            db.LicenseSeats.AddRange(
                new LicenseSeat
                {
                    LicenseId = lic.Id,
                    HardwareId = "C000000000000021",
                    FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
                    LastCheckInAt = DateTime.UtcNow.AddDays(-1),
                    IsActive = false,
                    UnlinkedAt = DateTime.UtcNow.AddMinutes(-5)
                },
                new LicenseSeat
                {
                    LicenseId = lic.Id,
                    HardwareId = "C000000000000022",
                    FirstActivatedAt = DateTime.UtcNow.AddDays(-2),
                    LastCheckInAt = DateTime.UtcNow.AddDays(-1),
                    IsActive = false,
                    UnlinkedAt = DateTime.UtcNow.AddMinutes(-4)
                });
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/activation/check", new
        {
            LicenseKey = licenseKey,
            HardwareId = "C000000000000021",
            AppName = "MultiApp"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(RemovedHardwareStatus, json.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("licenseFile").ValueKind);
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                return property.Value.ValueKind == JsonValueKind.Null ? null : property.Value.GetString();
        }

        return null;
    }
}

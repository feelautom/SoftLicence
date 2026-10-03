using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001277 lot 2a: the UUID machine identity on activation, check and trial. Endpoint behaviour only
/// (EF InMemory); the relational uniqueness and upsert semantics are covered by
/// <see cref="MachineEvidenceObservationPostgreSqlTests"/>.
/// </summary>
public sealed class MachineIdentityActivationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string AppName = "UuidApp";
    private const string ValidUuid = "4C4C4544-0051-3610-8052-B7C04F4A4E32";
    private const string GenericUuid = "03000200-0400-0500-0006-000700080009";

    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbName = Guid.NewGuid().ToString();

    public MachineIdentityActivationTests(WebApplicationFactory<Program> factory)
    {
        var notifier = new Mock<NotificationService>(
            Mock.Of<IDbContextFactory<LicenseDbContext>>(),
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<NotificationService>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseInMemoryDatabase(_dbName));
                services.AddSingleton(notifier.Object);
            });
        });
    }

    [Fact]
    public async Task Activate_LegacyClient_IsUnchanged_AndStoresNothing()
    {
        var licenseKey = await SeedLicenseAsync();
        var hardwareId = "A1B2C3D4E5F60718";

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation",
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotEqual("DEVICE_REFUSED", await ErrorCodeAsync(response));
        Assert.Empty(await ObservationsAsync());
    }

    [Fact]
    public async Task Activate_ValidUuid_IsAccepted_AndStoresRawEvidence()
    {
        var licenseKey = await SeedLicenseAsync();
        var hardwareId = MachineIdentity.FromUuid(ValidUuid).HardwareId!;

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            AppName,
            AppVersion = "3.0.0",
            SystemUuid = " " + ValidUuid.ToLowerInvariant(),
            MachineEvidence = new { biosSerial = new { status = "Present", values = new[] { "  SN-1 " } } }
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotEqual("DEVICE_REFUSED", await ErrorCodeAsync(response));
        var row = Assert.Single(await ObservationsAsync());
        Assert.Equal(hardwareId, row.HardwareId);
        Assert.Equal(" " + ValidUuid.ToLowerInvariant(), row.SystemUuidRaw);
        Assert.Equal(ValidUuid, row.SystemUuidCanonical);
        Assert.Equal(hardwareId, row.DerivedHardwareId);
        Assert.Null(row.RefusalCode);
        Assert.Contains("\"  SN-1 \"", row.EvidenceJson);
        Assert.Equal("ACTIVATE", row.LastEndpoint);
        Assert.Equal("3.0.0", row.LastAppVersion);
        Assert.Equal(1, row.ObservationCount);
    }

    [Theory]
    [InlineData(GenericUuid, MachineIdentity.RefusalUuidGenericKnown, "AR-04")]
    [InlineData("00000000-0000-0000-0000-000000000000", MachineIdentity.RefusalUuidGenericKnown, "AR-04")]
    [InlineData("not-a-uuid", MachineIdentity.RefusalUuidInvalidFormat, "AR-03")]
    [InlineData("", MachineIdentity.RefusalUuidAbsent, "AR-01")]
    public async Task Activate_RefusedUuid_ReturnsDeviceRefused_WithSupportCodeOnly(string uuid, string expectedReason, string expectedSupportCode)
    {
        var licenseKey = await SeedLicenseAsync();

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation",
            new { LicenseKey = licenseKey, HardwareId = "A1B2C3D4E5F60718", AppName, SystemUuid = uuid });

        Assert.Equal("DEVICE_REFUSED", await ErrorCodeAsync(response));
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(expectedReason, body);
        using (var document = JsonDocument.Parse(body))
            Assert.Contains("(code " + expectedSupportCode + ")", document.RootElement.GetProperty("message").GetString());
        Assert.Equal(expectedReason, Assert.Single(await ObservationsAsync()).RefusalCode);
        Assert.Empty(await ActiveSeatsAsync());
    }

    [Fact]
    public async Task Activate_EvidenceWithoutUuid_IsRefusedAsAbsent()
    {
        var licenseKey = await SeedLicenseAsync();

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation", new
        {
            LicenseKey = licenseKey, HardwareId = "A1B2C3D4E5F60718", AppName,
            MachineEvidence = new { systemUuid = new { status = "Error" } }
        });

        Assert.Equal("DEVICE_REFUSED", await ErrorCodeAsync(response));
        Assert.Equal(MachineIdentity.RefusalUuidAbsent, Assert.Single(await ObservationsAsync()).RefusalCode);
    }

    [Fact]
    public async Task Activate_IdentifierNotDerivedFromUuid_IsRefusedWithAr05()
    {
        var licenseKey = await SeedLicenseAsync();

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation",
            new { LicenseKey = licenseKey, HardwareId = "A1B2C3D4E5F60718", AppName, SystemUuid = ValidUuid });

        Assert.Equal("DEVICE_REFUSED", await ErrorCodeAsync(response));
        using (var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
            Assert.Contains("(code AR-05)", document.RootElement.GetProperty("message").GetString());
        Assert.Empty(await ActiveSeatsAsync());
        var row = Assert.Single(await ObservationsAsync());
        Assert.Equal(MachineIdentity.RefusalIdentifierMismatch, row.RefusalCode);
        Assert.Equal("A1B2C3D4E5F60718", row.HardwareId);
        Assert.Equal(MachineIdentity.FromUuid(ValidUuid).HardwareId, row.DerivedHardwareId);
    }

    [Fact]
    public async Task Activate_NonObjectEvidence_IsDropped_WithoutAffectingDecision()
    {
        var licenseKey = await SeedLicenseAsync();
        var hardwareId = MachineIdentity.FromUuid(ValidUuid).HardwareId!;

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation",
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName, SystemUuid = ValidUuid, MachineEvidence = new[] { 1, 2 } });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(Assert.Single(await ObservationsAsync()).EvidenceJson);
    }

    [Fact]
    public async Task Check_RepeatedIdenticalReport_CountsOnOneRow_AndGenericUuidIsRefused()
    {
        var licenseKey = await SeedLicenseAsync();
        var hardwareId = MachineIdentity.FromUuid(ValidUuid).HardwareId!;
        var client = _factory.CreateClient();
        await client.PostAsJsonAsync("/api/activation",
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName, SystemUuid = ValidUuid });

        await client.PostAsJsonAsync("/api/activation/check",
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName, SystemUuid = ValidUuid });
        var refused = await client.PostAsJsonAsync("/api/activation/check",
            new { LicenseKey = licenseKey, HardwareId = hardwareId, AppName, SystemUuid = GenericUuid });

        using var document = JsonDocument.Parse(await refused.Content.ReadAsStringAsync());
        Assert.Equal("DEVICE_REFUSED", document.RootElement.GetProperty("status").GetString());
        Assert.Equal("AR-04", document.RootElement.GetProperty("supportCode").GetString());
        Assert.Contains("(code AR-04)", document.RootElement.GetProperty("errorMessage").GetString());
        var rows = await ObservationsAsync();
        Assert.Equal(2, rows.Count);
        var accepted = Assert.Single(rows, row => row.RefusalCode is null);
        Assert.Equal(2, accepted.ObservationCount);
        Assert.Equal("CHECK", accepted.LastEndpoint);
    }

    [Fact]
    public async Task Trial_GenericUuid_ReturnsDeviceRefused_AndCreatesNoLicence()
    {
        await SeedLicenseAsync();
        int licencesBefore;
        using (var scope = _factory.Services.CreateScope())
            licencesBefore = await scope.ServiceProvider.GetRequiredService<LicenseDbContext>().Licenses.CountAsync();

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/activation/trial",
            new { HardwareId = "A1B2C3D4E5F60718", AppName, TypeSlug = "TRIAL", SystemUuid = GenericUuid });

        Assert.Equal("DEVICE_REFUSED", await ErrorCodeAsync(response));
        using var after = _factory.Services.CreateScope();
        Assert.Equal(licencesBefore, await after.ServiceProvider.GetRequiredService<LicenseDbContext>().Licenses.CountAsync());
    }

    private static async Task<string?> ErrorCodeAsync(HttpResponseMessage response) =>
        response.Headers.TryGetValues("X-SoftLicence-Error-Code", out var values) ? values.Single() : null;

    private async Task<List<MachineEvidenceObservation>> ObservationsAsync()
    {
        using var scope = _factory.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<LicenseDbContext>()
            .MachineEvidenceObservations.AsNoTracking().ToListAsync();
    }

    private async Task<List<LicenseSeat>> ActiveSeatsAsync()
    {
        using var scope = _factory.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<LicenseDbContext>()
            .LicenseSeats.AsNoTracking().Where(seat => seat.IsActive).ToListAsync();
    }

    private async Task<string> SeedLicenseAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
        var encryption = scope.ServiceProvider.GetRequiredService<EncryptionService>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var keys = LicenseService.GenerateKeys();
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = AppName,
            PrivateKeyXml = encryption.Encrypt(keys.PrivateKey),
            PublicKeyXml = keys.PublicKey,
            ApiSecret = "secret"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(), ProductId = product.Id, Name = "Pro", Slug = "PRO", IsFree = false, DefaultDurationDays = 365
        };
        var trialType = new LicenseType
        {
            Id = Guid.NewGuid(), ProductId = product.Id, Name = "Trial", Slug = "TRIAL", IsFree = true, DefaultDurationDays = 7
        };
        var license = new License
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            LicenseTypeId = type.Id,
            LicenseKey = Guid.NewGuid().ToString("N").ToUpperInvariant(),
            CustomerName = "Uuid User",
            CustomerEmail = "uuid@example.com",
            IsActive = true,
            MaxSeats = 1,
            AllowedVersions = "*"
        };
        db.Products.Add(product);
        db.LicenseTypes.AddRange(type, trialType);
        db.Licenses.Add(license);
        await db.SaveChangesAsync();
        return license.LicenseKey;
    }
}

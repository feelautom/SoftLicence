using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves the paid weekly activity aggregation of TKT-003652 on PostgreSQL, the production provider: the SQL
/// grouping by upper-cased hardware ID and UTC day, the day-level machine attribution across licenses, the
/// paid and status filters, the product scope and the pagination. EF InMemory cannot prove the
/// <c>upper()</c> and <c>date_trunc</c> translations, so every assertion here runs on a migrated clone.
/// </summary>
public sealed class PaidWeeklyActivityPostgreSqlTests
{
    /// <summary>
    /// Seeds paid, free, released, revoked and foreign-product data with mixed-case hardware IDs and checks
    /// that each event lands on exactly the license that owned the machine that day.
    /// </summary>
    [Fact]
    public async Task WeeklyActivity_AttributesMachineDaysToOwningPaidLicense_AndAggregatesInSql()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString)
            .Options;
        var factory = new PostgreSqlContextFactory(options);
        var now = DateTime.UtcNow;
        var ids = await SeedAsync(factory, now);

        var service = new PaidWeeklyActivityAnalyticsService(factory, new MemoryCache(new MemoryCacheOptions()));
        var result = await service.GetForProductIdAsync(ids.ProductId, status: "all", weeks: 12, take: 50);

        // Only the three paid licenses of the product are listed; the Freemium one never appears.
        Assert.Equal(4, result.TotalLicenses);
        Assert.DoesNotContain(result.Licenses, l => l.LicenseId == ids.FreemiumLicenseId);

        var pro = Assert.Single(result.Licenses, l => l.LicenseId == ids.ProLicenseId);
        Assert.Equal("pro@example.invalid", pro.CustomerEmail);
        Assert.DoesNotContain("PRO-KEY-0001-SECRET", pro.LicenseKeyRedacted);
        // Lower-case telemetry IDs match the upper-case seat; the pre-activation failure (3 days before the
        // seat) and the foreign-product rows are respectively included and excluded.
        Assert.Equal(3, pro.WeeklyActivity.Sum(w => w.McpToolCalls));
        Assert.Equal(2, pro.WeeklyActivity.Sum(w => w.LicenseFailures));
        Assert.Equal(1, pro.WeeklyActivity.Sum(w => w.LicensePrompts));
        Assert.Equal(1, pro.WeeklyActivity.Sum(w => w.Errors));
        Assert.Equal(1, pro.WeeklyActivity.Sum(w => w.Startups));
        Assert.Equal(4, pro.WeeklyActivity.Sum(w => w.UsageEvents));
        Assert.Equal(1, pro.WeeklyActivity.Sum(w => w.NewMachines));
        Assert.Contains(pro.WeeklyActivity, w => w.LatestVersion == "2.5.10");
        Assert.All(pro.WeeklyActivity, w => Assert.Matches("^[0-9]{4}-W[0-9]{2}$", w.IsoWeek));
        Assert.All(pro.WeeklyActivity, w => Assert.Equal(DayOfWeek.Monday, w.WeekStartUtc.DayOfWeek));
        Assert.NotNull(pro.LastUsageUtc);
        var seat = Assert.Single(pro.Seats);
        Assert.Equal(16, seat.HardwareIdHash.Length);
        Assert.DoesNotContain("PROMACHINE0001", seat.HardwareIdRedacted);

        // The shared machine belonged to the Freemium license until the paid seat started: only the later
        // usage is attributed to the paid license.
        var handover = Assert.Single(result.Licenses, l => l.LicenseId == ids.HandoverLicenseId);
        Assert.Equal(2, handover.WeeklyActivity.Sum(w => w.UsageEvents));

        // A released seat keeps its machine: failures after the release still show on the departing customer.
        var released = Assert.Single(result.Licenses, l => l.LicenseId == ids.ReleasedLicenseId);
        Assert.Equal(1, released.WeeklyActivity.Sum(w => w.LicenseFailures));
        Assert.Equal(0, released.WeeklyActivity.Sum(w => w.UsageEvents));

        // Status filter and pagination.
        var active = await service.GetForProductIdAsync(ids.ProductId, status: "active", weeks: 12, take: 50);
        Assert.DoesNotContain(active.Licenses, l => l.LicenseId == ids.RevokedLicenseId);
        var secondPage = await service.GetForProductIdAsync(ids.ProductId, status: "all", weeks: 12, skip: 1, take: 1);
        Assert.Equal(4, secondPage.TotalLicenses);
        Assert.Equal(result.Licenses[1].LicenseId, Assert.Single(secondPage.Licenses).LicenseId);
    }

    /// <summary>
    /// Seeds one product with Pro, Freemium, handover, released and revoked licenses plus a foreign product
    /// sharing a hardware ID, and returns the identifiers the assertions need.
    /// </summary>
    private static async Task<SeedIds> SeedAsync(IDbContextFactory<LicenseDbContext> factory, DateTime now)
    {
        await using var db = await factory.CreateDbContextAsync();
        var product = new Product { Id = Guid.NewGuid(), Name = "TKT-003652 weekly", PrivateKeyXml = "p", PublicKeyXml = "p" };
        var foreign = new Product { Id = Guid.NewGuid(), Name = "TKT-003652 foreign", PrivateKeyXml = "p", PublicKeyXml = "p" };
        var pro = new LicenseType { Id = Guid.NewGuid(), Product = product, Name = "TIA Connect Pro", Slug = "TIA-CONNECT-PRO" };
        var free = new LicenseType { Id = Guid.NewGuid(), Product = product, Name = "TIA Connect Freemium", Slug = "TIA-CONNECT-FREEMIUM", IsFree = true };
        var foreignType = new LicenseType { Id = Guid.NewGuid(), Product = foreign, Name = "Other Pro", Slug = "OTHER-PRO" };

        var proLicense = NewLicense(product, pro, "PRO-KEY-0001-SECRET", "pro@example.invalid", now.AddDays(-30));
        var freemium = NewLicense(product, free, "FREE-KEY-0001", "free@example.invalid", now.AddDays(-60));
        var handover = NewLicense(product, pro, "PRO-KEY-0002", "handover@example.invalid", now.AddDays(-20));
        var released = NewLicense(product, pro, "PRO-KEY-0003", "released@example.invalid", now.AddDays(-25));
        var revoked = NewLicense(product, pro, "PRO-KEY-0004", "revoked@example.invalid", now.AddDays(-15));
        revoked.IsActive = false;
        revoked.RevokedAt = now.AddDays(-1);
        var foreignLicense = NewLicense(foreign, foreignType, "OTHER-KEY-0001", "other@example.invalid", now.AddDays(-30));

        db.AddRange(product, foreign, pro, free, foreignType, proLicense, freemium, handover, released, revoked, foreignLicense);
        db.AddRange(
            NewSeat(proLicense, "PROMACHINE0001", now.AddDays(-14)),
            NewSeat(freemium, "SHAREDMACHINE01", now.AddDays(-50)),
            NewSeat(handover, "SHAREDMACHINE01", now.AddDays(-5)),
            NewSeat(released, "RELEASEDMACH01", now.AddDays(-24), unlinkedAt: now.AddDays(-10)),
            NewSeat(foreignLicense, "PROMACHINE0001", now.AddDays(-30)));

        db.AddRange(
            // Pro machine, telemetry sent in lower case.
            Telemetry(product, "promachine0001", "LicenseActivation_InvalidKey", now.AddDays(-17), "2.5.9"),
            Telemetry(product, "promachine0001", "Startup_AppStarted", now.AddDays(-12), "2.5.9"),
            Telemetry(product, "promachine0001", "Mcp_ToolCall", now.AddDays(-11), "2.5.10"),
            Telemetry(product, "promachine0001", "Mcp_ToolCall", now.AddDays(-11), "2.5.10"),
            Telemetry(product, "promachine0001", "Mcp_ToolCall", now.AddDays(-11), "2.5.10"),
            Telemetry(product, "PROMACHINE0001", "Block_Export", now.AddDays(-9), "2.5.10"),
            Telemetry(product, "PROMACHINE0001", "Mcp_ToolResult", now.AddDays(-9), "2.5.10"),
            Telemetry(product, "PROMACHINE0001", "LicenseCache_HardwareMismatch", now.AddDays(-3), "2.5.10"),
            Telemetry(product, "PROMACHINE0001", "LicensePrompt_Shown", now.AddDays(-3), "2.5.10"),
            Telemetry(product, "PROMACHINE0001", "Unhandled", now.AddDays(-2), "2.5.10", TelemetryType.Error),
            // Same machine on the foreign product: excluded by the product scope.
            Telemetry(foreign, "PROMACHINE0001", "Mcp_ToolCall", now.AddDays(-2), "9.9.9"),
            // Way before the seat (beyond the 7-day grace): owned by the foreign seat only, never by Pro.
            Telemetry(product, "PROMACHINE0001", "Block_Import", now.AddDays(-40), "2.5.1"),
            // Shared machine: Freemium days, then the paid seat.
            Telemetry(product, "SHAREDMACHINE01", "Block_Export", now.AddDays(-20), "2.5.10"),
            Telemetry(product, "SHAREDMACHINE01", "Compile_Success", now.AddDays(-2), "2.5.10"),
            Telemetry(product, "sharedmachine01", "Tag_Create", now.AddDays(-1), "2.5.10"),
            // Released seat: a license failure after the release.
            Telemetry(product, "RELEASEDMACH01", "Startup_NoLicenseDetected", now.AddDays(-4), "2.4.806"));

        await db.SaveChangesAsync();
        return new SeedIds(product.Id, proLicense.Id, freemium.Id, handover.Id, released.Id, revoked.Id);
    }

    /// <summary>Builds an active, activated license of the given type.</summary>
    private static License NewLicense(Product product, LicenseType type, string key, string email, DateTime createdAt) => new()
    {
        Id = Guid.NewGuid(),
        Product = product,
        Type = type,
        LicenseTypeId = type.Id,
        LicenseKey = key,
        CustomerName = "Synthetic TKT-003652",
        CustomerEmail = email,
        CreationDate = createdAt,
        ActivationDate = createdAt,
        IsActive = true,
        MaxSeats = 2
    };

    /// <summary>Builds a seat, released when <paramref name="unlinkedAt"/> is given.</summary>
    private static LicenseSeat NewSeat(License license, string hardwareId, DateTime firstActivatedAt, DateTime? unlinkedAt = null) => new()
    {
        Id = Guid.NewGuid(),
        License = license,
        LicenseId = license.Id,
        HardwareId = hardwareId,
        FirstActivatedAt = firstActivatedAt,
        LastCheckInAt = firstActivatedAt,
        IsActive = unlinkedAt == null,
        UnlinkedAt = unlinkedAt
    };

    /// <summary>Builds one telemetry record with an exact hardware ID spelling.</summary>
    private static TelemetryRecord Telemetry(
        Product product,
        string hardwareId,
        string eventName,
        DateTime timestamp,
        string version,
        TelemetryType type = TelemetryType.Event) => new()
    {
        Id = Guid.NewGuid(),
        Product = product,
        HardwareId = hardwareId,
        AppName = "TIAConnect",
        EventName = eventName,
        Type = type,
        Version = version,
        Timestamp = timestamp
    };

    /// <summary>Identifiers produced by <see cref="SeedAsync"/>.</summary>
    private sealed record SeedIds(
        Guid ProductId,
        Guid ProLicenseId,
        Guid FreemiumLicenseId,
        Guid HandoverLicenseId,
        Guid ReleasedLicenseId,
        Guid RevokedLicenseId);

    /// <summary>Creates independent contexts over the isolated clone.</summary>
    private sealed class PostgreSqlContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);

        /// <inheritdoc />
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>Owns one isolated migrated PostgreSQL database and drops it during disposal.</summary>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        /// <summary>Gets the isolated ticket-owned database connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Clones a uniquely named database from the shared current-schema model.</summary>
        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("paid_weekly");
            return new PostgreSqlProvision(clone.MaintenanceConnectionString, clone.ConnectionString, clone.DatabaseName);
        }

        /// <summary>Drops the exact generated database even when an assertion fails.</summary>
        public async ValueTask DisposeAsync() =>
            await PostgreSqlModelDatabase.DropAsync(maintenanceConnectionString, database);
    }
}

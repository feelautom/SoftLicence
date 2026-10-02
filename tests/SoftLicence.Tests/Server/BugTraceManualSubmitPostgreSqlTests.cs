using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves manual BugTrace seat and resolved-alias authorization against PostgreSQL, including the
/// production provider's exact string equality and same-licence relational predicates.
/// </summary>
public sealed class BugTraceManualSubmitPostgreSqlTests
{
    private const string ProjectId = "9f3c8fea-8740-42af-be83-6f527c6d102a";

    /// <summary>
    /// Executes the direct-seat and alias-seat predicates on PostgreSQL and proves that a resolved
    /// foreign seat remains rejected by the controller's independent authority recheck.
    /// </summary>
    [Fact]
    public async Task SeatAndResolvedAliasPredicates_EnforceActiveSameLicenseAuthority()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString)
            .Options;
        var factory = new PostgreSqlContextFactory(options);
        var fixture = await SeedAuthorityAsync(factory);
        var aliases = new Mock<IHardwareAuthorityAliasResolver>();
        aliases
            .Setup(resolver => resolver.ResolveAsync(
                It.IsAny<LicenseDbContext>(),
                fixture.ProductId,
                fixture.LicenseId,
                fixture.AliasHardwareId,
                HardwareAuthorityResolutionIntent.StatusCheck,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateResolution(
                fixture.AliasHardwareId,
                fixture.AliasSeatHardwareId,
                fixture.AliasSeatId));
        aliases
            .Setup(resolver => resolver.ResolveAsync(
                It.IsAny<LicenseDbContext>(),
                fixture.ProductId,
                fixture.LicenseId,
                fixture.ForeignAliasHardwareId,
                HardwareAuthorityResolutionIntent.StatusCheck,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateResolution(
                fixture.ForeignAliasHardwareId,
                fixture.ForeignSeatHardwareId,
                fixture.ForeignSeatId));

        using var cache = new MemoryCache(new MemoryCacheOptions());
        var proxy = new FakeBugTraceProxyService();
        var controller = CreateController(factory, aliases.Object, proxy, cache);

        Assert.IsType<OkObjectResult>(await controller.Submit(
            CreateRequest(fixture.LicenseKey, fixture.DirectSeatHardwareId),
            CancellationToken.None));
        Assert.IsType<OkObjectResult>(await controller.Submit(
            CreateRequest(fixture.LicenseKey, fixture.AliasHardwareId),
            CancellationToken.None));
        Assert.IsType<BadRequestObjectResult>(await controller.Submit(
            CreateRequest(fixture.LicenseKey, fixture.ForeignAliasHardwareId),
            CancellationToken.None));
        Assert.Equal(2, proxy.SubmittedTickets.Count);
    }

    /// <summary>Creates a controller whose authority reads use the isolated PostgreSQL database.</summary>
    /// <param name="factory">PostgreSQL context factory.</param>
    /// <param name="aliases">Deterministic alias authority used to exercise the consuming predicate.</param>
    /// <param name="proxy">Recording provider relay.</param>
    /// <param name="cache">Isolated rate-limit state.</param>
    /// <returns>A controller with a valid request context for audit annotations.</returns>
    private static BugTraceController CreateController(
        IDbContextFactory<LicenseDbContext> factory,
        IHardwareAuthorityAliasResolver aliases,
        IBugTraceProxyService proxy,
        IMemoryCache cache)
    {
        var controller = new BugTraceController(
            proxy,
            Mock.Of<IBugTraceAutoReportService>(),
            factory,
            aliases,
            cache,
            NullLogger<BugTraceController>.Instance);
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    /// <summary>Builds one valid manual support payload around exact synthetic authority identifiers.</summary>
    /// <param name="licenseKey">Selected licence boundary.</param>
    /// <param name="hardwareId">Direct or legacy machine identity.</param>
    /// <returns>A bounded request accepted by the controller's content validation.</returns>
    private static BugTraceSubmitRequest CreateRequest(string licenseKey, string hardwareId) => new()
    {
        LicenseKey = licenseKey,
        HardwareId = hardwareId,
        ProjectId = ProjectId,
        Ticket = new BugTraceTicketBody { Title = "PostgreSQL proof", Description = "Synthetic regression" }
    };

    /// <summary>Builds authenticated alias evidence whose seat is still revalidated relationally.</summary>
    /// <param name="submittedHardwareId">Exact legacy wire identity.</param>
    /// <param name="effectiveHardwareId">Exact canonical seat identity.</param>
    /// <param name="seatId">Claimed canonical seat.</param>
    /// <returns>A resolved result suitable only as evidence for the controller recheck.</returns>
    private static HardwareAuthorityResolution CreateResolution(
        string submittedHardwareId,
        string effectiveHardwareId,
        Guid seatId) => new(
            submittedHardwareId,
            effectiveHardwareId,
            Guid.NewGuid(),
            HardwareAuthorityResolutionStatus.Resolved,
            LicenseSeatId: seatId);

    /// <summary>Seeds two licence boundaries and the seats needed for positive and foreign proofs.</summary>
    /// <param name="factory">Factory bound to the isolated migrated database.</param>
    /// <returns>Opaque relational identifiers and synthetic canonical hardware values.</returns>
    private static async Task<AuthorityFixture> SeedAuthorityAsync(IDbContextFactory<LicenseDbContext> factory)
    {
        await using var db = await factory.CreateDbContextAsync();
        var product = new Product
        {
            Id = Guid.NewGuid(),
            Name = "TKT-000893 PostgreSQL proof",
            PrivateKeyXml = "test-private-placeholder",
            PublicKeyXml = "test-public-placeholder"
        };
        var type = new LicenseType
        {
            Id = Guid.NewGuid(),
            Product = product,
            Name = "TKT-000893 test type",
            Slug = "TKT893-PG"
        };
        var license = new License
        {
            Id = Guid.NewGuid(),
            Product = product,
            Type = type,
            LicenseTypeId = type.Id,
            LicenseKey = "TKT893-POSTGRES-PRIMARY",
            CustomerName = "Synthetic test",
            CustomerEmail = "tkt893-primary@example.invalid",
            HardwareId = "AAAABBBBCCCCDDDD",
            IsActive = true,
            MaxSeats = 2
        };
        var foreignLicense = new License
        {
            Id = Guid.NewGuid(),
            Product = product,
            Type = type,
            LicenseTypeId = type.Id,
            LicenseKey = "TKT893-POSTGRES-FOREIGN",
            CustomerName = "Synthetic foreign test",
            CustomerEmail = "tkt893-foreign@example.invalid",
            HardwareId = "BBBBCCCCDDDDEEEE",
            IsActive = true,
            MaxSeats = 1
        };
        var directSeat = new LicenseSeat
        {
            Id = Guid.NewGuid(),
            License = license,
            LicenseId = license.Id,
            HardwareId = "1111222233334444",
            IsActive = true
        };
        var aliasSeat = new LicenseSeat
        {
            Id = Guid.NewGuid(),
            License = license,
            LicenseId = license.Id,
            HardwareId = "ABCDEF0123456789",
            IsActive = true
        };
        var foreignSeat = new LicenseSeat
        {
            Id = Guid.NewGuid(),
            License = foreignLicense,
            LicenseId = foreignLicense.Id,
            HardwareId = "CDEF0123456789AB",
            IsActive = true
        };
        db.AddRange(product, type, license, foreignLicense, directSeat, aliasSeat, foreignSeat);
        await db.SaveChangesAsync();
        return new AuthorityFixture(
            product.Id,
            license.Id,
            license.LicenseKey,
            directSeat.HardwareId,
            "1234567890ABCDEF",
            aliasSeat.Id,
            aliasSeat.HardwareId,
            "234567890ABCDEF1",
            foreignSeat.Id,
            foreignSeat.HardwareId);
    }

    /// <summary>Owns immutable authority values shared across the PostgreSQL assertions.</summary>
    private sealed record AuthorityFixture(
        Guid ProductId,
        Guid LicenseId,
        string LicenseKey,
        string DirectSeatHardwareId,
        string AliasHardwareId,
        Guid AliasSeatId,
        string AliasSeatHardwareId,
        string ForeignAliasHardwareId,
        Guid ForeignSeatId,
        string ForeignSeatHardwareId);

    /// <summary>Creates independent contexts for each controller authority read.</summary>
    private sealed class PostgreSqlContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);

        /// <inheritdoc />
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>Owns one isolated migrated PostgreSQL database and force-drops it during disposal.</summary>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        /// <summary>Gets the isolated ticket-owned database connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Creates and migrates a uniquely named database from the test-only provider authority.</summary>
        /// <returns>An owner that guarantees exact database cleanup.</returns>
        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000893 PostgreSQL tests.");

            var database = "tkt893_bugtrace_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            var target = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString;
            try
            {
                await using var db = new LicenseDbContext(
                    new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options);
                await db.GetService<IMigrator>().MigrateAsync();
                return new PostgreSqlProvision(maintenance, target, database);
            }
            catch
            {
                await DropDatabaseAsync(maintenance, database);
                throw;
            }
        }

        /// <summary>Drops the exact generated database even when a relational assertion fails.</summary>
        public async ValueTask DisposeAsync() =>
            await DropDatabaseAsync(maintenanceConnectionString, database);

        /// <summary>Clears provider pools and removes one generated database name, never caller input.</summary>
        /// <param name="maintenanceConnectionString">Test-only maintenance authority.</param>
        /// <param name="database">Internally generated lowercase database identifier.</param>
        private static async Task DropDatabaseAsync(string maintenanceConnectionString, string database)
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenanceConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)";
            await command.ExecuteNonQueryAsync();
        }
    }
}

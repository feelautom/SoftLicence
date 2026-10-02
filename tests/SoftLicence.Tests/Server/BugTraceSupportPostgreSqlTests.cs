using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves SUP product, customer, revocation and key lookup boundaries on isolated PostgreSQL 17.</summary>
public sealed class BugTraceSupportPostgreSqlTests
{
    /// <summary>Expired, unexpired and perpetual licences share support eligibility; product/customer and revocation checks remain Desktop-relay authority only.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    public async Task ProductCustomerAndRevocation_EnforceRelationalAuthority(int expirationDays)
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var factory = new PostgreSqlContextFactory(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(provision.ConnectionString).Options);
        var product = new Product { Name = "TKT871 synthetic", PrivateKeyXml = "synthetic", PublicKeyXml = "synthetic" };
        var foreign = new Product { Name = "TKT871 foreign", PrivateKeyXml = "synthetic", PublicKeyXml = "synthetic" };
        var type = new LicenseType { Product = product, Name = "Synthetic", Slug = "TKT871" };
        var license = new License { Product = product, Type = type, LicenseKey = "SUP871-PG-LOCAL", CustomerEmail = "synthetic@example.invalid", HardwareId = "OLD", IsActive = true };
        license.ExpirationDate = expirationDays == 0 ? null : DateTime.UtcNow.AddDays(expirationDays);
        var foreignType = new LicenseType { Product = foreign, Name = "Foreign", Slug = "TKT871-FOREIGN" };
        var foreignLicense = new License { Product = foreign, Type = foreignType, LicenseKey = "SUP871-PG-FOREIGN", CustomerEmail = license.CustomerEmail, IsActive = true };
        await using (var db = factory.CreateDbContext())
        {
            db.AddRange(product, foreign, type, license, foreignType, foreignLicense);
            await db.SaveChangesAsync();
        }
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["BUGTRACE_SUPPORT_PRODUCT_ID"] = product.Id.ToString("D") }).Build();
        var proxy = new FakeBugTraceProxyService();
        var controller = new BugTraceController(proxy, Mock.Of<IBugTraceAutoReportService>(), factory,
            Mock.Of<IHardwareAuthorityAliasResolver>(), cache, NullLogger<BugTraceController>.Instance, config, new BugTraceSupportQuota())
        { ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() } };
        controller.Request.Headers["Idempotency-Key"] = "synthetic-postgres-0001";
        var payload = new BugTraceSupportCaseCreateRequest { LicenseKey = " sup871-pg-local ", HardwareId = "NEW", ProjectId = proxy.ExpectedProjectId,
            ReporterEmail = " SYNTHETIC@example.invalid ", SupportCase = new() { Title = "Synthetic", Description = "Synthetic body" } };
        Assert.Equal(201, Assert.IsType<ObjectResult>(await controller.CreateSupportCase(payload, default)).StatusCode);
        payload.ReporterEmail = "foreign@example.invalid";
        Assert.Equal(403, Assert.IsType<ObjectResult>(await controller.CreateSupportCase(payload, default)).StatusCode);
        payload.ReporterEmail = license.CustomerEmail;
        payload.LicenseKey = foreignLicense.LicenseKey;
        Assert.Equal(403, Assert.IsType<ObjectResult>(await controller.CreateSupportCase(payload, default)).StatusCode);
        await using (var db = factory.CreateDbContext())
        {
            var stored = await db.Licenses.SingleAsync(item => item.Id == license.Id);
            stored.IsActive = false;
            await db.SaveChangesAsync();
        }
        payload.LicenseKey = license.LicenseKey;
        Assert.Equal(403, Assert.IsType<ObjectResult>(await controller.CreateSupportCase(payload, default)).StatusCode);
        Assert.Single(proxy.CreatedSupportCases);
    }

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
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000871 PostgreSQL tests.");

            var database = "tkt871_support_" + Guid.NewGuid().ToString("N");
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

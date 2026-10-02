using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Globalization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves that the existing provider provisioning endpoint persists one explicit commercial subject
/// and the complete product-scoped ownership batch in the same PostgreSQL transaction.
/// </summary>
public sealed class CommercialSubjectProvisioningPostgreSqlTests
{
    private const string GlobalSecret = "tkt780-provider-secret";

    /// <summary>
    /// Establishes the causal TKT-000780 contract: one caller-supplied opaque subject owns every
    /// license in the newly provisioned batch, without deriving authority from customer metadata.
    /// </summary>
    [Fact]
    public async Task Provisioning_ExplicitCommercialSubjectPersistsOneSubjectAndWholeBatchOwnership()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        var productName = "tkt780-product-" + Guid.NewGuid().ToString("N");
        await SeedProductAsync(factory.Services, productName);

        var subjectId = Guid.NewGuid();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        using var response = await client.PostAsJsonAsync("/api/admin/licenses", new
        {
            ProductName = productName,
            CustomerName = "Presentation only",
            CustomerEmail = "presentation@example.test",
            TypeSlug = "TKT780-PRO",
            Reference = "TKT780-BATCH-001",
            CommercialSubjectId = subjectId,
            Quantity = 2
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        var productId = await db.Products.Where(item => item.Name == productName).Select(item => item.Id).SingleAsync();
        var licenseIds = await db.Licenses.Where(item => item.ProductId == productId).Select(item => item.Id).ToListAsync();

        Assert.Equal(2, licenseIds.Count);
        Assert.Equal(1, await db.RuntimeRecoveryCommercialSubjects.CountAsync(item =>
            item.ProductId == productId && item.Id == subjectId));
        Assert.Equal(2, await db.RuntimeRecoveryCommercialOwnerships.CountAsync(item =>
            item.ProductId == productId
            && item.OwnerSubjectId == subjectId
            && item.State == "ACTIVE"
            && licenseIds.Contains(item.LicenseId)));
        var ledger = await db.LicenseProvisioningRequests.SingleAsync(item =>
            item.Reference == "TKT780-BATCH-001");
        Assert.Equal(subjectId, ledger.CommercialSubjectId);
        Assert.Equal(LicenseProvisioningRequest.ProviderAdminApiProvenance, ledger.AuthorityProvenance);
        Assert.Matches("^[0-9a-f]{64}$", ledger.RequestHash);
    }

    /// <summary>
    /// Proves PostgreSQL replay accepts only canonical lowercase or the exact historical uppercase
    /// representation of the same digest, without widening comparison to mixed or malformed text.
    /// </summary>
    [Fact]
    public async Task Provisioning_PostgreSqlHistoricalUppercaseReplaysWhileMixedAndUnicodeFailClosed()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        const string productName = "tkt800-deterministic-hash-compatibility";
        var productId = await SeedProductAsync(
            factory.Services,
            productName,
            Guid.Parse("80000000-0000-0000-0000-000000000020"),
            Guid.Parse("80000000-0000-0000-0000-000000000021"));
        var payload = new ProvisioningPayload(
            productName, "Presentation only", "hash-contract@example.test", "TKT780-PRO",
            "TKT800-PG-HASH-COMPATIBILITY", Guid.Parse("80000000-0000-0000-0000-000000000022"), 1);

        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        using var first = await client.PostAsJsonAsync("/api/admin/licenses", payload);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        var ledger = await db.LicenseProvisioningRequests.SingleAsync(item => item.Reference == payload.Reference);
        Assert.Matches("^[0-9a-f]{64}$", ledger.RequestHash);
        ledger.RequestHash = ledger.RequestHash.ToUpperInvariant();
        await db.SaveChangesAsync();

        using var uppercaseReplay = await client.PostAsJsonAsync("/api/admin/licenses", payload);
        Assert.Equal(HttpStatusCode.OK, uppercaseReplay.StatusCode);

        var mixedHash = ledger.RequestHash.ToCharArray();
        var hexadecimalLetter = Array.FindIndex(mixedHash, character => character is >= 'A' and <= 'F');
        Assert.True(hexadecimalLetter >= 0, "The deterministic compatibility fixture must contain a hexadecimal letter.");
        mixedHash[hexadecimalLetter] = char.ToLowerInvariant(mixedHash[hexadecimalLetter]);
        var rejectedHashes = new[]
        {
            new string(mixedHash),
            "Ａ" + ledger.RequestHash[1..],
            new string('A', 63),
            new string('G', 64),
            new string(' ', 64),
            string.Empty
        };
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("tr-TR");
            foreach (var rejectedHash in rejectedHashes)
            {
                ledger.RequestHash = rejectedHash;
                await db.SaveChangesAsync();
                using var rejectedReplay = await client.PostAsJsonAsync("/api/admin/licenses", payload);
                Assert.Equal(HttpStatusCode.Conflict, rejectedReplay.StatusCode);
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }

        Assert.Equal(1, await db.Licenses.CountAsync(item => item.ProductId == productId));
        Assert.Equal(1, await db.LicenseProvisioningRequests.CountAsync(item => item.ProductId == productId));
    }

    /// <summary>
    /// Proves concurrent exact retries converge on one frozen batch while subject and product
    /// divergence fail closed without creating an additional subject, license, ownership, or ledger.
    /// </summary>
    [Fact]
    public async Task Provisioning_ConcurrentReplayAndDivergenceConvergeOnOneFrozenBatch()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        var firstProduct = "tkt780-replay-a-" + Guid.NewGuid().ToString("N");
        var secondProduct = "tkt780-replay-b-" + Guid.NewGuid().ToString("N");
        var firstProductId = await SeedProductAsync(factory.Services, firstProduct);
        var secondProductId = await SeedProductAsync(factory.Services, secondProduct);
        var subjectId = Guid.NewGuid();
        var payload = new ProvisioningPayload(
            firstProduct, "Presentation A", "presentation-a@example.test", "TKT780-PRO",
            "TKT780-CONCURRENT-001", subjectId, 2);

        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        var responses = await Task.WhenAll(Enumerable.Range(0, 4)
            .Select(_ => client.PostAsJsonAsync("/api/admin/licenses", payload)));
        try
        {
            Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
            var batches = new List<string[]>();
            foreach (var response in responses)
            {
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                batches.Add(json.RootElement.GetProperty("licenseKeys").EnumerateArray()
                    .Select(item => item.GetString()!).ToArray());
            }
            Assert.All(batches.Skip(1), batch => Assert.Equal(batches[0], batch));
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }

        using var subjectConflict = await client.PostAsJsonAsync("/api/admin/licenses", payload with
        {
            CommercialSubjectId = Guid.NewGuid()
        });
        using var productConflict = await client.PostAsJsonAsync("/api/admin/licenses", payload with
        {
            ProductName = secondProduct
        });
        Assert.Equal(HttpStatusCode.Conflict, subjectConflict.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, productConflict.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        Assert.Equal(1, await db.LicenseProvisioningRequests.CountAsync(item =>
            item.Reference == payload.Reference));
        Assert.Equal(1, await db.RuntimeRecoveryCommercialSubjects.CountAsync(item =>
            item.ProductId == firstProductId && item.Id == subjectId));
        Assert.Equal(2, await db.Licenses.CountAsync(item => item.ProductId == firstProductId));
        Assert.Equal(2, await db.RuntimeRecoveryCommercialOwnerships.CountAsync(item =>
            item.ProductId == firstProductId && item.OwnerSubjectId == subjectId));
        Assert.False(await db.Licenses.AnyAsync(item => item.ProductId == secondProductId));
        Assert.False(await db.RuntimeRecoveryCommercialSubjects.AnyAsync(item => item.ProductId == secondProductId));
    }

    /// <summary>
    /// Proves a relational failure while inserting an ownership rolls back the subject, complete
    /// license batch, idempotency ledger, and every ownership as one PostgreSQL transaction.
    /// </summary>
    [Fact]
    public async Task Provisioning_OwnershipFailureRollsBackWholeBatch()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        var productName = "tkt780-rollback-" + Guid.NewGuid().ToString("N");
        var productId = await SeedProductAsync(factory.Services, productName);
        var subjectId = Guid.NewGuid();
        await using (var connection = new NpgsqlConnection(provision.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $$"""
                CREATE FUNCTION tkt780_reject_owned_subject() RETURNS trigger LANGUAGE plpgsql AS $fn$
                BEGIN
                    IF NEW."OwnerSubjectId" = '{{subjectId:D}}'::uuid THEN
                        RAISE EXCEPTION 'TKT-000780 injected ownership failure' USING ERRCODE = '23514';
                    END IF;
                    RETURN NEW;
                END;
                $fn$;
                CREATE TRIGGER tkt780_reject_owned_subject
                BEFORE INSERT ON public."RuntimeRecoveryCommercialOwnerships"
                FOR EACH ROW EXECUTE FUNCTION tkt780_reject_owned_subject();
                """;
            await command.ExecuteNonQueryAsync();
        }

        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        HttpResponseMessage? response = null;
        Exception? transportFailure = null;
        try
        {
            response = await client.PostAsJsonAsync("/api/admin/licenses", new ProvisioningPayload(
                productName, "Presentation rollback", "rollback@example.test", "TKT780-PRO",
                "TKT780-ROLLBACK-001", subjectId, 2));
        }
        catch (Exception exception)
        {
            transportFailure = exception;
        }
        Assert.True(transportFailure != null || response is { IsSuccessStatusCode: false });
        response?.Dispose();

        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        Assert.False(await db.LicenseProvisioningRequests.AnyAsync(item => item.ProductId == productId));
        Assert.False(await db.RuntimeRecoveryCommercialSubjects.AnyAsync(item => item.ProductId == productId));
        Assert.False(await db.Licenses.AnyAsync(item => item.ProductId == productId));
        Assert.False(await db.RuntimeRecoveryCommercialOwnerships.AnyAsync(item => item.ProductId == productId));
    }

    /// <summary>Builds a provider-authenticated HTTP host backed by the isolated PostgreSQL database.</summary>
    private static WebApplicationFactory<Program> CreateFactory(string connectionString) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", GlobalSecret);
            builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connectionString));
            });
        });

    /// <summary>Seeds only the product and license type required by the existing provisioning writer.</summary>
    /// <param name="services">The isolated provider service collection.</param>
    /// <param name="productName">The exact product name.</param>
    /// <param name="productId">An optional deterministic product identifier.</param>
    /// <param name="typeId">An optional deterministic license-type identifier.</param>
    /// <returns>The persisted product identifier.</returns>
    private static async Task<Guid> SeedProductAsync(
        IServiceProvider services,
        string productName,
        Guid? productId = null,
        Guid? typeId = null)
    {
        await using var scope = services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        var product = new Product
        {
            Id = productId ?? Guid.NewGuid(),
            Name = productName,
            ApiSecret = "tkt780-product-secret"
        };
        db.AddRange(product, new LicenseType
        {
            Id = typeId ?? Guid.NewGuid(),
            Product = product,
            Name = "TKT-780 Pro",
            Slug = "TKT780-PRO",
            DefaultMaxSeats = 1
        });
        await db.SaveChangesAsync();
        return product.Id;
    }

    /// <summary>Represents the exact provider-owned provisioning payload used by relational retries.</summary>
    private sealed record ProvisioningPayload(
        string ProductName,
        string CustomerName,
        string CustomerEmail,
        string TypeSlug,
        string Reference,
        Guid CommercialSubjectId,
        int Quantity);

    /// <summary>Owns one isolated PostgreSQL database and removes it after each relational proof.</summary>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;

        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000780 PostgreSQL tests.");

            var database = "tkt780_provisioning_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured) { Database = "postgres" }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = $"CREATE DATABASE \"{database}\"";
                await command.ExecuteNonQueryAsync();
            }

            var target = new NpgsqlConnectionStringBuilder(configured) { Database = database }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options;
            await using (var db = new LicenseDbContext(options))
                await db.Database.MigrateAsync();
            return new PostgreSqlProvision(maintenance, target, database);
        }

        public async ValueTask DisposeAsync()
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

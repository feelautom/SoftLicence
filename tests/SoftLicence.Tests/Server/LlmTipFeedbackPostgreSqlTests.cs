using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003573 relational proof on PostgreSQL 17: a concurrent burst of usage events is stored in
/// full, linked to the product resolved by the production <c>lower(Name) = lower(@appName)</c>
/// predicate, and the product is looked up once instead of once per event.
/// </summary>
public sealed class LlmTipFeedbackPostgreSqlTests
{
    /// <summary>
    /// Production case of 10/11/2026: a client sent several <c>llm_tip_searched</c> events per second
    /// and every one paid a product lookup before its insert. After one warm-up event the burst must
    /// issue no product query, store every event and raise no error.
    /// </summary>
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task ConcurrentUsageBurst_StoresEveryEvent_AndResolvesTheProductOnlyOnce()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("llmtipburst");
        try
        {
            // 16 sessions at most: the complete suite shares a server limited to 100 connections.
            var connectionString = new NpgsqlConnectionStringBuilder(clone.ConnectionString) { MaxPoolSize = 16 }
                .ConnectionString;
            var productQueries = new ProductQueryCounter();
            var factory = new CountingDbContextFactory(connectionString, productQueries);
            var productId = Guid.NewGuid();
            await using (var seed = factory.CreateDbContext())
            {
                seed.Products.Add(new Product
                {
                    Id = productId,
                    Name = "BurstApp",
                    PrivateKeyXml = "key",
                    PublicKeyXml = "key",
                    ApiSecret = "secret-burst"
                });
                await seed.SaveChangesAsync();
            }

            var service = new LlmTipFeedbackService(factory, productIdCache: new LlmTipProductIdCache());
            // Lower-case spelling on purpose: the match must come from the relational predicate.
            await service.SaveUsageAsync(Usage("burstapp", 0));
            Assert.Equal(1, productQueries.Count);

            const int burstSize = 120;
            var results = await Task.WhenAll(Enumerable.Range(1, burstSize)
                .Select(index => service.SaveUsageAsync(Usage("burstapp", index))));

            Assert.All(results, result => Assert.Equal("accepted", result.Status));
            Assert.Equal(1, productQueries.Count);
            await using var db = factory.CreateDbContext();
            var rows = await db.LlmTipFeedbackEvents.AsNoTracking().ToListAsync();
            Assert.Equal(burstSize + 1, rows.Count);
            Assert.All(rows, row => Assert.Equal(productId, row.ProductId));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await PostgreSqlModelDatabase.DropAsync(clone.MaintenanceConnectionString, clone.DatabaseName);
        }
    }

    /// <summary>Builds one valid search event; <paramref name="index"/> only varies its timestamp.</summary>
    private static LlmTipFeedbackUsageRequest Usage(string appName, int index) => new()
    {
        Timestamp = DateTime.UtcNow.AddMilliseconds(index),
        AppName = appName,
        Version = "2.5.354",
        SchemaVersion = "1",
        EventName = "llm_tip_searched",
        Properties = new Dictionary<string, string> { ["Category"] = "lad" }
    };

    /// <summary>
    /// Counts commands that read the <c>Products</c> table, i.e. product lookups, thread-safely.
    /// </summary>
    private sealed class ProductQueryCounter : DbCommandInterceptor
    {
        private int _count;

        /// <summary>Product lookups executed so far.</summary>
        public int Count => Volatile.Read(ref _count);

        /// <inheritdoc/>
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("FROM \"Products\"", StringComparison.Ordinal))
                Interlocked.Increment(ref _count);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }
    }

    /// <summary>Context factory for the clone, with the product-query counter attached.</summary>
    private sealed class CountingDbContextFactory(string connectionString, ProductQueryCounter counter)
        : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connectionString)
            .AddInterceptors(counter)
            .Options;

        /// <inheritdoc/>
        public LicenseDbContext CreateDbContext() => new(_options);
    }
}

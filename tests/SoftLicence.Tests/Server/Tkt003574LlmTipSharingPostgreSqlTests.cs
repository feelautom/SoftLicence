using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003574 relational proof on PostgreSQL 17, on a clone of the fully migrated model database (so the new
/// migration is applied): the public snapshot matches the product name and the category case-insensitively, including
/// a historical row stored with another case, excludes retracted and foreign-product tips, and the journal CHECK
/// constraints refuse a retraction without reason and an unknown channel even when written directly in SQL.
/// </summary>
public sealed class Tkt003574LlmTipSharingPostgreSqlTests
{
    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task SharedSnapshot_UsesCaseInsensitiveProductAndCategory_AndExcludesRetractedTips()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("tipshare");
        try
        {
            var factory = new CloneDbContextFactory(clone.ConnectionString);
            await using (var seed = factory.CreateDbContext())
            {
                seed.Products.AddRange(
                    new Product { Name = "TIAConnect", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "s1" },
                    new Product { Name = "OtherApp", PrivateKeyXml = "k", PublicKeyXml = "k", ApiSecret = "s2" });
                await seed.SaveChangesAsync();
            }

            var service = new LlmTipFeedbackService(factory, productIdCache: new LlmTipProductIdCache());
            var historical = await service.SaveTipAsync(Tip("hash-pg-historical", "Lad"));
            var lower = await service.SaveTipAsync(Tip("hash-pg-lower", "lad"));
            var otherCategory = await service.SaveTipAsync(Tip("hash-pg-hmi", "hmi"));
            var retracted = await service.SaveTipAsync(Tip("hash-pg-retracted", "lad"));
            var foreign = await service.SaveTipAsync(Tip("hash-pg-foreign", "lad", appName: "OtherApp"));
            foreach (var id in new[] { historical.Id, lower.Id, otherCategory.Id, retracted.Id, foreign.Id })
                await service.SetSharingAsync(id, null, null, true, null, "admin-ui:alice", "admin-ui", null);
            await service.SetSharingAsync(retracted.Id, null, null, false, "Product bug report", "admin-ui:alice", "admin-ui", null);

            var all = await service.ListSharedTipsAsync("tiaconnect", null);
            var lad = await service.ListSharedTipsAsync("  TIACONNECT ", " LAD ");

            Assert.Equal(
                new[] { "hash-pg-historical", "hash-pg-hmi", "hash-pg-lower" },
                all.Select(t => t.ContentHash).OrderBy(h => h, StringComparer.Ordinal).ToArray());
            Assert.Equal(
                new[] { "hash-pg-historical", "hash-pg-lower" },
                lad.Select(t => t.ContentHash).OrderBy(h => h, StringComparer.Ordinal).ToArray());

            await using var db = factory.CreateDbContext();
            var sql = db.LlmTipFeedbackTips
                .Where(t => t.SharedWithClients && t.Category != null && t.Category.ToLower() == "lad")
                .ToQueryString();
            Assert.Contains("lower(", sql, StringComparison.Ordinal);
            Assert.Equal(6, await db.LlmTipFeedbackSharingDecisions.CountAsync());
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await PostgreSqlModelDatabase.DropAsync(clone.MaintenanceConnectionString, clone.DatabaseName);
        }
    }

    [Fact]
    [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
    public async Task JournalCheckConstraints_RefuseARetractionWithoutReasonAndAnUnknownChannel()
    {
        var clone = await PostgreSqlModelDatabase.CloneAsync("tipsharechk");
        try
        {
            var factory = new CloneDbContextFactory(clone.ConnectionString);
            Guid tipId;
            await using (var seed = factory.CreateDbContext())
            {
                var tip = new LlmTipFeedbackTip { AppName = "TIAConnect", ContentHash = "hash-pg-check", Title = "t" };
                seed.LlmTipFeedbackTips.Add(tip);
                await seed.SaveChangesAsync();
                tipId = tip.Id;
            }

            await using var connection = new NpgsqlConnection(clone.ConnectionString);
            await connection.OpenAsync();

            var noReason = await Assert.ThrowsAsync<PostgresException>(() => InsertDecisionAsync(connection, tipId, "retracted", "   ", "admin-ui"));
            var badChannel = await Assert.ThrowsAsync<PostgresException>(() => InsertDecisionAsync(connection, tipId, "shared", null, "website"));
            await InsertDecisionAsync(connection, tipId, "shared", null, "api");

            Assert.Equal(PostgresErrorCodes.CheckViolation, noReason.SqlState);
            Assert.Equal("CK_LlmTipFeedbackSharingDecisions_RetractionReason", noReason.ConstraintName);
            Assert.Equal(PostgresErrorCodes.CheckViolation, badChannel.SqlState);
            Assert.Equal("CK_LlmTipFeedbackSharingDecisions_Channel", badChannel.ConstraintName);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await PostgreSqlModelDatabase.DropAsync(clone.MaintenanceConnectionString, clone.DatabaseName);
        }
    }

    /// <summary>Writes one journal row directly in SQL, bypassing the service, to exercise the CHECK constraints.</summary>
    private static async Task InsertDecisionAsync(NpgsqlConnection connection, Guid tipId, string action, string? reason, string channel)
    {
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO "LlmTipFeedbackSharingDecisions" ("Id", "TipId", "Action", "Reason", "DecidedBy", "Channel", "DecidedAtUtc")
            VALUES (@id, @tipId, @action, @reason, 'sql-test', @channel, now())
            """, connection);
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("tipId", tipId);
        command.Parameters.AddWithValue("action", action);
        command.Parameters.AddWithValue("reason", (object?)reason ?? DBNull.Value);
        command.Parameters.AddWithValue("channel", channel);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Anonymized client tip for <paramref name="appName"/> with the given stored category.</summary>
    private static LlmTipFeedbackTipRequest Tip(string contentHash, string category, string appName = "TIAConnect")
    {
        var tip = Tkt003574LlmTipSharingTests.BuildClientTip(contentHash, clientApproved: false, appName);
        tip.Category = category;
        return tip;
    }

    /// <summary>Context factory bound to the clone's connection string.</summary>
    private sealed class CloneDbContextFactory(string connectionString) : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        /// <inheritdoc/>
        public LicenseDbContext CreateDbContext() => new(_options);
    }
}

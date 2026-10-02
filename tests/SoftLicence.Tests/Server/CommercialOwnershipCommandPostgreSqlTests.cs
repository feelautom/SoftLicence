using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Proves provider-authenticated commercial ownership transitions against isolated PostgreSQL databases.
/// </summary>
public sealed class CommercialOwnershipCommandPostgreSqlTests
{
    /// <summary>Provides the test-only global provider credential configured on the isolated host.</summary>
    private const string GlobalSecret = "tkt782-provider-secret";
    /// <summary>Identifies the exact TKT-000780 schema used as the migration-upgrade baseline.</summary>
    private const string Tkt782PreviousMigration =
        "20260829133039_AddTkt000780CommercialSubjectProvisioning";

    /// <summary>
    /// Proves an exact TKT-000780 database upgrades without rewriting its ACTIVE owner, installs the
    /// product/license predecessor FK, and rejects self/cross-license lineage and terminal restoration.
    /// </summary>
    [Fact]
    public async Task Migration_Tkt780HeadAddsLineageAndImmutableTerminalGuard()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync(Tkt782PreviousMigration);
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var legacy = await SeedTkt780OwnershipAsync(options, provision.ConnectionString);
        await using (var db = new LicenseDbContext(options))
            await db.GetService<IMigrator>().MigrateAsync();

        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        Assert.True(await ScalarAsync<bool>(connection, """
            SELECT to_regclass('public."RuntimeRecoveryCommercialOwnershipCommands"') IS NOT NULL AS "Value";
            """));
        Assert.Equal(1L, await ScalarAsync<long>(connection, """
            SELECT count(*)::bigint AS "Value" FROM pg_catalog.pg_constraint
            WHERE conname = 'FK_RRCO_Previous_ProductId_LicenseId_OwnershipId'
              AND contype = 'f' AND convalidated AND confdeltype = 'a';
            """));
        Assert.Equal(1L, await ScalarAsync<long>(connection, """
            SELECT count(*)::bigint AS "Value" FROM pg_catalog.pg_trigger
            WHERE tgname = 'trg_tkt000782_commercial_ownership_version' AND tgenabled = 'O';
            """));
        Assert.Equal(1L, await ScalarAsync<long>(connection, $$"""
            SELECT count(*)::bigint AS "Value"
            FROM public."RuntimeRecoveryCommercialOwnerships"
            WHERE "Id" = '{{legacy.ActiveOwnershipId:D}}'::uuid
              AND "PreviousOwnershipId" IS NULL AND "State" = 'ACTIVE';
            """));

        await using (var terminate = connection.CreateCommand())
        {
            terminate.CommandText = $$"""
                UPDATE public."RuntimeRecoveryCommercialOwnerships"
                SET "State" = 'TRANSFERRED', "EndedAtUtc" = clock_timestamp()
                WHERE "Id" = '{{legacy.ActiveOwnershipId:D}}'::uuid;
                """;
            Assert.Equal(1, await terminate.ExecuteNonQueryAsync());
        }
        await AssertSqlStateAsync("55000", async () =>
        {
            await using var restore = connection.CreateCommand();
            restore.CommandText = $$"""
                UPDATE public."RuntimeRecoveryCommercialOwnerships"
                SET "State" = 'ACTIVE', "EndedAtUtc" = NULL
                WHERE "Id" = '{{legacy.ActiveOwnershipId:D}}'::uuid;
                """;
            await restore.ExecuteNonQueryAsync();
        });
        await AssertSqlStateAsync(PostgresErrorCodes.ForeignKeyViolation, () =>
            InsertOwnershipAsync(connection, Guid.NewGuid(), legacy.ProductId, legacy.SecondLicenseId,
                legacy.TargetSubjectId, legacy.ActiveOwnershipId));
        var selfId = Guid.NewGuid();
        await AssertSqlStateAsync(PostgresErrorCodes.CheckViolation, () =>
            InsertOwnershipAsync(connection, selfId, legacy.ProductId, legacy.SecondLicenseId,
                legacy.TargetSubjectId, selfId));
    }

    /// <summary>
    /// Establishes the causal TKT-000782 contract: an authenticated transfer command must replace the
    /// exact expected ACTIVE ownership with a successor owned by the explicit same-product subject.
    /// </summary>
    [Fact]
    public async Task TransferOwnership_ExplicitTargetReplacesExactExpectedHead()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        var fixture = await SeedOwnershipAsync(factory.Services);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);

        var commandId = Guid.NewGuid();
        var command = new OwnershipCommandPayload(
            commandId, "TRANSFER_OWNERSHIP", fixture.LicenseId,
            fixture.ActiveOwnershipId, fixture.TargetSubjectId);
        using var response = await PostCommandAsync(client, fixture.ProductId, command);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var firstBytes = await response.Content.ReadAsByteArrayAsync();
        using var firstJson = JsonDocument.Parse(firstBytes);
        var successorId = firstJson.RootElement.GetProperty("currentOwnershipId").GetGuid();
        Assert.NotEqual(fixture.ActiveOwnershipId, successorId);

        using var replay = await PostCommandAsync(client, fixture.ProductId, command);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(firstBytes, await replay.Content.ReadAsByteArrayAsync());

        using var divergent = await PostCommandAsync(client, fixture.ProductId, command with
        {
            TargetCommercialSubjectId = fixture.CurrentSubjectId
        });
        Assert.Equal(HttpStatusCode.Conflict, divergent.StatusCode);
        Assert.Equal("idempotency_conflict", await ReadErrorAsync(divergent));

        using var transferBack = await PostCommandAsync(client, fixture.ProductId,
            new OwnershipCommandPayload(Guid.NewGuid(), "TRANSFER_OWNERSHIP", fixture.LicenseId,
                successorId, fixture.CurrentSubjectId));
        Assert.Equal(HttpStatusCode.OK, transferBack.StatusCode);
        using var transferBackJson = JsonDocument.Parse(await transferBack.Content.ReadAsByteArrayAsync());
        var thirdId = transferBackJson.RootElement.GetProperty("currentOwnershipId").GetGuid();
        Assert.NotEqual(fixture.ActiveOwnershipId, thirdId);
        Assert.NotEqual(successorId, thirdId);

        var revoke = new OwnershipCommandPayload(Guid.NewGuid(), "REVOKE_OWNERSHIP",
            fixture.LicenseId, thirdId, null);
        using var revoked = await PostCommandAsync(client, fixture.ProductId, revoke);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        var revokedBytes = await revoked.Content.ReadAsByteArrayAsync();
        using var revokeReplay = await PostCommandAsync(client, fixture.ProductId, revoke);
        Assert.Equal(revokedBytes, await revokeReplay.Content.ReadAsByteArrayAsync());

        using var restoration = await PostCommandAsync(client, fixture.ProductId,
            new OwnershipCommandPayload(Guid.NewGuid(), "TRANSFER_OWNERSHIP", fixture.LicenseId,
                thirdId, fixture.TargetSubjectId));
        Assert.Equal(HttpStatusCode.Conflict, restoration.StatusCode);
        Assert.Equal("ownership_not_active", await ReadErrorAsync(restoration));

        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        var versions = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .Where(item => item.ProductId == fixture.ProductId && item.LicenseId == fixture.LicenseId)
            .OrderBy(item => item.CreatedAtUtc).ToListAsync();
        Assert.Equal(3, versions.Count);
        Assert.Equal(new[] { "TRANSFERRED", "TRANSFERRED", "REVOKED" },
            versions.Select(item => item.State));
        Assert.Null(versions[0].PreviousOwnershipId);
        Assert.Equal(versions[0].Id, versions[1].PreviousOwnershipId);
        Assert.Equal(versions[1].Id, versions[2].PreviousOwnershipId);
        Assert.Equal(versions[0].EndedAtUtc, versions[1].CreatedAtUtc);
        Assert.Equal(versions[1].EndedAtUtc, versions[2].CreatedAtUtc);
        Assert.Equal(3, await db.RuntimeRecoveryCommercialOwnershipCommands.CountAsync(item =>
            item.ProductId == fixture.ProductId && item.LicenseId == fixture.LicenseId));
        var license = await db.Licenses.AsNoTracking().SingleAsync(item => item.Id == fixture.LicenseId);
        Assert.True(license.IsActive);
        Assert.Null(license.RevokedAt);
        Assert.Equal(0, await CountRecoveryRowsAsync(db));
    }

    /// <summary>
    /// Proves closed command grammar, product-secret scope, opaque UUID selection, stale CAS, and
    /// absent, identical, or cross-product targets all fail without changing the current authority.
    /// </summary>
    [Fact]
    public async Task Commands_InvalidAuthoritySelectorsFailClosedWithoutDerivation()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        var first = await SeedOwnershipAsync(factory.Services);
        var second = await SeedOwnershipAsync(factory.Services);
        using var global = factory.CreateClient();
        global.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);

        var cases = new[]
        {
            new ExpectedFailure(
                new(Guid.NewGuid(), "transfer_ownership", first.LicenseId,
                    first.ActiveOwnershipId, first.TargetSubjectId), HttpStatusCode.BadRequest, "invalid_request"),
            new ExpectedFailure(
                new(Guid.NewGuid(), "TRANSFER_OWNERSHIP", first.LicenseId,
                    first.ActiveOwnershipId, null), HttpStatusCode.BadRequest, "invalid_request"),
            new ExpectedFailure(
                new(Guid.NewGuid(), "TRANSFER_OWNERSHIP", first.LicenseId,
                    Guid.NewGuid(), first.TargetSubjectId), HttpStatusCode.Conflict, "ownership_version_conflict"),
            new ExpectedFailure(
                new(Guid.NewGuid(), "TRANSFER_OWNERSHIP", first.LicenseId,
                    first.ActiveOwnershipId, first.CurrentSubjectId), HttpStatusCode.Conflict, "target_subject_invalid"),
            new ExpectedFailure(
                new(Guid.NewGuid(), "TRANSFER_OWNERSHIP", first.LicenseId,
                    first.ActiveOwnershipId, second.TargetSubjectId), HttpStatusCode.Conflict, "target_subject_invalid"),
            new ExpectedFailure(
                new(Guid.NewGuid(), "REVOKE_OWNERSHIP", first.LicenseId,
                    first.ActiveOwnershipId, first.TargetSubjectId), HttpStatusCode.BadRequest, "invalid_request")
        };
        foreach (var item in cases)
        {
            using var response = await PostCommandAsync(global, first.ProductId, item.Payload);
            Assert.Equal(item.StatusCode, response.StatusCode);
            Assert.Equal(item.ErrorCode, await ReadErrorAsync(response));
        }

        using var scoped = factory.CreateClient();
        scoped.DefaultRequestHeaders.Add("X-Admin-Secret", first.ProductSecret);
        using var crossScope = await PostCommandAsync(scoped, second.ProductId,
            new OwnershipCommandPayload(Guid.NewGuid(), "REVOKE_OWNERSHIP", second.LicenseId,
                second.ActiveOwnershipId, null));
        Assert.Equal(HttpStatusCode.Forbidden, crossScope.StatusCode);
        Assert.Equal("product_scope_forbidden", await ReadErrorAsync(crossScope));

        using var missingAuth = await PostCommandAsync(factory.CreateClient(), first.ProductId,
            new OwnershipCommandPayload(Guid.NewGuid(), "REVOKE_OWNERSHIP", first.LicenseId,
                first.ActiveOwnershipId, null));
        Assert.Equal(HttpStatusCode.Unauthorized, missingAuth.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        var current = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .SingleAsync(item => item.Id == first.ActiveOwnershipId);
        Assert.Equal("ACTIVE", current.State);
        Assert.Null(current.EndedAtUtc);
        Assert.False(await db.RuntimeRecoveryCommercialOwnershipCommands.AnyAsync(item =>
            item.ProductId == first.ProductId));
        Assert.Equal(0, await CountRecoveryRowsAsync(db));
    }

    /// <summary>
    /// Proves different command UUIDs racing on one expected head serialize on the license and yield
    /// exactly one terminal command, both for transfer/transfer and transfer/revoke competition.
    /// </summary>
    [Fact]
    public async Task Commands_ConcurrentExpectedHeadAllowsExactlyOneWinner()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        var transferRace = await SeedOwnershipAsync(factory.Services);
        var mixedRace = await SeedOwnershipAsync(factory.Services);
        var transferRaceOtherTarget = await AddSubjectAsync(factory.Services, transferRace.ProductId);
        var mixedRaceTarget = mixedRace.TargetSubjectId;
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);

        var transferResponses = await Task.WhenAll(
            PostCommandAsync(client, transferRace.ProductId,
                new(Guid.NewGuid(), "TRANSFER_OWNERSHIP", transferRace.LicenseId,
                    transferRace.ActiveOwnershipId, transferRace.TargetSubjectId)),
            PostCommandAsync(client, transferRace.ProductId,
                new(Guid.NewGuid(), "TRANSFER_OWNERSHIP", transferRace.LicenseId,
                    transferRace.ActiveOwnershipId, transferRaceOtherTarget)));
        try
        {
            Assert.Equal(1, transferResponses.Count(item => item.StatusCode == HttpStatusCode.OK));
            Assert.Equal(1, transferResponses.Count(item => item.StatusCode == HttpStatusCode.Conflict));
        }
        finally
        {
            foreach (var response in transferResponses) response.Dispose();
        }

        var mixedResponses = await Task.WhenAll(
            PostCommandAsync(client, mixedRace.ProductId,
                new(Guid.NewGuid(), "TRANSFER_OWNERSHIP", mixedRace.LicenseId,
                    mixedRace.ActiveOwnershipId, mixedRaceTarget)),
            PostCommandAsync(client, mixedRace.ProductId,
                new(Guid.NewGuid(), "REVOKE_OWNERSHIP", mixedRace.LicenseId,
                    mixedRace.ActiveOwnershipId, null)));
        var transferWon = mixedResponses[0].StatusCode == HttpStatusCode.OK;
        try
        {
            Assert.Equal(1, mixedResponses.Count(item => item.StatusCode == HttpStatusCode.OK));
            Assert.Equal(1, mixedResponses.Count(item => item.StatusCode == HttpStatusCode.Conflict));
        }
        finally
        {
            foreach (var response in mixedResponses) response.Dispose();
        }

        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        Assert.Equal(1, await db.RuntimeRecoveryCommercialOwnershipCommands.CountAsync(item =>
            item.ProductId == transferRace.ProductId));
        Assert.Equal(1, await db.RuntimeRecoveryCommercialOwnerships.CountAsync(item =>
            item.ProductId == transferRace.ProductId && item.State == "ACTIVE"));
        Assert.Equal(1, await db.RuntimeRecoveryCommercialOwnershipCommands.CountAsync(item =>
            item.ProductId == mixedRace.ProductId));
        Assert.Equal(transferWon ? 1 : 0, await db.RuntimeRecoveryCommercialOwnerships.CountAsync(item =>
            item.ProductId == mixedRace.ProductId && item.State == "ACTIVE"));
        Assert.Equal(0, await CountRecoveryRowsAsync(db));
    }

    /// <summary>
    /// Proves a failure while freezing the command terminal rolls back the old-head CAS, successor,
    /// ledger, and every recovery table to their exact pre-command state.
    /// </summary>
    [Fact]
    public async Task Commands_TerminalWriteFailureRollsBackEntireTransition()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        using var factory = CreateFactory(provision.ConnectionString);
        var fixture = await SeedOwnershipAsync(factory.Services);
        var commandId = Guid.NewGuid();
        await using (var connection = new NpgsqlConnection(provision.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $$"""
                CREATE FUNCTION tkt782_reject_command() RETURNS trigger LANGUAGE plpgsql AS $fn$
                BEGIN
                    IF NEW."Id" = '{{commandId:D}}'::uuid THEN
                        RAISE EXCEPTION 'TKT-000782 injected terminal failure' USING ERRCODE = '23514';
                    END IF;
                    RETURN NEW;
                END;
                $fn$;
                CREATE TRIGGER tkt782_reject_command
                BEFORE INSERT ON public."RuntimeRecoveryCommercialOwnershipCommands"
                FOR EACH ROW EXECUTE FUNCTION tkt782_reject_command();
                """;
            await command.ExecuteNonQueryAsync();
        }

        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", GlobalSecret);
        HttpResponseMessage? response = null;
        Exception? transportFailure = null;
        try
        {
            response = await PostCommandAsync(client, fixture.ProductId,
                new(commandId, "TRANSFER_OWNERSHIP", fixture.LicenseId,
                    fixture.ActiveOwnershipId, fixture.TargetSubjectId));
        }
        catch (Exception exception)
        {
            transportFailure = exception;
        }
        Assert.True(transportFailure is not null || response is { IsSuccessStatusCode: false });
        response?.Dispose();

        await using var scope = factory.Services.CreateAsyncScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await contextFactory.CreateDbContextAsync();
        var ownership = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking()
            .SingleAsync(item => item.Id == fixture.ActiveOwnershipId);
        Assert.Equal("ACTIVE", ownership.State);
        Assert.Null(ownership.EndedAtUtc);
        Assert.Equal(1, await db.RuntimeRecoveryCommercialOwnerships.CountAsync(item =>
            item.ProductId == fixture.ProductId && item.LicenseId == fixture.LicenseId));
        Assert.False(await db.RuntimeRecoveryCommercialOwnershipCommands.AnyAsync(item =>
            item.Id == commandId));
        Assert.Equal(0, await CountRecoveryRowsAsync(db));
    }

    /// <summary>Builds the authenticated provider host over one isolated PostgreSQL database.</summary>
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

    /// <summary>Seeds one product, license, current owner, and explicit same-product target subject.</summary>
    private static async Task<OwnershipFixture> SeedOwnershipAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await factory.CreateDbContextAsync();
        var productSecret = "tkt782-product-secret-" + Guid.NewGuid().ToString("N");
        var product = new Product
        {
            Name = "tkt782-product-" + Guid.NewGuid().ToString("N"),
            ApiSecret = productSecret
        };
        var type = new LicenseType { Product = product, Name = "TKT-782", Slug = "TKT782" };
        var license = new License
        {
            Product = product,
            Type = type,
            LicenseKey = "TKT782-" + Guid.NewGuid().ToString("N"),
            CustomerName = "presentation-only",
            CustomerEmail = "presentation@example.test"
        };
        var current = new RuntimeRecoveryCommercialSubject
        {
            Product = product,
            Id = Guid.NewGuid(),
            CreatedAtUtc = DateTime.UtcNow
        };
        var target = new RuntimeRecoveryCommercialSubject
        {
            Product = product,
            Id = Guid.NewGuid(),
            CreatedAtUtc = DateTime.UtcNow
        };
        var ownership = new RuntimeRecoveryCommercialOwnership
        {
            Id = Guid.NewGuid(),
            ProductId = product.Id,
            LicenseId = license.Id,
            OwnerSubjectId = current.Id,
            State = "ACTIVE",
            CreatedAtUtc = DateTime.UtcNow
        };
        db.AddRange(product, type, license, current, target, ownership);
        await db.SaveChangesAsync();
        return new(product.Id, license.Id, ownership.Id, current.Id, target.Id, productSecret);
    }

    /// <summary>Seeds the exact pre-TKT-000782 schema without referencing the not-yet-added column.</summary>
    private static async Task<LegacyOwnershipFixture> SeedTkt780OwnershipAsync(
        DbContextOptions<LicenseDbContext> options,
        string connectionString)
    {
        await using var db = new LicenseDbContext(options);
        var product = new Product
        {
            Name = "tkt782-upgrade-" + Guid.NewGuid().ToString("N"),
            ApiSecret = "tkt782-upgrade-secret-" + Guid.NewGuid().ToString("N")
        };
        var type = new LicenseType { Product = product, Name = "TKT-782 upgrade", Slug = "TKT782-UPGRADE" };
        var firstLicense = new License
        {
            Product = product,
            Type = type,
            LicenseKey = "TKT782-UPGRADE-A-" + Guid.NewGuid().ToString("N")
        };
        var secondLicense = new License
        {
            Product = product,
            Type = type,
            LicenseKey = "TKT782-UPGRADE-B-" + Guid.NewGuid().ToString("N")
        };
        var current = new RuntimeRecoveryCommercialSubject
        {
            Product = product,
            Id = Guid.NewGuid(),
            CreatedAtUtc = DateTime.UtcNow
        };
        var target = new RuntimeRecoveryCommercialSubject
        {
            Product = product,
            Id = Guid.NewGuid(),
            CreatedAtUtc = DateTime.UtcNow
        };
        // Keep the historical license seed independent of later EF columns such as AuthorityVersion.
        // The actual migration below remains responsible for introducing those columns.
        db.AddRange(product, type, current, target);
        await db.SaveChangesAsync();

        var ownershipId = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        foreach (var license in new[] { firstLicense, secondLicense })
        {
            await using var seedLicense = connection.CreateCommand();
            seedLicense.CommandText = """
                INSERT INTO public."Licenses"
                    ("Id","ProductId","LicenseTypeId","LicenseKey","CustomerName","CustomerEmail",
                     "CreationDate","RecoveryCount","IsActive","AllowedVersions","MaxSeats","HasUninstallEvent")
                VALUES (@id,@product,@type,@key,'','',clock_timestamp(),0,true,'*',1,false);
                """;
            seedLicense.Parameters.AddWithValue("id", license.Id);
            seedLicense.Parameters.AddWithValue("product", product.Id);
            seedLicense.Parameters.AddWithValue("type", type.Id);
            seedLicense.Parameters.AddWithValue("key", license.LicenseKey);
            await seedLicense.ExecuteNonQueryAsync();
        }
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO public."RuntimeRecoveryCommercialOwnerships"
                ("Id","ProductId","LicenseId","OwnerSubjectId","State","CreatedAtUtc","EndedAtUtc")
            VALUES (@id,@product,@license,@subject,'ACTIVE',clock_timestamp(),NULL);
            """;
        command.Parameters.AddWithValue("id", ownershipId);
        command.Parameters.AddWithValue("product", product.Id);
        command.Parameters.AddWithValue("license", firstLicense.Id);
        command.Parameters.AddWithValue("subject", current.Id);
        await command.ExecuteNonQueryAsync();
        return new(product.Id, firstLicense.Id, secondLicense.Id, ownershipId, target.Id);
    }

    /// <summary>Adds one further opaque subject inside an existing exact product scope.</summary>
    private static async Task<Guid> AddSubjectAsync(IServiceProvider services, Guid productId)
    {
        await using var scope = services.CreateAsyncScope();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
        await using var db = await factory.CreateDbContextAsync();
        var subject = new RuntimeRecoveryCommercialSubject
        {
            ProductId = productId,
            Id = Guid.NewGuid(),
            CreatedAtUtc = DateTime.UtcNow
        };
        db.Add(subject);
        await db.SaveChangesAsync();
        return subject.Id;
    }

    /// <summary>Sends one typed command to the only TKT-000782 provider route.</summary>
    private static Task<HttpResponseMessage> PostCommandAsync(
        HttpClient client,
        Guid productId,
        OwnershipCommandPayload payload) =>
        client.PostAsJsonAsync(
            $"/api/admin/products/{productId:D}/runtime-recovery-commercial-ownership-commands",
            payload);

    /// <summary>Reads the stable error token from one failed provider response.</summary>
    private static async Task<string?> ReadErrorAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
        return json.RootElement.GetProperty("error").GetString();
    }

    /// <summary>Counts every recovery table that TKT-000782 is forbidden to mutate.</summary>
    private static async Task<int> CountRecoveryRowsAsync(LicenseDbContext db) =>
        await db.RuntimeSeatRecoveryAuthorizations.CountAsync()
        + await db.RuntimeSeatRecoveryReservations.CountAsync()
        + await db.RuntimeSeatRecoveryAuthorities.CountAsync()
        + await db.RuntimeRecoveryGrantOwnerships.CountAsync();

    /// <summary>Inserts one successor candidate directly so PostgreSQL remains the tested authority.</summary>
    private static async Task InsertOwnershipAsync(
        NpgsqlConnection connection,
        Guid id,
        Guid productId,
        Guid licenseId,
        Guid subjectId,
        Guid previousOwnershipId)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO public."RuntimeRecoveryCommercialOwnerships"
                ("Id","ProductId","LicenseId","PreviousOwnershipId","OwnerSubjectId",
                 "State","CreatedAtUtc","EndedAtUtc")
            VALUES (@id,@product,@license,@previous,@subject,'ACTIVE',clock_timestamp(),NULL);
            """;
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("product", productId);
        command.Parameters.AddWithValue("license", licenseId);
        command.Parameters.AddWithValue("previous", previousOwnershipId);
        command.Parameters.AddWithValue("subject", subjectId);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Asserts one direct PostgreSQL operation fails with the exact integrity SQLSTATE.</summary>
    private static async Task AssertSqlStateAsync(string sqlState, Func<Task> operation)
    {
        var exception = await Assert.ThrowsAsync<PostgresException>(operation);
        Assert.Equal(sqlState, exception.SqlState);
    }

    /// <summary>Reads one named scalar from an open PostgreSQL connection.</summary>
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        var value = await command.ExecuteScalarAsync();
        return (T)value!;
    }

    /// <summary>Groups the exact provider-owned UUIDs required by one transition proof.</summary>
    /// <param name="ProductId">The exact product scope authorized by the fixture credential.</param>
    /// <param name="LicenseId">The license whose ownership head is under test.</param>
    /// <param name="ActiveOwnershipId">The opaque ACTIVE ownership version used as the expected CAS token.</param>
    /// <param name="CurrentSubjectId">The subject owning the initial ACTIVE version.</param>
    /// <param name="TargetSubjectId">A distinct subject inside the same product scope.</param>
    /// <param name="ProductSecret">The test-only credential scoped to <paramref name="ProductId"/>.</param>
    private sealed record OwnershipFixture(
        Guid ProductId,
        Guid LicenseId,
        Guid ActiveOwnershipId,
        Guid CurrentSubjectId,
        Guid TargetSubjectId,
        string ProductSecret);

    /// <summary>Groups the pre-migration product, licenses, head, and target UUIDs.</summary>
    /// <param name="ProductId">The exact product scope preserved across migration.</param>
    /// <param name="FirstLicenseId">The license owning the pre-migration ACTIVE head.</param>
    /// <param name="SecondLicenseId">A same-product license used to prove cross-license lineage rejection.</param>
    /// <param name="ActiveOwnershipId">The opaque pre-migration ACTIVE ownership version.</param>
    /// <param name="TargetSubjectId">A distinct same-product subject available after migration.</param>
    private sealed record LegacyOwnershipFixture(
        Guid ProductId,
        Guid FirstLicenseId,
        Guid SecondLicenseId,
        Guid ActiveOwnershipId,
        Guid TargetSubjectId);

    /// <summary>Represents the exact JSON command shape accepted by the provider controller.</summary>
    /// <param name="CommandId">The global opaque idempotency UUID.</param>
    /// <param name="Operation">The exact ordinal transfer or revoke protocol token.</param>
    /// <param name="LicenseId">The license inside the route product scope.</param>
    /// <param name="ExpectedOwnershipId">The opaque ACTIVE ownership UUID used as the CAS token.</param>
    /// <param name="TargetCommercialSubjectId">The explicit transfer target, or null only for revocation.</param>
    private sealed record OwnershipCommandPayload(
        Guid CommandId,
        string Operation,
        Guid LicenseId,
        Guid ExpectedOwnershipId,
        Guid? TargetCommercialSubjectId);

    /// <summary>Pairs one invalid typed command with its exact fail-closed HTTP contract.</summary>
    /// <param name="Payload">The deliberately invalid typed command sent to the provider route.</param>
    /// <param name="StatusCode">The exact fail-closed HTTP status expected from the boundary.</param>
    /// <param name="ErrorCode">The exact non-oracular error token expected in the response.</param>
    private sealed record ExpectedFailure(
        OwnershipCommandPayload Payload,
        HttpStatusCode StatusCode,
        string ErrorCode);

    /// <summary>Owns one isolated PostgreSQL database and force-removes it after the proof.</summary>
    /// <param name="maintenanceConnectionString">The maintenance database connection used only for create/drop.</param>
    /// <param name="connectionString">The isolated application database connection.</param>
    /// <param name="database">The generated database name exclusively owned by this fixture.</param>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        /// <summary>Gets the isolated application connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Creates and migrates one isolated database from the configured PostgreSQL authority.</summary>
        public static async Task<PostgreSqlProvision> CreateAsync(string? targetMigration = null)
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
            {
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000782 PostgreSQL tests.");
            }

            var database = "tkt782_ownership_" + Guid.NewGuid().ToString("N");
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
            {
                var migrator = db.GetService<IMigrator>();
                await migrator.MigrateAsync(targetMigration);
            }
            return new PostgreSqlProvision(maintenance, target, database);
        }

        /// <summary>Clears pools and drops the isolated database even after a failed assertion.</summary>
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

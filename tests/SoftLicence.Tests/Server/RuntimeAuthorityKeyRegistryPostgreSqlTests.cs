using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves the dedicated key-registry model owns its relational head and readback tuples.</summary>
public sealed class RuntimeAuthorityKeyRegistryPostgreSqlTests
{
    /// <summary>Exact migration identity generated for the item-1 relations.</summary>
    private const string Migration = "20260830003915_AddTkt000789RuntimeAuthorityKeyRegistry";

    /// <summary>Requires valid non-object JSON stored bytes to be rejected as false without throwing.</summary>
    [Fact]
    public void Contract_NonObjectStoredBodyReturnsFalse() =>
        Assert.False(RuntimeAuthorityKeyRegistryContract.HasExactObservedAtUtc(
            "[]"u8, "2026-08-30T01:00:00.0000001+00:00"));

    /// <summary>Requires the three item-1 relations and their exact composite principal keys in the EF model.</summary>
    [Fact]
    public void Model_ContainsDedicatedSnapshotHeadAndReadbackRelations()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);

        var snapshot = db.Model.FindEntityType(typeof(RuntimeAuthorityKeyRegistrySnapshot));
        var head = db.Model.FindEntityType(typeof(RuntimeAuthorityKeyRegistryHead));
        var readback = db.Model.FindEntityType(typeof(RuntimeAuthorityKeyRegistryReadback));

        Assert.NotNull(snapshot);
        Assert.NotNull(head);
        Assert.NotNull(readback);
        Assert.Contains(snapshot!.GetKeys(), key =>
            key.Properties.Select(property => property.Name).SequenceEqual(
                ["RegistryId", "SnapshotId", "SnapshotVersion", "MetadataDigestSha256",
                    "RegistryAuthenticationInputDigestSha256", "PublicationState"]));
        Assert.Contains(snapshot.GetKeys(), key =>
            key.Properties.Select(property => property.Name).SequenceEqual(
                ["SnapshotId", "ExactResponseBodySha256"]));
    }

    /// <summary>
    /// Proves the real item-1 service bootstraps exactly one dedicated tuple, returns byte-exact
    /// readback, and PostgreSQL rejects immutable-body and crossed-readback mutations.
    /// </summary>
    [Fact]
    public async Task Service_BootstrapAndExactReadbackAreRelationallyClosed()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        var runtimeOptions = CreateRuntimeOptions();
        var service = new RuntimeAuthorityKeyRegistrySnapshotService(
            factory, Options.Create(runtimeOptions));
        var body = Encoding.UTF8.GetBytes(
            "{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"11111111-1111-4111-8111-111111111111\",\"productId\":\"22222222-2222-4222-8222-222222222222\"}");

        var first = await service.ReadCurrentAsync("registry-client", body, CancellationToken.None);
        var replay = await service.ReadCurrentAsync("registry-client", body, CancellationToken.None);

        Assert.Equal(first, replay);
        await using (var db = factory.CreateDbContext())
        {
            Assert.Equal(1, await db.RuntimeAuthorityKeyRegistrySnapshots.CountAsync());
            Assert.Equal(1, await db.RuntimeAuthorityKeyRegistryHeads.CountAsync());
            Assert.Equal(1, await db.RuntimeAuthorityKeyRegistryReadbacks.CountAsync());
            Assert.Equal(runtimeOptions.AuthorityGenerationV2.RegistryObservedAtUtc,
                (await db.RuntimeAuthorityKeyRegistrySnapshots.SingleAsync()).ObservedAtUtc);
        }
        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        var immutable = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, """
            UPDATE public."RuntimeAuthorityKeyRegistrySnapshots"
            SET "ExactResponseBody" = decode('00', 'hex');
            """));
        Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, immutable.SqlState);
        await ExecuteAsync(connection, """
            INSERT INTO public."RuntimeAuthorityKeyRegistrySnapshots"
                ("SnapshotId","RegistryId","SnapshotVersion","MetadataDigestSha256",
                 "RegistryAuthenticationInputDigestSha256","ObservedAtUtc","PublicationState",
                 "RevokedAtUtc","ExactResponseBody","ExactResponseBodySha256",
                 "RegistrySignatureBase64Url","CreatedAtUtc")
            SELECT 'registry-snapshot-tuple-b',"RegistryId",2,repeat('a',64),repeat('b',64),
                   "ObservedAtUtc",'superseded',NULL,convert_to('{"tuple":"b"}','UTF8'),
                   repeat('c',64),repeat('A',342),clock_timestamp()
            FROM public."RuntimeAuthorityKeyRegistrySnapshots"
            WHERE "SnapshotId"='registry-snapshot-item1';
            """);
        var crossed = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, """
            INSERT INTO public."RuntimeAuthorityKeyRegistryReadbacks"
                ("ClientId","RequestId","RequestDigestSha256","SnapshotId","ExactResponseBodySha256","CreatedAtUtc")
            VALUES
                ('other-client','33333333-3333-4333-8333-333333333333',
                 repeat('0',64),'registry-snapshot-item1',repeat('c',64),clock_timestamp());
            """));
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, crossed.SqlState);
    }

    /// <summary>
    /// Proves a provider-authenticated higher version atomically replaces the durable head while
    /// preserving the previous snapshot as superseded and returning only the new canonical bytes.
    /// </summary>
    [Fact]
    public async Task Service_HigherVersionPromotesOneCurrentSnapshot()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = DateTimeOffset.UtcNow.AddSeconds(-1);
        var firstOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v1", 1);
        var nextOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed.AddTicks(1), "registry-snapshot-item2-v4", 4);

        var first = await new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(firstOptions))
            .ReadCurrentAsync("registry-client", RequestBody(), CancellationToken.None);
        var next = await new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(nextOptions))
            .ReadCurrentAsync("registry-client", RequestBody(Guid.NewGuid()), CancellationToken.None);

        Assert.NotEqual(first, next);
        await using var db = factory.CreateDbContext();
        var snapshots = await db.RuntimeAuthorityKeyRegistrySnapshots
            .OrderBy(item => item.SnapshotVersion).ToListAsync();
        var head = await db.RuntimeAuthorityKeyRegistryHeads.SingleAsync();
        Assert.Equal(2, snapshots.Count);
        Assert.Equal("superseded", snapshots[0].PublicationState);
        Assert.Equal("current", snapshots[1].PublicationState);
        Assert.Equal(4, snapshots[1].SnapshotVersion);
        Assert.Equal(snapshots[1].SnapshotId, head.CurrentSnapshotId);
        Assert.Equal(snapshots[1].SnapshotVersion, head.CurrentSnapshotVersion);
        Assert.Equal(snapshots[1].ExactResponseBody, next);
    }

    /// <summary>Proves equal source bytes support semantic replay and recovery after a lost response.</summary>
    [Fact]
    public async Task Service_SameVersionReplayAndLostResponseRemainByteExact()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        var service = new RuntimeAuthorityKeyRegistrySnapshotService(
            factory, Options.Create(CreateRuntimeOptions()));
        var firstRequest = RequestBody();

        var lostResponse = await service.ReadCurrentAsync(
            "registry-client", firstRequest, CancellationToken.None);
        var recovered = await service.ReadCurrentAsync(
            "registry-client", firstRequest, CancellationToken.None);
        var independentRead = await service.ReadCurrentAsync(
            "registry-client", RequestBody(Guid.NewGuid()), CancellationToken.None);

        Assert.Equal(lostResponse, recovered);
        Assert.Equal(lostResponse, independentRead);
        await using var db = factory.CreateDbContext();
        Assert.Equal(1, await db.RuntimeAuthorityKeyRegistrySnapshots.CountAsync());
        Assert.Equal(2, await db.RuntimeAuthorityKeyRegistryReadbacks.CountAsync());
    }

    /// <summary>Refuses equal/lower versions and reused identities without changing the durable winner.</summary>
    [Fact]
    public async Task Service_NonMonotoneAndIdentityDivergenceFailClosedWithoutEffects()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = DateTimeOffset.UtcNow.AddSeconds(-1);
        var winner = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v4", 4);
        var first = await new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(winner))
            .ReadCurrentAsync("registry-client", RequestBody(), CancellationToken.None);
        var rejected = new[]
        {
            CreateRuntimeOptions(registry, operational, recovery, observed, "registry-snapshot-equal", 4),
            CreateRuntimeOptions(registry, operational, recovery, observed, "registry-snapshot-lower", 3),
            CreateRuntimeOptions(registry, operational, recovery, observed, "registry-snapshot-item2-v4", 5)
        };

        foreach (var candidate in rejected)
        {
            var failure = await Assert.ThrowsAsync<RuntimeAuthorityKeyRegistryContractException>(() =>
                new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(candidate))
                    .ReadCurrentAsync("registry-client", RequestBody(Guid.NewGuid()), CancellationToken.None));
            Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
        }

        await using var db = factory.CreateDbContext();
        var snapshot = await db.RuntimeAuthorityKeyRegistrySnapshots.SingleAsync();
        var head = await db.RuntimeAuthorityKeyRegistryHeads.SingleAsync();
        Assert.Equal("registry-snapshot-item2-v4", snapshot.SnapshotId);
        Assert.Equal("current", snapshot.PublicationState);
        Assert.Equal(snapshot.SnapshotId, head.CurrentSnapshotId);
        Assert.Equal(first, snapshot.ExactResponseBody);
        Assert.Equal(1, await db.RuntimeAuthorityKeyRegistryReadbacks.CountAsync());
    }

    /// <summary>Refuses an old tombstone after promotion while the current read remains recoverable.</summary>
    [Fact]
    public async Task Service_PromotionInvalidatesOldReplayAndPreservesNewLostResponseReadback()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = DateTimeOffset.UtcNow.AddSeconds(-1);
        var firstOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v1", 1);
        var nextOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v2", 2);
        var oldRequest = RequestBody();
        await new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(firstOptions))
            .ReadCurrentAsync("registry-client", oldRequest, CancellationToken.None);
        var nextRequest = RequestBody(Guid.NewGuid());
        var nextService = new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(nextOptions));
        var lost = await nextService.ReadCurrentAsync("registry-client", nextRequest, CancellationToken.None);

        var oldReplay = await Assert.ThrowsAsync<RuntimeAuthorityKeyRegistryContractException>(() =>
            nextService.ReadCurrentAsync("registry-client", oldRequest, CancellationToken.None));
        var recovered = await nextService.ReadCurrentAsync(
            "registry-client", nextRequest, CancellationToken.None);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, oldReplay.StatusCode);
        Assert.Equal(lost, recovered);
        await using var db = factory.CreateDbContext();
        Assert.Equal(2, await db.RuntimeAuthorityKeyRegistrySnapshots.CountAsync());
        Assert.Equal(2, await db.RuntimeAuthorityKeyRegistryReadbacks.CountAsync());
    }

    /// <summary>Rolls back every promotion write when an old semantic tombstone rejects the response.</summary>
    [Fact]
    public async Task Service_OldReplayDuringPromotionRollsBackAllCandidateEffects()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = DateTimeOffset.UtcNow.AddSeconds(-1);
        var firstOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v1", 1);
        var nextOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v2", 2);
        var oldRequest = RequestBody();
        await new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(firstOptions))
            .ReadCurrentAsync("registry-client", oldRequest, CancellationToken.None);

        var failure = await Assert.ThrowsAsync<RuntimeAuthorityKeyRegistryContractException>(() =>
            new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(nextOptions))
                .ReadCurrentAsync("registry-client", oldRequest, CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
        await using var db = factory.CreateDbContext();
        var snapshot = await db.RuntimeAuthorityKeyRegistrySnapshots.SingleAsync();
        var head = await db.RuntimeAuthorityKeyRegistryHeads.SingleAsync();
        Assert.Equal("registry-snapshot-item2-v1", snapshot.SnapshotId);
        Assert.Equal("current", snapshot.PublicationState);
        Assert.Equal(snapshot.SnapshotId, head.CurrentSnapshotId);
        Assert.Equal(1, await db.RuntimeAuthorityKeyRegistryReadbacks.CountAsync());
    }

    /// <summary>Proves concurrent promotion and same-request replay converge on one current body.</summary>
    [Fact]
    public async Task Service_ConcurrentPromotionAndReplayConvergeWithoutDuplicateEffects()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        var observed = DateTimeOffset.UtcNow.AddSeconds(-1);
        var firstOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v1", 1);
        await new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(firstOptions))
            .ReadCurrentAsync("registry-client", RequestBody(), CancellationToken.None);
        var nextOptions = CreateRuntimeOptions(
            registry, operational, recovery, observed, "registry-snapshot-item2-v7", 7);
        var firstService = new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(nextOptions));
        var secondService = new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(nextOptions));
        var sharedRequest = RequestBody(Guid.NewGuid());

        var promotion = await Task.WhenAll(
            firstService.ReadCurrentAsync("registry-client-a", sharedRequest, CancellationToken.None),
            secondService.ReadCurrentAsync("registry-client-b", RequestBody(Guid.NewGuid()), CancellationToken.None));
        var replay = await Task.WhenAll(
            firstService.ReadCurrentAsync("registry-client-a", sharedRequest, CancellationToken.None),
            secondService.ReadCurrentAsync("registry-client-a", sharedRequest, CancellationToken.None));

        Assert.Equal(promotion[0], promotion[1]);
        Assert.Equal(promotion[0], replay[0]);
        Assert.Equal(replay[0], replay[1]);
        await using var db = factory.CreateDbContext();
        Assert.Equal(2, await db.RuntimeAuthorityKeyRegistrySnapshots.CountAsync());
        Assert.Equal(1, await db.RuntimeAuthorityKeyRegistrySnapshots
            .CountAsync(item => item.PublicationState == "current"));
        Assert.Equal(3, await db.RuntimeAuthorityKeyRegistryReadbacks.CountAsync());
        Assert.Equal(7, (await db.RuntimeAuthorityKeyRegistryHeads.SingleAsync()).CurrentSnapshotVersion);
    }

    /// <summary>Proves the complete head tuple FK is initially deferred yet rejects a missing target at commit.</summary>
    [Fact]
    public async Task HeadForeignKey_IsInitiallyDeferredAndCommitClosed()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        await using var connection = new NpgsqlConnection(provision.ConnectionString);
        await connection.OpenAsync();
        await using (var flags = new NpgsqlCommand("""
            SELECT condeferrable AND condeferred
            FROM pg_catalog.pg_constraint
            WHERE conname='FK_RAKRHeads_RAKRSnapshots_CurrentTuple';
            """, connection))
            Assert.True((bool)(await flags.ExecuteScalarAsync())!);

        await using (var transaction = await connection.BeginTransactionAsync())
        {
            await ExecuteAsync(connection, """
                INSERT INTO public."RuntimeAuthorityKeyRegistryHeads"
                    ("RegistryId","CurrentSnapshotId","CurrentSnapshotVersion",
                     "CurrentMetadataDigestSha256","CurrentRegistryAuthenticationInputDigestSha256",
                     "CurrentPublicationState","UpdatedAtUtc")
                VALUES ('runtime-enrollment-authority-generation-v2','deferred-snapshot',1,
                        repeat('a',64),repeat('b',64),'current',clock_timestamp());
                INSERT INTO public."RuntimeAuthorityKeyRegistrySnapshots"
                    ("SnapshotId","RegistryId","SnapshotVersion","MetadataDigestSha256",
                     "RegistryAuthenticationInputDigestSha256","ObservedAtUtc","PublicationState",
                     "RevokedAtUtc","ExactResponseBody","ExactResponseBodySha256",
                     "RegistrySignatureBase64Url","CreatedAtUtc")
                VALUES ('deferred-snapshot','runtime-enrollment-authority-generation-v2',1,
                        repeat('a',64),repeat('b',64),'2026-08-30T01:00:00.0000001+00:00','current',
                        NULL,convert_to('{}','UTF8'),repeat('c',64),repeat('A',342),clock_timestamp());
                """);
            await transaction.CommitAsync();
        }

        await ExecuteAsync(connection, "DELETE FROM public.\"RuntimeAuthorityKeyRegistryHeads\";");
        await using var missing = await connection.BeginTransactionAsync();
        await ExecuteAsync(connection, """
            INSERT INTO public."RuntimeAuthorityKeyRegistryHeads"
                ("RegistryId","CurrentSnapshotId","CurrentSnapshotVersion",
                 "CurrentMetadataDigestSha256","CurrentRegistryAuthenticationInputDigestSha256",
                 "CurrentPublicationState","UpdatedAtUtc")
            VALUES ('runtime-enrollment-authority-generation-v2','missing-snapshot',2,
                    repeat('d',64),repeat('e',64),'current',clock_timestamp());
            """);
        var violation = await Assert.ThrowsAsync<PostgresException>(() => missing.CommitAsync());
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, violation.SqlState);
    }

    /// <summary>Refuses a source older than the inclusive freshness bound and persists no registry row.</summary>
    [Fact]
    public async Task Service_StaleSourceFailsClosedWithoutPersistence()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        var stale = DateTimeOffset.UtcNow.AddMinutes(-6).AddTicks(1);
        var service = new RuntimeAuthorityKeyRegistrySnapshotService(
            factory, Options.Create(CreateRuntimeOptions(stale)));

        var failure = await Assert.ThrowsAsync<RuntimeAuthorityKeyRegistryContractException>(() =>
            service.ReadCurrentAsync("registry-client", RequestBody(), CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
        await using var db = factory.CreateDbContext();
        Assert.Empty(await db.RuntimeAuthorityKeyRegistrySnapshots.ToListAsync());
        Assert.Empty(await db.RuntimeAuthorityKeyRegistryHeads.ToListAsync());
        Assert.Empty(await db.RuntimeAuthorityKeyRegistryReadbacks.ToListAsync());
    }

    /// <summary>Refuses a replay frozen against a snapshot that has since been atomically revoked.</summary>
    [Fact]
    public async Task Service_ReplayOfRevokedSnapshotFailsClosed()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        var firstOptions = CreateRuntimeOptions();
        var request = RequestBody();
        await new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(firstOptions))
            .ReadCurrentAsync("registry-client", request, CancellationToken.None);
        var secondOptions = CreateRuntimeOptions(snapshotId: "registry-snapshot-item1-v2", version: 2);
        var second = RuntimeAuthorityKeyRegistryContract.BuildSnapshot(secondOptions, DateTimeOffset.UtcNow);
        await PromoteAndRevokeAsync(provision.ConnectionString, second);

        var failure = await Assert.ThrowsAsync<RuntimeAuthorityKeyRegistryContractException>(() =>
            new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(secondOptions))
                .ReadCurrentAsync("registry-client", request, CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
    }

    /// <summary>Refuses stored response bytes altered behind the immutable trigger before returning success.</summary>
    [Fact]
    public async Task Service_CorruptedStoredBodyFailsClosed()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var dbOptions = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(provision.ConnectionString).Options;
        var factory = new TestDbFactory(dbOptions);
        var options = CreateRuntimeOptions();
        var service = new RuntimeAuthorityKeyRegistrySnapshotService(factory, Options.Create(options));
        await service.ReadCurrentAsync("registry-client", RequestBody(), CancellationToken.None);
        int snapshotsBefore;
        int headsBefore;
        int readbacksBefore;
        await using (var baseline = factory.CreateDbContext())
        {
            snapshotsBefore = await baseline.RuntimeAuthorityKeyRegistrySnapshots.CountAsync();
            headsBefore = await baseline.RuntimeAuthorityKeyRegistryHeads.CountAsync();
            readbacksBefore = await baseline.RuntimeAuthorityKeyRegistryReadbacks.CountAsync();
        }
        await using (var connection = new NpgsqlConnection(provision.ConnectionString))
        {
            await connection.OpenAsync();
            await ExecuteAsync(connection, """
                ALTER TABLE public."RuntimeAuthorityKeyRegistrySnapshots"
                    DISABLE TRIGGER "TR_RAKRSnapshots_GuardRows";
                UPDATE public."RuntimeAuthorityKeyRegistrySnapshots"
                    SET "ExactResponseBody"=convert_to('[]','UTF8');
                ALTER TABLE public."RuntimeAuthorityKeyRegistrySnapshots"
                    ENABLE TRIGGER "TR_RAKRSnapshots_GuardRows";
                """);
        }

        var failure = await Assert.ThrowsAsync<RuntimeAuthorityKeyRegistryContractException>(() =>
            service.ReadCurrentAsync("new-client", RequestBody(Guid.NewGuid()), CancellationToken.None));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, failure.StatusCode);
        await using var readback = factory.CreateDbContext();
        Assert.Equal(snapshotsBefore, await readback.RuntimeAuthorityKeyRegistrySnapshots.CountAsync());
        Assert.Equal(headsBefore, await readback.RuntimeAuthorityKeyRegistryHeads.CountAsync());
        Assert.Equal(readbacksBefore, await readback.RuntimeAuthorityKeyRegistryReadbacks.CountAsync());
        Assert.False(await readback.RuntimeAuthorityKeyRegistryReadbacks
            .AnyAsync(item => item.ClientId == "new-client"));
    }

    /// <summary>Proves migration discovery retains the exact bounded item-1 migration identity.</summary>
    [Fact]
    public void MigrationAssembly_ContainsItem1Migration()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        Assert.Contains(Migration, db.GetService<IMigrationsAssembly>().Migrations.Keys);
    }

    /// <summary>Creates fresh public registry material and its valid independent authority signature.</summary>
    private static RuntimeEnrollmentOptions CreateRuntimeOptions(
        DateTimeOffset? observedAtUtc = null,
        string snapshotId = "registry-snapshot-item1",
        long version = 1)
    {
        using var registry = RSA.Create(2048);
        using var operational = RSA.Create(2048);
        using var recovery = RSA.Create(2048);
        return CreateRuntimeOptions(
            registry, operational, recovery, observedAtUtc ?? DateTimeOffset.UtcNow, snapshotId, version);
    }

    /// <summary>Creates a signed snapshot configuration over caller-owned stable key material.</summary>
    private static RuntimeEnrollmentOptions CreateRuntimeOptions(
        RSA registry,
        RSA operational,
        RSA recovery,
        DateTimeOffset observedAtUtc,
        string snapshotId,
        long version)
    {
        var wall = observedAtUtc;
        var observed = new DateTimeOffset(
            wall.Year, wall.Month, wall.Day, wall.Hour, wall.Minute, wall.Second, TimeSpan.Zero).AddTicks(1);
        var signing = new RuntimeAuthorityGenerationSigningOptions
        {
            ActiveSigningKeyId = "operational-2026-01",
            RegistrySnapshotId = snapshotId,
            RegistrySnapshotVersion = version,
            Keys =
            [
                Key("operational-2026-01", "operational", "generation", operational, observed,
                    operational.ExportPkcs8PrivateKeyPem()),
                Key("recovery-2026-01", "recovery", "recovery", recovery, observed, null)
            ]
        };
        var crypto = new RuntimeEnrollmentAuthorityCryptography(
            new FixedTimeProvider(observed), registry.ExportSubjectPublicKeyInfo());
        var input = crypto.GetRegistrySnapshotAuthenticationInput(signing, observed).Value!;
        return new()
        {
            Mode = "enabled",
            MaximumTransactionAttempts = 3,
            AuthorityGenerationSigning = signing,
            AuthorityGenerationV2 = new()
            {
                Mode = "enabled",
                RegistryAuthoritySpkiBase64 = Convert.ToBase64String(registry.ExportSubjectPublicKeyInfo()),
                RegistryObservedAtUtc = observed.ToString("O"),
                RegistrySnapshotSignatureBase64Url = Encode(
                    registry.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            }
        };
    }

    /// <summary>Builds one canonical readback request with a caller-selected semantic identity.</summary>
    private static byte[] RequestBody(Guid? requestId = null) => Encoding.UTF8.GetBytes(
        "{\"schema\":\"runtime-enrollment-authority-key-registry-readback-v1\",\"contractVersion\":1,\"requestId\":\"" +
        (requestId ?? Guid.Parse("11111111-1111-4111-8111-111111111111")).ToString("D") +
        "\",\"productId\":\"22222222-2222-4222-8222-222222222222\"}");

    /// <summary>Applies only the fixture-owned deferred promotion needed to prove revoked replay refusal.</summary>
    private static async Task PromoteAndRevokeAsync(
        string connectionString,
        RuntimeAuthorityKeyRegistryContract.Snapshot next)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE public."RuntimeAuthorityKeyRegistrySnapshots"
            SET "PublicationState"='revoked',"RevokedAtUtc"=clock_timestamp()
            WHERE "PublicationState"='current';
            INSERT INTO public."RuntimeAuthorityKeyRegistrySnapshots"
                ("SnapshotId","RegistryId","SnapshotVersion","MetadataDigestSha256",
                 "RegistryAuthenticationInputDigestSha256","ObservedAtUtc","PublicationState",
                 "RevokedAtUtc","ExactResponseBody","ExactResponseBodySha256",
                 "RegistrySignatureBase64Url","CreatedAtUtc")
            VALUES (@id,'runtime-enrollment-authority-generation-v2',@version,@metadata,@authentication,
                    @observed,'current',NULL,@body,@bodyDigest,@signature,clock_timestamp());
            UPDATE public."RuntimeAuthorityKeyRegistryHeads"
            SET "CurrentSnapshotId"=@id,"CurrentSnapshotVersion"=@version,
                "CurrentMetadataDigestSha256"=@metadata,
                "CurrentRegistryAuthenticationInputDigestSha256"=@authentication,
                "CurrentPublicationState"='current',"UpdatedAtUtc"=clock_timestamp();
            """;
        command.Parameters.AddWithValue("id", next.SnapshotId);
        command.Parameters.AddWithValue("version", next.SnapshotVersion);
        command.Parameters.AddWithValue("metadata", next.MetadataDigestSha256);
        command.Parameters.AddWithValue("authentication", next.RegistryAuthenticationInputDigestSha256);
        command.Parameters.AddWithValue("observed", next.ObservedAtUtc);
        command.Parameters.AddWithValue("body", next.ExactResponseBody);
        command.Parameters.AddWithValue("bodyDigest", next.ExactResponseBodySha256);
        command.Parameters.AddWithValue("signature", next.SignatureBase64Url);
        await command.ExecuteNonQueryAsync();
        await transaction.CommitAsync();
    }

    /// <summary>Creates one exact configured key without transforming its identifier or lifecycle.</summary>
    private static RuntimeAuthorityGenerationKeyOptions Key(
        string id, string purpose, string domain, RSA rsa, DateTimeOffset observed, string? privateKey) => new()
    {
        KeyId = id,
        Purpose = purpose,
        Domain = domain,
        ContractVersion = 2,
        Status = "active",
        PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
        PrivateKeyPem = privateKey,
        ActivatedAtUtc = observed.AddDays(-1)
    };

    /// <summary>Encodes canonical unpadded Base64Url.</summary>
    private static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Executes one bounded fixture-owned PostgreSQL statement.</summary>
    private static async Task<int> ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteNonQueryAsync();
    }

    /// <summary>Supplies the authenticated test observation as trusted time.</summary>
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        /// <inheritdoc />
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>Creates independent non-pooled contexts for the real service transaction boundary.</summary>
    private sealed class TestDbFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);
    }

    /// <summary>Owns one isolated PostgreSQL database and drops only that database after the proof.</summary>
    private sealed class PostgreSqlProvision(
        string maintenanceConnectionString,
        string connectionString,
        string database) : IAsyncDisposable
    {
        /// <summary>Gets the isolated application database connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Creates and migrates one UUID-named database on the configured PostgreSQL authority.</summary>
        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "SOFTLICENCE_RUNTIME_TEST_POSTGRES is required for TKT-000789 PostgreSQL tests.");
            var database = "tkt789_registry_" + Guid.NewGuid().ToString("N");
            var maintenance = new NpgsqlConnectionStringBuilder(configured)
            {
                Database = "postgres",
                Pooling = false
            }.ConnectionString;
            await using (var connection = new NpgsqlConnection(maintenance))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"CREATE DATABASE \"{database}\"");
            }
            var target = new NpgsqlConnectionStringBuilder(configured)
            {
                Database = database,
                Pooling = false
            }.ConnectionString;
            var options = new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(target).Options;
            await using (var db = new LicenseDbContext(options))
                await db.GetService<IMigrator>().MigrateAsync(Migration);
            return new(maintenance, target, database);
        }

        /// <summary>Clears pools and force-drops only the fixture-owned UUID database.</summary>
        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(maintenanceConnectionString);
            await connection.OpenAsync();
            await ExecuteAsync(connection, $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)");
        }
    }
}

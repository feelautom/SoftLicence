using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Verifies the production PostgreSQL migration enforces the additive v3/v4 authority shape.</summary>
public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Fact]
    public async Task Tkt000686_PostgreSql_RejectsV4WithoutAuthorityTuple_AndAllowsV3()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);

        await using var db = await factory.CreateDbContextAsync();
        var v3 = new SoftLicence.Server.Data.DistributionEntitlement
        {
            Id = Guid.NewGuid(), ClientId = "website-step1", ProductId = fixture.ProductId,
            LicenseId = fixture.LicenseId, GrantRefDigestSha256 = new string('a', 64),
            SubjectRefDigestSha256 = new string('b', 64), ContractVersion = 3,
            State = "issued", IssuedAtUtc = DateTime.UtcNow, ExpiresAtUtc = DateTime.UtcNow.AddHours(1)
        };
        db.DistributionEntitlements.Add(v3);
        await db.SaveChangesAsync();

        db.ChangeTracker.Clear();
        var v4 = new SoftLicence.Server.Data.DistributionEntitlement
        {
            Id = Guid.NewGuid(), ClientId = "website-step1", ProductId = fixture.ProductId,
            LicenseId = fixture.LicenseId, GrantRefDigestSha256 = new string('c', 64),
            SubjectRefDigestSha256 = new string('d', 64), ContractVersion = 4,
            State = "issued", IssuedAtUtc = DateTime.UtcNow, ExpiresAtUtc = DateTime.UtcNow.AddHours(1)
        };
        db.DistributionEntitlements.Add(v4);
        var failure = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation,
            Assert.IsType<PostgresException>(failure.InnerException).SqlState);
    }

    [Fact]
    public async Task Tkt000686_PostgreSql_DirectSqlRejectsDivergentAndMutableAuthorityTuple_ButAllowsLifecycle()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var authority = await SeedTkt000686AuthorityAsync(
            factory, fixture.ProductId, fixture.Version, fixture.GrantRef);
        var now = DateTime.UtcNow;

        var mismatches = new[]
        {
            (ProductId: Guid.NewGuid(), GrantDigest: Sha256(fixture.GrantRef), ArtifactDigest: authority.ArtifactDigest),
            (ProductId: fixture.ProductId, GrantDigest: new string('f', 64), ArtifactDigest: authority.ArtifactDigest),
            (ProductId: fixture.ProductId, GrantDigest: Sha256(fixture.GrantRef), ArtifactDigest: new string('e', 64))
        };
        foreach (var mismatchTuple in mismatches)
        {
            await using var mismatchDb = await factory.CreateDbContextAsync();
            var mismatch = await Assert.ThrowsAsync<PostgresException>(() =>
                mismatchDb.Database.ExecuteSqlInterpolatedAsync($$"""
                    INSERT INTO "DistributionEntitlements"
                        ("Id", "ClientId", "ProductId", "LicenseId", "GrantRefDigestSha256",
                         "SubjectRefDigestSha256", "AuthorityLineageId", "AuthorityGenerationId",
                         "ArtifactSetDigestSha256", "ContractVersion", "State", "IssuedAtUtc", "ExpiresAtUtc")
                    VALUES
                        ({{Guid.NewGuid()}}, 'website-step1', {{mismatchTuple.ProductId}}, {{fixture.LicenseId}},
                         {{mismatchTuple.GrantDigest}}, {{new string('b', 64)}}, {{authority.LineageId}},
                         {{authority.GenerationId}}, {{mismatchTuple.ArtifactDigest}}, 4, 'issued', {{now}}, {{now.AddHours(1)}})
                    """));
            Assert.Equal(PostgresErrorCodes.CheckViolation, mismatch.SqlState);
            Assert.Contains("TKT000686 authority tuple is inconsistent", mismatch.MessageText, StringComparison.Ordinal);
        }

        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), new FixedTimeProvider(new DateTimeOffset(now)),
            TestHardwareAuthorityAliasResolver.Instance);
        await service.IssueEntitlementAsync("website-step1", Sha256("tkt000686-direct-sql-valid"),
            Tkt000686IssueRequest(fixture, authority.GenerationId, Guid.NewGuid().ToString("D")));

        Guid entitlementId;
        await using (var lifecycleDb = await factory.CreateDbContextAsync())
        {
            entitlementId = await lifecycleDb.DistributionEntitlements
                .Where(item => item.ProductId == fixture.ProductId)
                .Select(item => item.Id)
                .SingleAsync();
            var requestedFinalizedAtUtc = now.AddMinutes(1);
            var finalizedAtUtc = new DateTime(
                requestedFinalizedAtUtc.Ticks - requestedFinalizedAtUtc.Ticks % 10,
                DateTimeKind.Utc);
            var updated = await lifecycleDb.Database.ExecuteSqlInterpolatedAsync($$"""
                UPDATE "DistributionEntitlements"
                SET "State" = 'finalized', "FinalizedAtUtc" = {{finalizedAtUtc}}
                WHERE "Id" = {{entitlementId}}
                """);
            Assert.Equal(1, updated);
            lifecycleDb.ChangeTracker.Clear();
            var lifecycle = await lifecycleDb.DistributionEntitlements.AsNoTracking()
                .SingleAsync(item => item.Id == entitlementId);
            Assert.Equal("finalized", lifecycle.State);
            Assert.Equal(finalizedAtUtc, lifecycle.FinalizedAtUtc);
        }

        var protectedUpdates = new[]
        {
            "UPDATE \"DistributionEntitlements\" SET \"ProductId\" = '018f6fd4-8f31-4cc2-8d19-9e79c8b87a03' WHERE \"Id\" = {0}",
            "UPDATE \"DistributionEntitlements\" SET \"LicenseId\" = '018f6fd4-8f31-4cc2-8d19-9e79c8b87a04' WHERE \"Id\" = {0}",
            $"UPDATE \"DistributionEntitlements\" SET \"GrantRefDigestSha256\" = '{new string('d', 64)}' WHERE \"Id\" = {{0}}",
            $"UPDATE \"DistributionEntitlements\" SET \"SubjectRefDigestSha256\" = '{new string('e', 64)}' WHERE \"Id\" = {{0}}",
            "UPDATE \"DistributionEntitlements\" SET \"ContractVersion\" = 3 WHERE \"Id\" = {0}",
            "UPDATE \"DistributionEntitlements\" SET \"AuthorityLineageId\" = '018f6fd4-8f31-4cc2-8d19-9e79c8b87a01' WHERE \"Id\" = {0}",
            "UPDATE \"DistributionEntitlements\" SET \"AuthorityGenerationId\" = '018f6fd4-8f31-4cc2-8d19-9e79c8b87a02' WHERE \"Id\" = {0}",
            $"UPDATE \"DistributionEntitlements\" SET \"ArtifactSetDigestSha256\" = '{new string('f', 64)}' WHERE \"Id\" = {{0}}",
            "UPDATE \"DistributionEntitlements\" SET \"IssuedAtUtc\" = \"IssuedAtUtc\" - interval '1 second' WHERE \"Id\" = {0}",
            "UPDATE \"DistributionEntitlements\" SET \"ExpiresAtUtc\" = \"ExpiresAtUtc\" + interval '1 second' WHERE \"Id\" = {0}"
        };
        foreach (var sql in protectedUpdates)
        {
            await using var immutableDb = await factory.CreateDbContextAsync();
            var immutable = await Assert.ThrowsAsync<PostgresException>(() =>
                immutableDb.Database.ExecuteSqlRawAsync(sql, entitlementId));
            Assert.Equal(PostgresErrorCodes.CheckViolation, immutable.SqlState);
            Assert.Contains("TKT000686 protected authority tuple is immutable",
                immutable.MessageText, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("incomplete")]
    [InlineData("wrong-linked")]
    [InlineData("malformed")]
    public async Task Tkt000686_V4_RegistrationChildren_FailClosedInServiceAndDirectSql(string mutation)
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var artifactDigest = await RegisterTkt000686ReleaseAsync(factory, fixture.ProductId, fixture.Version);
        await using (var mutationDb = await factory.CreateDbContextAsync())
        {
            var row = await mutationDb.ApprovedBinaries.SingleAsync(item =>
                item.ProductId == fixture.ProductId && item.Version == fixture.Version
                && item.Key == (mutation == "incomplete" ? "FP_CORE" : "FP_EXE"));
            switch (mutation)
            {
                case "incomplete":
                    mutationDb.ApprovedBinaries.Remove(row);
                    break;
                case "wrong-linked":
                    row.Version = fixture.Version + "-wrong";
                    break;
                case "malformed":
                    row.Hash = new string('d', 64);
                    break;
            }
            await mutationDb.SaveChangesAsync();
        }
        var authority = await PersistTkt000686AuthorityAsync(
            factory, fixture.ProductId, fixture.Version, fixture.GrantRef, artifactDigest);

        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), TimeProvider.System,
            TestHardwareAuthorityAliasResolver.Instance);
        var issueFailure = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.IssueEntitlementAsync("website-step1", Sha256("tkt000686-malformed-" + mutation),
                Tkt000686IssueRequest(fixture, authority.GenerationId, Guid.NewGuid().ToString("D"))));
        Assert.Equal("entitlement_ineligible", issueFailure.ErrorCode);

        await using var directDb = await factory.CreateDbContextAsync();
        var now = DateTime.UtcNow;
        var directFailure = await Assert.ThrowsAsync<PostgresException>(() =>
            directDb.Database.ExecuteSqlInterpolatedAsync($$"""
                INSERT INTO "DistributionEntitlements"
                    ("Id", "ClientId", "ProductId", "LicenseId", "GrantRefDigestSha256",
                     "SubjectRefDigestSha256", "AuthorityLineageId", "AuthorityGenerationId",
                     "ArtifactSetDigestSha256", "ContractVersion", "State", "IssuedAtUtc", "ExpiresAtUtc")
                VALUES
                    ({{Guid.NewGuid()}}, 'website-step1', {{fixture.ProductId}}, {{fixture.LicenseId}},
                     {{Sha256(fixture.GrantRef)}}, {{new string('b', 64)}}, {{authority.LineageId}},
                     {{authority.GenerationId}}, {{authority.ArtifactDigest}}, 4, 'issued', {{now}}, {{now.AddHours(1)}})
                """));
        Assert.Equal(PostgresErrorCodes.CheckViolation, directFailure.SqlState);
        Assert.Contains("TKT000686 authority tuple is inconsistent",
            directFailure.MessageText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tkt000686_V4_ConcurrentIssue_ReplaysAfterRotation_AndFinalizesFrozenGeneration()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var authority = await SeedTkt000686AuthorityAsync(factory, fixture.ProductId, fixture.Version, fixture.GrantRef);
        var protectorProvider = new EphemeralDataProtectionProvider();
        var now = DateTimeOffset.UtcNow;
        var firstService = new DistributionInstallationBindingService(
            factory, protectorProvider, new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var secondService = new DistributionInstallationBindingService(
            factory, protectorProvider, new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var requestId = Guid.NewGuid().ToString("D");
        var request = Tkt000686IssueRequest(fixture, authority.GenerationId, requestId);
        var digest = Sha256("tkt000686-concurrent-exact");

        var outcomes = await Task.WhenAll(
            firstService.IssueEntitlementAsync("website-step1", digest, request),
            secondService.IssueEntitlementAsync("website-step1", digest,
                Tkt000686IssueRequest(fixture, authority.GenerationId, requestId)));

        Assert.Single(outcomes, item => !item.Idempotent);
        Assert.Single(outcomes, item => item.Idempotent);
        Assert.Equal(outcomes[0].Response, outcomes[1].Response);
        await using (var ownershipVerification = await factory.CreateDbContextAsync())
        {
            var ownership = await ownershipVerification.DistributionGrantOwnerships.SingleAsync(item =>
                item.ProductId == fixture.ProductId
                && item.GrantRefDigestSha256 == Sha256(fixture.GrantRef));
            Assert.Equal("issue_v4", ownership.Source);
        }

        var divergent = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            firstService.IssueEntitlementAsync("website-step1", Sha256("tkt000686-divergent"),
                Tkt000686IssueRequest(fixture, authority.GenerationId, requestId)));
        Assert.Equal("idempotency_conflict", divergent.ErrorCode);

        await RotateTkt000686AuthorityAsync(factory, authority, fixture.ProductId, fixture.Version, fixture.GrantRef);
        await using (var eligibility = await factory.CreateDbContextAsync())
        {
            var license = await eligibility.Licenses.SingleAsync(item => item.Id == fixture.LicenseId);
            license.IsActive = false;
            await eligibility.SaveChangesAsync();
        }
        var replay = await firstService.IssueEntitlementAsync("website-step1", digest,
            Tkt000686IssueRequest(fixture, authority.GenerationId, requestId));
        Assert.True(replay.Idempotent);
        Assert.Equal(outcomes[0].Response, replay.Response);

        await using (var eligibility = await factory.CreateDbContextAsync())
        {
            var license = await eligibility.Licenses.SingleAsync(item => item.Id == fixture.LicenseId);
            license.IsActive = true;
            await eligibility.SaveChangesAsync();
        }
        var finalized = await firstService.FinalizeAsync("website-step1", Sha256("tkt000686-finalize"),
            Tkt000686FinalizeRequest(fixture, replay.Response.EntitlementRef, now));
        Assert.Equal("active", finalized.Response.State);
        await using var verification = await factory.CreateDbContextAsync();
        var persisted = await verification.DistributionEntitlements
            .SingleAsync(item => item.ProductId == fixture.ProductId);
        Assert.Equal(4, persisted.ContractVersion);
        Assert.Equal("finalized", persisted.State);
        Assert.Equal(authority.GenerationId, persisted.AuthorityGenerationId);
    }

    [Fact]
    public async Task Tkt000686_V4_PostGrantWaiter_ReplaysFrozenResponseAfterCommittedRotation()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var authority = await SeedTkt000686AuthorityAsync(factory, fixture.ProductId, fixture.Version, fixture.GrantRef);
        var protector = new EphemeralDataProtectionProvider();
        var now = DateTimeOffset.UtcNow;
        var firstService = new DistributionInstallationBindingService(
            factory, protector, new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var waiterService = new DistributionInstallationBindingService(
            factory, protector, new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var requestId = Guid.NewGuid().ToString("D");
        var digest = Sha256("tkt000686-post-lock-replay");

        await using var insertGate = new NpgsqlConnection(connections.App);
        await insertGate.OpenAsync();
        await using var insertGateTransaction = await insertGate.BeginTransactionAsync();
        await using (var command = new NpgsqlCommand(
            "LOCK TABLE \"DistributionBindingRequests\" IN SHARE MODE", insertGate, insertGateTransaction))
            await command.ExecuteNonQueryAsync();

        var first = firstService.IssueEntitlementAsync("website-step1", digest,
            Tkt000686IssueRequest(fixture, authority.GenerationId, requestId));
        await WaitForPostgreSqlWaitAsync(connections.App, "relation");

        var waiter = waiterService.IssueEntitlementAsync("website-step1", digest,
            Tkt000686IssueRequest(fixture, authority.GenerationId, requestId));
        await WaitForPostgreSqlWaitAsync(connections.App, "advisory");

        await using var replayGate = new NpgsqlConnection(connections.App);
        await replayGate.OpenAsync();
        await using var replayGateTransaction = await replayGate.BeginTransactionAsync();
        await using var replayGateCommand = new NpgsqlCommand(
            "LOCK TABLE \"DistributionBindingRequests\" IN ACCESS EXCLUSIVE MODE",
            replayGate, replayGateTransaction);
        var replayGateQueued = replayGateCommand.ExecuteNonQueryAsync();

        await insertGateTransaction.CommitAsync();
        var issued = await first;
        await replayGateQueued;
        await RotateTkt000686AuthorityAsync(
            factory, authority, fixture.ProductId, fixture.Version, fixture.GrantRef);
        await replayGateTransaction.CommitAsync();

        var replayed = await waiter;
        Assert.False(issued.Idempotent);
        Assert.True(replayed.Idempotent);
        Assert.Equal(issued.Response, replayed.Response);
        var divergent = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            waiterService.IssueEntitlementAsync("website-step1", Sha256("tkt000686-post-lock-divergent"),
                Tkt000686IssueRequest(fixture, authority.GenerationId, requestId)));
        Assert.Equal("idempotency_conflict", divergent.ErrorCode);
    }

    [Fact]
    public async Task Tkt000686_V4_IssueV3OwnershipPairing_FailsClosed()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var authority = await SeedTkt000686AuthorityAsync(factory, fixture.ProductId, fixture.Version, fixture.GrantRef);
        await using (var db = await factory.CreateDbContextAsync())
        {
            db.DistributionGrantOwnerships.Add(new DistributionGrantOwnership
            {
                ProductId = fixture.ProductId,
                GrantRefDigestSha256 = Sha256(fixture.GrantRef),
                ClientId = "website-step1",
                Source = "issue_v3",
                CreatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }

        var service = new DistributionInstallationBindingService(
            factory, new EphemeralDataProtectionProvider(), TimeProvider.System,
            TestHardwareAuthorityAliasResolver.Instance);
        var failure = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.IssueEntitlementAsync("website-step1", Sha256("tkt000686-source-pair-mismatch"),
                Tkt000686IssueRequest(fixture, authority.GenerationId, Guid.NewGuid().ToString("D"))));

        Assert.Equal("grant_ownership_conflict", failure.ErrorCode);
    }

    [Fact]
    public async Task Tkt000686_V4_TokenTupleAndFinalizeArtifacts_FailClosedOrdinally()
    {
        var connections = await ProvisionAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedDistributionAuthorityWithoutBindingAsync(factory);
        var authority = await SeedTkt000686AuthorityAsync(factory, fixture.ProductId, fixture.Version, fixture.GrantRef);
        var protectorProvider = new EphemeralDataProtectionProvider();
        var now = DateTimeOffset.UtcNow;
        var service = new DistributionInstallationBindingService(
            factory, protectorProvider, new FixedTimeProvider(now), TestHardwareAuthorityAliasResolver.Instance);
        var issued = await service.IssueEntitlementAsync("website-step1", Sha256("tkt000686-tamper-issue"),
            Tkt000686IssueRequest(fixture, authority.GenerationId, Guid.NewGuid().ToString("D")));

        var wrongArtifacts = Tkt000686FinalizeRequest(fixture, issued.Response.EntitlementRef, now);
        wrongArtifacts.Binaries![0].Sha256 = new string('f', 64);
        var binaryFailure = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync("website-step1", Sha256("tkt000686-tamper-finalize"), wrongArtifacts));
        Assert.Equal("binary_mismatch", binaryFailure.ErrorCode);

        var protector = protectorProvider.CreateProtector(DistributionInstallationBindingService.EntitlementPurpose);
        await using var db = await factory.CreateDbContextAsync();
        var row = await db.DistributionEntitlements
            .SingleAsync(item => item.ProductId == fixture.ProductId);
        var tamperedToken = protector.Protect(JsonSerializer.Serialize(new
        {
            schema = DistributionInstallationBindingService.IssueV2ResponseSchema,
            entitlementId = row.Id.ToString("D"), clientId = "website-step1",
            licenseId = row.LicenseId.ToString("D"), productId = row.ProductId.ToString("D"),
            issuedAtUtc = FormatUtc(new DateTimeOffset(DateTime.SpecifyKind(row.IssuedAtUtc, DateTimeKind.Utc))),
            expiresAtUtc = FormatUtc(new DateTimeOffset(DateTime.SpecifyKind(row.ExpiresAtUtc, DateTimeKind.Utc))),
            grantRefDigestSha256 = row.GrantRefDigestSha256,
            subjectRefDigestSha256 = row.SubjectRefDigestSha256, contractVersion = 4,
            authorityLineageId = row.AuthorityLineageId!.Value.ToString("D"),
            authorityGenerationId = Guid.NewGuid().ToString("D"),
            artifactSetDigestSha256 = row.ArtifactSetDigestSha256
        }));
        var tokenFailure = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            DistributionInstallationBindingService.ReadEntitlementAsync(
                db, protector, tamperedToken, "website-step1", fixture.ProductId, now, default));
        Assert.Equal("entitlement_ineligible", tokenFailure.ErrorCode);
    }

    /// <summary>Seeds one canonical provider-issued generation and its exact release registration.</summary>
    private static async Task<Tkt000686Authority> SeedTkt000686AuthorityAsync(
        TestDbFactory factory, Guid productId, string version, string grantRef)
    {
        var artifactDigest = await RegisterTkt000686ReleaseAsync(factory, productId, version);
        return await PersistTkt000686AuthorityAsync(factory, productId, version, grantRef, artifactDigest);
    }

    /// <summary>Registers the exact release through the production release-registration boundary.</summary>
    private static async Task<string> RegisterTkt000686ReleaseAsync(
        TestDbFactory factory, Guid productId, string version)
    {
        var artifacts = new List<ApprovedBinaryArtifact>
        {
            new("FP_EXE", new string('a', 64)),
            new("FP_DLL", new string('b', 64)),
            new("FP_CORE", new string('c', 64))
        };
        await using (var db = await factory.CreateDbContextAsync())
        {
            var rows = await db.ApprovedBinaries.Where(item => item.ProductId == productId && item.Version == version).ToListAsync();
            db.ApprovedBinaries.RemoveRange(rows);
            await db.SaveChangesAsync();
        }
        var registrationResult = await new ApprovedBinaryService(
                factory, NullLogger<ApprovedBinaryService>.Instance)
            .RegisterReleaseBaselineAsync(productId, version, $"tkt000686-{productId:D}",
                new string('e', 64), artifacts);
        Assert.True(registrationResult.ProductExists);
        Assert.Equal(ApprovedBinaryVerdict.Approved, registrationResult.Result.Verdict);
        var artifactDigest = Assert.IsType<string>(registrationResult.Result.BaselineDigestSha256);
        Assert.Equal(ApprovedBinaryService.ComputeBaselineDigestSha256(artifacts), artifactDigest);
        return artifactDigest;
    }

    /// <summary>Persists one provider-issued authority generation over an already registered release.</summary>
    private static async Task<Tkt000686Authority> PersistTkt000686AuthorityAsync(
        TestDbFactory factory, Guid productId, string version, string grantRef, string artifactDigest)
    {
        var lineageId = Guid.NewGuid();
        var generationId = Guid.NewGuid();
        var payload = Tkt000686Payload(lineageId, generationId, null, 0, productId, version, grantRef, artifactDigest);
        await using (var db = await factory.CreateDbContextAsync())
        {
            var result = await AuthorityPersistence(factory).PersistValidatedGenerationAsync(db,
                Tkt000686Candidate(payload, lineageId, generationId, null, 0, productId, grantRef));
            Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created, result.Status);
        }
        return new(lineageId, generationId, artifactDigest);
    }

    /// <summary>Appends a canonical successor solely to prove old entitlement replay/finalize ignores the later head.</summary>
    private static async Task RotateTkt000686AuthorityAsync(
        TestDbFactory factory, Tkt000686Authority previous, Guid productId, string version, string grantRef)
    {
        var generationId = Guid.NewGuid();
        var payload = Tkt000686Payload(previous.LineageId, generationId, previous.GenerationId, 1,
            productId, version, grantRef, previous.ArtifactDigest);
        await using var db = await factory.CreateDbContextAsync();
        var result = await AuthorityPersistence(factory).PersistValidatedGenerationAsync(db,
            Tkt000686Candidate(payload, previous.LineageId, generationId, previous.GenerationId, 1,
                productId, grantRef));
        Assert.Equal(RuntimeEnrollmentAuthorityPersistenceStatus.Created, result.Status);
    }

    /// <summary>Builds one closed canonical v2 payload with exact opaque grant and release evidence.</summary>
    private static byte[] Tkt000686Payload(Guid lineageId, Guid generationId, Guid? predecessor, long sequence,
        Guid productId, string version, string grantRef, string artifactDigest) =>
        JsonSerializer.SerializeToUtf8Bytes(new RuntimeEnrollmentAuthorityGenerationPayloadV2
        {
            Schema = "runtime-enrollment-authority-generation-v2", ContractVersion = 2,
            AuthorityLineageId = lineageId.ToString("D"), AuthorityGenerationId = generationId.ToString("D"),
            PreviousGenerationId = predecessor?.ToString("D"), Sequence = sequence, Provider = "softlicence",
            ProductId = productId.ToString("D"), ProviderGrantRef = grantRef,
            Release = new() { Version = version, ArtifactSetDigest = artifactDigest },
            Binding = new() { BindingId = Guid.NewGuid().ToString("D"), HardwareIdDigest = new string('1', 64) },
            Enrollment = new() { EnrollmentId = Guid.NewGuid().ToString("D"), State = "active", IssuedAtUtc = "2026-08-26T08:00:00.000000Z", ExpiresAtUtc = null },
            Key = new() { AuthorityKeyId = "operational-2026-01", SecurityEpoch = 1 },
            Installation = new() { InstallationId = Guid.NewGuid().ToString("D"), SeatId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" },
            Transition = new() { Kind = sequence == 0 ? "genesis" : "successor", ReasonCode = sequence == 0 ? "INITIAL_ENROLLMENT" : "APPROVED_RELEASE_ADVANCE", RequestId = Guid.NewGuid().ToString("D"), OccurredAtUtc = $"2026-08-26T08:00:0{sequence}.000000Z" }
        }, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());

    /// <summary>Wraps already canonical payload bytes for the production authority persistence boundary.</summary>
    private static RuntimeEnrollmentAuthorityPersistenceCandidate Tkt000686Candidate(byte[] payload,
        Guid lineageId, Guid generationId, Guid? predecessor, long sequence, Guid productId, string grantRef) => new()
    {
        AuthorityLineageId = lineageId, AuthorityGenerationId = generationId, RequestId = Guid.NewGuid(),
        RequestDigest = Convert.ToHexStringLower(SHA256.HashData(Guid.NewGuid().ToByteArray())),
        Provider = "softlicence", ProductId = productId,
        LicenseSeatId = Guid.Parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), ProviderGrantRef = grantRef,
        ProviderGrantRefScalarCount = grantRef.EnumerateRunes().Count(), LineageCreatedAtUtc = new DateTime(2026, 8, 26, 8, 0, 0, DateTimeKind.Utc),
        Sequence = sequence, PreviousGenerationId = predecessor, CanonicalPayloadUtf8 = payload,
        SignedStatementUtf8 = Encoding.UTF8.GetBytes("signed"), AuthorityDigest = Convert.ToHexStringLower(SHA256.HashData(payload)),
        SignatureAlgorithm = "PS256", SignatureKeyId = "tkt000686-key", SignatureValue = new string('A', 342),
        OccurredAtUtc = new DateTime(2026, 8, 26, 8, 0, (int)sequence, DateTimeKind.Utc),
        CreatedAtUtc = new DateTime(2026, 8, 26, 8, 0, (int)sequence, DateTimeKind.Utc)
    };

    /// <summary>Waits until the task-owned database exposes the requested PostgreSQL lock wait.</summary>
    private static async Task WaitForPostgreSqlWaitAsync(string connectionString, string waitEvent)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync();
        for (var attempt = 0; attempt < 200; attempt++)
        {
            await using var command = new NpgsqlCommand("""
                SELECT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_stat_activity
                    WHERE datname = current_database()
                      AND wait_event_type = 'Lock'
                      AND lower(wait_event) = @wait_event)
                """, observer);
            command.Parameters.AddWithValue("wait_event", waitEvent);
            if (Assert.IsType<bool>(await command.ExecuteScalarAsync()))
                return;
            await Task.Delay(25);
        }
        throw new TimeoutException($"PostgreSQL did not expose the expected {waitEvent} lock wait.");
    }

    /// <summary>Creates one exact v4 issue request without sharing mutable request instances.</summary>
    private static DistributionEntitlementIssueRequest Tkt000686IssueRequest(
        (Guid ProductId, Guid LicenseId, string HardwareId, string Version, string GrantRef) fixture,
        Guid generationId, string requestId) => new()
    {
        Schema = DistributionInstallationBindingService.IssueV4Schema, RequestId = requestId,
        ProductId = fixture.ProductId.ToString("D"), SoftLicenceLicenseId = fixture.LicenseId.ToString("D"),
        GrantRefDigestSha256 = Sha256(fixture.GrantRef),
        SubjectRef = Convert.ToBase64String(SHA256.HashData("tkt000686-subject"u8.ToArray())).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
        AuthorityGenerationId = generationId.ToString("D")
    };

    /// <summary>Creates exact Finalize evidence matching the frozen v4 registration.</summary>
    private static DistributionInstallationFinalizeRequest Tkt000686FinalizeRequest(
        (Guid ProductId, Guid LicenseId, string HardwareId, string Version, string GrantRef) fixture,
        string entitlementRef, DateTimeOffset now) => new()
    {
        Schema = DistributionInstallationBindingService.FinalizeV2Schema, RequestId = Guid.NewGuid().ToString("D"),
        AllowSameAuthorityRecovery = true,
        GrantRef = fixture.GrantRef, HandoffDigestSha256 = Sha256(Guid.NewGuid().ToString("D")),
        HandoffIssuedAtUtc = FormatUtc(now.AddMinutes(-2)), HandoffExpiresAtUtc = FormatUtc(now.AddMinutes(20)),
        DownloadCompletedAtUtc = FormatUtc(now.AddMinutes(-1)), ProductId = fixture.ProductId.ToString("D"),
        EntitlementRef = entitlementRef, InstallationId = Guid.NewGuid().ToString("D"), HardwareId = fixture.HardwareId,
        Release = new() { Version = fixture.Version, InstallerFilename = $"TiaConnect-Setup_v{fixture.Version}.exe", InstallerSha256 = new string('d', 64) },
        Binaries = [new() { Key = "FP_EXE", Sha256 = new string('a', 64) }, new() { Key = "FP_DLL", Sha256 = new string('b', 64) }, new() { Key = "FP_CORE", Sha256 = new string('c', 64) }]
    };

    /// <summary>Identifies the exact seeded authority tuple used by Stage 2 tests.</summary>
    private sealed record Tkt000686Authority(Guid LineageId, Guid GenerationId, string ArtifactDigest);
}

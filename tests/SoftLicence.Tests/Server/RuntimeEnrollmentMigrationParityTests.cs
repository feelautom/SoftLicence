using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using System.Text;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves terminal authority-result relation metadata remains identical across model and migration artifacts.</summary>
public sealed class RuntimeEnrollmentAuthorityTerminalRelationParityTests
{
    /// <summary>
    /// Verifies exact terminal shapes, ordered composite keys, raw nullable-result FK ownership, and model
    /// annotations in the migration, designer, and current snapshot without connecting to PostgreSQL.
    /// </summary>
    [Fact]
    public void AuthorityTerminalRelations_ModelMigrationAndSnapshotRemainExact()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=127.0.0.1;Database=not-opened;Username=not-opened;Password=not-opened")
            .Options;
        using var db = new LicenseDbContext(options);
        var model = db.GetService<Microsoft.EntityFrameworkCore.Metadata.IDesignTimeModel>().Model;
        var request = model.FindEntityType(typeof(RuntimeEnrollmentAuthorityRequest))!;
        var attempt = model.FindEntityType(typeof(RuntimeEnrollmentAuthorityAttempt))!;
        var generation = model.FindEntityType(typeof(RuntimeEnrollmentAuthorityGeneration))!;

        Assert.Equal(
            "(\"ResultCode\" = 'ACCEPTED' AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"ResultCode\" = 'REFUSED' AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400, 403, 409, 503))",
            request.GetCheckConstraints().Single(item => item.Name == "CK_REAuthorityRequests_TerminalShape").Sql);
        Assert.Equal(
            "(\"Status\" = 'ACCEPTED' AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"Status\" = 'REFUSED' AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400, 403, 409, 503))",
            attempt.GetCheckConstraints().Single(item => item.Name == "CK_REAuthorityAttempts_TerminalShape").Sql);
        Assert.Equal(new[] { "AuthorityLineageId", "AuthorityGenerationId", "RequestId" },
            request.GetForeignKeys().Single(item =>
                item.GetConstraintName() == "FK_REAuthorityRequests_REAuthorityGenerations_Result")
                .Properties.Select(item => item.Name));
        Assert.Contains(generation.GetKeys(), key => key.GetName()
            == "AK_REAuthorityGenerations_LineageId_GenerationId_RequestId");
        Assert.Equal("RequestId,AuthorityLineageId,AuthorityGenerationId|NO ACTION",
            attempt["RuntimeEnrollment:CompositeRequestResultForeignKey"]);

        var root = RepositoryRoot();
        var relativeFiles = new[]
        {
            "src/SoftLicence.Server/Migrations/20260824114500_AddRuntimeEnrollmentAuthorityAttemptResults.cs",
            "src/SoftLicence.Server/Migrations/20260824114500_AddRuntimeEnrollmentAuthorityAttemptResults.Designer.cs",
            "src/SoftLicence.Server/Migrations/LicenseDbContextModelSnapshot.cs"
        };
        var sources = relativeFiles.Select(path => File.ReadAllText(Path.Combine(root, path))).ToArray();
        foreach (var source in sources)
        {
            Assert.Contains("AK_REAuthorityGenerations_LineageId_GenerationId_RequestId", source, StringComparison.Ordinal);
            Assert.Contains("FK_REAuthorityRequests_REAuthorityGenerations_Result", source, StringComparison.Ordinal);
            Assert.Contains("RequestId", source, StringComparison.Ordinal);
            Assert.Contains("AuthorityLineageId", source, StringComparison.Ordinal);
            Assert.Contains("AuthorityGenerationId", source, StringComparison.Ordinal);
        }
        Assert.Contains("FK_REAuthorityAttempts_REAuthorityRequests_Terminal", sources[0], StringComparison.Ordinal);
        Assert.Contains("RuntimeEnrollment:CompositeRequestResultForeignKey", sources[1], StringComparison.Ordinal);
        Assert.Contains("RuntimeEnrollment:CompositeRequestResultForeignKey", sources[2], StringComparison.Ordinal);
    }

    /// <summary>Finds the repository root without mutating the filesystem.</summary>
    /// <returns>The directory containing both source and test roots.</returns>
    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null; directory = directory.Parent)
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "tests")))
                return directory.FullName;
        throw new InvalidOperationException("Repository root was not found.");
    }
}

public sealed class RuntimeEnrollmentMigrationParityTests
{
    /// <summary>
    /// Proves TKT-000779 models the opaque subject with a product-scoped key and installs exact
    /// NO ACTION ownership relations to Product, the same-product License, and the same-product subject.
    /// </summary>
    [Fact]
    public void RuntimeRecoveryCommercialSubjectMigration_ContainsExactProductScopedRelations()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var subject = db.Model.FindEntityType(typeof(RuntimeRecoveryCommercialSubject))!;
        var ownership = db.Model.FindEntityType(typeof(RuntimeRecoveryCommercialOwnership))!;

        Assert.Equal(["ProductId", "Id"], subject.FindPrimaryKey()!.Properties
            .Select(property => property.Name));
        Assert.All(subject.GetForeignKeys(), foreignKey =>
            Assert.Equal(DeleteBehavior.NoAction, foreignKey.DeleteBehavior));
        Assert.Contains(ownership.GetForeignKeys(), foreignKey =>
            foreignKey.GetConstraintName() == "FK_RRCO_Products_ProductId"
            && foreignKey.Properties.Select(property => property.Name).SequenceEqual(["ProductId"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);
        Assert.Contains(ownership.GetForeignKeys(), foreignKey =>
            foreignKey.GetConstraintName() == "FK_RRCO_Licenses_ProductId_LicenseId"
            && foreignKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ProductId", "LicenseId"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);
        Assert.Contains(ownership.GetForeignKeys(), foreignKey =>
            foreignKey.GetConstraintName() == "FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId"
            && foreignKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ProductId", "OwnerSubjectId"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);

        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260829121357_AddTkt000779CommercialSubjectOwnershipIntegrity"],
            db.Database.ProviderName!);
        var foreignKeys = migration.UpOperations.OfType<AddForeignKeyOperation>()
            .Concat(migration.UpOperations.OfType<CreateTableOperation>()
                .SelectMany(table => table.ForeignKeys))
            .ToArray();
        Assert.Equal(4, foreignKeys.Count(foreignKey =>
            foreignKey.Name is "FK_RRCS_Products_ProductId"
                or "FK_RRCO_Products_ProductId"
                or "FK_RRCO_Licenses_ProductId_LicenseId"
                or "FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId"
            && foreignKey.OnDelete == ReferentialAction.NoAction));
        Assert.DoesNotContain(migration.UpOperations.OfType<SqlOperation>(), operation =>
            operation.Sql.Contains("INSERT", StringComparison.OrdinalIgnoreCase)
            || operation.Sql.Contains("UPDATE", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Proves TKT-000782 adds only product/license-scoped predecessor lineage and a frozen command
    /// ledger whose exact relations, closed strings, and terminal-update guard match the EF model.
    /// </summary>
    [Fact]
    public void RuntimeRecoveryCommercialOwnershipTransitionMigration_ContainsExactCasRelations()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var model = db.GetService<Microsoft.EntityFrameworkCore.Metadata.IDesignTimeModel>().Model;
        var ownership = model.FindEntityType(typeof(RuntimeRecoveryCommercialOwnership))!;
        var command = model.FindEntityType(typeof(RuntimeRecoveryCommercialOwnershipCommand))!;

        Assert.True(ownership.FindProperty("PreviousOwnershipId")!.IsNullable);
        Assert.Contains(ownership.GetKeys(), key => key.GetName() == "AK_RRCO_ProductId_LicenseId_Id"
            && key.Properties.Select(property => property.Name)
                .SequenceEqual(["ProductId", "LicenseId", "Id"]));
        Assert.Contains(ownership.GetForeignKeys(), foreignKey =>
            foreignKey.GetConstraintName() == "FK_RRCO_Previous_ProductId_LicenseId_OwnershipId"
            && foreignKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ProductId", "LicenseId", "PreviousOwnershipId"])
            && foreignKey.PrincipalKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ProductId", "LicenseId", "Id"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);
        Assert.Contains(ownership.GetCheckConstraints(), check =>
            check.Name == "CK_RRCO_Previous_NotSelf"
            && check.Sql == "\"PreviousOwnershipId\" IS NULL OR \"PreviousOwnershipId\" <> \"Id\"");
        Assert.Equal("C", command.FindProperty("Operation")!.GetCollation());
        Assert.Equal("C", command.FindProperty("RequestDigestSha256")!.GetCollation());
        Assert.Equal("C", command.FindProperty("ResponseJson")!.GetCollation());
        Assert.All(command.GetForeignKeys(), foreignKey =>
            Assert.Equal(DeleteBehavior.NoAction, foreignKey.DeleteBehavior));
        Assert.Equal(
            [
                "FK_RRCOC_ExpectedOwnership_ProductId_LicenseId_Id",
                "FK_RRCOC_Licenses_ProductId_LicenseId",
                "FK_RRCOC_Products_ProductId",
                "FK_RRCOC_ResultOwnership_ProductId_LicenseId_Id",
                "FK_RRCOC_TargetSubjects_ProductId_SubjectId"
            ],
            command.GetForeignKeys().Select(foreignKey => foreignKey.GetConstraintName())
                .OrderBy(name => name, StringComparer.Ordinal));

        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260829143035_AddTkt000782CommercialOwnershipTransitions"],
            db.Database.ProviderName!);
        Assert.Contains(migration.UpOperations.OfType<AddColumnOperation>(), operation =>
            operation.Table == "RuntimeRecoveryCommercialOwnerships"
            && operation.Name == "PreviousOwnershipId" && operation.IsNullable);
        Assert.Contains(migration.UpOperations.OfType<CreateTableOperation>(), operation =>
            operation.Name == "RuntimeRecoveryCommercialOwnershipCommands");
        Assert.Contains(migration.UpOperations.OfType<AddForeignKeyOperation>(), operation =>
            operation.Name == "FK_RRCO_Previous_ProductId_LicenseId_OwnershipId"
            && operation.Columns.SequenceEqual(["ProductId", "LicenseId", "PreviousOwnershipId"])
            && operation.PrincipalColumns is { } columns
            && columns.SequenceEqual(["ProductId", "LicenseId", "Id"])
            && operation.OnDelete == ReferentialAction.NoAction);
        var triggerSql = Assert.Single(migration.UpOperations.OfType<SqlOperation>()).Sql;
        Assert.Contains("trg_tkt000782_commercial_ownership_version", triggerSql, StringComparison.Ordinal);
        Assert.Contains("OLD.\"State\" <> 'ACTIVE'", triggerSql, StringComparison.Ordinal);
        Assert.Contains("NEW.\"State\" NOT IN ('TRANSFERRED', 'REVOKED')", triggerSql, StringComparison.Ordinal);
        Assert.DoesNotContain("INSERT INTO", triggerSql, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Proves TKT-000784 adds only a nullable historical compatibility column and an exact
    /// product/license/ownership-version NO ACTION relation, with no inferred ownership backfill.
    /// </summary>
    [Fact]
    public void RuntimeRecoveryGrantOwnershipVersionMigration_ContainsExactNullableRelationWithoutBackfill()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var model = db.GetService<Microsoft.EntityFrameworkCore.Metadata.IDesignTimeModel>().Model;
        var grant = model.FindEntityType(typeof(RuntimeRecoveryGrantOwnership))!;

        Assert.True(grant.FindProperty("CommercialOwnershipId")!.IsNullable);
        Assert.Contains(grant.GetForeignKeys(), foreignKey =>
            foreignKey.GetConstraintName() == "FK_RRGO_CommercialOwnership_ProductId_LicenseId_OwnershipId"
            && foreignKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ProductId", "LicenseId", "CommercialOwnershipId"])
            && foreignKey.PrincipalKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ProductId", "LicenseId", "Id"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);

        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260829190000_BindTkt000784RecoveryGrantOwnershipVersion"],
            db.Database.ProviderName!);
        Assert.Contains(migration.UpOperations.OfType<AddColumnOperation>(), operation =>
            operation.Table == "RuntimeRecoveryGrantOwnerships"
            && operation.Name == "CommercialOwnershipId" && operation.IsNullable);
        Assert.Contains(migration.UpOperations.OfType<CreateIndexOperation>(), operation =>
            operation.Name == "IX_RuntimeRecoveryGrantOwnerships_ProductId_LicenseId_CommercialOwnershipId"
            && operation.Columns.SequenceEqual(["ProductId", "LicenseId", "CommercialOwnershipId"]));
        Assert.Contains(migration.UpOperations.OfType<AddForeignKeyOperation>(), operation =>
            operation.Name == "FK_RRGO_CommercialOwnership_ProductId_LicenseId_OwnershipId"
            && operation.Columns.SequenceEqual(["ProductId", "LicenseId", "CommercialOwnershipId"])
            && operation.PrincipalColumns is { } principalColumns
            && principalColumns.SequenceEqual(["ProductId", "LicenseId", "Id"])
            && operation.OnDelete == ReferentialAction.NoAction);
        Assert.DoesNotContain(migration.UpOperations.OfType<SqlOperation>(), operation =>
            operation.Sql.Contains("INSERT", StringComparison.OrdinalIgnoreCase)
            || operation.Sql.Contains("UPDATE", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Proves the W10.2 proof ledger is additive, immutable, one-shot without JTI, and stores the
    /// exact preparation/reservation expiry minimum used by the PROVED receipt.
    /// </summary>
    [Fact]
    public void RuntimeSeatRecoveryKeyProofMigration_ContainsExactProviderInvariants()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260829200000_AddTkt000773RuntimeSeatRecoveryKeyProof"],
            db.Database.ProviderName!);
        var tables = migration.UpOperations.OfType<CreateTableOperation>()
            .ToDictionary(table => table.Name, StringComparer.Ordinal);

        Assert.Equal([
            "RuntimeSeatRecoveryKeyConfirmations",
            "RuntimeSeatRecoveryKeyPreparations",
            "RuntimeSeatRecoveryProofReceipts"
        ], tables.Keys.Order(StringComparer.Ordinal));
        Assert.DoesNotContain(tables.Values.SelectMany(table => table.Columns), column =>
            column.Name.Contains("jti", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(tables["RuntimeSeatRecoveryKeyPreparations"].UniqueConstraints, constraint =>
            constraint.Name == "AK_RSRKP_Client_Request_Recovery"
            && constraint.Columns.SequenceEqual(["AuthenticatedClientId", "RequestId", "RecoveryOperationRef"]));
        Assert.Contains(tables["RuntimeSeatRecoveryProofReceipts"].CheckConstraints, constraint =>
            constraint.Name == "CK_RSRPR_ExpiryMinimum"
            && constraint.Sql == "\"ExpiresAtUtc\" = LEAST(\"PreparationExpiresAtUtc\", \"ReservationExpiresAtUtc\")");
        Assert.All(tables.Values.SelectMany(table => table.ForeignKeys), foreignKey =>
            Assert.Equal(ReferentialAction.NoAction, foreignKey.OnDelete));

        var sql = string.Join('\n', migration.UpOperations.OfType<SqlOperation>().Select(operation => operation.Sql));
        Assert.Contains("ERRCODE = '55000'", sql, StringComparison.Ordinal);
        Assert.Contains("BEFORE TRUNCATE", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("ACTIVE", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("COMMITTED", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("SUPERSEDED", sql, StringComparison.Ordinal);
    }

    /// <summary>Proves the activation migration backfills seat identity, freezes receipts, and enforces one ACTIVE authority.</summary>
    [Fact]
    public void RuntimeSeatRecoveryActivationMigration_ContainsTripleCasStorageInvariants()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260829214251_AddTkt000767RuntimeSeatRecoveryActivation"],
            db.Database.ProviderName!);
        var receipt = Assert.Single(migration.UpOperations.OfType<CreateTableOperation>(), operation =>
            operation.Name == "RuntimeSeatRecoveryActivationReceipts");
        var indexes = migration.UpOperations.OfType<CreateIndexOperation>().ToArray();

        Assert.Equal(["AuthenticatedClientId", "RequestId"], receipt.PrimaryKey!.Columns);
        Assert.Contains(receipt.CheckConstraints, constraint => constraint.Name == "CK_RSRActivation_RequestBytes"
            && constraint.Sql == "octet_length(\"CanonicalRequestUtf8\") = 524");
        Assert.Contains(receipt.CheckConstraints, constraint => constraint.Name == "CK_RSRActivation_TerminalShape"
            && constraint.Sql.Contains("activation_expired", StringComparison.Ordinal)
            && constraint.Sql.Contains("activation_conflict", StringComparison.Ordinal));
        Assert.All(receipt.ForeignKeys, foreignKey => Assert.Equal(ReferentialAction.NoAction, foreignKey.OnDelete));
        Assert.Contains(indexes, index => index.Name == "UX_RSRAuthorities_OneActivePerSeat"
            && index.IsUnique && index.Filter == "\"State\" = 'ACTIVE'");
        Assert.Contains(indexes, index =>
            index.Name == "IX_RuntimeSeatRecoveryAuthorities_ReservationRef_LicenseSeatId"
            && index.IsUnique
            && index.Columns.SequenceEqual(["ReservationRef", "LicenseSeatId"]));
        Assert.Contains(indexes, index => index.Name == "UX_RSRActivation_Client_PrepareRef" && index.IsUnique);
        Assert.Contains(migration.UpOperations.OfType<AddUniqueConstraintOperation>(), constraint =>
            constraint.Table == "RuntimeSeatRecoveryReservations"
            && constraint.Name == "AK_RuntimeSeatRecoveryReservations_ReservationRef_LicenseSeatId"
            && constraint.Columns.SequenceEqual(["ReservationRef", "LicenseSeatId"]));
        Assert.Contains(migration.UpOperations.OfType<AddForeignKeyOperation>(), foreignKey =>
            foreignKey.Table == "RuntimeSeatRecoveryAuthorities"
            && foreignKey.Columns.SequenceEqual(["ReservationRef", "LicenseSeatId"])
            && foreignKey.PrincipalTable == "RuntimeSeatRecoveryReservations"
            && foreignKey.PrincipalColumns is { } principalColumns
            && principalColumns.SequenceEqual(["ReservationRef", "LicenseSeatId"])
            && foreignKey.OnDelete == ReferentialAction.NoAction);
        var sql = string.Join('\n', migration.UpOperations.OfType<SqlOperation>().Select(operation => operation.Sql));
        Assert.Contains("SET \"LicenseSeatId\" = reservation.\"LicenseSeatId\"", sql, StringComparison.Ordinal);
        Assert.Contains("ERRCODE = '55000'", sql, StringComparison.Ordinal);
        Assert.Contains("BEFORE TRUNCATE", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("jti", sql, StringComparison.OrdinalIgnoreCase);

        var authority = db.Model.FindEntityType(typeof(RuntimeSeatRecoveryAuthority))!;
        Assert.Contains(authority.GetIndexes(), index => index.IsUnique
            && index.GetDatabaseName() == "UX_RSRAuthorities_OneActivePerSeat"
            && index.GetFilter() == "\"State\" = 'ACTIVE'");
        var reservation = db.Model.FindEntityType(typeof(RuntimeSeatRecoveryReservation))!;
        Assert.Contains(reservation.GetKeys(), key => !key.IsPrimaryKey()
            && key.Properties.Select(property => property.Name)
                .SequenceEqual(["ReservationRef", "LicenseSeatId"]));
        Assert.Contains(authority.GetForeignKeys(), foreignKey =>
            foreignKey.PrincipalEntityType.ClrType == typeof(RuntimeSeatRecoveryReservation)
            && foreignKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ReservationRef", "LicenseSeatId"])
            && foreignKey.PrincipalKey.Properties.Select(property => property.Name)
                .SequenceEqual(["ReservationRef", "LicenseSeatId"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);
    }

    /// <summary>
    /// Proves F6 models two distinct lineage/generation relations for the prepared authority and its
    /// proven predecessor, and that the additive migration installs both as composite NO ACTION keys.
    /// </summary>
    [Fact]
    public void RuntimeSeatRecoveryF6Migration_ContainsExactCompositeAuthorityRelations()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var authority = db.Model.FindEntityType(typeof(RuntimeSeatRecoveryAuthority))!;
        var relations = authority.GetForeignKeys()
            .Where(foreignKey => foreignKey.PrincipalEntityType.ClrType
                == typeof(RuntimeEnrollmentAuthorityGeneration))
            .ToArray();

        Assert.Contains(relations, foreignKey => foreignKey.Properties.Select(property => property.Name)
            .SequenceEqual(["AuthorityLineageId", "AuthorityGenerationId"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);
        Assert.Contains(relations, foreignKey => foreignKey.Properties.Select(property => property.Name)
            .SequenceEqual(["PreviousAuthorityLineageId", "PreviousAuthorityGenerationId"])
            && foreignKey.DeleteBehavior == DeleteBehavior.NoAction);
        Assert.Contains(authority.GetIndexes(), index => index.Properties.Select(property => property.Name)
            .SequenceEqual(["PreviousAuthorityLineageId", "PreviousAuthorityGenerationId"]));

        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260829110137_CloseTkt000763F6RecoveryAuthorityIntegrity"],
            db.Database.ProviderName!);
        var foreignKeys = migration.UpOperations.OfType<AddForeignKeyOperation>().ToArray();
        Assert.Contains(foreignKeys, foreignKey => foreignKey.Columns.SequenceEqual(
            ["AuthorityLineageId", "AuthorityGenerationId"])
            && foreignKey.PrincipalColumns is { } newPrincipalColumns
            && newPrincipalColumns.SequenceEqual(["AuthorityLineageId", "AuthorityGenerationId"])
            && foreignKey.OnDelete == ReferentialAction.NoAction);
        Assert.Contains(foreignKeys, foreignKey => foreignKey.Columns.SequenceEqual(
            ["PreviousAuthorityLineageId", "PreviousAuthorityGenerationId"])
            && foreignKey.PrincipalColumns is { } previousPrincipalColumns
            && previousPrincipalColumns.SequenceEqual(["AuthorityLineageId", "AuthorityGenerationId"])
            && foreignKey.OnDelete == ReferentialAction.NoAction);
    }

    /// <summary>
    /// Proves the TKT-000763 migration carries client-scoped terminal identity, globally unique
    /// authorized resources, seat uniqueness, and lifecycle guards.
    /// </summary>
    [Fact]
    public void RuntimeSeatRecoveryMigration_ContainsAtomicProviderInvariants()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260829100000_AddTkt000763RuntimeSeatRecoveryAuthorization"],
            db.Database.ProviderName!);
        var tables = migration.UpOperations.OfType<CreateTableOperation>()
            .ToDictionary(table => table.Name, StringComparer.Ordinal);

        Assert.Contains("RuntimeSeatRecoveryAuthorizations", tables.Keys);
        Assert.Contains("RuntimeSeatRecoveryReservations", tables.Keys);
        Assert.Contains("RuntimeSeatRecoveryAuthorities", tables.Keys);
        Assert.Contains("RuntimeRecoveryCommercialOwnerships", tables.Keys);
        Assert.Contains("RuntimeRecoveryGrantOwnerships", tables.Keys);
        Assert.Contains("RuntimeSeatRecoveryRevokedClaimNonces", tables.Keys);
        var authorization = tables["RuntimeSeatRecoveryAuthorizations"];
        Assert.Equal(["AuthenticatedClientId", "RequestId"], authorization.PrimaryKey!.Columns);
        Assert.Contains(authorization.UniqueConstraints, constraint => constraint.Columns.SequenceEqual(
            ["AuthenticatedClientId", "RequestId", "RecoveryOperationRef"]));
        var indexes = migration.UpOperations.OfType<CreateIndexOperation>().ToList();
        Assert.Contains(indexes, index =>
            index.Name == "IX_RuntimeSeatRecoveryAuthorizations_RecoveryOperationRef" && !index.IsUnique);
        Assert.Contains(indexes, index =>
            index.Name == "IX_RuntimeRecoveryGrantOwnerships_RecoveryOperationRef" && index.IsUnique);
        Assert.Contains(indexes, index =>
            index.Name == "IX_RuntimeSeatRecoveryReservations_RecoveryOperationRef" && index.IsUnique);
        var authorizationModel = db.Model.FindEntityType(typeof(RuntimeSeatRecoveryAuthorization))!;
        Assert.False(authorizationModel.GetIndexes().Single(index =>
            index.Properties.Select(property => property.Name).SequenceEqual(["RecoveryOperationRef"])).IsUnique);
        var reservation = tables["RuntimeSeatRecoveryReservations"];
        Assert.Contains(reservation.ForeignKeys, foreignKey => foreignKey.Columns.SequenceEqual(
            ["AuthenticatedClientId", "RequestId", "RecoveryOperationRef"]));
        Assert.Contains(indexes, index =>
            index.Name == "UX_RSRR_OneReservedPerSeat" && index.IsUnique
            && index.Filter == "\"State\" = 'RESERVED'");
        var sql = string.Join('\n', migration.UpOperations.OfType<SqlOperation>().Select(operation => operation.Sql));
        Assert.Contains("runtime seat recovery terminal history is immutable", sql, StringComparison.Ordinal);
        Assert.Contains("OLD.\"State\" <> 'RESERVED'", sql, StringComparison.Ordinal);
        Assert.Contains("NEW.\"State\" NOT IN ('ACTIVE','ABANDONED','SUPERSEDED')", sql, StringComparison.Ordinal);
    }

    /// <summary>Proves item 3 performs guarded historical backfill before terminal constraints and attempt immutability.</summary>
    [Fact]
    public void AuthorityAttemptResultMigration_HasClosedTerminalSurfaces()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused").Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260824114500_AddRuntimeEnrollmentAuthorityAttemptResults"],
            db.Database.ProviderName!);
        var attempt = Assert.Single(migration.UpOperations.OfType<CreateTableOperation>(),
            table => table.Name == "RuntimeEnrollmentAuthorityAttempts");
        Assert.Equal("PK_REAuthorityAttempts", attempt.PrimaryKey!.Name);
        Assert.Equal("bytea", attempt.Columns.Single(column => column.Name == "ExactResponseUtf8").ColumnType);
        Assert.Equal("C", attempt.Columns.Single(column => column.Name == "RequestDigest").Collation);
        Assert.False(attempt.Columns.Single(column => column.Name == "HttpStatusCode").IsNullable);
        var fk = Assert.Single(attempt.ForeignKeys);
        Assert.Equal(["RequestId"], fk.Columns);
        Assert.Equal(ReferentialAction.NoAction, fk.OnDelete);
        Assert.Contains(migration.UpOperations.OfType<AddColumnOperation>(), operation =>
            operation.Table == "RuntimeEnrollmentAuthorityRequests" && operation.Name == "ExactResponseUtf8"
            && operation.ColumnType == "bytea" && operation.IsNullable);
        Assert.Contains(migration.UpOperations.OfType<AlterColumnOperation>(), operation =>
            operation.Table == "RuntimeEnrollmentAuthorityRequests" && operation.Name == "ExactResponseUtf8"
            && operation.ColumnType == "bytea" && !operation.IsNullable && operation.OldColumn.IsNullable);
        Assert.Contains(migration.UpOperations.OfType<AddCheckConstraintOperation>(), operation =>
            operation.Name == "CK_REAuthorityRequests_TerminalShape");
        Assert.Contains(attempt.CheckConstraints, check => check.Name == "CK_REAuthorityAttempts_ResponseBytes"
            && check.Sql == "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
        Assert.Contains(attempt.CheckConstraints, check => check.Name == "CK_REAuthorityAttempts_Chronology");
        Assert.Contains(attempt.CheckConstraints, check => check.Name == "CK_REAuthorityAttempts_HttpStatus"
            && check.Sql == "\"HttpStatusCode\" IN (200, 400, 403, 409, 503)");
        Assert.Contains(migration.UpOperations.OfType<AddCheckConstraintOperation>(), operation =>
            operation.Name == "CK_REAuthorityRequests_ResponseBytes"
            && operation.Sql == "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
        var sqlOperations = migration.UpOperations.OfType<SqlOperation>().ToArray();
        var sql = string.Join('\n', sqlOperations.Select(operation => operation.Sql));
        Assert.Contains("BEFORE UPDATE OR DELETE", sql, StringComparison.Ordinal);
        Assert.Contains("BEFORE TRUNCATE", sql, StringComparison.Ordinal);
        Assert.Contains("Runtime Enrollment authority attempts are immutable", sql, StringComparison.Ordinal);
        var dropGuard = Array.FindIndex(sqlOperations, operation => operation.Sql.Contains(
            "DROP TRIGGER trg_runtime_enrollment_authority_requests_immutable", StringComparison.Ordinal));
        var backfill = Array.FindIndex(sqlOperations, operation => operation.Sql.Contains(
            "UPDATE public.\"RuntimeEnrollmentAuthorityRequests\"", StringComparison.Ordinal));
        var restoreGuard = Array.FindIndex(sqlOperations, operation => operation.Sql.Contains(
            "CREATE TRIGGER trg_runtime_enrollment_authority_requests_immutable", StringComparison.Ordinal));
        Assert.True(dropGuard >= 0 && dropGuard < backfill && backfill < restoreGuard);
        Assert.Contains("request.\"AuthorityGenerationId\" = generation.\"AuthorityGenerationId\"", sqlOperations[backfill].Sql,
            StringComparison.Ordinal);
        Assert.Contains("request.\"RequestId\" = generation.\"RequestId\"", sqlOperations[backfill].Sql,
            StringComparison.Ordinal);
        Assert.Contains("runtime enrollment authority request backfill is incomplete", sqlOperations[backfill].Sql,
            StringComparison.Ordinal);
        var operations = migration.UpOperations.ToArray();
        var restoreOperationIndex = Array.IndexOf(operations, sqlOperations[restoreGuard]);
        Assert.All(migration.UpOperations.OfType<AlterColumnOperation>().Where(operation =>
                operation.Table == "RuntimeEnrollmentAuthorityRequests" && !operation.IsNullable
                && operation.Name is "CompletedAtUtc" or "ExactResponseUtf8" or "HttpStatusCode"),
            operation => Assert.True(restoreOperationIndex < Array.IndexOf(operations, operation)));
        Assert.All(migration.UpOperations.OfType<AddCheckConstraintOperation>().Where(operation =>
                operation.Table == "RuntimeEnrollmentAuthorityRequests"),
            operation => Assert.True(restoreOperationIndex < Array.IndexOf(operations, operation)));
        var downSql = string.Join('\n', migration.DownOperations.OfType<SqlOperation>()
            .Select(operation => operation.Sql));
        Assert.Equal(1, CountOrdinal(downSql,
            "DROP TRIGGER IF EXISTS trg_re_authority_attempts_immutable"));
        Assert.Equal(1, CountOrdinal(downSql,
            "DROP TRIGGER IF EXISTS trg_re_authority_attempts_no_truncate"));
    }
    /// <summary>Proves the runtime model and generated migration snapshot have no relational differences.</summary>
    [Fact]
    public void RuntimeEnrollmentModel_MatchesMigrationSnapshot()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var differ = db.GetService<IMigrationsModelDiffer>();
        var initializer = db.GetService<IModelRuntimeInitializer>();
        var snapshot = initializer.Initialize(migrations.ModelSnapshot!.Model, designTime: true);
        var design = db.GetService<Microsoft.EntityFrameworkCore.Metadata.IDesignTimeModel>().Model;
        var operations = differ.GetDifferences(
            snapshot.GetRelationalModel(),
            design.GetRelationalModel());

        Assert.True(operations.Count == 0,
            string.Join(Environment.NewLine, operations.Take(50).Select(Describe)));
    }

    [Fact]
    public void RuntimeEnrollmentMigration_ContainsAllModeledBusinessChecks()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260719024400_AddRuntimeEnrollments"],
            db.Database.ProviderName!);
        var checks = migration.UpOperations.OfType<CreateTableOperation>()
            .SelectMany(table => table.CheckConstraints.Select(check => check.Name))
            .ToHashSet(StringComparer.Ordinal);

        Assert.Subset(checks, new HashSet<string>(StringComparer.Ordinal)
        {
            "CK_RuntimeEnrollments_State",
            "CK_RuntimeEnrollments_Epoch",
            "CK_RuntimeEnrollmentRequests_Operation",
            "CK_RuntimeEnrollmentProofNonces_Operation",
            "CK_RuntimeEnrollmentQuotas_Count"
        });
    }

    [Fact]
    public void CriticalRecoveryClientRefetchMigration_ExtendsProofOperationAllowlist()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260720093153_AddRuntimeCriticalRecoveryClientRefetch"],
            db.Database.ProviderName!);

        var constraint = Assert.Single(migration.UpOperations.OfType<AddCheckConstraintOperation>());
        Assert.Equal("CK_RuntimeEnrollmentProofNonces_Operation", constraint.Name);
        Assert.Equal(
            "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch')",
            constraint.Sql);
    }

    [Fact]
    public void RuntimeMilestoneMigration_EnforcesProtocolAllowlistsAndUniqueness()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260720102528_AddRuntimeMilestones"],
            db.Database.ProviderName!);
        var milestoneTable = Assert.Single(migration.UpOperations.OfType<CreateTableOperation>(),
            table => table.Name == "RuntimeMilestones");
        var checks = milestoneTable.CheckConstraints.ToDictionary(check => check.Name, StringComparer.Ordinal);

        Assert.Equal("\"EvidenceClass\" = 'client_declared'",
            checks["CK_RuntimeMilestones_EvidenceClass"].Sql);
        Assert.Contains("'bootstrap_entered'", checks["CK_RuntimeMilestones_Code"].Sql, StringComparison.Ordinal);
        Assert.Contains("'tia_operation_failed'", checks["CK_RuntimeMilestones_Code"].Sql, StringComparison.Ordinal);
        Assert.Equal(20, checks["CK_RuntimeMilestones_Code"].Sql!.Count(character => character == '\'' ) / 2);
        Assert.Contains(migration.UpOperations.OfType<CreateIndexOperation>(), index =>
            index.Name == "IX_RuntimeMilestones_EventId" && index.IsUnique);
        Assert.Contains(migration.UpOperations.OfType<CreateIndexOperation>(), index =>
            index.Name == "IX_RuntimeMilestones_EnrollmentId_SessionId_Code" && index.IsUnique);
        var proofConstraint = Assert.Single(migration.UpOperations.OfType<AddCheckConstraintOperation>());
        Assert.Contains("'milestone'", proofConstraint.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void RuntimeUpgradeMigration_ExtendsBothOperationAllowlists()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260724070458_AddRuntimeEnrollmentUpgrade"],
            db.Database.ProviderName!);
        var constraints = migration.UpOperations.OfType<AddCheckConstraintOperation>()
            .ToDictionary(constraint => constraint.Name, StringComparer.Ordinal);

        Assert.Equal("\"Operation\" IN ('prepare', 'upgrade')",
            constraints["CK_RuntimeEnrollmentRequests_Operation"].Sql);
        Assert.Equal("\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade')",
            constraints["CK_RuntimeEnrollmentProofNonces_Operation"].Sql);
    }

    [Fact]
    public void RuntimeRecoveryRollbackMigration_ExtendsBothOperationAllowlists()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        var migration = migrations.CreateMigration(
            migrations.Migrations["20260724165835_AddRuntimeEnrollmentRecoveryRollback"],
            db.Database.ProviderName!);
        var constraints = migration.UpOperations.OfType<AddCheckConstraintOperation>()
            .ToDictionary(constraint => constraint.Name, StringComparer.Ordinal);

        Assert.Equal("\"Operation\" IN ('prepare', 'upgrade', 'rollback')",
            constraints["CK_RuntimeEnrollmentRequests_Operation"].Sql);
        Assert.Equal("\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade', 'rollback')",
            constraints["CK_RuntimeEnrollmentProofNonces_Operation"].Sql);
    }

    /// <summary>Proves canonical names, exact digest storage, collation, nullability, and ordered unique surfaces.</summary>
    [Fact]
    public void GenerationAuthorityMigration_UsesCanonicalNamesAndStrictDigestColumns()
    {
        var migration = GenerationAuthorityMigration();
        string[] names =
        [
            "FK_REAuthorityLineages_REAuthorityGenerations_Head",
            "PK_REAuthorityLineages",
            "UX_REAuthorityLineages_Provider_ProductId_GrantRef",
            "PK_REAuthorityGenerations",
            "AK_REAuthorityGenerations_LineageId_GenerationId",
            "AK_REAuthorityGenerations_LineageId_GenerationId_Sequence",
            "AK_REAuthorityGenerations_GenerationId_RequestId",
            "UX_REAuthorityGenerations_LineageId_Sequence",
            "UX_REAuthorityGenerations_LineageId_PredecessorId",
            "PK_REAuthorityRequests"
        ];

        Assert.Equal(names.Length, names.Distinct(StringComparer.Ordinal).Count());
        Assert.All(names, name => Assert.True(Encoding.UTF8.GetByteCount(name) <= 63, name));

        var tables = migration.UpOperations.OfType<CreateTableOperation>()
            .ToDictionary(table => table.Name, StringComparer.Ordinal);
        var generation = tables["RuntimeEnrollmentAuthorityGenerations"];
        var request = tables["RuntimeEnrollmentAuthorityRequests"];
        Assert.Equal("varchar(64)", generation.Columns.Single(column =>
            column.Name == "AuthorityDigest").ColumnType);
        Assert.Equal("varchar(64)", request.Columns.Single(column =>
            column.Name == "RequestDigest").ColumnType);
        Assert.Equal("C", generation.Columns.Single(column =>
            column.Name == "AuthorityDigest").Collation);
        Assert.False(generation.Columns.Single(column =>
            column.Name == "AuthorityDigest").IsNullable);
        Assert.Equal("C", request.Columns.Single(column =>
            column.Name == "RequestDigest").Collation);
        Assert.False(request.Columns.Single(column =>
            column.Name == "RequestDigest").IsNullable);
        Assert.Equal(
            "octet_length(\"AuthorityDigest\") = 64 AND \"AuthorityDigest\" ~ '^[0-9a-f]{64}$'",
            generation.CheckConstraints.Single(check =>
                check.Name == "CK_RuntimeEnrollmentAuthorityGenerations_AuthorityDigest").Sql);
        Assert.Equal(
            "octet_length(\"RequestDigest\") = 64 AND \"RequestDigest\" ~ '^[0-9a-f]{64}$'",
            request.CheckConstraints.Single(check =>
                check.Name == "CK_RuntimeEnrollmentAuthorityRequests_RequestDigest").Sql);

        var modeledUniqueNames = tables.Values.SelectMany(table =>
                table.UniqueConstraints.Select(constraint => constraint.Name)
                    .Append(table.PrimaryKey!.Name))
            .Concat(migration.UpOperations.OfType<CreateIndexOperation>()
                .Where(index => index.IsUnique).Select(index => index.Name))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(names.Skip(1).OrderBy(name => name, StringComparer.Ordinal), modeledUniqueNames);

        var nullableColumns = tables.Values.SelectMany(table => table.Columns
                .Where(column => column.IsNullable)
                .Select(column => $"{table.Name}.{column.Name}"))
            .ToArray();
        Assert.Equal(["RuntimeEnrollmentAuthorityGenerations.PreviousGenerationId"], nullableColumns);
        var collatedColumns = tables.Values.SelectMany(table => table.Columns
                .Where(column => column.Collation != null)
                .Select(column => $"{table.Name}.{column.Name}:{column.Collation}"))
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(new[]
        {
            "RuntimeEnrollmentAuthorityGenerations.AuthorityDigest:C",
            "RuntimeEnrollmentAuthorityGenerations.SignatureAlgorithm:C",
            "RuntimeEnrollmentAuthorityGenerations.SignatureKeyId:C",
            "RuntimeEnrollmentAuthorityGenerations.SignatureValue:C",
            "RuntimeEnrollmentAuthorityLineages.Provider:C",
            "RuntimeEnrollmentAuthorityLineages.ProviderGrantRef:C",
            "RuntimeEnrollmentAuthorityRequests.RequestDigest:C",
            "RuntimeEnrollmentAuthorityRequests.ResultCode:C"
        }, collatedColumns);

        var orderedKeys = tables.Values.SelectMany(table =>
                table.UniqueConstraints
                    .Select(key => $"{key.Name}:{string.Join(",", key.Columns)}")
                    .Append($"{table.PrimaryKey!.Name}:{string.Join(",", table.PrimaryKey.Columns)}"))
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(new[]
        {
            "AK_REAuthorityGenerations_GenerationId_RequestId:AuthorityGenerationId,RequestId",
            "AK_REAuthorityGenerations_LineageId_GenerationId:AuthorityLineageId,AuthorityGenerationId",
            "AK_REAuthorityGenerations_LineageId_GenerationId_Sequence:AuthorityLineageId,AuthorityGenerationId,Sequence",
            "PK_REAuthorityGenerations:AuthorityGenerationId",
            "PK_REAuthorityLineages:AuthorityLineageId",
            "PK_REAuthorityRequests:RequestId"
        }, orderedKeys);
        var orderedIndexes = migration.UpOperations.OfType<CreateIndexOperation>()
            .Select(index => $"{index.Name}:{string.Join(",", index.Columns)}:{index.IsUnique}")
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(new[]
        {
            "IX_REAuthorityRequests_GenerationId_RequestId:AuthorityGenerationId,RequestId:False",
            "IX_RuntimeEnrollmentAuthorityLineages_AuthorityLineageId_HeadG~:AuthorityLineageId,HeadGenerationId,HeadSequence:False",
            "UX_REAuthorityGenerations_LineageId_PredecessorId:AuthorityLineageId,PreviousGenerationId:True",
            "UX_REAuthorityGenerations_LineageId_Sequence:AuthorityLineageId,Sequence:True",
            "UX_REAuthorityLineages_Provider_ProductId_GrantRef:Provider,ProductId,ProviderGrantRef:True"
        }, orderedIndexes);
    }

    /// <summary>Proves every modeled FK surface plus the sole raw deferred head FK and its one local Down drop.</summary>
    [Fact]
    public void GenerationAuthorityMigration_HasOneDeferredHeadForeignKeyAndStaticGuards()
    {
        var migration = GenerationAuthorityMigration();
        var modeledFks = AllModeledUpForeignKeys(migration).ToArray();
        Assert.Equal(3, modeledFks.Length);
        Assert.Contains(modeledFks, operation =>
            operation.Table == "RuntimeEnrollmentAuthorityGenerations"
            && operation.PrincipalTable == "RuntimeEnrollmentAuthorityGenerations"
            && operation.Columns.SequenceEqual(["AuthorityLineageId", "PreviousGenerationId"])
            && (operation.PrincipalColumns ?? []).SequenceEqual(
                ["AuthorityLineageId", "AuthorityGenerationId"])
            && operation.OnDelete == ReferentialAction.NoAction);
        Assert.Contains(modeledFks, operation =>
            operation.Table == "RuntimeEnrollmentAuthorityGenerations"
            && operation.PrincipalTable == "RuntimeEnrollmentAuthorityLineages"
            && operation.Columns.SequenceEqual(["AuthorityLineageId"])
            && (operation.PrincipalColumns ?? []).SequenceEqual(["AuthorityLineageId"])
            && operation.OnDelete == ReferentialAction.NoAction);
        Assert.Contains(modeledFks, operation =>
            operation.Table == "RuntimeEnrollmentAuthorityRequests"
            && operation.PrincipalTable == "RuntimeEnrollmentAuthorityGenerations"
            && operation.Columns.SequenceEqual(["AuthorityGenerationId", "RequestId"])
            && (operation.PrincipalColumns ?? []).SequenceEqual(
                ["AuthorityGenerationId", "RequestId"])
            && operation.OnDelete == ReferentialAction.NoAction);
        Assert.DoesNotContain(modeledFks, operation =>
            operation.Table == "RuntimeEnrollmentAuthorityLineages"
            && operation.Columns.SequenceEqual(
                ["AuthorityLineageId", "HeadGenerationId", "HeadSequence"]));

        var sql = string.Join("\n", migration.UpOperations.OfType<SqlOperation>()
            .Select(operation => operation.Sql));
        var downSql = string.Join("\n", migration.DownOperations.OfType<SqlOperation>()
            .Select(operation => operation.Sql));
        const string headName = "FK_REAuthorityLineages_REAuthorityGenerations_Head";
        Assert.Equal(1, CountOrdinal(sql, headName));
        Assert.Equal(1, CountOrdinal(downSql,
            "DROP CONSTRAINT IF EXISTS \"FK_REAuthorityLineages_REAuthorityGenerations_Head\""));
        Assert.Contains(
            "FOREIGN KEY (\"AuthorityLineageId\", \"HeadGenerationId\", \"HeadSequence\")",
            sql, StringComparison.Ordinal);
        Assert.Contains(
            "(\"AuthorityLineageId\", \"AuthorityGenerationId\", \"Sequence\")",
            sql, StringComparison.Ordinal);
        Assert.Contains("ON DELETE NO ACTION", sql, StringComparison.Ordinal);
        Assert.Contains("DEFERRABLE INITIALLY DEFERRED", sql, StringComparison.Ordinal);
        Assert.Contains("trg_runtime_enrollment_generation_predecessor_insert", sql, StringComparison.Ordinal);
        Assert.Contains("NEW.\"Sequence\" <> predecessor_sequence + 1", sql, StringComparison.Ordinal);
        Assert.Contains("generation.\"PreviousGenerationId\" = OLD.\"HeadGenerationId\"", sql,
            StringComparison.Ordinal);
        Assert.Contains("NEW.\"HeadSequence\" <> OLD.\"HeadSequence\" + 1", sql,
            StringComparison.Ordinal);
        Assert.Contains("trg_runtime_enrollment_authority_generations_immutable", sql,
            StringComparison.Ordinal);
        Assert.Contains("trg_runtime_enrollment_authority_requests_immutable", sql,
            StringComparison.Ordinal);
        Assert.Contains("trg_runtime_enrollment_authority_lineage_update", sql,
            StringComparison.Ordinal);
        Assert.DoesNotContain("CASCADE", sql, StringComparison.Ordinal);
    }

    /// <summary>Creates the generated migration without opening a database connection.</summary>
    private static Migration GenerationAuthorityMigration()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new LicenseDbContext(options);
        var migrations = db.GetService<IMigrationsAssembly>();
        return migrations.CreateMigration(
            migrations.Migrations["20260823131005_AddRuntimeEnrollmentGenerationAuthority"],
            db.Database.ProviderName!);
    }

    /// <summary>Enumerates top-level and CreateTable-owned FK operations without relying on constraint names.</summary>
    private static IEnumerable<AddForeignKeyOperation> AllModeledUpForeignKeys(Migration migration) =>
        migration.UpOperations.OfType<AddForeignKeyOperation>()
            .Concat(migration.UpOperations.OfType<CreateTableOperation>()
                .SelectMany(table => table.ForeignKeys));

    /// <summary>Counts non-overlapping exact ordinal occurrences for static SQL assertions.</summary>
    private static int CountOrdinal(string value, string pattern)
    {
        var count = 0;
        for (var index = 0; (index = value.IndexOf(pattern, index, StringComparison.Ordinal)) >= 0;
             index += pattern.Length)
            count++;
        return count;
    }

    /// <summary>Describes one relational model difference for an actionable parity failure.</summary>
    private static string Describe(MigrationOperation operation) => operation switch
    {
        AddColumnOperation item => $"AddColumn:{item.Table}.{item.Name}",
        AlterColumnOperation item => $"AlterColumn:{item.Table}.{item.Name}",
        DropColumnOperation item => $"DropColumn:{item.Table}.{item.Name}",
        CreateIndexOperation item => $"CreateIndex:{item.Table}.{item.Name}",
        DropIndexOperation item => $"DropIndex:{item.Table}.{item.Name}",
        AddForeignKeyOperation item => $"AddForeignKey:{item.Table}.{item.Name}",
        DropForeignKeyOperation item => $"DropForeignKey:{item.Table}.{item.Name}",
        AddPrimaryKeyOperation item => $"AddPrimaryKey:{item.Table}.{item.Name}",
        DropPrimaryKeyOperation item => $"DropPrimaryKey:{item.Table}.{item.Name}",
        CreateTableOperation item => $"CreateTable:{item.Name}",
        DropTableOperation item => $"DropTable:{item.Name}",
        _ => operation.GetType().Name
    };
}

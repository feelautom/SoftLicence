using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentMigrationParityTests
{
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

using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Migrations;

/// <summary>Adds nullable decision lookup/deduplication columns to existing licence history without reconstructing old events.</summary>
/// <remarks>PostgreSQL indexes allow multiple null legacy values. Apply only through a separately authorized migration deployment; rollback discards new lookup metadata, preserving Details.</remarks>
[DbContext(typeof(LicenseDbContext))]
[Migration("20260906180000_AddTkt000976DecisionHistory")]
public sealed class AddTkt000976DecisionHistory : Migration
{
    /// <summary>Adds exact digest and operation indexes transactionally; no existing row receives invented provenance.</summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(name: "DecisionCorrelationId", table: "LicenseHistories", type: "character varying(200)", maxLength: 200, nullable: true);
        migrationBuilder.AddColumn<string>(name: "DecisionSubmittedHardwareId", table: "LicenseHistories", type: "character varying(512)", maxLength: 512, nullable: true);
        migrationBuilder.AddColumn<string>(name: "DecisionResolvedHardwareId", table: "LicenseHistories", type: "character varying(512)", maxLength: 512, nullable: true);
        migrationBuilder.AddColumn<string>(name: "DecisionCorrelatedHardwareId", table: "LicenseHistories", type: "character varying(512)", maxLength: 512, nullable: true);
        migrationBuilder.CreateIndex(name: "IX_LicenseHistories_DecisionCorrelationId", table: "LicenseHistories", column: "DecisionCorrelationId");
        migrationBuilder.CreateIndex(name: "IX_LicenseHistories_DecisionSubmittedHardwareId", table: "LicenseHistories", column: "DecisionSubmittedHardwareId");
        migrationBuilder.CreateIndex(name: "IX_LicenseHistories_DecisionResolvedHardwareId", table: "LicenseHistories", column: "DecisionResolvedHardwareId");
        migrationBuilder.CreateIndex(name: "IX_LicenseHistories_DecisionCorrelatedHardwareId", table: "LicenseHistories", column: "DecisionCorrelatedHardwareId");

        migrationBuilder.AddColumn<string>(
            name: "DecisionKey", table: "LicenseHistories", type: "character varying(64)", maxLength: 64, nullable: true);
        migrationBuilder.AddColumn<string>(
            name: "DecisionOperationId", table: "LicenseHistories", type: "character varying(200)", maxLength: 200, nullable: true);
        migrationBuilder.CreateIndex(name: "IX_LicenseHistories_DecisionOperationId", table: "LicenseHistories", column: "DecisionOperationId");
        migrationBuilder.CreateIndex(
            name: "IX_LicenseHistories_DecisionKey", table: "LicenseHistories", column: "DecisionKey", unique: true);
        migrationBuilder.CreateIndex(
            name: "IX_LicenseHistories_LicenseId_DecisionOperationId", table: "LicenseHistories",
            columns: ["LicenseId", "DecisionOperationId"]);
    }

    /// <summary>Removes only the new indexes and lookup columns; historical Details content and existing ownership are retained.</summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(name: "IX_LicenseHistories_DecisionOperationId", table: "LicenseHistories");
        migrationBuilder.DropIndex(name: "IX_LicenseHistories_DecisionCorrelationId", table: "LicenseHistories");
        migrationBuilder.DropIndex(name: "IX_LicenseHistories_DecisionSubmittedHardwareId", table: "LicenseHistories");
        migrationBuilder.DropIndex(name: "IX_LicenseHistories_DecisionResolvedHardwareId", table: "LicenseHistories");
        migrationBuilder.DropIndex(name: "IX_LicenseHistories_DecisionCorrelatedHardwareId", table: "LicenseHistories");
        migrationBuilder.DropColumn(name: "DecisionCorrelationId", table: "LicenseHistories");
        migrationBuilder.DropColumn(name: "DecisionSubmittedHardwareId", table: "LicenseHistories");
        migrationBuilder.DropColumn(name: "DecisionResolvedHardwareId", table: "LicenseHistories");
        migrationBuilder.DropColumn(name: "DecisionCorrelatedHardwareId", table: "LicenseHistories");

        migrationBuilder.DropIndex(name: "IX_LicenseHistories_DecisionKey", table: "LicenseHistories");
        migrationBuilder.DropIndex(name: "IX_LicenseHistories_LicenseId_DecisionOperationId", table: "LicenseHistories");
        migrationBuilder.DropColumn(name: "DecisionKey", table: "LicenseHistories");
        migrationBuilder.DropColumn(name: "DecisionOperationId", table: "LicenseHistories");
    }
}

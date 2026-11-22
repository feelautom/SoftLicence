using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Adds the per-type <c>TeamEligible</c> flag (TKT-002717). The migration is purely additive: every existing type
/// starts at <c>false</c>, and no key, activation, quota or rule of SoftLicence reads the column. External clients
/// read it through the admin API and decide alone what it means.
/// </summary>
public partial class AddTkt002717LicenseTypeTeamEligible : Migration
{
    /// <summary>Adds the non-null column with a false default under a bounded PostgreSQL DDL lock wait.</summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Fail quickly instead of waiting indefinitely behind production traffic on LicenseTypes.
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.AddColumn<bool>(
            name: "TeamEligible",
            table: "LicenseTypes",
            type: "boolean",
            nullable: false,
            defaultValue: false);
    }

    /// <summary>Drops the column; the previous version neither read nor wrote it.</summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.DropColumn(
            name: "TeamEligible",
            table: "LicenseTypes");
    }
}

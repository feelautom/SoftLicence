using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Adds the per-type opt-in that the anonymous public trial routes require before creating or renewing a licence
/// (TKT-002466). Every existing type starts closed (<c>false</c>); no slug or product is opened by the migration,
/// so an administrator must enable each legitimate trial type before deployment.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20261022220000_AddTkt002466LicenseTypeAllowPublicTrial")]
public partial class AddTkt002466LicenseTypeAllowPublicTrial : Migration
{
    /// <summary>Adds the non-null column with a closed default under a bounded PostgreSQL DDL lock wait.</summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Fail quickly instead of waiting indefinitely behind production traffic on LicenseTypes.
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.AddColumn<bool>(
            name: "AllowPublicTrial",
            table: "LicenseTypes",
            type: "boolean",
            nullable: false,
            defaultValue: false);
    }

    /// <summary>Drops the column; the public trial routes of the previous version did not read it.</summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.DropColumn(
            name: "AllowPublicTrial",
            table: "LicenseTypes");
    }
}

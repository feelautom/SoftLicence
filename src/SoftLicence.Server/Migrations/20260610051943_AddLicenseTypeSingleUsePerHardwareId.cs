using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddLicenseTypeSingleUsePerHardwareId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "EnforceSingleUsePerHardwareId",
                table: "LicenseTypes",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.Sql("""
                UPDATE "LicenseTypes"
                SET "EnforceSingleUsePerHardwareId" = TRUE
                WHERE UPPER("Slug") = 'TIA-CONNECT-FREEMIUM';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EnforceSingleUsePerHardwareId",
                table: "LicenseTypes");
        }
    }
}

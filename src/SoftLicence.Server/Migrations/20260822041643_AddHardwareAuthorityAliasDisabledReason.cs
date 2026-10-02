using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddHardwareAuthorityAliasDisabledReason : Migration
    {
        /// <summary>
        /// Adds a durable state reason and classifies every historical inactive row as ambiguous
        /// without making any alias active. Only a later verified operator repair may prove a
        /// specific original-backfill row eligible for bounded Finalize reconciliation.
        /// </summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DisabledReason",
                table: "HardwareAuthorityAliases",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.Sql("""
                UPDATE "HardwareAuthorityAliases"
                SET "DisabledReason" = 'legacy_disabled_unknown'
                WHERE NOT "IsActive";
                """);

            migrationBuilder.DropCheckConstraint(
                name: "CK_HardwareAuthorityAliases_State",
                table: "HardwareAuthorityAliases");

            migrationBuilder.AddCheckConstraint(
                name: "CK_HardwareAuthorityAliases_State",
                table: "HardwareAuthorityAliases",
                sql: "(\"IsActive\" AND \"DisabledAtUtc\" IS NULL AND \"DisabledReason\" IS NULL) OR " +
                     "(NOT \"IsActive\" AND \"DisabledAtUtc\" IS NOT NULL AND \"DisabledReason\" IS NOT NULL)");

        }

        /// <summary>Restores the pre-reason alias state constraint.</summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_HardwareAuthorityAliases_State",
                table: "HardwareAuthorityAliases");

            migrationBuilder.DropColumn(
                name: "DisabledReason",
                table: "HardwareAuthorityAliases");

            migrationBuilder.AddCheckConstraint(
                name: "CK_HardwareAuthorityAliases_State",
                table: "HardwareAuthorityAliases",
                sql: "(\"IsActive\" AND \"DisabledAtUtc\" IS NULL) OR " +
                     "(NOT \"IsActive\" AND \"DisabledAtUtc\" IS NOT NULL)");

        }
    }
}

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt001296AliasRecognizedAuthorityMode : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeDistributionHardwareDecisions_AuthorityMode",
                table: "RuntimeDistributionHardwareDecisions");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeDistributionHardwareDecisions_AuthorityMode",
                table: "RuntimeDistributionHardwareDecisions",
                sql: "\"AuthorityMode\" IN ('server-derived', 'known-enrollment', 'digest-revalidation', 'alias-recognized')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeDistributionHardwareDecisions_AuthorityMode",
                table: "RuntimeDistributionHardwareDecisions");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeDistributionHardwareDecisions_AuthorityMode",
                table: "RuntimeDistributionHardwareDecisions",
                sql: "\"AuthorityMode\" IN ('server-derived', 'known-enrollment', 'digest-revalidation')");
        }
    }
}

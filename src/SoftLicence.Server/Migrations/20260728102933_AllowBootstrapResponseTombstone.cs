using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AllowBootstrapResponseTombstone : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Consumption",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Consumption",
                table: "DistributionLicenseBootstrapAuthorizations",
                sql: "(\"State\" = 'ISSUED' AND \"ConsumedAtUtc\" IS NULL AND \"ResponseCiphertext\" IS NULL) OR (\"State\" = 'CONSUMED' AND \"ConsumedAtUtc\" IS NOT NULL AND \"ReplayExpiresAtUtc\" IS NOT NULL AND ((\"ResponseCiphertext\" IS NOT NULL AND \"ResponseKeyId\" IS NOT NULL) OR (\"ResponseCiphertext\" IS NULL AND \"ResponseKeyId\" IS NULL))) OR \"State\" IN ('REVOKED', 'EXPIRED')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Consumption",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Consumption",
                table: "DistributionLicenseBootstrapAuthorizations",
                sql: "(\"State\" = 'ISSUED' AND \"ConsumedAtUtc\" IS NULL AND \"ResponseCiphertext\" IS NULL) OR (\"State\" = 'CONSUMED' AND \"ConsumedAtUtc\" IS NOT NULL AND \"ResponseCiphertext\" IS NOT NULL AND \"ResponseKeyId\" IS NOT NULL AND \"ReplayExpiresAtUtc\" IS NOT NULL) OR \"State\" IN ('REVOKED', 'EXPIRED')");
        }
    }
}

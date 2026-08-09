using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class HardenDistributionLicenseBootstrap : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DROP TRIGGER IF EXISTS trg_runtime_authority_distributioninstallationbindings_update
                    ON public."DistributionInstallationBindings";
                CREATE TRIGGER trg_runtime_authority_distributioninstallationbindings_update
                BEFORE UPDATE OF "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId",
                    "SubjectRefDigestSha256", "GrantRef", "GrantRefDigestSha256", "HandoffDigestSha256",
                    "HandoffIssuedAtUtc", "HandoffExpiresAtUtc", "DownloadCompletedAtUtc",
                    "InstallationId", "HardwareIdHash", "Version", "InstallerFilename", "InstallerSha256",
                    "ExecutableSha256", "NativeDllSha256", "CoreSha256", "ApprovedBinariesSource",
                    "State", "InvalidatedAtUtc", "InvalidationReason"
                ON public."DistributionInstallationBindings"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                """);
            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionLicenseBootstrapCapabilities_Times",
                table: "DistributionLicenseBootstrapCapabilities",
                sql: "\"MintedAtUtc\" < \"ExpiresAtUtc\"");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_LicenseId",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_LicenseSeatId",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "LicenseSeatId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_ProductId",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "ProductId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_RuntimeEnrollmen~",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "RuntimeEnrollmentId");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Consumption",
                table: "DistributionLicenseBootstrapAuthorizations",
                sql: "(\"State\" = 'ISSUED' AND \"ConsumedAtUtc\" IS NULL AND \"ResponseCiphertext\" IS NULL) OR (\"State\" = 'CONSUMED' AND \"ConsumedAtUtc\" IS NOT NULL AND \"ResponseCiphertext\" IS NOT NULL AND \"ResponseKeyId\" IS NOT NULL AND \"ReplayExpiresAtUtc\" IS NOT NULL) OR \"State\" IN ('REVOKED', 'EXPIRED')");

            migrationBuilder.AddForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_DistributionInst~",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "BindingId",
                principalTable: "DistributionInstallationBindings",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_LicenseSeats_Lic~",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "LicenseSeatId",
                principalTable: "LicenseSeats",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_Licenses_License~",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "LicenseId",
                principalTable: "Licenses",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_Products_Product~",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "ProductId",
                principalTable: "Products",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_RuntimeEnrollmen~",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "RuntimeEnrollmentId",
                principalTable: "RuntimeEnrollments",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DROP TRIGGER IF EXISTS trg_runtime_authority_distributioninstallationbindings_update
                    ON public."DistributionInstallationBindings";
                CREATE TRIGGER trg_runtime_authority_distributioninstallationbindings_update
                BEFORE UPDATE OF "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId", "GrantRef",
                    "GrantRefDigestSha256", "HandoffDigestSha256", "InstallationId", "HardwareIdHash", "Version",
                    "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256", "CoreSha256",
                    "ApprovedBinariesSource", "State", "InvalidatedAtUtc", "InvalidationReason"
                ON public."DistributionInstallationBindings"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                """);
            migrationBuilder.DropForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_DistributionInst~",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_LicenseSeats_Lic~",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_Licenses_License~",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_Products_Product~",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_RuntimeEnrollmen~",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionLicenseBootstrapCapabilities_Times",
                table: "DistributionLicenseBootstrapCapabilities");

            migrationBuilder.DropIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_LicenseId",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_LicenseSeatId",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_ProductId",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_RuntimeEnrollmen~",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Consumption",
                table: "DistributionLicenseBootstrapAuthorizations");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddSameAuthorityInstallationRecovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "InitialSecurityEpoch",
                table: "DistributionInstallationBindings",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<Guid>(
                name: "SupersededBindingId",
                table: "DistributionInstallationBindings",
                type: "uuid",
                nullable: true);

            migrationBuilder.Sql(
                """
                DO $migration$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM public."DistributionInstallationBindings"
                        WHERE "State" = 'active'
                        GROUP BY "ProductId", "HardwareIdHash"
                        HAVING count(*) > 1
                    ) THEN
                        RAISE EXCEPTION USING ERRCODE = '23505',
                            MESSAGE = 'active distribution installation bindings contain duplicate product/hardware authority';
                    END IF;
                END
                $migration$;
                """);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionInstallationBindings_ProductId_HardwareIdHash",
                table: "DistributionInstallationBindings",
                columns: new[] { "ProductId", "HardwareIdHash" },
                unique: true,
                filter: "\"State\" = 'active'");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionInstallationBindings_SupersededBindingId",
                table: "DistributionInstallationBindings",
                column: "SupersededBindingId",
                unique: true,
                filter: "\"SupersededBindingId\" IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionInstallationBindings_InitialSecurityEpoch",
                table: "DistributionInstallationBindings",
                sql: "\"InitialSecurityEpoch\" >= 1");

            migrationBuilder.AddForeignKey(
                name: "FK_DistributionInstallationBindings_DistributionInstallationBi~",
                table: "DistributionInstallationBindings",
                column: "SupersededBindingId",
                principalTable: "DistributionInstallationBindings",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

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
                    "State", "SupersededBindingId", "InitialSecurityEpoch", "InvalidatedAtUtc", "InvalidationReason"
                ON public."DistributionInstallationBindings"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
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
            migrationBuilder.DropForeignKey(
                name: "FK_DistributionInstallationBindings_DistributionInstallationBi~",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropIndex(
                name: "IX_DistributionInstallationBindings_ProductId_HardwareIdHash",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropIndex(
                name: "IX_DistributionInstallationBindings_SupersededBindingId",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionInstallationBindings_InitialSecurityEpoch",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropColumn(
                name: "InitialSecurityEpoch",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropColumn(
                name: "SupersededBindingId",
                table: "DistributionInstallationBindings");
        }
    }
}

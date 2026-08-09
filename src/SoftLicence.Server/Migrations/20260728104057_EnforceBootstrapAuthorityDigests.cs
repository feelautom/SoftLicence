using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class EnforceBootstrapAuthorityDigests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DO $bootstrap_digest_guard$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM public."DistributionEntitlements"
                        WHERE "SubjectRefDigestSha256" IS NULL
                    ) THEN
                        RAISE EXCEPTION USING ERRCODE = '23502',
                            MESSAGE = 'distribution v3 entitlement subject digest is missing';
                    END IF;
                END;
                $bootstrap_digest_guard$;
                """);

            migrationBuilder.AlterColumn<string>(
                name: "SubjectRefDigestSha256",
                table: "DistributionEntitlements",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(64)",
                oldMaxLength: 64,
                oldNullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Digests",
                table: "DistributionLicenseBootstrapAuthorizations",
                sql: "length(\"GrantRefDigestSha256\") = 64 AND length(\"SubjectRefDigestSha256\") = 64 AND length(\"HandoffDigestSha256\") = 64 AND length(\"HardwareIdHash\") = 64 AND length(\"ApprovedBinariesDigestSha256\") = 64 AND length(\"RuntimePublicKeySpkiSha256\") = 64");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionEntitlements_Digests",
                table: "DistributionEntitlements",
                sql: "length(\"GrantRefDigestSha256\") = 64 AND length(\"SubjectRefDigestSha256\") = 64");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionLicenseBootstrapAuthorizations_Digests",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionEntitlements_Digests",
                table: "DistributionEntitlements");

            migrationBuilder.AlterColumn<string>(
                name: "SubjectRefDigestSha256",
                table: "DistributionEntitlements",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(64)",
                oldMaxLength: 64);
        }
    }
}

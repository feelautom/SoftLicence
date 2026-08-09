using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddDistributionBindingInvalidations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "GrantRefDigestSha256",
                table: "DistributionInstallationBindings",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE "DistributionInstallationBindings"
                SET "GrantRefDigestSha256" = encode(sha256(convert_to("GrantRef", 'UTF8')), 'hex')
                WHERE "GrantRefDigestSha256" IS NULL;
                """);

            migrationBuilder.CreateTable(
                name: "DistributionGrantOwnerships",
                columns: table => new
                {
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    GrantRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Source = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionGrantOwnerships", x => new { x.ProductId, x.GrantRefDigestSha256 });
                    table.CheckConstraint("CK_DistributionGrantOwnerships_Source", "\"Source\" IN ('issue_v2', 'finalize_v1')");
                    table.ForeignKey(
                        name: "FK_DistributionGrantOwnerships_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.Sql(
                """
                DO $ownership_backfill$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM public."DistributionInstallationBindings" AS binding
                        LEFT JOIN (
                            SELECT request."BindingId", count(DISTINCT request."ClientId") AS owner_count
                            FROM public."DistributionBindingRequests" AS request
                            WHERE request."Operation" = 'finalize_binding'
                              AND request."BindingId" IS NOT NULL
                            GROUP BY request."BindingId"
                        ) AS owners ON owners."BindingId" = binding."Id"
                        WHERE binding."State" = 'active'
                          AND COALESCE(owners.owner_count, 0) <> 1
                    ) THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '55000',
                            MESSAGE = 'Cannot backfill distribution grant ownership: every active binding must have exactly one finalize_binding client.';
                    END IF;
                END
                $ownership_backfill$;

                INSERT INTO public."DistributionGrantOwnerships"
                    ("ProductId", "GrantRefDigestSha256", "ClientId", "Source", "CreatedAtUtc")
                SELECT binding."ProductId",
                       binding."GrantRefDigestSha256",
                       min(request."ClientId"),
                       'finalize_v1',
                       min(request."CreatedAtUtc")
                FROM public."DistributionInstallationBindings" AS binding
                JOIN public."DistributionBindingRequests" AS request
                  ON request."BindingId" = binding."Id"
                 AND request."Operation" = 'finalize_binding'
                WHERE binding."State" = 'active'
                GROUP BY binding."ProductId", binding."GrantRefDigestSha256", binding."Id"
                HAVING count(DISTINCT request."ClientId") = 1;
                """);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionGrantOwnerships_ClientId_ProductId",
                table: "DistributionGrantOwnerships",
                columns: new[] { "ClientId", "ProductId" });

            migrationBuilder.Sql(
                """
                CREATE TRIGGER trg_runtime_authority_distributiongrantownerships_insert
                BEFORE INSERT ON public."DistributionGrantOwnerships"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                CREATE TRIGGER trg_runtime_authority_distributiongrantownerships_update
                BEFORE UPDATE OF "ProductId", "GrantRefDigestSha256", "ClientId", "Source"
                ON public."DistributionGrantOwnerships"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                CREATE TRIGGER trg_runtime_authority_distributiongrantownerships_delete
                BEFORE DELETE ON public."DistributionGrantOwnerships"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                CREATE TRIGGER trg_runtime_authority_distributiongrantownerships_truncate
                BEFORE TRUNCATE ON public."DistributionGrantOwnerships"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                """);

            migrationBuilder.AlterColumn<string>(
                name: "GrantRefDigestSha256",
                table: "DistributionInstallationBindings",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(64)",
                oldMaxLength: 64,
                oldNullable: true);

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

            migrationBuilder.CreateTable(
                name: "DistributionBindingInvalidations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    GrantRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Epoch = table.Column<long>(type: "bigint", nullable: false),
                    ReceivedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionBindingInvalidations", x => x.Id);
                    table.CheckConstraint("CK_DistributionBindingInvalidations_Epoch_One", "\"Epoch\" = 1");
                    table.CheckConstraint("CK_DistributionBindingInvalidations_Reason", "\"Reason\" IN ('account_closed', 'fraud_flagged', 'grant_revoked', 'security_lockdown')");
                    table.ForeignKey(
                        name: "FK_DistributionBindingInvalidations_DistributionInstallationBi~",
                        column: x => x.BindingId,
                        principalTable: "DistributionInstallationBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DistributionBindingInvalidations_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DistributionInstallationBindings_ProductId_GrantRefDigestSh~",
                table: "DistributionInstallationBindings",
                columns: new[] { "ProductId", "GrantRefDigestSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionBindingInvalidations_BindingId",
                table: "DistributionBindingInvalidations",
                column: "BindingId",
                unique: true,
                filter: "\"BindingId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionBindingInvalidations_ClientId_RequestId",
                table: "DistributionBindingInvalidations",
                columns: new[] { "ClientId", "RequestId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionBindingInvalidations_ProductId_GrantRefDigestSh~",
                table: "DistributionBindingInvalidations",
                columns: new[] { "ProductId", "GrantRefDigestSha256" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DistributionBindingInvalidations");

            migrationBuilder.DropTable(
                name: "DistributionGrantOwnerships");

            migrationBuilder.DropIndex(
                name: "IX_DistributionInstallationBindings_ProductId_GrantRefDigestSh~",
                table: "DistributionInstallationBindings");

            migrationBuilder.Sql(
                """
                DROP TRIGGER IF EXISTS trg_runtime_authority_distributioninstallationbindings_update
                    ON public."DistributionInstallationBindings";
                CREATE TRIGGER trg_runtime_authority_distributioninstallationbindings_update
                BEFORE UPDATE OF "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId", "GrantRef",
                    "HandoffDigestSha256", "InstallationId", "HardwareIdHash", "Version", "InstallerFilename",
                    "InstallerSha256", "ExecutableSha256", "NativeDllSha256", "CoreSha256",
                    "ApprovedBinariesSource", "State", "InvalidatedAtUtc", "InvalidationReason"
                ON public."DistributionInstallationBindings"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                """);

            migrationBuilder.DropColumn(
                name: "GrantRefDigestSha256",
                table: "DistributionInstallationBindings");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds product/license-scoped ownership lineage, a frozen provider command ledger, and the
    /// PostgreSQL guard that permits only one ACTIVE-to-terminal transition per retained version.
    /// The additive migration performs no ownership inference, backfill, or recovery mutation.
    /// </summary>
    public partial class AddTkt000782CommercialOwnershipTransitions : Migration
    {
        /// <summary>
        /// Installs nullable predecessor lineage for existing heads, exact composite relations, and
        /// an update trigger that preserves terminal history while allowing the command CAS update.
        /// </summary>
        /// <param name="migrationBuilder">Provider operations executed atomically by PostgreSQL.</param>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "PreviousOwnershipId",
                table: "RuntimeRecoveryCommercialOwnerships",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddUniqueConstraint(
                name: "AK_RRCO_ProductId_LicenseId_Id",
                table: "RuntimeRecoveryCommercialOwnerships",
                columns: new[] { "ProductId", "LicenseId", "Id" });

            migrationBuilder.CreateTable(
                name: "RuntimeRecoveryCommercialOwnershipCommands",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    Operation = table.Column<string>(type: "varchar(32)", nullable: false, collation: "C"),
                    RequestDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ExpectedOwnershipId = table.Column<Guid>(type: "uuid", nullable: false),
                    TargetCommercialSubjectId = table.Column<Guid>(type: "uuid", nullable: true),
                    ResultOwnershipId = table.Column<Guid>(type: "uuid", nullable: true),
                    OccurredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ResponseJson = table.Column<string>(type: "text", nullable: false, collation: "C")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeRecoveryCommercialOwnershipCommands", x => x.Id);
                    table.CheckConstraint("CK_RRCOC_Operation", "\"Operation\" IN ('TRANSFER_OWNERSHIP','REVOKE_OWNERSHIP')");
                    table.CheckConstraint("CK_RRCOC_RequestDigest", "octet_length(\"RequestDigestSha256\") = 64 AND \"RequestDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RRCOC_ResultShape", "(\"Operation\" = 'TRANSFER_OWNERSHIP' AND \"TargetCommercialSubjectId\" IS NOT NULL AND \"ResultOwnershipId\" IS NOT NULL) OR (\"Operation\" = 'REVOKE_OWNERSHIP' AND \"TargetCommercialSubjectId\" IS NULL AND \"ResultOwnershipId\" IS NULL)");
                    table.ForeignKey(
                        name: "FK_RRCOC_ExpectedOwnership_ProductId_LicenseId_Id",
                        columns: x => new { x.ProductId, x.LicenseId, x.ExpectedOwnershipId },
                        principalTable: "RuntimeRecoveryCommercialOwnerships",
                        principalColumns: new[] { "ProductId", "LicenseId", "Id" });
                    table.ForeignKey(
                        name: "FK_RRCOC_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" });
                    table.ForeignKey(
                        name: "FK_RRCOC_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_RRCOC_ResultOwnership_ProductId_LicenseId_Id",
                        columns: x => new { x.ProductId, x.LicenseId, x.ResultOwnershipId },
                        principalTable: "RuntimeRecoveryCommercialOwnerships",
                        principalColumns: new[] { "ProductId", "LicenseId", "Id" });
                    table.ForeignKey(
                        name: "FK_RRCOC_TargetSubjects_ProductId_SubjectId",
                        columns: x => new { x.ProductId, x.TargetCommercialSubjectId },
                        principalTable: "RuntimeRecoveryCommercialSubjects",
                        principalColumns: new[] { "ProductId", "Id" });
                });

            migrationBuilder.CreateIndex(
                name: "IX_RRCO_PreviousOwnership",
                table: "RuntimeRecoveryCommercialOwnerships",
                columns: new[] { "ProductId", "LicenseId", "PreviousOwnershipId" });

            migrationBuilder.AddCheckConstraint(
                name: "CK_RRCO_Previous_NotSelf",
                table: "RuntimeRecoveryCommercialOwnerships",
                sql: "\"PreviousOwnershipId\" IS NULL OR \"PreviousOwnershipId\" <> \"Id\"");

            migrationBuilder.CreateIndex(
                name: "IX_RRCOC_ExpectedOwnership",
                table: "RuntimeRecoveryCommercialOwnershipCommands",
                columns: new[] { "ProductId", "LicenseId", "ExpectedOwnershipId" });

            migrationBuilder.CreateIndex(
                name: "IX_RRCOC_ResultOwnership",
                table: "RuntimeRecoveryCommercialOwnershipCommands",
                columns: new[] { "ProductId", "LicenseId", "ResultOwnershipId" });

            migrationBuilder.CreateIndex(
                name: "IX_RRCOC_TargetSubject",
                table: "RuntimeRecoveryCommercialOwnershipCommands",
                columns: new[] { "ProductId", "TargetCommercialSubjectId" });

            migrationBuilder.AddForeignKey(
                name: "FK_RRCO_Previous_ProductId_LicenseId_OwnershipId",
                table: "RuntimeRecoveryCommercialOwnerships",
                columns: new[] { "ProductId", "LicenseId", "PreviousOwnershipId" },
                principalTable: "RuntimeRecoveryCommercialOwnerships",
                principalColumns: new[] { "ProductId", "LicenseId", "Id" });

            // The command engine updates only State and EndedAtUtc on the ACTIVE head. Keeping this
            // rule in PostgreSQL prevents another writer from rewriting authority or restoring history.
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.tkt000782_guard_commercial_ownership_version()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    IF OLD."State" <> 'ACTIVE' THEN
                        RAISE EXCEPTION 'terminal commercial ownership history is immutable'
                            USING ERRCODE = '55000';
                    END IF;

                    IF NEW."Id" IS DISTINCT FROM OLD."Id"
                       OR NEW."ProductId" IS DISTINCT FROM OLD."ProductId"
                       OR NEW."LicenseId" IS DISTINCT FROM OLD."LicenseId"
                       OR NEW."PreviousOwnershipId" IS DISTINCT FROM OLD."PreviousOwnershipId"
                       OR NEW."OwnerSubjectId" IS DISTINCT FROM OLD."OwnerSubjectId"
                       OR NEW."CreatedAtUtc" IS DISTINCT FROM OLD."CreatedAtUtc"
                       OR NEW."State" NOT IN ('TRANSFERRED', 'REVOKED')
                       OR NEW."EndedAtUtc" IS NULL THEN
                        RAISE EXCEPTION 'invalid commercial ownership transition'
                            USING ERRCODE = '55000';
                    END IF;

                    RETURN NEW;
                END;
                $function$;

                CREATE TRIGGER trg_tkt000782_commercial_ownership_version
                BEFORE UPDATE ON public."RuntimeRecoveryCommercialOwnerships"
                FOR EACH ROW
                EXECUTE FUNCTION public.tkt000782_guard_commercial_ownership_version();
                """);
        }

        /// <summary>Removes only the additive TKT-000782 schema after dropping its trigger and function.</summary>
        /// <param name="migrationBuilder">Provider operations executed atomically by PostgreSQL.</param>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS trg_tkt000782_commercial_ownership_version
                    ON public."RuntimeRecoveryCommercialOwnerships";
                DROP FUNCTION IF EXISTS public.tkt000782_guard_commercial_ownership_version();
                """);

            migrationBuilder.DropForeignKey(
                name: "FK_RRCO_Previous_ProductId_LicenseId_OwnershipId",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropTable(
                name: "RuntimeRecoveryCommercialOwnershipCommands");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_RRCO_ProductId_LicenseId_Id",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropIndex(
                name: "IX_RRCO_PreviousOwnership",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RRCO_Previous_NotSelf",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropColumn(
                name: "PreviousOwnershipId",
                table: "RuntimeRecoveryCommercialOwnerships");
        }
    }
}

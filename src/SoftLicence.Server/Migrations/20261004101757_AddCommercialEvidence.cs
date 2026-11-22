using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>Adds purchase proof and paid-equivalent historical UNKNOWN without reconstructing past commercial facts.</summary>
    public partial class AddCommercialEvidence : Migration
    {
        /// <summary>Creates constrained order/operation identities and append-only guards with the additive license column; historical rows default to UNKNOWN.</summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CommercialNature",
                table: "Licenses",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "UNKNOWN");

            migrationBuilder.CreateTable(
                name: "CommercialOrderEvidence",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    OrderId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false, collation: "C"),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    CommercialSubjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    Nature = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    PaidAmountMinor = table.Column<int>(type: "integer", nullable: false),
                    Currency = table.Column<string>(type: "character varying(3)", maxLength: 3, nullable: false),
                    Producer = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ReceiptKey = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    AttributionDigest = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CommercialOrderEvidence", x => x.Id);
                    table.CheckConstraint("CK_CommercialOrderEvidence_Values", "\"Version\" = 2 AND \"Currency\" = 'eur' AND length(\"AttributionDigest\") = 64 AND ((\"Nature\" IN ('FIRST_ORDER_FREE','FREE') AND \"PaidAmountMinor\" = 0) OR (\"Nature\" = 'PAID_TRIAL' AND \"PaidAmountMinor\" = 10000) OR (\"Nature\" = 'PAID' AND \"PaidAmountMinor\" > 0))");
                    table.ForeignKey(
                        name: "FK_CommercialOrderEvidence_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_CommercialOrderEvidence_RuntimeRecoveryCommercialSubjects_P~",
                        columns: x => new { x.ProductId, x.CommercialSubjectId },
                        principalTable: "RuntimeRecoveryCommercialSubjects",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CommercialEvidenceOperations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    OrderEvidenceId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigest = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CommercialEvidenceOperations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CommercialEvidenceOperations_CommercialOrderEvidence_OrderE~",
                        column: x => x.OrderEvidenceId,
                        principalTable: "CommercialOrderEvidence",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            // Commercial provenance is append-only even for direct SQL writers. Rollback remains transactional.
            migrationBuilder.Sql("""
                CREATE FUNCTION public.reject_commercial_evidence_mutation() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN
                    RAISE EXCEPTION 'Commercial evidence is immutable' USING ERRCODE = '23514';
                END $$;
                CREATE TRIGGER commercial_order_evidence_immutable BEFORE UPDATE OR DELETE
                    ON public."CommercialOrderEvidence" FOR EACH ROW EXECUTE FUNCTION public.reject_commercial_evidence_mutation();
                CREATE TRIGGER commercial_operation_evidence_immutable BEFORE UPDATE OR DELETE
                    ON public."CommercialEvidenceOperations" FOR EACH ROW EXECUTE FUNCTION public.reject_commercial_evidence_mutation();
                """);
            migrationBuilder.CreateIndex(
                name: "IX_CommercialEvidenceOperations_OrderEvidenceId",
                table: "CommercialEvidenceOperations",
                column: "OrderEvidenceId");

            migrationBuilder.CreateIndex(
                name: "IX_CommercialOrderEvidence_ProductId_CommercialSubjectId",
                table: "CommercialOrderEvidence",
                columns: new[] { "ProductId", "CommercialSubjectId" });

            migrationBuilder.CreateIndex(
                name: "IX_CommercialOrderEvidence_ProductId_LicenseId",
                table: "CommercialOrderEvidence",
                columns: new[] { "ProductId", "LicenseId" });

            migrationBuilder.CreateIndex(
                name: "IX_CommercialOrderEvidence_ProductId_OrderId",
                table: "CommercialOrderEvidence",
                columns: new[] { "ProductId", "OrderId" },
                unique: true);
        }

        /// <summary>Removes only this migration's guards, proof tables and classification column during an explicitly authorized rollback.</summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TRIGGER commercial_order_evidence_immutable ON public.\"CommercialOrderEvidence\"; DROP TRIGGER commercial_operation_evidence_immutable ON public.\"CommercialEvidenceOperations\"; DROP FUNCTION public.reject_commercial_evidence_mutation();");
            migrationBuilder.DropTable(
                name: "CommercialEvidenceOperations");

            migrationBuilder.DropTable(
                name: "CommercialOrderEvidence");

            migrationBuilder.DropColumn(
                name: "CommercialNature",
                table: "Licenses");
        }
    }
}

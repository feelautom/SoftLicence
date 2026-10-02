using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>Adds isolated paid-pass identities, payment evidence and historical receipts; existing customer authority is not backfilled.</summary>
    public partial class AddPersonalDayPassAuthority : Migration
    {
        /// <summary>Creates restrictive foreign keys, canonical payment uniqueness and exact-period checks in PostgreSQL.</summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PersonalDayPasses",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    CommercialSubjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    PaidThroughUtc = table.Column<DateTime>(type: "timestamp(3) with time zone", precision: 3, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PersonalDayPasses", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PersonalDayPasses_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_PersonalDayPasses_RuntimeRecoveryCommercialSubjects_Product~",
                        columns: x => new { x.ProductId, x.CommercialSubjectId },
                        principalTable: "RuntimeRecoveryCommercialSubjects",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PersonalDayPassPayments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    PassId = table.Column<Guid>(type: "uuid", nullable: false),
                    Provider = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false, collation: "C"),
                    ProviderAccount = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false, collation: "C"),
                    Environment = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false, collation: "C"),
                    PaymentId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false, collation: "C"),
                    EvidenceDigest = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false, collation: "C"),
                    PaidAtUtc = table.Column<DateTime>(type: "timestamp(3) with time zone", precision: 3, nullable: false),
                    AmountMinor = table.Column<int>(type: "integer", nullable: false),
                    Currency = table.Column<string>(type: "character varying(3)", maxLength: 3, nullable: false, collation: "C")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PersonalDayPassPayments", x => x.Id);
                    table.CheckConstraint("CK_PersonalDayPassPayments_Digest", "length(\"EvidenceDigest\") = 64");
                    table.CheckConstraint("CK_PersonalDayPassPayments_Identity", "length(\"Provider\") > 0 AND length(\"ProviderAccount\") > 0 AND length(\"Environment\") > 0 AND length(\"PaymentId\") > 0");
                    table.CheckConstraint("CK_PersonalDayPassPayments_Price", "\"AmountMinor\" = 1000 AND \"Currency\" = 'eur'");
                    table.ForeignKey(
                        name: "FK_PersonalDayPassPayments_PersonalDayPasses_PassId",
                        column: x => x.PassId,
                        principalTable: "PersonalDayPasses",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PersonalDayPassOperations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    PaymentId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigest = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false, collation: "C"),
                    ResultAuthorityVersion = table.Column<Guid>(type: "uuid", nullable: false),
                    PeriodStartsAtUtc = table.Column<DateTime>(type: "timestamp(3) with time zone", precision: 3, nullable: false),
                    PeriodExpiresAtUtc = table.Column<DateTime>(type: "timestamp(3) with time zone", precision: 3, nullable: false),
                    PaidThroughUtc = table.Column<DateTime>(type: "timestamp(3) with time zone", precision: 3, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PersonalDayPassOperations", x => x.Id);
                    table.CheckConstraint("CK_PersonalDayPassOperations_Digest", "length(\"RequestDigest\") = 64");
                    table.CheckConstraint("CK_PersonalDayPassOperations_Period", "\"PeriodExpiresAtUtc\" = \"PeriodStartsAtUtc\" + interval '24 hours' AND \"PaidThroughUtc\" >= \"PeriodExpiresAtUtc\"");
                    table.ForeignKey(
                        name: "FK_PersonalDayPassOperations_PersonalDayPassPayments_PaymentId",
                        column: x => x.PaymentId,
                        principalTable: "PersonalDayPassPayments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PersonalDayPasses_LicenseId",
                table: "PersonalDayPasses",
                column: "LicenseId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PersonalDayPasses_ProductId_CommercialSubjectId",
                table: "PersonalDayPasses",
                columns: new[] { "ProductId", "CommercialSubjectId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PersonalDayPasses_ProductId_LicenseId",
                table: "PersonalDayPasses",
                columns: new[] { "ProductId", "LicenseId" });

            migrationBuilder.CreateIndex(
                name: "IX_PersonalDayPassOperations_PaymentId",
                table: "PersonalDayPassOperations",
                column: "PaymentId");

            migrationBuilder.CreateIndex(
                name: "IX_PersonalDayPassPayments_PassId_PaidAtUtc",
                table: "PersonalDayPassPayments",
                columns: new[] { "PassId", "PaidAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_PersonalDayPassPayments_Provider_ProviderAccount_Environmen~",
                table: "PersonalDayPassPayments",
                columns: new[] { "Provider", "ProviderAccount", "Environment", "PaymentId" },
                unique: true);
        }

        /// <summary>Drops only the new tables in dependency order. Production rollback requires separate authorization and paid-evidence preservation.</summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PersonalDayPassOperations");

            migrationBuilder.DropTable(
                name: "PersonalDayPassPayments");

            migrationBuilder.DropTable(
                name: "PersonalDayPasses");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>Adds durable authenticated migration evidence without backfilling historical aliases.</summary>
    public partial class AddDurableHardwareMigrationReceipts : Migration
    {
        /// <summary>Adds nullable alias provenance, restricted receipt references, and append-only/key-retention guards.</summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "MigrationReceiptId",
                table: "HardwareAuthorityAliases",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "HardwareAuthorityMigrationReceipts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    Jti = table.Column<Guid>(type: "uuid", nullable: false),
                    ParentReceiptId = table.Column<Guid>(type: "uuid", nullable: true),
                    EnrollmentEpoch = table.Column<int>(type: "integer", nullable: false),
                    KeyPurpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    KeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Ciphertext = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HardwareAuthorityMigrationReceipts", x => x.Id);
                    table.CheckConstraint("CK_MigrationReceipt_Envelope", "\"KeyPurpose\" = 'encryption' AND \"EnrollmentEpoch\" >= 1 AND length(\"Ciphertext\") > 0");
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityMigrationReceipts_HardwareAuthorityMigrati~",
                        column: x => x.ParentReceiptId,
                        principalTable: "HardwareAuthorityMigrationReceipts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityMigrationReceipts_RuntimeEnrollmentKeyRegi~",
                        columns: x => new { x.KeyPurpose, x.KeyId },
                        principalTable: "RuntimeEnrollmentKeyRegistries",
                        principalColumns: new[] { "Purpose", "KeyId" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityMigrationReceipts_RuntimeEnrollments_Enrol~",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityAliases_MigrationReceiptId",
                table: "HardwareAuthorityAliases",
                column: "MigrationReceiptId");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityMigrationReceipts_EnrollmentId_Jti",
                table: "HardwareAuthorityMigrationReceipts",
                columns: new[] { "EnrollmentId", "Jti" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityMigrationReceipts_EnrollmentId_RequestId",
                table: "HardwareAuthorityMigrationReceipts",
                columns: new[] { "EnrollmentId", "RequestId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityMigrationReceipts_KeyPurpose_KeyId",
                table: "HardwareAuthorityMigrationReceipts",
                columns: new[] { "KeyPurpose", "KeyId" });

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityMigrationReceipts_ParentReceiptId",
                table: "HardwareAuthorityMigrationReceipts",
                column: "ParentReceiptId");

            migrationBuilder.AddForeignKey(
                name: "FK_HardwareAuthorityAliases_HardwareAuthorityMigrationReceipts~",
                table: "HardwareAuthorityAliases",
                column: "MigrationReceiptId",
                principalTable: "HardwareAuthorityMigrationReceipts",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
            MigrationReceiptGuards.Install(migrationBuilder);
        }

        /// <summary>Removes the additive schema only when no durable evidence exists; otherwise requires backup restoration.</summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            MigrationReceiptGuards.RemoveWhenEmpty(migrationBuilder);
            migrationBuilder.DropForeignKey(
                name: "FK_HardwareAuthorityAliases_HardwareAuthorityMigrationReceipts~",
                table: "HardwareAuthorityAliases");

            migrationBuilder.DropTable(
                name: "HardwareAuthorityMigrationReceipts");

            migrationBuilder.DropIndex(
                name: "IX_HardwareAuthorityAliases_MigrationReceiptId",
                table: "HardwareAuthorityAliases");

            migrationBuilder.DropColumn(
                name: "MigrationReceiptId",
                table: "HardwareAuthorityAliases");
        }
    }
}

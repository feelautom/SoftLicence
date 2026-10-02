using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds the provider-owned, product-scoped CommercialSubject authority and exact ownership
    /// foreign keys without synthesizing subjects or rewriting historical ownership.
    /// </summary>
    /// <remarks>
    /// PostgreSQL applies the migration transactionally. A pre-existing ownership without an
    /// explicitly persisted subject makes FK validation fail and rolls the complete migration back.
    /// </remarks>
    public partial class AddTkt000779CommercialSubjectOwnershipIntegrity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddUniqueConstraint(
                name: "AK_Licenses_ProductId_Id",
                table: "Licenses",
                columns: new[] { "ProductId", "Id" });

            migrationBuilder.CreateTable(
                name: "RuntimeRecoveryCommercialSubjects",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeRecoveryCommercialSubjects", x => new { x.ProductId, x.Id });
                    table.ForeignKey(
                        name: "FK_RRCS_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeRecoveryCommercialOwnerships_ProductId_OwnerSubjectId",
                table: "RuntimeRecoveryCommercialOwnerships",
                columns: new[] { "ProductId", "OwnerSubjectId" });

            migrationBuilder.AddForeignKey(
                name: "FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId",
                table: "RuntimeRecoveryCommercialOwnerships",
                columns: new[] { "ProductId", "OwnerSubjectId" },
                principalTable: "RuntimeRecoveryCommercialSubjects",
                principalColumns: new[] { "ProductId", "Id" });

            migrationBuilder.AddForeignKey(
                name: "FK_RRCO_Licenses_ProductId_LicenseId",
                table: "RuntimeRecoveryCommercialOwnerships",
                columns: new[] { "ProductId", "LicenseId" },
                principalTable: "Licenses",
                principalColumns: new[] { "ProductId", "Id" });

            migrationBuilder.AddForeignKey(
                name: "FK_RRCO_Products_ProductId",
                table: "RuntimeRecoveryCommercialOwnerships",
                column: "ProductId",
                principalTable: "Products",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropForeignKey(
                name: "FK_RRCO_Licenses_ProductId_LicenseId",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropForeignKey(
                name: "FK_RRCO_Products_ProductId",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropTable(
                name: "RuntimeRecoveryCommercialSubjects");

            migrationBuilder.DropIndex(
                name: "IX_RuntimeRecoveryCommercialOwnerships_ProductId_OwnerSubjectId",
                table: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_Licenses_ProductId_Id",
                table: "Licenses");
        }
    }
}

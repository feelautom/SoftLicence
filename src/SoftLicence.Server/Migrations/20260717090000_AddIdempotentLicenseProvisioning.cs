using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    [DbContext(typeof(Data.LicenseDbContext))]
    [Migration("20260717090000_AddIdempotentLicenseProvisioning")]
    public partial class AddIdempotentLicenseProvisioning : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "TransactionId",
                table: "LicenseRenewals",
                type: "character varying(256)",
                maxLength: 256,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AddColumn<string>(
                name: "ResultingReference",
                table: "LicenseRenewals",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ResultingExpirationDate",
                table: "LicenseRenewals",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "LicenseProvisioningRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    Reference = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    RequestHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LicenseProvisioningRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LicenseProvisioningRequests_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.AddColumn<Guid>(
                name: "ProvisioningRequestId",
                table: "Licenses",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ProvisioningSequence",
                table: "Licenses",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Licenses_ProvisioningRequestId",
                table: "Licenses",
                column: "ProvisioningRequestId");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseProvisioningRequests_ProductId_Reference",
                table: "LicenseProvisioningRequests",
                columns: new[] { "ProductId", "Reference" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Licenses_LicenseProvisioningRequests_ProvisioningRequestId",
                table: "Licenses",
                column: "ProvisioningRequestId",
                principalTable: "LicenseProvisioningRequests",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Licenses_LicenseProvisioningRequests_ProvisioningRequestId",
                table: "Licenses");

            migrationBuilder.DropIndex(
                name: "IX_Licenses_ProvisioningRequestId",
                table: "Licenses");

            migrationBuilder.DropColumn(name: "ProvisioningRequestId", table: "Licenses");
            migrationBuilder.DropColumn(name: "ProvisioningSequence", table: "Licenses");
            migrationBuilder.DropTable(name: "LicenseProvisioningRequests");
            migrationBuilder.DropColumn(name: "ResultingExpirationDate", table: "LicenseRenewals");
            migrationBuilder.DropColumn(name: "ResultingReference", table: "LicenseRenewals");

            migrationBuilder.AlterColumn<string>(
                name: "TransactionId",
                table: "LicenseRenewals",
                type: "text",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(256)",
                oldMaxLength: 256);
        }
    }
}

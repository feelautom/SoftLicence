using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class DataIntegrityAndPerformance : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Licenses_LicenseTypes_LicenseTypeId",
                table: "Licenses");

            migrationBuilder.DropIndex(
                name: "IX_LicenseSeats_LicenseId",
                table: "LicenseSeats");

            migrationBuilder.DropIndex(
                name: "IX_Licenses_ProductId",
                table: "Licenses");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseSeats_LicenseId_HardwareId",
                table: "LicenseSeats",
                columns: new[] { "LicenseId", "HardwareId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Licenses_ProductId_HardwareId",
                table: "Licenses",
                columns: new[] { "ProductId", "HardwareId" });

            migrationBuilder.CreateIndex(
                name: "IX_AccessLogs_ClientIp",
                table: "AccessLogs",
                column: "ClientIp");

            migrationBuilder.CreateIndex(
                name: "IX_AccessLogs_Timestamp",
                table: "AccessLogs",
                column: "Timestamp");

            migrationBuilder.AddForeignKey(
                name: "FK_Licenses_LicenseTypes_LicenseTypeId",
                table: "Licenses",
                column: "LicenseTypeId",
                principalTable: "LicenseTypes",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Licenses_LicenseTypes_LicenseTypeId",
                table: "Licenses");

            migrationBuilder.DropIndex(
                name: "IX_LicenseSeats_LicenseId_HardwareId",
                table: "LicenseSeats");

            migrationBuilder.DropIndex(
                name: "IX_Licenses_ProductId_HardwareId",
                table: "Licenses");

            migrationBuilder.DropIndex(
                name: "IX_AccessLogs_ClientIp",
                table: "AccessLogs");

            migrationBuilder.DropIndex(
                name: "IX_AccessLogs_Timestamp",
                table: "AccessLogs");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseSeats_LicenseId",
                table: "LicenseSeats",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_Licenses_ProductId",
                table: "Licenses",
                column: "ProductId");

            migrationBuilder.AddForeignKey(
                name: "FK_Licenses_LicenseTypes_LicenseTypeId",
                table: "Licenses",
                column: "LicenseTypeId",
                principalTable: "LicenseTypes",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}

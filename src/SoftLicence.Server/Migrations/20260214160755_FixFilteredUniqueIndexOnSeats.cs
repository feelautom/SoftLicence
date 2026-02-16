using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class FixFilteredUniqueIndexOnSeats : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_LicenseSeats_LicenseId_HardwareId",
                table: "LicenseSeats");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseSeats_LicenseId_HardwareId",
                table: "LicenseSeats",
                columns: new[] { "LicenseId", "HardwareId" },
                unique: true,
                filter: "\"IsActive\" = true");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_LicenseSeats_LicenseId_HardwareId",
                table: "LicenseSeats");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseSeats_LicenseId_HardwareId",
                table: "LicenseSeats",
                columns: new[] { "LicenseId", "HardwareId" },
                unique: true);
        }
    }
}

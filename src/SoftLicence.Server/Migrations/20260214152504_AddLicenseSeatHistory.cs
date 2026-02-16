using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddLicenseSeatHistory : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsActive",
                table: "LicenseSeats",
                type: "boolean",
                nullable: false,
                defaultValue: true);

            // Ensure existing seats are marked as active
            migrationBuilder.Sql("UPDATE \"LicenseSeats\" SET \"IsActive\" = true;");

            migrationBuilder.AddColumn<DateTime>(
                name: "UnlinkedAt",
                table: "LicenseSeats",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsActive",
                table: "LicenseSeats");

            migrationBuilder.DropColumn(
                name: "UnlinkedAt",
                table: "LicenseSeats");
        }
    }
}

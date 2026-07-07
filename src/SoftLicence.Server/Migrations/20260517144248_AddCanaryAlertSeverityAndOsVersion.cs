using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCanaryAlertSeverityAndOsVersion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "OsVersion",
                table: "CanaryAlerts",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Severity",
                table: "CanaryAlerts",
                type: "integer",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "OsVersion",
                table: "CanaryAlerts");

            migrationBuilder.DropColumn(
                name: "Severity",
                table: "CanaryAlerts");
        }
    }
}

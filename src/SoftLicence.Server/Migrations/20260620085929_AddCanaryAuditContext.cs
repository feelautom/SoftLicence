using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCanaryAuditContext : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AssemblyLocation",
                table: "CanaryAlerts",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BaseDirectory",
                table: "CanaryAlerts",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BinaryFingerprintsJson",
                table: "CanaryAlerts",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BuildConfiguration",
                table: "CanaryAlerts",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ProcessPath",
                table: "CanaryAlerts",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ServerAction",
                table: "CanaryAlerts",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AssemblyLocation",
                table: "CanaryAlerts");

            migrationBuilder.DropColumn(
                name: "BaseDirectory",
                table: "CanaryAlerts");

            migrationBuilder.DropColumn(
                name: "BinaryFingerprintsJson",
                table: "CanaryAlerts");

            migrationBuilder.DropColumn(
                name: "BuildConfiguration",
                table: "CanaryAlerts");

            migrationBuilder.DropColumn(
                name: "ProcessPath",
                table: "CanaryAlerts");

            migrationBuilder.DropColumn(
                name: "ServerAction",
                table: "CanaryAlerts");
        }
    }
}

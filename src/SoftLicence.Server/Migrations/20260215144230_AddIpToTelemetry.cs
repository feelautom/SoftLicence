using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddIpToTelemetry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ClientIp",
                table: "TelemetryRecords",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Isp",
                table: "TelemetryRecords",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ClientIp",
                table: "TelemetryRecords");

            migrationBuilder.DropColumn(
                name: "Isp",
                table: "TelemetryRecords");
        }
    }
}

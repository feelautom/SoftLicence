using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class HardenCertPinningDailyAlertContext : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "LastCertificateIssuer",
                table: "TelemetryCertPinningDailyAlerts",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastFailureReason",
                table: "TelemetryCertPinningDailyAlerts",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastCertificateIssuer",
                table: "TelemetryCertPinningDailyAlerts");

            migrationBuilder.DropColumn(
                name: "LastFailureReason",
                table: "TelemetryCertPinningDailyAlerts");
        }
    }
}

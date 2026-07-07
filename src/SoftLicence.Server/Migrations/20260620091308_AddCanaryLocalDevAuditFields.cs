using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCanaryLocalDevAuditFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsLocalDevBuild",
                table: "CanaryAlerts",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LocalDevBuildReason",
                table: "CanaryAlerts",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsLocalDevBuild",
                table: "CanaryAlerts");

            migrationBuilder.DropColumn(
                name: "LocalDevBuildReason",
                table: "CanaryAlerts");
        }
    }
}

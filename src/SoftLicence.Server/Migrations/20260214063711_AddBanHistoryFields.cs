using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddBanHistoryFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "BanCount",
                table: "BannedIps",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "IsActive",
                table: "BannedIps",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BanCount",
                table: "BannedIps");

            migrationBuilder.DropColumn(
                name: "IsActive",
                table: "BannedIps");
        }
    }
}

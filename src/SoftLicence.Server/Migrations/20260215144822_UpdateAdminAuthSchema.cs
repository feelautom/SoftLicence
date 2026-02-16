using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class UpdateAdminAuthSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AdminPath",
                table: "AdminUsers",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AdminPath",
                table: "AdminUsers");
        }
    }
}

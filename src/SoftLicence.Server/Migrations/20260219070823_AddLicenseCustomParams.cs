using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddLicenseCustomParams : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Idempotent: safe to run even if column already exists
            migrationBuilder.Sql("""
                ALTER TABLE "Licenses" ADD COLUMN IF NOT EXISTS "CustomParamsJson" text;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CustomParamsJson",
                table: "Licenses");
        }
    }
}

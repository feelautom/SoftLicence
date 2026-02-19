using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddLicenseTypeCustomParams : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Idempotent: drop CustomParamsJson if it was added by the previous migration
            migrationBuilder.Sql("""
                ALTER TABLE "Licenses" DROP COLUMN IF EXISTS "CustomParamsJson";
                """);

            // Idempotent: create LicenseTypeCustomParams table
            migrationBuilder.Sql("""
                CREATE TABLE IF NOT EXISTS "LicenseTypeCustomParams" (
                    "Id" uuid NOT NULL DEFAULT gen_random_uuid(),
                    "LicenseTypeId" uuid NOT NULL,
                    "Key" text NOT NULL,
                    "Name" text NOT NULL,
                    "Value" text NOT NULL DEFAULT '',
                    CONSTRAINT "PK_LicenseTypeCustomParams" PRIMARY KEY ("Id"),
                    CONSTRAINT "FK_LicenseTypeCustomParams_LicenseTypes_LicenseTypeId"
                        FOREIGN KEY ("LicenseTypeId") REFERENCES "LicenseTypes" ("Id") ON DELETE CASCADE
                );
                """);

            migrationBuilder.Sql("""
                CREATE UNIQUE INDEX IF NOT EXISTS "IX_LicenseTypeCustomParams_LicenseTypeId_Key"
                    ON "LicenseTypeCustomParams" ("LicenseTypeId", "Key");
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LicenseTypeCustomParams");

            migrationBuilder.AddColumn<string>(
                name: "CustomParamsJson",
                table: "Licenses",
                type: "text",
                nullable: true);
        }
    }
}

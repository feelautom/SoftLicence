using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddProductScopedTypesAndSubProducts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Idempotent: the DB may already have some of these columns/indexes from a prior
            // partial deployment. Use raw SQL with IF NOT EXISTS / IF EXISTS guards.

            migrationBuilder.Sql("""
                DROP INDEX IF EXISTS "IX_LicenseTypes_Slug";
                """);

            migrationBuilder.Sql("""
                ALTER TABLE "Products" ADD COLUMN IF NOT EXISTS "ParentProductId" uuid;
                """);

            migrationBuilder.Sql("""
                ALTER TABLE "LicenseTypes" ADD COLUMN IF NOT EXISTS "ProductId" uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                ALTER TABLE "AdminUsers" ADD COLUMN IF NOT EXISTS "AdminPath" text;
                """);

            migrationBuilder.Sql("""
                CREATE INDEX IF NOT EXISTS "IX_Products_ParentProductId" ON "Products" ("ParentProductId");
                """);

            migrationBuilder.Sql("""
                CREATE UNIQUE INDEX IF NOT EXISTS "IX_LicenseTypes_ProductId_Slug" ON "LicenseTypes" ("ProductId", "Slug");
                """);

            // Data migration: existing LicenseTypes got the zero-UUID default for ProductId.
            // Assign them to the first available Product so the FK constraint can be applied.
            migrationBuilder.Sql("""
                UPDATE "LicenseTypes"
                SET "ProductId" = (SELECT "Id" FROM "Products" ORDER BY "Name" LIMIT 1)
                WHERE "ProductId" = '00000000-0000-0000-0000-000000000000'
                  AND EXISTS (SELECT 1 FROM "Products");
                """);

            migrationBuilder.Sql("""
                DO $BODY$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'FK_LicenseTypes_Products_ProductId') THEN
                        ALTER TABLE "LicenseTypes"
                            ADD CONSTRAINT "FK_LicenseTypes_Products_ProductId"
                            FOREIGN KEY ("ProductId") REFERENCES "Products" ("Id") ON DELETE CASCADE;
                    END IF;
                END $BODY$;
                """);

            migrationBuilder.Sql("""
                DO $BODY$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'FK_Products_Products_ParentProductId') THEN
                        ALTER TABLE "Products"
                            ADD CONSTRAINT "FK_Products_Products_ParentProductId"
                            FOREIGN KEY ("ParentProductId") REFERENCES "Products" ("Id") ON DELETE RESTRICT;
                    END IF;
                END $BODY$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LicenseTypes_Products_ProductId",
                table: "LicenseTypes");

            migrationBuilder.DropForeignKey(
                name: "FK_Products_Products_ParentProductId",
                table: "Products");

            migrationBuilder.DropIndex(
                name: "IX_Products_ParentProductId",
                table: "Products");

            migrationBuilder.DropIndex(
                name: "IX_LicenseTypes_ProductId_Slug",
                table: "LicenseTypes");

            migrationBuilder.DropColumn(
                name: "ParentProductId",
                table: "Products");

            migrationBuilder.DropColumn(
                name: "ProductId",
                table: "LicenseTypes");

            migrationBuilder.DropColumn(
                name: "AdminPath",
                table: "AdminUsers");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseTypes_Slug",
                table: "LicenseTypes",
                column: "Slug",
                unique: true);
        }
    }
}

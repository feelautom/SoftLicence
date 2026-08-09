using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddApprovedBinaryRegistrationContract : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ApprovedBinaryRegistrationId",
                table: "ApprovedBinaries",
                type: "uuid",
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE "ApprovedBinaries"
                SET "Hash" = lower(btrim("Hash"))
                WHERE btrim("Hash") ~* '^[0-9a-f]{64}$';
                """);

            migrationBuilder.AddCheckConstraint(
                name: "CK_ApprovedBinaries_Hash",
                table: "ApprovedBinaries",
                sql: "\"Hash\" ~ '^[0-9a-f]{64}$'");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ApprovedBinaries_Key",
                table: "ApprovedBinaries",
                sql: "\"Key\" IN ('FP_EXE', 'FP_DLL', 'FP_CORE')");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ApprovedBinaries_RegistrationSource",
                table: "ApprovedBinaries",
                sql: "\"ApprovedBinaryRegistrationId\" IS NULL OR \"Source\" = 'release'");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ApprovedBinaries_Source",
                table: "ApprovedBinaries",
                sql: "\"Source\" IN ('release', 'admin', 'auto', 'publish', 'local-test')");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ApprovedBinaries_Version",
                table: "ApprovedBinaries",
                sql: "\"Version\" ~ '^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$'");

            migrationBuilder.CreateTable(
                name: "ApprovedBinaryRegistrations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false, collation: "C"),
                    RegistrationKey = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false, collation: "C"),
                    ManifestDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    BaselineDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Source = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    RegisteredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApprovedBinaryRegistrations", x => x.Id);
                    table.CheckConstraint("CK_ApprovedBinaryRegistrations_Digests", "\"ManifestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"BaselineDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_ApprovedBinaryRegistrations_RegistrationKey", "octet_length(\"RegistrationKey\") BETWEEN 1 AND 128 AND \"RegistrationKey\" ~ '^[!-~]+$'");
                    table.CheckConstraint("CK_ApprovedBinaryRegistrations_Source", "\"Source\" = 'release'");
                    table.CheckConstraint("CK_ApprovedBinaryRegistrations_Version", "\"Version\" ~ '^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$'");
                    table.ForeignKey(
                        name: "FK_ApprovedBinaryRegistrations_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ApprovedBinaries_ApprovedBinaryRegistrationId",
                table: "ApprovedBinaries",
                column: "ApprovedBinaryRegistrationId");

            migrationBuilder.CreateIndex(
                name: "IX_ApprovedBinaryRegistrations_ProductId_Version",
                table: "ApprovedBinaryRegistrations",
                columns: new[] { "ProductId", "Version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApprovedBinaryRegistrations_RegistrationKey",
                table: "ApprovedBinaryRegistrations",
                column: "RegistrationKey",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_ApprovedBinaries_ApprovedBinaryRegistrations_ApprovedBinary~",
                table: "ApprovedBinaries",
                column: "ApprovedBinaryRegistrationId",
                principalTable: "ApprovedBinaryRegistrations",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ApprovedBinaries_ApprovedBinaryRegistrations_ApprovedBinary~",
                table: "ApprovedBinaries");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ApprovedBinaries_Hash",
                table: "ApprovedBinaries");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ApprovedBinaries_Key",
                table: "ApprovedBinaries");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ApprovedBinaries_RegistrationSource",
                table: "ApprovedBinaries");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ApprovedBinaries_Source",
                table: "ApprovedBinaries");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ApprovedBinaries_Version",
                table: "ApprovedBinaries");

            migrationBuilder.DropTable(
                name: "ApprovedBinaryRegistrations");

            migrationBuilder.DropIndex(
                name: "IX_ApprovedBinaries_ApprovedBinaryRegistrationId",
                table: "ApprovedBinaries");

            migrationBuilder.DropColumn(
                name: "ApprovedBinaryRegistrationId",
                table: "ApprovedBinaries");

        }
    }
}

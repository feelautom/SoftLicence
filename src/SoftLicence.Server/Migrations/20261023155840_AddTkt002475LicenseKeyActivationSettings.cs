using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt002475LicenseKeyActivationSettings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "LicenseKeyActivationOperations",
                columns: table => new
                {
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    Intent = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Outcome = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Actor = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LicenseKeyActivationOperations", x => x.RequestId);
                    table.CheckConstraint("CK_LicenseKeyActivationOperations_Actor", "\"Actor\" IN ('s2s', 'admin')");
                    table.CheckConstraint("CK_LicenseKeyActivationOperations_IntentOutcome", "(\"Intent\" = 'disable' AND \"Outcome\" IN ('disabled', 'already_disabled')) OR (\"Intent\" = 'lift' AND \"Outcome\" IN ('lifted', 'already_lifted'))");
                    table.ForeignKey(
                        name: "FK_LicenseKeyActivationOperations_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "LicenseKeyActivationSettings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    Disabled = table.Column<bool>(type: "boolean", nullable: false),
                    DisabledAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LiftedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    DisabledByRequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    LiftedByRequestId = table.Column<Guid>(type: "uuid", nullable: true),
                    DisabledByActor = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    LiftedByActor = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    DisabledByClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    LiftedByClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LicenseKeyActivationSettings", x => x.Id);
                    table.CheckConstraint("CK_LicenseKeyActivationSettings_Actors", "\"DisabledByActor\" IN ('s2s', 'admin') AND (\"LiftedByActor\" IS NULL OR \"LiftedByActor\" IN ('s2s', 'admin'))");
                    table.CheckConstraint("CK_LicenseKeyActivationSettings_ClientIds", "(\"DisabledByClientId\" = 'admin' OR \"DisabledByClientId\" ~ '^[a-z0-9][a-z0-9._-]{2,63}$') AND (\"LiftedByClientId\" IS NULL OR \"LiftedByClientId\" = 'admin' OR \"LiftedByClientId\" ~ '^[a-z0-9][a-z0-9._-]{2,63}$')");
                    table.CheckConstraint("CK_LicenseKeyActivationSettings_Shape", "(\"Disabled\" = TRUE AND \"LiftedAtUtc\" IS NULL AND \"LiftedByRequestId\" IS NULL AND \"LiftedByActor\" IS NULL AND \"LiftedByClientId\" IS NULL) OR (\"Disabled\" = FALSE AND \"LiftedAtUtc\" IS NOT NULL AND \"LiftedByRequestId\" IS NOT NULL AND \"LiftedByActor\" IS NOT NULL AND \"LiftedByClientId\" IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_LicenseKeyActivationSettings_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_LicenseKeyActivationOperations_LicenseId",
                table: "LicenseKeyActivationOperations",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseKeyActivationOperations_ProductId_LicenseId",
                table: "LicenseKeyActivationOperations",
                columns: new[] { "ProductId", "LicenseId" });

            migrationBuilder.CreateIndex(
                name: "IX_LicenseKeyActivationSettings_DisabledByRequestId",
                table: "LicenseKeyActivationSettings",
                column: "DisabledByRequestId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LicenseKeyActivationSettings_LicenseId",
                table: "LicenseKeyActivationSettings",
                column: "LicenseId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LicenseKeyActivationSettings_LiftedByRequestId",
                table: "LicenseKeyActivationSettings",
                column: "LiftedByRequestId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LicenseKeyActivationSettings_ProductId_LicenseId",
                table: "LicenseKeyActivationSettings",
                columns: new[] { "ProductId", "LicenseId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LicenseKeyActivationOperations");

            migrationBuilder.DropTable(
                name: "LicenseKeyActivationSettings");
        }
    }
}

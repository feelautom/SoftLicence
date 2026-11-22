using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt002041LicenseHardwareExclusions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_PortalDeactivationOperations_Reason",
                table: "PortalDeactivationOperations");

            migrationBuilder.CreateTable(
                name: "LicenseHardwareExclusions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LiftedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedByRequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    LiftedByRequestId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedByClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedByRequestFingerprintSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Actor = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    LiftedByClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    LiftedByActor = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    ReleaseActiveSeat = table.Column<bool>(type: "boolean", nullable: false),
                    ReleaseOutcome = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LicenseHardwareExclusions", x => x.Id);
                    table.CheckConstraint("CK_LicenseHardwareExclusions_Actor", "\"Actor\" IN ('s2s', 'admin')");
                    table.CheckConstraint("CK_LicenseHardwareExclusions_HardwareId", "\"HardwareId\" ~ '^[0-9A-F]{16}$'");
                    table.CheckConstraint("CK_LicenseHardwareExclusions_LiftedByActor", "\"LiftedByActor\" IS NULL OR \"LiftedByActor\" IN ('s2s', 'admin')");
                    table.CheckConstraint("CK_LicenseHardwareExclusions_ReleaseOutcome", "\"ReleaseOutcome\" IN ('deactivated', 'already_inactive', 'none')");
                    table.CheckConstraint("CK_LicenseHardwareExclusions_RequestFingerprintSha256", "length(\"CreatedByRequestFingerprintSha256\") = 64 AND \"CreatedByRequestFingerprintSha256\" ~ '^[0-9a-f]{64}$'");
                    table.ForeignKey(
                        name: "FK_LicenseHardwareExclusions_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_PortalDeactivationOperations_Reason",
                table: "PortalDeactivationOperations",
                sql: "\"Reason\" IN ('settings_button', 'subscription_termination', 'uninstall', 'provider_authority_release')");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseHardwareExclusions_CreatedByRequestId",
                table: "LicenseHardwareExclusions",
                column: "CreatedByRequestId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LicenseHardwareExclusions_LicenseId",
                table: "LicenseHardwareExclusions",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseHardwareExclusions_LicenseId_HardwareId",
                table: "LicenseHardwareExclusions",
                columns: new[] { "LicenseId", "HardwareId" },
                unique: true,
                filter: "\"LiftedAtUtc\" IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseHardwareExclusions_LiftedByRequestId",
                table: "LicenseHardwareExclusions",
                column: "LiftedByRequestId",
                unique: true,
                filter: "\"LiftedByRequestId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LicenseHardwareExclusions_ProductId_LicenseId",
                table: "LicenseHardwareExclusions",
                columns: new[] { "ProductId", "LicenseId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LicenseHardwareExclusions");

            migrationBuilder.DropCheckConstraint(
                name: "CK_PortalDeactivationOperations_Reason",
                table: "PortalDeactivationOperations");

            migrationBuilder.AddCheckConstraint(
                name: "CK_PortalDeactivationOperations_Reason",
                table: "PortalDeactivationOperations",
                sql: "\"Reason\" IN ('settings_button', 'subscription_termination', 'uninstall')");
        }
    }
}

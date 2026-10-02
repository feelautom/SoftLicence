using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations.TKT798
{
    /// <inheritdoc />
    public partial class AddTkt000798PortalDeactivationOperations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PortalDeactivationOperations",
                columns: table => new
                {
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestFingerprintSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Reason = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Outcome = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PortalDeactivationOperations", x => x.RequestId);
                    table.CheckConstraint("CK_PortalDeactivationOperations_ClientId", "\"ClientId\" ~ '^[a-z0-9][a-z0-9._-]{2,63}$'");
                    table.CheckConstraint("CK_PortalDeactivationOperations_HardwareId", "\"HardwareId\" ~ '^[A-Z0-9][A-Z0-9:_-]{4,199}$'");
                    table.CheckConstraint("CK_PortalDeactivationOperations_Outcome", "\"Outcome\" IN ('deactivated', 'already_inactive')");
                    table.CheckConstraint("CK_PortalDeactivationOperations_Reason", "\"Reason\" IN ('settings_button', 'subscription_termination', 'uninstall')");
                    table.CheckConstraint("CK_PortalDeactivationOperations_RequestFingerprintSha256", "length(\"RequestFingerprintSha256\") = 64 AND \"RequestFingerprintSha256\" ~ '^[0-9a-f]{64}$'");
                    table.ForeignKey(
                        name: "FK_PortalDeactivationOperations_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PortalDeactivationOperations_LicenseId",
                table: "PortalDeactivationOperations",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_PortalDeactivationOperations_ProductId_LicenseId",
                table: "PortalDeactivationOperations",
                columns: new[] { "ProductId", "LicenseId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PortalDeactivationOperations");
        }
    }
}

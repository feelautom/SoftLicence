using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class BindBootstrapToEntitlement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "EntitlementId",
                table: "DistributionLicenseBootstrapAuthorizations",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_EntitlementId",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "EntitlementId");

            migrationBuilder.AddForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_DistributionEnti~",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "EntitlementId",
                principalTable: "DistributionEntitlements",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_DistributionLicenseBootstrapAuthorizations_DistributionEnti~",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_EntitlementId",
                table: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropColumn(
                name: "EntitlementId",
                table: "DistributionLicenseBootstrapAuthorizations");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt000780CommercialSubjectProvisioning : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AuthorityProvenance",
                table: "LicenseProvisioningRequests",
                type: "varchar(32)",
                maxLength: 32,
                nullable: true,
                collation: "C");

            migrationBuilder.AddColumn<Guid>(
                name: "CommercialSubjectId",
                table: "LicenseProvisioningRequests",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_LicenseProvisioningRequests_ProductId_CommercialSubjectId",
                table: "LicenseProvisioningRequests",
                columns: new[] { "ProductId", "CommercialSubjectId" });

            migrationBuilder.CreateIndex(
                name: "UX_LicenseProvisioningRequests_ProviderReference",
                table: "LicenseProvisioningRequests",
                column: "Reference",
                unique: true,
                filter: "\"AuthorityProvenance\" = 'PROVIDER_ADMIN_API_V1'");

            migrationBuilder.AddCheckConstraint(
                name: "CK_LicenseProvisioningRequests_CommercialAuthority",
                table: "LicenseProvisioningRequests",
                sql: "(\"CommercialSubjectId\" IS NULL AND \"AuthorityProvenance\" IS NULL) OR (\"CommercialSubjectId\" IS NOT NULL AND \"AuthorityProvenance\" = 'PROVIDER_ADMIN_API_V1')");

            migrationBuilder.AddForeignKey(
                name: "FK_LicenseProvisioningRequests_CommercialSubjects_ProductId_SubjectId",
                table: "LicenseProvisioningRequests",
                columns: new[] { "ProductId", "CommercialSubjectId" },
                principalTable: "RuntimeRecoveryCommercialSubjects",
                principalColumns: new[] { "ProductId", "Id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LicenseProvisioningRequests_CommercialSubjects_ProductId_SubjectId",
                table: "LicenseProvisioningRequests");

            migrationBuilder.DropIndex(
                name: "IX_LicenseProvisioningRequests_ProductId_CommercialSubjectId",
                table: "LicenseProvisioningRequests");

            migrationBuilder.DropIndex(
                name: "UX_LicenseProvisioningRequests_ProviderReference",
                table: "LicenseProvisioningRequests");

            migrationBuilder.DropCheckConstraint(
                name: "CK_LicenseProvisioningRequests_CommercialAuthority",
                table: "LicenseProvisioningRequests");

            migrationBuilder.DropColumn(
                name: "AuthorityProvenance",
                table: "LicenseProvisioningRequests");

            migrationBuilder.DropColumn(
                name: "CommercialSubjectId",
                table: "LicenseProvisioningRequests");
        }
    }
}

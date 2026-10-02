using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds an optional exact commercial-ownership-version binding to recovery grants. Existing rows remain
    /// null without inference or backfill and are rejected by the authorization service after deployment.
    /// </summary>
    public partial class BindTkt000784RecoveryGrantOwnershipVersion : Migration
    {
        /// <summary>
        /// Adds the nullable compatibility column, its lookup index, and the product/license/version-scoped
        /// NO ACTION foreign key without updating any existing recovery grant.
        /// </summary>
        /// <param name="migrationBuilder">The provider migration builder that owns the transactional DDL.</param>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "CommercialOwnershipId",
                table: "RuntimeRecoveryGrantOwnerships",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeRecoveryGrantOwnerships_ProductId_LicenseId_CommercialOwnershipId",
                table: "RuntimeRecoveryGrantOwnerships",
                columns: new[] { "ProductId", "LicenseId", "CommercialOwnershipId" });

            migrationBuilder.AddForeignKey(
                name: "FK_RRGO_CommercialOwnership_ProductId_LicenseId_OwnershipId",
                table: "RuntimeRecoveryGrantOwnerships",
                columns: new[] { "ProductId", "LicenseId", "CommercialOwnershipId" },
                principalTable: "RuntimeRecoveryCommercialOwnerships",
                principalColumns: new[] { "ProductId", "LicenseId", "Id" },
                onDelete: ReferentialAction.NoAction);
        }

        /// <summary>
        /// Removes only the version-binding foreign key, index, and nullable column introduced by this migration.
        /// No historical data repair or ownership-state mutation is performed in either direction.
        /// </summary>
        /// <param name="migrationBuilder">The provider migration builder that owns the transactional DDL.</param>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_RRGO_CommercialOwnership_ProductId_LicenseId_OwnershipId",
                table: "RuntimeRecoveryGrantOwnerships");

            migrationBuilder.DropIndex(
                name: "IX_RuntimeRecoveryGrantOwnerships_ProductId_LicenseId_CommercialOwnershipId",
                table: "RuntimeRecoveryGrantOwnerships");

            migrationBuilder.DropColumn(
                name: "CommercialOwnershipId",
                table: "RuntimeRecoveryGrantOwnerships");
        }
    }
}

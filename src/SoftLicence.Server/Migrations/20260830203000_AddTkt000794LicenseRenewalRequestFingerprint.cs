using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds the nullable versioned request fingerprint used to verify renewal transaction replays.
    /// </summary>
    /// <remarks>
    /// Existing rows intentionally remain null because their omitted versus explicit request fields
    /// cannot be reconstructed. The additive migration takes no table rewrite or backfill dependency.
    /// </remarks>
    public partial class AddTkt000794LicenseRenewalRequestFingerprint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RequestFingerprint",
                table: "LicenseRenewals",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RequestFingerprintVersion",
                table: "LicenseRenewals",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RequestFingerprint",
                table: "LicenseRenewals");

            migrationBuilder.DropColumn(
                name: "RequestFingerprintVersion",
                table: "LicenseRenewals");
        }
    }
}

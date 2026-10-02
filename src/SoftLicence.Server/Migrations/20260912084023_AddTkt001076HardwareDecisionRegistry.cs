using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds the privacy-bounded pre-download decision registry, its product relationship, exact replay
    /// uniqueness, investigation indexes, and PostgreSQL constraints. Down removes only this new table.
    /// </summary>
    public partial class AddTkt001076HardwareDecisionRegistry : Migration
    {
        /// <summary>Creates the empty registry without rewriting existing licensing or security rows.</summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RuntimeDistributionHardwareDecisions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    PayloadDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    GrantRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    HardwareIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    InstallationIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    KeyThumbprint = table.Column<string>(type: "character varying(43)", maxLength: 43, nullable: true),
                    AuthorityMode = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Outcome = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    ReasonCode = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    BanCategoriesJson = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    LicenseActive = table.Column<bool>(type: "boolean", nullable: false),
                    LicenseRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    LicenseExpired = table.Column<bool>(type: "boolean", nullable: false),
                    PaidAutoUnbanEligible = table.Column<bool>(type: "boolean", nullable: false),
                    AutoUnbannedCount = table.Column<int>(type: "integer", nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeDistributionHardwareDecisions", x => x.Id);
                    table.CheckConstraint("CK_RuntimeDistributionHardwareDecisions_AttemptCount", "\"AttemptCount\" >= 1");
                    table.CheckConstraint("CK_RuntimeDistributionHardwareDecisions_AutoUnbanCount", "\"AutoUnbannedCount\" >= 0");
                    table.CheckConstraint("CK_RuntimeDistributionHardwareDecisions_AuthorityMode", "\"AuthorityMode\" IN ('server-derived', 'known-enrollment', 'digest-revalidation')");
                    table.CheckConstraint("CK_RuntimeDistributionHardwareDecisions_Digests", "\"PayloadDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"GrantRefDigestSha256\" ~ '^[0-9a-f]{64}$' AND (\"HardwareIdHash\" IS NULL OR \"HardwareIdHash\" ~ '^[0-9a-f]{64}$') AND (\"InstallationIdHash\" IS NULL OR \"InstallationIdHash\" ~ '^[0-9a-f]{64}$')");
                    table.CheckConstraint("CK_RuntimeDistributionHardwareDecisions_Outcome", "\"Outcome\" IN ('accepted', 'auto-unbanned', 'refused')");
                    table.ForeignKey(
                        name: "FK_RuntimeDistributionHardwareDecisions_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeDistributionHardwareDecisions_ClientId_RequestId",
                table: "RuntimeDistributionHardwareDecisions",
                columns: new[] { "ClientId", "RequestId" },
                unique: true);
            migrationBuilder.CreateIndex(
                name: "IX_RuntimeDistributionHardwareDecisions_ProductId_CreatedAtUtc",
                table: "RuntimeDistributionHardwareDecisions",
                columns: new[] { "ProductId", "CreatedAtUtc" });
            migrationBuilder.CreateIndex(
                name: "IX_RuntimeDistributionHardwareDecisions_ProductId_HardwareIdHash_CreatedAtUtc",
                table: "RuntimeDistributionHardwareDecisions",
                columns: new[] { "ProductId", "HardwareIdHash", "CreatedAtUtc" });
            migrationBuilder.CreateIndex(
                name: "IX_RuntimeDistributionHardwareDecisions_ProductId_LicenseId_CreatedAtUtc",
                table: "RuntimeDistributionHardwareDecisions",
                columns: new[] { "ProductId", "LicenseId", "CreatedAtUtc" });
        }

        /// <summary>Drops the registry and its contained audit history during an explicit rollback.</summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "RuntimeDistributionHardwareDecisions");
        }
    }
}

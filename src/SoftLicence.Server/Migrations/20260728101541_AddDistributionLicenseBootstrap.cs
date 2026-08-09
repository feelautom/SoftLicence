using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddDistributionLicenseBootstrap : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships");

            migrationBuilder.AddColumn<string>(
                name: "SubjectRefDigestSha256",
                table: "RuntimeEnrollments",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "DownloadCompletedAtUtc",
                table: "DistributionInstallationBindings",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "HandoffExpiresAtUtc",
                table: "DistributionInstallationBindings",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "HandoffIssuedAtUtc",
                table: "DistributionInstallationBindings",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SubjectRefDigestSha256",
                table: "DistributionInstallationBindings",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "DistributionEntitlements",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    GrantRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SubjectRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    ContractVersion = table.Column<int>(type: "integer", nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    IssuedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FinalizedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionEntitlements", x => x.Id);
                    table.CheckConstraint("CK_DistributionEntitlements_ContractVersion", "\"ContractVersion\" = 3");
                    table.CheckConstraint("CK_DistributionEntitlements_State", "\"State\" IN ('issued', 'finalized', 'expired', 'revoked')");
                    table.CheckConstraint("CK_DistributionEntitlements_Times", "\"IssuedAtUtc\" < \"ExpiresAtUtc\"");
                    table.ForeignKey(
                        name: "FK_DistributionEntitlements_Licenses_LicenseId",
                        column: x => x.LicenseId,
                        principalTable: "Licenses",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DistributionEntitlements_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "DistributionLicenseBootstrapAuthorizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    RuntimeEnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    GrantRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SubjectRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    HandoffDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    HardwareIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ReleaseVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ApprovedBinariesDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RuntimePublicKeySpkiSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RuntimeKeyThumbprint = table.Column<string>(type: "character varying(43)", maxLength: 43, nullable: false),
                    RuntimeEpoch = table.Column<int>(type: "integer", nullable: false),
                    SecurityEpoch = table.Column<int>(type: "integer", nullable: false),
                    AuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    Audience = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Use = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    IssuedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ConsumedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ConsumedRequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: true),
                    ConsumedJti = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: true),
                    ConsumedBodyDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    ConsumedProofDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    ResponseCiphertext = table.Column<byte[]>(type: "bytea", nullable: true),
                    ResponseKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    ResponsePlaintextLength = table.Column<int>(type: "integer", nullable: true),
                    ResponseCiphertextLength = table.Column<int>(type: "integer", nullable: true),
                    ReplayExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionLicenseBootstrapAuthorizations", x => x.Id);
                    table.CheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_ResponseLengths", "\"ResponsePlaintextLength\" IS NULL OR (\"ResponsePlaintextLength\" >= 1 AND \"ResponsePlaintextLength\" <= 65536)");
                    table.CheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_State", "\"State\" IN ('ISSUED', 'CONSUMED', 'REVOKED', 'EXPIRED')");
                    table.CheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_Times", "\"IssuedAtUtc\" < \"ExpiresAtUtc\"");
                });

            migrationBuilder.CreateTable(
                name: "DistributionLicenseBootstrapCapabilities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorizationId = table.Column<Guid>(type: "uuid", nullable: false),
                    CapabilityDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    MintedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ConsumedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionLicenseBootstrapCapabilities", x => x.Id);
                    table.CheckConstraint("CK_DistributionLicenseBootstrapCapabilities_State", "\"State\" IN ('ISSUED', 'CONSUMED', 'REVOKED', 'EXPIRED')");
                    table.ForeignKey(
                        name: "FK_DistributionLicenseBootstrapCapabilities_DistributionLicens~",
                        column: x => x.AuthorizationId,
                        principalTable: "DistributionLicenseBootstrapAuthorizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DistributionLicenseBootstrapRequests",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Operation = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    PayloadDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    AuthorizationId = table.Column<Guid>(type: "uuid", nullable: false),
                    CapabilityId = table.Column<Guid>(type: "uuid", nullable: false),
                    ExactResponseCiphertext = table.Column<byte[]>(type: "bytea", nullable: false),
                    ResponseKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionLicenseBootstrapRequests", x => new { x.ClientId, x.Operation, x.RequestId });
                    table.ForeignKey(
                        name: "FK_DistributionLicenseBootstrapRequests_DistributionLicenseBoo~",
                        column: x => x.AuthorizationId,
                        principalTable: "DistributionLicenseBootstrapAuthorizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_DistributionLicenseBootstrapRequests_DistributionLicenseBo~1",
                        column: x => x.CapabilityId,
                        principalTable: "DistributionLicenseBootstrapCapabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships",
                sql: "\"Source\" IN ('issue_v2', 'issue_v3', 'finalize_v1')");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionEntitlements_LicenseId",
                table: "DistributionEntitlements",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionEntitlements_ProductId_GrantRefDigestSha256",
                table: "DistributionEntitlements",
                columns: new[] { "ProductId", "GrantRefDigestSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_BindingId_Runtim~",
                table: "DistributionLicenseBootstrapAuthorizations",
                columns: new[] { "BindingId", "RuntimeEnrollmentId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapAuthorizations_ExpiresAtUtc",
                table: "DistributionLicenseBootstrapAuthorizations",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapCapabilities_AuthorizationId",
                table: "DistributionLicenseBootstrapCapabilities",
                column: "AuthorizationId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapCapabilities_CapabilityDigestSh~",
                table: "DistributionLicenseBootstrapCapabilities",
                column: "CapabilityDigestSha256",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapRequests_AuthorizationId",
                table: "DistributionLicenseBootstrapRequests",
                column: "AuthorizationId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionLicenseBootstrapRequests_CapabilityId",
                table: "DistributionLicenseBootstrapRequests",
                column: "CapabilityId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DistributionEntitlements");

            migrationBuilder.DropTable(
                name: "DistributionLicenseBootstrapRequests");

            migrationBuilder.DropTable(
                name: "DistributionLicenseBootstrapCapabilities");

            migrationBuilder.DropTable(
                name: "DistributionLicenseBootstrapAuthorizations");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships");

            migrationBuilder.DropColumn(
                name: "SubjectRefDigestSha256",
                table: "RuntimeEnrollments");

            migrationBuilder.DropColumn(
                name: "DownloadCompletedAtUtc",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropColumn(
                name: "HandoffExpiresAtUtc",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropColumn(
                name: "HandoffIssuedAtUtc",
                table: "DistributionInstallationBindings");

            migrationBuilder.DropColumn(
                name: "SubjectRefDigestSha256",
                table: "DistributionInstallationBindings");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships",
                sql: "\"Source\" IN ('issue_v2', 'finalize_v1')");
        }
    }
}

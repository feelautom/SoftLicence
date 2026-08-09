using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddDistributionInstallationBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DistributionInstallationBindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                    EntitlementId = table.Column<Guid>(type: "uuid", nullable: false),
                    GrantRef = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    HandoffDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    HardwareIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    InstallerFilename = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    InstallerSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ExecutableSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    NativeDllSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CoreSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ApprovedBinariesSource = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    BoundAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    InvalidatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    InvalidationReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionInstallationBindings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DistributionInstallationBindings_LicenseSeats_LicenseSeatId",
                        column: x => x.LicenseSeatId,
                        principalTable: "LicenseSeats",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DistributionInstallationBindings_Licenses_LicenseId",
                        column: x => x.LicenseId,
                        principalTable: "Licenses",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DistributionInstallationBindings_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "DistributionS2SNonces",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Nonce = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    SentAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionS2SNonces", x => new { x.ClientId, x.Nonce });
                });

            migrationBuilder.CreateTable(
                name: "DistributionBindingRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Operation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    PayloadDigest = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: true),
                    ResponseJson = table.Column<string>(type: "character varying(8192)", maxLength: 8192, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DistributionBindingRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DistributionBindingRequests_DistributionInstallationBinding~",
                        column: x => x.BindingId,
                        principalTable: "DistributionInstallationBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DistributionBindingRequests_BindingId",
                table: "DistributionBindingRequests",
                column: "BindingId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionBindingRequests_ClientId_RequestId",
                table: "DistributionBindingRequests",
                columns: new[] { "ClientId", "RequestId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionInstallationBindings_HandoffDigestSha256",
                table: "DistributionInstallationBindings",
                column: "HandoffDigestSha256",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionInstallationBindings_LicenseId",
                table: "DistributionInstallationBindings",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionInstallationBindings_LicenseSeatId",
                table: "DistributionInstallationBindings",
                column: "LicenseSeatId");

            migrationBuilder.CreateIndex(
                name: "IX_DistributionInstallationBindings_ProductId_InstallationId",
                table: "DistributionInstallationBindings",
                columns: new[] { "ProductId", "InstallationId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionS2SNonces_ExpiresAtUtc",
                table: "DistributionS2SNonces",
                column: "ExpiresAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DistributionBindingRequests");

            migrationBuilder.DropTable(
                name: "DistributionS2SNonces");

            migrationBuilder.DropTable(
                name: "DistributionInstallationBindings");
        }
    }
}

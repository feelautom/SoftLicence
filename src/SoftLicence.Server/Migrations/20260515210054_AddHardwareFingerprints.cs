using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddHardwareFingerprints : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BannedComponents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentType = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    ComponentHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    BannedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BannedComponents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_BannedComponents_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "HardwareFingerprints",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CpuHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    MotherboardHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    BiosHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    DiskHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    HostHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    FirstSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ClusterId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HardwareFingerprints", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BannedComponents_ComponentType_ComponentHash_ProductId",
                table: "BannedComponents",
                columns: new[] { "ComponentType", "ComponentHash", "ProductId" },
                unique: true,
                filter: "\"IsActive\" = true");

            migrationBuilder.CreateIndex(
                name: "IX_BannedComponents_ProductId",
                table: "BannedComponents",
                column: "ProductId");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareFingerprints_BiosHash",
                table: "HardwareFingerprints",
                column: "BiosHash");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareFingerprints_ClusterId",
                table: "HardwareFingerprints",
                column: "ClusterId");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareFingerprints_CpuHash",
                table: "HardwareFingerprints",
                column: "CpuHash");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareFingerprints_DiskHash",
                table: "HardwareFingerprints",
                column: "DiskHash");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareFingerprints_HardwareId",
                table: "HardwareFingerprints",
                column: "HardwareId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HardwareFingerprints_HostHash",
                table: "HardwareFingerprints",
                column: "HostHash");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareFingerprints_MotherboardHash",
                table: "HardwareFingerprints",
                column: "MotherboardHash");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BannedComponents");

            migrationBuilder.DropTable(
                name: "HardwareFingerprints");
        }
    }
}

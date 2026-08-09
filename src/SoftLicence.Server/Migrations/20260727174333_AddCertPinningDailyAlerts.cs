using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCertPinningDailyAlerts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TelemetryCertPinningDailyAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    AlertType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ParisDate = table.Column<DateOnly>(type: "date", nullable: false),
                    OccurrenceCount = table.Column<long>(type: "bigint", nullable: false),
                    ClientSuppressedCount = table.Column<long>(type: "bigint", nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FirstHost = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: true),
                    LastHost = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: true),
                    LastVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    NotificationClaimId = table.Column<Guid>(type: "uuid", nullable: true),
                    NotificationClaimedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NotificationSentAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TelemetryCertPinningDailyAlerts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TelemetryCertPinningDailyAlerts_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryCertPinningDailyAlerts_ProductId_HardwareId_AlertT~",
                table: "TelemetryCertPinningDailyAlerts",
                columns: new[] { "ProductId", "HardwareId", "AlertType", "ParisDate" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryCertPinningDailyAlerts_ProductId_LastSeenUtc",
                table: "TelemetryCertPinningDailyAlerts",
                columns: new[] { "ProductId", "LastSeenUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TelemetryCertPinningDailyAlerts");
        }
    }
}

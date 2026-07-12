using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTelemetryFloodSuppressionCounters : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TelemetryFloodSuppressionCounters",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: true),
                    HardwareId = table.Column<string>(type: "text", nullable: false),
                    AppName = table.Column<string>(type: "text", nullable: true),
                    Version = table.Column<string>(type: "text", nullable: true),
                    EventName = table.Column<string>(type: "text", nullable: false),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    WindowStartUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    WindowEndUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    WindowMinutes = table.Column<int>(type: "integer", nullable: false),
                    Threshold = table.Column<int>(type: "integer", nullable: false),
                    RawStoredCount = table.Column<int>(type: "integer", nullable: false),
                    SuppressedCount = table.Column<int>(type: "integer", nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastClientIp = table.Column<string>(type: "text", nullable: true),
                    LastIsp = table.Column<string>(type: "text", nullable: true),
                    LastPayloadHash = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TelemetryFloodSuppressionCounters", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TelemetryFloodSuppressionCounters_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryFloodSuppressionCounters_ProductId_HardwareId_Even~",
                table: "TelemetryFloodSuppressionCounters",
                columns: new[] { "ProductId", "HardwareId", "EventName", "Type", "WindowStartUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryFloodSuppressionCounters_ProductId_LastSeenUtc",
                table: "TelemetryFloodSuppressionCounters",
                columns: new[] { "ProductId", "LastSeenUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TelemetryFloodSuppressionCounters");
        }
    }
}

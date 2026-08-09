using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTelemetryOperations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ActivationIncidents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: true),
                    HardwareIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    HardwareIdMasked = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Category = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    Severity = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RepeatCount = table.Column<int>(type: "integer", nullable: false),
                    Version = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    CountryCode = table.Column<string>(type: "character varying(8)", maxLength: 8, nullable: true),
                    Isp = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: true),
                    ClientIpMasked = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    LastNotifiedSeverity = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: true),
                    RecoveredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ActivationIncidents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ActivationIncidents_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TelemetryIngestionRejections",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TimestampUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Route = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                    ValidationCode = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    InvalidFields = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    AppName = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    Version = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    EventName = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: true),
                    HardwareIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    HardwareIdMasked = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    ClientIpMasked = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    ClientName = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    Alerted = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TelemetryIngestionRejections", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ActivationIncidents_ProductId_HardwareIdHash_Status_LastSee~",
                table: "ActivationIncidents",
                columns: new[] { "ProductId", "HardwareIdHash", "Status", "LastSeenUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryIngestionRejections_TimestampUtc_ValidationCode",
                table: "TelemetryIngestionRejections",
                columns: new[] { "TimestampUtc", "ValidationCode" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ActivationIncidents");

            migrationBuilder.DropTable(
                name: "TelemetryIngestionRejections");
        }
    }
}

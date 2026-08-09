using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddSecurityIncidents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SecurityIncidents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Family = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Severity = table.Column<int>(type: "integer", nullable: false),
                    WindowStartUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    WindowEndUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    OccurrenceCount = table.Column<int>(type: "integer", nullable: false),
                    Version = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    ClientIp = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    IsHardwareBanned = table.Column<bool>(type: "boolean", nullable: false),
                    InitialNotificationSentAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityIncidents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecurityIncidents_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SecurityIncidentEvidence",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SecurityIncidentId = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentType = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    ComponentHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    OccurrenceCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityIncidentEvidence", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecurityIncidentEvidence_SecurityIncidents_SecurityIncident~",
                        column: x => x.SecurityIncidentId,
                        principalTable: "SecurityIncidents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidentEvidence_SecurityIncidentId_ComponentType_C~",
                table: "SecurityIncidentEvidence",
                columns: new[] { "SecurityIncidentId", "ComponentType", "ComponentHash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidents_ProductId_HardwareId_Family_WindowStartUtc",
                table: "SecurityIncidents",
                columns: new[] { "ProductId", "HardwareId", "Family", "WindowStartUtc" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidents_ProductId_LastSeenUtc",
                table: "SecurityIncidents",
                columns: new[] { "ProductId", "LastSeenUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecurityIncidentEvidence");

            migrationBuilder.DropTable(
                name: "SecurityIncidents");
        }
    }
}

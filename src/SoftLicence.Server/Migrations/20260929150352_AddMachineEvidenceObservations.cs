using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddMachineEvidenceObservations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "MachineEvidenceObservations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    SystemUuidRaw = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    SystemUuidCanonical = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: true),
                    DerivedHardwareId = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    RefusalCode = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    EvidenceJson = table.Column<string>(type: "text", nullable: true),
                    EvidenceSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    LastEndpoint = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    LastAppVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ObservationCount = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MachineEvidenceObservations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MachineEvidenceObservations_ProductId_HardwareId_EvidenceSh~",
                table: "MachineEvidenceObservations",
                columns: new[] { "ProductId", "HardwareId", "EvidenceSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MachineEvidenceObservations_SystemUuidCanonical",
                table: "MachineEvidenceObservations",
                column: "SystemUuidCanonical");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MachineEvidenceObservations");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt001202SecurityLockAlertOutbox : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SecurityLockAlertDeliveries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SecurityLockReportId = table.Column<Guid>(type: "uuid", nullable: false),
                    Channel = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Target = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    TargetDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Trigger = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    NewBan = table.Column<bool>(type: "boolean", nullable: false),
                    ClientIp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Title = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    Message = table.Column<string>(type: "text", nullable: true),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    NextAttemptUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LeaseToken = table.Column<Guid>(type: "uuid", nullable: true),
                    LeaseExpiresUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastError = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SentAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityLockAlertDeliveries", x => x.Id);
                    table.CheckConstraint("CK_SecurityLockAlertDeliveries_Attempts", "\"AttemptCount\" >= 0");
                    table.CheckConstraint("CK_SecurityLockAlertDeliveries_Channel", "\"Channel\" IN ('EMAIL', 'WEBHOOK')");
                    table.CheckConstraint("CK_SecurityLockAlertDeliveries_State", "\"State\" IN ('PENDING', 'PROCESSING', 'SENT', 'SKIPPED', 'FAILED', 'UNKNOWN')");
                    table.CheckConstraint("CK_SecurityLockAlertDeliveries_TargetDigest", "\"TargetDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.ForeignKey(
                        name: "FK_SecurityLockAlertDeliveries_SecurityLockReports_SecurityLoc~",
                        column: x => x.SecurityLockReportId,
                        principalTable: "SecurityLockReports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockAlertDeliveries_SecurityLockReportId_Trigger_Ch~",
                table: "SecurityLockAlertDeliveries",
                columns: new[] { "SecurityLockReportId", "Trigger", "Channel", "TargetDigestSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockAlertDeliveries_State_NextAttemptUtc",
                table: "SecurityLockAlertDeliveries",
                columns: new[] { "State", "NextAttemptUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecurityLockAlertDeliveries");
        }
    }
}

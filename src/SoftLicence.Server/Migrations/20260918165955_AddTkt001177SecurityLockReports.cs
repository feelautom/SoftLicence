using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt001177SecurityLockReports : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SecurityLockEnforcementPolicies",
                columns: table => new
                {
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    Cause = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Mode = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityLockEnforcementPolicies", x => new { x.ProductId, x.Cause });
                    table.CheckConstraint("CK_SecurityLockEnforcementPolicies_Mode", "\"Mode\" IN ('SHADOW', 'REVIEW', 'ENFORCE')");
                });

            migrationBuilder.CreateTable(
                name: "SecurityLockReportNonces",
                columns: table => new
                {
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Jti = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    ReportId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    BodyDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ResponseJson = table.Column<string>(type: "text", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityLockReportNonces", x => new { x.EnrollmentId, x.Jti });
                    table.ForeignKey(
                        name: "FK_SecurityLockReportNonces_RuntimeEnrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SecurityLockReports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    AppVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    LockId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Cause = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Level = table.Column<int>(type: "integer", nullable: false),
                    ClientMode = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    EffectiveMode = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    EvidenceDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FirstReportedUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastReportedUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReportCount = table.Column<int>(type: "integer", nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    LastVerdict = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    AdminDecision = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    AdminDecisionAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AdminDecisionBy = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    AdminDecisionReason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityLockReports", x => x.Id);
                    table.CheckConstraint("CK_SecurityLockReports_AdminDecision", "\"AdminDecision\" IS NULL OR \"AdminDecision\" IN ('RELEASE', 'BAN')");
                    table.CheckConstraint("CK_SecurityLockReports_CanonicalIds", "\"LockId\" ~ '^[0-9a-f]{32}$' AND \"EvidenceDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"Cause\" ~ '^[A-Z][A-Z0-9_]*$' AND \"HardwareId\" ~ '^[A-Z0-9_.-]+$'");
                    table.CheckConstraint("CK_SecurityLockReports_LastVerdict", "\"LastVerdict\" IN ('MAINTAIN', 'RELEASE', 'BAN')");
                    table.CheckConstraint("CK_SecurityLockReports_Level", "\"Level\" BETWEEN 0 AND 5");
                    table.CheckConstraint("CK_SecurityLockReports_Modes", "\"ClientMode\" IN ('NOT_APPLICABLE', 'SHADOW', 'REVIEW', 'ENFORCE') AND \"EffectiveMode\" IN ('NOT_APPLICABLE', 'SHADOW', 'REVIEW', 'ENFORCE')");
                    table.CheckConstraint("CK_SecurityLockReports_State", "\"State\" IN ('OPEN', 'RELEASED', 'BANNED')");
                    table.ForeignKey(
                        name: "FK_SecurityLockReports_RuntimeEnrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockReportNonces_ExpiresAtUtc",
                table: "SecurityLockReportNonces",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockReports_EnrollmentId_LockId",
                table: "SecurityLockReports",
                columns: new[] { "EnrollmentId", "LockId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockReports_HardwareId",
                table: "SecurityLockReports",
                column: "HardwareId");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockReports_State_LastReportedUtc",
                table: "SecurityLockReports",
                columns: new[] { "State", "LastReportedUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecurityLockEnforcementPolicies");

            migrationBuilder.DropTable(
                name: "SecurityLockReportNonces");

            migrationBuilder.DropTable(
                name: "SecurityLockReports");
        }
    }
}

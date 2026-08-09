using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeMilestones : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.CreateTable(
                name: "RuntimeMilestoneSessions",
                columns: table => new
                {
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    SessionId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    SecurityEpoch = table.Column<int>(type: "integer", nullable: false),
                    LastSequence = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastAcceptedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeMilestoneSessions", x => new { x.EnrollmentId, x.SessionId });
                    table.CheckConstraint("CK_RuntimeMilestoneSessions_LastSequence", "\"LastSequence\" >= 1");
                    table.CheckConstraint("CK_RuntimeMilestoneSessions_SecurityEpoch", "\"SecurityEpoch\" >= 1");
                    table.CheckConstraint("CK_RuntimeMilestoneSessions_Times", "\"CreatedAtUtc\" <= \"LastAcceptedAtUtc\" AND \"LastAcceptedAtUtc\" < \"ExpiresAtUtc\"");
                    table.ForeignKey(
                        name: "FK_RuntimeMilestoneSessions_RuntimeEnrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeMilestones",
                columns: table => new
                {
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    SessionId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Sequence = table.Column<long>(type: "bigint", nullable: false),
                    EventId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Jti = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    EvidenceClass = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    BodyDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProofDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    AuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AcceptedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeMilestones", x => new { x.EnrollmentId, x.SessionId, x.Sequence });
                    table.CheckConstraint("CK_RuntimeMilestones_Code", "\"Code\" IN ('api_opened', 'bootstrap_entered', 'capability_issued', 'integrity_allowed', 'integrity_denied', 'license_allowed', 'license_denied', 'mcp_invocation_allowed', 'mcp_invocation_denied', 'mcp_invocation_requested', 'mcp_opened', 'rest_invocation_allowed', 'rest_invocation_denied', 'rest_invocation_requested', 'tia_connected', 'tia_detection_allowed', 'tia_detection_denied', 'tia_operation_completed', 'tia_operation_failed', 'tia_operation_started')");
                    table.CheckConstraint("CK_RuntimeMilestones_EvidenceClass", "\"EvidenceClass\" = 'client_declared'");
                    table.CheckConstraint("CK_RuntimeMilestones_Sequence", "\"Sequence\" >= 1");
                    table.CheckConstraint("CK_RuntimeMilestones_Times", "\"AcceptedAtUtc\" < \"ExpiresAtUtc\"");
                    table.ForeignKey(
                        name: "FK_RuntimeMilestones_RuntimeMilestoneSessions_EnrollmentId_Ses~",
                        columns: x => new { x.EnrollmentId, x.SessionId },
                        principalTable: "RuntimeMilestoneSessions",
                        principalColumns: new[] { "EnrollmentId", "SessionId" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone')");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeMilestones_EnrollmentId_Jti",
                table: "RuntimeMilestones",
                columns: new[] { "EnrollmentId", "Jti" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeMilestones_EnrollmentId_SessionId_Code",
                table: "RuntimeMilestones",
                columns: new[] { "EnrollmentId", "SessionId", "Code" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeMilestones_EventId",
                table: "RuntimeMilestones",
                column: "EventId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeMilestones_ExpiresAtUtc",
                table: "RuntimeMilestones",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeMilestoneSessions_ExpiresAtUtc",
                table: "RuntimeMilestoneSessions",
                column: "ExpiresAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RuntimeMilestones");

            migrationBuilder.DropTable(
                name: "RuntimeMilestoneSessions");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch')");
        }
    }
}

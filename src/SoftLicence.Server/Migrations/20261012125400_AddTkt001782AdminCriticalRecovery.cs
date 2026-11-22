using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt001782AdminCriticalRecovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Populated recovery tables require strong metadata locks; fail promptly instead of waiting indefinitely.
            migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");

            migrationBuilder.AddColumn<string>(
                name: "RecoveredByAdmin",
                table: "RuntimeCriticalRecoveries",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SecurityLockReportId",
                table: "RuntimeCriticalRecoveries",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "RuntimeCriticalRecoveries",
                type: "character varying(24)",
                maxLength: 24,
                nullable: false,
                defaultValue: "S2S");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalRecoveries_SecurityLockReportId",
                table: "RuntimeCriticalRecoveries",
                column: "SecurityLockReportId");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeCriticalRecoveries_Source",
                table: "RuntimeCriticalRecoveries",
                sql: "(\"Source\" = 'S2S' AND \"SecurityLockReportId\" IS NULL AND \"RecoveredByAdmin\" IS NULL) OR (\"Source\" = 'ADMIN_RELEASE' AND \"SecurityLockReportId\" IS NOT NULL AND \"RecoveredByAdmin\" IS NOT NULL)");

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeCriticalRecoveries_SecurityLockReports_SecurityLockR~",
                table: "RuntimeCriticalRecoveries",
                column: "SecurityLockReportId",
                principalTable: "SecurityLockReports",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.Sql("""
                DO $grants$
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                        REVOKE ALL ON public."RuntimeCriticalRecoveries" FROM softlicence_app;
                        GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalRecoveries" TO softlicence_app;
                    END IF;
                END;
                $grants$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");

            migrationBuilder.DropForeignKey(
                name: "FK_RuntimeCriticalRecoveries_SecurityLockReports_SecurityLockR~",
                table: "RuntimeCriticalRecoveries");

            migrationBuilder.DropIndex(
                name: "IX_RuntimeCriticalRecoveries_SecurityLockReportId",
                table: "RuntimeCriticalRecoveries");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeCriticalRecoveries_Source",
                table: "RuntimeCriticalRecoveries");

            migrationBuilder.DropColumn(
                name: "RecoveredByAdmin",
                table: "RuntimeCriticalRecoveries");

            migrationBuilder.DropColumn(
                name: "SecurityLockReportId",
                table: "RuntimeCriticalRecoveries");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "RuntimeCriticalRecoveries");
        }
    }
}

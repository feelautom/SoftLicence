using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt001783RememberedSecurityLockRelease : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Constraint replacement on populated evidence tables must never wait without a deployment bound.
            migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_Resolution",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_State",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.AddColumn<Guid>(
                name: "RememberedReleaseDecisionId",
                table: "SecurityLockReports",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NonBlockingReason",
                table: "RuntimeCriticalIncidents",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "RememberedReleaseDecisionId",
                table: "RuntimeCriticalIncidents",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "SecurityLockReleaseDecisions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Cause = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    SourceSecurityLockReportId = table.Column<Guid>(type: "uuid", nullable: false),
                    ActivatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ActivatedBy = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ActivationCount = table.Column<int>(type: "integer", nullable: false),
                    RevokedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedBy = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    CoveredDetectionCount = table.Column<int>(type: "integer", nullable: false),
                    LastCoveredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityLockReleaseDecisions", x => x.Id);
                    table.CheckConstraint("CK_SecurityLockReleaseDecisions_Counts", "\"ActivationCount\" >= 1 AND \"CoveredDetectionCount\" >= 0 AND ((\"CoveredDetectionCount\" = 0 AND \"LastCoveredAtUtc\" IS NULL) OR (\"CoveredDetectionCount\" > 0 AND \"LastCoveredAtUtc\" IS NOT NULL))");
                    table.CheckConstraint("CK_SecurityLockReleaseDecisions_Lifecycle", "(\"IsActive\" AND \"RevokedAtUtc\" IS NULL AND \"RevokedBy\" IS NULL) OR (NOT \"IsActive\" AND \"RevokedAtUtc\" IS NOT NULL AND \"RevokedBy\" IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_SLRD_Licenses_ProductId_LicenseId",
                        columns: x => new { x.ProductId, x.LicenseId },
                        principalTable: "Licenses",
                        principalColumns: new[] { "ProductId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_SecurityLockReleaseDecisions_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_SecurityLockReleaseDecisions_SecurityLockReports_SourceSecu~",
                        column: x => x.SourceSecurityLockReportId,
                        principalTable: "SecurityLockReports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockReports_RememberedReleaseDecisionId",
                table: "SecurityLockReports",
                column: "RememberedReleaseDecisionId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalIncidents_RememberedReleaseDecisionId",
                table: "RuntimeCriticalIncidents",
                column: "RememberedReleaseDecisionId");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_Resolution",
                table: "RuntimeCriticalIncidents",
                sql: "(\"State\" = 'OPEN' AND \"RecoveryId\" IS NULL AND \"RecoveredSecurityEpoch\" IS NULL AND \"RecoveredAuthorityEpoch\" IS NULL AND \"RecoveredAtUtc\" IS NULL AND \"NonBlockingReason\" IS NULL AND \"RememberedReleaseDecisionId\" IS NULL) OR (\"State\" = 'RESOLVED' AND \"RecoveryId\" IS NOT NULL AND \"RecoveredSecurityEpoch\" IS NOT NULL AND \"RecoveredAuthorityEpoch\" IS NOT NULL AND \"RecoveredAtUtc\" IS NOT NULL AND \"NonBlockingReason\" IS NULL AND \"RememberedReleaseDecisionId\" IS NULL) OR (\"State\" = 'WAIVED' AND \"RecoveryId\" IS NULL AND \"RecoveredSecurityEpoch\" IS NULL AND \"RecoveredAuthorityEpoch\" IS NULL AND \"RecoveredAtUtc\" IS NULL AND ((\"NonBlockingReason\" = 'REMEMBERED_RELEASE' AND \"RememberedReleaseDecisionId\" IS NOT NULL) OR (\"NonBlockingReason\" = 'MODE_SHADOW' AND \"RememberedReleaseDecisionId\" IS NULL)))");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_State",
                table: "RuntimeCriticalIncidents",
                sql: "\"State\" IN ('OPEN', 'RESOLVED', 'WAIVED')");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockReleaseDecisions_ProductId_LicenseId_HardwareId~",
                table: "SecurityLockReleaseDecisions",
                columns: new[] { "ProductId", "LicenseId", "HardwareId", "Cause" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityLockReleaseDecisions_SourceSecurityLockReportId",
                table: "SecurityLockReleaseDecisions",
                column: "SourceSecurityLockReportId");

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeCriticalIncidents_SecurityLockReleaseDecisions_Remem~",
                table: "RuntimeCriticalIncidents",
                column: "RememberedReleaseDecisionId",
                principalTable: "SecurityLockReleaseDecisions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_SecurityLockReports_SecurityLockReleaseDecisions_Remembered~",
                table: "SecurityLockReports",
                column: "RememberedReleaseDecisionId",
                principalTable: "SecurityLockReleaseDecisions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.Sql("""
                DO $grants$
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                        REVOKE ALL ON public."SecurityLockReports" FROM softlicence_app;
                        GRANT SELECT, INSERT ON public."SecurityLockReports" TO softlicence_app;
                        GRANT UPDATE ("ClientMode", "EffectiveMode", "LastReportedUtc", "ReportCount",
                                      "State", "LastVerdict", "AdminDecision", "AdminDecisionAtUtc",
                                      "AdminDecisionBy", "AdminDecisionReason", "RememberedReleaseDecisionId")
                            ON public."SecurityLockReports" TO softlicence_app;
                        REVOKE ALL ON public."SecurityLockReleaseDecisions" FROM softlicence_app;
                        GRANT SELECT, INSERT ON public."SecurityLockReleaseDecisions" TO softlicence_app;
                        GRANT UPDATE ("IsActive", "SourceSecurityLockReportId", "ActivatedAtUtc", "ActivatedBy",
                                      "ActivationCount", "RevokedAtUtc", "RevokedBy", "CoveredDetectionCount",
                                      "LastCoveredAtUtc")
                            ON public."SecurityLockReleaseDecisions" TO softlicence_app;
                        REVOKE ALL ON public."RuntimeCriticalIncidents" FROM softlicence_app;
                        GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalIncidents" TO softlicence_app;
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

            migrationBuilder.Sql("""
                CREATE TEMP TABLE "Tkt001783WaivedRollback" ON COMMIT DROP AS
                WITH candidates AS (
                    SELECT incident."Id" AS "IncidentId",
                           pg_catalog.gen_random_uuid() AS "RecoveryId",
                           incident."EnrollmentId",
                           incident."BindingId",
                           incident."ProductId",
                           incident."InstallationId",
                           incident."EventId",
                           incident."OpenedAuthorityEpoch",
                           incident."OpenedAtUtc",
                           GREATEST(
                               incident."OpenedSecurityEpoch",
                               enrollment."SecurityEpoch",
                               COALESCE((SELECT MAX(existing."NewSecurityEpoch")
                                         FROM public."RuntimeCriticalRecoveries" existing
                                         WHERE existing."BindingId" = incident."BindingId"
                                           AND existing."InstallationId" = incident."InstallationId"), 0))
                               AS "BaseSecurityEpoch"
                    FROM public."RuntimeCriticalIncidents" incident
                    JOIN public."RuntimeEnrollments" enrollment ON enrollment."Id" = incident."EnrollmentId"
                    WHERE incident."State" = 'WAIVED'
                ), numbered AS (
                    SELECT "IncidentId", "RecoveryId", "EnrollmentId", "BindingId", "ProductId",
                           "InstallationId", "EventId", "OpenedAuthorityEpoch", "OpenedAtUtc",
                           MAX("BaseSecurityEpoch") OVER (
                               PARTITION BY "BindingId", "InstallationId")
                             + ROW_NUMBER() OVER (
                                   PARTITION BY "BindingId", "InstallationId"
                                   ORDER BY "OpenedAtUtc", "EventId") AS "NewSecurityEpoch"
                    FROM candidates
                )
                SELECT * FROM numbered;

                INSERT INTO public."RuntimeCriticalRecoveries"
                    ("Id", "EnrollmentId", "BindingId", "ProductId", "InstallationId", "RequestedEventId",
                     "OldSecurityEpoch", "NewSecurityEpoch", "ResolvedIncidentCount", "AuthorityEpoch",
                     "RecoveredByClientId", "RecoveredByKeyId", "Source", "SecurityLockReportId",
                     "RecoveredByAdmin", "RecoveredAtUtc")
                SELECT "RecoveryId", "EnrollmentId", "BindingId", "ProductId", "InstallationId", "EventId",
                       "NewSecurityEpoch" - 1, "NewSecurityEpoch", 1, "OpenedAuthorityEpoch",
                       'migration-rollback', 'tkt-001783-waived', 'S2S', NULL, NULL,
                       GREATEST("OpenedAtUtc", pg_catalog.clock_timestamp())
                FROM "Tkt001783WaivedRollback";

                UPDATE public."RuntimeCriticalIncidents" incident
                SET "State" = 'RESOLVED',
                    "RecoveryId" = rollback."RecoveryId",
                    "RecoveredSecurityEpoch" = rollback."NewSecurityEpoch",
                    "RecoveredAuthorityEpoch" = rollback."OpenedAuthorityEpoch",
                    "RecoveredAtUtc" = GREATEST(rollback."OpenedAtUtc", pg_catalog.clock_timestamp()),
                    "NonBlockingReason" = NULL,
                    "RememberedReleaseDecisionId" = NULL
                FROM "Tkt001783WaivedRollback" rollback
                WHERE incident."Id" = rollback."IncidentId";

                UPDATE public."RuntimeEnrollments" enrollment
                SET "SecurityEpoch" = rollback."MaximumSecurityEpoch"
                FROM (
                    -- Recovery epochs are allocated per stable binding/installation pair. Advancing every
                    -- historical and active enrollment prevents the downgraded writer from reusing one.
                    SELECT "BindingId", "InstallationId", MAX("NewSecurityEpoch") AS "MaximumSecurityEpoch"
                    FROM "Tkt001783WaivedRollback"
                    GROUP BY "BindingId", "InstallationId"
                ) rollback
                WHERE enrollment."BindingId" = rollback."BindingId"
                  AND enrollment."InstallationId" = rollback."InstallationId"
                  AND enrollment."SecurityEpoch" < rollback."MaximumSecurityEpoch";
                """);

            migrationBuilder.DropForeignKey(
                name: "FK_RuntimeCriticalIncidents_SecurityLockReleaseDecisions_Remem~",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.DropForeignKey(
                name: "FK_SecurityLockReports_SecurityLockReleaseDecisions_Remembered~",
                table: "SecurityLockReports");

            migrationBuilder.DropTable(
                name: "SecurityLockReleaseDecisions");

            migrationBuilder.DropIndex(
                name: "IX_SecurityLockReports_RememberedReleaseDecisionId",
                table: "SecurityLockReports");

            migrationBuilder.DropIndex(
                name: "IX_RuntimeCriticalIncidents_RememberedReleaseDecisionId",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_Resolution",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_State",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.DropColumn(
                name: "RememberedReleaseDecisionId",
                table: "SecurityLockReports");

            migrationBuilder.DropColumn(
                name: "NonBlockingReason",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.DropColumn(
                name: "RememberedReleaseDecisionId",
                table: "RuntimeCriticalIncidents");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_Resolution",
                table: "RuntimeCriticalIncidents",
                sql: "(\"State\" = 'OPEN' AND \"RecoveryId\" IS NULL AND \"RecoveredSecurityEpoch\" IS NULL AND \"RecoveredAuthorityEpoch\" IS NULL AND \"RecoveredAtUtc\" IS NULL) OR (\"State\" = 'RESOLVED' AND \"RecoveryId\" IS NOT NULL AND \"RecoveredSecurityEpoch\" IS NOT NULL AND \"RecoveredAuthorityEpoch\" IS NOT NULL AND \"RecoveredAtUtc\" IS NOT NULL)");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeCriticalIncidents_State",
                table: "RuntimeCriticalIncidents",
                sql: "\"State\" IN ('OPEN', 'RESOLVED')");

            migrationBuilder.Sql("""
                DO $grants$
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                        REVOKE ALL ON public."SecurityLockReports" FROM softlicence_app;
                        GRANT SELECT, INSERT ON public."SecurityLockReports" TO softlicence_app;
                        GRANT UPDATE ("ClientMode", "EffectiveMode", "LastReportedUtc", "ReportCount",
                                      "State", "LastVerdict", "AdminDecision", "AdminDecisionAtUtc",
                                      "AdminDecisionBy", "AdminDecisionReason")
                            ON public."SecurityLockReports" TO softlicence_app;
                        REVOKE ALL ON public."RuntimeCriticalIncidents" FROM softlicence_app;
                        GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalIncidents" TO softlicence_app;
                    END IF;
                END;
                $grants$;
                """);
        }
    }
}

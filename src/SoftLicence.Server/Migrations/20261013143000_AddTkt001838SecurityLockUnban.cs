using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Allows the distinct audited UNBAN decision under a bounded PostgreSQL DDL lock wait. Downgrade fails closed while
/// any UNBAN audit marker exists so rollback cannot silently relabel historical decisions.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20261013143000_AddTkt001838SecurityLockUnban")]
public partial class AddTkt001838SecurityLockUnban : Migration
{
    /// <summary>Adds UNBAN constraint values after bounding PostgreSQL lock acquisition to fifteen seconds.</summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Fail quickly instead of allowing constraint replacement to wait indefinitely behind production traffic.
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.DropCheckConstraint(
            name: "CK_SecurityLockReports_AdminDecision",
            table: "SecurityLockReports");
        migrationBuilder.DropCheckConstraint(
            name: "CK_SecurityLockReports_BanDecision",
            table: "SecurityLockReports");
        migrationBuilder.DropCheckConstraint(
            name: "CK_RuntimeCriticalRecoveries_Source",
            table: "RuntimeCriticalRecoveries");
        migrationBuilder.AddCheckConstraint(
            name: "CK_SecurityLockReports_AdminDecision",
            table: "SecurityLockReports",
            sql: "\"AdminDecision\" IS NULL OR \"AdminDecision\" IN ('RELEASE', 'BAN', 'UNBAN')");
        migrationBuilder.AddCheckConstraint(
            name: "CK_SecurityLockReports_BanDecision",
            table: "SecurityLockReports",
            sql: "\"State\" <> 'BANNED' OR \"AdminDecision\" IS NULL OR \"AdminDecision\" = 'BAN'");
        migrationBuilder.AddCheckConstraint(
            name: "CK_RuntimeCriticalRecoveries_Source",
            table: "RuntimeCriticalRecoveries",
            sql: "(\"Source\" = 'S2S' AND \"SecurityLockReportId\" IS NULL AND \"RecoveredByAdmin\" IS NULL) OR (\"Source\" IN ('ADMIN_RELEASE', 'ADMIN_UNBAN') AND \"SecurityLockReportId\" IS NOT NULL AND \"RecoveredByAdmin\" IS NOT NULL)");
    }

    /// <summary>
    /// Restores the earlier constraints only when no UNBAN or ADMIN_UNBAN audit row exists; otherwise PostgreSQL
    /// aborts the transactional migration with an actionable error instead of rewriting evidence.
    /// </summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Keep the same bounded DDL wait and preserve explicit audit meaning rather than relabeling it for compatibility.
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.Sql("""
            DO $tkt001838_guard$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM public."SecurityLockReports"
                    WHERE "AdminDecision" = 'UNBAN'
                ) OR EXISTS (
                    SELECT 1 FROM public."RuntimeCriticalRecoveries"
                    WHERE "Source" = 'ADMIN_UNBAN'
                ) THEN
                    RAISE EXCEPTION 'TKT-001838 downgrade refused: explicit UNBAN or ADMIN_UNBAN audit records exist; archive or remove them explicitly before retrying.';
                END IF;
            END
            $tkt001838_guard$;
            """);
        migrationBuilder.DropCheckConstraint(
            name: "CK_SecurityLockReports_AdminDecision",
            table: "SecurityLockReports");
        migrationBuilder.DropCheckConstraint(
            name: "CK_SecurityLockReports_BanDecision",
            table: "SecurityLockReports");
        migrationBuilder.DropCheckConstraint(
            name: "CK_RuntimeCriticalRecoveries_Source",
            table: "RuntimeCriticalRecoveries");
        migrationBuilder.AddCheckConstraint(
            name: "CK_SecurityLockReports_AdminDecision",
            table: "SecurityLockReports",
            sql: "\"AdminDecision\" IS NULL OR \"AdminDecision\" IN ('RELEASE', 'BAN')");
        migrationBuilder.AddCheckConstraint(
            name: "CK_SecurityLockReports_BanDecision",
            table: "SecurityLockReports",
            sql: "\"State\" <> 'BANNED' OR \"AdminDecision\" IS DISTINCT FROM 'RELEASE'");
        migrationBuilder.AddCheckConstraint(
            name: "CK_RuntimeCriticalRecoveries_Source",
            table: "RuntimeCriticalRecoveries",
            sql: "(\"Source\" = 'S2S' AND \"SecurityLockReportId\" IS NULL AND \"RecoveredByAdmin\" IS NULL) OR (\"Source\" = 'ADMIN_RELEASE' AND \"SecurityLockReportId\" IS NOT NULL AND \"RecoveredByAdmin\" IS NOT NULL)");
    }
}

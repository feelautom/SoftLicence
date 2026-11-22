using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Lets the application role take the row locks that seat release needs on enrollment assignments
/// without restoring any write access to that table.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20261010130000_GrantSeatReleaseAssignmentRowLock")]
public sealed class GrantSeatReleaseAssignmentRowLock : Migration
{
    /// <summary>
    /// Grants UPDATE on the <c>"Id"</c> column only. PostgreSQL refuses <c>SELECT ... FOR UPDATE</c>
    /// with 42501 unless the role holds UPDATE on at least one column, and the dual-write migration
    /// left the application role with SELECT alone, which broke seat release in production
    /// (TKT-001717). Assignment state stays writable only through the SECURITY DEFINER writers.
    /// The grant is idempotent: production already received it as an emergency fix.
    /// </summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DO $grants$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = 'softlicence_app'
                ) THEN
                    GRANT UPDATE ("Id") ON public."EnrollmentLicenseAssignments" TO softlicence_app;
                END IF;
            END;
            $grants$;
            """);
    }

    /// <summary>
    /// Removes the column-level lock right, returning the application role to SELECT only.
    /// Seat release fails again with 42501 after this downgrade.
    /// </summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DO $grants$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = 'softlicence_app'
                ) THEN
                    REVOKE UPDATE ("Id") ON public."EnrollmentLicenseAssignments" FROM softlicence_app;
                END IF;
            END;
            $grants$;
            """);
    }
}

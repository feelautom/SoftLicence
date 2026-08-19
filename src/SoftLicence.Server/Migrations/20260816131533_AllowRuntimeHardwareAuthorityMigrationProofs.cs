using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AllowRuntimeHardwareAuthorityMigrationProofs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade', 'rollback', 'websetup-upgrade', 'hardware-authority-migration')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade', 'rollback', 'websetup-upgrade')");
        }
    }
}

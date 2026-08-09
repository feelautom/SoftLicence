using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeEnrollmentUpgrade : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests",
                sql: "\"Operation\" IN ('prepare', 'upgrade')");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests",
                sql: "\"Operation\" = 'prepare'");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone')");
        }
    }
}

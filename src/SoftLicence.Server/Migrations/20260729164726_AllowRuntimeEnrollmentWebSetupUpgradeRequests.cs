using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AllowRuntimeEnrollmentWebSetupUpgradeRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests",
                sql: "\"Operation\" IN ('prepare', 'upgrade', 'rollback', 'websetup-upgrade')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM \"RuntimeEnrollmentRequests\" WHERE \"Operation\" = 'websetup-upgrade';");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentRequests_Operation",
                table: "RuntimeEnrollmentRequests",
                sql: "\"Operation\" IN ('prepare', 'upgrade', 'rollback')");
        }
    }
}

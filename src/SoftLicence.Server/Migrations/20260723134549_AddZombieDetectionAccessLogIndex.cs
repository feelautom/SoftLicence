using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddZombieDetectionAccessLogIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                CREATE INDEX CONCURRENTLY IF NOT EXISTS "IX_AccessLogs_HardwareId_Timestamp_Endpoint_ResultStatus"
                ON "AccessLogs" ("HardwareId", "Timestamp", "Endpoint", "ResultStatus");
                """,
                suppressTransaction: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DROP INDEX CONCURRENTLY IF EXISTS "IX_AccessLogs_HardwareId_Timestamp_Endpoint_ResultStatus";
                """,
                suppressTransaction: true);
        }
    }
}

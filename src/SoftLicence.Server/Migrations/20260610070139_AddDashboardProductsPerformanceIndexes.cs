using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddDashboardProductsPerformanceIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_TelemetryRecords_ProductId",
                table: "TelemetryRecords");

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryRecords_ProductId_Timestamp",
                table: "TelemetryRecords",
                columns: new[] { "ProductId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_Licenses_ProductId_ActivationDate",
                table: "Licenses",
                columns: new[] { "ProductId", "ActivationDate" });

            migrationBuilder.CreateIndex(
                name: "IX_Licenses_ProductId_CreationDate",
                table: "Licenses",
                columns: new[] { "ProductId", "CreationDate" });

            migrationBuilder.CreateIndex(
                name: "IX_Licenses_ProductId_IsActive",
                table: "Licenses",
                columns: new[] { "ProductId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_AccessLogs_AppName_Endpoint_Timestamp",
                table: "AccessLogs",
                columns: new[] { "AppName", "Endpoint", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AccessLogs_AppName_Timestamp",
                table: "AccessLogs",
                columns: new[] { "AppName", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AccessLogs_Timestamp_Endpoint_IsSuccess",
                table: "AccessLogs",
                columns: new[] { "Timestamp", "Endpoint", "IsSuccess" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_TelemetryRecords_ProductId_Timestamp",
                table: "TelemetryRecords");

            migrationBuilder.DropIndex(
                name: "IX_Licenses_ProductId_ActivationDate",
                table: "Licenses");

            migrationBuilder.DropIndex(
                name: "IX_Licenses_ProductId_CreationDate",
                table: "Licenses");

            migrationBuilder.DropIndex(
                name: "IX_Licenses_ProductId_IsActive",
                table: "Licenses");

            migrationBuilder.DropIndex(
                name: "IX_AccessLogs_AppName_Endpoint_Timestamp",
                table: "AccessLogs");

            migrationBuilder.DropIndex(
                name: "IX_AccessLogs_AppName_Timestamp",
                table: "AccessLogs");

            migrationBuilder.DropIndex(
                name: "IX_AccessLogs_Timestamp_Endpoint_IsSuccess",
                table: "AccessLogs");

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryRecords_ProductId",
                table: "TelemetryRecords",
                column: "ProductId");
        }
    }
}

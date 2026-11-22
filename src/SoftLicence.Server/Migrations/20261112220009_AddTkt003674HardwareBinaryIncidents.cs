using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-003674: attaches ApprovedBinaries mismatch evidence to the machine and its licence, and makes the
    /// modified-binary alert reach the phone. Adds the nullable <c>SecurityIncidents.LicenseId</c> link (cleared when
    /// the licence is deleted) and the <c>SecurityIncidentObservations</c> table of counted starts behind the 24-hour
    /// threshold. Then subscribes every webhook already receiving serious security bans (<c>Security.IpBanned</c>, in
    /// production the ntfy alert topic) to <c>Security.BinaryTampered</c>: until now the daily ApprovedBinaries
    /// notification used <c>Security.EvidenceObserved</c>, to which no webhook was subscribed, so it reached nobody.
    /// </summary>
    /// <remarks>
    /// Additive schema change, no data rewrite; the new table starts empty and the new column null. The subscription is
    /// idempotent and uses the same trigger key as TKT-003668, whose own migration subscribes it the same way: whichever
    /// runs second changes nothing. Down removes the trigger from every webhook (including subscriptions added by hand
    /// after the upgrade), then drops the foreign key, the table, the index and the column.
    /// </remarks>
    public partial class AddTkt003674HardwareBinaryIncidents : Migration
    {
        /// <summary>
        /// Adds Security.BinaryTampered once to every webhook subscribed to Security.IpBanned. EnabledEvents is an exact
        /// comma-separated list compared ordinally by delivery; entries are trimmed before matching, as delivery does,
        /// and other entries are kept exactly as they are. Running it twice changes nothing.
        /// </summary>
        internal const string SubscribeBinaryTamperedAlertSql = """
            UPDATE "Webhooks"
            SET "EnabledEvents" = "EnabledEvents" || ',Security.BinaryTampered'
            WHERE 'Security.IpBanned' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry)
              AND NOT 'Security.BinaryTampered' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry);
            """;

        /// <summary>Rollback: removes Security.BinaryTampered from every webhook, keeping every other entry.</summary>
        internal const string UnsubscribeBinaryTamperedAlertSql = """
            UPDATE "Webhooks"
            SET "EnabledEvents" = array_to_string(ARRAY(
                    SELECT entry FROM unnest(string_to_array("EnabledEvents", ',')) AS entry
                    WHERE btrim(entry) <> 'Security.BinaryTampered'), ',')
            WHERE 'Security.BinaryTampered' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry);
            """;

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "LicenseId",
                table: "SecurityIncidents",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "SecurityIncidentObservations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SecurityIncidentId = table.Column<Guid>(type: "uuid", nullable: false),
                    ObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ClientIp = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Version = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityIncidentObservations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecurityIncidentObservations_SecurityIncidents_SecurityInci~",
                        column: x => x.SecurityIncidentId,
                        principalTable: "SecurityIncidents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidents_LicenseId",
                table: "SecurityIncidents",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidentObservations_SecurityIncidentId_ObservedAtU~",
                table: "SecurityIncidentObservations",
                columns: new[] { "SecurityIncidentId", "ObservedAtUtc" });

            migrationBuilder.AddForeignKey(
                name: "FK_SecurityIncidents_Licenses_LicenseId",
                table: "SecurityIncidents",
                column: "LicenseId",
                principalTable: "Licenses",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.Sql(SubscribeBinaryTamperedAlertSql);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(UnsubscribeBinaryTamperedAlertSql);

            migrationBuilder.DropForeignKey(
                name: "FK_SecurityIncidents_Licenses_LicenseId",
                table: "SecurityIncidents");

            migrationBuilder.DropTable(
                name: "SecurityIncidentObservations");

            migrationBuilder.DropIndex(
                name: "IX_SecurityIncidents_LicenseId",
                table: "SecurityIncidents");

            migrationBuilder.DropColumn(
                name: "LicenseId",
                table: "SecurityIncidents");
        }
    }
}

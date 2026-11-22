using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-002685: journal of operator threat-score resets, and subscription of every webhook already
    /// receiving IP bans to the new threshold alert, so the alert reaches ntfy without manual setup.
    /// </summary>
    public partial class AddTkt002685ThreatScoreResets : Migration
    {
        /// <summary>
        /// Adds Security.ThreatScoreRaised once to every webhook already subscribed to Security.IpBanned.
        /// EnabledEvents is an exact comma-separated list compared ordinally by NotificationService; entries
        /// are trimmed before matching, as the service does, and other entries are kept as-is.
        /// </summary>
        internal const string SubscribeThreatScoreAlertSql = """
            UPDATE "Webhooks"
            SET "EnabledEvents" = "EnabledEvents" || ',Security.ThreatScoreRaised'
            WHERE 'Security.IpBanned' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry)
              AND NOT 'Security.ThreatScoreRaised' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry);
            """;

        /// <summary>Rollback: removes Security.ThreatScoreRaised from every webhook.</summary>
        internal const string UnsubscribeThreatScoreAlertSql = """
            UPDATE "Webhooks"
            SET "EnabledEvents" = array_to_string(ARRAY(
                    SELECT entry FROM unnest(string_to_array("EnabledEvents", ',')) AS entry
                    WHERE btrim(entry) <> 'Security.ThreatScoreRaised'), ',')
            WHERE 'Security.ThreatScoreRaised' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry);
            """;

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "IpThreatScoreResets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    IpAddress = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    PreviousScore = table.Column<int>(type: "integer", nullable: false),
                    ResetAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ResetBy = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IpThreatScoreResets", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_IpThreatScoreResets_IpAddress_ResetAtUtc",
                table: "IpThreatScoreResets",
                columns: new[] { "IpAddress", "ResetAtUtc" });

            migrationBuilder.Sql(SubscribeThreatScoreAlertSql);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(UnsubscribeThreatScoreAlertSql);

            migrationBuilder.DropTable(
                name: "IpThreatScoreResets");
        }
    }
}

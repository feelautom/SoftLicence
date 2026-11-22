using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-003668: serious alerts reached no phone. Security-lock alerts (new lock of level 3 to 5, hardware ban issued
    /// by the lock system) went only to the admin email, and the new critical trigger for an activation through a
    /// local licence server is subscribed nowhere. Every webhook already receiving the serious security bans
    /// (<c>Security.IpBanned</c>, in production the ntfy alert topic) is subscribed to <c>Security.LockReported</c>,
    /// <c>Security.LockBanned</c> and <c>Security.LicenseServerSpoofed</c>, so these alerts reach the phone without
    /// manual setup. Same pattern as TKT-002685 (<c>Security.ThreatScoreRaised</c>) and TKT-003674, whose migration
    /// <c>20261112220009_AddTkt003674HardwareBinaryIncidents</c> already subscribes <c>Security.BinaryTampered</c>:
    /// that trigger is deliberately not repeated here.
    /// </summary>
    /// <remarks>
    /// Data only: no schema change, the model snapshot is unchanged. The update touches a handful of configuration
    /// rows. Webhooks created only for the TKT-003668 noise triggers do not list <c>Security.IpBanned</c> (the admin
    /// page forbids mixing) and are therefore never subscribed to alerts. Down removes the three triggers from every
    /// webhook, including subscriptions an operator may have added by hand after the upgrade, and leaves
    /// <c>Security.BinaryTampered</c> to the TKT-003674 migration.
    /// </remarks>
    public partial class AddTkt003668SeriousAlertSubscriptions : Migration
    {
        /// <summary>Serious triggers added to the alert webhooks, in the order they are appended.</summary>
        private static readonly string[] SeriousTriggers =
        {
            "Security.LockReported",
            "Security.LockBanned",
            "Security.LicenseServerSpoofed"
        };

        /// <summary>
        /// Appends each serious trigger once to every webhook subscribed to <c>Security.IpBanned</c>. EnabledEvents is
        /// an exact comma-separated list compared ordinally by the delivery code; entries are trimmed before matching,
        /// as delivery does, and other entries are kept exactly as they are. Running it twice changes nothing. The
        /// trigger names are fixed ASCII constants, so inlining them in SQL is safe.
        /// </summary>
        internal static readonly string SubscribeSeriousAlertsSql = string.Concat(SeriousTriggers.Select(trigger => $"""
            UPDATE "Webhooks"
            SET "EnabledEvents" = "EnabledEvents" || ',{trigger}'
            WHERE 'Security.IpBanned' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry)
              AND NOT '{trigger}' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry);

            """));

        /// <summary>Rollback: removes the three serious triggers from every webhook, keeping every other entry.</summary>
        internal static readonly string UnsubscribeSeriousAlertsSql = $"""
            UPDATE "Webhooks"
            SET "EnabledEvents" = array_to_string(ARRAY(
                    SELECT entry FROM unnest(string_to_array("EnabledEvents", ',')) AS entry
                    WHERE btrim(entry) NOT IN ({string.Join(", ", SeriousTriggers.Select(trigger => "'" + trigger + "'"))})), ',')
            WHERE EXISTS (
                    SELECT 1 FROM unnest(string_to_array("EnabledEvents", ',')) AS entry
                    WHERE btrim(entry) IN ({string.Join(", ", SeriousTriggers.Select(trigger => "'" + trigger + "'"))}));
            """;

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(SubscribeSeriousAlertsSql);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(UnsubscribeSeriousAlertsSql);
        }
    }
}

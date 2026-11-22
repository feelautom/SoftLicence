using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-003615: single-use control token of the managed licence check. Creates <c>SeatCloneGuards</c> (one row per
    /// guarded seat: SHA-256 digests of the current and previous tokens, last accepted check, VM Generation ID, collision
    /// counter, alert deduplication instants) and the append-only journal <c>SeatCloneGuardEvents</c>, whose
    /// <c>REACTIVATED</c> rows also count in the licence's daily quota. Then subscribes every webhook already receiving
    /// serious security bans (<c>Security.IpBanned</c>, in production the ntfy alert topic) to
    /// <c>Security.CloneSuspected</c>, so the new alert reaches the administrator.
    /// </summary>
    /// <remarks>
    /// Additive: two new empty tables, no existing row is read or rewritten, so installed clients (which send no clone
    /// guard) are unaffected. The unique index on <c>SeatCloneGuards.LicenseSeatId</c> is what makes concurrent arming
    /// atomic (<c>INSERT ... ON CONFLICT</c>); CHECK constraints pin token digests to exactly 32 bytes and the journal
    /// kinds to a closed list. Foreign keys to <c>LicenseSeats</c> are RESTRICT: seats are never deleted. The webhook
    /// subscription is idempotent (same pattern as TKT-003674). Down removes the trigger from every webhook, then drops
    /// both tables, losing only clone guard state and journal (clients re-arm on their next check).
    /// </remarks>
    public partial class AddTkt003615SeatCloneGuards : Migration
    {
        /// <summary>
        /// Adds Security.CloneSuspected once to every webhook subscribed to Security.IpBanned. EnabledEvents is an exact
        /// comma-separated list compared ordinally by delivery; entries are trimmed before matching, as delivery does,
        /// and other entries are kept exactly as they are. Running it twice changes nothing.
        /// </summary>
        internal const string SubscribeCloneSuspectedAlertSql = """
            UPDATE "Webhooks"
            SET "EnabledEvents" = "EnabledEvents" || ',Security.CloneSuspected'
            WHERE 'Security.IpBanned' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry)
              AND NOT 'Security.CloneSuspected' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry);
            """;

        /// <summary>Rollback: removes Security.CloneSuspected from every webhook, keeping every other entry.</summary>
        internal const string UnsubscribeCloneSuspectedAlertSql = """
            UPDATE "Webhooks"
            SET "EnabledEvents" = array_to_string(ARRAY(
                    SELECT entry FROM unnest(string_to_array("EnabledEvents", ',')) AS entry
                    WHERE btrim(entry) <> 'Security.CloneSuspected'), ',')
            WHERE 'Security.CloneSuspected' = ANY (
                    SELECT btrim(entry) FROM unnest(string_to_array("EnabledEvents", ',')) AS entry);
            """;

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SeatCloneGuardEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    Reason = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    OccurredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IpAddress = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    AppVersion = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    VmGenerationId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    KnownVmGenerationId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SeatCloneGuardEvents", x => x.Id);
                    table.CheckConstraint("CK_SeatCloneGuardEvents_Kind", "\"Kind\" IN ('ARMED', 'REARMED_AFTER_ACTIVATION', 'COLLISION', 'VM_GENERATION_CHANGED', 'REACTIVATED', 'REACTIVATION_REFUSED')");
                    table.ForeignKey(
                        name: "FK_SeatCloneGuardEvents_LicenseSeats_LicenseSeatId",
                        column: x => x.LicenseSeatId,
                        principalTable: "LicenseSeats",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "SeatCloneGuards",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                    CurrentTokenHash = table.Column<byte[]>(type: "bytea", nullable: false),
                    PreviousTokenHash = table.Column<byte[]>(type: "bytea", nullable: true),
                    ArmedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastAcceptedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastAcceptedIp = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    LastVmGenerationId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    CollisionCount = table.Column<int>(type: "integer", nullable: false),
                    LastCollisionAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastAlertAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastLimitAlertAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SeatCloneGuards", x => x.Id);
                    table.CheckConstraint("CK_SeatCloneGuards_CurrentTokenHash", "octet_length(\"CurrentTokenHash\") = 32");
                    table.CheckConstraint("CK_SeatCloneGuards_PreviousTokenHash", "\"PreviousTokenHash\" IS NULL OR octet_length(\"PreviousTokenHash\") = 32");
                    table.ForeignKey(
                        name: "FK_SeatCloneGuards_LicenseSeats_LicenseSeatId",
                        column: x => x.LicenseSeatId,
                        principalTable: "LicenseSeats",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SeatCloneGuardEvents_LicenseId_Kind_OccurredAt",
                table: "SeatCloneGuardEvents",
                columns: new[] { "LicenseId", "Kind", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_SeatCloneGuardEvents_LicenseSeatId_OccurredAt",
                table: "SeatCloneGuardEvents",
                columns: new[] { "LicenseSeatId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_SeatCloneGuards_LicenseSeatId",
                table: "SeatCloneGuards",
                column: "LicenseSeatId",
                unique: true);

            migrationBuilder.Sql(SubscribeCloneSuspectedAlertSql);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(UnsubscribeCloneSuspectedAlertSql);

            migrationBuilder.DropTable(
                name: "SeatCloneGuardEvents");

            migrationBuilder.DropTable(
                name: "SeatCloneGuards");
        }
    }
}

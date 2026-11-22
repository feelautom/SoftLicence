using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-003574: administrator decision to share an LLM tip with every client. Adds to <c>LlmTipFeedbackTips</c> the
    /// state <c>SharedWithClients</c> (false for every existing row: nothing was ever shared, the client-driven
    /// <c>Approved</c> flag is left untouched and stays informational), the instant and actor of the last decision, an
    /// index (ProductId, SharedWithClients) for the public read route, and the append-only journal
    /// <c>LlmTipFeedbackSharingDecisions</c>.
    /// </summary>
    /// <remarks>
    /// Additive: three nullable or defaulted columns and one new empty table, no existing row is rewritten, so the
    /// ingestion of installed clients is unaffected. CHECK constraints close the action and channel lists and forbid a
    /// retraction without a reason; the journal foreign key is RESTRICT so the history survives any tip deletion
    /// attempt. Table privileges for the application role come from the default privileges set by
    /// <c>ConfigureApplicationDatabaseRole</c>. Down drops the journal and the columns, losing only sharing decisions
    /// (clients then receive an empty snapshot).
    /// </remarks>
    public partial class AddTkt003574LlmTipSharing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "SharedWithClients",
                table: "LlmTipFeedbackTips",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "SharingChangedAtUtc",
                table: "LlmTipFeedbackTips",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SharingChangedBy",
                table: "LlmTipFeedbackTips",
                type: "character varying(160)",
                maxLength: 160,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "LlmTipFeedbackSharingDecisions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TipId = table.Column<Guid>(type: "uuid", nullable: false),
                    Action = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    DecidedBy = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                    Channel = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    CallerIp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    DecidedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LlmTipFeedbackSharingDecisions", x => x.Id);
                    table.CheckConstraint("CK_LlmTipFeedbackSharingDecisions_Action", "\"Action\" IN ('shared', 'retracted')");
                    table.CheckConstraint("CK_LlmTipFeedbackSharingDecisions_Channel", "\"Channel\" IN ('admin-ui', 'api', 'mcp')");
                    table.CheckConstraint("CK_LlmTipFeedbackSharingDecisions_RetractionReason", "\"Action\" <> 'retracted' OR (\"Reason\" IS NOT NULL AND length(trim(\"Reason\")) > 0)");
                    table.ForeignKey(
                        name: "FK_LlmTipFeedbackSharingDecisions_LlmTipFeedbackTips_TipId",
                        column: x => x.TipId,
                        principalTable: "LlmTipFeedbackTips",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_LlmTipFeedbackTips_ProductId_SharedWithClients",
                table: "LlmTipFeedbackTips",
                columns: new[] { "ProductId", "SharedWithClients" });

            migrationBuilder.CreateIndex(
                name: "IX_LlmTipFeedbackSharingDecisions_TipId_DecidedAtUtc",
                table: "LlmTipFeedbackSharingDecisions",
                columns: new[] { "TipId", "DecidedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LlmTipFeedbackSharingDecisions");

            migrationBuilder.DropIndex(
                name: "IX_LlmTipFeedbackTips_ProductId_SharedWithClients",
                table: "LlmTipFeedbackTips");

            migrationBuilder.DropColumn(
                name: "SharedWithClients",
                table: "LlmTipFeedbackTips");

            migrationBuilder.DropColumn(
                name: "SharingChangedAtUtc",
                table: "LlmTipFeedbackTips");

            migrationBuilder.DropColumn(
                name: "SharingChangedBy",
                table: "LlmTipFeedbackTips");
        }
    }
}

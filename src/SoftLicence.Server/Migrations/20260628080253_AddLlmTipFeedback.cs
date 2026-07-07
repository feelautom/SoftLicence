using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddLlmTipFeedback : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "LlmTipFeedbackEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    TimestampUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SchemaVersion = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    AppName = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    AppVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    EventName = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: true),
                    Category = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    ToolName = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    LicenseEdition = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    RequestSource = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    RuntimeMode = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    UiMode = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    PayloadJson = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LlmTipFeedbackEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LlmTipFeedbackEvents_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "LlmTipFeedbackTips",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SubmittedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    SchemaVersion = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    AppName = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    AppVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: true),
                    ContentHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Category = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    Title = table.Column<string>(type: "character varying(240)", maxLength: 240, nullable: false),
                    Description = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    Severity = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    Confidence = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    Approved = table.Column<bool>(type: "boolean", nullable: false),
                    Upvotes = table.Column<int>(type: "integer", nullable: false),
                    OccurrenceCount = table.Column<int>(type: "integer", nullable: false),
                    LicenseEdition = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    RequestSource = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    RuntimeMode = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    UiMode = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    ReviewStatus = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    PromotedTo = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: true),
                    FixedInVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    BugTraceTicketRef = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    PayloadJson = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LlmTipFeedbackTips", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LlmTipFeedbackTips_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_LlmTipFeedbackEvents_ProductId_CreatedAtUtc",
                table: "LlmTipFeedbackEvents",
                columns: new[] { "ProductId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_LlmTipFeedbackEvents_ProductId_EventName_CreatedAtUtc",
                table: "LlmTipFeedbackEvents",
                columns: new[] { "ProductId", "EventName", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_LlmTipFeedbackTips_ContentHash",
                table: "LlmTipFeedbackTips",
                column: "ContentHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LlmTipFeedbackTips_ProductId_Category_OccurrenceCount",
                table: "LlmTipFeedbackTips",
                columns: new[] { "ProductId", "Category", "OccurrenceCount" });

            migrationBuilder.CreateIndex(
                name: "IX_LlmTipFeedbackTips_ProductId_LastSeenAtUtc",
                table: "LlmTipFeedbackTips",
                columns: new[] { "ProductId", "LastSeenAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LlmTipFeedbackEvents");

            migrationBuilder.DropTable(
                name: "LlmTipFeedbackTips");
        }
    }
}

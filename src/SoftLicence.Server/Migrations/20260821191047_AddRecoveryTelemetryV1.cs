using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRecoveryTelemetryV1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RecoveryTelemetryRejections",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: true),
                    RecoveryRunId = table.Column<Guid>(type: "uuid", nullable: true),
                    EventId = table.Column<Guid>(type: "uuid", nullable: true),
                    Code = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CorrelationId = table.Column<Guid>(type: "uuid", nullable: false),
                    ReceivedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RecoveryTelemetryRejections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RecoveryTelemetryRejections_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RecoveryTelemetryRuns",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    RecoveryRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    LastSequence = table.Column<int>(type: "integer", nullable: false),
                    LastStage = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    LastOutcome = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    IsTerminal = table.Column<bool>(type: "boolean", nullable: false),
                    Status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    ErrorCode = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    SourceVersion = table.Column<string>(type: "character varying(17)", maxLength: 17, nullable: true),
                    TargetVersion = table.Column<string>(type: "character varying(17)", maxLength: 17, nullable: true),
                    VerifiedRestoredVersion = table.Column<string>(type: "character varying(17)", maxLength: 17, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RecoveryTelemetryRuns", x => x.Id);
                    table.CheckConstraint("CK_RecoveryTelemetryRuns_LastSequence", "\"LastSequence\" >= 1 AND \"LastSequence\" <= 32");
                    table.CheckConstraint("CK_RecoveryTelemetryRuns_Status", "\"Status\" IN ('incomplete', 'completed', 'failed', 'cancelled')");
                    table.ForeignKey(
                        name: "FK_RecoveryTelemetryRuns_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RecoveryTelemetryEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    RunId = table.Column<Guid>(type: "uuid", nullable: false),
                    RecoveryRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    EventId = table.Column<Guid>(type: "uuid", nullable: false),
                    Sequence = table.Column<int>(type: "integer", nullable: false),
                    PayloadSha256 = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReceivedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ClientVersion = table.Column<string>(type: "character varying(17)", maxLength: 17, nullable: false),
                    ProcessRole = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Stage = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Outcome = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    SourceVersion = table.Column<string>(type: "character varying(17)", maxLength: 17, nullable: true),
                    TargetVersion = table.Column<string>(type: "character varying(17)", maxLength: 17, nullable: true),
                    VerifiedRestoredVersion = table.Column<string>(type: "character varying(17)", maxLength: 17, nullable: true),
                    DurationMs = table.Column<int>(type: "integer", nullable: true),
                    ErrorCode = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    MsiExitCode = table.Column<int>(type: "integer", nullable: true),
                    IsTerminal = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RecoveryTelemetryEvents", x => x.Id);
                    table.CheckConstraint("CK_RecoveryTelemetryEvents_PayloadSha256", "length(\"PayloadSha256\") = 64 AND \"PayloadSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RecoveryTelemetryEvents_Sequence", "\"Sequence\" >= 1 AND \"Sequence\" <= 32");
                    table.ForeignKey(
                        name: "FK_RecoveryTelemetryEvents_RecoveryTelemetryRuns_RunId",
                        column: x => x.RunId,
                        principalTable: "RecoveryTelemetryRuns",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryEvents_ProductId_EventId",
                table: "RecoveryTelemetryEvents",
                columns: new[] { "ProductId", "EventId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryEvents_ProductId_ReceivedAtUtc",
                table: "RecoveryTelemetryEvents",
                columns: new[] { "ProductId", "ReceivedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryEvents_ProductId_RecoveryRunId",
                table: "RecoveryTelemetryEvents",
                columns: new[] { "ProductId", "RecoveryRunId" },
                unique: true,
                filter: "\"IsTerminal\" = true");

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryEvents_ProductId_RecoveryRunId_Sequence",
                table: "RecoveryTelemetryEvents",
                columns: new[] { "ProductId", "RecoveryRunId", "Sequence" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryEvents_RunId",
                table: "RecoveryTelemetryEvents",
                column: "RunId");

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryRejections_ProductId_ReceivedAtUtc",
                table: "RecoveryTelemetryRejections",
                columns: new[] { "ProductId", "ReceivedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryRejections_ProductId_RecoveryRunId_Receive~",
                table: "RecoveryTelemetryRejections",
                columns: new[] { "ProductId", "RecoveryRunId", "ReceivedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryRuns_ProductId_RecoveryRunId",
                table: "RecoveryTelemetryRuns",
                columns: new[] { "ProductId", "RecoveryRunId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RecoveryTelemetryRuns_ProductId_UpdatedAtUtc",
                table: "RecoveryTelemetryRuns",
                columns: new[] { "ProductId", "UpdatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RecoveryTelemetryEvents");

            migrationBuilder.DropTable(
                name: "RecoveryTelemetryRejections");

            migrationBuilder.DropTable(
                name: "RecoveryTelemetryRuns");
        }
    }
}

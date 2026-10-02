using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Migrations;

/// <summary>Adds durable 30-minute aggregates for actual UPD startup-shell presentations.</summary>
/// <remarks>
/// The table contains bounded diagnostic tokens only. Applying or rolling back this migration is a
/// separate deployment operation; rollback removes alert aggregates but never raw telemetry records.
/// </remarks>
[DbContext(typeof(LicenseDbContext))]
[Migration("20260920073500_AddTkt001227UpdatePreflightAlerts")]
public sealed class AddTkt001227UpdatePreflightAlerts : Migration
{
    /// <summary>Creates the product-scoped signature window and notification-claim projection.</summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "TelemetryUpdatePreflightAlerts",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                SignatureSha256 = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                WindowStartUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                WindowEndUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                OccurrenceCount = table.Column<long>(type: "bigint", nullable: false),
                FirstSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                LastSeenUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                SupportCode = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                CurrentVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                LatestVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                DecisionReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                SelectedChannel = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                ReconciliationOutcome = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                LastPresentationStage = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                NotificationClaimId = table.Column<Guid>(type: "uuid", nullable: true),
                NotificationClaimedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                NotificationSentAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_TelemetryUpdatePreflightAlerts", item => item.Id);
                table.CheckConstraint(
                    "CK_TelemetryUpdatePreflightAlerts_SignatureSha256",
                    "length(\"SignatureSha256\") = 64 AND \"SignatureSha256\" ~ '^[0-9a-f]{64}$'");
                table.ForeignKey(
                    name: "FK_TelemetryUpdatePreflightAlerts_Products_ProductId",
                    column: item => item.ProductId,
                    principalTable: "Products",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_TelemetryUpdatePreflightAlerts_ProductId_LastSeenUtc",
            table: "TelemetryUpdatePreflightAlerts",
            columns: new[] { "ProductId", "LastSeenUtc" });
        migrationBuilder.CreateIndex(
            name: "IX_TelemetryUpdatePreflightAlerts_ProductId_SignatureSha256_Wi~",
            table: "TelemetryUpdatePreflightAlerts",
            columns: new[] { "ProductId", "SignatureSha256", "WindowStartUtc" },
            unique: true);
    }

    /// <summary>Removes only the notification aggregate; immutable raw presentation events remain intact.</summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "TelemetryUpdatePreflightAlerts");
    }
}

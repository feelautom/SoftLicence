using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeCriticalRecovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "SecurityEpoch",
                table: "RuntimeEnrollments",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddUniqueConstraint(
                name: "AK_RuntimeEnrollments_Id_BindingId_ProductId_InstallationId",
                table: "RuntimeEnrollments",
                columns: new[] { "Id", "BindingId", "ProductId", "InstallationId" });

            migrationBuilder.CreateTable(
                name: "RuntimeCriticalRecoveries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    RequestedEventId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    OldSecurityEpoch = table.Column<int>(type: "integer", nullable: false),
                    NewSecurityEpoch = table.Column<int>(type: "integer", nullable: false),
                    ResolvedIncidentCount = table.Column<int>(type: "integer", nullable: false),
                    AuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    RecoveredByClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RecoveredByKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RecoveredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeCriticalRecoveries", x => x.Id);
                    table.CheckConstraint("CK_RuntimeCriticalRecoveries_Epochs", "\"OldSecurityEpoch\" >= 1 AND \"NewSecurityEpoch\" = \"OldSecurityEpoch\" + 1");
                    table.CheckConstraint("CK_RuntimeCriticalRecoveries_IncidentCount", "\"ResolvedIncidentCount\" >= 1");
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalRecoveries_DistributionInstallationBindings_~",
                        column: x => x.BindingId,
                        principalTable: "DistributionInstallationBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalRecoveries_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalRecoveries_RuntimeEnrollments_EnrollmentId_B~",
                        columns: x => new { x.EnrollmentId, x.BindingId, x.ProductId, x.InstallationId },
                        principalTable: "RuntimeEnrollments",
                        principalColumns: new[] { "Id", "BindingId", "ProductId", "InstallationId" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeCriticalIncidents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    EventId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Trigger = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    OpenedSecurityEpoch = table.Column<int>(type: "integer", nullable: false),
                    OpenedAuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    OpenedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RecoveryId = table.Column<Guid>(type: "uuid", nullable: true),
                    RecoveredSecurityEpoch = table.Column<int>(type: "integer", nullable: true),
                    RecoveredAuthorityEpoch = table.Column<long>(type: "bigint", nullable: true),
                    RecoveredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeCriticalIncidents", x => x.Id);
                    table.CheckConstraint("CK_RuntimeCriticalIncidents_Epochs", "\"OpenedSecurityEpoch\" >= 1 AND (\"RecoveredSecurityEpoch\" IS NULL OR \"RecoveredSecurityEpoch\" >= \"OpenedSecurityEpoch\" + 1)");
                    table.CheckConstraint("CK_RuntimeCriticalIncidents_Resolution", "(\"State\" = 'OPEN' AND \"RecoveryId\" IS NULL AND \"RecoveredSecurityEpoch\" IS NULL AND \"RecoveredAuthorityEpoch\" IS NULL AND \"RecoveredAtUtc\" IS NULL) OR (\"State\" = 'RESOLVED' AND \"RecoveryId\" IS NOT NULL AND \"RecoveredSecurityEpoch\" IS NOT NULL AND \"RecoveredAuthorityEpoch\" IS NOT NULL AND \"RecoveredAtUtc\" IS NOT NULL)");
                    table.CheckConstraint("CK_RuntimeCriticalIncidents_State", "\"State\" IN ('OPEN', 'RESOLVED')");
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalIncidents_DistributionInstallationBindings_B~",
                        column: x => x.BindingId,
                        principalTable: "DistributionInstallationBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalIncidents_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalIncidents_RuntimeCriticalRecoveries_Recovery~",
                        column: x => x.RecoveryId,
                        principalTable: "RuntimeCriticalRecoveries",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalIncidents_RuntimeEnrollments_EnrollmentId_Bi~",
                        columns: x => new { x.EnrollmentId, x.BindingId, x.ProductId, x.InstallationId },
                        principalTable: "RuntimeEnrollments",
                        principalColumns: new[] { "Id", "BindingId", "ProductId", "InstallationId" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeCriticalRecoveryReceipts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RecoveryId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    RequestDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestedByClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestedByKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    IssuedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    DeliveryPurgedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExactResponseBody = table.Column<byte[]>(type: "bytea", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeCriticalRecoveryReceipts", x => x.Id);
                    table.CheckConstraint("CK_RuntimeCriticalRecoveryReceipts_Delivery", "(\"ExactResponseBody\" IS NOT NULL AND \"DeliveryPurgedAtUtc\" IS NULL AND octet_length(\"ExactResponseBody\") BETWEEN 1 AND 8192) OR (\"ExactResponseBody\" IS NULL AND \"DeliveryPurgedAtUtc\" IS NOT NULL AND \"DeliveryPurgedAtUtc\" >= \"ExpiresAtUtc\")");
                    table.CheckConstraint("CK_RuntimeCriticalRecoveryReceipts_Times", "\"ExpiresAtUtc\" > \"IssuedAtUtc\"");
                    table.ForeignKey(
                        name: "FK_RuntimeCriticalRecoveryReceipts_RuntimeCriticalRecoveries_R~",
                        column: x => x.RecoveryId,
                        principalTable: "RuntimeCriticalRecoveries",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollments_SecurityEpoch",
                table: "RuntimeEnrollments",
                sql: "\"SecurityEpoch\" >= 1");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalIncidents_BindingId_InstallationId_State",
                table: "RuntimeCriticalIncidents",
                columns: new[] { "BindingId", "InstallationId", "State" },
                filter: "\"State\" = 'OPEN'");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalIncidents_EnrollmentId_BindingId_ProductId_I~",
                table: "RuntimeCriticalIncidents",
                columns: new[] { "EnrollmentId", "BindingId", "ProductId", "InstallationId" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalIncidents_EventId",
                table: "RuntimeCriticalIncidents",
                column: "EventId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalIncidents_ProductId",
                table: "RuntimeCriticalIncidents",
                column: "ProductId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalIncidents_RecoveryId",
                table: "RuntimeCriticalIncidents",
                column: "RecoveryId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalRecoveries_BindingId_InstallationId_NewSecur~",
                table: "RuntimeCriticalRecoveries",
                columns: new[] { "BindingId", "InstallationId", "NewSecurityEpoch" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalRecoveries_EnrollmentId_BindingId_ProductId_~",
                table: "RuntimeCriticalRecoveries",
                columns: new[] { "EnrollmentId", "BindingId", "ProductId", "InstallationId" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalRecoveries_ProductId",
                table: "RuntimeCriticalRecoveries",
                column: "ProductId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalRecoveryReceipts_ExpiresAtUtc",
                table: "RuntimeCriticalRecoveryReceipts",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalRecoveryReceipts_RecoveryId",
                table: "RuntimeCriticalRecoveryReceipts",
                column: "RecoveryId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCriticalRecoveryReceipts_RequestId",
                table: "RuntimeCriticalRecoveryReceipts",
                column: "RequestId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RuntimeCriticalIncidents");

            migrationBuilder.DropTable(
                name: "RuntimeCriticalRecoveryReceipts");

            migrationBuilder.DropTable(
                name: "RuntimeCriticalRecoveries");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_RuntimeEnrollments_Id_BindingId_ProductId_InstallationId",
                table: "RuntimeEnrollments");

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollments_SecurityEpoch",
                table: "RuntimeEnrollments");

            migrationBuilder.DropColumn(
                name: "SecurityEpoch",
                table: "RuntimeEnrollments");
        }
    }
}

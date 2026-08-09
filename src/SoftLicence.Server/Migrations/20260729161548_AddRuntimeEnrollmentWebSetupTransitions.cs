using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeEnrollmentWebSetupTransitions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentWebSetupTransitions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    SourceVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    TargetVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    TargetInstallerFilename = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    TargetInstallerSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CapabilityDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SourceSecurityEpoch = table.Column<int>(type: "integer", nullable: false),
                    AuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    IssuedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ConsumedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ConsumedPayloadDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentWebSetupTransitions", x => x.Id);
                    table.CheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_Capability", "length(\"CapabilityDigestSha256\") = 64");
                    table.CheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_Consumption", "(\"State\" = 'ISSUED' AND \"ConsumedAtUtc\" IS NULL AND \"ConsumedPayloadDigestSha256\" IS NULL) OR (\"State\" = 'CONSUMED' AND \"ConsumedAtUtc\" IS NOT NULL AND length(\"ConsumedPayloadDigestSha256\") = 64) OR \"State\" IN ('REVOKED', 'EXPIRED')");
                    table.CheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_State", "\"State\" IN ('ISSUED', 'CONSUMED', 'REVOKED', 'EXPIRED')");
                    table.CheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_Times", "\"IssuedAtUtc\" < \"ExpiresAtUtc\"");
                    table.ForeignKey(
                        name: "FK_RuntimeEnrollmentWebSetupTransitions_DistributionInstallati~",
                        column: x => x.BindingId,
                        principalTable: "DistributionInstallationBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeEnrollmentWebSetupTransitions_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeEnrollmentWebSetupTransitions_RuntimeEnrollments_Enr~",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentWebSetupTransitionRequests",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Operation = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    PayloadDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    TransitionId = table.Column<Guid>(type: "uuid", nullable: false),
                    ExactResponseCiphertext = table.Column<byte[]>(type: "bytea", nullable: false),
                    ResponseKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentWebSetupTransitionRequests", x => new { x.ClientId, x.Operation, x.RequestId });
                    table.ForeignKey(
                        name: "FK_RuntimeEnrollmentWebSetupTransitionRequests_RuntimeEnrollme~",
                        column: x => x.TransitionId,
                        principalTable: "RuntimeEnrollmentWebSetupTransitions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentWebSetupTransitionRequests_TransitionId",
                table: "RuntimeEnrollmentWebSetupTransitionRequests",
                column: "TransitionId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentWebSetupTransitions_BindingId",
                table: "RuntimeEnrollmentWebSetupTransitions",
                column: "BindingId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentWebSetupTransitions_CapabilityDigestSha256",
                table: "RuntimeEnrollmentWebSetupTransitions",
                column: "CapabilityDigestSha256",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentWebSetupTransitions_EnrollmentId_State_Exp~",
                table: "RuntimeEnrollmentWebSetupTransitions",
                columns: new[] { "EnrollmentId", "State", "ExpiresAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentWebSetupTransitions_ProductId",
                table: "RuntimeEnrollmentWebSetupTransitions",
                column: "ProductId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentWebSetupTransitionRequests");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentWebSetupTransitions");
        }
    }
}

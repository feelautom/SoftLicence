using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds authenticated legacy-to-V2 hardware aliases and reconstructs only migrations whose live authority graph still matches the signed migration history.
    /// </summary>
    public partial class AddAuthenticatedHardwareAuthorityAliases : Migration
    {
        /// <summary>
        /// Creates the constrained alias table and performs one bounded PostgreSQL backfill from HWID_V2_MIGRATED history rows.
        /// </summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "HardwareAuthorityAliases",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                    RuntimeEnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    MigrationRequestId = table.Column<Guid>(type: "uuid", nullable: true),
                    LegacyHardwareIdSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CanonicalHardwareIdSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SecurityEpoch = table.Column<int>(type: "integer", nullable: false),
                    AuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    DisabledAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ObservationCount = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HardwareAuthorityAliases", x => x.Id);
                    table.CheckConstraint("CK_HardwareAuthorityAliases_CanonicalHardwareIdSha256", "length(\"CanonicalHardwareIdSha256\") = 64 AND \"CanonicalHardwareIdSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_HardwareAuthorityAliases_Epochs", "\"SecurityEpoch\" >= 1 AND \"AuthorityEpoch\" >= 0");
                    table.CheckConstraint("CK_HardwareAuthorityAliases_LegacyHardwareIdSha256", "length(\"LegacyHardwareIdSha256\") = 64 AND \"LegacyHardwareIdSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_HardwareAuthorityAliases_ObservationCount", "\"ObservationCount\" >= 0");
                    table.CheckConstraint("CK_HardwareAuthorityAliases_State", "(\"IsActive\" AND \"DisabledAtUtc\" IS NULL) OR (NOT \"IsActive\" AND \"DisabledAtUtc\" IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityAliases_DistributionInstallationBindings_B~",
                        column: x => x.BindingId,
                        principalTable: "DistributionInstallationBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityAliases_LicenseSeats_LicenseSeatId",
                        column: x => x.LicenseSeatId,
                        principalTable: "LicenseSeats",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityAliases_Licenses_LicenseId",
                        column: x => x.LicenseId,
                        principalTable: "Licenses",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityAliases_Products_ProductId",
                        column: x => x.ProductId,
                        principalTable: "Products",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_HardwareAuthorityAliases_RuntimeEnrollments_RuntimeEnrollme~",
                        column: x => x.RuntimeEnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityAliases_BindingId",
                table: "HardwareAuthorityAliases",
                column: "BindingId");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityAliases_LicenseId_LegacyHardwareIdSha256",
                table: "HardwareAuthorityAliases",
                columns: new[] { "LicenseId", "LegacyHardwareIdSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityAliases_LicenseSeatId",
                table: "HardwareAuthorityAliases",
                column: "LicenseSeatId");

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityAliases_ProductId_LegacyHardwareIdSha256",
                table: "HardwareAuthorityAliases",
                columns: new[] { "ProductId", "LegacyHardwareIdSha256" });

            migrationBuilder.CreateIndex(
                name: "IX_HardwareAuthorityAliases_RuntimeEnrollmentId",
                table: "HardwareAuthorityAliases",
                column: "RuntimeEnrollmentId");

            migrationBuilder.Sql("""
                WITH migration_candidates AS (
                    SELECT
                        h."Id" AS "AliasId",
                        h."LicenseId",
                        h."Timestamp" AS "CreatedAtUtc",
                        h."Details"::jsonb AS details
                    FROM "LicenseHistories" h
                    WHERE h."Action" = 'HWID_V2_MIGRATED'
                      AND h."Details" IS NOT NULL
                ), relational_candidates AS (
                    SELECT DISTINCT ON (candidate."LicenseId", candidate.details->>'legacyHardwareIdSha256')
                        candidate."AliasId",
                        l."ProductId",
                        l."Id" AS "LicenseId",
                        s."Id" AS "LicenseSeatId",
                        e."Id" AS "RuntimeEnrollmentId",
                        b."Id" AS "BindingId",
                        candidate.details->>'legacyHardwareIdSha256' AS "LegacyHardwareIdSha256",
                        candidate.details->>'hardwareIdV2Sha256' AS "CanonicalHardwareIdSha256",
                        e."SecurityEpoch",
                        e."AuthorityEpoch",
                        candidate."CreatedAtUtc",
                        (
                            s."LicenseId" = l."Id"
                            AND e."BindingId" = b."Id"
                            AND e."ProductId" = l."ProductId"
                            AND e."LicenseId" = l."Id"
                            AND e."LicenseSeatId" = s."Id"
                            AND b."ProductId" = l."ProductId"
                            AND b."LicenseId" = l."Id"
                            AND b."LicenseSeatId" = s."Id"
                            AND b."InstallationId" = e."InstallationId"
                            AND l."IsActive"
                            AND l."RevokedAt" IS NULL
                            AND (l."ExpirationDate" IS NULL OR l."ExpirationDate" > CURRENT_TIMESTAMP)
                            AND s."HardwareId" ~ '^[0-9A-F]{16}$'
                            AND encode(sha256(convert_to(s."HardwareId", 'UTF8')), 'hex') = candidate.details->>'hardwareIdV2Sha256'
                            AND e."State" = 'ACTIVE'
                            AND e."HardwareIdHash" = candidate.details->>'hardwareIdV2Sha256'
                            AND b."State" = 'active'
                            AND b."HardwareIdHash" = candidate.details->>'hardwareIdV2Sha256'
                        ) AS "AuthorityValid"
                    FROM migration_candidates candidate
                    JOIN "Licenses" l ON l."Id" = candidate."LicenseId"
                    JOIN "LicenseSeats" s
                      ON s."Id"::text = candidate.details->>'seatId'
                    JOIN "RuntimeEnrollments" e
                      ON e."Id"::text = candidate.details->>'enrollmentId'
                    JOIN "DistributionInstallationBindings" b
                      ON b."Id"::text = candidate.details->>'bindingId'
                    WHERE candidate.details->>'legacyHardwareIdSha256' ~ '^[0-9a-f]{64}$'
                      AND candidate.details->>'hardwareIdV2Sha256' ~ '^[0-9a-f]{64}$'
                    ORDER BY candidate."LicenseId", candidate.details->>'legacyHardwareIdSha256', candidate."CreatedAtUtc" DESC
                )
                INSERT INTO "HardwareAuthorityAliases" (
                    "Id", "ProductId", "LicenseId", "LicenseSeatId", "RuntimeEnrollmentId", "BindingId",
                    "MigrationRequestId", "LegacyHardwareIdSha256", "CanonicalHardwareIdSha256",
                    "SecurityEpoch", "AuthorityEpoch", "IsActive", "CreatedAtUtc", "DisabledAtUtc",
                    "LastObservedAtUtc", "ObservationCount")
                SELECT
                    candidate."AliasId", candidate."ProductId", candidate."LicenseId", candidate."LicenseSeatId",
                    candidate."RuntimeEnrollmentId", candidate."BindingId", NULL,
                    candidate."LegacyHardwareIdSha256", candidate."CanonicalHardwareIdSha256",
                    candidate."SecurityEpoch", candidate."AuthorityEpoch", candidate."AuthorityValid",
                    candidate."CreatedAtUtc",
                    CASE WHEN candidate."AuthorityValid" THEN NULL ELSE CURRENT_TIMESTAMP END,
                    NULL, 0
                FROM relational_candidates candidate;
                """);
        }

        /// <summary>
        /// Removes the compatibility aliases. Existing authoritative seats, bindings, and enrollments remain unchanged.
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "HardwareAuthorityAliases");
        }
    }
}

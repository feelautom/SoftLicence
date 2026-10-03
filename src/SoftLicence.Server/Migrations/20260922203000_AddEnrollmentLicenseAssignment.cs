using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Adds HWID-free commercial assignments and quarantines legacy graphs that cannot
/// be joined unambiguously from enrollment through binding to license and seat.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20260922203000_AddEnrollmentLicenseAssignment")]
public sealed class AddEnrollmentLicenseAssignment : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // The redundant composite key lets PostgreSQL enforce that an assignment's
        // seat belongs to its license, even for future direct or bulk writers.
        migrationBuilder.AddUniqueConstraint(
            name: "AK_LicenseSeats_Id_LicenseId",
            table: "LicenseSeats",
            columns: new[] { "Id", "LicenseId" });

        migrationBuilder.CreateTable(
            name: "EnrollmentLicenseAssignments",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                ActivatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                EndedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                Revision = table.Column<int>(type: "integer", nullable: false),
                EndReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EnrollmentLicenseAssignments", x => x.Id);
                table.ForeignKey("FK_EnrollmentLicenseAssignments_RuntimeEnrollments_EnrollmentId",
                    x => x.EnrollmentId, "RuntimeEnrollments", "Id", onDelete: ReferentialAction.Restrict);
                table.ForeignKey("FK_EnrollmentLicenseAssignments_Licenses_LicenseId",
                    x => x.LicenseId, "Licenses", "Id", onDelete: ReferentialAction.Restrict);
                table.ForeignKey("FK_EnrollmentLicenseAssignments_LicenseSeats_LicenseSeatId_LicenseId",
                    x => new { x.LicenseSeatId, x.LicenseId }, "LicenseSeats",
                    new[] { "Id", "LicenseId" }, onDelete: ReferentialAction.Restrict);
                table.CheckConstraint("CK_EnrollmentLicenseAssignments_Revision", "\"Revision\" >= 1");
                table.CheckConstraint("CK_EnrollmentLicenseAssignments_StateAndTimes",
                    "(\"State\" = 'ACTIVE' AND \"EndedAtUtc\" IS NULL AND \"EndReason\" IS NULL) OR (\"State\" = 'ENDED' AND \"EndedAtUtc\" IS NOT NULL AND \"EndReason\" IS NOT NULL AND \"EndedAtUtc\" >= \"ActivatedAtUtc\")");
                table.CheckConstraint("CK_EnrollmentLicenseAssignments_EndReason",
                    "\"EndReason\" IS NULL OR length(\"EndReason\") BETWEEN 1 AND 64");
            });

        migrationBuilder.CreateTable(
            name: "EnrollmentLicenseAssignmentQuarantines",
            columns: table => new
            {
                EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                BindingId = table.Column<Guid>(type: "uuid", nullable: true),
                LicenseId = table.Column<Guid>(type: "uuid", nullable: true),
                LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: true),
                Reason = table.Column<string>(type: "character varying(48)", maxLength: 48, nullable: false),
                ObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EnrollmentLicenseAssignmentQuarantines", x => x.EnrollmentId);
                table.ForeignKey("FK_EnrollmentLicenseAssignmentQuarantines_RuntimeEnrollments_EnrollmentId",
                    x => x.EnrollmentId, "RuntimeEnrollments", "Id", onDelete: ReferentialAction.Restrict);
                table.CheckConstraint("CK_EnrollmentLicenseAssignmentQuarantines_Reason",
                    "\"Reason\" IN ('binding_missing', 'binding_mismatch', 'seat_missing', 'seat_mismatch', 'license_missing', 'license_mismatch', 'live_state_mismatch', 'live_seat_ambiguous', 'terminal_time_invalid')");
            });

        migrationBuilder.CreateIndex("IX_EnrollmentLicenseAssignments_EnrollmentId_Revision",
            "EnrollmentLicenseAssignments", new[] { "EnrollmentId", "Revision" }, unique: true);
        migrationBuilder.CreateIndex("IX_EnrollmentLicenseAssignments_EnrollmentId",
            "EnrollmentLicenseAssignments", "EnrollmentId", unique: true, filter: "\"State\" = 'ACTIVE'");
        migrationBuilder.CreateIndex("IX_EnrollmentLicenseAssignments_LicenseSeatId",
            "EnrollmentLicenseAssignments", "LicenseSeatId", unique: true, filter: "\"State\" = 'ACTIVE'");
        migrationBuilder.CreateIndex("IX_EnrollmentLicenseAssignments_LicenseSeatId_LicenseId",
            "EnrollmentLicenseAssignments", new[] { "LicenseSeatId", "LicenseId" });
        migrationBuilder.CreateIndex("IX_EnrollmentLicenseAssignments_LicenseId_State",
            "EnrollmentLicenseAssignments", new[] { "LicenseId", "State" });
        migrationBuilder.CreateIndex("IX_EnrollmentLicenseAssignmentQuarantines_Reason",
            "EnrollmentLicenseAssignmentQuarantines", "Reason");

        // Test and production migrators may differ from the role that owns default
        // privileges. Explicit grants keep the application role able to read and
        // dual-write assignments while quarantine remains read-only to it.
        migrationBuilder.Sql("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                    REVOKE DELETE ON public."EnrollmentLicenseAssignments" FROM softlicence_app;
                    GRANT SELECT, INSERT, UPDATE ON public."EnrollmentLicenseAssignments" TO softlicence_app;
                    REVOKE ALL ON public."EnrollmentLicenseAssignmentQuarantines" FROM softlicence_app;
                    GRANT SELECT ON public."EnrollmentLicenseAssignmentQuarantines" TO softlicence_app;
                END IF;
            END $$;
            """);

        // The temporary classification is one migration-local snapshot. Every historical
        // enrollment receives exactly one assignment or one quarantine record. No HWID
        // comparison or arbitrary tie-breaker is used to infer commercial ownership.
        migrationBuilder.Sql("""
            CREATE TEMP TABLE "_EnrollmentAssignmentBackfill" ON COMMIT DROP AS
            WITH joined AS (
                SELECT e."Id" AS "EnrollmentId", e."BindingId", e."LicenseId" AS "EnrollmentLicenseId",
                       e."LicenseSeatId" AS "EnrollmentSeatId", e."ProductId" AS "EnrollmentProductId",
                       e."State" AS "EnrollmentState", e."InvalidatedAtUtc",
                       e."InstallationId" AS "EnrollmentInstallationId",
                       e."HandoffDigestSha256" AS "EnrollmentHandoffDigest",
                       e."ReleaseVersion" AS "EnrollmentReleaseVersion",
                       b."Id" AS "FoundBindingId", b."LicenseId" AS "BindingLicenseId",
                       b."LicenseSeatId" AS "BindingSeatId", b."ProductId" AS "BindingProductId",
                       b."State" AS "BindingState", b."BoundAtUtc",
                       b."InstallationId" AS "BindingInstallationId",
                       b."HandoffDigestSha256" AS "BindingHandoffDigest",
                       b."Version" AS "BindingReleaseVersion",
                       s."Id" AS "FoundSeatId", s."LicenseId" AS "SeatLicenseId", s."IsActive" AS "SeatActive",
                       l."Id" AS "FoundLicenseId", l."ProductId" AS "LicenseProductId"
                FROM "RuntimeEnrollments" e
                LEFT JOIN "DistributionInstallationBindings" b ON b."Id" = e."BindingId"
                LEFT JOIN "LicenseSeats" s ON s."Id" = b."LicenseSeatId"
                LEFT JOIN "Licenses" l ON l."Id" = b."LicenseId"
            ), counted AS (
                SELECT joined.*,
                       count(*) FILTER (WHERE "EnrollmentState" COLLATE "C" IN ('PENDING', 'ACTIVE')
                                         AND "BindingState" COLLATE "C" = 'active' AND "SeatActive") OVER
                           (PARTITION BY "BindingSeatId") AS "LiveSeatCount"
                FROM joined
            )
            SELECT counted.*,
                   CASE
                       WHEN "FoundBindingId" IS NULL THEN 'binding_missing'
                       WHEN "BindingLicenseId" <> "EnrollmentLicenseId"
                         OR "BindingSeatId" <> "EnrollmentSeatId"
                         OR "BindingProductId" <> "EnrollmentProductId"
                         OR "BindingInstallationId" COLLATE "C" <> "EnrollmentInstallationId" COLLATE "C"
                         OR "BindingHandoffDigest" COLLATE "C" <> "EnrollmentHandoffDigest" COLLATE "C"
                         OR "BindingReleaseVersion" COLLATE "C" <> "EnrollmentReleaseVersion" COLLATE "C" THEN 'binding_mismatch'
                       WHEN "FoundLicenseId" IS NULL THEN 'license_missing'
                       WHEN "LicenseProductId" <> "BindingProductId" THEN 'license_mismatch'
                       WHEN "FoundSeatId" IS NULL THEN 'seat_missing'
                       WHEN "SeatLicenseId" <> "BindingLicenseId" THEN 'seat_mismatch'
                       WHEN "EnrollmentState" COLLATE "C" = 'INVALIDATED'
                         AND ("InvalidatedAtUtc" IS NULL OR "InvalidatedAtUtc" < "BoundAtUtc") THEN 'terminal_time_invalid'
                       WHEN "EnrollmentState" COLLATE "C" = 'INVALIDATED' THEN NULL
                       WHEN "EnrollmentState" COLLATE "C" NOT IN ('PENDING', 'ACTIVE')
                         OR "BindingState" COLLATE "C" <> 'active' OR NOT "SeatActive" THEN 'live_state_mismatch'
                       WHEN "LiveSeatCount" <> 1 THEN 'live_seat_ambiguous'
                       ELSE NULL
                   END AS "QuarantineReason"
            FROM counted;

            INSERT INTO "EnrollmentLicenseAssignments"
                ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                 "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
            SELECT "EnrollmentId", "EnrollmentId", "BindingLicenseId", "BindingSeatId",
                   CASE WHEN "EnrollmentState" COLLATE "C" = 'INVALIDATED' THEN 'ENDED' ELSE 'ACTIVE' END,
                   "BoundAtUtc",
                   CASE WHEN "EnrollmentState" COLLATE "C" = 'INVALIDATED' THEN "InvalidatedAtUtc" ELSE NULL END,
                   1,
                   CASE WHEN "EnrollmentState" COLLATE "C" = 'INVALIDATED' THEN 'legacy_enrollment_invalidated' ELSE NULL END
            FROM "_EnrollmentAssignmentBackfill" WHERE "QuarantineReason" IS NULL;

            INSERT INTO "EnrollmentLicenseAssignmentQuarantines"
                ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId", "Reason", "ObservedAtUtc")
            SELECT "EnrollmentId", "BindingId", "EnrollmentLicenseId", "EnrollmentSeatId",
                   "QuarantineReason", now()
            FROM "_EnrollmentAssignmentBackfill" WHERE "QuarantineReason" IS NOT NULL;
            """);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // A downgrade must not silently erase either proven assignment history or
        // unresolved quarantine evidence after the initial backfill has run.
        migrationBuilder.Sql("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM public."EnrollmentLicenseAssignments")
                   OR EXISTS (SELECT 1 FROM public."EnrollmentLicenseAssignmentQuarantines") THEN
                    RAISE EXCEPTION 'Enrollment assignment rollback requires explicit data reconciliation';
                END IF;
            END $$;
            """);
        migrationBuilder.DropTable("EnrollmentLicenseAssignmentQuarantines");
        migrationBuilder.DropTable("EnrollmentLicenseAssignments");
        migrationBuilder.DropUniqueConstraint("AK_LicenseSeats_Id_LicenseId", "LicenseSeats");
    }
}

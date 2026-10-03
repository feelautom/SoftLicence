using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Freezes the server's first-receipt hardware linkage for security-lock reports and denies
/// irreversible decisions without historical proof or a previously committed live ban.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20260923011500_AddSecurityLockReportLinkProof")]
public sealed class AddSecurityLockReportLinkProof : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // This table lock closes the installation/backfill interval. A report writer either commits
        // before the migration and remains UNKNOWN_LEGACY or is captured by the installed trigger.
        migrationBuilder.Sql("""
            SET LOCAL lock_timeout = '15s';
            LOCK TABLE public."SecurityLockReports" IN SHARE ROW EXCLUSIVE MODE;
            DO $preflight$
            BEGIN
                IF EXISTS (SELECT 1 FROM public."SecurityLockReports"
                           WHERE "State" = 'BANNED' AND "AdminDecision" = 'RELEASE') THEN
                    RAISE EXCEPTION 'security-lock report has BANNED state with RELEASE decision'
                        USING ERRCODE = '23514';
                END IF;
            END;
            $preflight$;

            ALTER TABLE public."SecurityLockReports"
                ADD COLUMN "LinkStatus" character varying(20) NOT NULL DEFAULT 'UNKNOWN_LEGACY',
                ADD COLUMN "LinkAssignmentId" uuid NULL,
                ADD COLUMN "LinkLicenseSeatId" uuid NULL,
                ADD COLUMN "LinkAliasId" uuid NULL,
                ADD COLUMN "LinkVerifiedAtUtc" timestamptz NULL,
                ADD COLUMN "LinkReasonCode" character varying(64) NULL DEFAULT 'legacy_unknown';
            UPDATE public."SecurityLockReports"
               SET "LinkStatus" = 'UNKNOWN_LEGACY', "LinkReasonCode" = 'legacy_unknown';
            ALTER TABLE public."SecurityLockReports"
                ADD CONSTRAINT "FK_SecurityLockReports_LinkAssignment"
                    FOREIGN KEY ("LinkAssignmentId") REFERENCES public."EnrollmentLicenseAssignments" ("Id") ON DELETE RESTRICT,
                ADD CONSTRAINT "FK_SecurityLockReports_LinkSeat"
                    FOREIGN KEY ("LinkLicenseSeatId") REFERENCES public."LicenseSeats" ("Id") ON DELETE RESTRICT,
                ADD CONSTRAINT "FK_SecurityLockReports_LinkAlias"
                    FOREIGN KEY ("LinkAliasId") REFERENCES public."HardwareAuthorityAliases" ("Id") ON DELETE RESTRICT,
                ADD CONSTRAINT "CK_SecurityLockReports_LinkProof" CHECK (
                    ("LinkStatus" = 'UNKNOWN_LEGACY' AND "LinkVerifiedAtUtc" IS NULL AND "LinkAssignmentId" IS NULL AND "LinkLicenseSeatId" IS NULL AND "LinkAliasId" IS NULL AND "LinkReasonCode" = 'legacy_unknown')
                    OR ("LinkStatus" = 'UNLINKED' AND "LinkVerifiedAtUtc" IS NOT NULL AND "LinkAssignmentId" IS NULL AND "LinkLicenseSeatId" IS NULL AND "LinkAliasId" IS NULL AND "LinkReasonCode" IN ('enrollment_mismatch','assignment_missing','assignment_ambiguous','assignment_relation_missing','hardware_unlinked','alias_ambiguous'))
                    OR ("LinkStatus" = 'VERIFIED_SEAT' AND "LinkVerifiedAtUtc" IS NOT NULL AND "LinkAssignmentId" IS NOT NULL AND "LinkLicenseSeatId" IS NOT NULL AND "LinkAliasId" IS NULL AND "LinkReasonCode" IS NULL)
                    OR ("LinkStatus" = 'VERIFIED_ALIAS' AND "LinkVerifiedAtUtc" IS NOT NULL AND "LinkAssignmentId" IS NOT NULL AND "LinkLicenseSeatId" IS NOT NULL AND "LinkAliasId" IS NOT NULL AND "LinkReasonCode" IS NULL)),
                ADD CONSTRAINT "CK_SecurityLockReports_BanDecision" CHECK (
                    "State" <> 'BANNED' OR "AdminDecision" IS DISTINCT FROM 'RELEASE');

            CREATE FUNCTION public.guard_security_lock_report_identity()
            RETURNS trigger LANGUAGE plpgsql
            SET search_path = pg_catalog, pg_temp
            AS $guard$
            BEGIN
                IF NEW."ProductId" IS DISTINCT FROM OLD."ProductId"
                   OR NEW."EnrollmentId" IS DISTINCT FROM OLD."EnrollmentId"
                   OR NEW."BindingId" IS DISTINCT FROM OLD."BindingId"
                   OR NEW."InstallationId" IS DISTINCT FROM OLD."InstallationId"
                   OR NEW."HardwareId" IS DISTINCT FROM OLD."HardwareId"
                   OR NEW."AppVersion" IS DISTINCT FROM OLD."AppVersion"
                   OR NEW."LockId" IS DISTINCT FROM OLD."LockId"
                   OR NEW."Cause" IS DISTINCT FROM OLD."Cause"
                   OR NEW."Level" IS DISTINCT FROM OLD."Level"
                   OR NEW."EvidenceDigestSha256" IS DISTINCT FROM OLD."EvidenceDigestSha256"
                   OR NEW."FirstSeenUtc" IS DISTINCT FROM OLD."FirstSeenUtc"
                   OR NEW."FirstReportedUtc" IS DISTINCT FROM OLD."FirstReportedUtc" THEN
                    RAISE EXCEPTION 'security-lock report identity is immutable' USING ERRCODE = '23514';
                END IF;
                IF NEW."LinkStatus" IS DISTINCT FROM OLD."LinkStatus"
                   OR NEW."LinkAssignmentId" IS DISTINCT FROM OLD."LinkAssignmentId"
                   OR NEW."LinkLicenseSeatId" IS DISTINCT FROM OLD."LinkLicenseSeatId"
                   OR NEW."LinkAliasId" IS DISTINCT FROM OLD."LinkAliasId"
                   OR NEW."LinkVerifiedAtUtc" IS DISTINCT FROM OLD."LinkVerifiedAtUtc"
                   OR NEW."LinkReasonCode" IS DISTINCT FROM OLD."LinkReasonCode" THEN
                    RAISE EXCEPTION 'security-lock first-receipt proof is immutable'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END;
            $guard$;

            CREATE TRIGGER "TR_SecurityLockReports_ImmutableIdentity"
            BEFORE UPDATE ON public."SecurityLockReports" FOR EACH ROW
            EXECUTE FUNCTION public.guard_security_lock_report_identity();

            CREATE FUNCTION public.capture_security_lock_report_link()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $capture$
            DECLARE
                enrollment_row public."RuntimeEnrollments"%ROWTYPE;
                assignment_row public."EnrollmentLicenseAssignments"%ROWTYPE;
                seat_row public."LicenseSeats"%ROWTYPE;
                license_row public."Licenses"%ROWTYPE;
                alias_id uuid;
                alias_count integer := 0;
                assignment_count integer := 0;
                link_status text := 'UNLINKED';
                link_reason text := 'assignment_missing';
                link_assignment_id uuid;
                link_seat_id uuid;
                link_alias_id uuid;
                verified_at timestamptz;
                legacy_digest text;
                seat_digest text;
            BEGIN
                -- The item-2 assignment trigger takes the exclusive half of this key at commit.
                -- NOWAIT row locks below abort/retry instead of deadlocking against a writer
                -- that already holds a seat or alias row and waits for the exclusive half.
                PERFORM pg_catalog.pg_advisory_xact_lock_shared(1312, 1);
                SELECT * INTO enrollment_row FROM public."RuntimeEnrollments"
                 WHERE "Id" = NEW."EnrollmentId" FOR SHARE NOWAIT;
                -- This DB clock reading follows the authority lock. FirstReportedUtc
                -- was staged earlier and may precede it under contention.
                verified_at := pg_catalog.clock_timestamp();
                IF NOT FOUND OR enrollment_row."ProductId" IS DISTINCT FROM NEW."ProductId"
                   OR enrollment_row."BindingId" IS DISTINCT FROM NEW."BindingId"
                   OR enrollment_row."InstallationId" COLLATE "C" IS DISTINCT FROM NEW."InstallationId" COLLATE "C" THEN
                    link_reason := 'enrollment_mismatch';
                ELSE
                    FOR assignment_row IN
                        SELECT * FROM public."EnrollmentLicenseAssignments"
                         WHERE "EnrollmentId" = NEW."EnrollmentId" AND "State" = 'ACTIVE'
                         ORDER BY "Id" FOR SHARE NOWAIT
                    LOOP
                        assignment_count := assignment_count + 1;
                        EXIT WHEN assignment_count > 1;
                    END LOOP;
                    IF assignment_count > 1 THEN
                        link_reason := 'assignment_ambiguous';
                    ELSIF assignment_count = 1 THEN
                        SELECT * INTO seat_row FROM public."LicenseSeats"
                         WHERE "Id" = assignment_row."LicenseSeatId" FOR SHARE NOWAIT;
                        IF NOT FOUND THEN
                            link_reason := 'assignment_relation_missing';
                        ELSE
                            SELECT * INTO license_row FROM public."Licenses"
                             WHERE "Id" = assignment_row."LicenseId" FOR SHARE NOWAIT;
                            IF NOT FOUND OR seat_row."LicenseId" IS DISTINCT FROM assignment_row."LicenseId"
                               OR license_row."ProductId" IS DISTINCT FROM NEW."ProductId"
                               OR NOT seat_row."IsActive"
                               OR seat_row."FirstActivatedAt" > verified_at
                               OR seat_row."UnlinkedAt" <= verified_at THEN
                                link_reason := 'assignment_relation_missing';
                            ELSIF pg_catalog.upper(seat_row."HardwareId") = NEW."HardwareId" THEN
                                link_status := 'VERIFIED_SEAT';
                                link_reason := NULL;
                                link_assignment_id := assignment_row."Id";
                                link_seat_id := seat_row."Id";
                            ELSE
                                legacy_digest := pg_catalog.encode(pg_catalog.sha256(
                                    pg_catalog.convert_to(NEW."HardwareId", 'UTF8')), 'hex');
                                seat_digest := pg_catalog.encode(pg_catalog.sha256(
                                    pg_catalog.convert_to(seat_row."HardwareId", 'UTF8')), 'hex');
                                FOR alias_id IN
                                    SELECT alias."Id" FROM public."HardwareAuthorityAliases" alias
                                     WHERE alias."ProductId" = NEW."ProductId"
                                       AND alias."LicenseId" = assignment_row."LicenseId"
                                       AND alias."LicenseSeatId" = seat_row."Id"
                                       AND alias."RuntimeEnrollmentId" = NEW."EnrollmentId"
                                       AND alias."BindingId" = NEW."BindingId"
                                       AND alias."LegacyHardwareIdSha256" = legacy_digest
                                       AND alias."CanonicalHardwareIdSha256" = seat_digest
                                       AND alias."SecurityEpoch" <= enrollment_row."SecurityEpoch"
                                       AND alias."IsActive" AND alias."DisabledAtUtc" IS NULL
                                       AND alias."CreatedAtUtc" <= verified_at
                                     ORDER BY alias."Id" FOR SHARE NOWAIT
                                LOOP
                                    alias_count := alias_count + 1;
                                    link_alias_id := alias_id;
                                    EXIT WHEN alias_count > 1;
                                END LOOP;
                                IF alias_count = 1 THEN
                                    link_status := 'VERIFIED_ALIAS';
                                    link_reason := NULL;
                                    link_assignment_id := assignment_row."Id";
                                    link_seat_id := seat_row."Id";
                                ELSIF alias_count > 1 THEN
                                    link_alias_id := NULL;
                                    link_reason := 'alias_ambiguous';
                                ELSE
                                    link_reason := 'hardware_unlinked';
                                END IF;
                            END IF;
                        END IF;
                    END IF;
                END IF;
                -- Every caller-supplied proof value is discarded before table CHECK/FK
                -- constraints. This is the sole INSERT trigger for this evidence.
                NEW."LinkStatus" := link_status;
                NEW."LinkAssignmentId" := link_assignment_id;
                NEW."LinkLicenseSeatId" := link_seat_id;
                NEW."LinkAliasId" := link_alias_id;
                NEW."LinkVerifiedAtUtc" := verified_at;
                NEW."LinkReasonCode" := link_reason;
                RETURN NEW;
            END;
            $capture$;
            REVOKE ALL ON FUNCTION public.capture_security_lock_report_link() FROM PUBLIC;
            CREATE TRIGGER "TR_SecurityLockReports_CaptureLink"
            BEFORE INSERT ON public."SecurityLockReports" FOR EACH ROW
            EXECUTE FUNCTION public.capture_security_lock_report_link();

            CREATE FUNCTION public.guard_security_lock_report_ban()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $ban$
            DECLARE
                report_row public."SecurityLockReports"%ROWTYPE;
            BEGIN
                SELECT * INTO report_row FROM public."SecurityLockReports" WHERE "Id" = NEW."Id";
                IF report_row."State" = 'BANNED'
                   AND report_row."LinkStatus" NOT IN ('VERIFIED_SEAT', 'VERIFIED_ALIAS')
                   AND NOT EXISTS (
                       SELECT 1 FROM public."BannedHardwareIds" ban
                        WHERE pg_catalog.upper(ban."HardwareId") = report_row."HardwareId"
                          AND ban."IsActive"
                          AND (ban."ProductId" IS NULL OR ban."ProductId" = report_row."ProductId")
                          AND (ban."ExpiresAt" IS NULL OR ban."ExpiresAt" > pg_catalog.clock_timestamp())
                          -- A ban staged by this transaction (including an EF savepoint
                          -- subtransaction) is not visible in the transaction snapshot.
                          AND pg_catalog.pg_visible_in_snapshot(
                              ban.xmin::text::xid8, pg_catalog.pg_current_snapshot())) THEN
                    RAISE EXCEPTION 'security-lock ban lacks first-receipt proof or a prior live ban'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NULL;
            END;
            $ban$;
            REVOKE ALL ON FUNCTION public.guard_security_lock_report_ban() FROM PUBLIC;
            CREATE CONSTRAINT TRIGGER "TR_SecurityLockReports_BanProof"
            AFTER INSERT OR UPDATE ON public."SecurityLockReports"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
            EXECUTE FUNCTION public.guard_security_lock_report_ban();

            DO $grants$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                    REVOKE ALL ON public."SecurityLockReports" FROM softlicence_app;
                    GRANT SELECT, INSERT ON public."SecurityLockReports" TO softlicence_app;
                    GRANT UPDATE ("ClientMode", "EffectiveMode", "LastReportedUtc", "ReportCount",
                                  "State", "LastVerdict", "AdminDecision", "AdminDecisionAtUtc",
                                  "AdminDecisionBy", "AdminDecisionReason")
                        ON public."SecurityLockReports" TO softlicence_app;
                END IF;
            END;
            $grants$;
            """);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Any post-upgrade report has frozen evidence or an explicit negative result. Dropping it
        // would let an older binary reinterpret mutable seats, so rollback needs separate approval.
        migrationBuilder.Sql("""
            DO $guard$
            BEGIN
                IF EXISTS (SELECT 1 FROM public."SecurityLockReports"
                           WHERE "LinkStatus" <> 'UNKNOWN_LEGACY') THEN
                    RAISE EXCEPTION 'security-lock proof rollback would discard first-receipt evidence'
                        USING ERRCODE = '23514';
                END IF;
            END;
            $guard$;
            DROP TRIGGER "TR_SecurityLockReports_BanProof" ON public."SecurityLockReports";
            DROP FUNCTION public.guard_security_lock_report_ban();
            DROP TRIGGER "TR_SecurityLockReports_CaptureLink" ON public."SecurityLockReports";
            DROP FUNCTION public.capture_security_lock_report_link();
            DROP TRIGGER "TR_SecurityLockReports_ImmutableIdentity" ON public."SecurityLockReports";
            DROP FUNCTION public.guard_security_lock_report_identity();
            ALTER TABLE public."SecurityLockReports"
                DROP CONSTRAINT "CK_SecurityLockReports_BanDecision",
                DROP CONSTRAINT "CK_SecurityLockReports_LinkProof",
                DROP CONSTRAINT "FK_SecurityLockReports_LinkAlias",
                DROP CONSTRAINT "FK_SecurityLockReports_LinkSeat",
                DROP CONSTRAINT "FK_SecurityLockReports_LinkAssignment",
                DROP COLUMN "LinkReasonCode", DROP COLUMN "LinkVerifiedAtUtc",
                DROP COLUMN "LinkAliasId", DROP COLUMN "LinkLicenseSeatId",
                DROP COLUMN "LinkAssignmentId", DROP COLUMN "LinkStatus";
            DO $grants$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                    REVOKE ALL ON public."SecurityLockReports" FROM softlicence_app;
                    REVOKE UPDATE ("ClientMode", "EffectiveMode", "LastReportedUtc", "ReportCount",
                                   "State", "LastVerdict", "AdminDecision", "AdminDecisionAtUtc",
                                   "AdminDecisionBy", "AdminDecisionReason")
                        ON public."SecurityLockReports" FROM softlicence_app;
                    GRANT SELECT, INSERT, UPDATE, DELETE ON public."SecurityLockReports" TO softlicence_app;
                END IF;
            END;
            $grants$;
            """);
    }
}

using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Reconciles post-backfill legacy writes and keeps commercial assignment history
/// in the same PostgreSQL transaction as every enrollment mutation.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20260922213000_AddEnrollmentAssignmentDualWrite")]
public sealed class AddEnrollmentAssignmentDualWrite : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Locks on all four authority sources close the interval between the item-1
        // snapshot and trigger installation. A concurrent writer either commits
        // before catch-up sees it or waits for the committed triggers. The entire
        // migration, including trigger creation and catch-up, is one EF transaction.
        // The assignment lock also excludes direct DML until its app-role grant is
        // revoked. Keep this bounded: a busy production database needs a planned
        // migration window, not an indefinitely waiting deployment.
        migrationBuilder.Sql("""
            SET LOCAL lock_timeout = '15s';
            DO $lock$
            BEGIN
                LOCK TABLE public."Licenses",
                           public."LicenseSeats",
                           public."DistributionInstallationBindings",
                           public."RuntimeEnrollments",
                           public."EnrollmentLicenseAssignments"
                IN SHARE ROW EXCLUSIVE MODE;
            EXCEPTION WHEN lock_not_available THEN
                RAISE EXCEPTION
                    'Enrollment assignment migration could not lock authority tables within 15 seconds'
                    USING ERRCODE = '55P03';
            END;
            $lock$;

            DO $grants$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = 'softlicence_app'
                ) THEN
                    REVOKE ALL ON public."EnrollmentLicenseAssignments" FROM softlicence_app;
                    GRANT SELECT ON public."EnrollmentLicenseAssignments" TO softlicence_app;
                END IF;
            END;
            $grants$;

            CREATE FUNCTION public.sync_enrollment_license_assignment(
                p_enrollment_id uuid, p_catchup boolean)
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
            DECLARE
                row_data record;
                active_assignment record;
                prior_revision integer;
                live_claimants integer;
                quarantine_reason text;
                diagnostic_prefix text;
                observed_at timestamptz := clock_timestamp();
            BEGIN
                -- One transaction-wide lock serializes seat transfers and concurrent
                -- legacy writers. Partial unique indexes remain the final guard.
                PERFORM pg_advisory_xact_lock(1312, 1);

                SELECT e."Id" AS enrollment_id, e."BindingId" AS binding_id,
                       e."LicenseId" AS enrollment_license_id,
                       e."LicenseSeatId" AS enrollment_seat_id,
                       e."ProductId" AS enrollment_product_id,
                       e."State" AS enrollment_state,
                       e."InvalidatedAtUtc" AS invalidated_at,
                       e."InstallationId" AS enrollment_installation_id,
                       e."HandoffDigestSha256" AS enrollment_handoff_digest,
                       e."ReleaseVersion" AS enrollment_release_version,
                       b."Id" AS found_binding_id, b."LicenseId" AS binding_license_id,
                       b."LicenseSeatId" AS binding_seat_id,
                       b."ProductId" AS binding_product_id,
                       b."State" AS binding_state, b."BoundAtUtc" AS bound_at,
                       b."InstallationId" AS binding_installation_id,
                       b."HandoffDigestSha256" AS binding_handoff_digest,
                       b."Version" AS binding_release_version,
                       s."Id" AS found_seat_id, s."LicenseId" AS seat_license_id,
                       s."IsActive" AS seat_active,
                       l."Id" AS found_license_id, l."ProductId" AS license_product_id,
                       l."IsActive" AS license_active,
                       l."RevokedAt" AS license_revoked_at
                INTO row_data
                FROM public."RuntimeEnrollments" e
                LEFT JOIN public."DistributionInstallationBindings" b ON b."Id" = e."BindingId"
                LEFT JOIN public."LicenseSeats" s ON s."Id" = b."LicenseSeatId"
                LEFT JOIN public."Licenses" l ON l."Id" = b."LicenseId"
                WHERE e."Id" = p_enrollment_id;
                IF NOT FOUND THEN
                    RETURN;
                END IF;
                diagnostic_prefix := pg_catalog.format(
                    'enrollment=%s seat=%s reason=',
                    p_enrollment_id, COALESCE(row_data.binding_seat_id::text, 'none'));

                SELECT count(*) INTO live_claimants
                FROM public."RuntimeEnrollments" claimant
                JOIN public."DistributionInstallationBindings" binding
                  ON binding."Id" = claimant."BindingId"
                JOIN public."LicenseSeats" seat ON seat."Id" = binding."LicenseSeatId"
                WHERE binding."LicenseSeatId" = row_data.binding_seat_id
                  AND claimant."State" COLLATE "C" IN ('PENDING', 'ACTIVE')
                  AND binding."State" COLLATE "C" = 'active'
                  AND seat."IsActive";

                quarantine_reason := CASE
                    WHEN row_data.found_binding_id IS NULL THEN 'binding_missing'
                    WHEN row_data.binding_license_id IS DISTINCT FROM row_data.enrollment_license_id
                      OR row_data.binding_seat_id IS DISTINCT FROM row_data.enrollment_seat_id
                      OR row_data.binding_product_id IS DISTINCT FROM row_data.enrollment_product_id
                      OR row_data.binding_installation_id COLLATE "C"
                           IS DISTINCT FROM row_data.enrollment_installation_id COLLATE "C"
                      OR row_data.binding_handoff_digest COLLATE "C"
                           IS DISTINCT FROM row_data.enrollment_handoff_digest COLLATE "C"
                      OR row_data.binding_release_version COLLATE "C"
                           IS DISTINCT FROM row_data.enrollment_release_version COLLATE "C"
                        THEN 'binding_mismatch'
                    WHEN row_data.found_license_id IS NULL THEN 'license_missing'
                    WHEN row_data.license_product_id IS DISTINCT FROM row_data.binding_product_id
                        THEN 'license_mismatch'
                    WHEN row_data.found_seat_id IS NULL THEN 'seat_missing'
                    WHEN row_data.seat_license_id IS DISTINCT FROM row_data.binding_license_id
                        THEN 'seat_mismatch'
                    WHEN row_data.enrollment_state COLLATE "C" = 'INVALIDATED'
                      AND (row_data.invalidated_at IS NULL
                        OR row_data.invalidated_at < row_data.bound_at)
                        THEN 'terminal_time_invalid'
                    WHEN row_data.enrollment_state COLLATE "C" = 'INVALIDATED' THEN NULL
                    WHEN row_data.enrollment_state COLLATE "C" NOT IN ('PENDING', 'ACTIVE')
                      OR row_data.binding_state COLLATE "C" <> 'active'
                      OR NOT row_data.seat_active THEN 'live_state_mismatch'
                    WHEN live_claimants <> 1 THEN 'live_seat_ambiguous'
                    ELSE NULL
                END;

                IF quarantine_reason = 'live_seat_ambiguous' THEN
                    -- Historical ambiguity is quarantined during catch-up. A new
                    -- runtime conflict aborts its whole transaction for retry or
                    -- explicit refusal; no valid write is silently quarantined.
                    IF NOT p_catchup THEN
                        RAISE EXCEPTION 'concurrent commercial seat claimant'
                            USING ERRCODE = '40001',
                                  DETAIL = diagnostic_prefix || 'live_seat_ambiguous';
                    END IF;
                    UPDATE public."EnrollmentLicenseAssignments" assignment
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, assignment."ActivatedAtUtc"),
                        "EndReason" = 'live_seat_ambiguous'
                    WHERE assignment."LicenseSeatId" = row_data.binding_seat_id
                      AND assignment."State" = 'ACTIVE';

                    INSERT INTO public."EnrollmentLicenseAssignmentQuarantines"
                        ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId",
                         "Reason", "ObservedAtUtc")
                    SELECT claimant."Id", claimant."BindingId", claimant."LicenseId",
                           claimant."LicenseSeatId", 'live_seat_ambiguous', observed_at
                    FROM public."RuntimeEnrollments" claimant
                    JOIN public."DistributionInstallationBindings" binding
                      ON binding."Id" = claimant."BindingId"
                    WHERE binding."LicenseSeatId" = row_data.binding_seat_id
                      AND claimant."State" COLLATE "C" IN ('PENDING', 'ACTIVE')
                    ON CONFLICT ("EnrollmentId") DO NOTHING;
                    RETURN;
                END IF;

                SELECT * INTO active_assignment
                FROM public."EnrollmentLicenseAssignments"
                WHERE "EnrollmentId" = p_enrollment_id AND "State" = 'ACTIVE'
                FOR UPDATE;

                -- Commercial revocation and binding/seat release can be written
                -- without touching RuntimeEnrollments. They end the right without
                -- changing cryptographic enrollment or signed generations.
                IF row_data.found_license_id IS NOT NULL
                   AND (quarantine_reason IS NULL
                     OR quarantine_reason = 'live_state_mismatch')
                   AND (NOT row_data.license_active
                     OR row_data.license_revoked_at IS NOT NULL
                     OR row_data.binding_state COLLATE "C" <> 'active'
                     OR NOT row_data.seat_active)
                   AND row_data.enrollment_state COLLATE "C" IN ('PENDING', 'ACTIVE') THEN
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, "ActivatedAtUtc"),
                        "EndReason" = CASE
                            WHEN NOT row_data.license_active
                              OR row_data.license_revoked_at IS NOT NULL THEN 'license_revoked'
                            WHEN NOT row_data.seat_active THEN 'seat_released'
                            ELSE 'binding_invalidated' END
                    WHERE "EnrollmentId" = p_enrollment_id AND "State" = 'ACTIVE';
                    RETURN;
                END IF;

                IF quarantine_reason IS NOT NULL THEN
                    -- Terminal rows may be historical or a present revocation.
                    -- Revoke only a right that actually exists, then quarantine
                    -- the divergent graph. Never synthesize terminal history or
                    -- a grant from a malformed terminal enrollment. A malformed
                    -- live write still aborts instead of silently quarantining.
                    IF row_data.enrollment_state COLLATE "C" = 'INVALIDATED' THEN
                        UPDATE public."EnrollmentLicenseAssignments"
                        SET "State" = 'ENDED',
                            "EndedAtUtc" = GREATEST(observed_at, "ActivatedAtUtc"),
                            "EndReason" = 'terminal_graph_diverged'
                        WHERE "EnrollmentId" = p_enrollment_id AND "State" = 'ACTIVE';
                        INSERT INTO public."EnrollmentLicenseAssignmentQuarantines"
                            ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId",
                             "Reason", "ObservedAtUtc")
                        VALUES (p_enrollment_id, row_data.binding_id,
                                row_data.enrollment_license_id, row_data.enrollment_seat_id,
                                quarantine_reason, observed_at)
                        ON CONFLICT ("EnrollmentId") DO NOTHING;
                        RETURN;
                    END IF;
                    IF NOT p_catchup THEN
                        RAISE EXCEPTION 'unresolved commercial assignment graph: %',
                            quarantine_reason
                            USING ERRCODE = '23514',
                                  DETAIL = diagnostic_prefix || quarantine_reason;
                    END IF;
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, "ActivatedAtUtc"),
                        "EndReason" = 'legacy_graph_diverged'
                    WHERE "EnrollmentId" = p_enrollment_id AND "State" = 'ACTIVE';
                    INSERT INTO public."EnrollmentLicenseAssignmentQuarantines"
                        ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId",
                         "Reason", "ObservedAtUtc")
                    VALUES (p_enrollment_id, row_data.binding_id,
                            row_data.enrollment_license_id, row_data.enrollment_seat_id,
                            quarantine_reason, observed_at)
                    ON CONFLICT ("EnrollmentId") DO NOTHING;
                    RETURN;
                END IF;

                -- A quarantine is a durable human-reconciliation boundary. A later
                -- graph repair cannot silently turn the old diagnostic into a grant.
                IF EXISTS (
                    SELECT 1 FROM public."EnrollmentLicenseAssignmentQuarantines"
                    WHERE "EnrollmentId" = p_enrollment_id
                ) THEN
                    IF NOT p_catchup THEN
                        RAISE EXCEPTION 'commercial assignment remains quarantined'
                            USING ERRCODE = '23514',
                                  DETAIL = diagnostic_prefix || 'enrollment_quarantined';
                    END IF;
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, "ActivatedAtUtc"),
                        "EndReason" = 'enrollment_quarantined'
                    WHERE "EnrollmentId" = p_enrollment_id AND "State" = 'ACTIVE';
                    RETURN;
                END IF;

                IF row_data.enrollment_state COLLATE "C" IN ('PENDING', 'ACTIVE')
                   AND EXISTS (
                       SELECT 1 FROM public."EnrollmentLicenseAssignments"
                       WHERE "EnrollmentId" = p_enrollment_id
                         AND "State" = 'ENDED'
                         AND "EndReason" IN (
                             'enrollment_invalidated', 'legacy_enrollment_invalidated')
                   ) THEN
                    IF NOT p_catchup THEN
                        RAISE EXCEPTION 'terminal enrollment cannot regain commercial authority'
                            USING ERRCODE = '23514',
                                  DETAIL = diagnostic_prefix || 'terminal_resurrection';
                    END IF;
                    INSERT INTO public."EnrollmentLicenseAssignmentQuarantines"
                        ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId",
                         "Reason", "ObservedAtUtc")
                    VALUES (p_enrollment_id, row_data.binding_id,
                            row_data.enrollment_license_id, row_data.enrollment_seat_id,
                            'live_state_mismatch', observed_at)
                    ON CONFLICT ("EnrollmentId") DO NOTHING;
                    RETURN;
                END IF;

                IF row_data.enrollment_state COLLATE "C" = 'INVALIDATED' THEN
                    IF active_assignment."Id" IS NOT NULL THEN
                        IF row_data.invalidated_at < active_assignment."ActivatedAtUtc" THEN
                            IF NOT p_catchup THEN
                                RAISE EXCEPTION 'terminal time precedes assignment activation'
                                    USING ERRCODE = '23514',
                                          DETAIL = diagnostic_prefix || 'terminal_time_invalid';
                            END IF;
                            INSERT INTO public."EnrollmentLicenseAssignmentQuarantines"
                                ("EnrollmentId", "BindingId", "LicenseId", "LicenseSeatId",
                                 "Reason", "ObservedAtUtc")
                            VALUES (p_enrollment_id, row_data.binding_id,
                                    row_data.enrollment_license_id, row_data.enrollment_seat_id,
                                    'terminal_time_invalid', observed_at)
                            ON CONFLICT ("EnrollmentId") DO NOTHING;
                            RETURN;
                        END IF;
                        UPDATE public."EnrollmentLicenseAssignments"
                        SET "State" = 'ENDED',
                            "EndedAtUtc" = GREATEST(row_data.invalidated_at, "ActivatedAtUtc"),
                            "EndReason" = 'enrollment_invalidated'
                        WHERE "Id" = active_assignment."Id";
                    ELSIF NOT EXISTS (
                        SELECT 1 FROM public."EnrollmentLicenseAssignments"
                        WHERE "EnrollmentId" = p_enrollment_id
                    ) THEN
                        INSERT INTO public."EnrollmentLicenseAssignments"
                            ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                             "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
                        VALUES (p_enrollment_id, p_enrollment_id,
                                row_data.binding_license_id, row_data.binding_seat_id,
                                'ENDED', row_data.bound_at, row_data.invalidated_at,
                                1, 'legacy_enrollment_invalidated');
                    END IF;
                    RETURN;
                END IF;

                IF active_assignment."Id" IS NOT NULL
                   AND active_assignment."LicenseId" = row_data.binding_license_id
                   AND active_assignment."LicenseSeatId" = row_data.binding_seat_id THEN
                    -- A same-key hardware change touches only legacy hardware fields.
                    -- It must not revise assignment history or enrollment epochs.
                    RETURN;
                END IF;

                IF active_assignment."Id" IS NOT NULL THEN
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, "ActivatedAtUtc"),
                        "EndReason" = 'commercial_transfer'
                    WHERE "Id" = active_assignment."Id";
                END IF;

                -- A transfer may create the successor before the source trigger
                -- fires. Deferred execution sees its final terminal state.
                IF EXISTS (
                    SELECT 1
                    FROM public."EnrollmentLicenseAssignments" previous
                    JOIN public."RuntimeEnrollments" source
                      ON source."Id" = previous."EnrollmentId"
                    WHERE previous."LicenseSeatId" = row_data.binding_seat_id
                      AND previous."EnrollmentId" <> p_enrollment_id
                      AND previous."State" = 'ACTIVE'
                      AND source."State" COLLATE "C" = 'INVALIDATED'
                      AND (source."InvalidatedAtUtc" IS NULL
                        OR source."InvalidatedAtUtc" < previous."ActivatedAtUtc")
                ) THEN
                    RAISE EXCEPTION 'predecessor terminal time is invalid'
                        USING ERRCODE = '23514',
                              DETAIL = diagnostic_prefix || 'predecessor_terminal_time_invalid';
                END IF;
                UPDATE public."EnrollmentLicenseAssignments" previous
                SET "State" = 'ENDED',
                    "EndedAtUtc" = source."InvalidatedAtUtc",
                    "EndReason" = 'enrollment_invalidated'
                FROM public."RuntimeEnrollments" source
                WHERE previous."LicenseSeatId" = row_data.binding_seat_id
                  AND previous."EnrollmentId" = source."Id"
                  AND previous."EnrollmentId" <> p_enrollment_id
                  AND previous."State" = 'ACTIVE'
                  AND source."State" COLLATE "C" = 'INVALIDATED';

                IF EXISTS (
                    SELECT 1 FROM public."EnrollmentLicenseAssignments"
                    WHERE "LicenseSeatId" = row_data.binding_seat_id
                      AND "EnrollmentId" <> p_enrollment_id AND "State" = 'ACTIVE'
                ) THEN
                    RAISE EXCEPTION 'commercial seat has an unresolved active assignment'
                        USING ERRCODE = '40001',
                              DETAIL = diagnostic_prefix || 'active_assignment_conflict';
                END IF;

                SELECT COALESCE(max("Revision"), 0) INTO prior_revision
                FROM public."EnrollmentLicenseAssignments"
                WHERE "EnrollmentId" = p_enrollment_id;
                INSERT INTO public."EnrollmentLicenseAssignments"
                    ("Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                     "ActivatedAtUtc", "EndedAtUtc", "Revision", "EndReason")
                VALUES (CASE WHEN prior_revision = 0 THEN p_enrollment_id
                             ELSE pg_catalog.gen_random_uuid() END,
                        p_enrollment_id, row_data.binding_license_id,
                        row_data.binding_seat_id, 'ACTIVE',
                        CASE WHEN prior_revision = 0 THEN row_data.bound_at
                             ELSE GREATEST(observed_at, row_data.bound_at) END,
                        NULL, prior_revision + 1, NULL);
            END;
            $function$;

            CREATE FUNCTION public.sync_enrollment_license_assignment_trigger()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
            BEGIN
                IF TG_OP = 'UPDATE' THEN
                    IF TG_TABLE_NAME = 'RuntimeEnrollments' THEN
                        IF NEW."State" IS NOT DISTINCT FROM OLD."State"
                           AND NEW."BindingId" IS NOT DISTINCT FROM OLD."BindingId"
                           AND NEW."ProductId" IS NOT DISTINCT FROM OLD."ProductId"
                           AND NEW."LicenseId" IS NOT DISTINCT FROM OLD."LicenseId"
                           AND NEW."LicenseSeatId" IS NOT DISTINCT FROM OLD."LicenseSeatId"
                           AND NEW."InstallationId" IS NOT DISTINCT FROM OLD."InstallationId"
                           AND NEW."HandoffDigestSha256" IS NOT DISTINCT FROM OLD."HandoffDigestSha256"
                           AND NEW."ReleaseVersion" IS NOT DISTINCT FROM OLD."ReleaseVersion"
                           AND NEW."InvalidatedAtUtc" IS NOT DISTINCT FROM OLD."InvalidatedAtUtc"
                            THEN RETURN NULL;
                        END IF;
                    ELSIF TG_TABLE_NAME = 'DistributionInstallationBindings' THEN
                        IF NEW."State" IS NOT DISTINCT FROM OLD."State"
                           AND NEW."ProductId" IS NOT DISTINCT FROM OLD."ProductId"
                           AND NEW."LicenseId" IS NOT DISTINCT FROM OLD."LicenseId"
                           AND NEW."LicenseSeatId" IS NOT DISTINCT FROM OLD."LicenseSeatId"
                           AND NEW."BoundAtUtc" IS NOT DISTINCT FROM OLD."BoundAtUtc"
                           AND NEW."InstallationId" IS NOT DISTINCT FROM OLD."InstallationId"
                           AND NEW."HandoffDigestSha256" IS NOT DISTINCT FROM OLD."HandoffDigestSha256"
                           AND NEW."Version" IS NOT DISTINCT FROM OLD."Version"
                            THEN RETURN NULL;
                        END IF;
                    ELSIF TG_TABLE_NAME = 'LicenseSeats' THEN
                        IF NEW."LicenseId" IS NOT DISTINCT FROM OLD."LicenseId"
                           AND NEW."IsActive" IS NOT DISTINCT FROM OLD."IsActive"
                            THEN RETURN NULL;
                        END IF;
                    ELSIF TG_TABLE_NAME = 'Licenses' THEN
                        IF NEW."ProductId" IS NOT DISTINCT FROM OLD."ProductId"
                           AND NEW."IsActive" IS NOT DISTINCT FROM OLD."IsActive"
                           AND NEW."RevokedAt" IS NOT DISTINCT FROM OLD."RevokedAt"
                            THEN RETURN NULL;
                        END IF;
                    END IF;
                END IF;
                IF TG_TABLE_NAME = 'RuntimeEnrollments' THEN
                    PERFORM public.sync_enrollment_license_assignment(NEW."Id", false);
                ELSIF TG_TABLE_NAME = 'DistributionInstallationBindings' THEN
                    PERFORM public.sync_enrollment_license_assignment(enrollment."Id", false)
                    FROM public."RuntimeEnrollments" enrollment
                    WHERE enrollment."BindingId" = NEW."Id";
                ELSIF TG_TABLE_NAME = 'LicenseSeats' THEN
                    PERFORM public.sync_enrollment_license_assignment(enrollment."Id", false)
                    FROM public."RuntimeEnrollments" enrollment
                    WHERE enrollment."LicenseSeatId" = NEW."Id";
                ELSIF TG_TABLE_NAME = 'Licenses' THEN
                    PERFORM public.sync_enrollment_license_assignment(enrollment."Id", false)
                    FROM public."RuntimeEnrollments" enrollment
                    WHERE enrollment."LicenseId" = NEW."Id";
                END IF;
                RETURN NULL;
            END;
            $function$;

            REVOKE ALL ON FUNCTION public.sync_enrollment_license_assignment(uuid, boolean) FROM PUBLIC;
            REVOKE ALL ON FUNCTION public.sync_enrollment_license_assignment_trigger() FROM PUBLIC;

            -- Mutation coverage:
            -- RuntimeEnrollments INSERT/UPDATE: creation, confirmation, replacement,
            -- transfer, invalidation and old binary writers.
            -- DistributionInstallationBindings INSERT/UPDATE: supersession,
            -- invalidation, restoration and commercial binding retargeting.
            -- LicenseSeats INSERT/UPDATE: seat activation, release and reassignment.
            -- Licenses INSERT/UPDATE: revocation, reactivation and product changes.
            -- FK restrictions prevent hard deletion of referenced authority rows.
            -- Hardware-only updates execute but leave a matching assignment intact.
            CREATE CONSTRAINT TRIGGER "TR_RuntimeEnrollments_AssignmentDualWrite"
            AFTER INSERT OR UPDATE ON public."RuntimeEnrollments"
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION public.sync_enrollment_license_assignment_trigger();

            CREATE CONSTRAINT TRIGGER "TR_DistributionBindings_AssignmentDualWrite"
            AFTER INSERT OR UPDATE ON public."DistributionInstallationBindings"
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION public.sync_enrollment_license_assignment_trigger();

            CREATE CONSTRAINT TRIGGER "TR_LicenseSeats_AssignmentDualWrite"
            AFTER INSERT OR UPDATE ON public."LicenseSeats"
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION public.sync_enrollment_license_assignment_trigger();

            CREATE CONSTRAINT TRIGGER "TR_Licenses_AssignmentDualWrite"
            AFTER INSERT OR UPDATE ON public."Licenses"
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION public.sync_enrollment_license_assignment_trigger();

            -- Revisit every row, including rows already backfilled: legacy binaries
            -- may have changed their state or commercial IDs after the item-1 snapshot.
            DO $catchup$
            DECLARE enrollment_id uuid;
            BEGIN
                FOR enrollment_id IN
                    SELECT "Id" FROM public."RuntimeEnrollments" ORDER BY "Id"
                LOOP
                    PERFORM public.sync_enrollment_license_assignment(enrollment_id, true);
                END LOOP;
            END;
            $catchup$;
            """);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Removing this trigger while legacy writers exist would reopen a silent
        // assignment gap. An operator must explicitly reconcile before downgrade.
        migrationBuilder.Sql("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM public."EnrollmentLicenseAssignments")
                   OR EXISTS (SELECT 1 FROM public."EnrollmentLicenseAssignmentQuarantines") THEN
                    RAISE EXCEPTION 'Enrollment dual-write rollback requires explicit data reconciliation';
                END IF;
            END $$;
            DROP TRIGGER "TR_RuntimeEnrollments_AssignmentDualWrite" ON public."RuntimeEnrollments";
            DROP TRIGGER "TR_DistributionBindings_AssignmentDualWrite" ON public."DistributionInstallationBindings";
            DROP TRIGGER "TR_LicenseSeats_AssignmentDualWrite" ON public."LicenseSeats";
            DROP TRIGGER "TR_Licenses_AssignmentDualWrite" ON public."Licenses";
            DROP FUNCTION public.sync_enrollment_license_assignment_trigger();
            DROP FUNCTION public.sync_enrollment_license_assignment(uuid, boolean);
            -- Restore the item-1 transitional contract on an allowed empty
            -- rollback. That migration granted SELECT/INSERT/UPDATE only.
            DO $grants$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = 'softlicence_app'
                ) THEN
                    REVOKE ALL ON public."EnrollmentLicenseAssignments" FROM softlicence_app;
                    GRANT SELECT, INSERT, UPDATE
                        ON public."EnrollmentLicenseAssignments" TO softlicence_app;
                END IF;
            END;
            $grants$;
            """);
    }
}

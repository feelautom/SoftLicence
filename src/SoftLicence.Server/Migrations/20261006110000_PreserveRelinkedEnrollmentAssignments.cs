using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Makes the explicit current assignment authoritative after a Runtime enrollment is commercially
/// relinked, while retaining the installation binding as immutable historical evidence.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20261006110000_PreserveRelinkedEnrollmentAssignments")]
public sealed class PreserveRelinkedEnrollmentAssignments : Migration
{
    /// <summary>
    /// Routes licence and seat mutations through the active assignment and prevents an old binding,
    /// including a quarantined migration row, from ending a valid explicit successor.
    /// The privileged writer checks time-dependent authority only after its row locks are acquired;
    /// lock contention must not extend a licence or entitlement beyond its persisted expiration.
    /// </summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            CREATE FUNCTION public.sync_current_enrollment_license_assignment(p_enrollment_id uuid)
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
            DECLARE
                enrollment_state text;
                enrollment_product_id uuid;
                enrollment_binding_id uuid;
                enrollment_installation_id text;
                enrollment_handoff_digest text;
                enrollment_release_version text;
                historical_license_id uuid;
                historical_seat_id uuid;
                binding_license_id uuid;
                binding_seat_id uuid;
                binding_product_id uuid;
                binding_installation_id text;
                binding_handoff_digest text;
                binding_release_version text;
                assignment_id uuid;
                assignment_license_id uuid;
                assignment_seat_id uuid;
                assignment_activated_at timestamp with time zone;
                historical_quarantine_exists boolean;
                seat_license_id uuid;
                seat_active boolean;
                license_product_id uuid;
                license_active boolean;
                license_revoked_at timestamp with time zone;
                observed_at timestamp with time zone := pg_catalog.clock_timestamp();
            BEGIN
                SELECT enrollment."State", enrollment."ProductId", enrollment."BindingId",
                       enrollment."InstallationId", enrollment."HandoffDigestSha256",
                       enrollment."ReleaseVersion", enrollment."LicenseId",
                       enrollment."LicenseSeatId"
                INTO enrollment_state, enrollment_product_id, enrollment_binding_id,
                     enrollment_installation_id, enrollment_handoff_digest,
                     enrollment_release_version, historical_license_id, historical_seat_id
                FROM public."RuntimeEnrollments" enrollment
                WHERE enrollment."Id" = p_enrollment_id;
                IF NOT FOUND THEN
                    RETURN;
                END IF;

                SELECT assignment."Id", assignment."LicenseId", assignment."LicenseSeatId",
                       assignment."ActivatedAtUtc"
                INTO assignment_id, assignment_license_id, assignment_seat_id,
                     assignment_activated_at
                FROM public."EnrollmentLicenseAssignments" assignment
                WHERE assignment."EnrollmentId" = p_enrollment_id
                  AND assignment."State" = 'ACTIVE'
                FOR UPDATE;

                IF NOT FOUND THEN
                    PERFORM public.sync_enrollment_license_assignment(p_enrollment_id, false);
                    RETURN;
                END IF;

                SELECT EXISTS (
                    SELECT 1
                    FROM public."EnrollmentLicenseAssignmentQuarantines" quarantine
                    WHERE quarantine."EnrollmentId" = p_enrollment_id
                )
                INTO historical_quarantine_exists;

                IF assignment_license_id = historical_license_id
                   AND assignment_seat_id = historical_seat_id
                   AND NOT historical_quarantine_exists THEN
                    PERFORM public.sync_enrollment_license_assignment(p_enrollment_id, false);
                    RETURN;
                END IF;

                IF enrollment_state COLLATE "C" NOT IN ('PENDING', 'ACTIVE') THEN
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, assignment_activated_at),
                        "EndReason" = 'enrollment_invalidated'
                    WHERE "Id" = assignment_id AND "State" = 'ACTIVE';
                    RETURN;
                END IF;

                SELECT seat."LicenseId", seat."IsActive"
                INTO seat_license_id, seat_active
                FROM public."LicenseSeats" seat
                WHERE seat."Id" = assignment_seat_id;
                IF NOT FOUND OR seat_license_id IS DISTINCT FROM assignment_license_id THEN
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, assignment_activated_at),
                        "EndReason" = 'commercial_transfer'
                    WHERE "Id" = assignment_id AND "State" = 'ACTIVE';
                    RETURN;
                END IF;

                SELECT license."ProductId", license."IsActive", license."RevokedAt"
                INTO license_product_id, license_active, license_revoked_at
                FROM public."Licenses" license
                WHERE license."Id" = assignment_license_id;
                IF NOT FOUND OR license_product_id IS DISTINCT FROM enrollment_product_id THEN
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, assignment_activated_at),
                        "EndReason" = 'commercial_transfer'
                    WHERE "Id" = assignment_id AND "State" = 'ACTIVE';
                    RETURN;
                END IF;

                IF NOT license_active OR license_revoked_at IS NOT NULL THEN
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, assignment_activated_at),
                        "EndReason" = 'license_revoked'
                    WHERE "Id" = assignment_id AND "State" = 'ACTIVE';
                    RETURN;
                END IF;

                IF NOT seat_active THEN
                    UPDATE public."EnrollmentLicenseAssignments"
                    SET "State" = 'ENDED',
                        "EndedAtUtc" = GREATEST(observed_at, assignment_activated_at),
                        "EndReason" = 'seat_released'
                    WHERE "Id" = assignment_id AND "State" = 'ACTIVE';
                    RETURN;
                END IF;

                -- A migration quarantine is retained as historical evidence only. Once the server
                -- has authorized an explicit successor, that old verdict cannot veto the current
                -- right. Non-quarantined graph corruption remains rejected for live assignments.
                IF NOT historical_quarantine_exists THEN
                    SELECT binding."LicenseId", binding."LicenseSeatId", binding."ProductId",
                           binding."InstallationId", binding."HandoffDigestSha256", binding."Version"
                    INTO binding_license_id, binding_seat_id, binding_product_id,
                         binding_installation_id, binding_handoff_digest, binding_release_version
                    FROM public."DistributionInstallationBindings" binding
                    WHERE binding."Id" = enrollment_binding_id;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION 'unresolved commercial assignment graph: binding_missing'
                            USING ERRCODE = '23514';
                    END IF;
                    IF binding_license_id IS DISTINCT FROM historical_license_id
                       OR binding_seat_id IS DISTINCT FROM historical_seat_id
                       OR binding_product_id IS DISTINCT FROM enrollment_product_id
                       OR binding_installation_id COLLATE "C"
                            IS DISTINCT FROM enrollment_installation_id COLLATE "C"
                       OR binding_handoff_digest COLLATE "C"
                            IS DISTINCT FROM enrollment_handoff_digest COLLATE "C"
                       OR binding_release_version COLLATE "C"
                            IS DISTINCT FROM enrollment_release_version COLLATE "C" THEN
                        RAISE EXCEPTION 'unresolved commercial assignment graph: binding_mismatch'
                            USING ERRCODE = '23514';
                    END IF;
                END IF;
            END;
            $function$;

            CREATE FUNCTION public.relink_runtime_commercial_assignment(
                p_enrollment_id uuid,
                p_license_id uuid,
                p_seat_id uuid,
                p_subject_ref_digest_sha256 text,
                p_authenticated_client_id text,
                p_distribution_entitlement_id uuid,
                p_recovery_grant_digest_sha256 text,
                p_recovery_owner_subject_id uuid)
            RETURNS uuid
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
            DECLARE
                enrollment_state text;
                enrollment_product_id uuid;
                enrollment_subject_digest text;
                license_product_id uuid;
                license_active boolean;
                license_revoked_at timestamp with time zone;
                license_expiration_date timestamp without time zone;
                license_max_seats integer;
                seat_license_id uuid;
                seat_active boolean;
                active_seat_count integer;
                authority_valid boolean;
                current_assignment_id uuid;
                current_license_id uuid;
                current_seat_id uuid;
                next_revision integer;
                inserted_assignment_id uuid;
                observed_at timestamp with time zone;
            BEGIN
                SELECT enrollment."State", enrollment."ProductId", enrollment."SubjectRefDigestSha256"
                INTO enrollment_state, enrollment_product_id, enrollment_subject_digest
                FROM public."RuntimeEnrollments" enrollment
                WHERE enrollment."Id" = p_enrollment_id
                FOR UPDATE;
                IF NOT FOUND
                   OR enrollment_state COLLATE "C" NOT IN ('PENDING', 'ACTIVE')
                   OR enrollment_subject_digest IS DISTINCT FROM p_subject_ref_digest_sha256 THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE = 'runtime_commercial_relink_enrollment_ineligible';
                END IF;

                SELECT license."ProductId", license."IsActive", license."RevokedAt",
                       license."ExpirationDate", license."MaxSeats"
                INTO license_product_id, license_active, license_revoked_at,
                     license_expiration_date, license_max_seats
                FROM public."Licenses" license
                WHERE license."Id" = p_license_id
                FOR UPDATE;
                IF NOT FOUND
                   OR license_product_id IS DISTINCT FROM enrollment_product_id
                   OR NOT license_active
                   OR license_revoked_at IS NOT NULL
                   OR license_max_seats < 1 THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE = 'runtime_commercial_relink_license_ineligible';
                END IF;

                SELECT seat."LicenseId", seat."IsActive"
                INTO seat_license_id, seat_active
                FROM public."LicenseSeats" seat
                WHERE seat."Id" = p_seat_id
                FOR UPDATE;
                IF NOT FOUND OR seat_license_id IS DISTINCT FROM p_license_id OR NOT seat_active THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE = 'runtime_commercial_relink_seat_ineligible';
                END IF;

                -- Acquire the final potentially blocking row lock before sampling the clock.
                -- A timestamp taken on function entry would let contention extend expired
                -- authority and backdate the successor's activation.
                SELECT assignment."Id", assignment."LicenseId", assignment."LicenseSeatId"
                INTO current_assignment_id, current_license_id, current_seat_id
                FROM public."EnrollmentLicenseAssignments" assignment
                WHERE assignment."EnrollmentId" = p_enrollment_id
                  AND assignment."State" = 'ACTIVE'
                ORDER BY assignment."Id"
                FOR UPDATE;

                observed_at := pg_catalog.clock_timestamp();
                IF license_expiration_date IS NOT NULL
                   AND license_expiration_date <= observed_at AT TIME ZONE 'UTC' THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE = 'runtime_commercial_relink_license_ineligible';
                END IF;

                SELECT COUNT(*)
                INTO active_seat_count
                FROM public."LicenseSeats" seat
                WHERE seat."LicenseId" = p_license_id AND seat."IsActive";
                IF active_seat_count > license_max_seats THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE = 'runtime_commercial_relink_seat_capacity_exceeded';
                END IF;

                authority_valid := (
                    p_distribution_entitlement_id IS NOT NULL
                    AND p_recovery_grant_digest_sha256 IS NULL
                    AND p_recovery_owner_subject_id IS NULL
                    AND EXISTS (
                        SELECT 1
                        FROM public."DistributionEntitlements" entitlement
                        WHERE entitlement."Id" = p_distribution_entitlement_id
                          AND entitlement."ClientId" = p_authenticated_client_id
                          AND entitlement."ProductId" = enrollment_product_id
                          AND entitlement."LicenseId" = p_license_id
                          AND entitlement."SubjectRefDigestSha256" = p_subject_ref_digest_sha256
                          AND entitlement."State" IN ('issued', 'finalized')
                          AND entitlement."ExpiresAtUtc" > observed_at
                    )
                ) OR (
                    p_distribution_entitlement_id IS NULL
                    AND p_recovery_grant_digest_sha256 IS NOT NULL
                    AND p_recovery_owner_subject_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1
                        FROM public."RuntimeRecoveryGrantOwnerships" grant_row
                        INNER JOIN public."RuntimeRecoveryCommercialOwnerships" owner_row
                            ON owner_row."Id" = grant_row."CommercialOwnershipId"
                        WHERE grant_row."ProductId" = enrollment_product_id
                          AND grant_row."ProviderGrantRefDigestSha256" = p_recovery_grant_digest_sha256
                          AND grant_row."AuthenticatedClientId" = p_authenticated_client_id
                          AND grant_row."LicenseId" = p_license_id
                          AND grant_row."OwnerSubjectId" = p_recovery_owner_subject_id
                          AND owner_row."ProductId" = enrollment_product_id
                          AND owner_row."LicenseId" = p_license_id
                          AND owner_row."OwnerSubjectId" = p_recovery_owner_subject_id
                          AND owner_row."State" = 'ACTIVE'
                          AND pg_catalog.encode(
                              pg_catalog.sha256(
                                  pg_catalog.decode(
                                      '534f46544c4943454e43450052554e54494d452d5245434f564552592d4f574e4552005631',
                                      'hex')
                                  || pg_catalog.decode('0a', 'hex')
                                  || pg_catalog.convert_to(p_recovery_owner_subject_id::text, 'UTF8')),
                              'hex') = p_subject_ref_digest_sha256
                    )
                );
                IF NOT authority_valid THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE = 'runtime_commercial_relink_authority_ineligible';
                END IF;

                -- Later authority queries change FOUND; the locked assignment identifier is
                -- the stable presence evidence for this idempotent return.
                IF current_assignment_id IS NOT NULL THEN
                    IF current_license_id IS NOT DISTINCT FROM p_license_id
                       AND current_seat_id IS NOT DISTINCT FROM p_seat_id THEN
                        RETURN current_assignment_id;
                    END IF;
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE = 'runtime_commercial_relink_assignment_conflict';
                END IF;

                SELECT COALESCE(MAX(assignment."Revision"), 0) + 1
                INTO next_revision
                FROM public."EnrollmentLicenseAssignments" assignment
                WHERE assignment."EnrollmentId" = p_enrollment_id;

                INSERT INTO public."EnrollmentLicenseAssignments" (
                    "Id", "EnrollmentId", "LicenseId", "LicenseSeatId", "State",
                    "ActivatedAtUtc", "EndedAtUtc", "EndReason", "Revision")
                VALUES (
                    pg_catalog.gen_random_uuid(), p_enrollment_id, p_license_id, p_seat_id, 'ACTIVE',
                    observed_at, NULL, NULL, next_revision)
                RETURNING "Id" INTO inserted_assignment_id;
                RETURN inserted_assignment_id;
            END;
            $function$;

            CREATE OR REPLACE FUNCTION public.sync_enrollment_license_assignment_trigger()
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
                    IF TG_OP = 'UPDATE'
                       AND (NEW."LicenseId" IS DISTINCT FROM OLD."LicenseId"
                            OR NEW."LicenseSeatId" IS DISTINCT FROM OLD."LicenseSeatId")
                       AND EXISTS (
                           SELECT 1
                           FROM public."EnrollmentLicenseAssignments" assignment
                           WHERE assignment."EnrollmentId" = NEW."Id"
                             AND assignment."State" = 'ACTIVE'
                             AND assignment."LicenseId" IS NOT DISTINCT FROM OLD."LicenseId"
                             AND assignment."LicenseSeatId" IS NOT DISTINCT FROM OLD."LicenseSeatId"
                       ) THEN
                        -- Preserve the historical transfer contract when the enrollment row itself
                        -- moves the current commercial tuple. An explicit Runtime relink never
                        -- rewrites that row, so its successor assignment continues through the
                        -- current-assignment path below.
                        PERFORM public.sync_enrollment_license_assignment(NEW."Id", false);
                    ELSE
                        PERFORM public.sync_current_enrollment_license_assignment(NEW."Id");
                    END IF;
                ELSIF TG_TABLE_NAME = 'DistributionInstallationBindings' THEN
                    PERFORM public.sync_current_enrollment_license_assignment(enrollment."Id")
                    FROM public."RuntimeEnrollments" enrollment
                    WHERE enrollment."BindingId" = NEW."Id";
                ELSIF TG_TABLE_NAME = 'LicenseSeats' THEN
                    PERFORM public.sync_current_enrollment_license_assignment(scope."EnrollmentId")
                    FROM (
                        SELECT enrollment."Id" AS "EnrollmentId"
                        FROM public."RuntimeEnrollments" enrollment
                        WHERE enrollment."LicenseSeatId" = NEW."Id"
                        UNION
                        SELECT assignment."EnrollmentId"
                        FROM public."EnrollmentLicenseAssignments" assignment
                        WHERE assignment."LicenseSeatId" = NEW."Id"
                          AND assignment."State" = 'ACTIVE'
                    ) scope;
                ELSIF TG_TABLE_NAME = 'Licenses' THEN
                    PERFORM public.sync_current_enrollment_license_assignment(scope."EnrollmentId")
                    FROM (
                        SELECT enrollment."Id" AS "EnrollmentId"
                        FROM public."RuntimeEnrollments" enrollment
                        WHERE enrollment."LicenseId" = NEW."Id"
                        UNION
                        SELECT assignment."EnrollmentId"
                        FROM public."EnrollmentLicenseAssignments" assignment
                        WHERE assignment."LicenseId" = NEW."Id"
                          AND assignment."State" = 'ACTIVE'
                    ) scope;
                END IF;
                RETURN NULL;
            END;
            $function$;

            REVOKE ALL ON FUNCTION public.sync_current_enrollment_license_assignment(uuid) FROM PUBLIC;
            REVOKE ALL ON FUNCTION public.relink_runtime_commercial_assignment(
                uuid, uuid, uuid, text, text, uuid, text, uuid) FROM PUBLIC;
            REVOKE ALL ON FUNCTION public.sync_enrollment_license_assignment_trigger() FROM PUBLIC;
            DO $grant$
            BEGIN
                IF pg_catalog.to_regrole('softlicence_app') IS NOT NULL THEN
                    GRANT EXECUTE ON FUNCTION public.relink_runtime_commercial_assignment(
                        uuid, uuid, uuid, text, text, uuid, text, uuid)
                    TO softlicence_app;
                END IF;
            END;
            $grant$;
            """);
    }

    /// <summary>
    /// Restores the historical-binding router only when no successor depends on current-assignment semantics.
    /// </summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            -- The historical router cannot represent a successor assignment. Refuse before
            -- changing any function so the enclosing migration transaction remains lossless.
            DO $guard$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM public."EnrollmentLicenseAssignments" assignment
                    INNER JOIN public."RuntimeEnrollments" enrollment
                        ON enrollment."Id" = assignment."EnrollmentId"
                    WHERE assignment."State" = 'ACTIVE'
                      AND (
                          assignment."Revision" > 1
                          OR assignment."LicenseId" IS DISTINCT FROM enrollment."LicenseId"
                          OR assignment."LicenseSeatId" IS DISTINCT FROM enrollment."LicenseSeatId"
                          OR EXISTS (
                              SELECT 1
                              FROM public."EnrollmentLicenseAssignmentQuarantines" quarantine
                              WHERE quarantine."EnrollmentId" = assignment."EnrollmentId"))
                ) THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '55000',
                        MESSAGE = 'tkt001617_down_blocked_successor_assignments';
                END IF;
            END;
            $guard$;

            CREATE OR REPLACE FUNCTION public.sync_enrollment_license_assignment_trigger()
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

            REVOKE ALL ON FUNCTION public.sync_enrollment_license_assignment_trigger() FROM PUBLIC;
            DROP FUNCTION public.relink_runtime_commercial_assignment(
                uuid, uuid, uuid, text, text, uuid, text, uuid);
            DROP FUNCTION public.sync_current_enrollment_license_assignment(uuid);
            """);
    }
}

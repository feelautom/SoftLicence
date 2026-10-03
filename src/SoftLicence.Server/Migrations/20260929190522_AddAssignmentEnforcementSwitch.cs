using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddAssignmentEnforcementSwitch : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AssignmentEnforcementEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Source = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Control = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CaseNumber = table.Column<int>(type: "integer", nullable: true),
                    Reason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Action = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: true),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: true),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: true),
                    Detail = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    ObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AlertedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AssignmentEnforcementEvents", x => x.Id);
                    table.CheckConstraint("CK_AssignmentEnforcementEvents_CaseNumber", "\"CaseNumber\" IS NULL OR \"CaseNumber\" BETWEEN 1 AND 8");
                    table.CheckConstraint("CK_AssignmentEnforcementEvents_Source", "\"Source\" IN ('database', 'application')");
                });

            migrationBuilder.CreateTable(
                name: "AssignmentEnforcementSettings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    Mode = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AssignmentEnforcementSettings", x => x.Id);
                    table.CheckConstraint("CK_AssignmentEnforcementSettings_Mode", "\"Mode\" IN ('open', 'closed')");
                    table.CheckConstraint("CK_AssignmentEnforcementSettings_SingleRow", "\"Id\" = 1");
                });

            migrationBuilder.InsertData(
                table: "AssignmentEnforcementSettings",
                columns: new[] { "Id", "Mode", "UpdatedAtUtc", "UpdatedBy" },
                values: new object[] { 1, "open", new DateTime(2026, 9, 29, 0, 0, 0, 0, DateTimeKind.Utc), "migration" });

            migrationBuilder.CreateIndex(
                name: "IX_AssignmentEnforcementEvents_AlertedAtUtc",
                table: "AssignmentEnforcementEvents",
                column: "AlertedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AssignmentEnforcementEvents_EnrollmentId",
                table: "AssignmentEnforcementEvents",
                column: "EnrollmentId");

            migrationBuilder.CreateIndex(
                name: "IX_AssignmentEnforcementEvents_ObservedAtUtc",
                table: "AssignmentEnforcementEvents",
                column: "ObservedAtUtc");

            // TKT-001277 lot 2d (decided by Franck, 29/09/2026): every blocking branch of the commercial-assignment
            // trigger is kept verbatim behind a single open/closed switch. Open (default): the would-be block is
            // recorded in AssignmentEnforcementEvents (and as a PostgreSQL WARNING) and the right is produced as if
            // the operation were valid, when the data allows it. Closed: the original code runs unchanged.
            migrationBuilder.Sql("""
            CREATE OR REPLACE FUNCTION public.assignment_enforcement_is_open()
            RETURNS boolean
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
                SELECT COALESCE(
                    (SELECT "Mode" = 'open' FROM public."AssignmentEnforcementSettings" WHERE "Id" = 1),
                    true);
            $function$;

            CREATE OR REPLACE FUNCTION public.record_assignment_enforcement_event(
                p_case integer, p_reason text, p_action text, p_enrollment_id uuid,
                p_license_id uuid, p_seat_id uuid, p_detail text)
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
            BEGIN
                INSERT INTO public."AssignmentEnforcementEvents"
                    ("Source", "Control", "CaseNumber", "Reason", "Action", "EnrollmentId",
                     "LicenseId", "LicenseSeatId", "Detail", "ObservedAtUtc")
                VALUES ('database', 'assignment_trigger', p_case,
                        pg_catalog.left(COALESCE(p_reason, 'unknown'), 64),
                        pg_catalog.left(COALESCE(p_action, 'none'), 64),
                        p_enrollment_id, p_license_id, p_seat_id,
                        pg_catalog.left(COALESCE(p_detail, ''), 512),
                        pg_catalog.clock_timestamp());
                RAISE WARNING 'assignment control would have blocked (switch open): case=% reason=% action=% detail=%',
                    p_case, p_reason, p_action, p_detail;
            END;
            $function$;

            REVOKE ALL ON FUNCTION public.assignment_enforcement_is_open() FROM PUBLIC;
            REVOKE ALL ON FUNCTION public.record_assignment_enforcement_event(integer, text, text, uuid, uuid, uuid, text) FROM PUBLIC;

            DO $grants$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                    REVOKE ALL ON public."AssignmentEnforcementSettings" FROM softlicence_app;
                    GRANT SELECT, UPDATE ON public."AssignmentEnforcementSettings" TO softlicence_app;
                    REVOKE ALL ON public."AssignmentEnforcementEvents" FROM softlicence_app;
                    GRANT SELECT, INSERT, UPDATE ON public."AssignmentEnforcementEvents" TO softlicence_app;
                END IF;
            END;
            $grants$;

            CREATE OR REPLACE FUNCTION public.sync_enrollment_license_assignment(
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
                        IF public.assignment_enforcement_is_open() THEN
                            -- Open switch: would have blocked; the latest claimant takes the seat.
                            PERFORM public.record_assignment_enforcement_event(
                                6, 'live_seat_ambiguous', 'seat_taken_by_latest_claimant', p_enrollment_id,
                                row_data.binding_license_id, row_data.binding_seat_id,
                                diagnostic_prefix || 'live_seat_ambiguous');
                            UPDATE public."EnrollmentLicenseAssignments" assignment
                            SET "State" = 'ENDED',
                                "EndedAtUtc" = GREATEST(observed_at, assignment."ActivatedAtUtc"),
                                "EndReason" = 'fail_open_superseded'
                            WHERE assignment."LicenseSeatId" = row_data.binding_seat_id
                              AND assignment."EnrollmentId" <> p_enrollment_id
                              AND assignment."State" = 'ACTIVE';
                            quarantine_reason := NULL;
                        ELSE
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
                        IF public.assignment_enforcement_is_open() THEN
                            -- Open switch: would have blocked. The binding is the reference, so a
                            -- diverging enrollment copy is granted from it; missing rows cannot be granted.
                            IF quarantine_reason = 'binding_mismatch' THEN
                                PERFORM public.record_assignment_enforcement_event(
                                    1, quarantine_reason, 'granted_from_binding', p_enrollment_id,
                                    row_data.binding_license_id, row_data.binding_seat_id,
                                    diagnostic_prefix || quarantine_reason);
                                quarantine_reason := NULL;
                            ELSE
                                PERFORM public.record_assignment_enforcement_event(
                                    1, quarantine_reason, 'not_granted_graph_incomplete', p_enrollment_id,
                                    row_data.binding_license_id, row_data.binding_seat_id,
                                    diagnostic_prefix || quarantine_reason);
                                RETURN;
                            END IF;
                        ELSE
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
                    END IF;

                    -- A quarantine is a durable human-reconciliation boundary. A later
                    -- graph repair cannot silently turn the old diagnostic into a grant.
                    IF EXISTS (
                        SELECT 1 FROM public."EnrollmentLicenseAssignmentQuarantines"
                        WHERE "EnrollmentId" = p_enrollment_id
                    ) THEN
                        IF public.assignment_enforcement_is_open() THEN
                            PERFORM public.record_assignment_enforcement_event(
                                2, 'enrollment_quarantined', 'granted_despite_quarantine', p_enrollment_id,
                                row_data.binding_license_id, row_data.binding_seat_id,
                                diagnostic_prefix || 'enrollment_quarantined');
                        ELSE
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
                    END IF;

                    IF row_data.enrollment_state COLLATE "C" IN ('PENDING', 'ACTIVE')
                       AND EXISTS (
                           SELECT 1 FROM public."EnrollmentLicenseAssignments"
                           WHERE "EnrollmentId" = p_enrollment_id
                             AND "State" = 'ENDED'
                             AND "EndReason" IN (
                                 'enrollment_invalidated', 'legacy_enrollment_invalidated')
                       ) THEN
                        IF public.assignment_enforcement_is_open() THEN
                            PERFORM public.record_assignment_enforcement_event(
                                3, 'terminal_resurrection', 'granted_despite_terminal_history', p_enrollment_id,
                                row_data.binding_license_id, row_data.binding_seat_id,
                                diagnostic_prefix || 'terminal_resurrection');
                        ELSE
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
                    END IF;

                    IF row_data.enrollment_state COLLATE "C" = 'INVALIDATED' THEN
                        IF active_assignment."Id" IS NOT NULL THEN
                            IF row_data.invalidated_at < active_assignment."ActivatedAtUtc" THEN
                                IF public.assignment_enforcement_is_open() THEN
                                    PERFORM public.record_assignment_enforcement_event(
                                        4, 'terminal_time_invalid', 'ended_at_activation_time', p_enrollment_id,
                                        row_data.binding_license_id, row_data.binding_seat_id,
                                        diagnostic_prefix || 'terminal_time_invalid');
                                    UPDATE public."EnrollmentLicenseAssignments"
                                    SET "State" = 'ENDED',
                                        "EndedAtUtc" = "ActivatedAtUtc",
                                        "EndReason" = 'enrollment_invalidated'
                                    WHERE "Id" = active_assignment."Id";
                                    RETURN;
                                ELSE
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
                        IF public.assignment_enforcement_is_open() THEN
                            PERFORM public.record_assignment_enforcement_event(
                                5, 'predecessor_terminal_time_invalid', 'predecessor_ended_now', p_enrollment_id,
                                row_data.binding_license_id, row_data.binding_seat_id,
                                diagnostic_prefix || 'predecessor_terminal_time_invalid');
                            UPDATE public."EnrollmentLicenseAssignments" previous
                            SET "State" = 'ENDED',
                                "EndedAtUtc" = GREATEST(COALESCE(source."InvalidatedAtUtc", observed_at),
                                                        previous."ActivatedAtUtc"),
                                "EndReason" = 'enrollment_invalidated'
                            FROM public."RuntimeEnrollments" source
                            WHERE previous."LicenseSeatId" = row_data.binding_seat_id
                              AND previous."EnrollmentId" = source."Id"
                              AND previous."EnrollmentId" <> p_enrollment_id
                              AND previous."State" = 'ACTIVE'
                              AND source."State" COLLATE "C" = 'INVALIDATED'
                              AND (source."InvalidatedAtUtc" IS NULL
                                OR source."InvalidatedAtUtc" < previous."ActivatedAtUtc");
                        ELSE
                            RAISE EXCEPTION 'predecessor terminal time is invalid'
                                USING ERRCODE = '23514',
                                      DETAIL = diagnostic_prefix || 'predecessor_terminal_time_invalid';
                        END IF;
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
                        IF public.assignment_enforcement_is_open() THEN
                            PERFORM public.record_assignment_enforcement_event(
                                7, 'active_assignment_conflict', 'seat_taken_by_latest_claimant', p_enrollment_id,
                                row_data.binding_license_id, row_data.binding_seat_id,
                                diagnostic_prefix || 'active_assignment_conflict');
                            UPDATE public."EnrollmentLicenseAssignments"
                            SET "State" = 'ENDED',
                                "EndedAtUtc" = GREATEST(observed_at, "ActivatedAtUtc"),
                                "EndReason" = 'fail_open_superseded'
                            WHERE "LicenseSeatId" = row_data.binding_seat_id
                              AND "EnrollmentId" <> p_enrollment_id AND "State" = 'ACTIVE';
                        ELSE
                            RAISE EXCEPTION 'commercial seat has an unresolved active assignment'
                                USING ERRCODE = '40001',
                                      DETAIL = diagnostic_prefix || 'active_assignment_conflict';
                        END IF;
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
                EXCEPTION WHEN OTHERS THEN
                    IF public.assignment_enforcement_is_open() THEN
                        -- Case 8: unexpected error. This block is rolled back (no partial change),
                        -- the error is recorded and the customer write passes.
                        PERFORM public.record_assignment_enforcement_event(
                            8, 'unexpected_error', 'write_passed_without_change', p_enrollment_id,
                            NULL, NULL,
                            pg_catalog.format('enrollment=%s reason=unexpected_error sqlstate=%s message=%s',
                                p_enrollment_id, SQLSTATE, SQLERRM));
                    ELSE
                        RAISE;
                    END IF;
                END;
            END;
            $function$;

            -- Historical rows quarantined by the item-2 catch-up get a right now when the switch is open,
            -- each case being recorded; with a closed switch nothing changes.
            DO $regrant$
            DECLARE enrollment_id uuid;
            BEGIN
                IF public.assignment_enforcement_is_open() THEN
                    FOR enrollment_id IN
                        SELECT enrollment."Id" FROM public."RuntimeEnrollments" enrollment
                        WHERE enrollment."State" COLLATE "C" IN ('PENDING', 'ACTIVE')
                          AND NOT EXISTS (
                              SELECT 1 FROM public."EnrollmentLicenseAssignments" assignment
                              WHERE assignment."EnrollmentId" = enrollment."Id"
                                AND assignment."State" = 'ACTIVE')
                        ORDER BY enrollment."Id"
                    LOOP
                        PERFORM public.sync_enrollment_license_assignment(enrollment_id, false);
                    END LOOP;
                END IF;
            END;
            $regrant$;
            """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Restores the strict function of 20260922213000_AddEnrollmentAssignmentDualWrite verbatim.
            migrationBuilder.Sql("""
            CREATE OR REPLACE FUNCTION public.sync_enrollment_license_assignment(
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
            DROP FUNCTION public.record_assignment_enforcement_event(integer, text, text, uuid, uuid, uuid, text);
            DROP FUNCTION public.assignment_enforcement_is_open();
            """);

            migrationBuilder.DropTable(
                name: "AssignmentEnforcementEvents");

            migrationBuilder.DropTable(
                name: "AssignmentEnforcementSettings");
        }
    }
}

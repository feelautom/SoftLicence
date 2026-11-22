using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-002919: account relink by sign-in. Creates the <c>RuntimeAccountRelinkRequests</c> ledger (PENDING proof
    /// row inside the relink transaction, COMPLETED frozen response kept 30 days), admits the <c>account-relink</c>
    /// operation in the installation proof registry, and gives the relink writer a fourth authority proof that
    /// revalidates the PENDING row, the enrollment client, the machine and the registry owner of both licences.
    /// Signature, grants and the three earlier proofs are unchanged. Down restores the TKT-002904 writer exactly,
    /// then drops the table, the account-relink proof rows and the operation.
    /// </summary>
    public partial class AddRuntimeAccountRelink : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.CreateTable(
                name: "RuntimeAccountRelinkRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthenticatedClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    EnrollmentClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    BodyDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    OwnerSubjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    SubjectRefDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    ResponseBody = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeAccountRelinkRequests", x => x.Id);
                    table.CheckConstraint("CK_RuntimeAccountRelinkRequests_ClientIds", "\"AuthenticatedClientId\" ~ '^[a-z0-9][a-z0-9._-]{2,63}$' AND \"EnrollmentClientId\" ~ '^[a-z0-9][a-z0-9._-]{2,63}$' AND \"AuthenticatedClientId\" <> \"EnrollmentClientId\"");
                    table.CheckConstraint("CK_RuntimeAccountRelinkRequests_Digests", "\"BodyDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"SubjectRefDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RuntimeAccountRelinkRequests_State", "(\"State\" = 'PENDING' AND \"ResponseBody\" IS NULL AND \"CompletedAtUtc\" IS NULL) OR (\"State\" = 'COMPLETED' AND \"ResponseBody\" IS NOT NULL AND \"CompletedAtUtc\" IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_RuntimeAccountRelinkRequests_RuntimeEnrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade', 'rollback', 'websetup-upgrade', 'hardware-authority-migration', 'account-relink')");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeAccountRelinkRequests_AuthenticatedClientId_RequestId",
                table: "RuntimeAccountRelinkRequests",
                columns: new[] { "AuthenticatedClientId", "RequestId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeAccountRelinkRequests_CompletedAtUtc",
                table: "RuntimeAccountRelinkRequests",
                column: "CompletedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeAccountRelinkRequests_EnrollmentId",
                table: "RuntimeAccountRelinkRequests",
                column: "EnrollmentId");

            // TKT-002919: fourth authority proof of the relink writer, after the table it reads exists.
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.relink_runtime_commercial_assignment(
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
                    enrollment_client_id text;
                    enrollment_license_id uuid;
                    enrollment_hardware_hash text;
                    seat_hardware_id text;
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
                    SELECT enrollment."State", enrollment."ProductId", enrollment."SubjectRefDigestSha256",
                           enrollment."ClientId", enrollment."LicenseId", enrollment."HardwareIdHash"
                    INTO enrollment_state, enrollment_product_id, enrollment_subject_digest,
                         enrollment_client_id, enrollment_license_id, enrollment_hardware_hash
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

                    SELECT seat."LicenseId", seat."IsActive", seat."HardwareId"
                    INTO seat_license_id, seat_active, seat_hardware_id
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
                    ) OR (
                        -- TKT-002904: capability request of the installation itself after a seat release.
                        -- Only the enrollment's own client, only a seat on the enrollment's own machine.
                        p_distribution_entitlement_id IS NULL
                        AND p_recovery_grant_digest_sha256 IS NULL
                        AND enrollment_state COLLATE "C" = 'ACTIVE'
                        AND enrollment_client_id = p_authenticated_client_id
                        AND seat_hardware_id IS NOT NULL
                        AND pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(seat_hardware_id, 'UTF8')),
                            'hex') = enrollment_hardware_hash
                        AND (
                            -- The installation's own licence, even without a registered owner.
                            p_license_id = enrollment_license_id
                            OR (
                                -- Another licence of the same active account owner, never for a licence whose
                                -- seats its administrator manages (key activation disabled, TKT-002475): neither
                                -- the installation licence nor the licence of the latest ended assignment.
                                p_recovery_owner_subject_id IS NOT NULL
                                AND NOT EXISTS (
                                    SELECT 1
                                    FROM public."LicenseKeyActivationSettings" setting
                                    WHERE setting."Disabled"
                                      AND (setting."LicenseId" = enrollment_license_id
                                           OR setting."LicenseId" = (
                                               SELECT ended."LicenseId"
                                               FROM public."EnrollmentLicenseAssignments" ended
                                               WHERE ended."EnrollmentId" = p_enrollment_id
                                                 AND ended."State" = 'ENDED'
                                               ORDER BY ended."Revision" DESC, ended."Id" DESC
                                               LIMIT 1))
                                )
                                AND EXISTS (
                                    SELECT 1
                                    FROM public."RuntimeRecoveryCommercialOwnerships" owner_row
                                    WHERE owner_row."ProductId" = enrollment_product_id
                                      AND owner_row."LicenseId" = enrollment_license_id
                                      AND owner_row."OwnerSubjectId" = p_recovery_owner_subject_id
                                      AND owner_row."State" = 'ACTIVE'
                                )
                                AND EXISTS (
                                    SELECT 1
                                    FROM public."RuntimeRecoveryCommercialOwnerships" owner_row
                                    WHERE owner_row."ProductId" = enrollment_product_id
                                      AND owner_row."LicenseId" = p_license_id
                                      AND owner_row."OwnerSubjectId" = p_recovery_owner_subject_id
                                      AND owner_row."State" = 'ACTIVE'
                                )
                            )
                        )
                    ) OR (
                        -- TKT-002919: account relink requested by the dedicated relink identity after the account
                        -- signed in inside the application. The application layer wrote a PENDING ledger row in this
                        -- same transaction after checking the installation proof, the account digest and the owner;
                        -- the writer revalidates that row and every relation it names, never the caller's word.
                        p_distribution_entitlement_id IS NULL
                        AND p_recovery_grant_digest_sha256 IS NULL
                        AND p_recovery_owner_subject_id IS NOT NULL
                        AND enrollment_state COLLATE "C" = 'ACTIVE'
                        AND seat_hardware_id IS NOT NULL
                        AND pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(seat_hardware_id, 'UTF8')),
                            'hex') = enrollment_hardware_hash
                        AND EXISTS (
                            SELECT 1
                            FROM public."RuntimeAccountRelinkRequests" relink
                            WHERE relink."AuthenticatedClientId" = p_authenticated_client_id
                              AND relink."EnrollmentClientId" = enrollment_client_id
                              AND relink."EnrollmentId" = p_enrollment_id
                              AND relink."ProductId" = enrollment_product_id
                              AND relink."LicenseId" = p_license_id
                              AND relink."OwnerSubjectId" = p_recovery_owner_subject_id
                              AND relink."SubjectRefDigestSha256" = p_subject_ref_digest_sha256
                              AND relink."State" = 'PENDING'
                              AND relink."CreatedAtUtc" > observed_at - interval '5 minutes'
                        )
                        AND EXISTS (
                            SELECT 1
                            FROM public."RuntimeRecoveryCommercialOwnerships" owner_row
                            WHERE owner_row."ProductId" = enrollment_product_id
                              AND owner_row."LicenseId" = p_license_id
                              AND owner_row."OwnerSubjectId" = p_recovery_owner_subject_id
                              AND owner_row."State" = 'ACTIVE'
                        )
                        AND EXISTS (
                            SELECT 1
                            FROM public."RuntimeRecoveryCommercialOwnerships" owner_row
                            WHERE owner_row."ProductId" = enrollment_product_id
                              AND owner_row."LicenseId" = enrollment_license_id
                              AND owner_row."OwnerSubjectId" = p_recovery_owner_subject_id
                              AND owner_row."State" = 'ACTIVE'
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
                REVOKE ALL ON FUNCTION public.relink_runtime_commercial_assignment(
                    uuid, uuid, uuid, text, text, uuid, text, uuid) FROM PUBLIC;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Restores exactly the relink writer merged by TKT-002904
            // (20261031200000_AddCapabilityInstallationOwnerRelinkProof, Up), before its fourth proof's table goes.
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.relink_runtime_commercial_assignment(
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
                    enrollment_client_id text;
                    enrollment_license_id uuid;
                    enrollment_hardware_hash text;
                    seat_hardware_id text;
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
                    SELECT enrollment."State", enrollment."ProductId", enrollment."SubjectRefDigestSha256",
                           enrollment."ClientId", enrollment."LicenseId", enrollment."HardwareIdHash"
                    INTO enrollment_state, enrollment_product_id, enrollment_subject_digest,
                         enrollment_client_id, enrollment_license_id, enrollment_hardware_hash
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

                    SELECT seat."LicenseId", seat."IsActive", seat."HardwareId"
                    INTO seat_license_id, seat_active, seat_hardware_id
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
                    ) OR (
                        -- TKT-002904: capability request of the installation itself after a seat release.
                        -- Only the enrollment's own client, only a seat on the enrollment's own machine.
                        p_distribution_entitlement_id IS NULL
                        AND p_recovery_grant_digest_sha256 IS NULL
                        AND enrollment_state COLLATE "C" = 'ACTIVE'
                        AND enrollment_client_id = p_authenticated_client_id
                        AND seat_hardware_id IS NOT NULL
                        AND pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(seat_hardware_id, 'UTF8')),
                            'hex') = enrollment_hardware_hash
                        AND (
                            -- The installation's own licence, even without a registered owner.
                            p_license_id = enrollment_license_id
                            OR (
                                -- Another licence of the same active account owner, never for a licence whose
                                -- seats its administrator manages (key activation disabled, TKT-002475): neither
                                -- the installation licence nor the licence of the latest ended assignment.
                                p_recovery_owner_subject_id IS NOT NULL
                                AND NOT EXISTS (
                                    SELECT 1
                                    FROM public."LicenseKeyActivationSettings" setting
                                    WHERE setting."Disabled"
                                      AND (setting."LicenseId" = enrollment_license_id
                                           OR setting."LicenseId" = (
                                               SELECT ended."LicenseId"
                                               FROM public."EnrollmentLicenseAssignments" ended
                                               WHERE ended."EnrollmentId" = p_enrollment_id
                                                 AND ended."State" = 'ENDED'
                                               ORDER BY ended."Revision" DESC, ended."Id" DESC
                                               LIMIT 1))
                                )
                                AND EXISTS (
                                    SELECT 1
                                    FROM public."RuntimeRecoveryCommercialOwnerships" owner_row
                                    WHERE owner_row."ProductId" = enrollment_product_id
                                      AND owner_row."LicenseId" = enrollment_license_id
                                      AND owner_row."OwnerSubjectId" = p_recovery_owner_subject_id
                                      AND owner_row."State" = 'ACTIVE'
                                )
                                AND EXISTS (
                                    SELECT 1
                                    FROM public."RuntimeRecoveryCommercialOwnerships" owner_row
                                    WHERE owner_row."ProductId" = enrollment_product_id
                                      AND owner_row."LicenseId" = p_license_id
                                      AND owner_row."OwnerSubjectId" = p_recovery_owner_subject_id
                                      AND owner_row."State" = 'ACTIVE'
                                )
                            )
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
                REVOKE ALL ON FUNCTION public.relink_runtime_commercial_assignment(
                    uuid, uuid, uuid, text, text, uuid, text, uuid) FROM PUBLIC;
                """);

            migrationBuilder.DropTable(
                name: "RuntimeAccountRelinkRequests");

            // The restored constraint no longer admits account-relink proof rows; drop them so Down cannot fail.
            migrationBuilder.Sql("""
                DELETE FROM public."RuntimeEnrollmentProofNonces" WHERE "Operation" = 'account-relink';
                """);

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces");

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentProofNonces_Operation",
                table: "RuntimeEnrollmentProofNonces",
                sql: "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade', 'rollback', 'websetup-upgrade', 'hardware-authority-migration')");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt000763RuntimeSeatRecoveryAuthorization : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryRevokedClaimNonces",
                columns: table => new
                {
                    Nonce = table.Column<Guid>(type: "uuid", nullable: false),
                    RevokedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReasonCode = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryRevokedClaimNonces", x => x.Nonce);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeRecoveryCommercialOwnerships",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    OwnerSubjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    State = table.Column<string>(type: "varchar(24)", nullable: false, collation: "C"),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    EndedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeRecoveryCommercialOwnerships", x => x.Id);
                    table.CheckConstraint("CK_RRCO_Ended", "(\"State\" = 'ACTIVE' AND \"EndedAtUtc\" IS NULL) OR (\"State\" <> 'ACTIVE' AND \"EndedAtUtc\" IS NOT NULL)");
                    table.CheckConstraint("CK_RRCO_State", "\"State\" IN ('PENDING_TRANSFER','ACTIVE','TRANSFERRED','REVOKED')");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeRecoveryGrantOwnerships",
                columns: table => new
                {
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderGrantRefDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    AuthenticatedClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    OwnerSubjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    RecoveryOperationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    RecoveryDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeRecoveryGrantOwnerships", x => new { x.ProductId, x.ProviderGrantRefDigestSha256 });
                    table.CheckConstraint("CK_RRGO_Digests", "\"ProviderGrantRefDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"RecoveryDigestSha256\" ~ '^[0-9a-f]{64}$'");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryAuthorizations",
                columns: table => new
                {
                    AuthenticatedClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RecoveryOperationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    RecoveryDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    CanonicalRequestUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    ReservationRef = table.Column<Guid>(type: "uuid", nullable: true),
                    Decision = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    HttpStatusCode = table.Column<int>(type: "integer", nullable: false),
                    ContentType = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ErrorCode = table.Column<string>(type: "varchar(64)", nullable: true, collation: "C"),
                    ExactResponseUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryAuthorizations", x => new { x.AuthenticatedClientId, x.RequestId });
                    table.UniqueConstraint("AK_RuntimeSeatRecoveryAuthorizations_AuthenticatedClientId_Req~", x => new { x.AuthenticatedClientId, x.RequestId, x.RecoveryOperationRef });
                    table.CheckConstraint("CK_RSRA_Decision", "\"Decision\" IN ('AUTHORIZED', 'REFUSED')");
                    table.CheckConstraint("CK_RSRA_RecoveryDigest", "octet_length(\"RecoveryDigestSha256\") = 64 AND \"RecoveryDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RSRA_RequestBytes", "octet_length(\"CanonicalRequestUtf8\") BETWEEN 1 AND 4096");
                    table.CheckConstraint("CK_RSRA_RequestDigest", "octet_length(\"RequestDigestSha256\") = 64 AND \"RequestDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RSRA_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 16384");
                    table.CheckConstraint("CK_RSRA_TerminalShape", "(\"Decision\" = 'AUTHORIZED' AND \"ReservationRef\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"Decision\" = 'REFUSED' AND \"ReservationRef\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400,403,409,410))");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryReservations",
                columns: table => new
                {
                    ReservationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthenticatedClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                    RecoveryOperationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderGrantRef = table.Column<string>(type: "varchar(1536)", nullable: false, collation: "C"),
                    State = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryReservations", x => x.ReservationRef);
                    table.CheckConstraint("CK_RSRR_Chronology", "\"CreatedAtUtc\" < \"ExpiresAtUtc\"");
                    table.CheckConstraint("CK_RSRR_State", "\"State\" IN ('RESERVED','COMMITTED','ABANDONED')");
                    table.ForeignKey(
                        name: "FK_RuntimeSeatRecoveryReservations_LicenseSeats_LicenseSeatId",
                        column: x => x.LicenseSeatId,
                        principalTable: "LicenseSeats",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_RuntimeSeatRecoveryReservations_Licenses_LicenseId",
                        column: x => x.LicenseId,
                        principalTable: "Licenses",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_RuntimeSeatRecoveryReservations_RuntimeSeatRecoveryAuthoriz~",
                        columns: x => new { x.AuthenticatedClientId, x.RequestId, x.RecoveryOperationRef },
                        principalTable: "RuntimeSeatRecoveryAuthorizations",
                        principalColumns: new[] { "AuthenticatedClientId", "RequestId", "RecoveryOperationRef" });
                });

            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryAuthorities",
                columns: table => new
                {
                    ReservationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorityLineageId = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    PreviousAuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    InstallationId = table.Column<Guid>(type: "uuid", nullable: false),
                    HardwareIdDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ReleaseVersion = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ArtifactSetDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    PublicKeySpkiSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    KeyThumbprint = table.Column<string>(type: "varchar(43)", nullable: false, collation: "C"),
                    State = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    IsCurrentHead = table.Column<bool>(type: "boolean", nullable: false),
                    PreviousAuthorityState = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    SubjectRefDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryAuthorities", x => x.ReservationRef);
                    table.CheckConstraint("CK_RSRAuthority_Digests", "\"HardwareIdDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"ArtifactSetDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"PublicKeySpkiSha256\" ~ '^[0-9a-f]{64}$' AND \"SubjectRefDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RSRAuthority_PreviousState", "\"PreviousAuthorityState\" IN ('ACTIVE','SUPERSEDED')");
                    table.CheckConstraint("CK_RSRAuthority_State", "\"State\" IN ('PREPARED','ACTIVE','ABANDONED','SUPERSEDED')");
                    table.ForeignKey(
                        name: "FK_RuntimeSeatRecoveryAuthorities_RuntimeEnrollmentAuthorityGe~",
                        column: x => x.AuthorityGenerationId,
                        principalTable: "RuntimeEnrollmentAuthorityGenerations",
                        principalColumn: "AuthorityGenerationId");
                    table.ForeignKey(
                        name: "FK_RuntimeSeatRecoveryAuthorities_RuntimeSeatRecoveryReservati~",
                        column: x => x.ReservationRef,
                        principalTable: "RuntimeSeatRecoveryReservations",
                        principalColumn: "ReservationRef");
                });

            migrationBuilder.CreateIndex(
                name: "UX_RRCO_OneActiveOwner",
                table: "RuntimeRecoveryCommercialOwnerships",
                columns: new[] { "ProductId", "LicenseId" },
                unique: true,
                filter: "\"State\" = 'ACTIVE'");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeRecoveryGrantOwnerships_RecoveryOperationRef",
                table: "RuntimeRecoveryGrantOwnerships",
                column: "RecoveryOperationRef",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryAuthorities_AuthorityGenerationId",
                table: "RuntimeSeatRecoveryAuthorities",
                column: "AuthorityGenerationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryAuthorities_BindingId",
                table: "RuntimeSeatRecoveryAuthorities",
                column: "BindingId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryAuthorities_EnrollmentId",
                table: "RuntimeSeatRecoveryAuthorities",
                column: "EnrollmentId",
                unique: true);

            // RecoveryOperationRef is intentionally non-unique on terminal history because the
            // authenticated client is part of terminal identity; resource tables stay globally unique.
            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryAuthorizations_RecoveryOperationRef",
                table: "RuntimeSeatRecoveryAuthorizations",
                column: "RecoveryOperationRef");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryAuthorizations_ReservationRef",
                table: "RuntimeSeatRecoveryAuthorizations",
                column: "ReservationRef",
                unique: true,
                filter: "\"ReservationRef\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryReservations_AuthenticatedClientId_Reque~",
                table: "RuntimeSeatRecoveryReservations",
                columns: new[] { "AuthenticatedClientId", "RequestId", "RecoveryOperationRef" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryReservations_LicenseId",
                table: "RuntimeSeatRecoveryReservations",
                column: "LicenseId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryReservations_RecoveryOperationRef",
                table: "RuntimeSeatRecoveryReservations",
                column: "RecoveryOperationRef",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_RSRR_OneReservedPerSeat",
                table: "RuntimeSeatRecoveryReservations",
                column: "LicenseSeatId",
                unique: true,
                filter: "\"State\" = 'RESERVED'");

            migrationBuilder.Sql("""
                CREATE FUNCTION public.runtime_seat_recovery_immutable() RETURNS trigger
                LANGUAGE plpgsql AS $guard$
                BEGIN
                    RAISE EXCEPTION 'runtime seat recovery terminal history is immutable' USING ERRCODE = '55000';
                END;
                $guard$;
                CREATE TRIGGER trg_runtime_seat_recovery_authorizations_immutable
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryAuthorizations"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                CREATE TRIGGER trg_runtime_seat_recovery_authorizations_no_truncate
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryAuthorizations"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                CREATE TRIGGER trg_runtime_recovery_grants_immutable
                BEFORE UPDATE OR DELETE ON public."RuntimeRecoveryGrantOwnerships"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                CREATE TRIGGER trg_runtime_recovery_grants_no_truncate
                BEFORE TRUNCATE ON public."RuntimeRecoveryGrantOwnerships"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                CREATE TRIGGER trg_runtime_seat_recovery_revocations_immutable
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryRevokedClaimNonces"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                CREATE TRIGGER trg_runtime_seat_recovery_revocations_no_truncate
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryRevokedClaimNonces"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                """);

            migrationBuilder.Sql("""
                CREATE FUNCTION public.runtime_seat_recovery_reservation_guard() RETURNS trigger
                LANGUAGE plpgsql AS $guard$
                BEGIN
                    IF TG_OP <> 'UPDATE'
                       OR OLD."State" <> 'RESERVED'
                       OR NEW."State" NOT IN ('COMMITTED','ABANDONED')
                       OR (to_jsonb(NEW) - 'State') IS DISTINCT FROM (to_jsonb(OLD) - 'State') THEN
                        RAISE EXCEPTION 'invalid runtime seat recovery reservation transition' USING ERRCODE = '55000';
                    END IF;
                    RETURN NEW;
                END;
                $guard$;
                CREATE TRIGGER trg_runtime_seat_recovery_reservations_guard
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryReservations"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_reservation_guard();
                CREATE TRIGGER trg_runtime_seat_recovery_reservations_no_truncate
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryReservations"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                """);

            migrationBuilder.Sql("""
                CREATE FUNCTION public.runtime_seat_recovery_authority_guard() RETURNS trigger
                LANGUAGE plpgsql AS $guard$
                BEGIN
                    IF TG_OP <> 'UPDATE'
                       OR OLD."State" <> 'PREPARED'
                       OR NEW."State" NOT IN ('ACTIVE','ABANDONED','SUPERSEDED')
                       OR (to_jsonb(NEW) - ARRAY['State','IsCurrentHead','PreviousAuthorityState'])
                          IS DISTINCT FROM
                          (to_jsonb(OLD) - ARRAY['State','IsCurrentHead','PreviousAuthorityState']) THEN
                        RAISE EXCEPTION 'invalid runtime seat recovery authority transition' USING ERRCODE = '55000';
                    END IF;
                    RETURN NEW;
                END;
                $guard$;
                CREATE TRIGGER trg_runtime_seat_recovery_authorities_guard
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryAuthorities"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_authority_guard();
                CREATE TRIGGER trg_runtime_seat_recovery_authorities_no_truncate
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryAuthorities"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_immutable();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryRevokedClaimNonces");

            migrationBuilder.DropTable(
                name: "RuntimeRecoveryCommercialOwnerships");

            migrationBuilder.DropTable(
                name: "RuntimeRecoveryGrantOwnerships");

            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryReservations");

            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryAuthorizations");

            migrationBuilder.Sql("""
                DROP FUNCTION IF EXISTS public.runtime_seat_recovery_authority_guard();
                DROP FUNCTION IF EXISTS public.runtime_seat_recovery_reservation_guard();
                DROP FUNCTION IF EXISTS public.runtime_seat_recovery_immutable();
                """);
        }
    }
}

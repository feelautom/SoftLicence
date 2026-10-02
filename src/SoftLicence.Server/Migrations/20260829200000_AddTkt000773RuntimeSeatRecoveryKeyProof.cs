using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt000773RuntimeSeatRecoveryKeyProof : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryKeyPreparations",
                columns: table => new
                {
                    PrepareRef = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthenticatedClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RecoveryOperationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    ReservationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    CanonicalRequestUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    PublicKeySpkiSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    PublicKeySpkiCiphertext = table.Column<string>(type: "text", nullable: false, collation: "C"),
                    PublicKeySpkiKeyId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ChallengeDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ChallengeCiphertext = table.Column<string>(type: "text", nullable: false, collation: "C"),
                    ChallengeKeyId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ConfirmAudience = table.Column<string>(type: "varchar(96)", nullable: false, collation: "C"),
                    ExactResponseUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ChallengeConsumedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryKeyPreparations", x => new { x.AuthenticatedClientId, x.PrepareRef });
                    table.UniqueConstraint("AK_RSRKP_Client_Request_Recovery", x => new { x.AuthenticatedClientId, x.RequestId, x.RecoveryOperationRef });
                    table.CheckConstraint("CK_RSRKP_Audience", "\"ConfirmAudience\" = 'softlicence:runtime-identity-recovery:confirm:v1'");
                    table.CheckConstraint("CK_RSRKP_Chronology", "\"CreatedAtUtc\" < \"ExpiresAtUtc\" AND (\"ChallengeConsumedAtUtc\" IS NULL OR \"ChallengeConsumedAtUtc\" >= \"CreatedAtUtc\")");
                    table.CheckConstraint("CK_RSRKP_Digests", "\"RequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"PublicKeySpkiSha256\" ~ '^[0-9a-f]{64}$' AND \"ChallengeDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RSRKP_RequestBytes", "octet_length(\"CanonicalRequestUtf8\") BETWEEN 1 AND 4096");
                    table.CheckConstraint("CK_RSRKP_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.ForeignKey(
                        name: "FK_RSRKP_RSRAuthorizations_Client_Request_Recovery",
                        columns: x => new { x.AuthenticatedClientId, x.RequestId, x.RecoveryOperationRef },
                        principalTable: "RuntimeSeatRecoveryAuthorizations",
                        principalColumns: new[] { "AuthenticatedClientId", "RequestId", "RecoveryOperationRef" });
                    table.ForeignKey(
                        name: "FK_RSRKP_RSRReservations_ReservationRef",
                        column: x => x.ReservationRef,
                        principalTable: "RuntimeSeatRecoveryReservations",
                        principalColumn: "ReservationRef");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryKeyConfirmations",
                columns: table => new
                {
                    AuthenticatedClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    PrepareRef = table.Column<Guid>(type: "uuid", nullable: false),
                    ConfirmationRequestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    CanonicalRequestUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    State = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    HttpStatusCode = table.Column<int>(type: "integer", nullable: false),
                    ContentType = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ErrorCode = table.Column<string>(type: "varchar(64)", nullable: true, collation: "C"),
                    ExactResponseUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryKeyConfirmations", x => new { x.AuthenticatedClientId, x.PrepareRef });
                    table.CheckConstraint("CK_RSRKC_Digest", "\"ConfirmationRequestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RSRKC_RequestBytes", "octet_length(\"CanonicalRequestUtf8\") BETWEEN 1 AND 4096");
                    table.CheckConstraint("CK_RSRKC_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.CheckConstraint("CK_RSRKC_State", "\"State\" IN ('PROVED','REFUSED')");
                    table.CheckConstraint("CK_RSRKC_TerminalShape", "(\"State\" = 'PROVED' AND \"HttpStatusCode\" = 200 AND \"ErrorCode\" IS NULL) OR (\"State\" = 'REFUSED' AND \"HttpStatusCode\" IN (403,409,410) AND \"ErrorCode\" IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_RSRKC_RSRKeyPreparations_Client_Prepare",
                        columns: x => new { x.AuthenticatedClientId, x.PrepareRef },
                        principalTable: "RuntimeSeatRecoveryKeyPreparations",
                        principalColumns: new[] { "AuthenticatedClientId", "PrepareRef" });
                });

            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryProofReceipts",
                columns: table => new
                {
                    AuthenticatedClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    PrepareRef = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RecoveryOperationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    ReservationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    PublicKeySpkiSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ConfirmationRequestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    State = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    ProvedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PreparationExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReservationExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryProofReceipts", x => new { x.AuthenticatedClientId, x.PrepareRef });
                    table.CheckConstraint("CK_RSRPR_Chronology", "\"ProvedAtUtc\" < \"ExpiresAtUtc\"");
                    table.CheckConstraint("CK_RSRPR_Digests", "\"RequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"PublicKeySpkiSha256\" ~ '^[0-9a-f]{64}$' AND \"ConfirmationRequestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RSRPR_ExpiryMinimum", "\"ExpiresAtUtc\" = LEAST(\"PreparationExpiresAtUtc\", \"ReservationExpiresAtUtc\")");
                    table.CheckConstraint("CK_RSRPR_State", "\"State\" = 'PROVED'");
                    table.ForeignKey(
                        name: "FK_RSRPR_RSRKeyConfirmations_Client_Prepare",
                        columns: x => new { x.AuthenticatedClientId, x.PrepareRef },
                        principalTable: "RuntimeSeatRecoveryKeyConfirmations",
                        principalColumns: new[] { "AuthenticatedClientId", "PrepareRef" });
                    table.ForeignKey(
                        name: "FK_RSRPR_RSRReservations_ReservationRef",
                        column: x => x.ReservationRef,
                        principalTable: "RuntimeSeatRecoveryReservations",
                        principalColumn: "ReservationRef");
                });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryKeyPreparations_AuthorityGenerationId",
                table: "RuntimeSeatRecoveryKeyPreparations",
                column: "AuthorityGenerationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryKeyPreparations_EnrollmentId",
                table: "RuntimeSeatRecoveryKeyPreparations",
                column: "EnrollmentId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryKeyPreparations_ReservationRef",
                table: "RuntimeSeatRecoveryKeyPreparations",
                column: "ReservationRef",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryProofReceipts_AuthorityGenerationId",
                table: "RuntimeSeatRecoveryProofReceipts",
                column: "AuthorityGenerationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryProofReceipts_ReservationRef",
                table: "RuntimeSeatRecoveryProofReceipts",
                column: "ReservationRef",
                unique: true);

            migrationBuilder.Sql("""
                CREATE FUNCTION public.runtime_seat_recovery_key_preparation_guard()
                RETURNS trigger LANGUAGE plpgsql AS $guard$
                BEGIN
                    IF TG_OP = 'DELETE' THEN
                        RAISE EXCEPTION 'runtime recovery key preparation is immutable' USING ERRCODE = '55000';
                    END IF;
                    IF OLD."ChallengeConsumedAtUtc" IS NULL
                       AND NEW."ChallengeConsumedAtUtc" IS NOT NULL
                       AND ROW(OLD."PrepareRef",OLD."AuthenticatedClientId",OLD."ProductId",OLD."RequestId",
                               OLD."RequestDigestSha256",OLD."RecoveryOperationRef",OLD."ReservationRef",
                               OLD."EnrollmentId",OLD."AuthorityGenerationId",OLD."CanonicalRequestUtf8",
                               OLD."PublicKeySpkiSha256",OLD."PublicKeySpkiCiphertext",OLD."PublicKeySpkiKeyId",
                               OLD."ChallengeDigestSha256",OLD."ChallengeCiphertext",OLD."ChallengeKeyId",
                               OLD."ConfirmAudience",OLD."ExactResponseUtf8",OLD."CreatedAtUtc",OLD."ExpiresAtUtc")
                           IS NOT DISTINCT FROM
                           ROW(NEW."PrepareRef",NEW."AuthenticatedClientId",NEW."ProductId",NEW."RequestId",
                               NEW."RequestDigestSha256",NEW."RecoveryOperationRef",NEW."ReservationRef",
                               NEW."EnrollmentId",NEW."AuthorityGenerationId",NEW."CanonicalRequestUtf8",
                               NEW."PublicKeySpkiSha256",NEW."PublicKeySpkiCiphertext",NEW."PublicKeySpkiKeyId",
                               NEW."ChallengeDigestSha256",NEW."ChallengeCiphertext",NEW."ChallengeKeyId",
                               NEW."ConfirmAudience",NEW."ExactResponseUtf8",NEW."CreatedAtUtc",NEW."ExpiresAtUtc")
                    THEN
                        RETURN NEW;
                    END IF;
                    RAISE EXCEPTION 'runtime recovery key preparation is immutable' USING ERRCODE = '55000';
                END;
                $guard$;

                CREATE TRIGGER trg_runtime_seat_recovery_key_preparation_guard
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryKeyPreparations"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_key_preparation_guard();

                CREATE FUNCTION public.runtime_seat_recovery_key_terminal_guard()
                RETURNS trigger LANGUAGE plpgsql AS $guard$
                BEGIN
                    RAISE EXCEPTION 'runtime recovery key proof terminal is immutable' USING ERRCODE = '55000';
                END;
                $guard$;

                CREATE TRIGGER trg_runtime_seat_recovery_key_confirmation_guard
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryKeyConfirmations"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_key_terminal_guard();

                CREATE TRIGGER trg_runtime_seat_recovery_proof_receipt_guard
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryProofReceipts"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_seat_recovery_key_terminal_guard();

                CREATE TRIGGER trg_runtime_seat_recovery_key_preparation_truncate_guard
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryKeyPreparations"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_key_terminal_guard();

                CREATE TRIGGER trg_runtime_seat_recovery_key_confirmation_truncate_guard
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryKeyConfirmations"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_key_terminal_guard();

                CREATE TRIGGER trg_runtime_seat_recovery_proof_receipt_truncate_guard
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryProofReceipts"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_seat_recovery_key_terminal_guard();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS trg_runtime_seat_recovery_proof_receipt_truncate_guard
                    ON public."RuntimeSeatRecoveryProofReceipts";
                DROP TRIGGER IF EXISTS trg_runtime_seat_recovery_key_confirmation_truncate_guard
                    ON public."RuntimeSeatRecoveryKeyConfirmations";
                DROP TRIGGER IF EXISTS trg_runtime_seat_recovery_key_preparation_truncate_guard
                    ON public."RuntimeSeatRecoveryKeyPreparations";
                DROP TRIGGER IF EXISTS trg_runtime_seat_recovery_proof_receipt_guard
                    ON public."RuntimeSeatRecoveryProofReceipts";
                DROP TRIGGER IF EXISTS trg_runtime_seat_recovery_key_confirmation_guard
                    ON public."RuntimeSeatRecoveryKeyConfirmations";
                DROP TRIGGER IF EXISTS trg_runtime_seat_recovery_key_preparation_guard
                    ON public."RuntimeSeatRecoveryKeyPreparations";
                DROP FUNCTION IF EXISTS public.runtime_seat_recovery_key_terminal_guard();
                DROP FUNCTION IF EXISTS public.runtime_seat_recovery_key_preparation_guard();
                """);

            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryProofReceipts");

            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryKeyConfirmations");

            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryKeyPreparations");
        }
    }
}

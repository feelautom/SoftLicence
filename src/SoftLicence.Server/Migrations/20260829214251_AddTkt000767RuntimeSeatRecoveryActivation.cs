using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt000767RuntimeSeatRecoveryActivation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "LicenseSeatId",
                table: "RuntimeSeatRecoveryAuthorities",
                type: "uuid",
                nullable: true);

            migrationBuilder.Sql("""
                ALTER TABLE public."RuntimeSeatRecoveryAuthorities"
                    DISABLE TRIGGER trg_runtime_seat_recovery_authorities_guard;

                UPDATE public."RuntimeSeatRecoveryAuthorities" authority
                SET "LicenseSeatId" = reservation."LicenseSeatId"
                FROM public."RuntimeSeatRecoveryReservations" reservation
                WHERE reservation."ReservationRef" = authority."ReservationRef";

                ALTER TABLE public."RuntimeSeatRecoveryAuthorities"
                    ENABLE TRIGGER trg_runtime_seat_recovery_authorities_guard;
                """);

            migrationBuilder.AlterColumn<Guid>(
                name: "LicenseSeatId",
                table: "RuntimeSeatRecoveryAuthorities",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.DropForeignKey(
                name: "FK_RuntimeSeatRecoveryAuthorities_RuntimeSeatRecoveryReservati~",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.AddUniqueConstraint(
                name: "AK_RuntimeSeatRecoveryReservations_ReservationRef_LicenseSeatId",
                table: "RuntimeSeatRecoveryReservations",
                columns: new[] { "ReservationRef", "LicenseSeatId" });

            migrationBuilder.AddForeignKey(
                name: "FK_RSRAuthorities_RSRReservations_ReservationRef_LicenseSeatId",
                table: "RuntimeSeatRecoveryAuthorities",
                columns: new[] { "ReservationRef", "LicenseSeatId" },
                principalTable: "RuntimeSeatRecoveryReservations",
                principalColumns: new[] { "ReservationRef", "LicenseSeatId" });

            migrationBuilder.CreateTable(
                name: "RuntimeSeatRecoveryActivationReceipts",
                columns: table => new
                {
                    AuthenticatedClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    ActivationRequestDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    CanonicalRequestUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RecoveryOperationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    ReservationRef = table.Column<Guid>(type: "uuid", nullable: false),
                    PrepareRef = table.Column<Guid>(type: "uuid", nullable: false),
                    ConfirmationRequestSha256 = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    PreviousAuthorityLineageId = table.Column<Guid>(type: "uuid", nullable: false),
                    PreviousAuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    NewAuthorityLineageId = table.Column<Guid>(type: "uuid", nullable: false),
                    NewAuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    State = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    HttpStatusCode = table.Column<int>(type: "integer", nullable: false),
                    ContentType = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ErrorCode = table.Column<string>(type: "varchar(64)", nullable: true, collation: "C"),
                    ExactResponseUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeSeatRecoveryActivationReceipts", x => new { x.AuthenticatedClientId, x.RequestId });
                    table.CheckConstraint("CK_RSRActivation_ContentType", "\"ContentType\" = 'application/json; charset=utf-8'");
                    table.CheckConstraint("CK_RSRActivation_Digests", "\"ActivationRequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"RequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"ConfirmationRequestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RSRActivation_RequestBytes", "octet_length(\"CanonicalRequestUtf8\") = 524");
                    table.CheckConstraint("CK_RSRActivation_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.CheckConstraint("CK_RSRActivation_State", "\"State\" IN ('COMMITTED','REFUSED')");
                    table.CheckConstraint("CK_RSRActivation_TerminalShape", "(\"State\" = 'COMMITTED' AND \"HttpStatusCode\" = 200 AND \"ErrorCode\" IS NULL) OR (\"State\" = 'REFUSED' AND \"HttpStatusCode\" IN (409,410) AND \"ErrorCode\" IN ('activation_conflict','activation_expired'))");
                    table.ForeignKey(
                        name: "FK_RuntimeSeatRecoveryActivationReceipts_RuntimeSeatRecoveryPr~",
                        columns: x => new { x.AuthenticatedClientId, x.PrepareRef },
                        principalTable: "RuntimeSeatRecoveryProofReceipts",
                        principalColumns: new[] { "AuthenticatedClientId", "PrepareRef" });
                    table.ForeignKey(
                        name: "FK_RuntimeSeatRecoveryActivationReceipts_RuntimeSeatRecoveryRe~",
                        column: x => x.ReservationRef,
                        principalTable: "RuntimeSeatRecoveryReservations",
                        principalColumn: "ReservationRef");
                });

            migrationBuilder.CreateIndex(
                name: "UX_RSRAuthorities_OneActivePerSeat",
                table: "RuntimeSeatRecoveryAuthorities",
                column: "LicenseSeatId",
                unique: true,
                filter: "\"State\" = 'ACTIVE'");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryAuthorities_ReservationRef_LicenseSeatId",
                table: "RuntimeSeatRecoveryAuthorities",
                columns: new[] { "ReservationRef", "LicenseSeatId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeSeatRecoveryActivationReceipts_ReservationRef",
                table: "RuntimeSeatRecoveryActivationReceipts",
                column: "ReservationRef",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_RSRActivation_Client_PrepareRef",
                table: "RuntimeSeatRecoveryActivationReceipts",
                columns: new[] { "AuthenticatedClientId", "PrepareRef" },
                unique: true);

            migrationBuilder.Sql("""
                CREATE FUNCTION public.tkt000767_reject_runtime_seat_recovery_activation_receipt_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    RAISE EXCEPTION 'Runtime seat recovery activation receipts are immutable'
                        USING ERRCODE = '55000';
                END;
                $function$;

                CREATE TRIGGER "TR_RuntimeSeatRecoveryActivationReceipts_ImmutableRows"
                BEFORE UPDATE OR DELETE ON public."RuntimeSeatRecoveryActivationReceipts"
                FOR EACH ROW EXECUTE FUNCTION public.tkt000767_reject_runtime_seat_recovery_activation_receipt_mutation();

                CREATE TRIGGER "TR_RuntimeSeatRecoveryActivationReceipts_ImmutableTruncate"
                BEFORE TRUNCATE ON public."RuntimeSeatRecoveryActivationReceipts"
                FOR EACH STATEMENT EXECUTE FUNCTION public.tkt000767_reject_runtime_seat_recovery_activation_receipt_mutation();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS "TR_RuntimeSeatRecoveryActivationReceipts_ImmutableTruncate"
                    ON public."RuntimeSeatRecoveryActivationReceipts";
                DROP TRIGGER IF EXISTS "TR_RuntimeSeatRecoveryActivationReceipts_ImmutableRows"
                    ON public."RuntimeSeatRecoveryActivationReceipts";
                DROP FUNCTION IF EXISTS public.tkt000767_reject_runtime_seat_recovery_activation_receipt_mutation();
                """);

            migrationBuilder.DropTable(
                name: "RuntimeSeatRecoveryActivationReceipts");

            migrationBuilder.DropIndex(
                name: "UX_RSRAuthorities_OneActivePerSeat",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_RuntimeSeatRecoveryAuthorities_ReservationRef_LicenseSeatId",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropForeignKey(
                name: "FK_RSRAuthorities_RSRReservations_ReservationRef_LicenseSeatId",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_RuntimeSeatRecoveryReservations_ReservationRef_LicenseSeatId",
                table: "RuntimeSeatRecoveryReservations");

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeSeatRecoveryAuthorities_RuntimeSeatRecoveryReservati~",
                table: "RuntimeSeatRecoveryAuthorities",
                column: "ReservationRef",
                principalTable: "RuntimeSeatRecoveryReservations",
                principalColumn: "ReservationRef");

            migrationBuilder.DropColumn(
                name: "LicenseSeatId",
                table: "RuntimeSeatRecoveryAuthorities");
        }
    }
}

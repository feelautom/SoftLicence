using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeEnrollmentAuthorityAttemptResults : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Runtime Enrollment owns this forward-only enrichment. The request immutability guard is
            // removed only for the deterministic historical backfill and is restored before constraints.
            migrationBuilder.Sql("""
                DROP TRIGGER trg_runtime_enrollment_authority_requests_immutable
                    ON public."RuntimeEnrollmentAuthorityRequests";
                """);

            migrationBuilder.DropCheckConstraint(
                name: "CK_REAuthorityRequests_ResultCode",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropForeignKey(
                name: "FK_REAuthorityRequests_REAuthorityGenerations_Result",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.AddUniqueConstraint(
                name: "AK_REAuthorityGenerations_LineageId_GenerationId_RequestId",
                table: "RuntimeEnrollmentAuthorityGenerations",
                columns: new[] { "AuthorityLineageId", "AuthorityGenerationId", "RequestId" });

            migrationBuilder.AlterColumn<Guid>(
                name: "AuthorityGenerationId",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AddColumn<Guid>(
                name: "AuthorityLineageId",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "CompletedAtUtc",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ErrorCode",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "varchar(64)",
                nullable: true,
                collation: "C");

            migrationBuilder.AddColumn<byte[]>(
                name: "ExactResponseUtf8",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "bytea",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HttpStatusCode",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "integer",
                nullable: true);

            migrationBuilder.Sql("""
                UPDATE public."RuntimeEnrollmentAuthorityRequests" AS request
                SET "AuthorityLineageId" = generation."AuthorityLineageId",
                    "CompletedAtUtc" = request."CreatedAtUtc",
                    "ExactResponseUtf8" = generation."SignedStatementUtf8",
                    "HttpStatusCode" = 200
                FROM public."RuntimeEnrollmentAuthorityGenerations" AS generation
                WHERE request."AuthorityGenerationId" = generation."AuthorityGenerationId"
                  AND request."RequestId" = generation."RequestId"
                  AND request."ResultCode" = 'ACCEPTED';

                DO $body$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM public."RuntimeEnrollmentAuthorityRequests"
                        WHERE "AuthorityLineageId" IS NULL
                           OR "CompletedAtUtc" IS NULL
                           OR "ExactResponseUtf8" IS NULL
                           OR octet_length("ExactResponseUtf8") NOT BETWEEN 1 AND 8192
                           OR "HttpStatusCode" IS NULL
                    ) THEN
                        RAISE EXCEPTION USING ERRCODE = '23514',
                            MESSAGE = 'runtime enrollment authority request backfill is incomplete';
                    END IF;
                END;
                $body$;
                """);

            migrationBuilder.Sql("""
                CREATE TRIGGER trg_runtime_enrollment_authority_requests_immutable
                BEFORE UPDATE OR DELETE ON public."RuntimeEnrollmentAuthorityRequests"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_reject_authority_history_mutation();
                """);

            migrationBuilder.AlterColumn<DateTime>(
                name: "CompletedAtUtc",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "timestamp with time zone",
                nullable: false,
                oldClrType: typeof(DateTime),
                oldType: "timestamp with time zone",
                oldNullable: true);

            migrationBuilder.AlterColumn<byte[]>(
                name: "ExactResponseUtf8",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "bytea",
                nullable: false,
                oldClrType: typeof(byte[]),
                oldType: "bytea",
                oldNullable: true);

            migrationBuilder.AlterColumn<int>(
                name: "HttpStatusCode",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "integer",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "integer",
                oldNullable: true);

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentAuthorityAttempts",
                columns: table => new
                {
                    AttemptId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigest = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    AuthorityLineageId = table.Column<Guid>(type: "uuid", nullable: true),
                    AuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: true),
                    Status = table.Column<string>(type: "varchar(8)", nullable: false, collation: "C"),
                    ErrorCode = table.Column<string>(type: "varchar(64)", nullable: true, collation: "C"),
                    HttpStatusCode = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExactResponseUtf8 = table.Column<byte[]>(type: "bytea", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_REAuthorityAttempts", x => x.AttemptId);
                    table.CheckConstraint("CK_REAuthorityAttempts_RequestDigest", "octet_length(\"RequestDigest\") = 64 AND \"RequestDigest\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_REAuthorityAttempts_Chronology", "\"CreatedAtUtc\" <= \"CompletedAtUtc\"");
                    table.CheckConstraint("CK_REAuthorityAttempts_ErrorCode", "\"ErrorCode\" IS NULL OR (octet_length(\"ErrorCode\") BETWEEN 1 AND 64 AND \"ErrorCode\" ~ '^[A-Z0-9_]+$')");
                    table.CheckConstraint("CK_REAuthorityAttempts_HttpStatus", "\"HttpStatusCode\" IN (200, 400, 403, 409, 503)");
                    table.CheckConstraint("CK_REAuthorityAttempts_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.CheckConstraint("CK_REAuthorityAttempts_Status", "\"Status\" IN ('ACCEPTED', 'REFUSED')");
                    table.CheckConstraint("CK_REAuthorityAttempts_TerminalShape", "(\"Status\" = 'ACCEPTED' AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"Status\" = 'REFUSED' AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400, 403, 409, 503))");
                    table.ForeignKey(
                        name: "FK_REAuthorityAttempts_REAuthorityRequests_Request",
                        column: x => x.RequestId,
                        principalTable: "RuntimeEnrollmentAuthorityRequests",
                        principalColumn: "RequestId");
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_REAuthorityRequests_ResultCode",
                table: "RuntimeEnrollmentAuthorityRequests",
                sql: "\"ResultCode\" IN ('ACCEPTED', 'REFUSED')");

            migrationBuilder.AddCheckConstraint(
                name: "CK_REAuthorityRequests_TerminalShape",
                table: "RuntimeEnrollmentAuthorityRequests",
                sql: "(\"ResultCode\" = 'ACCEPTED' AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"ResultCode\" = 'REFUSED' AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400, 403, 409, 503))");

            migrationBuilder.AddCheckConstraint(name: "CK_REAuthorityRequests_Chronology",
                table: "RuntimeEnrollmentAuthorityRequests", sql: "\"CreatedAtUtc\" <= \"CompletedAtUtc\"");
            migrationBuilder.AddCheckConstraint(name: "CK_REAuthorityRequests_ErrorCode",
                table: "RuntimeEnrollmentAuthorityRequests", sql: "\"ErrorCode\" IS NULL OR (octet_length(\"ErrorCode\") BETWEEN 1 AND 64 AND \"ErrorCode\" ~ '^[A-Z0-9_]+$')");
            migrationBuilder.AddCheckConstraint(name: "CK_REAuthorityRequests_HttpStatus",
                table: "RuntimeEnrollmentAuthorityRequests", sql: "\"HttpStatusCode\" IN (200, 400, 403, 409, 503)");
            migrationBuilder.AddCheckConstraint(name: "CK_REAuthorityRequests_ResponseBytes",
                table: "RuntimeEnrollmentAuthorityRequests", sql: "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");

            migrationBuilder.CreateIndex(
                name: "IX_REAuthorityAttempts_RequestId",
                table: "RuntimeEnrollmentAuthorityAttempts",
                column: "RequestId");

            migrationBuilder.CreateIndex(
                name: "IX_REAuthorityAttempts_RequestId_LineageId_GenerationId",
                table: "RuntimeEnrollmentAuthorityAttempts",
                columns: new[] { "RequestId", "AuthorityLineageId", "AuthorityGenerationId" });

            migrationBuilder.CreateIndex(
                name: "UX_REAuthorityRequests_RequestId_LineageId_GenerationId",
                table: "RuntimeEnrollmentAuthorityRequests",
                columns: new[] { "RequestId", "AuthorityLineageId", "AuthorityGenerationId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_REAuthorityRequests_LineageId_GenerationId_RequestId",
                table: "RuntimeEnrollmentAuthorityRequests",
                columns: new[] { "AuthorityLineageId", "AuthorityGenerationId", "RequestId" });

            migrationBuilder.AddForeignKey(
                name: "FK_REAuthorityRequests_REAuthorityGenerations_Result",
                table: "RuntimeEnrollmentAuthorityRequests",
                columns: new[] { "AuthorityLineageId", "AuthorityGenerationId", "RequestId" },
                principalTable: "RuntimeEnrollmentAuthorityGenerations",
                principalColumns: new[] { "AuthorityLineageId", "AuthorityGenerationId", "RequestId" },
                onDelete: ReferentialAction.NoAction);

            migrationBuilder.AddForeignKey(
                name: "FK_REAuthorityAttempts_REAuthorityRequests_Terminal",
                table: "RuntimeEnrollmentAuthorityAttempts",
                columns: new[] { "RequestId", "AuthorityLineageId", "AuthorityGenerationId" },
                principalTable: "RuntimeEnrollmentAuthorityRequests",
                principalColumns: new[] { "RequestId", "AuthorityLineageId", "AuthorityGenerationId" },
                onDelete: ReferentialAction.NoAction);

            // Runtime Enrollment owns immutable terminal attempts. Up is additive and forward-only;
            // Down exists only for local migration tooling and is not an operational rollback recipe.
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.re_authority_attempts_immutable()
                RETURNS trigger LANGUAGE plpgsql AS $body$
                BEGIN
                    RAISE EXCEPTION 'Runtime Enrollment authority attempts are immutable' USING ERRCODE = '55000';
                END;
                $body$;
                CREATE TRIGGER trg_re_authority_attempts_immutable
                BEFORE UPDATE OR DELETE ON public."RuntimeEnrollmentAuthorityAttempts"
                FOR EACH ROW EXECUTE FUNCTION public.re_authority_attempts_immutable();
                CREATE TRIGGER trg_re_authority_attempts_no_truncate
                BEFORE TRUNCATE ON public."RuntimeEnrollmentAuthorityAttempts"
                FOR EACH STATEMENT EXECUTE FUNCTION public.re_authority_attempts_immutable();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_REAuthorityAttempts_REAuthorityRequests_Terminal",
                table: "RuntimeEnrollmentAuthorityAttempts");

            migrationBuilder.DropForeignKey(
                name: "FK_REAuthorityRequests_REAuthorityGenerations_Result",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS trg_re_authority_attempts_no_truncate ON public."RuntimeEnrollmentAuthorityAttempts";
                DROP TRIGGER IF EXISTS trg_re_authority_attempts_immutable ON public."RuntimeEnrollmentAuthorityAttempts";
                DROP FUNCTION IF EXISTS public.re_authority_attempts_immutable();
                """);

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentAuthorityAttempts");

            migrationBuilder.DropCheckConstraint(
                name: "CK_REAuthorityRequests_ResultCode",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropCheckConstraint(
                name: "CK_REAuthorityRequests_TerminalShape",
                table: "RuntimeEnrollmentAuthorityRequests");
            migrationBuilder.DropCheckConstraint(name: "CK_REAuthorityRequests_Chronology", table: "RuntimeEnrollmentAuthorityRequests");
            migrationBuilder.DropCheckConstraint(name: "CK_REAuthorityRequests_ErrorCode", table: "RuntimeEnrollmentAuthorityRequests");
            migrationBuilder.DropCheckConstraint(name: "CK_REAuthorityRequests_HttpStatus", table: "RuntimeEnrollmentAuthorityRequests");
            migrationBuilder.DropCheckConstraint(name: "CK_REAuthorityRequests_ResponseBytes", table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropColumn(
                name: "AuthorityLineageId",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropColumn(
                name: "CompletedAtUtc",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropColumn(
                name: "ErrorCode",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropColumn(
                name: "ExactResponseUtf8",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropColumn(
                name: "HttpStatusCode",
                table: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_REAuthorityGenerations_LineageId_GenerationId_RequestId",
                table: "RuntimeEnrollmentAuthorityGenerations");

            migrationBuilder.AlterColumn<Guid>(
                name: "AuthorityGenerationId",
                table: "RuntimeEnrollmentAuthorityRequests",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_REAuthorityRequests_ResultCode",
                table: "RuntimeEnrollmentAuthorityRequests",
                sql: "\"ResultCode\" = 'ACCEPTED'");

            migrationBuilder.AddForeignKey(
                name: "FK_REAuthorityRequests_REAuthorityGenerations_Result",
                table: "RuntimeEnrollmentAuthorityRequests",
                columns: new[] { "AuthorityGenerationId", "RequestId" },
                principalTable: "RuntimeEnrollmentAuthorityGenerations",
                principalColumns: new[] { "AuthorityGenerationId", "RequestId" },
                onDelete: ReferentialAction.NoAction);
        }
    }
}

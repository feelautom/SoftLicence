using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    // This forward-only production migration commits genesis lineage and generation in one transaction.
    // Its single deferred composite head FK permits insertion order without allowing a committed lineage
    // to lack a coherent head. Triggers make generations and requests immutable and restrict lineage
    // mutation to one adjacent head advance. Down exists for local migration tooling only; production
    // rollback must never erase authority history.
    /// <inheritdoc />
    public partial class AddRuntimeEnrollmentGenerationAuthority : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentAuthorityGenerations",
                columns: table => new
                {
                    AuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorityLineageId = table.Column<Guid>(type: "uuid", nullable: false),
                    Sequence = table.Column<long>(type: "bigint", nullable: false),
                    PreviousGenerationId = table.Column<Guid>(type: "uuid", nullable: true),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    CanonicalPayloadUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    SignedStatementUtf8 = table.Column<byte[]>(type: "bytea", nullable: false),
                    AuthorityDigest = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    SignatureAlgorithm = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    SignatureKeyId = table.Column<string>(type: "varchar(128)", nullable: false, collation: "C"),
                    SignatureValue = table.Column<string>(type: "varchar(342)", nullable: false, collation: "C"),
                    OccurredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_REAuthorityGenerations", x => x.AuthorityGenerationId);
                    table.UniqueConstraint("AK_REAuthorityGenerations_GenerationId_RequestId", x => new { x.AuthorityGenerationId, x.RequestId });
                    table.UniqueConstraint("AK_REAuthorityGenerations_LineageId_GenerationId", x => new { x.AuthorityLineageId, x.AuthorityGenerationId });
                    table.UniqueConstraint("AK_REAuthorityGenerations_LineageId_GenerationId_Sequence", x => new { x.AuthorityLineageId, x.AuthorityGenerationId, x.Sequence });
                    table.CheckConstraint("CK_REAuthorityGenerations_Algorithm", "\"SignatureAlgorithm\" = 'PS256'");
                    table.CheckConstraint("CK_REAuthorityGenerations_KeyId", "octet_length(\"SignatureKeyId\") BETWEEN 1 AND 128 AND \"SignatureKeyId\" ~ '^[a-z0-9][a-z0-9._-]{0,127}$'");
                    table.CheckConstraint("CK_REAuthorityGenerations_PayloadBytes", "octet_length(\"CanonicalPayloadUtf8\") BETWEEN 1 AND 2895");
                    table.CheckConstraint("CK_REAuthorityGenerations_Sequence", "(\"Sequence\" = 0 AND \"PreviousGenerationId\" IS NULL) OR (\"Sequence\" > 0 AND \"PreviousGenerationId\" IS NOT NULL)");
                    table.CheckConstraint("CK_REAuthorityGenerations_Signature", "octet_length(\"SignatureValue\") = 342 AND \"SignatureValue\" !~ '[^A-Za-z0-9_-]'");
                    table.CheckConstraint("CK_REAuthorityGenerations_StatementBytes", "octet_length(\"SignedStatementUtf8\") BETWEEN 1 AND 3569");
                    table.CheckConstraint("CK_RuntimeEnrollmentAuthorityGenerations_AuthorityDigest", "octet_length(\"AuthorityDigest\") = 64 AND \"AuthorityDigest\" ~ '^[0-9a-f]{64}$'");
                    table.ForeignKey(
                        name: "FK_REAuthorityGenerations_REAuthorityGenerations_Predecessor",
                        columns: x => new { x.AuthorityLineageId, x.PreviousGenerationId },
                        principalTable: "RuntimeEnrollmentAuthorityGenerations",
                        principalColumns: new[] { "AuthorityLineageId", "AuthorityGenerationId" });
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentAuthorityLineages",
                columns: table => new
                {
                    AuthorityLineageId = table.Column<Guid>(type: "uuid", nullable: false),
                    Provider = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderGrantRef = table.Column<string>(type: "varchar(1536)", nullable: false, collation: "C"),
                    ProviderGrantRefScalarCount = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    HeadGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    HeadSequence = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_REAuthorityLineages", x => x.AuthorityLineageId);
                    table.CheckConstraint("CK_REAuthorityLineages_GrantRef", "octet_length(\"ProviderGrantRef\") BETWEEN 1 AND 1536 AND \"ProviderGrantRefScalarCount\" BETWEEN 1 AND 256");
                    table.CheckConstraint("CK_REAuthorityLineages_HeadSequence", "\"HeadSequence\" >= 0");
                    table.CheckConstraint("CK_REAuthorityLineages_Provider", "octet_length(\"Provider\") BETWEEN 1 AND 64 AND \"Provider\" ~ '^[a-z0-9][a-z0-9._-]{0,63}$'");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentAuthorityRequests",
                columns: table => new
                {
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigest = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    AuthorityGenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    ResultCode = table.Column<string>(type: "varchar(8)", nullable: false, collation: "C"),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_REAuthorityRequests", x => x.RequestId);
                    table.CheckConstraint("CK_REAuthorityRequests_ResultCode", "\"ResultCode\" = 'ACCEPTED'");
                    table.CheckConstraint("CK_RuntimeEnrollmentAuthorityRequests_RequestDigest", "octet_length(\"RequestDigest\") = 64 AND \"RequestDigest\" ~ '^[0-9a-f]{64}$'");
                    table.ForeignKey(
                        name: "FK_REAuthorityRequests_REAuthorityGenerations_Result",
                        columns: x => new { x.AuthorityGenerationId, x.RequestId },
                        principalTable: "RuntimeEnrollmentAuthorityGenerations",
                        principalColumns: new[] { "AuthorityGenerationId", "RequestId" });
                });

            migrationBuilder.CreateIndex(
                name: "UX_REAuthorityGenerations_LineageId_PredecessorId",
                table: "RuntimeEnrollmentAuthorityGenerations",
                columns: new[] { "AuthorityLineageId", "PreviousGenerationId" },
                unique: true,
                filter: "\"PreviousGenerationId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "UX_REAuthorityGenerations_LineageId_Sequence",
                table: "RuntimeEnrollmentAuthorityGenerations",
                columns: new[] { "AuthorityLineageId", "Sequence" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentAuthorityLineages_AuthorityLineageId_HeadG~",
                table: "RuntimeEnrollmentAuthorityLineages",
                columns: new[] { "AuthorityLineageId", "HeadGenerationId", "HeadSequence" });

            migrationBuilder.CreateIndex(
                name: "UX_REAuthorityLineages_Provider_ProductId_GrantRef",
                table: "RuntimeEnrollmentAuthorityLineages",
                columns: new[] { "Provider", "ProductId", "ProviderGrantRef" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_REAuthorityRequests_GenerationId_RequestId",
                table: "RuntimeEnrollmentAuthorityRequests",
                columns: new[] { "AuthorityGenerationId", "RequestId" });

            migrationBuilder.AddForeignKey(
                name: "FK_REAuthorityGenerations_REAuthorityLineages_Lineage",
                table: "RuntimeEnrollmentAuthorityGenerations",
                column: "AuthorityLineageId",
                principalTable: "RuntimeEnrollmentAuthorityLineages",
                principalColumn: "AuthorityLineageId");

            migrationBuilder.Sql("""
                ALTER TABLE public."RuntimeEnrollmentAuthorityLineages"
                ADD CONSTRAINT "FK_REAuthorityLineages_REAuthorityGenerations_Head"
                FOREIGN KEY ("AuthorityLineageId", "HeadGenerationId", "HeadSequence")
                REFERENCES public."RuntimeEnrollmentAuthorityGenerations"
                    ("AuthorityLineageId", "AuthorityGenerationId", "Sequence")
                ON DELETE NO ACTION
                DEFERRABLE INITIALLY DEFERRED;

                CREATE FUNCTION public.runtime_enrollment_validate_generation_predecessor()
                RETURNS trigger
                LANGUAGE plpgsql
                SET search_path = pg_catalog, pg_temp
                AS $function$
                DECLARE
                    predecessor_sequence bigint;
                BEGIN
                    IF NEW."PreviousGenerationId" IS NULL THEN
                        IF NEW."Sequence" <> 0 THEN
                            RAISE EXCEPTION USING ERRCODE = '23514',
                                MESSAGE = 'runtime enrollment genesis sequence is invalid';
                        END IF;
                        RETURN NEW;
                    END IF;

                    SELECT generation."Sequence"
                    INTO predecessor_sequence
                    FROM public."RuntimeEnrollmentAuthorityGenerations" AS generation
                    WHERE generation."AuthorityLineageId" = NEW."AuthorityLineageId"
                      AND generation."AuthorityGenerationId" = NEW."PreviousGenerationId";

                    IF NOT FOUND THEN
                        RAISE EXCEPTION USING ERRCODE = '23503',
                            MESSAGE = 'runtime enrollment predecessor is missing';
                    END IF;
                    IF predecessor_sequence = 9223372036854775807
                       OR NEW."Sequence" <> predecessor_sequence + 1 THEN
                        RAISE EXCEPTION USING ERRCODE = '23514',
                            MESSAGE = 'runtime enrollment generation sequence is not adjacent';
                    END IF;
                    RETURN NEW;
                END;
                $function$;

                CREATE TRIGGER trg_runtime_enrollment_generation_predecessor_insert
                BEFORE INSERT ON public."RuntimeEnrollmentAuthorityGenerations"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_validate_generation_predecessor();

                CREATE FUNCTION public.runtime_enrollment_reject_authority_history_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                SET search_path = pg_catalog, pg_temp
                AS $function$
                BEGIN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment authority history is immutable';
                END;
                $function$;

                CREATE TRIGGER trg_runtime_enrollment_authority_generations_immutable
                BEFORE UPDATE OR DELETE ON public."RuntimeEnrollmentAuthorityGenerations"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_reject_authority_history_mutation();
                CREATE TRIGGER trg_runtime_enrollment_authority_generations_no_truncate
                BEFORE TRUNCATE ON public."RuntimeEnrollmentAuthorityGenerations"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_reject_authority_history_mutation();
                CREATE TRIGGER trg_runtime_enrollment_authority_requests_immutable
                BEFORE UPDATE OR DELETE ON public."RuntimeEnrollmentAuthorityRequests"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_reject_authority_history_mutation();
                CREATE TRIGGER trg_runtime_enrollment_authority_requests_no_truncate
                BEFORE TRUNCATE ON public."RuntimeEnrollmentAuthorityRequests"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_reject_authority_history_mutation();
                CREATE TRIGGER trg_runtime_enrollment_authority_lineages_no_delete
                BEFORE DELETE ON public."RuntimeEnrollmentAuthorityLineages"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_reject_authority_history_mutation();
                CREATE TRIGGER trg_runtime_enrollment_authority_lineages_no_truncate
                BEFORE TRUNCATE ON public."RuntimeEnrollmentAuthorityLineages"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_reject_authority_history_mutation();

                CREATE FUNCTION public.runtime_enrollment_guard_authority_lineage_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                SET search_path = pg_catalog, pg_temp
                AS $function$
                BEGIN
                    IF NEW."AuthorityLineageId" IS DISTINCT FROM OLD."AuthorityLineageId"
                       OR NEW."Provider" IS DISTINCT FROM OLD."Provider"
                       OR NEW."ProductId" IS DISTINCT FROM OLD."ProductId"
                       OR NEW."ProviderGrantRef" IS DISTINCT FROM OLD."ProviderGrantRef"
                       OR NEW."ProviderGrantRefScalarCount" IS DISTINCT FROM OLD."ProviderGrantRefScalarCount"
                       OR NEW."CreatedAtUtc" IS DISTINCT FROM OLD."CreatedAtUtc"
                       OR NEW."HeadGenerationId" IS NOT DISTINCT FROM OLD."HeadGenerationId"
                       OR OLD."HeadSequence" = 9223372036854775807
                       OR NEW."HeadSequence" <> OLD."HeadSequence" + 1
                       OR NOT EXISTS (
                           SELECT 1
                           FROM public."RuntimeEnrollmentAuthorityGenerations" AS generation
                           WHERE generation."AuthorityLineageId" = OLD."AuthorityLineageId"
                             AND generation."AuthorityGenerationId" = NEW."HeadGenerationId"
                             AND generation."Sequence" = NEW."HeadSequence"
                             AND generation."PreviousGenerationId" = OLD."HeadGenerationId"
                       ) THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment lineage mutation is not an adjacent head advance';
                    END IF;
                    RETURN NEW;
                END;
                $function$;

                CREATE TRIGGER trg_runtime_enrollment_authority_lineage_update
                BEFORE UPDATE ON public."RuntimeEnrollmentAuthorityLineages"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_guard_authority_lineage_mutation();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_authority_lineage_update
                    ON public."RuntimeEnrollmentAuthorityLineages";
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_authority_lineages_no_truncate
                    ON public."RuntimeEnrollmentAuthorityLineages";
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_authority_lineages_no_delete
                    ON public."RuntimeEnrollmentAuthorityLineages";
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_authority_requests_no_truncate
                    ON public."RuntimeEnrollmentAuthorityRequests";
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_authority_requests_immutable
                    ON public."RuntimeEnrollmentAuthorityRequests";
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_authority_generations_no_truncate
                    ON public."RuntimeEnrollmentAuthorityGenerations";
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_authority_generations_immutable
                    ON public."RuntimeEnrollmentAuthorityGenerations";
                DROP TRIGGER IF EXISTS trg_runtime_enrollment_generation_predecessor_insert
                    ON public."RuntimeEnrollmentAuthorityGenerations";
                DROP FUNCTION IF EXISTS public.runtime_enrollment_guard_authority_lineage_mutation();
                DROP FUNCTION IF EXISTS public.runtime_enrollment_reject_authority_history_mutation();
                DROP FUNCTION IF EXISTS public.runtime_enrollment_validate_generation_predecessor();
                ALTER TABLE public."RuntimeEnrollmentAuthorityLineages"
                    DROP CONSTRAINT IF EXISTS "FK_REAuthorityLineages_REAuthorityGenerations_Head";
                """);

            migrationBuilder.DropForeignKey(
                name: "FK_REAuthorityGenerations_REAuthorityLineages_Lineage",
                table: "RuntimeEnrollmentAuthorityGenerations");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentAuthorityRequests");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentAuthorityLineages");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentAuthorityGenerations");
        }
    }
}

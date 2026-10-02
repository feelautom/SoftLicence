using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Backfills and freezes the commercial seat identity that partitions provider authority lineages.
/// The upgrade fails closed when historical canonical generations do not prove one stable lowercase
/// UUID-D seat for the complete lineage. Downgrade removes only the additive seat scope and restores
/// the former grant-wide uniqueness rule, so it fails when several seat-scoped lineages share a grant.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20260828095000_AddTkt000732SeatScopedAuthorityLineages")]
public partial class AddTkt000732SeatScopedAuthorityLineages : Migration
{
    /// <summary>
    /// Adds a nullable staging column, derives it from every lineage's canonical generations, rejects
    /// ambiguous or changing seats, then makes the seat part of the immutable unique tuple. The existing
    /// head-only update trigger is removed only around the transactional backfill and restored immediately.
    /// </summary>
    /// <param name="migrationBuilder">The EF migration command builder for the current transaction.</param>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<Guid>(
            name: "LicenseSeatId",
            table: "RuntimeEnrollmentAuthorityLineages",
            type: "uuid",
            nullable: true);

        migrationBuilder.Sql("""
            DO $tkt000732$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM public."RuntimeEnrollmentAuthorityGenerations" generation
                    CROSS JOIN LATERAL (
                        SELECT convert_from(generation."CanonicalPayloadUtf8", 'UTF8')::jsonb AS payload
                    ) parsed
                    WHERE parsed.payload #>> '{installation,seatId}' IS NULL
                       OR parsed.payload #>> '{installation,seatId}'
                            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                       OR parsed.payload ->> 'authorityLineageId' <> generation."AuthorityLineageId"::text
                ) THEN
                    RAISE EXCEPTION 'TKT000732 historical authority seat scope is not provable'
                        USING ERRCODE = '23514';
                END IF;

                IF EXISTS (
                    SELECT 1
                    FROM public."RuntimeEnrollmentAuthorityGenerations" generation
                    CROSS JOIN LATERAL (
                        SELECT convert_from(generation."CanonicalPayloadUtf8", 'UTF8')::jsonb AS payload
                    ) parsed
                    GROUP BY generation."AuthorityLineageId"
                    HAVING count(DISTINCT parsed.payload #>> '{installation,seatId}') <> 1
                ) THEN
                    RAISE EXCEPTION 'TKT000732 historical lineage crosses commercial seats'
                        USING ERRCODE = '23514';
                END IF;

                DROP TRIGGER trg_runtime_enrollment_authority_lineage_update
                    ON public."RuntimeEnrollmentAuthorityLineages";

                UPDATE public."RuntimeEnrollmentAuthorityLineages" lineage
                SET "LicenseSeatId" = scoped."SeatId"
                FROM (
                    SELECT generation."AuthorityLineageId",
                           min(parsed.payload #>> '{installation,seatId}')::uuid AS "SeatId"
                    FROM public."RuntimeEnrollmentAuthorityGenerations" generation
                    CROSS JOIN LATERAL (
                        SELECT convert_from(generation."CanonicalPayloadUtf8", 'UTF8')::jsonb AS payload
                    ) parsed
                    GROUP BY generation."AuthorityLineageId"
                ) scoped
                WHERE scoped."AuthorityLineageId" = lineage."AuthorityLineageId";

                CREATE TRIGGER trg_runtime_enrollment_authority_lineage_update
                BEFORE UPDATE ON public."RuntimeEnrollmentAuthorityLineages"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_guard_authority_lineage_mutation();

                IF EXISTS (
                    SELECT 1 FROM public."RuntimeEnrollmentAuthorityLineages"
                    WHERE "LicenseSeatId" IS NULL
                ) THEN
                    RAISE EXCEPTION 'TKT000732 lineage has no canonical seat evidence'
                        USING ERRCODE = '23514';
                END IF;
            END
            $tkt000732$;
            """);

        migrationBuilder.AlterColumn<Guid>(
            name: "LicenseSeatId",
            table: "RuntimeEnrollmentAuthorityLineages",
            type: "uuid",
            nullable: false,
            oldClrType: typeof(Guid),
            oldType: "uuid",
            oldNullable: true);

        migrationBuilder.DropIndex(
            name: "UX_REAuthorityLineages_Provider_ProductId_GrantRef",
            table: "RuntimeEnrollmentAuthorityLineages");

        migrationBuilder.CreateIndex(
            name: "UX_REAuthorityLineages_Provider_ProductId_GrantRef_SeatId",
            table: "RuntimeEnrollmentAuthorityLineages",
            columns: new[] { "Provider", "ProductId", "ProviderGrantRef", "LicenseSeatId" },
            unique: true);

        migrationBuilder.Sql("""
            CREATE FUNCTION public."Tkt000732_FreezeAuthorityLineageSeatScope"()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $function$
            BEGIN
                IF NEW."LicenseSeatId" IS DISTINCT FROM OLD."LicenseSeatId" THEN
                    RAISE EXCEPTION 'TKT000732 authority lineage seat scope is immutable'
                        USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END;
            $function$;

            CREATE TRIGGER "TR_Tkt000732_REAuthorityLineages_SeatScopeImmutable"
            BEFORE UPDATE OF "LicenseSeatId"
            ON public."RuntimeEnrollmentAuthorityLineages"
            FOR EACH ROW EXECUTE FUNCTION public."Tkt000732_FreezeAuthorityLineageSeatScope"();
            """);
    }

    /// <summary>
    /// Restores grant-wide uniqueness before removing the seat column; PostgreSQL rejects downgrade
    /// transactionally when distinct seats now legitimately occupy the same provider grant.
    /// </summary>
    /// <param name="migrationBuilder">The EF migration command builder for the current transaction.</param>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DROP TRIGGER IF EXISTS "TR_Tkt000732_REAuthorityLineages_SeatScopeImmutable"
                ON public."RuntimeEnrollmentAuthorityLineages";
            DROP FUNCTION IF EXISTS public."Tkt000732_FreezeAuthorityLineageSeatScope"();
            """);

        migrationBuilder.DropIndex(
            name: "UX_REAuthorityLineages_Provider_ProductId_GrantRef_SeatId",
            table: "RuntimeEnrollmentAuthorityLineages");

        migrationBuilder.CreateIndex(
            name: "UX_REAuthorityLineages_Provider_ProductId_GrantRef",
            table: "RuntimeEnrollmentAuthorityLineages",
            columns: new[] { "Provider", "ProductId", "ProviderGrantRef" },
            unique: true);

        migrationBuilder.DropColumn(
            name: "LicenseSeatId",
            table: "RuntimeEnrollmentAuthorityLineages");
    }
}

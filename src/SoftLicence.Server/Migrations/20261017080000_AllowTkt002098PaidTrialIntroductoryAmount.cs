using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Accepts the 9700-cent PAID_TRIAL introductory offer beside the historical 10000-cent amount under a bounded
/// PostgreSQL DDL lock wait. Downgrade fails closed while any 9700-cent PAID_TRIAL proof exists so rollback never
/// rewrites or orphans immutable commercial evidence.
/// </summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20261017080000_AllowTkt002098PaidTrialIntroductoryAmount")]
public partial class AllowTkt002098PaidTrialIntroductoryAmount : Migration
{
    /// <summary>Replaces the evidence value constraint after bounding PostgreSQL lock acquisition to fifteen seconds.</summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Fail quickly instead of allowing constraint replacement to wait indefinitely behind production traffic.
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.DropCheckConstraint(
            name: "CK_CommercialOrderEvidence_Values",
            table: "CommercialOrderEvidence");
        migrationBuilder.AddCheckConstraint(
            name: "CK_CommercialOrderEvidence_Values",
            table: "CommercialOrderEvidence",
            sql: "\"Version\" = 2 AND \"Currency\" = 'eur' AND length(\"AttributionDigest\") = 64 AND ((\"Nature\" IN ('FIRST_ORDER_FREE','FREE') AND \"PaidAmountMinor\" = 0) OR (\"Nature\" = 'PAID_TRIAL' AND \"PaidAmountMinor\" IN (9700, 10000)) OR (\"Nature\" = 'PAID' AND \"PaidAmountMinor\" > 0))");
    }

    /// <summary>
    /// Restores the 10000-only constraint only when no 9700-cent PAID_TRIAL proof exists; otherwise PostgreSQL aborts
    /// the transactional migration with an actionable error instead of rewriting evidence.
    /// </summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Keep the same bounded DDL wait and refuse a rollback that the historical constraint could not represent.
        migrationBuilder.Sql("SET LOCAL lock_timeout = '15s';");
        migrationBuilder.Sql("""
            DO $tkt002098_guard$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM public."CommercialOrderEvidence"
                    WHERE "Nature" = 'PAID_TRIAL' AND "PaidAmountMinor" = 9700
                ) THEN
                    RAISE EXCEPTION 'TKT-002098 downgrade refused: PAID_TRIAL evidence at 9700 cents exists; archive or remove it explicitly before retrying.';
                END IF;
            END
            $tkt002098_guard$;
            """);
        migrationBuilder.DropCheckConstraint(
            name: "CK_CommercialOrderEvidence_Values",
            table: "CommercialOrderEvidence");
        migrationBuilder.AddCheckConstraint(
            name: "CK_CommercialOrderEvidence_Values",
            table: "CommercialOrderEvidence",
            sql: "\"Version\" = 2 AND \"Currency\" = 'eur' AND length(\"AttributionDigest\") = 64 AND ((\"Nature\" IN ('FIRST_ORDER_FREE','FREE') AND \"PaidAmountMinor\" = 0) OR (\"Nature\" = 'PAID_TRIAL' AND \"PaidAmountMinor\" = 10000) OR (\"Nature\" = 'PAID' AND \"PaidAmountMinor\" > 0))");
    }
}

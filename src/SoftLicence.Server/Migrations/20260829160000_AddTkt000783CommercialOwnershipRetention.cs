using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Installs PostgreSQL-owned guards that reject physical removal of retained commercial
    /// ownership history without changing the EF model or any recovery writer.
    /// </summary>
    /// <remarks>
    /// PostgreSQL applies the function and both triggers in the migration transaction. The row-level
    /// DELETE guard and statement-level TRUNCATE guard deliberately share one closed failure contract.
    /// </remarks>
    public partial class AddTkt000783CommercialOwnershipRetention : Migration
    {
        /// <summary>
        /// Creates the SQLSTATE 55000 rejection function and exact DELETE/TRUNCATE trigger pair.
        /// </summary>
        /// <param name="migrationBuilder">Provider operations executed atomically by PostgreSQL.</param>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Physical retention is a PostgreSQL authority invariant. Keeping both entry points in
            // one function guarantees identical closed failures for row and statement operations.
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.tkt000783_reject_commercial_ownership_removal()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    RAISE EXCEPTION 'commercial ownership authority history cannot be physically removed'
                        USING ERRCODE = '55000';
                END;
                $function$;

                CREATE TRIGGER trg_tkt000783_commercial_ownership_no_delete
                BEFORE DELETE ON public."RuntimeRecoveryCommercialOwnerships"
                FOR EACH ROW
                EXECUTE FUNCTION public.tkt000783_reject_commercial_ownership_removal();

                CREATE TRIGGER trg_tkt000783_commercial_ownership_no_truncate
                BEFORE TRUNCATE ON public."RuntimeRecoveryCommercialOwnerships"
                FOR EACH STATEMENT
                EXECUTE FUNCTION public.tkt000783_reject_commercial_ownership_removal();
                """);
        }

        /// <summary>
        /// Removes only the TKT-000783 trigger pair and its dedicated function in dependency order.
        /// </summary>
        /// <param name="migrationBuilder">Provider operations executed atomically by PostgreSQL.</param>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS trg_tkt000783_commercial_ownership_no_truncate
                    ON public."RuntimeRecoveryCommercialOwnerships";
                DROP TRIGGER IF EXISTS trg_tkt000783_commercial_ownership_no_delete
                    ON public."RuntimeRecoveryCommercialOwnerships";
                DROP FUNCTION IF EXISTS public.tkt000783_reject_commercial_ownership_removal();
                """);
        }
    }
}

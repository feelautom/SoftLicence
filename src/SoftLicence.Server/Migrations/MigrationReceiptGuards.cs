using Microsoft.EntityFrameworkCore.Migrations;

namespace SoftLicence.Server.Migrations;

/// <summary>
/// Frozen SQL for the additive TKT-001493 receipt migration. Durable proof has no TTL and cannot
/// be rolled back by dropping populated evidence; operators must restore a verified pre-migration backup.
/// </summary>
internal static class MigrationReceiptGuards
{
    /// <summary>Frozen append-only function body, also checked by the runtime catalog validator.</summary>
    internal const string ImmutableSource = """
        BEGIN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'accepted migration receipt is immutable';
        END;
        """;

    /// <summary>Frozen key-retention function body; referenced keys cannot enter the retired state.</summary>
    internal const string KeyRetentionSource = """
        BEGIN
            IF OLD."Purpose" = 'encryption' AND NEW."State" = 'retired'
               AND EXISTS (SELECT 1 FROM public."HardwareAuthorityMigrationReceipts"
                           WHERE "KeyId" = OLD."KeyId") THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'key is referenced by durable migration receipt';
            END IF;
            RETURN NEW;
        END;
        """;

    /// <summary>Installs append-only storage and an independent encryption-key retirement guard.</summary>
    /// <param name="migrationBuilder">PostgreSQL migration transaction after creation of the receipt table.</param>
    internal static void Install(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql($$"""
            CREATE FUNCTION public.runtime_migration_receipt_immutable()
            RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $guard${{ImmutableSource}}$guard$;
            REVOKE ALL ON FUNCTION public.runtime_migration_receipt_immutable() FROM PUBLIC;
            CREATE TRIGGER "TR_MigrationReceipt_Immutable"
                BEFORE UPDATE OR DELETE ON public."HardwareAuthorityMigrationReceipts"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_migration_receipt_immutable();
            CREATE TRIGGER "TR_MigrationReceipt_NoTruncate"
                BEFORE TRUNCATE ON public."HardwareAuthorityMigrationReceipts"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_migration_receipt_immutable();

            CREATE FUNCTION public.runtime_migration_receipt_key_retirement()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $guard${{KeyRetentionSource}}$guard$;
            REVOKE ALL ON FUNCTION public.runtime_migration_receipt_key_retirement() FROM PUBLIC;
            CREATE TRIGGER "TR_MigrationReceipt_KeyRetention"
                BEFORE UPDATE ON public."RuntimeEnrollmentKeyRegistries"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_migration_receipt_key_retirement();
            DO $owner$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                           WHERE rolname = 'softlicence_runtime_authority_owner' AND NOT rolcanlogin) THEN
                    ALTER FUNCTION public.runtime_migration_receipt_key_retirement()
                        OWNER TO softlicence_runtime_authority_owner;
                    ALTER FUNCTION public.runtime_migration_receipt_immutable()
                        OWNER TO softlicence_runtime_authority_owner;
                    GRANT SELECT ON public."HardwareAuthorityMigrationReceipts" TO softlicence_runtime_authority_owner;
                END IF;
            END;
            $owner$;
            """);
    }

    /// <summary>
    /// Refuses destructive rollback once durable facts exist; otherwise removes only this migration's guards.
    /// The caller must subsequently remove the empty table and nullable alias reference in dependency order.
    /// </summary>
    /// <param name="migrationBuilder">PostgreSQL rollback transaction.</param>
    internal static void RemoveWhenEmpty(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            LOCK TABLE public."HardwareAuthorityMigrationReceipts" IN ACCESS EXCLUSIVE MODE;
            DO $guard$
            BEGIN
                IF EXISTS (SELECT 1 FROM public."HardwareAuthorityMigrationReceipts") THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'durable migration receipts exist; restore a verified backup instead of dropping proof';
                END IF;
            END;
            $guard$;
            DROP TRIGGER "TR_MigrationReceipt_KeyRetention" ON public."RuntimeEnrollmentKeyRegistries";
            DROP FUNCTION public.runtime_migration_receipt_key_retirement();
            DROP TRIGGER "TR_MigrationReceipt_Immutable" ON public."HardwareAuthorityMigrationReceipts";
            DROP TRIGGER "TR_MigrationReceipt_NoTruncate" ON public."HardwareAuthorityMigrationReceipts";
            DROP FUNCTION public.runtime_migration_receipt_immutable();
            """);
    }
}

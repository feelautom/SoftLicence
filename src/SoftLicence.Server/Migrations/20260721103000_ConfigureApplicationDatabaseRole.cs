using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

[DbContext(typeof(LicenseDbContext))]
[Migration("20260721103000_ConfigureApplicationDatabaseRole")]
public sealed class ConfigureApplicationDatabaseRole : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
            throw new NotSupportedException("Application database role migration requires PostgreSQL.");

        migrationBuilder.Sql("""
            DO $application_role$
            DECLARE
                role_record pg_catalog.pg_roles%ROWTYPE;
            BEGIN
                SELECT * INTO role_record
                FROM pg_catalog.pg_roles
                WHERE rolname = 'softlicence_app';

                IF NOT FOUND THEN
                    RAISE NOTICE 'softlicence_app does not exist; application grants were not applied';
                    RETURN;
                END IF;

                IF NOT role_record.rolcanlogin
                   OR role_record.rolinherit
                   OR role_record.rolsuper
                   OR role_record.rolcreatedb
                   OR role_record.rolcreaterole
                   OR role_record.rolreplication
                   OR role_record.rolbypassrls
                   OR pg_catalog.pg_has_role(
                       'softlicence_app',
                       'softlicence_runtime_authority_owner',
                       'MEMBER') THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'softlicence_app role attributes are not safe';
                END IF;

                EXECUTE pg_catalog.format(
                    'GRANT CONNECT ON DATABASE %I TO softlicence_app',
                    pg_catalog.current_database());
                GRANT USAGE ON SCHEMA public TO softlicence_app;
                GRANT SELECT, INSERT, UPDATE, DELETE
                    ON ALL TABLES IN SCHEMA public TO softlicence_app;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO softlicence_app;
                ALTER DEFAULT PRIVILEGES IN SCHEMA public
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO softlicence_app;
                ALTER DEFAULT PRIVILEGES IN SCHEMA public
                    GRANT USAGE, SELECT ON SEQUENCES TO softlicence_app;

                REVOKE ALL ON public."__EFMigrationsHistory" FROM softlicence_app;

                REVOKE ALL ON public."RuntimeEnrollmentAuthorityStates" FROM softlicence_app;
                REVOKE ALL ON public."RuntimeEnrollmentKeyRegistries" FROM softlicence_app;
                GRANT SELECT ON public."RuntimeEnrollmentAuthorityStates" TO softlicence_app;
                GRANT SELECT ON public."RuntimeEnrollmentKeyRegistries" TO softlicence_app;

                REVOKE ALL ON public."RuntimeCriticalIncidents" FROM softlicence_app;
                REVOKE ALL ON public."RuntimeCriticalRecoveries" FROM softlicence_app;
                REVOKE ALL ON public."RuntimeCriticalRecoveryReceipts" FROM softlicence_app;
                GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalIncidents" TO softlicence_app;
                GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalRecoveries" TO softlicence_app;
                GRANT SELECT, INSERT, UPDATE ON public."RuntimeCriticalRecoveryReceipts" TO softlicence_app;
            END;
            $application_role$;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
            throw new NotSupportedException("Application database role migration requires PostgreSQL.");

        migrationBuilder.Sql("""
            DO $application_role$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app'
                ) THEN
                    RETURN;
                END IF;

                ALTER DEFAULT PRIVILEGES IN SCHEMA public
                    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM softlicence_app;
                ALTER DEFAULT PRIVILEGES IN SCHEMA public
                    REVOKE USAGE, SELECT ON SEQUENCES FROM softlicence_app;
                REVOKE ALL ON ALL TABLES IN SCHEMA public FROM softlicence_app;
                REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM softlicence_app;
                REVOKE USAGE ON SCHEMA public FROM softlicence_app;
                EXECUTE pg_catalog.format(
                    'REVOKE CONNECT ON DATABASE %I FROM softlicence_app',
                    pg_catalog.current_database());
            END;
            $application_role$;
            """);
    }
}

using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

[DbContext(typeof(LicenseDbContext))]
[Migration("20260721114433_GrantApplicationMigrationHistoryRead")]
public sealed class GrantApplicationMigrationHistoryRead : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
            throw new NotSupportedException("Application database role migration requires PostgreSQL.");

        migrationBuilder.Sql("""
            DO $application_role$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app'
                ) THEN
                    GRANT SELECT ON public."__EFMigrationsHistory" TO softlicence_app;
                END IF;
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
                IF EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app'
                ) THEN
                    REVOKE SELECT ON public."__EFMigrationsHistory" FROM softlicence_app;
                END IF;
            END;
            $application_role$;
            """);
    }
}

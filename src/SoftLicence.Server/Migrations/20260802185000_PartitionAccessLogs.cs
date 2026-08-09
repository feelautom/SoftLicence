using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

[DbContext(typeof(LicenseDbContext))]
[Migration("20260802185000_PartitionAccessLogs")]
public sealed class PartitionAccessLogs : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
            throw new NotSupportedException("AccessLogs partitioning requires PostgreSQL.");

        migrationBuilder.Sql("""
            CREATE TABLE public."AccessLogPartitionState" (
                "Id" boolean PRIMARY KEY DEFAULT true CHECK ("Id"),
                "LegacyUpperBoundUtc" timestamp with time zone NOT NULL,
                "LastEnsuredThroughUtc" timestamp with time zone NOT NULL,
                "UpdatedAtUtc" timestamp with time zone NOT NULL
            );

            DO $partition_cutover$
            DECLARE
                legacy_upper_bound timestamp with time zone;
            BEGIN
                LOCK TABLE public."AccessLogs" IN ACCESS EXCLUSIVE MODE;

                SELECT GREATEST(
                    (date_trunc('day', clock_timestamp() AT TIME ZONE 'UTC') + interval '1 day')
                        AT TIME ZONE 'UTC',
                    (date_trunc(
                        'day',
                        COALESCE(
                            MAX("Timestamp") AT TIME ZONE 'UTC',
                            clock_timestamp() AT TIME ZONE 'UTC')) + interval '1 day')
                        AT TIME ZONE 'UTC')
                INTO legacy_upper_bound
                FROM public."AccessLogs";

                ALTER TABLE public."AccessLogs" RENAME TO "AccessLogsLegacy";
                ALTER TABLE public."AccessLogsLegacy"
                    RENAME CONSTRAINT "PK_AccessLogs" TO "PK_AccessLogsLegacy";
                ALTER INDEX public."IX_AccessLogs_ClientIp"
                    RENAME TO "IX_AccessLogsLegacy_ClientIp";
                ALTER INDEX public."IX_AccessLogs_Timestamp"
                    RENAME TO "IX_AccessLogsLegacy_Timestamp";
                ALTER INDEX public."IX_AccessLogs_AppName_Timestamp"
                    RENAME TO "IX_AccessLogsLegacy_AppName_Timestamp";
                ALTER INDEX public."IX_AccessLogs_AppName_Endpoint_Timestamp"
                    RENAME TO "IX_AccessLogsLegacy_AppName_Endpoint_Timestamp";
                ALTER INDEX public."IX_AccessLogs_Timestamp_Endpoint_IsSuccess"
                    RENAME TO "IX_AccessLogsLegacy_Timestamp_Endpoint_IsSuccess";
                ALTER INDEX public."IX_AccessLogs_HardwareId_Timestamp_Endpoint_ResultStatus"
                    RENAME TO "IX_AccessLogsLegacy_HardwareId_Timestamp_Endpoint_ResultStatus";

                CREATE TABLE public."AccessLogs" (
                    LIKE public."AccessLogsLegacy"
                        INCLUDING DEFAULTS
                        INCLUDING STORAGE
                        INCLUDING COMMENTS
                ) PARTITION BY RANGE ("Timestamp");

                EXECUTE format(
                    'ALTER TABLE public."AccessLogs" ATTACH PARTITION public."AccessLogsLegacy" '
                    'FOR VALUES FROM (MINVALUE) TO (%L)',
                    legacy_upper_bound);

                INSERT INTO public."AccessLogPartitionState" (
                    "Id",
                    "LegacyUpperBoundUtc",
                    "LastEnsuredThroughUtc",
                    "UpdatedAtUtc")
                VALUES (
                    true,
                    legacy_upper_bound,
                    legacy_upper_bound - interval '1 day',
                    clock_timestamp());
            END;
            $partition_cutover$;

            CREATE UNIQUE INDEX "UX_AccessLogs_Id_Timestamp"
                ON ONLY public."AccessLogs" ("Id", "Timestamp");
            CREATE UNIQUE INDEX "UX_AccessLogsLegacy_Id_Timestamp"
                ON public."AccessLogsLegacy" ("Id", "Timestamp");
            ALTER INDEX public."UX_AccessLogs_Id_Timestamp"
                ATTACH PARTITION public."UX_AccessLogsLegacy_Id_Timestamp";

            CREATE INDEX "IX_AccessLogs_ClientIp"
                ON ONLY public."AccessLogs" ("ClientIp");
            ALTER INDEX public."IX_AccessLogs_ClientIp"
                ATTACH PARTITION public."IX_AccessLogsLegacy_ClientIp";

            CREATE INDEX "IX_AccessLogs_Timestamp"
                ON ONLY public."AccessLogs" ("Timestamp");
            ALTER INDEX public."IX_AccessLogs_Timestamp"
                ATTACH PARTITION public."IX_AccessLogsLegacy_Timestamp";

            CREATE INDEX "IX_AccessLogs_AppName_Timestamp"
                ON ONLY public."AccessLogs" ("AppName", "Timestamp");
            ALTER INDEX public."IX_AccessLogs_AppName_Timestamp"
                ATTACH PARTITION public."IX_AccessLogsLegacy_AppName_Timestamp";

            CREATE INDEX "IX_AccessLogs_AppName_Endpoint_Timestamp"
                ON ONLY public."AccessLogs" ("AppName", "Endpoint", "Timestamp");
            ALTER INDEX public."IX_AccessLogs_AppName_Endpoint_Timestamp"
                ATTACH PARTITION public."IX_AccessLogsLegacy_AppName_Endpoint_Timestamp";

            CREATE INDEX "IX_AccessLogs_Timestamp_Endpoint_IsSuccess"
                ON ONLY public."AccessLogs" ("Timestamp", "Endpoint", "IsSuccess");
            ALTER INDEX public."IX_AccessLogs_Timestamp_Endpoint_IsSuccess"
                ATTACH PARTITION public."IX_AccessLogsLegacy_Timestamp_Endpoint_IsSuccess";

            CREATE INDEX "IX_AccessLogs_HardwareId_Timestamp_Endpoint_ResultStatus"
                ON ONLY public."AccessLogs" ("HardwareId", "Timestamp", "Endpoint", "ResultStatus");
            ALTER INDEX public."IX_AccessLogs_HardwareId_Timestamp_Endpoint_ResultStatus"
                ATTACH PARTITION public."IX_AccessLogsLegacy_HardwareId_Timestamp_Endpoint_ResultStatus";

            CREATE OR REPLACE FUNCTION public.softlicence_ensure_access_log_partitions(
                requested_through date)
            RETURNS integer
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $partition_function$
            DECLARE
                state_record public."AccessLogPartitionState"%ROWTYPE;
                partition_day date;
                partition_end date;
                partition_name text;
                default_has_rows boolean;
                created_count integer := 0;
            BEGIN
                IF requested_through IS NULL
                   OR requested_through < (clock_timestamp() AT TIME ZONE 'UTC')::date
                   OR requested_through > (clock_timestamp() AT TIME ZONE 'UTC')::date + 90 THEN
                    RAISE EXCEPTION USING ERRCODE = '22023',
                        MESSAGE = 'access_log_partition_horizon_invalid';
                END IF;

                PERFORM pg_advisory_xact_lock(6002242448535449415);
                SELECT * INTO STRICT state_record
                FROM public."AccessLogPartitionState"
                WHERE "Id" = true
                FOR UPDATE;

                partition_day := GREATEST(
                    (state_record."LegacyUpperBoundUtc" AT TIME ZONE 'UTC')::date,
                    (state_record."LastEnsuredThroughUtc" AT TIME ZONE 'UTC')::date + 1);

                WHILE partition_day <= requested_through LOOP
                    partition_end := partition_day + 1;
                    partition_name := 'AccessLogs_p' || to_char(partition_day, 'YYYYMMDD');

                    IF to_regclass('public.' || quote_ident(partition_name)) IS NULL THEN
                        IF to_regclass('public."AccessLogs_default"') IS NULL THEN
                            default_has_rows := false;
                        ELSE
                            EXECUTE format(
                                'SELECT EXISTS ('
                                'SELECT 1 FROM public."AccessLogs_default" '
                                'WHERE "Timestamp" >= %L AND "Timestamp" < %L)',
                                partition_day::timestamp AT TIME ZONE 'UTC',
                                partition_end::timestamp AT TIME ZONE 'UTC')
                            INTO default_has_rows;
                        END IF;

                        IF default_has_rows THEN
                            LOCK TABLE public."AccessLogs_default" IN ACCESS EXCLUSIVE MODE;
                            EXECUTE format(
                                'CREATE TABLE public.%I ('
                                'LIKE public."AccessLogs" INCLUDING DEFAULTS INCLUDING STORAGE INCLUDING COMMENTS)',
                                partition_name);
                            EXECUTE format(
                                'ALTER TABLE public.%I ADD CONSTRAINT %I '
                                'CHECK ("Timestamp" >= %L AND "Timestamp" < %L)',
                                partition_name,
                                partition_name || '_timestamp_check',
                                partition_day::timestamp AT TIME ZONE 'UTC',
                                partition_end::timestamp AT TIME ZONE 'UTC');
                            EXECUTE format(
                                'INSERT INTO public.%I SELECT * FROM public."AccessLogs_default" '
                                'WHERE "Timestamp" >= %L AND "Timestamp" < %L',
                                partition_name,
                                partition_day::timestamp AT TIME ZONE 'UTC',
                                partition_end::timestamp AT TIME ZONE 'UTC');
                            EXECUTE format(
                                'DELETE FROM public."AccessLogs_default" '
                                'WHERE "Timestamp" >= %L AND "Timestamp" < %L',
                                partition_day::timestamp AT TIME ZONE 'UTC',
                                partition_end::timestamp AT TIME ZONE 'UTC');
                            EXECUTE format(
                                'ALTER TABLE public."AccessLogs" ATTACH PARTITION public.%I '
                                'FOR VALUES FROM (%L) TO (%L)',
                                partition_name,
                                partition_day::timestamp AT TIME ZONE 'UTC',
                                partition_end::timestamp AT TIME ZONE 'UTC');
                        ELSE
                            EXECUTE format(
                                'CREATE TABLE public.%I PARTITION OF public."AccessLogs" '
                                'FOR VALUES FROM (%L) TO (%L)',
                                partition_name,
                                partition_day::timestamp AT TIME ZONE 'UTC',
                                partition_end::timestamp AT TIME ZONE 'UTC');
                        END IF;
                        created_count := created_count + 1;
                    END IF;

                    partition_day := partition_end;
                END LOOP;

                UPDATE public."AccessLogPartitionState"
                SET "LastEnsuredThroughUtc" = GREATEST(
                        "LastEnsuredThroughUtc",
                        requested_through::timestamp AT TIME ZONE 'UTC'),
                    "UpdatedAtUtc" = clock_timestamp()
                WHERE "Id" = true;

                RETURN created_count;
            END;
            $partition_function$;

            REVOKE ALL ON FUNCTION public.softlicence_ensure_access_log_partitions(date) FROM PUBLIC;

            SELECT public.softlicence_ensure_access_log_partitions(
                ((clock_timestamp() AT TIME ZONE 'UTC')::date + 45));

            CREATE TABLE public."AccessLogs_default"
                PARTITION OF public."AccessLogs" DEFAULT;

            DO $application_role$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'softlicence_app') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON public."AccessLogs" TO softlicence_app;
                    GRANT EXECUTE ON FUNCTION public.softlicence_ensure_access_log_partitions(date)
                        TO softlicence_app;
                END IF;
            END;
            $application_role$;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
            throw new NotSupportedException("AccessLogs partitioning requires PostgreSQL.");

        migrationBuilder.Sql("""
            DROP FUNCTION IF EXISTS public.softlicence_ensure_access_log_partitions(date);

            LOCK TABLE public."AccessLogs" IN ACCESS EXCLUSIVE MODE;
            ALTER TABLE public."AccessLogs"
                DETACH PARTITION public."AccessLogsLegacy";
            ALTER TABLE public."AccessLogs" RENAME TO "AccessLogsPartitionedRollback";

            ALTER INDEX public."UX_AccessLogs_Id_Timestamp"
                RENAME TO "UX_AccessLogsPartitionedRollback_Id_Timestamp";
            ALTER INDEX public."IX_AccessLogs_ClientIp"
                RENAME TO "IX_AccessLogsPartitionedRollback_ClientIp";
            ALTER INDEX public."IX_AccessLogs_Timestamp"
                RENAME TO "IX_AccessLogsPartitionedRollback_Timestamp";
            ALTER INDEX public."IX_AccessLogs_AppName_Timestamp"
                RENAME TO "IX_AccessLogsPartitionedRollback_AppName_Timestamp";
            ALTER INDEX public."IX_AccessLogs_AppName_Endpoint_Timestamp"
                RENAME TO "IX_AccessLogsPartitionedRollback_AppName_Endpoint_Timestamp";
            ALTER INDEX public."IX_AccessLogs_Timestamp_Endpoint_IsSuccess"
                RENAME TO "IX_AccessLogsPartitionedRollback_Timestamp_Endpoint_IsSuccess";
            ALTER INDEX public."IX_AccessLogs_HardwareId_Timestamp_Endpoint_ResultStatus"
                RENAME TO "IX_AccessLogsPartitionedRollback_HardwareId_Timestamp_Endpoint_ResultStatus";

            ALTER TABLE public."AccessLogsLegacy" RENAME TO "AccessLogs";
            DROP INDEX public."UX_AccessLogsLegacy_Id_Timestamp";
            ALTER TABLE public."AccessLogs"
                RENAME CONSTRAINT "PK_AccessLogsLegacy" TO "PK_AccessLogs";
            ALTER INDEX public."IX_AccessLogsLegacy_ClientIp"
                RENAME TO "IX_AccessLogs_ClientIp";
            ALTER INDEX public."IX_AccessLogsLegacy_Timestamp"
                RENAME TO "IX_AccessLogs_Timestamp";
            ALTER INDEX public."IX_AccessLogsLegacy_AppName_Timestamp"
                RENAME TO "IX_AccessLogs_AppName_Timestamp";
            ALTER INDEX public."IX_AccessLogsLegacy_AppName_Endpoint_Timestamp"
                RENAME TO "IX_AccessLogs_AppName_Endpoint_Timestamp";
            ALTER INDEX public."IX_AccessLogsLegacy_Timestamp_Endpoint_IsSuccess"
                RENAME TO "IX_AccessLogs_Timestamp_Endpoint_IsSuccess";
            ALTER INDEX public."IX_AccessLogsLegacy_HardwareId_Timestamp_Endpoint_ResultStatus"
                RENAME TO "IX_AccessLogs_HardwareId_Timestamp_Endpoint_ResultStatus";

            INSERT INTO public."AccessLogs"
            SELECT * FROM public."AccessLogsPartitionedRollback";

            DROP TABLE public."AccessLogsPartitionedRollback" CASCADE;
            DROP TABLE public."AccessLogPartitionState";
            """);
    }
}

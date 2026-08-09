using System;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Services;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeKeyRetentionAndOperatorGuard : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "RetainUntilUtc",
                table: "RuntimeEnrollmentKeyRegistries",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_RuntimeEnrollmentKeyRegistries_LifecycleTimestamps",
                table: "RuntimeEnrollmentKeyRegistries",
                sql: "(\"State\" = 'previous' AND \"Purpose\" = 'capability-signing' AND \"RetainUntilUtc\" IS NOT NULL AND \"RetiredAtUtc\" IS NULL) OR (\"State\" = 'retired' AND \"RetiredAtUtc\" IS NOT NULL) OR (\"State\" NOT IN ('previous', 'retired') AND \"RetainUntilUtc\" IS NULL AND \"RetiredAtUtc\" IS NULL)");

            InstallGuard(migrationBuilder, RuntimeEnrollmentKeyRegistryService.GuardFunctionSource);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            InstallGuard(migrationBuilder, LegacyGuardFunctionSource);

            migrationBuilder.DropCheckConstraint(
                name: "CK_RuntimeEnrollmentKeyRegistries_LifecycleTimestamps",
                table: "RuntimeEnrollmentKeyRegistries");

            migrationBuilder.DropColumn(
                name: "RetainUntilUtc",
                table: "RuntimeEnrollmentKeyRegistries");
        }

        private static void InstallGuard(MigrationBuilder migrationBuilder, string source)
        {
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.runtime_enrollment_guard_key_registry()
                RETURNS trigger
                LANGUAGE plpgsql
                SECURITY DEFINER
                SET search_path = pg_catalog, pg_temp
                AS $runtime_key_guard$
                """ + source + """

                $runtime_key_guard$;
                REVOKE ALL ON FUNCTION public.runtime_enrollment_guard_key_registry() FROM PUBLIC;
                """);
        }

        private const string LegacyGuardFunctionSource = """
            DECLARE
                referenced boolean;
            BEGIN
                PERFORM pg_catalog.pg_advisory_xact_lock(999831, 1);
                IF TG_OP = 'INSERT' THEN
                    IF NEW."Purpose" = 'registry-version' THEN
                        IF NEW."KeyId" <> 'global'
                           OR NEW."MaterialDigestSha256" <> repeat('0', 64)
                           OR NEW."State" <> 'active'
                           OR NEW."Epoch" <> 1
                           OR NEW."RetiredAtUtc" IS NOT NULL THEN
                            RAISE EXCEPTION USING ERRCODE = '55000',
                                MESSAGE = 'runtime enrollment registry version sentinel is invalid';
                        END IF;
                        RETURN NEW;
                    END IF;
                    IF NEW."RetiredAtUtc" IS NOT NULL OR NEW."Epoch" <> 1 THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment key insertion is invalid';
                    END IF;
                    IF EXISTS (
                        SELECT 1 FROM public."RuntimeEnrollmentKeyRegistries" existing
                        WHERE existing."Purpose" = NEW."Purpose" AND existing."KeyId" = NEW."KeyId"
                          AND (existing."MaterialDigestSha256" IS DISTINCT FROM NEW."MaterialDigestSha256"
                               OR existing."State" IS DISTINCT FROM NEW."State"
                               OR existing."Epoch" IS DISTINCT FROM NEW."Epoch"
                               OR existing."RetiredAtUtc" IS DISTINCT FROM NEW."RetiredAtUtc")
                    ) THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment key id cannot be rebound';
                    END IF;
                    RETURN NEW;
                END IF;
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment key tombstones are permanent';
                END IF;
                IF OLD."Purpose" = 'registry-version' THEN
                    IF NEW."Purpose" IS DISTINCT FROM OLD."Purpose"
                       OR NEW."KeyId" IS DISTINCT FROM OLD."KeyId"
                       OR NEW."MaterialDigestSha256" IS DISTINCT FROM OLD."MaterialDigestSha256"
                       OR NEW."State" IS DISTINCT FROM OLD."State"
                       OR NEW."CreatedAtUtc" IS DISTINCT FROM OLD."CreatedAtUtc"
                       OR NEW."RetiredAtUtc" IS NOT NULL
                       OR NEW."Epoch" <> OLD."Epoch" + 1 THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment registry version transition is invalid';
                    END IF;
                    RETURN NEW;
                END IF;
                IF NEW."Purpose" IS DISTINCT FROM OLD."Purpose"
                   OR NEW."KeyId" IS DISTINCT FROM OLD."KeyId"
                   OR NEW."MaterialDigestSha256" IS DISTINCT FROM OLD."MaterialDigestSha256"
                   OR NEW."CreatedAtUtc" IS DISTINCT FROM OLD."CreatedAtUtc"
                   OR NEW."Epoch" <> OLD."Epoch" + 1
                   OR (OLD."State" = 'retired' AND NEW."State" <> 'retired')
                   OR (NEW."State" = 'retired' AND NEW."RetiredAtUtc" IS NULL)
                   OR (NEW."State" <> 'retired' AND NEW."RetiredAtUtc" IS NOT NULL)
                   OR (OLD."Purpose" = 'encryption' AND NOT (
                       (OLD."State" = 'active' AND NEW."State" IN ('decrypt-only', 'retired'))
                       OR (OLD."State" = 'decrypt-only' AND NEW."State" = 'retired')
                   ))
                   OR (OLD."Purpose" = 'capability-signing' AND NOT (
                       (OLD."State" = 'next' AND NEW."State" = 'active')
                       OR (OLD."State" = 'active' AND NEW."State" = 'previous')
                       OR (OLD."State" IN ('previous', 'verify-only') AND NEW."State" = 'retired')
                   )) THEN
                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'runtime enrollment key lifecycle transition is invalid';
                END IF;
                IF OLD."Purpose" = 'encryption' THEN
                    SELECT EXISTS (
                        SELECT 1 FROM public."RuntimeEnrollments" e
                        WHERE e."PublicKeySpkiKeyId" = OLD."KeyId" OR e."ChallengeKeyId" = OLD."KeyId"
                        UNION ALL SELECT 1 FROM public."RuntimeEnrollmentRequests" r WHERE r."ResponseKeyId" = OLD."KeyId"
                        UNION ALL SELECT 1 FROM public."RuntimeEnrollmentProofNonces" p WHERE p."ResponseKeyId" = OLD."KeyId"
                        UNION ALL SELECT 1 FROM public."RuntimeEnrollmentEncryptionNonces" n WHERE n."KeyId" = OLD."KeyId"
                    ) INTO referenced;
                    IF referenced AND NEW."State" = 'retired' THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment key is still referenced';
                    END IF;
                END IF;
                RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
            END;
            """;
    }
}

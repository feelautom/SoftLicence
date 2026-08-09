using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCanaryAckKeyRegistry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CanaryAckKeyRegistries",
                columns: table => new
                {
                    KeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    MaterialDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Epoch = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RetainUntilUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RetiredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CanaryAckKeyRegistries", x => x.KeyId);
                    table.CheckConstraint("CK_CanaryAckKeyRegistries_Digest", "length(\"MaterialDigestSha256\") = 64 AND \"MaterialDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_CanaryAckKeyRegistries_Epoch", "\"Epoch\" >= 1");
                    table.CheckConstraint("CK_CanaryAckKeyRegistries_Retention", "(\"State\" = 'previous' AND \"RetainUntilUtc\" IS NOT NULL AND \"RetiredAtUtc\" IS NULL) OR (\"State\" = 'retired' AND \"RetiredAtUtc\" IS NOT NULL) OR (\"State\" IN ('active', 'next') AND \"RetainUntilUtc\" IS NULL AND \"RetiredAtUtc\" IS NULL)");
                    table.CheckConstraint("CK_CanaryAckKeyRegistries_State", "\"State\" IN ('active', 'next', 'previous', 'retired')");
                });

            migrationBuilder.CreateTable(
                name: "CanaryAckKeyRegistryStates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    RegistryVersion = table.Column<int>(type: "integer", nullable: false),
                    ContentDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CanaryAckKeyRegistryStates", x => x.Id);
                    table.CheckConstraint("CK_CanaryAckKeyRegistryStates_Digest", "length(\"ContentDigestSha256\") = 64 AND \"ContentDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_CanaryAckKeyRegistryStates_Singleton", "\"Id\" = 1");
                    table.CheckConstraint("CK_CanaryAckKeyRegistryStates_Version", "\"RegistryVersion\" >= 1");
                });

            migrationBuilder.CreateIndex(
                name: "IX_CanaryAckKeyRegistries_Active",
                table: "CanaryAckKeyRegistries",
                column: "State",
                unique: true,
                filter: "\"State\" = 'active'");

            migrationBuilder.CreateIndex(
                name: "IX_CanaryAckKeyRegistries_MaterialDigestSha256",
                table: "CanaryAckKeyRegistries",
                column: "MaterialDigestSha256",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CanaryAckKeyRegistries_Next",
                table: "CanaryAckKeyRegistries",
                column: "State",
                unique: true,
                filter: "\"State\" = 'next'");

            migrationBuilder.Sql(
                """
                CREATE OR REPLACE FUNCTION public.softlicence_canary_ack_key_guard()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    IF TG_OP = 'INSERT' THEN
                        IF NEW."Epoch" <> 1
                           OR NEW."State" NOT IN ('active', 'next')
                           OR NEW."RetainUntilUtc" IS NOT NULL
                           OR NEW."RetiredAtUtc" IS NOT NULL THEN
                            RAISE EXCEPTION USING ERRCODE = '55000',
                                MESSAGE = 'canary ack key insertion is invalid';
                        END IF;
                        RETURN NEW;
                    END IF;

                    IF TG_OP = 'UPDATE' THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'canary ack key promotion is not enabled';
                    END IF;

                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'canary ack key deletion is forbidden';
                END;
                $function$;

                CREATE TRIGGER "TR_CanaryAckKeyRegistries_Guard"
                BEFORE INSERT OR UPDATE OR DELETE ON public."CanaryAckKeyRegistries"
                FOR EACH ROW EXECUTE FUNCTION public.softlicence_canary_ack_key_guard();

                CREATE OR REPLACE FUNCTION public.softlicence_canary_ack_registry_state_guard()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    IF TG_OP = 'INSERT' THEN
                        IF NEW."Id" <> 1 OR NEW."RegistryVersion" <> 1 THEN
                            RAISE EXCEPTION USING ERRCODE = '55000',
                                MESSAGE = 'canary ack registry initialization is invalid';
                        END IF;
                        RETURN NEW;
                    END IF;

                    IF TG_OP = 'UPDATE' THEN
                        IF NEW."Id" IS DISTINCT FROM OLD."Id"
                           OR NEW."RegistryVersion" <> OLD."RegistryVersion" + 1
                           OR NEW."ContentDigestSha256" = OLD."ContentDigestSha256"
                           OR NEW."UpdatedAtUtc" <= OLD."UpdatedAtUtc" THEN
                            RAISE EXCEPTION USING ERRCODE = '55000',
                                MESSAGE = 'canary ack registry version transition is invalid';
                        END IF;
                        RETURN NEW;
                    END IF;

                    RAISE EXCEPTION USING ERRCODE = '55000',
                        MESSAGE = 'canary ack registry deletion is forbidden';
                END;
                $function$;

                CREATE TRIGGER "TR_CanaryAckKeyRegistryStates_Guard"
                BEFORE INSERT OR UPDATE OR DELETE ON public."CanaryAckKeyRegistryStates"
                FOR EACH ROW EXECUTE FUNCTION public.softlicence_canary_ack_registry_state_guard();

                DO $roles$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_roles
                        WHERE rolname = 'softlicence_app'
                    ) THEN
                        REVOKE ALL ON public."CanaryAckKeyRegistries" FROM softlicence_app;
                        REVOKE ALL ON public."CanaryAckKeyRegistryStates" FROM softlicence_app;
                        GRANT SELECT ON public."CanaryAckKeyRegistries" TO softlicence_app;
                        GRANT SELECT ON public."CanaryAckKeyRegistryStates" TO softlicence_app;
                    END IF;
                END;
                $roles$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CanaryAckKeyRegistries");

            migrationBuilder.DropTable(
                name: "CanaryAckKeyRegistryStates");

            migrationBuilder.Sql(
                """
                DROP FUNCTION IF EXISTS public.softlicence_canary_ack_key_guard();
                DROP FUNCTION IF EXISTS public.softlicence_canary_ack_registry_state_guard();
                """);
        }
    }
}

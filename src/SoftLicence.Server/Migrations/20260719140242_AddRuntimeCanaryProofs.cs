using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeCanaryProofs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RuntimeCanaryProofNonces",
                columns: table => new
                {
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Jti = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    EventId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    HardwareIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ReleaseVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    BodyDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProofDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ResponseCiphertext = table.Column<string>(type: "character varying(8192)", maxLength: 8192, nullable: false),
                    ResponseKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ResponseKeyPurpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false, defaultValue: "encryption"),
                    AuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    SentAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeCanaryProofNonces", x => new { x.EnrollmentId, x.Jti });
                    table.CheckConstraint("CK_RuntimeCanaryProofNonces_ResponseKeyPurpose", "\"ResponseKeyPurpose\" = 'encryption'");
                    table.ForeignKey(
                        name: "FK_RuntimeCanaryProofNonces_RuntimeEnrollmentKeyRegistries_Res~",
                        columns: x => new { x.ResponseKeyPurpose, x.ResponseKeyId },
                        principalTable: "RuntimeEnrollmentKeyRegistries",
                        principalColumns: new[] { "Purpose", "KeyId" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RuntimeCanaryProofNonces_RuntimeEnrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCanaryProofNonces_EventId",
                table: "RuntimeCanaryProofNonces",
                column: "EventId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCanaryProofNonces_ExpiresAtUtc",
                table: "RuntimeCanaryProofNonces",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeCanaryProofNonces_ResponseKeyPurpose_ResponseKeyId",
                table: "RuntimeCanaryProofNonces",
                columns: new[] { "ResponseKeyPurpose", "ResponseKeyId" });

            if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
                throw new NotSupportedException("Runtime canary proof migration requires PostgreSQL.");

            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.runtime_canary_guard_key_retirement()
                RETURNS trigger
                LANGUAGE plpgsql
                SECURITY DEFINER
                SET search_path = pg_catalog, pg_temp
                AS $runtime_canary_key_guard$
                BEGIN
                    IF OLD."Purpose" = 'encryption'
                       AND NEW."State" = 'retired'
                       AND OLD."State" <> 'retired'
                       AND EXISTS (
                           SELECT 1 FROM public."RuntimeCanaryProofNonces" proof
                           WHERE proof."ResponseKeyId" = OLD."KeyId"
                       ) THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment key is still referenced by canary proof';
                    END IF;
                    RETURN NEW;
                END;
                $runtime_canary_key_guard$;
                REVOKE ALL ON FUNCTION public.runtime_canary_guard_key_retirement() FROM PUBLIC;
                CREATE TRIGGER trg_runtime_canary_key_retirement_guard
                BEFORE UPDATE ON public."RuntimeEnrollmentKeyRegistries"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_canary_guard_key_retirement();

                DO $runtime_canary_owner$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_catalog.pg_roles
                        WHERE rolname = 'softlicence_runtime_authority_owner' AND NOT rolcanlogin
                    ) THEN
                        ALTER FUNCTION public.runtime_canary_guard_key_retirement()
                            OWNER TO softlicence_runtime_authority_owner;
                        GRANT SELECT ON public."RuntimeCanaryProofNonces"
                            TO softlicence_runtime_authority_owner;
                    END IF;
                END;
                $runtime_canary_owner$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
                throw new NotSupportedException("Runtime canary proof migration requires PostgreSQL.");

            migrationBuilder.Sql("DROP TRIGGER IF EXISTS trg_runtime_canary_key_retirement_guard ON public.\"RuntimeEnrollmentKeyRegistries\";");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS public.runtime_canary_guard_key_retirement();");
            migrationBuilder.DropTable(
                name: "RuntimeCanaryProofNonces");
        }
    }
}

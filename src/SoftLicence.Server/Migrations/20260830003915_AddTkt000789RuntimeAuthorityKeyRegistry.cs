using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt000789RuntimeAuthorityKeyRegistry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RuntimeAuthorityKeyRegistrySnapshots",
                columns: table => new
                {
                    SnapshotId = table.Column<string>(type: "varchar(128)", nullable: false, collation: "C"),
                    RegistryId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    SnapshotVersion = table.Column<long>(type: "bigint", nullable: false),
                    MetadataDigestSha256 = table.Column<string>(type: "char(64)", nullable: false, collation: "C"),
                    RegistryAuthenticationInputDigestSha256 = table.Column<string>(type: "char(64)", nullable: false, collation: "C"),
                    ObservedAtUtc = table.Column<string>(type: "varchar(33)", nullable: false, collation: "C"),
                    PublicationState = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    RevokedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExactResponseBody = table.Column<byte[]>(type: "bytea", nullable: false),
                    ExactResponseBodySha256 = table.Column<string>(type: "char(64)", nullable: false, collation: "C"),
                    RegistrySignatureBase64Url = table.Column<string>(type: "varchar(342)", nullable: false, collation: "C"),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeAuthorityKeyRegistrySnapshots", x => x.SnapshotId);
                    table.UniqueConstraint("AK_RAKRSnapshots_Registry_Snapshot_Version_Metadata_Authentication_State", x => new { x.RegistryId, x.SnapshotId, x.SnapshotVersion, x.MetadataDigestSha256, x.RegistryAuthenticationInputDigestSha256, x.PublicationState });
                    table.UniqueConstraint("AK_RAKRSnapshots_Snapshot_ResponseBodyDigest", x => new { x.SnapshotId, x.ExactResponseBodySha256 });
                    table.CheckConstraint("CK_RAKRSnapshots_Digests", "\"MetadataDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"RegistryAuthenticationInputDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"ExactResponseBodySha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RAKRSnapshots_ObservedAtUtc", "\"ObservedAtUtc\" ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{7}\\+00:00$'");
                    table.CheckConstraint("CK_RAKRSnapshots_RegistryId", "\"RegistryId\" = 'runtime-enrollment-authority-generation-v2'");
                    table.CheckConstraint("CK_RAKRSnapshots_ResponseBytes", "octet_length(\"ExactResponseBody\") BETWEEN 1 AND 16384");
                    table.CheckConstraint("CK_RAKRSnapshots_Revocation", "(\"PublicationState\" = 'revoked' AND \"RevokedAtUtc\" IS NOT NULL) OR (\"PublicationState\" <> 'revoked' AND \"RevokedAtUtc\" IS NULL)");
                    table.CheckConstraint("CK_RAKRSnapshots_Signature", "length(\"RegistrySignatureBase64Url\") = 342 AND \"RegistrySignatureBase64Url\" !~ '[^A-Za-z0-9_-]'");
                    table.CheckConstraint("CK_RAKRSnapshots_State", "\"PublicationState\" IN ('current','superseded','revoked')");
                    table.CheckConstraint("CK_RAKRSnapshots_Version", "\"SnapshotVersion\" > 0");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeAuthorityKeyRegistryHeads",
                columns: table => new
                {
                    RegistryId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    CurrentSnapshotId = table.Column<string>(type: "varchar(128)", nullable: false, collation: "C"),
                    CurrentSnapshotVersion = table.Column<long>(type: "bigint", nullable: false),
                    CurrentMetadataDigestSha256 = table.Column<string>(type: "char(64)", nullable: false, collation: "C"),
                    CurrentRegistryAuthenticationInputDigestSha256 = table.Column<string>(type: "char(64)", nullable: false, collation: "C"),
                    CurrentPublicationState = table.Column<string>(type: "varchar(16)", nullable: false, collation: "C"),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeAuthorityKeyRegistryHeads", x => x.RegistryId);
                    table.CheckConstraint("CK_RAKRHeads_Digests", "\"CurrentMetadataDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"CurrentRegistryAuthenticationInputDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RAKRHeads_RegistryId", "\"RegistryId\" = 'runtime-enrollment-authority-generation-v2'");
                    table.CheckConstraint("CK_RAKRHeads_State", "\"CurrentPublicationState\" = 'current'");
                    table.CheckConstraint("CK_RAKRHeads_Version", "\"CurrentSnapshotVersion\" > 0");
                    table.ForeignKey(
                        name: "FK_RAKRHeads_RAKRSnapshots_CurrentTuple",
                        columns: x => new { x.RegistryId, x.CurrentSnapshotId, x.CurrentSnapshotVersion, x.CurrentMetadataDigestSha256, x.CurrentRegistryAuthenticationInputDigestSha256, x.CurrentPublicationState },
                        principalTable: "RuntimeAuthorityKeyRegistrySnapshots",
                        principalColumns: new[] { "RegistryId", "SnapshotId", "SnapshotVersion", "MetadataDigestSha256", "RegistryAuthenticationInputDigestSha256", "PublicationState" });
                });

            migrationBuilder.CreateTable(
                name: "RuntimeAuthorityKeyRegistryReadbacks",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "varchar(64)", nullable: false, collation: "C"),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigestSha256 = table.Column<string>(type: "char(64)", nullable: false, collation: "C"),
                    SnapshotId = table.Column<string>(type: "varchar(128)", nullable: false, collation: "C"),
                    ExactResponseBodySha256 = table.Column<string>(type: "char(64)", nullable: false, collation: "C"),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeAuthorityKeyRegistryReadbacks", x => new { x.ClientId, x.RequestId });
                    table.CheckConstraint("CK_RAKRReadbacks_ClientId", "length(\"ClientId\") BETWEEN 1 AND 64");
                    table.CheckConstraint("CK_RAKRReadbacks_Digests", "\"RequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"ExactResponseBodySha256\" ~ '^[0-9a-f]{64}$'");
                    table.ForeignKey(
                        name: "FK_RAKRReadbacks_RAKRSnapshots_Body",
                        columns: x => new { x.SnapshotId, x.ExactResponseBodySha256 },
                        principalTable: "RuntimeAuthorityKeyRegistrySnapshots",
                        principalColumns: new[] { "SnapshotId", "ExactResponseBodySha256" });
                });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeAuthorityKeyRegistryHeads_RegistryId_CurrentSnapshot~",
                table: "RuntimeAuthorityKeyRegistryHeads",
                columns: new[] { "RegistryId", "CurrentSnapshotId", "CurrentSnapshotVersion", "CurrentMetadataDigestSha256", "CurrentRegistryAuthenticationInputDigestSha256", "CurrentPublicationState" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeAuthorityKeyRegistryReadbacks_SnapshotId_ExactRespon~",
                table: "RuntimeAuthorityKeyRegistryReadbacks",
                columns: new[] { "SnapshotId", "ExactResponseBodySha256" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeAuthorityKeyRegistrySnapshots_RegistryId_MetadataDig~",
                table: "RuntimeAuthorityKeyRegistrySnapshots",
                columns: new[] { "RegistryId", "MetadataDigestSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeAuthorityKeyRegistrySnapshots_RegistryId_SnapshotVer~",
                table: "RuntimeAuthorityKeyRegistrySnapshots",
                columns: new[] { "RegistryId", "SnapshotVersion" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_RAKRSnapshots_OneCurrentPerRegistry",
                table: "RuntimeAuthorityKeyRegistrySnapshots",
                column: "RegistryId",
                unique: true,
                filter: "\"PublicationState\" = 'current'");

            migrationBuilder.Sql("""
                -- The head FK is deferred only to permit atomic snapshot-then-head bootstrap and promotion.
                -- PostgreSQL still validates the complete current tuple at commit; rollback exposes no orphan head.
                ALTER TABLE public."RuntimeAuthorityKeyRegistryHeads"
                    ALTER CONSTRAINT "FK_RAKRHeads_RAKRSnapshots_CurrentTuple"
                    DEFERRABLE INITIALLY DEFERRED;

                -- Snapshot bytes and authenticated metadata are immutable. Only the closed lifecycle transitions
                -- current->superseded/revoked and superseded->revoked may occur in the same atomic transaction.
                CREATE FUNCTION public.tkt000789_guard_runtime_authority_key_registry_snapshot()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    IF TG_OP = 'UPDATE'
                       AND NEW."SnapshotId" = OLD."SnapshotId"
                       AND NEW."RegistryId" = OLD."RegistryId"
                       AND NEW."SnapshotVersion" = OLD."SnapshotVersion"
                       AND NEW."MetadataDigestSha256" = OLD."MetadataDigestSha256"
                       AND NEW."RegistryAuthenticationInputDigestSha256" = OLD."RegistryAuthenticationInputDigestSha256"
                       AND NEW."ObservedAtUtc" = OLD."ObservedAtUtc"
                       AND NEW."ExactResponseBody" = OLD."ExactResponseBody"
                       AND NEW."ExactResponseBodySha256" = OLD."ExactResponseBodySha256"
                       AND NEW."RegistrySignatureBase64Url" = OLD."RegistrySignatureBase64Url"
                       AND NEW."CreatedAtUtc" = OLD."CreatedAtUtc"
                       AND (
                           (OLD."PublicationState" = 'current' AND NEW."PublicationState" IN ('superseded','revoked'))
                           OR (OLD."PublicationState" = 'superseded' AND NEW."PublicationState" = 'revoked')
                       )
                    THEN
                        RETURN NEW;
                    END IF;
                    RAISE EXCEPTION 'Runtime authority key-registry snapshots are immutable outside closed state transitions'
                        USING ERRCODE = '55000';
                END;
                $function$;

                -- Readbacks and truncation are immutable so rollback/replay cannot silently replace frozen bytes.
                CREATE FUNCTION public.tkt000789_reject_runtime_authority_key_registry_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    RAISE EXCEPTION 'Runtime authority key-registry rows are immutable'
                        USING ERRCODE = '55000';
                END;
                $function$;

                CREATE TRIGGER "TR_RAKRSnapshots_GuardRows"
                BEFORE UPDATE OR DELETE ON public."RuntimeAuthorityKeyRegistrySnapshots"
                FOR EACH ROW EXECUTE FUNCTION public.tkt000789_guard_runtime_authority_key_registry_snapshot();

                CREATE TRIGGER "TR_RAKRSnapshots_ImmutableTruncate"
                BEFORE TRUNCATE ON public."RuntimeAuthorityKeyRegistrySnapshots"
                FOR EACH STATEMENT EXECUTE FUNCTION public.tkt000789_reject_runtime_authority_key_registry_mutation();

                CREATE TRIGGER "TR_RAKRReadbacks_ImmutableRows"
                BEFORE UPDATE OR DELETE ON public."RuntimeAuthorityKeyRegistryReadbacks"
                FOR EACH ROW EXECUTE FUNCTION public.tkt000789_reject_runtime_authority_key_registry_mutation();

                CREATE TRIGGER "TR_RAKRReadbacks_ImmutableTruncate"
                BEFORE TRUNCATE ON public."RuntimeAuthorityKeyRegistryReadbacks"
                FOR EACH STATEMENT EXECUTE FUNCTION public.tkt000789_reject_runtime_authority_key_registry_mutation();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS "TR_RAKRReadbacks_ImmutableTruncate"
                    ON public."RuntimeAuthorityKeyRegistryReadbacks";
                DROP TRIGGER IF EXISTS "TR_RAKRReadbacks_ImmutableRows"
                    ON public."RuntimeAuthorityKeyRegistryReadbacks";
                DROP TRIGGER IF EXISTS "TR_RAKRSnapshots_ImmutableTruncate"
                    ON public."RuntimeAuthorityKeyRegistrySnapshots";
                DROP TRIGGER IF EXISTS "TR_RAKRSnapshots_GuardRows"
                    ON public."RuntimeAuthorityKeyRegistrySnapshots";
                DROP FUNCTION IF EXISTS public.tkt000789_reject_runtime_authority_key_registry_mutation();
                DROP FUNCTION IF EXISTS public.tkt000789_guard_runtime_authority_key_registry_snapshot();
                """);

            migrationBuilder.DropTable(
                name: "RuntimeAuthorityKeyRegistryHeads");

            migrationBuilder.DropTable(
                name: "RuntimeAuthorityKeyRegistryReadbacks");

            migrationBuilder.DropTable(
                name: "RuntimeAuthorityKeyRegistrySnapshots");
        }
    }
}

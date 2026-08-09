using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRuntimeEnrollments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
                throw new NotSupportedException("Runtime enrollment migration requires PostgreSQL.");

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentAuthorityStates",
                columns: table => new
                {
                    Id = table.Column<short>(type: "smallint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Epoch = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentAuthorityStates", x => x.Id);
                    table.CheckConstraint("CK_RuntimeEnrollmentAuthorityStates_Epoch", "\"Epoch\" >= 0");
                    table.CheckConstraint("CK_RuntimeEnrollmentAuthorityStates_Id", "\"Id\" = 1");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentCredentialMutexes",
                columns: table => new
                {
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    TransitionKind = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    OwnerReference = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ExpectedEpoch = table.Column<int>(type: "integer", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentCredentialMutexes", x => x.BindingId);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentEncryptionNonces",
                columns: table => new
                {
                    Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false, defaultValue: "encryption"),
                    KeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Nonce = table.Column<byte[]>(type: "bytea", maxLength: 12, nullable: false),
                    OwnerType = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    OwnerId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentEncryptionNonces", x => new { x.KeyId, x.Nonce });
                    table.CheckConstraint("CK_RuntimeEnrollmentEncryptionNonces_NonceLength", "octet_length(\"Nonce\") = 12");
                    table.CheckConstraint("CK_RuntimeEnrollmentEncryptionNonces_Purpose", "\"Purpose\" = 'encryption'");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentKeyRegistries",
                columns: table => new
                {
                    Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    KeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    MaterialDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Epoch = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RetiredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentKeyRegistries", x => new { x.Purpose, x.KeyId });
                    table.CheckConstraint("CK_RuntimeEnrollmentKeyRegistries_Digest", "length(\"MaterialDigestSha256\") = 64 AND \"MaterialDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.CheckConstraint("CK_RuntimeEnrollmentKeyRegistries_Epoch", "\"Epoch\" >= 1");
                    table.CheckConstraint("CK_RuntimeEnrollmentKeyRegistries_Purpose", "\"Purpose\" IN ('encryption', 'capability-signing', 'registry-version')");
                    table.CheckConstraint("CK_RuntimeEnrollmentKeyRegistries_State", "\"State\" IN ('active', 'next', 'previous', 'decrypt-only', 'verify-only', 'retired')");
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentQuotas",
                columns: table => new
                {
                    Scope = table.Column<string>(type: "character varying(48)", maxLength: 48, nullable: false),
                    SubjectPseudonym = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    WindowStartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Count = table.Column<int>(type: "integer", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentQuotas", x => new { x.Scope, x.SubjectPseudonym, x.WindowStartedAtUtc });
                    table.CheckConstraint("CK_RuntimeEnrollmentQuotas_Count", "\"Count\" >= 0");
                });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentKeyRegistries_KeyId",
                table: "RuntimeEnrollmentKeyRegistries",
                column: "KeyId",
                unique: true);

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseId = table.Column<Guid>(type: "uuid", nullable: false),
                    LicenseSeatId = table.Column<Guid>(type: "uuid", nullable: false),
                    InstallationId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    HardwareIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ReleaseVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    HandoffDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProtocolVersion = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    Algorithm = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    KeyBackend = table.Column<string>(type: "character varying(48)", maxLength: 48, nullable: false),
                    AttestationLevel = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    PublicKeySpkiCiphertext = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: false),
                    PublicKeySpkiKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    PublicKeySpkiKeyPurpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false, defaultValue: "encryption"),
                    PublicKeySpkiSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    KeyThumbprint = table.Column<string>(type: "character varying(43)", maxLength: 43, nullable: false),
                    ChallengeCiphertext = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: false),
                    ChallengeKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ChallengeKeyPurpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false, defaultValue: "encryption"),
                    ChallengeDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Epoch = table.Column<int>(type: "integer", nullable: false),
                    ChallengeExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ActivatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ChallengeConsumedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    InvalidatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AuthorityEpoch = table.Column<long>(type: "bigint", nullable: false),
                    InvalidationReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollments", x => x.Id);
                    table.CheckConstraint("CK_RuntimeEnrollments_ChallengeKeyPurpose", "\"ChallengeKeyPurpose\" = 'encryption'");
                    table.CheckConstraint("CK_RuntimeEnrollments_Epoch", "\"Epoch\" = 1");
                    table.CheckConstraint("CK_RuntimeEnrollments_PublicKeySpkiKeyPurpose", "\"PublicKeySpkiKeyPurpose\" = 'encryption'");
                    table.CheckConstraint("CK_RuntimeEnrollments_State", "\"State\" IN ('PENDING', 'ACTIVE', 'INVALIDATED')");
                    table.ForeignKey(
                        name: "FK_RuntimeEnrollments_DistributionInstallationBindings_Binding~",
                        column: x => x.BindingId,
                        principalTable: "DistributionInstallationBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentProofNonces",
                columns: table => new
                {
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Jti = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Operation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ProofDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    BodyDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
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
                    table.PrimaryKey("PK_RuntimeEnrollmentProofNonces", x => new { x.EnrollmentId, x.Jti });
                    table.CheckConstraint("CK_RuntimeEnrollmentProofNonces_Operation", "\"Operation\" IN ('confirm', 'capability')");
                    table.CheckConstraint("CK_RuntimeEnrollmentProofNonces_ResponseKeyPurpose", "\"ResponseKeyPurpose\" = 'encryption'");
                    table.ForeignKey(
                        name: "FK_RuntimeEnrollmentProofNonces_RuntimeEnrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnrollmentRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestId = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    Operation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    PayloadDigestSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    EnrollmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    ResponseCiphertext = table.Column<string>(type: "character varying(8192)", maxLength: 8192, nullable: false),
                    ResponseKeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ResponseKeyPurpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false, defaultValue: "encryption"),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnrollmentRequests", x => x.Id);
                    table.CheckConstraint("CK_RuntimeEnrollmentRequests_Operation", "\"Operation\" = 'prepare'");
                    table.CheckConstraint("CK_RuntimeEnrollmentRequests_ResponseKeyPurpose", "\"ResponseKeyPurpose\" = 'encryption'");
                    table.ForeignKey(
                        name: "FK_RuntimeEnrollmentRequests_RuntimeEnrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "RuntimeEnrollments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeEncryptionNonces_KeyRegistry",
                table: "RuntimeEnrollmentEncryptionNonces",
                columns: new[] { "Purpose", "KeyId" },
                principalTable: "RuntimeEnrollmentKeyRegistries",
                principalColumns: new[] { "Purpose", "KeyId" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeEnrollments_PublicKey_KeyRegistry",
                table: "RuntimeEnrollments",
                columns: new[] { "PublicKeySpkiKeyPurpose", "PublicKeySpkiKeyId" },
                principalTable: "RuntimeEnrollmentKeyRegistries",
                principalColumns: new[] { "Purpose", "KeyId" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeEnrollments_Challenge_KeyRegistry",
                table: "RuntimeEnrollments",
                columns: new[] { "ChallengeKeyPurpose", "ChallengeKeyId" },
                principalTable: "RuntimeEnrollmentKeyRegistries",
                principalColumns: new[] { "Purpose", "KeyId" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeProofNonces_Response_KeyRegistry",
                table: "RuntimeEnrollmentProofNonces",
                columns: new[] { "ResponseKeyPurpose", "ResponseKeyId" },
                principalTable: "RuntimeEnrollmentKeyRegistries",
                principalColumns: new[] { "Purpose", "KeyId" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeRequests_Response_KeyRegistry",
                table: "RuntimeEnrollmentRequests",
                columns: new[] { "ResponseKeyPurpose", "ResponseKeyId" },
                principalTable: "RuntimeEnrollmentKeyRegistries",
                principalColumns: new[] { "Purpose", "KeyId" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentCredentialMutexes_ExpiresAtUtc",
                table: "RuntimeEnrollmentCredentialMutexes",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentProofNonces_ExpiresAtUtc",
                table: "RuntimeEnrollmentProofNonces",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEncryptionNonces_Purpose_KeyId",
                table: "RuntimeEnrollmentEncryptionNonces",
                columns: new[] { "Purpose", "KeyId" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeProofNonces_ResponseKeyPurpose_ResponseKeyId",
                table: "RuntimeEnrollmentProofNonces",
                columns: new[] { "ResponseKeyPurpose", "ResponseKeyId" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentQuotas_ExpiresAtUtc",
                table: "RuntimeEnrollmentQuotas",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentRequests_ClientId_Operation_RequestId",
                table: "RuntimeEnrollmentRequests",
                columns: new[] { "ClientId", "Operation", "RequestId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentRequests_EnrollmentId",
                table: "RuntimeEnrollmentRequests",
                column: "EnrollmentId");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeRequests_ResponseKeyPurpose_ResponseKeyId",
                table: "RuntimeEnrollmentRequests",
                columns: new[] { "ResponseKeyPurpose", "ResponseKeyId" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollments_BindingId",
                table: "RuntimeEnrollments",
                column: "BindingId",
                unique: true,
                filter: "\"State\" IN ('PENDING', 'ACTIVE')");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollments_KeyThumbprint",
                table: "RuntimeEnrollments",
                column: "KeyThumbprint",
                unique: true,
                filter: "\"State\" IN ('PENDING', 'ACTIVE')");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollments_PublicKeyPurpose_KeyId",
                table: "RuntimeEnrollments",
                columns: new[] { "PublicKeySpkiKeyPurpose", "PublicKeySpkiKeyId" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollments_ChallengePurpose_KeyId",
                table: "RuntimeEnrollments",
                columns: new[] { "ChallengeKeyPurpose", "ChallengeKeyId" });

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollmentKeyRegistries_Purpose_MaterialDigestSha256",
                table: "RuntimeEnrollmentKeyRegistries",
                columns: new[] { "Purpose", "MaterialDigestSha256" },
                unique: true);

            migrationBuilder.Sql("""
                CREATE INDEX "IX_BannedHardwareIds_UpperHardwareId_ProductId"
                ON public."BannedHardwareIds" (upper("HardwareId"), "ProductId");
                """);

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnrollments_State_ChallengeExpiresAtUtc",
                table: "RuntimeEnrollments",
                columns: new[] { "State", "ChallengeExpiresAtUtc" });

            migrationBuilder.Sql("""
                INSERT INTO public."RuntimeEnrollmentAuthorityStates" ("Id", "Epoch", "UpdatedAtUtc")
                VALUES (1, 0, statement_timestamp())
                ON CONFLICT ("Id") DO NOTHING;

                INSERT INTO public."RuntimeEnrollmentKeyRegistries"
                    ("Purpose", "KeyId", "MaterialDigestSha256", "State", "Epoch", "CreatedAtUtc", "RetiredAtUtc")
                VALUES ('registry-version', 'global', repeat('0', 64), 'active', 1, statement_timestamp(), NULL)
                ON CONFLICT ("Purpose", "KeyId") DO NOTHING;

                CREATE OR REPLACE FUNCTION public.runtime_enrollment_bump_authority_epoch()
                RETURNS trigger
                LANGUAGE plpgsql
                SECURITY DEFINER
                SET search_path = pg_catalog, pg_temp
                SET lock_timeout = '5s'
                SET statement_timeout = '15s'
                AS $runtime_authority$
                BEGIN
                    PERFORM pg_catalog.pg_advisory_xact_lock(999831, 1);
                    UPDATE public."RuntimeEnrollmentAuthorityStates"
                    SET "Epoch" = "Epoch" + 1,
                        "UpdatedAtUtc" = statement_timestamp()
                    WHERE "Id" = 1;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION USING ERRCODE = '55000',
                            MESSAGE = 'runtime enrollment authority singleton is missing';
                    END IF;
                    RETURN NULL;
                END;
                $runtime_authority$;

                REVOKE ALL ON FUNCTION public.runtime_enrollment_bump_authority_epoch() FROM PUBLIC;

                CREATE OR REPLACE FUNCTION public.runtime_enrollment_guard_key_registry()
                RETURNS trigger
                LANGUAGE plpgsql
                SECURITY DEFINER
                SET search_path = pg_catalog, pg_temp
                AS $runtime_key_guard$
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
                $runtime_key_guard$;
                REVOKE ALL ON FUNCTION public.runtime_enrollment_guard_key_registry() FROM PUBLIC;
                CREATE TRIGGER trg_runtime_key_registry_guard
                BEFORE INSERT OR DELETE OR UPDATE ON public."RuntimeEnrollmentKeyRegistries"
                FOR EACH ROW EXECUTE FUNCTION public.runtime_enrollment_guard_key_registry();

                DO $runtime_owner$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_catalog.pg_roles
                        WHERE rolname = 'softlicence_runtime_authority_owner' AND NOT rolcanlogin
                    ) THEN
                        ALTER FUNCTION public.runtime_enrollment_bump_authority_epoch()
                            OWNER TO softlicence_runtime_authority_owner;
                        ALTER FUNCTION public.runtime_enrollment_guard_key_registry()
                            OWNER TO softlicence_runtime_authority_owner;
                        GRANT SELECT, UPDATE ON public."RuntimeEnrollmentAuthorityStates"
                            TO softlicence_runtime_authority_owner;
                        GRANT SELECT ON public."RuntimeEnrollments", public."RuntimeEnrollmentRequests",
                            public."RuntimeEnrollmentProofNonces", public."RuntimeEnrollmentEncryptionNonces"
                            TO softlicence_runtime_authority_owner;
                        ALTER TABLE public."RuntimeEnrollmentAuthorityStates"
                            OWNER TO softlicence_runtime_authority_owner;
                        ALTER TABLE public."RuntimeEnrollmentKeyRegistries"
                            OWNER TO softlicence_runtime_authority_owner;
                        EXECUTE pg_catalog.format(
                            'GRANT SELECT ON public."RuntimeEnrollmentAuthorityStates", public."RuntimeEnrollmentKeyRegistries" TO %I',
                            current_user);
                    END IF;
                END;
                $runtime_owner$;
                """);

            AddAuthorityTriggers(migrationBuilder, "ApprovedBinaries",
                "ProductId", "Version", "Key", "Hash", "Source");
            AddAuthorityTriggers(migrationBuilder, "BannedComponents",
                "ComponentType", "ComponentHash", "ProductId", "ExpiresAt", "IsActive");
            AddAuthorityTriggers(migrationBuilder, "BannedHardwareIds",
                "HardwareId", "ProductId", "ExpiresAt", "IsActive");
            AddAuthorityTriggers(migrationBuilder, "DistributionBindingRequests",
                "ClientId", "Operation", "BindingId");
            AddAuthorityTriggers(migrationBuilder, "DistributionInstallationBindings",
                "ProductId", "LicenseId", "LicenseSeatId", "EntitlementId", "GrantRef",
                "HandoffDigestSha256", "InstallationId", "HardwareIdHash", "Version",
                "InstallerFilename", "InstallerSha256", "ExecutableSha256", "NativeDllSha256",
                "CoreSha256", "ApprovedBinariesSource", "State", "InvalidatedAtUtc", "InvalidationReason");
            AddAuthorityTriggers(migrationBuilder, "LicenseSeats",
                "LicenseId", "HardwareId", "IsActive");
            AddAuthorityTriggers(migrationBuilder, "Licenses",
                "ProductId", "IsActive", "RevokedAt", "ExpirationDate", "MaxSeats", "AllowedVersions");
            AddAuthorityTriggers(migrationBuilder, "Products", "MinimumAllowedVersion");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder.ActiveProvider != "Npgsql.EntityFrameworkCore.PostgreSQL")
                throw new NotSupportedException("Runtime enrollment migration requires PostgreSQL.");

            foreach (var table in AuthorityTables)
            {
                var stem = table.ToLowerInvariant();
                migrationBuilder.Sql($"DROP TRIGGER IF EXISTS trg_runtime_authority_{stem}_insert ON public.\"{table}\";");
                migrationBuilder.Sql($"DROP TRIGGER IF EXISTS trg_runtime_authority_{stem}_update ON public.\"{table}\";");
                migrationBuilder.Sql($"DROP TRIGGER IF EXISTS trg_runtime_authority_{stem}_delete ON public.\"{table}\";");
                migrationBuilder.Sql($"DROP TRIGGER IF EXISTS trg_runtime_authority_{stem}_truncate ON public.\"{table}\";");
            }
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS public.runtime_enrollment_bump_authority_epoch();");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS trg_runtime_key_registry_guard ON public.\"RuntimeEnrollmentKeyRegistries\";");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS public.runtime_enrollment_guard_key_registry();");

            migrationBuilder.Sql("DROP INDEX IF EXISTS public.\"IX_BannedHardwareIds_UpperHardwareId_ProductId\";");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentProofNonces");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentRequests");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollments");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentEncryptionNonces");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentKeyRegistries");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentQuotas");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentCredentialMutexes");

            migrationBuilder.DropTable(
                name: "RuntimeEnrollmentAuthorityStates");
        }

        private static readonly string[] AuthorityTables =
        [
            "ApprovedBinaries",
            "BannedComponents",
            "BannedHardwareIds",
            "DistributionBindingRequests",
            "DistributionInstallationBindings",
            "LicenseSeats",
            "Licenses",
            "Products"
        ];

        private static void AddAuthorityTriggers(
            MigrationBuilder migrationBuilder,
            string table,
            params string[] updateColumns)
        {
            var stem = table.ToLowerInvariant();
            var columns = string.Join(", ", updateColumns.Select(column => $"\"{column}\""));
            migrationBuilder.Sql($$"""
                CREATE TRIGGER trg_runtime_authority_{{stem}}_insert
                BEFORE INSERT ON public."{{table}}"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                CREATE TRIGGER trg_runtime_authority_{{stem}}_update
                BEFORE UPDATE OF {{columns}} ON public."{{table}}"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                CREATE TRIGGER trg_runtime_authority_{{stem}}_delete
                BEFORE DELETE ON public."{{table}}"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                CREATE TRIGGER trg_runtime_authority_{{stem}}_truncate
                BEFORE TRUNCATE ON public."{{table}}"
                FOR EACH STATEMENT EXECUTE FUNCTION public.runtime_enrollment_bump_authority_epoch();
                """);
        }
    }
}

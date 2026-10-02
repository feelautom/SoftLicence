using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTkt000686DistributionEntitlementAuthorityGeneration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // This migration is additive for v3 rows. PostgreSQL validates only newly inserted v4
            // authority tuples and prevents later replacement while allowing lifecycle transitions.
            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionEntitlements_ContractVersion",
                table: "DistributionEntitlements");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships");

            migrationBuilder.AddColumn<string>(
                name: "ArtifactSetDigestSha256",
                table: "DistributionEntitlements",
                type: "character varying(64)",
                maxLength: 64,
                collation: "C",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AuthorityGenerationId",
                table: "DistributionEntitlements",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AuthorityLineageId",
                table: "DistributionEntitlements",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_DistributionEntitlements_AuthorityLineageId_AuthorityGenera~",
                table: "DistributionEntitlements",
                columns: new[] { "AuthorityLineageId", "AuthorityGenerationId" });

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionEntitlements_ContractVersion",
                table: "DistributionEntitlements",
                sql: "\"ContractVersion\" IN (3, 4)");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Tkt000686_DistributionEntitlements_ArtifactDigest",
                table: "DistributionEntitlements",
                sql: "\"ArtifactSetDigestSha256\" IS NULL OR (octet_length(\"ArtifactSetDigestSha256\") = 64 AND \"ArtifactSetDigestSha256\" ~ '^[0-9a-f]{64}$')");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Tkt000686_DistributionEntitlements_AuthorityShape",
                table: "DistributionEntitlements",
                sql: "(\"ContractVersion\" = 3 AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ArtifactSetDigestSha256\" IS NULL) OR (\"ContractVersion\" = 4 AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ArtifactSetDigestSha256\" IS NOT NULL)");

            migrationBuilder.AddForeignKey(
                name: "FK_Tkt000686_DistributionEntitlements_REAuthorityGeneration",
                table: "DistributionEntitlements",
                columns: new[] { "AuthorityLineageId", "AuthorityGenerationId" },
                principalTable: "RuntimeEnrollmentAuthorityGenerations",
                principalColumns: new[] { "AuthorityLineageId", "AuthorityGenerationId" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships",
                sql: "\"Source\" IN ('issue_v2', 'issue_v3', 'issue_v4', 'finalize_v1')");

            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION "Tkt000686_ValidateDistributionEntitlementAuthorityGeneration"()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                DECLARE
                    authority_lineage "RuntimeEnrollmentAuthorityLineages"%ROWTYPE;
                    authority_generation "RuntimeEnrollmentAuthorityGenerations"%ROWTYPE;
                    approved_registration "ApprovedBinaryRegistrations"%ROWTYPE;
                    authority_payload jsonb;
                    artifact_baseline text;
                BEGIN
                    IF TG_OP = 'UPDATE' THEN
                        IF (OLD."ContractVersion" = 4 OR NEW."ContractVersion" = 4)
                           AND ROW(NEW."Id", NEW."ClientId", NEW."ProductId", NEW."LicenseId",
                               NEW."GrantRefDigestSha256", NEW."SubjectRefDigestSha256",
                               NEW."ContractVersion", NEW."AuthorityLineageId", NEW."AuthorityGenerationId",
                               NEW."ArtifactSetDigestSha256", NEW."IssuedAtUtc", NEW."ExpiresAtUtc")
                           IS DISTINCT FROM
                           ROW(OLD."Id", OLD."ClientId", OLD."ProductId", OLD."LicenseId",
                               OLD."GrantRefDigestSha256", OLD."SubjectRefDigestSha256",
                               OLD."ContractVersion", OLD."AuthorityLineageId", OLD."AuthorityGenerationId",
                               OLD."ArtifactSetDigestSha256", OLD."IssuedAtUtc", OLD."ExpiresAtUtc") THEN
                            RAISE EXCEPTION 'TKT000686 protected authority tuple is immutable' USING ERRCODE = '23514';
                        END IF;
                        RETURN NEW;
                    END IF;

                    IF NEW."ContractVersion" <> 4 THEN
                        RETURN NEW;
                    END IF;

                    SELECT * INTO STRICT authority_lineage
                    FROM "RuntimeEnrollmentAuthorityLineages"
                    WHERE "AuthorityLineageId" = NEW."AuthorityLineageId";
                    SELECT * INTO STRICT authority_generation
                    FROM "RuntimeEnrollmentAuthorityGenerations"
                    WHERE "AuthorityLineageId" = NEW."AuthorityLineageId"
                      AND "AuthorityGenerationId" = NEW."AuthorityGenerationId";
                    authority_payload := convert_from(authority_generation."CanonicalPayloadUtf8", 'UTF8')::jsonb;
                    SELECT * INTO STRICT approved_registration
                    FROM "ApprovedBinaryRegistrations"
                    WHERE "ProductId" = NEW."ProductId"
                      AND "Version" = authority_payload #>> '{release,version}'
                      AND "BaselineDigestSha256" = NEW."ArtifactSetDigestSha256"
                      AND "Source" = 'release';
                    SELECT encode(sha256(convert_to(string_agg(
                               artifact."Key" || ':' || artifact."Hash", E'\n'
                               ORDER BY CASE artifact."Key"
                                   WHEN 'FP_EXE' THEN 1 WHEN 'FP_DLL' THEN 2 WHEN 'FP_CORE' THEN 3 END), 'UTF8')), 'hex')
                    INTO artifact_baseline
                    FROM "ApprovedBinaries" artifact
                    WHERE artifact."ApprovedBinaryRegistrationId" = approved_registration."Id";

                    IF authority_lineage."Provider" <> 'softlicence'
                       OR authority_lineage."ProductId" <> NEW."ProductId"
                       OR authority_lineage."HeadGenerationId" <> NEW."AuthorityGenerationId"
                       OR authority_lineage."HeadSequence" <> authority_generation."Sequence"
                       OR encode(sha256(convert_to(authority_lineage."ProviderGrantRef", 'UTF8')), 'hex') <> NEW."GrantRefDigestSha256"
                       OR authority_payload ->> 'schema' <> 'runtime-enrollment-authority-generation-v2'
                       OR authority_payload ->> 'contractVersion' <> '2'
                       OR authority_payload ->> 'authorityLineageId' <> NEW."AuthorityLineageId"::text
                       OR authority_payload ->> 'authorityGenerationId' <> NEW."AuthorityGenerationId"::text
                       OR authority_payload ->> 'provider' <> authority_lineage."Provider"
                       OR authority_payload ->> 'productId' <> NEW."ProductId"::text
                       OR authority_payload ->> 'providerGrantRef' <> authority_lineage."ProviderGrantRef"
                       OR authority_payload #>> '{release,artifactSetDigest}' <> NEW."ArtifactSetDigestSha256"
                       OR (SELECT count(*) FROM "ApprovedBinaries" artifact
                           WHERE artifact."ApprovedBinaryRegistrationId" = approved_registration."Id") <> 3
                       OR EXISTS (
                           SELECT 1 FROM "ApprovedBinaries" artifact
                           WHERE artifact."ApprovedBinaryRegistrationId" = approved_registration."Id"
                             AND (artifact."ProductId" <> approved_registration."ProductId"
                               OR artifact."Version" <> approved_registration."Version"
                               OR artifact."Source" <> 'release'
                               OR artifact."Key" NOT IN ('FP_EXE', 'FP_DLL', 'FP_CORE')
                               OR octet_length(artifact."Hash") <> 64
                               OR artifact."Hash" !~ '^[0-9a-f]{64}$'))
                       OR EXISTS (
                           SELECT 1 FROM "ApprovedBinaries" artifact
                           WHERE artifact."ProductId" = approved_registration."ProductId"
                             AND artifact."Version" = approved_registration."Version"
                             AND artifact."ApprovedBinaryRegistrationId" IS DISTINCT FROM approved_registration."Id")
                       OR NOT EXISTS (SELECT 1 FROM "ApprovedBinaries" artifact WHERE artifact."ApprovedBinaryRegistrationId" = approved_registration."Id" AND artifact."Key" = 'FP_EXE')
                       OR NOT EXISTS (SELECT 1 FROM "ApprovedBinaries" artifact WHERE artifact."ApprovedBinaryRegistrationId" = approved_registration."Id" AND artifact."Key" = 'FP_DLL')
                       OR NOT EXISTS (SELECT 1 FROM "ApprovedBinaries" artifact WHERE artifact."ApprovedBinaryRegistrationId" = approved_registration."Id" AND artifact."Key" = 'FP_CORE')
                       OR artifact_baseline <> NEW."ArtifactSetDigestSha256" THEN
                        RAISE EXCEPTION 'TKT000686 authority tuple is inconsistent' USING ERRCODE = '23514';
                    END IF;
                    RETURN NEW;
                EXCEPTION WHEN NO_DATA_FOUND OR invalid_text_representation OR character_not_in_repertoire THEN
                    RAISE EXCEPTION 'TKT000686 authority tuple is inconsistent' USING ERRCODE = '23514';
                END;
                $function$;

                CREATE TRIGGER "TR_Tkt000686_DistributionEntitlements_AuthorityGeneration"
                BEFORE INSERT OR UPDATE ON "DistributionEntitlements"
                FOR EACH ROW EXECUTE FUNCTION "Tkt000686_ValidateDistributionEntitlementAuthorityGeneration"();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Downgrade is deliberately fail-closed: restoring the v3-only checks below fails in
            // this migration transaction while any contract-v4 entitlement or issue_v4 owner exists.
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS "TR_Tkt000686_DistributionEntitlements_AuthorityGeneration" ON "DistributionEntitlements";
                DROP FUNCTION IF EXISTS "Tkt000686_ValidateDistributionEntitlementAuthorityGeneration"();
                """);

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships");
            migrationBuilder.DropForeignKey(
                name: "FK_Tkt000686_DistributionEntitlements_REAuthorityGeneration",
                table: "DistributionEntitlements");

            migrationBuilder.DropIndex(
                name: "IX_DistributionEntitlements_AuthorityLineageId_AuthorityGenera~",
                table: "DistributionEntitlements");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionEntitlements_ContractVersion",
                table: "DistributionEntitlements");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Tkt000686_DistributionEntitlements_ArtifactDigest",
                table: "DistributionEntitlements");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Tkt000686_DistributionEntitlements_AuthorityShape",
                table: "DistributionEntitlements");

            migrationBuilder.DropColumn(
                name: "ArtifactSetDigestSha256",
                table: "DistributionEntitlements");

            migrationBuilder.DropColumn(
                name: "AuthorityGenerationId",
                table: "DistributionEntitlements");

            migrationBuilder.DropColumn(
                name: "AuthorityLineageId",
                table: "DistributionEntitlements");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionEntitlements_ContractVersion",
                table: "DistributionEntitlements",
                sql: "\"ContractVersion\" = 3");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionGrantOwnerships_Source",
                table: "DistributionGrantOwnerships",
                sql: "\"Source\" IN ('issue_v2', 'issue_v3', 'finalize_v1')");
        }
    }
}

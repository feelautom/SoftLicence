using Microsoft.EntityFrameworkCore.Migrations;

namespace SoftLicence.Server.Migrations;

/// <summary>Adds nullable authenticated machine proof; historical decisions remain explicitly unclassified.</summary>
public partial class AddRuntimeMachineClassification : Migration
{
    /// <summary>Adds bounded proof metadata without reconstructing historical machine facts.</summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<int>("MachineClassifierVersion", "RuntimeDistributionHardwareDecisions", type: "integer", nullable: true);
        migrationBuilder.AddColumn<Guid>("MachineEvidenceSourceDecisionId", "RuntimeDistributionHardwareDecisions", type: "uuid", nullable: true);
        migrationBuilder.AddColumn<string>("MachineClassification", "RuntimeDistributionHardwareDecisions", type: "character varying(16)", maxLength: 16, nullable: true);
        migrationBuilder.AddColumn<string>("MachineClassificationReason", "RuntimeDistributionHardwareDecisions", type: "character varying(64)", maxLength: 64, nullable: true);
        migrationBuilder.AddColumn<string>("MachineEvidenceDigestSha256", "RuntimeDistributionHardwareDecisions", type: "character varying(64)", maxLength: 64, nullable: true);
        // Exact replays may update their delivery counters, never their original authority or proof.
        migrationBuilder.Sql("""
            CREATE FUNCTION public.tkt1550_immutable_machine_decision() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF ROW(NEW."ClientId",NEW."RequestId",NEW."PayloadDigestSha256",NEW."ProductId",NEW."LicenseId",
                     NEW."GrantRefDigestSha256",NEW."HardwareIdHash",NEW."InstallationIdHash",NEW."KeyThumbprint",
                     NEW."AuthorityMode",NEW."Outcome",NEW."ReasonCode",NEW."CreatedAtUtc",NEW."MachineClassifierVersion",
                     NEW."MachineClassification",NEW."MachineClassificationReason",NEW."MachineEvidenceDigestSha256",NEW."MachineEvidenceSourceDecisionId")
                 IS DISTINCT FROM
                 ROW(OLD."ClientId",OLD."RequestId",OLD."PayloadDigestSha256",OLD."ProductId",OLD."LicenseId",
                     OLD."GrantRefDigestSha256",OLD."HardwareIdHash",OLD."InstallationIdHash",OLD."KeyThumbprint",
                     OLD."AuthorityMode",OLD."Outcome",OLD."ReasonCode",OLD."CreatedAtUtc",OLD."MachineClassifierVersion",
                     OLD."MachineClassification",OLD."MachineClassificationReason",OLD."MachineEvidenceDigestSha256",OLD."MachineEvidenceSourceDecisionId") THEN
                RAISE EXCEPTION 'Machine decision authority is immutable' USING ERRCODE = '23514';
              END IF;
              RETURN NEW;
            END $$;
            CREATE TRIGGER tkt1550_immutable_machine_decision BEFORE UPDATE ON public."RuntimeDistributionHardwareDecisions"
              FOR EACH ROW EXECUTE FUNCTION public.tkt1550_immutable_machine_decision();
            """);
    }

    /// <summary>Removes only this migration's proof metadata.</summary>
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("DROP TRIGGER tkt1550_immutable_machine_decision ON public.\"RuntimeDistributionHardwareDecisions\"; DROP FUNCTION public.tkt1550_immutable_machine_decision();");
        foreach (var name in new[] { "MachineClassifierVersion", "MachineEvidenceSourceDecisionId", "MachineClassification", "MachineClassificationReason", "MachineEvidenceDigestSha256" })
            migrationBuilder.DropColumn(name, "RuntimeDistributionHardwareDecisions");
    }
}

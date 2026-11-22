using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-004112: widens <c>MachineEvidenceObservations.LastEndpoint</c> from 16 to 32 characters so the clone-guard
    /// reactivation label <c>CLONE_GUARD_REACTIVATE</c> (22 characters) can be stored. Until then every reactivation
    /// failed to store its machine evidence with SQLSTATE 22001 (storage is fail-open, so the reactivation itself
    /// succeeded and only the evidence was lost).
    /// </summary>
    /// <remarks>
    /// Up only raises a <c>varchar</c> length limit: PostgreSQL changes the type metadata without rewriting the table
    /// or its indexes (the column is not indexed), under a brief ACCESS EXCLUSIVE lock, and every existing value stays
    /// valid. Down shrinks the limit back to 16 and fails with 22001 if a longer label has been stored since, which is
    /// the intended refusal: rolling back must not silently truncate evidence.
    /// </remarks>
    public partial class AddTkt004112WidenMachineEvidenceLastEndpoint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "LastEndpoint",
                table: "MachineEvidenceObservations",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(16)",
                oldMaxLength: 16);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "LastEndpoint",
                table: "MachineEvidenceObservations",
                type: "character varying(16)",
                maxLength: 16,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(32)",
                oldMaxLength: 32);
        }
    }
}

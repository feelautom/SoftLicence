using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Qualifies both recovery-authority generation references by lineage and backfills the previous
    /// lineage from the globally unique historical generation before enforcing composite foreign keys.
    /// </summary>
    public partial class CloseTkt000763F6RecoveryAuthorityIntegrity : Migration
    {
        /// <summary>
        /// Adds and validates the previous-lineage column, replaces the incomplete single-column
        /// relation, and installs separate NO ACTION relations for new and previous generations.
        /// </summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_RuntimeSeatRecoveryAuthorities_RuntimeEnrollmentAuthorityGe~",
                table: "RuntimeSeatRecoveryAuthorities");

            // Existing rows can be upgraded without inventing lineage identity because generation IDs
            // are globally unique and already point at the authoritative generation table.
            migrationBuilder.AddColumn<Guid>(
                name: "PreviousAuthorityLineageId",
                table: "RuntimeSeatRecoveryAuthorities",
                type: "uuid",
                nullable: true);

            // The legacy lifecycle trigger rejects every non-state update. PostgreSQL DDL is
            // transactional here: coherent history is backfilled with the trigger briefly disabled,
            // while any 23503 abort rolls back the data, column, and trigger state together.
            migrationBuilder.Sql("""
                ALTER TABLE public."RuntimeSeatRecoveryAuthorities"
                    DISABLE TRIGGER trg_runtime_seat_recovery_authorities_guard;

                UPDATE public."RuntimeSeatRecoveryAuthorities" AS authority
                SET "PreviousAuthorityLineageId" = generation."AuthorityLineageId"
                FROM public."RuntimeEnrollmentAuthorityGenerations" AS generation
                WHERE generation."AuthorityGenerationId" = authority."PreviousAuthorityGenerationId";

                DO $f6_previous_lineage$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM public."RuntimeSeatRecoveryAuthorities"
                        WHERE "PreviousAuthorityLineageId" IS NULL
                    ) THEN
                        RAISE EXCEPTION 'runtime seat recovery previous lineage backfill is incomplete'
                            USING ERRCODE = '23503';
                    END IF;
                END
                $f6_previous_lineage$;

                ALTER TABLE public."RuntimeSeatRecoveryAuthorities"
                    ENABLE TRIGGER trg_runtime_seat_recovery_authorities_guard;
                """);

            migrationBuilder.AlterColumn<Guid>(
                name: "PreviousAuthorityLineageId",
                table: "RuntimeSeatRecoveryAuthorities",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_RSRAuthorities_PreviousLineageGeneration",
                table: "RuntimeSeatRecoveryAuthorities",
                columns: new[] { "PreviousAuthorityLineageId", "PreviousAuthorityGenerationId" });

            migrationBuilder.CreateIndex(
                name: "UX_RSRAuthorities_NewLineageGeneration",
                table: "RuntimeSeatRecoveryAuthorities",
                columns: new[] { "AuthorityLineageId", "AuthorityGenerationId" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_RSRAuthorities_REAuthorityGenerations_New",
                table: "RuntimeSeatRecoveryAuthorities",
                columns: new[] { "AuthorityLineageId", "AuthorityGenerationId" },
                principalTable: "RuntimeEnrollmentAuthorityGenerations",
                principalColumns: new[] { "AuthorityLineageId", "AuthorityGenerationId" },
                onDelete: ReferentialAction.NoAction);

            migrationBuilder.AddForeignKey(
                name: "FK_RSRAuthorities_REAuthorityGenerations_Previous",
                table: "RuntimeSeatRecoveryAuthorities",
                columns: new[] { "PreviousAuthorityLineageId", "PreviousAuthorityGenerationId" },
                principalTable: "RuntimeEnrollmentAuthorityGenerations",
                principalColumns: new[] { "AuthorityLineageId", "AuthorityGenerationId" },
                onDelete: ReferentialAction.NoAction);
        }

        /// <summary>
        /// Removes the composite relations and previous-lineage column, restoring the former
        /// single-generation relation for an explicit schema rollback.
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_RSRAuthorities_REAuthorityGenerations_New",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropForeignKey(
                name: "FK_RSRAuthorities_REAuthorityGenerations_Previous",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_RSRAuthorities_PreviousLineageGeneration",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropIndex(
                name: "UX_RSRAuthorities_NewLineageGeneration",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.DropColumn(
                name: "PreviousAuthorityLineageId",
                table: "RuntimeSeatRecoveryAuthorities");

            migrationBuilder.AddForeignKey(
                name: "FK_RuntimeSeatRecoveryAuthorities_RuntimeEnrollmentAuthorityGe~",
                table: "RuntimeSeatRecoveryAuthorities",
                column: "AuthorityGenerationId",
                principalTable: "RuntimeEnrollmentAuthorityGenerations",
                principalColumn: "AuthorityGenerationId",
                onDelete: ReferentialAction.NoAction);
        }
    }
}

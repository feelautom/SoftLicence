using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>Extends the closed provider invalidation vocabulary with the auditable seat-release transition.</summary>
    [DbContext(typeof(LicenseDbContext))]
    [Migration("20260828123000_AddTkt000734SeatReleaseTransfer")]
    public partial class AddTkt000734SeatReleaseTransfer : Migration
    {
        /// <summary>Adds only <c>seat_released</c> to the existing reason check constraint.</summary>
        /// <param name="migrationBuilder">Builder for the transactional schema change.</param>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionBindingInvalidations_Reason",
                table: "DistributionBindingInvalidations");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionBindingInvalidations_Reason",
                table: "DistributionBindingInvalidations",
                sql: "\"Reason\" IN ('account_closed', 'fraud_flagged', 'grant_revoked', 'security_lockdown', 'seat_released')");
        }

        /// <summary>Restores the former vocabulary only when no seat-release history would be lost.</summary>
        /// <param name="migrationBuilder">Builder for the fail-closed downgrade.</param>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DO $seat_release_downgrade$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM public."DistributionBindingInvalidations"
                        WHERE "Reason" = 'seat_released'
                    ) THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '55000',
                            MESSAGE = 'Cannot downgrade TKT-000734 while seat_released invalidation history exists.';
                    END IF;
                END
                $seat_release_downgrade$;
                """);

            migrationBuilder.DropCheckConstraint(
                name: "CK_DistributionBindingInvalidations_Reason",
                table: "DistributionBindingInvalidations");

            migrationBuilder.AddCheckConstraint(
                name: "CK_DistributionBindingInvalidations_Reason",
                table: "DistributionBindingInvalidations",
                sql: "\"Reason\" IN ('account_closed', 'fraud_flagged', 'grant_revoked', 'security_lockdown')");
        }
    }
}

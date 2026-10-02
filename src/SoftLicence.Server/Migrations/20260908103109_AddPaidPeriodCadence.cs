using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddPaidPeriodCadence : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments");

            migrationBuilder.DropCheckConstraint(
                name: "CK_PersonalDayPassOperations_Period",
                table: "PersonalDayPassOperations");

            migrationBuilder.AddColumn<int>(
                name: "DurationSeconds",
                table: "PersonalDayPassPayments",
                type: "integer",
                nullable: false,
                defaultValue: 86400);

            migrationBuilder.AddColumn<string>(
                name: "Offer",
                table: "PersonalDayPassPayments",
                type: "character varying(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "day_pass",
                collation: "C");

            migrationBuilder.AddCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments",
                sql: "\"MaxSeats\" BETWEEN 1 AND 10 AND \"Currency\" = 'eur' AND ((\"Offer\" = 'day_pass' AND \"DurationSeconds\" = 86400 AND \"AmountMinor\" = 1000 * \"MaxSeats\") OR (\"Offer\" = 'subscription' AND \"DurationSeconds\" BETWEEN 86400 AND 31622400 AND \"AmountMinor\" > 0))");

            migrationBuilder.AddCheckConstraint(
                name: "CK_PersonalDayPassOperations_Period",
                table: "PersonalDayPassOperations",
                sql: "\"PeriodExpiresAtUtc\" >= \"PeriodStartsAtUtc\" + interval '1 day' AND \"PeriodExpiresAtUtc\" <= \"PeriodStartsAtUtc\" + interval '366 days' AND \"PaidThroughUtc\" >= \"PeriodExpiresAtUtc\"");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments");

            migrationBuilder.DropCheckConstraint(
                name: "CK_PersonalDayPassOperations_Period",
                table: "PersonalDayPassOperations");

            migrationBuilder.DropColumn(
                name: "DurationSeconds",
                table: "PersonalDayPassPayments");

            migrationBuilder.DropColumn(
                name: "Offer",
                table: "PersonalDayPassPayments");

            migrationBuilder.AddCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments",
                sql: "\"MaxSeats\" BETWEEN 1 AND 10 AND \"AmountMinor\" = 1000 * \"MaxSeats\" AND \"Currency\" = 'eur'");

            migrationBuilder.AddCheckConstraint(
                name: "CK_PersonalDayPassOperations_Period",
                table: "PersonalDayPassOperations",
                sql: "\"PeriodExpiresAtUtc\" = \"PeriodStartsAtUtc\" + interval '24 hours' AND \"PaidThroughUtc\" >= \"PeriodExpiresAtUtc\"");
        }
    }
}

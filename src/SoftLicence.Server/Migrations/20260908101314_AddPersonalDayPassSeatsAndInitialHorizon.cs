using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddPersonalDayPassSeatsAndInitialHorizon : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments");

            migrationBuilder.AddColumn<int>(
                name: "MaxSeats",
                table: "PersonalDayPassPayments",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<DateTime>(
                name: "InitialPaidThroughUtc",
                table: "PersonalDayPasses",
                type: "timestamp(3) with time zone",
                precision: 3,
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments",
                sql: "\"MaxSeats\" BETWEEN 1 AND 10 AND \"AmountMinor\" = 1000 * \"MaxSeats\" AND \"Currency\" = 'eur'");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments");

            migrationBuilder.DropColumn(
                name: "MaxSeats",
                table: "PersonalDayPassPayments");

            migrationBuilder.DropColumn(
                name: "InitialPaidThroughUtc",
                table: "PersonalDayPasses");

            migrationBuilder.AddCheckConstraint(
                name: "CK_PersonalDayPassPayments_Price",
                table: "PersonalDayPassPayments",
                sql: "\"AmountMinor\" = 1000 AND \"Currency\" = 'eur'");
        }
    }
}

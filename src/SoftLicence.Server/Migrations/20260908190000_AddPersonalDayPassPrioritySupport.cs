using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftLicence.Server.Data;

#nullable disable

namespace SoftLicence.Server.Migrations;

/// <summary>Adds the paid priority-support term and its current FIFO projection without rewriting history.</summary>
[DbContext(typeof(LicenseDbContext))]
[Migration("20260908190000_AddPersonalDayPassPrioritySupport")]
public sealed class AddPersonalDayPassPrioritySupport : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropCheckConstraint("CK_PersonalDayPassPayments_Price", "PersonalDayPassPayments");
        migrationBuilder.AddColumn<bool>("CurrentPrioritySupport", "PersonalDayPasses", "boolean", nullable: false, defaultValue: false);
        migrationBuilder.AddColumn<bool>("PrioritySupport", "PersonalDayPassPayments", "boolean", nullable: false, defaultValue: false);
        migrationBuilder.AddColumn<bool>("PeriodPrioritySupport", "PersonalDayPassOperations", "boolean", nullable: false, defaultValue: false);
        migrationBuilder.AddCheckConstraint("CK_PersonalDayPassPayments_Price", "PersonalDayPassPayments",
            "\"MaxSeats\" BETWEEN 1 AND 10 AND \"Currency\" = 'eur' AND ((\"Offer\" = 'day_pass' AND \"DurationSeconds\" = 86400 AND \"AmountMinor\" = (CASE WHEN \"PrioritySupport\" THEN 1140 ELSE 1000 END) * \"MaxSeats\") OR (\"Offer\" = 'subscription' AND NOT \"PrioritySupport\" AND \"DurationSeconds\" BETWEEN 86400 AND 31622400 AND \"AmountMinor\" > 0))");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropCheckConstraint("CK_PersonalDayPassPayments_Price", "PersonalDayPassPayments");
        migrationBuilder.DropColumn("PeriodPrioritySupport", "PersonalDayPassOperations");
        migrationBuilder.DropColumn("PrioritySupport", "PersonalDayPassPayments");
        migrationBuilder.DropColumn("CurrentPrioritySupport", "PersonalDayPasses");
        migrationBuilder.AddCheckConstraint("CK_PersonalDayPassPayments_Price", "PersonalDayPassPayments",
            "\"MaxSeats\" BETWEEN 1 AND 10 AND \"Currency\" = 'eur' AND ((\"Offer\" = 'day_pass' AND \"DurationSeconds\" = 86400 AND \"AmountMinor\" = 1000 * \"MaxSeats\") OR (\"Offer\" = 'subscription' AND \"DurationSeconds\" BETWEEN 86400 AND 31622400 AND \"AmountMinor\" > 0))");
    }
}

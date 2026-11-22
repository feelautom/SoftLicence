using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// TKT-003751: adds <c>LicenseSeats.LastActivatedAt</c>, the UTC instant a seat last became active on its hardware
    /// identifier. The daily hardware quota counts the distinct identifiers of a key activated in one UTC day from
    /// this column (owner rule: a key may not be activated on more than N different identifiers in one day,
    /// N read from <c>LicenseTypes.MaxActivationsPerDay</c>; everything else is free).
    /// </summary>
    /// <remarks>
    /// Additive nullable column, no default and no backfill: existing rows stay null, which only means "not activated
    /// since the column exists", so nothing activated before the upgrade counts against the day of the upgrade, and
    /// the last-PC fallback of the quota uses <c>LastCheckInAt</c> for such rows. PostgreSQL adds a nullable column
    /// without a table rewrite (metadata-only, brief ACCESS EXCLUSIVE lock). The application role keeps its
    /// table-level grants, which cover the new column. Down drops the column and loses only quota history of the
    /// current day.
    /// </remarks>
    public partial class AddTkt003751SeatLastActivatedAt : Migration
    {
        /// <summary>Adds the nullable activation instant.</summary>
        /// <param name="migrationBuilder">Migration builder of the PostgreSQL provider.</param>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "LastActivatedAt",
                table: "LicenseSeats",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <summary>Rollback: drops the activation instant.</summary>
        /// <param name="migrationBuilder">Migration builder of the PostgreSQL provider.</param>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastActivatedAt",
                table: "LicenseSeats");
        }
    }
}

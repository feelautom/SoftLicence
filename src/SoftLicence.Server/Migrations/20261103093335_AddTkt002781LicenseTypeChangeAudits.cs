using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds the journal of licence-type changes applied through the analytics write route (TKT-002781). Purely additive:
    /// a new table with no foreign key, so no existing row, key, activation or rule is affected; rollback drops it.
    /// </summary>
    public partial class AddTkt002781LicenseTypeChangeAudits : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "LicenseTypeChangeAudits",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AppliedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ProductId = table.Column<Guid>(type: "uuid", nullable: false),
                    AnalyticsKeyId = table.Column<Guid>(type: "uuid", nullable: false),
                    CallerIp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    RequestedBy = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    PreviewHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    OperationCount = table.Column<int>(type: "integer", nullable: false),
                    ChangesJson = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LicenseTypeChangeAudits", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_LicenseTypeChangeAudits_ProductId_AppliedAtUtc",
                table: "LicenseTypeChangeAudits",
                columns: new[] { "ProductId", "AppliedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LicenseTypeChangeAudits");
        }
    }
}

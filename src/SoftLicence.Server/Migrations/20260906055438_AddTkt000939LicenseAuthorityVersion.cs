using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftLicence.Server.Migrations
{
    /// <summary>
    /// Adds an opaque row version maintained by PostgreSQL for all license writers. The volatile
    /// default backfills existing rows; deployment must account for the additive table rewrite.
    /// </summary>
    public partial class AddTkt000939LicenseAuthorityVersion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "AuthorityVersion",
                table: "Licenses",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()");

            // Rotate even for same-value updates: an older decision must not become valid again
            // after a revoke/reactivate/revoke cycle or an independent legacy administration write.
            migrationBuilder.Sql("""
                CREATE FUNCTION public.tkt939_rotate_license_authority_version()
                RETURNS trigger LANGUAGE plpgsql AS $body$
                BEGIN
                    NEW."AuthorityVersion" := gen_random_uuid();
                    RETURN NEW;
                END;
                $body$;
                CREATE TRIGGER tkt939_license_authority_version
                BEFORE UPDATE ON public."Licenses"
                FOR EACH ROW EXECUTE FUNCTION public.tkt939_rotate_license_authority_version();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER tkt939_license_authority_version ON public."Licenses";
                DROP FUNCTION public.tkt939_rotate_license_authority_version();
                """);
            migrationBuilder.DropColumn(
                name: "AuthorityVersion",
                table: "Licenses");
        }
    }
}

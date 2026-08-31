using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

namespace YowThi.EfAcceptance.Migrations;

[DbContext(typeof(EfAcceptanceDbContext))]
[Migration("20260831000100_InitialAcceptance")]
public sealed class InitialAcceptanceMigration : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.EnsureSchema(EfAcceptanceDatabase.Schema);
        migrationBuilder.CreateTable(
            name: "probe",
            schema: EfAcceptanceDatabase.Schema,
            columns: table => new
            {
                Id = table.Column<int>(type: "integer", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                Value = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_probe", x => x.Id);
            });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "probe", schema: EfAcceptanceDatabase.Schema);
    }
}

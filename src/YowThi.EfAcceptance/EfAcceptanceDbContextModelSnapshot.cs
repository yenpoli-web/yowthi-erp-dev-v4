using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

namespace YowThi.EfAcceptance.Migrations;

[DbContext(typeof(EfAcceptanceDbContext))]
public sealed class EfAcceptanceDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
    {
#pragma warning disable 612, 618
        modelBuilder
            .HasDefaultSchema(EfAcceptanceDatabase.Schema)
            .HasAnnotation("ProductVersion", "10.0.10")
            .HasAnnotation("Relational:MaxIdentifierLength", 63);

        NpgsqlModelBuilderExtensions.UseIdentityByDefaultColumns(modelBuilder);

        modelBuilder.Entity("YowThi.EfAcceptance.EfAcceptanceProbe", entity =>
        {
            entity.Property<int>("Id")
                .ValueGeneratedOnAdd()
                .HasColumnType("integer");

            NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(entity.Property<int>("Id"));

            entity.Property<string>("Value")
                .IsRequired()
                .HasMaxLength(200)
                .HasColumnType("character varying(200)");

            entity.HasKey("Id");
            entity.ToTable("probe", EfAcceptanceDatabase.Schema);
        });
#pragma warning restore 612, 618
    }
}

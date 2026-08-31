using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace YowThi.EfAcceptance;

internal static class EfAcceptanceDatabase
{
    public const string ConnectionString = "Host=127.0.0.1;Port=55432;Database=yowthi_dev;Username=yowthi_dev;SSL Mode=Disable;Timeout=5;Command Timeout=30;Application Name=YowThi.EfAcceptance;Pooling=false";
    public const string Schema = "dev_ef_acceptance";
}

public sealed class EfAcceptanceDbContext : DbContext
{
    public EfAcceptanceDbContext(DbContextOptions<EfAcceptanceDbContext> options) : base(options) { }

    public DbSet<EfAcceptanceProbe> Probes => Set<EfAcceptanceProbe>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(EfAcceptanceDatabase.Schema);
        modelBuilder.Entity<EfAcceptanceProbe>(entity =>
        {
            entity.ToTable("probe");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Value).HasMaxLength(200).IsRequired();
        });
    }
}

public sealed class EfAcceptanceDbContextFactory : IDesignTimeDbContextFactory<EfAcceptanceDbContext>
{
    public EfAcceptanceDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<EfAcceptanceDbContext>();
        options.UseNpgsql(EfAcceptanceDatabase.ConnectionString, npgsql =>
            npgsql.MigrationsHistoryTable("__EFMigrationsHistory", EfAcceptanceDatabase.Schema));
        return new EfAcceptanceDbContext(options.Options);
    }
}

public sealed class EfAcceptanceProbe
{
    public int Id { get; set; }
    public string Value { get; set; } = string.Empty;
}

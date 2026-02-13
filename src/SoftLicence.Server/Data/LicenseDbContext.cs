using Microsoft.EntityFrameworkCore;

namespace SoftLicence.Server.Data
{
    public class LicenseDbContext : DbContext
    {
        public LicenseDbContext(DbContextOptions<LicenseDbContext> options) : base(options) { }

        public DbSet<Product> Products { get; set; }
        public DbSet<License> Licenses { get; set; }
        public DbSet<AccessLog> AccessLogs { get; set; }
        public DbSet<LicenseType> LicenseTypes { get; set; }
        public DbSet<TelemetryRecord> TelemetryRecords { get; set; }
        public DbSet<TelemetryEvent> TelemetryEvents { get; set; }
        public DbSet<TelemetryDiagnostic> TelemetryDiagnostics { get; set; }
        public DbSet<TelemetryDiagnosticResult> TelemetryDiagnosticResults { get; set; }
        public DbSet<TelemetryDiagnosticPort> TelemetryDiagnosticPorts { get; set; }
        public DbSet<TelemetryError> TelemetryErrors { get; set; }
        public DbSet<LicenseRenewal> LicenseRenewals { get; set; }
        public DbSet<BannedIp> BannedIps { get; set; }
        public DbSet<Webhook> Webhooks { get; set; }
        public DbSet<LicenseSeat> LicenseSeats { get; set; }
        public DbSet<SystemSetting> SystemSettings { get; set; }
        public DbSet<AdminRole> AdminRoles { get; set; }
        public DbSet<AdminUser> AdminUsers { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Product>()
                .HasIndex(p => p.Name)
                .IsUnique();

            modelBuilder.Entity<License>()
                .HasIndex(l => l.LicenseKey)
                .IsUnique();

            modelBuilder.Entity<License>()
                .HasOne(l => l.Product)
                .WithMany(p => p.Licenses)
                .HasForeignKey(l => l.ProductId)
                .OnDelete(DeleteBehavior.Restrict); // Protection : On ne supprime pas un produit s'il a des licences

            modelBuilder.Entity<LicenseType>()
                .HasIndex(t => t.Slug)
                .IsUnique();

            modelBuilder.Entity<LicenseRenewal>()
                .HasIndex(r => r.TransactionId)
                .IsUnique();

            modelBuilder.Entity<TelemetryRecord>()
                .HasOne(t => t.Product)
                .WithMany(p => p.TelemetryRecords)
                .HasForeignKey(t => t.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<TelemetryEvent>()
                .HasOne(e => e.Record)
                .WithOne(r => r.EventData)
                .HasForeignKey<TelemetryEvent>(e => e.TelemetryRecordId);

            modelBuilder.Entity<TelemetryDiagnostic>()
                .HasOne(d => d.Record)
                .WithOne(r => r.DiagnosticData)
                .HasForeignKey<TelemetryDiagnostic>(d => d.TelemetryRecordId);

            modelBuilder.Entity<TelemetryError>()
                .HasOne(e => e.Record)
                .WithOne(r => r.ErrorData)
                .HasForeignKey<TelemetryError>(e => e.TelemetryRecordId);
        }
    }
}

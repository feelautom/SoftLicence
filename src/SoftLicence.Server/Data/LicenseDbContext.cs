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
        public DbSet<LicenseHistory> LicenseHistories { get; set; }
        public DbSet<SystemSetting> SystemSettings { get; set; }
        public DbSet<AdminRole> AdminRoles { get; set; }
        public DbSet<AdminUser> AdminUsers { get; set; }
        public DbSet<LicenseTypeCustomParam> LicenseTypeCustomParams { get; set; }
        public DbSet<IpThreatScore> IpThreatScores { get; set; }
        public DbSet<ProductWebhook> ProductWebhooks { get; set; }

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

            // LicenseType appartient à un produit — slug unique par produit
            modelBuilder.Entity<LicenseType>()
                .HasOne(t => t.Product)
                .WithMany(p => p.LicenseTypes)
                .HasForeignKey(t => t.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<LicenseType>()
                .HasIndex(t => new { t.ProductId, t.Slug })
                .IsUnique();

            // Protection : empêcher la suppression d'un type s'il a des licences
            modelBuilder.Entity<License>()
                .HasOne(l => l.Type)
                .WithMany(t => t.Licenses)
                .HasForeignKey(l => l.LicenseTypeId)
                .OnDelete(DeleteBehavior.Restrict);

            // Hiérarchie produit / plugin (self-referencing)
            modelBuilder.Entity<Product>()
                .HasOne(p => p.ParentProduct)
                .WithMany(p => p.SubProducts)
                .HasForeignKey(p => p.ParentProductId)
                .OnDelete(DeleteBehavior.Restrict);

            // Empêcher les doublons de seat actif (même licence + même machine)
            modelBuilder.Entity<LicenseSeat>()
                .HasIndex(s => new { s.LicenseId, s.HardwareId })
                .IsUnique()
                .HasFilter("\"IsActive\" = true");

            // Index de performance sur les colonnes fréquemment requêtées
            modelBuilder.Entity<License>()
                .HasIndex(l => new { l.ProductId, l.HardwareId });

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => a.ClientIp);

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => a.Timestamp);

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

            modelBuilder.Entity<LicenseHistory>()
                .HasOne(h => h.License)
                .WithMany(l => l.History)
                .HasForeignKey(h => h.LicenseId)
                .OnDelete(DeleteBehavior.Cascade);

            // Paramètres personnalisés par type de licence — clé unique par type
            modelBuilder.Entity<LicenseTypeCustomParam>()
                .HasOne(p => p.LicenseType)
                .WithMany(t => t.CustomParams)
                .HasForeignKey(p => p.LicenseTypeId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<LicenseTypeCustomParam>()
                .HasIndex(p => new { p.LicenseTypeId, p.Key })
                .IsUnique();

            // Webhooks télémétrie par produit
            modelBuilder.Entity<ProductWebhook>()
                .HasOne(w => w.Product)
                .WithMany(p => p.Webhooks)
                .HasForeignKey(w => w.ProductId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace SoftLicence.Server.Data
{
    public class LicenseDbContext : DbContext
    {
        private readonly ILogger<LicenseDbContext>? _logger;

        public LicenseDbContext(DbContextOptions<LicenseDbContext> options, ILogger<LicenseDbContext>? logger = null) : base(options)
        {
            _logger = logger;
        }

        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                return await base.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                foreach (var entry in ex.Entries)
                {
                    var entityType = entry.Entity.GetType().Name;
                    var state = entry.State;
                    var primaryKey = entry.Properties
                        .Where(p => p.Metadata.IsPrimaryKey())
                        .Select(p => $"{p.Metadata.Name}={p.CurrentValue}")
                        .FirstOrDefault() ?? "?";

                    var msg = $"[CONCURRENCY] Entity={entityType} PK={primaryKey} State={state} — row missing or modified";
                    _logger?.LogError(msg);
                    Console.Error.WriteLine(msg);
                }
                throw;
            }
        }

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
        public DbSet<PiracySuspect> PiracySuspects { get; set; }
        public DbSet<BannedHardwareId> BannedHardwareIds { get; set; }
        public DbSet<ResellerPartner> ResellerPartners { get; set; }
        public DbSet<HardwareFingerprint> HardwareFingerprints { get; set; }
        public DbSet<BannedComponent> BannedComponents { get; set; }
        public DbSet<CanaryAlert> CanaryAlerts { get; set; }
        public DbSet<ApprovedBinary> ApprovedBinaries { get; set; }
        public DbSet<AnalyticsApiKey> AnalyticsApiKeys { get; set; }
        public DbSet<LlmTipFeedbackEvent> LlmTipFeedbackEvents { get; set; }
        public DbSet<LlmTipFeedbackTip> LlmTipFeedbackTips { get; set; }

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

            modelBuilder.Entity<License>()
                .HasIndex(l => new { l.ProductId, l.CreationDate });

            modelBuilder.Entity<License>()
                .HasIndex(l => new { l.ProductId, l.ActivationDate });

            modelBuilder.Entity<License>()
                .HasIndex(l => new { l.ProductId, l.IsActive });

            modelBuilder.Entity<PiracySuspect>()
                .HasIndex(p => new { p.ProductId, p.HardwareId })
                .IsUnique();

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => a.ClientIp);

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => a.Timestamp);

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => new { a.AppName, a.Timestamp });

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => new { a.AppName, a.Endpoint, a.Timestamp });

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => new { a.Timestamp, a.Endpoint, a.IsSuccess });

            modelBuilder.Entity<LicenseRenewal>()
                .HasIndex(r => r.TransactionId)
                .IsUnique();

            modelBuilder.Entity<TelemetryRecord>()
                .HasOne(t => t.Product)
                .WithMany(p => p.TelemetryRecords)
                .HasForeignKey(t => t.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<TelemetryRecord>()
                .HasIndex(t => new { t.ProductId, t.Timestamp });

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

            // Reseller partners
            modelBuilder.Entity<ResellerPartner>()
                .HasIndex(r => r.Code)
                .IsUnique();

            // Blacklist hardware IDs
            modelBuilder.Entity<BannedHardwareId>()
                .HasIndex(b => new { b.HardwareId, b.ProductId })
                .IsUnique()
                .HasFilter("\"IsActive\" = true");

            modelBuilder.Entity<BannedHardwareId>()
                .HasOne(b => b.Product)
                .WithMany()
                .HasForeignKey(b => b.ProductId)
                .OnDelete(DeleteBehavior.SetNull);

            // Hardware fingerprints
            modelBuilder.Entity<HardwareFingerprint>()
                .HasIndex(f => f.HardwareId)
                .IsUnique();

            modelBuilder.Entity<HardwareFingerprint>()
                .HasIndex(f => f.CpuHash);
            modelBuilder.Entity<HardwareFingerprint>()
                .HasIndex(f => f.MotherboardHash);
            modelBuilder.Entity<HardwareFingerprint>()
                .HasIndex(f => f.BiosHash);
            modelBuilder.Entity<HardwareFingerprint>()
                .HasIndex(f => f.DiskHash);
            modelBuilder.Entity<HardwareFingerprint>()
                .HasIndex(f => f.HostHash);
            modelBuilder.Entity<HardwareFingerprint>()
                .HasIndex(f => f.ClusterId);

            // Banned components
            modelBuilder.Entity<BannedComponent>()
                .HasIndex(b => new { b.ComponentType, b.ComponentHash, b.ProductId })
                .IsUnique()
                .HasFilter("\"IsActive\" = true");

            modelBuilder.Entity<BannedComponent>()
                .HasOne(b => b.Product)
                .WithMany()
                .HasForeignKey(b => b.ProductId)
                .OnDelete(DeleteBehavior.SetNull);

            // Webhooks télémétrie par produit
            modelBuilder.Entity<ProductWebhook>()
                .HasOne(w => w.Product)
                .WithMany(p => p.Webhooks)
                .HasForeignKey(w => w.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            // Hashes binaires approuvés — clé unique par produit+version+clé
            modelBuilder.Entity<ApprovedBinary>()
                .HasIndex(b => new { b.ProductId, b.Version, b.Key })
                .IsUnique();

            modelBuilder.Entity<ApprovedBinary>()
                .HasOne(b => b.Product)
                .WithMany()
                .HasForeignKey(b => b.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<AnalyticsApiKey>()
                .HasIndex(k => k.KeyHash)
                .IsUnique();

            modelBuilder.Entity<AnalyticsApiKey>()
                .HasIndex(k => new { k.ProductId, k.Prefix });

            modelBuilder.Entity<AnalyticsApiKey>()
                .HasOne(k => k.Product)
                .WithMany(p => p.AnalyticsApiKeys)
                .HasForeignKey(k => k.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<LlmTipFeedbackEvent>()
                .HasIndex(e => new { e.ProductId, e.CreatedAtUtc });

            modelBuilder.Entity<LlmTipFeedbackEvent>()
                .HasIndex(e => new { e.ProductId, e.EventName, e.CreatedAtUtc });

            modelBuilder.Entity<LlmTipFeedbackEvent>()
                .HasOne(e => e.Product)
                .WithMany()
                .HasForeignKey(e => e.ProductId)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<LlmTipFeedbackTip>()
                .HasIndex(t => t.ContentHash)
                .IsUnique();

            modelBuilder.Entity<LlmTipFeedbackTip>()
                .HasIndex(t => new { t.ProductId, t.Category, t.OccurrenceCount });

            modelBuilder.Entity<LlmTipFeedbackTip>()
                .HasIndex(t => new { t.ProductId, t.LastSeenAtUtc });

            modelBuilder.Entity<LlmTipFeedbackTip>()
                .HasOne(t => t.Product)
                .WithMany()
                .HasForeignKey(t => t.ProductId)
                .OnDelete(DeleteBehavior.SetNull);
        }
    }
}

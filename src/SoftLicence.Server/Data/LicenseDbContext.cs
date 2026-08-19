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
        public DbSet<TelemetryFloodSuppressionCounter> TelemetryFloodSuppressionCounters { get; set; }
        public DbSet<TelemetryCertPinningDailyAlert> TelemetryCertPinningDailyAlerts { get; set; }
        public DbSet<TelemetryIngestionRejection> TelemetryIngestionRejections { get; set; }
        public DbSet<ActivationIncident> ActivationIncidents { get; set; }
        public DbSet<LicenseRenewal> LicenseRenewals { get; set; }
        public DbSet<LicenseProvisioningRequest> LicenseProvisioningRequests { get; set; }
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
        public DbSet<SecurityIncident> SecurityIncidents { get; set; }
        public DbSet<SecurityIncidentEvidence> SecurityIncidentEvidence { get; set; }
        public DbSet<ApprovedBinary> ApprovedBinaries { get; set; }
        public DbSet<ApprovedBinaryRegistration> ApprovedBinaryRegistrations { get; set; }
        public DbSet<DistributionS2SNonce> DistributionS2SNonces { get; set; }
        public DbSet<DistributionBindingRequest> DistributionBindingRequests { get; set; }
        public DbSet<DistributionInstallationBinding> DistributionInstallationBindings { get; set; }
        public DbSet<DistributionBindingInvalidation> DistributionBindingInvalidations { get; set; }
        public DbSet<DistributionGrantOwnership> DistributionGrantOwnerships { get; set; }
        public DbSet<DistributionEntitlement> DistributionEntitlements { get; set; }
        public DbSet<DistributionLicenseBootstrapAuthorization> DistributionLicenseBootstrapAuthorizations { get; set; }
        public DbSet<DistributionLicenseBootstrapCapability> DistributionLicenseBootstrapCapabilities { get; set; }
        public DbSet<DistributionLicenseBootstrapRequest> DistributionLicenseBootstrapRequests { get; set; }
        public DbSet<RuntimeEnrollment> RuntimeEnrollments { get; set; }
        public DbSet<RuntimeEnrollmentWebSetupTransition> RuntimeEnrollmentWebSetupTransitions { get; set; }
        public DbSet<RuntimeEnrollmentWebSetupTransitionRequest> RuntimeEnrollmentWebSetupTransitionRequests { get; set; }
        public DbSet<RuntimeEnrollmentRequest> RuntimeEnrollmentRequests { get; set; }
        public DbSet<RuntimeEnrollmentProofNonce> RuntimeEnrollmentProofNonces { get; set; }
        public DbSet<RuntimeCanaryProofNonce> RuntimeCanaryProofNonces { get; set; }
        public DbSet<RuntimeMilestoneSession> RuntimeMilestoneSessions { get; set; }
        public DbSet<RuntimeMilestone> RuntimeMilestones { get; set; }
        public DbSet<RuntimeCriticalIncident> RuntimeCriticalIncidents { get; set; }
        public DbSet<RuntimeCriticalRecovery> RuntimeCriticalRecoveries { get; set; }
        public DbSet<RuntimeCriticalRecoveryReceipt> RuntimeCriticalRecoveryReceipts { get; set; }
        public DbSet<RuntimeEnrollmentQuota> RuntimeEnrollmentQuotas { get; set; }
        public DbSet<RuntimeEnrollmentCredentialMutex> RuntimeEnrollmentCredentialMutexes { get; set; }
        public DbSet<RuntimeEnrollmentAuthorityState> RuntimeEnrollmentAuthorityStates { get; set; }
        public DbSet<RuntimeEnrollmentEncryptionNonce> RuntimeEnrollmentEncryptionNonces { get; set; }
        public DbSet<RuntimeEnrollmentKeyRegistry> RuntimeEnrollmentKeyRegistries { get; set; }
        public DbSet<CanaryAckKeyRegistry> CanaryAckKeyRegistries { get; set; }
        public DbSet<CanaryAckKeyRegistryState> CanaryAckKeyRegistryStates { get; set; }
        public DbSet<AnalyticsApiKey> AnalyticsApiKeys { get; set; }
        public DbSet<LlmTipFeedbackEvent> LlmTipFeedbackEvents { get; set; }
        public DbSet<LlmTipFeedbackTip> LlmTipFeedbackTips { get; set; }
        /// <summary>Gets or sets authenticated, license-scoped legacy identity aliases whose live authority graph is revalidated on every use.</summary>
        public DbSet<HardwareAuthorityAlias> HardwareAuthorityAliases { get; set; }

        /// <inheritdoc />
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

            modelBuilder.Entity<HardwareAuthorityAlias>()
                .HasIndex(alias => new { alias.LicenseId, alias.LegacyHardwareIdSha256 })
                .IsUnique();
            modelBuilder.Entity<HardwareAuthorityAlias>()
                .HasIndex(alias => new { alias.ProductId, alias.LegacyHardwareIdSha256 });
            modelBuilder.Entity<HardwareAuthorityAlias>()
                .HasOne(alias => alias.Product)
                .WithMany()
                .HasForeignKey(alias => alias.ProductId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<HardwareAuthorityAlias>()
                .HasOne(alias => alias.License)
                .WithMany()
                .HasForeignKey(alias => alias.LicenseId)
                .OnDelete(DeleteBehavior.Cascade);
            modelBuilder.Entity<HardwareAuthorityAlias>()
                .HasOne(alias => alias.LicenseSeat)
                .WithMany()
                .HasForeignKey(alias => alias.LicenseSeatId)
                .OnDelete(DeleteBehavior.Cascade);
            modelBuilder.Entity<HardwareAuthorityAlias>()
                .HasOne(alias => alias.RuntimeEnrollment)
                .WithMany()
                .HasForeignKey(alias => alias.RuntimeEnrollmentId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<HardwareAuthorityAlias>()
                .HasOne(alias => alias.Binding)
                .WithMany()
                .HasForeignKey(alias => alias.BindingId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<HardwareAuthorityAlias>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint(
                        "CK_HardwareAuthorityAliases_LegacyHardwareIdSha256",
                        Database.IsNpgsql()
                            ? "length(\"LegacyHardwareIdSha256\") = 64 AND \"LegacyHardwareIdSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"LegacyHardwareIdSha256\") = 64");
                    table.HasCheckConstraint(
                        "CK_HardwareAuthorityAliases_CanonicalHardwareIdSha256",
                        Database.IsNpgsql()
                            ? "length(\"CanonicalHardwareIdSha256\") = 64 AND \"CanonicalHardwareIdSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"CanonicalHardwareIdSha256\") = 64");
                    table.HasCheckConstraint(
                        "CK_HardwareAuthorityAliases_ObservationCount",
                        "\"ObservationCount\" >= 0");
                    table.HasCheckConstraint(
                        "CK_HardwareAuthorityAliases_Epochs",
                        "\"SecurityEpoch\" >= 1 AND \"AuthorityEpoch\" >= 0");
                    table.HasCheckConstraint(
                        "CK_HardwareAuthorityAliases_State",
                        "(\"IsActive\" AND \"DisabledAtUtc\" IS NULL) OR (NOT \"IsActive\" AND \"DisabledAtUtc\" IS NOT NULL)");
                });

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

            modelBuilder.Entity<AccessLog>()
                .HasIndex(a => new { a.HardwareId, a.Timestamp, a.Endpoint, a.ResultStatus });

            modelBuilder.Entity<LicenseRenewal>()
                .HasIndex(r => r.TransactionId)
                .IsUnique();

            modelBuilder.Entity<LicenseRenewal>()
                .Property(r => r.TransactionId)
                .HasMaxLength(256);

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .HasIndex(r => new { r.ProductId, r.Reference })
                .IsUnique();

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .HasOne(r => r.Product)
                .WithMany()
                .HasForeignKey(r => r.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<License>()
                .HasOne(l => l.ProvisioningRequest)
                .WithMany(r => r.Licenses)
                .HasForeignKey(l => l.ProvisioningRequestId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<TelemetryRecord>()
                .HasOne(t => t.Product)
                .WithMany(p => p.TelemetryRecords)
                .HasForeignKey(t => t.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<TelemetryRecord>()
                .HasIndex(t => new { t.ProductId, t.Timestamp });

            modelBuilder.Entity<TelemetryFloodSuppressionCounter>()
                .HasOne(c => c.Product)
                .WithMany()
                .HasForeignKey(c => c.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<TelemetryFloodSuppressionCounter>()
                .HasIndex(c => new { c.ProductId, c.HardwareId, c.EventName, c.Type, c.WindowStartUtc });

            modelBuilder.Entity<TelemetryFloodSuppressionCounter>()
                .HasIndex(c => new { c.ProductId, c.LastSeenUtc });

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .HasOne(a => a.Product)
                .WithMany()
                .HasForeignKey(a => a.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .HasIndex(a => new { a.ProductId, a.HardwareId, a.AlertType, a.ParisDate })
                .IsUnique();

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .HasIndex(a => new { a.ProductId, a.LastSeenUtc });

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .Property(a => a.HardwareId)
                .HasMaxLength(256);

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .Property(a => a.AlertType)
                .HasMaxLength(64);

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .Property(a => a.FirstHost)
                .HasMaxLength(253);

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .Property(a => a.LastHost)
                .HasMaxLength(253);

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .Property(a => a.LastVersion)
                .HasMaxLength(64);

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .Property(a => a.LastFailureReason)
                .HasMaxLength(128);

            modelBuilder.Entity<TelemetryCertPinningDailyAlert>()
                .Property(a => a.LastCertificateIssuer)
                .HasMaxLength(512);

            modelBuilder.Entity<TelemetryIngestionRejection>()
                .HasIndex(r => new { r.TimestampUtc, r.ValidationCode });

            modelBuilder.Entity<ActivationIncident>()
                .HasOne(i => i.Product)
                .WithMany()
                .HasForeignKey(i => i.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ActivationIncident>()
                .HasIndex(i => new { i.ProductId, i.HardwareIdHash, i.Status, i.LastSeenUtc });

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

            modelBuilder.Entity<SecurityIncident>()
                .HasIndex(i => new { i.ProductId, i.HardwareId, i.Family, i.WindowStartUtc })
                .IsUnique();

            modelBuilder.Entity<SecurityIncident>()
                .HasIndex(i => new { i.ProductId, i.LastSeenUtc });

            modelBuilder.Entity<SecurityIncident>()
                .HasOne(i => i.Product)
                .WithMany()
                .HasForeignKey(i => i.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<SecurityIncidentEvidence>()
                .HasIndex(e => new { e.SecurityIncidentId, e.ComponentType, e.ComponentHash })
                .IsUnique();

            modelBuilder.Entity<SecurityIncidentEvidence>()
                .HasOne(e => e.SecurityIncident)
                .WithMany(i => i.Evidence)
                .HasForeignKey(e => e.SecurityIncidentId)
                .OnDelete(DeleteBehavior.Cascade);

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

            modelBuilder.Entity<ApprovedBinary>()
                .HasOne(binary => binary.Registration)
                .WithMany(registration => registration.Artifacts)
                .HasForeignKey(binary => binary.ApprovedBinaryRegistrationId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ApprovedBinary>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_ApprovedBinaries_Key",
                        "\"Key\" IN ('FP_EXE', 'FP_DLL', 'FP_CORE')");
                    table.HasCheckConstraint("CK_ApprovedBinaries_Hash",
                        Database.IsNpgsql()
                            ? "\"Hash\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"Hash\") = 64");
                    table.HasCheckConstraint("CK_ApprovedBinaries_Version",
                        Database.IsNpgsql()
                            ? "\"Version\" ~ '^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$'"
                            : "length(\"Version\") BETWEEN 1 AND 64");
                    table.HasCheckConstraint("CK_ApprovedBinaries_Source",
                        "\"Source\" IN ('release', 'admin', 'auto', 'publish', 'local-test')");
                    table.HasCheckConstraint("CK_ApprovedBinaries_RegistrationSource",
                        "\"ApprovedBinaryRegistrationId\" IS NULL OR \"Source\" = 'release'");
                });

            modelBuilder.Entity<ApprovedBinaryRegistration>()
                .HasIndex(registration => new { registration.ProductId, registration.Version })
                .IsUnique();

            modelBuilder.Entity<ApprovedBinaryRegistration>()
                .HasIndex(registration => registration.RegistrationKey)
                .IsUnique();

            modelBuilder.Entity<ApprovedBinaryRegistration>()
                .HasOne(registration => registration.Product)
                .WithMany()
                .HasForeignKey(registration => registration.ProductId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ApprovedBinaryRegistration>()
                .Property(registration => registration.RegistrationKey)
                .UseCollation(Database.IsNpgsql() ? "C" : "BINARY");

            modelBuilder.Entity<ApprovedBinaryRegistration>()
                .Property(registration => registration.Version)
                .UseCollation(Database.IsNpgsql() ? "C" : "BINARY");

            modelBuilder.Entity<ApprovedBinaryRegistration>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_ApprovedBinaryRegistrations_RegistrationKey",
                        Database.IsNpgsql()
                            ? "octet_length(\"RegistrationKey\") BETWEEN 1 AND 128 AND \"RegistrationKey\" ~ '^[!-~]+$'"
                            : "length(\"RegistrationKey\") BETWEEN 1 AND 128");
                    table.HasCheckConstraint("CK_ApprovedBinaryRegistrations_Version",
                        Database.IsNpgsql()
                            ? "\"Version\" ~ '^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$'"
                            : "length(\"Version\") BETWEEN 1 AND 64");
                    table.HasCheckConstraint("CK_ApprovedBinaryRegistrations_Digests",
                        Database.IsNpgsql()
                            ? "\"ManifestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"BaselineDigestSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"ManifestDigestSha256\") = 64 AND length(\"BaselineDigestSha256\") = 64");
                    table.HasCheckConstraint("CK_ApprovedBinaryRegistrations_Source", "\"Source\" = 'release'");
                });

            modelBuilder.Entity<DistributionS2SNonce>()
                .HasKey(nonce => new { nonce.ClientId, nonce.Nonce });

            modelBuilder.Entity<DistributionS2SNonce>()
                .HasIndex(nonce => nonce.ExpiresAtUtc);

            modelBuilder.Entity<DistributionBindingRequest>()
                .HasIndex(request => new { request.ClientId, request.RequestId })
                .IsUnique();

            modelBuilder.Entity<DistributionBindingRequest>()
                .HasOne(request => request.Binding)
                .WithMany()
                .HasForeignKey(request => request.BindingId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasIndex(binding => binding.HandoffDigestSha256)
                .IsUnique();

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasIndex(binding => new { binding.ProductId, binding.GrantRefDigestSha256 })
                .IsUnique();

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasIndex(binding => new { binding.ProductId, binding.InstallationId })
                .IsUnique();

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasIndex(binding => new { binding.ProductId, binding.HardwareIdHash })
                .HasFilter("\"State\" = 'active'")
                .IsUnique();

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasIndex(binding => binding.SupersededBindingId)
                .HasFilter("\"SupersededBindingId\" IS NOT NULL")
                .IsUnique();

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasOne<DistributionInstallationBinding>()
                .WithMany()
                .HasForeignKey(binding => binding.SupersededBindingId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionInstallationBinding>()
                .ToTable(table => table.HasCheckConstraint(
                    "CK_DistributionInstallationBindings_InitialSecurityEpoch",
                    "\"InitialSecurityEpoch\" >= 1"));

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasOne<Product>()
                .WithMany()
                .HasForeignKey(binding => binding.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasOne<License>()
                .WithMany()
                .HasForeignKey(binding => binding.LicenseId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionInstallationBinding>()
                .HasOne<LicenseSeat>()
                .WithMany()
                .HasForeignKey(binding => binding.LicenseSeatId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionBindingInvalidation>()
                .HasIndex(invalidation => new { invalidation.ProductId, invalidation.GrantRefDigestSha256 })
                .IsUnique();

            modelBuilder.Entity<DistributionBindingInvalidation>()
                .HasIndex(invalidation => new { invalidation.ClientId, invalidation.RequestId })
                .IsUnique();

            modelBuilder.Entity<DistributionBindingInvalidation>()
                .HasIndex(invalidation => invalidation.BindingId)
                .IsUnique()
                .HasFilter("\"BindingId\" IS NOT NULL");

            modelBuilder.Entity<DistributionBindingInvalidation>()
                .HasOne(invalidation => invalidation.Binding)
                .WithMany()
                .HasForeignKey(invalidation => invalidation.BindingId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionBindingInvalidation>()
                .HasOne<Product>()
                .WithMany()
                .HasForeignKey(invalidation => invalidation.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionBindingInvalidation>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint(
                        "CK_DistributionBindingInvalidations_Epoch_One",
                        "\"Epoch\" = 1");
                    table.HasCheckConstraint(
                        "CK_DistributionBindingInvalidations_Reason",
                        "\"Reason\" IN ('account_closed', 'fraud_flagged', 'grant_revoked', 'security_lockdown')");
                });

            modelBuilder.Entity<DistributionGrantOwnership>()
                .HasKey(ownership => new { ownership.ProductId, ownership.GrantRefDigestSha256 });

            modelBuilder.Entity<DistributionGrantOwnership>()
                .HasIndex(ownership => new { ownership.ClientId, ownership.ProductId });

            modelBuilder.Entity<DistributionGrantOwnership>()
                .HasOne<Product>()
                .WithMany()
                .HasForeignKey(ownership => ownership.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<DistributionGrantOwnership>()
                .ToTable(table => table.HasCheckConstraint(
                    "CK_DistributionGrantOwnerships_Source",
                    "\"Source\" IN ('issue_v2', 'issue_v3', 'finalize_v1')"));

            modelBuilder.Entity<DistributionEntitlement>()
                .HasIndex(entitlement => new { entitlement.ProductId, entitlement.GrantRefDigestSha256 })
                .IsUnique();
            modelBuilder.Entity<DistributionEntitlement>()
                .HasOne<Product>().WithMany().HasForeignKey(entitlement => entitlement.ProductId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionEntitlement>()
                .HasOne<License>().WithMany().HasForeignKey(entitlement => entitlement.LicenseId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionEntitlement>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_DistributionEntitlements_ContractVersion", "\"ContractVersion\" = 3");
                    table.HasCheckConstraint("CK_DistributionEntitlements_State", "\"State\" IN ('issued', 'finalized', 'expired', 'revoked')");
                    table.HasCheckConstraint("CK_DistributionEntitlements_Times", "\"IssuedAtUtc\" < \"ExpiresAtUtc\"");
                    table.HasCheckConstraint("CK_DistributionEntitlements_Digests", "length(\"GrantRefDigestSha256\") = 64 AND length(\"SubjectRefDigestSha256\") = 64");
                });

            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasIndex(authorization => new { authorization.BindingId, authorization.RuntimeEnrollmentId })
                .IsUnique();
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasIndex(authorization => authorization.ExpiresAtUtc);
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasOne<Product>().WithMany().HasForeignKey(authorization => authorization.ProductId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasOne<License>().WithMany().HasForeignKey(authorization => authorization.LicenseId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasOne<LicenseSeat>().WithMany().HasForeignKey(authorization => authorization.LicenseSeatId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasOne<DistributionInstallationBinding>().WithMany().HasForeignKey(authorization => authorization.BindingId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasOne<RuntimeEnrollment>().WithMany().HasForeignKey(authorization => authorization.RuntimeEnrollmentId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .HasOne<DistributionEntitlement>().WithMany().HasForeignKey(authorization => authorization.EntitlementId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<DistributionLicenseBootstrapAuthorization>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_State", "\"State\" IN ('ISSUED', 'CONSUMED', 'REVOKED', 'EXPIRED')");
                    table.HasCheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_Times", "\"IssuedAtUtc\" < \"ExpiresAtUtc\"");
                    table.HasCheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_Digests", "length(\"GrantRefDigestSha256\") = 64 AND length(\"SubjectRefDigestSha256\") = 64 AND length(\"HandoffDigestSha256\") = 64 AND length(\"HardwareIdHash\") = 64 AND length(\"ApprovedBinariesDigestSha256\") = 64 AND length(\"RuntimePublicKeySpkiSha256\") = 64");
                    table.HasCheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_ResponseLengths", "\"ResponsePlaintextLength\" IS NULL OR (\"ResponsePlaintextLength\" >= 1 AND \"ResponsePlaintextLength\" <= 65536)");
                    table.HasCheckConstraint("CK_DistributionLicenseBootstrapAuthorizations_Consumption", "(\"State\" = 'ISSUED' AND \"ConsumedAtUtc\" IS NULL AND \"ResponseCiphertext\" IS NULL) OR (\"State\" = 'CONSUMED' AND \"ConsumedAtUtc\" IS NOT NULL AND \"ReplayExpiresAtUtc\" IS NOT NULL AND ((\"ResponseCiphertext\" IS NOT NULL AND \"ResponseKeyId\" IS NOT NULL) OR (\"ResponseCiphertext\" IS NULL AND \"ResponseKeyId\" IS NULL))) OR \"State\" IN ('REVOKED', 'EXPIRED')");
                });

            modelBuilder.Entity<DistributionLicenseBootstrapCapability>()
                .HasIndex(capability => capability.CapabilityDigestSha256).IsUnique();
            modelBuilder.Entity<DistributionLicenseBootstrapCapability>()
                .HasOne<DistributionLicenseBootstrapAuthorization>().WithMany()
                .HasForeignKey(capability => capability.AuthorizationId).OnDelete(DeleteBehavior.Cascade);
            modelBuilder.Entity<DistributionLicenseBootstrapCapability>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_DistributionLicenseBootstrapCapabilities_State", "\"State\" IN ('ISSUED', 'CONSUMED', 'REVOKED', 'EXPIRED')");
                    table.HasCheckConstraint("CK_DistributionLicenseBootstrapCapabilities_Times", "\"MintedAtUtc\" < \"ExpiresAtUtc\"");
                });

            modelBuilder.Entity<DistributionLicenseBootstrapRequest>()
                .HasKey(request => new { request.ClientId, request.Operation, request.RequestId });
            modelBuilder.Entity<DistributionLicenseBootstrapRequest>()
                .HasOne<DistributionLicenseBootstrapAuthorization>().WithMany()
                .HasForeignKey(request => request.AuthorizationId).OnDelete(DeleteBehavior.Cascade);
            modelBuilder.Entity<DistributionLicenseBootstrapRequest>()
                .HasOne<DistributionLicenseBootstrapCapability>().WithMany()
                .HasForeignKey(request => request.CapabilityId).OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransition>()
                .HasIndex(transition => transition.CapabilityDigestSha256).IsUnique();
            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransition>()
                .HasIndex(transition => new { transition.EnrollmentId, transition.State, transition.ExpiresAtUtc });
            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransition>()
                .HasOne<Product>().WithMany().HasForeignKey(transition => transition.ProductId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransition>()
                .HasOne<DistributionInstallationBinding>().WithMany().HasForeignKey(transition => transition.BindingId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransition>()
                .HasOne<RuntimeEnrollment>().WithMany().HasForeignKey(transition => transition.EnrollmentId)
                .OnDelete(DeleteBehavior.Restrict);
            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransition>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_State", "\"State\" IN ('ISSUED', 'CONSUMED', 'REVOKED', 'EXPIRED')");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_Times", "\"IssuedAtUtc\" < \"ExpiresAtUtc\"");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_Capability", "length(\"CapabilityDigestSha256\") = 64");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentWebSetupTransitions_Consumption", "(\"State\" = 'ISSUED' AND \"ConsumedAtUtc\" IS NULL AND \"ConsumedPayloadDigestSha256\" IS NULL) OR (\"State\" = 'CONSUMED' AND \"ConsumedAtUtc\" IS NOT NULL AND length(\"ConsumedPayloadDigestSha256\") = 64) OR \"State\" IN ('REVOKED', 'EXPIRED')");
                });

            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransitionRequest>()
                .HasKey(request => new { request.ClientId, request.Operation, request.RequestId });
            modelBuilder.Entity<RuntimeEnrollmentWebSetupTransitionRequest>()
                .HasOne<RuntimeEnrollmentWebSetupTransition>().WithMany()
                .HasForeignKey(request => request.TransitionId).OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RuntimeEnrollment>()
                .HasOne(enrollment => enrollment.Binding)
                .WithMany()
                .HasForeignKey(enrollment => enrollment.BindingId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeEnrollment>()
                .Property(enrollment => enrollment.PublicKeySpkiKeyPurpose)
                .HasDefaultValue("encryption");

            modelBuilder.Entity<RuntimeEnrollment>()
                .Property(enrollment => enrollment.ChallengeKeyPurpose)
                .HasDefaultValue("encryption");

            modelBuilder.Entity<RuntimeEnrollment>()
                .Property(enrollment => enrollment.SecurityEpoch)
                .HasDefaultValue(1);

            modelBuilder.Entity<RuntimeEnrollment>()
                .HasOne<RuntimeEnrollmentKeyRegistry>()
                .WithMany()
                .HasForeignKey(enrollment => new { enrollment.PublicKeySpkiKeyPurpose, enrollment.PublicKeySpkiKeyId })
                .HasPrincipalKey(key => new { key.Purpose, key.KeyId })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeEnrollment>()
                .HasOne<RuntimeEnrollmentKeyRegistry>()
                .WithMany()
                .HasForeignKey(enrollment => new { enrollment.ChallengeKeyPurpose, enrollment.ChallengeKeyId })
                .HasPrincipalKey(key => new { key.Purpose, key.KeyId })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeEnrollment>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeEnrollments_PublicKeySpkiKeyPurpose", "\"PublicKeySpkiKeyPurpose\" = 'encryption'");
                    table.HasCheckConstraint("CK_RuntimeEnrollments_ChallengeKeyPurpose", "\"ChallengeKeyPurpose\" = 'encryption'");
                    table.HasCheckConstraint("CK_RuntimeEnrollments_State", "\"State\" IN ('PENDING', 'ACTIVE', 'INVALIDATED')");
                    table.HasCheckConstraint("CK_RuntimeEnrollments_Epoch", "\"Epoch\" = 1");
                    table.HasCheckConstraint("CK_RuntimeEnrollments_SecurityEpoch", "\"SecurityEpoch\" >= 1");
                });

            modelBuilder.Entity<RuntimeEnrollment>()
                .HasIndex(enrollment => enrollment.BindingId)
                .HasFilter("\"State\" IN ('PENDING', 'ACTIVE')")
                .IsUnique();

            modelBuilder.Entity<RuntimeEnrollment>()
                .HasIndex(enrollment => enrollment.KeyThumbprint)
                .HasFilter("\"State\" IN ('PENDING', 'ACTIVE')")
                .IsUnique();

            modelBuilder.Entity<RuntimeEnrollment>()
                .HasIndex(enrollment => new { enrollment.State, enrollment.ChallengeExpiresAtUtc });

            modelBuilder.Entity<RuntimeEnrollmentRequest>()
                .HasIndex(request => new { request.ClientId, request.Operation, request.RequestId })
                .IsUnique();

            modelBuilder.Entity<RuntimeEnrollmentRequest>()
                .Property(request => request.ResponseKeyPurpose)
                .HasDefaultValue("encryption");

            modelBuilder.Entity<RuntimeEnrollmentRequest>()
                .HasOne(request => request.Enrollment)
                .WithMany()
                .HasForeignKey(request => request.EnrollmentId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RuntimeEnrollmentRequest>()
                .HasOne<RuntimeEnrollmentKeyRegistry>()
                .WithMany()
                .HasForeignKey(request => new { request.ResponseKeyPurpose, request.ResponseKeyId })
                .HasPrincipalKey(key => new { key.Purpose, key.KeyId })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeEnrollmentRequest>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeEnrollmentRequests_ResponseKeyPurpose",
                        "\"ResponseKeyPurpose\" = 'encryption'");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentRequests_Operation",
                        "\"Operation\" IN ('prepare', 'upgrade', 'rollback', 'websetup-upgrade')");
                });

            modelBuilder.Entity<RuntimeEnrollmentProofNonce>()
                .HasKey(nonce => new { nonce.EnrollmentId, nonce.Jti });

            modelBuilder.Entity<RuntimeEnrollmentProofNonce>()
                .Property(nonce => nonce.ResponseKeyPurpose)
                .HasDefaultValue("encryption");

            modelBuilder.Entity<RuntimeEnrollmentProofNonce>()
                .HasOne(nonce => nonce.Enrollment)
                .WithMany()
                .HasForeignKey(nonce => nonce.EnrollmentId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RuntimeEnrollmentProofNonce>()
                .HasOne<RuntimeEnrollmentKeyRegistry>()
                .WithMany()
                .HasForeignKey(nonce => new { nonce.ResponseKeyPurpose, nonce.ResponseKeyId })
                .HasPrincipalKey(key => new { key.Purpose, key.KeyId })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeEnrollmentProofNonce>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeEnrollmentProofNonces_ResponseKeyPurpose",
                        "\"ResponseKeyPurpose\" = 'encryption'");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentProofNonces_Operation",
                        "\"Operation\" IN ('confirm', 'capability', 'critical-recovery-refetch', 'milestone', 'upgrade', 'rollback', 'websetup-upgrade', 'hardware-authority-migration')");
                });

            modelBuilder.Entity<RuntimeEnrollmentProofNonce>()
                .HasIndex(nonce => nonce.ExpiresAtUtc);

            modelBuilder.Entity<RuntimeCanaryProofNonce>()
                .HasKey(nonce => new { nonce.EnrollmentId, nonce.Jti });

            modelBuilder.Entity<RuntimeCanaryProofNonce>()
                .HasOne(nonce => nonce.Enrollment)
                .WithMany()
                .HasForeignKey(nonce => nonce.EnrollmentId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RuntimeCanaryProofNonce>()
                .HasIndex(nonce => nonce.EventId)
                .IsUnique();

            modelBuilder.Entity<RuntimeCanaryProofNonce>()
                .Property(nonce => nonce.ResponseKeyPurpose)
                .HasDefaultValue("encryption");

            modelBuilder.Entity<RuntimeCanaryProofNonce>()
                .HasOne<RuntimeEnrollmentKeyRegistry>()
                .WithMany()
                .HasForeignKey(nonce => new { nonce.ResponseKeyPurpose, nonce.ResponseKeyId })
                .HasPrincipalKey(key => new { key.Purpose, key.KeyId })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCanaryProofNonce>()
                .ToTable(table => table.HasCheckConstraint(
                    "CK_RuntimeCanaryProofNonces_ResponseKeyPurpose", "\"ResponseKeyPurpose\" = 'encryption'"));

            modelBuilder.Entity<RuntimeCanaryProofNonce>()
                .HasIndex(nonce => nonce.ExpiresAtUtc);

            modelBuilder.Entity<RuntimeMilestoneSession>()
                .HasKey(session => new { session.EnrollmentId, session.SessionId });

            modelBuilder.Entity<RuntimeMilestoneSession>()
                .HasOne(session => session.Enrollment)
                .WithMany()
                .HasForeignKey(session => session.EnrollmentId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RuntimeMilestoneSession>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeMilestoneSessions_SecurityEpoch", "\"SecurityEpoch\" >= 1");
                    table.HasCheckConstraint("CK_RuntimeMilestoneSessions_LastSequence", "\"LastSequence\" >= 1");
                    table.HasCheckConstraint("CK_RuntimeMilestoneSessions_Times",
                        "\"CreatedAtUtc\" <= \"LastAcceptedAtUtc\" AND \"LastAcceptedAtUtc\" < \"ExpiresAtUtc\"");
                });

            modelBuilder.Entity<RuntimeMilestoneSession>()
                .HasIndex(session => session.ExpiresAtUtc);

            modelBuilder.Entity<RuntimeMilestone>()
                .HasKey(milestone => new { milestone.EnrollmentId, milestone.SessionId, milestone.Sequence });

            modelBuilder.Entity<RuntimeMilestone>()
                .HasOne(milestone => milestone.Session)
                .WithMany()
                .HasForeignKey(milestone => new { milestone.EnrollmentId, milestone.SessionId })
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RuntimeMilestone>()
                .HasIndex(milestone => milestone.EventId)
                .IsUnique();

            modelBuilder.Entity<RuntimeMilestone>()
                .HasIndex(milestone => new { milestone.EnrollmentId, milestone.Jti })
                .IsUnique();

            modelBuilder.Entity<RuntimeMilestone>()
                .HasIndex(milestone => new { milestone.EnrollmentId, milestone.SessionId, milestone.Code })
                .IsUnique();

            modelBuilder.Entity<RuntimeMilestone>()
                .HasIndex(milestone => milestone.ExpiresAtUtc);

            modelBuilder.Entity<RuntimeMilestone>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeMilestones_Sequence", "\"Sequence\" >= 1");
                    table.HasCheckConstraint("CK_RuntimeMilestones_EvidenceClass", "\"EvidenceClass\" = 'client_declared'");
                    table.HasCheckConstraint("CK_RuntimeMilestones_Code", "\"Code\" IN ('api_opened', 'bootstrap_entered', 'capability_issued', 'integrity_allowed', 'integrity_denied', 'license_allowed', 'license_denied', 'mcp_invocation_allowed', 'mcp_invocation_denied', 'mcp_invocation_requested', 'mcp_opened', 'rest_invocation_allowed', 'rest_invocation_denied', 'rest_invocation_requested', 'tia_connected', 'tia_detection_allowed', 'tia_detection_denied', 'tia_operation_completed', 'tia_operation_failed', 'tia_operation_started')");
                    table.HasCheckConstraint("CK_RuntimeMilestones_Times",
                        "\"AcceptedAtUtc\" < \"ExpiresAtUtc\"");
                });

            modelBuilder.Entity<RuntimeCriticalIncident>()
                .HasOne(incident => incident.Enrollment)
                .WithMany()
                .HasForeignKey(incident => new
                {
                    incident.EnrollmentId,
                    incident.BindingId,
                    incident.ProductId,
                    incident.InstallationId
                })
                .HasPrincipalKey(enrollment => new
                {
                    enrollment.Id,
                    enrollment.BindingId,
                    enrollment.ProductId,
                    enrollment.InstallationId
                })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalIncident>()
                .HasOne<DistributionInstallationBinding>()
                .WithMany()
                .HasForeignKey(incident => incident.BindingId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalIncident>()
                .HasOne<Product>()
                .WithMany()
                .HasForeignKey(incident => incident.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalIncident>()
                .HasIndex(incident => incident.EventId)
                .IsUnique();

            modelBuilder.Entity<RuntimeCriticalIncident>()
                .HasIndex(incident => new { incident.BindingId, incident.InstallationId, incident.State })
                .HasFilter("\"State\" = 'OPEN'");

            modelBuilder.Entity<RuntimeCriticalIncident>()
                .HasOne(incident => incident.Recovery)
                .WithMany()
                .HasForeignKey(incident => incident.RecoveryId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalIncident>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeCriticalIncidents_State",
                        "\"State\" IN ('OPEN', 'RESOLVED')");
                    table.HasCheckConstraint("CK_RuntimeCriticalIncidents_Epochs",
                        "\"OpenedSecurityEpoch\" >= 1 AND (\"RecoveredSecurityEpoch\" IS NULL OR \"RecoveredSecurityEpoch\" >= \"OpenedSecurityEpoch\" + 1)");
                    table.HasCheckConstraint("CK_RuntimeCriticalIncidents_Resolution",
                        "(\"State\" = 'OPEN' AND \"RecoveryId\" IS NULL AND \"RecoveredSecurityEpoch\" IS NULL AND \"RecoveredAuthorityEpoch\" IS NULL AND \"RecoveredAtUtc\" IS NULL) OR (\"State\" = 'RESOLVED' AND \"RecoveryId\" IS NOT NULL AND \"RecoveredSecurityEpoch\" IS NOT NULL AND \"RecoveredAuthorityEpoch\" IS NOT NULL AND \"RecoveredAtUtc\" IS NOT NULL)");
                });

            modelBuilder.Entity<RuntimeCriticalRecovery>()
                .HasOne<RuntimeEnrollment>()
                .WithMany()
                .HasForeignKey(recovery => new
                {
                    recovery.EnrollmentId,
                    recovery.BindingId,
                    recovery.ProductId,
                    recovery.InstallationId
                })
                .HasPrincipalKey(enrollment => new
                {
                    enrollment.Id,
                    enrollment.BindingId,
                    enrollment.ProductId,
                    enrollment.InstallationId
                })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalRecovery>()
                .HasOne<DistributionInstallationBinding>()
                .WithMany()
                .HasForeignKey(recovery => recovery.BindingId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalRecovery>()
                .HasOne<Product>()
                .WithMany()
                .HasForeignKey(recovery => recovery.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalRecovery>()
                .HasIndex(recovery => new
                {
                    recovery.BindingId,
                    recovery.InstallationId,
                    recovery.NewSecurityEpoch
                })
                .IsUnique();

            modelBuilder.Entity<RuntimeCriticalRecovery>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeCriticalRecoveries_Epochs",
                        "\"OldSecurityEpoch\" >= 1 AND \"NewSecurityEpoch\" = \"OldSecurityEpoch\" + 1");
                    table.HasCheckConstraint("CK_RuntimeCriticalRecoveries_IncidentCount",
                        "\"ResolvedIncidentCount\" >= 1");
                });

            modelBuilder.Entity<RuntimeCriticalRecoveryReceipt>()
                .HasOne(receipt => receipt.Recovery)
                .WithMany()
                .HasForeignKey(receipt => receipt.RecoveryId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeCriticalRecoveryReceipt>()
                .HasIndex(receipt => receipt.RequestId)
                .IsUnique();

            modelBuilder.Entity<RuntimeCriticalRecoveryReceipt>()
                .HasIndex(receipt => receipt.ExpiresAtUtc);

            modelBuilder.Entity<RuntimeCriticalRecoveryReceipt>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeCriticalRecoveryReceipts_Delivery",
                        Database.IsNpgsql()
                            ? "(\"ExactResponseBody\" IS NOT NULL AND \"DeliveryPurgedAtUtc\" IS NULL AND octet_length(\"ExactResponseBody\") BETWEEN 1 AND 8192) OR (\"ExactResponseBody\" IS NULL AND \"DeliveryPurgedAtUtc\" IS NOT NULL AND \"DeliveryPurgedAtUtc\" >= \"ExpiresAtUtc\")"
                            : "(\"ExactResponseBody\" IS NOT NULL AND \"DeliveryPurgedAtUtc\" IS NULL AND length(\"ExactResponseBody\") BETWEEN 1 AND 8192) OR (\"ExactResponseBody\" IS NULL AND \"DeliveryPurgedAtUtc\" IS NOT NULL AND \"DeliveryPurgedAtUtc\" >= \"ExpiresAtUtc\")");
                    table.HasCheckConstraint("CK_RuntimeCriticalRecoveryReceipts_Times",
                        "\"ExpiresAtUtc\" > \"IssuedAtUtc\"");
                });

            modelBuilder.Entity<RuntimeEnrollmentQuota>()
                .HasKey(quota => new { quota.Scope, quota.SubjectPseudonym, quota.WindowStartedAtUtc });

            modelBuilder.Entity<RuntimeEnrollmentQuota>()
                .ToTable(table => table.HasCheckConstraint(
                    "CK_RuntimeEnrollmentQuotas_Count", "\"Count\" >= 0"));

            modelBuilder.Entity<RuntimeEnrollmentQuota>()
                .HasIndex(quota => quota.ExpiresAtUtc);

            modelBuilder.Entity<RuntimeEnrollmentCredentialMutex>()
                .HasKey(mutex => mutex.BindingId);

            modelBuilder.Entity<RuntimeEnrollmentCredentialMutex>()
                .HasIndex(mutex => mutex.ExpiresAtUtc);

            modelBuilder.Entity<RuntimeEnrollmentAuthorityState>()
                .HasKey(state => state.Id);

            modelBuilder.Entity<RuntimeEnrollmentAuthorityState>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeEnrollmentAuthorityStates_Id", "\"Id\" = 1");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentAuthorityStates_Epoch", "\"Epoch\" >= 0");
                });

            modelBuilder.Entity<RuntimeEnrollmentEncryptionNonce>()
                .HasKey(nonce => new { nonce.KeyId, nonce.Nonce });

            modelBuilder.Entity<RuntimeEnrollmentEncryptionNonce>()
                .Property(nonce => nonce.Purpose)
                .HasDefaultValue("encryption");

            modelBuilder.Entity<RuntimeEnrollmentEncryptionNonce>()
                .ToTable(table => table.HasCheckConstraint(
                    "CK_RuntimeEnrollmentEncryptionNonces_NonceLength",
                    Database.IsNpgsql()
                        ? "octet_length(\"Nonce\") = 12"
                        : "length(\"Nonce\") = 12"));

            modelBuilder.Entity<RuntimeEnrollmentEncryptionNonce>()
                .ToTable(table => table.HasCheckConstraint(
                    "CK_RuntimeEnrollmentEncryptionNonces_Purpose",
                    "\"Purpose\" = 'encryption'"));

            modelBuilder.Entity<RuntimeEnrollmentEncryptionNonce>()
                .HasOne<RuntimeEnrollmentKeyRegistry>()
                .WithMany()
                .HasForeignKey(nonce => new { nonce.Purpose, nonce.KeyId })
                .HasPrincipalKey(key => new { key.Purpose, key.KeyId })
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuntimeEnrollmentKeyRegistry>()
                .HasKey(key => new { key.Purpose, key.KeyId });

            modelBuilder.Entity<RuntimeEnrollmentKeyRegistry>()
                .HasIndex(key => new { key.Purpose, key.MaterialDigestSha256 })
                .IsUnique();

            modelBuilder.Entity<RuntimeEnrollmentKeyRegistry>()
                .HasIndex(key => key.KeyId)
                .IsUnique();

            modelBuilder.Entity<RuntimeEnrollmentKeyRegistry>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeEnrollmentKeyRegistries_Purpose",
                        "\"Purpose\" IN ('encryption', 'capability-signing', 'registry-version')");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentKeyRegistries_State",
                        "\"State\" IN ('active', 'next', 'previous', 'decrypt-only', 'verify-only', 'retired')");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentKeyRegistries_Epoch", "\"Epoch\" >= 1");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentKeyRegistries_Digest",
                        Database.IsNpgsql()
                            ? "length(\"MaterialDigestSha256\") = 64 AND \"MaterialDigestSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"MaterialDigestSha256\") = 64 AND \"MaterialDigestSha256\" NOT GLOB '*[^0-9a-f]*'");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentKeyRegistries_LifecycleTimestamps",
                        "(\"State\" = 'previous' AND \"Purpose\" = 'capability-signing' AND \"RetainUntilUtc\" IS NOT NULL AND \"RetiredAtUtc\" IS NULL)"
                        + " OR (\"State\" = 'retired' AND \"RetiredAtUtc\" IS NOT NULL)"
                        + " OR (\"State\" NOT IN ('previous', 'retired') AND \"RetainUntilUtc\" IS NULL AND \"RetiredAtUtc\" IS NULL)");
                });

            modelBuilder.Entity<CanaryAckKeyRegistry>()
                .HasKey(key => key.KeyId);

            modelBuilder.Entity<CanaryAckKeyRegistry>()
                .HasIndex(key => key.MaterialDigestSha256)
                .IsUnique();

            modelBuilder.Entity<CanaryAckKeyRegistry>()
                .HasIndex(key => key.State, "IX_CanaryAckKeyRegistries_Active")
                .IsUnique()
                .HasFilter("\"State\" = 'active'");

            modelBuilder.Entity<CanaryAckKeyRegistry>()
                .HasIndex(key => key.State, "IX_CanaryAckKeyRegistries_Next")
                .IsUnique()
                .HasFilter("\"State\" = 'next'");

            modelBuilder.Entity<CanaryAckKeyRegistry>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_CanaryAckKeyRegistries_State",
                        "\"State\" IN ('active', 'next', 'previous', 'retired')");
                    table.HasCheckConstraint("CK_CanaryAckKeyRegistries_Epoch", "\"Epoch\" >= 1");
                    table.HasCheckConstraint("CK_CanaryAckKeyRegistries_Digest",
                        Database.IsNpgsql()
                            ? "length(\"MaterialDigestSha256\") = 64 AND \"MaterialDigestSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"MaterialDigestSha256\") = 64 AND \"MaterialDigestSha256\" NOT GLOB '*[^0-9a-f]*'");
                    table.HasCheckConstraint("CK_CanaryAckKeyRegistries_Retention",
                        "(\"State\" = 'previous' AND \"RetainUntilUtc\" IS NOT NULL AND \"RetiredAtUtc\" IS NULL)"
                        + " OR (\"State\" = 'retired' AND \"RetiredAtUtc\" IS NOT NULL)"
                        + " OR (\"State\" IN ('active', 'next') AND \"RetainUntilUtc\" IS NULL AND \"RetiredAtUtc\" IS NULL)");
                });

            modelBuilder.Entity<CanaryAckKeyRegistryState>()
                .HasKey(state => state.Id);

            modelBuilder.Entity<CanaryAckKeyRegistryState>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_CanaryAckKeyRegistryStates_Singleton", "\"Id\" = 1");
                    table.HasCheckConstraint("CK_CanaryAckKeyRegistryStates_Version", "\"RegistryVersion\" >= 1");
                    table.HasCheckConstraint("CK_CanaryAckKeyRegistryStates_Digest",
                        Database.IsNpgsql()
                            ? "length(\"ContentDigestSha256\") = 64 AND \"ContentDigestSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"ContentDigestSha256\") = 64 AND \"ContentDigestSha256\" NOT GLOB '*[^0-9a-f]*'");
                });

            modelBuilder.Entity<AnalyticsApiKey>()
                .HasIndex(k => k.KeyHash)
                .IsUnique();

            modelBuilder.Entity<AnalyticsApiKey>()
                .HasIndex(k => new { k.ProductId, k.Prefix });

            modelBuilder.Entity<AnalyticsApiKey>()
                .Property(k => k.ScopeKind)
                .HasMaxLength(32)
                .HasDefaultValue(AnalyticsApiKeyScopeKinds.Product);

            modelBuilder.Entity<AnalyticsApiKey>()
                .HasOne(k => k.Product)
                .WithMany(p => p.AnalyticsApiKeys)
                .HasForeignKey(k => k.ProductId)
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired(false);

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

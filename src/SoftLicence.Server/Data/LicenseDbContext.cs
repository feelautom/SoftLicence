using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace SoftLicence.Server.Data
{
    /// <summary>Maps licensing authority, provenance and audit persistence, including additive paid-pass evidence.</summary>
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

        /// <summary>Stable paid-pass identities; current license authority is reconciled under PostgreSQL locks.</summary>
        public DbSet<PersonalDayPass> PersonalDayPasses { get; set; }
        /// <summary>Exact confirmed-payment evidence, independent of transport event identifiers.</summary>
        public DbSet<PersonalDayPassPayment> PersonalDayPassPayments { get; set; }
        /// <summary>Historical operation receipts, never a substitute for current ownership/version readback.</summary>
        public DbSet<PersonalDayPassOperation> PersonalDayPassOperations { get; set; }
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
        public DbSet<TelemetryUpdatePreflightAlert> TelemetryUpdatePreflightAlerts { get; set; }
        public DbSet<TelemetryIngestionRejection> TelemetryIngestionRejections { get; set; }
        /// <summary>Gets or sets dedicated Recovery run projections.</summary>
        public DbSet<RecoveryTelemetryRun> RecoveryTelemetryRuns { get; set; }
        /// <summary>Gets or sets immutable accepted Recovery events.</summary>
        public DbSet<RecoveryTelemetryEvent> RecoveryTelemetryEvents { get; set; }
        /// <summary>Gets or sets bounded privacy-safe Recovery rejections.</summary>
        public DbSet<RecoveryTelemetryRejection> RecoveryTelemetryRejections { get; set; }
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
        /// <summary>Gets distinct machine-identity evidence reports from UUID-aware clients (TKT-001277 lot 2a).</summary>
        public DbSet<MachineEvidenceObservation> MachineEvidenceObservations { get; set; }
        public DbSet<BannedComponent> BannedComponents { get; set; }
        public DbSet<CanaryAlert> CanaryAlerts { get; set; }
        public DbSet<SecurityIncident> SecurityIncidents { get; set; }
        public DbSet<SecurityIncidentEvidence> SecurityIncidentEvidence { get; set; }
        public DbSet<ApprovedBinary> ApprovedBinaries { get; set; }
        public DbSet<ApprovedBinaryRegistration> ApprovedBinaryRegistrations { get; set; }
        public DbSet<DistributionS2SNonce> DistributionS2SNonces { get; set; }
        /// <summary>Gets provider-owned portal-deactivation idempotency terminals.</summary>
        public DbSet<PortalDeactivationOperation> PortalDeactivationOperations { get; set; }
        public DbSet<DistributionBindingRequest> DistributionBindingRequests { get; set; }
        public DbSet<DistributionInstallationBinding> DistributionInstallationBindings { get; set; }
        public DbSet<DistributionBindingInvalidation> DistributionBindingInvalidations { get; set; }
        public DbSet<DistributionGrantOwnership> DistributionGrantOwnerships { get; set; }
        public DbSet<DistributionEntitlement> DistributionEntitlements { get; set; }
        /// <summary>Gets provider-owned, privacy-bounded pre-download hardware decisions.</summary>
        public DbSet<RuntimeDistributionHardwareDecision> RuntimeDistributionHardwareDecisions { get; set; }
        public DbSet<DistributionLicenseBootstrapAuthorization> DistributionLicenseBootstrapAuthorizations { get; set; }
        public DbSet<DistributionLicenseBootstrapCapability> DistributionLicenseBootstrapCapabilities { get; set; }
        public DbSet<DistributionLicenseBootstrapRequest> DistributionLicenseBootstrapRequests { get; set; }
        public DbSet<RuntimeEnrollment> RuntimeEnrollments { get; set; }
        /// <summary>Current and historical commercial assignments, independent of hardware identity.</summary>
        public DbSet<EnrollmentLicenseAssignment> EnrollmentLicenseAssignments { get; set; }
        /// <summary>Legacy enrollment graphs that could not be mapped to one proven seat.</summary>
        public DbSet<EnrollmentLicenseAssignmentQuarantine> EnrollmentLicenseAssignmentQuarantines { get; set; }
        /// <summary>Single-row open/closed switch of the commercial-assignment controls (TKT-001277 lot 2d).</summary>
        public DbSet<AssignmentEnforcementSetting> AssignmentEnforcementSettings { get; set; }
        /// <summary>Places where an assignment control would have blocked while the switch was open.</summary>
        public DbSet<AssignmentEnforcementEvent> AssignmentEnforcementEvents { get; set; }
        public DbSet<RuntimeEnrollmentWebSetupTransition> RuntimeEnrollmentWebSetupTransitions { get; set; }
        public DbSet<RuntimeEnrollmentWebSetupTransitionRequest> RuntimeEnrollmentWebSetupTransitionRequests { get; set; }
        public DbSet<RuntimeEnrollmentRequest> RuntimeEnrollmentRequests { get; set; }
        public DbSet<RuntimeEnrollmentProofNonce> RuntimeEnrollmentProofNonces { get; set; }

        /// <summary>Gets durable migration acceptance facts, separate from replay-nonce retention.</summary>
        public DbSet<HardwareAuthorityMigrationReceipt> HardwareAuthorityMigrationReceipts { get; set; }
        public DbSet<RuntimeCanaryProofNonce> RuntimeCanaryProofNonces { get; set; }
        public DbSet<SecurityLockReport> SecurityLockReports { get; set; }
        public DbSet<SecurityLockReportNonce> SecurityLockReportNonces { get; set; }
        public DbSet<SecurityLockEnforcementPolicy> SecurityLockEnforcementPolicies { get; set; }
        /// <summary>Gets durable per-channel security-lock alert deliveries.</summary>
        public DbSet<SecurityLockAlertDelivery> SecurityLockAlertDeliveries { get; set; }
        public DbSet<RuntimeMilestoneSession> RuntimeMilestoneSessions { get; set; }
        public DbSet<RuntimeMilestone> RuntimeMilestones { get; set; }
        public DbSet<RuntimeCriticalIncident> RuntimeCriticalIncidents { get; set; }
        public DbSet<RuntimeCriticalRecovery> RuntimeCriticalRecoveries { get; set; }
        public DbSet<RuntimeCriticalRecoveryReceipt> RuntimeCriticalRecoveryReceipts { get; set; }
        public DbSet<RuntimeEnrollmentQuota> RuntimeEnrollmentQuotas { get; set; }
        public DbSet<RuntimeEnrollmentCredentialMutex> RuntimeEnrollmentCredentialMutexes { get; set; }
        public DbSet<RuntimeEnrollmentAuthorityState> RuntimeEnrollmentAuthorityStates { get; set; }
        public DbSet<RuntimeEnrollmentAuthorityLineage> RuntimeEnrollmentAuthorityLineages { get; set; }
        public DbSet<RuntimeEnrollmentAuthorityGeneration> RuntimeEnrollmentAuthorityGenerations { get; set; }
        public DbSet<RuntimeEnrollmentAuthorityRequest> RuntimeEnrollmentAuthorityRequests { get; set; }
        public DbSet<RuntimeEnrollmentAuthorityAttempt> RuntimeEnrollmentAuthorityAttempts { get; set; }
        /// <summary>Gets the immutable public Runtime authority key-registry snapshots.</summary>
        public DbSet<RuntimeAuthorityKeyRegistrySnapshot> RuntimeAuthorityKeyRegistrySnapshots { get; set; }
        /// <summary>Gets the sole durable current head of each public Runtime authority key registry.</summary>
        public DbSet<RuntimeAuthorityKeyRegistryHead> RuntimeAuthorityKeyRegistryHeads { get; set; }
        /// <summary>Gets semantic S2S readbacks bound to immutable public snapshot bodies.</summary>
        public DbSet<RuntimeAuthorityKeyRegistryReadback> RuntimeAuthorityKeyRegistryReadbacks { get; set; }
        /// <summary>Gets or sets immutable composite-key recovery authorization terminals.</summary>
        public DbSet<RuntimeSeatRecoveryAuthorization> RuntimeSeatRecoveryAuthorizations { get; set; }
        /// <summary>Gets or sets provider-owned recovery seat reservations.</summary>
        public DbSet<RuntimeSeatRecoveryReservation> RuntimeSeatRecoveryReservations { get; set; }
        /// <summary>Gets or sets recovery lifecycle envelopes around immutable v2 generations.</summary>
        public DbSet<RuntimeSeatRecoveryAuthority> RuntimeSeatRecoveryAuthorities { get; set; }
        /// <summary>Provider-protected one-shot key preparations for Runtime recovery.</summary>
        public DbSet<RuntimeSeatRecoveryKeyPreparation> RuntimeSeatRecoveryKeyPreparations { get; set; }
        /// <summary>Immutable key-confirmation terminals used for exact replay.</summary>
        public DbSet<RuntimeSeatRecoveryKeyConfirmation> RuntimeSeatRecoveryKeyConfirmations { get; set; }
        /// <summary>Immutable PROVED receipts consumed only by later activation work.</summary>
        public DbSet<RuntimeSeatRecoveryProofReceipt> RuntimeSeatRecoveryProofReceipts { get; set; }
        public DbSet<RuntimeSeatRecoveryActivationReceipt> RuntimeSeatRecoveryActivationReceipts { get; set; }
        /// <summary>Gets or sets versioned commercial ownership authority.</summary>
        public DbSet<RuntimeRecoveryCommercialOwnership> RuntimeRecoveryCommercialOwnerships { get; set; }
        /// <summary>Gets or sets provider-owned commercial subjects scoped by exact product UUID.</summary>
        public DbSet<RuntimeRecoveryCommercialSubject> RuntimeRecoveryCommercialSubjects { get; set; }
        /// <summary>Gets or sets frozen provider ownership-transition command terminals.</summary>
        public DbSet<RuntimeRecoveryCommercialOwnershipCommand> RuntimeRecoveryCommercialOwnershipCommands { get; set; }
        public DbSet<RuntimeSeatRecoveryRevokedClaimNonce> RuntimeSeatRecoveryRevokedClaimNonces { get; set; }
        /// <summary>Gets or sets exact recovery grant ownership bindings.</summary>
        public DbSet<RuntimeRecoveryGrantOwnership> RuntimeRecoveryGrantOwnerships { get; set; }
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
        /// <summary>Configures entity ownership and constraints, including additive paid-pass evidence, nullable decision lookup columns and exact-key deduplication; legacy null rows remain independent and no data is backfilled.</summary>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            ConfigurePersonalDayPass(modelBuilder);
            // The database trigger rotates this token for all writers, including older deployments.
            // It is not a global EF concurrency token: conditional callers explicitly compare it
            // under a row lock, leaving unrelated legacy update contracts unchanged.
            modelBuilder.Entity<License>().Property(l => l.AuthorityVersion)
                .HasDefaultValueSql("gen_random_uuid()")
                .ValueGeneratedOnAddOrUpdate();
            modelBuilder.Entity<Product>()
                .HasIndex(p => p.Name)
                .IsUnique();

            modelBuilder.Entity<License>()
                .HasIndex(l => l.LicenseKey)
                .IsUnique();

            // PostgreSQL requires an explicit unique principal key for the product-qualified
            // ownership FK; the global License.Id key alone cannot prove same-product coherence.
            modelBuilder.Entity<License>()
                .HasAlternateKey(l => new { l.ProductId, l.Id })
                .HasName("AK_Licenses_ProductId_Id");

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

            modelBuilder.Entity<PortalDeactivationOperation>(entity =>
            {
                entity.HasKey(operation => operation.RequestId);
                entity.Property(operation => operation.RequestId).ValueGeneratedNever();
                entity.Property(operation => operation.ClientId).HasMaxLength(64).IsRequired();
                entity.Property(operation => operation.RequestFingerprintSha256).HasMaxLength(64).IsRequired();
                entity.Property(operation => operation.HardwareId).HasMaxLength(200).IsRequired();
                entity.Property(operation => operation.Reason).HasMaxLength(32).IsRequired();
                entity.Property(operation => operation.Outcome).HasMaxLength(32).IsRequired();
                entity.HasIndex(operation => operation.LicenseId);
                entity.HasOne<License>()
                    .WithMany()
                    .HasForeignKey(operation => new { operation.ProductId, operation.LicenseId })
                    .HasPrincipalKey(license => new { license.ProductId, license.Id })
                    .OnDelete(DeleteBehavior.Restrict);
                entity.ToTable(table =>
                {
                    table.HasCheckConstraint(
                        "CK_PortalDeactivationOperations_RequestFingerprintSha256",
                        Database.IsNpgsql()
                            ? "length(\"RequestFingerprintSha256\") = 64 AND \"RequestFingerprintSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"RequestFingerprintSha256\") = 64");
                    table.HasCheckConstraint(
                        "CK_PortalDeactivationOperations_ClientId",
                        Database.IsNpgsql()
                            ? "\"ClientId\" ~ '^[a-z0-9][a-z0-9._-]{2,63}$'"
                            : "length(\"ClientId\") BETWEEN 3 AND 64");
                    table.HasCheckConstraint(
                        "CK_PortalDeactivationOperations_HardwareId",
                        Database.IsNpgsql()
                            ? "\"HardwareId\" ~ '^[A-Z0-9][A-Z0-9:_-]{4,199}$'"
                            : "length(\"HardwareId\") BETWEEN 5 AND 200");
                    table.HasCheckConstraint(
                        "CK_PortalDeactivationOperations_Reason",
                        "\"Reason\" IN ('settings_button', 'subscription_termination', 'uninstall')");
                    table.HasCheckConstraint(
                        "CK_PortalDeactivationOperations_Outcome",
                        "\"Outcome\" IN ('deactivated', 'already_inactive')");
                });
            });

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
                        "(\"IsActive\" AND \"DisabledAtUtc\" IS NULL AND \"DisabledReason\" IS NULL) OR " +
                        "(NOT \"IsActive\" AND \"DisabledAtUtc\" IS NOT NULL AND \"DisabledReason\" IS NOT NULL)");
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

            modelBuilder.Entity<LicenseRenewal>()
                .Property(r => r.RequestFingerprint)
                .HasMaxLength(64);

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .HasIndex(r => new { r.ProductId, r.Reference })
                .IsUnique();

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .HasIndex(r => r.Reference)
                .IsUnique()
                .HasFilter("\"AuthorityProvenance\" = 'PROVIDER_ADMIN_API_V1'")
                .HasDatabaseName("UX_LicenseProvisioningRequests_ProviderReference");

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .ToTable(table => table.HasCheckConstraint(
                    "CK_LicenseProvisioningRequests_CommercialAuthority",
                    "(\"CommercialSubjectId\" IS NULL AND \"AuthorityProvenance\" IS NULL) OR " +
                    "(\"CommercialSubjectId\" IS NOT NULL AND \"AuthorityProvenance\" = 'PROVIDER_ADMIN_API_V1')"));

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .Property(r => r.AuthorityProvenance)
                .HasColumnType("varchar(32)")
                .UseCollation("C");

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .HasOne(r => r.Product)
                .WithMany()
                .HasForeignKey(r => r.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<LicenseProvisioningRequest>()
                .HasOne(r => r.CommercialSubject)
                .WithMany()
                .HasForeignKey(r => new { r.ProductId, r.CommercialSubjectId })
                .HasPrincipalKey(subject => new { subject.ProductId, subject.Id })
                .OnDelete(DeleteBehavior.NoAction)
                .HasConstraintName("FK_LicenseProvisioningRequests_CommercialSubjects_ProductId_SubjectId");

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

            modelBuilder.Entity<TelemetryUpdatePreflightAlert>(alert =>
            {
                alert.HasOne(item => item.Product)
                    .WithMany()
                    .HasForeignKey(item => item.ProductId)
                    .OnDelete(DeleteBehavior.Cascade);
                alert.HasIndex(item => new { item.ProductId, item.SignatureSha256, item.WindowStartUtc })
                    .IsUnique();
                alert.HasIndex(item => new { item.ProductId, item.LastSeenUtc });
                alert.Property(item => item.SignatureSha256).HasMaxLength(64).IsFixedLength();
                alert.Property(item => item.SupportCode).HasMaxLength(16);
                alert.Property(item => item.CurrentVersion).HasMaxLength(64);
                alert.Property(item => item.LatestVersion).HasMaxLength(64);
                alert.Property(item => item.DecisionReason).HasMaxLength(64);
                alert.Property(item => item.SelectedChannel).HasMaxLength(64);
                alert.Property(item => item.ReconciliationOutcome).HasMaxLength(64);
                alert.Property(item => item.LastPresentationStage).HasMaxLength(16);
                alert.ToTable(table => table.HasCheckConstraint(
                    "CK_TelemetryUpdatePreflightAlerts_SignatureSha256",
                    Database.IsNpgsql()
                        ? "length(\"SignatureSha256\") = 64 AND \"SignatureSha256\" ~ '^[0-9a-f]{64}$'"
                        : "length(\"SignatureSha256\") = 64"));
            });

            modelBuilder.Entity<TelemetryIngestionRejection>()
                .HasIndex(r => new { r.TimestampUtc, r.ValidationCode });

            modelBuilder.Entity<RecoveryTelemetryRun>(run =>
            {
                run.HasIndex(item => new { item.ProductId, item.RecoveryRunId }).IsUnique();
                run.HasIndex(item => new { item.ProductId, item.UpdatedAtUtc });
                run.Property(item => item.LastStage).HasMaxLength(32);
                run.Property(item => item.LastOutcome).HasMaxLength(16);
                run.Property(item => item.Status).HasMaxLength(16);
                run.Property(item => item.ErrorCode).HasMaxLength(64);
                run.Property(item => item.SourceVersion).HasMaxLength(17);
                run.Property(item => item.TargetVersion).HasMaxLength(17);
                run.Property(item => item.VerifiedRestoredVersion).HasMaxLength(17);
                run.HasOne(item => item.Product).WithMany().HasForeignKey(item => item.ProductId).OnDelete(DeleteBehavior.Cascade);
                run.ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RecoveryTelemetryRuns_LastSequence", "\"LastSequence\" >= 1 AND \"LastSequence\" <= 32");
                    table.HasCheckConstraint("CK_RecoveryTelemetryRuns_Status", "\"Status\" IN ('incomplete', 'completed', 'failed', 'cancelled')");
                });
            });

            modelBuilder.Entity<RecoveryTelemetryEvent>(telemetryEvent =>
            {
                telemetryEvent.HasIndex(item => new { item.ProductId, item.EventId }).IsUnique();
                telemetryEvent.HasIndex(item => new { item.ProductId, item.RecoveryRunId, item.Sequence }).IsUnique();
                telemetryEvent.HasIndex(item => new { item.ProductId, item.RecoveryRunId })
                    .IsUnique().HasFilter("\"IsTerminal\" = true");
                telemetryEvent.HasIndex(item => new { item.ProductId, item.ReceivedAtUtc });
                telemetryEvent.Property(item => item.PayloadSha256).HasMaxLength(64).IsFixedLength();
                telemetryEvent.Property(item => item.ClientVersion).HasMaxLength(17);
                telemetryEvent.Property(item => item.ProcessRole).HasMaxLength(16);
                telemetryEvent.Property(item => item.Stage).HasMaxLength(32);
                telemetryEvent.Property(item => item.Outcome).HasMaxLength(16);
                telemetryEvent.Property(item => item.SourceVersion).HasMaxLength(17);
                telemetryEvent.Property(item => item.TargetVersion).HasMaxLength(17);
                telemetryEvent.Property(item => item.VerifiedRestoredVersion).HasMaxLength(17);
                telemetryEvent.Property(item => item.ErrorCode).HasMaxLength(64);
                telemetryEvent.HasOne(item => item.Run).WithMany(item => item.Events).HasForeignKey(item => item.RunId).OnDelete(DeleteBehavior.Cascade);
                telemetryEvent.ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RecoveryTelemetryEvents_Sequence", "\"Sequence\" >= 1 AND \"Sequence\" <= 32");
                    table.HasCheckConstraint("CK_RecoveryTelemetryEvents_PayloadSha256",
                        Database.IsNpgsql()
                            ? "length(\"PayloadSha256\") = 64 AND \"PayloadSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"PayloadSha256\") = 64");
                });
            });

            modelBuilder.Entity<RecoveryTelemetryRejection>(rejection =>
            {
                rejection.HasIndex(item => new { item.ProductId, item.ReceivedAtUtc });
                rejection.HasIndex(item => new { item.ProductId, item.RecoveryRunId, item.ReceivedAtUtc });
                rejection.Property(item => item.Code).HasMaxLength(32);
                rejection.HasOne(item => item.Product).WithMany().HasForeignKey(item => item.ProductId).OnDelete(DeleteBehavior.Cascade);
            });

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

            // Nullable additive indexes preserve legacy rows. Exact digest equality deduplicates
            // decision writes; operation lookup stays scoped to the owning licence, not telemetry.
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => h.DecisionKey).IsUnique();
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => h.LicenseId);
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => new { h.LicenseId, h.DecisionOperationId });
            // Exact nullable metadata supports targeted reads without scanning raw Details or reconstructing old events.
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => h.DecisionOperationId);
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => h.DecisionCorrelationId);
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => h.DecisionSubmittedHardwareId);
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => h.DecisionResolvedHardwareId);
            modelBuilder.Entity<LicenseHistory>().HasIndex(h => h.DecisionCorrelatedHardwareId);

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

            // TKT-001277 lot 2a: one row per product, canonical hardware identifier and evidence digest.
            // All three keys are server-validated canonical ASCII values compared ordinally.
            modelBuilder.Entity<MachineEvidenceObservation>()
                .HasIndex(o => new { o.ProductId, o.HardwareId, o.EvidenceSha256 })
                .IsUnique();
            modelBuilder.Entity<MachineEvidenceObservation>()
                .HasIndex(o => o.SystemUuidCanonical);

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
                        "\"Reason\" IN ('account_closed', 'fraud_flagged', 'grant_revoked', 'security_lockdown', 'seat_released')");
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
                    "\"Source\" IN ('issue_v2', 'issue_v3', 'issue_v4', 'finalize_v1')"));

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
                .HasOne<RuntimeEnrollmentAuthorityGeneration>().WithMany()
                .HasForeignKey(entitlement => new { entitlement.AuthorityLineageId, entitlement.AuthorityGenerationId })
                .HasPrincipalKey(generation => new { generation.AuthorityLineageId, generation.AuthorityGenerationId })
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("FK_Tkt000686_DistributionEntitlements_REAuthorityGeneration");
            if (Database.IsNpgsql())
            {
                modelBuilder.Entity<DistributionEntitlement>()
                    .Property(entitlement => entitlement.ArtifactSetDigestSha256)
                    .UseCollation("C");
            }
            modelBuilder.Entity<DistributionEntitlement>()
                .ToTable(table =>
                {
                    table.HasCheckConstraint("CK_DistributionEntitlements_ContractVersion", "\"ContractVersion\" IN (3, 4)");
                    table.HasCheckConstraint("CK_DistributionEntitlements_State", "\"State\" IN ('issued', 'finalized', 'expired', 'revoked')");
                    table.HasCheckConstraint("CK_DistributionEntitlements_Times", "\"IssuedAtUtc\" < \"ExpiresAtUtc\"");
                    table.HasCheckConstraint("CK_DistributionEntitlements_Digests", "length(\"GrantRefDigestSha256\") = 64 AND length(\"SubjectRefDigestSha256\") = 64");
                    table.HasCheckConstraint("CK_Tkt000686_DistributionEntitlements_AuthorityShape", "(\"ContractVersion\" = 3 AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ArtifactSetDigestSha256\" IS NULL) OR (\"ContractVersion\" = 4 AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ArtifactSetDigestSha256\" IS NOT NULL)");
                    table.HasCheckConstraint("CK_Tkt000686_DistributionEntitlements_ArtifactDigest",
                        Database.IsNpgsql()
                            ? "\"ArtifactSetDigestSha256\" IS NULL OR (octet_length(\"ArtifactSetDigestSha256\") = 64 AND \"ArtifactSetDigestSha256\" ~ '^[0-9a-f]{64}$')"
                            : "\"ArtifactSetDigestSha256\" IS NULL OR length(\"ArtifactSetDigestSha256\") = 64");
                });

            modelBuilder.Entity<RuntimeDistributionHardwareDecision>()
                .HasIndex(decision => new { decision.ClientId, decision.RequestId })
                .IsUnique();
            modelBuilder.Entity<RuntimeDistributionHardwareDecision>()
                .HasIndex(decision => new { decision.ProductId, decision.CreatedAtUtc });
            modelBuilder.Entity<RuntimeDistributionHardwareDecision>()
                .HasIndex(decision => new { decision.ProductId, decision.LicenseId, decision.CreatedAtUtc });
            modelBuilder.Entity<RuntimeDistributionHardwareDecision>()
                .HasIndex(decision => new { decision.ProductId, decision.HardwareIdHash, decision.CreatedAtUtc });
            modelBuilder.Entity<RuntimeDistributionHardwareDecision>()
                .HasOne<Product>().WithMany().HasForeignKey(decision => decision.ProductId)
                .OnDelete(DeleteBehavior.Restrict);
            if (Database.IsNpgsql())
            {
                modelBuilder.Entity<RuntimeDistributionHardwareDecision>().ToTable(table =>
                {
                    table.HasCheckConstraint("CK_RuntimeDistributionHardwareDecisions_Digests",
                        "\"PayloadDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"GrantRefDigestSha256\" ~ '^[0-9a-f]{64}$' AND (\"HardwareIdHash\" IS NULL OR \"HardwareIdHash\" ~ '^[0-9a-f]{64}$') AND (\"InstallationIdHash\" IS NULL OR \"InstallationIdHash\" ~ '^[0-9a-f]{64}$')");
                    table.HasCheckConstraint("CK_RuntimeDistributionHardwareDecisions_Outcome",
                        "\"Outcome\" IN ('accepted', 'auto-unbanned', 'refused')");
                    table.HasCheckConstraint("CK_RuntimeDistributionHardwareDecisions_AuthorityMode",
                        "\"AuthorityMode\" IN ('server-derived', 'known-enrollment', 'digest-revalidation', 'alias-recognized')");
                    table.HasCheckConstraint("CK_RuntimeDistributionHardwareDecisions_AutoUnbanCount",
                        "\"AutoUnbannedCount\" >= 0");
                    table.HasCheckConstraint("CK_RuntimeDistributionHardwareDecisions_AttemptCount",
                        "\"AttemptCount\" >= 1");
                });
            }

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

            modelBuilder.Entity<EnrollmentLicenseAssignment>(assignment =>
            {
                assignment.HasOne<RuntimeEnrollment>().WithMany()
                    .HasForeignKey(item => item.EnrollmentId).OnDelete(DeleteBehavior.Restrict);
                assignment.HasOne<License>().WithMany()
                    .HasForeignKey(item => item.LicenseId).OnDelete(DeleteBehavior.Restrict);
                assignment.HasOne<LicenseSeat>().WithMany()
                    .HasForeignKey(item => new { item.LicenseSeatId, item.LicenseId })
                    .HasPrincipalKey(seat => new { seat.Id, seat.LicenseId })
                    .OnDelete(DeleteBehavior.Restrict);
                assignment.HasIndex(item => new { item.EnrollmentId, item.Revision }).IsUnique();
                assignment.HasIndex(item => item.EnrollmentId)
                    .HasFilter("\"State\" = 'ACTIVE'").IsUnique();
                assignment.HasIndex(item => item.LicenseSeatId)
                    .HasFilter("\"State\" = 'ACTIVE'").IsUnique();
                assignment.HasIndex(item => new { item.LicenseSeatId, item.LicenseId });
                assignment.HasIndex(item => new { item.LicenseId, item.State });
                assignment.ToTable(table =>
                {
                    table.HasCheckConstraint("CK_EnrollmentLicenseAssignments_Revision", "\"Revision\" >= 1");
                    table.HasCheckConstraint("CK_EnrollmentLicenseAssignments_StateAndTimes",
                        "(\"State\" = 'ACTIVE' AND \"EndedAtUtc\" IS NULL AND \"EndReason\" IS NULL) OR (\"State\" = 'ENDED' AND \"EndedAtUtc\" IS NOT NULL AND \"EndReason\" IS NOT NULL AND \"EndedAtUtc\" >= \"ActivatedAtUtc\")");
                    table.HasCheckConstraint("CK_EnrollmentLicenseAssignments_EndReason",
                        "\"EndReason\" IS NULL OR length(\"EndReason\") BETWEEN 1 AND 64");
                });
            });

            modelBuilder.Entity<AssignmentEnforcementSetting>(setting =>
            {
                setting.Property(item => item.Id).ValueGeneratedNever();
                setting.ToTable(table =>
                {
                    table.HasCheckConstraint("CK_AssignmentEnforcementSettings_SingleRow", "\"Id\" = 1");
                    table.HasCheckConstraint("CK_AssignmentEnforcementSettings_Mode", "\"Mode\" IN ('open', 'closed')");
                });
                setting.HasData(new AssignmentEnforcementSetting
                {
                    Id = 1,
                    Mode = AssignmentEnforcementSetting.Open,
                    UpdatedAtUtc = new DateTime(2026, 9, 29, 0, 0, 0, DateTimeKind.Utc),
                    UpdatedBy = "migration"
                });
            });

            modelBuilder.Entity<AssignmentEnforcementEvent>(enforcementEvent =>
            {
                enforcementEvent.HasIndex(item => item.ObservedAtUtc);
                enforcementEvent.HasIndex(item => item.AlertedAtUtc);
                enforcementEvent.HasIndex(item => item.EnrollmentId);
                enforcementEvent.ToTable(table =>
                {
                    table.HasCheckConstraint("CK_AssignmentEnforcementEvents_Source", "\"Source\" IN ('database', 'application')");
                    table.HasCheckConstraint("CK_AssignmentEnforcementEvents_CaseNumber", "\"CaseNumber\" IS NULL OR \"CaseNumber\" BETWEEN 1 AND 8");
                });
            });

            modelBuilder.Entity<EnrollmentLicenseAssignmentQuarantine>(quarantine =>
            {
                quarantine.HasOne<RuntimeEnrollment>().WithOne()
                    .HasForeignKey<EnrollmentLicenseAssignmentQuarantine>(item => item.EnrollmentId)
                    .OnDelete(DeleteBehavior.Restrict);
                quarantine.HasIndex(item => item.Reason);
                quarantine.ToTable(table => table.HasCheckConstraint(
                    "CK_EnrollmentLicenseAssignmentQuarantines_Reason",
                    "\"Reason\" IN ('binding_missing', 'binding_mismatch', 'seat_missing', 'seat_mismatch', 'license_missing', 'license_mismatch', 'live_state_mismatch', 'live_seat_ambiguous', 'terminal_time_invalid')"));
            });

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

            // Durable accepted lineage is append-only and cannot be cascade-deleted with credentials or keys.
            modelBuilder.Entity<HardwareAuthorityMigrationReceipt>(entity =>
            {
                entity.HasKey(receipt => receipt.Id);
                entity.HasIndex(receipt => new { receipt.EnrollmentId, receipt.RequestId }).IsUnique();
                entity.HasIndex(receipt => new { receipt.EnrollmentId, receipt.Jti }).IsUnique();
                entity.HasOne<RuntimeEnrollment>().WithMany().HasForeignKey(receipt => receipt.EnrollmentId)
                    .OnDelete(DeleteBehavior.Restrict);
                entity.HasOne<HardwareAuthorityMigrationReceipt>().WithMany()
                    .HasForeignKey(receipt => receipt.ParentReceiptId).OnDelete(DeleteBehavior.Restrict);
                entity.HasOne<RuntimeEnrollmentKeyRegistry>().WithMany()
                    .HasForeignKey(receipt => new { receipt.KeyPurpose, receipt.KeyId })
                    .HasPrincipalKey(key => new { key.Purpose, key.KeyId }).OnDelete(DeleteBehavior.Restrict);
                entity.ToTable(table => table.HasCheckConstraint("CK_MigrationReceipt_Envelope",
                    "\"KeyPurpose\" = 'encryption' AND \"EnrollmentEpoch\" >= 1 AND length(\"Ciphertext\") > 0"));
            });
            modelBuilder.Entity<HardwareAuthorityAlias>().HasOne<HardwareAuthorityMigrationReceipt>().WithMany()
                .HasForeignKey(alias => alias.MigrationReceiptId).OnDelete(DeleteBehavior.Restrict);

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

            // TKT-001177: security lock reports, one-use proof nonces and the per-cause buffer zone.
            modelBuilder.Entity<SecurityLockReport>(entity =>
            {
                entity.HasIndex(report => new { report.EnrollmentId, report.LockId }).IsUnique();
                entity.HasIndex(report => new { report.State, report.LastReportedUtc });
                entity.HasIndex(report => report.HardwareId);
                entity.HasOne(report => report.Enrollment)
                    .WithMany()
                    .HasForeignKey(report => report.EnrollmentId)
                    .OnDelete(DeleteBehavior.Cascade);
                entity.HasOne<EnrollmentLicenseAssignment>().WithMany()
                    .HasForeignKey(report => report.LinkAssignmentId).OnDelete(DeleteBehavior.Restrict);
                entity.HasOne<LicenseSeat>().WithMany()
                    .HasForeignKey(report => report.LinkLicenseSeatId).OnDelete(DeleteBehavior.Restrict);
                entity.HasOne<HardwareAuthorityAlias>().WithMany()
                    .HasForeignKey(report => report.LinkAliasId).OnDelete(DeleteBehavior.Restrict);
                entity.ToTable(table =>
                {
                    // PostgreSQL repeats this shape rule in the hand-written trigger migration.
                    table.HasCheckConstraint("CK_SecurityLockReports_LinkProof", """
                        ("LinkStatus" = 'UNKNOWN_LEGACY' AND "LinkVerifiedAtUtc" IS NULL AND "LinkAssignmentId" IS NULL AND "LinkLicenseSeatId" IS NULL AND "LinkAliasId" IS NULL AND "LinkReasonCode" = 'legacy_unknown')
                        OR ("LinkStatus" = 'UNLINKED' AND "LinkVerifiedAtUtc" IS NOT NULL AND "LinkAssignmentId" IS NULL AND "LinkLicenseSeatId" IS NULL AND "LinkAliasId" IS NULL AND "LinkReasonCode" IN ('enrollment_mismatch','assignment_missing','assignment_ambiguous','assignment_relation_missing','hardware_unlinked','alias_ambiguous'))
                        OR ("LinkStatus" = 'VERIFIED_SEAT' AND "LinkVerifiedAtUtc" IS NOT NULL AND "LinkAssignmentId" IS NOT NULL AND "LinkLicenseSeatId" IS NOT NULL AND "LinkAliasId" IS NULL AND "LinkReasonCode" IS NULL)
                        OR ("LinkStatus" = 'VERIFIED_ALIAS' AND "LinkVerifiedAtUtc" IS NOT NULL AND "LinkAssignmentId" IS NOT NULL AND "LinkLicenseSeatId" IS NOT NULL AND "LinkAliasId" IS NOT NULL AND "LinkReasonCode" IS NULL)
                        """);
                    table.HasCheckConstraint("CK_SecurityLockReports_BanDecision",
                        "\"State\" <> 'BANNED' OR \"AdminDecision\" IS DISTINCT FROM 'RELEASE'");
                    table.HasCheckConstraint("CK_SecurityLockReports_Level", "\"Level\" BETWEEN 0 AND 5");
                    table.HasCheckConstraint("CK_SecurityLockReports_State",
                        "\"State\" IN ('OPEN', 'RELEASED', 'BANNED')");
                    table.HasCheckConstraint("CK_SecurityLockReports_LastVerdict",
                        "\"LastVerdict\" IN ('MAINTAIN', 'RELEASE', 'BAN')");
                    table.HasCheckConstraint("CK_SecurityLockReports_AdminDecision",
                        "\"AdminDecision\" IS NULL OR \"AdminDecision\" IN ('RELEASE', 'BAN')");
                    table.HasCheckConstraint("CK_SecurityLockReports_Modes",
                        "\"ClientMode\" IN ('NOT_APPLICABLE', 'SHADOW', 'REVIEW', 'ENFORCE') AND \"EffectiveMode\" IN ('NOT_APPLICABLE', 'SHADOW', 'REVIEW', 'ENFORCE')");
                    table.HasCheckConstraint("CK_SecurityLockReports_CanonicalIds",
                        Database.IsNpgsql()
                            ? "\"LockId\" ~ '^[0-9a-f]{32}$' AND \"EvidenceDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"Cause\" ~ '^[A-Z][A-Z0-9_]*$' AND \"HardwareId\" ~ '^[A-Z0-9_.-]+$'"
                            : "length(\"LockId\") = 32 AND length(\"EvidenceDigestSha256\") = 64");
                });
            });


            modelBuilder.Entity<SecurityLockReportNonce>(entity =>
            {
                entity.HasKey(nonce => new { nonce.EnrollmentId, nonce.Jti });
                entity.HasIndex(nonce => nonce.ExpiresAtUtc);
                entity.HasOne<RuntimeEnrollment>()
                    .WithMany()
                    .HasForeignKey(nonce => nonce.EnrollmentId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<SecurityLockEnforcementPolicy>(entity =>
            {
                entity.HasKey(policy => new { policy.ProductId, policy.Cause });
                entity.ToTable(table => table.HasCheckConstraint("CK_SecurityLockEnforcementPolicies_Mode",
                    "\"Mode\" IN ('SHADOW', 'REVIEW', 'ENFORCE')"));
            });

            modelBuilder.Entity<SecurityLockAlertDelivery>(entity =>
            {
                entity.HasIndex(delivery => new { delivery.State, delivery.NextAttemptUtc });
                entity.HasIndex(delivery => new
                    { delivery.SecurityLockReportId, delivery.Trigger, delivery.Channel, delivery.TargetDigestSha256 }).IsUnique();
                entity.HasOne(delivery => delivery.SecurityLockReport)
                    .WithMany()
                    .HasForeignKey(delivery => delivery.SecurityLockReportId)
                    .OnDelete(DeleteBehavior.Cascade);
                entity.ToTable(table =>
                {
                    table.HasCheckConstraint("CK_SecurityLockAlertDeliveries_Channel",
                        "\"Channel\" IN ('EMAIL', 'WEBHOOK')");
                    table.HasCheckConstraint("CK_SecurityLockAlertDeliveries_State",
                        "\"State\" IN ('PENDING', 'PROCESSING', 'SENT', 'SKIPPED', 'FAILED', 'UNKNOWN')");
                    table.HasCheckConstraint("CK_SecurityLockAlertDeliveries_Attempts", "\"AttemptCount\" >= 0");
                    table.HasCheckConstraint("CK_SecurityLockAlertDeliveries_TargetDigest",
                        Database.IsNpgsql()
                            ? "\"TargetDigestSha256\" ~ '^[0-9a-f]{64}$'"
                            : "length(\"TargetDigestSha256\") = 64");
                });
            });

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

            modelBuilder.Entity<RuntimeEnrollmentAuthorityLineage>(entity =>
            {
                entity.ToTable("RuntimeEnrollmentAuthorityLineages", table =>
                {
                    table.HasCheckConstraint("CK_REAuthorityLineages_Provider",
                        "octet_length(\"Provider\") BETWEEN 1 AND 64 AND \"Provider\" ~ '^[a-z0-9][a-z0-9._-]{0,63}$'");
                    table.HasCheckConstraint("CK_REAuthorityLineages_GrantRef",
                        "octet_length(\"ProviderGrantRef\") BETWEEN 1 AND 1536 AND \"ProviderGrantRefScalarCount\" BETWEEN 1 AND 256");
                    table.HasCheckConstraint("CK_REAuthorityLineages_HeadSequence", "\"HeadSequence\" >= 0");
                });
                entity.HasKey(item => item.AuthorityLineageId).HasName("PK_REAuthorityLineages");
                entity.Property(item => item.Provider).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ProviderGrantRef).HasColumnType("varchar(1536)").UseCollation("C");
                entity.HasIndex(item => new
                    { item.Provider, item.ProductId, item.ProviderGrantRef, item.LicenseSeatId })
                    .IsUnique().HasDatabaseName("UX_REAuthorityLineages_Provider_ProductId_GrantRef_SeatId");
                entity.HasOne(item => item.HeadGeneration)
                    .WithMany()
                    .HasForeignKey(item => new { item.AuthorityLineageId, item.HeadGenerationId, item.HeadSequence })
                    .HasPrincipalKey(item => new { item.AuthorityLineageId, item.AuthorityGenerationId, item.Sequence })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_REAuthorityLineages_REAuthorityGenerations_Head");
            });

            modelBuilder.Entity<RuntimeEnrollmentAuthorityGeneration>(entity =>
            {
                entity.ToTable("RuntimeEnrollmentAuthorityGenerations", table =>
                {
                    table.HasCheckConstraint("CK_REAuthorityGenerations_Sequence",
                        "(\"Sequence\" = 0 AND \"PreviousGenerationId\" IS NULL) OR (\"Sequence\" > 0 AND \"PreviousGenerationId\" IS NOT NULL)");
                    table.HasCheckConstraint("CK_REAuthorityGenerations_PayloadBytes",
                        "octet_length(\"CanonicalPayloadUtf8\") BETWEEN 1 AND 2895");
                    table.HasCheckConstraint("CK_REAuthorityGenerations_StatementBytes",
                        "octet_length(\"SignedStatementUtf8\") BETWEEN 1 AND 3569");
                    table.HasCheckConstraint("CK_RuntimeEnrollmentAuthorityGenerations_AuthorityDigest",
                        "octet_length(\"AuthorityDigest\") = 64 AND \"AuthorityDigest\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_REAuthorityGenerations_Algorithm", "\"SignatureAlgorithm\" = 'PS256'");
                    table.HasCheckConstraint("CK_REAuthorityGenerations_KeyId",
                        "octet_length(\"SignatureKeyId\") BETWEEN 1 AND 128 AND \"SignatureKeyId\" ~ '^[a-z0-9][a-z0-9._-]{0,127}$'");
                    table.HasCheckConstraint("CK_REAuthorityGenerations_Signature",
                        "octet_length(\"SignatureValue\") = 342 AND \"SignatureValue\" !~ '[^A-Za-z0-9_-]'");
                });
                entity.HasKey(item => item.AuthorityGenerationId).HasName("PK_REAuthorityGenerations");
                entity.HasAlternateKey(item => new { item.AuthorityLineageId, item.AuthorityGenerationId })
                    .HasName("AK_REAuthorityGenerations_LineageId_GenerationId");
                entity.HasAlternateKey(item => new { item.AuthorityLineageId, item.AuthorityGenerationId, item.Sequence })
                    .HasName("AK_REAuthorityGenerations_LineageId_GenerationId_Sequence");
                entity.HasAlternateKey(item => new { item.AuthorityGenerationId, item.RequestId })
                    .HasName("AK_REAuthorityGenerations_GenerationId_RequestId");
                entity.HasAlternateKey(item => new
                    { item.AuthorityLineageId, item.AuthorityGenerationId, item.RequestId })
                    .HasName("AK_REAuthorityGenerations_LineageId_GenerationId_RequestId");
                entity.Property(item => item.CanonicalPayloadUtf8).HasColumnType("bytea");
                entity.Property(item => item.SignedStatementUtf8).HasColumnType("bytea");
                entity.Property(item => item.AuthorityDigest).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.SignatureAlgorithm).HasColumnType("varchar(16)").UseCollation("C");
                entity.Property(item => item.SignatureKeyId).HasColumnType("varchar(128)").UseCollation("C");
                entity.Property(item => item.SignatureValue).HasColumnType("varchar(342)").UseCollation("C");
                entity.HasIndex(item => new { item.AuthorityLineageId, item.Sequence })
                    .IsUnique().HasDatabaseName("UX_REAuthorityGenerations_LineageId_Sequence");
                entity.HasIndex(item => new { item.AuthorityLineageId, item.PreviousGenerationId })
                    .IsUnique().HasFilter("\"PreviousGenerationId\" IS NOT NULL")
                    .HasDatabaseName("UX_REAuthorityGenerations_LineageId_PredecessorId");
                entity.HasOne(item => item.Lineage)
                    .WithMany(item => item.Generations)
                    .HasForeignKey(item => item.AuthorityLineageId)
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_REAuthorityGenerations_REAuthorityLineages_Lineage");
                entity.HasOne(item => item.PreviousGeneration)
                    .WithMany()
                    .HasForeignKey(item => new { item.AuthorityLineageId, item.PreviousGenerationId })
                    .HasPrincipalKey(item => new { item.AuthorityLineageId, item.AuthorityGenerationId })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_REAuthorityGenerations_REAuthorityGenerations_Predecessor");
            });

            modelBuilder.Entity<RuntimeAuthorityKeyRegistrySnapshot>(entity =>
            {
                entity.ToTable("RuntimeAuthorityKeyRegistrySnapshots", table =>
                {
                    table.HasCheckConstraint("CK_RAKRSnapshots_RegistryId",
                        @"""RegistryId"" = 'runtime-enrollment-authority-generation-v2'");
                    table.HasCheckConstraint("CK_RAKRSnapshots_Version", @"""SnapshotVersion"" > 0");
                    table.HasCheckConstraint("CK_RAKRSnapshots_Digests",
                        @"""MetadataDigestSha256"" ~ '^[0-9a-f]{64}$' AND ""RegistryAuthenticationInputDigestSha256"" ~ '^[0-9a-f]{64}$' AND ""ExactResponseBodySha256"" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RAKRSnapshots_State",
                        @"""PublicationState"" IN ('current','superseded','revoked')");
                    table.HasCheckConstraint("CK_RAKRSnapshots_ObservedAtUtc",
                        @"""ObservedAtUtc"" ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}\+00:00$'");
                    table.HasCheckConstraint("CK_RAKRSnapshots_Revocation",
                        @"(""PublicationState"" = 'revoked' AND ""RevokedAtUtc"" IS NOT NULL) OR (""PublicationState"" <> 'revoked' AND ""RevokedAtUtc"" IS NULL)");
                    table.HasCheckConstraint("CK_RAKRSnapshots_ResponseBytes",
                        @"octet_length(""ExactResponseBody"") BETWEEN 1 AND 16384");
                    table.HasCheckConstraint("CK_RAKRSnapshots_Signature",
                        @"length(""RegistrySignatureBase64Url"") = 342 AND ""RegistrySignatureBase64Url"" !~ '[^A-Za-z0-9_-]'");
                });
                entity.HasKey(item => item.SnapshotId);
                entity.Property(item => item.SnapshotId).HasColumnType("varchar(128)").UseCollation("C");
                entity.Property(item => item.RegistryId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.MetadataDigestSha256).HasColumnType("char(64)").UseCollation("C");
                entity.Property(item => item.RegistryAuthenticationInputDigestSha256).HasColumnType("char(64)").UseCollation("C");
                entity.Property(item => item.ObservedAtUtc).HasColumnType("varchar(33)").UseCollation("C");
                entity.Property(item => item.PublicationState).HasColumnType("varchar(16)").UseCollation("C");
                entity.Property(item => item.ExactResponseBodySha256).HasColumnType("char(64)").UseCollation("C");
                entity.Property(item => item.RegistrySignatureBase64Url).HasColumnType("varchar(342)").UseCollation("C");
                entity.HasAlternateKey(item => new
                {
                    item.RegistryId,
                    item.SnapshotId,
                    item.SnapshotVersion,
                    item.MetadataDigestSha256,
                    item.RegistryAuthenticationInputDigestSha256,
                    item.PublicationState
                }).HasName("AK_RAKRSnapshots_Registry_Snapshot_Version_Metadata_Authentication_State");
                entity.HasAlternateKey(item => new { item.SnapshotId, item.ExactResponseBodySha256 })
                    .HasName("AK_RAKRSnapshots_Snapshot_ResponseBodyDigest");
                entity.HasIndex(item => new { item.RegistryId, item.SnapshotVersion }).IsUnique();
                entity.HasIndex(item => new { item.RegistryId, item.MetadataDigestSha256 }).IsUnique();
                entity.HasIndex(item => item.RegistryId).IsUnique().HasFilter(@"""PublicationState"" = 'current'")
                    .HasDatabaseName("UX_RAKRSnapshots_OneCurrentPerRegistry");
            });

            modelBuilder.Entity<RuntimeAuthorityKeyRegistryHead>(entity =>
            {
                entity.ToTable("RuntimeAuthorityKeyRegistryHeads", table =>
                {
                    table.HasCheckConstraint("CK_RAKRHeads_RegistryId",
                        @"""RegistryId"" = 'runtime-enrollment-authority-generation-v2'");
                    table.HasCheckConstraint("CK_RAKRHeads_Version", @"""CurrentSnapshotVersion"" > 0");
                    table.HasCheckConstraint("CK_RAKRHeads_Digests",
                        @"""CurrentMetadataDigestSha256"" ~ '^[0-9a-f]{64}$' AND ""CurrentRegistryAuthenticationInputDigestSha256"" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RAKRHeads_State", @"""CurrentPublicationState"" = 'current'");
                });
                entity.HasKey(item => item.RegistryId);
                entity.Property(item => item.RegistryId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.CurrentSnapshotId).HasColumnType("varchar(128)").UseCollation("C");
                entity.Property(item => item.CurrentMetadataDigestSha256).HasColumnType("char(64)").UseCollation("C");
                entity.Property(item => item.CurrentRegistryAuthenticationInputDigestSha256).HasColumnType("char(64)").UseCollation("C");
                entity.Property(item => item.CurrentPublicationState).HasColumnType("varchar(16)").UseCollation("C");
                entity.HasOne<RuntimeAuthorityKeyRegistrySnapshot>().WithMany()
                    .HasForeignKey(item => new
                    {
                        item.RegistryId,
                        item.CurrentSnapshotId,
                        item.CurrentSnapshotVersion,
                        item.CurrentMetadataDigestSha256,
                        item.CurrentRegistryAuthenticationInputDigestSha256,
                        item.CurrentPublicationState
                    })
                    .HasPrincipalKey(item => new
                    {
                        item.RegistryId,
                        item.SnapshotId,
                        item.SnapshotVersion,
                        item.MetadataDigestSha256,
                        item.RegistryAuthenticationInputDigestSha256,
                        item.PublicationState
                    })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RAKRHeads_RAKRSnapshots_CurrentTuple");
            });

            modelBuilder.Entity<RuntimeAuthorityKeyRegistryReadback>(entity =>
            {
                entity.ToTable("RuntimeAuthorityKeyRegistryReadbacks", table =>
                {
                    table.HasCheckConstraint("CK_RAKRReadbacks_ClientId",
                        @"length(""ClientId"") BETWEEN 1 AND 64");
                    table.HasCheckConstraint("CK_RAKRReadbacks_Digests",
                        @"""RequestDigestSha256"" ~ '^[0-9a-f]{64}$' AND ""ExactResponseBodySha256"" ~ '^[0-9a-f]{64}$'");
                });
                entity.HasKey(item => new { item.ClientId, item.RequestId });
                entity.Property(item => item.ClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.RequestDigestSha256).HasColumnType("char(64)").UseCollation("C");
                entity.Property(item => item.SnapshotId).HasColumnType("varchar(128)").UseCollation("C");
                entity.Property(item => item.ExactResponseBodySha256).HasColumnType("char(64)").UseCollation("C");
                entity.HasOne<RuntimeAuthorityKeyRegistrySnapshot>().WithMany()
                    .HasForeignKey(item => new { item.SnapshotId, item.ExactResponseBodySha256 })
                    .HasPrincipalKey(item => new { item.SnapshotId, item.ExactResponseBodySha256 })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RAKRReadbacks_RAKRSnapshots_Body");
            });

            modelBuilder.Entity<RuntimeEnrollmentAuthorityRequest>(entity =>
            {
                entity.ToTable("RuntimeEnrollmentAuthorityRequests", table =>
                {
                    table.HasCheckConstraint("CK_RuntimeEnrollmentAuthorityRequests_RequestDigest",
                        "octet_length(\"RequestDigest\") = 64 AND \"RequestDigest\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_REAuthorityRequests_ResultCode", "\"ResultCode\" IN ('ACCEPTED', 'REFUSED')");
                    table.HasCheckConstraint("CK_REAuthorityRequests_TerminalShape", "(\"ResultCode\" = 'ACCEPTED' AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"ResultCode\" = 'REFUSED' AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400, 403, 409, 503))");
                    table.HasCheckConstraint("CK_REAuthorityRequests_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.HasCheckConstraint("CK_REAuthorityRequests_Chronology", "\"CreatedAtUtc\" <= \"CompletedAtUtc\"");
                    table.HasCheckConstraint("CK_REAuthorityRequests_ErrorCode", "\"ErrorCode\" IS NULL OR (octet_length(\"ErrorCode\") BETWEEN 1 AND 64 AND \"ErrorCode\" ~ '^[A-Z0-9_]+$')");
                    table.HasCheckConstraint("CK_REAuthorityRequests_HttpStatus", "\"HttpStatusCode\" IN (200, 400, 403, 409, 503)");
                });
                entity.HasKey(item => item.RequestId).HasName("PK_REAuthorityRequests");
                entity.Property(item => item.RequestDigest).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ResultCode).HasColumnType("varchar(8)").UseCollation("C");
                entity.Property(item => item.ErrorCode).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ExactResponseUtf8).HasColumnType("bytea");
                entity.HasIndex(item => new { item.AuthorityGenerationId, item.RequestId })
                    .HasDatabaseName("IX_REAuthorityRequests_GenerationId_RequestId");
                entity.HasIndex(item => new
                    { item.AuthorityLineageId, item.AuthorityGenerationId, item.RequestId })
                    .HasDatabaseName("IX_REAuthorityRequests_LineageId_GenerationId_RequestId");
                entity.HasIndex(item => new
                    { item.RequestId, item.AuthorityLineageId, item.AuthorityGenerationId })
                    .IsUnique().HasDatabaseName("UX_REAuthorityRequests_RequestId_LineageId_GenerationId");
                entity.HasOne(item => item.Generation)
                    .WithMany()
                    .HasForeignKey(item =>
                        new { item.AuthorityLineageId, item.AuthorityGenerationId, item.RequestId })
                    .HasPrincipalKey(item =>
                        new { item.AuthorityLineageId, item.AuthorityGenerationId, item.RequestId })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_REAuthorityRequests_REAuthorityGenerations_Result");
            });

            modelBuilder.Entity<RuntimeEnrollmentAuthorityAttempt>(entity =>
            {
                entity.ToTable("RuntimeEnrollmentAuthorityAttempts", table =>
                {
                    table.HasCheckConstraint("CK_REAuthorityAttempts_RequestDigest", "octet_length(\"RequestDigest\") = 64 AND \"RequestDigest\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_REAuthorityAttempts_Status", "\"Status\" IN ('ACCEPTED', 'REFUSED')");
                    table.HasCheckConstraint("CK_REAuthorityAttempts_TerminalShape", "(\"Status\" = 'ACCEPTED' AND \"AuthorityLineageId\" IS NOT NULL AND \"AuthorityGenerationId\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"Status\" = 'REFUSED' AND \"AuthorityLineageId\" IS NULL AND \"AuthorityGenerationId\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400, 403, 409, 503))");
                    table.HasCheckConstraint("CK_REAuthorityAttempts_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.HasCheckConstraint("CK_REAuthorityAttempts_Chronology", "\"CreatedAtUtc\" <= \"CompletedAtUtc\"");
                    table.HasCheckConstraint("CK_REAuthorityAttempts_ErrorCode", "\"ErrorCode\" IS NULL OR (octet_length(\"ErrorCode\") BETWEEN 1 AND 64 AND \"ErrorCode\" ~ '^[A-Z0-9_]+$')");
                    table.HasCheckConstraint("CK_REAuthorityAttempts_HttpStatus", "\"HttpStatusCode\" IN (200, 400, 403, 409, 503)");
                });
                entity.HasKey(item => item.AttemptId).HasName("PK_REAuthorityAttempts");
                entity.Property(item => item.RequestDigest).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.Status).HasColumnType("varchar(8)").UseCollation("C");
                entity.Property(item => item.ErrorCode).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ExactResponseUtf8).HasColumnType("bytea");
                entity.HasIndex(item => item.RequestId).HasDatabaseName("IX_REAuthorityAttempts_RequestId");
                entity.HasIndex(item => new
                    { item.RequestId, item.AuthorityLineageId, item.AuthorityGenerationId })
                    .HasDatabaseName("IX_REAuthorityAttempts_RequestId_LineageId_GenerationId");
                entity.HasAnnotation("RuntimeEnrollment:CompositeRequestResultForeignKey",
                    "RequestId,AuthorityLineageId,AuthorityGenerationId|NO ACTION");
                entity.HasOne(item => item.Request).WithMany().HasForeignKey(item => item.RequestId)
                    .OnDelete(DeleteBehavior.NoAction).HasConstraintName("FK_REAuthorityAttempts_REAuthorityRequests_Request");
            });

            modelBuilder.Entity<RuntimeSeatRecoveryAuthorization>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryAuthorizations", table =>
                {
                    table.HasCheckConstraint("CK_RSRA_RequestDigest", "octet_length(\"RequestDigestSha256\") = 64 AND \"RequestDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RSRA_RecoveryDigest", "octet_length(\"RecoveryDigestSha256\") = 64 AND \"RecoveryDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RSRA_Decision", "\"Decision\" IN ('AUTHORIZED', 'REFUSED')");
                    table.HasCheckConstraint("CK_RSRA_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 16384");
                    table.HasCheckConstraint("CK_RSRA_RequestBytes", "octet_length(\"CanonicalRequestUtf8\") BETWEEN 1 AND 4096");
                    table.HasCheckConstraint("CK_RSRA_TerminalShape", "(\"Decision\" = 'AUTHORIZED' AND \"ReservationRef\" IS NOT NULL AND \"ErrorCode\" IS NULL AND \"HttpStatusCode\" = 200) OR (\"Decision\" = 'REFUSED' AND \"ReservationRef\" IS NULL AND \"ErrorCode\" IS NOT NULL AND \"HttpStatusCode\" IN (400,403,409,410))");
                });
                entity.HasKey(item => new { item.AuthenticatedClientId, item.RequestId });
                entity.HasAlternateKey(item => new
                    { item.AuthenticatedClientId, item.RequestId, item.RecoveryOperationRef });
                entity.Property(item => item.AuthenticatedClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.RequestDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.RecoveryDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.Decision).HasColumnType("varchar(16)").UseCollation("C");
                entity.Property(item => item.ContentType).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ErrorCode).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.CanonicalRequestUtf8).HasColumnType("bytea");
                entity.Property(item => item.ExactResponseUtf8).HasColumnType("bytea");
                // Terminal outcomes are client-command scoped; only authorized resource tables own
                // global operation uniqueness, allowing a second client to freeze its own refusal.
                entity.HasIndex(item => item.RecoveryOperationRef);
                entity.HasIndex(item => item.ReservationRef).IsUnique().HasFilter("\"ReservationRef\" IS NOT NULL");
            });

            modelBuilder.Entity<RuntimeSeatRecoveryReservation>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryReservations", table =>
                {
                    table.HasCheckConstraint("CK_RSRR_State", "\"State\" IN ('RESERVED','COMMITTED','ABANDONED')");
                    table.HasCheckConstraint("CK_RSRR_Chronology", "\"CreatedAtUtc\" < \"ExpiresAtUtc\"");
                });
                entity.HasKey(item => item.ReservationRef);
                entity.HasAlternateKey(item => new { item.ReservationRef, item.LicenseSeatId })
                    .HasName("AK_RuntimeSeatRecoveryReservations_ReservationRef_LicenseSeatId");
                entity.Property(item => item.AuthenticatedClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ProviderGrantRef).HasColumnType("varchar(1536)").UseCollation("C");
                entity.Property(item => item.State).HasColumnType("varchar(16)").UseCollation("C");
                entity.HasIndex(item => item.RecoveryOperationRef).IsUnique();
                entity.HasIndex(item => item.LicenseSeatId).IsUnique().HasFilter("\"State\" = 'RESERVED'")
                    .HasDatabaseName("UX_RSRR_OneReservedPerSeat");
                entity.HasOne<RuntimeSeatRecoveryAuthorization>().WithOne()
                    .HasPrincipalKey<RuntimeSeatRecoveryAuthorization>(item => new
                        { item.AuthenticatedClientId, item.RequestId, item.RecoveryOperationRef })
                    .HasForeignKey<RuntimeSeatRecoveryReservation>(item => new
                        { item.AuthenticatedClientId, item.RequestId, item.RecoveryOperationRef })
                    .OnDelete(DeleteBehavior.NoAction);
                entity.HasOne<License>().WithMany().HasForeignKey(item => item.LicenseId).OnDelete(DeleteBehavior.NoAction);
                entity.HasOne<LicenseSeat>().WithMany().HasForeignKey(item => item.LicenseSeatId).OnDelete(DeleteBehavior.NoAction);
            });

            modelBuilder.Entity<RuntimeSeatRecoveryAuthority>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryAuthorities", table =>
                {
                    table.HasCheckConstraint("CK_RSRAuthority_State", "\"State\" IN ('PREPARED','ACTIVE','ABANDONED','SUPERSEDED')");
                    table.HasCheckConstraint("CK_RSRAuthority_PreviousState", "\"PreviousAuthorityState\" IN ('ACTIVE','SUPERSEDED')");
                    table.HasCheckConstraint("CK_RSRAuthority_Digests", "\"HardwareIdDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"ArtifactSetDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"PublicKeySpkiSha256\" ~ '^[0-9a-f]{64}$' AND \"SubjectRefDigestSha256\" ~ '^[0-9a-f]{64}$'");
                });
                entity.HasKey(item => item.ReservationRef);
                entity.HasIndex(item => item.AuthorityGenerationId).IsUnique();
                entity.HasIndex(item => new { item.AuthorityLineageId, item.AuthorityGenerationId }).IsUnique()
                    .HasDatabaseName("UX_RSRAuthorities_NewLineageGeneration");
                entity.HasIndex(item => new
                    { item.PreviousAuthorityLineageId, item.PreviousAuthorityGenerationId })
                    .HasDatabaseName("IX_RSRAuthorities_PreviousLineageGeneration");
                entity.HasIndex(item => item.BindingId).IsUnique();
                entity.HasIndex(item => item.EnrollmentId).IsUnique();
                entity.HasIndex(item => item.LicenseSeatId).IsUnique().HasFilter("\"State\" = 'ACTIVE'")
                    .HasDatabaseName("UX_RSRAuthorities_OneActivePerSeat");
                entity.Property(item => item.HardwareIdDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ReleaseVersion).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ArtifactSetDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.PublicKeySpkiSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.KeyThumbprint).HasColumnType("varchar(43)").UseCollation("C");
                entity.Property(item => item.State).HasColumnType("varchar(16)").UseCollation("C");
                entity.Property(item => item.PreviousAuthorityState).HasColumnType("varchar(16)").UseCollation("C");
                entity.Property(item => item.SubjectRefDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.HasOne<RuntimeSeatRecoveryReservation>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryAuthority>(item => new
                        { item.ReservationRef, item.LicenseSeatId })
                    .HasPrincipalKey<RuntimeSeatRecoveryReservation>(item => new
                        { item.ReservationRef, item.LicenseSeatId })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRAuthorities_RSRReservations_ReservationRef_LicenseSeatId");
                entity.HasOne<RuntimeEnrollmentAuthorityGeneration>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryAuthority>(item => new
                        { item.AuthorityLineageId, item.AuthorityGenerationId })
                    .HasPrincipalKey<RuntimeEnrollmentAuthorityGeneration>(item => new
                        { item.AuthorityLineageId, item.AuthorityGenerationId })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRAuthorities_REAuthorityGenerations_New");
                entity.HasOne<RuntimeEnrollmentAuthorityGeneration>().WithMany()
                    .HasForeignKey(item => new
                        { item.PreviousAuthorityLineageId, item.PreviousAuthorityGenerationId })
                    .HasPrincipalKey(item => new
                        { item.AuthorityLineageId, item.AuthorityGenerationId })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRAuthorities_REAuthorityGenerations_Previous");
            });

            modelBuilder.Entity<RuntimeSeatRecoveryActivationReceipt>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryActivationReceipts", table =>
                {
                    table.HasCheckConstraint("CK_RSRActivation_Digests",
                        "\"ActivationRequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"RequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"ConfirmationRequestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RSRActivation_RequestBytes",
                        "octet_length(\"CanonicalRequestUtf8\") = 524");
                    table.HasCheckConstraint("CK_RSRActivation_ResponseBytes",
                        "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.HasCheckConstraint("CK_RSRActivation_State", "\"State\" IN ('COMMITTED','REFUSED')");
                    table.HasCheckConstraint("CK_RSRActivation_TerminalShape",
                        "(\"State\" = 'COMMITTED' AND \"HttpStatusCode\" = 200 AND \"ErrorCode\" IS NULL) OR (\"State\" = 'REFUSED' AND \"HttpStatusCode\" IN (409,410) AND \"ErrorCode\" IN ('activation_conflict','activation_expired'))");
                    table.HasCheckConstraint("CK_RSRActivation_ContentType",
                        "\"ContentType\" = 'application/json; charset=utf-8'");
                });
                entity.HasKey(item => new { item.AuthenticatedClientId, item.RequestId });
                entity.Property(item => item.AuthenticatedClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ActivationRequestDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.CanonicalRequestUtf8).HasColumnType("bytea");
                entity.Property(item => item.RequestDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ConfirmationRequestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.State).HasColumnType("varchar(16)").UseCollation("C");
                entity.Property(item => item.ContentType).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ErrorCode).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ExactResponseUtf8).HasColumnType("bytea");
                entity.HasIndex(item => new { item.AuthenticatedClientId, item.PrepareRef }).IsUnique()
                    .HasDatabaseName("UX_RSRActivation_Client_PrepareRef");
                entity.HasIndex(item => item.ReservationRef).IsUnique();
                entity.HasOne<RuntimeSeatRecoveryProofReceipt>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryActivationReceipt>(item => new
                        { item.AuthenticatedClientId, item.PrepareRef })
                    .OnDelete(DeleteBehavior.NoAction);
                entity.HasOne<RuntimeSeatRecoveryReservation>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryActivationReceipt>(item => item.ReservationRef)
                    .OnDelete(DeleteBehavior.NoAction);
            });

            modelBuilder.Entity<RuntimeSeatRecoveryKeyPreparation>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryKeyPreparations", table =>
                {
                    table.HasCheckConstraint("CK_RSRKP_Digests",
                        "\"RequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"PublicKeySpkiSha256\" ~ '^[0-9a-f]{64}$' AND \"ChallengeDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RSRKP_Chronology",
                        "\"CreatedAtUtc\" < \"ExpiresAtUtc\" AND (\"ChallengeConsumedAtUtc\" IS NULL OR \"ChallengeConsumedAtUtc\" >= \"CreatedAtUtc\")");
                    table.HasCheckConstraint("CK_RSRKP_Audience",
                        "\"ConfirmAudience\" = 'softlicence:runtime-identity-recovery:confirm:v1'");
                    table.HasCheckConstraint("CK_RSRKP_RequestBytes",
                        "octet_length(\"CanonicalRequestUtf8\") BETWEEN 1 AND 4096");
                    table.HasCheckConstraint("CK_RSRKP_ResponseBytes",
                        "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                });
                entity.HasKey(item => new { item.AuthenticatedClientId, item.PrepareRef });
                entity.HasAlternateKey(item => new
                    { item.AuthenticatedClientId, item.RequestId, item.RecoveryOperationRef })
                    .HasName("AK_RSRKP_Client_Request_Recovery");
                entity.Property(item => item.AuthenticatedClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.RequestDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.PublicKeySpkiSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.PublicKeySpkiCiphertext).HasColumnType("text").UseCollation("C");
                entity.Property(item => item.PublicKeySpkiKeyId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ChallengeDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ChallengeCiphertext).HasColumnType("text").UseCollation("C");
                entity.Property(item => item.ChallengeKeyId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ConfirmAudience).HasColumnType("varchar(96)").UseCollation("C");
                entity.Property(item => item.CanonicalRequestUtf8).HasColumnType("bytea");
                entity.Property(item => item.ExactResponseUtf8).HasColumnType("bytea");
                entity.HasIndex(item => item.ReservationRef).IsUnique();
                entity.HasIndex(item => item.EnrollmentId).IsUnique();
                entity.HasIndex(item => item.AuthorityGenerationId).IsUnique();
                entity.HasOne<RuntimeSeatRecoveryAuthorization>().WithOne()
                    .HasPrincipalKey<RuntimeSeatRecoveryAuthorization>(item => new
                        { item.AuthenticatedClientId, item.RequestId, item.RecoveryOperationRef })
                    .HasForeignKey<RuntimeSeatRecoveryKeyPreparation>(item => new
                        { item.AuthenticatedClientId, item.RequestId, item.RecoveryOperationRef })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRKP_RSRAuthorizations_Client_Request_Recovery");
                entity.HasOne<RuntimeSeatRecoveryReservation>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryKeyPreparation>(item => item.ReservationRef)
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRKP_RSRReservations_ReservationRef");
            });

            modelBuilder.Entity<RuntimeSeatRecoveryKeyConfirmation>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryKeyConfirmations", table =>
                {
                    table.HasCheckConstraint("CK_RSRKC_Digest", "\"ConfirmationRequestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RSRKC_State", "\"State\" IN ('PROVED','REFUSED')");
                    table.HasCheckConstraint("CK_RSRKC_RequestBytes", "octet_length(\"CanonicalRequestUtf8\") BETWEEN 1 AND 4096");
                    table.HasCheckConstraint("CK_RSRKC_ResponseBytes", "octet_length(\"ExactResponseUtf8\") BETWEEN 1 AND 8192");
                    table.HasCheckConstraint("CK_RSRKC_TerminalShape",
                        "(\"State\" = 'PROVED' AND \"HttpStatusCode\" = 200 AND \"ErrorCode\" IS NULL) OR (\"State\" = 'REFUSED' AND \"HttpStatusCode\" IN (403,409,410) AND \"ErrorCode\" IS NOT NULL)");
                });
                entity.HasKey(item => new { item.AuthenticatedClientId, item.PrepareRef });
                entity.Property(item => item.AuthenticatedClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ConfirmationRequestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.State).HasColumnType("varchar(16)").UseCollation("C");
                entity.Property(item => item.ContentType).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ErrorCode).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.CanonicalRequestUtf8).HasColumnType("bytea");
                entity.Property(item => item.ExactResponseUtf8).HasColumnType("bytea");
                entity.HasOne<RuntimeSeatRecoveryKeyPreparation>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryKeyConfirmation>(item => new
                        { item.AuthenticatedClientId, item.PrepareRef })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRKC_RSRKeyPreparations_Client_Prepare");
            });

            modelBuilder.Entity<RuntimeSeatRecoveryProofReceipt>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryProofReceipts", table =>
                {
                    table.HasCheckConstraint("CK_RSRPR_State", "\"State\" = 'PROVED'");
                    table.HasCheckConstraint("CK_RSRPR_Digests",
                        "\"RequestDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"PublicKeySpkiSha256\" ~ '^[0-9a-f]{64}$' AND \"ConfirmationRequestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RSRPR_ExpiryMinimum",
                        "\"ExpiresAtUtc\" = LEAST(\"PreparationExpiresAtUtc\", \"ReservationExpiresAtUtc\")");
                    table.HasCheckConstraint("CK_RSRPR_Chronology", "\"ProvedAtUtc\" < \"ExpiresAtUtc\"");
                });
                entity.HasKey(item => new { item.AuthenticatedClientId, item.PrepareRef });
                entity.Property(item => item.AuthenticatedClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.RequestDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.PublicKeySpkiSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ConfirmationRequestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.State).HasColumnType("varchar(16)").UseCollation("C");
                entity.HasIndex(item => item.ReservationRef).IsUnique();
                entity.HasIndex(item => item.AuthorityGenerationId).IsUnique();
                entity.HasOne<RuntimeSeatRecoveryKeyConfirmation>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryProofReceipt>(item => new
                        { item.AuthenticatedClientId, item.PrepareRef })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRPR_RSRKeyConfirmations_Client_Prepare");
                entity.HasOne<RuntimeSeatRecoveryReservation>().WithOne()
                    .HasForeignKey<RuntimeSeatRecoveryProofReceipt>(item => item.ReservationRef)
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RSRPR_RSRReservations_ReservationRef");
            });

            modelBuilder.Entity<RuntimeRecoveryCommercialOwnership>(entity =>
            {
                entity.ToTable("RuntimeRecoveryCommercialOwnerships", table =>
                {
                    table.HasCheckConstraint("CK_RRCO_State", "\"State\" IN ('PENDING_TRANSFER','ACTIVE','TRANSFERRED','REVOKED')");
                    table.HasCheckConstraint("CK_RRCO_Ended", "(\"State\" = 'ACTIVE' AND \"EndedAtUtc\" IS NULL) OR (\"State\" <> 'ACTIVE' AND \"EndedAtUtc\" IS NOT NULL)");
                    table.HasCheckConstraint("CK_RRCO_Previous_NotSelf", "\"PreviousOwnershipId\" IS NULL OR \"PreviousOwnershipId\" <> \"Id\"");
                });
                entity.HasKey(item => item.Id);
                entity.HasAlternateKey(item => new { item.ProductId, item.LicenseId, item.Id })
                    .HasName("AK_RRCO_ProductId_LicenseId_Id");
                entity.Property(item => item.State).HasColumnType("varchar(24)").UseCollation("C");
                entity.HasIndex(item => new { item.ProductId, item.LicenseId }).IsUnique()
                    .HasFilter("\"State\" = 'ACTIVE'").HasDatabaseName("UX_RRCO_OneActiveOwner");
                entity.HasIndex(item => new { item.ProductId, item.LicenseId, item.PreviousOwnershipId })
                    .HasDatabaseName("IX_RRCO_PreviousOwnership");
                entity.HasOne<Product>().WithMany()
                    .HasForeignKey(item => item.ProductId)
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCO_Products_ProductId");
                entity.HasOne<License>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.LicenseId })
                    .HasPrincipalKey(item => new { item.ProductId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCO_Licenses_ProductId_LicenseId");
                entity.HasOne<RuntimeRecoveryCommercialSubject>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.OwnerSubjectId })
                    .HasPrincipalKey(item => new { item.ProductId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCO_CommercialSubjects_ProductId_OwnerSubjectId");
                entity.HasOne<RuntimeRecoveryCommercialOwnership>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.LicenseId, item.PreviousOwnershipId })
                    .HasPrincipalKey(item => new { item.ProductId, item.LicenseId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCO_Previous_ProductId_LicenseId_OwnershipId");
            });

            modelBuilder.Entity<RuntimeRecoveryCommercialSubject>(entity =>
            {
                entity.ToTable("RuntimeRecoveryCommercialSubjects");
                entity.HasKey(item => new { item.ProductId, item.Id });
                entity.HasOne(item => item.Product).WithMany()
                    .HasForeignKey(item => item.ProductId)
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCS_Products_ProductId");
            });

            modelBuilder.Entity<RuntimeRecoveryCommercialOwnershipCommand>(entity =>
            {
                entity.ToTable("RuntimeRecoveryCommercialOwnershipCommands", table =>
                {
                    table.HasCheckConstraint("CK_RRCOC_Operation",
                        "\"Operation\" IN ('TRANSFER_OWNERSHIP','REVOKE_OWNERSHIP')");
                    table.HasCheckConstraint("CK_RRCOC_RequestDigest",
                        "octet_length(\"RequestDigestSha256\") = 64 AND \"RequestDigestSha256\" ~ '^[0-9a-f]{64}$'");
                    table.HasCheckConstraint("CK_RRCOC_ResultShape",
                        "(\"Operation\" = 'TRANSFER_OWNERSHIP' AND \"TargetCommercialSubjectId\" IS NOT NULL AND \"ResultOwnershipId\" IS NOT NULL) OR " +
                        "(\"Operation\" = 'REVOKE_OWNERSHIP' AND \"TargetCommercialSubjectId\" IS NULL AND \"ResultOwnershipId\" IS NULL)");
                });
                entity.HasKey(item => item.Id);
                entity.Property(item => item.Operation).HasColumnType("varchar(32)").UseCollation("C");
                entity.Property(item => item.RequestDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.ResponseJson).HasColumnType("text").UseCollation("C");
                entity.HasIndex(item => new { item.ProductId, item.LicenseId, item.ExpectedOwnershipId })
                    .HasDatabaseName("IX_RRCOC_ExpectedOwnership");
                entity.HasIndex(item => new { item.ProductId, item.LicenseId, item.ResultOwnershipId })
                    .HasDatabaseName("IX_RRCOC_ResultOwnership");
                entity.HasIndex(item => new { item.ProductId, item.TargetCommercialSubjectId })
                    .HasDatabaseName("IX_RRCOC_TargetSubject");
                entity.HasOne<Product>().WithMany()
                    .HasForeignKey(item => item.ProductId)
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCOC_Products_ProductId");
                entity.HasOne<License>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.LicenseId })
                    .HasPrincipalKey(item => new { item.ProductId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCOC_Licenses_ProductId_LicenseId");
                entity.HasOne<RuntimeRecoveryCommercialSubject>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.TargetCommercialSubjectId })
                    .HasPrincipalKey(item => new { item.ProductId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCOC_TargetSubjects_ProductId_SubjectId");
                entity.HasOne<RuntimeRecoveryCommercialOwnership>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.LicenseId, item.ExpectedOwnershipId })
                    .HasPrincipalKey(item => new { item.ProductId, item.LicenseId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCOC_ExpectedOwnership_ProductId_LicenseId_Id");
                entity.HasOne<RuntimeRecoveryCommercialOwnership>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.LicenseId, item.ResultOwnershipId })
                    .HasPrincipalKey(item => new { item.ProductId, item.LicenseId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRCOC_ResultOwnership_ProductId_LicenseId_Id");
            });

            modelBuilder.Entity<RuntimeSeatRecoveryRevokedClaimNonce>(entity =>
            {
                entity.ToTable("RuntimeSeatRecoveryRevokedClaimNonces");
                entity.HasKey(item => item.Nonce);
                entity.Property(item => item.ReasonCode).HasColumnType("varchar(64)").UseCollation("C");
            });

            modelBuilder.Entity<RuntimeRecoveryGrantOwnership>(entity =>
            {
                entity.ToTable("RuntimeRecoveryGrantOwnerships", table =>
                    table.HasCheckConstraint("CK_RRGO_Digests", "\"ProviderGrantRefDigestSha256\" ~ '^[0-9a-f]{64}$' AND \"RecoveryDigestSha256\" ~ '^[0-9a-f]{64}$'"));
                entity.HasKey(item => new { item.ProductId, item.ProviderGrantRefDigestSha256 });
                entity.Property(item => item.ProviderGrantRefDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.AuthenticatedClientId).HasColumnType("varchar(64)").UseCollation("C");
                entity.Property(item => item.RecoveryDigestSha256).HasColumnType("varchar(64)").UseCollation("C");
                entity.HasIndex(item => item.RecoveryOperationRef).IsUnique();
                entity.HasOne<RuntimeRecoveryCommercialOwnership>().WithMany()
                    .HasForeignKey(item => new { item.ProductId, item.LicenseId, item.CommercialOwnershipId })
                    .HasPrincipalKey(item => new { item.ProductId, item.LicenseId, item.Id })
                    .OnDelete(DeleteBehavior.NoAction)
                    .HasConstraintName("FK_RRGO_CommercialOwnership_ProductId_LicenseId_OwnershipId");
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
        /// <summary>
        /// Maps additive paid-pass tables with scoped restrictive foreign keys, ordinal provider strings
        /// and explicit paid-period checks. SQL checks enforce shape, while the controller owns atomic
        /// chronology and append-only writes; these mappings do not claim SQL-trigger immutability.
        /// </summary>
        private void ConfigurePersonalDayPass(ModelBuilder modelBuilder)
        {
            // Stable pass and license identity prevent concurrent purchases creating a second key.
            var pass = modelBuilder.Entity<PersonalDayPass>();
            pass.HasKey(p => p.Id);
            pass.HasIndex(p => new { p.ProductId, p.CommercialSubjectId }).IsUnique();
            pass.HasIndex(p => p.LicenseId).IsUnique();
            pass.Property(p => p.PaidThroughUtc).HasPrecision(3);
            pass.Property(p => p.InitialPaidThroughUtc).HasPrecision(3);
            pass.HasOne<License>().WithMany().HasForeignKey(p => new { p.ProductId, p.LicenseId })
                .HasPrincipalKey(l => new { l.ProductId, l.Id }).OnDelete(DeleteBehavior.Restrict);
            pass.HasOne<RuntimeRecoveryCommercialSubject>().WithMany()
                .HasForeignKey(p => new { p.ProductId, p.CommercialSubjectId })
                .HasPrincipalKey(s => new { s.ProductId, s.Id }).OnDelete(DeleteBehavior.Restrict);

            // The provider tuple is unique across products: one payment cannot buy two passes.
            var payment = modelBuilder.Entity<PersonalDayPassPayment>();
            payment.HasKey(p => p.Id);
            payment.HasOne<PersonalDayPass>().WithMany().HasForeignKey(p => p.PassId).OnDelete(DeleteBehavior.Restrict);
            payment.HasIndex(p => new { p.Provider, p.ProviderAccount, p.Environment, p.PaymentId }).IsUnique();
            payment.HasIndex(p => new { p.PassId, p.PaidAtUtc });
            payment.Property(p => p.Provider).HasMaxLength(200).UseCollation("C");
            payment.Property(p => p.ProviderAccount).HasMaxLength(200).UseCollation("C");
            payment.Property(p => p.Environment).HasMaxLength(200).UseCollation("C");
            payment.Property(p => p.PaymentId).HasMaxLength(200).UseCollation("C");
            payment.Property(p => p.EvidenceDigest).HasMaxLength(64).UseCollation("C");
            payment.Property(p => p.Currency).HasMaxLength(3).UseCollation("C");
            payment.Property(p => p.Offer).HasMaxLength(20).UseCollation("C");
            payment.Property(p => p.PaidAtUtc).HasPrecision(3);
            payment.ToTable("PersonalDayPassPayments", table =>
            {
                // Required CLR members generate NOT NULL; checks never rely on SQL UNKNOWN rejection.
                table.HasCheckConstraint("CK_PersonalDayPassPayments_Price", "\"MaxSeats\" BETWEEN 1 AND 10 AND \"Currency\" = 'eur' AND ((\"Offer\" = 'day_pass' AND \"DurationSeconds\" = 86400 AND \"AmountMinor\" = (CASE WHEN \"PrioritySupport\" THEN 1140 ELSE 1000 END) * \"MaxSeats\") OR (\"Offer\" = 'subscription' AND NOT \"PrioritySupport\" AND \"DurationSeconds\" BETWEEN 86400 AND 31622400 AND \"AmountMinor\" > 0))");
                table.HasCheckConstraint("CK_PersonalDayPassPayments_Digest", "length(\"EvidenceDigest\") = 64");
                table.HasCheckConstraint("CK_PersonalDayPassPayments_Identity", "length(\"Provider\") > 0 AND length(\"ProviderAccount\") > 0 AND length(\"Environment\") > 0 AND length(\"PaymentId\") > 0");
            });

            // Historical periods are immutable through this store even when the current projection changes.
            var operation = modelBuilder.Entity<PersonalDayPassOperation>();
            operation.HasKey(o => o.Id);
            operation.HasOne<PersonalDayPassPayment>().WithMany().HasForeignKey(o => o.PaymentId).OnDelete(DeleteBehavior.Restrict);
            operation.Property(o => o.RequestDigest).HasMaxLength(64).UseCollation("C");
            operation.Property(o => o.PeriodStartsAtUtc).HasPrecision(3);
            operation.Property(o => o.PeriodExpiresAtUtc).HasPrecision(3);
            operation.Property(o => o.PaidThroughUtc).HasPrecision(3);
            operation.ToTable("PersonalDayPassOperations", table =>
            {
                // Other model providers remain usable for existing tests; paid-pass writes themselves require PG.
                table.HasCheckConstraint("CK_PersonalDayPassOperations_Period", Database.IsNpgsql()
                    ? "\"PeriodExpiresAtUtc\" >= \"PeriodStartsAtUtc\" + interval '1 day' AND \"PeriodExpiresAtUtc\" <= \"PeriodStartsAtUtc\" + interval '366 days' AND \"PaidThroughUtc\" >= \"PeriodExpiresAtUtc\""
                    : "julianday(\"PeriodExpiresAtUtc\") >= julianday(\"PeriodStartsAtUtc\") + 1 AND julianday(\"PeriodExpiresAtUtc\") <= julianday(\"PeriodStartsAtUtc\") + 366 AND julianday(\"PaidThroughUtc\") >= julianday(\"PeriodExpiresAtUtc\")");
                table.HasCheckConstraint("CK_PersonalDayPassOperations_Digest", "length(\"RequestDigest\") = 64");
            });
        }
    }
}

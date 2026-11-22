using Microsoft.EntityFrameworkCore;

namespace SoftLicence.Server.Data;

/// <summary>Shared constrained storage for commercial proof across all issuance routes.</summary>
internal static class CommercialEvidenceMapping
{
    /// <summary>Uses ordinal database identities and restrictive foreign keys, without historical backfill.</summary>
    internal static void Configure(ModelBuilder builder, bool postgres)
    {
        builder.Entity<License>().Property(x => x.CommercialNature).HasMaxLength(32).HasDefaultValue("UNKNOWN");
        var order = builder.Entity<CommercialOrderEvidence>();
        order.HasKey(x => x.Id);
        order.Property(x => x.OrderId).HasMaxLength(200);
        order.Property(x => x.Nature).HasMaxLength(32);
        order.Property(x => x.Currency).HasMaxLength(3);
        order.Property(x => x.Producer).HasMaxLength(32);
        order.Property(x => x.ReceiptKey).HasMaxLength(512);
        order.Property(x => x.AttributionDigest).HasMaxLength(64);
        if (postgres) order.Property(x => x.OrderId).UseCollation("C");
        order.HasIndex(x => new { x.ProductId, x.OrderId }).IsUnique();
        order.HasOne<License>().WithMany().HasForeignKey(x => new { x.ProductId, x.LicenseId })
            .HasPrincipalKey(x => new { x.ProductId, x.Id }).OnDelete(DeleteBehavior.Restrict);
        order.HasOne<RuntimeRecoveryCommercialSubject>().WithMany()
            .HasForeignKey(x => new { x.ProductId, x.CommercialSubjectId })
            .HasPrincipalKey(x => new { x.ProductId, x.Id }).OnDelete(DeleteBehavior.Restrict);
        order.ToTable("CommercialOrderEvidence", table => table.HasCheckConstraint("CK_CommercialOrderEvidence_Values",
            "\"Version\" = 2 AND \"Currency\" = 'eur' AND length(\"AttributionDigest\") = 64 AND " +
            "((\"Nature\" IN ('FIRST_ORDER_FREE','FREE') AND \"PaidAmountMinor\" = 0) OR " +
            "(\"Nature\" = 'PAID_TRIAL' AND \"PaidAmountMinor\" IN (9700, 10000)) OR (\"Nature\" = 'PAID' AND \"PaidAmountMinor\" > 0))"));
        var operation = builder.Entity<CommercialEvidenceOperation>();
        operation.HasKey(x => x.Id);
        operation.Property(x => x.Id).ValueGeneratedNever();
        operation.Property(x => x.RequestDigest).HasMaxLength(64);
        operation.HasOne<CommercialOrderEvidence>().WithMany().HasForeignKey(x => x.OrderEvidenceId).OnDelete(DeleteBehavior.Restrict);
        operation.ToTable("CommercialEvidenceOperations");
    }
}

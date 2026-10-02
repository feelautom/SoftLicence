using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>TKT-001177: level 3+ alerts carry the full dossier; the migrated legacy marker released on a clean record stays silent.</summary>
public sealed class SecurityLockAlertPolicyTests
{
    [Theory]
    [InlineData("HEARTBEAT_UNREACHABLE", 1, "RELEASE", false)]
    [InlineData("LICENSE_EXPIRED", 2, "RELEASE", false)]
    [InlineData("LEGACY_MARKER", 3, "RELEASE", false)]
    [InlineData("LEGACY_MARKER", 3, "MAINTAIN", true)]
    [InlineData("STATE_UNREADABLE", 3, "MAINTAIN", true)]
    [InlineData("NATIVE_DLL_REPLACED", 4, "RELEASE", true)]
    [InlineData("NATIVE_DLL_REPLACED", 4, "MAINTAIN", true)]
    [InlineData("DEBUGGER_ATTACHED_KERNEL", 5, "BAN", true)]
    public void NewLockAlert_FollowsTheOwnerDecision(string cause, int level, string verdict, bool expected)
    {
        Assert.Equal(expected, SecurityLockAlertPolicy.ShouldAlertNewLock(cause, level, verdict));
    }

    [Fact]
    public void LicenseKey_IsMaskedAndDossierContainsTheDecisionFacts()
    {
        Assert.Null(SecurityLockAlertPolicy.MaskLicenseKey(null));
        Assert.Equal("****", SecurityLockAlertPolicy.MaskLicenseKey("ABCD-123"));
        Assert.Equal("ABCD…WXYZ", SecurityLockAlertPolicy.MaskLicenseKey("ABCD-EFGH-IJKL-WXYZ"));

        var text = SecurityLockAlertPolicy.BuildDossier(new SecurityLockDossier(
            "TIAConnect", "Client", "client@example.com", "ABCD…WXYZ", "PC-01", "HWID-ABC", "2.4.300",
            "11111111-1111-4111-8111-111111111111", Guid.Parse("22222222-2222-4222-8222-222222222222"),
            new string('a', 32), "NATIVE_DLL_REPLACED", 4, "REVIEW", "REVIEW", "MAINTAIN", "OPEN",
            new DateTime(2026, 9, 18, 10, 0, 0, DateTimeKind.Utc), new DateTime(2026, 9, 18, 10, 1, 0, DateTimeKind.Utc),
            2, 1, true, new string('b', 64)));
        foreach (var expected in new[]
        {
            "Produit : TIAConnect", "Client : Client <client@example.com>", "Licence : ABCD…WXYZ", "Machine : PC-01",
            "HWID : HWID-ABC", "Verrou : " + new string('a', 32), "Cause : NATIVE_DLL_REPLACED (niveau 4)",
            "Mode serveur : REVIEW (client : REVIEW)", "Verdict : MAINTAIN, état OPEN",
            "Première détection : 2026-09-18 10:00:00 UTC", "Rapports reçus : 2", "Autres verrous sur ce matériel : 1",
            "Incident critique ouvert : oui", "Empreinte de la preuve : " + new string('b', 64)
        })
            Assert.Contains(expected, text, StringComparison.Ordinal);
        Assert.DoesNotContain("ABCD-EFGH", text, StringComparison.Ordinal);
        // Franck, 19/09/2026: never an em dash anywhere.
        Assert.DoesNotContain("\u2014", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Triggers_AreRegisteredForWebhookSubscription()
    {
        Assert.True(NotificationService.AvailableTriggers.ContainsKey(NotificationService.Triggers.SecurityLockReported));
        Assert.True(NotificationService.AvailableTriggers.ContainsKey(NotificationService.Triggers.SecurityLockBanned));
    }
}

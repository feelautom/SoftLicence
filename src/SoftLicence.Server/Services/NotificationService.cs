using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Text.Json;
using System.Net.Http.Json;

namespace SoftLicence.Server.Services;

public sealed record NotificationDeliveryResult(int Configured, int Delivered, int Failed);

public class NotificationService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<NotificationService> _logger;
    private readonly IHttpClientFactory _httpFactory;

    // Définition des événements supportés
    public static class Triggers
    {
        public const string SecurityIpBanned = "Security.IpBanned";
        public const string SecurityZombieDetected = "Security.ZombieDetected";
        public const string SecurityHwidReuseDetected = "Security.HwidReuseDetected";
        public const string SecurityAuthFailure = "Security.AuthFailure";
        public const string SecurityEvidenceObserved = "Security.EvidenceObserved";
        /// <summary>Grouped "would have blocked" events of the assignment controls while the switch is open (TKT-001277).</summary>
        public const string SecurityAssignmentEnforcement = "Security.AssignmentEnforcement";
        public const string LicenseCreated = "License.Created";
        public const string LicenseActivated = "License.Activated";
        public const string LicenseRevoked = "License.Revoked";
        public const string SystemStartup = "System.Startup";
        public const string TelemetryRejected = "Telemetry.Rejected";
        /// <summary>An UPD-100x startup shell was actually presented to a Desktop user.</summary>
        public const string UpdatePreflightFailureShown = "Update.PreflightFailureShown";
        public const string ActivationIncident = "Activation.Incident";
        public const string ActivationRecovered = "Activation.Recovered";
        /// <summary>New security lock of level 3 or more (TKT-001177), sent with the full dossier.</summary>
        public const string SecurityLockReported = "Security.LockReported";
        /// <summary>Permanent hardware ban issued by the lock system (TKT-001177).</summary>
        public const string SecurityLockBanned = "Security.LockBanned";
    }

    public static readonly Dictionary<string, string> AvailableTriggers = new()
    {
        { Triggers.SecurityIpBanned, "🚨 IP Bannue (Sécurité)" },
        { Triggers.SecurityZombieDetected, "🧟 Zombie Détecté (Fraude)" },
        { Triggers.SecurityHwidReuseDetected, "🚨 HWID réutilisé (Multi-compte)" },
        { Triggers.SecurityAuthFailure, "⚠️ Echec Authentification (Admin)" },
        { Triggers.SecurityEvidenceObserved, "⚠️ Preuve sécurité observée" },
        { Triggers.LicenseCreated, "✨ Nouvelle Licence Créée" },
        { Triggers.LicenseActivated, "✅ Licence Activée" },
        { Triggers.LicenseRevoked, "🚫 Licence Révoquée" },
        { Triggers.SystemStartup, "🚀 Démarrage Serveur" },
        { Triggers.TelemetryRejected, "⚠️ Télémétrie rejetée" },
        { Triggers.UpdatePreflightFailureShown, "⚠️ Blocage de démarrage UPD affiché" },
        { Triggers.ActivationIncident, "⚠️ Incident activation" },
        { Triggers.ActivationRecovered, "✅ Activation rétablie" },
        { Triggers.SecurityLockReported, "🔒 Verrou de sécurité à examiner" },
        { Triggers.SecurityLockBanned, "⛔ Verrou : matériel banni" }
    };

    public NotificationService(IDbContextFactory<LicenseDbContext> dbFactory, ILogger<NotificationService> logger, IHttpClientFactory httpFactory)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _httpFactory = httpFactory;
    }

    public virtual void Notify(string trigger, string title, string message, object? data = null)
    {
        // Fire-and-forget pour ne pas bloquer le thread appelant
        _ = Task.Run(async () => await SendWebhooksAsync(trigger, title, message, data));
    }

    /// <summary>
    /// Delivers a notification through configured webhooks and returns an exact provider outcome.
    /// Durable callers use this overload before marking their notification claim as sent.
    /// </summary>
    public virtual Task<NotificationDeliveryResult> NotifyAsync(
        string trigger,
        string title,
        string message,
        object? data = null) =>
        SendWebhooksAsync(trigger, title, message, data);

    private string GetEmojiForTrigger(string trigger) => trigger switch
    {
        Triggers.SecurityIpBanned => "no_entry",
        Triggers.SecurityZombieDetected => "zombie",
        Triggers.SecurityHwidReuseDetected => "warning",
        Triggers.SecurityAuthFailure => "warning",
        Triggers.SecurityEvidenceObserved => "warning",
        Triggers.SecurityAssignmentEnforcement => "warning",
        Triggers.LicenseCreated => "sparkles",
        Triggers.LicenseActivated => "white_check_mark",
        Triggers.LicenseRevoked => "no_entry_sign",
        Triggers.SystemStartup => "rocket",
        Triggers.TelemetryRejected => "warning",
        Triggers.UpdatePreflightFailureShown => "warning",
        Triggers.ActivationIncident => "warning",
        Triggers.ActivationRecovered => "white_check_mark",
        Triggers.SecurityLockReported => "lock",
        Triggers.SecurityLockBanned => "no_entry",
        _ => "bell"
    };

    private async Task<NotificationDeliveryResult> SendWebhooksAsync(
        string trigger,
        string title,
        string message,
        object? data)
    {
        var configured = 0;
        var delivered = 0;
        var failed = 0;
        try
        {
            using var db = await _dbFactory.CreateDbContextAsync();
            
            // Récupérer les webhooks actifs qui sont abonnés à ce trigger
            // Note: Comme EnabledEvents est une string CSV, on filtre en mémoire ou via Contains
            // PostgreSQL supporte ILIKE ou LIKE, EF Core traduit Contains de manière appropriée
            var webhooks = await db.Webhooks
                .Where(w => w.IsEnabled && w.EnabledEvents.Contains(trigger))
                .ToListAsync();

            if (!webhooks.Any()) return new NotificationDeliveryResult(0, 0, 0);

            var client = _httpFactory.CreateClient();
            var payload = new
            {
                trigger,
                title,
                message,
                timestamp = DateTime.UtcNow,
                data
            };

            foreach (var hook in webhooks)
            {
                // Double vérification précise (au cas où "Security.IpBanned" matcherait "Security.IpBannedv2")
                var events = hook.EnabledEvents.Split(
                    ',',
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (!events.Contains(trigger, StringComparer.Ordinal)) continue;
                configured++;

                try
                {
                    // Support pour NTFY (Texte brut avec métadonnées en Query Params pour supporter l'UTF-8/Emojis)
                    if (hook.Url.Contains("ntfy"))
                    {
                        var uriBuilder = new UriBuilder(hook.Url);
                        var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
                        
                        query["title"] = title;
                        query["tags"] = GetEmojiForTrigger(trigger);
                        if (trigger.StartsWith("Security", StringComparison.Ordinal)
                            || trigger.StartsWith("Activation.", StringComparison.Ordinal)
                            || trigger.StartsWith("Telemetry.", StringComparison.Ordinal)
                            || trigger.StartsWith("Update.", StringComparison.Ordinal)) query["priority"] = "4";
                        
                        uriBuilder.Query = query.ToString();
                        
                        // Envoi en texte brut (le corps du message est ce qui s'affiche sur le téléphone)
                        using var response = await client.PostAsync(uriBuilder.ToString(), new StringContent(message));
                        response.EnsureSuccessStatusCode();
                    }
                    else
                    {
                        // Webhook Standard (JSON)
                        using var response = await client.PostAsJsonAsync(hook.Url, payload);
                        response.EnsureSuccessStatusCode();
                    }

                    hook.LastTriggeredAt = DateTime.UtcNow;
                    hook.LastError = null;
                    delivered++;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Echec webhook {Name} ({Url})", hook.Name, hook.Url);
                    hook.LastError = ex.Message;
                    failed++;
                }
            }

            await db.SaveChangesAsync();
            return new NotificationDeliveryResult(configured, delivered, failed);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur globale notification");
            return new NotificationDeliveryResult(configured, delivered, Math.Max(1, failed));
        }
    }
}

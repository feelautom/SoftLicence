using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Text.Json;
using System.Net.Http.Json;

namespace SoftLicence.Server.Services;

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
        public const string LicenseCreated = "License.Created";
        public const string LicenseActivated = "License.Activated";
        public const string LicenseRevoked = "License.Revoked";
        public const string SystemStartup = "System.Startup";
        public const string TelemetryRejected = "Telemetry.Rejected";
        public const string ActivationIncident = "Activation.Incident";
        public const string ActivationRecovered = "Activation.Recovered";
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
        { Triggers.ActivationIncident, "⚠️ Incident activation" },
        { Triggers.ActivationRecovered, "✅ Activation rétablie" }
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

    private string GetEmojiForTrigger(string trigger) => trigger switch
    {
        Triggers.SecurityIpBanned => "no_entry",
        Triggers.SecurityZombieDetected => "zombie",
        Triggers.SecurityHwidReuseDetected => "warning",
        Triggers.SecurityAuthFailure => "warning",
        Triggers.SecurityEvidenceObserved => "warning",
        Triggers.LicenseCreated => "sparkles",
        Triggers.LicenseActivated => "white_check_mark",
        Triggers.LicenseRevoked => "no_entry_sign",
        Triggers.SystemStartup => "rocket",
        Triggers.TelemetryRejected => "warning",
        Triggers.ActivationIncident => "warning",
        Triggers.ActivationRecovered => "white_check_mark",
        _ => "bell"
    };

    private async Task SendWebhooksAsync(string trigger, string title, string message, object? data)
    {
        try
        {
            using var db = await _dbFactory.CreateDbContextAsync();
            
            // Récupérer les webhooks actifs qui sont abonnés à ce trigger
            // Note: Comme EnabledEvents est une string CSV, on filtre en mémoire ou via Contains
            // PostgreSQL supporte ILIKE ou LIKE, EF Core traduit Contains de manière appropriée
            var webhooks = await db.Webhooks
                .Where(w => w.IsEnabled && w.EnabledEvents.Contains(trigger))
                .ToListAsync();

            if (!webhooks.Any()) return;

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
                var events = hook.EnabledEvents.Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (!events.Contains(trigger)) continue;

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
                            || trigger.StartsWith("Telemetry.", StringComparison.Ordinal)) query["priority"] = "4";
                        
                        uriBuilder.Query = query.ToString();
                        
                        // Envoi en texte brut (le corps du message est ce qui s'affiche sur le téléphone)
                        await client.PostAsync(uriBuilder.ToString(), new StringContent(message));
                    }
                    else
                    {
                        // Webhook Standard (JSON)
                        await client.PostAsJsonAsync(hook.Url, payload);
                    }

                    hook.LastTriggeredAt = DateTime.UtcNow;
                    hook.LastError = null;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Echec webhook {Name} ({Url})", hook.Name, hook.Url);
                    hook.LastError = ex.Message;
                }
            }

            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur globale notification");
        }
    }
}

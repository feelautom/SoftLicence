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

    /// <summary>
    /// Exact trigger keys stored in <see cref="Webhook.EnabledEvents"/> (ordinal, case-sensitive). A webhook row is one
    /// destination (for ntfy: one topic); the keys it lists decide which events reach it. Since TKT-003668 routine
    /// noise has its own keys (<see cref="NoiseTriggers"/>) so that it never shares a topic with real alerts.
    /// </summary>
    public static class Triggers
    {
        /// <summary>
        /// Serious hardware or component ban (piracy, debugger, quota abuse, manual, dev canary quarantine) and the
        /// rare paid-licence auto-unban. Historical name kept because production webhooks are subscribed to it; since
        /// TKT-003668 it no longer carries automatic IP bans nor outdated-version bans.
        /// </summary>
        public const string SecurityIpBanned = "Security.IpBanned";
        /// <summary>
        /// Routine noise (TKT-003668): automatic IP ban decided by the threat score, almost always a web scanner probing
        /// <c>.env</c>, <c>.git</c> or similar paths. Several per day; route it to a separate, low-priority topic.
        /// </summary>
        public const string SecurityIpAutoBanned = "Security.IpAutoBanned";
        /// <summary>
        /// Routine noise (TKT-003668): hardware ban of an installation below the minimum version, and its automatic
        /// lift once the installation is updated. Route it to a separate, low-priority topic.
        /// </summary>
        public const string SecurityOutdatedVersionBanned = "Security.OutdatedVersionBanned";
        /// <summary>
        /// Critical alert (TKT-003668): a client reported a successful licence activation against a loopback or
        /// private-network licence server, i.e. a local or fake server answering in place of SoftLicence.
        /// </summary>
        public const string SecurityLicenseServerSpoofed = "Security.LicenseServerSpoofed";
        public const string SecurityZombieDetected = "Security.ZombieDetected";
        public const string SecurityHwidReuseDetected = "Security.HwidReuseDetected";
        public const string SecurityAuthFailure = "Security.AuthFailure";
        /// <summary>An IP threat score crossed 50 or 100 upward (TKT-002685); sent once per crossing.</summary>
        public const string SecurityThreatScoreRaised = "Security.ThreatScoreRaised";
        public const string SecurityEvidenceObserved = "Security.EvidenceObserved";
        /// <summary>
        /// A machine announcing a product version ran, on at least three distinct starts within 24 hours, an EXE, DLL
        /// or Core whose fingerprint belongs to no approved build of the product: a modified binary (TKT-003674).
        /// Sent once per per-hardware incident with the customer, masked licence, hardware and IP. Alert only: no
        /// automatic sanction (decision of 12/11/2026). Same key and meaning as the TKT-003668 critical trigger.
        /// </summary>
        public const string SecurityBinaryTampered = "Security.BinaryTampered";
        /// <summary>
        /// A copied or restored installation was detected by the single-use control token (TKT-003615): at least two
        /// collisions or two guided reactivations of one seat within 24 hours, a collision from another network than the
        /// live copy, or a reactivation refused because the licence's daily quota is exhausted. At most one alert per
        /// seat and 24 hours for each of the two causes. Alert only: never a ban nor a revocation (product decision).
        /// </summary>
        public const string SecurityCloneSuspected = "Security.CloneSuspected";
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
        { Triggers.SecurityThreatScoreRaised, "⚠️ Score de menace d'une IP (50, puis 100)" },
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
        { Triggers.SecurityLockBanned, "⛔ Verrou : matériel banni" },
        { Triggers.SecurityBinaryTampered, "🚨 Binaire modifié détecté (empreinte non approuvée)" },
        { Triggers.SecurityCloneSuspected, "⚠️ Copie d'installation suspectée (jeton de contrôle)" },
        { Triggers.SecurityLicenseServerSpoofed, "🚨 Activation par un serveur de licences local ou faux" },
        { Triggers.SecurityIpAutoBanned, "🔇 Bruit : IP de scanner bannie automatiquement" },
        { Triggers.SecurityOutdatedVersionBanned, "🔇 Bruit : ban ou déban de version trop ancienne" }
    };

    /// <summary>
    /// Routine, high-volume triggers (TKT-003668). They are sent to ntfy at low priority and a webhook listing one of
    /// them must list nothing else, so that noise can never bury a real alert on the same topic.
    /// </summary>
    public static readonly IReadOnlySet<string> NoiseTriggers = new HashSet<string>(StringComparer.Ordinal)
    {
        Triggers.SecurityIpAutoBanned,
        Triggers.SecurityOutdatedVersionBanned
    };

    /// <summary>
    /// Critical triggers sent through this service (TKT-003668): evidence of an attack on the software itself. They
    /// are sent to ntfy at maximum priority, like a level-5 security lock. Security-lock alerts are critical too but
    /// are delivered by <see cref="SecurityLockAlertOutboxProcessor"/>.
    /// </summary>
    public static readonly IReadOnlySet<string> CriticalTriggers = new HashSet<string>(StringComparer.Ordinal)
    {
        Triggers.SecurityBinaryTampered,
        Triggers.SecurityLicenseServerSpoofed
    };

    /// <summary>
    /// Checks the TKT-003668 separation rule for one webhook subscription: noise triggers and any other trigger may
    /// not share a destination. Entries are trimmed and compared ordinally, exactly as delivery matches them.
    /// </summary>
    /// <param name="enabledEvents">Subscribed trigger keys (the parsed CSV of <see cref="Webhook.EnabledEvents"/>).</param>
    /// <returns><see langword="true"/> when the list mixes at least one noise trigger with at least one other trigger.</returns>
    public static bool MixesNoiseWithAlerts(IEnumerable<string> enabledEvents)
    {
        var entries = enabledEvents.Select(entry => entry.Trim()).Where(entry => entry.Length > 0)
            .Distinct(StringComparer.Ordinal).ToList();
        return entries.Any(NoiseTriggers.Contains) && entries.Any(entry => !NoiseTriggers.Contains(entry));
    }

    /// <summary>
    /// ntfy priority sent with a trigger by <see cref="Notify"/> and <see cref="NotifyAsync"/>: 5 (max) for
    /// <see cref="CriticalTriggers"/>, 2 (low, silent) for noise, 4 (high) for
    /// security, activation, telemetry and update events, and none (ntfy default 3) otherwise. Security-lock alerts
    /// are delivered by <see cref="SecurityLockAlertOutboxProcessor"/> with their own level-based priority.
    /// </summary>
    /// <param name="trigger">Exact trigger key.</param>
    /// <returns>The ntfy priority as its decimal string, or <see langword="null"/> to keep the server default.</returns>
    public static string? NtfyPriorityFor(string trigger)
    {
        // Critical and noise sets are checked first: their keys also start with "Security." and must not fall
        // through to the generic high priority.
        if (CriticalTriggers.Contains(trigger)) return "5";
        if (NoiseTriggers.Contains(trigger)) return "2";
        if (trigger.StartsWith("Security", StringComparison.Ordinal)
            || trigger.StartsWith("Activation.", StringComparison.Ordinal)
            || trigger.StartsWith("Telemetry.", StringComparison.Ordinal)
            || trigger.StartsWith("Update.", StringComparison.Ordinal)) return "4";
        return null;
    }

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

    /// <summary>
    /// Maps a trigger to the ntfy tag shown as an emoji on the phone; critical alerts use "rotating_light" so they
    /// stand out, noise uses "mute" so it is recognisable at a glance. Unknown triggers get "bell".
    /// </summary>
    /// <param name="trigger">Exact trigger key.</param>
    private string GetEmojiForTrigger(string trigger) => trigger switch
    {
        Triggers.SecurityIpBanned => "no_entry",
        Triggers.SecurityLicenseServerSpoofed => "rotating_light",
        Triggers.SecurityIpAutoBanned => "mute",
        Triggers.SecurityOutdatedVersionBanned => "mute",
        Triggers.SecurityZombieDetected => "zombie",
        Triggers.SecurityHwidReuseDetected => "warning",
        Triggers.SecurityAuthFailure => "warning",
        Triggers.SecurityThreatScoreRaised => "warning",
        Triggers.SecurityEvidenceObserved => "warning",
        Triggers.SecurityBinaryTampered => "rotating_light",
        Triggers.SecurityCloneSuspected => "warning",
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

    /// <summary>
    /// Sends one event to every enabled webhook whose <see cref="Webhook.EnabledEvents"/> lists the exact trigger. ntfy
    /// URLs receive the plain message with title, tag and the priority of <see cref="NtfyPriorityFor"/> as query
    /// parameters; other URLs receive a JSON payload. Each webhook's last success or error is persisted.
    /// </summary>
    /// <remarks>
    /// Never throws: a failing webhook is logged and counted in <see cref="NotificationDeliveryResult.Failed"/>, and a
    /// global failure (database, configuration) is reported as at least one failure. No retry is made here; durable
    /// callers such as the security-lock outbox use their own retry policy.
    /// </remarks>
    /// <param name="trigger">Exact trigger key.</param>
    /// <param name="title">Notification title.</param>
    /// <param name="message">Notification body shown on the phone for ntfy.</param>
    /// <param name="data">Optional structured data, sent only to JSON webhooks.</param>
    /// <returns>Counts of matching, delivered and failed webhooks.</returns>
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
                        var priority = NtfyPriorityFor(trigger);
                        if (priority != null) query["priority"] = priority;
                        
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

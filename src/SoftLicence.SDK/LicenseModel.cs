using System.Globalization;
using System.Text.Json.Serialization;

namespace SoftLicence.SDK
{
    // L'énumération est supprimée au profit d'un système de Slugs dynamiques (ex: "PRO", "TRIAL_15D")

    public class LicenseModel
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string LicenseKey { get; set; } = string.Empty;
        public string CustomerName { get; set; } = string.Empty;
        public string CustomerEmail { get; set; } = string.Empty;
        
        public string TypeSlug { get; set; } = "STANDARD"; // Le slug choisi par l'admin

        /// <summary>
        /// Optional signed plugin/sub-product identifier. Standard product licenses omit this field when null.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? PluginId { get; set; }

        /// <summary>
        /// Optional signed plugin version. Standard product licenses omit this field when null.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? PluginVersion { get; set; }

        /// <summary>
        /// Optional minimum host application version required by this plugin license.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? MinAppVersion { get; set; }

        /// <summary>
        /// Optional signed feature allow-list for a plugin/sub-product license.
        /// Standard product licenses omit this field when null.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string[]? AllowedFeatures { get; set; }

        public string? Reference { get; set; } // Champ personnalisé (ex: ID Commande, Ref Client)
        
        public DateTime CreationDate { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string HardwareId { get; set; } = string.Empty;
        public Dictionary<string, string> Features { get; set; } = new();
        
        public string Signature { get; set; } = string.Empty;

        public bool IsExpired => ExpirationDate.HasValue && DateTime.UtcNow > ExpirationDate.Value;

        public T GetParam<T>(string key, T fallback = default!)
        {
            if (Features == null || !Features.TryGetValue(key, out var raw) || raw == null)
                return fallback;
            try
            {
                var t = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
                if (t == typeof(string))   return (T)(object)raw;
                if (t == typeof(int))      return (T)(object)int.Parse(raw, CultureInfo.InvariantCulture);
                if (t == typeof(long))     return (T)(object)long.Parse(raw, CultureInfo.InvariantCulture);
                if (t == typeof(double))   return (T)(object)double.Parse(raw, CultureInfo.InvariantCulture);
                if (t == typeof(bool))     return (T)(object)bool.Parse(raw);
                if (t == typeof(Guid))     return (T)(object)Guid.Parse(raw);
                return (T)Convert.ChangeType(raw, t, CultureInfo.InvariantCulture);
            }
            catch { return fallback; }
        }
    }
}

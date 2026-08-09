using System.Security.Cryptography;
using SoftLicence.SDK;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public interface ISignedLicenseFileService
{
    string Generate(License license, string hardwareId, IReadOnlyDictionary<string, string>? featureOverride = null);
}

public sealed class SignedLicenseFileService(EncryptionService encryption) : ISignedLicenseFileService
{
    public string Generate(License license, string hardwareId, IReadOnlyDictionary<string, string>? featureOverride = null)
    {
        var model = CreateModel(license, hardwareId, featureOverride);
        var encryptedPrivateKey = license.Product?.PrivateKeyXml
            ?? throw new InvalidOperationException("Signing product unavailable.");
        var privateKey = encryption.Decrypt(encryptedPrivateKey);
        if (privateKey == "ERROR_DECRYPTION_FAILED")
            throw new CryptographicException("Signing key unavailable.");
        return LicenseService.GenerateLicense(model, privateKey);
    }

    public static LicenseModel CreateModel(
        License license,
        string hardwareId,
        IReadOnlyDictionary<string, string>? featureOverride = null)
    {
        var model = new LicenseModel
        {
            Id = license.Id,
            LicenseKey = license.LicenseKey,
            CustomerName = license.CustomerName,
            CustomerEmail = license.CustomerEmail,
            TypeSlug = license.Type?.Slug ?? "STANDARD",
            Reference = license.Reference,
            CreationDate = license.CreationDate,
            ExpirationDate = license.ExpirationDate,
            HardwareId = hardwareId,
            Features = featureOverride?.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal)
                ?? BuildFeatures(license.Type?.CustomParams)
        };
        ApplyPluginMetadataFromReference(model);
        return model;
    }

    public static Dictionary<string, string> BuildFeatures(IEnumerable<LicenseTypeCustomParam>? customParams) =>
        customParams?.ToDictionary(parameter => parameter.Key, parameter => parameter.Value, StringComparer.Ordinal)
        ?? new Dictionary<string, string>(StringComparer.Ordinal);

    public static void ApplyPluginMetadataFromReference(LicenseModel model)
    {
        if (string.IsNullOrWhiteSpace(model.Reference))
            return;
        var parts = model.Reference.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2 || !string.Equals(parts[0], "plugin", StringComparison.OrdinalIgnoreCase))
            return;
        model.PluginId = parts[1];
        model.AllowedFeatures = ["*"];
        if (model.Features.TryGetValue("pluginVersion", out var pluginVersion) && !string.IsNullOrWhiteSpace(pluginVersion))
            model.PluginVersion = pluginVersion;
        if (model.Features.TryGetValue("minAppVersion", out var minimumVersion) && !string.IsNullOrWhiteSpace(minimumVersion))
            model.MinAppVersion = minimumVersion;
        foreach (var part in parts.Skip(2))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0 || separator == part.Length - 1)
                continue;
            var key = part[..separator];
            var value = part[(separator + 1)..];
            if (string.Equals(key, "pluginVersion", StringComparison.OrdinalIgnoreCase))
                model.PluginVersion = value;
            else if (string.Equals(key, "minAppVersion", StringComparison.OrdinalIgnoreCase))
                model.MinAppVersion = value;
            else if (string.Equals(key, "allowedFeatures", StringComparison.OrdinalIgnoreCase))
                model.AllowedFeatures = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .DefaultIfEmpty("*").ToArray();
        }
    }
}

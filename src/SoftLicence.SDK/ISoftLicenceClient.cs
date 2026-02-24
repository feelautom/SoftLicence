namespace SoftLicence.SDK
{
    public interface ISoftLicenceClient
    {
        /// <summary>
        /// Active une licence en ligne pour cette machine.
        /// </summary>
        Task<ActivationResult> ActivateAsync(string licenseKey, string appName, string? appId = null, string? appVersion = null, string? customerEmail = null, string? customerName = null);

        /// <summary>
        /// Effectue une demande de version d'essai (Auto-Trial) pour cette machine.
        /// </summary>
        Task<ActivationResult> RequestTrialAsync(string appName, string? appId = null, string typeSlug = "TRIAL", string? appVersion = null, string? customerEmail = null, string? customerName = null);

        /// <summary>
        /// Vérifie le statut d'une licence en ligne.
        /// </summary>
        Task<LicenseStatusResult> CheckStatusAsync(string licenseKey, string appName, string? appId = null);

        /// <summary>
        /// Valide une licence pour un matériel spécifique (Signature RSA + Hardware ID + Expiration).
        /// </summary>
        (bool IsValid, LicenseModel? License, string ErrorMessage) ValidateLocal(string licenseString, string hardwareId);

        /// <summary>
        /// Valide une licence pour un matériel spécifique de manière asynchrone.
        /// </summary>
        Task<(bool IsValid, LicenseModel? License, string ErrorMessage)> ValidateLocalAsync(string licenseString, string hardwareId);

        /// <summary>
        /// Valide une licence pour la machine actuelle.
        /// </summary>
        (bool IsValid, LicenseModel? License, string ErrorMessage) ValidateForCurrentMachine(string licenseString);

        /// <summary>
        /// Valide une licence pour la machine actuelle de manière asynchrone.
        /// </summary>
        Task<(bool IsValid, LicenseModel? License, string ErrorMessage)> ValidateForCurrentMachineAsync(string licenseString);

        /// <summary>
        /// Délie uniquement la machine actuelle de la licence (sans email).
        /// Utile pour un bouton "Transférer ce poste" dans l'application.
        /// </summary>
        Task<DeactivationResult> DeactivateAsync(string licenseKey, string appName, string? appId = null);

        /// <summary>
        /// Demande un code de reset envoyé par email. Délie tous les postes après confirmation.
        /// Utile si la machine est perdue ou inaccessible.
        /// </summary>
        Task<bool> ResetRequestAsync(string licenseKey, string appName, string? appId = null);

        /// <summary>
        /// Confirme le reset avec le code reçu par email. Délie tous les postes actifs.
        /// </summary>
        Task<bool> ResetConfirmAsync(string licenseKey, string appName, string resetCode, string? appId = null);
    }
}

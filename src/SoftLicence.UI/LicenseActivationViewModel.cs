using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SoftLicence.SDK;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace SoftLicence.UI
{
    public partial class LicenseActivationViewModel : ObservableObject
    {
        private readonly string _publicKeyXml;
        private readonly string _appName;
        private readonly string? _appVersion;
        private readonly string _appDataPath;
        private readonly ISoftLicenceClient _client;

        [ObservableProperty]
        private string licenseKey = string.Empty;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        [ObservableProperty]
        private bool isLicensed = false;

        [ObservableProperty]
        private bool isBusy = false;

        [ObservableProperty]
        private string licenseInfo = string.Empty;

        [ObservableProperty]
        private string currentHardwareId = string.Empty;

        private System.Timers.Timer? _validationTimer;

        public LicenseActivationViewModel(string publicKeyXml, string appName, string serverUrl = "http://localhost:5000", string? appVersion = null)
        {
            _publicKeyXml = publicKeyXml;
            _appName = appName;
            _appVersion = appVersion;
            _appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), appName, "license.lic");
            _client = new SoftLicenceClient(serverUrl, publicKeyXml);

            CurrentHardwareId = HardwareInfo.GetHardwareId();

            // Timer de vérification périodique (Toutes les 2 heures)
            _validationTimer = new System.Timers.Timer(TimeSpan.FromHours(2).TotalMilliseconds);
            _validationTimer.Elapsed += async (s, e) => await CheckOnlineStatus();
            _validationTimer.AutoReset = true;
        }

        public async Task InitializeAsync()
        {
            await LoadLicenseAsync();
            if (IsLicensed)
            {
                // Si on a chargé une licence locale, on vérifie direct si elle est toujours valide en ligne
                await CheckOnlineStatus();
            }
        }

        private void StartTimer() => _validationTimer?.Start();
        private void StopTimer() => _validationTimer?.Stop();

        [RelayCommand]
        public async Task Activate()
        {
            if (string.IsNullOrWhiteSpace(LicenseKey))
            {
                StatusMessage = "Veuillez entrer une clé.";
                return;
            }

            IsBusy = true;
            StatusMessage = "Vérification...";

            var input = LicenseKey.Trim();

            if (input.Length > 100)
            {
                await ValidateLocal(input);
            }
            else
            {
                await ActivateOnline(input);
            }

            if (IsLicensed)
            {
                await CheckOnlineStatus();
            }

            IsBusy = false;
        }

        private async Task ActivateOnline(string key)
        {
            var result = await _client.ActivateAsync(key, _appName, appVersion: _appVersion);

            if (result.Success && !string.IsNullOrEmpty(result.LicenseFile))
            {
                if (await ValidateLocal(result.LicenseFile))
                {
                    StatusMessage = "Activation réussie !";
                }
            }
            else
            {
                StatusMessage = $"Erreur : {result.ErrorMessage ?? result.ErrorCode.ToString()}";
            }
        }

        private async Task<bool> ValidateLocal(string licenseContent)
        {
            var result = await _client.ValidateForCurrentMachineAsync(licenseContent);

            if (result.IsValid && result.License != null)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    IsLicensed = true;
                    LicenseKey = result.License.LicenseKey;
                    StatusMessage = "Activation locale OK.";
                    UpdateLicenseInfo(result.License);
                });

                SaveLicense(licenseContent);
                StartTimer();
                return true;
            }
            else
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    StatusMessage = $"Erreur : {result.ErrorMessage}";
                    IsLicensed = false;
                });
                StopTimer();
                DeleteLocalLicense();
                return false;
            }
        }

        private async Task LoadLicenseAsync()
        {
            if (File.Exists(_appDataPath))
            {
                try
                {
                    var content = await File.ReadAllTextAsync(_appDataPath);
                    await ValidateLocal(content);
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Erreur chargement licence : {ex.Message}";
                }
            }
        }

        private async Task CheckOnlineStatus()
        {
            if (string.IsNullOrEmpty(LicenseKey)) return;

            var result = await _client.CheckStatusAsync(LicenseKey, _appName, appVersion: _appVersion);

            if (result.Success && result.Status == "VALID" && !string.IsNullOrEmpty(result.LicenseFile))
            {
                // Mettre à jour le fichier de licence local avec les paramètres frais du serveur
                await ValidateLocal(result.LicenseFile);
                return;
            }

            Application.Current.Dispatcher.Invoke(() =>
            {
                if (result.Success && result.Status == "VALID")
                {
                    if (!IsLicensed) IsLicensed = true;
                }
                else if (result.Success && (result.Status == "REVOKED" || result.Status == "HARDWARE_MISMATCH" || result.Status == "EXPIRED" || result.Status == "NOT_FOUND" || result.Status == "FREEMIUM_HWID_ALREADY_CONSUMED" || result.Status == "UPDATE_REQUIRED"))
                {
                    StatusMessage = result.Status switch
                    {
                        "NOT_FOUND" => "LICENCE INTROUVABLE. Accès bloqué.",
                        "FREEMIUM_HWID_ALREADY_CONSUMED" => "FREEMIUM DÉJÀ UTILISÉ SUR CETTE MACHINE. Accès bloqué.",
                        "UPDATE_REQUIRED" => "MISE À JOUR OBLIGATOIRE. Accès bloqué.",
                        _ => $"LICENCE RÉVOQUÉE ({result.Status}). Accès bloqué."
                    };
                    IsLicensed = false;
                    StopTimer();
                    DeleteLocalLicense();
                }
            });
        }

        private void DeleteLocalLicense()
        {
            try
            {
                if (File.Exists(_appDataPath)) File.Delete(_appDataPath);
            }
            catch { }
        }

        private void SaveLicense(string key)
        {
            try
            {
                var dir = Path.GetDirectoryName(_appDataPath);
                if (dir != null)
                {
                    if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    File.WriteAllText(_appDataPath, key);
                }
            }
            catch { }
        }

        private void UpdateLicenseInfo(LicenseModel model)
        {
            if (model == null) return;
            LicenseInfo = $"Client : {model.CustomerName}\n" +
                          $"Type : {model.TypeSlug}\n" +
                          $"Expire le : {(model.ExpirationDate.HasValue ? model.ExpirationDate.Value.ToString("d") : "Jamais")}";
        }
    }
}

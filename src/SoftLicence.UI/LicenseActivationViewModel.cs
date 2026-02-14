using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SoftLicence.SDK;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace SoftLicence.UI
{
    public partial class LicenseActivationViewModel : ObservableObject
    {
        private readonly string _publicKeyXml;
        private readonly string _appName;
        private readonly string _appDataPath;
        private readonly string _serverUrl;
        private readonly HttpClient _httpClient = new();

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

        public LicenseActivationViewModel(string publicKeyXml, string appName, string serverUrl = "http://localhost:5000")
        {
            _publicKeyXml = publicKeyXml;
            _appName = appName;
            _serverUrl = serverUrl;
            _appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), appName, "license.lic");

            CurrentHardwareId = HardwareInfo.GetHardwareId();

            // Timer de vérification périodique (Toutes les 2 heures)
            _validationTimer = new System.Timers.Timer(TimeSpan.FromHours(2).TotalMilliseconds);
            _validationTimer.Elapsed += async (s, e) => await CheckOnlineStatus();
            _validationTimer.AutoReset = true;
        }

        public async Task InitializeAsync()
        {
            await LoadLicenseAsync();
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
                ValidateLocal(input);
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
            try
            {
                var payload = new
                {
                    LicenseKey = key,
                    HardwareId = CurrentHardwareId,
                    AppName = _appName
                };

                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl.TrimEnd('/')}/api/activation", payload);

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ActivationResponse>();
                    if (result != null && !string.IsNullOrEmpty(result.LicenseFile))
                    {
                        if (ValidateLocal(result.LicenseFile))
                        {
                            StatusMessage = "Activation réussie !";
                        }
                    }
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    StatusMessage = $"Erreur : {error}";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Erreur réseau : {ex.Message}";
            }
        }

        private bool ValidateLocal(string licenseContent)
        {
            var result = LicenseService.ValidateLicense(licenseContent, _publicKeyXml, CurrentHardwareId);

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
                    ValidateLocal(content);
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

            var status = await LicenseService.CheckOnlineStatusAsync(_httpClient, _serverUrl, _appName, LicenseKey, CurrentHardwareId);

            Application.Current.Dispatcher.Invoke(() =>
            {
                if (status == "VALID")
                {
                    if (!IsLicensed) IsLicensed = true;
                }
                else if (status == "REVOKED" || status == "HARDWARE_MISMATCH" || status == "EXPIRED")
                {
                    StatusMessage = $"LICENCE RÉVOQUÉE ({status}). Accès bloqué.";
                    IsLicensed = false;
                    StopTimer();
                }
            });
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

        private class ActivationResponse
        {
            public string LicenseFile { get; set; } = string.Empty;
        }
    }
}

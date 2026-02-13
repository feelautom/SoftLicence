using System.Windows;
using SoftLicence.UI;

namespace SoftLicence.Samples.SimpleApp
{
    public partial class App : Application
    {
        // Clé Publique générée par le serveur pour le produit "SimpleAppSample"
        private const string SamplePublicKey = @"<RSAKeyValue><Modulus>uVFz8hFsno0sb5qT806FFyOGkszr7Rw5SR4I89C3PCVCXHB4TAq3CIQAKU83/PIHcs9vJqlqnbUEcGQkLuzE5vOIYelBhm0NZEvsD4QnljVr8+1brLgPhkPoevZxCgyYompO1xY/Mqv1N6gPo/AIr9jG1u56MSeY1u3xd5W9fifufjiHyl3s2aSt8VsVjObOz+fI8hb0yDnUcT463WC1ztyW+wZD+On1YJuWKuuj5jc+aMIGyHeJT7PzCkcgqAcqBXmQsSYTUeZPB2AWX2kEygaBWpmE/WwYz9Gm6Bs9COmEUBIhGsgoduazlS+KI5elaBrSFNqXq5dU9wutkLxzgBVndlWGeny8XTuSeIg+/py3Xeq1teCABFCdbe+kULYEwoOWVnGleMZGQsIjqe34fvr6TZ//75wJHhLHrUkok6rMIY7+geRbladTk0RUWMqzzhUdQ5U5FXpd3aKvHlxtHyINu9nZL4vtwApl6lWnvy9uWNocGlbTVH4Ezo92ndc2tlageNmC1/dCC5yNY9XQLdy/HJtERwxJZzChRCTnHehyklLiU+mRkSHqDnfXE0k9/0e3EpzNOB8D9jE9H1Fp7E8MWMySEnioFq6rUclXcbKdU7gGD6+kqPchwgAAl/CA0ya/3OV2TojRgYG1AM1f9+W8YHItCuo7t+8vQcaSpTU=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        
        private const string AppName = "SimpleAppSample"; 
        private const string ServerUrl = "http://localhost:5200"; 

        private LicenseActivationViewModel? _licenseVm;
        private MainWindow? _mainWindow;
        private Window? _activationWindow;

        protected override async void OnStartup(StartupEventArgs e)
        {
            try 
            {
                base.OnStartup(e);
                
                // Empecher la fermeture automatique quand la MainWindow se ferme (pour rouvrir l'activation)
                ShutdownMode = ShutdownMode.OnExplicitShutdown;

                _licenseVm = new LicenseActivationViewModel(SamplePublicKey, AppName, ServerUrl);
                
                // Abonnement aux changements d'état (Architecture Réactive)
                _licenseVm.PropertyChanged += OnLicenseStatusChanged;

                // Initialisation (Chargement + Check)
                await _licenseVm.InitializeAsync();

                // Premier affichage selon l'état initial
                UpdateAppState();
            }
            catch (System.Exception ex)
            {
                MessageBox.Show($"Erreur fatale au démarrage :\n{ex.ToString()}", "Erreur SoftLicence", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown();
            }
        }

        private void OnLicenseStatusChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(LicenseActivationViewModel.IsLicensed))
            {
                UpdateAppState();
            }
        }

        private void UpdateAppState()
        {
            if (_licenseVm == null) return;

            if (_licenseVm.IsLicensed)
            {
                // LICENCE VALIDE : On ouvre l'appli principale
                if (_activationWindow != null)
                {
                    _activationWindow.Close();
                    _activationWindow = null;
                }

                if (_mainWindow == null)
                {
                    _mainWindow = new MainWindow();
                    // Si l'utilisateur ferme la main window manuellement, on ferme tout
                    _mainWindow.Closed += (s, e) => Shutdown(); 
                    _mainWindow.Show();
                }
                else
                {
                    _mainWindow.Show(); // Au cas où elle était cachée
                    _mainWindow.Activate();
                }
            }
            else
            {
                // LICENCE INVALIDE/RÉVOQUÉE : On ferme l'appli et on demande l'activation
                if (_mainWindow != null)
                {
                    // On cache ou ferme la MainWindow. Ici on cache pour ne pas perdre l'état si reconnexion rapide
                    // Ou on ferme pour sécurité maximale. Choisissons Fermer pour l'exemple "Hard".
                    _mainWindow.Hide(); 
                }

                if (_activationWindow == null)
                {
                    _activationWindow = new Window
                    {
                        Title = "Licence requise - SimpleApp",
                        Content = new LicenseActivationView { DataContext = _licenseVm },
                        SizeToContent = SizeToContent.WidthAndHeight,
                        WindowStartupLocation = WindowStartupLocation.CenterScreen,
                        ResizeMode = ResizeMode.NoResize
                    };
                    
                    // Si l'utilisateur ferme la fenêtre d'activation sans activer, on quitte tout
                    _activationWindow.Closed += (s, e) => 
                    {
                        if (!_licenseVm.IsLicensed) Shutdown();
                        _activationWindow = null;
                    };
                    
                    _activationWindow.Show();
                }
                else
                {
                    _activationWindow.Activate();
                }
            }
        }
    }
}
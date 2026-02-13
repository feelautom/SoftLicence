using SoftLicence.UI;
using System.Windows;

namespace SoftLicence.Template
{
    public partial class App : Application
    {
        // REMPLACE CECI PAR LE CONTENU DE public_key.xml GÉNÉRÉ PAR KEYGEN
        public const string PublicKey = @"<RSAKeyValue><Modulus>...</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        private void Application_Startup(object sender, StartupEventArgs e)
        {
            // Initialisation du ViewModel de Licence
            var licenseVm = new LicenseActivationViewModel(PublicKey, "SoftLicenceApp");

            // On vérifie si une licence valide est déjà chargée
            if (licenseVm.IsLicensed)
            {
                ShowMainWindow();
            }
            else
            {
                // Sinon on montre la fenêtre d'activation
                var activationWindow = new Window
                {
                    Title = "Activation Requise",
                    Content = new LicenseActivationView { DataContext = licenseVm },
                    Width = 450,
                    Height = 500,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen
                };

                // On écoute le changement d'état pour fermer et lancer l'app si activé
                licenseVm.PropertyChanged += (s, args) =>
                {
                    if (args.PropertyName == nameof(LicenseActivationViewModel.IsLicensed) && licenseVm.IsLicensed)
                    {
                        activationWindow.Close();
                        ShowMainWindow();
                    }
                };

                activationWindow.ShowDialog();
                
                // Si on ferme la fenêtre sans activer, on kill l'app (sauf si ShowMainWindow a été appelé)
                if (!licenseVm.IsLicensed)
                {
                    Shutdown();
                }
            }
        }

        private void ShowMainWindow()
        {
            var main = new MainWindow();
            main.Show();
        }
    }
}

# 🛡️ Guide : Protéger un nouveau logiciel

Ce guide explique pas à pas comment transformer un logiciel WPF standard en une version protégée par SoftLicence.

## Étape 1 : Préparation sur le Serveur
1. Connectez-vous sur votre dashboard SoftLicence.
2. Allez dans l'onglet **Produits**.
3. Cliquez sur "Créer" pour votre nouveau logiciel (ex: "MyTool v1").
4. **Copiez la Clé Publique XML** (celle qui commence par `<RSAKeyValue>`). Vous en aurez besoin à l'étape 3.

## Étape 2 : Ajout des bibliothèques
Dans votre projet Visual Studio (WPF) :
1. Ajoutez une référence aux projets (ou DLLs) :
   - `SoftLicence.Core` (Moteur cryptographique)
   - `SoftLicence.UI` (Interfaces d'activation)
2. Ajoutez le package NuGet `CommunityToolkit.Mvvm` (utilisé par l'UI).

## Étape 3 : Câblage du démarrage
Ouvrez `App.xaml.cs` et remplacez le contenu par une machine à états robuste :

```csharp
public partial class App : Application
{
    private const string MyPublicKey = @"<RSAKeyValue>...COLLEZ ICI VOTRE CLE...</RSAKeyValue>";
    private LicenseActivationViewModel _vm;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        _vm = new LicenseActivationViewModel(MyPublicKey, "MyTool", "https://votre-serveur.fr");
        _vm.PropertyChanged += (s, args) => {
            if (args.PropertyName == nameof(_vm.IsLicensed) && !_vm.IsLicensed) {
                // Licence révoquée pendant l'utilisation !
                MessageBox.Show("Votre licence n'est plus valide.");
                Shutdown();
            }
        };

        await _vm.InitializeAsync();

        if (_vm.IsLicensed) {
            new MainWindow().Show();
        } else {
            var win = new Window { 
                Content = new LicenseActivationView { DataContext = _vm },
                SizeToContent = SizeToContent.WidthAndHeight 
            };
            win.ShowDialog();
            if (_vm.IsLicensed) new MainWindow().Show(); else Shutdown();
        }
    }
}
```

## Étape 4 : Blindage (Obfuscation)
Il est inutile de mettre une licence si n'importe qui peut la supprimer en modifiant une ligne de code.
1. Ajoutez le package NuGet `Obfuscar`.
2. Créez un fichier `obfuscar.xml` à la racine de votre projet (voir exemple dans `samples/SoftLicence.Samples.SimpleApp/obfuscar.xml`).
3. Configurez-le pour masquer votre DLL principale et les DLLs de SoftLicence.
4. **Compilez toujours en mode Release** pour que la protection soit appliquée.

### Comprendre les résultats de l'obfuscation
Après la compilation, un dossier `Obfuscated` est créé dans votre dossier de sortie (`bin/Release/...`). 
- **DLLs protégées** : Ce sont les fichiers que vous devez distribuer.
- **Mapping.txt** : C'est votre "Pierre de Rosette". Il contient la correspondance entre les noms originaux (ex: `ValidateLicense`) et les noms obfusqués (ex: `a`). 
  **Gardez ce fichier précieusement**, il est indispensable pour comprendre les rapports d'erreurs (stacktraces) envoyés par vos clients.

## Étape 5 : Livraison
Distribuez à votre client :
1. Votre `.exe` et ses DLLs (contenus dans le dossier `Obfuscated`).
2. Pour activer son logiciel, le client devra vous demander une clé. 
3. Générez cette clé dans l'onglet **Logiciels** du serveur et envoyez-la lui.


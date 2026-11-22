# 💻 Documentation Client (SoftLicence.UI & Core)

La partie client permet de verrouiller l'accès à un logiciel WPF et de gérer la communication sécurisée avec le serveur.

## 🛠️ Intégration Technique (Cycle de vie)

Pour une protection robuste, l'intégration doit se faire dans le fichier `App.xaml.cs` avant même l'affichage de la fenêtre principale.

### 1. Initialisation Asynchrone
Le système utilise désormais une approche asynchrone pour ne pas bloquer l'UI lors du chargement des fichiers ou des appels réseau.

```csharp
protected override async void OnStartup(StartupEventArgs e)
{
    base.OnStartup(e);
    
    // 1. Création du ViewModel
    var vm = new LicenseActivationViewModel(PUBLIC_KEY, "NomProduit", "https://url-serveur.fr");
    
    // 2. Chargement et vérification (Offline + Online)
    await vm.InitializeAsync();

    // 3. Orchestration des fenêtres
    if (vm.IsLicensed) {
        new MainWindow().Show();
    } else {
        new Window { Content = new LicenseActivationView { DataContext = vm } }.ShowDialog();
    }
}
```

### 2. Monitoring Live (Timer)
Le `LicenseActivationViewModel` intègre un **Timer automatique** (toutes les 2 heures par défaut).
- Si la licence est révoquée sur le serveur pendant que l'utilisateur travaille, la propriété `IsLicensed` passera à `false`.
- **Architecture Réactive** : Il est recommandé de s'abonner à `PropertyChanged` dans votre `App.xaml.cs` pour réagir instantanément et fermer le logiciel si la licence saute en cours d'utilisation.

### 3. Auto-Activation (Mode Community / Trial)
Activation automatique au premier lancement. Pour les types récurrents (ex: Community), le renouvellement est automatique à expiration.

**Endpoint** : `POST /api/activation/trial`
**Payload** :
```json
{
  "HardwareId": "ABC-123-HID",
  "AppName": "VotreLogiciel",
  "TypeSlug": "YOUR_APP_NAME-COMMUNITY"
}
```

**Comportement :**
- **Type non ouvert à l'essai public** (réglage `AllowPublicTrial` du type, faux par défaut) : refus `LICENSE_TYPE_PUBLIC_TRIAL_NOT_ALLOWED`
- **Première demande** : crée une licence (durée = `DefaultDurationDays` du type)
- **HardwareId connu, licence active du type demandé** : renvoi de la licence existante (recovery) ; l'e-mail et le nom envoyés sont ignorés
- **HardwareId connu, licence en cours d'un autre type, ou licence payante** : refus `HARDWARE_ALREADY_LICENSED` ; récupérer la licence avec sa clé
- **HardwareId connu, licence expirée renouvelable** : renouvellement automatique (+30 jours)
- **HardwareId connu, licence révoquée** : `403 Forbidden`
- **HardwareId connu, licence du type demandé expirée et non renouvelable** : refus `LICENSE_EXPIRED` (le client reste restreint)

## 🛡️ Protection contre le Piratage

### Obfuscation (Obfuscar)
Le code .NET est très facile à décompiler. Pour protéger votre logique de licence :
1. Ajoutez le package NuGet `Obfuscar`.
2. Configurez le fichier `obfuscar.xml`.
3. Assurez-vous que l'obfuscation est exécutée en mode **Release**. 
Cela rendra votre DLL indéchiffrable par des outils comme `dnSpy`.

### Verrouillage Matériel (Hardware ID)
Le `HardwareID` est une empreinte digitale unique du PC du client. 
- Une licence activée sur le "PC A" ne pourra pas être copiée sur le "PC B". 
- Le serveur renverra une erreur `HARDWARE_MISMATCH`.
- **Réinitialisation** : L'administrateur peut réinitialiser ce lien via le dashboard ("Reset HWID"). Le client peut également le faire lui-même (Self-Service) si votre site implémente les routes de réinitialisation par email du serveur.

## 📁 Stockage local & Sécurité SDK



Le fichier de licence signé est stocké ici :

`%AppData%/Local/[NomDeLApp]/license.lic`

Il s'agit d'un JSON cryptographiquement signé et encodé en Base64.



### Comportement Strict du SDK

Pour garantir une protection maximale, le SDK applique les règles suivantes :

1.  **Vérification au démarrage** : Contrairement aux systèmes classiques, SoftLicence effectue un appel réseau **immédiat** dès le lancement si une licence locale est trouvée. Si le serveur renvoie `REVOKED` ou `NOT_FOUND` (licence supprimée), l'accès est coupé instantanément.

2.  **Suppression physique** : Si le serveur invalide la licence (expiration, révocation ou suppression), le SDK **supprime physiquement** le fichier `license.lic` du disque. L'utilisateur ne peut donc pas "tricher" en coupant internet après un premier rejet.

3.  **Arrêt Net** : En cas de perte de licence (révocation à distance), l'application d'exemple est configurée pour fermer toutes ses fenêtres, ce qui arrête immédiatement tous les processus de fond (télémétrie, calculs, etc.).

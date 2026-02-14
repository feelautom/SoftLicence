# Proposition : SDK Officiel SoftLicence

Cette proposition vise à transformer la logique de licence actuelle en un SDK industriel robuste, réutilisable par toutes vos applications présentes et futures.

## 1. Standardisation de l'ID Matériel (Hardware ID)

Pour supprimer la confusion actuelle entre le format long Base64 et le format court UI, le SDK imposera le format **16 caractères hexadécimaux** (ex: `5015F8FFD54606CE`).

### Algorithme unifié (C#) :
```csharp
public static string GetMachineId() {
    var rawId = GetCpuId() + GetDiskSerial() + GetMotherboardId();
    using var sha256 = SHA256.Create();
    var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawId));
    // On ne garde que les 16 premiers caractères hexa (64 bits de sécurité)
    return BitConverter.ToString(hash).Replace("-", "").Substring(0, 16);
}
```

## 2. Structure du SDK (.NET Standard 2.0)

Le SDK sera composé de 3 briques principales :

### A. `SoftLicence.Core.Hardware`
Fournit l'identité unique de la machine de manière constante sur tous les OS.

### B. `SoftLicence.Core.Client` (L'interface développeur)
Une classe `LicenceManager` simple pour l'intégration :
```csharp
var client = new LicenceManager("https://votre-serveur.fr");

// 1. Activation
var result = await client.ActivateAsync("CLE-CLIENT-123");

// 2. Vérification rapide au démarrage (Offline + Online)
if (client.IsAuthorized) {
    // Lancer l'app
}
```

### C. `SoftLicence.Core.Security`
Gère la validation locale des fichiers `.lic` via cryptographie asymétrique (RSA). Le SDK embarque votre clé publique pour vérifier que le fichier n'a pas été falsifié.

## 3. Guide d'Intégration (Exemple pour un logiciel tiers)

Le développeur du logiciel tiers n'aura qu'à faire :

1. Ajouter la référence `SoftLicence.Core.dll`.
2. Initialiser le client dans son `Main()` :
```csharp
SoftLicenceProvider.Initialize(new LicenceOptions {
    AppId = "MonLogicielPro",
    ServerUrl = "https://softlicence.feelautom.fr"
});
```
3. Vérifier l'état n'importe où dans son code :
```csharp
if (SoftLicenceProvider.Current.Level == LicenceLevel.Pro) {
    // Activer fonctions premium
}
```

## 4. Impact sur SIPLine
Dès que ce SDK sera prêt, nous remplacerons le code "maison" de SIPLine par ce SDK officiel. L'ID affiché dans l'onglet "À Propos" sera strictement le même que celui envoyé au serveur.

---
**Standard validé :** ID Matériel = 16 caractères hexadécimaux (ex: 5015F8FFD54606CE).

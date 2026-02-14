# SoftLicence SDK - Guide d'Intégration

Ce SDK (`SoftLicence.SDK`) est la bibliothèque standard pour intégrer le système de licence dans vos applications .NET (WPF, Console, ASP.NET, MAUI, etc.).

## 📦 Installation

1.  Ajouter la référence au projet `SoftLicence.SDK.csproj` ou à la DLL compilée.
2.  Assurez-vous que les dépendances (System.Management, System.Text.Json) sont présentes.

## 🔑 Identité Machine (Hardware ID)

L'ID matériel est désormais standardisé sur **16 caractères hexadécimaux** (ex: `5015F8FFD54606CE`). C'est le même format utilisé par le serveur et l'installeur.

```csharp
using SoftLicence.SDK;

// Récupérer l'ID unique de la machine
string myHwId = HardwareInfo.GetHardwareId();
Console.WriteLine($"Mon ID : {myHwId}");
```

## 🌐 Utilisation du Client (API)

La classe `SoftLicenceClient` simplifie les interactions avec le serveur.

```csharp
using SoftLicence.SDK;

var client = new SoftLicenceClient("http://votre-serveur-licence.com");

try 
{
    // 1. Activer une licence
    // Retourne le fichier de licence signé (XML/JSON) si succès, sinon lève une exception.
    string licenseFile = await client.ActivateAsync("VOTRE-CLE-LICENCE", "NomDeVotreApp", "1.0.0");
    
    // Sauvegarder 'licenseFile' localement (ex: license.lic)
    File.WriteAllText("license.lic", licenseFile);
}
catch (Exception ex)
{
    Console.WriteLine($"Erreur d'activation : {ex.Message}");
}

// 2. Vérifier l'état (Heartbeat / Online Check)
// Retourne "VALID", "REVOKED", "EXPIRED" ou "SERVER_ERROR"
string status = await client.CheckStatusAsync("VOTRE-CLE-LICENCE", "NomDeVotreApp");

if (status == "VALID") { /* Continuer */ }
```

## 🔒 Validation Locale (Offline)

Pour valider le fichier `.lic` sans internet (au démarrage de l'app) :

```csharp
using SoftLicence.SDK;

string publicKey = "<RSAKeyValue>...</RSAKeyValue>"; // Votre clé publique
string licenseContent = File.ReadAllText("license.lic");

var (isValid, licenseModel, error) = LicenseService.ValidateLicense(licenseContent, publicKey, HardwareInfo.GetHardwareId());

if (isValid)
{
    Console.WriteLine($"Licence valide pour : {licenseModel.CustomerName}");
    Console.WriteLine($"Expiration : {licenseModel.ExpirationDate}");
}
else
{
    Console.WriteLine($"Erreur : {error}"); // Ex: "Signature invalide", "Mauvaise machine"
}
```

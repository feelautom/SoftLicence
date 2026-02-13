# API de Télémétrie SoftLicence

Cette documentation décrit les spécifications de l'API de télémétrie intégrée au serveur SoftLicence.

## 1. Informations Générales

*   **Format des données** : JSON
*   **Méthode HTTP** : `POST`
*   **Content-Type** : `application/json`
*   **Authentification** : Basée sur le `HardwareId` (inclus dans chaque requête).

## 2. Structure Commune (Header)

Chaque requête envoyée par l'application contient les champs suivants :

| Champ | Type | Description |
| :--- | :--- | :--- |
| `Timestamp` | DateTime (UTC) | Date et heure de l'événement. |
| `HardwareId` | String | Identifiant unique du PC (généré par SoftLicence). |
| `AppName` | String | Nom de l'application (ex: "YourApp"). |
| `Version` | String | Version de l'application YourApp (ex: "1.0.4"). |
| `EventName` | String | Nom de l'événement (ex: "AppStarted", "Error"). |

---

## 3. Endpoints Spécifiques

### 3.1. Événements simples
**URL** : `/api/telemetry/event`

Utilisé pour le suivi du cycle de vie et de l'utilisation.

**Payload :**
```json
{
  "Timestamp": "2026-02-10T23:45:00Z",
  "HardwareId": "XXXX-XXXX-XXXX-XXXX",
  "AppName": "YourApp",
  "Version": "1.0.4",
  "EventName": "PluginsLoaded",
  "Properties": {
    "Count": "2",
    "PluginIds": "YourApp.Plugin.HelloWorld,YourApp.Plugin.Recordings"
  }
}
```

**Événements envoyés par l'app :**
*   `AppStarted` : Au lancement réussi de l'hôte.
*   `PluginsLoaded` : Après le scan des dossiers plugins.
*   `LicenseActivated` : Après une activation réussie (contient la clé dans `Properties`).

---

### 3.2. Rapports de Diagnostic
**URL** : `/api/telemetry/diagnostic`

Envoyé à chaque exécution du diagnostic réseau (Pre-flight).

**Payload :**
```json
{
  "Timestamp": "2026-02-10T23:45:00Z",
  "HardwareId": "XXXX-XXXX-XXXX-XXXX",
  "Version": "1.0.4",
  "EventName": "DiagnosticResult",
  "Score": 85,
  "Results": [
    {
      "ModuleName": "Windows Firewall",
      "Success": true,
      "Severity": "Info",
      "Message": "YourApp est autorisé."
    },
    {
      "ModuleName": "SIP ALG",
      "Success": false,
      "Severity": "Error",
      "Message": "SIP ALG détecté sur le routeur."
    }
  ],
  "Ports": [
    { "Name": "Signalisation SIP", "ExternalPort": 15060, "Protocol": "UDP" },
    { "Name": "Audio RTP", "ExternalPort": 10000, "Protocol": "UDP" }
  ]
}
```

---

### 3.3. Erreurs et Crashs
**URL** : `/api/telemetry/error`

Captures des exceptions non gérées et des échecs critiques.

**Payload :**
```json
{
  "Timestamp": "2026-02-10T23:45:00Z",
  "HardwareId": "XXXX-XXXX-XXXX-XXXX",
  "Version": "1.0.4",
  "EventName": "Error",
  "ErrorType": "FatalUnhandled",
  "Message": "Object reference not set to an instance of an object.",
  "StackTrace": "at YourApp.UI.App.OnStartup..."
}
```

**Types d'erreurs envoyés :**
*   `FatalUnhandled` : Crash global de l'application.
*   `UiCrash` : Erreur dans la boucle de rendu WPF.
*   `SipRegistrationFailed` : Échec de connexion au serveur SIP.
*   `LicenseNetworkError` : Impossible de joindre le serveur de licence.

---

## 4. Activation Automatique (Trial)

**URL** : `/api/activation/trial`

Utilisé au premier lancement de l'application si aucune licence n'est présente localement.

**Payload :**
```json
{
  "HardwareId": "XXXX-XXXX-XXXX-XXXX",
  "AppName": "YourApp",
  "TypeSlug": "TRIAL"
}
```

**Réponse (Success 200) :**
```json
{
  "LicenseFile": "BASE64_SIGNED_DATA..."
}
```

---

## 5. Recommandations pour le Serveur

1.  **Dédoublonnage** : Utilisez le `HardwareId` pour ne pas compter plusieurs fois le même utilisateur dans vos statistiques quotidiennes.
2.  **Alertes** : Configurez une alerte (email ou Discord/Slack) si le endpoint `/error` reçoit plus de X messages en une heure (indique un bug généralisé).
3.  **Stockage** : Une base de données NoSQL (MongoDB) ou une simple table SQL avec un champ JSON est recommandée pour stocker les `Results` du diagnostic qui sont variables.
4.  **Réponse** : Le serveur doit répondre rapidement (HTTP 200 ou 202) pour ne pas ralentir le client, même s'il traite les données de manière asynchrone.

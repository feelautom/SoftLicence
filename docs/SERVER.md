# 🖥️ Documentation Serveur (SoftLicence.Server)

Le serveur SoftLicence fait office d'**Autorité de Certification** et de **Console d'Administration**. Il gère le cycle de vie des produits, des licences et assure la traçabilité des accès.

## 🚀 Déploiement (Production)

Le serveur est entièrement conteneurisé. Pour le déployer sur un VPS (via Docker ou Docker direct) :

1. Poussez votre code sur votre dépôt Git.
2. Utilisez le fichier `docker/docker-compose.yml`.
3. Configurez les **Variables d'Environnement** dans Docker :

| Variable | Description | Exemple |
| :--- | :--- | :--- |
| `AdminSettings__Username` | Identifiant Admin Web | `admin` |
| `AdminSettings__Password` | Mot de passe Admin Web | `votre_password` |
| `AdminSettings__ApiSecret` | Clé pour l'API Admin (CLI) | `secret_tres_long` |
| `AdminSettings__LoginPath` | URL secrète de connexion | `mon-entree-secrete` |
| `AdminSettings__AllowedIps` | WhiteList IPs (Séparées par virgules) | `91.x.x.x, 127.0.0.1` |
| `SmtpSettings__Host` | Serveur SMTP | `smtp.gmail.com` |
| `SmtpSettings__Port` | Port SMTP | `587` |
| `SmtpSettings__Username` | User SMTP | `contact@EXAMPLE.COM` |
| `SmtpSettings__Password` | Pass SMTP | `app_password` |
| `SmtpSettings__FromEmail` | Email expéditeur | `noreply@EXAMPLE.COM` |
| `SmtpSettings__FromName` | Nom expéditeur | `YOUR_COMPANY_NAME` |
| `FORCE_DB_RESET` | Supprimer et recréer la BDD | `true` ou `false` |

## 📡 API Publique (Activation)

### 1. Activation (`POST /api/activation`)
Enregistre un produit sur une machine.

**Payload :**
```json
{
  "LicenseKey": "XXXX-XXXX-XXXX-XXXX",
  "HardwareId": "FINGERPRINT_DU_PC",
  "AppName": "YOUR_APP_NAME",
  "AppVersion": "1.2.3"
}
```
*   `AppVersion` (Optionnel) : Si renseigné, le serveur vérifie la compatibilité avec le masque `AllowedVersions` de la licence.

**Réponses :**
*   `200 OK` : Contient le fichier de licence signé.
*   `400 Bad Request` : 
    *   "Clé de licence invalide".
    *   "Licence expirée".
    *   "Cette licence n'est pas valide pour la version X.Y.Z".
    *   "Nombre maximum d'activations atteint (X)".

### 2. Auto-Trial / Community (`POST /api/activation/trial`)
Activation automatique au premier lancement, ou renouvellement d'une licence récurrente (Community).

**Payload :**
```json
{
  "HardwareId": "FINGERPRINT_DU_PC",
  "AppName": "YOUR_APP_NAME",
  "TypeSlug": "SIPLINE-COMMUNITY",
  "AppVersion": "1.2.3"
}
```

**Comportement quand une licence existe déjà pour ce HardwareId :**

| Cas | Résultat |
|---|---|
| `IsActive = false` (révoquée) | `403 Forbidden` |
| `IsRecurring = true` + expirée | Renouvellement auto : `ExpirationDate += DefaultDurationDays`, historique `RENEWED`, renvoi licence signée |
| Sinon (active ou expirée non-récurrente) | Renvoi tel quel (le client gère le blocage) |

**Première demande (HardwareId inconnu) :** crée une licence avec la durée `DefaultDurationDays` du type.

**Alternative :** Une clé se terminant par `-FREE-TRIAL` dans `POST /api/activation` déclenche le même flux.

### 3. Système de Reset (Self-Service)
Le serveur permet aux clients de délier eux-mêmes leur licence de leur matériel (Reset HWID) via une double validation par email :
1. Demande de code via `/api/activation/reset-request`.
2. Validation via `/api/activation/reset-confirm` avec le code à 6 chiffres reçu.

## 🛠️ Fonctionnalités Avancées

### Système Multi-Postes (Seats)
Chaque licence possède un champ `MaxSeats` (Défaut: 1).
*   Lorsqu'un nouveau `HardwareId` s'active, un "siège" est consommé.
*   Si le même `HardwareId` demande une nouvelle activation, il s'agit d'un **Recovery** (pas de siège consommé).
*   Si la limite est atteinte, l'activation est refusée.

### Contrôle de Version
Les licences et types de licences supportent le champ `AllowedVersions`.
*   `*` : Toutes les versions autorisées (Défaut).
*   `1.*` : Uniquement les versions majeures 1.
*   `2.1.0` : Uniquement cette version exacte.

### Recurring subscription renewal

Use the provider-authenticated administration endpoint to extend a license whose type is marked as recurring.

**Endpoint:** `POST /api/admin/licenses/{licenseKey}/renew`

**Header:** `X-Admin-Secret: <YOUR_SECRET>`

**Payload:**
```json
{
  "transactionId": "STRIPE_ID_12345",
  "reference": "ORDER_#99",
  "targetExpirationUtc": "2027-01-31T00:00:00Z"
}
```

`targetExpirationUtc` must be UTC and is mutually exclusive with `daysToAdd`. If neither is present, the license type's default duration applies.

The transaction identifier is opaque and exact. The server binds it to a versioned SHA-256 fingerprint of the complete canonical request, including optional-property presence. Only an identical retry returns the frozen result. Changing or omitting a reference, duration, or exact target returns HTTP `409` with `transaction_payload_conflict`.

Historical renewal rows that predate the fingerprint cannot prove request equality. They fail closed with HTTP `409`:

```json
{
  "error": "legacy_transaction_unverified",
  "retryable": false
}
```

There is no compatibility window and no fingerprint backfill for historical rows.

## 🛡️ Forteresse : Sécurité Active & Anti-Bot

SoftLicence intègre un système de défense proactive adaptatif pour protéger votre serveur des scans et attaques par force brute.

### 1. Système de Scoring Adaptatif
Le serveur attribue un "Score de Menace" à chaque IP suspecte selon la gravité de l'action :
- **Erreur 404 standard** : +2 points.
- **Scan intentionnel** (Patterns suspects : .env, wp-admin...) : +20 points.
- **Échec Auth** (Tentative de login admin) : +50 points.

### 2. Quarantaine & Throttling (Ralentissement)
Au lieu de bannir immédiatement, le serveur applique une sanction progressive :
- **Score 0 à 99** : Vitesse de réponse normale.
- **Score 100 à 199 (Quarantaine)** : Le serveur impose un délai artificiel de **5 à 15 secondes** avant chaque réponse. Durant cette phase, la pénalité pour un 404 remonte à **10 points**.
- **Score 200+** : Bannissement strict (403 Forbidden).

### 3. Surtaxe de Récidive (Punition Géométrique)
Si une IP a déjà été bannie par le passé, le système devient "allergique" à sa présence :
- **Algorithme** : `Points = ScoreDeBase * (NombreDeBannissements * 2)`.
- Plus un attaquant revient, plus vite il est banni (ses points sont multipliés par 2, 4, 6...).

### 4. Tolérance Zéro
Pour les multirécidivistes lourds (**5 bannissements historiques ou plus**), le système passe en mode "Basta" :
- Le moindre faux pas (404, scan) entraîne un bannissement **immédiat** (200 points appliqués d'un coup).

### 5. Détection de Fraude (Zombies)
Le système surveille le partage de licences :
- Si un même `HardwareID` est utilisé par plus de **5 adresses IP différentes** en 24h, la licence associée est automatiquement révoquée pour "Fraude suspecte".

### 6. Immunité Admin (Whitelist)
Les adresses IP renseignées dans `AdminSettings:AllowedIps` ou les sessions authentifiées sont totalement immunisées contre le scoring de menace et la détection zombie.

## 📊 Surveillance & Audit

### Journal d'Audit Total
Grâce à un Middleware dédié, le serveur enregistre **chaque requête HTTP** reçue avec l'IP réelle, la performance, et les données reçues/envoyées (corps de requête et réponse).

### Dashboard Analytics
Le tableau de bord fournit une vue consolidée de l'état du parc, de l'activité API et du taux d'erreur global.

## 🗄️ Base de Données & Migrations

Le serveur utilise **PostgreSQL** en production et **InMemory** pour les tests.
- **Migrations EF Core** : Le schéma évolue sans perte de données.
- **Auto-Update** : Le serveur tente d'appliquer les migrations automatiquement au démarrage (avec logique de retry).

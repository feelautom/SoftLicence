# 🖥️ Documentation Serveur (SoftLicence.Server)

Le serveur SoftLicence fait office d'**Autorité de Certification** et de **Console d'Administration**. Il gère le cycle de vie des produits, des licences et assure la traçabilité des accès.

## 🚀 Déploiement (Production)

Le serveur est entièrement conteneurisé. Pour le déployer sur un VPS :

1. Poussez votre code sur votre dépôt Git.
2. Utilisez le fichier `docker/docker-compose.yml`.
3. Configurez les **Variables d'Environnement** :

| Variable | Description | Exemple |
| :--- | :--- | :--- |
| `AdminSettings__Username` | Identifiant Admin Web | `admin` |
| `AdminSettings__Password` | Mot de passe Admin Web | `votre_password` |
| `AdminSettings__ApiSecret` | Clé pour l'API Admin (CLI) | `secret_tres_long` |
| `AdminSettings__LoginPath` | URL secrète de connexion | `mon-entree-secrete` |
| `AdminSettings__AllowedIps` | WhiteList IPs (Séparées par virgules) | `91.x.x.x, 127.0.0.1` |
| `SmtpSettings__Host` | Serveur SMTP | `smtp.gmail.com` |
| `SmtpSettings__Port` | Port SMTP | `587` |
| `SmtpSettings__Username` | User SMTP | `contact@example.com` |
| `SmtpSettings__Password` | Pass SMTP | `app_password` |
| `SmtpSettings__FromEmail` | Email expéditeur | `noreply@example.com` |
| `SmtpSettings__FromName` | Nom expéditeur | `YourCompany` |
| `FORCE_DB_RESET` | Supprimer et recréer la BDD | `true` ou `false` |

## 📡 API Publique (Activation)

### 1. Activation (`POST /api/activation`)
Enregistre un produit sur une machine.

**Payload :**
```json
{
  "LicenseKey": "XXXX-XXXX-XXXX-XXXX",
  "HardwareId": "FINGERPRINT_DU_PC",
  "AppName": "YourApp",
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

### 2. Auto-Trial (Activation sans clé)
Le serveur permet une activation automatique au premier lancement via `/api/activation/trial` ou en utilisant une clé se terminant par `-FREE-TRIAL`.
- **Fonctionnement** : Si le matériel est inconnu, le serveur crée une licence avec la durée définie dans les paramètres du type de licence.

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

### Gestion des Abonnements (Renouvellement)
Pour les types de licences marqués comme **Récurrent (Abonnement)**, vous pouvez prolonger la durée de validité via l'API d'administration.

**Endpoint** : `POST /api/admin/licenses/{licenseKey}/renew`  
**Header** : `X-Admin-Secret: <VOTRE_SECRET>`  
**Payload** :
```json
{
  "TransactionId": "STRIPE_ID_12345",
  "Reference": "COMMANDE_#99"
}
```

## 🛡️ Forteresse : Sécurité Active & Anti-Bot

SoftLicence intègre un système de défense proactive pour protéger votre serveur des scans et attaques par force brute.

### 1. Threat Scoring & Auto-Ban
Le serveur attribue un "Score de Menace" à chaque IP suspecte :
- **Erreur 404 (Scan)** : +10 points.
- **Échec Auth (Login)** : +50 points.
- **Bannissement** : Si une IP atteint **100 points**, elle est bannie pour 24h.

### 2. Alertes Temps-Réel (ntfy)
Le serveur peut envoyer des notifications immédiates lors d'événements critiques (Bannissement, tentative de fraude).

### 3. Intelligence Geo-IP & ISP
Chaque requête dans le journal d'audit est enrichie avec le pays et le fournisseur d'accès (ISP).

### 4. Nettoyage Automatique
Un service de fond purge périodiquement les logs obsolètes :
*   Audit : 30 jours.
*   Télémétrie : 90 jours.
*   Suivi d'une optimisation SQLite (`VACUUM`).

## 📊 Surveillance & Audit

### Journal d'Audit Total
Grâce à un Middleware dédié, le serveur enregistre **chaque requête HTTP** reçue avec l'IP réelle, la performance et la version de l'application cliente.

### Dashboard Analytics
Le tableau de bord fournit une vue consolidée de l'état du parc et de l'activité.

## 🗄️ Base de Données & Migrations

Le serveur utilise **SQLite**.
- **Migrations EF Core** : Le schéma évolue sans perte de données.
- **Auto-Update** : Le serveur applique les migrations automatiquement au démarrage.

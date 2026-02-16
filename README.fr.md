# 🛡️ SoftLicence - DRM Industriel pour l'écosystème .NET

**SoftLicence** est une plateforme complète pour protéger, distribuer et surveiller vos logiciels WPF. Elle combine la puissance de la cryptographie RSA avec une interface d'administration moderne et réactive.

## 🚀 Puissance de la v1.1

- **Abonnements & Renouvellements** : Gérez des licences récurrentes via l'API de renouvellement sécurisée. Intégrez facilement vos paiements Stripe/PayPal pour prolonger automatiquement l'accès de vos clients.
- **Champs Personnalisés (Reference)** : Liez chaque licence à un ID de commande ou une référence client interne. Ce champ est chiffré et inclus dans le fichier de licence signé.
- **Auto-Trial Generation** : Permettez à vos logiciels de s'auto-activer lors du premier lancement via une "Clé Magique" ou un endpoint dédié.
- **Analytique & Télémétrie** : Suivez vos activations et recevez des rapports d'erreurs et de diagnostic en temps réel.
- **Gestion des Récupérations** : Système intelligent de décompte des réactivations (Recovery) pour identifier les abus.
- **Self-Service Reset** : Permettez à vos clients de délier eux-mêmes leur licence via email.
- **Sécurité Industrielle** : RSA-4096, Rate Limiting, Audit complet et détection automatique du fuseau horaire.

## 📚 Documentation

- [**Guide de Protection**](docs/PROTECTION_GUIDE.md) : Intégration pas à pas.
- [**Documentation Client**](docs/CLIENT.md) : Fonctionnement technique.
- [**Documentation Serveur**](docs/SERVER.md) : Déploiement et API.
- [**Internationalisation**](docs/I18N.fr.md) : Multi-langue et ressources locales.
- [**Roadmap**](docs/ROADMAP.md) : Suivi des développements.

## ⚡ Quick Start

1. **Déploiement** : Utilisez `Docker/docker-compose.yml` pour mettre en ligne votre serveur en 2 minutes.
2. **Logiciel** : Créez votre premier logiciel dans l'admin et récupérez sa clé publique.
3. **Protection** : Suivez le guide d'intégration WPF et compilez en mode Release avec Obfuscar.

## ⚙️ Configuration & Personnalisation

Le dépôt contient des placeholders (valeurs à remplacer) pour assurer votre sécurité et la personnalisation de l'outil. Voici la liste des termes à rechercher et à modifier avant votre premier déploiement :

| Terme à rechercher | Description |
| :--- | :--- |
| `YOUR_APP_NAME` | Le nom de votre logiciel (ex: YOUR_APP_NAME). |
| `YOUR_COMPANY_NAME` | Votre nom ou entreprise pour les copyrights et emails. |
| `EXAMPLE.COM` | Votre nom de domaine réel pour les liens et configurations SMTP. |
| `CHANGE_ME_DB_PASSWORD` | Mot de passe pour la base de données PostgreSQL. |
| `CHANGE_ME_ADMIN_PASSWORD` | Mot de passe initial pour le compte Admin. |
| `CHANGE_ME_RANDOM_SECRET` | Clé secrète indispensable pour sécuriser les échanges API. |
| `CHANGE_ME_SECRET_LOGIN_PATH` | URL personnalisée pour cacher votre page de connexion (ex: `ma-porte-secrete`). |
| `CHANGE_ME_MAXMIND_KEY` | Votre clé de licence MaxMind pour la géolocalisation des IPs. |

---
Développé avec ❤️ pour un déploiement industriel robuste.

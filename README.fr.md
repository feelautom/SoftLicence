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
- [**Roadmap**](docs/ROADMAP.md) : Suivi des développements.

## ⚡ Quick Start

1. **Déploiement** : Utilisez `docker/docker-compose.yml` pour mettre en ligne votre serveur en 2 minutes.
2. **Logiciel** : Créez votre premier logiciel dans l'admin et récupérez sa clé publique.
3. **Protection** : Suivez le guide d'intégration WPF et compilez en mode Release avec Obfuscar.

---
Développé avec ❤️ pour un déploiement industriel robuste.

# Roadmap - SoftLicence

Voici l'état d'avancement de la solution industrielle de gestion de licences.

## ✅ Phase 1 : Sécurité & Stabilité (Terminée)
- [x] **Auth Admin** : Système de login sécurisé pour le Dashboard.
- [x] **Sécurité API** : Double protection par Secret et Liste blanche d'IPs (WhiteList).
- [x] **Audit Total** : Middleware capturant 100% du trafic avec IP réelle et télémétrie.
- [x] **Migrations EF Core** : Système de mise à jour de schéma professionnel.
- [x] **Auto-Heal** : Mécanisme de récupération automatique de la base de données.

## ✅ Phase 2 : Fonctionnalités Avancées (Terminée)
- [x] **Types de Licences Dynamiques** : Création de types personnalisés via Slugs (PRO, GOLD, TRIAL).
- [x] **Analytics Dashboard** : Graphiques d'activité, KPIs et tunnel de conversion.
- [x] **Timer de Révocation** : Vérification en temps réel côté client WPF.
- [x] **Emailing Industriel** : Intégration de MailKit pour l'envoi fiable des clés.

## ✅ Phase 3 : Infrastructure & Automatisation (Terminée)
- [x] **Nettoyage automatique** : Tâche de fond pour purger les vieux logs.
- [x] **Gestion des Versions** : Restreindre une licence à une version majeure spécifique (ex: v1.x).
- [x] **Multi-Postes** : Autoriser une licence sur X machines simultanément.

## ✅ Phase 4 : Quality Assurance & Tests Industriels (Terminée)
- [x] **Core Stability** : Tests unitaires du moteur RSA et de la logique de validation.
- [x] **Active Defense** : Validation des services de bannissement et détection zombie.
- [x] **Integrity Lock** : Tests de verrouillage des configurations de compilation (Warnings as Errors).
- [x] **API Functional Tests** : Validation des endpoints d'activation, auto-trial et renouvellement.
- [x] **Telemetry Integrity** : Tests de parsing JSON complexe et isolation des données produits.
- [x] **Stats Accuracy** : Validation des calculs de KPIs et graphiques du dashboard.
- [x] **I18N Validation** : Tests de conversion automatique des fuseaux horaires.

## 🌟 Phase 5 : Portail & Écosystème (v1.2)
- [x] **UI Gestion des Postes** : Interface d'administration pour visualiser et libérer les machines liées à une licence.
- [ ] **Portail Client Self-Service** : Espace dédié pour que les clients gèrent leurs clés et effectuent des resets.
- [ ] **Connecteur Stripe** : Automatisation totale de la vente et génération de licence.
- [ ] **Anti-Tamper Avancé** : Détection de Debuggers et VM dans le Core.

## 🛠️ Maintenance & Optimisation
- [x] **Audit Total** : Middleware v1.1.
- [x] **Nettoyage automatique** : Background service de purge.
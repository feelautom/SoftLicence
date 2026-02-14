# Plan : Création du SDK SoftLicence Officiel (v1.0)

Ce plan définit la stratégie pour rapatrier la logique de licence dans une bibliothèque standardisée et unifier le format de l'ID Matériel.

## 1. Objectif Principal
- Créer une bibliothèque `.NET Standard 2.0` nommée `SoftLicence.Core`.
- Unifier le **Hardware ID** sur le format **16 caractères hexadécimaux**.
- Fournir une interface simple pour l'activation et la vérification.

## 2. Structure du SDK

### A. Classe `HardwareInfo` (L'Identité)
- Méthode `GetMachineId()` : Renvoie l'ID court (16 Hex).
- Logiciel concerné : Utilisé par SipLine et le Serveur de Licence.

### B. Classe `LicenceClient` (La Communication)
- `ActivateAsync(string key)` : Enregistre la machine sur le serveur.
- `CheckStatusAsync()` : Vérifie si la licence est toujours valide (Heartbeat).
- `GetLicenceDetails()` : Récupère les infos (Expiration, Type PRO/GOLD).

### C. Classe `Security` (La Protection)
- Validation RSA locale de la signature du fichier `.lic`.
- Empêche la modification manuelle des dates ou du type de licence.

## 3. Étapes d'exécution

1. **Création du projet** : Initialiser `SoftLicence.Core`.
2. **Extraction du code** : Déplacer la logique depuis SipLine vers le SDK.
3. **Harmonisation** : Modifier le code de hashage pour produire le format 16-Hex partout.
4. **Mise à jour SipLine** : Remplacer l'ancienne logique par l'appel au nouveau SDK.

---
**Standard validé :** ID Matériel = 16 caractères hexadécimaux (ex: 5015F8FFD54606CE).

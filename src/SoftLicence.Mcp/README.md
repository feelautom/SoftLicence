# SoftLicence.Mcp

Serveur MCP stdio pour les analytics SoftLicence et les opérations de sécurité explicitement contrôlées.

Le serveur ne se connecte jamais directement a PostgreSQL. Il appelle uniquement les endpoints HTTP de `SoftLicence.Server`.
Le traitement lourd, le cache, le scope produit et la redaction globale restent cote serveur.
Les lectures utilisent `SOFTLICENCE_API_KEY`. Les mutations de blacklist utilisent une
credential séparée `SOFTLICENCE_ADMIN_SECRET`, ne sont jamais disponibles avec la seule
clé analytics et effectuent une lecture de post-vérification.
Les tools `security/*` exigent en plus le scope `security:read` sur la clé analytics.
Le snapshot complet exige une clé cumulant `security:read telemetry:read` ; ajouter
`analytics:multi-product:read` pour une clé globale.

Guide interne complet : `docs-internal/MCP_ANALYTICS.md`.

## Configuration

Configuration recommandee avec l'executable publie :

```json
{
  "mcpServers": {
    "softlicence-analytics": {
      "command": "D:/Apps/SoftLicence.Mcp/SoftLicence.Mcp.exe",
      "env": {
        "SOFTLICENCE_BASE_URL": "https://softlicence.EXAMPLE.COM",
        "SOFTLICENCE_API_KEY": "sla_REPLACE_WITH_ANALYTICS_KEY"
      }
    }
  }
}
```

Publication locale :

```powershell
.\scripts\Update-LocalMcp.ps1
```

Ce script est la procédure canonique. Il publie d'abord le single-file win-x64 dans un
staging, gère la course avec le gestionnaire Codex qui relance automatiquement
`SoftLicence.Mcp.exe`, remplace le binaire pendant une fenêtre bornée, vérifie le hash,
supprime les anciens artifacts et exécute un smoke standalone. Le dossier final doit
contenir uniquement `D:\Apps\SoftLicence.Mcp\SoftLicence.Mcp.exe`.

Ne pas copier seulement l'apphost framework-dependent produit par un build standard :
ce petit EXE charge les DLL voisines et peut donc continuer à exécuter un ancien code.
Le single-file self-contained installé par le script embarque le code publié dans
l'exécutable dont le hash est vérifié.

La session MCP ayant lancé la mise à jour perd normalement son ancien transport stdio.
Recharger la session Codex/MCP après le succès du script, puis effectuer le smoke réel
des tools. Ne pas créer de dossiers parallèles `SoftLicence.Mcp-new` ou
`SoftLicence.Mcp-pending`.

Variables d'environnement requises en mode developpement :

```powershell
$env:SOFTLICENCE_BASE_URL = "https://softlicence.example.com"
$env:SOFTLICENCE_API_KEY = "sla_xxx"
# Requis uniquement pour create/unban security tools :
$env:SOFTLICENCE_ADMIN_SECRET = "admin-secret"
dotnet run --project src/SoftLicence.Mcp/SoftLicence.Mcp.csproj
```

Pour un MCP mono-produit, `SOFTLICENCE_API_KEY` peut etre une cle analytics produit creee via :

```http
POST /api/admin/products/{productId}/analytics-keys
```

Pour un MCP multi-produit Codex/LeadOps, `SOFTLICENCE_API_KEY` doit etre une cle globale creee via l'UI root `/analytics-keys/global` ou :

```http
POST /api/admin/analytics-keys/global
```

La cle globale a `ProductId=null`, `ScopeKind=Global` et les scopes `telemetry:read analytics:multi-product:read`. Une cle produit avec le scope multi-produit reste bornee a son produit.

Le serveur MCP envoie cette cle dans le header `X-Analytics-Key`.

La configuration client doit pointer vers le dossier stable `D:/Apps/SoftLicence.Mcp/SoftLicence.Mcp.exe`, pas vers un dossier publie versionne comme `SoftLicence.Mcp-<hash>`.

Avec une cle globale, les tools lies a un produit doivent recevoir un `productName`
exact ou un `productId`. Le MCP accepte explicitement `TIAConnect` et l'alias humain
`T-IA Connect`, puis envoie toujours la forme canonique `TIAConnect` au serveur. Les
autres noms sont seulement trimmes et restent inchanges. Utiliser `list_products` quand
le nom n'est pas certain. Si un tool recoit une erreur
de selection produit connue (`PRODUCT_SELECTOR_REQUIRED`, `PRODUCT_NOT_FOUND`,
`PRODUCT_NAME_AMBIGUOUS`, `PRODUCT_SELECTOR_AMBIGUOUS`), le MCP retourne une reponse
JSON d'erreur avec `availableProducts` pour permettre de relancer immediatement avec
le bon selecteur.

Exemple de configuration client MCP en mode developpement :

```json
{
  "mcpServers": {
    "softlicence-analytics": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "D:/Labs/SoftLicence/src/SoftLicence.Mcp/SoftLicence.Mcp.csproj"
      ],
      "env": {
        "SOFTLICENCE_BASE_URL": "https://softlicence.example.com",
        "SOFTLICENCE_API_KEY": "sla_REPLACE_WITH_ANALYTICS_KEY"
      }
    }
  }
}
```

L'exemple publie est disponible dans `docs-internal/examples/softlicence-mcp.config.example.json`.

## Tools

Le SDK MCP expose les méthodes C# en noms de tools `snake_case` :

- `get_telemetry_overview`
- `get_telemetry_devices`
- `get_telemetry_insights`
- `get_telemetry_raw_sample`
- `get_telemetry_schema_summary`
- `get_telemetry_tool_usage`
- `get_telemetry_quota_summary`
- `get_telemetry_startup_health`
- `get_telemetry_cert_pinning_summary`
- `get_telemetry_activation_funnel`
- `get_activation_failures`
- `get_telemetry_machine_profile`
- `get_telemetry_version_health`
- `get_support_telemetry_profile`
- `get_customer_license_timeline`
- `get_license_onboarding_metrics`
- `get_license_usage_scores`
- `get_current_product`
- `list_products`
- `list_security_canary_alerts`
- `get_security_canary_alert_details`
- `get_security_ban_status`
- `list_security_bans`
- `list_security_blacklist_overview`
- `get_security_ban_details`
- `get_security_ban_source_event`
- `get_security_case_snapshot`
- `get_security_hardware_ban_categories`
- `create_security_hardware_ban`
- `unban_security_hardware_ban`
- `create_security_component_ban`
- `unban_security_component_ban`

Toutes les limites sont bornees cote MCP avant l'appel API :

- `days` : 1 a 30
- `top` / `topEvents` : 1 a 100
- `take` : 1 a 50
- `take` : 1 a 500 pour `get_telemetry_devices`
- `emailFragment` : minimum 3 caracteres
- `licenseFragment` : minimum 6 caracteres hors separateurs
- `licenseType` pour `get_license_onboarding_metrics` : `paid`, `freemium`, `all`
- `activationAgeMaxDays` pour `get_license_onboarding_metrics` : 0 a 3650
- `licenseType` pour `get_license_usage_scores` : `paid`, `freemium`, `trial`, `subscription`, `all`
- `activityWindowDays` pour `get_license_usage_scores` : 1 a 90
- `sortBy` pour `get_license_usage_scores` : `score`, `conversionPotential`, `retentionConfidence`, `recentActivity`
- `date` : jour UTC explicite au format `YYYY-MM-DD`
- `fromUtc` / `toUtc` : plage UTC explicite, obligatoires ensemble

Les reponses restent les DTOs analytics compactes produites cote SoftLicence Server.
Les donnees brutes et les champs sensibles ne doivent pas transiter par le MCP.

Les listes Canary sont bornées et n'exposent ni chemins locaux ni JSON brut des
fingerprints. `get_security_canary_alert_details` est une lecture interne authentifiée
qui expose ces détails uniquement pour un identifiant d'alerte précis. Les outils de
ban composant acceptent `FP_EXE`, `FP_DLL`, `FP_CORE`, `CPU`, `MB`, `BIOS`, `DISK` et
`HOST`. Les mutations enrichissent le motif avec `ticketRef`, `createdBy` et
`auditNote`, puis relisent l'état persisté. Avec une clé analytics globale, fournir
`productId` ou `productName` pour cette post-vérification.
Les levées de ban exigent une raison opérateur explicite. Le snapshot de cas accepte
`ticketRef` et `securityCaseId`, propage les HWID résolus vers Canary et les profils
support, puis distingue les corrélations exactes des rapprochements probabilistes.

`get_telemetry_overview`, `get_telemetry_devices`, `get_telemetry_raw_sample`, `get_telemetry_insights` et
`get_activation_failures`
acceptent une periode explicite. `days` reste disponible comme fenetre glissante.

`get_telemetry_devices` liste les `HardwareId` uniques sur une periode et retourne
un résumé borné par machine : première/dernière activité, nombre d'événements,
dernière version, dernière IP client, appName, top events et familles d'events.
Il ne retourne pas de propriétés brutes ni de données licence.

`get_activation_failures` retourne les derniers echecs d'activation licence avec
statut, raison serveur, machine, IP et version client inferee. `LicenseKey` et
`RequestBody` ne sont jamais exposes.

`get_support_telemetry_profile` permet une recherche support read-only par `hardwareId`,
`email`, `emailFragment`, `licenseFragment` ou `clientIp`. `hardwareId` accepte un HWID
complet ou un prefixe/fragment de 6+ caracteres quand aucun match exact n'existe. Si
plusieurs machines correspondent, la reponse est bornee et `isAmbiguous=true`.
`clientIp` accepte IPv4 et IPv6 en correspondance exacte ; les IPv6 sont encodees dans
l'URL et ne sont pas decoupees sur `:`.

`get_customer_license_timeline` est l'outil support global pour reconstituer l'historique
client/licence de n'importe quel utilisateur a partir d'un email, HWID, `licenseId` ou
fragment de cle. Il retourne les emails et HWID internes complets, les cles licence
redigees, les licences candidates, les sieges, un resume par HWID et une timeline
chronologique paginee. Il distingue explicitement `Update_RevokeLicense` (clear local
cote desktop via update-check) d'une vraie trace serveur de deliaison de siege
(`SeatUnlinked`/equivalent), avec le verdict `no_server_seat_unlink_trace_found` quand
aucune trace serveur n'est presente dans la fenetre demandee.

`get_customer_license_timeline` accepte une fenetre glissante ou une plage explicite
de 90 jours maximum. Au-dessus de 30 jours, le MCP la decoupe automatiquement en
segments serveur contigus de 30 jours maximum et retourne les segments dans une seule
reponse (`segmented=true`). La borne serveur de 30 jours reste donc appliquee a chaque
requete. Une demande superieure a 90 jours retourne localement
`TIMELINE_RANGE_TOO_LARGE`, sans appel serveur. Les autres erreurs de periode restent
structurees au lieu de devenir une erreur MCP generique.

## Resultats volumineux sans troncature

Le MCP ne supprime aucune donnee d'une reponse analytics. Tant que le JSON reste sous
la limite inline configuree, la reponse est retournee sans modification. Quand le JSON
complet depasse cette limite, il est conserve temporairement dans un artifact local et
la commande retourne `resultDelivery=artifact` avec :

- un `artifactId` opaque ;
- les nombres exacts de caracteres, octets et chunks ;
- le checksum SHA-256 du JSON UTF-8 complet ;
- l'expiration de l'artifact ;
- `complete=true` et `truncated=false`.

Utiliser ensuite `get_mcp_result_artifact_info`, puis appeler
`get_mcp_result_artifact_chunk` avec `offset=0`. Reprendre le `nextOffset` tant que
`hasMore=true`. La concatenation des champs `content`, dans l'ordre, reconstitue le JSON
original exact. Le checksum final permet de verifier cette reconstruction.

Les outils MCP n'acceptent qu'un identifiant d'artifact et jamais un chemin. Les fichiers
JSON restent toutefois lisibles par le compte Windows et les administrateurs ayant acces
au repertoire local. Chaque processus MCP utilise par defaut son propre repertoire de
session. Un artifact non expire n'est jamais evince : si la capacite restante est
insuffisante, la commande echoue explicitement au lieu d'annoncer un resultat incomplet.
Chaque lecture prolonge le delai d'expiration afin qu'une reconstruction active puisse se
terminer. Les seuils peuvent etre ajustes avec :

- `SOFTLICENCE_MCP_MAX_INLINE_RESULT_CHARACTERS` ;
- `SOFTLICENCE_MCP_RESULT_CHUNK_CHARACTERS` ;
- `SOFTLICENCE_MCP_RESULT_TTL_MINUTES` ;
- `SOFTLICENCE_MCP_RESULT_MAX_TOTAL_BYTES` ;
- `SOFTLICENCE_MCP_RESULT_DIRECTORY`.

`get_license_onboarding_metrics` retourne les licences recentes triees par
activation ou creation decroissante, avec Time-To-Value onboarding, segmentation simple
et chemins detectes (`ui_only`, `mcp_direct`, `copilot_via_mcp`, `unknown`). Les emails,
HWID et cles licence restent redacted ou absents.

`get_license_usage_scores` complete l'onboarding avec des scores bornes 0-100 :
`usageScore`, `conversionPotentialScore`, `retentionConfidenceScore` et
`churnRiskScore`. La classification distingue notamment `hot_trial`,
`engaged_subscriber`, `power_user`, `needs_followup`, `dormant`, `at_risk` et
`unknown`. Les signaux de conversion favorisent l'usage multi-jours, les retours apres
premiere session, les evenements productifs, MCP/Copilot et l'onboarding complete. La
retention penalise fortement l'absence d'activite recente, meme avec un historique eleve.

# SoftLicence.Mcp

Serveur MCP stdio read-only pour les analytics SoftLicence.

Le serveur ne se connecte jamais directement a PostgreSQL. Il appelle uniquement les endpoints HTTP analytics de `SoftLicence.Server`.
Le traitement lourd, le cache, le scope produit et la redaction globale restent cote serveur.

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
dotnet publish src/SoftLicence.Mcp/SoftLicence.Mcp.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o D:\Apps\SoftLicence.Mcp
```

Variables d'environnement requises en mode developpement :

```powershell
$env:SOFTLICENCE_BASE_URL = "https://softlicence.example.com"
$env:SOFTLICENCE_API_KEY = "sla_xxx"
dotnet run --project src/SoftLicence.Mcp/SoftLicence.Mcp.csproj
```

`SOFTLICENCE_API_KEY` doit etre une cle analytics creee via :

```http
POST /api/admin/products/{productId}/analytics-keys
```

Le serveur MCP envoie cette cle dans le header `X-Analytics-Key`.

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
- `get_license_onboarding_metrics`
- `get_license_usage_scores`

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

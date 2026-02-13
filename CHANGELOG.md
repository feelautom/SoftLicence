# Changelog

## 2026-02-13
- security: auto-backup database before applying migrations
- feat(auth): add email notifications for users and force password change on first login
- feat(auth): fix and complete RBAC permissions for all pages and menu items
- feat(auth): implement RBAC with custom roles, users management and granular permissions
- fix(products): prevent deletion of products with existing licenses and ensure confirmation
- feat(security): backup full RSA key pair (Private + Public) to cloud on product creation
- ui(backup): update refresh and restore icons to Lucide style
- ui(backup): update restore icon and fix table header
- ui(nav): update menu icons to Lucide-style SVGs
- feat(backup): add side-by-side database comparison and high-end restoration modal
- deploy: fix rclone config persistence and permission error
- fix(backup): persist last backup date to prevent redundant backups on restart
- ui(backup): improve diagnostic feedback and log visibility
- feat(backup): implement database restoration system with cloud download and auto-restart
- ui(backup): reorganize layout with status, diagnostic console, and full-width history table
- feat(settings): implement persistent server settings table and fix backup toggle state
- ui(nav): remove redundant maintenance link from sidebar
- chore: disable backups by default and fix resets icon
- feat(backup): add cloud backup master toggle in dashboard
- ui(nav): replace text-only links with consistent SVG icons in admin menu
- chore(release): update changelog and bump version to 0.0.71
- test(server): fix CleanupServiceTests dependency injection for BackupService
- feat(backup): complete rclone integration and diagnostic dashboard implementation
- feat(backup): add daily cloud backup dashboard with remote file listing and health diagnostic
- feat(backup): integrate rclone for automatic Google Drive encrypted backups (keys and database)
- feat(security): implement RSA private key encryption at-rest and improved product creation UX with backup option

## 2026-02-12
- security: comprehensive server audit fix and architectural hardening

### 1. Sécurité & Défense Active
- Audit Complet : Tracement des actions administrateurs dans les logs d'audit.
- Whitelist IP Admin : Correction de la logique de vérification (match exact requis).
- Codes de Réinitialisation : Utilisation de RandomNumberGenerator (CSPRNG) pour les codes à 6 chiffres.
- Fuites de Données : Suppression de l'énumération des clés de licence dans les logs d'erreur.
- Détection Zombie : Seuil assoupli à 5 IPs/24h et suppression du ban IP automatique agressif.

### 2. Architecture & Fiabilité
- Thread-Safety : Refactoring du TelemetryService avec IDbContextFactory.
- Protection des Données : CleanupService désactivé par défaut (configurable).
- Intégrité Référentielle : Désactivation de la suppression en cascade sur les produits (Restrict).
- Migration DB : Ajout de la migration 'ProtectProductDelete'.

### 3. Corrections Techniques & UI
- Routing Furtif : Correction du blocage des fichiers statiques (favicon) via contrainte Regex.
- Mode Trial : Sécurisation de la détection et suppression du fallback arbitraire.
- Maintenance des Tests : Mise à jour complète de la suite de tests unitaires.
- UI : Remplacement des '??' par '--' pour les pays manquants dans les tableaux d'audit et maintenance.
- security: fix multiple vulnerabilities and architectural issues from code audit

- Fix CleanupService silent data deletion (now configurable)
- Fix TelemetryService thread-safety with IDbContextFactory
- Fix AdminController IP whitelist logic
- Fix AuditMiddleware to include admin actions and prevent race conditions
- Fix ActivationController: remove license key leakage and use CSPRNG for reset codes
- Fix SecurityService: soften zombie detection to reduce false positives
- Fix Login routing to prevent blocking static files (favicon.ico)
- Fix LicenseDbContext: prevent cascade delete on products
- security: remove dangerous automatic database deletion logic in Program.cs
- fix(geoip): resolve dual database reader for local ISP and City resolution
- security: harden middleware against bot scans and finalize security dashboard
- feat(security): enrich banned IPs view with GeoIP, ISP and reasons; add proactive scan detection
- feat: implement admin UI for multi-seat management and license type seat configuration
- fix(ui): restore background opacity for BOT_SCAN logs
- feat: implement software version control for licenses with automated masking and audit tracking
- docs: update roadmap and finalize version
- fix(ui): improve audit logs visibility with BOT_SCAN contrast and full IP tooltips
- feat(geoip): implement 100% local ISP resolution with GeoLite2-ASN database
- feat: implement background cleanup service for logs and telemetry
- build: final preparation for production deployment
- build: prepare for deployment and production testing
- docs: update roadmap and project metadata
- fix(audit): reposition middleware before authorization and harden background logging scope
- fix(notifications): use query parameters for NTFY to support UTF-8 and raw text messages
- quality: implement project integrity tests, resolve GeoIP obsoleteness and modernize build script UI
- ci: integrate unit tests into build script via -Test parameter
- test: implement comprehensive unit test suite for core and security services
- feat(security): implement active defense with auto-ban, threat scoring and ntfy notifications
- feat(security): implement Geo-IP and ISP/Proxy detection in audit logs
- feat(ui): add banned IPs management and display revocation reasons in admin
- feat(webhooks): implement programmable notifications system (UI + Service)
- feat(security): implement local GeoIP and Zombie Detection (Multi-IP HardwareID Ban)
- fix: Login page blank screen, AuditMiddleware stream issue, and minor fixes
- feat(audit): capture and display raw request body in audit logs for enhanced debugging of validation errors

## 2026-02-11
- feat(api): implement secure license renewal with transaction tracking and recurring mode validation
- feat(core): add 'Reference' custom field to licenses and signed license files
- feat(api): support auto-trial via magic license key suffix (-FREE-TRIAL)
- feat(api): implement auto-trial endpoint and default duration per license type
- fix(api): add detailed server-side logging for activation failures and normalize license keys (Trim/ToUpper)
- feat(ui): implement automatic browser timezone detection for all date displays
- feat(telemetry): implement license recovery tracking and detailed telemetry UI
- feat(telemetry): implement license recovery tracking with activation counter
- feat(ui): add detailed telemetry modal to product management page
- feat(audit): add modal to display and copy detailed error messages
- feat(api): allow regenerating product API secret from dashboard with confirmation
- style(ui): move settings to top bar and add professional icons for user, settings and logout
- fix(api): fix build errors in documentation and telemetry controller
- feat(telemetry): add read-only API endpoint for product-specific telemetry retrieval with API key protection
- feat(audit): capture and display detailed error messages in access logs
- style(ui): apply dark mode theme to pagination components globally
- feat(ui): add tabbed interface and improved pagination to product details view
- feat(ui): overhaul product detailed view with independent paginated tables for Licenses, Telemetry and Access Logs
- feat(ui): add dedicated license reset tracking page and improved logging
- feat(reset): implement self-service license reset system via email validation
- feat(email): finalize branding by removing all technical mentions and using product name as sender
- feat(email): apply professional HTML template to both license delivery and diagnostic emails
- feat(email): implement professional HTML template for license delivery
- fix(email): restore professional license template and separate diagnostic logic
- security(smtp): remove password length and format from diagnostic logs after success
- diag(smtp): show masked password format to help debug docker interpolation
- fix(smtp): also trim single quotes from configuration values
- fix(deploy): use direct env pass-through for SMTP to avoid $ expansion issues
- diag(smtp): capture specific SMTP status codes for better debugging
- fix(smtp): sanitize configuration by trimming quotes and log password length for debugging
- fix(smtp): log supported auth mechanisms for better diagnostic
- fix(ui): restore missing @page directive on settings page
- fix(deploy): pass SMTP environment variables to the docker container
- fix(smtp): improve diagnostic accuracy and display current server configuration
- feat(ui): add pagination with configurable page size to all tables
- feat(smtp): implement detailed live diagnostic console for SMTP testing
- fix(telemetry): make product search case-insensitive
- style(ui): improve status code coloring in audit log
- feat(telemetry): implement complete structured telemetry system with API, Service and UI
- feat(ui): add interactive filters for Method and Status in audit log
- style(ui): condense audit log table to single line per row
- style(ui): apply sentence case to all page titles and section headers

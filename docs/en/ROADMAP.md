# Roadmap - SoftLicence

Current progress of the license management platform.

## Phase 1: Security & Stability (Completed)
- [x] **Admin Auth**: Secure login system for the Dashboard.
- [x] **API Security**: Dual protection via Secret key and IP Whitelist.
- [x] **Full Audit**: Middleware capturing 100% of traffic with real IP and telemetry.
- [x] **EF Core Migrations**: Professional schema update system.
- [x] **Auto-Heal**: Automatic database recovery mechanism.

## Phase 2: Advanced Features (Completed)
- [x] **Dynamic License Types**: Custom type creation via Slugs (PRO, GOLD, TRIAL).
- [x] **Analytics Dashboard**: Activity charts, KPIs and conversion funnel.
- [x] **Revocation Timer**: Real-time client-side verification in WPF.
- [x] **Industrial Emailing**: MailKit integration for reliable key delivery.

## Phase 3: Infrastructure & Automation (Completed)
- [x] **Automatic Cleanup**: Background task to purge old logs.
- [x] **Version Management**: Restrict a license to a specific major version (e.g., v1.x).
- [x] **Multi-Seat**: Allow a license on X machines simultaneously.

## Phase 4: Quality Assurance & Testing (Completed)
- [x] **Core Stability**: Unit tests for RSA engine and validation logic.
- [x] **Active Defense**: Validation of ban services and zombie detection.
- [x] **Integrity Lock**: Build configuration lock tests (Warnings as Errors).
- [x] **API Functional Tests**: Activation, auto-trial and renewal endpoint validation.
- [x] **Telemetry Integrity**: Complex JSON parsing tests and product data isolation.
- [x] **Stats Accuracy**: KPI calculations and dashboard chart validation.
- [x] **I18N Validation**: Automatic timezone conversion tests.

## Phase 5: Portal & Ecosystem (v1.2)
- [x] **Seat Management UI**: Admin interface to view and release machines linked to a license.
- [ ] **Customer Self-Service Portal**: Dedicated space for customers to manage their keys and perform resets.
- [ ] **Stripe Connector**: Full automation of sales and license generation.
- [ ] **Advanced Anti-Tamper**: Debugger and VM detection in Core.

## Maintenance & Optimization
- [x] **Full Audit**: Middleware v1.1.
- [x] **Automatic Cleanup**: Background purge service.

# Server Documentation (SoftLicence.Server)

The SoftLicence server acts as both a **Certificate Authority** and an **Administration Console**. It manages the lifecycle of products, licenses, and ensures full access traceability.

## Deployment (Production)

The server is fully containerized. To deploy on a VPS:

1. Push your code to your Git repository.
2. Use the `docker/docker-compose.yml` file.
3. Configure the **Environment Variables**:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `AdminSettings__Username` | Admin Web username | `admin` |
| `AdminSettings__Password` | Admin Web password | `your_password` |
| `AdminSettings__ApiSecret` | Admin API key (CLI) | `long_random_secret` |
| `AdminSettings__LoginPath` | Secret login URL path | `my-secret-entrance` |
| `AdminSettings__AllowedIps` | IP whitelist (comma-separated) | `91.x.x.x, 127.0.0.1` |
| `SmtpSettings__Host` | SMTP server | `smtp.gmail.com` |
| `SmtpSettings__Port` | SMTP port | `587` |
| `SmtpSettings__Username` | SMTP user | `contact@example.com` |
| `SmtpSettings__Password` | SMTP password | `app_password` |
| `SmtpSettings__FromEmail` | Sender email | `noreply@example.com` |
| `SmtpSettings__FromName` | Sender name | `MyCompany` |
| `FORCE_DB_RESET` | Drop and recreate the database | `true` or `false` |

## Public API (Activation)

### 1. Activation (`POST /api/activation`)
Registers a product on a machine.

**Payload:**
```json
{
  "LicenseKey": "XXXX-XXXX-XXXX-XXXX",
  "HardwareId": "PC_FINGERPRINT",
  "AppName": "YourApp",
  "AppVersion": "1.2.3"
}
```
* `AppVersion` (Optional): If provided, the server checks compatibility against the `AllowedVersions` mask of the license.

**Responses:**
* `200 OK`: Contains the signed license file.
* `400 Bad Request`:
    * "Invalid license key".
    * "License expired".
    * "This license is not valid for version X.Y.Z".
    * "Maximum number of activations reached (X)".

### 2. Auto-Trial (Keyless Activation)
The server allows automatic activation on first launch via `/api/activation/trial` or by using a key ending with `-FREE-TRIAL`.
- **How it works**: If the hardware is unknown, the server creates a license with the duration defined in the license type settings.

### 3. Reset System (Self-Service)
The server allows customers to unbind their license from their hardware (HWID Reset) via double email verification:
1. Request a code via `/api/activation/reset-request`.
2. Validate via `/api/activation/reset-confirm` with the 6-digit code received by email.

## Advanced Features

### Multi-Seat System
Each license has a `MaxSeats` field (Default: 1).
* When a new `HardwareId` activates, a "seat" is consumed.
* If the same `HardwareId` requests a new activation, it's a **Recovery** (no seat consumed).
* If the limit is reached, activation is denied.

### Version Control
Licenses and license types support the `AllowedVersions` field.
* `*`: All versions allowed (Default).
* `1.*`: Only major version 1.
* `2.1.0`: Only this exact version.

### Subscription Management (Renewal)
For license types marked as **Recurring (Subscription)**, you can extend the validity period via the admin API.

**Endpoint**: `POST /api/admin/licenses/{licenseKey}/renew`
**Header**: `X-Admin-Secret: <YOUR_SECRET>`
**Payload**:
```json
{
  "TransactionId": "STRIPE_ID_12345",
  "Reference": "ORDER_#99"
}
```

## Security: Active Defense & Anti-Bot

SoftLicence includes a proactive defense system to protect your server from scans and brute force attacks.

### 1. Threat Scoring & Auto-Ban
The server assigns a "Threat Score" to each suspicious IP:
- **404 Error (Scan)**: +10 points.
- **Auth Failure (Login)**: +50 points.
- **Ban**: If an IP reaches **100 points**, it is banned for 24 hours.

### 2. Real-Time Alerts (ntfy)
The server can send immediate notifications on critical events (banning, fraud attempts).

### 3. GeoIP & ISP Intelligence
Every request in the audit log is enriched with country and ISP (Internet Service Provider) data.

### 4. Automatic Cleanup
A background service periodically purges obsolete logs:
* Audit: 30 days.
* Telemetry: 90 days.
* Followed by SQLite optimization (`VACUUM`).

## Monitoring & Audit

### Full Audit Log
Through a dedicated Middleware, the server records **every HTTP request** received with the real IP, performance metrics, and client application version.

### Analytics Dashboard
The dashboard provides a consolidated view of the fleet status and activity.

## Database & Migrations

The server uses **PostgreSQL** (or SQLite for development).
- **EF Core Migrations**: The schema evolves without data loss.
- **Auto-Update**: The server applies migrations automatically on startup.

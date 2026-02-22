namespace SoftLicence.Server.Services;

public class DocumentationService
{
    private readonly Dictionary<string, (string Title, Func<string> Content)> _sections;

    public DocumentationService()
    {
        _sections = new Dictionary<string, (string Title, Func<string> Content)>(StringComparer.OrdinalIgnoreCase)
        {
            ["overview"] = ("Overview", GetOverview),
            ["architecture"] = ("Architecture", GetArchitecture),
            ["crypto"] = ("Cryptography (RSA-4096)", GetCrypto),
            ["hardware"] = ("Hardware Fingerprinting", GetHardware),
            ["products"] = ("Products & Plugins", GetProducts),
            ["licenses"] = ("License Lifecycle", GetLicenses),
            ["security"] = ("Security System", GetSecurity),
            ["database"] = ("Database Schema", GetDatabase),
            ["api-public"] = ("Public API Reference", GetApiPublic),
            ["api-admin"] = ("Admin API Reference", GetApiAdmin),
            ["client-integration"] = ("WPF Client Integration", GetClientIntegration),
            ["rbac"] = ("Users & Roles (RBAC)", GetRbac),
            ["webhooks"] = ("Webhook Notifications", GetWebhooks),
            ["config"] = ("Configuration & Deployment", GetConfig),
            ["troubleshooting"] = ("Troubleshooting", GetTroubleshooting),
        };
    }

    public string? GetSection(string sectionId)
    {
        return _sections.TryGetValue(sectionId, out var section) ? section.Content() : null;
    }

    public string GetFullDocumentation()
    {
        var parts = new List<string>
        {
            "# SoftLicence — Complete System Documentation",
            "",
            "> Auto-generated LLM-friendly documentation. Security follows Kerckhoffs's principle:",
            "> the system is secure even if everything except the private key is public knowledge.",
            ""
        };

        foreach (var (id, (title, content)) in _sections)
        {
            parts.Add(content());
            parts.Add("");
            parts.Add("---");
            parts.Add("");
        }

        return string.Join("\n", parts);
    }

    public List<SectionInfo> GetSectionIndex()
    {
        return _sections.Select(kvp => new SectionInfo
        {
            Id = kvp.Key,
            Title = kvp.Value.Title,
            Url = $"/api/docs/{kvp.Key}"
        }).ToList();
    }

    public List<SearchResult> Search(string query, int maxResults = 20)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new List<SearchResult>();

        var terms = query.ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var results = new List<SearchResult>();

        foreach (var (id, (title, content)) in _sections)
        {
            var markdown = content();
            var lines = markdown.Split('\n');

            for (int i = 0; i < lines.Length; i++)
            {
                var lineLower = lines[i].ToLowerInvariant();
                if (terms.All(t => lineLower.Contains(t)))
                {
                    results.Add(new SearchResult
                    {
                        Section = id,
                        SectionTitle = title,
                        Line = i + 1,
                        Content = lines[i].Trim(),
                        Url = $"/api/docs/{id}"
                    });

                    if (results.Count >= maxResults)
                        return results;
                }
            }
        }

        return results;
    }

    // ── Section 1: Overview ──────────────────────────────────────────

    private static string GetOverview() => """
        ## 1. Overview

        **SoftLicence** is a DRM and license management platform for .NET WPF applications.
        It provides RSA-4096 cryptographic license signing with hardware fingerprinting for
        offline-capable license validation.

        ### Philosophy

        Security follows **Kerckhoffs's principle**: the system's security relies entirely on
        the RSA private key, not on keeping the architecture secret. All algorithms, schemas,
        and protocols are documented here. An attacker who reads every line of this documentation
        still cannot forge a license without the 4096-bit private key.

        ### Solution Structure (5 projects)

        | Project | Type | Purpose |
        |---------|------|---------|
        | **SoftLicence.Core** (SDK) | .NET Class Library | Cryptographic engine: RSA-4096 key generation, license signing/verification (SHA-256), hardware ID generation. Central class: `LicenseService`. No ASP.NET dependency. |
        | **SoftLicence.Server** | ASP.NET Core 9.0 | Central authority server. Web API for license operations + Blazor Server admin UI. SQLite/PostgreSQL via EF Core. Runs on port 5200. |
        | **SoftLicence.UI** | WPF Class Library | Reusable `ActivationWindow` and `LicenseActivationViewModel` for client apps. Uses CommunityToolkit.Mvvm. |
        | **SoftLicence.Template** | WPF App Template | Starter template for new WPF apps integrating SoftLicence. |
        | **SoftLicence.KeyGen** | Console App | CLI tool for RSA-4096 key pair generation. |

        ### How It Works (High Level)

        1. **Admin** creates a Product on the server → RSA-4096 key pair is generated
        2. **Admin** creates License Types (e.g., "PRO", "TRIAL") with duration, features, seat limits
        3. **Admin** creates Licenses linked to a Product and License Type
        4. **Client app** calls `POST /api/activation` with license key + hardware ID
        5. **Server** validates, binds to hardware, signs a `LicenseModel` with the private key
        6. **Client** receives a Base64-encoded signed license file, stores it locally
        7. **Client** can verify the license offline using only the public key
        8. **Periodic checks** (every 2h) call `POST /api/activation/check` to detect revocations
        """;

    // ── Section 2: Architecture ──────────────────────────────────────

    private static string GetArchitecture() => """
        ## 2. Architecture

        ### ASP.NET Core Middleware Pipeline (exact order)

        ```
        1. ForwardedHeaders     → Extract real client IP from X-Forwarded-For (Docker/proxy)
        2. RateLimiter           → Enforce per-policy rate limits (PublicAPI, AdminAPI, DocsAPI)
        3. StaticFiles           → Serve wwwroot/ (CSS, JS, favicon, llms.txt, robots.txt)
        4. RequestLocalization   → i18n (en, fr)
        5. Antiforgery           → CSRF protection for Blazor forms
        6. Authentication        → Cookie auth (7-day expiry, stealth mode: 404 on redirect)
        7. AuditMiddleware       → Log every request, threat scoring, zombie detection, throttling
        8. Authorization         → Role-based access control
        ```

        ### Service Registrations

        | Service | Lifetime | Purpose |
        |---------|----------|---------|
        | `DocumentationService` | Singleton | LLM documentation content |
        | `SettingsService` | Singleton | Key-value settings from DB + config |
        | `BackupService` | Singleton | rclone-based database and key backups |
        | `AuditNotifier` | Singleton | Real-time audit log push |
        | `NotificationService` | Singleton | Webhook dispatch |
        | `SecurityService` | Scoped | Threat scoring, banning, password hashing |
        | `EncryptionService` | Scoped | DataProtection API for RSA key encryption |
        | `AuthService` | Scoped | RBAC permission checks |
        | `TimeZoneService` | Scoped | Timezone management |
        | `GeoIpService` | Scoped | MaxMind GeoLite2 IP geolocation |
        | `TelemetryService` | Scoped | Client telemetry ingestion |
        | `ToastService` | Scoped | Blazor UI notifications |
        | `EmailService` | Transient | SMTP email via MailKit |
        | `StatsService` | Transient | Dashboard statistics |
        | `CleanupService` | HostedService | Background retention cleanup |

        ### Database

        - **Development**: SQLite (`softlicence.db`)
        - **Production**: PostgreSQL 16 (via Docker)
        - **ORM**: Entity Framework Core (code-first with migrations)
        - **Auto-migration** on startup with retry logic (up to 10 attempts, 5s delay)

        ### Blazor Admin UI

        Server-side Blazor with interactive components. Pages: Dashboard, Products, Licenses,
        Audit Logs, Telemetry, Maintenance, Documentation, Settings. Layout in `Components/Layout/`.
        """;

    // ── Section 3: Cryptography ──────────────────────────────────────

    private static string GetCrypto() => """
        ## 3. Cryptography (RSA-4096)

        ### Key Generation

        ```csharp
        using var rsa = RSA.Create(4096);
        string privateKeyXml = rsa.ToXmlString(true);   // includes private parameters
        string publicKeyXml = rsa.ToXmlString(false);    // public parameters only
        ```

        - Key size: **4096 bits** (≈128 decimal digits of security)
        - Format: .NET XML (`<RSAKeyValue>` with `<Modulus>`, `<Exponent>`, `<P>`, `<Q>`, `<D>`, etc.)
        - Generated per product (each product has its own key pair)
        - Private keys encrypted at rest using ASP.NET DataProtection API

        ### License Signing Process

        ```
        LicenseModel (object)
            → JSON serialization (System.Text.Json)
            → UTF-8 byte encoding
            → SHA-256 hash
            → RSA PKCS#1 v1.5 signature (4096-bit private key)
            → Base64 encode signature → store in model.Signature
            → Serialize full model (with signature) to JSON
            → Base64 encode entire JSON → final license string
        ```

        Step by step in code:
        1. `JsonSerializer.Serialize(model)` → JSON string
        2. `Encoding.UTF8.GetBytes(json)` → byte array
        3. `rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)` → signature bytes
        4. `Convert.ToBase64String(signatureBytes)` → `model.Signature`
        5. `JsonSerializer.Serialize(model)` → JSON with signature
        6. `Convert.ToBase64String(Encoding.UTF8.GetBytes(json))` → final license file content

        ### License Verification Process

        ```
        Base64 license string
            → Base64 decode → JSON string
            → Deserialize to LicenseModel
            → Extract and remove Signature field
            → Re-serialize to JSON (without signature)
            → UTF-8 encode → byte array
            → RSA PKCS#1 v1.5 verify with public key + SHA-256
            → Check expiration date
            → Validate HardwareId match
        ```

        ### Private Key Encryption at Rest

        - API: ASP.NET Core DataProtection (`IDataProtector`)
        - Purpose string: `"SoftLicence.ProductKeys.v1"`
        - Keys persisted to: `{ContentRoot}/data/keys/` (or `/app/data/keys/` in Docker)
        - Application name: `"SoftLicence"`
        - On decryption failure: returns `"ERROR_DECRYPTION_FAILED"`

        ### Password Hashing

        - Algorithm: **bcrypt** (cost factor = 12)
        - Library: BCrypt.Net
        - Used for: admin user passwords
        - Comparison: timing-safe (`BCrypt.Verify`)

        ### Why This Is Secure

        - RSA-4096 requires factoring a 4096-bit semiprime — no known algorithm can do this
        - Even with full knowledge of the public key, signing algorithm, and license format,
          forging a signature requires the private key
        - Hardware binding prevents license file copying between machines
        - Online checks detect revocations even if offline verification passes
        """;

    // ── Section 4: Hardware Fingerprinting ────────────────────────────

    private static string GetHardware() => """
        ## 4. Hardware Fingerprinting

        ### Components (5 WMI properties)

        | # | WMI Class | Property | Example |
        |---|-----------|----------|---------|
        | 1 | `Win32_Processor` | `ProcessorId` | `BFEBFBFF000906EA` |
        | 2 | `Win32_BaseBoard` | `SerialNumber` | `PF1RXXXX` |
        | 3 | `Win32_BIOS` | `SerialNumber` | `XXXXX-XXXXX` |
        | 4 | `Win32_DiskDrive` | `SerialNumber` | `WD-WMXXXXXXX` |
        | 5 | (Environment) | `MachineName` | `DESKTOP-ABC123` |

        ### Algorithm

        ```
        raw = GetCpuId() + GetMotherboardId() + GetBiosId() + GetDiskId() + MachineName
        hash = SHA256(UTF8.GetBytes(raw))
        hardwareId = BitConverter.ToString(hash).Replace("-", "")[..16].ToUpper()
        ```

        Result: **16-character uppercase hexadecimal string** (e.g., `A1B2C3D4E5F67890`)

        ### Fallback Behavior

        | Scenario | Result |
        |----------|--------|
        | Non-Windows platform | Each component returns `"NON-WINDOWS"` |
        | WMI query fails | Component returns `"UNKNOWN"` |
        | Component not present | Component returns `"UNKNOWN"` |

        ### When Hardware ID Changes

        The ID changes when any of these components is replaced:
        - CPU replacement → different `ProcessorId`
        - Motherboard replacement → different `SerialNumber`
        - BIOS update (rare) → potentially different `SerialNumber`
        - Primary disk replacement → different `SerialNumber`
        - Machine rename → different `MachineName`

        Users can self-reset their license via the reset-request/reset-confirm API flow,
        or an admin can unlink via the admin UI.
        """;

    // ── Section 5: Products & Plugins ─────────────────────────────────

    private static string GetProducts() => """
        ## 5. Products & Plugins

        ### Hierarchy (3 levels)

        ```
        Product (Level 1)
        ├── Plugin (Level 2)  — ParentProductId = Product.Id
        │   └── Sub-Plugin (Level 3)  — ParentProductId = Plugin.Id
        └── Plugin (Level 2)
        ```

        ### Product Entity

        | Field | Type | Description |
        |-------|------|-------------|
        | `Id` | Guid | Primary key (auto-generated) |
        | `Name` | string | Unique product name |
        | `PrivateKeyXml` | string | RSA private key (encrypted via DataProtection) |
        | `PublicKeyXml` | string | RSA public key (plaintext XML) |
        | `ApiSecret` | string | Per-product secret for telemetry auth (Guid format) |
        | `ParentProductId` | Guid? | Parent product ID (null = root product) |

        ### Key Inheritance

        - Level 1 and 2: Each product generates its own RSA-4096 key pair
        - Level 3 (sub-plugins): Inherit keys from their parent (level 2) product
        - The `ApiSecret` is unique per product (used for telemetry ingestion auth)

        ### Creating Products

        **Via Admin API:**
        ```http
        POST /api/admin/products
        X-Admin-Secret: {secret}
        Content-Type: application/json

        "MyProduct"
        ```
        Response: `{ "id": "guid", "name": "MyProduct", "publicKeyXml": "<RSAKeyValue>..." }`

        **Via Admin UI:** Products page → "New Product" button

        ### RSA Key Diagnostics

        ```http
        GET /api/admin/products/{id}/key-check
        X-Admin-Secret: {secret}
        ```
        Verifies that:
        1. Private key can be decrypted
        2. Public key modulus matches private key modulus
        3. Returns status: `OK`, `ERROR`, or `MISMATCH`
        """;

    // ── Section 6: License Lifecycle ──────────────────────────────────

    private static string GetLicenses() => """
        ## 6. License Lifecycle

        ### States

        ```
        CREATED → ACTIVATED → VALID (periodic checks)
                                ↓
                            EXPIRED (ExpirationDate passed)
                                ↓
                            RENEWED (if IsRecurring, via /renew endpoint)
                                ↓
                            VALID again

        CREATED → ACTIVATED → REVOKED (admin action or zombie detection)

        ACTIVATED → RESET (self-service or admin unlink) → ACTIVATED (new device)
        ```

        ### License Types

        | Field | Type | Description |
        |-------|------|-------------|
        | `Name` | string | Display name (e.g., "Professional Edition") |
        | `Slug` | string | Technical ID, unique per product (e.g., "PRO", "TRIAL") |
        | `DefaultDurationDays` | int | License validity in days (default: 30) |
        | `IsRecurring` | bool | If true, license can be renewed via API (subscription model) |
        | `DefaultAllowedVersions` | string | Version mask (default: "*") |
        | `DefaultMaxSeats` | int | Max concurrent devices (default: 1) |

        ### Multi-Seat Licensing

        - `MaxSeats` on License controls how many devices can be active simultaneously
        - Each activation creates a `LicenseSeat` record (LicenseId + HardwareId)
        - `LastCheckInAt` updated on each validation call
        - Seats can be deactivated (unlinked) by admin or self-service reset
        - Unique constraint: one active seat per (LicenseId, HardwareId)

        ### Custom Parameters (Features)

        `LicenseTypeCustomParam` entries are injected into the signed license as `Features` dictionary:
        - `Key`: technical identifier (alphanumeric + underscore)
        - `Name`: display name
        - `Value`: the feature value (string, parsed client-side)

        Client reads features via `model.GetParam<T>(key, fallback)` for typed access.

        ### Version Masking

        `AllowedVersions` field supports:
        - `*` or empty → all versions allowed
        - `1.*` → any version starting with "1."
        - `2.1.0` → exact version match only

        ### Auto-Trial

        `POST /api/activation/trial` with `TypeSlug` (e.g., "TRIAL"):
        - If no existing license for HardwareId + Product: creates a new trial license
        - If existing unexpired license: returns it
        - If existing expired + IsRecurring (community): auto-renews
        - License key format: `FREE-TRIAL` suffix

        ### Self-Service Reset

        1. `POST /api/activation/reset-request` → generates 6-digit code, emails it
        2. Code expires in 15 minutes
        3. `POST /api/activation/reset-confirm` with code → unlinks all active seats
        4. Code comparison uses fixed-time comparison (anti timing-attack)
        5. One-use: code is cleared after successful reset

        ### History Actions

        | Action | Trigger |
        |--------|---------|
        | `CREATED` | License created by admin |
        | `ACTIVATED` | First activation on a device |
        | `RECOVERY` | Re-activation on same device (existing seat) |
        | `REVOKED` | Admin revocation or zombie detection |
        | `REACTIVATED` | Admin reactivation after revocation |
        | `UNLINKED_API` | Self-service reset via API |
        | `UNLINKED_MANUAL` | Manual unlink via admin UI |
        | `UNLINKED_ADMIN_TOOL` | Unlink via admin CLI tool |
        | `GLOBAL_RESET` | Full license reset (all seats) |
        | `RENEWED` | Subscription renewal |
        """;

    // ── Section 7: Security System ────────────────────────────────────

    private static string GetSecurity() => """
        ## 7. Security System

        ### Threat Scoring (Persistent)

        Scores accumulate permanently per IP address and are stored in the `IpThreatScores` table
        (survive server restarts). In-memory cache (`ConcurrentDictionary`) for fast lookups.
        Score resets to 0 only after the IP serves its ban period.

        | Zone | Score Range | Effect |
        |------|-------------|--------|
        | **Normal** | 0–99 | No penalty |
        | **Quarantine** | 100–199 | Progressive throttling |
        | **Ban** | ≥ 200 | Immediate IP ban |

        ### Quarantine Throttling

        When score is between 100–199, each request is delayed:
        ```
        delay = 5 seconds + 1 second per 10 points above 100
        maximum delay = 15 seconds
        ```
        Example: score 150 → delay = 5 + (150-100)/10 = 10 seconds

        ### Points Per Event

        All base points are multiplied by `Math.Max(1, banCount × 2)` for repeat offenders.

        | Event | Base Points | Notes |
        |-------|-------------|-------|
        | Proactive scan pattern | 20 | Instant 200 if ≥5 prior bans |
        | 404 (clean IP, no history) | 2 | |
        | 404 (has prior ban or in quarantine) | 10 | |
        | Auth failure (401/403) | 50 | |
        | Any request with ≥5 prior bans | 200 | Zero tolerance, instant ban |

        ### Proactive Scan Patterns (30+)

        Requests matching these patterns are immediately scored as proactive scans:
        ```
        .php, .env, .git, .aws, .ssh, .config, .bak, .sql, .zip, .tar,
        wp-admin, wp-CHANGE_ME_LOGIN_PATH, wp-content, wp-includes, xmlrpc,
        /admin, /administrator, /phpmyadmin, /mysql, /cgi-bin,
        /shell, /cmd, /exec, /eval, /system,
        .asp, .aspx, .jsp, .cgi,
        /etc/passwd, /proc/self, /windows/system32
        ```

        ### Ban Escalation

        | Ban Count | Duration |
        |-----------|----------|
        | 1st ban | 1 day |
        | 2nd ban | 7 days |
        | 3rd+ ban | 30 days |

        After ban expires, threat score resets to 0 (fresh start).

        ### Zombie Detection

        If the same `HardwareId` is seen from **more than 5 distinct IP addresses within 24 hours**,
        the license is automatically revoked. This detects shared/leaked license files.

        The check runs in the `AuditMiddleware` after each activation request.

        ### Rate Limiting

        | Policy | Limit | Applies To |
        |--------|-------|------------|
        | `PublicAPI` | 10 req/min | Activation, telemetry endpoints |
        | `AdminAPI` | 100 req/min | Admin management endpoints |
        | `DocsAPI` | 30 req/min | Documentation endpoints |

        All use fixed-window algorithm. Excess requests receive HTTP 429.

        ### VPN/Proxy Detection

        GeoIP service (MaxMind GeoLite2) flags proxied connections. The `IsProxy` field
        is logged in `AccessLog` for each request. VPN usage is informational (not auto-blocked).

        ### Anti Timing-Attack

        All secret comparisons use fixed-time comparison:
        - Admin API secret (`X-Admin-Secret` header)
        - Reset confirmation codes (6-digit)
        - Password verification (bcrypt inherently constant-time)
        """;

    // ── Section 8: Database Schema ────────────────────────────────────

    private static string GetDatabase() => """
        ## 8. Database Schema

        20 tables total. PostgreSQL 16 in production, SQLite in development.
        EF Core code-first with auto-migration on startup.

        ### Entity Relationship Diagram

        ```
        Product (1) ──→ (N) License
        Product (1) ──→ (N) LicenseType ──→ (N) LicenseTypeCustomParam
        Product (1) ──→ (N) TelemetryRecord
        Product (1) ──→ (N) SubProducts (self-referencing via ParentProductId)

        LicenseType (1) ──→ (N) License

        License (1) ──→ (N) LicenseSeat
        License (1) ──→ (N) LicenseHistory
        License (1) ──→ (N) LicenseRenewal

        TelemetryRecord (1) ──→ (0..1) TelemetryEvent
        TelemetryRecord (1) ──→ (0..1) TelemetryDiagnostic
        TelemetryRecord (1) ──→ (0..1) TelemetryError

        TelemetryDiagnostic (1) ──→ (N) TelemetryDiagnosticResult
        TelemetryDiagnostic (1) ──→ (N) TelemetryDiagnosticPort

        AdminRole (1) ──→ (N) AdminUser
        ```

        ### Table: Product

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | Name | string | No | — | **Unique index** |
        | PrivateKeyXml | string | No | — | Encrypted (DataProtection) |
        | PublicKeyXml | string | No | — | Plaintext XML |
        | ApiSecret | string | No | Guid.NewGuid().ToString("N") | Per-product telemetry key |
        | ParentProductId | Guid? | Yes | null | FK → Product.Id (self-ref) |

        ### Table: License

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | LicenseKey | string | No | — | **Unique index** |
        | CustomerName | string | No | — | |
        | CustomerEmail | string | No | — | |
        | Reference | string? | Yes | null | Custom reference field |
        | LicenseTypeId | Guid | No | — | FK → LicenseType.Id (Restrict) |
        | ProductId | Guid | No | — | FK → Product.Id (Restrict) |
        | CreationDate | DateTime | No | UtcNow | |
        | ExpirationDate | DateTime? | Yes | null | null = lifetime license |
        | HardwareId | string? | Yes | null | Legacy single-device binding |
        | ActivationDate | DateTime? | Yes | null | First activation timestamp |
        | RecoveryCount | int | No | 0 | Re-activation counter |
        | IsActive | bool | No | true | false = revoked |
        | RevocationReason | string? | Yes | null | |
        | RevokedAt | DateTime? | Yes | null | |
        | ResetCode | string? | Yes | null | 6-digit self-service reset |
        | ResetCodeExpiry | DateTime? | Yes | null | 15-min expiry |
        | AllowedVersions | string | No | "*" | Version mask |
        | MaxSeats | int | No | 1 | Concurrent device limit |

        Index: `(ProductId, HardwareId)`

        ### Table: LicenseType

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | Name | string | No | — | Display name |
        | Slug | string | No | — | Technical ID |
        | Description | string | No | — | |
        | DefaultDurationDays | int | No | 30 | |
        | IsRecurring | bool | No | false | Subscription model |
        | DefaultAllowedVersions | string | No | "*" | |
        | DefaultMaxSeats | int | No | 1 | |
        | ProductId | Guid | No | — | FK → Product.Id (Cascade) |

        **Unique index**: `(ProductId, Slug)`

        ### Table: LicenseTypeCustomParam

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | LicenseTypeId | Guid | No | — | FK → LicenseType.Id |
        | Key | string | No | — | Alphanumeric + underscore |
        | Name | string | No | — | Display name |
        | Value | string | No | — | Feature value |

        **Unique index**: `(LicenseTypeId, Key)`

        ### Table: LicenseSeat

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | LicenseId | Guid | No | — | FK → License.Id (Cascade) |
        | HardwareId | string | No | — | Device fingerprint |
        | FirstActivatedAt | DateTime | No | UtcNow | |
        | LastCheckInAt | DateTime | No | UtcNow | Updated on validation |
        | MachineName | string? | Yes | null | Optional device name |
        | IsActive | bool | No | true | |
        | UnlinkedAt | DateTime? | Yes | null | Deactivation timestamp |

        **Unique filtered index**: `(LicenseId, HardwareId) WHERE IsActive = true`

        ### Table: LicenseHistory

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | LicenseId | Guid | No | — | FK → License.Id (Cascade) |
        | Timestamp | DateTime | No | UtcNow | |
        | Action | string | No | — | See History Actions enum |
        | Details | string? | Yes | null | |
        | PerformedBy | string? | Yes | null | "Admin", "User", "System", or IP |

        ### Table: LicenseRenewal

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | LicenseId | Guid | No | — | FK → License.Id |
        | TransactionId | string | No | — | **Unique** (idempotency key) |
        | RenewalDate | DateTime | No | UtcNow | |
        | DaysAdded | int | No | — | Duration extension |

        ### Table: AccessLog

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | Timestamp | DateTime | No | UtcNow | **Index** |
        | ClientIp | string | No | — | **Index** |
        | Method | string | No | — | HTTP method |
        | Path | string | No | — | Request path |
        | Endpoint | string | No | — | Business tag |
        | LicenseKey | string | No | — | |
        | HardwareId | string | No | — | |
        | AppName | string | No | — | |
        | UserAgent | string? | Yes | null | |
        | CountryCode | string? | Yes | null | GeoIP |
        | Isp | string? | Yes | null | GeoIP |
        | IsProxy | bool | No | false | GeoIP VPN detection |
        | ThreatScore | int | No | 0 | Current score at request time |
        | StatusCode | int | No | — | HTTP response code |
        | ResultStatus | string | No | — | Business result |
        | RequestBody | string? | Yes | null | Raw request data |
        | ErrorDetails | string? | Yes | null | Server error response |
        | IsSuccess | bool | No | — | |
        | DurationMs | long | No | — | Request duration |

        ### Table: IpThreatScore

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | IpAddress | string | No | — | **PK** |
        | Score | int | No | 0 | Persistent threat score |
        | LastHit | DateTime | No | UtcNow | |
        | FirstSeen | DateTime | No | UtcNow | |

        ### Table: BannedIp

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | IpAddress | string | No | — | **PK** |
        | BannedAt | DateTime | No | UtcNow | |
        | ExpiresAt | DateTime? | Yes | null | null = permanent |
        | Reason | string | No | — | |
        | BanCount | int | No | 1 | Increments on repeat bans |
        | IsActive | bool | No | true | |

        ### Table: TelemetryRecord

        | Column | Type | Nullable | Default | Constraints |
        |--------|------|----------|---------|-------------|
        | Id | Guid | No | NewGuid() | PK |
        | Timestamp | DateTime | No | UtcNow | |
        | HardwareId | string | No | — | |
        | ClientIp | string? | Yes | null | |
        | Isp | string? | Yes | null | |
        | AppName | string | No | — | |
        | Version | string? | Yes | null | |
        | EventName | string | No | — | |
        | Type | TelemetryType | No | — | Enum: Event, Diagnostic, Error |
        | ProductId | Guid? | Yes | null | FK → Product.Id |

        ### Table: TelemetryEvent

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | TelemetryRecordId | Guid | No | FK → TelemetryRecord.Id |
        | PropertiesJson | string? | Yes | null |

        ### Table: TelemetryDiagnostic

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | TelemetryRecordId | Guid | No | FK → TelemetryRecord.Id |
        | Score | int | No | 0 |

        ### Table: TelemetryDiagnosticResult

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | TelemetryDiagnosticId | Guid | No | FK |
        | ModuleName | string? | Yes | null |
        | Success | bool | No | — |
        | Severity | string? | Yes | null |
        | Message | string? | Yes | null |

        ### Table: TelemetryDiagnosticPort

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | TelemetryDiagnosticId | Guid | No | FK |
        | Name | string? | Yes | null |
        | ExternalPort | int | No | — |
        | Protocol | string? | Yes | null |

        ### Table: TelemetryError

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | TelemetryRecordId | Guid | No | FK |
        | ErrorType | string? | Yes | null |
        | Message | string? | Yes | null |
        | StackTrace | string? | Yes | null |

        ### Table: AdminRole

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | Name | string | No | — |
        | Permissions | string | No | — |

        Permissions is a CSV string: `"dashboard.view,products.view,products.edit,licenses.view,..."`

        ### Table: AdminUser

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | Username | string | No | — |
        | Email | string | No | — |
        | PasswordHash | string | No | — |
        | MustChangePassword | bool | No | true |
        | IsEnabled | bool | No | true |
        | AdminPath | string? | Yes | null |
        | CreatedAt | DateTime | No | UtcNow |
        | RoleId | Guid | No | FK → AdminRole.Id |

        ### Table: Webhook

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Id | Guid | No | NewGuid() |
        | Name | string | No | — |
        | Url | string | No | — |
        | EnabledEvents | string | No | — |
        | IsEnabled | bool | No | true |
        | CreatedAt | DateTime | No | UtcNow |
        | LastTriggeredAt | DateTime? | Yes | null |
        | LastError | string? | Yes | null |

        ### Table: SystemSetting

        | Column | Type | Nullable | Default |
        |--------|------|----------|---------|
        | Key | string | No | — |
        | Value | string | No | — |
        | LastUpdated | DateTime | No | UtcNow |
        """;

    // ── Section 9: Public API Reference ───────────────────────────────

    private static string GetApiPublic() => """
        ## 9. Public API Reference

        Base URL: `https://your-server:5200`
        Rate Limit: 10 requests/minute (PublicAPI policy)
        Authentication: None required

        ---

        ### POST /api/activation

        Activate a license on a specific device.

        **Request Body:**
        ```json
        {
          "licenseKey": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "hardwareId": "A1B2C3D4E5F67890",
          "appName": "MyProduct",
          "appId": "optional-product-guid",
          "appVersion": "1.2.3",
          "customerEmail": "user@example.com",
          "customerName": "John Doe"
        }
        ```

        > `customerEmail` and `customerName` are optional. When provided, they update the license record in the database (useful for associating real user info with auto-trial or pre-created licenses).

        **Success Response (200):**
        ```json
        {
          "licenseFile": "base64-encoded-signed-license-json"
        }
        ```

        **Error Responses:**
        - `400` — Product not found, key invalid, license expired, version not allowed, seat limit reached
        - `403` — License revoked
        - `500` — Server-side decryption or signing error

        **Behavior:**
        - If `licenseKey` contains "FREE-TRIAL": redirects to auto-trial flow
        - First activation: creates LicenseSeat, sets ActivationDate, records ACTIVATED history
        - Re-activation (same HardwareId): updates LastCheckInAt, increments RecoveryCount
        - New device: checks MaxSeats limit, creates new seat if under limit
        - Version check: validates `appVersion` against `AllowedVersions` mask
        - If `customerEmail`/`customerName` provided: updates the license record

        ---

        ### POST /api/activation/check

        Verify license status without performing activation.

        **Request Body:**
        ```json
        {
          "licenseKey": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "hardwareId": "A1B2C3D4E5F67890",
          "appName": "MyProduct",
          "appId": "optional-product-guid"
        }
        ```

        **Response (200):**
        ```json
        {
          "status": "VALID"
        }
        ```

        **Possible statuses:**
        - `VALID` — License is active and device is authorized
        - `REVOKED` — License has been revoked (IsActive = false)
        - `EXPIRED` — License expiration date has passed
        - `REQUIRES_ACTIVATION` — License exists but no device is activated
        - `HARDWARE_MISMATCH` — Device not in active seats list

        ---

        ### POST /api/activation/trial

        Auto-generate a trial or community license.

        **Request Body:**
        ```json
        {
          "hardwareId": "A1B2C3D4E5F67890",
          "appName": "MyProduct",
          "appId": "optional-product-guid",
          "typeSlug": "TRIAL",
          "appVersion": "1.0.0",
          "customerEmail": "user@example.com",
          "customerName": "John Doe"
        }
        ```

        > `customerEmail` and `customerName` are optional. When provided, they are used instead of the default "Auto Trial" / "trial@auto.local" values. If the user already has an existing license, these fields update it.

        **Success Response (200):**
        ```json
        {
          "licenseFile": "base64-encoded-signed-license-json"
        }
        ```

        **Behavior:**
        - Finds product by AppId (Guid) or AppName (case-insensitive)
        - Finds LicenseType by Slug within that product
        - If existing unexpired license for HardwareId: returns it (updates customer info if provided)
        - If expired + IsRecurring: auto-renews and returns
        - Otherwise: creates new license using provided customer info or defaults

        ---

        ### POST /api/activation/reset-request

        Request a hardware reset code (sent via email).

        **Request Body:**
        ```json
        {
          "licenseKey": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "appName": "MyProduct",
          "appId": "optional-product-guid"
        }
        ```

        **Success Response (200):**
        ```json
        {
          "message": "Code sent"
        }
        ```

        **Requirements:**
        - License must have a `CustomerEmail` set
        - Generates 6-digit code (cryptographically random)
        - Code expires in 15 minutes
        - Sends email via configured SMTP

        ---

        ### POST /api/activation/reset-confirm

        Confirm hardware reset with the emailed code.

        **Request Body:**
        ```json
        {
          "licenseKey": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "appName": "MyProduct",
          "appId": "optional-product-guid",
          "resetCode": "123456"
        }
        ```

        **Success Response (200):**
        ```json
        {
          "message": "Unlink successful"
        }
        ```

        **Behavior:**
        - Fixed-time code comparison (anti timing-attack)
        - Clears HardwareId, ActivationDate, ResetCode, RecoveryCount
        - Deactivates all active LicenseSeats
        - Creates UNLINKED_API history entries
        - One-use: code is cleared after success

        ---

        ### POST /api/telemetry/event

        Send a client telemetry event.

        **Request Body:**
        ```json
        {
          "timestamp": "2024-01-15T10:30:00Z",
          "hardwareId": "A1B2C3D4E5F67890",
          "appName": "MyProduct",
          "version": "1.2.3",
          "eventName": "AppStarted",
          "properties": {
            "key1": "value1",
            "key2": "value2"
          }
        }
        ```

        **Response:** `200 OK`

        ---

        ### POST /api/telemetry/diagnostic

        Send a diagnostic report.

        **Request Body:**
        ```json
        {
          "timestamp": "2024-01-15T10:30:00Z",
          "hardwareId": "A1B2C3D4E5F67890",
          "appName": "MyProduct",
          "version": "1.2.3",
          "eventName": "HealthCheck",
          "score": 85,
          "results": [
            { "moduleName": "Database", "success": true, "severity": "info", "message": "OK" }
          ],
          "ports": [
            { "name": "HTTP", "externalPort": 8080, "protocol": "TCP" }
          ]
        }
        ```

        ---

        ### POST /api/telemetry/error

        Send an error report.

        **Request Body:**
        ```json
        {
          "timestamp": "2024-01-15T10:30:00Z",
          "hardwareId": "A1B2C3D4E5F67890",
          "appName": "MyProduct",
          "version": "1.2.3",
          "eventName": "UnhandledException",
          "errorType": "NullReferenceException",
          "message": "Object reference not set",
          "stackTrace": "at MyApp.Foo.Bar() in ..."
        }
        ```

        ---

        ### GET /api/telemetry

        Retrieve telemetry data for a product.

        **Headers:**
        - `X-Product-Key: {product-api-secret}` (required)

        **Query Parameters:**
        - `page` (int, default: 1)
        - `pageSize` (int, default: 50)

        **Response:** Paginated list of telemetry records.
        """;

    // ── Section 10: Admin API Reference ───────────────────────────────

    private static string GetApiAdmin() => """
        ## 10. Admin API Reference

        Base URL: `https://your-server:5200`
        Rate Limit: 100 requests/minute (AdminAPI policy)

        ### Authentication

        All admin endpoints require:
        - **Header**: `X-Admin-Secret: {secret}` — compared using fixed-time comparison
        - **IP Whitelist** (optional): `AdminSettings:AllowedIps` in config (comma-separated)
        - Localhost (127.0.0.1, ::1) always allowed

        Unauthorized requests return `401 Unauthorized`.

        ---

        ### POST /api/admin/products

        Create a new product with auto-generated RSA-4096 keys.

        **Request Body:** (raw string)
        ```json
        "MyProduct"
        ```

        **Response (200):**
        ```json
        {
          "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "name": "MyProduct",
          "publicKeyXml": "<RSAKeyValue><Modulus>...</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
        }
        ```

        **Behavior:**
        - Validates name is unique
        - Generates RSA-4096 key pair
        - Encrypts private key with DataProtection API
        - Generates unique ApiSecret

        ---

        ### GET /api/admin/products

        List all products.

        **Response (200):**
        ```json
        [
          { "id": "guid", "name": "MyProduct" },
          { "id": "guid", "name": "MyPlugin" }
        ]
        ```

        ---

        ### GET /api/admin/products/{id}/key-check

        Diagnostic: verify RSA key pair integrity.

        **Response (200):**
        ```json
        {
          "status": "OK",
          "publicModulus": "first-32-chars...",
          "privateModulus": "first-32-chars...",
          "keysMatch": true
        }
        ```

        **Possible statuses:** `OK`, `ERROR` (decryption failed), `MISMATCH` (modulus mismatch)

        ---

        ### PUT /api/admin/products/{id}/keys

        Replace product RSA keys (emergency key rotation).

        **Request Body:**
        ```json
        {
          "privateKeyXml": "<RSAKeyValue>...full private key XML...</RSAKeyValue>"
        }
        ```

        **Behavior:**
        - Validates RSA XML format
        - Extracts public key from private key
        - Re-encrypts and stores both keys

        ---

        ### POST /api/admin/licenses

        Create a new license.

        **Request Body:**
        ```json
        {
          "productName": "MyProduct",
          "customerName": "John Doe",
          "customerEmail": "john@example.com",
          "typeSlug": "PRO",
          "daysValidity": 365,
          "reference": "INV-2024-001"
        }
        ```

        **Response (200):**
        ```json
        {
          "licenseKey": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        }
        ```

        **Key format:** `Guid.NewGuid().ToString("D").ToUpper()` (e.g., `A1B2C3D4-E5F6-7890-ABCD-EF1234567890`)

        ---

        ### GET /api/admin/licenses

        List licenses with optional product filter.

        **Query Parameters:**
        - `productName` (string, optional) — filter by product name

        **Response (200):**
        ```json
        [
          {
            "id": "guid",
            "product": "MyProduct",
            "licenseKey": "XXXX-...",
            "customerName": "John Doe",
            "type": "PRO",
            "isActive": true,
            "hardwareId": "A1B2C3D4E5F67890",
            "expirationDate": "2025-01-15T00:00:00Z"
          }
        ]
        ```

        ---

        ### POST /api/admin/licenses/{licenseKey}/renew

        Renew a recurring license (subscription model).

        **Request Body:**
        ```json
        {
          "transactionId": "stripe_pi_123456789",
          "reference": "INV-2024-002"
        }
        ```

        **Response (200):**
        ```json
        {
          "licenseKey": "XXXX-...",
          "newExpirationDate": "2026-01-15T00:00:00Z",
          "reference": "INV-2024-002",
          "message": "License renewed"
        }
        ```

        **Behavior:**
        - License type must have `IsRecurring = true`
        - `TransactionId` must be unique (idempotency — duplicate returns 409)
        - Extends expiration by `LicenseType.DefaultDurationDays`
        - Reactivates license if it was expired
        - Creates `LicenseRenewal` record and `RENEWED` history entry
        """;

    // ── Section 11: WPF Client Integration ────────────────────────────

    private static string GetClientIntegration() => """
        ## 11. WPF Client Integration

        ### Required Packages

        - `SoftLicence.SDK` — Core library (LicenseService, HardwareInfo, SoftLicenceClient)
        - `SoftLicence.UI` — WPF window and ViewModel (ActivationWindow, LicenseActivationViewModel)

        ### SoftLicenceClient (Low-Level API)

        ```csharp
        var client = new SoftLicenceClient("https://your-server:5200", "MyProduct");

        // Activate (with optional customer info)
        var result = await client.ActivateAsync(licenseKey, appName,
            customerEmail: "user@example.com", customerName: "John Doe");
        // result.IsSuccess, result.LicenseFile, result.ErrorMessage

        // Check status
        var status = await client.CheckStatusAsync(licenseKey, appName);
        // status.Status: "VALID", "REVOKED", "EXPIRED", etc.

        // Trial (with optional customer info)
        var trial = await client.RequestTrialAsync(appName, typeSlug: "TRIAL",
            customerEmail: "user@example.com", customerName: "John Doe");
        ```

        ### LicenseActivationViewModel (High-Level MVVM)

        Properties:
        - `LicenseKey` (string) — user input
        - `StatusMessage` (string) — display feedback
        - `IsActivated` (bool) — activation state
        - `IsLoading` (bool) — async operation in progress
        - `LicenseModel` (LicenseModel?) — parsed license data after activation

        Commands:
        - `ActivateCommand` — trigger activation flow
        - `DeactivateCommand` — clear local license

        ### Activation Flow (Cold Start)

        ```
        1. App starts
        2. Check local cache: %LOCALAPPDATA%/{appName}/license.lic
        3. If cache exists:
           a. Verify signature offline (public key)
           b. Check expiration
           c. Validate HardwareId
           d. If valid → app starts, schedule periodic check
        4. If cache missing or invalid:
           a. Show ActivationWindow
           b. User enters license key
           c. POST /api/activation with key + HardwareId
           d. Server returns signed license file
           e. Save to local cache
           f. App starts
        ```

        ### Periodic Verification

        - Timer: every **2 hours**
        - Calls `POST /api/activation/check`
        - If status != VALID → revoke mid-session (show message, disable features)

        ### Local Storage

        - Path: `%LOCALAPPDATA%/{appName}/license.lic`
        - Content: Base64-encoded signed JSON (same as server response)
        - The file is self-validating: signature verification + expiration check

        ### Reading Custom Parameters

        ```csharp
        // After activation, LicenseModel.Features contains custom params
        int maxAccounts = model.GetParam<int>("max_accounts", 5);
        string tier = model.GetParam<string>("tier", "basic");
        bool canExport = model.GetParam<bool>("can_export", false);
        ```

        ### XAML Binding Example

        ```xml
        <Window DataContext="{Binding ActivationVM}">
            <StackPanel>
                <TextBox Text="{Binding LicenseKey, UpdateSourceTrigger=PropertyChanged}" />
                <Button Command="{Binding ActivateCommand}" Content="Activate" />
                <TextBlock Text="{Binding StatusMessage}" />
                <ProgressBar IsIndeterminate="{Binding IsLoading}" />
            </StackPanel>
        </Window>
        ```

        ### Starter Template vs Advanced Sample

        - **SoftLicence.Template**: Minimal starter — shows basic activation window integration
        - **samples/SoftLicence.Samples.SimpleApp**: Advanced — includes Obfuscar integration for release builds
        """;

    // ── Section 12: RBAC ──────────────────────────────────────────────

    private static string GetRbac() => """
        ## 12. Users & Roles (RBAC)

        ### Authentication Types

        #### 1. Root Account (from appsettings.json)

        ```json
        {
          "AdminSettings": {
            "Username": "admin",
            "Password": "secure-password",
            "ApiSecret": "api-secret-for-header"
          }
        }
        ```

        - Has **all permissions** (CHANGE_ME_RANDOM_SECRET role)
        - Cannot be deleted or disabled
        - Login path: configured via `AdminSettings:LoginPath`
        - Used for initial setup and emergency access

        #### 2. Database Admin Users

        Stored in `AdminUsers` table with:
        - `Username` + `PasswordHash` (bcrypt cost=12)
        - `RoleId` → links to `AdminRole` for permissions
        - `AdminPath` → custom login URL per user (e.g., `/coco` instead of default login path)
        - `MustChangePassword` → forces password change on first login
        - `IsEnabled` → can be disabled without deletion

        ### AdminRole Permissions

        Permissions are stored as CSV in the `Permissions` column:

        ```
        dashboard.view, products.view, products.edit, products.delete,
        licenses.view, licenses.edit, licenses.delete,
        audit.view, telemetry.view, maintenance.view,
        settings.view, settings.edit, users.view, users.edit
        ```

        ### Permission Check Flow

        ```csharp
        // In Blazor components:
        @inject AuthService Auth

        if (await Auth.HasPermissionAsync("products.edit"))
        {
            // show edit button
        }
        ```

        1. Check if user is authenticated
        2. If role = "CHANGE_ME_RANDOM_SECRET" → return true (all permissions)
        3. Read "Permissions" claim from cookie → split by comma
        4. Check if requested permission is in the list (or "all")

        ### Cookie Authentication

        - Cookie name: `SoftLicence_Auth`
        - Expiry: 7 days
        - **Stealth mode**: unauthenticated requests to protected pages return HTTP 404
          (never redirects to login page, preventing login URL discovery)

        ### Login Endpoint

        ```
        POST /account/login
        Content-Type: application/x-www-form-urlencoded

        username=admin&password=secret
        ```

        - First checks root account (appsettings.json)
        - Then checks database AdminUsers (bcrypt verify)
        - Sets authentication cookie with claims: Name, Role, Permissions, MustChangePassword
        """;

    // ── Section 13: Webhooks ──────────────────────────────────────────

    private static string GetWebhooks() => """
        ## 13. Webhook Notifications

        SoftLicence supports two webhook systems:

        ### A. Global Webhooks (System Events)

        Configured in the admin UI (Maintenance page), stored in the `Webhooks` table.
        These fire for system-wide events like security alerts and license operations.

        | Field | Description |
        |-------|-------------|
        | Name | Display name (max 100 chars) |
        | Url | Target URL (validated) |
        | EnabledEvents | CSV of event triggers |
        | IsEnabled | Active/inactive toggle |

        **Available Global Triggers:**

        | Trigger | Description |
        |---------|-------------|
        | `Security.IpBanned` | An IP address has been banned |
        | `Security.ZombieDetected` | Zombie license detected (>5 IPs/24h) |
        | `Security.AuthFailure` | Authentication failure on admin endpoints |
        | `License.Created` | A new license has been created |
        | `License.Activated` | A license has been activated on a device |
        | `System.Startup` | Server has started |

        ### B. Product Webhooks (Telemetry)

        Configured per-product in the admin UI (Products page), stored in the `ProductWebhooks` table.
        These fire whenever telemetry data is received for the specific product.

        | Field | Description |
        |-------|-------------|
        | Name | Display name (max 100 chars) |
        | Url | Target URL (validated) |
        | Secret | Optional authentication secret |
        | IsEnabled | Active/inactive toggle |

        **Telemetry triggers (per-product):**

        | Trigger | Description |
        |---------|-------------|
        | `Telemetry.Event` | A telemetry event has been received |
        | `Telemetry.Diagnostic` | A diagnostic report has been received |
        | `Telemetry.Error` | An error report has been received |

        **Product Webhook Payload:**

        ```json
        {
          "trigger": "Telemetry.Event",
          "title": "Event: AppStarted",
          "message": "MyProduct v1.2.3 — A1B2C3D4",
          "timestamp": "2024-01-15T10:30:00Z",
          "data": { ... full request DTO ... }
        }
        ```

        **Headers sent:**
        - `Content-Type: application/json`
        - `X-Webhook-Secret: {secret}` (only if a secret is configured on the webhook)

        ### Standard Global Webhook Payload

        ```json
        {
          "trigger": "Security.IpBanned",
          "title": "IP Banned",
          "message": "IP 1.2.3.4 banned for proactive scanning",
          "timestamp": "2024-01-15T10:30:00Z",
          "data": {
            "ip": "1.2.3.4",
            "reason": "Proactive scan: /wp-CHANGE_ME_LOGIN_PATH.php",
            "banCount": 2,
            "duration": "7 days"
          }
        }
        ```

        ### NTFY Integration (Global Webhooks)

        If the webhook URL contains "ntfy", the service uses ntfy-specific formatting:
        - Body: plain text message
        - Query parameters: `title`, `tags` (mapped to trigger emoji), `priority` (3)
        - This provides native push notifications on mobile devices

        ### Error Handling

        - `LastTriggeredAt`: updated on each webhook call
        - `LastError`: stores error message if delivery fails
        - Webhooks are fire-and-forget (don't block the triggering operation)
        - Failed deliveries are logged but not retried
        """;

    // ── Section 14: Configuration & Deployment ────────────────────────

    private static string GetConfig() => """
        ## 14. Configuration & Deployment

        ### appsettings.json Structure

        ```json
        {
          "AdminSettings": {
            "Username": "admin",
            "Password": "your-password",
            "ApiSecret": "your-api-secret",
            "LoginPath": "mon-entree-secrete",
            "AllowedIps": ""
          },
          "RetentionSettings": {
            "CleanupEnabled": false,
            "CleanupIntervalHours": 24,
            "AuditLogsDays": 30,
            "TelemetryDays": 90
          },
          "BackupSettings": {
            "Enabled": false,
            "RcloneRemote": "gdrive-crypt:softlicence",
            "DatabaseBackupPath": "backups/db",
            "KeysBackupPath": "backups/keys"
          },
          "SmtpSettings": {
            "Host": "smtp.example.com",
            "Port": 587,
            "Username": "noreply@example.com",
            "Password": "smtp-password",
            "FromEmail": "noreply@example.com",
            "FromName": "SoftLicence"
          },
          "ConnectionStrings": {
            "DefaultConnection": "Host=localhost;Database=softlicence;Username=postgres;Password=..."
          }
        }
        ```

        ### Environment Variables (Docker)

        All settings can be overridden via environment variables using double-underscore notation:

        ```
        AdminSettings__Username=admin
        AdminSettings__Password=secure-password
        AdminSettings__ApiSecret=my-api-secret
        AdminSettings__LoginPath=secret-path
        ConnectionStrings__DefaultConnection=Host=db;Database=softlicence;...
        SmtpSettings__Host=smtp.example.com
        ```

        ### Docker Deployment

        ```yaml
        # Docker/docker-compose.yml
        services:
          db:
            image: postgres:16
            volumes:
              - pgdata:/var/lib/postgresql/data
            environment:
              POSTGRES_DB: softlicence
              POSTGRES_USER: postgres
              POSTGRES_PASSWORD: ${DB_PASSWORD}

          server:
            build: ..
            ports:
              - "5200:5200"
            volumes:
              - appdata:/app/data
            environment:
              ConnectionStrings__DefaultConnection: Host=db;Database=softlicence;...
              AdminSettings__Username: ${ADMIN_USER}
              AdminSettings__Password: ${ADMIN_PASSWORD}
            depends_on:
              - db
        ```

        ### Available Scripts

        | Script | Purpose |
        |--------|---------|
        | `scripts/build.ps1` | Build solution, optional `-Run` to start server |
        | `scripts/build.ps1 -Clean` | Clean build artifacts |
        | `scripts/Admin-Cli.ps1` | PowerShell CLI for API interaction |
        | `tests/api-test.ps1` | Integration test suite |

        ### Backup System (rclone)

        - **Tool**: rclone with encrypted Google Drive remote
        - **Database**: `pg_dump` → `.sql` file → rclone upload
        - **RSA Keys**: uploaded individually per product
        - **Schedule**: daily (via CleanupService if enabled)
        - **Health check**: `BackupService.CheckHealthAsync()` verifies rclone + remote config

        ### Automatic Retention

        | Data | Default Retention | Config Key |
        |------|-------------------|------------|
        | Audit logs (AccessLog) | 30 days | `RetentionSettings:AuditLogsDays` |
        | Telemetry records | 90 days | `RetentionSettings:TelemetryDays` |

        Cleanup runs as a background `HostedService`:
        - Initial delay: 30 seconds after startup
        - Interval: configurable (default 24 hours)
        - Includes `VACUUM ANALYZE` for PostgreSQL after cleanup
        """;

    // ── Section 15: Troubleshooting ───────────────────────────────────

    private static string GetTroubleshooting() => """
        ## 15. Troubleshooting

        ### RSA Key Diagnostics

        ```http
        GET /api/admin/products/{productId}/key-check
        X-Admin-Secret: {secret}
        ```

        | Status | Meaning | Fix |
        |--------|---------|-----|
        | `OK` | Keys are valid and match | No action needed |
        | `ERROR` | Private key decryption failed | DataProtection key rotation issue — re-inject keys via PUT /api/admin/products/{id}/keys |
        | `MISMATCH` | Public/private key modulus mismatch | Keys were corrupted — re-inject matching pair |

        ### DataProtection / Decryption Errors

        **Symptom**: `ERROR_DECRYPTION_FAILED` when trying to sign licenses

        **Causes:**
        1. Server migrated to new machine (DataProtection keys don't follow)
        2. Docker volume for `/app/data/keys/` was lost
        3. Application name changed

        **Fix:**
        1. Re-inject the original private key XML via `PUT /api/admin/products/{id}/keys`
        2. Or restore the DataProtection keys from backup (`/app/data/keys/` directory)

        ### Hardware ID Issues

        **Symptom**: `HARDWARE_MISMATCH` on activation check

        **Common causes:**
        - CPU, motherboard, or disk was replaced
        - Machine was renamed
        - Running on non-Windows platform (all components return "NON-WINDOWS")
        - WMI service not running (components return "UNKNOWN")

        **Fix:**
        1. Self-service reset: `POST /api/activation/reset-request` + `reset-confirm`
        2. Admin unlink: via admin UI (Licenses → device management)
        3. Admin API: The admin can create a new license or reset the existing one

        ### Self-Service Reset Issues

        **"No email configured"**: License was created without `CustomerEmail`. Admin must set it in the UI.

        **"Code expired"**: Reset codes expire after 15 minutes. Request a new one.

        **"Invalid code"**: Codes are 6 digits and case-sensitive. Check for typos.

        ### IP Ban / Quarantine

        **Check if IP is banned:**
        Look in the Audit Logs page for the IP address. Banned IPs show in the BannedIps table.

        **Unban an IP:**
        1. Admin UI: Maintenance → IP Management
        2. Direct DB: Delete from `BannedIps` where `IpAddress = '{ip}'`

        **Reduce threat score:**
        Threat scores reset to 0 after a ban expires. There is no manual score reduction.

        ### Common Activation Errors

        | Error | Cause | Solution |
        |-------|-------|----------|
        | "Product not found" | AppName doesn't match any product | Check product name (case-insensitive) or use AppId (Guid) |
        | "License key not found" | Key doesn't exist for this product | Verify key format (UUID uppercase) |
        | "License is disabled" | License was revoked | Admin must reactivate in UI |
        | "License has expired" | ExpirationDate passed | Renew via API or create new license |
        | "Version not allowed" | Client version doesn't match AllowedVersions mask | Update mask in license type or client version |
        | "Seat limit reached" | MaxSeats exceeded | Unlink old devices or increase MaxSeats |
        | "Decryption error" | Server can't read private key | See DataProtection section above |

        ### Zombie Detection False Positives

        **Symptom**: License revoked with reason "Zombie detection"

        **Cause**: Same HardwareId seen from >5 IPs in 24h. Can happen with:
        - VPN users changing servers frequently
        - Corporate networks with multiple exit IPs
        - Mobile hotspot users

        **Fix:**
        1. Admin reactivates the license in the UI
        2. Consider increasing the zombie threshold (currently hardcoded at 5)
        3. Whitelist known corporate IPs in `AdminSettings:AllowedIps`
        """;

    // ── DTOs ──────────────────────────────────────────────────────────

    public class SectionInfo
    {
        public string Id { get; set; } = "";
        public string Title { get; set; } = "";
        public string Url { get; set; } = "";
    }

    public class SearchResult
    {
        public string Section { get; set; } = "";
        public string SectionTitle { get; set; } = "";
        public int Line { get; set; }
        public string Content { get; set; } = "";
        public string Url { get; set; } = "";
    }
}

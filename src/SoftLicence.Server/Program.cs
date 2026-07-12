using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Components;
using SoftLicence.Server;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using System.Net;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Réseaux privés exemptés du rate limiting (Docker, loopback)
static bool IsPrivateNetwork(IPAddress? ip)
{
    if (ip == null) return false;
    if (IPAddress.IsLoopback(ip)) return true;
    if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
    var bytes = ip.GetAddressBytes();
    if (bytes.Length != 4) return false;
    return bytes[0] == 10                                           // 10.0.0.0/8
        || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)   // 172.16.0.0/12
        || (bytes[0] == 192 && bytes[1] == 168);                   // 192.168.0.0/16
}

static string GetRateLimitPartition(HttpContext ctx)
{
    var ip = ctx.Connection.RemoteIpAddress;
    return IsPrivateNetwork(ip) ? "__unlimited__" : (ip?.ToString() ?? "unknown");
}

// Configuration du Rate Limiting (Protection anti-spam)
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, cancellationToken) =>
    {
        const int retryAfterSeconds = 60;

        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.ContentType = "application/json";
        context.HttpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString();

        await context.HttpContext.Response.WriteAsJsonAsync(
            new { error = "rate_limited", retryAfterSeconds },
            cancellationToken);
    };

    // Politique pour l'activation client (Stricte) — IPs privées exemptées
    options.AddPolicy("PublicAPI", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(GetRateLimitPartition(ctx), key =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = key == "__unlimited__" ? 10000 : 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    // Politique pour l'administration (Plus souple) — IPs privées exemptées
    options.AddPolicy("AdminAPI", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(GetRateLimitPartition(ctx), key =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = key == "__unlimited__" ? 10000 : 100,
                Window = TimeSpan.FromMinutes(1)
            }));

    // Politique pour la documentation LLM (Modérée) — IPs privées exemptées
    options.AddPolicy("DocsAPI", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(GetRateLimitPartition(ctx), key =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = key == "__unlimited__" ? 10000 : 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    // Politique pour la télémétrie (Souple) — les clients envoient en rafale
    options.AddPolicy("TelemetryAPI", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(GetRateLimitPartition(ctx), key =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = key == "__unlimited__" ? 10000 : 120,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    // Politique pour le proxy BugTrace. Le desktop enchaine lectures et commentaires
    // pendant un flux normal, donc la limite IP doit rester souple.
    options.AddPolicy("BugTraceAPI", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(GetRateLimitPartition(ctx), key =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = key == "__unlimited__" ? 10000 : 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));
});

// Configuration DataProtection (Persistance des clés de session)
var keysFolder = Path.Combine(builder.Environment.ContentRootPath, "data", "keys");
Directory.CreateDirectory(keysFolder);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysFolder))
    .SetApplicationName("SoftLicence");

// Localization (i18n)
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");

// Services API
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Auth Services
var rawLoginConfig = builder.Configuration["AdminSettings:LoginPath"] ?? "login";
var loginPathValue = rawLoginConfig.Replace("\"", "").Trim().Trim('/');
var loginPath = "/" + loginPathValue;

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "SoftLicence_Auth";
        options.LoginPath = loginPath;
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        // Stealth Mode: never redirect to the secret login path.
        // Unauthenticated requests get a 404 instead of leaking the login URL.
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = 404;
            context.Response.ContentType = "text/html; charset=utf-8";
            return context.Response.WriteAsync("""
                <!DOCTYPE html>
                <html><head><title>404</title><link rel="icon" type="image/png" href="/favicon.png?v=3" /></head>
                <body style="display:flex;justify-content:center;align-items:center;height:100vh;background-color:#121212;color:#6c757d;font-family:'Segoe UI',sans-serif;margin:0;">
                <div style="text-align:center;"><h1 style="font-size:4rem;margin:0;">404</h1><p>Page inexistante.</p></div>
                </body></html>
                """);
        };
    });
builder.Services.AddCascadingAuthenticationState();

// Services Blazor (Admin UI)
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents(options => 
    {
        options.DetailedErrors = true;
    });

builder.Services.AddSingleton<SoftLicence.Server.Services.DocumentationService>(); // Documentation LLM
builder.Services.AddScoped<SoftLicence.Server.Services.ToastService>();
builder.Services.AddSingleton<SoftLicence.Server.Services.SettingsService>(); 
builder.Services.AddScoped<SoftLicence.Server.Services.AuthService>(); // Service d'autorisation custom
builder.Services.AddScoped<SoftLicence.Server.Services.TimeZoneService>(); // Gestion Fuseau Horaire
builder.Services.AddScoped<SoftLicence.Server.Services.SecurityService>(); // Défense Active
builder.Services.AddScoped<SoftLicence.Server.Services.EncryptionService>(); // Chiffrement des clés
builder.Services.AddSingleton<SoftLicence.Server.Services.BackupService>(); // Sauvegardes Drive (rclone)
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<SoftLicence.Server.Services.GeoIpService>(); // Intelligence Geo-IP
builder.Services.AddTransient<SoftLicence.Server.Services.EmailService>();
builder.Services.AddSingleton<SoftLicence.Server.Services.AuditNotifier>(); // Push temps réel audit logs
builder.Services.AddSingleton<SoftLicence.Server.Services.NotificationService>(); // Webhooks & Alertes
builder.Services.AddTransient<SoftLicence.Server.Services.StatsService>(); // Stats
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryAnalyticsService>(); // Telemetry Analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryOverviewAnalyticsService>(); // Telemetry overview analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryDevicesAnalyticsService>(); // Telemetry devices analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetrySchemaAnalyticsService>(); // Telemetry schema analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryToolUsageAnalyticsService>(); // Telemetry tool usage analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryQuotaAnalyticsService>(); // Telemetry quota analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryCertPinningAnalyticsService>(); // Telemetry cert pinning analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryActivationFunnelAnalyticsService>(); // Telemetry activation funnel analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryActivationFailuresAnalyticsService>(); // Telemetry activation failure detail analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryMachineProfileAnalyticsService>(); // Telemetry machine profile analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetrySupportProfileAnalyticsService>(); // Telemetry support lookup analytics
builder.Services.AddTransient<SoftLicence.Server.Services.CustomerLicenseTimelineAnalyticsService>(); // Global customer/license support timeline analytics
builder.Services.AddTransient<SoftLicence.Server.Services.HwidReuseAlertService>(); // HWID reuse security alerts
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryVersionHealthAnalyticsService>(); // Telemetry version health analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryStartupHealthAnalyticsService>(); // Telemetry startup health analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryRawSampleAnalyticsService>(); // Telemetry redacted raw sample analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryInsightsAnalyticsService>(); // Telemetry insights analytics
builder.Services.AddTransient<SoftLicence.Server.Services.LicenseDurationMigrationImpactAnalyticsService>(); // License duration migration impact analytics
builder.Services.AddTransient<SoftLicence.Server.Services.FreemiumActivityRankingAnalyticsService>(); // Freemium activity and conversion ranking analytics
builder.Services.AddTransient<SoftLicence.Server.Services.RecentLicenseOnboardingMetricsAnalyticsService>(); // Recent license onboarding Time-To-Value analytics
builder.Services.AddTransient<SoftLicence.Server.Services.LicenseUsageScoringAnalyticsService>(); // License usage conversion and retention scoring analytics
builder.Services.AddTransient<SoftLicence.Server.Services.TelemetryLicenseHardwareAuditAnalyticsService>(); // Telemetry/license/HWID audit analytics
builder.Services.AddTransient<SoftLicence.Server.Services.LicenseSeatConsistencyCheckService>(); // Read-only license seat/legacy consistency check
builder.Services.AddTransient<SoftLicence.Server.Services.LicenseHardwareVerifierAnalyticsService>(); // Authoritative license/HWID verifier for server-to-server consumers
builder.Services.AddTransient<SoftLicence.Server.Services.FreemiumAbuseRiskAnalyticsService>(); // Freemium group abuse risk analytics
builder.Services.AddTransient<SoftLicence.Server.Services.AnalyticsApiKeyAuthService>(); // Analytics/MCP API key auth
builder.Services.AddTransient<SoftLicence.Server.Services.LlmTipFeedbackService>(); // LLM tips feedback dedicated ingestion
builder.Services.AddTransient<SoftLicence.Server.Services.SecurityBanAuditAnalyticsService>(); // Security ban read-only audit analytics
builder.Services.AddTransient<SoftLicence.Server.Services.SecurityCaseContextService>(); // Shared securityCaseId and redacted enrichment context
builder.Services.AddTransient<SoftLicence.Server.Services.CertPinningBugTraceAlertService>(); // Auto BugTrace tickets for cert pinning alerts
builder.Services.AddTransient<SoftLicence.Server.Services.FreemiumAbuseBugTraceAlertService>(); // Auto BugTrace tickets for Freemium abuse risk alerts
builder.Services.AddScoped<SoftLicence.Server.Services.TelemetryService>(); // Télémétrie
builder.Services.AddScoped<SoftLicence.Server.Services.FingerprintService>(); // Hardware Fingerprints
builder.Services.AddScoped<SoftLicence.Server.Services.SeatCleanupService>(); // Enforcement un HWID par produit
builder.Services.AddTransient<SoftLicence.Server.Services.PiracyDetectionService>(); // Détection piratage
builder.Services.AddSingleton<SoftLicence.Server.Services.IBugTraceProxyService, SoftLicence.Server.Services.BugTraceProxyService>(); // Proxy BugTrace
builder.Services.AddTransient<SoftLicence.Server.Services.AiAnalysisService>(); // Analyse IA télémétrie
builder.Services.AddHostedService<SoftLicence.Server.Services.CleanupService>(); // Nettoyage Automatique
builder.Services.Configure<SoftLicence.Server.Services.SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.AddHttpClient(); // Pour GeoIP et Webhooks

// Database Configuration
builder.Services.AddSoftLicenceDatabase(builder.Configuration);

builder.Services.AddQuickGridEntityFrameworkAdapter();

var app = builder.Build();

// 1. CONFIGURATION PROXY (DOIT ETRE EN PREMIER POUR L'IP REELLE)
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
    ForwardLimit = 2, // Traefik/Docker + éventuel CDN
    ForwardedForHeaderName = "X-Forwarded-For",
    ForwardedProtoHeaderName = "X-Forwarded-Proto",
    RequireHeaderSymmetry = false,
    KnownNetworks = { new Microsoft.AspNetCore.HttpOverrides.IPNetwork(System.Net.IPAddress.Parse("172.16.0.0"), 12) }, // Réseau Docker
    KnownProxies = { System.Net.IPAddress.Loopback }
});

app.UseRateLimiter(); 

app.UseStaticFiles();

// Localization middleware
var supportedCultures = new[] { "en", "fr" };
app.UseRequestLocalization(options =>
{
    options.SetDefaultCulture("en");
    options.AddSupportedCultures(supportedCultures);
    options.AddSupportedUICultures(supportedCultures);
    options.ApplyCurrentCultureToResponseHeaders = true;
});

app.UseAntiforgery();

app.UseAuthentication();

// 2. LOGGING D'AUDIT GLOBAL (Placé AVANT l'autorisation pour capturer les accès refusés)
app.UseMiddleware<SoftLicence.Server.Middlewares.AuditMiddleware>();

app.UseAuthorization();

// Application des Migrations avec Retry Logic
if (builder.Configuration["IsIntegrationTest"] != "true")
{
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<LicenseDbContext>();

        int retryCount = 0;
        const int maxRetries = 10;
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        
        if (app.Environment.IsDevelopment())
        {
            // Diagnostic DNS
            try {
                var host = connectionString?.Split(';').FirstOrDefault(s => s.StartsWith("Host="))?.Split('=')[1];
                if (!string.IsNullOrEmpty(host)) {
                    Console.WriteLine($"🌐 Résolution DNS pour : {host}...");
                    var ips = System.Net.Dns.GetHostAddresses(host);
                    Console.WriteLine($"🌐 DNS {host} résolu en : {string.Join(", ", ips.Select(i => i.ToString()))}");
                }
            } catch (Exception ex) { Console.WriteLine($"🌐 DNS Wait : {ex.Message}"); }

            var displayConn = connectionString?.Split(';').Select(s => s.StartsWith("Password") ? "Password=***" : s).Aggregate((a, b) => a + ";" + b);
            Console.WriteLine($"🔍 Tentative de connexion : {displayConn}");
        }

        while (retryCount < maxRetries)
        {
            try 
            {
                db.Database.Migrate();
                if (app.Environment.IsDevelopment())
                {
                    Console.WriteLine("✅ Base de données prête et migrations appliquées.");
                }

                break;
            }
            catch (Exception ex)
            {
                retryCount++;
                if (app.Environment.IsDevelopment())
                {
                    Console.WriteLine($"⚠️ Tentative {retryCount}/{maxRetries} échouée.");
                    Console.WriteLine($"   Erreur : {ex.GetType().Name} - {ex.Message}");
                    if (ex.InnerException != null) Console.WriteLine($"   Interne : {ex.InnerException.Message}");
                }

                if (retryCount >= maxRetries)
                {
                    Console.WriteLine($"[FATAL] Impossible de se connecter à PostgreSQL après {maxRetries} tentatives.");
                    throw; 
                }
                
                if (app.Environment.IsDevelopment())
                {
                    Console.WriteLine($"[WAIT] PostgreSQL n'est pas encore prêt. Attente de 5s...");
                }
                Thread.Sleep(5000); 
            }
        }
    }
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.MapControllers(); 

// Blazor Routes
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

// Requis pour les tests d'intégration
public partial class Program { }

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

if (builder.Configuration.GetValue<bool>("Database:RuntimeKeyRegistryOperator:Enabled"))
{
    await SoftLicence.Server.Services.RuntimeEnrollmentKeyRegistryOperatorRunner.RunAsync(
        builder.Configuration);
    return;
}

if (builder.Configuration.GetValue<bool>("Database:MigrationOnly"))
{
    await DatabaseMigrationRunner.RunAsync(builder.Configuration);
    return;
}

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
        if (context.HttpContext.Request.Path.StartsWithSegments("/api/v1/runtime-enrollments")
            || context.HttpContext.Request.Path.StartsWithSegments("/api/internal/v1/runtime-enrollments"))
        {
            context.HttpContext.Response.Headers.CacheControl = "no-store, max-age=0";
            context.HttpContext.Response.Headers.Pragma = "no-cache";
        }

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

    // Distribution v2 S2S: private callers remain bounded; authentication has
    // its own nonce replay protection in addition to this transport throttle.
    options.AddPolicy("DistributionS2SAPI", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    // Runtime enrollment proof endpoints: deliberately bounded even for private
    // callers because every accepted request performs asymmetric cryptography.
    options.AddPolicy("RuntimeEnrollmentPublicAPI", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
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
builder.Services.AddControllers()
    .ConfigureApiBehaviorOptions(options =>
    {
        options.InvalidModelStateResponseFactory = context =>
            context.HttpContext.Request.Path.StartsWithSegments("/api/telemetry")
                ? new Microsoft.AspNetCore.Mvc.BadRequestObjectResult(new
                {
                    errorCode = "TELEMETRY_MODEL_VALIDATION_FAILED",
                    correlationId = context.HttpContext.TraceIdentifier,
                    invalidFields = context.ModelState
                        .Where(x => x.Value?.Errors.Count > 0)
                        .Select(x => x.Key)
                        .OrderBy(x => x, StringComparer.Ordinal)
                        .ToArray()
                })
                : new Microsoft.AspNetCore.Mvc.BadRequestObjectResult(
                    new Microsoft.AspNetCore.Mvc.ValidationProblemDetails(context.ModelState));
    });
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
builder.Services.AddScoped<SoftLicence.Server.Services.AdminSecretAuthenticationService>(); // Auth API admin globale/produit
builder.Services.AddScoped<SoftLicence.Server.Services.IPrivateValidationTestResetService,
    SoftLicence.Server.Services.PrivateValidationTestResetService>();
builder.Services.AddScoped<SoftLicence.Server.Services.ApprovedBinaryService>(); // Baselines binaires autoritatives
builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<SoftLicence.Server.Services.DistributionS2SOptions>,
    SoftLicence.Server.Services.DistributionS2SOptionsValidator>();
builder.Services.AddOptions<SoftLicence.Server.Services.DistributionS2SOptions>()
    .Bind(builder.Configuration.GetSection("DistributionS2S"))
    .ValidateOnStart();
builder.Services.AddScoped<SoftLicence.Server.Services.IDistributionS2SAuthenticationService,
    SoftLicence.Server.Services.DistributionS2SAuthenticationService>();
builder.Services.AddScoped<SoftLicence.Server.Services.IDistributionInstallationBindingService,
    SoftLicence.Server.Services.DistributionInstallationBindingService>();
builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<SoftLicence.Server.Services.RuntimeEnrollmentOptions>,
    SoftLicence.Server.Services.RuntimeEnrollmentOptionsValidator>();
builder.Services.AddOptions<SoftLicence.Server.Services.RuntimeEnrollmentOptions>()
    .Bind(builder.Configuration.GetSection("RuntimeEnrollment"))
    .PostConfigure(SoftLicence.Server.Services.RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders)
    .ValidateOnStart();
builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<SoftLicence.Server.Services.CanaryAckOptions>,
    SoftLicence.Server.Services.CanaryAckOptionsValidator>();
builder.Services.AddOptions<SoftLicence.Server.Services.CanaryAckOptions>()
    .Bind(builder.Configuration.GetSection("CanaryAck"));
builder.Services.AddSingleton<SoftLicence.Server.Services.ICanaryAckKeyring,
    SoftLicence.Server.Services.CanaryAckKeyring>();
builder.Services.AddSingleton<SoftLicence.Server.Services.ICanaryAckKeyRegistryService,
    SoftLicence.Server.Services.CanaryAckKeyRegistryService>();
builder.Services.AddHostedService<SoftLicence.Server.Services.CanaryAckKeyRegistryStartupValidator>();
builder.Services.AddSingleton<SoftLicence.Server.Services.IRuntimeEnrollmentAuthorityService,
    SoftLicence.Server.Services.RuntimeEnrollmentAuthorityService>();
builder.Services.AddSingleton<SoftLicence.Server.Services.IRuntimeEnrollmentCryptoService,
    SoftLicence.Server.Services.RuntimeEnrollmentCryptoService>();
builder.Services.AddScoped<SoftLicence.Server.Services.IRuntimeEnrollmentService,
    SoftLicence.Server.Services.RuntimeEnrollmentService>();
builder.Services.AddScoped<SoftLicence.Server.Services.IDistributionLicenseBootstrapService,
    SoftLicence.Server.Services.DistributionLicenseBootstrapService>();
builder.Services.AddHostedService<SoftLicence.Server.Services.RuntimeEnrollmentStartupValidator>();
builder.Services.AddSingleton<SoftLicence.Server.Services.IRuntimeEnrollmentKeyRegistryService,
    SoftLicence.Server.Services.RuntimeEnrollmentKeyRegistryService>();
builder.Services.AddHostedService<SoftLicence.Server.Services.RuntimeEnrollmentKeyRegistryStartupValidator>();
builder.Services.AddHostedService<SoftLicence.Server.Services.RuntimeEnrollmentCleanupService>();
builder.Services.AddScoped<SoftLicence.Server.Services.CanaryAckService>(); // Reçus canaris signés et anti-rejeu
builder.Services.AddScoped<SoftLicence.Server.Services.EncryptionService>(); // Chiffrement des clés
builder.Services.AddScoped<SoftLicence.Server.Services.ISignedLicenseFileService,
    SoftLicence.Server.Services.SignedLicenseFileService>();
builder.Services.AddSingleton<SoftLicence.Server.Services.IBackupProcessRunner,
    SoftLicence.Server.Services.BackupProcessRunner>();
builder.Services.AddSingleton<SoftLicence.Server.Services.BackupService>(); // Sauvegardes Drive (rclone)
builder.Services.AddMemoryCache();
builder.Services.AddSingleton(TimeProvider.System);
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
builder.Services.AddTransient<SoftLicence.Server.Services.SecurityCanaryAnalyticsService>(); // Canary security analytics
builder.Services.AddScoped<SoftLicence.Server.Services.SecurityIncidentService>(); // Aggregated server-side security incidents
builder.Services.AddTransient<SoftLicence.Server.Services.SecurityCaseContextService>(); // Shared securityCaseId and redacted enrichment context
builder.Services.AddTransient<SoftLicence.Server.Services.CertPinningBugTraceAlertService>(); // Auto BugTrace tickets for cert pinning alerts
builder.Services.AddTransient<SoftLicence.Server.Services.CertPinningDailyAlertService>(); // Persistent daily ntfy dedupe for cert pinning alerts
builder.Services.AddTransient<SoftLicence.Server.Services.FreemiumAbuseBugTraceAlertService>(); // Auto BugTrace tickets for Freemium abuse risk alerts
builder.Services.AddScoped<SoftLicence.Server.Services.TelemetryService>(); // Télémétrie
builder.Services.AddScoped<SoftLicence.Server.Services.TelemetryRejectionService>();
builder.Services.AddScoped<SoftLicence.Server.Services.ActivationIncidentService>();
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

// Runtime enrollment responses are sensitive on the entire route prefix,
// including routing errors (404/405), throttling, and failures before MVC.
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/v1/runtime-enrollments")
        || context.Request.Path.StartsWithSegments("/api/internal/v1/runtime-enrollments"))
    {
        context.Response.Headers.CacheControl = "no-store, max-age=0";
        context.Response.Headers.Pragma = "no-cache";
    }
    await next(context);
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

app.UseMiddleware<SoftLicence.Server.Middlewares.TelemetryRejectionCaptureMiddleware>();

// 2. LOGGING D'AUDIT GLOBAL (Placé AVANT l'autorisation pour capturer les accès refusés)
app.UseMiddleware<SoftLicence.Server.Middlewares.AuditMiddleware>();

app.UseAuthorization();

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

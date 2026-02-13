using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Components;
using SoftLicence.Server;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Configuration du Rate Limiting (Protection anti-spam)
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    
    // Politique pour l'activation client (Stricte)
    options.AddFixedWindowLimiter("PublicAPI", opt =>
    {
        opt.PermitLimit = 10;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 0;
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });

    // Politique pour l'administration (Plus souple)
    options.AddFixedWindowLimiter("AdminAPI", opt =>
    {
        opt.PermitLimit = 100;
        opt.Window = TimeSpan.FromMinutes(1);
    });
});

// Configuration DataProtection (Persistance des clés de session)
var keysFolder = Path.Combine(builder.Environment.ContentRootPath, "data", "keys");
Directory.CreateDirectory(keysFolder);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysFolder))
    .SetApplicationName("SoftLicence");

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
        options.DetailedErrors = builder.Environment.IsDevelopment();
    });

builder.Services.AddScoped<SoftLicence.Server.Services.ToastService>();
builder.Services.AddSingleton<SoftLicence.Server.Services.SettingsService>(); 
builder.Services.AddScoped<SoftLicence.Server.Services.AuthService>(); // Service d'autorisation custom
builder.Services.AddScoped<SoftLicence.Server.Services.TimeZoneService>(); // Gestion Fuseau Horaire
builder.Services.AddScoped<SoftLicence.Server.Services.SecurityService>(); // Défense Active
builder.Services.AddScoped<SoftLicence.Server.Services.EncryptionService>(); // Chiffrement des clés
builder.Services.AddSingleton<SoftLicence.Server.Services.BackupService>(); // Sauvegardes Drive (rclone)
builder.Services.AddMemoryCache();
builder.Services.AddScoped<SoftLicence.Server.Services.GeoIpService>(); // Intelligence Geo-IP
builder.Services.AddTransient<SoftLicence.Server.Services.EmailService>();
builder.Services.AddSingleton<SoftLicence.Server.Services.AuditNotifier>(); // Push temps réel audit logs
builder.Services.AddSingleton<SoftLicence.Server.Services.NotificationService>(); // Webhooks & Alertes
builder.Services.AddTransient<SoftLicence.Server.Services.StatsService>(); // Stats
builder.Services.AddScoped<SoftLicence.Server.Services.TelemetryService>(); // Télémétrie
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
    ForwardLimit = 2, // Traefik/Dokploy + éventuel CDN
    ForwardedForHeaderName = "X-Forwarded-For",
    ForwardedProtoHeaderName = "X-Forwarded-Proto",
    RequireHeaderSymmetry = false,
    KnownNetworks = { new Microsoft.AspNetCore.HttpOverrides.IPNetwork(System.Net.IPAddress.Parse("172.16.0.0"), 12) }, // Réseau Docker
    KnownProxies = { System.Net.IPAddress.Loopback }
});

app.UseRateLimiter(); 

app.UseStaticFiles(); 
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

        while (retryCount < maxRetries)
        {
            try 
            {
                db.Database.Migrate();
                Console.WriteLine("✅ Base de données prête et migrations appliquées.");
                break;
            }
            catch (Exception ex)
            {
                retryCount++;
                Console.WriteLine($"⚠️ Tentative {retryCount}/{maxRetries} échouée.");
                Console.WriteLine($"   Erreur : {ex.GetType().Name} - {ex.Message}");
                if (ex.InnerException != null) Console.WriteLine($"   Interne : {ex.InnerException.Message}");

                if (retryCount >= maxRetries)
                {
                    Console.WriteLine($"[FATAL] Impossible de se connecter à PostgreSQL après {maxRetries} tentatives.");
                    throw; 
                }
                Console.WriteLine($"[WAIT] PostgreSQL n'est pas encore prêt. Attente de 5s...");
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

// Notification de démarrage
using (var scope = app.Services.CreateScope())
{
    var notifier = scope.ServiceProvider.GetRequiredService<SoftLicence.Server.Services.NotificationService>();
    notifier.Notify(SoftLicence.Server.Services.NotificationService.Triggers.SystemStartup, 
        "🚀 Serveur SoftLicence opérationnel", 
        $"Le système de protection est en ligne. Environnement : {app.Environment.EnvironmentName}");
}

app.Run();

// Requis pour les tests d'intégration
public partial class Program { }
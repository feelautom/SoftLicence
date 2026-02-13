using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Diagnostics;

namespace SoftLicence.Server.Middlewares
{
    public class AuditMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<AuditMiddleware> _logger;
        private readonly IServiceScopeFactory _scopeFactory;

        public AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger, IServiceScopeFactory scopeFactory)
        {
            _next = next;
            _logger = logger;
            _scopeFactory = scopeFactory;
        }

        public async Task InvokeAsync(HttpContext context, IDbContextFactory<LicenseDbContext> dbFactory, Services.SecurityService security, Services.GeoIpService geoIp, IConfiguration config, Services.AuditNotifier auditNotifier)
        {
            var path = context.Request.Path.ToString().ToLower();

            // EXCLUSIONS SYSTEME : Blazor, fichiers statiques, et navigation admin (pages UI)
            // On logue uniquement les appels API (/api/*) et les accès suspects, pas le browsing admin
            if (path.StartsWith("/_blazor") ||
                path.StartsWith("/_framework") ||
                path.Contains(".js") ||
                path.Contains(".css") ||
                path.Contains(".png") ||
                path.Contains(".ico") ||
                path.Contains(".txt"))
            {
                await _next(context);
                return;
            }

            // Navigation admin (pages Blazor) : on laisse passer sans loguer
            // Les vraies actions admin passent par /api/admin/* et sont loguees
            if (!path.StartsWith("/api/") && !path.StartsWith("/account/") &&
                (context.User.Identity?.IsAuthenticated == true || security.IsWhitelisted(context.Connection.RemoteIpAddress?.ToString() ?? "")))
            {
                await _next(context);
                return;
            }

            // --- DEBUT SECURITE & AUDIT ---
            
            // 1. Détection proactive de scan (Dictionnaire étendu)
            var suspiciousPatterns = new[] { 
                // Scripts & Frameworks (qu'on n'utilise pas)
                ".php", ".aspx", ".asp", ".jsp", ".cgi", "wp-admin", "wp-content", "wp-includes", "xmlrpc",
                // Configuration & Secrets
                ".env", ".git", ".ds_store", "web.config", "appsettings.json", "docker-compose", ".aws", ".ssh",
                // Bases de données & Backups
                ".sql", ".db", ".sqlite", ".bak", ".zip", ".rar", ".tar", "phpmyadmin", "mysql", "dump",
                // Backdoors & Exploits connus
                "shell", "cmd", "eval", "invoker", "wlwmanifest", "autodiscover", "well-known"
            };
            
            bool isScan = suspiciousPatterns.Any(p => path.Contains(p));

            // 2. IP (Recherche approfondie anti-spoofing)
            string clientIp = "Unknown";
            // ... (logique IP existante) ...
            var forwarded = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
            
            if (!string.IsNullOrEmpty(forwarded)) {
                var parts = forwarded.Split(',');
                foreach(var p in parts) {
                    var clean = p.Trim();
                    if (clean != "127.0.0.1" && clean != "::1") { clientIp = clean; break; }
                }
            }
            if (clientIp == "Unknown" && !string.IsNullOrEmpty(realIp) && realIp != "127.0.0.1") clientIp = realIp;
            if (clientIp == "Unknown") clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

            // Si c'est un scan et que l'IP n'est PAS whitelisted, on bloque
            if (isScan && !security.IsWhitelisted(clientIp))
            {
                context.Response.StatusCode = 404;
                await security.ReportThreatAsync(clientIp, 15, $"Proactive scan detection: {path}"); // 15 pts pour les scans connus
                
                // GeoIP : Capturé AVANT le Task.Run car le service est Scoped
                var geo = await geoIp.GetGeoInfoAsync(clientIp);
                var userAgent = context.Request.Headers["User-Agent"].ToString();
                var method = context.Request.Method;

                _ = Task.Run(async () => {
                    try {
                        using var db = await dbFactory.CreateDbContextAsync();
                        db.AccessLogs.Add(new AccessLog {
                            Timestamp = DateTime.UtcNow, ClientIp = clientIp, Method = method,
                            Path = path, StatusCode = 404, ResultStatus = "BOT_SCAN", AppName = "SECURITY_SHIELD",
                            Endpoint = "PROACTIVE_BLOCK", ThreatScore = security.GetThreatScore(clientIp),
                            CountryCode = geo.CountryCode, Isp = geo.Isp, UserAgent = userAgent
                        });
                        await db.SaveChangesAsync();
                        auditNotifier.NotifyNewLog();
                    } catch { /* Background logging failure */ }
                });

                await context.Response.WriteAsync("Not Found");
                return;
            }

            // VÉRIFICATION BAN
            if (await security.IsBannedAsync(clientIp))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Access Denied (Banned)");
                return;
            }

            // --- FIN EXCLUSION ADMIN (LOGGING MAINTENU POUR LES ACTIONS REELLES) ---

            // Permettre la relecture du corps de la requête uniquement pour l'API
            context.Request.EnableBuffering();

            // --- CAPTURE DU CORPS DE LA REQUÊTE ---
            string requestBodyContent = "";
            try {
                if (context.Request.ContentLength > 0)
                {
                    context.Request.Body.Position = 0;
                    using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
                    requestBodyContent = await reader.ReadToEndAsync();
                    context.Request.Body.Position = 0; // Remise à zéro pour le contrôleur
                }
            } catch { /* Capture failure */ }

            var sw = Stopwatch.StartNew();
            var originalBodyStream = context.Response.Body;
            using var responseBody = new MemoryStream();
            context.Response.Body = responseBody;
            
            try
            {
                await _next(context);
            }
            finally
            {
                sw.Stop();
                
                // --- CAPTURE DU MESSAGE D'ERREUR (Si 400+) ---
                string errorDetails = "";
                if (context.Response.StatusCode >= 400)
                {
                    try {
                        responseBody.Seek(0, SeekOrigin.Begin);
                        errorDetails = await new StreamReader(responseBody).ReadToEndAsync();
                        responseBody.Seek(0, SeekOrigin.Begin);
                    } catch { /* Ignore capture failure */ }
                }

                // Restauration du stream original pour le client
                responseBody.Seek(0, SeekOrigin.Begin);
                await responseBody.CopyToAsync(originalBodyStream);
                context.Response.Body = originalBodyStream;

                // --- CAPTURE DES DONNÉES ---
                
                // 1. IP (Recherche approfondie anti-spoofing) - Déjà capturée en début de méthode
                // var remoteIp = context.Connection.RemoteIpAddress?.ToString(); // Inutilisé

                // 2. Infos HTTP
                var method = context.Request.Method;
                var requestPath = context.Request.Path.ToString();
                var statusCode = context.Response.StatusCode;
                var duration = sw.ElapsedMilliseconds;
                var userAgent = context.Request.Headers["User-Agent"].ToString();

                // 3. Infos Métier (Items)
                var appName = context.Items[LogKeys.AppName]?.ToString() ?? "";
                var licenseKey = context.Items[LogKeys.LicenseKey]?.ToString() ?? "";
                var hardwareId = context.Items[LogKeys.HardwareId]?.ToString() ?? "";
                var endpoint = context.Items[LogKeys.Endpoint]?.ToString() ?? "HTTP_REQUEST";

                // Defaults intelligents & Détection de Bot Scan
                if (statusCode == 404 && string.IsNullOrEmpty(appName))
                {
                    appName = "BOT_SCAN";
                    endpoint = "SUSPICIOUS";
                }
                else if (string.IsNullOrEmpty(appName) && requestPath.StartsWith("/api", StringComparison.OrdinalIgnoreCase))
                {
                    appName = "API_CLIENT";
                }
                else if (string.IsNullOrEmpty(appName))
                {
                    appName = "ADMIN_PORTAL";
                }

                // GeoIP : On l'appelle AVANT le Task.Run car le service geoIp est Scoped
                // et serait disposé si on attendait l'exécution de la tâche de fond.
                var geo = await geoIp.GetGeoInfoAsync(clientIp);
                var isAuthenticated = context.User.Identity?.IsAuthenticated == true;

                // --- ENREGISTREMENT ASYNCHRONE ---
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using (var scope = _scopeFactory.CreateScope())
                        {
                            var scopedSecurity = scope.ServiceProvider.GetRequiredService<Services.SecurityService>();
                            var scopedDbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();

                            // Scoring de menace (uniquement pour les visiteurs non-authentifiés)
                            if (!isAuthenticated && !scopedSecurity.IsWhitelisted(clientIp))
                            {
                                if (statusCode == 404) await scopedSecurity.ReportThreatAsync(clientIp, 10, $"404 on {requestPath}");
                                if (statusCode == 401 || statusCode == 403) await scopedSecurity.ReportThreatAsync(clientIp, 50, $"Auth failure on {requestPath}");
                            }

                            // ZOMBIE DETECTION (Anti-Fraude)
                            if (!string.IsNullOrEmpty(hardwareId) && hardwareId != "Unknown")
                            {
                                await scopedSecurity.CheckForZombieAsync(hardwareId, clientIp);
                            }

                            using (var db = await scopedDbFactory.CreateDbContextAsync())
                            {
                                var log = new AccessLog
                                {
                                    Timestamp = DateTime.UtcNow,
                                    ClientIp = clientIp,
                                    Method = method,
                                    Path = requestPath,
                                    StatusCode = statusCode,
                                    DurationMs = duration,
                                    IsSuccess = statusCode >= 200 && statusCode < 300,
                                    ResultStatus = GetStatusLabel(statusCode),
                                    RequestBody = requestBodyContent,
                                    ErrorDetails = errorDetails,
                                    UserAgent = userAgent,
                                                                    CountryCode = geo.CountryCode,
                                                                    Isp = geo.Isp,
                                                                    IsProxy = geo.IsProxy,
                                                                    ThreatScore = security.GetThreatScore(clientIp),
                                                                    
                                                                    AppName = appName,                                    LicenseKey = licenseKey,
                                    HardwareId = hardwareId,
                                    Endpoint = endpoint
                                };

                                db.AccessLogs.Add(log);
                                await db.SaveChangesAsync();
                                auditNotifier.NotifyNewLog();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[AUDIT ERROR] {ex.Message}");
                    }
                });
            }
        }

        private string GetStatusLabel(int code) => code switch
        {
            200 => "OK",
            201 => "CREATED",
            400 => "BAD_REQUEST",
            401 => "UNAUTHORIZED",
            403 => "FORBIDDEN",
            404 => "NOT_FOUND",
            500 => "INTERNAL_ERROR",
            _ => $"HTTP_{code}"
        };
    }
}

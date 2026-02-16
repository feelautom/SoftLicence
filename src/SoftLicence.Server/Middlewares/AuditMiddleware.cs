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
            
            // 1. IP (Recherche approfondie anti-spoofing)
            string clientIp = "Unknown";
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

            // 1. VÉRIFICATION BAN (PRIORITÉ ABSOLUE)
            if (await security.IsBannedAsync(clientIp))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Access Denied (Banned)");
                return;
            }

            // 1.5 ZONE DE QUARANTAINE (THROTTLING)
            // Si le score est entre 100 et 199, on ralentit volontairement la réponse
            var currentScore = security.GetThreatScore(clientIp);
            var banCount = await security.GetBanCountAsync(clientIp);

            if (currentScore >= 100 && currentScore < 200 && !security.IsWhitelisted(clientIp))
            {
                // Délai progressif : 5s de base + 1s par tranche de 10 points au dessus de 100
                int delaySec = 5 + ((currentScore - 100) / 10);
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(delaySec, 15))); 
            }

            // 2. Détection proactive de scan (Dictionnaire étendu)
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

            // Si c'est un scan et que l'IP n'est PAS whitelisted, on bloque
            if (isScan && !security.IsWhitelisted(clientIp))
            {
                context.Response.StatusCode = 404;
                
                // TOLÉRANCE ZÉRO pour les multirécidivistes (5+ bans) : Ban instantané
                // Sinon, punition géométrique : Points = Base(20) * (BanCount * 2)
                int scanPts = banCount >= 5 ? 200 : (20 * Math.Max(1, banCount * 2));
                
                await security.ReportThreatAsync(clientIp, scanPts, $"Proactive scan detection: {path} (Ban history: x{banCount})");
                
                // GeoIP : Capturé AVANT le Task.Run car le service est Scoped
                var geo = await geoIp.GetGeoInfoAsync(clientIp);
                var userAgent = context.Request.Headers["User-Agent"].ToString();
                var method = context.Request.Method;
                var threatScore = security.GetThreatScore(clientIp);

                _ = Task.Run(async () => {
                    try {
                        using var db = await dbFactory.CreateDbContextAsync();
                        db.AccessLogs.Add(new AccessLog {
                            Timestamp = DateTime.UtcNow, ClientIp = clientIp, Method = method,
                            Path = path, StatusCode = 404, ResultStatus = "BOT_SCAN", AppName = "SECURITY_SHIELD",
                            Endpoint = "PROACTIVE_BLOCK", ThreatScore = threatScore,
                            CountryCode = geo.CountryCode, Isp = geo.Isp, UserAgent = userAgent
                        });
                        await db.SaveChangesAsync();
                        auditNotifier.NotifyNewLog();
                    } catch { /* Background logging failure */ }
                });

                await context.Response.WriteAsync("Not Found");
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
                
                // --- CAPTURE DU MESSAGE DE RÉPONSE (RECU/ENVOYÉ) ---
                string responseContent = "";
                try {
                    responseBody.Seek(0, SeekOrigin.Begin);
                    responseContent = await new StreamReader(responseBody).ReadToEndAsync();
                    responseBody.Seek(0, SeekOrigin.Begin);
                } catch { /* Ignore capture failure */ }

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

                // Auth check (nécessaire pour le tri PORTAL_ENTRY vs ADMIN_PORTAL)
                var isAuthenticated = context.User.Identity?.IsAuthenticated == true;

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
                    // Si c'est la racine et pas authentifié, on marque comme bruit de portail
                    if (requestPath == "/" && !isAuthenticated)
                    {
                        appName = "PORTAL_ENTRY";
                    }
                    else
                    {
                        appName = "ADMIN_PORTAL";
                    }
                }

                // GeoIP : On l'appelle AVANT le Task.Run car le service geoIp est Scoped
                // et serait disposé si on attendait l'exécution de la tâche de fond.
                var geo = await geoIp.GetGeoInfoAsync(clientIp);

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
                                if (banCount >= 5)
                                {
                                    // BASTA : Tolérance zéro pour les récidivistes lourds
                                    await scopedSecurity.ReportThreatAsync(clientIp, 200, $"Zero tolerance (Ban history: x{banCount})");
                                }
                                else
                                {
                                    int multiplier = Math.Max(1, banCount * 2);

                                    if (statusCode == 404)
                                    {
                                        // Si déjà banni ou en quarantaine, base 10, sinon base 2
                                        int basePts = (banCount > 0 || currentScore >= 100) ? 10 : 2;
                                        await scopedSecurity.ReportThreatAsync(clientIp, basePts * multiplier, $"404 on {requestPath} (Multiplier: x{multiplier})");
                                    }
                                    
                                    if (statusCode == 401 || statusCode == 403) 
                                    {
                                        await scopedSecurity.ReportThreatAsync(clientIp, 50 * multiplier, $"Auth failure on {requestPath} (Multiplier: x{multiplier})");
                                    }
                                }
                            }

                            // ZOMBIE DETECTION (Anti-Fraude) - Immunité pour la whitelist
                            if (!string.IsNullOrEmpty(hardwareId) && hardwareId != "Unknown" && !scopedSecurity.IsWhitelisted(clientIp))
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
                                    ErrorDetails = responseContent,
                                    UserAgent = userAgent,
                                    CountryCode = geo.CountryCode,
                                    Isp = geo.Isp,
                                    IsProxy = geo.IsProxy,
                                    ThreatScore = scopedSecurity.GetThreatScore(clientIp),
                                    AppName = appName,
                                    LicenseKey = licenseKey,
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

using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace SoftLicence.Server.Middlewares
{
    public class AuditMiddleware
    {
        private const int MaximumErrorDetailsBytes = 8 * 1024;
        private const string TruncationMarker = "\n[TRUNCATED]";
        private static readonly Regex SensitiveJsonValuePattern = new(
            "(?i)(\\\"(?:licenseKey|licenseFile|token|secret|password|authorization|capability|subjectRef|email|customerEmail|customerName|hardwareId)\\\"\\s*:\\s*)\\\"(?:\\\\.|[^\\\"])*\\\"",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex EmailPattern = new(
            "(?i)(?<![a-z0-9.!#$%&'*+/=?^_`{|}~-])[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\\.[a-z]{2,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex BearerPattern = new(
            "(?i)\\bBearer\\s+[A-Za-z0-9._~+/-]+=*",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
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
            var path = context.Request.Path.ToString().ToLowerInvariant();
            var redactSensitivePayload = IsActivationApiPath(path)
                || IsDistributionS2SPath(path)
                || IsRuntimeEnrollmentPath(path)
                || IsTelemetryApiPath(path)
                || IsTargetedLicenseResolutionPath(path);

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

            // ForwardedHeaders has already accepted only configured trusted proxies.
            // Never parse raw forwarding headers again here.
            var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

            // 1. VÉRIFICATION BAN (PRIORITÉ ABSOLUE)
            // Exception : la télémétrie reste accessible même pour les IPs bannies
            // - Télémétrie : on veut continuer à recevoir les données de nos clients légitimes
            bool isTelemetryPath = path.StartsWith("/api/telemetry");
            if (!isTelemetryPath && await security.IsBannedAsync(clientIp))
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
                ".php", ".aspx", ".asp", ".jsp", ".cgi", "wordpress", "wp-admin", "wp-content", "wp-includes", "wp-CHANGE_ME_LOGIN_PATH", "xmlrpc",
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
                        using var scope = _scopeFactory.CreateScope();
                        var scopedDbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<LicenseDbContext>>();
                        var scopedNotifier = scope.ServiceProvider.GetRequiredService<Services.AuditNotifier>();
                        using var db = await scopedDbFactory.CreateDbContextAsync();
                        db.AccessLogs.Add(new AccessLog {
                            Timestamp = DateTime.UtcNow, ClientIp = clientIp, Method = method,
                            Path = path, StatusCode = 404, ResultStatus = "BOT_SCAN", AppName = "SECURITY_SHIELD",
                            Endpoint = "PROACTIVE_BLOCK", ThreatScore = threatScore,
                            CountryCode = geo.CountryCode, Isp = geo.Isp, UserAgent = userAgent
                        });
                        await db.SaveChangesAsync();
                        scopedNotifier.NotifyNewLog();
                    } catch { /* Background logging failure */ }
                });

                await context.Response.WriteAsync("Not Found");
                return;
            }

            // Preserve admission controls above, then avoid duplicating authenticated canary
            // IP, headers, body, HWID, user-agent or signed ACK in generic AccessLogs.
            if (IsCanaryEvidencePath(path))
            {
                await _next(context);
                return;
            }

            // --- FIN EXCLUSION ADMIN (LOGGING MAINTENU POUR LES ACTIONS REELLES) ---

            // Permettre la relecture du corps de la requête uniquement pour l'API
            context.Request.EnableBuffering();

            // --- CAPTURE DU CORPS DE LA REQUÊTE ---
            string requestBodyContent = "";
            try {
                if (redactSensitivePayload)
                {
                    requestBodyContent = "[REDACTED]";
                }
                else if (context.Request.ContentLength > 0)
                {
                    context.Request.Body.Position = 0;
                    using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
                    requestBodyContent = await reader.ReadToEndAsync();
                    context.Request.Body.Position = 0; // Remise à zéro pour le contrôleur
                }
            }
            catch (BadHttpRequestException ex) when (IsClientAbort(ex))
            {
                _logger.LogDebug(ex, "Request body capture skipped because the client aborted the request");
                requestBodyContent = "[client aborted while reading request body]";
            } catch { /* Capture failure */ }

            var sw = Stopwatch.StartNew();
            var originalBodyStream = context.Response.Body;
            using var responseCapture = new BoundedResponseCaptureStream(
                originalBodyStream,
                MaximumErrorDetailsBytes + Encoding.UTF8.GetMaxByteCount(1));
            context.Response.Body = responseCapture;
            var requestAbortedByClient = false;

            try
            {
                await _next(context);
            }
            catch (BadHttpRequestException ex) when (IsClientAbort(ex))
            {
                _logger.LogDebug(ex, "Request aborted by client while processing {Path}", context.Request.Path);
                requestAbortedByClient = true;
            }
            finally
            {
                sw.Stop();

                if (requestAbortedByClient)
                {
                    context.Response.Body = originalBodyStream;
                }
                else
                {
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
                var responseSizeBytes = responseCapture.BytesWritten;
                string? responseContent = null;
                if (statusCode < 200 || statusCode >= 300)
                {
                    responseContent = SanitizeErrorDetails(
                        responseCapture.GetCapturedText(),
                        redactSensitivePayload,
                        responseCapture.IsCaptureTruncated);
                }

                // 3. Infos Métier (Items)
                var appName = context.Items[LogKeys.AppName]?.ToString() ?? "";
                var licenseKey = context.Items[LogKeys.LicenseKey]?.ToString() ?? "";
                var hardwareId = context.Items[LogKeys.HardwareId]?.ToString() ?? "";
                var hardwareIdForSecurityChecks = hardwareId;
                var endpoint = context.Items[LogKeys.Endpoint]?.ToString() ?? "HTTP_REQUEST";
                var resultStatusOverride = context.Items[LogKeys.ResultStatusOverride]?.ToString();

                // Distribution v2 requests contain a short-lived bearer entitlement and raw
                // installation evidence. Keep only HTTP metadata for these internal routes,
                // even if a downstream component accidentally populates structured log items.
                if (IsDistributionS2SPath(path) || IsRuntimeEnrollmentPath(path) || IsTelemetryApiPath(path)
                    || IsTargetedLicenseResolutionPath(path))
                {
                    licenseKey = "";
                    hardwareId = "";
                }

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
                            var scopedNotifier = scope.ServiceProvider.GetRequiredService<Services.AuditNotifier>();

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
                                        // Endpoints légitimes d'autres produits feelautom qui n'existent pas
                                        // sur ce serveur — ne pas pénaliser (vrais clients, pas des bots)
                                        var knownCrossDomainPaths = new[] { "/api/build-id", "/api/updates/check", "/api/internal/" };
                                        bool isKnownCrossProduct = knownCrossDomainPaths.Any(p => requestPath.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                                        if (!isKnownCrossProduct)
                                        {
                                            // Si déjà banni ou en quarantaine, base 10, sinon base 2
                                            int basePts = (banCount > 0 || currentScore >= 100) ? 10 : 2;
                                            await scopedSecurity.ReportThreatAsync(clientIp, basePts * multiplier, $"404 on {requestPath} (Multiplier: x{multiplier})");
                                        }
                                    }

                                    if (statusCode == 401 || statusCode == 403)
                                    {
                                        await scopedSecurity.ReportThreatAsync(clientIp, 50 * multiplier, $"Auth failure on {requestPath} (Multiplier: x{multiplier})");
                                    }
                                }
                            }

                            // ZOMBIE DETECTION (Anti-Fraude) - Immunité pour la whitelist
                            if (!string.IsNullOrEmpty(hardwareIdForSecurityChecks)
                                && hardwareIdForSecurityChecks != "Unknown"
                                && !scopedSecurity.IsWhitelisted(clientIp))
                            {
                                var effectiveResultStatus = string.IsNullOrWhiteSpace(resultStatusOverride)
                                    ? GetStatusLabel(statusCode)
                                    : resultStatusOverride;
                                await scopedSecurity.CheckForZombieAsync(
                                    hardwareIdForSecurityChecks,
                                    clientIp,
                                    endpoint,
                                    effectiveResultStatus);
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
                                    ResultStatus = string.IsNullOrWhiteSpace(resultStatusOverride)
                                        ? GetStatusLabel(statusCode)
                                        : resultStatusOverride,
                                    RequestBody = requestBodyContent,
                                    ErrorDetails = responseContent,
                                    ResponseSizeBytes = responseSizeBytes,
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
                                scopedNotifier.NotifyNewLog();
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

        private static string SanitizeErrorDetails(string body, bool forceRedaction) =>
            SanitizeErrorDetails(body, forceRedaction, captureTruncated: false);

        private static string SanitizeErrorDetails(string body, bool forceRedaction, bool captureTruncated)
        {
            if (forceRedaction || captureTruncated || string.IsNullOrWhiteSpace(body))
                return "[REDACTED]";

            try
            {
                using var document = System.Text.Json.JsonDocument.Parse(body);
            }
            catch (System.Text.Json.JsonException)
            {
                return "[REDACTED]";
            }

            var sanitized = SensitiveJsonValuePattern.Replace(body, "$1\"[REDACTED]\"");
            sanitized = BearerPattern.Replace(sanitized, "Bearer [REDACTED]");
            sanitized = EmailPattern.Replace(sanitized, "[REDACTED_EMAIL]");
            return TruncateUtf8(sanitized, MaximumErrorDetailsBytes);
        }

        private static string TruncateUtf8(string value, int maximumBytes)
        {
            if (Encoding.UTF8.GetByteCount(value) <= maximumBytes)
                return value;

            var markerBytes = Encoding.UTF8.GetByteCount(TruncationMarker);
            var availableBytes = maximumBytes - markerBytes;
            var builder = new StringBuilder(Math.Min(value.Length, availableBytes));
            var byteCount = 0;
            foreach (var rune in value.EnumerateRunes())
            {
                var runeBytes = rune.Utf8SequenceLength;
                if (byteCount + runeBytes > availableBytes)
                    break;
                builder.Append(rune.ToString());
                byteCount += runeBytes;
            }
            return builder.Append(TruncationMarker).ToString();
        }

        private sealed class BoundedResponseCaptureStream : Stream
        {
            private readonly Stream _inner;
            private readonly MemoryStream _capture;
            private readonly int _captureLimit;

            public BoundedResponseCaptureStream(Stream inner, int captureLimit)
            {
                _inner = inner;
                _captureLimit = captureLimit;
                _capture = new MemoryStream(captureLimit);
            }

            public long BytesWritten { get; private set; }
            public bool IsCaptureTruncated { get; private set; }
            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => _inner.CanWrite;
            public override long Length => BytesWritten;
            public override long Position { get => BytesWritten; set => throw new NotSupportedException(); }
            public override void Flush() => _inner.Flush();
            public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
            {
                Capture(buffer.AsSpan(offset, count));
                _inner.Write(buffer, offset, count);
                BytesWritten += count;
            }

            public override async Task WriteAsync(
                byte[] buffer,
                int offset,
                int count,
                CancellationToken cancellationToken)
            {
                Capture(buffer.AsSpan(offset, count));
                await _inner.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
                BytesWritten += count;
            }

            public override async ValueTask WriteAsync(
                ReadOnlyMemory<byte> buffer,
                CancellationToken cancellationToken = default)
            {
                Capture(buffer.Span);
                await _inner.WriteAsync(buffer, cancellationToken);
                BytesWritten += buffer.Length;
            }

            public string GetCapturedText() => Encoding.UTF8.GetString(_capture.GetBuffer(), 0, checked((int)_capture.Length));

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                    _capture.Dispose();
                base.Dispose(disposing);
            }

            private void Capture(ReadOnlySpan<byte> buffer)
            {
                var remaining = _captureLimit - checked((int)_capture.Length);
                if (remaining <= 0)
                {
                    if (!buffer.IsEmpty) IsCaptureTruncated = true;
                    return;
                }
                var captured = Math.Min(remaining, buffer.Length);
                _capture.Write(buffer[..captured]);
                if (captured < buffer.Length) IsCaptureTruncated = true;
            }
        }

        private static bool IsActivationApiPath(string path)
        {
            const string activationPath = "/api/activation";
            return path.Equals(activationPath, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(activationPath + "/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsTargetedLicenseResolutionPath(string path)
        {
            var normalizedPath = path.EndsWith("/", StringComparison.Ordinal) ? path[..^1] : path;
            return normalizedPath.Equals("/api/admin/licenses/resolve", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsDistributionS2SPath(string path)
        {
            var normalizedPath = path.EndsWith("/", StringComparison.Ordinal) ? path[..^1] : path;
            return normalizedPath.Equals("/api/internal/v1/distribution-entitlements/issue", StringComparison.OrdinalIgnoreCase)
                || normalizedPath.Equals("/api/internal/v1/distribution-installation-bindings/finalize", StringComparison.OrdinalIgnoreCase)
                || normalizedPath.Equals("/api/internal/v1/distribution-installation-bindings/invalidate", StringComparison.OrdinalIgnoreCase)
                || normalizedPath.Equals("/api/internal/v1/distribution-license-bootstraps/issue", StringComparison.OrdinalIgnoreCase)
                || normalizedPath.Equals("/api/internal/v1/distribution-license-bootstraps/remint", StringComparison.OrdinalIgnoreCase)
                || normalizedPath.Equals("/api/internal/v1/distribution-license-bootstraps/recover", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsRuntimeEnrollmentPath(string path)
        {
            return path.Equals("/api/internal/v1/runtime-enrollments", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/internal/v1/runtime-enrollments/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/api/v1/runtime-enrollments", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/v1/runtime-enrollments/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsTelemetryApiPath(string path)
        {
            const string telemetryPath = "/api/telemetry";
            return path.Equals(telemetryPath, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(telemetryPath + "/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsCanaryEvidencePath(string path)
        {
            return path.Equals("/api/health/ping", StringComparison.Ordinal);
        }

        private static bool IsClientAbort(BadHttpRequestException ex)
        {
            return ex.Message.Contains("Unexpected end of request content", StringComparison.OrdinalIgnoreCase);
        }
    }
}

using System.Text.Json;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public class TelemetryService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<TelemetryService> _logger;
    private readonly GeoIpService _geoIp;
    private readonly IHttpClientFactory _httpFactory;

    public TelemetryService(IDbContextFactory<LicenseDbContext> dbFactory, ILogger<TelemetryService> logger, GeoIpService geoIp, IHttpClientFactory httpFactory)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _geoIp = geoIp;
        _httpFactory = httpFactory;
    }

    public async Task SaveEventAsync(TelemetryEventRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;

        var record = new TelemetryRecord
        {
            Timestamp = req.Timestamp,
            HardwareId = req.HardwareId,
            ClientIp = ip,
            Isp = geo?.Isp,
            AppName = req.AppName,
            Version = req.Version,
            EventName = req.EventName,
            Type = TelemetryType.Event,
            ProductId = productId
        };

        record.EventData = new TelemetryEvent
        {
            PropertiesJson = req.Properties != null ? JsonSerializer.Serialize(req.Properties) : null
        };

        db.TelemetryRecords.Add(record);
        await db.SaveChangesAsync();

        if (productId.HasValue)
        {
            var hwShort = req.HardwareId.Length > 8 ? req.HardwareId[..8] : req.HardwareId;
            FireProductWebhooks(db, productId.Value, "Telemetry.Event",
                $"Event: {req.EventName}",
                $"{req.AppName} v{req.Version} — {hwShort}", req);
        }
    }

    public async Task SaveDiagnosticAsync(TelemetryDiagnosticRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;

        var record = new TelemetryRecord
        {
            Timestamp = req.Timestamp,
            HardwareId = req.HardwareId,
            ClientIp = ip,
            Isp = geo?.Isp,
            AppName = req.AppName,
            Version = req.Version,
            EventName = req.EventName,
            Type = TelemetryType.Diagnostic,
            ProductId = productId
        };

        record.DiagnosticData = new TelemetryDiagnostic
        {
            Score = req.Score,
            Results = req.Results?.Select(r => new TelemetryDiagnosticResult
            {
                ModuleName = r.ModuleName,
                Success = r.Success,
                Severity = r.Severity,
                Message = r.Message
            }).ToList() ?? new List<TelemetryDiagnosticResult>(),
            Ports = req.Ports?.Select(p => new TelemetryDiagnosticPort
            {
                Name = p.Name,
                ExternalPort = p.ExternalPort,
                Protocol = p.Protocol
            }).ToList() ?? new List<TelemetryDiagnosticPort>()
        };

        db.TelemetryRecords.Add(record);
        await db.SaveChangesAsync();

        if (productId.HasValue)
        {
            var hwShort = req.HardwareId.Length > 8 ? req.HardwareId[..8] : req.HardwareId;
            FireProductWebhooks(db, productId.Value, "Telemetry.Diagnostic",
                $"Diagnostic: {req.EventName}",
                $"{req.AppName} v{req.Version} — {hwShort}", req);
        }
    }

    public async Task SaveErrorAsync(TelemetryErrorRequest req, string? ip = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var geo = ip != null ? await _geoIp.GetGeoInfoAsync(ip) : null;

        var record = new TelemetryRecord
        {
            Timestamp = req.Timestamp,
            HardwareId = req.HardwareId,
            ClientIp = ip,
            Isp = geo?.Isp,
            AppName = req.AppName,
            Version = req.Version,
            EventName = req.EventName,
            Type = TelemetryType.Error,
            ProductId = productId
        };

        record.ErrorData = new TelemetryError
        {
            ErrorType = req.ErrorType,
            Message = req.Message,
            StackTrace = req.StackTrace
        };

        db.TelemetryRecords.Add(record);
        await db.SaveChangesAsync();

        if (productId.HasValue)
        {
            var hwShort = req.HardwareId.Length > 8 ? req.HardwareId[..8] : req.HardwareId;
            FireProductWebhooks(db, productId.Value, "Telemetry.Error",
                $"Error: {req.ErrorType}",
                $"{req.AppName} v{req.Version} — {hwShort}", req);
        }
    }

    public async Task<List<TelemetryResponse>> GetTelemetryForProductAsync(string apiSecret, int page = 1, int pageSize = 50, TelemetryType? type = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var product = await db.Products.AsNoTracking().FirstOrDefaultAsync(p => p.ApiSecret == apiSecret);
        if (product == null) return new List<TelemetryResponse>();

        var query = db.TelemetryRecords
            .AsNoTracking()
            .AsSplitQuery()
            .Include(t => t.EventData)
            .Include(t => t.DiagnosticData).ThenInclude(d => d!.Results)
            .Include(t => t.DiagnosticData).ThenInclude(d => d!.Ports)
            .Include(t => t.ErrorData)
            .Where(t => t.ProductId == product.Id);

        if (type.HasValue)
        {
            query = query.Where(t => t.Type == type.Value);
        }

        var records = await query
            .OrderByDescending(t => t.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return records.Select(r => new TelemetryResponse
        {
            Id = r.Id,
            Timestamp = r.Timestamp,
            HardwareId = r.HardwareId,
            AppName = r.AppName,
            Version = r.Version,
            EventName = r.EventName,
            Type = r.Type.ToString(),
            Data = GetSpecializedData(r)
        }).ToList();
    }

    private void FireProductWebhooks(LicenseDbContext db, Guid productId, string trigger, string title, string message, object data)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var webhooks = await db.ProductWebhooks
                    .Where(w => w.ProductId == productId && w.IsEnabled)
                    .ToListAsync();

                if (!webhooks.Any()) return;

                var client = _httpFactory.CreateClient();
                var payload = new
                {
                    trigger,
                    title,
                    message,
                    timestamp = DateTime.UtcNow,
                    data
                };

                foreach (var hook in webhooks)
                {
                    try
                    {
                        var request = new HttpRequestMessage(HttpMethod.Post, hook.Url)
                        {
                            Content = JsonContent.Create(payload)
                        };

                        if (!string.IsNullOrWhiteSpace(hook.Secret))
                        {
                            request.Headers.Add("X-Webhook-Secret", hook.Secret);
                        }

                        await client.SendAsync(request);
                        hook.LastTriggeredAt = DateTime.UtcNow;
                        hook.LastError = null;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Echec webhook produit {Name} ({Url})", hook.Name, hook.Url);
                        hook.LastError = ex.Message;
                    }
                }

                await db.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur globale webhooks produit");
            }
        });
    }

    private object? GetSpecializedData(TelemetryRecord r)
    {
        return r.Type switch
        {
            TelemetryType.Event => r.EventData != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(r.EventData.PropertiesJson ?? "{}") : null,
            TelemetryType.Diagnostic => r.DiagnosticData != null ? new {
                r.DiagnosticData.Score,
                Results = r.DiagnosticData.Results.Select(res => new { res.ModuleName, res.Success, res.Severity, res.Message }),
                Ports = r.DiagnosticData.Ports.Select(p => new { p.Name, p.ExternalPort, p.Protocol })
            } : null,
            TelemetryType.Error => r.ErrorData != null ? new {
                r.ErrorData.ErrorType,
                r.ErrorData.Message,
                r.ErrorData.StackTrace
            } : null,
            _ => null
        };
    }

    private async Task<Guid?> GetProductIdAsync(LicenseDbContext db, string appName)
    {
        var product = await db.Products.AsNoTracking().FirstOrDefaultAsync(p => p.Name.ToLower() == appName.ToLower());
        return product?.Id;
    }
}

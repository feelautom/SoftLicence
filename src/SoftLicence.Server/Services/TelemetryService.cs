using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public class TelemetryService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<TelemetryService> _logger;

    public TelemetryService(IDbContextFactory<LicenseDbContext> dbFactory, ILogger<TelemetryService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task SaveEventAsync(TelemetryEventRequest req)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var record = new TelemetryRecord
        {
            Timestamp = req.Timestamp,
            HardwareId = req.HardwareId,
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
    }

    public async Task SaveDiagnosticAsync(TelemetryDiagnosticRequest req)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var record = new TelemetryRecord
        {
            Timestamp = req.Timestamp,
            HardwareId = req.HardwareId,
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
    }

    public async Task SaveErrorAsync(TelemetryErrorRequest req)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var productId = await GetProductIdAsync(db, req.AppName);
        var record = new TelemetryRecord
        {
            Timestamp = req.Timestamp,
            HardwareId = req.HardwareId,
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
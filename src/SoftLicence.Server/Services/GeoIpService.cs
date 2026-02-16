using SoftLicence.Server.Models;
using Microsoft.Extensions.Caching.Memory;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;

namespace SoftLicence.Server.Services;

public class GeoIpService : IDisposable
{
    private readonly DatabaseReader? _cityReader;
    private readonly DatabaseReader? _asnReader;
    private readonly IMemoryCache _cache;
    private readonly ILogger<GeoIpService> _logger;

    public GeoIpService(IWebHostEnvironment env, IMemoryCache cache, ILogger<GeoIpService> logger)
    {
        _cache = cache;
        _logger = logger;
        
        var cityPath = Path.Combine(env.ContentRootPath, "Data", "GeoLite2-City.mmdb");
        var asnPath = Path.Combine(env.ContentRootPath, "Data", "GeoLite2-ASN.mmdb");

        try
        {
            if (File.Exists(cityPath))
            {
                _cityReader = new DatabaseReader(cityPath);
                _logger.LogInformation("GeoIP City Database loaded.");
            }
            if (File.Exists(asnPath))
            {
                _asnReader = new DatabaseReader(asnPath);
                _logger.LogInformation("GeoIP ASN Database loaded.");
            }
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to load GeoIP Databases."); }
    }

    public virtual async Task<GeoInfo> GetGeoInfoAsync(string ip)
    {
        if (string.IsNullOrEmpty(ip) || ip == "127.0.0.1" || ip == "::1" || ip == "Unknown")
            return new GeoInfo();

        if (_cache.TryGetValue(ip, out GeoInfo? cached)) return cached!;

        try
        {
            return await Task.Run(() =>
            {
                var info = new GeoInfo();

                // 1. Localisation
                if (_cityReader != null && _cityReader.TryCity(ip, out var city))
                {
                    if (city != null)
                    {
                        info.Country = city.Country?.Name ?? "Unknown";
                        info.CountryCode = city.Country?.IsoCode ?? "??";
                        info.City = city.City?.Name ?? "Unknown";
                    }
                }

                // 2. Fournisseur
                if (_asnReader != null && _asnReader.TryAsn(ip, out var asn))
                {
                    if (asn != null)
                    {
                        info.Isp = asn.AutonomousSystemOrganization ?? "Unknown";
                    }
                }

                var ispLower = (info.Isp ?? "unknown").ToLower();
                info.IsProxy = ispLower.Contains("amazon") || ispLower.Contains("google") || 
                               ispLower.Contains("digitalocean") || ispLower.Contains("microsoft") ||
                               ispLower.Contains("ovh") || ispLower.Contains("hosting") || 
                               ispLower.Contains("datacenter");
                
                _cache.Set(ip, info, TimeSpan.FromDays(1));
                return info;
            });
        }
        catch { return new GeoInfo(); }
    }

    public void Dispose()
    {
        _cityReader?.Dispose();
        _asnReader?.Dispose();
    }
}

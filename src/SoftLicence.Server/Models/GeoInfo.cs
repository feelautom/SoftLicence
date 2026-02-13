namespace SoftLicence.Server.Models;

public class GeoInfo
{
    public string Country { get; set; } = "Unknown";
    public string CountryCode { get; set; } = "??";
    public string City { get; set; } = "Unknown";
    public string Isp { get; set; } = "Unknown";
    public bool IsProxy { get; set; } = false;
}

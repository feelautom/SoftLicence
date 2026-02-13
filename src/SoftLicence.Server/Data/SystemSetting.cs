using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class SystemSetting
{
    [Key]
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
}

namespace SoftLicence.SDK
{
    public sealed class HardwareIdMigrationInfo
    {
        public string LegacyHardwareId { get; set; } = string.Empty;

        public string? StableHardwareId { get; set; }

        public bool HasStableHardwareId => !string.IsNullOrWhiteSpace(StableHardwareId);

        public bool HasDistinctHardwareIds =>
            HasStableHardwareId
            && !string.Equals(LegacyHardwareId, StableHardwareId, StringComparison.OrdinalIgnoreCase);
    }
}

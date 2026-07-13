using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

namespace SoftLicence.SDK
{
    public static class HardwareInfo
    {
        internal delegate string WmiPropertyReader(string className, string propertyName, string? whereClause);

        private static WmiPropertyReader wmiPropertyReader = GetWmiProperty;

        /// <summary>
        /// Returns the contractual hardware ID used by SDK 1.1.8/1.1.9.
        /// The disk component intentionally uses the legacy first non-empty
        /// Win32_DiskDrive.SerialNumber value to preserve existing bindings.
        /// </summary>
        public static string GetHardwareId()
        {
            return ComputeHardwareId(GetLegacyDiskId());
        }

        /// <summary>
        /// Returns the deterministic V2 hardware ID based on Win32_DiskDrive WHERE Index=0.
        /// This value is an observation signal only and must not be treated as the
        /// contractual license identity unless a server-side migration explicitly decides so.
        /// </summary>
        public static string? GetStableHardwareId()
        {
            var stableDiskId = GetStableDiskId();
            return IsMissingWmiValue(stableDiskId) ? null : ComputeHardwareId(stableDiskId);
        }

        public static HardwareIdMigrationInfo GetHardwareIdMigrationInfo()
        {
            var legacyHardwareId = GetHardwareId();
            var stableHardwareId = GetStableHardwareId();

            return new HardwareIdMigrationInfo
            {
                LegacyHardwareId = legacyHardwareId,
                StableHardwareId = stableHardwareId
            };
        }

        private static string ComputeHardwareId(string diskId)
        {
            var cpuId = GetCpuId();
            var mbId = GetMotherboardId();
            var biosId = GetBiosId();
            var machineName = Environment.MachineName;
            
            // Alignement strict sur l'algorithme YOUR_APP_NAME (5 composants)
            var rawId = string.Concat(cpuId, mbId, biosId, diskId, machineName);
            
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawId));
                // Format : 16 caractères Hexadécimaux (Majuscules)
                return BitConverter.ToString(bytes).Replace("-", "").Substring(0, 16).ToUpper();
            }
        }

        private static string GetCpuId()
        {
            return wmiPropertyReader("Win32_Processor", "ProcessorId", null);
        }

        private static string GetMotherboardId()
        {
            return wmiPropertyReader("Win32_BaseBoard", "SerialNumber", null);
        }

        private static string GetBiosId()
        {
            return wmiPropertyReader("Win32_BIOS", "SerialNumber", null);
        }

        private static string GetLegacyDiskId()
        {
            return wmiPropertyReader("Win32_DiskDrive", "SerialNumber", null);
        }

        private static string GetStableDiskId()
        {
            return wmiPropertyReader("Win32_DiskDrive", "SerialNumber", "Index=0");
        }

        /// <summary>
        /// Returns individual SHA256 hashes of each hardware component (no salt).
        /// Keys: FP_CPU, FP_MB, FP_BIOS, FP_DISK, FP_HOST
        /// </summary>
        public static Dictionary<string, string> GetComponentFingerprints()
        {
            return new Dictionary<string, string>
            {
                ["FP_CPU"] = ComputeComponentHash(GetCpuId()),
                ["FP_MB"] = ComputeComponentHash(GetMotherboardId()),
                ["FP_BIOS"] = ComputeComponentHash(GetBiosId()),
                ["FP_DISK"] = ComputeComponentHash(GetLegacyDiskId()),
                ["FP_HOST"] = ComputeComponentHash(Environment.MachineName)
            };
        }

        private static string ComputeComponentHash(string value)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(value ?? "UNKNOWN"));
                return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            }
        }

        internal static IDisposable UseWmiPropertyReaderForTests(WmiPropertyReader reader)
        {
            var previous = wmiPropertyReader;
            wmiPropertyReader = reader;
            return new RestoreWmiPropertyReader(previous);
        }

        private static bool IsMissingWmiValue(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                || string.Equals(value, "UNKNOWN", StringComparison.Ordinal)
                || string.Equals(value, "NON-WINDOWS", StringComparison.Ordinal);
        }

        private sealed class RestoreWmiPropertyReader : IDisposable
        {
            private readonly WmiPropertyReader previous;
            private bool disposed;

            public RestoreWmiPropertyReader(WmiPropertyReader previous)
            {
                this.previous = previous;
            }

            public void Dispose()
            {
                if (disposed)
                {
                    return;
                }

                wmiPropertyReader = previous;
                disposed = true;
            }
        }

        private static string GetWmiProperty(string className, string propertyName, string? whereClause)
        {
            try
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return "NON-WINDOWS";

                var query = $"SELECT {propertyName} FROM {className}";
                if (!string.IsNullOrWhiteSpace(whereClause))
                {
                    query += $" WHERE {whereClause}";
                }

                using (var searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var value = obj[propertyName]?.ToString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            return value!.Trim();
                        }
                    }
                }
            }
            catch { }
            return "UNKNOWN";
        }
    }
}

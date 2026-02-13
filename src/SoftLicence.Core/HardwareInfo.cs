using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace SoftLicence.Core
{
    public static class HardwareInfo
    {
        public static string GetHardwareId()
        {
            var cpuId = GetCpuId();
            var diskId = GetDiskId();
            
            // On combine et on hash pour ne pas exposer les infos brutes
            var rawId = $"{cpuId}_|_{diskId}";
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawId));
            return Convert.ToBase64String(bytes);
        }

        private static string GetCpuId()
        {
            try
            {
                if (!OperatingSystem.IsWindows()) return "NON-WINDOWS-CPU";

                using var searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["ProcessorId"]?.ToString() ?? "UNKNOWN_CPU";
                }
            }
            catch { }
            return "UNAVAILABLE_CPU";
        }

        private static string GetDiskId()
        {
            try
            {
                if (!OperatingSystem.IsWindows()) return "NON-WINDOWS-DISK";

                // On vise le disque système C:
                using var searcher = new ManagementObjectSearcher("SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID = 'C:'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["VolumeSerialNumber"]?.ToString() ?? "UNKNOWN_DISK";
                }
            }
            catch { }
            return "UNAVAILABLE_DISK";
        }
    }
}

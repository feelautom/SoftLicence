using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

namespace SoftLicence.SDK
{
    public static class HardwareInfo
    {
        public static string GetHardwareId()
        {
            var cpuId = GetCpuId();
            var mbId = GetMotherboardId();
            var biosId = GetBiosId();
            var diskId = GetDiskId();
            var machineName = Environment.MachineName;
            
            // Alignement strict sur l'algorithme SipLine (5 composants)
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
            return GetWmiProperty("Win32_Processor", "ProcessorId");
        }

        private static string GetMotherboardId()
        {
            return GetWmiProperty("Win32_BaseBoard", "SerialNumber");
        }

        private static string GetBiosId()
        {
            return GetWmiProperty("Win32_BIOS", "SerialNumber");
        }

        private static string GetDiskId()
        {
            return GetWmiProperty("Win32_DiskDrive", "SerialNumber");
        }

        private static string GetWmiProperty(string className, string propertyName)
        {
            try
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return "NON-WINDOWS";

                using (var searcher = new ManagementObjectSearcher($"SELECT {propertyName} FROM {className}"))
                using (var collection = searcher.Get())
                {
                    foreach (var mObj in collection)
                    {
                        var obj = mObj as ManagementObject;
                        if (obj != null)
                        {
                            var propValue = obj.Properties[propertyName]?.Value;
                            if (propValue != null)
                            {
                                string? value = propValue.ToString();
                                if (!string.IsNullOrWhiteSpace(value))
                                {
                                    return value.Trim();
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return "UNKNOWN";
        }
    }
}

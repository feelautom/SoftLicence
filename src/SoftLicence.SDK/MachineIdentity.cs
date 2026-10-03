using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace SoftLicence.SDK
{
    /// <summary>
    /// Machine identity based solely on the SMBIOS system UUID (<c>Win32_ComputerSystemProduct.UUID</c>).
    /// </summary>
    /// <remarks>
    /// TKT-001310 / TKT-001277 (decision of 29/09/2026): the licence identity of a machine is its system UUID
    /// and nothing else. No multi-component hardware calculation is performed; the UUID is read, validated,
    /// canonicalized and mapped to the historical 16-character uppercase hexadecimal format so that every
    /// existing hardware-ID validator keeps working. Missing, unreadable, malformed or known generic UUIDs are
    /// refused with a stable reason code; they are never replaced by an invented value.
    /// This class has its own WMI and registry readers; the historical <see cref="HardwareInfo"/> calculation
    /// and its reader are intentionally left untouched for other products.
    /// </remarks>
    public static class MachineIdentity
    {
        /// <summary>Runs one WMI query and returns every instance with the requested properties, unmodified.</summary>
        internal delegate WmiQueryResult WmiQueryReader(string className, IReadOnlyList<string> propertyNames);

        /// <summary>Reads one registry value and reports whether it is present, absent, unreadable or unsupported.</summary>
        internal delegate MachineEvidenceValue RegistryValueReader(RegistryHive hive, string keyPath, string valueName);

        /// <summary>Stable refusal code: the firmware exposes no system UUID.</summary>
        public const string RefusalUuidAbsent = "UUID_ABSENT";

        /// <summary>Stable refusal code: the system UUID could not be read (WMI failure or non-Windows platform).</summary>
        public const string RefusalUuidUnreadable = "UUID_ILLISIBLE";

        /// <summary>Stable refusal code: the value is not a canonical 8-4-4-4-12 hexadecimal UUID.</summary>
        public const string RefusalUuidInvalidFormat = "UUID_FORMAT_INVALIDE";

        /// <summary>Stable refusal code: the UUID is a known firmware placeholder shared by unrelated machines.</summary>
        public const string RefusalUuidGenericKnown = "UUID_GENERIQUE_CONNU";

        /// <summary>
        /// Stable refusal code decided by the server: the submitted identifier is not the one derived from the
        /// submitted UUID (modified or faulty client). Never produced locally by <see cref="FromUuid"/>.
        /// </summary>
        public const string RefusalIdentifierMismatch = "UUID_IDENTIFIANT_INCOHERENT";

        /// <summary>
        /// Maps a refusal code to the short support code shown to the customer with "device refused". The mapping is
        /// the support contract shared by the SDK and the server: AR-01 UUID absent, AR-02 UUID unreadable,
        /// AR-03 UUID malformed, AR-04 known generic UUID, AR-05 identifier not derived from the UUID.
        /// </summary>
        /// <param name="refusalCode">A refusal code, or <c>null</c>.</param>
        /// <returns>The support code, <c>AR-00</c> for an unmapped code, or <c>null</c> when not refused.</returns>
        public static string? ToSupportCode(string? refusalCode) => refusalCode switch
        {
            null => null,
            RefusalUuidAbsent => "AR-01",
            RefusalUuidUnreadable => "AR-02",
            RefusalUuidInvalidFormat => "AR-03",
            RefusalUuidGenericKnown => "AR-04",
            RefusalIdentifierMismatch => "AR-05",
            _ => "AR-00",
        };

        /// <summary>Domain-separation prefix hashed with the canonical UUID; deliberately unversioned.</summary>
        private const string DerivationPrefix = "SOFTLICENCE-MACHINE-UUID|";

        /// <summary>
        /// Known firmware placeholder UUIDs, in canonical uppercase form. Compared ordinally after
        /// canonicalization. Measured in production on 29/09/2026: <c>03000200-…-0009</c> was shared by three
        /// unrelated machines.
        /// </summary>
        private static readonly HashSet<string> KnownGenericUuids = new HashSet<string>(StringComparer.Ordinal)
        {
            "03000200-0400-0500-0006-000700080009",
            "00020003-0004-0005-0006-000700080009",
            "12345678-1234-5678-90AB-CDDEEFAABBCC",
            "01234567-8910-1112-1314-151617181920",
        };

        private static readonly string[] UuidProperties = { "UUID" };
        private static readonly string[] DiskProperties = { "Index", "SerialNumber" };

        private static WmiQueryReader wmiQueryReader = QueryWmi;
        private static RegistryValueReader registryValueReader = ReadRegistryValue;

        /// <summary>
        /// Reads the system UUID of the current machine and resolves its licence identity.
        /// </summary>
        /// <returns>
        /// An accepted identity, or a refusal carrying one of the stable refusal codes. A WMI failure or a
        /// non-Windows platform yields <see cref="RefusalUuidUnreadable"/> with the cause in
        /// <see cref="MachineIdentityResult.ReadFailure"/>; a successful query without any UUID yields
        /// <see cref="RefusalUuidAbsent"/>.
        /// </returns>
        public static MachineIdentityResult Resolve()
        {
            var query = wmiQueryReader("Win32_ComputerSystemProduct", UuidProperties);
            if (query.Status == MachineEvidenceStatus.Unsupported)
                return MachineIdentityResult.Refused(RefusalUuidUnreadable, "NON-WINDOWS");
            if (query.Status == MachineEvidenceStatus.Error)
                return MachineIdentityResult.Refused(RefusalUuidUnreadable, query.Error);

            foreach (var row in query.Rows)
            {
                if (row.TryGetValue("UUID", out var raw) && !string.IsNullOrWhiteSpace(raw))
                    return FromUuid(raw);
            }
            return MachineIdentityResult.Refused(RefusalUuidAbsent, null);
        }

        /// <summary>
        /// Validates, canonicalizes and maps one raw system UUID. Pure and deterministic, so the server can apply
        /// exactly the same rule to a UUID reported by a client.
        /// </summary>
        /// <param name="rawUuid">The value as reported by WMI; surrounding whitespace and one pair of braces are tolerated.</param>
        /// <returns>
        /// An accepted identity, or a refusal: <see cref="RefusalUuidAbsent"/> for null or blank input,
        /// <see cref="RefusalUuidInvalidFormat"/> for any other non-UUID text (including legacy sentinels such as
        /// <c>UNKNOWN</c>), <see cref="RefusalUuidGenericKnown"/> for placeholders.
        /// </returns>
        public static MachineIdentityResult FromUuid(string? rawUuid)
        {
            if (rawUuid == null || rawUuid.Trim().Length == 0)
                return MachineIdentityResult.Refused(RefusalUuidAbsent, null);

            var canonical = Canonicalize(rawUuid.Trim());
            if (canonical == null)
                return MachineIdentityResult.Refused(RefusalUuidInvalidFormat, null);
            if (IsGeneric(canonical))
                return MachineIdentityResult.Refused(RefusalUuidGenericKnown, null);

            return MachineIdentityResult.Accepted(canonical, DeriveHardwareId(canonical));
        }

        /// <summary>
        /// Collects every hardware and Windows indicator reported alongside the identity, for investigation only.
        /// Each value keeps its exact raw text (no trimming, no sentinel substitution) together with a status that
        /// distinguishes a present value, an absent value, a read error and an unsupported platform. None of these
        /// values takes part in the licence identity.
        /// </summary>
        /// <returns>The observed indicators.</returns>
        public static MachineEvidence CollectEvidence()
        {
            return new MachineEvidence
            {
                SystemUuid = ReadWmi("Win32_ComputerSystemProduct", "UUID"),
                ProcessorId = ReadWmi("Win32_Processor", "ProcessorId"),
                MotherboardSerial = ReadWmi("Win32_BaseBoard", "SerialNumber"),
                BiosSerial = ReadWmi("Win32_BIOS", "SerialNumber"),
                SystemManufacturer = ReadWmi("Win32_ComputerSystem", "Manufacturer"),
                SystemModel = ReadWmi("Win32_ComputerSystem", "Model"),
                HypervisorPresent = ReadWmi("Win32_ComputerSystem", "HypervisorPresent"),
                SystemDiskSerial = ReadSystemDiskSerial(),
                MachineName = Environment.MachineName,
                MachineGuid = registryValueReader(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
                WindowsDeviceId = registryValueReader(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\SQMClient", "MachineId"),
                GlobalDeviceId = registryValueReader(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties", "LID"),
            };
        }

        /// <summary>Replaces the WMI reader for tests and restores it when disposed.</summary>
        internal static IDisposable UseWmiQueryReaderForTests(WmiQueryReader reader)
        {
            var previous = wmiQueryReader;
            wmiQueryReader = reader;
            return new RestoreAction(() => wmiQueryReader = previous);
        }

        /// <summary>Replaces the registry reader for tests and restores it when disposed.</summary>
        internal static IDisposable UseRegistryValueReaderForTests(RegistryValueReader reader)
        {
            var previous = registryValueReader;
            registryValueReader = reader;
            return new RestoreAction(() => registryValueReader = previous);
        }

        /// <summary>Reads one property of every instance of a WMI class as evidence.</summary>
        private static MachineEvidenceValue ReadWmi(string className, string propertyName)
        {
            var query = wmiQueryReader(className, new[] { propertyName });
            if (query.Status != MachineEvidenceStatus.Present)
                return new MachineEvidenceValue(query.Status, Array.Empty<string?>(), query.Error);

            var values = query.Rows.Select(row => GetOrNull(row, propertyName)).ToList();
            var status = values.Any(value => value != null) ? MachineEvidenceStatus.Present : MachineEvidenceStatus.Absent;
            return new MachineEvidenceValue(status, values, null);
        }

        /// <summary>Reads the serial number of disk index 0 only (the system disk), as evidence.</summary>
        private static MachineEvidenceValue ReadSystemDiskSerial()
        {
            var query = wmiQueryReader("Win32_DiskDrive", DiskProperties);
            if (query.Status != MachineEvidenceStatus.Present)
                return new MachineEvidenceValue(query.Status, Array.Empty<string?>(), query.Error);

            foreach (var row in query.Rows)
            {
                if (string.Equals(GetOrNull(row, "Index"), "0", StringComparison.Ordinal))
                {
                    var serial = GetOrNull(row, "SerialNumber");
                    return serial == null ? MachineEvidenceValue.Absent() : MachineEvidenceValue.Present(serial);
                }
            }
            return MachineEvidenceValue.Absent();
        }

        /// <summary>Returns the raw value of one property, or <c>null</c> when WMI reported none.</summary>
        private static string? GetOrNull(IReadOnlyDictionary<string, string?> row, string propertyName)
        {
            return row.TryGetValue(propertyName, out var value) ? value : null;
        }

        /// <summary>
        /// Returns the canonical uppercase 8-4-4-4-12 form, or <c>null</c> when the value is not an ASCII
        /// hexadecimal UUID. One pair of surrounding braces is accepted; nothing else is repaired.
        /// </summary>
        private static string? Canonicalize(string value)
        {
            if (value.Length == 38 && value[0] == '{' && value[37] == '}')
                value = value.Substring(1, 36);
            if (value.Length != 36)
                return null;

            var builder = new StringBuilder(36);
            for (var index = 0; index < 36; index++)
            {
                var character = value[index];
                var isSeparatorPosition = index == 8 || index == 13 || index == 18 || index == 23;
                if (isSeparatorPosition)
                {
                    if (character != '-') return null;
                    builder.Append('-');
                    continue;
                }
                if (character >= '0' && character <= '9') builder.Append(character);
                else if (character >= 'a' && character <= 'f') builder.Append((char)(character - 'a' + 'A'));
                else if (character >= 'A' && character <= 'F') builder.Append(character);
                else return null;
            }
            return builder.ToString();
        }

        /// <summary>
        /// Reports whether a canonical UUID is a placeholder: every hexadecimal digit identical (all zeros, all F,
        /// …) or listed in <see cref="KnownGenericUuids"/>.
        /// </summary>
        private static bool IsGeneric(string canonical)
        {
            if (KnownGenericUuids.Contains(canonical))
                return true;
            var first = canonical[0];
            foreach (var character in canonical)
            {
                if (character != '-' && character != first)
                    return false;
            }
            return true;
        }

        /// <summary>Maps a canonical UUID to the historical 16-character uppercase hexadecimal identifier format.</summary>
        private static string DeriveHardwareId(string canonical)
        {
            using (var sha256 = SHA256.Create())
            {
                var digest = sha256.ComputeHash(Encoding.UTF8.GetBytes(DerivationPrefix + canonical));
                return BitConverter.ToString(digest).Replace("-", string.Empty).Substring(0, 16);
            }
        }

        /// <summary>
        /// Runs <c>SELECT properties FROM className</c> and converts each property with the invariant culture.
        /// Failures are reported with the exception type name, never swallowed into a sentinel value.
        /// </summary>
        private static WmiQueryResult QueryWmi(string className, IReadOnlyList<string> propertyNames)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return WmiQueryResult.Unsupported();
            try
            {
                var rows = new List<IReadOnlyDictionary<string, string?>>();
                using (var searcher = new ManagementObjectSearcher($"SELECT {string.Join(", ", propertyNames)} FROM {className}"))
                using (var results = searcher.Get())
                {
                    foreach (ManagementObject instance in results)
                    {
                        using (instance)
                        {
                            var row = new Dictionary<string, string?>(StringComparer.Ordinal);
                            foreach (var propertyName in propertyNames)
                                row[propertyName] = Convert.ToString(instance[propertyName], CultureInfo.InvariantCulture);
                            rows.Add(row);
                        }
                    }
                }
                return WmiQueryResult.Success(rows);
            }
            catch (Exception exception)
            {
                return WmiQueryResult.Failed(exception.GetType().FullName ?? exception.GetType().Name);
            }
        }

        /// <summary>
        /// Reads one registry value from the 64-bit view. Strings are returned as stored; binary values as
        /// uppercase hexadecimal; other types with the invariant culture.
        /// </summary>
        private static MachineEvidenceValue ReadRegistryValue(RegistryHive hive, string keyPath, string valueName)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return MachineEvidenceValue.Unsupported();
            try
            {
                using (var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (var key = root.OpenSubKey(keyPath))
                {
                    var value = key?.GetValue(valueName);
                    if (value == null)
                        return MachineEvidenceValue.Absent();
                    var text = value is byte[] bytes
                        ? BitConverter.ToString(bytes).Replace("-", string.Empty)
                        : Convert.ToString(value, CultureInfo.InvariantCulture);
                    return MachineEvidenceValue.Present(text);
                }
            }
            catch (Exception exception)
            {
                return MachineEvidenceValue.Failed(exception.GetType().FullName ?? exception.GetType().Name);
            }
        }

        /// <summary>Runs a restore action once when a test scope ends.</summary>
        private sealed class RestoreAction : IDisposable
        {
            private Action? restore;

            /// <summary>Captures the action to run on disposal.</summary>
            public RestoreAction(Action restore)
            {
                this.restore = restore;
            }

            /// <summary>Runs the captured action once.</summary>
            public void Dispose()
            {
                restore?.Invoke();
                restore = null;
            }
        }
    }

    /// <summary>Raw result of one WMI query used by <see cref="MachineIdentity"/>.</summary>
    internal sealed class WmiQueryResult
    {
        private WmiQueryResult(MachineEvidenceStatus status, IReadOnlyList<IReadOnlyDictionary<string, string?>> rows, string? error)
        {
            Status = status;
            Rows = rows;
            Error = error;
        }

        /// <summary>Gets <see cref="MachineEvidenceStatus.Present"/> when the query ran, otherwise the failure kind.</summary>
        public MachineEvidenceStatus Status { get; }

        /// <summary>Gets one entry per WMI instance, property name to raw value (<c>null</c> when WMI reported none).</summary>
        public IReadOnlyList<IReadOnlyDictionary<string, string?>> Rows { get; }

        /// <summary>Gets the exception type name when the query failed.</summary>
        public string? Error { get; }

        /// <summary>Creates a successful result (possibly without any instance).</summary>
        public static WmiQueryResult Success(IReadOnlyList<IReadOnlyDictionary<string, string?>> rows) =>
            new WmiQueryResult(MachineEvidenceStatus.Present, rows, null);

        /// <summary>Creates a failed result carrying the exception type name.</summary>
        public static WmiQueryResult Failed(string error) =>
            new WmiQueryResult(MachineEvidenceStatus.Error, Array.Empty<IReadOnlyDictionary<string, string?>>(), error);

        /// <summary>Creates the result for a platform without WMI.</summary>
        public static WmiQueryResult Unsupported() =>
            new WmiQueryResult(MachineEvidenceStatus.Unsupported, Array.Empty<IReadOnlyDictionary<string, string?>>(), null);
    }

    /// <summary>Outcome of <see cref="MachineIdentity.Resolve"/> or <see cref="MachineIdentity.FromUuid"/>.</summary>
    public sealed class MachineIdentityResult
    {
        private MachineIdentityResult(bool isAccepted, string? canonicalUuid, string? hardwareId, string? refusalCode, string? readFailure)
        {
            IsAccepted = isAccepted;
            CanonicalUuid = canonicalUuid;
            HardwareId = hardwareId;
            RefusalCode = refusalCode;
            ReadFailure = readFailure;
        }

        /// <summary>Gets whether the machine has a usable licence identity.</summary>
        public bool IsAccepted { get; }

        /// <summary>Gets the canonical uppercase UUID when accepted; otherwise <c>null</c>.</summary>
        public string? CanonicalUuid { get; }

        /// <summary>Gets the 16-character uppercase hexadecimal licence identifier when accepted; otherwise <c>null</c>.</summary>
        public string? HardwareId { get; }

        /// <summary>Gets the stable refusal code when refused; otherwise <c>null</c>.</summary>
        public string? RefusalCode { get; }

        /// <summary>Gets the customer-visible support code (<c>AR-xx</c>) when refused; otherwise <c>null</c>.</summary>
        public string? SupportCode => MachineIdentity.ToSupportCode(RefusalCode);

        /// <summary>
        /// Gets the technical cause of <see cref="MachineIdentity.RefusalUuidUnreadable"/> (exception type name or
        /// <c>NON-WINDOWS</c>), for logs only; otherwise <c>null</c>.
        /// </summary>
        public string? ReadFailure { get; }

        /// <summary>Creates an accepted result.</summary>
        internal static MachineIdentityResult Accepted(string canonicalUuid, string hardwareId) =>
            new MachineIdentityResult(true, canonicalUuid, hardwareId, null, null);

        /// <summary>Creates a refused result carrying a stable refusal code and an optional read failure cause.</summary>
        internal static MachineIdentityResult Refused(string refusalCode, string? readFailure) =>
            new MachineIdentityResult(false, null, null, refusalCode, readFailure);
    }

    /// <summary>Observation status of one evidence value.</summary>
    public enum MachineEvidenceStatus
    {
        /// <summary>The source was read and returned at least one value.</summary>
        Present,

        /// <summary>The source was read successfully but holds no value.</summary>
        Absent,

        /// <summary>Reading the source failed; see <see cref="MachineEvidenceValue.Error"/>.</summary>
        Error,

        /// <summary>The source does not exist on this platform (non-Windows).</summary>
        Unsupported,
    }

    /// <summary>One evidence value: its status, its raw values and, on failure, the error type.</summary>
    public sealed class MachineEvidenceValue
    {
        /// <summary>Creates an evidence value.</summary>
        internal MachineEvidenceValue(MachineEvidenceStatus status, IReadOnlyList<string?> values, string? error)
        {
            Status = status;
            Values = values;
            Error = error;
        }

        /// <summary>Gets the observation status.</summary>
        public MachineEvidenceStatus Status { get; }

        /// <summary>
        /// Gets the raw values exactly as observed, one per WMI instance (a single entry for a registry value);
        /// an entry is <c>null</c> when that instance reported no value.
        /// </summary>
        public IReadOnlyList<string?> Values { get; }

        /// <summary>Gets the first raw value, or <c>null</c>.</summary>
        public string? Value => Values.Count > 0 ? Values[0] : null;

        /// <summary>Gets the exception type name when <see cref="Status"/> is <see cref="MachineEvidenceStatus.Error"/>.</summary>
        public string? Error { get; }

        /// <summary>Creates a present value.</summary>
        internal static MachineEvidenceValue Present(string? value) =>
            new MachineEvidenceValue(MachineEvidenceStatus.Present, new[] { value }, null);

        /// <summary>Creates an absent value.</summary>
        internal static MachineEvidenceValue Absent() =>
            new MachineEvidenceValue(MachineEvidenceStatus.Absent, Array.Empty<string?>(), null);

        /// <summary>Creates a failed read carrying the exception type name.</summary>
        internal static MachineEvidenceValue Failed(string error) =>
            new MachineEvidenceValue(MachineEvidenceStatus.Error, Array.Empty<string?>(), error);

        /// <summary>Creates the value for a platform without the source.</summary>
        internal static MachineEvidenceValue Unsupported() =>
            new MachineEvidenceValue(MachineEvidenceStatus.Unsupported, Array.Empty<string?>(), null);
    }

    /// <summary>
    /// Hardware and Windows indicators reported with the identity for investigation. Evidence only: none of these
    /// values takes part in the licence identity.
    /// </summary>
    public sealed class MachineEvidence
    {
        /// <summary>Gets the raw <c>Win32_ComputerSystemProduct.UUID</c>.</summary>
        public MachineEvidenceValue SystemUuid { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets <c>Win32_Processor.ProcessorId</c> of every processor (identifies the model, not the unit).</summary>
        public MachineEvidenceValue ProcessorId { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets <c>Win32_BaseBoard.SerialNumber</c>.</summary>
        public MachineEvidenceValue MotherboardSerial { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets <c>Win32_BIOS.SerialNumber</c> (the machine serial written by the manufacturer).</summary>
        public MachineEvidenceValue BiosSerial { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets <c>Win32_ComputerSystem.Manufacturer</c> (virtualization hint).</summary>
        public MachineEvidenceValue SystemManufacturer { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets <c>Win32_ComputerSystem.Model</c> (virtualization hint).</summary>
        public MachineEvidenceValue SystemModel { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets <c>Win32_ComputerSystem.HypervisorPresent</c> as reported by WMI.</summary>
        public MachineEvidenceValue HypervisorPresent { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets the raw <c>Win32_DiskDrive.SerialNumber</c> of disk index 0 (system disk), untrimmed.</summary>
        public MachineEvidenceValue SystemDiskSerial { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets the Windows computer name.</summary>
        public string MachineName { get; internal set; } = string.Empty;

        /// <summary>Gets <c>HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid</c> (changes on reinstall, copied by clones).</summary>
        public MachineEvidenceValue MachineGuid { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets <c>HKLM\SOFTWARE\Microsoft\SQMClient\MachineId</c> (Windows device ID).</summary>
        public MachineEvidenceValue WindowsDeviceId { get; internal set; } = MachineEvidenceValue.Absent();

        /// <summary>Gets the Windows Global Device ID (<c>HKCU\…\IdentityCRL\ExtendedProperties\LID</c>); absent on never-connected machines.</summary>
        public MachineEvidenceValue GlobalDeviceId { get; internal set; } = MachineEvidenceValue.Absent();
    }
}

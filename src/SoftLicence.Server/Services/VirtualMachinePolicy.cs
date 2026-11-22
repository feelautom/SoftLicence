using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SoftLicence.Server.Services;

/// <summary>Bounded, versioned interpretation of declarative machine observations, never hardware attestation.</summary>
public static class VirtualMachinePolicy
{
    /// <summary>Classifier version persisted with authenticated distribution decisions.</summary>
    public const int Version = 1;
    /// <summary>Recognized virtual-machine refusal.</summary>
    public const string VirtualMachineCode = "VIRTUAL_MACHINE_NOT_ALLOWED";
    /// <summary>Insufficient trustworthy machine-information refusal.</summary>
    public const string EvidenceRequiredCode = "MACHINE_EVIDENCE_REQUIRED";
    /// <summary>Exact public message, without upgrade or support suggestions.</summary>
    public const string VirtualMachineMessage = "Free and trial licenses cannot be activated on a virtual machine.";
    /// <summary>Exact public message for missing or ambiguous classification evidence.</summary>
    public const string EvidenceRequiredMessage = "Update your installer or application to provide the machine information required for free and trial licenses.";

    /// <summary>Classification contains no raw identifiers: Kind is physical/virtual/unknown, Reason is internal, EvidenceDigest is lowercase SHA-256, and SourceDecisionId is set only for authenticated reuse.</summary>
    public sealed record Assessment(string Kind, string Reason, string? EvidenceDigest, Guid? SourceDecisionId = null);

    /// <summary>Historical unqualified acquisitions and paid rights are deliberately exempt.</summary>
    public static bool IsRestricted(string? nature) => nature is "FIRST_ORDER_FREE" or "FREE" or "PAID_TRIAL";

    /// <summary>Returns a stable public refusal code, or null for an exempt or physical machine.</summary>
    public static string? Refusal(string? nature, Assessment assessment) => !IsRestricted(nature) ? null
        : assessment.Kind == "virtual" ? VirtualMachineCode
        : assessment.Kind == "physical" ? null : EvidenceRequiredCode;

    /// <summary>Maps only the two public policy codes; unrelated contracts retain their original shape.</summary>
    public static string? Message(string? code) => code switch
    {
        VirtualMachineCode or "virtual_machine_not_allowed" => VirtualMachineMessage,
        EvidenceRequiredCode or "machine_evidence_required" => EvidenceRequiredMessage,
        _ => null
    };

    /// <summary>Builds a public distribution refusal without exposing internal classification reasons.</summary>
    public static DistributionOperationException DistributionRefusal(string code) =>
        new(code.ToLowerInvariant(), StatusCodes.Status403Forbidden);

    /// <summary>
    /// Accepts only the SDK Status/Values/Error observations, with or without the identical Value shortcut that
    /// SDK 2.0.0 serializes next to the list, and the WebSetup status/value observations. Comparison uses
    /// trimmed invariant uppercase copies; raw evidence and identity are never normalized or changed.
    /// HypervisorPresent is deliberately not used as proof: physical Windows machines may report true.
    /// Absent, malformed or ambiguous bounded observations return unknown; classification has no persistence side effects.
    /// </summary>
    public static Assessment Classify(JsonElement? evidence)
    {
        if (evidence is not { ValueKind: JsonValueKind.Object } root)
            return new("unknown", "evidence_absent", null);
        var raw = root.GetRawText();
        if (Encoding.UTF8.GetByteCount(raw) > 16384)
            return new("unknown", "evidence_oversized", null);
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        if (!ReadObservation(root, "SystemManufacturer", "systemManufacturer", out var manufacturer)
            || !ReadObservation(root, "SystemModel", "systemModel", out var model))
            return new("unknown", "manufacturer_model_unusable", digest);

        var vm = (manufacturer == "VMWARE, INC." && model.StartsWith("VMWARE ", StringComparison.Ordinal))
            || ((manufacturer is "INNOTEK GMBH" or "ORACLE CORPORATION") && model == "VIRTUALBOX")
            || ((manufacturer is "QEMU" or "RED HAT" or "RED HAT, INC.")
                && (model.StartsWith("STANDARD PC", StringComparison.Ordinal) || model is "KVM" or "RHEV HYPERVISOR"))
            || (manufacturer == "MICROSOFT CORPORATION" && model == "VIRTUAL MACHINE")
            || (manufacturer == "XEN" && model == "HVM DOMU")
            || (manufacturer == "PARALLELS SOFTWARE INTERNATIONAL INC." && model.StartsWith("PARALLELS ", StringComparison.Ordinal));
        if (vm) return new("virtual", "manufacturer_model_vm_pair", digest);
        // A partial VM signature is contradictory, not evidence of a physical computer.
        if (manufacturer.Contains("VMWARE", StringComparison.Ordinal)
            || manufacturer.Contains("PARALLELS", StringComparison.Ordinal)
            || manufacturer is "QEMU" or "XEN" or "INNOTEK GMBH" or "ORACLE CORPORATION" or "RED HAT" or "RED HAT, INC."
            || model.Contains("VIRTUAL", StringComparison.Ordinal) || model.Contains("VMWARE", StringComparison.Ordinal)
            || model.Contains("HVM DOMU", StringComparison.Ordinal) || model == "KVM")
            return new("unknown", "manufacturer_model_conflict", digest);
        return new("physical", "manufacturer_model_nonvirtual", digest);
    }

    /// <summary>Requires one exact known spelling and one present value; duplicate or mixed representations fail closed, except the SDK's identical Value copy.</summary>
    private static bool ReadObservation(JsonElement root, string sdkName, string webName, out string value)
    {
        value = string.Empty;
        var matches = root.EnumerateObject().Where(p => string.Equals(p.Name, sdkName, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length != 1 || (matches[0].Name != sdkName && matches[0].Name != webName)
            || matches[0].Value.ValueKind != JsonValueKind.Object) return false;
        var fields = matches[0].Value.EnumerateObject().ToArray();
        if (fields.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != fields.Length) return false;
        var status = fields.SingleOrDefault(p => p.Name is "Status" or "status").Value;
        if (status.ValueKind != JsonValueKind.String || status.GetString() is not ("Present" or "present")) return false;
        var scalar = fields.Where(p => p.Name is "value" or "Value").ToArray();
        var arrays = fields.Where(p => p.Name is "Values" or "values").ToArray();
        var errors = fields.Where(p => p.Name is "Error" or "error").ToArray();
        if (errors.Any(p => p.Value.ValueKind != JsonValueKind.Null)) return false;
        JsonElement text;
        if (scalar.Length == 1 && arrays.Length == 0) text = scalar[0].Value;
        else if (arrays.Length == 1 && arrays[0].Value.ValueKind == JsonValueKind.Array
            && arrays[0].Value.GetArrayLength() == 1
            && (scalar.Length == 0 || (matches[0].Name == sdkName && IsSdkFirstValueCopy(fields, scalar, arrays[0]))))
            text = arrays[0].Value[0];
        else return false;
        if (text.ValueKind != JsonValueKind.String) return false;
        var raw = text.GetString()!;
        if (raw.Length > 512 || raw.Any(char.IsControl)) return false;
        value = raw.Trim().ToUpperInvariant();
        return value.Length > 0 && value is not ("UNKNOWN" or "DEFAULT STRING" or "SYSTEM MANUFACTURER"
            or "SYSTEM PRODUCT NAME" or "TO BE FILLED BY O.E.M." or "NONE" or "N/A" or "NOT SPECIFIED");
    }

    /// <summary>
    /// Recognizes the observation as SDK 2.0.0 really serializes it (TKT-001784): its list and the first-value
    /// shortcut of that list, <c>{"Status":"Present","Values":["X"],"Value":"X","Error":null}</c>. Only that
    /// exact producer shape with an ordinally identical string is one observation written twice. The caller also
    /// requires the SDK spelling of the observation name, so a pair under WebSetup spelling, with another or a
    /// missing field, another status spelling or a differing string stays a mixed representation. Field names
    /// are already distinct here, so four fields drawn from the four SDK names are exactly those four.
    /// </summary>
    /// <param name="fields">Every field of the observation.</param>
    /// <param name="scalar">Its scalar fields.</param>
    /// <param name="list">Its single-element list field.</param>
    /// <returns><see langword="true"/> when the observation is exactly the SDK shape and the scalar copies the list's only element.</returns>
    private static bool IsSdkFirstValueCopy(JsonProperty[] fields, JsonProperty[] scalar, JsonProperty list) =>
        fields.Length == 4 && fields.All(p => p.Name is "Status" or "Values" or "Value" or "Error")
        && fields.Any(p => p.Name == "Status" && p.Value.ValueEquals("Present"))
        && scalar.Length == 1 && scalar[0].Value.ValueKind == JsonValueKind.String
        && list.Value[0].ValueKind == JsonValueKind.String
        && string.Equals(scalar[0].Value.GetString(), list.Value[0].GetString(), StringComparison.Ordinal);
}

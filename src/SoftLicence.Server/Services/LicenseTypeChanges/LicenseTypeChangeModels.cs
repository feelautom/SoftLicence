namespace SoftLicence.Server.Services.LicenseTypeChanges;

/// <summary>
/// One batch of licence-type changes sent to the preview and apply routes (TKT-002781). Every operation targets the one
/// product the route resolved; there is no implicit "all types": parameters change only on the slugs listed.
/// </summary>
public sealed class LicenseTypeChangeRequest
{
    /// <summary>Product identifier; exclusive with <see cref="ProductName"/>.</summary>
    public string? ProductId { get; set; }

    /// <summary>Product name; exclusive with <see cref="ProductId"/>.</summary>
    public string? ProductName { get; set; }

    /// <summary>Optional free reference (ticket, instance) written to the journal; never used for authorization.</summary>
    public string? RequestedBy { get; set; }

    /// <summary>Fingerprint returned by the preview; required by apply, ignored by preview.</summary>
    public string? PreviewHash { get; set; }

    /// <summary>Ordered operations, 1 to 50.</summary>
    public List<LicenseTypeChangeOperation> Operations { get; set; } = new();
}

/// <summary>
/// One change. <see cref="Kind"/> selects the fields that matter: <c>createType</c>, <c>updateType</c>, <c>setParam</c>,
/// <c>removeParam</c> or <c>createPlugin</c>. Null settings are left unchanged.
/// </summary>
public sealed class LicenseTypeChangeOperation
{
    /// <summary>Operation kind, compared without regard to case.</summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>Slug of the type to create (createType) or to change (updateType).</summary>
    public string? Slug { get; set; }

    /// <summary>Explicit slugs a parameter is set on or removed from (setParam, removeParam).</summary>
    public List<string>? Slugs { get; set; }

    /// <summary>Display name of the type (createType, updateType) or of the plugin (createPlugin).</summary>
    public string? Name { get; set; }

    /// <summary>Type description.</summary>
    public string? Description { get; set; }

    /// <summary>Default key duration in days.</summary>
    public int? DefaultDurationDays { get; set; }

    /// <summary>Recurring subscription flag.</summary>
    public bool? IsRecurring { get; set; }

    /// <summary>Allowed versions pattern.</summary>
    public string? DefaultAllowedVersions { get; set; }

    /// <summary>Default seat count.</summary>
    public int? DefaultMaxSeats { get; set; }

    /// <summary>Maximum activations per day, 0 for unlimited.</summary>
    public int? MaxActivationsPerDay { get; set; }

    /// <summary>Anonymous keys allowed.</summary>
    public bool? AllowAnonymous { get; set; }

    /// <summary>Free type flag.</summary>
    public bool? IsFree { get; set; }

    /// <summary>One use per hardware identifier.</summary>
    public bool? EnforceSingleUsePerHardwareId { get; set; }

    /// <summary>New activations blocked.</summary>
    public bool? DisableNewActivations { get; set; }

    /// <summary>Anonymous public trial opt-in.</summary>
    public bool? AllowPublicTrial { get; set; }

    /// <summary>Team eligibility flag.</summary>
    public bool? TeamEligible { get; set; }

    /// <summary>Parameters of a created type.</summary>
    public List<LicenseTypeChangeParam>? Params { get; set; }

    /// <summary>Parameter key (setParam, removeParam), compared exactly.</summary>
    public string? Key { get; set; }

    /// <summary>Parameter display name; required by setParam when the key is new on a type.</summary>
    public string? ParamName { get; set; }

    /// <summary>Parameter value (setParam).</summary>
    public string? Value { get; set; }
}

/// <summary>Parameter of a created type.</summary>
public sealed class LicenseTypeChangeParam
{
    /// <summary>Key, compared exactly after trimming.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Display name, required.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Value.</summary>
    public string Value { get; set; } = string.Empty;
}

/// <summary>Result of a preview: what each operation would change, and the fingerprint apply must repeat.</summary>
/// <param name="ProductId">Resolved product.</param>
/// <param name="ProductName">Its name.</param>
/// <param name="PreviewHash">Fingerprint of the operations and of the full state they read.</param>
/// <param name="Operations">One entry per operation, in order.</param>
public sealed record LicenseTypeChangePreview(
    Guid ProductId,
    string ProductName,
    string PreviewHash,
    IReadOnlyList<LicenseTypeChangeOperationPreview> Operations);

/// <summary>What one operation changes on one target.</summary>
/// <param name="Index">Position of the operation in the batch.</param>
/// <param name="Kind">Normalized operation kind.</param>
/// <param name="Target">Slug of the type, or name of the plugin.</param>
/// <param name="Before">Values before, null for a creation.</param>
/// <param name="After">Values after, null for a removal.</param>
/// <param name="ActiveLicenses">Active licences of the target type (information only, not in the fingerprint).</param>
/// <param name="Notes">Facts the caller must see (key pair generated, backup state).</param>
public sealed record LicenseTypeChangeOperationPreview(
    int Index,
    string Kind,
    string Target,
    IReadOnlyDictionary<string, string?>? Before,
    IReadOnlyDictionary<string, string?>? After,
    int ActiveLicenses,
    IReadOnlyList<string> Notes);

/// <summary>Result of an apply.</summary>
/// <param name="AuditId">Journal row written in the same transaction.</param>
/// <param name="AppliedAtUtc">Commit time.</param>
/// <param name="Preview">The preview that was applied.</param>
/// <param name="CreatedPluginIds">Identifiers of created plugins (no key material).</param>
public sealed record LicenseTypeChangeResult(
    Guid AuditId,
    DateTime AppliedAtUtc,
    LicenseTypeChangePreview Preview,
    IReadOnlyList<Guid> CreatedPluginIds);

/// <summary>Refusal of a batch, with an HTTP status and a stable code; nothing was written.</summary>
public sealed class LicenseTypeChangeException : Exception
{
    /// <summary>Creates a refusal.</summary>
    /// <param name="status">HTTP status to answer.</param>
    /// <param name="code">Stable machine code.</param>
    /// <param name="message">Readable cause.</param>
    public LicenseTypeChangeException(int status, string code, string message) : base(message)
    {
        Status = status;
        Code = code;
    }

    /// <summary>HTTP status.</summary>
    public int Status { get; }

    /// <summary>Stable machine code.</summary>
    public string Code { get; }
}

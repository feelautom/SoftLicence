using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services.LicenseTypeChanges;

/// <summary>
/// Previews then applies licence-type, parameter and plugin changes for one product (TKT-002781). The preview writes
/// nothing and returns a fingerprint of the operations and of the full state they read. Apply rereads that state in a
/// SERIALIZABLE transaction, recomputes the fingerprint and writes only when it is unchanged, together with one
/// journal row; a concurrent change, a serialization failure or a uniqueness violation answers 409 with nothing
/// written. SoftLicence executes the request: no price, offer or commercial rule is checked here.
/// </summary>
/// <remarks>
/// String rules (string-normalization guard): slugs are created as <c>Trim().ToUpperInvariant()</c> with spaces turned
/// into <c>_</c>, like the administration route, and are targeted without regard to case, an ambiguous or unknown slug
/// refusing the whole batch. Parameter keys are trimmed and compared exactly (the unique index is case-sensitive); a
/// key that differs from an existing key of the product only by case is refused, so <c>hasClassroom</c> and
/// <c>HasClassroom</c> can never coexist by mistake. Plugin names are unique without regard to case, like the screen.
/// </remarks>
public sealed class LicenseTypeChangeService
{
    /// <summary>Largest batch accepted.</summary>
    public const int MaximumOperations = 50;

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly EncryptionService _encryption;
    private readonly BackupService _backup;
    private readonly SettingsService _settings;
    private readonly ILogger<LicenseTypeChangeService> _logger;

    /// <summary>
    /// Creates the service. It holds no per-request state: every preview and apply opens its own context, so one
    /// instance may serve concurrent requests (the database transaction is the only serialization point).
    /// </summary>
    /// <param name="dbFactory">Creates one context per call; the apply transaction runs on it.</param>
    /// <param name="encryption">Encrypts the private key of a level-2 plugin before it is stored.</param>
    /// <param name="backup">Backs up a level-2 plugin key pair to the Drive before the commit.</param>
    /// <param name="settings">Tells the preview whether the Drive backup is enabled.</param>
    /// <param name="logger">Journals applied batches and backup failures, never key material.</param>
    public LicenseTypeChangeService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        EncryptionService encryption,
        BackupService backup,
        SettingsService settings,
        ILogger<LicenseTypeChangeService> logger)
    {
        _dbFactory = dbFactory;
        _encryption = encryption;
        _backup = backup;
        _settings = settings;
        _logger = logger;
    }

    /// <summary>Computes what the batch would change; writes nothing.</summary>
    /// <param name="productId">Product resolved and authorized by the route.</param>
    /// <param name="keyIsGlobal">True for a global analytics key; plugin creation requires it.</param>
    /// <param name="request">Batch.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns>The preview and its fingerprint.</returns>
    /// <exception cref="LicenseTypeChangeException">The batch is invalid; nothing was written.</exception>
    public async Task<LicenseTypeChangePreview> PreviewAsync(
        Guid productId, bool keyIsGlobal, LicenseTypeChangeRequest request, CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var plan = await PlanAsync(db, productId, keyIsGlobal, request, tracked: false, cancellationToken);
        return plan.Preview;
    }

    /// <summary>
    /// Applies the batch when its fingerprint still matches, in one SERIALIZABLE transaction with its journal row. A
    /// level-2 plugin key pair is backed up to the Drive before the commit; a failed backup refuses the batch.
    /// </summary>
    /// <param name="productId">Product resolved and authorized by the route.</param>
    /// <param name="keyIsGlobal">True for a global analytics key.</param>
    /// <param name="analyticsKeyId">Key written to the journal.</param>
    /// <param name="callerIp">Caller address written to the journal.</param>
    /// <param name="request">Batch with the preview fingerprint.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns>The applied preview and the journal row.</returns>
    /// <exception cref="LicenseTypeChangeException">Refused (stale preview, conflict, invalid batch); nothing written.</exception>
    public async Task<LicenseTypeChangeResult> ApplyAsync(
        Guid productId,
        bool keyIsGlobal,
        Guid analyticsKeyId,
        string? callerIp,
        LicenseTypeChangeRequest request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.PreviewHash))
            throw new LicenseTypeChangeException(400, "PREVIEW_HASH_REQUIRED", "Apply requires the previewHash returned by the preview of the same batch.");

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        // PostgreSQL in production and in the contract tests: SERIALIZABLE is what makes the fingerprint check and the
        // writes atomic. The in-memory provider of the route tests has no transactions; it never reaches a write there.
        IDbContextTransaction? transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            : null;
        await using (transaction)
        {
            try
            {
                var plan = await PlanAsync(db, productId, keyIsGlobal, request, tracked: true, cancellationToken);
                if (!string.Equals(plan.Preview.PreviewHash, request.PreviewHash.Trim(), StringComparison.OrdinalIgnoreCase))
                    throw new LicenseTypeChangeException(409, "PREVIEW_STALE",
                        "The catalogue changed since the preview, or the batch is not the one previewed. Preview again.");

                var createdPlugins = new List<(Product Product, string? PrivateKey)>();
                ApplyTypes(db, plan);
                foreach (var plugin in plan.Plugins)
                    createdPlugins.Add(CreatePlugin(db, plan.ProductEntity!, plugin));

                var appliedAt = DateTime.UtcNow;
                var audit = new LicenseTypeChangeAudit
                {
                    AppliedAtUtc = appliedAt,
                    ProductId = productId,
                    AnalyticsKeyId = analyticsKeyId,
                    CallerIp = Truncate(callerIp, 64),
                    RequestedBy = Truncate(request.RequestedBy?.Trim(), 200),
                    PreviewHash = plan.Preview.PreviewHash,
                    OperationCount = plan.Preview.Operations.Count,
                    ChangesJson = JsonSerializer.Serialize(plan.Preview.Operations)
                };
                db.LicenseTypeChangeAudits.Add(audit);
                await db.SaveChangesAsync(cancellationToken);

                // External effect last before the commit: a plugin whose private key could not be backed up is not created.
                foreach (var (product, privateKey) in createdPlugins)
                {
                    if (privateKey == null) continue;
                    try
                    {
                        await _backup.UploadKeyPairAsync(product.Name, privateKey, product.PublicKeyXml);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[LICENSE_TYPE_CHANGES] Key pair backup failed for plugin {Plugin}; batch refused.", product.Name);
                        throw new LicenseTypeChangeException(502, "PLUGIN_KEY_BACKUP_FAILED",
                            "The key pair of the new plugin could not be backed up; nothing was written.");
                    }
                }

                if (transaction != null)
                    await transaction.CommitAsync(cancellationToken);
                _logger.LogInformation("[LICENSE_TYPE_CHANGES] Batch applied on product {ProductId}: {Count} operation(s), audit {AuditId}, key {KeyId}.",
                    productId, audit.OperationCount, audit.Id, analyticsKeyId);
                return new LicenseTypeChangeResult(audit.Id, appliedAt, plan.Preview, createdPlugins.Select(item => item.Product.Id).ToList());
            }
            catch (Exception ex) when (IsWriteConflict(ex))
            {
                throw new LicenseTypeChangeException(409, "CONCURRENT_CHANGE",
                    "Another change reached the catalogue at the same time; nothing was written. Preview again.");
            }
        }
    }

    /// <summary>Reads the journal of one product, newest first.</summary>
    /// <param name="productId">Product resolved and authorized by the route.</param>
    /// <param name="take">Rows, 1 to 200.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <returns>Journal rows; they never hold key material.</returns>
    public async Task<IReadOnlyList<LicenseTypeChangeAudit>> GetAuditAsync(Guid productId, int take, CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.LicenseTypeChangeAudits.AsNoTracking()
            .Where(row => row.ProductId == productId)
            .OrderByDescending(row => row.AppliedAtUtc)
            .Take(Math.Clamp(take, 1, 200))
            .ToListAsync(cancellationToken);
    }

    /// <summary>True for a PostgreSQL serialization failure or uniqueness violation, which must answer 409.</summary>
    internal static bool IsWriteConflict(Exception ex)
    {
        for (var current = ex; current != null; current = current.InnerException)
        {
            if (current is PostgresException postgres
                && postgres.SqlState is PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.UniqueViolation)
                return true;
        }
        return false;
    }

    // ── Planning ────────────────────────────────────────────────────────────────────────────────────

    /// <summary>Working copy of one type while the batch is planned.</summary>
    private sealed class TypeState
    {
        /// <summary>Loaded entity (tracked during apply, detached during preview); null for a type the batch creates.</summary>
        public LicenseType? Entity;
        /// <summary>Identifier of the existing type, or a new identifier assigned at planning for a created type.</summary>
        public Guid Id;
        /// <summary>True when the batch creates this type; <see cref="ApplyTypes"/> then adds it instead of updating.</summary>
        public bool IsNew;
        public string Slug = string.Empty;
        public string Name = string.Empty;
        public string Description = string.Empty;
        public int DefaultDurationDays;
        public bool IsRecurring;
        public string DefaultAllowedVersions = "*";
        public int DefaultMaxSeats;
        public int MaxActivationsPerDay;
        public bool AllowAnonymous;
        public bool IsFree;
        public bool EnforceSingleUsePerHardwareId;
        public bool DisableNewActivations;
        public bool AllowPublicTrial;
        public bool TeamEligible;
        /// <summary>
        /// Final parameters by exact key (ordinal, like the unique index). Sorted so the fingerprint and the
        /// before/after views are deterministic; <see cref="ApplyTypes"/> adds, updates and removes rows to match it.
        /// </summary>
        public SortedDictionary<string, (string Name, string Value)> Params = new(StringComparer.Ordinal);

        /// <summary>Direct settings as text, in a fixed order (fingerprint and before/after).</summary>
        public SortedDictionary<string, string?> Settings() => new(StringComparer.Ordinal)
        {
            ["allowAnonymous"] = AllowAnonymous.ToString(),
            ["allowPublicTrial"] = AllowPublicTrial.ToString(),
            ["defaultAllowedVersions"] = DefaultAllowedVersions,
            ["defaultDurationDays"] = DefaultDurationDays.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["defaultMaxSeats"] = DefaultMaxSeats.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["description"] = Description,
            ["disableNewActivations"] = DisableNewActivations.ToString(),
            ["enforceSingleUsePerHardwareId"] = EnforceSingleUsePerHardwareId.ToString(),
            ["isFree"] = IsFree.ToString(),
            ["isRecurring"] = IsRecurring.ToString(),
            ["maxActivationsPerDay"] = MaxActivationsPerDay.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["name"] = Name,
            ["slug"] = Slug,
            ["teamEligible"] = TeamEligible.ToString()
        };
    }

    /// <summary>A plugin the batch creates.</summary>
    /// <param name="Name">Plugin name.</param>
    /// <param name="GeneratesKeyPair">True for a level-2 plugin (new pair), false for level 3 (copy of its parent).</param>
    private sealed record PluginPlan(string Name, bool GeneratesKeyPair);

    /// <summary>Planned batch: the working copy shared by preview and apply, and the preview computed from it.</summary>
    private sealed class Plan
    {
        /// <summary>Resolved product; tracked during apply, where a level-3 plugin copies its stored key pair.</summary>
        public Product? ProductEntity;
        /// <summary>Every type of the product after replaying the operations, existing ones first, created ones after.</summary>
        public List<TypeState> Types = new();
        /// <summary>Plugins the batch creates, in operation order.</summary>
        public List<PluginPlan> Plugins = new();
        /// <summary>Preview returned to the caller and journaled; set once at the end of planning.</summary>
        public LicenseTypeChangePreview Preview = null!;
    }

    /// <summary>
    /// Reads the product, its types and their parameters, validates and replays the operations on a working copy, and
    /// computes the preview and its fingerprint. Used identically by preview and apply, so both see the same rules.
    /// </summary>
    private async Task<Plan> PlanAsync(
        LicenseDbContext db, Guid productId, bool keyIsGlobal, LicenseTypeChangeRequest request, bool tracked,
        CancellationToken cancellationToken)
    {
        var operations = request.Operations ?? new List<LicenseTypeChangeOperation>();
        if (operations.Count == 0 || operations.Count > MaximumOperations)
            throw new LicenseTypeChangeException(400, "OPERATIONS_COUNT_INVALID", $"Send 1 to {MaximumOperations} operations.");

        var productQuery = tracked ? db.Products : db.Products.AsNoTracking();
        var product = await productQuery.FirstOrDefaultAsync(p => p.Id == productId, cancellationToken)
            ?? throw new LicenseTypeChangeException(404, "PRODUCT_NOT_FOUND", "Requested product was not found.");
        var parentOfProduct = product.ParentProductId.HasValue
            ? await db.Products.AsNoTracking().Where(p => p.Id == product.ParentProductId.Value)
                .Select(p => new { p.Id, p.ParentProductId }).FirstOrDefaultAsync(cancellationToken)
            : null;

        var typeQuery = tracked ? db.LicenseTypes.Include(t => t.CustomParams) : db.LicenseTypes.AsNoTracking().Include(t => t.CustomParams);
        var entities = await typeQuery.Where(t => t.ProductId == productId).OrderBy(t => t.Id).ToListAsync(cancellationToken);
        var activeCounts = await db.Licenses.AsNoTracking()
            .Where(l => l.Type != null && l.Type.ProductId == productId && l.IsActive)
            .GroupBy(l => l.LicenseTypeId)
            .Select(g => new { TypeId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.TypeId, g => g.Count, cancellationToken);

        var plan = new Plan { ProductEntity = product };
        foreach (var entity in entities)
            plan.Types.Add(FromEntity(entity));
        var originalState = plan.Types.Select(StateForHash).ToList();
        var productKeys = plan.Types.SelectMany(t => t.Params.Keys).Distinct(StringComparer.Ordinal).ToList();

        var previews = new List<LicenseTypeChangeOperationPreview>();
        var normalizedOperations = new List<object>();
        var pluginNameChecks = new List<object>();
        for (var index = 0; index < operations.Count; index++)
        {
            var operation = operations[index] ?? throw new LicenseTypeChangeException(400, "OPERATION_INVALID", $"Operation {index} is empty.");
            var kind = (operation.Kind ?? string.Empty).Trim();
            switch (kind.ToLowerInvariant())
            {
                case "createtype":
                    previews.Add(PlanCreateType(plan, operation, index, productKeys, normalizedOperations));
                    break;
                case "updatetype":
                    previews.Add(PlanUpdateType(plan, operation, index, activeCounts, normalizedOperations));
                    break;
                case "setparam":
                    previews.AddRange(PlanSetParam(plan, operation, index, activeCounts, productKeys, normalizedOperations));
                    break;
                case "removeparam":
                    previews.AddRange(PlanRemoveParam(plan, operation, index, activeCounts, normalizedOperations));
                    break;
                case "createplugin":
                    previews.Add(await PlanCreatePluginAsync(db, plan, product, parentOfProduct?.ParentProductId, keyIsGlobal, operation, index,
                        normalizedOperations, pluginNameChecks, cancellationToken));
                    break;
                default:
                    throw new LicenseTypeChangeException(400, "OPERATION_KIND_UNKNOWN",
                        $"Operation {index}: unknown kind '{operation.Kind}'. Use createType, updateType, setParam, removeParam or createPlugin.");
            }
        }

        var fingerprint = new
        {
            product = new { product.Id, product.Name, product.ParentProductId, parentParent = parentOfProduct?.ParentProductId },
            operations = normalizedOperations,
            types = originalState,
            pluginNames = pluginNameChecks
        };
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(fingerprint)))).ToLowerInvariant();
        plan.Preview = new LicenseTypeChangePreview(product.Id, product.Name, hash, previews);
        return plan;
    }

    /// <summary>Copies an entity into a working state.</summary>
    private static TypeState FromEntity(LicenseType entity)
    {
        var state = new TypeState
        {
            Entity = entity,
            Id = entity.Id,
            Slug = entity.Slug,
            Name = entity.Name,
            Description = entity.Description,
            DefaultDurationDays = entity.DefaultDurationDays,
            IsRecurring = entity.IsRecurring,
            DefaultAllowedVersions = entity.DefaultAllowedVersions,
            DefaultMaxSeats = entity.DefaultMaxSeats,
            MaxActivationsPerDay = entity.MaxActivationsPerDay,
            AllowAnonymous = entity.AllowAnonymous,
            IsFree = entity.IsFree,
            EnforceSingleUsePerHardwareId = entity.EnforceSingleUsePerHardwareId,
            DisableNewActivations = entity.DisableNewActivations,
            AllowPublicTrial = entity.AllowPublicTrial,
            TeamEligible = entity.TeamEligible
        };
        foreach (var param in entity.CustomParams.OrderBy(p => p.Key, StringComparer.Ordinal))
            state.Params[param.Key] = (param.Name, param.Value);
        return state;
    }

    /// <summary>Full state of one existing type for the fingerprint: settings and every parameter, ordered.</summary>
    private static object StateForHash(TypeState state) => new
    {
        id = state.Id,
        settings = state.Settings(),
        parameters = state.Params.Select(p => new { key = p.Key, name = p.Value.Name, value = p.Value.Value }).ToList()
    };

    /// <summary>Normalizes a slug exactly like the administration route, with the invariant culture.</summary>
    internal static string NormalizeSlug(string slug) => slug.Trim().ToUpperInvariant().Replace(" ", "_", StringComparison.Ordinal);

    /// <summary>Finds one type by slug without regard to case; unknown or ambiguous refuses the batch.</summary>
    private static TypeState ResolveType(Plan plan, string? slug, int index)
    {
        if (string.IsNullOrWhiteSpace(slug))
            throw new LicenseTypeChangeException(400, "SLUG_REQUIRED", $"Operation {index}: a slug is required.");
        var matches = plan.Types.Where(t => string.Equals(t.Slug, slug.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0)
            throw new LicenseTypeChangeException(404, "LICENSE_TYPE_NOT_FOUND", $"Operation {index}: no type '{slug.Trim()}' on this product.");
        if (matches.Count > 1)
            throw new LicenseTypeChangeException(409, "LICENSE_TYPE_AMBIGUOUS", $"Operation {index}: several types match '{slug.Trim()}' without regard to case.");
        return matches[0];
    }

    /// <summary>Resolves an explicit, non-empty, deduplicated slug list.</summary>
    private static List<TypeState> ResolveTypes(Plan plan, List<string>? slugs, int index)
    {
        var list = (slugs ?? new List<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
        if (list.Count == 0)
            throw new LicenseTypeChangeException(400, "SLUGS_REQUIRED", $"Operation {index}: list the slugs explicitly; there is no 'all types'.");
        var resolved = new List<TypeState>();
        foreach (var slug in list)
        {
            var type = ResolveType(plan, slug, index);
            if (!resolved.Contains(type)) resolved.Add(type);
        }
        return resolved;
    }

    /// <summary>Validates a parameter key: trimmed, non-empty, and not a case variant of another key of the product.</summary>
    private static string ValidateKey(string? key, List<string> productKeys, int index)
    {
        var trimmed = key?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > 200)
            throw new LicenseTypeChangeException(400, "PARAM_KEY_INVALID", $"Operation {index}: a parameter key of 1 to 200 characters is required.");
        var variant = productKeys.FirstOrDefault(existing =>
            !string.Equals(existing, trimmed, StringComparison.Ordinal)
            && string.Equals(existing, trimmed, StringComparison.OrdinalIgnoreCase));
        if (variant != null)
            throw new LicenseTypeChangeException(409, "PARAM_KEY_CASE_VARIANT",
                $"Operation {index}: key '{trimmed}' differs from the existing key '{variant}' only by case. Use the exact key.");
        return trimmed;
    }

    /// <summary>Plans a type creation: never copies parameters from another type; an existing slug refuses the batch.</summary>
    private static LicenseTypeChangeOperationPreview PlanCreateType(
        Plan plan, LicenseTypeChangeOperation op, int index, List<string> productKeys, List<object> normalized)
    {
        if (string.IsNullOrWhiteSpace(op.Name) || string.IsNullOrWhiteSpace(op.Slug))
            throw new LicenseTypeChangeException(400, "TYPE_NAME_AND_SLUG_REQUIRED", $"Operation {index}: createType needs a name and a slug.");
        var slug = NormalizeSlug(op.Slug);
        if (plan.Types.Any(t => string.Equals(t.Slug, slug, StringComparison.OrdinalIgnoreCase)))
            throw new LicenseTypeChangeException(409, "LICENSE_TYPE_EXISTS", $"Operation {index}: a type '{slug}' already exists; use updateType.");

        var state = new TypeState
        {
            Id = Guid.NewGuid(),
            IsNew = true,
            Slug = slug,
            Name = op.Name.Trim(),
            Description = op.Description ?? string.Empty,
            DefaultDurationDays = op.DefaultDurationDays ?? 30,
            IsRecurring = op.IsRecurring ?? false,
            DefaultAllowedVersions = string.IsNullOrWhiteSpace(op.DefaultAllowedVersions) ? "*" : op.DefaultAllowedVersions.Trim(),
            DefaultMaxSeats = op.DefaultMaxSeats ?? 1,
            MaxActivationsPerDay = op.MaxActivationsPerDay ?? 0,
            AllowAnonymous = op.AllowAnonymous ?? false,
            IsFree = op.IsFree ?? false,
            EnforceSingleUsePerHardwareId = op.EnforceSingleUsePerHardwareId ?? false,
            DisableNewActivations = op.DisableNewActivations ?? false,
            AllowPublicTrial = op.AllowPublicTrial ?? false,
            TeamEligible = op.TeamEligible ?? false
        };
        ValidateNumbers(state, index);
        foreach (var param in op.Params ?? new List<LicenseTypeChangeParam>())
        {
            var key = ValidateKey(param.Key, productKeys, index);
            if (string.IsNullOrWhiteSpace(param.Name))
                throw new LicenseTypeChangeException(400, "PARAM_NAME_REQUIRED", $"Operation {index}: parameter '{key}' needs a name.");
            if (state.Params.ContainsKey(key))
                throw new LicenseTypeChangeException(400, "PARAM_KEY_DUPLICATE", $"Operation {index}: parameter '{key}' is listed twice.");
            state.Params[key] = (param.Name.Trim(), param.Value ?? string.Empty);
            if (!productKeys.Contains(key, StringComparer.Ordinal)) productKeys.Add(key);
        }
        plan.Types.Add(state);
        var after = new Dictionary<string, string?>(state.Settings(), StringComparer.Ordinal);
        foreach (var param in state.Params) after["param:" + param.Key] = param.Value.Value;
        normalized.Add(new { kind = "createType", after });
        return new LicenseTypeChangeOperationPreview(index, "createType", slug, null, after, 0, Array.Empty<string>());
    }

    /// <summary>Plans a settings change of one type; the slug is never renamed (contract of the site).</summary>
    private static LicenseTypeChangeOperationPreview PlanUpdateType(
        Plan plan, LicenseTypeChangeOperation op, int index, Dictionary<Guid, int> activeCounts, List<object> normalized)
    {
        var state = ResolveType(plan, op.Slug, index);
        var before = state.Settings();
        if (op.Name != null)
        {
            if (string.IsNullOrWhiteSpace(op.Name))
                throw new LicenseTypeChangeException(400, "TYPE_NAME_INVALID", $"Operation {index}: the name cannot be empty.");
            state.Name = op.Name.Trim();
        }
        if (op.Description != null) state.Description = op.Description;
        if (op.DefaultDurationDays.HasValue) state.DefaultDurationDays = op.DefaultDurationDays.Value;
        if (op.IsRecurring.HasValue) state.IsRecurring = op.IsRecurring.Value;
        if (op.DefaultAllowedVersions != null) state.DefaultAllowedVersions = op.DefaultAllowedVersions.Trim();
        if (op.DefaultMaxSeats.HasValue) state.DefaultMaxSeats = op.DefaultMaxSeats.Value;
        if (op.MaxActivationsPerDay.HasValue) state.MaxActivationsPerDay = op.MaxActivationsPerDay.Value;
        if (op.AllowAnonymous.HasValue) state.AllowAnonymous = op.AllowAnonymous.Value;
        if (op.IsFree.HasValue) state.IsFree = op.IsFree.Value;
        if (op.EnforceSingleUsePerHardwareId.HasValue) state.EnforceSingleUsePerHardwareId = op.EnforceSingleUsePerHardwareId.Value;
        if (op.DisableNewActivations.HasValue) state.DisableNewActivations = op.DisableNewActivations.Value;
        if (op.AllowPublicTrial.HasValue) state.AllowPublicTrial = op.AllowPublicTrial.Value;
        if (op.TeamEligible.HasValue) state.TeamEligible = op.TeamEligible.Value;
        ValidateNumbers(state, index);

        var after = state.Settings();
        var changedBefore = new Dictionary<string, string?>(StringComparer.Ordinal);
        var changedAfter = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var pair in after)
        {
            if (string.Equals(before[pair.Key], pair.Value, StringComparison.Ordinal)) continue;
            changedBefore[pair.Key] = before[pair.Key];
            changedAfter[pair.Key] = pair.Value;
        }
        if (changedAfter.Count == 0)
            throw new LicenseTypeChangeException(400, "NOTHING_TO_CHANGE", $"Operation {index}: updateType changes nothing on '{state.Slug}'.");
        normalized.Add(new { kind = "updateType", target = state.Slug, after = changedAfter });
        return new LicenseTypeChangeOperationPreview(index, "updateType", state.Slug, changedBefore, changedAfter,
            activeCounts.GetValueOrDefault(state.Id), Array.Empty<string>());
    }

    /// <summary>Refuses negative counts, which the screen never stores.</summary>
    private static void ValidateNumbers(TypeState state, int index)
    {
        if (state.DefaultDurationDays < 0 || state.DefaultMaxSeats < 0 || state.MaxActivationsPerDay < 0)
            throw new LicenseTypeChangeException(400, "TYPE_NUMBER_INVALID", $"Operation {index}: durations and counts cannot be negative.");
    }

    /// <summary>Plans a parameter set on an explicit slug list; a new key needs its display name.</summary>
    private static IEnumerable<LicenseTypeChangeOperationPreview> PlanSetParam(
        Plan plan, LicenseTypeChangeOperation op, int index, Dictionary<Guid, int> activeCounts, List<string> productKeys, List<object> normalized)
    {
        var types = ResolveTypes(plan, op.Slugs, index);
        var key = ValidateKey(op.Key, productKeys, index);
        if (op.Value == null)
            throw new LicenseTypeChangeException(400, "PARAM_VALUE_REQUIRED", $"Operation {index}: setParam needs a value.");
        var previews = new List<LicenseTypeChangeOperationPreview>();
        foreach (var type in types)
        {
            var exists = type.Params.TryGetValue(key, out var current);
            if (!exists && string.IsNullOrWhiteSpace(op.ParamName))
                throw new LicenseTypeChangeException(400, "PARAM_NAME_REQUIRED", $"Operation {index}: key '{key}' is new on '{type.Slug}'; give its paramName.");
            var name = string.IsNullOrWhiteSpace(op.ParamName) ? current.Name : op.ParamName.Trim();
            type.Params[key] = (name, op.Value);
            previews.Add(new LicenseTypeChangeOperationPreview(index, "setParam", type.Slug,
                exists ? ParamView(key, current) : null, ParamView(key, (name, op.Value)),
                activeCounts.GetValueOrDefault(type.Id), Array.Empty<string>()));
        }
        if (!productKeys.Contains(key, StringComparer.Ordinal)) productKeys.Add(key);
        normalized.Add(new { kind = "setParam", targets = types.Select(t => t.Slug).ToList(), key, name = op.ParamName?.Trim(), value = op.Value });
        return previews;
    }

    /// <summary>Plans an explicit parameter removal; a type without the key refuses the batch.</summary>
    private static IEnumerable<LicenseTypeChangeOperationPreview> PlanRemoveParam(
        Plan plan, LicenseTypeChangeOperation op, int index, Dictionary<Guid, int> activeCounts, List<object> normalized)
    {
        var types = ResolveTypes(plan, op.Slugs, index);
        var key = op.Key?.Trim();
        if (string.IsNullOrEmpty(key))
            throw new LicenseTypeChangeException(400, "PARAM_KEY_INVALID", $"Operation {index}: removeParam needs a key.");
        var previews = new List<LicenseTypeChangeOperationPreview>();
        foreach (var type in types)
        {
            if (!type.Params.TryGetValue(key, out var current))
                throw new LicenseTypeChangeException(404, "PARAM_NOT_FOUND", $"Operation {index}: '{type.Slug}' has no parameter '{key}'.");
            type.Params.Remove(key);
            previews.Add(new LicenseTypeChangeOperationPreview(index, "removeParam", type.Slug, ParamView(key, current), null,
                activeCounts.GetValueOrDefault(type.Id), Array.Empty<string>()));
        }
        normalized.Add(new { kind = "removeParam", targets = types.Select(t => t.Slug).ToList(), key });
        return previews;
    }

    /// <summary>Shows one parameter as before/after values.</summary>
    private static Dictionary<string, string?> ParamView(string key, (string Name, string Value) param) => new(StringComparer.Ordinal)
    {
        ["key"] = key,
        ["name"] = param.Name,
        ["value"] = param.Value
    };

    /// <summary>
    /// Plans a plugin under the product, like the screen: a plugin of a root product gets a new RSA key pair (encrypted,
    /// backed up to the Drive); a plugin of a plugin copies its parent's pair; deeper levels are refused. Global keys
    /// only, because a product key could not reach the new product afterwards.
    /// </summary>
    private async Task<LicenseTypeChangeOperationPreview> PlanCreatePluginAsync(
        LicenseDbContext db, Plan plan, Product product, Guid? parentOfParent, bool keyIsGlobal, LicenseTypeChangeOperation op, int index,
        List<object> normalized, List<object> nameChecks, CancellationToken cancellationToken)
    {
        if (!keyIsGlobal)
            throw new LicenseTypeChangeException(403, "PLUGIN_REQUIRES_GLOBAL_KEY", $"Operation {index}: only a global analytics key can create a plugin.");
        var name = op.Name?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > 200)
            throw new LicenseTypeChangeException(400, "PLUGIN_NAME_INVALID", $"Operation {index}: a plugin name of 1 to 200 characters is required.");
        if (product.ParentProductId.HasValue && parentOfParent.HasValue)
            throw new LicenseTypeChangeException(400, "PLUGIN_DEPTH_EXCEEDED", $"Operation {index}: a plugin cannot be created under a level-3 plugin.");
        var lowered = name.ToLowerInvariant();
        var exists = await db.Products.AsNoTracking().AnyAsync(p => p.Name.ToLower() == lowered, cancellationToken)
            || plan.Plugins.Any(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
        if (exists)
            throw new LicenseTypeChangeException(409, "PRODUCT_NAME_EXISTS", $"Operation {index}: a product or plugin named '{name}' already exists.");

        var generates = !product.ParentProductId.HasValue;
        plan.Plugins.Add(new PluginPlan(name, generates));
        nameChecks.Add(new { name = lowered, exists = false });
        normalized.Add(new { kind = "createPlugin", name, level = generates ? 2 : 3 });
        var backupEnabled = generates && await _settings.GetBoolSettingAsync("BackupSettings:Enabled", false);
        var notes = generates
            ? new[] { "A new RSA-4096 key pair is generated and its private key stored encrypted.",
                backupEnabled ? "The key pair is backed up to the Drive before the commit." : "Drive backup is disabled: the private key exists only encrypted in the database." }
            : new[] { $"The plugin shares the key pair of '{product.Name}'." };
        return new LicenseTypeChangeOperationPreview(index, "createPlugin", name, null,
            new Dictionary<string, string?>(StringComparer.Ordinal) { ["name"] = name, ["parent"] = product.Name, ["level"] = generates ? "2" : "3" },
            0, notes);
    }

    // ── Writing ─────────────────────────────────────────────────────────────────────────────────────

    /// <summary>Writes the final working states to the tracked entities: new types, changed settings, parameter sets.</summary>
    private static void ApplyTypes(LicenseDbContext db, Plan plan)
    {
        foreach (var state in plan.Types)
        {
            var entity = state.Entity;
            if (state.IsNew)
            {
                entity = new LicenseType { Id = state.Id, ProductId = plan.ProductEntity!.Id };
                db.LicenseTypes.Add(entity);
            }
            entity!.Name = state.Name;
            entity.Slug = state.Slug;
            entity.Description = state.Description;
            entity.DefaultDurationDays = state.DefaultDurationDays;
            entity.IsRecurring = state.IsRecurring;
            entity.DefaultAllowedVersions = state.DefaultAllowedVersions;
            entity.DefaultMaxSeats = state.DefaultMaxSeats;
            entity.MaxActivationsPerDay = state.MaxActivationsPerDay;
            entity.AllowAnonymous = state.AllowAnonymous;
            entity.IsFree = state.IsFree;
            entity.EnforceSingleUsePerHardwareId = state.EnforceSingleUsePerHardwareId;
            entity.DisableNewActivations = state.DisableNewActivations;
            entity.AllowPublicTrial = state.AllowPublicTrial;
            entity.TeamEligible = state.TeamEligible;

            foreach (var param in entity.CustomParams.ToList())
            {
                if (!state.Params.ContainsKey(param.Key))
                    db.LicenseTypeCustomParams.Remove(param);
            }
            foreach (var pair in state.Params)
            {
                var existing = entity.CustomParams.FirstOrDefault(p => string.Equals(p.Key, pair.Key, StringComparison.Ordinal));
                if (existing == null)
                {
                    var created = new LicenseTypeCustomParam { LicenseTypeId = entity.Id, Key = pair.Key, Name = pair.Value.Name, Value = pair.Value.Value };
                    if (state.IsNew) entity.CustomParams.Add(created); else db.LicenseTypeCustomParams.Add(created);
                }
                else
                {
                    existing.Name = pair.Value.Name;
                    existing.Value = pair.Value.Value;
                }
            }
        }
    }

    /// <summary>
    /// Adds one plugin product. Level 2: new pair, private key encrypted (the clear key is returned only for the Drive
    /// backup and never leaves the service). Level 3: copy of the parent's stored pair. A new API secret is generated by
    /// the entity default and is never returned.
    /// </summary>
    private (Product Product, string? PrivateKey) CreatePlugin(LicenseDbContext db, Product parent, PluginPlan plugin)
    {
        Product product;
        string? privateKey = null;
        if (plugin.GeneratesKeyPair)
        {
            var keys = SoftLicence.SDK.LicenseService.GenerateKeys();
            privateKey = keys.PrivateKey;
            product = new Product { Name = plugin.Name, PrivateKeyXml = _encryption.Encrypt(keys.PrivateKey), PublicKeyXml = keys.PublicKey, ParentProductId = parent.Id };
        }
        else
        {
            product = new Product { Name = plugin.Name, PrivateKeyXml = parent.PrivateKeyXml, PublicKeyXml = parent.PublicKeyXml, ParentProductId = parent.Id };
        }
        db.Products.Add(product);
        return (product, privateKey);
    }

    /// <summary>Cuts a text to a column length.</summary>
    private static string? Truncate(string? value, int length) =>
        value == null ? null : value.Length <= length ? value : value[..length];
}

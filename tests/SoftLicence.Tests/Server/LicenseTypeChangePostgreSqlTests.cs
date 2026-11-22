using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.LicenseTypeChanges;
using Xunit;
using TestDbFactory = SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTestBase.TestDbFactory;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002781: licence-type writes through the analytics route, on a real PostgreSQL clone. On 27/10/2026 one
/// screen checkbox set a parameter on 46 types without anyone seeing it; these tests pin that every write is
/// previewed, applied only with an unchanged fingerprint, atomic, journaled, limited to the listed slugs, never copies
/// parameters, and never exposes key material.
/// </summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed class LicenseTypeChangePostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    private static readonly Guid KeyId = Guid.NewGuid();

    /// <summary>
    /// Seeds TEACHER with two active licences out of three, previews a parameter on two listed slugs plus a duration
    /// change, proves the preview wrote nothing, then applies with its hash: only the listed slugs change (PLAIN stays
    /// untouched) and exactly one journal row records the key, reference and hash.
    /// </summary>
    [Fact]
    public async Task Preview_WritesNothing_ThenApplyWithTheHashWritesEverythingAndOneJournalRow()
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var (productId, _) = await SeedProductAsync(factory, "Product A");
        var service = CreateService(factory);
        var request = Batch(
            new LicenseTypeChangeOperation { Kind = "setParam", Slugs = new() { "TEACHER", "student" }, Key = "hasRole", ParamName = "Rôle", Value = "true" },
            new LicenseTypeChangeOperation { Kind = "updateType", Slug = "teacher", DefaultDurationDays = 7 });

        var preview = await service.PreviewAsync(productId, true, request);
        Assert.Equal(3, preview.Operations.Count);
        Assert.Equal(2, preview.Operations.Single(op => op.Kind == "setParam" && op.Target == "TEACHER").ActiveLicenses);
        Assert.Equal("30", preview.Operations.Single(op => op.Kind == "updateType").Before!["defaultDurationDays"]);
        await using (var check = await factory.CreateDbContextAsync())
        {
            Assert.False(await check.LicenseTypeCustomParams.AnyAsync(p => p.Key == "hasRole"), "A preview must write nothing.");
            Assert.Equal(0, await check.LicenseTypeChangeAudits.CountAsync());
        }

        request.PreviewHash = preview.PreviewHash;
        request.RequestedBy = "TKT-002781 test";
        var result = await service.ApplyAsync(productId, true, KeyId, "192.0.2.2", request);

        await using var verify = await factory.CreateDbContextAsync();
        Assert.Equal(2, await verify.LicenseTypeCustomParams.CountAsync(p => p.Key == "hasRole" && p.Value == "true"));
        Assert.Equal(7, (await verify.LicenseTypes.SingleAsync(t => t.ProductId == productId && t.Slug == "TEACHER")).DefaultDurationDays);
        Assert.False(await verify.LicenseTypeCustomParams.AnyAsync(p => p.LicenseType!.Slug == "PLAIN" && p.Key == "hasRole"),
            "Only the listed slugs change; there is no 'all types'.");
        var audit = await verify.LicenseTypeChangeAudits.SingleAsync();
        Assert.Equal(result.AuditId, audit.Id);
        Assert.Equal(KeyId, audit.AnalyticsKeyId);
        Assert.Equal("TKT-002781 test", audit.RequestedBy);
        Assert.Equal(preview.PreviewHash, audit.PreviewHash);
        Assert.Contains("hasRole", audit.ChangesJson, StringComparison.Ordinal);
    }

    /// <summary>
    /// An apply without hash is a 400; a parameter changed by another context between preview and apply makes the
    /// fingerprint stale, so the apply is a 409 PREVIEW_STALE that keeps the concurrent value and writes no journal
    /// row.
    /// </summary>
    [Fact]
    public async Task Apply_AfterTheCatalogueChangedOrWithoutHash_IsRefusedAndWritesNothing()
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var (productId, _) = await SeedProductAsync(factory, "Product A");
        var service = CreateService(factory);
        var request = Batch(new LicenseTypeChangeOperation { Kind = "setParam", Slugs = new() { "TEACHER" }, Key = "existing", Value = "new" });
        var preview = await service.PreviewAsync(productId, true, request);

        var missing = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.ApplyAsync(productId, true, KeyId, null, request));
        Assert.Equal("PREVIEW_HASH_REQUIRED", missing.Code);

        await using (var concurrent = await factory.CreateDbContextAsync())
        {
            var param = await concurrent.LicenseTypeCustomParams.SingleAsync(p => p.Key == "existing" && p.LicenseType!.Slug == "TEACHER");
            param.Value = "changed elsewhere";
            await concurrent.SaveChangesAsync();
        }
        request.PreviewHash = preview.PreviewHash;
        var stale = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.ApplyAsync(productId, true, KeyId, null, request));
        Assert.Equal(409, stale.Status);
        Assert.Equal("PREVIEW_STALE", stale.Code);

        await using var verify = await factory.CreateDbContextAsync();
        Assert.Equal("changed elsewhere", (await verify.LicenseTypeCustomParams.SingleAsync(p => p.Key == "existing" && p.LicenseType!.Slug == "TEACHER")).Value);
        Assert.Equal(0, await verify.LicenseTypeChangeAudits.CountAsync());
    }

    /// <summary>
    /// Two applies of one previewed batch race on separate contexts. Under SERIALIZABLE exactly one commits; the other
    /// either sees the new type in its fingerprint (PREVIEW_STALE) or loses on serialization or the unique slug index
    /// (CONCURRENT_CHANGE). Both are 409 with nothing written, never a 500 and never two types or two journal rows.
    /// </summary>
    [Fact]
    public async Task TwoConcurrentAppliesOfTheSameBatch_WriteOnceAndRefuseTheOtherWith409()
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var (productId, _) = await SeedProductAsync(factory, "Product A");
        var service = CreateService(factory);
        var request = Batch(new LicenseTypeChangeOperation { Kind = "createType", Slug = "new type", Name = "New" });
        request.PreviewHash = (await service.PreviewAsync(productId, true, request)).PreviewHash;

        var outcomes = await Task.WhenAll(Enumerable.Range(0, 2).Select(async _ =>
        {
            try
            {
                await service.ApplyAsync(productId, true, KeyId, null, request);
                return "applied";
            }
            catch (LicenseTypeChangeException ex) when (ex.Status == 409)
            {
                return ex.Code;
            }
        }));

        Assert.Single(outcomes, outcome => outcome == "applied");
        await using var verify = await factory.CreateDbContextAsync();
        Assert.Equal(1, await verify.LicenseTypes.CountAsync(t => t.ProductId == productId && t.Slug == "NEW_TYPE"));
        Assert.Equal(1, await verify.LicenseTypeChangeAudits.CountAsync());
    }

    /// <summary>
    /// The 27/10 incident came from a creation that copied parameters of other types: a created type carries only its
    /// own listed parameters, its slug is normalized like the administration route ("  plugin mcp " becomes
    /// PLUGIN_MCP), and an existing slug is refused instead of being silently updated.
    /// </summary>
    [Fact]
    public async Task CreateType_NeverCopiesParameters_AndRefusesAnExistingSlug()
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var (productId, _) = await SeedProductAsync(factory, "Product A");
        var service = CreateService(factory);

        var request = Batch(new LicenseTypeChangeOperation
        {
            Kind = "createType", Slug = "  plugin mcp ", Name = "Plugin MCP", DefaultDurationDays = 0,
            Params = new() { new LicenseTypeChangeParam { Key = "allowedFeatures", Name = "Features", Value = "mcp" } }
        });
        request.PreviewHash = (await service.PreviewAsync(productId, true, request)).PreviewHash;
        await service.ApplyAsync(productId, true, KeyId, null, request);

        await using (var verify = await factory.CreateDbContextAsync())
        {
            var created = await verify.LicenseTypes.Include(t => t.CustomParams).SingleAsync(t => t.ProductId == productId && t.Slug == "PLUGIN_MCP");
            Assert.Equal(new[] { "allowedFeatures" }, created.CustomParams.Select(p => p.Key).ToArray());
        }

        var duplicate = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(productId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "createType", Slug = "teacher", Name = "Again" })));
        Assert.Equal("LICENSE_TYPE_EXISTS", duplicate.Code);
    }

    /// <summary>
    /// The seed adds a "Teacher" type beside "TEACHER" to make slug targeting ambiguous. Each invalid batch (unknown
    /// slug, ambiguous slug, key differing only by case, removal of an absent key, new key without display name) is
    /// refused as a whole at preview time.
    /// </summary>
    [Fact]
    public async Task UnknownAmbiguousOrCaseVariantTargets_RefuseTheWholeBatch()
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var (productId, _) = await SeedProductAsync(factory, "Product A", extraSlug: "Teacher");
        var service = CreateService(factory);

        var unknown = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(productId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "setParam", Slugs = new() { "STUDENT", "MISSING" }, Key = "existing", Value = "x" })));
        Assert.Equal("LICENSE_TYPE_NOT_FOUND", unknown.Code);

        var ambiguous = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(productId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "updateType", Slug = "teacher", IsFree = true })));
        Assert.Equal("LICENSE_TYPE_AMBIGUOUS", ambiguous.Code);

        var variant = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(productId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "setParam", Slugs = new() { "STUDENT" }, Key = "Existing", ParamName = "E", Value = "x" })));
        Assert.Equal("PARAM_KEY_CASE_VARIANT", variant.Code);

        var absent = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(productId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "removeParam", Slugs = new() { "PLAIN" }, Key = "existing" })));
        Assert.Equal("PARAM_NOT_FOUND", absent.Code);

        var noName = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(productId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "setParam", Slugs = new() { "PLAIN" }, Key = "brandNew", Value = "x" })));
        Assert.Equal("PARAM_NAME_REQUIRED", noName.Code);
    }

    /// <summary>
    /// Uses one data-protection provider for the service and the check so the stored private key can be decrypted. A
    /// product key cannot create a plugin; under a root product the plugin gets a new encrypted pair, under that plugin
    /// a sub-plugin copies it, a fourth level and a case-variant name are refused, and neither the result nor the
    /// journal contains key material or the API secret.
    /// </summary>
    [Fact]
    public async Task CreatePlugin_GeneratesAnEncryptedPairUnderARoot_CopiesUnderAPlugin_AndNeverExposesKeyMaterial()
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var (rootId, _) = await SeedProductAsync(factory, "Root product");
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(factory, protector);

        var productKey = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(rootId, false,
            Batch(new LicenseTypeChangeOperation { Kind = "createPlugin", Name = "Plugin one" })));
        Assert.Equal("PLUGIN_REQUIRES_GLOBAL_KEY", productKey.Code);

        var level2 = Batch(new LicenseTypeChangeOperation { Kind = "createPlugin", Name = "Plugin one" });
        level2.PreviewHash = (await service.PreviewAsync(rootId, true, level2)).PreviewHash;
        var result2 = await service.ApplyAsync(rootId, true, KeyId, null, level2);
        var pluginId = Assert.Single(result2.CreatedPluginIds);

        var level3 = Batch(new LicenseTypeChangeOperation { Kind = "createPlugin", Name = "Sub plugin" });
        level3.PreviewHash = (await service.PreviewAsync(pluginId, true, level3)).PreviewHash;
        var subId = Assert.Single((await service.ApplyAsync(pluginId, true, KeyId, null, level3)).CreatedPluginIds);

        var level4 = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(subId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "createPlugin", Name = "Too deep" })));
        Assert.Equal("PLUGIN_DEPTH_EXCEEDED", level4.Code);

        var duplicate = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.PreviewAsync(rootId, true,
            Batch(new LicenseTypeChangeOperation { Kind = "createPlugin", Name = "PLUGIN ONE" })));
        Assert.Equal("PRODUCT_NAME_EXISTS", duplicate.Code);

        await using var verify = await factory.CreateDbContextAsync();
        var plugin = await verify.Products.SingleAsync(p => p.Id == pluginId);
        var sub = await verify.Products.SingleAsync(p => p.Id == subId);
        Assert.Equal(rootId, plugin.ParentProductId);
        Assert.StartsWith("<RSAKeyValue>", new EncryptionService(protector).Decrypt(plugin.PrivateKeyXml), StringComparison.Ordinal);
        Assert.DoesNotContain("<RSAKeyValue>", plugin.PrivateKeyXml, StringComparison.Ordinal);
        Assert.Equal(plugin.PrivateKeyXml, sub.PrivateKeyXml);
        Assert.Equal(plugin.PublicKeyXml, sub.PublicKeyXml);

        var serialized = System.Text.Json.JsonSerializer.Serialize(result2)
            + string.Join("", await verify.LicenseTypeChangeAudits.Select(a => a.ChangesJson).ToListAsync());
        Assert.DoesNotContain("RSAKeyValue", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(plugin.ApiSecret, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(plugin.PrivateKeyXml, serialized, StringComparison.Ordinal);
    }

    /// <summary>
    /// Backup enabled without a configured remote makes the Drive upload throw, standing for a Drive outage. The batch
    /// also changes a type, to prove the refusal is all or nothing: no plugin, no type change, no journal row.
    /// </summary>
    [Fact]
    public async Task CreatePlugin_WhenTheKeyBackupFails_WritesNothing()
    {
        await using var connections = await ProvisionCleanedIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var (rootId, _) = await SeedProductAsync(factory, "Root product");
        // Backup enabled without a remote: the upload refuses, like a Drive outage.
        var service = CreateService(factory, configuration: new Dictionary<string, string?> { ["BackupSettings:Enabled"] = "true" });
        var request = Batch(
            new LicenseTypeChangeOperation { Kind = "createPlugin", Name = "Plugin backup" },
            new LicenseTypeChangeOperation { Kind = "updateType", Slug = "TEACHER", IsFree = true });
        request.PreviewHash = (await service.PreviewAsync(rootId, true, request)).PreviewHash;

        var refused = await Assert.ThrowsAsync<LicenseTypeChangeException>(() => service.ApplyAsync(rootId, true, KeyId, null, request));
        Assert.Equal("PLUGIN_KEY_BACKUP_FAILED", refused.Code);

        await using var verify = await factory.CreateDbContextAsync();
        Assert.False(await verify.Products.AnyAsync(p => p.Name == "Plugin backup"));
        Assert.False((await verify.LicenseTypes.SingleAsync(t => t.ProductId == rootId && t.Slug == "TEACHER")).IsFree,
            "The batch is all or nothing.");
        Assert.Equal(0, await verify.LicenseTypeChangeAudits.CountAsync());
    }

    /// <summary>Builds a batch from operations.</summary>
    private static LicenseTypeChangeRequest Batch(params LicenseTypeChangeOperation[] operations) =>
        new() { Operations = operations.ToList() };

    /// <summary>Creates the service with real encryption, settings and backup services.</summary>
    private static LicenseTypeChangeService CreateService(
        TestDbFactory factory, IDataProtectionProvider? protector = null, Dictionary<string, string?>? configuration = null)
    {
        var values = new Dictionary<string, string?> { ["IsIntegrationTest"] = "true" };
        foreach (var pair in configuration ?? new Dictionary<string, string?>()) values[pair.Key] = pair.Value;
        var config = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var settings = new SettingsService(factory, config, NullLogger<SettingsService>.Instance);
        return new LicenseTypeChangeService(
            factory,
            new EncryptionService(protector ?? new EphemeralDataProtectionProvider()),
            new BackupService(config, NullLogger<BackupService>.Instance, settings),
            settings,
            NullLogger<LicenseTypeChangeService>.Instance);
    }

    /// <summary>
    /// Seeds one root product with TEACHER (two active licences, one inactive), STUDENT and PLAIN types; TEACHER and
    /// STUDENT carry the parameter <c>existing</c>. <paramref name="extraSlug"/> adds a type whose slug differs by case.
    /// </summary>
    private static async Task<(Guid ProductId, Guid TeacherId)> SeedProductAsync(TestDbFactory factory, string name, string? extraSlug = null)
    {
        await using var db = await factory.CreateDbContextAsync();
        var product = new Product { Name = name + " " + Guid.NewGuid().ToString("N"), PrivateKeyXml = "encrypted", PublicKeyXml = "public" };
        db.Products.Add(product);
        var teacher = new LicenseType { ProductId = product.Id, Name = "Teacher", Slug = "TEACHER" };
        teacher.CustomParams.Add(new LicenseTypeCustomParam { Key = "existing", Name = "Existing", Value = "old" });
        var student = new LicenseType { ProductId = product.Id, Name = "Student", Slug = "STUDENT" };
        student.CustomParams.Add(new LicenseTypeCustomParam { Key = "existing", Name = "Existing", Value = "old" });
        db.LicenseTypes.AddRange(teacher, student, new LicenseType { ProductId = product.Id, Name = "Plain", Slug = "PLAIN" });
        if (extraSlug != null)
            db.LicenseTypes.Add(new LicenseType { ProductId = product.Id, Name = "Variant", Slug = extraSlug });
        for (var index = 0; index < 3; index++)
        {
            db.Licenses.Add(new License
            {
                ProductId = product.Id,
                LicenseTypeId = teacher.Id,
                LicenseKey = "TEST-" + Guid.NewGuid().ToString("N"),
                IsActive = index < 2
            });
        }
        await db.SaveChangesAsync();
        return (product.Id, teacher.Id);
    }
}

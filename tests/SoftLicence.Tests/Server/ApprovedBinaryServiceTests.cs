using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class ApprovedBinaryServiceTests : IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private DbContextOptions<LicenseDbContext> _options = null!;
    private Guid _productId;

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        _options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseSqlite(_connection)
            .Options;

        await using var db = new LicenseDbContext(_options);
        await db.Database.EnsureCreatedAsync();
        _productId = Guid.NewGuid();
        db.Products.Add(new Product
        {
            Id = _productId,
            Name = "TIAConnect",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = "product-secret"
        });
        await db.SaveChangesAsync();
    }

    public async Task DisposeAsync() => await _connection.DisposeAsync();

    [Fact]
    public async Task RegisterReleaseBaseline_ValidCompleteSet_IsAtomicAndIdempotent()
    {
        var service = CreateService();
        var artifacts = ValidArtifacts();

        var first = await service.RegisterReleaseBaselineAsync(
            _productId,
            "2.2.844",
            "release-2.2.844-test",
            Hash('d'),
            artifacts);
        var retry = await service.RegisterReleaseBaselineAsync(
            _productId,
            "2.2.844",
            "release-2.2.844-test",
            Hash('d'),
            artifacts);

        Assert.True(first.ProductExists);
        Assert.Equal(ApprovedBinaryVerdict.Approved, first.Result.Verdict);
        Assert.False(first.Result.Idempotent);
        Assert.Equal(ApprovedBinaryVerdict.Approved, retry.Result.Verdict);
        Assert.True(retry.Result.Idempotent);

        await using var db = new LicenseDbContext(_options);
        var rows = await db.ApprovedBinaries.OrderBy(row => row.Key).ToListAsync();
        Assert.Equal(3, rows.Count);
        Assert.All(rows, row => Assert.Equal(ApprovedBinaryService.ReleaseSource, row.Source));
        Assert.All(rows, row => Assert.Equal(row.Hash, row.Hash.ToLowerInvariant()));
    }

    [Fact]
    public async Task RegisterReleaseBaseline_WhenPayloadIsPartial_WritesNothing()
    {
        var service = CreateService();

        var result = await service.RegisterReleaseBaselineAsync(
            _productId,
            "2.2.844",
            "release-2.2.844-partial",
            Hash('d'),
            [new ApprovedBinaryArtifact("FP_EXE", Hash('a'))]);

        Assert.Equal(ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted, result.Result.Verdict);
        Assert.Equal("required_key_missing", result.Result.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.ApprovedBinaries.ToListAsync());
    }

    [Fact]
    public async Task RegisterReleaseBaseline_WhenExistingHashDiffers_ReturnsConflictWithoutMutation()
    {
        var service = CreateService();
        var original = ValidArtifacts();
        await service.RegisterReleaseBaselineAsync(
            _productId,
            "2.2.844",
            "release-original",
            Hash('d'),
            original);
        var altered = original
            .Select(artifact => artifact.Key == "FP_EXE"
                ? artifact with { Sha256 = Hash('f') }
                : artifact)
            .ToList();

        var result = await service.RegisterReleaseBaselineAsync(
            _productId,
            "2.2.844",
            "release-altered",
            Hash('d'),
            altered);

        Assert.Equal(ApprovedBinaryVerdict.BaselineMissing, result.Result.Verdict);
        Assert.Equal("baseline_registration_conflict", result.Result.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Equal(Hash('a'), (await db.ApprovedBinaries.SingleAsync(row => row.Key == "FP_EXE")).Hash);
    }

    [Fact]
    public async Task EvaluateTelemetryEvidence_LegacyAutoBaseline_IsNeverAuthoritativeOrPromoted()
    {
        await using (var db = new LicenseDbContext(_options))
        {
            foreach (var artifact in ValidArtifacts())
            {
                db.ApprovedBinaries.Add(new ApprovedBinary
                {
                    ProductId = _productId,
                    Version = "2.2.798",
                    Key = artifact.Key,
                    Hash = artifact.Sha256,
                    Source = "auto"
                });
            }
            await db.SaveChangesAsync();
        }

        var service = CreateService();
        var evidence = ValidArtifacts().ToDictionary(a => a.Key, a => a.Sha256, StringComparer.Ordinal);
        var first = await service.EvaluateTelemetryEvidenceAsync(_productId, "2.2.798", evidence);
        var replay = await service.EvaluateTelemetryEvidenceAsync(_productId, "2.2.798", evidence);

        Assert.Equal(ApprovedBinaryVerdict.BaselineMissing, first.Verdict);
        Assert.Equal(ApprovedBinaryVerdict.BaselineMissing, replay.Verdict);
        await using var checkDb = new LicenseDbContext(_options);
        var rows = await checkDb.ApprovedBinaries.ToListAsync();
        Assert.Equal(3, rows.Count);
        Assert.All(rows, row => Assert.Equal("auto", row.Source));
    }

    [Fact]
    public async Task EvaluateTelemetryEvidence_OfficialBaseline_DistinguishesApprovedMismatchAndInvalid()
    {
        var service = CreateService();
        var artifacts = ValidArtifacts();
        await service.RegisterReleaseBaselineAsync(
            _productId,
            "2.2.844",
            "release-verdicts",
            Hash('d'),
            artifacts);
        var valid = artifacts.ToDictionary(a => a.Key, a => a.Sha256, StringComparer.Ordinal);
        var altered = new Dictionary<string, string>(valid, StringComparer.Ordinal)
        {
            ["FP_DLL"] = Hash('f')
        };
        var malformed = new Dictionary<string, string>(valid, StringComparer.Ordinal)
        {
            ["FP_CORE"] = "not-a-sha256"
        };

        var approved = await service.EvaluateTelemetryEvidenceAsync(_productId, "2.2.844", valid);
        var mismatch = await service.EvaluateTelemetryEvidenceAsync(_productId, "2.2.844", altered);
        var invalid = await service.EvaluateTelemetryEvidenceAsync(_productId, "2.2.844", malformed);

        Assert.Equal(ApprovedBinaryVerdict.Approved, approved.Verdict);
        Assert.Equal(ApprovedBinaryVerdict.Mismatch, mismatch.Verdict);
        Assert.Equal(Hash('f'), mismatch.Mismatches["FP_DLL"]);
        Assert.Equal(ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted, invalid.Verdict);
        Assert.Equal("invalid_hash", invalid.ErrorCode);
    }

    [Fact]
    public async Task EvaluateTelemetryEvidence_WhenAuthoritativeBaselineIsPartialAndDivergent_ReturnsBaselineMissingBeforeMismatch()
    {
        await using (var db = new LicenseDbContext(_options))
        {
            db.ApprovedBinaries.Add(new ApprovedBinary
            {
                ProductId = _productId,
                Version = "2.2.845",
                Key = "FP_EXE",
                Hash = Hash('a'),
                Source = ApprovedBinaryService.AdminSource
            });
            await db.SaveChangesAsync();
        }

        var result = await CreateService().EvaluateTelemetryEvidenceAsync(
            _productId,
            "2.2.845",
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["FP_EXE"] = Hash('f'),
                ["FP_DLL"] = Hash('b'),
                ["FP_CORE"] = Hash('c')
            });

        Assert.Equal(ApprovedBinaryVerdict.BaselineMissing, result.Verdict);
        Assert.Equal("baseline_missing", result.ErrorCode);
        Assert.Empty(result.Mismatches);
    }

    [Fact]
    public async Task AdoptLegacy2362_ExactRows_IsAtomicAndExactReplayIsIdempotent()
    {
        var productId = ApprovedBinaryService.TiaConnectLegacyAdoptionProductId;
        await using (var db = new LicenseDbContext(_options))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "T-IA Connect",
                PrivateKeyXml = "private",
                PublicKeyXml = "public",
                ApiSecret = "product-secret"
            });
            db.ApprovedBinaries.AddRange(ValidArtifacts().Select(artifact => new ApprovedBinary
            {
                ProductId = productId,
                Version = ApprovedBinaryService.TiaConnectLegacyAdoptionVersion,
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = ApprovedBinaryService.ReleaseSource,
                ApprovedBy = "historical-release"
            }));
            await db.SaveChangesAsync();
        }

        var service = CreateService();
        var first = await service.AdoptTiaConnect2362LegacyBaselineAsync(
            productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), ValidArtifacts());
        var replay = await service.AdoptTiaConnect2362LegacyBaselineAsync(
            productId, "2.3.62", "legacy-tia-2.3.62", Hash('d'), ValidArtifacts());

        Assert.Equal(ApprovedBinaryVerdict.Approved, first.Result.Verdict);
        Assert.False(first.Result.Idempotent);
        Assert.True(replay.Result.Idempotent);
        Assert.Equal(first.Result.BaselineId, replay.Result.BaselineId);
        await using var verification = new LicenseDbContext(_options);
        Assert.Single(await verification.ApprovedBinaryRegistrations.ToListAsync());
        Assert.All(await verification.ApprovedBinaries.Where(row => row.ProductId == productId).ToListAsync(),
            row => Assert.Equal(first.Result.BaselineId, row.ApprovedBinaryRegistrationId));
    }

    [Theory]
    [InlineData("wrong-product")]
    [InlineData("wrong-version")]
    [InlineData("padded-version")]
    [InlineData("uppercase-hash")]
    public async Task AdoptLegacy2362_DivergentBoundary_WritesNothing(string variant)
    {
        var productId = ApprovedBinaryService.TiaConnectLegacyAdoptionProductId;
        await using (var db = new LicenseDbContext(_options))
        {
            db.Products.Add(new Product
            {
                Id = productId,
                Name = "T-IA Connect",
                PrivateKeyXml = "private",
                PublicKeyXml = "public",
                ApiSecret = "product-secret"
            });
            db.ApprovedBinaries.AddRange(ValidArtifacts().Select(artifact => new ApprovedBinary
            {
                ProductId = productId,
                Version = "2.3.62",
                Key = artifact.Key,
                Hash = artifact.Sha256,
                Source = ApprovedBinaryService.ReleaseSource
            }));
            await db.SaveChangesAsync();
        }

        var requestProduct = variant == "wrong-product" ? Guid.NewGuid() : productId;
        var requestVersion = variant switch
        {
            "wrong-version" => "2.3.63",
            "padded-version" => " 2.3.62 ",
            _ => "2.3.62"
        };
        var artifacts = ValidArtifacts();
        if (variant == "uppercase-hash")
            artifacts[0] = artifacts[0] with { Sha256 = Hash('A') };

        var result = await CreateService().AdoptTiaConnect2362LegacyBaselineAsync(
            requestProduct, requestVersion, "legacy-tia-2.3.62", Hash('d'), artifacts);

        Assert.NotEqual(ApprovedBinaryVerdict.Approved, result.Result.Verdict);
        await using var verification = new LicenseDbContext(_options);
        Assert.Empty(await verification.ApprovedBinaryRegistrations.ToListAsync());
        Assert.All(await verification.ApprovedBinaries.Where(row => row.ProductId == productId).ToListAsync(),
            row => Assert.Null(row.ApprovedBinaryRegistrationId));
    }

    [Theory]
    [InlineData("not-hex")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void NormalizeSha256_InvalidValues_AreRejected(string value)
    {
        Assert.Null(ApprovedBinaryService.NormalizeSha256(value));
    }

    [Theory]
    [InlineData("uppercase")]
    [InlineData("leading-space")]
    [InlineData("trailing-space")]
    public async Task RegisterReleaseBaseline_NonCanonicalManifestDigest_IsRejected(string variant)
    {
        var digest = variant switch
        {
            "uppercase" => Hash('A'),
            "leading-space" => $" {Hash('a')}",
            _ => $"{Hash('a')} "
        };

        var result = await CreateService().RegisterReleaseBaselineAsync(
            _productId,
            "2.2.846",
            $"manifest-{variant}",
            digest,
            ValidArtifacts());

        Assert.Equal(ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted, result.Result.Verdict);
        Assert.Equal("invalid_manifest_digest", result.Result.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.ApprovedBinaryRegistrations.ToListAsync());
        Assert.Empty(await db.ApprovedBinaries.Where(row => row.Version == "2.2.846").ToListAsync());
    }

    private ApprovedBinaryService CreateService() => new(
        new TestDbContextFactory(_options),
        Mock.Of<ILogger<ApprovedBinaryService>>());

    private static List<ApprovedBinaryArtifact> ValidArtifacts() =>
    [
        new("FP_EXE", Hash('a')),
        new("FP_DLL", Hash('b')),
        new("FP_CORE", Hash('c'))
    ];

    private static string Hash(char value) => new(value, 64);

    private sealed class TestDbContextFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options;

        public TestDbContextFactory(DbContextOptions<LicenseDbContext> options) => _options = options;

        public LicenseDbContext CreateDbContext() => new(_options);

        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

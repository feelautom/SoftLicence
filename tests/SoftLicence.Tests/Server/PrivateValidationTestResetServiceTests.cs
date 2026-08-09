using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class PrivateValidationTestResetServiceTests
{
    [Fact]
    public async Task Validate_WithExactActivePair_ReturnsMutationReadySnapshot()
    {
        var fixture = await Fixture.CreateAsync();

        var result = await fixture.Service.ValidateAsync(fixture.Request);

        Assert.False(result.AlreadyApplied);
        Assert.False(result.Executed);
        Assert.Equal("ACTIVE", result.EnrollmentState);
        Assert.Equal("active", result.BindingState);
    }

    [Fact]
    public async Task Validate_WithDifferentInstallationId_FailsClosed()
    {
        var fixture = await Fixture.CreateAsync();
        var request = fixture.Request with { InstallationId = Guid.NewGuid().ToString("D") };

        var exception = await Assert.ThrowsAsync<PrivateValidationTestResetException>(
            () => fixture.Service.ValidateAsync(request));

        Assert.Equal("identity_mismatch", exception.ErrorCode);
        Assert.Equal(409, exception.StatusCode);
    }

    [Fact]
    public async Task Validate_ExactReplayOfSameReset_IsIdempotent()
    {
        var fixture = await Fixture.CreateAsync(alreadyApplied: true);

        var result = await fixture.Service.ValidateAsync(fixture.Request);

        Assert.True(result.AlreadyApplied);
        Assert.Equal("test_identity_reset_tkt_999962", result.InvalidationReason);
    }

    [Fact]
    public async Task Validate_MixedActiveAndInvalidatedPair_IsConflict()
    {
        var fixture = await Fixture.CreateAsync(bindingOnlyInvalidated: true);

        var exception = await Assert.ThrowsAsync<PrivateValidationTestResetException>(
            () => fixture.Service.ValidateAsync(fixture.Request));

        Assert.Equal("identity_state_conflict", exception.ErrorCode);
    }

    [Fact]
    public async Task Validate_WhenLicenseIsNotExplicitlyAllowlisted_IsForbidden()
    {
        var fixture = await Fixture.CreateAsync(allowLicense: false);

        var exception = await Assert.ThrowsAsync<PrivateValidationTestResetException>(
            () => fixture.Service.ValidateAsync(fixture.Request));

        Assert.Equal("test_identity_forbidden", exception.ErrorCode);
        Assert.Equal(403, exception.StatusCode);
    }

    [Fact]
    public async Task Validate_WhenLiveLicenseAuthorityIsIneligible_FailsClosed()
    {
        var fixture = await Fixture.CreateAsync(licenseActive: false);

        var exception = await Assert.ThrowsAsync<PrivateValidationTestResetException>(
            () => fixture.Service.ValidateAsync(fixture.Request));

        Assert.Equal("authority_ineligible", exception.ErrorCode);
        Assert.Equal(409, exception.StatusCode);
    }

    private sealed record Fixture(
        PrivateValidationTestResetService Service,
        PrivateValidationTestResetRequest Request)
    {
        public static async Task<Fixture> CreateAsync(
            bool alreadyApplied = false,
            bool bindingOnlyInvalidated = false,
            bool allowLicense = true,
            bool licenseActive = true)
        {
            var options = new DbContextOptionsBuilder<LicenseDbContext>()
                .UseInMemoryDatabase($"private-validation-reset-{Guid.NewGuid():N}")
                .Options;
            var factory = new TestDbFactory(options);
            var productId = Guid.NewGuid();
            var licenseId = Guid.NewGuid();
            var seatId = Guid.NewGuid();
            var bindingId = Guid.NewGuid();
            var enrollmentId = Guid.NewGuid();
            var installationId = Guid.NewGuid().ToString("D");
            var reason = "test_identity_reset_tkt_999962";
            var invalidatedAt = DateTime.UtcNow;
            var hardwareId = "RUNNER-" + Guid.NewGuid().ToString("N").ToUpperInvariant();
            var hardwareIdHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(hardwareId)));
            const string clientId = "website-step1";

            await using (var db = await factory.CreateDbContextAsync())
            {
                var licenseTypeId = Guid.NewGuid();
                db.Products.Add(new Product
                {
                    Id = productId,
                    Name = "Private validation product",
                    PrivateKeyXml = string.Empty,
                    PublicKeyXml = string.Empty,
                    ApiSecret = Guid.NewGuid().ToString("N")
                });
                db.LicenseTypes.Add(new LicenseType
                {
                    Id = licenseTypeId,
                    ProductId = productId,
                    Name = "Private validation",
                    Slug = "private-validation-" + productId.ToString("N")
                });
                db.Licenses.Add(new License
                {
                    Id = licenseId,
                    ProductId = productId,
                    LicenseTypeId = licenseTypeId,
                    LicenseKey = "PRIVATE-" + Guid.NewGuid().ToString("N"),
                    IsActive = licenseActive,
                    MaxSeats = 1,
                    AllowedVersions = "2.2.*",
                    ExpirationDate = DateTime.UtcNow.AddDays(1)
                });
                db.LicenseSeats.Add(new LicenseSeat
                {
                    Id = seatId,
                    LicenseId = licenseId,
                    HardwareId = hardwareId,
                    IsActive = true
                });
                db.ApprovedBinaries.AddRange(
                    new ApprovedBinary { ProductId = productId, Version = "2.2.944", Key = "FP_EXE", Hash = new string('c', 64), Source = ApprovedBinaryService.ReleaseSource },
                    new ApprovedBinary { ProductId = productId, Version = "2.2.944", Key = "FP_DLL", Hash = new string('d', 64), Source = ApprovedBinaryService.ReleaseSource },
                    new ApprovedBinary { ProductId = productId, Version = "2.2.944", Key = "FP_CORE", Hash = new string('e', 64), Source = ApprovedBinaryService.ReleaseSource });
                db.DistributionInstallationBindings.Add(new DistributionInstallationBinding
                {
                    Id = bindingId,
                    ProductId = productId,
                    LicenseId = licenseId,
                    LicenseSeatId = seatId,
                    InstallationId = installationId,
                    HardwareIdHash = hardwareIdHash,
                    HandoffDigestSha256 = new string('b', 64),
                    Version = "2.2.944",
                    ExecutableSha256 = new string('c', 64),
                    NativeDllSha256 = new string('d', 64),
                    CoreSha256 = new string('e', 64),
                    State = alreadyApplied || bindingOnlyInvalidated ? "invalidated" : "active",
                    InvalidatedAtUtc = alreadyApplied || bindingOnlyInvalidated ? invalidatedAt : null,
                    InvalidationReason = alreadyApplied || bindingOnlyInvalidated ? reason : null
                });
                db.RuntimeEnrollments.Add(new RuntimeEnrollment
                {
                    Id = enrollmentId,
                    BindingId = bindingId,
                    ProductId = productId,
                    LicenseId = licenseId,
                    LicenseSeatId = seatId,
                    InstallationId = installationId,
                    HardwareIdHash = hardwareIdHash,
                    HandoffDigestSha256 = new string('b', 64),
                    ClientId = clientId,
                    ReleaseVersion = "2.2.944",
                    SecurityEpoch = 3,
                    AuthorityEpoch = 9,
                    State = alreadyApplied ? "INVALIDATED" : "ACTIVE",
                    InvalidatedAtUtc = alreadyApplied ? invalidatedAt : null,
                    InvalidationReason = alreadyApplied ? reason : null
                });
                db.DistributionBindingRequests.Add(new DistributionBindingRequest
                {
                    ClientId = clientId,
                    RequestId = Guid.NewGuid().ToString("D"),
                    Operation = "finalize_binding",
                    PayloadDigest = new string('f', 64),
                    BindingId = bindingId,
                    ResponseJson = "{}",
                    CreatedAtUtc = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
            }

            var request = new PrivateValidationTestResetRequest(
                productId,
                enrollmentId,
                bindingId,
                installationId,
                "2.2.944",
                3,
                "TKT-999962");
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PrivateValidationTestReset:AllowedLicenseIds"] = allowLicense
                    ? licenseId.ToString("D")
                    : Guid.NewGuid().ToString("D")
            }).Build();
            return new(new PrivateValidationTestResetService(
                factory, new UnusedAuthorityService(), TimeProvider.System, configuration), request);
        }
    }

    private sealed class UnusedAuthorityService : IRuntimeEnrollmentAuthorityService
    {
        public Task<RuntimeAuthorityLease> AcquireAsync(
            LicenseDbContext db,
            Guid bindingId,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("ExecuteAsync is not used by these in-memory validation tests.");

        public Task<RuntimeAuthorityLease> AcquireMutationAsync(
            LicenseDbContext db,
            Guid bindingId,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("ExecuteAsync is not used by these in-memory validation tests.");

        public Task ValidateInfrastructureAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class TestDbFactory : IDbContextFactory<LicenseDbContext>
    {
        private readonly DbContextOptions<LicenseDbContext> _options;

        public TestDbFactory(DbContextOptions<LicenseDbContext> options) => _options = options;

        public LicenseDbContext CreateDbContext() => new(_options);

        public Task<LicenseDbContext> CreateDbContextAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

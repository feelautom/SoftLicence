using System.Security.Cryptography;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class DistributionInstallationBindingServiceTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 7, 18, 18, 30, 0, TimeSpan.Zero);
    private static readonly Guid ProductId = Guid.Parse("12345678-1234-4234-9234-1234567890ab");
    private static readonly Guid LicenseId = Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static readonly Guid SeatId = Guid.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private const string ClientId = "tia-connect-website";
    private const string HardwareId = "TEST-HWID-ABCDEF012345";
    private const string DefaultGrantRef = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

    private readonly SqliteConnection _keepAlive;
    private readonly DbContextOptions<LicenseDbContext> _options;
    private readonly DistributionInstallationBindingService _service;

    public DistributionInstallationBindingServiceTests()
    {
        var connectionString = $"Data Source=binding-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        _keepAlive = new SqliteConnection(connectionString);
        _keepAlive.Open();
        _options = new DbContextOptionsBuilder<LicenseDbContext>().UseSqlite(connectionString).Options;
        using (var db = new LicenseDbContext(_options))
        {
            db.Database.EnsureCreated();
            Seed(db);
        }
        _service = new DistributionInstallationBindingService(
            new TestDbContextFactory(_options),
            new EphemeralDataProtectionProvider(),
            new FixedTimeProvider(Now));
    }

    [Fact]
    public async Task IssueEntitlement_ValidLicense_IsOpaquePseudonymousAndIdempotent()
    {
        var request = IssueRequest();
        var digest = Hash("exact-issue-body");

        var first = await _service.IssueEntitlementAsync(ClientId, digest, request);
        var retry = await _service.IssueEntitlementAsync(ClientId, digest, request);

        Assert.False(first.Idempotent);
        Assert.True(retry.Idempotent);
        Assert.Equal(first.Response, retry.Response);
        Assert.Equal("2026-07-18T20:30:00.0000000Z", first.Response.ExpiresAtUtc);
        Assert.DoesNotContain(LicenseId.ToString("D"), first.Response.EntitlementRef, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@", JsonSerializer.Serialize(first.Response));
    }

    [Fact]
    public async Task IssueEntitlementV3_CanonicalSubject_IsFrozenWithRealAuthorityAndIdempotent()
    {
        var request = IssueRequest(Hash(DefaultGrantRef), v2: false);
        request.Schema = DistributionInstallationBindingService.IssueV3Schema;
        request.SubjectRef = Convert.ToBase64String(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray())
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var digest = Hash("exact-v3-issue-body");

        var first = await _service.IssueEntitlementAsync(ClientId, digest, request);
        var replay = await _service.IssueEntitlementAsync(ClientId, digest, request);

        Assert.False(first.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(first.Response, replay.Response);
        await using var db = new LicenseDbContext(_options);
        var entitlement = await db.DistributionEntitlements.SingleAsync();
        Assert.Equal(ProductId, entitlement.ProductId);
        Assert.Equal(LicenseId, entitlement.LicenseId);
        Assert.Equal(Hash(DefaultGrantRef), entitlement.GrantRefDigestSha256);
        Assert.Equal(Hash(request.SubjectRef), entitlement.SubjectRefDigestSha256);
        Assert.Equal(3, entitlement.ContractVersion);
    }

    [Theory]
    [InlineData(42)]
    [InlineData(44)]
    public async Task IssueEntitlementV3_NonCanonicalSubject_FailsClosed(int length)
    {
        var request = IssueRequest(Hash(DefaultGrantRef), v2: false);
        request.Schema = DistributionInstallationBindingService.IssueV3Schema;
        request.SubjectRef = new string('a', length);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.IssueEntitlementAsync(ClientId, Hash("invalid-subject-" + length), request));

        Assert.Equal("invalid_request", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionEntitlements.ToListAsync());
    }

    [Fact]
    public async Task FinalizeV3_PropagatesFrozenSubjectAndHandoffWindowByteExactly()
    {
        var issue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        issue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        issue.SubjectRef = Convert.ToBase64String(SHA256.HashData("website-account"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("v3-propagation-issue"), issue)).Response.EntitlementRef;
        var finalize = FinalizeRequest(entitlement);

        await _service.FinalizeAsync(ClientId, Hash("v3-propagation-finalize"), finalize);

        await using var db = new LicenseDbContext(_options);
        var persisted = await db.DistributionEntitlements.SingleAsync();
        var binding = await db.DistributionInstallationBindings.SingleAsync();
        Assert.Equal(Hash(issue.SubjectRef), binding.SubjectRefDigestSha256);
        Assert.Equal(persisted.SubjectRefDigestSha256, binding.SubjectRefDigestSha256);
        Assert.Equal(DateTimeOffset.Parse(finalize.HandoffIssuedAtUtc!).UtcDateTime, binding.HandoffIssuedAtUtc);
        Assert.Equal(DateTimeOffset.Parse(finalize.HandoffExpiresAtUtc!).UtcDateTime, binding.HandoffExpiresAtUtc);
        Assert.Equal(DateTimeOffset.Parse(finalize.DownloadCompletedAtUtc!).UtcDateTime, binding.DownloadCompletedAtUtc);
        Assert.Equal("finalized", persisted.State);
    }

    [Theory]
    [InlineData("distribution-installation-finalize-v1", true)]
    [InlineData("distribution-installation-finalize-v2", null)]
    [InlineData("distribution-installation-finalize-v2", false)]
    public async Task Finalize_RecoverySchemaAndFlagMismatch_FailsClosed(string schema, bool? flag)
    {
        var request = FinalizeRequest("opaque-entitlement-token");
        request.Schema = schema;
        request.AllowSameAuthorityRecovery = flag;

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("schema-flag-mismatch-" + schema + flag), request));

        Assert.Equal("invalid_request", exception.ErrorCode);
    }

    [Fact]
    public async Task FinalizeV3_ReplacementProof_IsStrictAndCannotAuthorizeInitialInstallation()
    {
        var canonicalSubject = Convert.ToBase64String(SHA256.HashData("replacement-source"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var legacyWithNullReplacement = FinalizeRequest("opaque-entitlement-token");
        legacyWithNullReplacement.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
        legacyWithNullReplacement.AllowSameAuthorityRecovery = true;
        legacyWithNullReplacement.LicenseReplacement = null;
        var legacyExtension = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(
                ClientId, Hash("replacement-v2-explicit-null"), legacyWithNullReplacement));
        Assert.Equal("invalid_request", legacyExtension.ErrorCode);

        var request = FinalizeRequest("opaque-entitlement-token");
        request.Schema = DistributionInstallationBindingService.FinalizeV3Schema;
        request.AllowSameAuthorityRecovery = true;

        var missing = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("replacement-missing"), request));
        Assert.Equal("invalid_request", missing.ErrorCode);

        request.LicenseReplacement = new DistributionLicenseReplacementProof
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
            SourceBindingId = Guid.NewGuid().ToString("D"),
            SourceLicenseId = Guid.NewGuid().ToString("D"),
            SourceSubjectRef = canonicalSubject,
            ExtensionData = new Dictionary<string, JsonElement>
            {
                ["sourceLicenseSeatId"] = JsonDocument.Parse($"\"{Guid.NewGuid():D}\"").RootElement.Clone()
            }
        };
        var extension = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("replacement-extension"), request));
        Assert.Equal("invalid_request", extension.ErrorCode);

        request.LicenseReplacement.ExtensionData = null;
        request.LicenseReplacement.SourceSubjectRef = canonicalSubject + "=";
        var nonCanonical = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("replacement-noncanonical"), request));
        Assert.Equal("invalid_request", nonCanonical.ErrorCode);

        var issue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        issue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        issue.SubjectRef = canonicalSubject;
        var entitlement = await _service.IssueEntitlementAsync(
            ClientId, Hash("replacement-initial-issue"), issue);
        request = FinalizeRequest(entitlement.Response.EntitlementRef);
        request.Schema = DistributionInstallationBindingService.FinalizeV3Schema;
        request.AllowSameAuthorityRecovery = true;
        request.LicenseReplacement = new DistributionLicenseReplacementProof
        {
            Schema = DistributionInstallationBindingService.LicenseReplacementSchema,
            SourceBindingId = Guid.NewGuid().ToString("D"),
            SourceLicenseId = Guid.NewGuid().ToString("D"),
            SourceSubjectRef = canonicalSubject
        };

        var noSource = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("replacement-initial-finalize"), request));
        Assert.Equal("binding_conflict", noSource.ErrorCode);
    }

    [Theory]
    [InlineData("distribution-installation-finalize-v1", "absent", true)]
    [InlineData("distribution-installation-finalize-v1", "null", false)]
    [InlineData("distribution-installation-finalize-v1", "false", false)]
    [InlineData("distribution-installation-finalize-v1", "true", false)]
    [InlineData("distribution-installation-finalize-v2", "absent", false)]
    [InlineData("distribution-installation-finalize-v2", "null", false)]
    [InlineData("distribution-installation-finalize-v2", "false", false)]
    [InlineData("distribution-installation-finalize-v2", "true", true)]
    public async Task Finalize_JsonRecoveryMemberPresence_IsSchemaExact(
        string schema,
        string memberState,
        bool expectedValid)
    {
        var issue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        issue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        issue.SubjectRef = Convert.ToBase64String(SHA256.HashData("json-presence-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var entitlement = await _service.IssueEntitlementAsync(
            ClientId, Hash("json-presence-issue-" + schema + memberState), issue);
        var node = JsonSerializer.SerializeToNode(
            FinalizeRequest(entitlement.Response.EntitlementRef),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!.AsObject();
        node["schema"] = schema;
        node.Remove("allowSameAuthorityRecovery");
        if (memberState == "null")
            node["allowSameAuthorityRecovery"] = null;
        else if (memberState is "false" or "true")
            node["allowSameAuthorityRecovery"] = JsonValue.Create(memberState == "true");
        var request = node.Deserialize<DistributionInstallationFinalizeRequest>(
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

        if (expectedValid)
        {
            var result = await _service.FinalizeAsync(
                ClientId, Hash("json-presence-finalize-" + schema + memberState), request);
            Assert.Equal("active", result.Response.State);
        }
        else
        {
            var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                _service.FinalizeAsync(
                    ClientId, Hash("json-presence-finalize-" + schema + memberState), request));
            Assert.Equal("invalid_request", exception.ErrorCode);
        }
    }

    [Fact]
    public async Task FinalizeV2_WithoutPriorBinding_AllowsInitialInstallation()
    {
        var issue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        issue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        issue.SubjectRef = Convert.ToBase64String(SHA256.HashData("v2-initial-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var entitlement = await _service.IssueEntitlementAsync(ClientId, Hash("v2-initial-issue"), issue);
        var request = FinalizeRequest(entitlement.Response.EntitlementRef);
        request.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
        request.AllowSameAuthorityRecovery = true;

        var result = await _service.FinalizeAsync(ClientId, Hash("v2-initial-finalize"), request);

        Assert.Equal("active", result.Response.State);
        await using var db = new LicenseDbContext(_options);
        Assert.Equal(1, (await db.DistributionInstallationBindings.SingleAsync()).InitialSecurityEpoch);
    }

    [Fact]
    public async Task FinalizeV3_SubMicrosecondClock_IsCanonicalizedToDatabasePrecision()
    {
        var subMicrosecondNow = Now.AddTicks(7);
        var service = new DistributionInstallationBindingService(
            new TestDbContextFactory(_options),
            new EphemeralDataProtectionProvider(),
            new FixedTimeProvider(subMicrosecondNow));
        var issue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        issue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        issue.SubjectRef = Convert.ToBase64String(SHA256.HashData("database-precision-subject"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var entitlement = await service.IssueEntitlementAsync(
            ClientId, Hash("v3-database-precision-issue"), issue);
        var finalized = await service.FinalizeAsync(
            ClientId,
            Hash("v3-database-precision-finalize"),
            FinalizeRequest(entitlement.Response.EntitlementRef));

        Assert.Equal("2026-07-18T20:30:00.0000000Z", entitlement.Response.ExpiresAtUtc);
        Assert.Equal("active", finalized.Response.State);
    }

    [Theory]
    [InlineData("2026-07-18T20:30:00.0000007Z", true)]
    [InlineData("2026-07-18T20:30:00.0000010Z", false)]
    public async Task FinalizeV3_HistoricalTimestamp_OnlyAcceptsSameDatabaseMicrosecond(
        string historicalExpiresAtUtc,
        bool expectedAccepted)
    {
        var dataProtectionProvider = new EphemeralDataProtectionProvider();
        var service = new DistributionInstallationBindingService(
            new TestDbContextFactory(_options),
            dataProtectionProvider,
            new FixedTimeProvider(Now));
        var issue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        issue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        issue.SubjectRef = Convert.ToBase64String(SHA256.HashData("historical-precision-subject"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var entitlement = await service.IssueEntitlementAsync(
            ClientId, Hash("historical-precision-issue"), issue);
        var protector = dataProtectionProvider.CreateProtector("SoftLicence.DistributionEntitlement.v1");
        var historicalIssuedAtUtc = historicalExpiresAtUtc.Replace("T20:30", "T18:30", StringComparison.Ordinal);
        var payload = protector.Unprotect(entitlement.Response.EntitlementRef)
            .Replace("2026-07-18T18:30:00.0000000Z", historicalIssuedAtUtc, StringComparison.Ordinal)
            .Replace("2026-07-18T20:30:00.0000000Z", historicalExpiresAtUtc, StringComparison.Ordinal);
        var finalize = FinalizeRequest(protector.Protect(payload));

        if (expectedAccepted)
        {
            var result = await service.FinalizeAsync(
                ClientId, Hash("historical-precision-finalize"), finalize);
            Assert.Equal("active", result.Response.State);
        }
        else
        {
            var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
                service.FinalizeAsync(ClientId, Hash("historical-precision-finalize"), finalize));
            Assert.Equal("entitlement_ineligible", exception.ErrorCode);
        }
    }

    [Fact]
    public async Task IssueEntitlement_SameRequestIdChangedExactBytes_IsConflictWithoutSecondRecord()
    {
        var request = IssueRequest();
        await _service.IssueEntitlementAsync(ClientId, Hash("first"), request);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.IssueEntitlementAsync(ClientId, Hash("changed"), request));

        Assert.Equal("idempotency_conflict", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Single(await db.DistributionBindingRequests.ToListAsync());
    }

    [Fact]
    public async Task Finalize_ValidEvidence_CreatesOnePseudonymousBindingAndRetriesExactly()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var request = FinalizeRequest(entitlement);
        var digest = Hash("exact-finalize-body");

        var first = await _service.FinalizeAsync(ClientId, digest, request);
        var retry = await _service.FinalizeAsync(ClientId, digest, request);

        Assert.False(first.Idempotent);
        Assert.True(retry.Idempotent);
        Assert.Equal(first.Response, retry.Response);
        Assert.Equal("active", first.Response.State);
        Assert.Equal("release", first.Response.ReleaseSource);
        Assert.Equal(Hash(HardwareId), first.Response.HardwareIdHash);
        var json = JsonSerializer.Serialize(first.Response);
        Assert.DoesNotContain(LicenseId.ToString("D"), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(HardwareId, json, StringComparison.Ordinal);

        await using var db = new LicenseDbContext(_options);
        Assert.Single(await db.DistributionInstallationBindings.ToListAsync());
        Assert.Equal(2, await db.DistributionBindingRequests.CountAsync());
    }

    [Fact]
    public async Task FinalizeV3_NewerSameAuthorityGeneration_RotatesBindingAndInvalidatesLiveEnrollment()
    {
        var subjectRef = Convert.ToBase64String(SHA256.HashData("same-runtime-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var originalIssue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        originalIssue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        originalIssue.SubjectRef = subjectRef;
        var originalEntitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("cross-generation-original-issue"), originalIssue)).Response.EntitlementRef;
        var originalRequest = FinalizeRequest(originalEntitlement);
        var original = await _service.FinalizeAsync(
            ClientId, Hash("cross-generation-original-finalize"), originalRequest);

        var enrollmentId = Guid.NewGuid();
        await using (var seed = new LicenseDbContext(_options))
        {
            seed.RuntimeEnrollmentKeyRegistries.Add(new RuntimeEnrollmentKeyRegistry
            {
                Purpose = "encryption",
                KeyId = "cross-generation-test-key",
                MaterialDigestSha256 = Hash("cross-generation-test-key"),
                State = "active",
                Epoch = 1,
                CreatedAtUtc = Now.UtcDateTime
            });
            seed.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = enrollmentId,
                ClientId = ClientId,
                BindingId = Guid.Parse(original.Response.BindingId),
                ProductId = ProductId,
                LicenseId = LicenseId,
                LicenseSeatId = SeatId,
                InstallationId = originalRequest.InstallationId!,
                HardwareIdHash = Hash(HardwareId),
                ReleaseVersion = originalRequest.Release!.Version!,
                HandoffDigestSha256 = originalRequest.HandoffDigestSha256!,
                SubjectRefDigestSha256 = Hash(subjectRef),
                ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
                Algorithm = "PS256",
                KeyBackend = "software-cng-unattested",
                AttestationLevel = "none",
                PublicKeySpkiCiphertext = "test",
                PublicKeySpkiKeyId = "cross-generation-test-key",
                PublicKeySpkiSha256 = Hash("cross-generation-spki"),
                KeyThumbprint = "cross-generation-thumbprint",
                ChallengeCiphertext = "test",
                ChallengeKeyId = "cross-generation-test-key",
                ChallengeDigestSha256 = Hash("cross-generation-challenge"),
                State = "ACTIVE",
                Epoch = 1,
                SecurityEpoch = 1,
                AuthorityEpoch = 7,
                ChallengeExpiresAtUtc = Now.AddHours(1).UtcDateTime,
                CreatedAtUtc = Now.AddHours(-1).UtcDateTime,
                ActivatedAtUtc = Now.AddMinutes(-30).UtcDateTime
            });
            seed.ApprovedBinaries.AddRange(
                new ApprovedBinary { ProductId = ProductId, Version = "2.2.845", Key = "FP_EXE", Hash = Hash('1'), Source = "release" },
                new ApprovedBinary { ProductId = ProductId, Version = "2.2.845", Key = "FP_DLL", Hash = Hash('2'), Source = "release" },
                new ApprovedBinary { ProductId = ProductId, Version = "2.2.845", Key = "FP_CORE", Hash = Hash('3'), Source = "release" });
            await seed.SaveChangesAsync();
        }

        const string nextGrantRef = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        var nextIssue = IssueRequest(Hash(nextGrantRef), v2: false);
        nextIssue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        nextIssue.SubjectRef = subjectRef;
        var nextEntitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("cross-generation-next-issue"), nextIssue)).Response.EntitlementRef;
        var nextRequest = FinalizeRequest(nextEntitlement);
        nextRequest.GrantRef = nextGrantRef;
        nextRequest.InstallationId = originalRequest.InstallationId;
        nextRequest.HandoffDigestSha256 = Hash("cross-generation-next-handoff");
        nextRequest.HandoffIssuedAtUtc = "2026-07-18T18:20:00.0000000Z";
        nextRequest.DownloadCompletedAtUtc = "2026-07-18T18:25:00.0000000Z";
        nextRequest.Release = new DistributionReleaseEvidence
        {
            Version = "2.2.845",
            InstallerFilename = "TiaConnect-Setup_v2.2.845.exe",
            InstallerSha256 = Hash('4')
        };
        nextRequest.Binaries =
        [
            new() { Key = "FP_EXE", Sha256 = Hash('1') },
            new() { Key = "FP_DLL", Sha256 = Hash('2') },
            new() { Key = "FP_CORE", Sha256 = Hash('3') }
        ];

        var rotated = await _service.FinalizeAsync(
            ClientId, Hash("cross-generation-next-finalize"), nextRequest);
        var replay = await _service.FinalizeAsync(
            ClientId, Hash("cross-generation-next-finalize"), nextRequest);

        Assert.False(rotated.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(original.Response.BindingId, rotated.Response.BindingId);
        Assert.Equal("2.2.845", rotated.Response.Version);
        await using var check = new LicenseDbContext(_options);
        var binding = await check.DistributionInstallationBindings.SingleAsync();
        var enrollment = await check.RuntimeEnrollments.SingleAsync(candidate => candidate.Id == enrollmentId);
        Assert.Equal(Hash("cross-generation-next-handoff"), binding.HandoffDigestSha256);
        Assert.Equal(Hash(nextGrantRef), binding.GrantRefDigestSha256);
        Assert.Equal("INVALIDATED", enrollment.State);
        Assert.Equal("binding_superseded", enrollment.InvalidationReason);
        Assert.Equal(Now.UtcDateTime, enrollment.InvalidatedAtUtc);
        Assert.Single(await check.DistributionInstallationBindings.Where(candidate => candidate.State == "active").ToListAsync());
        Assert.Single(await check.LicenseSeats.Where(candidate => candidate.IsActive).ToListAsync());
    }

    [Fact]
    public async Task FinalizeV3_ReusedInstallationWithDivergentSubject_FailsClosedWithoutMutation()
    {
        var originalSubject = Convert.ToBase64String(SHA256.HashData("original-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var originalIssue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        originalIssue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        originalIssue.SubjectRef = originalSubject;
        var originalEntitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("divergent-original-issue"), originalIssue)).Response.EntitlementRef;
        var originalRequest = FinalizeRequest(originalEntitlement);
        await _service.FinalizeAsync(ClientId, Hash("divergent-original-finalize"), originalRequest);

        const string nextGrantRef = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        var divergentIssue = IssueRequest(Hash(nextGrantRef), v2: false);
        divergentIssue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        divergentIssue.SubjectRef = Convert.ToBase64String(SHA256.HashData("different-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var divergentEntitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("divergent-next-issue"), divergentIssue)).Response.EntitlementRef;
        var divergentRequest = FinalizeRequest(divergentEntitlement);
        divergentRequest.GrantRef = nextGrantRef;
        divergentRequest.InstallationId = originalRequest.InstallationId;
        divergentRequest.HandoffDigestSha256 = Hash("divergent-next-handoff");
        divergentRequest.HandoffIssuedAtUtc = "2026-07-18T18:20:00.0000000Z";
        divergentRequest.DownloadCompletedAtUtc = "2026-07-18T18:25:00.0000000Z";

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("divergent-next-finalize"), divergentRequest));

        Assert.Equal("binding_conflict", exception.ErrorCode);
        Assert.Equal("cross_generation_subject_mismatch", exception.ReasonCode);
        await using var check = new LicenseDbContext(_options);
        var binding = await check.DistributionInstallationBindings.SingleAsync();
        Assert.Equal(Hash(DefaultGrantRef), binding.GrantRefDigestSha256);
        Assert.Equal(originalRequest.HandoffDigestSha256, binding.HandoffDigestSha256);
        Assert.Equal("2.2.844", binding.Version);
    }

    [Fact]
    public async Task Finalize_FullSeatCapacityOrNonReleaseBaseline_FailsClosedWithoutBinding()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var wrongHardware = FinalizeRequest(entitlement);
        wrongHardware.HardwareId = "ABCDEF1234567890";

        var seatException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("wrong-hwid"), wrongHardware));
        Assert.Equal("seat_limit_reached", seatException.ErrorCode);

        await using (var db = new LicenseDbContext(_options))
        {
            foreach (var binary in db.ApprovedBinaries)
                binary.Source = ApprovedBinaryService.AdminSource;
            await db.SaveChangesAsync();
        }
        var releaseException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("admin-source"), FinalizeRequest(entitlement, requestId: NewUuid())));
        Assert.Equal("release_unapproved", releaseException.ErrorCode);

        await using var checkDb = new LicenseDbContext(_options);
        Assert.Empty(await checkDb.DistributionInstallationBindings.ToListAsync());
    }

    [Fact]
    public async Task Finalize_EligibleLicenseWithoutSeat_CreatesInitialSeatAtomically()
    {
        await using (var db = new LicenseDbContext(_options))
        {
            db.LicenseSeats.RemoveRange(db.LicenseSeats);
            var license = await db.Licenses.SingleAsync(candidate => candidate.Id == LicenseId);
            license.HardwareId = null;
            license.ActivationDate = null;
            await db.SaveChangesAsync();
        }
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-without-seat"), IssueRequest())).Response.EntitlementRef;

        var result = await _service.FinalizeAsync(
            ClientId, Hash("finalize-without-seat"), FinalizeRequest(entitlement));

        Assert.Equal("active", result.Response.State);
        await using var check = new LicenseDbContext(_options);
        var seat = await check.LicenseSeats.SingleAsync();
        Assert.Equal(HardwareId, seat.HardwareId);
        Assert.True(seat.IsActive);
        Assert.Equal("2.2.844", seat.AppVersion);
        var licenseAfter = await check.Licenses.SingleAsync(candidate => candidate.Id == LicenseId);
        Assert.Equal(HardwareId, licenseAfter.HardwareId);
        Assert.NotNull(licenseAfter.ActivationDate);
        Assert.Contains(await check.LicenseHistories.ToListAsync(), history =>
            history.Action == "RUNTIME_INITIAL_SEAT_CREATED");
    }

    [Fact]
    public async Task Finalize_InactiveSameHardwareSeat_ReactivatesWithoutDuplicate()
    {
        await using (var db = new LicenseDbContext(_options))
        {
            var seat = await db.LicenseSeats.SingleAsync(candidate => candidate.Id == SeatId);
            seat.IsActive = false;
            seat.UnlinkedAt = Now.AddHours(-1).UtcDateTime;
            await db.SaveChangesAsync();
        }
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-inactive-seat"), IssueRequest())).Response.EntitlementRef;

        await _service.FinalizeAsync(
            ClientId, Hash("finalize-inactive-seat"), FinalizeRequest(entitlement));

        await using var check = new LicenseDbContext(_options);
        var seatAfter = await check.LicenseSeats.SingleAsync();
        Assert.Equal(SeatId, seatAfter.Id);
        Assert.True(seatAfter.IsActive);
        Assert.Null(seatAfter.UnlinkedAt);
        Assert.Contains(await check.LicenseHistories.ToListAsync(), history =>
            history.Action == "RUNTIME_INITIAL_SEAT_REACTIVATED");
    }

    [Fact]
    public async Task Finalize_RejectedBinary_DoesNotCreateInitialSeat()
    {
        await using (var db = new LicenseDbContext(_options))
        {
            db.LicenseSeats.RemoveRange(db.LicenseSeats);
            await db.SaveChangesAsync();
        }
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-rejected-binary"), IssueRequest())).Response.EntitlementRef;
        var request = FinalizeRequest(entitlement);
        request.Binaries![0].Sha256 = Hash('f');

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("finalize-rejected-binary"), request));

        Assert.Equal("binary_mismatch", exception.ErrorCode);
        await using var check = new LicenseDbContext(_options);
        Assert.Empty(await check.LicenseSeats.ToListAsync());
        Assert.Empty(await check.DistributionInstallationBindings.ToListAsync());
    }

    [Fact]
    public async Task Finalize_DisabledNewActivations_RejectsNewSeatButKeepsExistingSeatUsable()
    {
        await using (var db = new LicenseDbContext(_options))
        {
            var type = await db.LicenseTypes.SingleAsync();
            type.DisableNewActivations = true;
            await db.SaveChangesAsync();
        }
        var existingEntitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-disabled-existing"), IssueRequest())).Response.EntitlementRef;
        var existing = await _service.FinalizeAsync(
            ClientId, Hash("finalize-disabled-existing"), FinalizeRequest(existingEntitlement));
        Assert.Equal("active", existing.Response.State);

        await using (var db = new LicenseDbContext(_options))
        {
            db.DistributionInstallationBindings.RemoveRange(db.DistributionInstallationBindings);
            db.DistributionBindingRequests.RemoveRange(db.DistributionBindingRequests);
            db.DistributionGrantOwnerships.RemoveRange(db.DistributionGrantOwnerships);
            db.LicenseSeats.RemoveRange(db.LicenseSeats);
            await db.SaveChangesAsync();
        }
        var newSeatEntitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-disabled-new"), IssueRequest())).Response.EntitlementRef;
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(
                ClientId, Hash("finalize-disabled-new"), FinalizeRequest(newSeatEntitlement)));
        Assert.Equal("new_activations_disabled", exception.ErrorCode);
    }

    [Fact]
    public async Task Finalize_SingleUseHardwareConsumedByAnotherLicense_RejectsWithoutSeat()
    {
        await using (var db = new LicenseDbContext(_options))
        {
            db.LicenseSeats.RemoveRange(db.LicenseSeats);
            var type = await db.LicenseTypes.SingleAsync();
            type.EnforceSingleUsePerHardwareId = true;
            var consumedLicense = new License
            {
                ProductId = ProductId,
                LicenseTypeId = type.Id,
                LicenseKey = "CONSUMED-TEST-ONLY",
                IsActive = false,
                MaxSeats = 1
            };
            db.Licenses.Add(consumedLicense);
            db.LicenseSeats.Add(new LicenseSeat
            {
                License = consumedLicense,
                HardwareId = HardwareId,
                IsActive = false,
                UnlinkedAt = Now.AddDays(-1).UtcDateTime
            });
            await db.SaveChangesAsync();
        }
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-consumed-hardware"), IssueRequest())).Response.EntitlementRef;

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("finalize-consumed-hardware"), FinalizeRequest(entitlement)));

        Assert.Equal("hardware_already_consumed", exception.ErrorCode);
        await using var check = new LicenseDbContext(_options);
        Assert.DoesNotContain(await check.LicenseSeats.ToListAsync(), candidate =>
            candidate.LicenseId == LicenseId && candidate.IsActive);
    }

    [Fact]
    public async Task Finalize_BannedFingerprintOrExpiredHandoff_FailsClosed()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        await using (var db = new LicenseDbContext(_options))
        {
            db.BannedComponents.Add(new BannedComponent
            {
                ProductId = ProductId,
                ComponentType = "FP_DLL",
                ComponentHash = Hash('b'),
                IsActive = true
            });
            await db.SaveChangesAsync();
        }
        var binaryException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("banned"), FinalizeRequest(entitlement)));
        Assert.Equal("binary_mismatch", binaryException.ErrorCode);

        var expired = FinalizeRequest(entitlement, requestId: NewUuid());
        expired.HandoffIssuedAtUtc = "2026-07-18T15:00:00.0000000Z";
        expired.HandoffExpiresAtUtc = "2026-07-18T17:00:00.0000000Z";
        expired.DownloadCompletedAtUtc = "2026-07-18T16:00:00.0000000Z";
        var handoffException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("expired"), expired));
        Assert.Equal("handoff_unavailable", handoffException.ErrorCode);
    }

    [Fact]
    public async Task Finalize_WrongVersionProductInstallationOrHash_FailsClosedWithoutBinding()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;

        var wrongVersion = FinalizeRequest(entitlement);
        wrongVersion.Release!.Version = "3.0.0";
        var versionException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("wrong-version"), wrongVersion));
        Assert.Equal("version_not_allowed", versionException.ErrorCode);

        var wrongProduct = FinalizeRequest(entitlement, requestId: NewUuid());
        wrongProduct.ProductId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        var productException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("wrong-product"), wrongProduct));
        Assert.Equal("entitlement_ineligible", productException.ErrorCode);

        var wrongInstallation = FinalizeRequest(entitlement, requestId: NewUuid());
        wrongInstallation.InstallationId = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";
        var installationException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("wrong-installation"), wrongInstallation));
        Assert.Equal("invalid_request", installationException.ErrorCode);

        var wrongHash = FinalizeRequest(entitlement, requestId: NewUuid());
        wrongHash.Binaries![0].Sha256 = Hash('f');
        var hashException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("wrong-hash"), wrongHash));
        Assert.Equal("binary_mismatch", hashException.ErrorCode);

        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionInstallationBindings.ToListAsync());
    }

    [Fact]
    public async Task Finalize_ConcurrentSameRequest_CreatesSingleBinding()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var request = FinalizeRequest(entitlement);
        var digest = Hash("same-concurrent-body");

        var results = await Task.WhenAll(Enumerable.Range(0, 4)
            .Select(_ => _service.FinalizeAsync(ClientId, digest, request)));

        Assert.Single(results.Select(result => result.Response.BindingId).Distinct(StringComparer.Ordinal));
        await using var db = new LicenseDbContext(_options);
        Assert.Single(await db.DistributionInstallationBindings.ToListAsync());
        Assert.Equal(2, await db.DistributionBindingRequests.CountAsync());
    }

    [Fact]
    public async Task Finalize_SameHandoffWithNewRequestId_PersistsSecondIdempotencyRecord()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var firstRequest = FinalizeRequest(entitlement);
        var first = await _service.FinalizeAsync(ClientId, Hash("first-finalize"), firstRequest);
        var secondRequest = FinalizeRequest(entitlement, requestId: NewUuid());
        secondRequest.GrantRef = firstRequest.GrantRef;
        secondRequest.HandoffDigestSha256 = firstRequest.HandoffDigestSha256;
        secondRequest.InstallationId = firstRequest.InstallationId;

        var second = await _service.FinalizeAsync(ClientId, Hash("second-finalize"), secondRequest);

        Assert.True(second.Idempotent);
        Assert.Equal(first.Response, second.Response);
        await using var db = new LicenseDbContext(_options);
        Assert.Equal(3, await db.DistributionBindingRequests.CountAsync());
    }

    [Fact]
    public async Task Finalize_ForgedEntitlementOrRevokedLicense_FailsClosed()
    {
        var forged = FinalizeRequest(new string('A', 80));
        var forgedException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("forged"), forged));
        Assert.Equal("entitlement_ineligible", forgedException.ErrorCode);

        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var crossClientException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync("other-authorized-client", Hash("cross-client"), FinalizeRequest(entitlement)));
        Assert.Equal("entitlement_ineligible", crossClientException.ErrorCode);

        await using (var db = new LicenseDbContext(_options))
        {
            var license = await db.Licenses.SingleAsync(candidate => candidate.Id == LicenseId);
            license.IsActive = false;
            license.RevokedAt = Now.UtcDateTime;
            await db.SaveChangesAsync();
        }
        var revokedException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("revoked"), FinalizeRequest(entitlement)));
        Assert.Equal("entitlement_ineligible", revokedException.ErrorCode);
    }

    [Fact]
    public async Task Invalidate_AfterFinalize_IsAtomicPseudonymousAndExactlyIdempotent()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var finalizeRequest = FinalizeRequest(entitlement);
        var binding = await _service.FinalizeAsync(ClientId, Hash("finalize"), finalizeRequest);
        var request = InvalidationRequest(finalizeRequest, binding.Response.BindingId);
        var digest = Hash("exact-invalidation-body");

        var first = await _service.InvalidateAsync(ClientId, digest, request);
        var retryAfterLostResponse = await _service.InvalidateAsync(ClientId, digest, request);

        Assert.False(first.Idempotent);
        Assert.True(retryAfterLostResponse.Idempotent);
        Assert.Equal(first.Response, retryAfterLostResponse.Response);
        Assert.Equal("invalidated", first.Response.State);
        Assert.Equal("grant_revoked", first.Response.Reason);
        Assert.Equal(1, first.Response.Epoch);
        Assert.Equal(Hash(finalizeRequest.GrantRef!), first.Response.GrantRefDigestSha256);
        var json = JsonSerializer.Serialize(first.Response);
        Assert.DoesNotContain(finalizeRequest.GrantRef!, json, StringComparison.Ordinal);
        Assert.DoesNotContain(HardwareId, json, StringComparison.Ordinal);

        await using var db = new LicenseDbContext(_options);
        var persistedBinding = await db.DistributionInstallationBindings.SingleAsync();
        Assert.Equal("invalidated", persistedBinding.State);
        Assert.Equal("grant_revoked", persistedBinding.InvalidationReason);
        Assert.Single(await db.DistributionBindingInvalidations.ToListAsync());
        Assert.Equal(3, await db.DistributionBindingRequests.CountAsync());
    }

    [Fact]
    public async Task Invalidate_BeforeFinalize_PersistsTombstoneAndFinalizeCannotReactivate()
    {
        var finalizeRequest = FinalizeRequest("pending-entitlement");
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest(Hash(finalizeRequest.GrantRef!), v2: true))).Response.EntitlementRef;
        finalizeRequest.EntitlementRef = entitlement;
        var invalidation = InvalidationRequest(finalizeRequest);

        var result = await _service.InvalidateAsync(ClientId, Hash("invalidate-first"), invalidation);
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("finalize-late"), finalizeRequest));

        Assert.Null(result.Response.BindingId);
        Assert.Equal("binding_invalidated", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionInstallationBindings.ToListAsync());
        Assert.Single(await db.DistributionBindingInvalidations.ToListAsync());
    }

    [Fact]
    public async Task Invalidate_BeforeFinalizeWithV1Entitlement_FailsClosedWithoutTombstone()
    {
        var finalizeRequest = FinalizeRequest("pending-entitlement");
        await _service.IssueEntitlementAsync(ClientId, Hash("issue-v1"), IssueRequest());

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.InvalidateAsync(ClientId, Hash("invalidate-v1-first"), InvalidationRequest(finalizeRequest)));

        Assert.Equal("grant_ownership_mismatch", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionBindingInvalidations.ToListAsync());
        Assert.Empty(await db.DistributionGrantOwnerships.ToListAsync());
    }

    [Fact]
    public async Task IssueV2_OtherClientCannotClaimOrInvalidateOwnedGrantBeforeFinalize()
    {
        var finalizeRequest = FinalizeRequest("pending-entitlement");
        var digest = Hash(finalizeRequest.GrantRef!);
        await _service.IssueEntitlementAsync(ClientId, Hash("issue-owner"), IssueRequest(digest, v2: true));

        var secondIssue = IssueRequest(digest, v2: true);
        var issueException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.IssueEntitlementAsync("other-authorized-client", Hash("issue-other"), secondIssue));
        var invalidationException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.InvalidateAsync("other-authorized-client", Hash("invalidate-other"), InvalidationRequest(finalizeRequest)));

        Assert.Equal("grant_ownership_conflict", issueException.ErrorCode);
        Assert.Equal("grant_ownership_mismatch", invalidationException.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionBindingInvalidations.ToListAsync());
        Assert.Equal(ClientId, (await db.DistributionGrantOwnerships.SingleAsync()).ClientId);
    }

    [Fact]
    public async Task Finalize_V2EntitlementForDifferentGrant_IsRejected()
    {
        var finalizeRequest = FinalizeRequest("pending-entitlement");
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-v2"), IssueRequest(Hash("different-grant"), v2: true))).Response.EntitlementRef;
        finalizeRequest.EntitlementRef = entitlement;

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.FinalizeAsync(ClientId, Hash("finalize-wrong-grant"), finalizeRequest));

        Assert.Equal("grant_ownership_mismatch", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionInstallationBindings.ToListAsync());
    }

    [Fact]
    public async Task Invalidate_SameRequestChangedPayload_IsConflictWithoutSecondMutation()
    {
        var finalizeRequest = FinalizeRequest("not-used-for-invalidation");
        var request = InvalidationRequest(finalizeRequest);
        await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-v2-owner"), IssueRequest(request.GrantRefDigestSha256, v2: true));
        await _service.InvalidateAsync(ClientId, Hash("first"), request);

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.InvalidateAsync(ClientId, Hash("changed"), request));

        Assert.Equal("idempotency_conflict", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Single(await db.DistributionBindingInvalidations.ToListAsync());
        Assert.Equal(2, await db.DistributionBindingRequests.CountAsync());
    }

    [Fact]
    public async Task Invalidate_OtherClientAfterTombstone_RejectsOwnershipWithoutExistenceOracle()
    {
        var finalizeRequest = FinalizeRequest("pending-entitlement");
        var request = InvalidationRequest(finalizeRequest);
        await _service.IssueEntitlementAsync(
            ClientId, Hash("issue-v2-owner"), IssueRequest(request.GrantRefDigestSha256, v2: true));
        await _service.InvalidateAsync(ClientId, Hash("invalidate-owner"), request);

        var crossClient = InvalidationRequest(finalizeRequest);
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.InvalidateAsync("other-authorized-client", Hash("invalidate-other"), crossClient));

        Assert.Equal("grant_ownership_mismatch", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Single(await db.DistributionBindingInvalidations.ToListAsync());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public async Task Invalidate_EpochOtherThanOne_IsRejectedWithoutMutation(long epoch)
    {
        var request = InvalidationRequest(FinalizeRequest("not-used-for-invalidation"));
        request.Epoch = epoch;

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.InvalidateAsync(ClientId, Hash($"epoch-{epoch}"), request));

        Assert.Equal("invalid_request", exception.ErrorCode);
        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionBindingInvalidations.ToListAsync());
    }

    [Fact]
    public async Task Invalidate_WrongBindingOrClient_IsRejectedFailClosed()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var finalizeRequest = FinalizeRequest(entitlement);
        var binding = await _service.FinalizeAsync(ClientId, Hash("finalize"), finalizeRequest);

        var wrongBinding = InvalidationRequest(finalizeRequest, NewUuid());
        var bindingException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.InvalidateAsync(ClientId, Hash("wrong-binding"), wrongBinding));
        Assert.Equal("binding_mismatch", bindingException.ErrorCode);

        var crossClient = InvalidationRequest(finalizeRequest, binding.Response.BindingId);
        crossClient.RequestId = NewUuid();
        var clientException = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            _service.InvalidateAsync("other-authorized-client", Hash("wrong-client"), crossClient));
        Assert.Equal("grant_ownership_mismatch", clientException.ErrorCode);

        await using var db = new LicenseDbContext(_options);
        Assert.Empty(await db.DistributionBindingInvalidations.ToListAsync());
        Assert.Equal("active", (await db.DistributionInstallationBindings.SingleAsync()).State);
    }

    [Fact]
    public async Task RevalidateForCapability_AfterS2SInvalidation_RemainsInvalidated()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var finalizeRequest = FinalizeRequest(entitlement);
        var binding = await _service.FinalizeAsync(ClientId, Hash("finalize"), finalizeRequest);
        await _service.InvalidateAsync(
            ClientId, Hash("invalidate"), InvalidationRequest(finalizeRequest, binding.Response.BindingId));

        var capabilityView = await _service.RevalidateForCapabilityAsync(Guid.Parse(binding.Response.BindingId));

        Assert.Equal("invalidated", capabilityView.State);
        Assert.NotNull(capabilityView.InvalidatedAtUtc);
    }

    [Fact]
    public async Task RevalidateForCapability_AfterLicenseRevocation_PersistsInvalidatedState()
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var created = await _service.FinalizeAsync(
            ClientId, Hash("finalize"), FinalizeRequest(entitlement));
        await using (var db = new LicenseDbContext(_options))
        {
            var license = await db.Licenses.SingleAsync(candidate => candidate.Id == LicenseId);
            license.IsActive = false;
            license.RevokedAt = Now.UtcDateTime;
            await db.SaveChangesAsync();
        }

        var revalidated = await _service.RevalidateForCapabilityAsync(Guid.Parse(created.Response.BindingId));

        Assert.Equal("invalidated", revalidated.State);
        Assert.Equal("2026-07-18T18:30:00.0000000Z", revalidated.InvalidatedAtUtc);
        await using var checkDb = new LicenseDbContext(_options);
        var binding = await checkDb.DistributionInstallationBindings.SingleAsync();
        Assert.Equal("license_ineligible", binding.InvalidationReason);
    }

    [Theory]
    [InlineData("seat", "seat_ineligible")]
    [InlineData("version", "version_ineligible")]
    [InlineData("ban", "security_lockdown")]
    [InlineData("baseline", "release_changed")]
    public async Task RevalidateForCapability_WhenAuthorityChanges_InvalidatesBinding(
        string authorityChange,
        string expectedReason)
    {
        var entitlement = (await _service.IssueEntitlementAsync(
            ClientId, Hash("issue"), IssueRequest())).Response.EntitlementRef;
        var created = await _service.FinalizeAsync(
            ClientId, Hash("finalize"), FinalizeRequest(entitlement));
        await using (var db = new LicenseDbContext(_options))
        {
            switch (authorityChange)
            {
                case "seat":
                    (await db.LicenseSeats.SingleAsync(candidate => candidate.Id == SeatId)).IsActive = false;
                    break;
                case "version":
                    (await db.Licenses.SingleAsync(candidate => candidate.Id == LicenseId)).AllowedVersions = "3.0.*";
                    break;
                case "ban":
                    db.BannedComponents.Add(new BannedComponent
                    {
                        ProductId = ProductId,
                        ComponentType = "FP_CORE",
                        ComponentHash = Hash('c'),
                        IsActive = true
                    });
                    break;
                case "baseline":
                    db.ApprovedBinaries.Remove(await db.ApprovedBinaries.FirstAsync());
                    break;
                default:
                    throw new InvalidOperationException(authorityChange);
            }
            await db.SaveChangesAsync();
        }

        var revalidated = await _service.RevalidateForCapabilityAsync(Guid.Parse(created.Response.BindingId));

        Assert.Equal("invalidated", revalidated.State);
        await using var checkDb = new LicenseDbContext(_options);
        Assert.Equal(expectedReason, (await checkDb.DistributionInstallationBindings.SingleAsync()).InvalidationReason);
    }

    [Theory]
    [InlineData("23505", true)]
    [InlineData("40001", true)]
    [InlineData("23503", false)]
    [InlineData("42P01", false)]
    public void RetryClassifier_OnlyAcceptsPostgresUniqueAndSerializationFailures(string sqlState, bool expected)
    {
        var classifier = typeof(DistributionInstallationBindingService).GetMethod(
            "IsRetryablePostgresSqlState",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(classifier);
        Assert.Equal(expected, Assert.IsType<bool>(classifier.Invoke(null, [sqlState])));
    }

    public void Dispose() => _keepAlive.Dispose();

    private static DistributionEntitlementIssueRequest IssueRequest(
        string? grantRefDigestSha256 = null,
        bool v2 = false) => new()
    {
        Schema = v2
            ? DistributionInstallationBindingService.IssueV2Schema
            : DistributionInstallationBindingService.IssueSchema,
        RequestId = NewUuid(),
        ProductId = ProductId.ToString("D"),
        SoftLicenceLicenseId = LicenseId.ToString("D"),
        GrantRefDigestSha256 = grantRefDigestSha256
    };

    private static DistributionInstallationFinalizeRequest FinalizeRequest(
        string entitlementRef,
        string? requestId = null) => new()
    {
        Schema = DistributionInstallationBindingService.FinalizeSchema,
        RequestId = requestId ?? NewUuid(),
        GrantRef = DefaultGrantRef,
        HandoffDigestSha256 = Hash("handoff"),
        HandoffIssuedAtUtc = "2026-07-18T18:00:00.0000000Z",
        HandoffExpiresAtUtc = "2026-07-18T20:00:00.0000000Z",
        DownloadCompletedAtUtc = "2026-07-18T18:10:00.0000000Z",
        ProductId = ProductId.ToString("D"),
        EntitlementRef = entitlementRef,
        InstallationId = NewUuid(),
        HardwareId = HardwareId,
        Release = new DistributionReleaseEvidence
        {
            Version = "2.2.844",
            InstallerFilename = "TiaConnect-Setup_v2.2.844.exe",
            InstallerSha256 = Hash('d')
        },
        Binaries =
        [
            new() { Key = "FP_EXE", Sha256 = Hash('a') },
            new() { Key = "FP_DLL", Sha256 = Hash('b') },
            new() { Key = "FP_CORE", Sha256 = Hash('c') }
        ]
    };

    private static DistributionInstallationInvalidationRequest InvalidationRequest(
        DistributionInstallationFinalizeRequest finalize,
        string? bindingId = null) => new()
    {
        Schema = DistributionInstallationBindingService.InvalidationSchema,
        RequestId = NewUuid(),
        ProductId = finalize.ProductId,
        BindingId = bindingId,
        GrantRefDigestSha256 = Hash(finalize.GrantRef!),
        Reason = "grant_revoked",
        OccurredAtUtc = "2026-07-18T18:20:00.0000000Z",
        Epoch = 1
    };

    private static void Seed(LicenseDbContext db)
    {
        var product = new Product
        {
            Id = ProductId,
            Name = "TIAConnect",
            PrivateKeyXml = "private",
            PublicKeyXml = "public",
            ApiSecret = "test-only"
        };
        var type = new LicenseType
        {
            Id = Guid.Parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            ProductId = ProductId,
            Name = "Pro",
            Slug = "TIA-CONNECT-PRO",
            DefaultDurationDays = 30,
            DefaultMaxSeats = 1
        };
        var license = new License
        {
            Id = LicenseId,
            ProductId = ProductId,
            LicenseTypeId = type.Id,
            LicenseKey = "TEST-ONLY-NOT-A-REAL-KEY",
            IsActive = true,
            MaxSeats = 1,
            AllowedVersions = "2.2.*",
            ExpirationDate = Now.AddDays(10).UtcDateTime
        };
        var seat = new LicenseSeat
        {
            Id = SeatId,
            LicenseId = LicenseId,
            HardwareId = HardwareId,
            IsActive = true
        };
        db.AddRange(product, type, license, seat);
        db.ApprovedBinaries.AddRange(
            new ApprovedBinary { ProductId = ProductId, Version = "2.2.844", Key = "FP_EXE", Hash = Hash('a'), Source = "release" },
            new ApprovedBinary { ProductId = ProductId, Version = "2.2.844", Key = "FP_DLL", Hash = Hash('b'), Source = "release" },
            new ApprovedBinary { ProductId = ProductId, Version = "2.2.844", Key = "FP_CORE", Hash = Hash('c'), Source = "release" });
        db.SaveChanges();
    }

    private static string Hash(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Hash(char value) => new(value, 64);
    private static string NewUuid() => Guid.NewGuid().ToString("D");

    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}

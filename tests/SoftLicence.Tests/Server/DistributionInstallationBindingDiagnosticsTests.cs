using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Relational diagnostic scenarios sharing the existing isolated SQLite binding fixture.</summary>
public sealed partial class DistributionInstallationBindingServiceTests
{
    /// <summary>Exercises actual relational recovery refusals and verifies precise, private, request-correlated evidence.</summary>
    [Theory]
    [InlineData("handoff_not_newer", "required.handoff_newer")]
    [InlineData("handoff_absent", "required.source_handoff_present")]
    [InlineData("owner_wrong_case", "modern_source.grant_owner_client_matches")]
    [InlineData("owner_absent", "modern_source.grant_owner_present")]
    [InlineData("owner_source_invalid", "modern_source.grant_owner_source_matches")]
    [InlineData("combined", "required.handoff_newer")]
    public async Task RecoveryDiagnostic_RefusalIdentifiesExactChecksWithoutChangingContract(
        string scenario, string failedCheck)
    {
        var logger = new RecordingLogger<DistributionInstallationBindingService>();
        var (service, request) = await PrepareDiagnosticRecoveryAsync(logger);
        await using (var change = new LicenseDbContext(_options))
        {
            var binding = await change.DistributionInstallationBindings.SingleAsync();
            var owner = await change.DistributionGrantOwnerships.SingleAsync(candidate =>
                candidate.GrantRefDigestSha256 == binding.GrantRefDigestSha256);
            switch (scenario)
            {
                case "handoff_not_newer":
                    request.HandoffIssuedAtUtc = "2026-07-18T18:00:00.0000000Z";
                    break;
                case "handoff_absent":
                    binding.HandoffIssuedAtUtc = null;
                    break;
                case "owner_wrong_case":
                    owner.ClientId = "TIA-CONNECT-WEBSITE";
                    break;
                case "owner_absent":
                    change.DistributionGrantOwnerships.Remove(owner);
                    break;
                case "owner_source_invalid":
                    owner.Source = "issue_v2";
                    break;
                case "combined":
                    request.HandoffIssuedAtUtc = "2026-07-18T18:00:00.0000000Z";
                    owner.ClientId = "OTHER-CLIENT";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario));
            }
            await change.SaveChangesAsync();
        }

        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(ClientId, Hash("diagnostic-finalize"), request));
        Assert.Equal(409, exception.StatusCode);
        Assert.Equal("binding_conflict", exception.ErrorCode);
        Assert.Equal("same_authority_mismatch", exception.ReasonCode);
        Assert.Null(exception.HardwareAuthorityRefusal);
        var message = Assert.Single(logger.Messages);
        Assert.Contains("RequestId=" + request.RequestId, message, StringComparison.Ordinal);
        Assert.Contains("ReasonCode=same_authority_mismatch", message, StringComparison.Ordinal);
        using var parsed = JsonDocument.Parse(message[(message.IndexOf(" Checks=", StringComparison.Ordinal) + 8)..]);
        var checks = parsed.RootElement;
        Assert.False(checks.GetProperty(failedCheck).GetBoolean());
        Assert.False(checks.GetProperty("required").GetBoolean());
        Assert.True(checks.GetProperty("same_license").GetBoolean());
        Assert.Equal(JsonValueKind.Null, checks.GetProperty("renewal").ValueKind);
        Assert.Equal(JsonValueKind.Null, checks.GetProperty("legacy_renewal").ValueKind);
        if (scenario == "combined")
        {
            Assert.False(checks.GetProperty("modern_source.grant_owner_client_matches").GetBoolean());
            Assert.Contains("required.handoff_newer", message, StringComparison.Ordinal);
            Assert.Contains("required.historical_authority_matches", message, StringComparison.Ordinal);
        }
        if (scenario == "handoff_absent")
            Assert.Equal(JsonValueKind.Null, checks.GetProperty("required.handoff_newer").ValueKind);
        if (scenario == "owner_absent")
            Assert.Equal(JsonValueKind.Null, checks.GetProperty("modern_source.grant_owner_client_matches").ValueKind);
        Assert.All(checks.EnumerateObject(), property => Assert.Contains(
            property.Value.ValueKind, new[] { JsonValueKind.True, JsonValueKind.False, JsonValueKind.Null }));
        Assert.DoesNotContain(HardwareId, message, StringComparison.Ordinal);
        Assert.DoesNotContain(Hash(HardwareId), message, StringComparison.Ordinal);
        Assert.DoesNotContain(LicenseId.ToString("D"), message, StringComparison.Ordinal);
        Assert.DoesNotContain(request.EntitlementRef!, message, StringComparison.Ordinal);
        Assert.DoesNotContain(request.GrantRef!, message, StringComparison.Ordinal);
        Assert.DoesNotContain(request.InstallationId!, message, StringComparison.Ordinal);
        Assert.DoesNotContain(ClientId, message, StringComparison.OrdinalIgnoreCase);
        Assert.True(message.Length < 8000);

        await using var unchanged = new LicenseDbContext(_options);
        Assert.Single(await unchanged.DistributionInstallationBindings.ToListAsync());
        Assert.Single(await unchanged.LicenseSeats.ToListAsync());
        Assert.DoesNotContain(await unchanged.DistributionBindingRequests.ToListAsync(),
            receipt => receipt.RequestId == request.RequestId);
    }

    /// <summary>A sink outage must preserve the original refusal instead of changing it to a server exception.</summary>
    [Fact]
    public async Task RecoveryDiagnostic_ThrowingLoggerPreservesAuthorityRefusal()
    {
        var (service, request) = await PrepareDiagnosticRecoveryAsync(new ThrowingRecoveryLogger());
        request.HandoffIssuedAtUtc = "2026-07-18T18:00:00.0000000Z";
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(ClientId, Hash("diagnostic-throwing-log"), request));
        Assert.Equal(409, exception.StatusCode);
        Assert.Equal("same_authority_mismatch", exception.ReasonCode);
    }

    /// <summary>Passing authority checks must remain silent even when a later, separate enrollment gate refuses.</summary>
    [Fact]
    public async Task RecoveryDiagnostic_ValidAuthorityDoesNotLogAnOptionalBranchAsFailure()
    {
        var logger = new RecordingLogger<DistributionInstallationBindingService>();
        var (service, request) = await PrepareDiagnosticRecoveryAsync(logger);
        var exception = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            service.FinalizeAsync(ClientId, Hash("diagnostic-valid-authority"), request));
        Assert.NotEqual("same_authority_mismatch", exception.ReasonCode);
        Assert.Empty(logger.Messages);
    }

    /// <summary>
    /// A newly tracked seat must be resolved from the authoritative context after the database
    /// lookup misses it. Successful recovery must not emit the former missing-seat refusal.
    /// </summary>
    [Fact]
    public async Task RecoveryDiagnostic_NewTargetSeatUsesPendingServerEntity()
    {
        var logger = new RecordingLogger<DistributionInstallationBindingService>();
        var (service, request) = await PrepareDiagnosticRecoveryAsync(logger);
        await SeedDiagnosticEnrollmentAsync();
        await using (var unlink = new LicenseDbContext(_options))
        {
            var seat = await unlink.LicenseSeats.SingleAsync();
            seat.IsActive = false;
            seat.UnlinkedAt = Now.AddMinutes(-2).UtcDateTime;
            await unlink.SaveChangesAsync();
        }
        request.HardwareId = "DIFFERENT-TEST-HARDWARE";

        var result = await service.FinalizeAsync(ClientId, Hash("diagnostic-new-seat"), request);
        Assert.Equal("active", result.Response.State);
        Assert.Empty(logger.Messages);
        await using var db = new LicenseDbContext(_options);
        Assert.Equal(2, await db.LicenseSeats.CountAsync());
        Assert.Equal(request.HardwareId, (await db.LicenseSeats.SingleAsync(seat => seat.IsActive)).HardwareId);
        Assert.False((await db.LicenseSeats.SingleAsync(seat => seat.Id == SeatId)).IsActive);
    }

    /// <summary>Valid same-seat recovery still creates a successor and exact replay emits no refusal warning.</summary>
    [Fact]
    public async Task RecoveryDiagnostic_AcceptedRecoveryAndReplayRemainSilent()
    {
        var logger = new RecordingLogger<DistributionInstallationBindingService>();
        var (service, request) = await PrepareDiagnosticRecoveryAsync(logger);
        await SeedDiagnosticEnrollmentAsync();
        var result = await service.FinalizeAsync(ClientId, Hash("diagnostic-success"), request);
        var replay = await service.FinalizeAsync(ClientId, Hash("diagnostic-success"), request);
        Assert.Equal("active", result.Response.State);
        Assert.False(result.Idempotent);
        Assert.True(replay.Idempotent);
        Assert.Equal(result.Response, replay.Response);
        Assert.Empty(logger.Messages);
        await using var db = new LicenseDbContext(_options);
        Assert.Single(await db.LicenseSeats.Where(seat => seat.IsActive).ToListAsync());
        Assert.Single(await db.DistributionInstallationBindings.Where(binding => binding.State == "active").ToListAsync());
    }

    /// <summary>
    /// Adds a synthetic active enrollment matching the fixture's single binding. Dummy ciphertext
    /// is never decrypted by recovery; this arrangement covers authority transition only.
    /// </summary>
    private async Task SeedDiagnosticEnrollmentAsync()
    {
        await using var db = new LicenseDbContext(_options);
        var binding = await db.DistributionInstallationBindings.SingleAsync();
        const string keyId = "diagnostic-fixture-key";
        db.RuntimeEnrollmentKeyRegistries.Add(new RuntimeEnrollmentKeyRegistry
        {
            Purpose = "encryption", KeyId = keyId, MaterialDigestSha256 = Hash("diagnostic-key"),
            State = "active", Epoch = 1, CreatedAtUtc = Now.UtcDateTime
        });
        db.RuntimeEnrollments.Add(new RuntimeEnrollment
        {
            Id = Guid.NewGuid(), ClientId = ClientId, BindingId = binding.Id,
            ProductId = binding.ProductId, LicenseId = binding.LicenseId, LicenseSeatId = binding.LicenseSeatId,
            InstallationId = binding.InstallationId, HardwareIdHash = binding.HardwareIdHash,
            ReleaseVersion = binding.Version, HandoffDigestSha256 = binding.HandoffDigestSha256,
            SubjectRefDigestSha256 = binding.SubjectRefDigestSha256,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion, Algorithm = "PS256",
            KeyBackend = "software-cng-unattested", AttestationLevel = "none",
            PublicKeySpkiCiphertext = "test", PublicKeySpkiKeyId = keyId,
            PublicKeySpkiSha256 = Hash("diagnostic-spki"), KeyThumbprint = "diagnostic-thumbprint",
            ChallengeCiphertext = "test", ChallengeKeyId = keyId, ChallengeDigestSha256 = Hash("diagnostic-challenge"),
            State = "ACTIVE", Epoch = 1, SecurityEpoch = 1, AuthorityEpoch = 7,
            ChallengeExpiresAtUtc = Now.AddHours(1).UtcDateTime, CreatedAtUtc = Now.AddHours(-1).UtcDateTime,
            ActivatedAtUtc = Now.AddMinutes(-30).UtcDateTime
        });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Seeds one modern binding and a fresh recovery request against a SQLite relational fixture.
    /// Leaves the later runtime enrollment absent so authority failures are isolated from activation.
    /// </summary>
    /// <param name="logger">Synthetic sink whose output or failure is under test.</param>
    /// <returns>The service sharing the protector used for both entitlements and its fresh request.</returns>
    private async Task<(DistributionInstallationBindingService Service, DistributionInstallationFinalizeRequest Request)>
        PrepareDiagnosticRecoveryAsync(ILogger<DistributionInstallationBindingService> logger)
    {
        var service = CreateService(TestHardwareAuthorityAliasResolver.Instance, new EphemeralDataProtectionProvider(), logger);
        var subject = Convert.ToBase64String(SHA256.HashData("diagnostic-only-owner"u8.ToArray()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var issue = IssueRequest(Hash(DefaultGrantRef), v2: false);
        issue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        issue.SubjectRef = subject;
        var originalEntitlement = await service.IssueEntitlementAsync(ClientId, Hash("diagnostic-original-issue"), issue);
        await service.FinalizeAsync(ClientId, Hash("diagnostic-original-finalize"),
            FinalizeRequest(originalEntitlement.Response.EntitlementRef));

        var grant = NewUuid();
        var nextIssue = IssueRequest(Hash(grant), v2: false);
        nextIssue.Schema = DistributionInstallationBindingService.IssueV3Schema;
        nextIssue.SubjectRef = subject;
        var entitlement = await service.IssueEntitlementAsync(ClientId, Hash("diagnostic-next-issue"), nextIssue);
        var request = FinalizeRequest(entitlement.Response.EntitlementRef);
        request.Schema = DistributionInstallationBindingService.FinalizeV2Schema;
        request.AllowSameAuthorityRecovery = true;
        request.GrantRef = grant;
        request.HandoffDigestSha256 = Hash("diagnostic-next-handoff");
        request.HandoffIssuedAtUtc = "2026-07-18T18:05:00.0000000Z";
        return (service, request);
    }

    /// <summary>Simulates a broken logging provider without introducing any production or network dependency.</summary>
    private sealed class ThrowingRecoveryLogger : ILogger<DistributionInstallationBindingService>
    {
        /// <summary>No scope resources are allocated by this fault-injection sink.</summary>
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        /// <summary>Enables the diagnostic path so the write, not filtering, triggers the failure.</summary>
        public bool IsEnabled(LogLevel logLevel) => true;

        /// <summary>Throws on every write to prove logging cannot override an authority refusal.</summary>
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => throw new InvalidOperationException("Synthetic sink failure");
    }
}

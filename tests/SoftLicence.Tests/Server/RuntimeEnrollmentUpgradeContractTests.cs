using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentUpgradeContractTests
{
    private const string DesktopUpgradeAudience = "https://softlicence.app/runtime-enrollment/upgrade";
    private const string DesktopRollbackAudience = "https://softlicence.app/runtime-enrollment/recovery-rollback";

    [Fact]
    public void UpgradeContract_MatchesDesktopAndWebsiteWireIdentifiers()
    {
        Assert.Equal("runtime-enrollment-upgrade-response-v1", RuntimeEnrollmentService.UpgradeResponseSchema);
        Assert.Equal(DesktopUpgradeAudience, RuntimeEnrollmentService.UpgradeAudience);
        Assert.Equal("runtime-enrollment-upgrade", RuntimeEnrollmentService.UpgradeUse);
    }

    [Fact]
    public void UpgradeProofPayload_UsesDedicatedDesktopAudience()
    {
        var enrollmentId = Guid.Parse("11111111-2222-4333-8444-555555555555");

        var payload = RuntimeEnrollmentService.BuildProofPayload(
            "upgrade",
            enrollmentId,
            1,
            "/api/v1/runtime-enrollments/11111111-2222-4333-8444-555555555555/upgrades",
            RuntimeEnrollmentService.UpgradeAudience,
            "2026-07-24T14:18:35.0000000Z",
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "-",
            new string('f', 64));

        Assert.Equal(string.Join('\n',
            "runtime-enrollment-proof-v1",
            "PS256",
            "upgrade",
            "11111111-2222-4333-8444-555555555555",
            "1",
            "POST",
            "/api/v1/runtime-enrollments/11111111-2222-4333-8444-555555555555/upgrades",
            DesktopUpgradeAudience,
            "2026-07-24T14:18:35.0000000Z",
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "-",
            new string('f', 64)), payload);
    }

    [Fact]
    public void RollbackContract_UsesDistinctWireIdentifiersAndAudience()
    {
        Assert.Equal("runtime-enrollment-recovery-rollback-relay-v1",
            RuntimeEnrollmentService.RollbackRelaySchema);
        Assert.Equal("runtime-enrollment-recovery-rollback-authorization-v1",
            RuntimeEnrollmentService.RollbackAuthorizationSchema);
        Assert.Equal("runtime-enrollment-recovery-rollback-response-v1",
            RuntimeEnrollmentService.RollbackResponseSchema);
        Assert.Equal(DesktopRollbackAudience, RuntimeEnrollmentService.RollbackAudience);
        Assert.Equal("runtime-enrollment-recovery-rollback", RuntimeEnrollmentService.RollbackUse);
        Assert.Equal(
            "/api/v1/runtime-enrollments/11111111-2222-4333-8444-555555555555/recovery-rollbacks",
            RuntimeEnrollmentService.BuildProofPath(
                Guid.Parse("11111111-2222-4333-8444-555555555555"), "rollback"));
    }

    [Fact]
    public void UpgradeReceiptSignaturePayload_UsesWireContractIdentifiers()
    {
        var response = new RuntimeEnrollmentUpgradeResponse
        {
            Schema = RuntimeEnrollmentService.UpgradeResponseSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            Alg = "PS256",
            KeyId = "runtime-signing-1",
            Audience = RuntimeEnrollmentService.UpgradeAudience,
            Use = RuntimeEnrollmentService.UpgradeUse,
            RequestId = "11111111-1111-4111-8111-111111111111",
            ProductId = "22222222-2222-4222-8222-222222222222",
            EnrollmentId = "33333333-3333-4333-8333-333333333333",
            BindingId = "44444444-4444-4444-8444-444444444444",
            InstallationId = "55555555-5555-4555-8555-555555555555",
            SourceVersion = "2.2.916",
            TargetVersion = "2.2.924",
            OldSecurityEpoch = 1,
            NewSecurityEpoch = 2,
            RecoveryReceiptId = "66666666-6666-4666-8666-666666666666",
            RecoveryReceiptDigestSha256 = new string('a', 64),
            Decision = "upgraded",
            IssuedAtUtc = "2026-07-24T14:18:35.0000000Z",
            ExpiresAtUtc = "2026-07-24T14:28:35.0000000Z",
            Signature = string.Empty
        };

        var payload = RuntimeEnrollmentCryptoService.BuildUpgradeSignaturePayload(response);

        Assert.StartsWith(string.Join('\n',
            "runtime-enrollment-upgrade-response-v1",
            "runtime-enrollment-v1",
            "PS256",
            "runtime-signing-1",
            DesktopUpgradeAudience,
            "runtime-enrollment-upgrade") + "\n", payload, StringComparison.Ordinal);
    }
}

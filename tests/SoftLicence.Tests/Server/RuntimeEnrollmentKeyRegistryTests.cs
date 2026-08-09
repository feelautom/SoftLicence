using System.Security.Cryptography;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentKeyRegistryTests
{
    [Fact]
    public void OptionsValidator_RejectsAesMaterialAliases()
    {
        using var active = RSA.Create(3072);
        using var next = RSA.Create(3072);
        var options = CompleteOptions(active, next);
        options.Encryption.Keys.Add(new RuntimeEncryptionKeyOptions
        {
            KeyId = "enc-2026-02",
            KeyBase64 = options.Encryption.Keys[0].KeyBase64
        });

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("alias", result.FailureMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OptionsValidator_RejectsRsaMaterialAliasesAcrossKeyIds()
    {
        using var active = RSA.Create(3072);
        using var unusedNext = RSA.Create(3072);
        var options = CompleteOptions(active, unusedNext);
        options.CapabilitySigning.Keys[1].PublicKeyPem = active.ExportSubjectPublicKeyInfoPem();

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("alias", result.FailureMessage, StringComparison.OrdinalIgnoreCase);
    }

    private static RuntimeEnrollmentOptions CompleteOptions(RSA active, RSA next) => new()
    {
        Mode = "enabled",
        Issuer = "https://runtime.example.test",
        ConfirmAudience = "https://runtime.example.test",
        CanaryAudience = "https://runtime.example.test/api/health/ping",
        CanaryTriggers = ["RuntimeCheck_NativeDllSwapped"],
        IpPseudonymKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        PendingEnrollmentLimitPerBinding = 1,
        CapabilitySigning = new RuntimeCapabilitySigningOptions
        {
            ActiveKeyId = "sig-2026-01",
            Keys =
            [
                new() { KeyId = "sig-2026-01", Role = "active", PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(), PrivateKeyPem = active.ExportPkcs8PrivateKeyPem() },
                new() { KeyId = "sig-2026-02", Role = "next", PublicKeyPem = next.ExportSubjectPublicKeyInfoPem() }
            ]
        },
        Encryption = new RuntimeEncryptionOptions
        {
            ActiveKeyId = "enc-2026-01",
            Keys = [new() { KeyId = "enc-2026-01", KeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }]
        },
        Products =
        [
            new()
            {
                ProductId = "11111111-1111-4111-8111-111111111111",
                Capabilities = [new() { Audience = "https://broker.example.test", Scopes = ["runtime.execute"] }]
            }
        ]
    };
}

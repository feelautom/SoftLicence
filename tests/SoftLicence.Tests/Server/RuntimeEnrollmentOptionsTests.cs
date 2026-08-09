using System.Security.Cryptography;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentOptionsTests
{
    [Theory]
    [InlineData(120, true)]
    [InlineData(300, true)]
    [InlineData(301, false)]
    public void Validate_LicenseBootstrapCapabilityTtl_EnforcesAbsoluteFiveMinuteCeiling(
        int ttlSeconds,
        bool expectedValid)
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.LicenseBootstrapCapabilityTtlSeconds = ttlSeconds;

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.Equal(expectedValid, result.Succeeded);
    }
    [Fact]
    public void Validate_Off_AllowsNoRuntimeSecrets()
    {
        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, new RuntimeEnrollmentOptions());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_UnknownMode_FailsClosed()
    {
        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, new RuntimeEnrollmentOptions
        {
            Mode = "Enabled"
        });

        Assert.True(result.Failed);
    }

    [Fact]
    public void Validate_EnabledCompleteConfiguration_Succeeds()
    {
        using var rsa = RSA.Create(3072);
        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, ValidOptions(rsa));

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void RemoveEmptySigningKeyPlaceholders_RemovesOnlyFullyEmptyComposeSlots()
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.CapabilitySigning.Keys.Add(new RuntimeCapabilitySigningKeyOptions());
        options.CapabilitySigning.Keys.Add(new RuntimeCapabilitySigningKeyOptions { KeyId = " " });

        RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders(options);

        Assert.Equal(3, options.CapabilitySigning.Keys.Count);
        Assert.Equal(" ", options.CapabilitySigning.Keys[^1].KeyId);
        Assert.True(new RuntimeEnrollmentOptionsValidator().Validate(null, options).Failed);
    }

    [Fact]
    public void Validate_EnabledRejectsRsa2048AndNonCanonicalSecret()
    {
        using var rsa = RSA.Create(2048);
        var options = ValidOptions(rsa);
        options.IpPseudonymKeyBase64 = Convert.ToBase64String(new byte[31]);

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("RSA-3072", result.FailureMessage, StringComparison.Ordinal);
        Assert.Contains("32 bytes", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://runtime.example.test")]
    [InlineData("https://runtime.example.test/path")]
    [InlineData("https://runtime.example.test/")]
    [InlineData(" https://runtime.example.test")]
    public void Validate_EnabledRejectsNonCanonicalHttpsOrigin(string audience)
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.ConfirmAudience = audience;

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
    }

    [Fact]
    public void Validate_CapabilityTtlCannotDriftFrom120Seconds()
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.CapabilityTtlSeconds = 121;

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("exactly 120 seconds", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_EnabledRejectsIssuerAndProofAudienceDrift()
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.ConfirmAudience = "https://proof.example.test";

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("same canonical HTTPS origin", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_KeyIdCannotAliasAcrossPurposes()
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.Encryption.Keys[0].KeyId = options.CapabilitySigning.Keys[0].KeyId;
        options.Encryption.ActiveKeyId = options.Encryption.Keys[0].KeyId;

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("globally unique", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_KeyRegistryVersionMustBePositive()
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.KeyRegistryVersion = 0;

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("registry version", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_GlobalKeyIdIsReservedForRegistryVersionSentinel()
    {
        using var rsa = RSA.Create(3072);
        var options = ValidOptions(rsa);
        options.Encryption.Keys[0].KeyId = "global";
        options.Encryption.ActiveKeyId = "global";

        var result = new RuntimeEnrollmentOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("reserved", result.FailureMessage, StringComparison.Ordinal);
    }

    private static RuntimeEnrollmentOptions ValidOptions(RSA rsa) => new()
    {
        Mode = "enabled",
        Issuer = "https://runtime.example.test",
        ConfirmAudience = "https://runtime.example.test",
        CanaryAudience = "https://runtime.example.test/api/health/ping",
        CanaryTriggers = ["RuntimeCheck_NativeDllSwapped"],
        IpPseudonymKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        ChallengeTtlSeconds = 300,
        CapabilityTtlSeconds = 120,
        ProofClockSkewSeconds = 60,
        ProofNonceRetentionHours = 24,
        PendingEnrollmentLimitPerBinding = 1,
        CapabilitySigning = CreateSigningOptions(rsa),
        Encryption = new RuntimeEncryptionOptions
        {
            ActiveKeyId = "enc-2026-01",
            Keys =
            [
                new RuntimeEncryptionKeyOptions
                {
                    KeyId = "enc-2026-01",
                    KeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                }
            ]
        },
        Products =
        [
            new RuntimeProductCapabilityOptions
            {
                ProductId = "11111111-1111-4111-8111-111111111111",
                Capabilities =
                [
                    new RuntimeCapabilityGrantOptions
                    {
                        Audience = "https://broker.example.test",
                        Scopes = ["runtime.execute"]
                    }
                ]
            }
        ]
    };

    private static RuntimeCapabilitySigningOptions CreateSigningOptions(RSA active)
    {
        using var next = RSA.Create(3072);
        return new RuntimeCapabilitySigningOptions
        {
            ActiveKeyId = "runtime-2026-01",
            Keys =
            [
                new RuntimeCapabilitySigningKeyOptions
                {
                    KeyId = "runtime-2026-01",
                    Role = "active",
                    PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(),
                    PrivateKeyPem = active.ExportPkcs8PrivateKeyPem()
                },
                new RuntimeCapabilitySigningKeyOptions
                {
                    KeyId = "runtime-2026-02",
                    Role = "next",
                    PublicKeyPem = next.ExportSubjectPublicKeyInfoPem()
                }
            ]
        };
    }
}

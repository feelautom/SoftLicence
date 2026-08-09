using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class CanaryAckKeyringTests
{
    [Fact]
    public void LegacyConfiguration_PreservesInitialActiveIdentity()
    {
        using var active = RSA.Create(2048);
        var configuration = CanaryAckKeyringConfiguration.Build(new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem()
        });

        Assert.Equal(1, configuration.RegistryVersion);
        Assert.Equal(CanaryAckOptions.InitialKeyId, configuration.ActiveKeyId);
        var key = Assert.Single(configuration.Keys);
        Assert.Equal("active", key.Role);
        Assert.Equal(active.ExportSubjectPublicKeyInfo(), Convert.FromBase64String(key.PublicSpkiBase64));
    }

    [Fact]
    public void ExplicitConfiguration_ComparesCanonicalSpki_NotPemText()
    {
        using var active = RSA.Create(2048);
        var publicPemWithDifferentLineEndings = active.ExportSubjectPublicKeyInfoPem().Replace("\n", "\r\n", StringComparison.Ordinal);
        var configuration = CanaryAckKeyringConfiguration.Build(new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem(),
            Keys =
            [
                new CanaryAckPublicKeyOptions
                {
                    KeyId = CanaryAckOptions.InitialKeyId,
                    PublicKeyPem = publicPemWithDifferentLineEndings,
                    Role = "active"
                }
            ]
        });

        Assert.Equal(CanaryAckOptions.InitialKeyId, configuration.ActiveKey.KeyId);
    }

    [Fact]
    public void ExplicitConfiguration_RejectsMismatchedActiveMaterial()
    {
        using var active = RSA.Create(2048);
        using var other = RSA.Create(2048);
        var options = new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem(),
            Keys =
            [
                new CanaryAckPublicKeyOptions
                {
                    KeyId = CanaryAckOptions.InitialKeyId,
                    PublicKeyPem = other.ExportSubjectPublicKeyInfoPem(),
                    Role = "active"
                }
            ]
        };

        var exception = Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(options));
        Assert.Equal("Canary ACK active private and public keys do not match.", exception.Message);
    }

    [Fact]
    public void Configuration_RejectsPublicMaterialInPrivateField()
    {
        using var active = RSA.Create(2048);
        var options = new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportSubjectPublicKeyInfoPem()
        };

        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(options));
    }

    [Fact]
    public void ExplicitConfiguration_RejectsPrivateMaterialInPublicField()
    {
        using var active = RSA.Create(2048);
        var options = new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem(),
            Keys =
            [
                new CanaryAckPublicKeyOptions
                {
                    KeyId = CanaryAckOptions.InitialKeyId,
                    PublicKeyPem = active.ExportPkcs8PrivateKeyPem(),
                    Role = "active"
                }
            ]
        };

        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(options));
    }

    [Theory]
    [InlineData(" canary-rs256-2026-01")]
    [InlineData("canary-rs256-2026-01 ")]
    [InlineData("canary-rs256-2026-\u0131")]
    [InlineData("canary/rsa/2026")]
    [InlineData("")]
    public void KeyIds_AreExactAsciiWithoutNormalization(string keyId)
    {
        Assert.False(CanaryAckKeyringConfiguration.IsCanonicalKeyId(keyId));
    }

    [Fact]
    public void KeyIds_AreOrdinalCaseSensitive()
    {
        using var active = RSA.Create(2048);
        var options = new CanaryAckOptions
        {
            ActiveKeyId = CanaryAckOptions.InitialKeyId.ToUpperInvariant(),
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem()
        };

        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(options));
    }

    [Fact]
    public void Keyring_RejectsDuplicateRolesAndAliasedMaterial()
    {
        using var active = RSA.Create(2048);
        var options = new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem(),
            Keys =
            [
                new CanaryAckPublicKeyOptions
                {
                    KeyId = CanaryAckOptions.InitialKeyId,
                    PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(),
                    Role = "active"
                },
                new CanaryAckPublicKeyOptions
                {
                    KeyId = "canary-rs256-2026-02",
                    PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(),
                    Role = "next"
                }
            ]
        };

        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(options));
    }

    [Fact]
    public void PreviousRequiresRetention_AndOtherRolesForbidIt()
    {
        using var active = RSA.Create(2048);
        using var previous = RSA.Create(2048);
        var missingRetention = ExplicitOptions(active,
            new CanaryAckPublicKeyOptions
            {
                KeyId = "canary-rs256-2025-01",
                PublicKeyPem = previous.ExportSubjectPublicKeyInfoPem(),
                Role = "previous"
            });
        var activeRetention = ExplicitOptions(active);
        activeRetention.Keys.Single(key => key.Role == "active").RetainUntilUtc = DateTimeOffset.UtcNow.AddHours(1);

        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(missingRetention));
        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(activeRetention));
    }

    [Fact]
    public void Roles_AreMutuallyExclusiveAndComplete()
    {
        using var active = RSA.Create(2048);
        using var second = RSA.Create(2048);
        using var third = RSA.Create(2048);

        var twoActive = ExplicitOptions(active, new CanaryAckPublicKeyOptions
        {
            KeyId = "canary-rs256-2026-02",
            PublicKeyPem = second.ExportSubjectPublicKeyInfoPem(),
            Role = "active"
        });
        var twoNext = ExplicitOptions(active,
            new CanaryAckPublicKeyOptions
            {
                KeyId = "canary-rs256-2026-02",
                PublicKeyPem = second.ExportSubjectPublicKeyInfoPem(),
                Role = "next"
            },
            new CanaryAckPublicKeyOptions
            {
                KeyId = "canary-rs256-2026-03",
                PublicKeyPem = third.ExportSubjectPublicKeyInfoPem(),
                Role = "next"
            });
        var unknownRole = ExplicitOptions(active, new CanaryAckPublicKeyOptions
        {
            KeyId = "canary-rs256-2026-02",
            PublicKeyPem = second.ExportSubjectPublicKeyInfoPem(),
            Role = "retired"
        });
        var missingConfiguredActive = ExplicitOptions(active);
        missingConfiguredActive.ActiveKeyId = "canary-rs256-2026-02";

        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(twoActive));
        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(twoNext));
        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(unknownRole));
        Assert.Throws<CanaryAckConfigurationException>(() =>
            CanaryAckKeyringConfiguration.Build(missingConfiguredActive));
    }

    [Fact]
    public void PublicResolver_RefusesUnknownAndNonCanonicalKeyIds()
    {
        using var active = RSA.Create(2048);
        var keyring = new CanaryAckKeyring(Options.Create(new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem()
        }));

        Assert.True(keyring.TryGetPublicKey(CanaryAckOptions.InitialKeyId, out var published));
        Assert.Equal(CanaryAckOptions.InitialKeyId, published.KeyId);
        Assert.False(keyring.TryGetPublicKey(CanaryAckOptions.InitialKeyId.ToUpperInvariant(), out _));
        Assert.False(keyring.TryGetPublicKey(CanaryAckOptions.InitialKeyId + " ", out _));
    }

    private static CanaryAckOptions ExplicitOptions(
        RSA active,
        params CanaryAckPublicKeyOptions[] otherKeys)
    {
        var keys = new List<CanaryAckPublicKeyOptions>(otherKeys)
        {
            new()
            {
                KeyId = CanaryAckOptions.InitialKeyId,
                PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(),
                Role = "active"
            }
        };
        return new CanaryAckOptions
        {
            PrivateKeyPem = active.ExportPkcs8PrivateKeyPem(),
            Keys = keys.OrderBy(key => key.KeyId, StringComparer.Ordinal).ToList()
        };
    }
}

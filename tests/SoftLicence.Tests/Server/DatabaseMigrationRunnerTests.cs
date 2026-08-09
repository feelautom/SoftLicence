using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using SoftLicence.Server;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class DatabaseMigrationRunnerTests
{
    [Fact]
    public async Task RunAsync_WithoutMigrationConnection_FailsBeforeDatabaseAccess()
    {
        var configuration = new ConfigurationBuilder().Build();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DatabaseMigrationRunner.RunAsync(configuration));

        Assert.Contains("MigrationConnection", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_WithApplicationRole_FailsBeforeDatabaseAccess()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:MigrationConnection"] =
                    "Host=unreachable.invalid;Database=db_softlicence;Username=softlicence_app;Password=opaque"
            })
            .Build();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DatabaseMigrationRunner.RunAsync(configuration));

        Assert.Contains("must not run as the application role", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RuntimeKeyRegistryOperatorRunner_NonExactMode_FailsBeforeDatabaseAccess()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Database:RuntimeKeyRegistryOperator:Mode"] = "Execute"
            })
            .Build();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => RuntimeEnrollmentKeyRegistryOperatorRunner.RunAsync(configuration));

        Assert.Contains("mode must be exact", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RuntimeKeyRegistryOperator_ExecuteWithoutExactConfirmation_FailsBeforeDatabaseAccess()
    {
        using var active = RSA.Create(3072);
        using var next = RSA.Create(3072);
        var options = ValidRuntimeOptions(active, next);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RuntimeEnrollmentKeyRegistryOperator.RunAsync(
                "Host=unreachable.invalid;Database=db_softlicence;Username=authority;Password=opaque",
                options,
                1,
                true,
                "apply"));

        Assert.Contains("execute confirmation is invalid", exception.Message, StringComparison.Ordinal);
    }

    private static RuntimeEnrollmentOptions ValidRuntimeOptions(RSA active, RSA next)
    {
        var activeId = "runtime-test-active";
        var nextId = "runtime-test-next";
        return new RuntimeEnrollmentOptions
        {
            Mode = "enabled",
            Issuer = "https://runtime.example.test",
            ConfirmAudience = "https://runtime.example.test",
            CanaryAudience = "https://runtime.example.test/api/health/ping",
            CanaryTriggers = ["RuntimeCheck_Test"],
            IpPseudonymKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            CapabilitySigning = new RuntimeCapabilitySigningOptions
            {
                ActiveKeyId = activeId,
                Keys =
                [
                    new()
                    {
                        KeyId = activeId,
                        Role = "active",
                        PublicKeyPem = active.ExportSubjectPublicKeyInfoPem(),
                        PrivateKeyPem = active.ExportPkcs8PrivateKeyPem()
                    },
                    new()
                    {
                        KeyId = nextId,
                        Role = "next",
                        PublicKeyPem = next.ExportSubjectPublicKeyInfoPem()
                    }
                ]
            },
            Encryption = new RuntimeEncryptionOptions
            {
                ActiveKeyId = "runtime-test-encryption",
                Keys =
                [
                    new()
                    {
                        KeyId = "runtime-test-encryption",
                        KeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                    }
                ]
            },
            Products =
            [
                new()
                {
                    ProductId = Guid.NewGuid().ToString("D"),
                    Capabilities =
                    [
                        new()
                        {
                            Audience = "https://runtime.example.test",
                            Scopes = ["runtime.execute"]
                        }
                    ]
                }
            ]
        };
    }
}

using System;
using System.IO;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class DeploymentConfigurationTests
{
    private const string BootstrapEnvironmentName =
        "DistributionS2S__Clients__0__AllowLicenseBootstrap";
    private const string CanaryAckPrivateKeyEnvironmentName = "CanaryAck__PrivateKeyPem";

    [Fact]
    public void DockerCompose_WiresCanaryAckPrivateKeyToMigratorAndServerWithoutDefaultMaterial()
    {
        var compose = ReadProjectFile("Docker/docker-compose.yml");
        var expected =
            $"- {CanaryAckPrivateKeyEnvironmentName}=${{{CanaryAckPrivateKeyEnvironmentName}:-}}";
        var migratorStart = compose.IndexOf("\n  migrator:", StringComparison.Ordinal);
        var serverStart = compose.IndexOf("\n  server:", StringComparison.Ordinal);

        Assert.True(migratorStart >= 0);
        Assert.True(serverStart > migratorStart);
        Assert.Equal(2, CountOrdinal(compose, expected));
        Assert.Equal(4, CountOrdinal(compose, CanaryAckPrivateKeyEnvironmentName));
        Assert.Equal(1, CountOrdinal(compose[migratorStart..serverStart], expected));
        Assert.Equal(1, CountOrdinal(compose[serverStart..], expected));
    }

    [Fact]
    public void DockerCompose_WiresBootstrapPermissionToMigratorAndServerFailClosed()
    {
        var compose = ReadProjectFile("Docker/docker-compose.yml");
        var expected = $"- {BootstrapEnvironmentName}=${{{BootstrapEnvironmentName}:-false}}";

        Assert.Equal(2, CountOrdinal(compose, expected));
        Assert.DoesNotContain($"${{{BootstrapEnvironmentName}:-true}}", compose,
            StringComparison.Ordinal);
    }

    [Fact]
    public void DockerCompose_WiresRuntimeSigningRotationContractToMigratorAndServer()
    {
        var compose = ReadProjectFile("Docker/docker-compose.yml");
        var migratorStart = compose.IndexOf("\n  migrator:", StringComparison.Ordinal);
        var serverStart = compose.IndexOf("\n  server:", StringComparison.Ordinal);
        Assert.True(migratorStart >= 0);
        Assert.True(serverStart > migratorStart);

        var names = new List<string>
        {
            "RuntimeEnrollment__KeyRegistryVersion"
        };
        for (var index = 0; index < 3; index++)
        {
            names.Add($"RuntimeEnrollment__CapabilitySigning__Keys__{index}__KeyId");
            names.Add($"RuntimeEnrollment__CapabilitySigning__Keys__{index}__Role");
            names.Add($"RuntimeEnrollment__CapabilitySigning__Keys__{index}__PublicKeyPem");
            names.Add($"RuntimeEnrollment__CapabilitySigning__Keys__{index}__PrivateKeyPem");
            names.Add($"RuntimeEnrollment__CapabilitySigning__Keys__{index}__RetainUntilUtc");
        }

        foreach (var name in names)
        {
            var defaultValue = name.EndsWith("KeyRegistryVersion", StringComparison.Ordinal)
                ? "1"
                : string.Empty;
            var expected = $"- {name}=${{{name}:-{defaultValue}}}";
            Assert.Equal(2, CountOrdinal(compose, expected));
            Assert.Equal(1, CountOrdinal(compose[migratorStart..serverStart], expected));
            Assert.Equal(1, CountOrdinal(compose[serverStart..], expected));
        }

        Assert.DoesNotContain("PRIVATE KEY-----", compose, StringComparison.Ordinal);
        Assert.DoesNotContain("PUBLIC KEY-----", compose, StringComparison.Ordinal);
    }

    /// <summary>
    /// Requires both startup roles to receive every authority-generation setting without embedded key material.
    /// </summary>
    [Fact]
    public void DockerCompose_WiresAuthorityGenerationV2ContractToMigratorAndServer()
    {
        var compose = ReadProjectFile("Docker/docker-compose.yml");
        var migratorStart = compose.IndexOf("\n  migrator:", StringComparison.Ordinal);
        var serverStart = compose.IndexOf("\n  server:", StringComparison.Ordinal);
        Assert.True(migratorStart >= 0);
        Assert.True(serverStart > migratorStart);

        var names = new List<string>
        {
            "RuntimeEnrollment__AuthorityGenerationSigning__ActiveSigningKeyId",
            "RuntimeEnrollment__AuthorityGenerationSigning__RegistrySnapshotId",
            "RuntimeEnrollment__AuthorityGenerationSigning__RegistrySnapshotVersion",
            "RuntimeEnrollment__AuthorityGenerationV2__Mode",
            "RuntimeEnrollment__AuthorityGenerationV2__RegistryAuthoritySpkiBase64",
            "RuntimeEnrollment__AuthorityGenerationV2__RegistrySnapshotSignatureBase64Url",
            "RuntimeEnrollment__AuthorityGenerationV2__RegistryObservedAtUtc"
        };
        for (var index = 0; index < 3; index++)
        {
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__KeyId");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__Purpose");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__Domain");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__ContractVersion");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__Status");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__PublicKeyPem");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__PrivateKeyPem");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__ActivatedAtUtc");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__RetiredAtUtc");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__RevokedAtUtc");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__RevocationReason");
            names.Add($"RuntimeEnrollment__AuthorityGenerationSigning__Keys__{index}__CompromiseFromUtc");
        }

        foreach (var name in names)
        {
            var defaultValue =
                name.EndsWith("AuthorityGenerationV2__Mode", StringComparison.Ordinal) ? "off" :
                name.EndsWith("RegistrySnapshotVersion", StringComparison.Ordinal) ? "0" :
                name.EndsWith("ContractVersion", StringComparison.Ordinal) ? "2" :
                name.EndsWith("ActivatedAtUtc", StringComparison.Ordinal)
                    ? "0001-01-01T00:00:00.0000000+00:00"
                    : string.Empty;
            var expected = $"- {name}=${{{name}:-{defaultValue}}}";
            Assert.Equal(2, CountOrdinal(compose, expected));
            Assert.Equal(1, CountOrdinal(compose[migratorStart..serverStart], expected));
            Assert.Equal(1, CountOrdinal(compose[serverStart..], expected));
        }

        Assert.DoesNotContain("PRIVATE KEY-----", compose, StringComparison.Ordinal);
        Assert.DoesNotContain("PUBLIC KEY-----", compose, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "PrivateRepository")]
    public void DeployScript_ValidatesAndVerifiesBootstrapPermissionWithoutPrintingValue()
    {
        var deploy = ReadProjectFile("deploy.ps1");

        Assert.Contains($"{BootstrapEnvironmentName} must be canonical true or false", deploy,
            StringComparison.Ordinal);
        Assert.Contains($"printenv {BootstrapEnvironmentName}", deploy,
            StringComparison.Ordinal);
        Assert.Contains("{{range .Config.Env}}{{println .}}{{end}}", deploy,
            StringComparison.Ordinal);
        Assert.Contains("Container license bootstrap permission mismatch", deploy,
            StringComparison.Ordinal);
        Assert.Contains("Migrator license bootstrap permission mismatch", deploy,
            StringComparison.Ordinal);
        Assert.Contains($"{BootstrapEnvironmentName}=<verified>", deploy,
            StringComparison.Ordinal);
        Assert.DoesNotContain($"echo \"{BootstrapEnvironmentName}=$EXPECTED_LICENSE_BOOTSTRAP\"", deploy,
            StringComparison.Ordinal);
        Assert.True(CountOrdinal(deploy, BootstrapEnvironmentName) >= 11,
            "The deployment must validate local compose, Docker env/source, server and migrator wiring.");
    }

    private static string ReadProjectFile(string relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null &&
               !File.Exists(Path.Combine(directory.FullName, "src", "SoftLicence.sln")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        var path = Path.Combine(directory!.FullName,
            relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(path), $"Required project file not found: {relativePath}");
        return File.ReadAllText(path);
    }

    private static int CountOrdinal(string value, string expected)
    {
        var count = 0;
        var offset = 0;
        while ((offset = value.IndexOf(expected, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += expected.Length;
        }
        return count;
    }
}

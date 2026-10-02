using System.Security.Cryptography;
using System.Globalization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
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

    /// <summary>Collapses only wholly absent authority slots while preserving partial invalid input.</summary>
    [Fact]
    public void RemoveEmptySigningKeyPlaceholders_PreservesPartialAuthorityConfigurationForValidation()
    {
        var options = new RuntimeEnrollmentOptions
        {
            AuthorityGenerationSigning = new RuntimeAuthorityGenerationSigningOptions
            {
                Keys =
                [
                    new RuntimeAuthorityGenerationKeyOptions(),
                    new RuntimeAuthorityGenerationKeyOptions { KeyId = " " }
                ]
            }
        };

        RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders(options);

        Assert.NotNull(options.AuthorityGenerationSigning);
        Assert.Single(options.AuthorityGenerationSigning.Keys);
        Assert.Equal(" ", options.AuthorityGenerationSigning.Keys[0].KeyId);
        Assert.True(new RuntimeEnrollmentOptionsValidator().Validate(null, options).Failed);

        options.AuthorityGenerationSigning.Keys.Clear();
        RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders(options);
        Assert.Null(options.AuthorityGenerationSigning);
    }

    /// <summary>Requires the exact disabled Compose placeholders to bind and start without creating authority.</summary>
    [Fact]
    public async Task Startup_EmptyAuthorityComposePlaceholders_DefaultOffSucceeds()
    {
        var values = new Dictionary<string, string?>
        {
            ["RuntimeEnrollment:AuthorityGenerationSigning:ActiveSigningKeyId"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:RegistrySnapshotId"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:RegistrySnapshotVersion"] = "0",
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:KeyId"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:Purpose"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:Domain"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:ContractVersion"] = "2",
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:Status"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:PublicKeyPem"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:PrivateKeyPem"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:ActivatedAtUtc"] =
                "0001-01-01T00:00:00.0000000+00:00",
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:RetiredAtUtc"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:RevokedAtUtc"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:RevocationReason"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationSigning:Keys:0:CompromiseFromUtc"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationV2:Mode"] = "off",
            ["RuntimeEnrollment:AuthorityGenerationV2:RegistryAuthoritySpkiBase64"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationV2:RegistrySnapshotSignatureBase64Url"] = string.Empty,
            ["RuntimeEnrollment:AuthorityGenerationV2:RegistryObservedAtUtc"] = string.Empty
        };

        using var host = await StartBoundOptionsAsync(values);

        Assert.Null(host.Services.GetRequiredService<IOptions<RuntimeEnrollmentOptions>>().Value
            .AuthorityGenerationSigning);
    }

    /// <summary>Requires enabled startup to reject an absent authority-generation registry.</summary>
    [Fact]
    public async Task Startup_AuthorityGenerationV2EnabledWithoutAuthorityConfiguration_FailsClosed()
    {
        var failure = await Assert.ThrowsAsync<OptionsValidationException>(() => StartBoundOptionsAsync(
            new Dictionary<string, string?>
            {
                ["RuntimeEnrollment:Mode"] = "enabled",
                ["RuntimeEnrollment:AuthorityGenerationV2:Mode"] = "enabled"
            }));

        Assert.Contains("canonical registry authentication metadata", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>Requires enabled startup to reject a registry authority that aliases an operational signer.</summary>
    [Fact]
    public async Task Startup_AuthorityGenerationV2WithAliasedRegistryAuthority_FailsClosed()
    {
        using var fixture = CreateValidAuthorityGenerationFixture();
        var values = CreateConfigurationValues(fixture.Options);
        values["RuntimeEnrollment:AuthorityGenerationV2:RegistryAuthoritySpkiBase64"] =
            Convert.ToBase64String(ExportSubjectPublicKeyInfo(
                fixture.Options.AuthorityGenerationSigning!.Keys[0].PublicKeyPem));

        var failure = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            StartBoundOptionsAsync(values));

        Assert.Contains("separate from operational and recovery keys", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>Requires all 43 authority variables to bind and pass startup with synthetic key material.</summary>
    [Fact]
    public async Task Startup_CompleteBoundAuthorityGenerationV2Configuration_Succeeds()
    {
        using var fixture = CreateValidAuthorityGenerationFixture();
        var values = CreateConfigurationValues(fixture.Options);
        Assert.Equal(43, values.Keys.Count(key =>
            key.StartsWith("RuntimeEnrollment:AuthorityGenerationSigning:", StringComparison.Ordinal)
            || key.StartsWith("RuntimeEnrollment:AuthorityGenerationV2:", StringComparison.Ordinal)));

        using var host = await StartBoundOptionsAsync(values);
        var bound = host.Services.GetRequiredService<IOptions<RuntimeEnrollmentOptions>>().Value;

        Assert.Equal("enabled", bound.AuthorityGenerationV2.Mode);
        Assert.Equal(2, bound.AuthorityGenerationSigning!.Keys.Count);
        Assert.Equal(fixture.Options.AuthorityGenerationSigning!.Keys[0].PrivateKeyPem,
            bound.AuthorityGenerationSigning.Keys[0].PrivateKeyPem);
        Assert.Equal(fixture.Options.AuthorityGenerationSigning.Keys[1].ActivatedAtUtc,
            bound.AuthorityGenerationSigning.Keys[1].ActivatedAtUtc);
    }

    /// <summary>Starts the production binding and validation chain against exact in-memory environment values.</summary>
    /// <param name="configurationValues">
    /// Caller-owned exact configuration values; the helper reads them without mutation.
    /// </param>
    /// <returns>
    /// A started host owned by the caller, which must dispose it. Failed startup disposes the host
    /// before propagating the original exception.
    /// </returns>
    /// <exception cref="OptionsValidationException">Thrown when bound Runtime options fail startup validation.</exception>
    /// <exception cref="InvalidOperationException">Propagated when configuration binding or host startup fails.</exception>
    private static async Task<IHost> StartBoundOptionsAsync(
        IReadOnlyDictionary<string, string?> configurationValues)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configurationValues)
            .Build();
        var host = Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddSingleton<IValidateOptions<RuntimeEnrollmentOptions>, RuntimeEnrollmentOptionsValidator>();
                services.AddOptions<RuntimeEnrollmentOptions>()
                    .Bind(configuration.GetSection("RuntimeEnrollment"))
                    .PostConfigure(RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders)
                    .ValidateOnStart();
            })
            .Build();
        try
        {
            await host.StartAsync();
            return host;
        }
        catch
        {
            host.Dispose();
            throw;
        }
    }

    /// <summary>Flattens the complete fixture into the same configuration keys supplied by Compose.</summary>
    /// <param name="options">Complete test-owned Runtime options, read without mutation.</param>
    /// <returns>
    /// A new caller-owned dictionary containing exact test-only configuration strings, including
    /// ephemeral PEM material, array indexes, nullable placeholders, and round-trip timestamps.
    /// </returns>
    private static Dictionary<string, string?> CreateConfigurationValues(RuntimeEnrollmentOptions options)
    {
        var values = new Dictionary<string, string?>
        {
            ["RuntimeEnrollment:Mode"] = options.Mode,
            ["RuntimeEnrollment:Issuer"] = options.Issuer,
            ["RuntimeEnrollment:ConfirmAudience"] = options.ConfirmAudience,
            ["RuntimeEnrollment:CanaryAudience"] = options.CanaryAudience,
            ["RuntimeEnrollment:ChallengeTtlSeconds"] =
                options.ChallengeTtlSeconds.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:CapabilityTtlSeconds"] =
                options.CapabilityTtlSeconds.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:LicenseBootstrapCapabilityTtlSeconds"] =
                options.LicenseBootstrapCapabilityTtlSeconds.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:ProofClockSkewSeconds"] =
                options.ProofClockSkewSeconds.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:ProofNonceRetentionHours"] =
                options.ProofNonceRetentionHours.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:PendingEnrollmentLimitPerBinding"] =
                options.PendingEnrollmentLimitPerBinding.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:LockTimeoutMilliseconds"] =
                options.LockTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:StatementTimeoutMilliseconds"] =
                options.StatementTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:MaximumTransactionAttempts"] =
                options.MaximumTransactionAttempts.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:KeyRegistryVersion"] =
                options.KeyRegistryVersion.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:IpPseudonymKeyBase64"] = options.IpPseudonymKeyBase64,
            ["RuntimeEnrollment:CapabilitySigning:ActiveKeyId"] = options.CapabilitySigning.ActiveKeyId,
            ["RuntimeEnrollment:Encryption:ActiveKeyId"] = options.Encryption.ActiveKeyId,
            ["RuntimeEnrollment:Products:0:ProductId"] = options.Products[0].ProductId,
            ["RuntimeEnrollment:Products:0:Capabilities:0:Audience"] =
                options.Products[0].Capabilities[0].Audience,
            ["RuntimeEnrollment:AuthorityGenerationSigning:ActiveSigningKeyId"] =
                options.AuthorityGenerationSigning!.ActiveSigningKeyId,
            ["RuntimeEnrollment:AuthorityGenerationSigning:RegistrySnapshotId"] =
                options.AuthorityGenerationSigning.RegistrySnapshotId,
            ["RuntimeEnrollment:AuthorityGenerationSigning:RegistrySnapshotVersion"] =
                options.AuthorityGenerationSigning.RegistrySnapshotVersion.ToString(CultureInfo.InvariantCulture),
            ["RuntimeEnrollment:AuthorityGenerationV2:Mode"] = options.AuthorityGenerationV2.Mode,
            ["RuntimeEnrollment:AuthorityGenerationV2:RegistryAuthoritySpkiBase64"] =
                options.AuthorityGenerationV2.RegistryAuthoritySpkiBase64,
            ["RuntimeEnrollment:AuthorityGenerationV2:RegistrySnapshotSignatureBase64Url"] =
                options.AuthorityGenerationV2.RegistrySnapshotSignatureBase64Url,
            ["RuntimeEnrollment:AuthorityGenerationV2:RegistryObservedAtUtc"] =
                options.AuthorityGenerationV2.RegistryObservedAtUtc
        };

        for (var index = 0; index < options.CanaryTriggers.Count; index++)
            values[$"RuntimeEnrollment:CanaryTriggers:{index}"] = options.CanaryTriggers[index];
        for (var index = 0; index < options.CapabilitySigning.Keys.Count; index++)
        {
            var key = options.CapabilitySigning.Keys[index];
            var prefix = $"RuntimeEnrollment:CapabilitySigning:Keys:{index}";
            values[$"{prefix}:KeyId"] = key.KeyId;
            values[$"{prefix}:Role"] = key.Role;
            values[$"{prefix}:PublicKeyPem"] = key.PublicKeyPem;
            values[$"{prefix}:PrivateKeyPem"] = key.PrivateKeyPem ?? string.Empty;
            values[$"{prefix}:RetainUntilUtc"] =
                key.RetainUntilUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
        }
        for (var index = 0; index < options.Encryption.Keys.Count; index++)
        {
            var key = options.Encryption.Keys[index];
            values[$"RuntimeEnrollment:Encryption:Keys:{index}:KeyId"] = key.KeyId;
            values[$"RuntimeEnrollment:Encryption:Keys:{index}:KeyBase64"] = key.KeyBase64;
        }
        for (var index = 0; index < options.Products[0].Capabilities[0].Scopes.Count; index++)
        {
            values[$"RuntimeEnrollment:Products:0:Capabilities:0:Scopes:{index}"] =
                options.Products[0].Capabilities[0].Scopes[index];
        }
        for (var index = 0; index < 3; index++)
        {
            var key = index < options.AuthorityGenerationSigning.Keys.Count
                ? options.AuthorityGenerationSigning.Keys[index]
                : new RuntimeAuthorityGenerationKeyOptions();
            var prefix = $"RuntimeEnrollment:AuthorityGenerationSigning:Keys:{index}";
            values[$"{prefix}:KeyId"] = key.KeyId;
            values[$"{prefix}:Purpose"] = key.Purpose;
            values[$"{prefix}:Domain"] = key.Domain;
            values[$"{prefix}:ContractVersion"] = key.ContractVersion.ToString(CultureInfo.InvariantCulture);
            values[$"{prefix}:Status"] = key.Status;
            values[$"{prefix}:PublicKeyPem"] = key.PublicKeyPem;
            values[$"{prefix}:PrivateKeyPem"] = key.PrivateKeyPem ?? string.Empty;
            values[$"{prefix}:ActivatedAtUtc"] = key.ActivatedAtUtc.ToString("O", CultureInfo.InvariantCulture);
            values[$"{prefix}:RetiredAtUtc"] =
                key.RetiredAtUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            values[$"{prefix}:RevokedAtUtc"] =
                key.RevokedAtUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            values[$"{prefix}:RevocationReason"] = key.RevocationReason ?? string.Empty;
            values[$"{prefix}:CompromiseFromUtc"] =
                key.CompromiseFromUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
        }

        return values;
    }

    /// <summary>Creates a complete valid provider configuration from ephemeral test-only RSA material.</summary>
    /// <returns>
    /// A caller-owned fixture that owns every generated RSA instance and must be disposed after use.
    /// </returns>
    /// <exception cref="CryptographicException">Thrown when ephemeral RSA generation, export, or signing fails.</exception>
    private static AuthorityGenerationFixture CreateValidAuthorityGenerationFixture()
    {
        var observed = new DateTimeOffset(2026, 8, 31, 0, 0, 0, TimeSpan.Zero);
        var registry = RSA.Create(2048);
        var operational = RSA.Create(2048);
        var recovery = RSA.Create(2048);
        var capability = RSA.Create(3072);
        var options = ValidOptions(capability);
        var signing = new RuntimeAuthorityGenerationSigningOptions
        {
            ActiveSigningKeyId = "operational-2026-01",
            RegistrySnapshotId = "authority-registry-2026-01",
            RegistrySnapshotVersion = 1,
            Keys =
            [
                CreateAuthorityKey("operational-2026-01", "operational", "generation", operational,
                    observed.AddDays(-1), operational.ExportPkcs8PrivateKeyPem()),
                CreateAuthorityKey("recovery-2026-01", "recovery", "recovery", recovery,
                    observed.AddDays(-1), null)
            ]
        };
        var cryptography = new RuntimeEnrollmentAuthorityCryptography(
            new FixedTimeProvider(observed), registry.ExportSubjectPublicKeyInfo());
        var authenticationInput = cryptography.GetRegistrySnapshotAuthenticationInput(signing, observed).Value!;
        options.AuthorityGenerationSigning = signing;
        options.AuthorityGenerationV2 = new RuntimeAuthorityGenerationV2Options
        {
            Mode = "enabled",
            RegistryAuthoritySpkiBase64 = Convert.ToBase64String(registry.ExportSubjectPublicKeyInfo()),
            RegistryObservedAtUtc = observed.ToString("O"),
            RegistrySnapshotSignatureBase64Url = EncodeBase64Url(registry.SignData(
                authenticationInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        };
        return new AuthorityGenerationFixture(options, registry, operational, recovery, capability);
    }

    /// <summary>Creates one exact RSA-2048 authority key entry.</summary>
    /// <param name="keyId">Exact opaque key identifier.</param>
    /// <param name="purpose">Exact closed operational or recovery purpose.</param>
    /// <param name="domain">Exact closed generation or recovery signing domain.</param>
    /// <param name="rsa">Caller-owned RSA instance read only to export public material.</param>
    /// <param name="activatedAtUtc">Exact UTC activation instant.</param>
    /// <param name="privateKeyPem">Optional test-only private PEM owned by the caller.</param>
    /// <returns>A new caller-owned authority key options entry.</returns>
    /// <exception cref="CryptographicException">Thrown when RSA public-key export fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when <paramref name="rsa"/> is already disposed.</exception>
    private static RuntimeAuthorityGenerationKeyOptions CreateAuthorityKey(
        string keyId,
        string purpose,
        string domain,
        RSA rsa,
        DateTimeOffset activatedAtUtc,
        string? privateKeyPem) => new()
    {
        KeyId = keyId,
        Purpose = purpose,
        Domain = domain,
        ContractVersion = 2,
        Status = "active",
        PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
        PrivateKeyPem = privateKeyPem,
        ActivatedAtUtc = activatedAtUtc
    };

    /// <summary>Exports a canonical SPKI from one exact PEM value.</summary>
    /// <param name="publicKeyPem">Exact test-only public PEM to import without normalization.</param>
    /// <returns>A new caller-owned SPKI byte array.</returns>
    /// <exception cref="ArgumentException">Thrown when the PEM label or payload is invalid.</exception>
    /// <exception cref="CryptographicException">Thrown when RSA import or SPKI export fails.</exception>
    private static byte[] ExportSubjectPublicKeyInfo(string publicKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        return rsa.ExportSubjectPublicKeyInfo();
    }

    /// <summary>Encodes canonical unpadded Base64Url fixture bytes.</summary>
    /// <param name="bytes">Caller-owned bytes read without mutation.</param>
    /// <returns>A newly allocated canonical unpadded Base64Url string.</returns>
    private static string EncodeBase64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Supplies one immutable instant for the synthetic registry proof.</summary>
    /// <param name="now">Exact immutable UTC fixture instant returned by <see cref="GetUtcNow"/>.</param>
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        /// <inheritdoc />
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>Owns and clears all ephemeral RSA material used by the positive startup fixture.</summary>
    /// <param name="options">Fixture options retained for read-only test assertions.</param>
    /// <param name="registry">Registry-authority RSA instance transferred to this fixture.</param>
    /// <param name="operational">Operational-signing RSA instance transferred to this fixture.</param>
    /// <param name="recovery">Recovery-signing RSA instance transferred to this fixture.</param>
    /// <param name="capability">Capability-signing RSA instance transferred to this fixture.</param>
    private sealed class AuthorityGenerationFixture(
        RuntimeEnrollmentOptions options,
        RSA registry,
        RSA operational,
        RSA recovery,
        RSA capability) : IDisposable
    {
        /// <summary>Gets the fixture-owned Runtime options graph for read-only test use.</summary>
        internal RuntimeEnrollmentOptions Options { get; } = options;

        /// <inheritdoc />
        public void Dispose()
        {
            registry.Dispose();
            operational.Dispose();
            recovery.Dispose();
            capability.Dispose();
        }
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

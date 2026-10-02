using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    /// <summary>
    /// Proves the production Website PS256 client reaches the real SoftLicence controller,
    /// authentication service, authority resolver, and PostgreSQL graph without a mocked response.
    /// The same process then changes the graph to the authenticated alias-seat topology and proves
    /// that both same-target paths return none while a different eligible target remains fail-closed.
    /// </summary>
    [Fact]
    public async Task Tkt000617_WebsiteToSoftLicenceHttp_ResolvesSameTargetAndAliasWithoutMock()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        using var websiteSigningKey = RSA.Create(3072);
        using var loopbackCertificate = CreateLoopbackCertificate();
        var temporary = Directory.CreateTempSubdirectory("softlicence-tkt000617-http-");
        try
        {
            var privateKeyPath = Path.Combine(temporary.FullName, "website-s2s.pkcs8.pem");
            var certificatePath = Path.Combine(temporary.FullName, "loopback-ca.pem");
            await File.WriteAllTextAsync(privateKeyPath, websiteSigningKey.ExportPkcs8PrivateKeyPem());
            await File.WriteAllTextAsync(certificatePath, loopbackCertificate.Certificate.ExportCertificatePem());

            var authority = await ReadHttpAuthorityAsync(scenario);
            var conflictLicenseId = await AddEligibleConflictTargetAsync(scenario, authority.LicenseId);
            using var factory = CreateTkt000617ProviderFactory(
                scenario, websiteSigningKey.ExportSubjectPublicKeyInfoPem());
            using var providerClient = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost")
            });
            await using var proxy = await StartHttpsProxyAsync(providerClient, loopbackCertificate.Certificate);

            await RunWebsiteProbeAsync(new WebsiteProbeInput(
                "direct",
                proxy.BaseAddress,
                privateKeyPath,
                certificatePath,
                authority.ProductId,
                authority.LicenseId,
                conflictLicenseId,
                authority.HardwareId));

            await ConvertScenarioToAliasSeatTransitionAsync(scenario);
            await RunWebsiteProbeAsync(new WebsiteProbeInput(
                "alias",
                proxy.BaseAddress,
                privateKeyPath,
                certificatePath,
                authority.ProductId,
                authority.LicenseId,
                null,
                LegacyHardwareId));
        }
        finally
        {
            temporary.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Reads the exact product, licence, and hardware authority selected by the prepared relational
    /// fixture. Values remain canonical or opaque and are never recased or trimmed for the probe.
    /// </summary>
    private static async Task<HttpAuthority> ReadHttpAuthorityAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
        var seat = await db.LicenseSeats.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == binding.LicenseSeatId);
        return new HttpAuthority(
            binding.ProductId.ToString("D"),
            binding.LicenseId.ToString("D"),
            seat.HardwareId);
    }

    /// <summary>
    /// Adds one eligible target licence for the same product without creating hardware authority.
    /// Resolving the existing active binding against this target must remain a bounded conflict.
    /// </summary>
    private static async Task<string> AddEligibleConflictTargetAsync(
        PreparedBootstrapScenario scenario,
        string sourceLicenseId)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var source = await db.Licenses.AsNoTracking()
            .SingleAsync(candidate => candidate.Id == Guid.Parse(sourceLicenseId));
        var conflict = new License
        {
            LicenseKey = $"TKT617-HTTP-{Guid.NewGuid():N}",
            CustomerName = "TKT-000617 HTTP fixture",
            CustomerEmail = "tkt000617-http@example.test",
            LicenseTypeId = source.LicenseTypeId,
            CreationDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddDays(1),
            IsActive = true,
            AllowedVersions = source.AllowedVersions,
            MaxSeats = 1,
            ProductId = source.ProductId
        };
        db.Licenses.Add(conflict);
        await db.SaveChangesAsync();
        return conflict.Id.ToString("D");
    }

    /// <summary>
    /// Converts the direct authority into the confirmed V2-unlinked plus legacy-seat-reactivated
    /// topology. The authenticated alias remains the only recoverable binding and seat identity.
    /// </summary>
    private static async Task ConvertScenarioToAliasSeatTransitionAsync(PreparedBootstrapScenario scenario)
    {
        var subjectRef = Base64Url(SHA256.HashData("tkt000617-http-alias-subject"u8.ToArray()));
        await SetScenarioSubjectAuthorityAsync(scenario, subjectRef);
        await MigrateScenarioAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var sourceBinding = await db.DistributionInstallationBindings
            .SingleAsync(candidate => candidate.Id == scenario.Fixture.BindingId);
        var sourceEnrollment = await db.RuntimeEnrollments
            .SingleAsync(candidate => candidate.Id == scenario.EnrollmentId);
        var sourceSeat = await db.LicenseSeats
            .SingleAsync(candidate => candidate.Id == sourceBinding.LicenseSeatId);
        sourceSeat.IsActive = false;
        sourceSeat.UnlinkedAt = DateTime.UtcNow.AddMinutes(-5);
        sourceBinding.State = "invalidated";
        sourceBinding.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
        sourceBinding.InvalidationReason = "seat_ineligible";
        sourceEnrollment.State = "INVALIDATED";
        sourceEnrollment.InvalidatedAtUtc = DateTime.UtcNow.AddMinutes(-4);
        sourceEnrollment.InvalidationReason = "seat_ineligible";
        db.LicenseSeats.Add(new LicenseSeat
        {
            LicenseId = sourceBinding.LicenseId,
            HardwareId = LegacyHardwareId,
            IsActive = true,
            FirstActivatedAt = DateTime.UtcNow.AddMinutes(-3),
            LastCheckInAt = DateTime.UtcNow.AddMinutes(-3),
            AppVersion = scenario.Fixture.Version
        });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Builds the real provider application with production S2S authentication and authority
    /// services, replacing only infrastructure with the isolated PostgreSQL fixture and ephemeral
    /// data protection. No resolver, controller, or provider decision is mocked.
    /// </summary>
    private static WebApplicationFactory<Program> CreateTkt000617ProviderFactory(
        PreparedBootstrapScenario scenario,
        string websitePublicKeyPem)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("DistributionS2S:RequireHttps", "true");
            builder.UseSetting("DistributionS2S:ClockSkewSeconds", "60");
            builder.UseSetting("DistributionS2S:NonceRetentionHours", "24");
            builder.UseSetting("DistributionS2S:Clients:0:ClientId", "website-runtime-v1");
            builder.UseSetting("DistributionS2S:Clients:0:KeyId", "website-runtime-test-1");
            builder.UseSetting("DistributionS2S:Clients:0:PublicKeyPem", websitePublicKeyPem);
            builder.UseSetting("DistributionS2S:Clients:0:Enabled", "true");
            builder.UseSetting("DistributionS2S:Clients:0:ProductIds:0", scenario.Fixture.ProductId.ToString("D"));
            builder.UseSetting("DistributionS2S:Clients:0:AllowedCidrs:0", "127.0.0.1/32");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.RemoveAll<LicenseDbContext>();
                services.RemoveAll<IDataProtectionProvider>();
                services.RemoveAll<IHostedService>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseNpgsql(scenario.AppConnectionString));
                services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                services.AddSingleton<IStartupFilter, LoopbackRemoteAddressStartupFilter>();
            });
        });
    }

    /// <summary>
    /// Selects the valid local ASP.NET development certificate on Windows or creates a short-lived
    /// fallback certificate elsewhere. Only its public certificate is shared with the Node probe.
    /// </summary>
    private static LoopbackCertificate CreateLoopbackCertificate()
    {
        if (OperatingSystem.IsWindows())
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var developmentCertificate = store.Certificates
                .Where(certificate =>
                    certificate.HasPrivateKey
                    && certificate.NotBefore <= DateTime.Now
                    && certificate.NotAfter > DateTime.Now
                    && string.Equals(
                        certificate.GetNameInfo(X509NameType.SimpleName, false),
                        "localhost",
                        StringComparison.OrdinalIgnoreCase)
                    && certificate.Extensions.Cast<X509Extension>().Any(extension =>
                        string.Equals(extension.Oid?.Value, "1.3.6.1.4.1.311.84.1.1", StringComparison.Ordinal)))
                .OrderByDescending(certificate => certificate.NotAfter)
                .FirstOrDefault();
            if (developmentCertificate is not null)
            {
                return new LoopbackCertificate(null, new X509Certificate2(developmentCertificate));
            }
        }

        var key = RSA.Create(3072);
        var request = new CertificateRequest(
            "CN=localhost",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            true));
        var usages = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        return new LoopbackCertificate(key, certificate);
    }

    /// <summary>
    /// Starts a loopback-only HTTPS transport adapter that forwards exact requests to the real
    /// SoftLicence TestServer. The adapter changes no payload, status, or provider decision.
    /// </summary>
    private static async Task<HttpsProxy> StartHttpsProxyAsync(
        HttpClient providerClient,
        X509Certificate2 certificate)
    {
        var port = ReserveLoopbackPort();
        Assert.True(certificate.HasPrivateKey, "loopback HTTPS certificate must retain its private key");
        var builder = WebApplication.CreateBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Trace);
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(
                IPAddress.Loopback,
                port,
                listener => listener.UseHttps(https =>
                {
                    https.ServerCertificate = certificate;
                    https.SslProtocols = SslProtocols.Tls12;
                })));
        var application = builder.Build();
        application.Run(context => ForwardExactAsync(context, providerClient));
        await application.StartAsync();
        var baseAddress = $"https://localhost:{port}";
        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            SslProtocols = SslProtocols.Tls12
        };
        using var transportProbe = new HttpClient(handler);
        using var response = await transportProbe.GetAsync(
            baseAddress + "/api/internal/v1/distribution-installation-bindings/source-authority/resolve");
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        return new HttpsProxy(application, baseAddress);
    }

    /// <summary>
    /// Reserves an available IPv4 loopback port for the immediately following Kestrel bind.
    /// The listener is closed before return, so Kestrel remains the sole long-lived owner.
    /// </summary>
    private static int ReserveLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// Forwards one exact HTTP body and reviewed headers to the provider TestServer, then preserves
    /// the provider status, headers, and bounded JSON response at the external HTTPS boundary.
    /// </summary>
    private static async Task ForwardExactAsync(HttpContext context, HttpClient providerClient)
    {
        await using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, context.RequestAborted);
        using var request = new HttpRequestMessage(
            new HttpMethod(context.Request.Method),
            context.Request.Path + context.Request.QueryString)
        {
            Content = new ByteArrayContent(body.ToArray())
        };
        foreach (var header in context.Request.Headers)
        {
            if (string.Equals(header.Key, "Host", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
        }
        using var response = await providerClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            context.RequestAborted);
        context.Response.StatusCode = (int)response.StatusCode;
        foreach (var header in response.Headers.Concat(response.Content.Headers))
        {
            if (string.Equals(header.Key, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                || string.Equals(header.Key, "Connection", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            context.Response.Headers[header.Key] = header.Value.ToArray();
        }
        await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
    }

    /// <summary>
    /// Runs the production Website TypeScript S2S client in a separate Node process with only the
    /// ephemeral key, certificate, provider URL, and exact fixture identities in its environment.
    /// A timeout terminates the process tree and fails the integration test.
    /// </summary>
    private static async Task RunWebsiteProbeAsync(WebsiteProbeInput input)
    {
        var repository = Environment.GetEnvironmentVariable("TIA_CONNECT_WEBSITE_REPOSITORY_PATH")
            ?? @"D:\Works\T-IA-Connect_website";
        var workingDirectory = Path.Combine(repository, "t-ia-connect-marketing-landing");
        Assert.True(Directory.Exists(workingDirectory), $"Website repository is unavailable: {workingDirectory}");
        var start = new ProcessStartInfo("node")
        {
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("--import");
        start.ArgumentList.Add("tsx");
        start.ArgumentList.Add("scripts/test-runtime-enrollment-http-interservice.ts");
        start.Environment["NODE_ENV"] = "test";
        start.Environment["NODE_EXTRA_CA_CERTS"] = input.CertificatePath;
        start.Environment["SOFTLICENCE_INTERNAL_URL"] = input.BaseAddress;
        start.Environment["SOFTLICENCE_PRODUCT_ID"] = input.ProductId;
        start.Environment["DISTRIBUTION_S2S_CLIENT_ID"] = "website-runtime-v1";
        start.Environment["DISTRIBUTION_S2S_KEY_ID"] = "website-runtime-test-1";
        start.Environment["DISTRIBUTION_S2S_PRIVATE_KEY_PATH"] = input.PrivateKeyPath;
        start.Environment["RUNTIME_ENROLLMENT_CONFIRM_AUDIENCE"] = "https://runtime.example.test";
        start.Environment["TKT617_HTTP_MODE"] = input.Mode;
        start.Environment["TKT617_HTTP_TARGET_LICENSE_ID"] = input.TargetLicenseId;
        start.Environment["TKT617_HTTP_HARDWARE_ID"] = input.HardwareId;
        if (input.ConflictTargetLicenseId != null)
            start.Environment["TKT617_HTTP_CONFLICT_TARGET_LICENSE_ID"] = input.ConflictTargetLicenseId;

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start Website HTTP probe");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Website HTTP interservice probe exceeded three minutes");
        }
        var output = await outputTask;
        var error = await errorTask;
        Assert.True(process.ExitCode == 0,
            $"Website HTTP probe failed with exit {process.ExitCode}.{Environment.NewLine}{output}{Environment.NewLine}{error}");
        Assert.Contains($"TKT-000617 real Website-to-SoftLicence HTTP {input.Mode} checks passed.", output,
            StringComparison.Ordinal);
    }

    /// <summary>Exact provider authority values transferred to the Website probe without normalization.</summary>
    private sealed record HttpAuthority(string ProductId, string LicenseId, string HardwareId);

    /// <summary>Bounded non-secret process inputs used by one Website HTTP probe execution.</summary>
    private sealed record WebsiteProbeInput(
        string Mode,
        string BaseAddress,
        string PrivateKeyPath,
        string CertificatePath,
        string ProductId,
        string TargetLicenseId,
        string? ConflictTargetLicenseId,
        string HardwareId);

    /// <summary>
    /// Owns either the Windows development certificate or the fallback self-signed certificate and
    /// keeps any originating RSA key alive for the complete Kestrel lifetime.
    /// </summary>
    private sealed class LoopbackCertificate(RSA? key, X509Certificate2 certificate) : IDisposable
    {
        public X509Certificate2 Certificate { get; } = certificate;

        /// <summary>Releases the certificate before its originating private-key handle.</summary>
        public void Dispose()
        {
            Certificate.Dispose();
            key?.Dispose();
        }
    }

    /// <summary>Owns the loopback Kestrel adapter and guarantees bounded asynchronous shutdown.</summary>
    private sealed class HttpsProxy(WebApplication application, string baseAddress) : IAsyncDisposable
    {
        public string BaseAddress { get; } = baseAddress;

        /// <summary>Stops and disposes the temporary HTTPS adapter without retaining network state.</summary>
        public async ValueTask DisposeAsync()
        {
            await application.StopAsync();
            await application.DisposeAsync();
        }
    }

    /// <summary>
    /// Assigns the TestServer request a loopback remote address so the production S2S CIDR guard
    /// evaluates the same private-network authority as the external Kestrel adapter.
    /// </summary>
    private sealed class LoopbackRemoteAddressStartupFilter : IStartupFilter
    {
        /// <summary>Prepends the loopback connection authority before controller authentication.</summary>
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => application =>
        {
            application.Use(async (context, continuation) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Loopback;
                await continuation();
            });
            next(application);
        };
    }
}

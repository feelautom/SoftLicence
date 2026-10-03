using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.FileProviders;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Proves production absence, explicit test registration, gates, and exact safe HTTP serialization.</summary>
public sealed class Tkt000672SourceCAuthorityHttpTests
{
    /// <summary>Preserves production controllers while excluding unrelated historical test controllers.</summary>
    [Fact]
    public void TestApplication_DiscoversProductionAndOnlySourceCTestController()
    {
        using var factory = CreateFactory(true, true, true, new HttpScenarioExecutor());
        var manager = factory.Services.GetRequiredService<ApplicationPartManager>();
        var feature = new ControllerFeature();
        manager.PopulateFeature(feature);
        Assert.Contains(typeof(SoftLicence.Server.Controllers.ActivationController).GetTypeInfo(), feature.Controllers);
        Assert.DoesNotContain(typeof(SoftLicence.Server.Controllers.Tkt976BaselineActivationController).GetTypeInfo(), feature.Controllers);
        Assert.Equal(
            [typeof(Tkt000672SourceCAuthorityController).GetTypeInfo()],
            feature.Controllers.Where(type => type.Assembly == typeof(Tkt000672SourceCAuthorityController).Assembly).ToArray());
    }

    /// <summary>Proves the test-only route is absent when the production application parts are unchanged.</summary>
    [Fact]
    public async Task ProductionApplication_DoesNotDiscoverSourceCAuthorityRoute()
    {
        Assert.DoesNotContain(typeof(Program).Assembly.GetTypes(), type =>
            type == typeof(Tkt000672SourceCAuthorityController));
        Assert.NotEqual(typeof(Program).Assembly, typeof(Tkt000672SourceCAuthorityController).Assembly);
        await Task.CompletedTask;
    }

    /// <summary>Proves disabled, S2S, and permission gates fail before scenario execution.</summary>
    [Theory]
    [InlineData(false, false, false, HttpStatusCode.NotFound, "CAPABILITY_DISABLED", "capability")]
    [InlineData(true, false, false, HttpStatusCode.Unauthorized, "SERVICE_AUTHENTICATION_REQUIRED", "client")]
    [InlineData(true, true, false, HttpStatusCode.Forbidden, "PERMISSION_REQUIRED", "permission")]
    public async Task TestApplication_RequiresEveryClosedGate(
        bool enabled, bool authenticated, bool permitted, HttpStatusCode status, string reason, string field)
    {
        var executor = new HttpScenarioExecutor();
        using var factory = CreateFactory(enabled, authenticated, permitted, executor);
        using var client = factory.CreateClient();
        using var request = Request(addForgedHeaders: true);
        using var response = await client.SendAsync(request);
        Assert.Equal(status, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(reason, json.RootElement.GetProperty("reason").GetString());
        Assert.Equal(field, json.RootElement.GetProperty("field").GetString());
        Assert.Equal(0, executor.Calls);
    }

    /// <summary>Runs every scenario once and returns a bounded, no-store, signed metadata-only response.</summary>
    [Fact]
    public async Task TestApplication_EnabledAuthorizedRequestReturnsExactSafeEnvelope()
    {
        var executor = new HttpScenarioExecutor();
        using var factory = CreateFactory(true, true, true, executor);
        using var client = factory.CreateClient();
        using var request = Request();
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store, max-age=0", response.Headers.CacheControl!.ToString());
        var bytes = await response.Content.ReadAsByteArrayAsync();
        using var json = JsonDocument.Parse(bytes);
        Assert.Equal(Tkt000672SourceCAuthorityContract.ResponseSchema,
            json.RootElement.GetProperty("schema").GetString());
        Assert.Equal(4, json.RootElement.GetProperty("scenarioCount").GetInt32());
        Assert.Equal(4, executor.Calls);
        var proof = json.RootElement.GetProperty("manifest").GetProperty("payload").GetProperty("proofBoundary");
        Assert.False(proof.GetProperty("fixtureQualificationPromotable").GetBoolean());
        Assert.False(proof.GetProperty("materializationAuthorized").GetBoolean());
        Assert.DoesNotContain("providerGrantRef", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
        Assert.DoesNotContain("@", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
        using var replayRequest = Request();
        using var replayResponse = await client.SendAsync(replayRequest);
        Assert.Equal(HttpStatusCode.OK, replayResponse.StatusCode);
        using var replayJson = JsonDocument.Parse(await replayResponse.Content.ReadAsByteArrayAsync());
        Assert.Equal(json.RootElement.GetProperty("manifest").GetProperty("authorityDigest").GetString(),
            replayJson.RootElement.GetProperty("manifest").GetProperty("authorityDigest").GetString());
        Assert.Equal(8, executor.Calls);
    }

    /// <summary>Rejects unknown request keys with exact reason and field before flow execution.</summary>
    [Fact]
    public async Task TestApplication_UnknownRequestKeyFailsBeforeScenarioExecution()
    {
        var executor = new HttpScenarioExecutor();
        using var factory = CreateFactory(true, true, true, executor);
        using var client = factory.CreateClient();
        var bytes = ValidRequestBytes();
        using var document = JsonDocument.Parse(bytes);
        var dictionary = document.RootElement.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.Ordinal);
        dictionary.Add("extra", JsonSerializer.SerializeToElement(true));
        using var request = Request(JsonSerializer.SerializeToUtf8Bytes(dictionary));
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("SCHEMA_INVALID", json.RootElement.GetProperty("reason").GetString());
        Assert.Equal("request.keys", json.RootElement.GetProperty("field").GetString());
        Assert.Equal(0, executor.Calls);
    }

    /// <summary>Contains escaped lone surrogates in names and values as stable refusals before execution.</summary>
    [Theory]
    [InlineData("{\"\\uD800\":\"x\"}", "request.propertyNameUnicode")]
    [InlineData("{\"\\uDC00\":\"x\"}", "request.propertyNameUnicode")]
    [InlineData("{\"schema\":\"\\uD800\"}", "request.valueUnicode")]
    [InlineData("{\"schema\":\"\\uDC00\"}", "request.valueUnicode")]
    public async Task TestApplication_EscapedLoneSurrogateIsClosedRefusal(string rawJson, string field)
    {
        var executor = new HttpScenarioExecutor();
        using var factory = CreateFactory(true, true, true, executor);
        using var client = factory.CreateClient();
        using var response = await client.SendAsync(Request(Encoding.UTF8.GetBytes(rawJson)));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("UNICODE_INVALID", json.RootElement.GetProperty("reason").GetString());
        Assert.Equal(field, json.RootElement.GetProperty("field").GetString());
        Assert.Equal(0, executor.Calls);
    }

    /// <summary>Proves capability, host, authentication, and permission gates perform zero server body reads.</summary>
    [Theory]
    [InlineData(false, "Development", true, true, "CAPABILITY_DISABLED", "capability")]
    [InlineData(true, "Production", true, true, "NON_PRODUCTION_GATE_REQUIRED", "environment")]
    [InlineData(true, "Development", false, false, "SERVICE_AUTHENTICATION_REQUIRED", "client")]
    [InlineData(true, "Development", true, false, "PERMISSION_REQUIRED", "permission")]
    public async Task Controller_AccessRefusalDoesNotReadBodyOrExecute(
        bool enabled, string environment, bool authenticated, bool permitted, string reason, string field)
    {
        var executor = new HttpScenarioExecutor();
        using var signers = new Tkt000672ManifestSignerFactory();
        var harness = new Tkt000672SourceCAuthorityHarness(executor, executor, signers);
        var stream = new CountingReadStream(ValidRequestBytes());
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Request.Body = stream;
        context.Request.ContentType = "application/json";
        var controller = new Tkt000672SourceCAuthorityController(
            harness,
            new Tkt000672SourceCAuthorityGate(enabled, "tkt672-http-client",
                "runtime-enrollment.source-c.generate"),
            new TestHostEnvironment(environment),
            new TestAuthorization(authenticated, permitted))
        {
            ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext { HttpContext = context }
        };
        var result = Assert.IsType<Microsoft.AspNetCore.Mvc.ObjectResult>(
            await controller.Produce(CancellationToken.None));
        var refusal = Assert.IsType<Tkt000672Refusal>(result.Value);
        Assert.Equal(reason, refusal.Reason);
        Assert.Equal(field, refusal.Field);
        Assert.Equal(0, stream.ReadCalls);
        Assert.Equal(0, executor.Calls);
    }

    /// <summary>Proves the concrete authorizer trusts only an authenticated principal, never forged headers.</summary>
    [Fact]
    public async Task ClaimsAuthorization_UsesOnlyAuthenticatedPrincipalClaims()
    {
        var gate = new Tkt000672SourceCAuthorityGate(true, "tkt672-http-client",
            "runtime-enrollment.source-c.generate");
        var authorizer = new Tkt000672ClaimsAuthorization();
        var forged = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        forged.Request.Headers["X-TKT-000672-S2S-Client"] = gate.AuthorizedClientId;
        forged.Request.Headers["X-TKT-000672-Permission"] = gate.RequiredPermission;
        var rejected = await authorizer.AuthorizeAsync(forged, gate, CancellationToken.None);
        Assert.False(rejected.IsAuthenticated);
        Assert.False(rejected.IsAuthorized);

        var authenticated = new Microsoft.AspNetCore.Http.DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(Tkt000672ClaimsAuthorization.ClientIdClaim, gate.AuthorizedClientId),
                new Claim(Tkt000672ClaimsAuthorization.PermissionClaim, gate.RequiredPermission)
            ], "tkt672-test-s2s"))
        };
        var accepted = await authorizer.AuthorizeAsync(authenticated, gate, CancellationToken.None);
        Assert.True(accepted.IsAuthenticated);
        Assert.True(accepted.IsAuthorized);
    }

    /// <summary>Builds an explicit Development test host with closed authorization outcomes and application part.</summary>
    private static WebApplicationFactory<Program> CreateFactory(
        bool enabled, bool authenticated, bool permitted, HttpScenarioExecutor executor) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("IsIntegrationTest", "true");
            builder.ConfigureServices(services =>
            {
                // Keeps unrelated production middleware inside this isolated HTTP test host; the
                // Source C harness receives evidence only from the detached reader registered below.
                services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                services.AddDbContextFactory<LicenseDbContext>(options =>
                    options.UseInMemoryDatabase("tkt672-http-host-" + Guid.NewGuid().ToString("N")));
                services.AddSingleton<ITkt000672AuthorityScenarioExecutor>(executor);
                services.AddSingleton<ITkt000672PersistedEvidenceReader>(executor);
                services.AddSingleton<ITkt000672ManifestSignerFactory, Tkt000672ManifestSignerFactory>();
                services.AddSingleton(new Tkt000672SourceCAuthorityGate(enabled,
                    "tkt672-http-client", "runtime-enrollment.source-c.generate"));
                services.AddSingleton<ITkt000672SourceCAuthorityAuthorization>(
                    new TestAuthorization(authenticated, permitted));
                services.AddSingleton<Tkt000672SourceCAuthorityHarness>();
                services.AddControllers().ConfigureApplicationPartManager(manager =>
                {
                    manager.ApplicationParts.Add(new AssemblyPart(typeof(Tkt000672SourceCAuthorityController).Assembly));
                    // Replace default discovery so it cannot independently admit unrelated test controllers.
                    foreach (var provider in manager.FeatureProviders
                        .Where(provider => provider.GetType() == typeof(ControllerFeatureProvider)).ToArray())
                        manager.FeatureProviders.Remove(provider);
                    manager.FeatureProviders.Add(new InternalControllerFeatureProvider());
                }).AddControllersAsServices();
            });
        });

    /// <summary>Creates one exact JSON request; optional forged headers are deliberately non-authoritative.</summary>
    private static HttpRequestMessage Request(byte[]? body = null, bool addForgedHeaders = false)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, Tkt000672SourceCAuthorityController.Route);
        request.Content = new ByteArrayContent(body ?? ValidRequestBytes());
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        if (addForgedHeaders)
        {
            request.Headers.Add("X-TKT-000672-S2S-Client", "tkt672-http-client");
            request.Headers.Add("X-TKT-000672-Permission", "runtime-enrollment.source-c.generate");
        }
        return request;
    }

    /// <summary>Provides closed authoritative authentication outcomes without consulting request headers.</summary>
    private sealed class TestAuthorization(bool authenticated, bool permitted)
        : ITkt000672SourceCAuthorityAuthorization
    {
        /// <inheritdoc />
        public ValueTask<Tkt000672AuthorizationDecision> AuthorizeAsync(
            Microsoft.AspNetCore.Http.HttpContext context,
            Tkt000672SourceCAuthorityGate gate,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new Tkt000672AuthorizationDecision(authenticated, permitted));
        }
    }

    /// <summary>Supplies only the authoritative environment property used by the test controller.</summary>
    private sealed class TestHostEnvironment(string environmentName) : IWebHostEnvironment
    {
        /// <inheritdoc />
        public string ApplicationName { get; set; } = "SoftLicence.Tests";
        /// <inheritdoc />
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        /// <inheritdoc />
        public string WebRootPath { get; set; } = string.Empty;
        /// <inheritdoc />
        public string EnvironmentName { get; set; } = environmentName;
        /// <inheritdoc />
        public string ContentRootPath { get; set; } = string.Empty;
        /// <inheritdoc />
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    /// <summary>Counts server-side reads while preserving exact request bytes.</summary>
    private sealed class CountingReadStream(byte[] bytes) : MemoryStream(bytes, writable: false)
    {
        /// <summary>Gets the exact count of asynchronous server reads observed by this stream.</summary>
        internal int ReadCalls { get; private set; }

        /// <inheritdoc />
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ReadCalls++;
            return base.ReadAsync(buffer, cancellationToken);
        }
    }

    /// <summary>Serializes one closed request whose exact metadata is safe for HTTP transport assertions.</summary>
    private static byte[] ValidRequestBytes() => JsonSerializer.SerializeToUtf8Bytes(new
    {
        schema = Tkt000672SourceCAuthorityContract.RequestSchema,
        runId = "run_00000000000000000000000000000002",
        environment = Tkt000672SourceCAuthorityContract.Environment,
        sourceId = "source_c_http_01",
        observedAtUtc = "2026-08-26T08:00:00.000Z",
        snapshotHash = new string('1', 64), catalogHash = new string('2', 64),
        migrationsHash = new string('3', 64), oracleHash = new string('4', 64),
        generationSpecHash = new string('5', 64), providerScope = "provider_scope_http",
        productScope = "product_scope_http", grantScope = "grant_scope_http"
    });

    /// <summary>
    /// Adds only the internal test controller from the test assembly while preserving every production
    /// controller discovered by the base provider; production hosts never register this feature provider.
    /// </summary>
    private sealed class InternalControllerFeatureProvider : ControllerFeatureProvider
    {
        /// <summary>Includes only the TKT controller from the test assembly while retaining production controllers.</summary>
        protected override bool IsController(System.Reflection.TypeInfo typeInfo) =>
            typeInfo == typeof(Tkt000672SourceCAuthorityController).GetTypeInfo()
            || typeInfo.Assembly != typeof(Tkt000672SourceCAuthorityController).Assembly
                && base.IsController(typeInfo);
    }

    /// <summary>
    /// Supplies transport-only deterministic request IDs and detached canonical evidence without fabricating
    /// EF persistence. PostgreSQL persistence evidence is owned exclusively by the real controller harness.
    /// </summary>
    private sealed class HttpScenarioExecutor : ITkt000672AuthorityScenarioExecutor,
        ITkt000672PersistedEvidenceReader
    {
        /// <summary>Gets the exact number of closed scenario dispatches.</summary>
        internal int Calls { get; private set; }

        /// <inheritdoc />
        public async Task<Tkt000672ScenarioExecution> ExecuteAsync(
            Tkt000672Scenario scenario, Tkt000672SourceCRequest request,
            CancellationToken cancellationToken)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var requestId = DeterministicGuid(scenario.Order, 1);
            var conflictId = DeterministicGuid(scenario.Order, 4);
            var requestIds = scenario.Classification == "AMBIGUOUS"
                ? new[] { requestId, conflictId }
                : new[] { requestId };
            return new(scenario.ScenarioId, requestIds);
        }

        /// <inheritdoc />
        public Task<Tkt000672PersistedEvidenceSnapshot> ReadAsync(
            IReadOnlyCollection<Guid> ownedRequestIds, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var requests = new List<Tkt000672PersistedRequest>();
            var attempts = new List<Tkt000672PersistedAttempt>();
            var generations = new List<Tkt000672PersistedGeneration>();
            foreach (var scenario in Tkt000672SourceCAuthorityContract.Scenarios)
            {
                var primary = DeterministicGuid(scenario.Order, 1);
                if (!ownedRequestIds.Contains(primary)) continue;
                Add(primary, DeterministicGuid(scenario.Order, 2), 0);
                if (scenario.Classification == "AMBIGUOUS")
                    Add(DeterministicGuid(scenario.Order, 4), DeterministicGuid(scenario.Order, 5), 1);

                void Add(Guid requestId, Guid generationId, long sequence)
                {
                    var requestDigest = Hash($"http-request-{scenario.Order}-{sequence}");
                    requests.Add(new(requestId, requestDigest, "ACCEPTED", null));
                    attempts.Add(new(requestId, "ACCEPTED", null));
                    generations.Add(new(requestId, requestDigest, generationId,
                        Hash($"http-generation-{scenario.Order}-{sequence}"),
                        GenerationPayload(scenario, requestId, generationId, sequence)));
                }
            }
            return Task.FromResult(new Tkt000672PersistedEvidenceSnapshot(requests, attempts, generations));
        }

        /// <summary>Serializes one closed v2 tuple payload for transport-only response-shape coverage.</summary>
        private static byte[] GenerationPayload(
            Tkt000672Scenario scenario, Guid requestId, Guid generationId, long sequence) =>
            JsonSerializer.SerializeToUtf8Bytes(new RuntimeEnrollmentAuthorityGenerationPayloadV2
            {
                Schema = "runtime-enrollment-authority-generation-v2", ContractVersion = 2,
                AuthorityLineageId = DeterministicGuid(scenario.Order, 3).ToString("D"),
                AuthorityGenerationId = generationId.ToString("D"),
                PreviousGenerationId = sequence == 0 ? null : DeterministicGuid(scenario.Order, 2).ToString("D"),
                Sequence = sequence, Provider = "softlicence",
                ProductId = DeterministicGuid(scenario.Order, 30).ToString("D"),
                ProviderGrantRef = "grant-http-" + scenario.Order,
                Release = new() { Version = "2.3." + (600 + scenario.Order), ArtifactSetDigest = new string('a', 64) },
                Binding = new() { BindingId = DeterministicGuid(scenario.Order, 31).ToString("D"), HardwareIdDigest = new string('b', 64) },
                Enrollment = new()
                {
                    EnrollmentId = DeterministicGuid(scenario.Order, 32).ToString("D"), State = "active",
                    IssuedAtUtc = "2026-08-25T08:00:00.000000Z", ExpiresAtUtc = "2026-08-27T08:00:00.000000Z"
                },
                Key = new() { AuthorityKeyId = sequence == 0 ? "operational-2026-01" : "operational-2026-02", SecurityEpoch = 7 + (int)sequence },
                Installation = new() { InstallationId = "installation-http-" + scenario.Order, SeatId = null },
                Transition = new()
                {
                    Kind = sequence == 0 ? "genesis" : "recovery",
                    ReasonCode = sequence == 0 ? "INITIAL_ENROLLMENT" : "RECOVERY_AUTHORIZED",
                    RequestId = requestId.ToString("D"), OccurredAtUtc = "2026-08-26T08:00:00.000000Z"
                }
            }, RuntimeEnrollmentAuthorityJsonV2.CreateSerializerOptions());

        /// <summary>Creates a stable opaque test identifier from closed scenario and role discriminators.</summary>
        private static Guid DeterministicGuid(int index, byte kind)
        {
            var bytes = new byte[16];
            bytes[0] = (byte)index;
            bytes[15] = kind;
            return new Guid(bytes);
        }

        /// <summary>Computes lowercase SHA-256 for metadata-safe deterministic transport fixtures.</summary>
        private static string Hash(string value) => Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

}

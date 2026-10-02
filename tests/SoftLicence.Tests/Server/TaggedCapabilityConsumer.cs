using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Newtonsoft.Json.Linq;
using SoftLicence.Server.Models;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Executes the complete, unmodified capability validator from an immutable Desktop tag. Dependencies
/// are exact syntax nodes from that same tag; no acceptance predicate is recreated by this harness.
/// Only git show reads the client repository. Compilation and synthetic pins stay in memory.
/// </summary>
internal sealed class TaggedCapabilityConsumer
{
    /// <summary>One in-memory consumer assembly per exact tag, shared by the synthetic test matrix.</summary>
    private static readonly ConcurrentDictionary<string, Lazy<TaggedCapabilityConsumer>> Consumers = new(StringComparer.Ordinal);
    /// <summary>Immutable dynamically compiled consumer assembly; never loads an installed application.</summary>
    private readonly Assembly _assembly;
    /// <summary>Exact namespace of the tagged consumer contract.</summary>
    private const string ConsumerNamespace = "TiaPortalApi.Core.Services.RuntimeEnrollment.";

    /// <summary>Gets a cached immutable 647 or 924 consumer; arbitrary revisions are not accepted.</summary>
    internal static TaggedCapabilityConsumer For(string tag)
    {
        Assert.Contains(tag, new[] { "v2.3.647", "v2.3.924" });
        return Consumers.GetOrAdd(tag, value => new Lazy<TaggedCapabilityConsumer>(() => new(value))).Value;
    }

    /// <summary>
    /// Reads the exact tag sources and compiles the real validator with its exact dependency types.
    /// Missing source, unexpected declarations or compiler errors fail the test, never select a substitute.
    /// </summary>
    private TaggedCapabilityConsumer(string tag)
    {
        var root = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_CONSUMER_REPOSITORY")
            ?? throw new InvalidOperationException("SOFTLICENCE_RUNTIME_CONSUMER_REPOSITORY must identify the read-only Desktop repository.");
        var commit = tag == "v2.3.647" ? "c69222e85fe3b283ea5113b35871d51101396485" : "38949e58062bdcfc6d94eae838980ac7484e359b";
        Assert.Equal(commit + "\n", Git("rev-parse", tag + "^{commit}"));
        Assert.Equal("fdefbd2ffcb2fdf99a76fb5c77d7e0241d26bcf1\n", Git("rev-parse", commit + ":API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentCapabilityTokenValidator.cs"));
        var evidence = new List<object>();
        var trees = new List<SyntaxTree>();
        Add("API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentCapabilityTokenValidator.cs");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentContracts.cs");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentBroker.cs");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeCriticalRecoveryReceiptValidator.cs");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeMilestoneContracts.cs");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentDesktopFlow.cs", "RuntimeEnrollmentBinaryEvidence", "RuntimeEnrollmentDesktopProtocol");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentCoordinator.cs", "RuntimeEnrollmentCapabilityContext");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentServerKeyPins.cs", "IRuntimeEnrollmentServerKeyPins", "RuntimeEnrollmentServerKeyPins");
        Add("Shared/RuntimeEnrollment/Net48CryptoPrimitives.cs");
        Add("API/Core/Services/RuntimeEnrollment/RuntimeEnrollmentProofSigner.cs", "RuntimeEnrollmentProofSigner.RequireLowerSha256");
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Append(typeof(JObject).Assembly.Location).Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("TaggedConsumer_" + tag.Replace('.', '_'), trees, references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        using var output = new MemoryStream();
        var emitted = compilation.Emit(output);
        Assert.True(emitted.Success, string.Join(Environment.NewLine, emitted.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        _assembly = Assembly.Load(output.ToArray());
        var evidenceRoot = Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_COMPAT_EVIDENCE")
            ?? throw new InvalidOperationException("SOFTLICENCE_RUNTIME_COMPAT_EVIDENCE must be a task-owned output directory.");
        File.WriteAllText(Path.Combine(evidenceRoot, tag + "-sources.json"),
            System.Text.Json.JsonSerializer.Serialize(new { tag, commit, sources = evidence }));

        // Record original byte hashes and extracted-node hashes. The full validator is never rewritten.
        void Add(string path, params string[] symbols)
        {
            var source = Git("show", commit + ":" + path);
            var parsed = CSharpSyntaxTree.ParseText(source);
            var unit = parsed.GetCompilationUnitRoot();
            var selected = source;
            if (symbols.Length != 0)
            {
                var nodes = new List<string>();
                foreach (var symbol in symbols)
                {
                    var parts = symbol.Split('.');
                    var type = unit.DescendantNodes().OfType<TypeDeclarationSyntax>().Single(node => node.Identifier.Text == parts[0]);
                    nodes.Add(parts.Length == 1 ? type.ToFullString() :
                        "internal static class " + parts[0] + " { " + type.Members.OfType<MethodDeclarationSyntax>()
                            .Single(method => method.Identifier.Text == parts[1]).ToFullString() + " }");
                }
                var ns = unit.DescendantNodes().OfType<NamespaceDeclarationSyntax>().Single().Name.ToString();
                // Ignore unrelated using directives only; all selected executable declarations retain exact source text.
                var imports = unit.Usings.Where(item => item.Name!.ToString() is not
                    ("TiaPortalApi.Core.Services.Security" or "TiaPortalApi.Core.Services.Licensing"));
                selected = string.Concat(imports.Select(item => item.ToFullString())) + "namespace " + ns + " {\n" + string.Join("\n", nodes) + "\n}";
            }
            evidence.Add(new { path, symbols, sourceSha256 = Hash(source), compiledSha256 = Hash(selected) });
            trees.Add(CSharpSyntaxTree.ParseText(selected, path: tag + "/" + path));
        }

        // Read through argument-list APIs and byte streams so shell interpolation and text normalization cannot alter source.
        string Git(params string[] arguments)
        {
            var start = new ProcessStartInfo("git") { WorkingDirectory = root, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var argument in arguments) start.ArgumentList.Add(argument);
            using var process = Process.Start(start)!;
            using var bytes = new MemoryStream();
            var error = process.StandardError.ReadToEndAsync();
            process.StandardOutput.BaseStream.CopyTo(bytes);
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, error.GetAwaiter().GetResult());
            return new UTF8Encoding(false, true).GetString(bytes.ToArray());
        }
    }

    /// <summary>Hashes exact UTF-8 source bytes for the durable source and dependency manifest.</summary>
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>
    /// Executes the complete tagged HTTP broker against an in-memory HTTP response. Preserves real
    /// status parsing and verifies one request, so a rejected replay is not misreported as an automatic retry.
    /// </summary>
    internal async Task<(string? Error, int Requests)> MapResponseAsync(int status, string error)
    {
        var endpointsType = _assembly.GetType(ConsumerNamespace + "RuntimeEnrollmentBrokerEndpoints", true)!;
        var endpoints = Activator.CreateInstance(endpointsType, new Uri("https://website.example.test/pickup"), new Uri("https://runtime.example.test"))!;
        using var handler = new SyntheticResponseHandler(status, error);
        var brokerType = _assembly.GetType(ConsumerNamespace + "RuntimeEnrollmentHttpBroker", true)!;
        using var broker = (IDisposable)Activator.CreateInstance(brokerType, BindingFlags.Instance | BindingFlags.NonPublic,
            null, [endpoints, handler], CultureInfo.InvariantCulture)!;
        var proofType = _assembly.GetType(ConsumerNamespace + "RuntimeEnrollmentProofHeaders", true)!;
        var proof = Activator.CreateInstance(proofType, BindingFlags.Instance | BindingFlags.NonPublic, null,
            [DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture), Guid.NewGuid().ToString("D"), new string('a', 512)], CultureInfo.InvariantCulture)!;
        var task = (Task)brokerType.GetMethod("RequestCapabilityAsync")!.Invoke(broker,
            [Guid.NewGuid(), Encoding.UTF8.GetBytes("{}"), proof, CancellationToken.None])!;
        await task;
        var result = task.GetType().GetProperty("Result")!.GetValue(task)!;
        return ((string?)result.GetType().GetProperty("ErrorCode")!.GetValue(result), handler.Requests);
    }

    /// <summary>Returns one synthetic no-store JSON response without any network access and counts broker requests.</summary>
    private sealed class SyntheticResponseHandler(int status, string error) : HttpMessageHandler
    {
        /// <summary>Number of actual sends made by the unmodified broker, including any automatic retries.</summary>
        internal int Requests { get; private set; }

        /// <summary>Preserves the expected endpoint and HTTP headers required by the real consumer response parser.</summary>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            var response = new HttpResponseMessage((HttpStatusCode)status) { RequestMessage = request,
                Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(new { error }), Encoding.UTF8, "application/json") };
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            return Task.FromResult(response);
        }
    }

    /// <summary>
    /// Validates one modern server token through the real tagged validator with synthetic public pins.
    /// Returns the consumer's actual protocol error, or null on acceptance. Legacy JWTs are a distinct contract.
    /// </summary>
    internal string? Validate(string token, string issuer, string keyId, RSA signing,
        RuntimeEnrollmentCapabilityRequest request, string spkiSha256, DateTime now)
    {
        var pinsType = _assembly.GetType(ConsumerNamespace + "RuntimeEnrollmentServerKeyPins", true)!;
        var pins = Activator.CreateInstance(pinsType, new Dictionary<string, RSAParameters> { [keyId] = signing.ExportParameters(false) })!;
        var binaryType = _assembly.GetType(ConsumerNamespace + "RuntimeEnrollmentBinaryEvidence", true)!;
        var binaries = Array.CreateInstance(binaryType, request.Binaries!.Count);
        for (var i = 0; i < request.Binaries.Count; i++)
            binaries.SetValue(Activator.CreateInstance(binaryType, request.Binaries[i].Key, request.Binaries[i].Sha256), i);
        var contextType = _assembly.GetType(ConsumerNamespace + "RuntimeEnrollmentCapabilityContext", true)!;
        var context = Activator.CreateInstance(contextType, Guid.Parse(request.InstallationId!), request.ReleaseVersion,
            Guid.Parse(request.SessionId!), binaries)!;
        var validatorType = _assembly.GetType(ConsumerNamespace + "RuntimeEnrollmentCapabilityTokenValidator", true)!;
        var validator = Activator.CreateInstance(validatorType, pins)!;
        try
        {
            validatorType.GetMethods().Single(method => method.Name == "Validate" && method.GetParameters().Length == 10)
                .Invoke(validator, [token, issuer, request.Audience, Guid.Parse(request.EnrollmentId!), request.Epoch,
                    request.SecurityEpoch, context, request.Scope, spkiSha256, now]);
            return null;
        }
        catch (TargetInvocationException exception) when (exception.InnerException?.GetType().Name == "RuntimeEnrollmentProtocolException")
        {
            return (string?)exception.InnerException.GetType().GetProperty("ErrorCode")!.GetValue(exception.InnerException);
        }
    }
}

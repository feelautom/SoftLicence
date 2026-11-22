using System.Net;
using System.Text;
using System.Text.Json;
using SoftLicence.SDK;
using SoftLicence.Server.Services.CloneGuard;
using Xunit;

namespace SoftLicence.Tests.Core;

/// <summary>
/// TKT-003615 SDK unit tests without a database: validation of the token pair before any network request, the exact
/// request body (historical body unchanged, guarded body with protocol version 1), answer parsing, and the network
/// failure contract (no clone guard member, so the caller resends the same pair).
/// </summary>
public sealed class CloneGuardSdkTests
{
    /// <summary>Canonical hardware identifier (16 upper-case hexadecimal characters) accepted by the SDK authority check.</summary>
    private const string Hardware = "A1B2C3D4E5F60718";

    /// <summary>Generated tokens are canonical for both the SDK and the server codec, and distinct.</summary>
    [Fact]
    public void GenerateToken_IsCanonical_AndAcceptedByTheServerCodec()
    {
        var tokens = Enumerable.Range(0, 50).Select(_ => CloneGuardPresentation.GenerateToken()).ToList();
        Assert.Equal(50, tokens.Distinct(StringComparer.Ordinal).Count());
        Assert.All(tokens, token =>
        {
            Assert.Equal(43, token.Length);
            Assert.True(CloneGuardCodec.TryHashToken(token, out var digest));
            Assert.Equal(32, digest.Length);
        });
    }

    /// <summary>Every malformed pair is refused by the constructor, before any request.</summary>
    [Theory]
    [InlineData("short", null)]
    [InlineData("padded", null)]
    [InlineData("same", null)]
    [InlineData("vm", "xyz")]
    [InlineData("vm", "0123456789abcdef0123456789abcde")]
    public void Presentation_RefusesMalformedInput(string variant, string? vmGenerationId)
    {
        var good = CloneGuardPresentation.GenerateToken();
        Assert.Throws<ArgumentException>(() => variant switch
        {
            "short" => new CloneGuardPresentation(null, good[..42], null),
            "padded" => new CloneGuardPresentation(good + "=", CloneGuardPresentation.GenerateToken(), null),
            "same" => new CloneGuardPresentation(good, good, null),
            _ => new CloneGuardPresentation(null, good, vmGenerationId)
        });
    }

    /// <summary>The reactivation call validates its token and identifier before any request.</summary>
    [Fact]
    public async Task Reactivate_RefusesMalformedToken_BeforeAnyRequest()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK, "{}");
        var client = new SoftLicenceClient("http://server.test", httpClient: new HttpClient(handler));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ReactivateCloneGuardAsync("KEY", "App", null, null, Hardware, "not-a-token", null));
        Assert.Empty(handler.Bodies);
    }

    /// <summary>
    /// The historical overload sends no <c>CloneGuard</c> member; the guarded overload sends protocol 1 with the exact
    /// tokens, and parses outcome, reason and environmentChanged from the answer.
    /// </summary>
    [Fact]
    public async Task GuardedCheck_SendsTheMember_AndParsesTheAnswer()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK,
            """{"status":"VALID","licenseFile":"file","cloneGuard":{"outcome":"ACCEPTED","reason":null,"environmentChanged":true}}""");
        var client = new SoftLicenceClient("http://server.test", httpClient: new HttpClient(handler));
        var token = CloneGuardPresentation.GenerateToken();
        var next = CloneGuardPresentation.GenerateToken();

        await client.CheckStatusAsync("KEY", "App", null, null, Hardware);
        var guarded = await client.CheckStatusAsync("KEY", "App", null, null, Hardware,
            new CloneGuardPresentation(token, next, "0123456789ABCDEF0123456789ABCDEF"));

        using (var historical = JsonDocument.Parse(handler.Bodies[0]))
            Assert.False(historical.RootElement.TryGetProperty("CloneGuard", out _));
        using (var body = JsonDocument.Parse(handler.Bodies[1]))
        {
            var guard = body.RootElement.GetProperty("CloneGuard");
            Assert.Equal(1, guard.GetProperty("ProtocolVersion").GetInt32());
            Assert.Equal(token, guard.GetProperty("Token").GetString());
            Assert.Equal(next, guard.GetProperty("NextToken").GetString());
        }
        Assert.Equal(("ACCEPTED", true), (guarded.CloneGuard!.Outcome, guarded.CloneGuard.EnvironmentChanged));
        Assert.Equal("/api/activation/check", handler.Paths[1]);
    }

    /// <summary>
    /// Review 2439: the reactivation sends the same identity members as the status check (here the SDK version; the
    /// system UUID and evidence follow the machine and are covered by the server parity tests), the next token, and
    /// never a <c>CloneGuard</c> pair; it posts to the reactivation route and parses the answer like the check.
    /// </summary>
    [Fact]
    public async Task Reactivation_SendsTheCheckIdentityAndNextToken_ToItsRoute()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK,
            """{"status":"VALID","licenseFile":"file","cloneGuard":{"outcome":"REACTIVATED","reason":null,"environmentChanged":false}}""");
        var client = new SoftLicenceClient("http://server.test", httpClient: new HttpClient(handler));
        var next = CloneGuardPresentation.GenerateToken();

        var result = await client.ReactivateCloneGuardAsync("KEY", "App", null, "2.6.300", Hardware, next, null);

        Assert.Equal("/api/activation/clone-guard/reactivate", Assert.Single(handler.Paths));
        using var body = JsonDocument.Parse(Assert.Single(handler.Bodies));
        Assert.Equal(next, body.RootElement.GetProperty("NextToken").GetString());
        Assert.Equal("3.0.0", body.RootElement.GetProperty("SdkVersion").GetString());
        Assert.Equal("2.6.300", body.RootElement.GetProperty("AppVersion").GetString());
        Assert.False(body.RootElement.TryGetProperty("CloneGuard", out _));
        Assert.Equal(CloneGuardOutcome.Reactivated, result.CloneGuard!.Outcome);
    }

    /// <summary>A network failure returns a failed result with no clone guard member: the caller keeps and resends its pair.</summary>
    [Fact]
    public async Task NetworkFailure_HasNoCloneGuardMember()
    {
        var client = new SoftLicenceClient("http://server.test", httpClient: new HttpClient(new FailingHandler()));

        var result = await client.CheckStatusAsync("KEY", "App", null, null, Hardware,
            new CloneGuardPresentation(null, CloneGuardPresentation.GenerateToken(), null));

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusErrorCode.NetworkError, result.ErrorCode);
        Assert.Null(result.CloneGuard);
    }

    /// <summary>Handler answering a fixed body and recording request paths and bodies.</summary>
    private sealed class RecordingHandler(HttpStatusCode status, string answer) : HttpMessageHandler
    {
        /// <summary>Gets the recorded request bodies.</summary>
        public List<string> Bodies { get; } = [];

        /// <summary>Gets the recorded request paths.</summary>
        public List<string> Paths { get; } = [];

        /// <summary>Records the request and answers the fixed body.</summary>
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Bodies.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
            Paths.Add(request.RequestUri!.AbsolutePath);
            return new HttpResponseMessage(status) { Content = new StringContent(answer, Encoding.UTF8, "application/json") };
        }
    }

    /// <summary>Handler simulating a connection failure.</summary>
    private sealed class FailingHandler : HttpMessageHandler
    {
        /// <summary>Always throws <see cref="HttpRequestException"/>.</summary>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("connection refused");
    }
}

/// <summary>TKT-003615 server-side pure functions of the clone guard, without a database.</summary>
public sealed class CloneGuardServerUnitTests
{
    /// <summary>Network comparison of the alert: same /24 or /48 is the same network; another prefix or family is not.</summary>
    [Theory]
    [InlineData("203.0.113.10", "203.0.113.200", true)]
    [InlineData("203.0.113.10", "203.0.114.10", false)]
    [InlineData("::ffff:203.0.113.10", "203.0.113.99", true)]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:ffff::9", true)]
    [InlineData("2001:db8:1:2::1", "2001:db8:2:2::1", false)]
    [InlineData("203.0.113.10", "2001:db8::1", false)]
    [InlineData(null, "203.0.113.10", true)]
    [InlineData("garbage", "203.0.113.10", true)]
    public void SameNetwork_ComparesIpv4By24_AndIpv6By48(string? left, string? right, bool expected) =>
        Assert.Equal(expected, SoftLicence.Server.Services.CloneGuard.SeatCloneGuardService.SameNetwork(left, right));

    /// <summary>
    /// The server codec accepts only canonical unpadded base64url of 32 bytes and hashes the decoded bytes; the VM
    /// Generation ID is accepted in either case and stored lower-case, an invalid one is reported but never thrown.
    /// </summary>
    [Fact]
    public void Codec_IsStrict_OnTokens_AndCanonicalizesVmGenerationId()
    {
        var bytes = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var token = CloneGuardCodec.Encode(bytes);
        Assert.True(CloneGuardCodec.TryHashToken(token, out var digest));
        Assert.Equal(System.Security.Cryptography.SHA256.HashData(bytes), digest);
        Assert.False(CloneGuardCodec.TryHashToken(null, out _));
        Assert.False(CloneGuardCodec.TryHashToken(token + "=", out _));
        Assert.True(CloneGuardCodec.TryCanonicalVmGenerationId("ABCDEF0123456789ABCDEF0123456789", out var vm));
        Assert.Equal("abcdef0123456789abcdef0123456789", vm);
        Assert.True(CloneGuardCodec.TryCanonicalVmGenerationId(null, out var none));
        Assert.Null(none);
        Assert.False(CloneGuardCodec.TryCanonicalVmGenerationId("ABCDEF0123456789ABCDEF012345678G", out _));
    }
}

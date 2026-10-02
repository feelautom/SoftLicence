using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Uses controlled HTTP bodies to prove limits before allocation or sensitive logging.</summary>
public sealed class BugTraceSupportTransportTests
{
    /// <summary>SUP and legacy requests select distinct server credentials even when the test factory reuses a client.</summary>
    [Fact]
    public async Task SupportCredential_DoesNotReplaceLegacyCredential()
    {
        using var client = new HttpClient(new ReplyHandler(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") }));
        var service = BuildService(client);
        await service.GetSupportCaseAsync("SUP-000123");
        Assert.Equal("synthetic-support-token", Assert.Single(client.DefaultRequestHeaders.GetValues("X-Project-Token")));
        await service.SubmitTicketAsync(new { title = "synthetic" });
        Assert.Equal("synthetic-provider-token", Assert.Single(client.DefaultRequestHeaders.GetValues("X-Project-Token")));
    }

    /// <summary>Missing dedicated support configuration fails closed without sending the valid legacy credential.</summary>
    [Fact]
    public async Task MissingSupportCredential_NeverFallsBackToLegacy()
    {
        var factory = new Mock<IHttpClientFactory>(MockBehavior.Strict);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["BUGTRACE_BASE_URL"] = "https://provider.example.invalid",
            ["BUGTRACE_PROJECT_TOKEN"] = "synthetic-legacy-token",
            ["BUGTRACE_PROJECT_ID"] = "synthetic-project"
        }).Build();
        var service = new BugTraceProxyService(factory.Object, NullLogger<BugTraceProxyService>.Instance, config);
        var failure = await Assert.ThrowsAsync<BugTraceSupportException>(() => service.GetSupportCaseAsync("SUP-000123"));
        Assert.Equal(503, failure.Status);
        Assert.Equal("support_not_configured", failure.Code);
        factory.VerifyNoOtherCalls();
    }

    /// <summary>A known oversized error must be rejected from its headers without materializing any body.</summary>
    [Fact]
    public async Task OversizedError_IsRejectedBeforeBodyIsRead()
    {
        var content = new CountingContent();
        using var handler = new ReplyHandler(() => new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = content });
        using var client = new HttpClient(handler);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(x => x.CreateClient("BugTrace")).Returns(client);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["BUGTRACE_BASE_URL"] = "https://provider.example.invalid",
            ["BUGTRACE_PROJECT_TOKEN"] = "synthetic-provider-token",
            ["BUGTRACE_SUPPORT_PROJECT_TOKEN"] = "synthetic-support-token",
            ["BUGTRACE_PROJECT_ID"] = "synthetic-project"
        }).Build();
        var service = new BugTraceProxyService(factory.Object, NullLogger<BugTraceProxyService>.Instance, config);
        await Assert.ThrowsAnyAsync<Exception>(() => service.GetSupportCaseAsync("SUP-000123"));
        Assert.Equal(0, content.SerializedBytes);
    }

    /// <summary>Provider-selected filenames cannot retain traversal or Windows alternate-stream punctuation.</summary>
    [Fact]
    public async Task PostAudit_DownloadFilenameIsSafeOnWindows()
    {
        var content = new ByteArrayContent([1,2,3]);
        content.Headers.ContentDisposition = new System.Net.Http.Headers.ContentDispositionHeaderValue("attachment")
        { FileNameStar = "../../unsafe:stream.pdf" };
        using var client = new HttpClient(new ReplyHandler(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = content }));
        var download = await BuildService(client).DownloadSupportAttachmentAsync("SUP-000123", "07c8f639-14b5-4e61-bc3a-6c3bc3bed431");
        Assert.Equal("unsafestream.pdf", download.FileName);
    }

    /// <summary>Unknown-length JSON is stopped after at most two MiB plus one byte.</summary>
    [Fact]
    public async Task UnknownLengthJson_IsReadOnlyThroughLimitPlusOne()
    {
        using var stream = new MeasuredStream(3 * 1024 * 1024);
        using var client = new HttpClient(new ReplyHandler(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }));
        var failure = await Assert.ThrowsAsync<BugTraceSupportException>(() => BuildService(client).GetSupportCaseAsync("SUP-000123"));
        Assert.Equal("support_response_too_large", failure.Code);
        Assert.Equal(2 * 1024 * 1024 + 1, stream.ReadBytes);
    }

    /// <summary>Error bodies are never consumed, and only allowlisted status projections are returned.</summary>
    [Theory]
    [InlineData(400,400)] [InlineData(403,403)] [InlineData(404,404)] [InlineData(409,409)]
    [InlineData(413,413)] [InlineData(415,415)] [InlineData(422,422)] [InlineData(429,429)]
    [InlineData(503,503)] [InlineData(500,502)] [InlineData(302,502)]
    public async Task ProviderErrors_HaveStableSafeProjection(int providerStatus, int clientStatus)
    {
        var content = new CountingContent();
        using var client = new HttpClient(new ReplyHandler(() => new HttpResponseMessage((HttpStatusCode)providerStatus) { Content = content }));
        var failure = await Assert.ThrowsAsync<BugTraceSupportException>(() => BuildService(client).GetSupportCaseAsync("SUP-000123"));
        Assert.Equal(clientStatus, failure.Status);
        Assert.Null(failure.InnerException);
        Assert.Equal(0, content.SerializedBytes);
        if (clientStatus == 429) Assert.InRange(failure.RetryAfterSeconds!.Value, 1, 600);
    }

    /// <summary>Malformed or non-object JSON yields a bounded protocol failure.</summary>
    [Theory]
    [InlineData("not-json")]
    [InlineData("[]")]
    [InlineData("null")]
    public async Task InvalidJson_IsSafeProtocolFailure(string body)
    {
        using var client = new HttpClient(new ReplyHandler(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) }));
        var failure = await Assert.ThrowsAsync<BugTraceSupportException>(() => BuildService(client).GetSupportCaseAsync("SUP-000123"));
        Assert.Equal("support_invalid_response", failure.Code);
    }

    /// <summary>The application deadline still cancels a stalled body after response headers arrived.</summary>
    [Fact]
    public async Task StalledBody_IsCoveredByTransportDeadline()
    {
        using var stream = new MeasuredStream(1, stall: true);
        using var client = new HttpClient(new ReplyHandler(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }));
        var failure = await Assert.ThrowsAsync<BugTraceSupportException>(() => BuildService(client).GetSupportCaseAsync("SUP-000123"));
        Assert.Equal(504, failure.Status);
        Assert.True(stream.CancellationObserved);
    }

    /// <summary>Caller cancellation remains cancellation and is not mislabeled as a provider timeout.</summary>
    [Fact]
    public async Task CallerCancellation_IsPropagated()
    {
        using var stream = new MeasuredStream(1, stall: true);
        using var client = new HttpClient(new ReplyHandler(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }));
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => BuildService(client).GetSupportCaseAsync("SUP-000123", cancel.Token));
        Assert.True(stream.CancellationObserved);
    }

    /// <summary>Builds the actual transport with synthetic credentials and an in-process HTTP handler.</summary>
    private static BugTraceProxyService BuildService(HttpClient client)
    {
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(x => x.CreateClient("BugTrace")).Returns(client);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["BUGTRACE_BASE_URL"] = "https://provider.example.invalid",
            ["BUGTRACE_PROJECT_TOKEN"] = "synthetic-provider-token",
            ["BUGTRACE_SUPPORT_PROJECT_TOKEN"] = "synthetic-support-token",
            ["BUGTRACE_PROJECT_ID"] = "synthetic-project"
        }).Build();
        return new BugTraceProxyService(factory.Object, NullLogger<BugTraceProxyService>.Instance, config);
    }

    /// <summary>Produces unknown-length bytes or a cancellable stalled body without large allocations.</summary>
    private sealed class MeasuredStream(int length, bool stall = false) : Stream
    {
        /// <summary>Gets bytes actually requested by transport.</summary>
        public int ReadBytes { get; private set; }
        /// <summary>Gets whether a body read observed the passed cancellation token.</summary>
        public bool CancellationObserved { get; private set; }
        /// <inheritdoc/>
        public override bool CanRead => true;
        /// <inheritdoc/>
        public override bool CanSeek => false;
        /// <inheritdoc/>
        public override bool CanWrite => false;
        /// <inheritdoc/>
        public override long Length => throw new NotSupportedException();
        /// <inheritdoc/>
        public override long Position { get => ReadBytes; set => throw new NotSupportedException(); }
        /// <inheritdoc/>
        public override void Flush() { }
        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        /// <inheritdoc/>
        public override void SetLength(long value) => throw new NotSupportedException();
        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        /// <inheritdoc/>
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (stall)
            {
                try { await Task.Delay(Timeout.Infinite, cancellationToken); }
                catch (OperationCanceledException) { CancellationObserved = true; throw; }
            }
            var count = Math.Min(buffer.Length, length - ReadBytes);
            buffer.Span[..count].Fill((byte)'x');
            ReadBytes += count;
            return count;
        }
    }

    /// <summary>Produces one megabyte only if transport mistakenly requests body buffering.</summary>
    private sealed class CountingContent : HttpContent
    {
        /// <summary>Counts bytes materialized by HttpClient before application-level validation.</summary>
        public int SerializedBytes { get; private set; }
        /// <inheritdoc/>
        protected override bool TryComputeLength(out long length) { length = 1_000_000; return true; }
        /// <inheritdoc/>
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            SerializedBytes = 1_000_000;
            await stream.WriteAsync(new byte[SerializedBytes]);
        }
    }

    /// <summary>Returns a synthetic response without network, DNS or credential access.</summary>
    private sealed class ReplyHandler(Func<HttpResponseMessage> reply) : HttpMessageHandler
    {
        /// <inheritdoc/>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(reply());
    }
}

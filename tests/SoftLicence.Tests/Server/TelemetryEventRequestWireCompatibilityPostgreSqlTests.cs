using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Locks the wire compatibility of <c>POST /api/telemetry/event</c> for every producer already
/// deployed against it (TKT-001768). Each test sends raw JSON text through the real HTTP pipeline,
/// including ASP.NET Core model binding, because the production regression was a binding failure
/// that never reached the controller: YOUR_APP_NAME sends the string <c>"req":"event"</c> where
/// TKT-001758 had introduced an object-typed member.
/// </summary>
/// <remarks>
/// <para>
/// The <c>req</c> member is an untrusted legacy protocol value. The server applies no trimming, case
/// folding, or normalization to it: an object contributes its usable members, any other shape is
/// ignored. Routing identity (app name, hardware identifier, version, event name) always comes from
/// the outer request. The client timestamp is bound but never persisted: the service stamps the
/// row with the server clock, which predates this change.
/// </para>
/// <para>
/// Every other member keeps the contract it had before: a non-string outer <c>type</c>, a
/// non-string outer property value, and malformed or over-deep JSON are still rejected.
/// </para>
/// </remarks>
/// <param name="fixture">The fixture that owns the isolated PostgreSQL database and test server.</param>
public sealed class TelemetryEventRequestWireCompatibilityPostgreSqlTests(
    TelemetryActivationFailureClassificationPostgreSqlFixture fixture)
    : IClassFixture<TelemetryActivationFailureClassificationPostgreSqlFixture>
{
    /// <summary>
    /// Replays the exact camel-case payload produced by the YOUR_APP_NAME desktop client
    /// (<c>TrackEventAsync</c> and <c>TrackSecurityEventAsync</c>), whose <c>req</c> member is the
    /// string <c>event</c>. The event must be accepted and stored with its outer identity.
    /// </summary>
    [Fact]
    public async Task PostEvent_YOUR_APP_NAMEDesktopPayloadWithStringReq_ShouldBeAcceptedAsEvent()
    {
        var product = await fixture.CreateProductAsync("YOUR_APP_NAME-desktop");
        var hardwareId = NewHardwareId();

        var record = await PostRawAndReadAsync(product, hardwareId, YOUR_APP_NAMEDesktopJson(product, hardwareId));

        Assert.Equal(TelemetryType.Event, record.Type);
        Assert.Equal("AppHeartbeat", record.EventName);
        Assert.Equal("1.9.3", record.Version);
        Assert.Null(record.ErrorData);
        AssertProperties(record, ("Uptime", "240"), ("Mode", "Softphone"));
    }

    /// <summary>
    /// Replays the YOUR_APP_NAME desktop payload written to the transport in 64-byte pieces with chunked
    /// transfer encoding requested, so model binding reads the body across several buffers.
    /// </summary>
    /// <remarks>
    /// The in-process test server buffers the request content and may still compute a
    /// <c>Content-Length</c>; this test therefore proves fragmented delivery, not the absence of
    /// that header on a real socket.
    /// </remarks>
    [Fact]
    public async Task PostEvent_YOUR_APP_NAMEDesktopPayloadSentInFragments_ShouldBeAcceptedAsEvent()
    {
        var product = await fixture.CreateProductAsync("YOUR_APP_NAME-chunked");
        var hardwareId = NewHardwareId();
        var bytes = Encoding.UTF8.GetBytes(YOUR_APP_NAMEDesktopJson(product, hardwareId));

        using var client = fixture.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/telemetry/event");
        request.Headers.TransferEncodingChunked = true;
        request.Content = new UnknownLengthContent(bytes);
        request.Content.Headers.ContentType = new("application/json") { CharSet = "utf-8" };
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var record = await ReadSingleAsync(product, hardwareId);
        Assert.Equal(TelemetryType.Event, record.Type);
        AssertProperties(record, ("Uptime", "240"), ("Mode", "Softphone"));
    }

    /// <summary>
    /// Replays the Pascal-case payload produced by YOUR_APP_NAME's <c>Send-UninstallTelemetry.ps1</c>
    /// (<c>ConvertTo-Json</c> of a hashtable), which also carries the string <c>Req</c> member.
    /// </summary>
    [Fact]
    public async Task PostEvent_YOUR_APP_NAMEUninstallScriptPayloadWithStringReq_ShouldBeAcceptedAsEvent()
    {
        var product = await fixture.CreateProductAsync("YOUR_APP_NAME-uninstall");
        var hardwareId = NewHardwareId();
        var json = "{\"Req\":\"event\",\"Timestamp\":\"2026-10-12T06:06:50.1234567Z\","
            + $"\"HardwareId\":\"{hardwareId}\",\"AppName\":\"{product.Name}\",\"Version\":\"1.9.3\","
            + "\"EventName\":\"AppUninstalled\",\"Properties\":{\"Schema\":\"HardwareIdObservationV2\","
            + "\"Source\":\"MSI\",\"SettingsPresent\":\"True\"}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        Assert.Equal("AppUninstalled", record.EventName);
        Assert.Equal("1.9.3", record.Version);
        AssertProperties(
            record,
            ("Schema", "HardwareIdObservationV2"),
            ("Source", "MSI"),
            ("SettingsPresent", "True"));
    }

    /// <summary>
    /// Proves that no JSON shape of <c>req</c> can reject the request: scalars, null, arrays, an empty
    /// object, and objects whose nested members are unusable are all ignored, and the outer event is
    /// stored unchanged.
    /// </summary>
    /// <param name="reqJson">The raw JSON text placed after <c>"req":</c>.</param>
    [Theory]
    [InlineData("\"event\"")]
    [InlineData("\"\"")]
    [InlineData("42")]
    [InlineData("-1.5e3")]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("[1,\"a\",{\"type\":\"Error\"},[null]]")]
    [InlineData("{}")]
    [InlineData("{\"type\":5}")]
    [InlineData("{\"type\":[\"Error\"]}")]
    [InlineData("{\"properties\":\"not-an-object\"}")]
    [InlineData("{\"properties\":{\"Count\":1}}")]
    [InlineData("{\"properties\":{\"Kept\":\"no\",\"Nested\":{\"a\":1}}}")]
    [InlineData("{\"properties\":[\"a\"]}")]
    [InlineData("{\"unknown\":{\"deep\":[1,2,{\"x\":null}]}}")]
    public async Task PostEvent_AnyUnusableReqShape_ShouldBeIgnoredWithoutRejectingTheEvent(string reqJson)
    {
        var product = await fixture.CreateProductAsync("req-shape");
        var hardwareId = NewHardwareId();
        // req is the first member: a value that is not fully consumed would corrupt every member
        // that follows it, including the routing identity.
        var json = $"{{\"req\":{reqJson},\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.0.0\","
            + "\"eventName\":\"UsageSample\",\"properties\":{\"Outer\":\"kept\"}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        Assert.Equal("UsageSample", record.EventName);
        Assert.Equal("1.0.0", record.Version);
        AssertProperties(record, ("Outer", "kept"));
    }

    /// <summary>
    /// Proves that an ignored <c>req</c> value is fully consumed when it is the last member, so the
    /// request still binds and the event is stored.
    /// </summary>
    /// <param name="reqJson">The raw JSON text placed after the trailing <c>"req":</c>.</param>
    [Theory]
    [InlineData("\"event\"")]
    [InlineData("[[1,2],[3]]")]
    [InlineData("{\"properties\":7}")]
    [InlineData("{\"type\":{\"name\":\"Error\"}}")]
    public async Task PostEvent_UnusableReqAsLastMember_ShouldBeIgnored(string reqJson)
    {
        var product = await fixture.CreateProductAsync("req-last");
        var hardwareId = NewHardwareId();
        var json = "{\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.0.0\","
            + $"\"eventName\":\"UsageSample\",\"properties\":{{\"Outer\":\"kept\"}},\"req\":{reqJson}}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        AssertProperties(record, ("Outer", "kept"));
    }

    /// <summary>
    /// Proves that a large ignored <c>req</c> value (one mebibyte of text) is skipped without
    /// rejecting the event: the value is not materialized, only consumed.
    /// </summary>
    [Fact]
    public async Task PostEvent_LargeStringReq_ShouldBeIgnoredWithoutRejectingTheEvent()
    {
        var product = await fixture.CreateProductAsync("req-large");
        var hardwareId = NewHardwareId();
        var json = $"{{\"req\":\"{new string('x', 1024 * 1024)}\",\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.0.0\","
            + "\"eventName\":\"UsageSample\",\"properties\":{\"Outer\":\"kept\"}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        AssertProperties(record, ("Outer", "kept"));
    }

    /// <summary>
    /// Proves the nesting boundary of an ignored <c>req</c> value: a moderately nested array is
    /// skipped, while nesting beyond the JSON reader's maximum depth is still rejected for the whole
    /// body, exactly as an unmapped member was rejected before this change.
    /// </summary>
    /// <param name="depth">The number of nested arrays placed in <c>req</c>.</param>
    /// <param name="expected">The status the endpoint must return.</param>
    [Theory]
    [InlineData(16, HttpStatusCode.OK)]
    [InlineData(512, HttpStatusCode.BadRequest)]
    public async Task PostEvent_NestedArrayReq_ShouldFollowTheReaderDepthLimit(int depth, HttpStatusCode expected)
    {
        var product = await fixture.CreateProductAsync("req-depth");
        var hardwareId = NewHardwareId();
        var nested = new string('[', depth) + new string(']', depth);
        var json = $"{{\"req\":{nested},\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.0.0\","
            + "\"eventName\":\"UsageSample\",\"properties\":{\"Outer\":\"kept\"}}";

        using var response = await PostRawAsync(json);

        Assert.Equal(expected, response.StatusCode);
        await using var db = fixture.CreateDb();
        Assert.Equal(
            expected == HttpStatusCode.OK,
            await db.TelemetryRecords.AnyAsync(record => record.HardwareId == hardwareId));
    }

    /// <summary>
    /// Replays the T-IA Connect payload shape (<c>BuildTelemetryPayload</c>): direct members plus an
    /// equivalent nested <c>req</c> object. The object form must keep its TKT-001758 behavior.
    /// </summary>
    [Fact]
    public async Task PostEvent_TiaConnectPayloadWithObjectReq_ShouldKeepExplicitErrorClassification()
    {
        var product = await fixture.CreateProductAsync("tia-connect");
        var hardwareId = NewHardwareId();
        var inner = "\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"2.4.993\","
            + "\"eventName\":\"LicenseActivation_InvalidKey\",\"type\":\"Error\","
            + "\"properties\":{\"FailureReason\":\"InvalidKey\",\"CorrelationId\":\"corr-1768\"}";
        var json = $"{{{inner},\"req\":{{{inner}}}}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Error, record.Type);
        Assert.Equal("LicenseActivation_InvalidKey", record.EventName);
        Assert.Equal("2.4.993", record.Version);
        Assert.Null(record.ErrorData);
        AssertProperties(record, ("FailureReason", "InvalidKey"), ("CorrelationId", "corr-1768"));
    }

    /// <summary>
    /// Replays an ordinary T-IA Connect event, whose <c>type</c> is the event-kind name rather than
    /// <c>Error</c>, and proves it stays an event with the outer properties.
    /// </summary>
    [Fact]
    public async Task PostEvent_TiaConnectOrdinaryPayloadWithObjectReq_ShouldRemainEvent()
    {
        var product = await fixture.CreateProductAsync("tia-ordinary");
        var hardwareId = NewHardwareId();
        var inner = "\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"2.4.993\","
            + "\"eventName\":\"Startup_Ready\",\"type\":\"StartupPing\","
            + "\"properties\":{\"Step\":\"Ready\"}";
        var json = $"{{{inner},\"req\":{{{inner}}}}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        Assert.Equal("2.4.993", record.Version);
        AssertProperties(record, ("Step", "Ready"));
    }

    /// <summary>
    /// Proves that a producer sending only the nested object still has its classification and
    /// properties recovered from <c>req</c>, exactly as before this change, including when the
    /// nested member names use another casing.
    /// </summary>
    /// <param name="typeName">The nested classification member name as sent on the wire.</param>
    /// <param name="propertiesName">The nested property-bag member name as sent on the wire.</param>
    [Theory]
    [InlineData("type", "properties")]
    [InlineData("Type", "Properties")]
    [InlineData("TYPE", "PROPERTIES")]
    public async Task PostEvent_ObjectReqOnly_ShouldRecoverNestedTypeAndProperties(
        string typeName,
        string propertiesName)
    {
        var product = await fixture.CreateProductAsync("nested-only");
        var hardwareId = NewHardwareId();
        var json = "{\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"2.4.0\","
            + "\"eventName\":\"LicenseActivation_NetworkError\","
            + $"\"req\":{{\"{typeName}\":\"Error\",\"ignored\":[1,{{\"a\":2}}],"
            + $"\"{propertiesName}\":{{\"FailureReason\":\"NetworkError\"}}}}}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Error, record.Type);
        AssertProperties(record, ("FailureReason", "NetworkError"));
    }

    /// <summary>
    /// Proves that a nested object whose <c>type</c> is not a string still contributes its usable
    /// properties while the unusable classification is ignored.
    /// </summary>
    [Fact]
    public async Task PostEvent_ObjectReqWithNonStringType_ShouldIgnoreTypeAndKeepNestedProperties()
    {
        var product = await fixture.CreateProductAsync("nested-type");
        var hardwareId = NewHardwareId();
        var json = "{\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"2.4.0\","
            + "\"eventName\":\"UsageSample\","
            + "\"req\":{\"type\":{\"name\":\"Error\"},\"properties\":{\"Nested\":\"kept\"}}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        AssertProperties(record, ("Nested", "kept"));
    }

    /// <summary>
    /// Locks the repeated-member rule: like every other member bound by System.Text.Json, the last
    /// occurrence of <c>req</c> wins, whatever its casing. The order of an object and a string
    /// occurrence therefore decides whether the nested classification is used.
    /// </summary>
    /// <param name="objectFirst">Whether the object occurrence precedes the string occurrence.</param>
    /// <param name="expected">The classification that must be stored.</param>
    [Theory]
    [InlineData(true, TelemetryType.Event)]
    [InlineData(false, TelemetryType.Error)]
    public async Task PostEvent_RepeatedReqMember_LastOccurrenceWins(bool objectFirst, TelemetryType expected)
    {
        var product = await fixture.CreateProductAsync("req-repeated");
        var hardwareId = NewHardwareId();
        const string objectReq = "\"req\":{\"type\":\"Error\"}";
        const string stringReq = "\"REQ\":\"event\"";
        var (first, second) = objectFirst ? (objectReq, stringReq) : (stringReq, objectReq);
        var json = $"{{{first},\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.0.0\","
            + $"\"eventName\":\"UsageSample\",\"properties\":{{\"Outer\":\"kept\"}},{second}}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(expected, record.Type);
        AssertProperties(record, ("Outer", "kept"));
    }

    /// <summary>
    /// Proves that the request without any <c>req</c> or <c>type</c> member, the shape accepted before
    /// TKT-001758, is still accepted.
    /// </summary>
    [Fact]
    public async Task PostEvent_WithoutReqAndType_ShouldBeAcceptedAsEvent()
    {
        var product = await fixture.CreateProductAsync("no-req");
        var hardwareId = NewHardwareId();
        var json = "{\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.0.0\","
            + "\"eventName\":\"UsageSample\",\"properties\":{\"Outer\":\"kept\"}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        Assert.Equal("1.0.0", record.Version);
        AssertProperties(record, ("Outer", "kept"));
    }

    /// <summary>
    /// Proves that an outer string <c>type</c> other than the exact value <c>Error</c>, including
    /// case and whitespace lookalikes, never produces the error classification.
    /// </summary>
    /// <param name="typeJson">The raw JSON string placed after <c>"type":</c>.</param>
    [Theory]
    [InlineData("\"error\"")]
    [InlineData("\"ERROR\"")]
    [InlineData("\" Error\"")]
    [InlineData("\"Error \"")]
    [InlineData("\"StartupPing\"")]
    [InlineData("\"\"")]
    [InlineData("null")]
    public async Task PostEvent_OuterStringTypeThatIsNotExactError_ShouldBeAcceptedAsEvent(string typeJson)
    {
        var product = await fixture.CreateProductAsync("outer-type");
        var hardwareId = NewHardwareId();
        var json = $"{{\"req\":\"event\",\"type\":{typeJson},\"timestamp\":\"2026-10-12T06:06:50Z\","
            + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.0.0\","
            + "\"eventName\":\"UsageSample\",\"properties\":{\"Outer\":\"kept\"}}";

        var record = await PostRawAndReadAsync(product, hardwareId, json);

        Assert.Equal(TelemetryType.Event, record.Type);
        AssertProperties(record, ("Outer", "kept"));
    }

    /// <summary>
    /// Proves that tolerance is limited to <c>req</c>: every body the endpoint already rejected is
    /// still rejected by model binding and writes nothing. This covers a non-string outer
    /// <c>type</c>, a non-string outer property value, and JSON that is not well formed.
    /// </summary>
    /// <param name="template">The body, with placeholders for the hardware identifier and app name.</param>
    [Theory]
    [InlineData("{\"req\":\"event\",\"type\":5,\"hardwareId\":\"<H>\",\"appName\":\"<A>\",\"eventName\":\"UsageSample\"}")]
    [InlineData("{\"req\":\"event\",\"hardwareId\":\"<H>\",\"appName\":\"<A>\",\"eventName\":\"UsageSample\",\"type\":{\"value\":\"Error\"}}")]
    [InlineData("{\"req\":\"event\",\"type\":[\"Error\"],\"hardwareId\":\"<H>\",\"appName\":\"<A>\",\"eventName\":\"UsageSample\"}")]
    [InlineData("{\"req\":\"event\",\"hardwareId\":\"<H>\",\"appName\":\"<A>\",\"eventName\":\"UsageSample\",\"properties\":{\"Count\":1}}")]
    [InlineData("{\"req\":\"event\",\"hardwareId\":\"<H>\",\"appName\":\"<A>\",\"eventName\":\"UsageSample\"")]
    [InlineData("{\"req\":{\"type\":\"Error\",\"hardwareId\":\"<H>\",\"appName\":\"<A>\",\"eventName\":\"UsageSample\"")]
    public async Task PostEvent_BodyRejectedBeforeThisChange_ShouldStillBeRejected(string template)
    {
        var product = await fixture.CreateProductAsync("still-rejected");
        var hardwareId = NewHardwareId();
        var json = template
            .Replace("<H>", hardwareId, StringComparison.Ordinal)
            .Replace("<A>", product.Name, StringComparison.Ordinal);

        using var response = await PostRawAsync(json);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await using var db = fixture.CreateDb();
        Assert.False(await db.TelemetryRecords.AnyAsync(record => record.HardwareId == hardwareId));
    }

    /// <summary>
    /// Builds the exact camel-case body the YOUR_APP_NAME desktop client serializes for an event.
    /// </summary>
    /// <param name="product">The product whose name authorizes the request.</param>
    /// <param name="hardwareId">The unique hardware identifier of the test row.</param>
    /// <returns>The raw JSON request body.</returns>
    private static string YOUR_APP_NAMEDesktopJson(Product product, string hardwareId) =>
        "{\"req\":\"event\",\"timestamp\":\"2026-10-12T06:06:50.1234567Z\","
        + $"\"hardwareId\":\"{hardwareId}\",\"appName\":\"{product.Name}\",\"version\":\"1.9.3\","
        + "\"eventName\":\"AppHeartbeat\",\"properties\":{\"Uptime\":\"240\",\"Mode\":\"Softphone\"}}";

    /// <summary>
    /// Posts raw JSON text, with a declared length, through the public event endpoint.
    /// </summary>
    /// <param name="json">The exact request body to send.</param>
    /// <returns>The response, owned by the caller.</returns>
    private async Task<HttpResponseMessage> PostRawAsync(string json)
    {
        using var client = fixture.CreateClient();
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await client.PostAsync("/api/telemetry/event", content);
    }

    /// <summary>
    /// Posts raw JSON text through the public event endpoint, requires the success status deployed
    /// producers rely on, and reloads the single relational row written for the request.
    /// </summary>
    /// <param name="product">The unique product that authorizes the app name used by the endpoint.</param>
    /// <param name="hardwareId">The unique hardware identifier used to select the inserted row.</param>
    /// <param name="json">The exact request body to send.</param>
    /// <returns>The single row persisted for the supplied product and hardware identity.</returns>
    private async Task<TelemetryRecord> PostRawAndReadAsync(Product product, string hardwareId, string json)
    {
        using var response = await PostRawAsync(json);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(
            response.StatusCode == HttpStatusCode.OK,
            $"Expected 200 OK but received {(int)response.StatusCode}: {body}");

        return await ReadSingleAsync(product, hardwareId);
    }

    /// <summary>
    /// Reloads the single relational row written for one product and hardware identity, including
    /// both specialized-data navigation properties.
    /// </summary>
    /// <param name="product">The product that authorized the request.</param>
    /// <param name="hardwareId">The unique hardware identifier of the test row.</param>
    /// <returns>The single persisted row.</returns>
    private async Task<TelemetryRecord> ReadSingleAsync(Product product, string hardwareId)
    {
        await using var db = fixture.CreateDb();
        return await db.TelemetryRecords
            .AsNoTracking()
            .Include(record => record.EventData)
            .Include(record => record.ErrorData)
            .SingleAsync(record => record.ProductId == product.Id && record.HardwareId == hardwareId);
    }

    /// <summary>
    /// Asserts that the stored event payload contains exactly the expected key/value pairs.
    /// </summary>
    /// <param name="record">The reloaded telemetry row.</param>
    /// <param name="expected">The exact properties the producer submitted.</param>
    private static void AssertProperties(TelemetryRecord record, params (string Key, string Value)[] expected)
    {
        var propertiesJson = record.EventData?.PropertiesJson;
        Assert.False(string.IsNullOrWhiteSpace(propertiesJson));
        var actual = JsonSerializer.Deserialize<Dictionary<string, string>>(propertiesJson!);
        Assert.NotNull(actual);
        Assert.Equal(expected.Length, actual.Count);
        foreach (var (key, value) in expected)
            Assert.Equal(value, actual[key]);
    }

    /// <summary>
    /// Creates a canonical uppercase hexadecimal hardware identifier that is unique to one test row.
    /// </summary>
    /// <returns>A 16-character identifier accepted by the telemetry endpoint.</returns>
    private static string NewHardwareId() => Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();

    /// <summary>
    /// Sends a byte buffer as a body whose length is not declared in advance and which is written
    /// to the transport in small pieces.
    /// </summary>
    /// <param name="buffer">The complete request body.</param>
    private sealed class UnknownLengthContent(byte[] buffer) : HttpContent
    {
        /// <summary>
        /// Writes the body in small pieces so it reaches the server across several reads.
        /// </summary>
        /// <param name="stream">The transport stream.</param>
        /// <param name="context">The transport context, unused.</param>
        /// <returns>A task that completes when the whole body is written.</returns>
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            for (var offset = 0; offset < buffer.Length; offset += 64)
            {
                await stream.WriteAsync(buffer.AsMemory(offset, Math.Min(64, buffer.Length - offset)));
                await stream.FlushAsync();
            }
        }

        /// <summary>
        /// Reports that the length is unknown so the content cannot declare it up front.
        /// </summary>
        /// <param name="length">Always zero.</param>
        /// <returns><see langword="false"/>.</returns>
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}

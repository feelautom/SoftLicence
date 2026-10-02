using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SoftLicence.Server.Models;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Verifies strict parsing, canonical bytes, privacy rejection families, and the frozen cross-repository corpus identity.
/// </summary>
public sealed class RecoveryTelemetryParserTests
{
    /// <summary>Proves the frozen stage error map accepts outbox I/O failures broadly but keeps elevated-preflight authority exact.</summary>
    [Fact]
    public void StageErrorMap_MatchesFrozenClientContract()
    {
        var preflight = RecoveryTelemetryParser.Parse(ReadFixture("P01_nominal_uac_complete")[1]).Envelope!;
        var outboxFailure = RecoveryTelemetryParser.SerializeCanonical(preflight with
        {
            Outcome = "failed",
            ErrorCode = "outbox_io_failed"
        });
        Assert.True(RecoveryTelemetryParser.Parse(outboxFailure).IsSuccess);

        var elevatedPreflight = RecoveryTelemetryParser.Parse(ReadFixture("P01_nominal_uac_complete")[9]).Envelope!;
        var invalidAuthority = RecoveryTelemetryParser.SerializeCanonical(elevatedPreflight with
        {
            Outcome = "failed",
            ErrorCode = "transaction_invalid"
        });
        Assert.Equal(RecoveryTelemetryCodes.InvalidFieldValue, RecoveryTelemetryParser.Parse(invalidAuthority).RejectionCode);
    }

    /// <summary>Proves the materialized server corpus remains byte-identical to the client handoff.</summary>
    [Fact]
    public void Corpus_HasFrozenHashAndFixtureCount()
    {
        var bytes = File.ReadAllBytes(CorpusPath);
        Assert.False(bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }));
        Assert.Equal(37_679, bytes.Length);
        Assert.Equal("10c768770016495b7cadc0c4ffa7f7e264ab87080128826d7a9372f223a05369",
            Convert.ToHexStringLower(SHA256.HashData(bytes)));
        using var document = JsonDocument.Parse(bytes);
        Assert.Equal(23, document.RootElement.GetProperty("fixtures").GetArrayLength());
    }

    /// <summary>Proves every canonical fixture request is either field-valid or carries its exact frozen parser rejection.</summary>
    [Fact]
    public void CorpusRequests_MatchFrozenParserOutcomes()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(CorpusPath));
        foreach (var fixture in document.RootElement.GetProperty("fixtures").EnumerateArray())
        {
            var requests = fixture.GetProperty("requestBytes").EnumerateArray()
                .Select(item => MaterializeRequest(fixture, item.GetString()!)).ToList();
            var codes = fixture.TryGetProperty("expectedBodyCodes", out var expectedCodes)
                ? expectedCodes.EnumerateArray().Select(item => item.GetString()!).ToList()
                : [];
            for (var index = 0; index < requests.Count; index++)
            {
                var result = RecoveryTelemetryParser.Parse(requests[index]);
                var expectedParserRejection = index < codes.Count && codes[index] is
                    "malformed_product_code" or "malformed_run_id" or "malformed_event_id" or
                    "sequence_out_of_range" or "invalid_timestamp" or "unknown_stage" or "unknown_outcome" or
                    "invalid_stage_outcome" or "unknown_field" or "invalid_field_value" or "payload_too_large";
                if (expectedParserRejection)
                    Assert.Equal(codes[index], result.RejectionCode);
                else
                    Assert.True(result.IsSuccess, $"{fixture.GetProperty("id").GetString()} request {index}: {result.RejectionCode}");
            }
        }
    }

    /// <summary>Proves accepted bytes reserialize identically, which is required for exact payload hashing.</summary>
    [Fact]
    public void CanonicalRequest_RoundTripsExactBytes()
    {
        const string request = "{\"schemaVersion\":1,\"productCode\":\"TIA_CONNECT\",\"eventId\":\"00000000-0000-4000-8000-000000000001\",\"recoveryRunId\":\"10000000-0000-4000-8000-000000000001\",\"sequence\":1,\"occurredAtUtc\":\"2026-08-21T12:00:01.000000Z\",\"clientVersion\":\"2.3.404\",\"processRole\":\"unelevated\",\"stage\":\"run\",\"outcome\":\"started\"}";
        var bytes = Encoding.UTF8.GetBytes(request);
        var parsed = RecoveryTelemetryParser.Parse(bytes);
        Assert.NotNull(parsed.Envelope);
        Assert.Equal(bytes, RecoveryTelemetryParser.SerializeCanonical(parsed.Envelope!));
    }

    private static string CorpusPath => Path.Combine(AppContext.BaseDirectory, "TestData", "recovery-telemetry-v1.corpus.json");

    /// <summary>Reads every exact request byte string for one named fixture.</summary>
    private static IReadOnlyList<byte[]> ReadFixture(string id)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(CorpusPath));
        var fixture = document.RootElement.GetProperty("fixtures").EnumerateArray()
            .Single(item => item.GetProperty("id").GetString() == id);
        return fixture.GetProperty("requestBytes").EnumerateArray()
            .Select(item => Encoding.UTF8.GetBytes(item.GetString()!)).ToList();
    }

    /// <summary>Expands an explicitly declared corpus byte placeholder without changing the shared corpus file.</summary>
    private static byte[] MaterializeRequest(JsonElement fixture, string request)
    {
        if (!fixture.TryGetProperty("byteMaterialization", out var materialization)
            || !materialization.TryGetProperty(request, out var descriptor))
            return Encoding.UTF8.GetBytes(request);
        var asciiByte = descriptor.GetProperty("asciiByte").GetString()!;
        var count = descriptor.GetProperty("count").GetInt32();
        Assert.Single(asciiByte);
        return Enumerable.Repeat((byte)asciiByte[0], count).ToArray();
    }
}

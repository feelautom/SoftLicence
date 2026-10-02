using System.ComponentModel;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using SoftLicence.Mcp;
using SoftLicence.Server.Components.Shared;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Checks typed history presentation and MCP transport with synthetic in-memory data and no external calls.</summary>
public sealed class LicenseDecisionHistoryPresentationTests
{
    /// <summary>Incomplete identities, oversized UTF8 content and malformed nested facts remain unavailable rather than becoming plausible administrator evidence.</summary>
    /// <remarks>The licence/product link is provided by the authorized caller. Unicode remains unnormalized; the bound is bytes, not UTF16 characters. No malformed raw JSON is returned.</remarks>
    [Theory]
    [InlineData("code")]
    [InlineData("phase")]
    [InlineData("operation")]
    [InlineData("guarantee")]
    [InlineData("product")]
    [InlineData("product-mismatch")]
    [InlineData("utf8")]
    [InlineData("null-seat")]
    public void Projection_MalformedContracts_AreUnavailable(string mode)
    {
        var licenseId = Guid.NewGuid();
        var productId = Guid.NewGuid();
        var snapshot = new LicenseDecisionSnapshot(productId, licenseId, null, null,
            0, 1, null, null, null, [], false, null, "hardware_lock_observation");
        var decision = new LicenseDecisionHistory(1, "legacy_activation", "request", "refused", "SEAT_LIMIT",
            null, 400, "HWID", null, null, null, snapshot, null);
        decision = mode switch
        {
            "code" => decision with { Code = null! },
            "phase" => decision with { Phase = null! },
            "operation" => decision with { OperationId = null! },
            "guarantee" => decision with { Snapshot = snapshot with { ObservationGuarantee = null! } },
            "product" => decision with { Snapshot = snapshot with { ProductId = Guid.Empty } },
            "product-mismatch" => decision with { Snapshot = snapshot with { ProductId = Guid.NewGuid() } },
            "utf8" => decision with { AppVersion = new string('漢', 90000) },
            "null-seat" => decision with { Snapshot = snapshot with { ActiveSeatDetails = new LicenseDecisionSeat[] { null! } } },
            _ => throw new InvalidOperationException("Unknown synthetic mode.")
        };
        var details = JsonSerializer.Serialize(decision, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        var projection = LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
        { LicenseId = licenseId, License = new SoftLicence.Server.Data.License { Id = licenseId, ProductId = productId },
            Action = "ACTIVATION_DECISION_V1", Details = details });
        Assert.Equal("unavailable", projection.ParseStatus);
        Assert.Null(projection.Decision);
    }

    /// <summary>Another-HWID quota classification requires every original authority fact, never a hardware-lock-only observation.</summary>
    [Theory]
    [InlineData("ordered_authority_locks", false, 1, 1, "expected_other_hwid_seat_limit")]
    [InlineData("runtime_authority_locks", false, 2, 1, "expected_other_hwid_seat_limit")]
    [InlineData("hardware_lock_observation", false, 1, 1, "refusal_observed")]
    [InlineData("ordered_authority_locks", true, 1, 1, "refusal_observed")]
    [InlineData("ordered_authority_locks", null, 1, 1, "refusal_observed")]
    [InlineData("ordered_authority_locks", false, 0, 1, "refusal_observed")]
    public void Classification_RequiresStoredAuthorityFacts(string guarantee, bool? sameHardware,
        int occupied, int limit, string expected)
    {
        var licenseId = Guid.NewGuid();
        var snapshot = new LicenseDecisionSnapshot(Guid.NewGuid(), licenseId, null, null,
            occupied, limit, null, null, null, [], false, sameHardware, guarantee);
        var decision = new LicenseDecisionHistory(1, "distribution_finalize", "op", "refused",
            "seat_limit_reached", null, 422, "new-hwid", "new-hwid", null, "provider_direct", snapshot, null);
        var projection = new LicenseDecisionHistoryProjection(Guid.NewGuid(), licenseId, DateTime.UtcNow,
            decision, "available", "/licenses");
        Assert.Equal(expected, projection.Classification);
    }

    /// <summary>Malformed, unknown-version and legacy rows cannot expose raw content or invent provenance.</summary>
    [Theory]
    [InlineData("ACTIVATION_DECISION_V1", "{broken-secret", "unavailable")]
    [InlineData("ACTIVATION_DECISION_V1", "{\"version\":99}", "unavailable")]
    [InlineData("CREATED", "historical secret", "legacy")]
    public void Projection_UnknownContent_DoesNotExposeRawDetails(string action, string details, string status)
    {
        var projection = LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
            { LicenseId = Guid.NewGuid(), Action = action, Details = details });
        Assert.Null(projection.Decision);
        Assert.Equal(status, projection.ParseStatus);
        Assert.DoesNotContain(details, JsonSerializer.Serialize(projection));
    }

    /// <summary>Razor encodes hostile observed identifiers and explicitly displays unknown provenance and the original locking guarantee.</summary>
    [Fact]
    public async Task HistoryComponent_EncodesEvidenceAndDisplaysUtcAndObservationLimits()
    {
        var licenseId = Guid.NewGuid();
        var snapshot = new LicenseDecisionSnapshot(Guid.NewGuid(), licenseId, null, null,
            1, 1, null, 0, null, [], false, null, "hardware_lock_observation");
        var decision = new LicenseDecisionHistory(1, "legacy_activation", "request:test", "refused",
            "SEAT_LIMIT", null, 400, "<script>unsafe</script>", "provider:HWID", null,
            "provider_direct", snapshot, null);
        var row = new LicenseHistory { LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
            Timestamp = new DateTime(2026, 9, 6, 12, 0, 0, DateTimeKind.Utc),
            Details = JsonSerializer.Serialize(decision, new JsonSerializerOptions(JsonSerializerDefaults.Web)) };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization();
        services.AddSingleton<TimeZoneService>();
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = await renderer.RenderComponentAsync<LicenseDecisionDetails>(
                ParameterView.FromDictionary(new Dictionary<string, object?>
                { [nameof(LicenseDecisionDetails.Entry)] = LicenseDecisionHistoryProjection.FromHistory(row) }));
            return component.ToHtmlString();
        });
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("hardware_lock_observation", html);
        Assert.Contains("2026-09-06 12:00:00 UTC", html);
        Assert.Contains("2026-09-06 14:00:00", html);
        Assert.Contains("provider:HWID", html);
        Assert.DoesNotContain("licenseKey", html, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Tool discovery and pretransport bounds prevent accidental unbounded administrator reads.</summary>
    [Fact]
    public async Task McpTool_IsDiscoverableAndRejectsUntargetedOrInvalidPages()
    {
        var method = typeof(SoftLicenceAnalyticsTools).GetMethod(nameof(SoftLicenceAnalyticsTools.GetLicenseDecisions))!;
        Assert.NotNull(method.GetCustomAttribute<McpServerToolAttribute>());
        Assert.NotNull(method.GetCustomAttribute<DescriptionAttribute>());
        var tools = new SoftLicenceAnalyticsTools(null!, null!);
        await Assert.ThrowsAsync<ArgumentException>(() => tools.GetLicenseDecisions());
        await Assert.ThrowsAsync<ArgumentException>(() => tools.GetLicenseDecisions(requestId: "r", take: 201));
        await Assert.ThrowsAsync<ArgumentException>(() => tools.GetLicenseDecisions(requestId: "r", offset: -1));
        await Assert.ThrowsAsync<ArgumentException>(() => tools.GetLicenseDecisions(hardwareId: " HWID"));
    }

    /// <summary>The Runtime diagnostic is discoverable and rejects identifiers that would require normalization.</summary>
    [Fact]
    public async Task RuntimeAuthorityDiagnostic_IsDiscoverableAndRequiresCanonicalRequestId()
    {
        var method = typeof(SoftLicenceAnalyticsTools).GetMethod(
            nameof(SoftLicenceAnalyticsTools.GetRuntimeEnrollmentAuthorityDiagnostic))!;
        Assert.NotNull(method.GetCustomAttribute<McpServerToolAttribute>());
        Assert.NotNull(method.GetCustomAttribute<DescriptionAttribute>());
        var tools = new SoftLicenceAnalyticsTools(null!, null!);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            tools.GetRuntimeEnrollmentAuthorityDiagnostic("997F36D2-6790-4863-A4D3-76DB7F65CB44"));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            tools.GetRuntimeEnrollmentAuthorityDiagnostic(" 997f36d2-6790-4863-a4d3-76db7f65cb44"));
    }

    /// <summary>Candidate reasons survive the validated history projection without exposing subject digests.</summary>
    [Fact]
    public void Projection_AcceptsBoundedReplacementCandidateDiagnostics()
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var decision = new LicenseDecisionHistory(1, "distribution_finalize", Guid.NewGuid().ToString("D"),
            "refused", "binding_conflict", "replacement_candidate_none", 409, "HWID", "HWID",
            null, "provider_direct", new LicenseDecisionSnapshot(productId, licenseId, null, 1,
                0, 1, 0, 0, null, [], false, false, "ordered_authority_locks"), "2.3.986",
            ReplacementCandidates:
            [
                new LicenseReplacementCandidateDecision(Guid.NewGuid(), Guid.NewGuid(), "rejected",
                    ["source_license_mismatch", "not_selected_recovery_source"])
            ],
            SelectionOutcome: "none");
        var row = new LicenseHistory
        {
            Id = Guid.NewGuid(), LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
            Timestamp = DateTime.UtcNow,
            Details = JsonSerializer.Serialize(decision, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
        };

        var projection = LicenseDecisionHistoryProjection.FromHistory(row, productId);
        Assert.Equal("available", projection.ParseStatus);
        Assert.Equal("none", projection.Decision!.SelectionOutcome);
        Assert.Equal("source_license_mismatch",
            Assert.Single(projection.Decision.ReplacementCandidates!).ReasonCodes[0]);
        Assert.DoesNotContain("subject", row.Details!, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Observed empty candidate evidence remains distinct from legacy absent evidence.</summary>
    [Fact]
    public void Projection_PreservesObservedEmptyReplacementCandidates()
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var snapshot = new LicenseDecisionSnapshot(productId, licenseId, null, 1,
            0, 1, 0, 0, null, [], false, false, "ordered_authority_locks");
        var observedEmpty = new LicenseDecisionHistory(1, "distribution_finalize", Guid.NewGuid().ToString("D"),
            "refused", "binding_conflict", "replacement_candidate_none", 409, "HWID", "HWID",
            null, "provider_direct", snapshot, "2.3.986", ReplacementCandidates: [], SelectionOutcome: "none");
        var legacyAbsent = observedEmpty with { ReplacementCandidates = null, SelectionOutcome = null };

        LicenseDecisionHistoryProjection Project(LicenseDecisionHistory decision) =>
            LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
            {
                Id = Guid.NewGuid(), LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
                Timestamp = DateTime.UtcNow,
                Details = JsonSerializer.Serialize(decision, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            }, productId);

        Assert.Empty(Project(observedEmpty).Decision!.ReplacementCandidates!);
        Assert.Null(Project(legacyAbsent).Decision!.ReplacementCandidates);
    }

    /// <summary>Null or unknown candidate reasons fail closed without throwing or exposing malformed content.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("unknown")]
    public void Projection_InvalidReplacementCandidateReasons_AreUnavailable(string mode)
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var reasons = mode == "null" ? "null" : "[\"unknown_reason\"]";
        var details = $$"""
            {"version":1,"phase":"distribution_finalize","operationId":"{{Guid.NewGuid():D}}","outcome":"refused","code":"binding_conflict","reasonCode":"replacement_candidate_none","httpStatus":409,"submittedHardwareId":"HWID","resolvedHardwareId":"HWID","resolutionSource":"provider_direct","snapshot":{"productId":"{{productId:D}}","licenseId":"{{licenseId:D}}","activeSeatDetails":[],"activeSeatDetailsTruncated":false,"resolvedHardwareAlreadyActive":false,"observationGuarantee":"ordered_authority_locks"},"appVersion":"2.3.986","replacementCandidates":[{"sourceBindingId":"{{Guid.NewGuid():D}}","sourceLicenseId":"{{Guid.NewGuid():D}}","outcome":"rejected","reasonCodes":{{reasons}}}],"selectionOutcome":"none"}
            """;

        var projection = LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
        {
            Id = Guid.NewGuid(), LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
            Timestamp = DateTime.UtcNow, Details = details,
        }, productId);

        Assert.Equal("unavailable", projection.ParseStatus);
        Assert.Null(projection.Decision);
    }

    /// <summary>Structured provider errors cannot be downgraded to an empty historical diagnostic.</summary>
    [Fact]
    public async Task RuntimeAuthorityDiagnostic_RejectsStructuredDecisionErrors()
    {
        using var http = new HttpClient(new DecisionHandler(_ => new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent("{\"ok\":false,\"errorCode\":\"provider_failure\"}", Encoding.UTF8,
                "application/json")
        }));
        var client = new SoftLicenceAnalyticsClient(http, Options.Create(new SoftLicenceMcpOptions
            { SoftLicenceBaseUrl = "https://synthetic.invalid", SoftLicenceApiKey = "synthetic" }));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetRuntimeEnrollmentAuthorityDiagnosticAsync(Guid.NewGuid().ToString("D"), null,
                "tiaconnect", CancellationToken.None));
    }

    /// <summary>A large provider page stays composable instead of becoming an unreadable intermediate artifact.</summary>
    [Fact]
    public async Task RuntimeAuthorityDiagnostic_ComposesOversizedDecisionPageBeforeFinalDelivery()
    {
        var requestId = Guid.NewGuid().ToString("D");
        var resultRoot = Path.Combine(Path.GetTempPath(), $"softlicence-diagnostic-{Guid.NewGuid():N}");
        var requests = new List<string>();
        using var http = new HttpClient(new DecisionHandler(request =>
        {
            requests.Add(request.RequestUri!.AbsolutePath);
            if (request.RequestUri.AbsolutePath.EndsWith("/license-decisions/request-snapshot", StringComparison.Ordinal))
            {
                var page = JsonSerializer.Serialize(new
                {
                    requestId,
                    complete = true,
                    items = new[] { new { parseStatus = "available", decision = new
                    {
                        submittedHardwareId = "HWID-LARGE-PAGE",
                        replacementCandidates = Array.Empty<object>(),
                        diagnosticPadding = new string('x', 20_000)
                    } } }
                });
                return new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new StringContent(page, Encoding.UTF8, "application/json") };
            }
            var json = request.RequestUri.AbsolutePath switch
            {
                "/api/analytics/security/bans" => """{"recordsMatched":0,"recordsReturned":0,"resolvedHardwareIds":["HWID-LARGE-PAGE"],"bans":[]}""",
                "/api/analytics/security/canary-alerts" => """{"groupsMatched":0,"groupsReturned":0,"alerts":[]}""",
                "/api/analytics/telemetry/machine-profile" => """{"hardwareId":"HWID-LARGE-PAGE","days":30,"recordsAnalyzed":0,"complete":true,"firstActivityUtc":null,"lastActivityUtc":null,"recentRecords":[]}""",
                _ => throw new InvalidOperationException("Unexpected diagnostic request.")
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }));
        var options = Options.Create(new SoftLicenceMcpOptions
        {
            SoftLicenceBaseUrl = "https://synthetic.invalid",
            SoftLicenceApiKey = "synthetic",
            ResultDirectory = resultRoot,
            MaxInlineResultCharacters = 16_384
        });
        try
        {
            var client = new SoftLicenceAnalyticsClient(http, options);
            var result = await client.GetRuntimeEnrollmentAuthorityDiagnosticAsync(
                requestId, null, "tiaconnect", CancellationToken.None);

            Assert.Equal(4, requests.Count);
            Assert.Equal("/api/analytics/support/license-decisions/request-snapshot", requests[0]);
            Assert.Contains("/api/analytics/security/bans", requests[1], StringComparison.Ordinal);
            Assert.Contains("/api/analytics/security/canary-alerts", requests[2], StringComparison.Ordinal);
            Assert.Contains("/api/analytics/telemetry/machine-profile", requests[3], StringComparison.Ordinal);
            Assert.Equal("artifact", result.GetProperty("resultDelivery").GetString());
        }
        finally
        {
            if (Directory.Exists(resultRoot)) Directory.Delete(resultRoot, recursive: true);
        }
    }

    /// <summary>Distinct bindings may legitimately refer to the same source licence.</summary>
    [Fact]
    public void Projection_SharedSourceLicenseAcrossDistinctBindings_RemainsAvailable()
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var sourceLicenseId = Guid.NewGuid();
        var details = $$"""
            {"version":1,"phase":"distribution_finalize","operationId":"{{Guid.NewGuid():D}}","outcome":"refused","code":"binding_conflict","reasonCode":"replacement_candidate_none","httpStatus":409,"submittedHardwareId":"HWID","resolvedHardwareId":"HWID","resolutionSource":"provider_direct","snapshot":{"productId":"{{productId:D}}","licenseId":"{{licenseId:D}}","activeSeatDetails":[],"activeSeatDetailsTruncated":false,"resolvedHardwareAlreadyActive":false,"observationGuarantee":"ordered_authority_locks"},"appVersion":"2.3.986","replacementCandidates":[{"sourceBindingId":"{{Guid.NewGuid():D}}","sourceLicenseId":"{{sourceLicenseId:D}}","outcome":"rejected","reasonCodes":["source_license_mismatch"]},{"sourceBindingId":"{{Guid.NewGuid():D}}","sourceLicenseId":"{{sourceLicenseId:D}}","outcome":"rejected","reasonCodes":["source_license_mismatch"]}],"selectionOutcome":"none"}
            """;
        var projection = LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
        {
            Id = Guid.NewGuid(), LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
            Timestamp = DateTime.UtcNow, Details = details,
        }, productId);

        Assert.Equal("available", projection.ParseStatus);
        Assert.Equal(2, projection.Decision!.ReplacementCandidates!.Count);
    }

    /// <summary>Structurally safe contradictions remain inspectable and carry an explicit inconsistency marker.</summary>
    [Theory]
    [InlineData("selected", "none", "[]")]
    [InlineData("selected", "selected", "[\"source_license_mismatch\"]")]
    [InlineData("rejected", "none", "[]")]
    [InlineData("not_evaluated", "not_evaluated", "[\"source_license_mismatch\"]")]
    public void Projection_ContradictoryCandidateSelection_IsAvailableButInconsistent(
        string candidateOutcome, string selectionOutcome, string reasons)
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var details = $$"""
            {"version":1,"phase":"distribution_finalize","operationId":"{{Guid.NewGuid():D}}","outcome":"refused","code":"binding_conflict","reasonCode":"replacement_candidate_none","httpStatus":409,"submittedHardwareId":"HWID","resolvedHardwareId":"HWID","resolutionSource":"provider_direct","snapshot":{"productId":"{{productId:D}}","licenseId":"{{licenseId:D}}","activeSeatDetails":[],"activeSeatDetailsTruncated":false,"resolvedHardwareAlreadyActive":false,"observationGuarantee":"ordered_authority_locks"},"appVersion":"2.3.986","replacementCandidates":[{"sourceBindingId":"{{Guid.NewGuid():D}}","sourceLicenseId":"{{Guid.NewGuid():D}}","outcome":"{{candidateOutcome}}","reasonCodes":{{reasons}}}],"selectionOutcome":"{{selectionOutcome}}"}
            """;

        var projection = LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
        {
            Id = Guid.NewGuid(), LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
            Timestamp = DateTime.UtcNow, Details = details,
        }, productId);

        Assert.Equal("available", projection.ParseStatus);
        Assert.NotNull(projection.Decision);
        Assert.False(projection.SelectionConsistent);
    }

    /// <summary>Duplicate candidate identities cannot express two contradictory outcomes.</summary>
    [Fact]
    public void Projection_DuplicateCandidateIdentity_IsUnavailable()
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        var sourceLicenseId = Guid.NewGuid();
        var details = $$"""
            {"version":1,"phase":"distribution_finalize","operationId":"{{Guid.NewGuid():D}}","outcome":"refused","code":"binding_conflict","reasonCode":"replacement_candidate_none","httpStatus":409,"submittedHardwareId":"HWID","resolvedHardwareId":"HWID","resolutionSource":"provider_direct","snapshot":{"productId":"{{productId:D}}","licenseId":"{{licenseId:D}}","activeSeatDetails":[],"activeSeatDetailsTruncated":false,"resolvedHardwareAlreadyActive":false,"observationGuarantee":"ordered_authority_locks"},"appVersion":"2.3.986","replacementCandidates":[{"sourceBindingId":"{{bindingId:D}}","sourceLicenseId":"{{sourceLicenseId:D}}","outcome":"selected","reasonCodes":[]},{"sourceBindingId":"{{bindingId:D}}","sourceLicenseId":"{{Guid.NewGuid():D}}","outcome":"rejected","reasonCodes":["not_selected_recovery_source"]}],"selectionOutcome":"selected"}
            """;
        var projection = LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
        {
            Id = Guid.NewGuid(), LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
            Timestamp = DateTime.UtcNow, Details = details,
        }, productId);
        Assert.Equal("unavailable", projection.ParseStatus);
        Assert.Null(projection.Decision);
    }

    [Fact]
    public void Projection_UnknownSelectionOutcome_IsUnavailable()
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var details = $$"""
            {"version":1,"phase":"distribution_finalize","operationId":"{{Guid.NewGuid():D}}","outcome":"refused","code":"binding_conflict","httpStatus":409,"snapshot":{"productId":"{{productId:D}}","licenseId":"{{licenseId:D}}","observationGuarantee":"ordered_authority_locks"},"replacementCandidates":[],"selectionOutcome":"future_value"}
            """;
        var projection = LicenseDecisionHistoryProjection.FromHistory(new LicenseHistory
        {
            Id = Guid.NewGuid(), LicenseId = licenseId, Action = "ACTIVATION_DECISION_V1",
            Timestamp = DateTime.UtcNow, Details = details,
        }, productId);

        Assert.Equal("unavailable", projection.ParseStatus);
        Assert.Null(projection.Decision);
    }

    /// <summary>An exact request read cannot trust an indexed selector whose stored JSON carries another identity.</summary>
    [Theory]
    [InlineData("operation")]
    [InlineData("correlation")]
    public void Projection_RequestScopedIndexDrift_IsUnavailable(string selector)
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var requested = Guid.NewGuid().ToString("D");
        var operation = Guid.NewGuid().ToString("D");
        var correlation = selector == "correlation" ? Guid.NewGuid().ToString("D") : null;
        var decision = new LicenseDecisionHistory(1, "distribution_finalize", operation, "refused",
            "binding_conflict", null, 409, "HWID", "HWID", null, "provider_direct",
            new LicenseDecisionSnapshot(productId, licenseId, null, 1, 0, 1, 0, 0, null, [], false,
                false, "ordered_authority_locks"), "2.3.986", CorrelationId: correlation);
        var row = new LicenseHistory
        {
            LicenseId = licenseId,
            Action = "ACTIVATION_DECISION_V1",
            DecisionOperationId = selector == "operation" ? requested : operation,
            DecisionCorrelationId = selector == "correlation" ? requested : correlation,
            DecisionSubmittedHardwareId = decision.SubmittedHardwareId,
            DecisionResolvedHardwareId = decision.ResolvedHardwareId,
            DecisionCorrelatedHardwareId = decision.CorrelatedHardwareId,
            Details = JsonSerializer.Serialize(decision, new JsonSerializerOptions(JsonSerializerDefaults.Web))
        };

        var projection = LicenseDecisionHistoryProjection.FromHistory(row, productId, requested);

        Assert.Equal("unavailable", projection.ParseStatus);
        Assert.Null(projection.Decision);
    }

    /// <summary>Request-scoped evidence rejects drift in every HWID column duplicated beside the JSON.</summary>
    [Theory]
    [InlineData("submitted")]
    [InlineData("resolved")]
    [InlineData("correlated")]
    public void Projection_RequestScopedHardwareIndexDrift_IsUnavailable(string field)
    {
        var productId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var requested = Guid.NewGuid().ToString("D");
        var decision = new LicenseDecisionHistory(1, "distribution_finalize", requested, "refused",
            "binding_conflict", null, 409, "HW-SUBMITTED", "HW-RESOLVED", "HW-CORRELATED",
            "provider_direct", new LicenseDecisionSnapshot(productId, licenseId, null, 1, 0, 1,
                0, 0, null, [], false, false, "ordered_authority_locks"), "2.3.986");
        var row = new LicenseHistory
        {
            LicenseId = licenseId,
            Action = "ACTIVATION_DECISION_V1",
            DecisionOperationId = requested,
            DecisionSubmittedHardwareId = field == "submitted" ? "HW-DRIFT" : decision.SubmittedHardwareId,
            DecisionResolvedHardwareId = field == "resolved" ? "HW-DRIFT" : decision.ResolvedHardwareId,
            DecisionCorrelatedHardwareId = field == "correlated" ? "HW-DRIFT" : decision.CorrelatedHardwareId,
            Details = JsonSerializer.Serialize(decision, new JsonSerializerOptions(JsonSerializerDefaults.Web))
        };

        var projection = LicenseDecisionHistoryProjection.FromHistory(row, productId, requested);

        Assert.Equal("unavailable", projection.ParseStatus);
        Assert.Null(projection.Decision);
    }

    /// <summary>Dedicated MCP transport preserves case, Unicode and reserved characters without product alias replacement.</summary>
    [Fact]
    public async Task McpClient_PreservesExactSelectors()
    {
        Uri? uri = null;
        using var http = new HttpClient(new DecisionHandler(request =>
        {
            uri = request.RequestUri;
            Assert.Equal("synthetic", Assert.Single(request.Headers.GetValues("X-Analytics-Key")));
            return new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent("{\"items\":[]}", Encoding.UTF8, "application/json") };
        }));
        var client = new SoftLicenceAnalyticsClient(http, Options.Create(new SoftLicenceMcpOptions
            { SoftLicenceBaseUrl = "https://synthetic.invalid", SoftLicenceApiKey = "synthetic" }));
        await client.GetLicenseDecisionsAsync(null, "HWID:É&+", "Request/Case", 50, 0,
            null, "tiaconnect", CancellationToken.None);
        Assert.Equal("/api/analytics/support/license-decisions", uri!.AbsolutePath);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);
        Assert.Equal("HWID:É&+", query["hardwareId"]);
        Assert.Equal("Request/Case", query["requestId"]);
        Assert.Equal("tiaconnect", query["productName"]);
    }

    /// <summary>Returns a synthetic HTTP response without opening sockets.</summary>
    private sealed class DecisionHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        /// <inheritdoc />
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}

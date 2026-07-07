using System.Net;
using System.Text;
using Microsoft.Extensions.Options;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class SoftLicenceMcpClientTests
{
    [Fact]
    public async Task GetTelemetryOverviewAsync_SendsAnalyticsKeyAndExpectedUrl()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsAnalyzed":3}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.GetTelemetryOverviewAsync(days: 7, top: 20, date: null, fromUtc: null, toUtc: null, CancellationToken.None);

        Assert.Equal(3, result.GetProperty("recordsAnalyzed").GetInt32());
        Assert.NotNull(capturedRequest);
        Assert.Equal(HttpMethod.Get, capturedRequest.Method);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/overview?days=7&top=20",
            capturedRequest.RequestUri!.AbsoluteUri);
        Assert.True(capturedRequest.Headers.TryGetValues("X-Analytics-Key", out var values));
        Assert.Equal("analytics-key", Assert.Single(values));
    }

    [Fact]
    public async Task GetTelemetryOverviewAsync_EncodesExplicitDate()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsAnalyzed":3}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetTelemetryOverviewAsync(days: 7, top: 20, date: "2026-06-05", fromUtc: null, toUtc: null, CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/overview?days=7&top=20&date=2026-06-05",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetTelemetryDevicesAsync_EncodesExplicitRangeAndLimits()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"totalDevices":2}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetTelemetryDevicesAsync(
            days: 7,
            date: null,
            fromUtc: "2026-06-05T00:00:00Z",
            toUtc: "2026-06-06T00:00:00Z",
            take: 250,
            topEvents: 5,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/devices?days=7&fromUtc=2026-06-05T00%3A00%3A00Z&toUtc=2026-06-06T00%3A00%3A00Z&take=250&topEvents=5",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetTelemetryMachineProfileAsync_EncodesHardwareId()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"hardwareId":"HW A/B"}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetTelemetryMachineProfileAsync("HW A/B", days: 7, top: 20, take: 25, CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/machine-profile?hardwareId=HW%20A%2FB&days=7&top=20&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetTelemetryRawSampleAsync_EncodesFilters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsReturned":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetTelemetryRawSampleAsync(
            days: 7,
            date: "2026-06-05",
            fromUtc: null,
            toUtc: null,
            hardwareId: "HW A/B",
            eventName: "Mcp_ToolCall",
            eventFamily: "mcp",
            version: "2.1.857",
            type: "Event",
            take: 25,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/raw-sample?days=7&date=2026-06-05&hardwareId=HW%20A%2FB&eventName=Mcp_ToolCall&eventFamily=mcp&version=2.1.857&type=Event&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetTelemetryInsightsAsync_EncodesExplicitRange()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsAnalyzed":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetTelemetryInsightsAsync(
            days: 7,
            top: 20,
            date: null,
            fromUtc: "2026-06-05T00:00:00Z",
            toUtc: "2026-06-06T00:00:00Z",
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/insights?days=7&top=20&fromUtc=2026-06-05T00%3A00%3A00Z&toUtc=2026-06-06T00%3A00%3A00Z",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetActivationFailuresAsync_EncodesFilters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsReturned":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetActivationFailuresAsync(
            days: 7,
            date: "2026-06-05",
            fromUtc: null,
            toUtc: null,
            hardwareId: "HW A/B",
            status: "BAD_REQUEST",
            take: 25,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/activation-failures?days=7&date=2026-06-05&hardwareId=HW%20A%2FB&status=BAD_REQUEST&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetSupportTelemetryProfileAsync_EncodesHardwareIdAndIpv6ClientIp()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"candidateCount":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetSupportTelemetryProfileAsync(
            hardwareId: "769C9325",
            email: null,
            emailFragment: "fra",
            licenseFragment: "AAAA-BB",
            clientIp: "2001:db8::42",
            days: 7,
            take: 25,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/support/profile?hardwareId=769C9325&emailFragment=fra&licenseFragment=AAAA-BB&clientIp=2001%3Adb8%3A%3A42&days=7&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task ListSecurityBansAsync_EncodesFilters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsReturned":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.ListSecurityBansAsync(
            hardwareId: "HW A/B",
            componentHash: "abc123",
            componentType: "FP_EXE",
            clientIp: "2001:db8::42",
            emailFragment: "fra",
            licenseFragment: "AAAA-BB",
            includeInactive: true,
            take: 50,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/security/bans?hardwareId=HW%20A%2FB&componentHash=abc123&componentType=FP_EXE&clientIp=2001%3Adb8%3A%3A42&emailFragment=fra&licenseFragment=AAAA-BB&includeInactive=true&take=50",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetSecurityBanDetailsAsync_UsesBanIdRoute()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"ban":{"targetType":"component"}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);
        var banId = Guid.Parse("11111111-2222-3333-4444-555555555555");

        await client.GetSecurityBanDetailsAsync(banId, CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/security/bans/11111111-2222-3333-4444-555555555555",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetLicenseDurationMigrationImpactAsync_EncodesMigrationParameters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"summary":{"totalCandidates":2}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetLicenseDurationMigrationImpactAsync(
            licenseType: "TIA-CONNECT-FREEMIUM",
            currentDurationDays: 30,
            targetDurationDays: 7,
            activityWindowsDays: "1,3,7",
            includeSamples: true,
            sampleLimit: 10,
            topEvents: 15,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/duration-migration-impact?licenseType=TIA-CONNECT-FREEMIUM&currentDurationDays=30&targetDurationDays=7&activityWindowsDays=1%2C3%2C7&includeSamples=true&sampleLimit=10&topEvents=15",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetFreemiumActivityRankingAsync_EncodesRankingParameters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"summary":{"rankedMachines":2}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetFreemiumActivityRankingAsync(
            licenseType: "TIA-CONNECT-FREEMIUM",
            status: "expired_or_revoked",
            telemetryDays: 7,
            activationAgeMinDays: 7,
            activationAgeMaxDays: 30,
            includeSamples: true,
            take: 50,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/freemium-activity-ranking?licenseType=TIA-CONNECT-FREEMIUM&status=expired_or_revoked&telemetryDays=7&activationAgeMinDays=7&activationAgeMaxDays=30&includeSamples=true&take=50",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetPaidActivityRankingAsync_EncodesRankingParameters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"summary":{"rankedMachines":2}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetPaidActivityRankingAsync(
            licenseTypes: "TIA-CONNECT-PRO,TIA-CONNECT-ENT",
            status: "active",
            telemetryDays: 14,
            activationAgeMinDays: 30,
            activationAgeMaxDays: 365,
            includeSamples: true,
            take: 25,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/paid-activity-ranking?licenseTypes=TIA-CONNECT-PRO%2CTIA-CONNECT-ENT&status=active&telemetryDays=14&activationAgeMinDays=30&activationAgeMaxDays=365&includeSamples=true&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetLicenseTypesAsync_EncodesIncludeFree()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"totalTypes":2}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetLicenseTypesAsync(includeFree: false, CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/types?includeFree=false",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetRecentLicenseOnboardingMetricsAsync_EncodesFilters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"licensesReturned":2}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetRecentLicenseOnboardingMetricsAsync(
            take: 10,
            licenseType: "paid",
            status: "active",
            activationAgeMaxDays: 14,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/recent-onboarding-metrics?take=10&licenseType=paid&status=active&activationAgeMaxDays=14",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetLicenseUsageScoresAsync_EncodesFilters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"licensesReturned":2}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetLicenseUsageScoresAsync(
            take: 25,
            licenseType: "trial",
            status: "active",
            activationAgeMaxDays: 30,
            activityWindowDays: 14,
            minScore: 55.5,
            includeInactive: true,
            sortBy: "conversionPotential",
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/usage-scoring?take=25&licenseType=trial&status=active&activationAgeMaxDays=30&activityWindowDays=14&minScore=55.5&includeInactive=true&sortBy=conversionPotential",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task ListLlmTipFeedbackAsync_UsesDedicatedFeedbackEndpointAndEncodesFilters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"total":1,"items":[]}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.ListLlmTipFeedbackAsync(
            fromUtc: "2026-06-28T00:00:00Z",
            toUtc: "2026-06-29T00:00:00Z",
            productId: "11111111-2222-3333-4444-555555555555",
            appVersion: "2.2.501",
            category: "general",
            severity: "info",
            reviewStatus: "new",
            search: "AUTO FEEDBACK",
            limit: 50,
            offset: 10,
            sortBy: "occurrenceCount",
            sortDir: "desc",
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(HttpMethod.Get, capturedRequest.Method);
        Assert.Equal(
            "https://softlicence.test/api/llm-tips-feedback/admin/tips?fromUtc=2026-06-28T00%3A00%3A00Z&toUtc=2026-06-29T00%3A00%3A00Z&productId=11111111-2222-3333-4444-555555555555&appVersion=2.2.501&category=general&severity=info&reviewStatus=new&search=AUTO%20FEEDBACK&limit=50&offset=10&sortBy=occurrenceCount&sortDir=desc",
            capturedRequest.RequestUri!.AbsoluteUri);
        Assert.True(capturedRequest.Headers.TryGetValues("X-Analytics-Key", out var values));
        Assert.Equal("analytics-key", Assert.Single(values));
    }

    [Fact]
    public async Task GetLlmTipFeedbackDetailAsync_UsesDedicatedFeedbackEndpoint()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"contentHash":"hash"}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetLlmTipFeedbackDetailAsync("hash with spaces", CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/llm-tips-feedback/admin/tips/hash%20with%20spaces",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetLlmTipFeedbackStatsAsync_UsesDedicatedFeedbackEndpoint()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"totalTips":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetLlmTipFeedbackStatsAsync(
            days: 30,
            fromUtc: null,
            toUtc: null,
            productId: null,
            appVersion: "2.2.501",
            category: "general",
            severity: "info",
            reviewStatus: "new",
            search: "probe",
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/llm-tips-feedback/admin/stats?days=30&appVersion=2.2.501&category=general&severity=info&reviewStatus=new&search=probe",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task UpdateLlmTipFeedbackReviewStatusAsync_SendsPatchBodyToDedicatedFeedbackEndpoint()
    {
        HttpRequestMessage? capturedRequest = null;
        string? capturedBody = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            capturedBody = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"status":"updated"}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.UpdateLlmTipFeedbackReviewStatusAsync(
            id: null,
            contentHash: "hash-review",
            reviewStatus: "needs-doc",
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(HttpMethod.Patch, capturedRequest.Method);
        Assert.Equal(
            "https://softlicence.test/api/llm-tips-feedback/admin/tips/review-status",
            capturedRequest.RequestUri!.AbsoluteUri);
        Assert.Contains("\"contentHash\":\"hash-review\"", capturedBody);
        Assert.Contains("\"reviewStatus\":\"needs-doc\"", capturedBody);
    }

    [Fact]
    public async Task GetTelemetryLicenseHardwareAuditAsync_EncodesAuditParameters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"summary":{"telemetryMachines":2}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetTelemetryLicenseHardwareAuditAsync(
            days: 7,
            date: null,
            fromUtc: "2026-06-08T00:00:00Z",
            toUtc: "2026-06-09T00:00:00Z",
            activityWindowsDays: "1,3,7",
            take: 25,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/telemetry-hwid-audit?days=7&fromUtc=2026-06-08T00%3A00%3A00Z&toUtc=2026-06-09T00%3A00%3A00Z&activityWindowsDays=1%2C3%2C7&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetFreemiumAbuseRiskAsync_EncodesRiskParameters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"summary":{"groupsAnalyzed":2}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetFreemiumAbuseRiskAsync(
            licenseType: "TIA-CONNECT-FREEMIUM",
            days: 7,
            date: null,
            fromUtc: "2026-06-08T00:00:00Z",
            toUtc: "2026-06-09T00:00:00Z",
            take: 25,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/freemium-abuse-risk?licenseType=TIA-CONNECT-FREEMIUM&days=7&fromUtc=2026-06-08T00%3A00%3A00Z&toUtc=2026-06-09T00%3A00%3A00Z&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetTelemetryOverviewAsync_WhenApiKeyIsMissing_ThrowsConfigurationError()
    {
        var handler = new CapturingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var client = new SoftLicenceAnalyticsClient(
            new HttpClient(handler),
            Options.Create(new SoftLicenceMcpOptions { SoftLicenceBaseUrl = "https://softlicence.test" }));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetTelemetryOverviewAsync(days: 7, top: 20, date: null, fromUtc: null, toUtc: null, CancellationToken.None));

        Assert.Contains("SOFTLICENCE_API_KEY", ex.Message);
    }

    [Fact]
    public async Task GetTelemetryOverviewAsync_WhenApiRejectsKey_ThrowsAuthError()
    {
        var handler = new CapturingHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetTelemetryOverviewAsync(days: 7, top: 20, date: null, fromUtc: null, toUtc: null, CancellationToken.None));

        Assert.Contains("rejected SOFTLICENCE_API_KEY", ex.Message);
    }

    private static SoftLicenceAnalyticsClient CreateClient(HttpMessageHandler handler)
    {
        return new SoftLicenceAnalyticsClient(
            new HttpClient(handler),
            Options.Create(new SoftLicenceMcpOptions
            {
                SoftLicenceBaseUrl = "https://softlicence.test/",
                SoftLicenceApiKey = "analytics-key"
            }));
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public CapturingHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }
}

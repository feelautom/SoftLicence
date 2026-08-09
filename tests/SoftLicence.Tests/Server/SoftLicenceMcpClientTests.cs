using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SoftLicence.Mcp;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class SoftLicenceMcpClientTests
{
    [Fact]
    public async Task GetCurrentProductAsync_SendsAnalyticsKeyAndExpectedUrl()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"product":{"name":"T-IA Connect"}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.GetCurrentProductAsync(CancellationToken.None);

        Assert.Equal("T-IA Connect", result.GetProperty("product").GetProperty("name").GetString());
        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/products/current",
            capturedRequest.RequestUri!.AbsoluteUri);
        Assert.True(capturedRequest.Headers.TryGetValues("X-Analytics-Key", out var values));
        Assert.Equal("analytics-key", Assert.Single(values));
    }

    [Fact]
    public async Task ListProductsAsync_SendsExpectedUrl()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"productsReturned":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.ListProductsAsync(CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/products",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

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
    public async Task GetTelemetryOverviewAsync_EncodesProductSelector()
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

        await client.GetTelemetryOverviewAsync(
            days: 7,
            top: 20,
            date: null,
            fromUtc: null,
            toUtc: null,
            CancellationToken.None,
            productId: null,
            productName: "YOUR_APP_NAME");

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/overview?days=7&top=20&productName=YOUR_APP_NAME",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Theory]
    [InlineData("TIAConnect")]
    [InlineData("tiaConnect")]
    [InlineData("T-IA Connect")]
    [InlineData("  t-ia connect  ")]
    public async Task GetTelemetryOverviewAsync_CanonicalizesTiaConnectProductAliases(string productName)
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

        await client.GetTelemetryOverviewAsync(
            days: 7,
            top: 20,
            date: null,
            fromUtc: null,
            toUtc: null,
            CancellationToken.None,
            productId: null,
            productName: productName);

        Assert.NotNull(capturedRequest);
        Assert.Equal("TIAConnect", GetQueryValue(capturedRequest.RequestUri!, "productName"));
    }

    [Fact]
    public async Task GetTelemetryOverviewAsync_PreservesUnrelatedProductName()
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

        await client.GetTelemetryOverviewAsync(
            days: 7,
            top: 20,
            date: null,
            fromUtc: null,
            toUtc: null,
            CancellationToken.None,
            productId: null,
            productName: "  YOUR_APP_NAME  ");

        Assert.NotNull(capturedRequest);
        Assert.Equal("YOUR_APP_NAME", GetQueryValue(capturedRequest.RequestUri!, "productName"));
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
                Content = new StringContent("""{"recordsReturned":1,"records":[{"diagnostic":{"state":"available","results":[{"moduleName":"PLC","success":false}]}}]}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.GetTelemetryRawSampleAsync(
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
            "available",
            result.GetProperty("records")[0].GetProperty("diagnostic").GetProperty("state").GetString());
        Assert.Equal(
            "PLC",
            result.GetProperty("records")[0].GetProperty("diagnostic").GetProperty("results")[0].GetProperty("moduleName").GetString());
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/raw-sample?days=7&date=2026-06-05&hardwareId=HW%20A%2FB&eventName=Mcp_ToolCall&eventFamily=mcp&version=2.1.857&type=Event&take=25",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetTelemetryFloodSuppressionsAsync_EncodesFilters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"groupsMatched":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetTelemetryFloodSuppressionsAsync(
            days: 7,
            hardwareId: "8A96631C",
            eventName: "NativeExtractionFailed",
            take: 25,
            CancellationToken.None,
            productId: null,
            productName: "YOUR_APP_NAME");

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/telemetry/flood-suppressions?days=7&hardwareId=8A96631C&eventName=NativeExtractionFailed&take=25&productName=YOUR_APP_NAME",
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
    public async Task GetCustomerLicenseTimelineAsync_EncodesTimelineParameters()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"timelineReturned":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.GetCustomerLicenseTimelineAsync(
            email: "customer@example.com",
            emailFragment: null,
            hardwareId: "55BA0C1B",
            licenseId: null,
            licenseFragment: "9B1784",
            days: 30,
            date: null,
            fromUtc: "2026-07-01T00:00:00Z",
            toUtc: "2026-07-12T00:00:00Z",
            takeTimeline: 500,
            offset: 25,
            includeAccessLogs: true,
            includeNoise: false,
            importantOnly: true,
            includeProperties: true,
            mode: "full",
            CancellationToken.None,
            productId: null,
            productName: "TIAConnect");

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/support/customer-license-timeline?email=customer%40example.com&hardwareId=55BA0C1B&licenseFragment=9B1784&days=30&fromUtc=2026-07-01T00%3A00%3A00Z&toUtc=2026-07-12T00%3A00%3A00Z&takeTimeline=500&offset=25&includeAccessLogs=true&includeNoise=false&importantOnly=true&includeProperties=true&mode=full&productName=TIAConnect",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetCustomerLicenseTimelineAsync_WhenExplicitRangeIsFortyDays_SegmentsAutomatically()
    {
        var requests = new List<Uri>();
        var handler = new CapturingHandler(request =>
        {
            requests.Add(request.RequestUri!);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"timelineReturned":1,"timeline":[]}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.GetCustomerLicenseTimelineAsync(
            email: "customer@example.com",
            emailFragment: null,
            hardwareId: null,
            licenseId: null,
            licenseFragment: null,
            days: 30,
            date: null,
            fromUtc: "2026-05-11T00:00:00Z",
            toUtc: "2026-06-20T00:00:00Z",
            takeTimeline: 150,
            offset: 0,
            includeAccessLogs: true,
            includeNoise: false,
            importantOnly: true,
            includeProperties: true,
            mode: "timeline",
            CancellationToken.None,
            productId: null,
            productName: "T-IA Connect");

        Assert.True(result.GetProperty("ok").GetBoolean());
        Assert.True(result.GetProperty("segmented").GetBoolean());
        Assert.Equal(2, result.GetProperty("segmentCount").GetInt32());
        Assert.Equal(90, result.GetProperty("maxRangeDays").GetInt32());
        Assert.Equal(30, result.GetProperty("maxSegmentDays").GetInt32());
        Assert.Equal(2, requests.Count);
        Assert.All(requests, request => Assert.Equal("TIAConnect", GetQueryValue(request, "productName")));

        var firstFrom = DateTimeOffset.Parse(GetQueryValue(requests[0], "fromUtc")!);
        var firstTo = DateTimeOffset.Parse(GetQueryValue(requests[0], "toUtc")!);
        var secondFrom = DateTimeOffset.Parse(GetQueryValue(requests[1], "fromUtc")!);
        var secondTo = DateTimeOffset.Parse(GetQueryValue(requests[1], "toUtc")!);
        Assert.True(firstTo - firstFrom <= TimeSpan.FromDays(30));
        Assert.True(secondTo - secondFrom <= TimeSpan.FromDays(30));
        Assert.Equal(firstTo.AddTicks(1), secondFrom);
        Assert.Equal(DateTimeOffset.Parse("2026-05-11T00:00:00Z"), firstFrom);
        Assert.Equal(DateTimeOffset.Parse("2026-06-20T00:00:00Z"), secondTo);
    }

    [Fact]
    public async Task GetCustomerLicenseTimelineAsync_WhenExplicitRangeExceedsNinetyDays_ReturnsLocalError()
    {
        var requestCount = 0;
        var handler = new CapturingHandler(_ =>
        {
            requestCount++;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var client = CreateClient(handler);

        var result = await client.GetCustomerLicenseTimelineAsync(
            email: "customer@example.com",
            emailFragment: null,
            hardwareId: null,
            licenseId: null,
            licenseFragment: null,
            days: 30,
            date: null,
            fromUtc: "2026-01-01T00:00:00Z",
            toUtc: "2026-04-02T00:00:00Z",
            takeTimeline: 150,
            offset: 0,
            includeAccessLogs: true,
            includeNoise: false,
            importantOnly: true,
            includeProperties: true,
            mode: "timeline",
            CancellationToken.None,
            productId: null,
            productName: "TIAConnect");

        Assert.False(result.GetProperty("ok").GetBoolean());
        Assert.Equal("TIMELINE_RANGE_TOO_LARGE", result.GetProperty("errorCode").GetString());
        Assert.Equal(90, result.GetProperty("maxDays").GetInt32());
        Assert.Equal(0, requestCount);
    }

    [Fact]
    public async Task GetCustomerLicenseTimelineAsync_WhenRollingWindowIsNinetyDays_UsesThreeSegments()
    {
        var requests = new List<Uri>();
        var handler = new CapturingHandler(request =>
        {
            requests.Add(request.RequestUri!);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"timelineReturned":0,"timeline":[]}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.GetCustomerLicenseTimelineAsync(
            email: "customer@example.com",
            emailFragment: null,
            hardwareId: null,
            licenseId: null,
            licenseFragment: null,
            days: 90,
            date: null,
            fromUtc: null,
            toUtc: null,
            takeTimeline: 150,
            offset: 0,
            includeAccessLogs: true,
            includeNoise: false,
            importantOnly: true,
            includeProperties: true,
            mode: "timeline",
            CancellationToken.None,
            productId: null,
            productName: "T-IA Connect");

        Assert.True(result.GetProperty("ok").GetBoolean());
        Assert.Equal(3, result.GetProperty("segmentCount").GetInt32());
        Assert.Equal(3, requests.Count);
        Assert.All(requests, request =>
        {
            var from = DateTimeOffset.Parse(GetQueryValue(request, "fromUtc")!);
            var to = DateTimeOffset.Parse(GetQueryValue(request, "toUtc")!);
            Assert.True(to - from <= TimeSpan.FromDays(30));
            Assert.Equal("TIAConnect", GetQueryValue(request, "productName"));
        });
    }

    [Fact]
    public async Task GetTelemetryOverviewAsync_WhenServerFails_DoesNotExposeResponseDetails()
    {
        var handler = new CapturingHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(
                """{"errorCode":"INTERNAL_DATABASE_ERROR","message":"Internal database connection detail; diagnostic trace follows"}""",
                Encoding.UTF8,
                "application/json")
        });
        var client = CreateClient(handler);

        var result = await client.GetTelemetryOverviewAsync(
            days: 7,
            top: 20,
            date: null,
            fromUtc: null,
            toUtc: null,
            CancellationToken.None);

        Assert.False(result.GetProperty("ok").GetBoolean());
        Assert.Equal("ANALYTICS_SERVER_ERROR", result.GetProperty("errorCode").GetString());
        Assert.Equal("SoftLicence analytics API returned an internal server error.", result.GetProperty("message").GetString());
        Assert.DoesNotContain("connection detail", result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("diagnostic trace", result.ToString(), StringComparison.OrdinalIgnoreCase);
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
            CancellationToken.None,
            includeSourceEvents: true);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/security/bans?hardwareId=HW%20A%2FB&componentHash=abc123&componentType=FP_EXE&clientIp=2001%3Adb8%3A%3A42&emailFragment=fra&licenseFragment=AAAA-BB&includeInactive=true&includeSourceEvents=true&take=50",
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
    public async Task ListSecurityCanaryAlertsAsync_EncodesFiltersAndProduct()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new CapturingHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"groupsReturned":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        await client.ListSecurityCanaryAlertsAsync(
            "2026-07-01T00:00:00Z", "2026-07-15T00:00:00Z", "IntegrityCheck", 3,
            "HW A/B", "BOX", "analyst", "2001:db8::42", "2.1.839", true,
            50, 10, null, "TIAConnect", CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/security/canary-alerts?fromUtc=2026-07-01T00%3A00%3A00Z&toUtc=2026-07-15T00%3A00%3A00Z&trigger=IntegrityCheck&severity=3&hardwareId=HW%20A%2FB&machine=BOX&user=analyst&clientIp=2001%3Adb8%3A%3A42&version=2.1.839&isBanned=true&take=50&offset=10&productName=TIAConnect",
            capturedRequest.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetSecurityBanDetailsAsync_WithGlobalSelector_UsesProductName()
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

        await client.GetSecurityBanDetailsAsync(banId, CancellationToken.None, productName: "TIAConnect");

        Assert.Equal(
            "https://softlicence.test/api/analytics/security/bans/11111111-2222-3333-4444-555555555555?productName=TIAConnect",
            capturedRequest!.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task CreateSecurityComponentBanAsync_AuditsAndPostVerifiesMutation()
    {
        var requests = new List<(HttpMethod Method, string Url, string? AdminSecret, string? Body)>();
        var handler = new CapturingHandler(request =>
        {
            request.Headers.TryGetValues("X-Admin-Secret", out var values);
            requests.Add((request.Method, request.RequestUri!.AbsoluteUri, values?.SingleOrDefault(),
                request.Content?.ReadAsStringAsync().GetAwaiter().GetResult()));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(request.Method == HttpMethod.Post
                    ? """{"success":true}"""
                    : """{"recordsReturned":1}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.CreateSecurityComponentBanAsync(
            "FP_EXE", "abc123", "Binary patched", "integrity", null, null, null, null,
            "TKT-999615", "sec-test", "Codex", "confirmed", CancellationToken.None);

        Assert.Equal("create_security_component_ban", result.GetProperty("operation").GetString());
        Assert.Equal(2, requests.Count);
        Assert.Equal(HttpMethod.Post, requests[0].Method);
        Assert.Equal("https://softlicence.test/api/admin/banned-components", requests[0].Url);
        Assert.Equal("admin-secret", requests[0].AdminSecret);
        Assert.Contains("TKT-999615", requests[0].Body);
        Assert.Contains("securityCase=sec-test", requests[0].Body);
        Assert.Contains("category=integrity", requests[0].Body);
        Assert.Contains("Codex", requests[0].Body);
        Assert.Equal(
            "https://softlicence.test/api/analytics/security/bans?componentHash=abc123&componentType=FP_EXE&includeInactive=true&take=25",
            requests[1].Url);
    }

    [Fact]
    public async Task UnbanSecurityComponentBanAsync_AuditsAndPostVerifiesWithProductSelector()
    {
        var requests = new List<(HttpMethod Method, string Url, string? AdminSecret)>();
        var handler = new CapturingHandler(request =>
        {
            request.Headers.TryGetValues("X-Admin-Secret", out var values);
            requests.Add((request.Method, request.RequestUri!.AbsoluteUri, values?.SingleOrDefault()));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(request.Method == HttpMethod.Delete
                    ? """{"success":true}"""
                    : """{"ban":{"isActive":false}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);
        var banId = Guid.Parse("11111111-2222-3333-4444-555555555555");

        var result = await client.UnbanSecurityComponentBanAsync(
            banId, null, "TIAConnect", "Approved after review", "TKT-999615", "sec-test", "Codex", "validated",
            CancellationToken.None);

        Assert.Equal("unban_security_component_ban", result.GetProperty("operation").GetString());
        Assert.Equal(2, requests.Count);
        Assert.Equal(HttpMethod.Delete, requests[0].Method);
        Assert.Equal("admin-secret", requests[0].AdminSecret);
        Assert.Contains("auditReason=Approved%20after%20review", requests[0].Url);
        Assert.Contains("TKT-999615", requests[0].Url);
        Assert.Contains("securityCase%3Dsec-test", requests[0].Url);
        Assert.Equal(
            "https://softlicence.test/api/analytics/security/bans/11111111-2222-3333-4444-555555555555?productName=TIAConnect",
            requests[1].Url);
    }

    [Fact]
    public async Task UnbanSecurityComponentBanAsync_WhenAdminRejects_ReturnsStructuredMutationError()
    {
        var handler = new CapturingHandler(request =>
        {
            if (request.Method == HttpMethod.Delete)
            {
                return new HttpResponseMessage(HttpStatusCode.Conflict)
                {
                    Content = new StringContent(
                        """{"errorCode":"runtime_authority_conflict","message":"mutation rejected"}""",
                        Encoding.UTF8,
                        "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"ban":{"isActive":true}}""", Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.UnbanSecurityComponentBanAsync(
            Guid.Parse("11111111-2222-3333-4444-555555555555"),
            null,
            "TIAConnect",
            "Approved after review",
            "TKT-999923",
            null,
            "Codex",
            null,
            CancellationToken.None);

        var mutation = result.GetProperty("mutation");
        Assert.False(mutation.GetProperty("ok").GetBoolean());
        Assert.Equal("write_conflict", mutation.GetProperty("errorCode").GetString());
        Assert.Equal(409, mutation.GetProperty("statusCode").GetInt32());
        Assert.Equal(
            "runtime_authority_conflict",
            mutation.GetProperty("error").GetProperty("errorCode").GetString());
        Assert.True(result.GetProperty("verification").GetProperty("ban").GetProperty("isActive").GetBoolean());
    }

    [Fact]
    public async Task CreateSecurityHardwareBanAsync_WhenAdminSecretMissing_ReturnsStructuredErrorWithoutSending()
    {
        var requestsSent = 0;
        var handler = new CapturingHandler(_ =>
        {
            requestsSent++;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var client = CreateClient(handler, adminSecret: null);

        var result = await client.CreateSecurityHardwareBanAsync(
            "F000000000000381", "Controlled smoke", "manual", null, null, null, null,
            "TKT-999381", null, "Codex", null, CancellationToken.None);

        Assert.Equal("create_security_hardware_ban", result.GetProperty("operation").GetString());
        var mutation = result.GetProperty("mutation");
        Assert.False(mutation.GetProperty("ok").GetBoolean());
        Assert.Equal("write_credentials_missing", mutation.GetProperty("errorCode").GetString());
        Assert.False(mutation.GetProperty("requestSent").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.GetProperty("verification").ValueKind);
        Assert.Equal(0, requestsSent);
    }

    [Theory]
    [InlineData(" admin-secret")]
    [InlineData("admin-secret ")]
    [InlineData("admin\nsecret")]
    [InlineData("admin\u007Fsecret")]
    [InlineData("sécret")]
    public async Task CreateSecurityHardwareBanAsync_WhenAdminSecretIsNotExactPrintableAscii_ReturnsStructuredErrorWithoutSending(
        string adminSecret)
    {
        var requestsSent = 0;
        var handler = new CapturingHandler(_ =>
        {
            requestsSent++;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var client = CreateClient(handler, adminSecret);

        var result = await client.CreateSecurityHardwareBanAsync(
            "F000000000000381", "Controlled smoke", "manual", null, null, null, null,
            "TKT-999381", null, "Codex", null, CancellationToken.None);

        var mutation = result.GetProperty("mutation");
        Assert.Equal("write_credentials_invalid", mutation.GetProperty("errorCode").GetString());
        Assert.False(mutation.GetProperty("requestSent").GetBoolean());
        Assert.Equal(0, requestsSent);
    }

    [Fact]
    public async Task CreateSecurityHardwareBanAsync_PreservesExactSecretAndUsesOneProductSelectorForVerification()
    {
        const string exactSecret = "AdMiN-Secret_123~!";
        const string productId = "808648bc-a4b9-4f71-bcb1-b7c7e67ca98e";
        var requests = new List<(HttpMethod Method, string Url, string? AdminSecret)>();
        var handler = new CapturingHandler(request =>
        {
            request.Headers.TryGetValues("X-Admin-Secret", out var values);
            requests.Add((request.Method, request.RequestUri!.AbsoluteUri, values?.SingleOrDefault()));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    request.Method == HttpMethod.Post ? """{"message":"created"}""" : """{"recordsReturned":1}""",
                    Encoding.UTF8,
                    "application/json")
            };
        });
        var client = CreateClient(handler, exactSecret);

        var result = await client.CreateSecurityHardwareBanAsync(
            "F000000000000381", "Controlled smoke", "manual", productId, "TIAConnect", null, null,
            "TKT-999381", null, "Codex", null, CancellationToken.None);

        Assert.Equal("create_security_hardware_ban", result.GetProperty("operation").GetString());
        Assert.Equal(2, requests.Count);
        Assert.Equal(exactSecret, requests[0].AdminSecret);
        Assert.Contains($"productId={productId}", requests[1].Url, StringComparison.Ordinal);
        Assert.DoesNotContain("productName=", requests[1].Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateSecurityHardwareBanAsync_WhenAdminRejects_ReturnsStructuredMutationError()
    {
        var handler = new CapturingHandler(request => request.Method == HttpMethod.Post
            ? new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("""{"error":"unauthorized"}""", Encoding.UTF8, "application/json")
            }
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsReturned":0,"bans":[]}""", Encoding.UTF8, "application/json")
            });
        var client = CreateClient(handler);

        var result = await client.CreateSecurityHardwareBanAsync(
            "ABCDEF0123456789", "Confirmed incident", "manual", null, "TIAConnect", null, null,
            "TKT-999381", null, "Codex", null, CancellationToken.None);

        var mutation = result.GetProperty("mutation");
        Assert.False(mutation.GetProperty("ok").GetBoolean());
        Assert.Equal("admin_auth_failed", mutation.GetProperty("errorCode").GetString());
        Assert.Equal(401, mutation.GetProperty("statusCode").GetInt32());
        Assert.Equal(0, result.GetProperty("verification").GetProperty("recordsReturned").GetInt32());
    }

    [Fact]
    public async Task UnbanSecurityHardwareBanAsync_WhenAdminRejects_ReturnsStructuredMutationError()
    {
        var handler = new CapturingHandler(request => request.Method == HttpMethod.Delete
            ? new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("""{"error":"unauthorized"}""", Encoding.UTF8, "application/json")
            }
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"ban":{"isActive":true}}""", Encoding.UTF8, "application/json")
            });
        var client = CreateClient(handler);

        var result = await client.UnbanSecurityHardwareBanAsync(
            Guid.Parse("11111111-2222-3333-4444-555555555555"), null, "TIAConnect",
            "Controlled cleanup", "TKT-999381", null, "Codex", null, CancellationToken.None);

        var mutation = result.GetProperty("mutation");
        Assert.False(mutation.GetProperty("ok").GetBoolean());
        Assert.Equal("admin_auth_failed", mutation.GetProperty("errorCode").GetString());
        Assert.Equal(401, mutation.GetProperty("statusCode").GetInt32());
        Assert.True(result.GetProperty("verification").GetProperty("ban").GetProperty("isActive").GetBoolean());
    }

    [Fact]
    public async Task CreateSecurityComponentBanAsync_WhenAdminRejects_ReturnsStructuredMutationError()
    {
        var handler = new CapturingHandler(request => request.Method == HttpMethod.Post
            ? new HttpResponseMessage(HttpStatusCode.Conflict)
            {
                Content = new StringContent(
                    """{"errorCode":"runtime_authority_conflict"}""",
                    Encoding.UTF8,
                    "application/json")
            }
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"recordsReturned":0,"bans":[]}""", Encoding.UTF8, "application/json")
            });
        var client = CreateClient(handler);

        var result = await client.CreateSecurityComponentBanAsync(
            "FP_EXE", "abc123", "Binary patched", "integrity", null, "TIAConnect", null, null,
            "TKT-999381", null, "Codex", null, CancellationToken.None);

        var mutation = result.GetProperty("mutation");
        Assert.False(mutation.GetProperty("ok").GetBoolean());
        Assert.Equal("write_conflict", mutation.GetProperty("errorCode").GetString());
        Assert.Equal(409, mutation.GetProperty("statusCode").GetInt32());
        Assert.Equal(
            "runtime_authority_conflict",
            mutation.GetProperty("error").GetProperty("errorCode").GetString());
        Assert.Equal(0, result.GetProperty("verification").GetProperty("recordsReturned").GetInt32());
    }

    [Fact]
    public async Task GetSecurityCaseSnapshotAsync_PropagatesResolvedHardwareAndBuildsEvidenceGraph()
    {
        var handler = new CapturingHandler(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            var json = path switch
            {
                "/api/analytics/security/bans" => """{"resolvedHardwareIds":["HW-1"],"bans":[{"banId":"11111111-2222-3333-4444-555555555555","targetType":"component","componentMatchStrength":"strong","reason":"BinaryPatched | ticket=TKT-999615"}]}""",
                "/api/analytics/security/canary-alerts" => """{"alerts":[{"alertId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","hardwareId":"HW-1"}]}""",
                "/api/analytics/support/profile" => """{"candidates":[{"licenseId":"99999999-8888-7777-6666-555555555555","customerEmail":"security@example.test","hardwareId":"HW-1","clientIps":[{"name":"203.0.113.10","count":2}]}]}""",
                _ => "{}"
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        });
        var client = CreateClient(handler);

        var snapshot = await client.GetSecurityCaseSnapshotAsync(
            "TKT-999615", "sec_binary_test", null, "abc123", "FP_EXE", null, null, null,
            true, 25, null, "TIAConnect", CancellationToken.None);

        Assert.Contains(snapshot.GetProperty("resolvedHardwareIds").EnumerateArray(), h => h.GetString() == "HW-1");
        Assert.Contains(snapshot.GetProperty("correlatedTickets").EnumerateArray(), t => t.GetString() == "TKT-999615");
        var graph = snapshot.GetProperty("graph");
        Assert.True(graph.GetProperty("exactEvidence").GetInt32() >= 4);
        Assert.Contains(graph.GetProperty("nodes").EnumerateArray(), n => n.GetProperty("type").GetString() == "account");
        Assert.Contains(graph.GetProperty("nodes").EnumerateArray(), n => n.GetProperty("type").GetString() == "ip");
        Assert.Contains(graph.GetProperty("nodes").EnumerateArray(), n => n.GetProperty("type").GetString() == "canary_alert");
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
    public async Task GetLicenseTypesAsync_EncodesProductSelector()
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

        await client.GetLicenseTypesAsync(
            includeFree: true,
            CancellationToken.None,
            productId: "11111111-2222-3333-4444-555555555555",
            productName: null);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/analytics/licenses/types?includeFree=true&productId=11111111-2222-3333-4444-555555555555",
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
            productId: null,
            productName: "T-IA Connect",
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
            "https://softlicence.test/api/llm-tips-feedback/admin/tips?fromUtc=2026-06-28T00%3A00%3A00Z&toUtc=2026-06-29T00%3A00%3A00Z&productName=TIAConnect&appVersion=2.2.501&category=general&severity=info&reviewStatus=new&search=AUTO%20FEEDBACK&limit=50&offset=10&sortBy=occurrenceCount&sortDir=desc",
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

        await client.GetLlmTipFeedbackDetailAsync(
            "hash with spaces",
            productId: "808648bc-a4b9-4f71-bcb1-b7c7e67ca98e",
            productName: null,
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/llm-tips-feedback/admin/tips/hash%20with%20spaces?productId=808648bc-a4b9-4f71-bcb1-b7c7e67ca98e",
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
            productName: "TIAConnect",
            appVersion: "2.2.501",
            category: "general",
            severity: "info",
            reviewStatus: "new",
            search: "probe",
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://softlicence.test/api/llm-tips-feedback/admin/stats?days=30&productName=TIAConnect&appVersion=2.2.501&category=general&severity=info&reviewStatus=new&search=probe",
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
            productId: null,
            productName: "TIAConnect",
            CancellationToken.None);

        Assert.NotNull(capturedRequest);
        Assert.Equal(HttpMethod.Patch, capturedRequest.Method);
        Assert.Equal(
            "https://softlicence.test/api/llm-tips-feedback/admin/tips/review-status?productName=TIAConnect",
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
    public async Task GetTelemetryOverviewAsync_WhenProductSelectorIsRequired_ReturnsAvailableProducts()
    {
        var requests = new List<string>();
        var handler = new CapturingHandler(request =>
        {
            requests.Add(request.RequestUri!.AbsoluteUri);
            if (request.RequestUri.AbsolutePath.EndsWith("/api/analytics/products", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        """{"productsReturned":1,"products":[{"productId":"808648bc-a4b9-4f71-bcb1-b7c7e67ca98e","name":"TIAConnect"}]}""",
                        Encoding.UTF8,
                        "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent(
                    """{"errorCode":"PRODUCT_SELECTOR_REQUIRED","message":"Global analytics keys must provide productId or productName for product-scoped endpoints."}""",
                    Encoding.UTF8,
                    "application/json")
            };
        });
        var client = CreateClient(handler);

        var result = await client.GetTelemetryOverviewAsync(
            days: 1,
            top: 5,
            date: null,
            fromUtc: null,
            toUtc: null,
            CancellationToken.None);

        Assert.False(result.GetProperty("ok").GetBoolean());
        Assert.Equal("PRODUCT_SELECTOR_REQUIRED", result.GetProperty("errorCode").GetString());
        Assert.Contains("list_products", result.GetProperty("hint").GetString());
        Assert.Equal(400, result.GetProperty("statusCode").GetInt32());
        Assert.Equal(
            "TIAConnect",
            result.GetProperty("availableProducts").GetProperty("products")[0].GetProperty("name").GetString());
        Assert.Equal(2, requests.Count);
        Assert.Equal("https://softlicence.test/api/analytics/telemetry/overview?days=1&top=5", requests[0]);
        Assert.Equal("https://softlicence.test/api/analytics/products", requests[1]);
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

    [Fact]
    public async Task GetTelemetryOverviewAsync_WhenPayloadIsOversized_ReturnsReconstructableArtifact()
    {
        var sourceJson = JsonSerializer.Serialize(new
        {
            records = Enumerable.Range(0, 2_000).Select(index => new
            {
                index,
                value = $"record-{index:D4}-équipement-🚀"
            })
        });
        var handler = new CapturingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(sourceJson, Encoding.UTF8, "application/json")
        });
        var resultDirectory = Path.Combine(
            Path.GetTempPath(),
            "SoftLicence.Tests",
            nameof(SoftLicenceMcpClientTests),
            Guid.NewGuid().ToString("N"));
        var options = Options.Create(new SoftLicenceMcpOptions
        {
            SoftLicenceBaseUrl = "https://softlicence.test/",
            SoftLicenceApiKey = "analytics-key",
            ResultDirectory = resultDirectory,
            MaxInlineResultCharacters = 16_384,
            ResultChunkCharacters = 4_096
        });
        var store = new McpResultStore(options);
        var client = new SoftLicenceAnalyticsClient(new HttpClient(handler), options, store);

        var delivered = await client.GetTelemetryOverviewAsync(
            days: 7,
            top: 20,
            date: null,
            fromUtc: null,
            toUtc: null,
            CancellationToken.None);

        Assert.Equal("artifact", delivered.GetProperty("resultDelivery").GetString());
        var artifact = delivered.GetProperty("artifact");
        Assert.False(artifact.GetProperty("truncated").GetBoolean());
        var artifactId = artifact.GetProperty("artifactId").GetString()!;
        var reconstructed = new StringBuilder();
        var offset = 0;
        while (true)
        {
            var chunk = store.GetChunk(artifactId, offset, 4_096);
            reconstructed.Append(chunk.GetProperty("content").GetString());
            if (!chunk.GetProperty("hasMore").GetBoolean())
                break;

            offset = chunk.GetProperty("nextOffset").GetInt32();
        }

        Assert.Equal(sourceJson, reconstructed.ToString());
    }

    private static SoftLicenceAnalyticsClient CreateClient(
        HttpMessageHandler handler,
        string? adminSecret = "admin-secret")
    {
        return new SoftLicenceAnalyticsClient(
            new HttpClient(handler),
            Options.Create(new SoftLicenceMcpOptions
            {
                SoftLicenceBaseUrl = "https://softlicence.test/",
                SoftLicenceApiKey = "analytics-key",
                SoftLicenceAdminSecret = adminSecret
            }));
    }

    private static string? GetQueryValue(Uri uri, string name)
    {
        return uri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .Where(parts => Uri.UnescapeDataString(parts[0]).Equals(name, StringComparison.Ordinal))
            .Select(parts => parts.Length == 2 ? Uri.UnescapeDataString(parts[1]) : "")
            .SingleOrDefault();
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

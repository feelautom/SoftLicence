using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Moq;
using SoftLicence.Server.Data;
using SoftLicence.Server.Middlewares;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-002685: a real client must not be punished for a Runtime or lock-report refusal, a persisted score
/// must be visible after a restart, a crossing of 50 then 100 alerts once, and an operator can reset a
/// score in database and memory with a journal. These tests use EF InMemory; the atomic PostgreSQL
/// increment and the webhook migration are proven in <see cref="ThreatScorePostgreSqlTests"/>.
/// </summary>
public sealed class ThreatScoreTkt002685Tests
{
    private const string EnrollmentText = "805b8edc-164c-4b67-a71c-372500f63787";

    /// <summary>The lock report now shares the server-verified clock classification of the Runtime routes.</summary>
    [Theory]
    [InlineData("/api/security/lock-report", 401, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, true)]
    [InlineData("/API/SECURITY/LOCK-REPORT", 401, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, true)]
    [InlineData("/api/security/lock-report", 401, null, false)]
    [InlineData("/api/security/lock-report", 403, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, false)]
    [InlineData("/api/security/lock-report/extra", 401, RuntimeEnrollmentService.ProofClockSkewDiagnosticCode, false)]
    public void LockReportClockSkew_IsSuppressedOnlyForExactClassification(
        string path, int statusCode, string? disposition, bool expected)
    {
        var method = typeof(AuditMiddleware).GetMethod(
            "ShouldSuppressAuthenticationThreatScore",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

        Assert.NotNull(method);
        Assert.Equal(expected, (bool)method.Invoke(null, [path, statusCode, disposition])!);
    }

    /// <summary>Only an exact lower-case UUID in the Runtime path or the singleton lock-report header is used.</summary>
    [Theory]
    [InlineData("/api/v1/runtime-enrollments/" + EnrollmentText + "/capabilities", null, true)]
    [InlineData("/api/v1/runtime-enrollments/" + EnrollmentText, null, true)]
    [InlineData("/api/v1/runtime-enrollments/805B8EDC-164C-4B67-A71C-372500F63787/capabilities", null, false)]
    [InlineData("/api/v1/runtime-enrollments/not-a-uuid/capabilities", null, false)]
    [InlineData("/api/v1/runtime-enrollments/{" + EnrollmentText + "}/capabilities", null, false)]
    [InlineData("/api/security/lock-report", EnrollmentText, true)]
    [InlineData("/api/security/lock-report", " " + EnrollmentText, false)]
    [InlineData("/api/security/lock-report", null, false)]
    [InlineData("/api/activation/check", EnrollmentText, false)]
    [InlineData("/api/internal/v1/runtime-enrollments/" + EnrollmentText, null, false)]
    public void RuntimeEnrollmentId_IsExtractedFromExactFormsOnly(string path, string? header, bool expected)
    {
        var values = header == null ? StringValues.Empty : new StringValues(header);

        var parsed = AuditMiddleware.TryGetRuntimeEnrollmentId(path, values);

        Assert.Equal(expected, parsed.HasValue);
        if (expected) Assert.Equal(Guid.Parse(EnrollmentText), parsed!.Value);
    }

    /// <summary>Two header values are ambiguous and give no identifier.</summary>
    [Fact]
    public void RuntimeEnrollmentId_RefusesDuplicatedLockReportHeader()
    {
        Assert.Null(AuditMiddleware.TryGetRuntimeEnrollmentId(
            "/api/security/lock-report", new StringValues([EnrollmentText, EnrollmentText])));
    }

    /// <summary>Operator IP input maps to the canonical text and every persisted key form.</summary>
    [Theory]
    [InlineData("82.77.222.104", "82.77.222.104", "82.77.222.104|::ffff:82.77.222.104")]
    [InlineData(" 82.77.222.104 ", "82.77.222.104", "82.77.222.104|::ffff:82.77.222.104")]
    [InlineData("::ffff:82.77.222.104", "82.77.222.104", "82.77.222.104|::ffff:82.77.222.104")]
    [InlineData("::FFFF:82.77.222.104", "82.77.222.104", "82.77.222.104|::ffff:82.77.222.104")]
    [InlineData("2001:0DB8:0:0:0:0:0:1", "2001:db8::1", "2001:db8::1")]
    public void ThreatScoreKeys_AreCanonical(string input, string canonical, string keys)
    {
        Assert.True(SecurityService.TryGetThreatScoreKeys(input, out var actualCanonical, out var actualKeys));
        Assert.Equal(canonical, actualCanonical);
        Assert.Equal(keys.Split('|'), actualKeys);
    }

    /// <summary>Anything that is not an IP address is refused.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("example.com")]
    [InlineData("82.77.222.104/32")]
    [InlineData("82.77.222.104,1.2.3.4")]
    public void ThreatScoreKeys_RefuseNonIp(string? input)
    {
        Assert.False(SecurityService.TryGetThreatScoreKeys(input, out _, out _));
    }

    /// <summary>The licence key never leaves the server in clear.</summary>
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("SHORTKEY", "***")]
    [InlineData("ABCD-EFGH-IJKL-MNOP", "ABCD...MNOP")]
    public void LicenseKey_IsMasked(string? key, string expected)
    {
        Assert.Equal(expected, SecurityService.MaskLicenseKey(key));
    }

    /// <summary>
    /// A persisted score still inside the 30-day window is invisible before the load (old behaviour after a
    /// restart), then visible, and the next event adds to it.
    /// </summary>
    [Fact]
    public async Task PersistedScore_IsVisibleAfterLoad_AndAccumulates()
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();
        var lastHit = DateTime.UtcNow.AddDays(-29);
        await using (var db = fixture.CreateDb())
        {
            db.IpThreatScores.Add(new IpThreatScore { IpAddress = ip, Score = 50, FirstSeen = lastHit, LastHit = lastHit });
            await db.SaveChangesAsync();
        }

        Assert.Equal(0, fixture.Service.GetThreatScore(ip));
        await fixture.Service.EnsureThreatScoresLoadedAsync();
        Assert.Equal(50, fixture.Service.GetThreatScore(ip));

        await fixture.Service.ReportThreatAsync(ip, 10, "test");

        Assert.Equal(60, fixture.Service.GetThreatScore(ip));
        await using var verify = fixture.CreateDb();
        Assert.Equal(60, (await verify.IpThreatScores.SingleAsync(row => row.IpAddress == ip)).Score);
    }

    /// <summary>
    /// Reproduces the 24/10 incident with the decay decided on 25/10: the 50 points left on 19/08 are
    /// erased and journaled (reason « inactif 30 j ») instead of reviving, so the new refusal starts at 0.
    /// </summary>
    [Fact]
    public async Task DormantScore_IsErasedAndJournaled_InsteadOfReviving()
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();
        var lastHit = DateTime.UtcNow.AddDays(-67);
        await using (var db = fixture.CreateDb())
        {
            db.IpThreatScores.Add(new IpThreatScore { IpAddress = ip, Score = 50, FirstSeen = lastHit, LastHit = lastHit });
            await db.SaveChangesAsync();
        }

        await fixture.Service.ReportThreatAsync(ip, 50, "Auth failure on /api/security/lock-report",
            new ThreatScoreContext(ThreatScoreCategory.AuthFailure));

        Assert.Equal(50, fixture.Service.GetThreatScore(ip));
        await using var verify = fixture.CreateDb();
        Assert.Equal(50, (await verify.IpThreatScores.SingleAsync(row => row.IpAddress == ip)).Score);
        var journal = await verify.IpThreatScoreResets.SingleAsync(row => row.IpAddress == ip);
        Assert.Equal(50, journal.PreviousScore);
        Assert.Equal(SecurityService.InactivityResetReason, journal.Reason);
        Assert.Equal("inactif 30 j", journal.Reason);
        Assert.Equal(SecurityService.InactivityResetActor, journal.ResetBy);
        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityThreatScoreRaised,
            It.IsAny<string>(),
            It.Is<string>(message => message.Contains("Score : 0 -> 50")),
            It.IsAny<object>()), Times.Once);
    }

    /// <summary>The sweep erases only scores below 200 idle for 30 days or more, and the load applies it.</summary>
    [Fact]
    public async Task DecaySweep_ErasesOnlyIdleScoresBelowBanThreshold()
    {
        var fixture = CreateFixture();
        var now = DateTime.UtcNow;
        var idle = UniqueIp();
        var idleHigh = UniqueIp();
        var recent = UniqueIp();
        var banLevel = UniqueIp();
        await using (var db = fixture.CreateDb())
        {
            db.IpThreatScores.AddRange(
                new IpThreatScore { IpAddress = idle, Score = 50, FirstSeen = now.AddDays(-40), LastHit = now.AddDays(-30).AddMinutes(-1) },
                new IpThreatScore { IpAddress = idleHigh, Score = 199, FirstSeen = now.AddDays(-90), LastHit = now.AddDays(-31) },
                new IpThreatScore { IpAddress = recent, Score = 150, FirstSeen = now.AddDays(-40), LastHit = now.AddDays(-29) },
                new IpThreatScore { IpAddress = banLevel, Score = 250, FirstSeen = now.AddDays(-90), LastHit = now.AddDays(-60) });
            await db.SaveChangesAsync();
        }

        await fixture.Service.EnsureThreatScoresLoadedAsync();

        Assert.Equal(0, fixture.Service.GetThreatScore(idle));
        Assert.Equal(0, fixture.Service.GetThreatScore(idleHigh));
        Assert.Equal(150, fixture.Service.GetThreatScore(recent));
        await using var verify = fixture.CreateDb();
        var remaining = await verify.IpThreatScores.Select(row => row.IpAddress).ToListAsync();
        Assert.Equal(new[] { banLevel, recent }.OrderBy(value => value), remaining.OrderBy(value => value));
        var journal = await verify.IpThreatScoreResets.ToDictionaryAsync(row => row.IpAddress, row => row.PreviousScore);
        Assert.Equal(2, journal.Count);
        Assert.Equal(50, journal[idle]);
        Assert.Equal(199, journal[idleHigh]);
        Assert.Equal(0, await fixture.Service.PurgeInactiveThreatScoresAsync(now));
    }

    /// <summary>The decay rule: below 200 and idle for exactly 30 days or more.</summary>
    [Theory]
    [InlineData(50, 30 * 24 * 60, true)]
    [InlineData(50, 30 * 24 * 60 - 1, false)]
    [InlineData(199, 60 * 24 * 60, true)]
    [InlineData(200, 60 * 24 * 60, false)]
    [InlineData(0, 31 * 24 * 60, true)]
    public void DecayRule_IsBelowBanThresholdAndIdleThirtyDays(int score, int idleMinutes, bool expected)
    {
        var now = new DateTime(2026, 10, 25, 18, 0, 0, DateTimeKind.Utc);

        Assert.Equal(expected, SecurityService.IsThreatScoreDecayed(score, now.AddMinutes(-idleMinutes), now));
    }

    /// <summary>One alert at 50, none below the next threshold, one at 100, then the ban at 200.</summary>
    [Fact]
    public async Task ThresholdAlerts_AreSentOncePerCrossing()
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();
        var context = new ThreatScoreContext(
            ThreatScoreCategory.AuthFailure, "POST", "/api/security/lock-report",
            "295E9EDCB85175A6", "ABCD-EFGH-IJKL-MNOP", "TIAConnect", "RO", "Example ISP");

        await fixture.Service.ReportThreatAsync(ip, 20, "first", context);
        VerifyAlerts(fixture, Times.Never());
        await fixture.Service.ReportThreatAsync(ip, 30, "second", context);
        VerifyAlerts(fixture, Times.Once());
        await fixture.Service.ReportThreatAsync(ip, 20, "third", context);
        VerifyAlerts(fixture, Times.Once());
        await fixture.Service.ReportThreatAsync(ip, 30, "fourth", context);
        VerifyAlerts(fixture, Times.Exactly(2));

        var messages = fixture.Notifier.Invocations
            .Where(invocation => invocation.Method.Name == nameof(NotificationService.Notify)
                && (string)invocation.Arguments[0] == NotificationService.Triggers.SecurityThreatScoreRaised)
            .Select(invocation => (string)invocation.Arguments[2])
            .ToList();
        Assert.Contains("Score : 20 -> 50 (+30)", messages[0]);
        Assert.Contains("HWID 295E9EDCB85175A6", messages[0]);
        Assert.Contains("licence ABCD...MNOP", messages[0]);
        Assert.Contains("(RO, Example ISP)", messages[0]);
        Assert.Contains("Route : POST /api/security/lock-report", messages[0]);
        Assert.DoesNotContain("ABCD-EFGH-IJKL-MNOP", messages[0]);
        Assert.Contains("Score : 70 -> 100 (+30)", messages[1]);
        Assert.Contains("ralentie", messages[1]);
        Assert.DoesNotContain("2014", string.Concat(messages));
    }

    /// <summary>Robot scans from an IP with no client identity do not alert; an auth failure does.</summary>
    [Fact]
    public async Task ScanWithoutKnownClient_DoesNotAlert_AuthFailureDoes()
    {
        var fixture = CreateFixture();
        var scanner = UniqueIp();
        var stranger = UniqueIp();

        for (var index = 0; index < 3; index++)
            await fixture.Service.ReportThreatAsync(scanner, 20, "scan", new ThreatScoreContext(ThreatScoreCategory.Scan));
        await fixture.Service.ReportThreatAsync(stranger, 50, "auth", new ThreatScoreContext(ThreatScoreCategory.AuthFailure));

        Assert.Equal(60, fixture.Service.GetThreatScore(scanner));
        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityThreatScoreRaised,
            It.Is<string>(title => title.Contains(scanner)),
            It.IsAny<string>(), It.IsAny<object>()), Times.Never);
        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityThreatScoreRaised,
            It.Is<string>(title => title.Contains(stranger)),
            It.Is<string>(message => message.Contains("aucune identité client connue")),
            It.IsAny<object>()), Times.Once);
    }

    /// <summary>A scan from an IP already known as a client (audit log) still alerts, naming that client.</summary>
    [Fact]
    public async Task ScanFromKnownClientIp_AlertsWithAuditIdentity()
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();
        await using (var db = fixture.CreateDb())
        {
            db.AccessLogs.Add(new AccessLog
            {
                ClientIp = ip, Timestamp = DateTime.UtcNow.AddDays(-2), HardwareId = "295E9EDCB85175A6",
                LicenseKey = "ABCD-EFGH-IJKL-MNOP", AppName = "TIAConnect", Path = "/api/activation/check"
            });
            db.AccessLogs.Add(new AccessLog
            {
                ClientIp = UniqueIp(), Timestamp = DateTime.UtcNow, HardwareId = "OTHERHWID0000000",
                LicenseKey = "ZZZZ-YYYY-XXXX-WWWW", AppName = "TIAConnect", Path = "/api/activation/check"
            });
            await db.SaveChangesAsync();
        }

        await fixture.Service.ReportThreatAsync(ip, 60, "scan", new ThreatScoreContext(ThreatScoreCategory.Scan));

        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityThreatScoreRaised,
            It.IsAny<string>(),
            It.Is<string>(message => message.Contains("HWID 295E9EDCB85175A6") && message.Contains("ABCD...MNOP")
                && !message.Contains("OTHERHWID")),
            It.IsAny<object>()), Times.Once);
    }

    /// <summary>
    /// Reset erases both persisted key forms and the memory without restart, keeps bans unchanged, and
    /// journals the erased total; the next crossing alerts again.
    /// </summary>
    [Fact]
    public async Task Reset_ErasesDatabaseAndMemory_JournalsAndRearmsAlert()
    {
        var fixture = CreateFixture();
        var octet = Random.Shared.Next(1, 250);
        var plain = $"198.51.100.{octet}";
        var mapped = "::ffff:" + plain;
        var context = new ThreatScoreContext(ThreatScoreCategory.AuthFailure);
        await fixture.Service.ReportThreatAsync(plain, 100, "auth", context);
        await fixture.Service.ReportThreatAsync(mapped, 30, "auth", context);
        await using (var db = fixture.CreateDb())
        {
            db.BannedIps.Add(new BannedIp { IpAddress = plain, BannedAt = DateTime.UtcNow, Reason = "older ban", BanCount = 2, IsActive = false });
            await db.SaveChangesAsync();
        }

        var result = await fixture.Service.ResetThreatScoreAsync(mapped, "admin-ui:alice", "  Vrai client, TKT-002685  ");

        Assert.Equal(plain, result.IpAddress);
        Assert.Equal(130, result.PreviousScore);
        Assert.Equal(0, fixture.Service.GetThreatScore(plain));
        Assert.Equal(0, fixture.Service.GetThreatScore(mapped));
        await using (var verify = fixture.CreateDb())
        {
            Assert.False(await verify.IpThreatScores.AnyAsync(row => row.IpAddress == plain || row.IpAddress == mapped));
            var journal = await verify.IpThreatScoreResets.SingleAsync(row => row.Id == result.ResetId);
            Assert.Equal(plain, journal.IpAddress);
            Assert.Equal(130, journal.PreviousScore);
            Assert.Equal("admin-ui:alice", journal.ResetBy);
            Assert.Equal("Vrai client, TKT-002685", journal.Reason);
            Assert.Equal(2, (await verify.BannedIps.SingleAsync(ban => ban.IpAddress == plain)).BanCount);
        }

        await fixture.Service.ReportThreatAsync(plain, 50, "auth again", context);
        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityThreatScoreRaised,
            It.Is<string>(title => title.Contains(plain)),
            It.Is<string>(message => message.Contains("Score : 0 -> 50")),
            It.IsAny<object>()), Times.Once);

        var details = await fixture.Service.GetThreatScoreDetailsAsync(plain);
        Assert.Equal(50, Assert.Single(details.Scores).Score);
        Assert.Equal(result.ResetId, Assert.Single(details.RecentResets).Id);
    }

    /// <summary>Invalid reset requests are refused before any change.</summary>
    [Theory]
    [InlineData("not-an-ip", "reason", "invalid_ip")]
    [InlineData("203.0.113.9", "", "invalid_reason")]
    [InlineData("203.0.113.9", "   ", "invalid_reason")]
    public async Task Reset_RefusesInvalidRequest(string ip, string reason, string errorCode)
    {
        var fixture = CreateFixture();

        var exception = await Assert.ThrowsAsync<ThreatScoreResetValidationException>(
            () => fixture.Service.ResetThreatScoreAsync(ip, "test", reason));

        Assert.Equal(errorCode, exception.ErrorCode);
        await using var verify = fixture.CreateDb();
        Assert.False(await verify.IpThreatScoreResets.AnyAsync());
    }

    /// <summary>
    /// End to end through the middleware: a lock report refused for clock skew, and a Runtime refusal
    /// naming an enrollment that exists, are not scored; the same refusal naming an unknown enrollment is.
    /// </summary>
    [Theory]
    [InlineData("lock-report-clock-skew", 0)]
    [InlineData("runtime-known-enrollment", 0)]
    [InlineData("lock-report-known-enrollment", 0)]
    [InlineData("runtime-unknown-enrollment", 50)]
    [InlineData("lock-report-no-header", 50)]
    public async Task Middleware_DoesNotScoreIdentifiedRuntimeClients(string scenario, int expectedScore)
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();
        var knownEnrollment = Guid.NewGuid();
        await using (var db = fixture.CreateDb())
        {
            db.RuntimeEnrollments.Add(new RuntimeEnrollment
            {
                Id = knownEnrollment, BindingId = Guid.NewGuid(), ProductId = Guid.NewGuid(),
                LicenseId = Guid.NewGuid(), LicenseSeatId = Guid.NewGuid()
            });
            await db.SaveChangesAsync();
        }

        var (path, header, disposition) = scenario switch
        {
            "lock-report-clock-skew" => ("/api/security/lock-report", Guid.NewGuid().ToString("D"),
                RuntimeEnrollmentService.ProofClockSkewDiagnosticCode),
            "runtime-known-enrollment" => ($"/api/v1/runtime-enrollments/{knownEnrollment:D}/capabilities", null, null),
            "lock-report-known-enrollment" => ("/api/security/lock-report", knownEnrollment.ToString("D"), null),
            "runtime-unknown-enrollment" => ($"/api/v1/runtime-enrollments/{Guid.NewGuid():D}/capabilities", null, null),
            _ => ("/api/security/lock-report", (string?)null, (string?)null)
        };

        await InvokeMiddlewareAsync(fixture, ip, path, header, disposition, StatusCodes.Status401Unauthorized);

        Assert.Equal(expectedScore, fixture.Service.GetThreatScore(ip));
    }

    /// <summary>
    /// TKT-004159: the named 403 <c>license_hardware_excluded</c> of the activation routes is a commercial refusal of a
    /// legitimate client whose machine was excluded from the licence; repeating it must neither score nor ban the IP.
    /// Only that exact server-set code on a 403 is exempt: another code, a 401, or no code keeps the 50-point scoring.
    /// </summary>
    [Theory]
    [InlineData(StatusCodes.Status403Forbidden, "license_hardware_excluded", false)]
    [InlineData(StatusCodes.Status403Forbidden, "LICENSE_REVOKED", true)]
    [InlineData(StatusCodes.Status401Unauthorized, "license_hardware_excluded", true)]
    [InlineData(StatusCodes.Status403Forbidden, null, true)]
    public async Task Middleware_DoesNotScoreLicenceHardwareExclusion(int statusCode, string? errorCode, bool scored)
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();

        // Four attempts reach the 200-point ban threshold when the refusal is scored (the ban then resets the score).
        for (var attempt = 0; attempt < 4; attempt++)
            await InvokeMiddlewareAsync(fixture, ip, "/api/activation", null, null, statusCode, errorCode);

        Assert.Equal(scored, await fixture.Service.IsBannedAsync(ip));
        if (!scored)
            Assert.Equal(0, fixture.Service.GetThreatScore(ip));
    }

    /// <summary>
    /// Telemetry is never delayed by a quarantine score (it is never banned either), so a shared egress
    /// address carrying real client telemetry is not slowed down once persisted scores are loaded.
    /// </summary>
    [Fact]
    public async Task Middleware_DoesNotDelayTelemetryInQuarantine()
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();
        await fixture.Service.ReportThreatAsync(ip, 150, "seed", new ThreatScoreContext(ThreatScoreCategory.AuthFailure));

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        await InvokeMiddlewareAsync(fixture, ip, "/api/telemetry/event", null, null, StatusCodes.Status200OK);
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3), $"Telemetry was delayed {stopwatch.Elapsed}.");
        Assert.Equal(150, fixture.Service.GetThreatScore(ip));
    }

    /// <summary>Scans keep their full scoring.</summary>
    [Fact]
    public async Task Middleware_StillScoresScans()
    {
        var fixture = CreateFixture();
        var ip = UniqueIp();

        await InvokeMiddlewareAsync(fixture, ip, "/admin/.env", null, null, StatusCodes.Status200OK);

        Assert.Equal(20, fixture.Service.GetThreatScore(ip));
    }

    private static async Task InvokeMiddlewareAsync(
        Fixture fixture, string ip, string path, string? enrollmentHeader, string? disposition, int statusCode,
        string? resultStatusOverride = null)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["IsIntegrationTest"] = "true" })
            .Build();
        var auditNotifier = new AuditNotifier();
        using var provider = new ServiceCollection()
            .AddSingleton<IDbContextFactory<LicenseDbContext>>(fixture.Factory)
            .AddSingleton(fixture.Service)
            .AddSingleton(auditNotifier)
            .BuildServiceProvider();
        var environment = new Mock<IWebHostEnvironment>();
        environment.SetupGet(value => value.ContentRootPath).Returns(Path.GetTempPath());
        var geoIp = new Mock<GeoIpService>(
            environment.Object, new MemoryCache(new MemoryCacheOptions()), Mock.Of<ILogger<GeoIpService>>());
        geoIp.Setup(service => service.GetGeoInfoAsync(It.IsAny<string>())).ReturnsAsync(new GeoInfo());
        var middleware = new AuditMiddleware(
            async context =>
            {
                if (disposition != null)
                    context.Items[SoftLicence.Server.LogKeys.RuntimeAuthenticationDisposition] = disposition;
                // Same server-owned item the activation controller sets for a named refusal (TagActivationFailure).
                if (resultStatusOverride != null)
                    context.Items[SoftLicence.Server.LogKeys.ResultStatusOverride] = resultStatusOverride;
                context.Response.StatusCode = statusCode;
                await context.Response.WriteAsync("{\"error\":\"authentication_failed\"}");
            },
            Mock.Of<ILogger<AuditMiddleware>>(),
            provider.GetRequiredService<IServiceScopeFactory>());
        var httpContext = new DefaultHttpContext { RequestServices = provider, Response = { Body = new MemoryStream() } };
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Path = path;
        if (enrollmentHeader != null)
            httpContext.Request.Headers["X-Runtime-Enrollment-Id"] = enrollmentHeader;

        await middleware.InvokeAsync(httpContext, fixture.Factory, fixture.Service, geoIp.Object, configuration, auditNotifier);
    }

    private static void VerifyAlerts(Fixture fixture, Times times) =>
        fixture.Notifier.Verify(n => n.Notify(
            NotificationService.Triggers.SecurityThreatScoreRaised,
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object>()), times);

    private static string UniqueIp()
    {
        var bytes = Guid.NewGuid().ToByteArray();
        // 100.64.0.0/10 (shared address space) is neither private nor loopback, so it is scored.
        return $"100.{64 + (bytes[0] & 0x3F)}.{bytes[1]}.{Math.Max((int)bytes[2], 1)}";
    }

    private static Fixture CreateFixture()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase("tkt002685-" + Guid.NewGuid().ToString("N"))
            .Options;
        var factory = new InMemoryFactory(options);
        var notifier = new Mock<NotificationService>(
            Mock.Of<IDbContextFactory<LicenseDbContext>>(),
            Mock.Of<ILogger<NotificationService>>(),
            Mock.Of<IHttpClientFactory>());
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["AdminSettings:AllowedIps"] = string.Empty })
            .Build();
        var service = new SecurityService(factory, Mock.Of<ILogger<SecurityService>>(), notifier.Object, configuration);
        return new Fixture(service, factory, notifier);
    }

    private sealed record Fixture(SecurityService Service, InMemoryFactory Factory, Mock<NotificationService> Notifier)
    {
        public LicenseDbContext CreateDb() => Factory.CreateDbContext();
    }

    private sealed class InMemoryFactory(DbContextOptions<LicenseDbContext> options) : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }
}

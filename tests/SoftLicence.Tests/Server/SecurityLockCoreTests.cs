using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.SecurityLocks;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001177 server core: cause catalogue, strict report validation, verdict policy and signed verdicts.
/// </summary>
public sealed class SecurityLockCoreTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 18, 12, 0, 0, TimeSpan.Zero);
    private readonly RSA _rsa = RSA.Create(2048);

    public void Dispose() => _rsa.Dispose();

    // ── Catalogue ──────────────────────────────────────────────────────────

    [Fact]
    public void Catalog_MatchesTheDesktopCatalogue()
    {
        Assert.Equal(22, SecurityLockCauseCatalog.AllCauses.Count());
        Assert.True(SecurityLockCauseCatalog.TryGetLevel("HEARTBEAT_UNREACHABLE", out var offline));
        Assert.Equal(1, offline);
        Assert.True(SecurityLockCauseCatalog.TryGetLevel("LEGACY_MARKER", out var legacy));
        Assert.Equal(3, legacy);
        Assert.True(SecurityLockCauseCatalog.TryGetLevel("NATIVE_DLL_REPLACED", out var tamper));
        Assert.Equal(4, tamper);
        Assert.True(SecurityLockCauseCatalog.TryGetLevel("DEBUGGER_ATTACHED_KERNEL", out var attack));
        Assert.Equal(5, attack);
        foreach (var code in new[] { null, "", "legacy_marker", " LEGACY_MARKER", "LEGACY_MARKER ", "LİCENSE_EXPIRED", "UNKNOWN" })
            Assert.False(SecurityLockCauseCatalog.TryGetLevel(code, out _), code ?? "<null>");
    }

    // ── Validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Validate_AcceptsTheExactCanonicalContract()
    {
        var report = SecurityLockReportValidator.Validate(Request(), Now);
        Assert.Equal("NATIVE_DLL_REPLACED", report.Cause);
        Assert.Equal(4, report.Level);
        Assert.Equal(new string('a', 32), report.LockId);
    }

    /// <summary>Canonical parsing is independent from the provider clock used after transactional waits.</summary>
    [Fact]
    public void ValidateStructure_AcceptsCanonicalTimestampsUntilAuthoritativeTimeCheck()
    {
        var request = Request();
        request.SentAtUtc = SecurityLockReportValidator.FormatUtc(Now.AddHours(-1));
        request.FirstSeenUtc = SecurityLockReportValidator.FormatUtc(Now.AddHours(1));

        var report = SecurityLockReportValidator.ValidateStructure(request);

        Assert.Equal(Now.AddHours(-1), report.SentAtUtc);
        Assert.Equal(Now.AddHours(1), report.FirstSeenUtc);
        Assert.Equal("sent_at_outside_window", Assert.Throws<SecurityLockReportValidationException>(
            () => SecurityLockReportValidator.ValidateTime(report, Now)).ErrorCode);
    }

    /// <summary>Temporal validation uses only the explicit authoritative instant and preserves closed errors.</summary>
    [Fact]
    public void ValidateTime_RejectsFutureFirstSeenWithClosedDiagnostic()
    {
        var request = Request();
        request.FirstSeenUtc = SecurityLockReportValidator.FormatUtc(Now.AddMinutes(6));

        var report = SecurityLockReportValidator.ValidateStructure(request);

        Assert.Equal("first_seen_invalid", Assert.Throws<SecurityLockReportValidationException>(
            () => SecurityLockReportValidator.ValidateTime(report, Now)).ErrorCode);
    }

    public static IEnumerable<object[]> InvalidRequests() => new[]
    {
        new object[] { (Action<SecurityLockReportRequest>)(r => r.Schema = "TIA-SECURITY-LOCK-REPORT-V1"), "schema_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.ReportId = r.ReportId!.ToUpperInvariant()), "report_id_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.ReportId = "{" + r.ReportId + "}"), "report_id_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.SentAtUtc = "2026-09-18T12:00:00Z"), "sent_at_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.SentAtUtc = SecurityLockReportValidator.FormatUtc(Now.AddMinutes(-6))), "sent_at_outside_window" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.HardwareId = "abcdef"), "hardware_id_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.HardwareId = " ABCDEF"), "hardware_id_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.LockId = new string('A', 32)), "lock_id_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.LockId = new string('a', 31)), "lock_id_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.Cause = "native_dll_replaced"), "cause_unknown" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.Level = 3), "level_mismatch" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.Mode = "review"), "mode_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.Mode = "NOT_APPLICABLE"), "mode_mismatch" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.EvidenceDigestSha256 = new string('F', 64)), "evidence_digest_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.FirstSeenUtc = SecurityLockReportValidator.FormatUtc(Now.AddHours(1))), "first_seen_invalid" },
        new object[] { (Action<SecurityLockReportRequest>)(r => r.ExtensionData = new() { ["x"] = default }), "unexpected_field" }
    };

    [Theory]
    [MemberData(nameof(InvalidRequests))]
    public void Validate_RejectsEveryNonCanonicalVariant(Action<SecurityLockReportRequest> mutate, string expected)
    {
        var request = Request();
        mutate(request);
        var error = Assert.Throws<SecurityLockReportValidationException>(() => SecurityLockReportValidator.Validate(request, Now));
        Assert.Equal(expected, error.ErrorCode);
    }

    [Fact]
    public void Validate_ReversibleCauseRequiresNotApplicableMode()
    {
        var request = Request();
        request.Cause = "LEGACY_MARKER";
        request.Level = 3;
        request.Mode = "REVIEW";
        Assert.Equal("mode_mismatch", Assert.Throws<SecurityLockReportValidationException>(
            () => SecurityLockReportValidator.Validate(request, Now)).ErrorCode);
        request.Mode = "NOT_APPLICABLE";
        Assert.Equal(3, SecurityLockReportValidator.Validate(request, Now).Level);
    }

    // ── Policy ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("HEARTBEAT_UNREACHABLE", 1, "NOT_APPLICABLE", null, false, false, "RELEASE", "RELEASED")]
    [InlineData("LICENSE_EXPIRED", 2, "NOT_APPLICABLE", null, false, false, "RELEASE", "RELEASED")]
    [InlineData("SERVER_REVOKED", 3, "NOT_APPLICABLE", null, false, false, "MAINTAIN", "OPEN")]
    [InlineData("SERVER_REVOKED", 3, "NOT_APPLICABLE", "RELEASE", false, false, "RELEASE", "RELEASED")]
    [InlineData("LEGACY_MARKER", 3, "NOT_APPLICABLE", null, false, false, "RELEASE", "RELEASED")]
    [InlineData("LEGACY_MARKER", 3, "NOT_APPLICABLE", null, false, true, "MAINTAIN", "OPEN")]
    [InlineData("STATE_UNREADABLE", 3, "NOT_APPLICABLE", null, false, false, "MAINTAIN", "OPEN")]
    [InlineData("NATIVE_DLL_REPLACED", 4, "SHADOW", null, false, false, "RELEASE", "RELEASED")]
    [InlineData("NATIVE_DLL_REPLACED", 4, "REVIEW", null, false, false, "MAINTAIN", "OPEN")]
    [InlineData("NATIVE_DLL_REPLACED", 4, "REVIEW", "RELEASE", false, false, "RELEASE", "RELEASED")]
    [InlineData("NATIVE_DLL_REPLACED", 4, "REVIEW", "BAN", false, false, "BAN", "BANNED")]
    [InlineData("DEBUGGER_ATTACHED_KERNEL", 5, "ENFORCE", null, false, false, "BAN", "BANNED")]
    [InlineData("DEBUGGER_ATTACHED_KERNEL", 5, "ENFORCE", "RELEASE", false, false, "BAN", "BANNED")]
    [InlineData("LEGACY_MARKER", 3, "NOT_APPLICABLE", null, true, false, "BAN", "BANNED")]
    public void Policy_AppliesTheClosedDecisionTable(
        string cause, int level, string mode, string? admin, bool banned, bool incident, string verdict, string state)
    {
        var decision = SecurityLockVerdictPolicy.Decide(new SecurityLockDecisionInput(cause, level, mode, admin, banned, incident));
        Assert.Equal(verdict, decision.Verdict);
        Assert.Equal(state, decision.State);
    }

    [Fact]
    public void Policy_ResolvesServerModeAndNeverDefaultsToEnforce()
    {
        Assert.Equal("NOT_APPLICABLE", SecurityLockVerdictPolicy.ResolveEffectiveMode(3, "ENFORCE"));
        Assert.Equal("REVIEW", SecurityLockVerdictPolicy.ResolveEffectiveMode(5, null));
        Assert.Equal("REVIEW", SecurityLockVerdictPolicy.ResolveEffectiveMode(4, "enforce"));
        Assert.Equal("SHADOW", SecurityLockVerdictPolicy.ResolveEffectiveMode(4, "SHADOW"));
        Assert.Equal("ENFORCE", SecurityLockVerdictPolicy.ResolveEffectiveMode(5, "ENFORCE"));
        Assert.Equal("debugger", SecurityLockVerdictPolicy.BanCategoryFor(5));
        Assert.Equal("piracy", SecurityLockVerdictPolicy.BanCategoryFor(4));
    }

    // ── Signed verdict ─────────────────────────────────────────────────────

    [Fact]
    public void Verdict_IsSignedBoundAndShortLived()
    {
        var service = CreateService();
        var enrollment = Guid.Parse("11111111-2222-4333-8444-555555555555");
        var report = SecurityLockReportValidator.Validate(Request(), Now);
        var verdict = service.CreateSecurityLockVerdict(enrollment, report, SecurityLockVerdicts.Release, Now);

        Assert.Equal(CanaryAckService.SecurityLockVerdictSchema, verdict.Schema);
        Assert.Equal(enrollment.ToString("D"), verdict.EnrollmentId);
        Assert.Equal(report.ReportId, verdict.ReportId);
        Assert.Equal(report.LockId, verdict.LockId);
        Assert.Equal("2026-09-18T12:03:00.0000000Z", verdict.ExpiresAtUtc);
        var payload = Encoding.UTF8.GetBytes(CanaryAckService.BuildSecurityLockVerdictPayload(verdict));
        var signature = Base64UrlDecode(verdict.Signature);
        Assert.True(_rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        var tampered = verdict with { Verdict = SecurityLockVerdicts.Ban };
        Assert.False(_rsa.VerifyData(Encoding.UTF8.GetBytes(CanaryAckService.BuildSecurityLockVerdictPayload(tampered)),
            signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.CreateSecurityLockVerdict(enrollment, report, "release", Now));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static SecurityLockReportRequest Request() => new()
    {
        Schema = SecurityLockReportValidator.RequestSchema,
        ReportId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        SentAtUtc = SecurityLockReportValidator.FormatUtc(Now),
        HardwareId = "ABCDEF0123456789",
        AppVersion = "2.4.290",
        LockId = new string('a', 32),
        Cause = "NATIVE_DLL_REPLACED",
        Level = 4,
        Mode = "REVIEW",
        EvidenceDigestSha256 = new string('e', 64),
        FirstSeenUtc = SecurityLockReportValidator.FormatUtc(Now.AddMinutes(-2))
    };

    private CanaryAckService CreateService()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["CanaryAck:PrivateKeyPem"] = _rsa.ExportPkcs8PrivateKeyPem() })
            .Build();
        var options = new DbContextOptionsBuilder<LicenseDbContext>().UseSqlite("Data Source=:memory:").Options;
        return new CanaryAckService(new TestDbContextFactory(options), configuration, new FixedTimeProvider(Now));
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded + new string('=', (4 - padded.Length % 4) % 4));
    }

    private sealed class TestDbContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        public LicenseDbContext CreateDbContext() => new(options);
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}

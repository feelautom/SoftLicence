using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed record PrivateValidationTestResetRequest(
    Guid ProductId,
    Guid EnrollmentId,
    Guid BindingId,
    string InstallationId,
    string ReleaseVersion,
    int SecurityEpoch,
    string TicketRef);

public sealed record PrivateValidationTestResetResult(
    Guid ProductId,
    Guid EnrollmentId,
    Guid BindingId,
    string InstallationId,
    string ReleaseVersion,
    int SecurityEpoch,
    string EnrollmentState,
    string BindingState,
    long AuthorityEpoch,
    string InvalidationReason,
    bool AlreadyApplied,
    bool Executed);

public sealed class PrivateValidationTestResetException : Exception
{
    public string ErrorCode { get; }
    public int StatusCode { get; }

    public PrivateValidationTestResetException(string errorCode, int statusCode)
        : base(errorCode)
    {
        ErrorCode = errorCode;
        StatusCode = statusCode;
    }
}

public interface IPrivateValidationTestResetService
{
    Task<PrivateValidationTestResetResult> ValidateAsync(
        PrivateValidationTestResetRequest request,
        CancellationToken cancellationToken = default);

    Task<PrivateValidationTestResetResult> ExecuteAsync(
        PrivateValidationTestResetRequest request,
        CancellationToken cancellationToken = default);
}

public sealed partial class PrivateValidationTestResetService : IPrivateValidationTestResetService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IRuntimeEnrollmentAuthorityService _authority;
    private readonly TimeProvider _timeProvider;
    private readonly HashSet<Guid> _allowedLicenseIds;

    public PrivateValidationTestResetService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IRuntimeEnrollmentAuthorityService authority,
        TimeProvider timeProvider,
        IConfiguration configuration)
    {
        _dbFactory = dbFactory;
        _authority = authority;
        _timeProvider = timeProvider;
        _allowedLicenseIds = ParseAllowedLicenseIds(
            configuration["PrivateValidationTestReset:AllowedLicenseIds"]);
    }

    public async Task<PrivateValidationTestResetResult> ValidateAsync(
        PrivateValidationTestResetRequest request,
        CancellationToken cancellationToken = default)
    {
        var validated = ValidateRequest(request);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await InspectAsync(db, validated, executed: false, cancellationToken);
    }

    public async Task<PrivateValidationTestResetResult> ExecuteAsync(
        PrivateValidationTestResetRequest request,
        CancellationToken cancellationToken = default)
    {
        var validated = ValidateRequest(request);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        RuntimeAuthorityLease lease;
        try
        {
            lease = await _authority.AcquireMutationAsync(db, validated.BindingId, cancellationToken);
        }
        catch (InvalidOperationException)
        {
            throw Reject("infrastructure_ineligible", StatusCodes.Status503ServiceUnavailable);
        }
        await using var authorityLease = lease;

        var binding = await db.DistributionInstallationBindings
            .FromSqlInterpolated($"SELECT * FROM public.\"DistributionInstallationBindings\" WHERE \"Id\" = {validated.BindingId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken)
            ?? throw Reject("binding_not_found", StatusCodes.Status404NotFound);
        var enrollment = await db.RuntimeEnrollments
            .FromSqlInterpolated($"SELECT * FROM public.\"RuntimeEnrollments\" WHERE \"Id\" = {validated.EnrollmentId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken)
            ?? throw Reject("enrollment_not_found", StatusCodes.Status404NotFound);
        var current = Inspect(enrollment, binding, validated, executed: false);
        EnsureAllowedLicense(enrollment.LicenseId);
        if (current.AlreadyApplied)
        {
            await authorityLease.CommitAsync(cancellationToken);
            return current with { Executed = true };
        }

        var now = await RuntimeEnrollmentService.DatabaseNowAsync(db, cancellationToken);
        try
        {
            await RuntimeEnrollmentService.ValidateEnrollmentAuthorityAsync(
                db, enrollment, now, cancellationToken);
        }
        catch (RuntimeEnrollmentException)
        {
            throw Reject("authority_ineligible", StatusCodes.Status409Conflict);
        }

        binding.State = "invalidated";
        binding.InvalidatedAtUtc = now.UtcDateTime;
        binding.InvalidationReason = validated.InvalidationReason;
        await db.SaveChangesAsync(cancellationToken);

        var authorityEpoch = await db.RuntimeEnrollmentAuthorityStates.AsNoTracking()
            .Where(candidate => candidate.Id == 1)
            .Select(candidate => candidate.Epoch)
            .SingleAsync(cancellationToken);

        enrollment.State = "INVALIDATED";
        enrollment.InvalidatedAtUtc = now.UtcDateTime;
        enrollment.InvalidationReason = validated.InvalidationReason;
        enrollment.AuthorityEpoch = authorityEpoch;
        await db.SaveChangesAsync(cancellationToken);
        await authorityLease.CommitAsync(cancellationToken);

        return new(
            validated.ProductId,
            validated.EnrollmentId,
            validated.BindingId,
            validated.InstallationId,
            validated.ReleaseVersion,
            validated.SecurityEpoch,
            enrollment.State,
            binding.State,
            authorityEpoch,
            validated.InvalidationReason,
            AlreadyApplied: false,
            Executed: true);
    }

    private async Task<PrivateValidationTestResetResult> InspectAsync(
        LicenseDbContext db,
        ValidatedRequest request,
        bool executed,
        CancellationToken cancellationToken)
    {
        var enrollment = await db.RuntimeEnrollments.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == request.EnrollmentId, cancellationToken)
            ?? throw Reject("enrollment_not_found", StatusCodes.Status404NotFound);
        var binding = await db.DistributionInstallationBindings.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == request.BindingId, cancellationToken)
            ?? throw Reject("binding_not_found", StatusCodes.Status404NotFound);

        var result = Inspect(enrollment, binding, request, executed);
        EnsureAllowedLicense(enrollment.LicenseId);
        if (!result.AlreadyApplied)
        {
            try
            {
                await RuntimeEnrollmentService.ValidateEnrollmentAuthorityAsync(
                    db, enrollment, _timeProvider.GetUtcNow(), cancellationToken);
            }
            catch (RuntimeEnrollmentException)
            {
                throw Reject("authority_ineligible", StatusCodes.Status409Conflict);
            }
        }
        return result;
    }

    private static PrivateValidationTestResetResult Inspect(
        RuntimeEnrollment enrollment,
        DistributionInstallationBinding binding,
        ValidatedRequest request,
        bool executed)
    {

        if (enrollment.ProductId != request.ProductId
            || binding.ProductId != request.ProductId
            || enrollment.BindingId != binding.Id
            || enrollment.InstallationId != request.InstallationId
            || binding.InstallationId != request.InstallationId
            || enrollment.ReleaseVersion != request.ReleaseVersion
            || binding.Version != request.ReleaseVersion
            || enrollment.SecurityEpoch != request.SecurityEpoch
            || enrollment.LicenseId != binding.LicenseId
            || enrollment.LicenseSeatId != binding.LicenseSeatId
            || enrollment.HardwareIdHash != binding.HardwareIdHash
            || enrollment.HandoffDigestSha256 != binding.HandoffDigestSha256)
        {
            throw Reject("identity_mismatch", StatusCodes.Status409Conflict);
        }

        var active = enrollment.State == "ACTIVE" && binding.State == "active"
            && enrollment.InvalidatedAtUtc == null && binding.InvalidatedAtUtc == null
            && enrollment.InvalidationReason == null && binding.InvalidationReason == null;
        var alreadyApplied = enrollment.State == "INVALIDATED" && binding.State == "invalidated"
            && enrollment.InvalidatedAtUtc != null && binding.InvalidatedAtUtc != null
            && enrollment.InvalidationReason == request.InvalidationReason
            && binding.InvalidationReason == request.InvalidationReason;
        if (!active && !alreadyApplied)
            throw Reject("identity_state_conflict", StatusCodes.Status409Conflict);

        return new(
            request.ProductId,
            request.EnrollmentId,
            request.BindingId,
            request.InstallationId,
            request.ReleaseVersion,
            request.SecurityEpoch,
            enrollment.State,
            binding.State,
            enrollment.AuthorityEpoch,
            request.InvalidationReason,
            alreadyApplied,
            executed);
    }

    private void EnsureAllowedLicense(Guid licenseId)
    {
        if (!_allowedLicenseIds.Contains(licenseId))
            throw Reject("test_identity_forbidden", StatusCodes.Status403Forbidden);
    }

    private static HashSet<Guid> ParseAllowedLicenseIds(string? configured)
    {
        var result = new HashSet<Guid>();
        foreach (var value in (configured ?? string.Empty)
                     .Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            if (value != value.Trim()
                || !Guid.TryParseExact(value, "D", out var parsed)
                || value != parsed.ToString("D")
                || !result.Add(parsed))
            {
                return [];
            }
        }
        return result;
    }

    private static ValidatedRequest ValidateRequest(PrivateValidationTestResetRequest request)
    {
        var normalizedVersion = ApprovedBinaryService.NormalizeVersion(request.ReleaseVersion);
        var installationIdValid = Guid.TryParseExact(request.InstallationId, "D", out var installationId)
            && request.InstallationId == installationId.ToString("D");
        if (request.ProductId == Guid.Empty
            || request.EnrollmentId == Guid.Empty
            || request.BindingId == Guid.Empty
            || !installationIdValid
            || normalizedVersion == null
            || normalizedVersion != request.ReleaseVersion
            || request.SecurityEpoch < 1
            || !TicketPattern().IsMatch(request.TicketRef))
        {
            throw Reject("invalid_request", StatusCodes.Status400BadRequest);
        }

        var reason = $"test_identity_reset_{request.TicketRef.ToLowerInvariant().Replace('-', '_')}";
        return new(
            request.ProductId,
            request.EnrollmentId,
            request.BindingId,
            installationId.ToString("D"),
            normalizedVersion,
            request.SecurityEpoch,
            reason);
    }

    private static PrivateValidationTestResetException Reject(string code, int statusCode) =>
        new(code, statusCode);

    private sealed record ValidatedRequest(
        Guid ProductId,
        Guid EnrollmentId,
        Guid BindingId,
        string InstallationId,
        string ReleaseVersion,
        int SecurityEpoch,
        string InvalidationReason);

    [GeneratedRegex("^TKT-[0-9]{6}$", RegexOptions.CultureInvariant)]
    private static partial Regex TicketPattern();
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public interface IDistributionLicenseBootstrapService
{
    Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> IssueAsync(
        string clientId, string exactBodyDigest, DistributionLicenseBootstrapIssueRequest request,
        CancellationToken cancellationToken = default);
    Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> RemintAsync(
        string clientId, string exactBodyDigest, DistributionLicenseBootstrapRemintRequest request,
        CancellationToken cancellationToken = default);
    Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> RecoverAsync(
        string clientId, string exactBodyDigest, DistributionLicenseBootstrapRecoverRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class DistributionLicenseBootstrapService : IDistributionLicenseBootstrapService
{
    public const string IssueSchema = "distribution-license-bootstrap-issue-v1";
    public const string RemintSchema = "distribution-license-bootstrap-remint-v1";
    public const string RecoverSchema = "distribution-license-bootstrap-recover-v1";
    public const string ResponseSchema = "distribution-license-bootstrap-capability-v1";
    public const string Audience = "urn:softlicence:license-bootstrap-v1";
    private const string IssueOperation = "issue";
    private const string RemintOperation = "remint";
    private const string RecoverOperation = "recover";
    private const string UtcFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";
    private static readonly Regex LowerSha256 = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IRuntimeEnrollmentAuthorityService _authority;
    private readonly IRuntimeEnrollmentCryptoService _crypto;
    private readonly IRuntimeEnrollmentKeyRegistryService _keyRegistry;
    private readonly RuntimeEnrollmentOptions _options;
    private readonly TimeProvider _timeProvider;

    public DistributionLicenseBootstrapService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IRuntimeEnrollmentAuthorityService authority,
        IRuntimeEnrollmentCryptoService crypto,
        IRuntimeEnrollmentKeyRegistryService keyRegistry,
        IOptions<RuntimeEnrollmentOptions> options,
        TimeProvider timeProvider)
    {
        _dbFactory = dbFactory;
        _authority = authority;
        _crypto = crypto;
        _keyRegistry = keyRegistry;
        _options = options.Value;
        _timeProvider = timeProvider;
    }

    public Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> IssueAsync(
        string clientId, string exactBodyDigest, DistributionLicenseBootstrapIssueRequest request,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(clientId, exactBodyDigest, request, null, IssueOperation, cancellationToken);

    public Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> RemintAsync(
        string clientId, string exactBodyDigest, DistributionLicenseBootstrapRemintRequest request,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(clientId, exactBodyDigest, request, ParseUuid(request.BootstrapId), RemintOperation, cancellationToken);

    public Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> RecoverAsync(
        string clientId, string exactBodyDigest, DistributionLicenseBootstrapRecoverRequest request,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(clientId, exactBodyDigest, request, null, RecoverOperation, cancellationToken);

    /// <summary>
    /// Issues or advances one S2S bootstrap capability after validating immutable Runtime
    /// lineage and the current assignment independently. Exact request replay returns its
    /// sealed original bytes only while both authorities and generation scope remain valid.
    /// The binding lease and commercial read barrier hold through the atomic generation write;
    /// a business denial writes no capability or enrollment state, while unavailable authority
    /// remains distinct from a 422 refusal. Retriable PostgreSQL lock/serialization failures
    /// restart the whole transaction, bounded by the Runtime attempt policy. The lease's global
    /// epoch is not credential identity.
    /// </summary>
    /// <param name="clientId">Authenticated S2S principal that owns the finalized binding.</param>
    /// <param name="exactBodyDigest">SHA-256 of the strict request bytes for idempotency.</param>
    /// <param name="request">Strict issue, remint or recover request.</param>
    /// <param name="expectedAuthorizationId">Existing bootstrap ID required by remint.</param>
    /// <param name="operation">Closed issue/remint/recover operation code.</param>
    /// <param name="cancellationToken">Cancels reads or rolls back the transaction.</param>
    /// <returns>New generation or verified exact replay bytes.</returns>
    private async Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> ExecuteAsync(
        string clientId,
        string exactBodyDigest,
        DistributionLicenseBootstrapIssueRequest request,
        Guid? expectedAuthorizationId,
        string operation,
        CancellationToken cancellationToken)
    {
        var maximumAttempts = Math.Clamp(_options.MaximumTransactionAttempts, 1, 3);
        for (var attempt = 0; attempt < maximumAttempts; attempt++)
        {
            try
            {
                return await ExecuteOnceAsync(clientId, exactBodyDigest, request,
                    expectedAuthorizationId, operation, cancellationToken);
            }
            catch (Exception exception) when (RetryableBootstrapSqlState(exception) is not null)
            {
                var sqlState = RetryableBootstrapSqlState(exception)!;
                if (attempt + 1 >= maximumAttempts)
                    throw new DistributionOperationException("authority_unavailable",
                        StatusCodes.Status503ServiceUnavailable, "postgres_" + sqlState);
                // Only a rolled-back PostgreSQL transaction is retried. Re-entering from the
                // beginning rereads replay and both authorities after the contending writer.
                await Task.Delay(Random.Shared.Next(20, 80) * (attempt + 1), cancellationToken);
            }
        }
        throw new DistributionOperationException("authority_unavailable",
            StatusCodes.Status503ServiceUnavailable, "bootstrap_retry_exhausted");
    }

    /// <summary>
    /// Executes one issue, remint or recover transaction with fresh database state. The caller
    /// retries this complete unit only after PostgreSQL has aborted it for a known contention
    /// SQLSTATE; business refusals and unknown failures are never reclassified or retried.
    /// </summary>
    /// <param name="clientId">Authenticated S2S principal that owns the finalized binding.</param>
    /// <param name="exactBodyDigest">SHA-256 of the strict request bytes.</param>
    /// <param name="request">Strict issue, remint or recover request.</param>
    /// <param name="expectedAuthorizationId">Existing bootstrap ID required by remint.</param>
    /// <param name="operation">Closed issue/remint/recover operation code.</param>
    /// <param name="cancellationToken">Cancels reads or rolls back the transaction.</param>
    /// <returns>New generation or verified exact replay bytes from one transaction.</returns>
    private async Task<DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse>> ExecuteOnceAsync(
        string clientId,
        string exactBodyDigest,
        DistributionLicenseBootstrapIssueRequest request,
        Guid? expectedAuthorizationId,
        string operation,
        CancellationToken cancellationToken)
    {
        if (_options.Mode != "enabled")
            throw Unavailable();
        var expectedSchema = operation switch
        {
            IssueOperation => IssueSchema,
            RemintOperation => RemintSchema,
            RecoverOperation => RecoverSchema,
            _ => throw Invalid()
        };
        if (request.ExtensionData is { Count: > 0 }
            || request.Schema != expectedSchema
            || !TryUuid(request.RequestId, out var requestId)
            || !TryUuid(request.ProductId, out var productId)
            || !TryUuid(request.BindingId, out var bindingId)
            || !TryUuid(request.EnrollmentId, out var enrollmentId)
            || !LowerSha256.IsMatch(exactBodyDigest))
            throw Invalid();

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        // The binding lease orders the generation transaction. Its global epoch also advances
        // for seat, licence, ban and release changes, so it is not bootstrap credential identity.
        // Historical authorization and enrollment epochs must still match each other below.
        await using var lease = await _authority.AcquireAsync(db, bindingId, cancellationToken);
        await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
        await RuntimeCommercialEligibilityValidator.AcquireReadBarrierAsync(db, cancellationToken);
        var replay = await db.DistributionLicenseBootstrapRequests.AsNoTracking()
            .SingleOrDefaultAsync(row => row.ClientId == clientId && row.Operation == operation
                && row.RequestId == requestId.ToString("D"), cancellationToken);
        var now = _timeProvider.GetUtcNow();
        var binding = await db.DistributionInstallationBindings
            .SingleOrDefaultAsync(row => row.Id == bindingId, cancellationToken);
        var enrollment = await db.RuntimeEnrollments
            .SingleOrDefaultAsync(row => row.Id == enrollmentId, cancellationToken);
        var entitlement = binding == null ? null : await db.DistributionEntitlements.AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == binding.EntitlementId, cancellationToken);
        var bindingOwnedByClient = binding != null && await db.DistributionBindingRequests.AsNoTracking()
            .AnyAsync(row => row.BindingId == binding.Id
                && row.Operation == "finalize_binding"
                && row.ClientId == clientId, cancellationToken);
        if (binding == null || enrollment == null
            || entitlement == null
            || entitlement.ClientId != clientId
            || enrollment.ClientId != clientId
            || !bindingOwnedByClient
            || !IsModernEntitlementContractVersion(entitlement.ContractVersion)
            || entitlement.State != "finalized"
            || entitlement.ExpiresAtUtc <= now.UtcDateTime
            || entitlement.ProductId != binding.ProductId
            || entitlement.LicenseId != binding.LicenseId
            || entitlement.GrantRefDigestSha256 != binding.GrantRefDigestSha256
            || entitlement.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256
            || binding.State != "active"
            || binding.ProductId != productId
            || enrollment.ProductId != productId
            || enrollment.BindingId != binding.Id
            || enrollment.InstallationId != binding.InstallationId
            || enrollment.ReleaseVersion != binding.Version
            || enrollment.HandoffDigestSha256 != binding.HandoffDigestSha256
            || enrollment.SubjectRefDigestSha256 != binding.SubjectRefDigestSha256
            || binding.SubjectRefDigestSha256 is not { Length: 64 }
            || enrollment.State is not ("PENDING" or "ACTIVE")
            || binding.HandoffExpiresAtUtc is null
            || binding.HandoffExpiresAtUtc <= now.UtcDateTime)
            throw Reject("bootstrap_ineligible");

        // The frozen binding is a generation-scope witness; the current assignment is the
        // only commercial grant. A changed hardware value on the same seat does not rewrite
        // the historical digest or require a new Runtime credential.
        RuntimeCommercialEligibilityValidator.EligibleAssignment assignment;
        RuntimeEnrollmentIdentityValidator.ApprovedRelease approved;
        try
        {
            approved = await RuntimeEnrollmentIdentityValidator.ValidateBootstrapAsync(
                db, enrollment, cancellationToken);
            assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
                db, enrollment, approved.Binaries, now, cancellationToken);
        }
        catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status503ServiceUnavailable)
        {
            // An incomplete relation or release registry is not a commercial refusal. Keep
            // the public S2S error unavailable and retain the bounded internal reason.
            throw new DistributionOperationException("authority_unavailable",
                StatusCodes.Status503ServiceUnavailable, exception.DiagnosticCode);
        }
        catch (RuntimeEnrollmentException exception) when (
            exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
        {
            throw new DistributionOperationException("bootstrap_ineligible",
                StatusCodes.Status422UnprocessableEntity, exception.DiagnosticCode);
        }
        if (assignment.LicenseId != binding.LicenseId || assignment.SeatId != binding.LicenseSeatId)
            throw Reject("bootstrap_ineligible");
        if (!approved.Binaries.TryGetValue("FP_EXE", out var executable)
            || !approved.Binaries.TryGetValue("FP_DLL", out var nativeDll)
            || !approved.Binaries.TryGetValue("FP_CORE", out var core)
            || !string.Equals(executable, binding.ExecutableSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(nativeDll, binding.NativeDllSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(core, binding.CoreSha256, StringComparison.OrdinalIgnoreCase))
            throw Reject("bootstrap_ineligible");

        if (replay != null)
        {
            if (replay.PayloadDigestSha256 != exactBodyDigest)
                throw Conflict("idempotency_conflict");
            var replayAuthorization = await db.DistributionLicenseBootstrapAuthorizations.AsNoTracking()
                .SingleOrDefaultAsync(row => row.Id == replay.AuthorizationId, cancellationToken);
            var replayCapability = await db.DistributionLicenseBootstrapCapabilities.AsNoTracking()
                .SingleOrDefaultAsync(row => row.Id == replay.CapabilityId, cancellationToken);
            if (replayAuthorization == null
                || replayAuthorization.ExpiresAtUtc <= now.UtcDateTime
                || !AuthorizationMatches(replayAuthorization, binding, enrollment, clientId, productId)
                || replayCapability == null || replayCapability.AuthorizationId != replayAuthorization.Id
                || replayCapability.State != "ISSUED"
                || replayCapability.ExpiresAtUtc <= now.UtcDateTime)
                throw new DistributionOperationException("bootstrap_expired", StatusCodes.Status410Gone);
            var bytes = OpenResponse(replay);
            try
            {
                var replayResponse = JsonSerializer.Deserialize<DistributionLicenseBootstrapIssuedResponse>(bytes, JsonOptions)
                    ?? throw Unavailable();
                await lease.CommitAsync(cancellationToken);
                return new(replayResponse, true, bytes.ToArray());
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }

        DistributionLicenseBootstrapAuthorization authorization;
        if (expectedAuthorizationId.HasValue || operation == RecoverOperation)
        {
            authorization = await db.DistributionLicenseBootstrapAuthorizations
                .SingleOrDefaultAsync(row => expectedAuthorizationId.HasValue
                    ? row.Id == expectedAuthorizationId.Value
                    : row.BindingId == binding.Id && row.RuntimeEnrollmentId == enrollment.Id,
                    cancellationToken)
                ?? throw Reject("bootstrap_ineligible");
            if (authorization.ExpiresAtUtc <= now.UtcDateTime
                || !AuthorizationMatches(authorization, binding, enrollment, clientId, productId))
                throw Reject("bootstrap_ineligible");

            if (operation == RecoverOperation)
            {
                var activeGenerationExists = await db.DistributionLicenseBootstrapCapabilities.AsNoTracking()
                    .AnyAsync(row => row.AuthorizationId == authorization.Id
                        && row.State == "ISSUED" && row.ExpiresAtUtc > now.UtcDateTime,
                        cancellationToken);
                if (activeGenerationExists)
                    throw Conflict("bootstrap_generation_active");
            }

            var supersededCapabilities = await db.DistributionLicenseBootstrapCapabilities
                .Where(row => row.AuthorizationId == authorization.Id && row.State == "ISSUED")
                .ToListAsync(cancellationToken);
            foreach (var supersededCapability in supersededCapabilities)
                supersededCapability.State = "REVOKED";
        }
        else
        {
            var existingAuthorization = await db.DistributionLicenseBootstrapAuthorizations
                .SingleOrDefaultAsync(row => row.BindingId == binding.Id && row.RuntimeEnrollmentId == enrollment.Id,
                    cancellationToken);
            if (existingAuthorization != null)
                throw Conflict("bootstrap_already_issued");
            authorization = NewAuthorization(clientId, binding, enrollment, now);
            db.Add(authorization);
        }

        var expiresAt = now.AddSeconds(_options.LicenseBootstrapCapabilityTtlSeconds);
        if (expiresAt.UtcDateTime > authorization.ExpiresAtUtc)
            expiresAt = new DateTimeOffset(authorization.ExpiresAtUtc, TimeSpan.Zero);
        if (expiresAt <= now)
            throw new DistributionOperationException("bootstrap_expired", StatusCodes.Status410Gone);
        var capabilityBytes = RandomNumberGenerator.GetBytes(32);
        var capability = EncodeBase64Url(capabilityBytes);
        CryptographicOperations.ZeroMemory(capabilityBytes);
        var capabilityRow = new DistributionLicenseBootstrapCapability
        {
            Id = Guid.NewGuid(), AuthorizationId = authorization.Id,
            CapabilityDigestSha256 = Sha256(capability), State = "ISSUED",
            MintedAtUtc = now.UtcDateTime, ExpiresAtUtc = expiresAt.UtcDateTime
        };
        db.Add(capabilityRow);
        var response = new DistributionLicenseBootstrapIssuedResponse(
            ResponseSchema, authorization.Id.ToString("D"), capability,
            FormatUtc(expiresAt), FormatUtc(authorization.ExpiresAtUtc));
        var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
        var envelope = await _crypto.SealAsync(db, "bootstrap-issue-response", capabilityRow.Id, 1,
            responseBytes, RequestReference(clientId, operation, requestId), cancellationToken);
        db.Add(new DistributionLicenseBootstrapRequest
        {
            ClientId = clientId, RequestId = requestId.ToString("D"), Operation = operation,
            PayloadDigestSha256 = exactBodyDigest, AuthorizationId = authorization.Id,
            CapabilityId = capabilityRow.Id, ExactResponseCiphertext = Encoding.ASCII.GetBytes(envelope.Ciphertext),
            ResponseKeyId = envelope.KeyId, CreatedAtUtc = now.UtcDateTime,
            ExpiresAtUtc = authorization.ExpiresAtUtc
        });
        await db.SaveChangesAsync(cancellationToken);
        await lease.CommitAsync(cancellationToken);
        return new(response, false, responseBytes);
    }

    /// <summary>
    /// Recognizes only PostgreSQL transaction-abort states whose complete S2S operation can
    /// safely be retried after rollback. Unknown database failures preserve their original path.
    /// </summary>
    /// <param name="exception">Possible EF/Npgsql wrapper around the PostgreSQL failure.</param>
    /// <returns>The exact allowlisted SQLSTATE, or null when the failure must propagate.</returns>
    private static string? RetryableBootstrapSqlState(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
            if (current is PostgresException postgres
                && postgres.SqlState is "40001" or "40P01" or "55P03")
                return postgres.SqlState;
        return null;
    }

    /// <summary>Recognizes only persisted Distribution entitlement contracts with relational authority.</summary>
    private static bool IsModernEntitlementContractVersion(int contractVersion) => contractVersion is 3 or 4;

    private DistributionLicenseBootstrapAuthorization NewAuthorization(
        string clientId, DistributionInstallationBinding binding, RuntimeEnrollment enrollment, DateTimeOffset now) => new()
    {
        Id = Guid.NewGuid(), ProductId = binding.ProductId, LicenseId = binding.LicenseId,
        LicenseSeatId = binding.LicenseSeatId, EntitlementId = binding.EntitlementId,
        BindingId = binding.Id, RuntimeEnrollmentId = enrollment.Id,
        ClientId = clientId, GrantRefDigestSha256 = binding.GrantRefDigestSha256,
        SubjectRefDigestSha256 = binding.SubjectRefDigestSha256!, HandoffDigestSha256 = binding.HandoffDigestSha256,
        InstallationId = binding.InstallationId, HardwareIdHash = binding.HardwareIdHash,
        ReleaseVersion = binding.Version, ApprovedBinariesDigestSha256 = Sha256(string.Join('\n',
            binding.ExecutableSha256, binding.NativeDllSha256, binding.CoreSha256)),
        RuntimePublicKeySpkiSha256 = enrollment.PublicKeySpkiSha256,
        RuntimeKeyThumbprint = enrollment.KeyThumbprint, RuntimeEpoch = enrollment.Epoch,
        SecurityEpoch = enrollment.SecurityEpoch, AuthorityEpoch = enrollment.AuthorityEpoch,
        Audience = Audience, Use = "license-bootstrap", State = "ISSUED", IssuedAtUtc = now.UtcDateTime,
        ExpiresAtUtc = binding.HandoffExpiresAtUtc!.Value
    };

    /// <summary>
    /// Compares a stored generation with its issuance lineage and Runtime credential. Its
    /// hardware digest is retained as historical evidence and is never compared with mutable
    /// current seat hardware; current commercial scope is checked separately before this call.
    /// A global authority epoch bump does not invalidate matching historical epochs.
    /// </summary>
    /// <param name="authorization">Stored immutable bootstrap generation.</param>
    /// <param name="binding">Current binding used only for issuance-lineage comparisons.</param>
    /// <param name="enrollment">Current Runtime credential and frozen credential epochs.</param>
    /// <param name="clientId">Authenticated S2S owner of this request.</param>
    /// <param name="productId">Canonical product scope from the strict request.</param>
    /// <returns>Whether the old generation still matches its original issuance lineage.</returns>
    private static bool AuthorizationMatches(
        DistributionLicenseBootstrapAuthorization authorization,
        DistributionInstallationBinding binding,
        RuntimeEnrollment enrollment,
        string clientId,
        Guid productId) =>
        authorization.State == "ISSUED"
        && authorization.ClientId == clientId
        && authorization.BindingId == binding.Id
        && authorization.RuntimeEnrollmentId == enrollment.Id
        && authorization.ProductId == productId
        && authorization.LicenseId == binding.LicenseId
        && authorization.LicenseSeatId == binding.LicenseSeatId
        && authorization.EntitlementId == binding.EntitlementId
        && authorization.GrantRefDigestSha256 == binding.GrantRefDigestSha256
        && authorization.SubjectRefDigestSha256 == binding.SubjectRefDigestSha256
        && authorization.HandoffDigestSha256 == binding.HandoffDigestSha256
        && authorization.InstallationId == binding.InstallationId
        && authorization.ReleaseVersion == binding.Version
        && authorization.ApprovedBinariesDigestSha256 == Sha256(string.Join('\n',
            binding.ExecutableSha256, binding.NativeDllSha256, binding.CoreSha256))
        && authorization.RuntimePublicKeySpkiSha256 == enrollment.PublicKeySpkiSha256
        && authorization.RuntimeKeyThumbprint == enrollment.KeyThumbprint
        && authorization.RuntimeEpoch == enrollment.Epoch
        && authorization.SecurityEpoch == enrollment.SecurityEpoch
        && authorization.AuthorityEpoch == enrollment.AuthorityEpoch
        && authorization.Audience == Audience
        && authorization.Use == "license-bootstrap"
        && authorization.ExpiresAtUtc == binding.HandoffExpiresAtUtc;

    private byte[] OpenResponse(DistributionLicenseBootstrapRequest request)
    {
        try
        {
            return _crypto.Open("bootstrap-issue-response", request.CapabilityId, 1,
                request.ResponseKeyId, Encoding.ASCII.GetString(request.ExactResponseCiphertext),
                RequestReference(request.ClientId, request.Operation, Guid.Parse(request.RequestId)));
        }
        catch (CryptographicException) { throw Unavailable(); }
    }

    private static string RequestReference(string clientId, string operation, Guid requestId) =>
        $"{clientId}/{operation}/{requestId:D}";
    private static bool TryUuid(string? value, out Guid id) =>
        Guid.TryParseExact(value, "D", out id) && value == id.ToString("D");
    private static Guid ParseUuid(string? value) => TryUuid(value, out var id) ? id : throw Invalid();
    private static string Sha256(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string EncodeBase64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string FormatUtc(DateTimeOffset value) => value.UtcDateTime.ToString(UtcFormat, System.Globalization.CultureInfo.InvariantCulture);
    private static DistributionOperationException Invalid() => new("invalid_request", StatusCodes.Status400BadRequest);
    private static DistributionOperationException Reject(string error) => new(error, StatusCodes.Status422UnprocessableEntity);
    private static DistributionOperationException Conflict(string error) => new(error, StatusCodes.Status409Conflict);
    private static DistributionOperationException Unavailable() => new("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
}

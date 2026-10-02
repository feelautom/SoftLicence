using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
public sealed class RuntimeEnrollmentsController : ControllerBase
{
    /// <summary>Names the canonical transport header carrying the v2 attempt UUID.</summary>
    private const string AuthorityAttemptHeader = "X-Runtime-Enrollment-Attempt-Id";
    /// <summary>Names the detached recovery key identifier header.</summary>
    private const string AuthorityRecoveryKeyHeader = "X-Runtime-Enrollment-Recovery-Key-Id";
    /// <summary>Names the detached canonical recovery PS256 signature header.</summary>
    private const string AuthorityRecoverySignatureHeader = "X-Runtime-Enrollment-Recovery-Signature";
    /// <summary>Names the signed short-lived server preparation token header.</summary>
    private const string AuthorityRecoveryPreparationHeader = "X-Runtime-Enrollment-Recovery-Preparation";
    /// <summary>Names the response header carrying the existing ASP.NET request correlation identifier.</summary>
    private const string CorrelationHeader = "X-Correlation-Id";
    /// <summary>Names the response header carrying a closed, non-sensitive support classification.</summary>
    private const string SupportCodeHeader = "X-Support-Code";
    private const int MaximumBodyBytes = 4096;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions RequestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly IDistributionS2SAuthenticationService _s2s;
    private readonly IRuntimeEnrollmentService _enrollments;
    private readonly RuntimeEnrollmentOptions _options;
    private readonly ILogger<RuntimeEnrollmentsController>? _logger;
    /// <summary>Optional public key-registry publisher; null keeps the endpoint fail-closed.</summary>
    private readonly IRuntimeAuthorityKeyRegistrySnapshotService? _keyRegistrySnapshots;

    public RuntimeEnrollmentsController(
        IDistributionS2SAuthenticationService s2s,
        IRuntimeEnrollmentService enrollments,
        IOptions<RuntimeEnrollmentOptions> options,
        ILogger<RuntimeEnrollmentsController>? logger = null,
        IRuntimeAuthorityKeyRegistrySnapshotService? keyRegistrySnapshots = null)
    {
        _s2s = s2s;
        _enrollments = enrollments;
        _options = options.Value;
        _logger = logger;
        _keyRegistrySnapshots = keyRegistrySnapshots;
    }

    /// <summary>
    /// Resolves provider-owned Runtime source authority when Website lacks its historical grant.
    /// The provider verifies the exact WebSetup proof. Version 1 remains byte-shape compatible;
    /// version 2 may additionally return one bounded provider-signed generation statement.
    /// </summary>
    [HttpPost("/api/internal/v1/runtime-enrollments/reinstall-source-authority/resolve")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> ResolveReinstallSourceAuthority(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            const string path = "/api/internal/v1/runtime-enrollments/reinstall-source-authority/resolve";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            var request = Deserialize<RuntimeReinstallSourceResolutionRequest>(exactBody);
            var result = await _enrollments.ResolveReinstallSourceAuthorityAsync(
                principal.ClientId, request, cancellationToken);
            return Ok(result);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    /// <summary>
    /// Authorizes an exact reinstall proof and records bounded server-only refusal diagnostics
    /// while preserving the generic public error contract.
    /// </summary>
    /// <param name="cancellationToken">Request cancellation token.</param>
    /// <returns>The minimal authority assertion or a generic error response.</returns>
    [HttpPost("/api/internal/v1/runtime-enrollments/reinstall-authorizations")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> AuthorizeReinstall(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        string? correlationId = null;
        try
        {
            const string path = "/api/internal/v1/runtime-enrollments/reinstall-authorizations";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            var request = Deserialize<RuntimeReinstallAuthorityRequest>(exactBody);
            correlationId = request.BootstrapId;
            var result = await _enrollments.AuthorizeReinstallAsync(
                principal.ClientId, request, cancellationToken);
            _logger?.LogInformation(
                "Runtime reinstall authority {Outcome} CorrelationId={CorrelationId} BindingId={BindingId} EnrollmentId={EnrollmentId}",
                result.Decision, result.CorrelationId, result.BindingId, result.EnrollmentId);
            return Ok(result);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            _logger?.LogWarning(
                "Runtime reinstall authority {Outcome} CorrelationId={CorrelationId} ReasonCode={ReasonCode} DiagnosticCode={DiagnosticCode}",
                "refused", correlationId ?? "unavailable", exception.ErrorCode,
                exception.DiagnosticCode ?? "unspecified");
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/runtime-enrollments/prepare")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> Prepare(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            EnsureExactTarget("/api/internal/v1/runtime-enrollments/prepare");
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            var request = Deserialize<RuntimeEnrollmentPrepareRequest>(exactBody);
            var result = await _enrollments.PrepareAsync(
                principal.ClientId, Digest(exactBody.Span), request, cancellationToken);
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/runtime-enrollments/refresh")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> Refresh(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            const string path = "/api/internal/v1/runtime-enrollments/refresh";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowLicenseBootstrap)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new RuntimeEnrollmentApiError("license_bootstrap_forbidden"));
            var request = Deserialize<RuntimeEnrollmentRefreshRequest>(exactBody);
            var result = await _enrollments.RefreshPendingAsync(
                principal.ClientId, Digest(exactBody.Span), request, cancellationToken);
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/runtime-enrollments/critical-recoveries")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public Task<IActionResult> RecoverCritical(CancellationToken cancellationToken) =>
        ExecuteRecoveryS2SAsync(refetch: false, cancellationToken);

    [HttpPost("/api/internal/v1/runtime-enrollments/upgrades")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> Upgrade(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            const string path = "/api/internal/v1/runtime-enrollments/upgrades";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var relay = Deserialize<RuntimeEnrollmentUpgradeRelayRequest>(exactBody);
            var authorizationBytes = DecodeBase64Url(relay.AuthorizationBodyBase64Url);
            string productId;
            try { productId = ExtractUniqueString(authorizationBytes, "productId"); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowRuntimeUpgrade)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new RuntimeEnrollmentApiError("upgrade_forbidden"));
            var result = await _enrollments.UpgradeAsync(
                principal.ClientId, principal.KeyId, Digest(exactBody.Span), relay, cancellationToken);
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/runtime-enrollments/websetup-transitions")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> IssueWebSetupTransition(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            const string path = "/api/internal/v1/runtime-enrollments/websetup-transitions";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowRuntimeUpgrade)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new RuntimeEnrollmentApiError("upgrade_forbidden"));
            var request = Deserialize<RuntimeWebSetupTransitionIssueRequest>(exactBody);
            var result = await _enrollments.IssueWebSetupTransitionAsync(
                principal.ClientId, Digest(exactBody.Span), request, cancellationToken);
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/runtime-enrollments/websetup-upgrades")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> UpgradeFromWebSetup(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            const string path = "/api/internal/v1/runtime-enrollments/websetup-upgrades";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var relay = Deserialize<RuntimeWebSetupUpgradeRelayRequest>(exactBody);
            var authorizationBytes = DecodeBase64Url(relay.AuthorizationBodyBase64Url);
            string productId;
            try { productId = ExtractUniqueString(authorizationBytes, "productId"); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowRuntimeUpgrade)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new RuntimeEnrollmentApiError("upgrade_forbidden"));
            var result = await _enrollments.UpgradeFromWebSetupAsync(
                principal.ClientId, principal.KeyId, Digest(exactBody.Span), relay, cancellationToken);
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/runtime-enrollments/recovery-rollbacks")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> Rollback(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            const string path = "/api/internal/v1/runtime-enrollments/recovery-rollbacks";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var relay = Deserialize<RuntimeEnrollmentUpgradeRelayRequest>(exactBody);
            var authorizationBytes = DecodeBase64Url(relay.AuthorizationBodyBase64Url);
            string productId;
            try { productId = ExtractUniqueString(authorizationBytes, "productId"); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowRuntimeRecovery)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new RuntimeEnrollmentApiError("recovery_forbidden"));
            var result = await _enrollments.RollbackAsync(
                principal.ClientId, principal.KeyId, Digest(exactBody.Span), relay, cancellationToken);
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/runtime-enrollments/critical-recoveries/refetch")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public Task<IActionResult> RefetchCriticalRecovery(CancellationToken cancellationToken) =>
        ExecuteRecoveryS2SAsync(refetch: true, cancellationToken);

    private async Task<IActionResult> ExecuteRecoveryS2SAsync(
        bool refetch,
        CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            var path = refetch
                ? "/api/internal/v1/runtime-enrollments/critical-recoveries/refetch"
                : "/api/internal/v1/runtime-enrollments/critical-recoveries";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowRuntimeRecovery)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new RuntimeEnrollmentApiError("recovery_forbidden"));

            RuntimeEnrollmentOperationResult<RuntimeCriticalRecoveryResponse> result;
            if (refetch)
            {
                result = await _enrollments.RefetchCriticalRecoveryAsync(
                    principal.ClientId,
                    principal.KeyId,
                    Digest(exactBody.Span),
                    Deserialize<RuntimeCriticalRecoveryRefetchRequest>(exactBody),
                    cancellationToken);
            }
            else
            {
                result = await _enrollments.RecoverCriticalAsync(
                    principal.ClientId,
                    principal.KeyId,
                    Digest(exactBody.Span),
                    Deserialize<RuntimeCriticalRecoveryRequest>(exactBody),
                    cancellationToken);
            }
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (RuntimeEnrollmentException exception)
        {
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    [HttpPost("/api/v1/runtime-enrollments/{enrollmentId}/confirm")]
    [EnableRateLimiting("RuntimeEnrollmentPublicAPI")]
    public Task<IActionResult> Confirm(string enrollmentId, CancellationToken cancellationToken) =>
        ExecutePublicAsync(enrollmentId, "confirm", cancellationToken);

    [HttpPost("/api/v1/runtime-enrollments/{enrollmentId}/capabilities")]
    [EnableRateLimiting("RuntimeEnrollmentPublicAPI")]
    public Task<IActionResult> Capability(string enrollmentId, CancellationToken cancellationToken) =>
        ExecutePublicAsync(enrollmentId, "capabilities", cancellationToken);

    [HttpPost("/api/v1/runtime-enrollments/{enrollmentId}/milestones")]
    [EnableRateLimiting("RuntimeEnrollmentPublicAPI")]
    public Task<IActionResult> Milestone(string enrollmentId, CancellationToken cancellationToken) =>
        ExecutePublicAsync(enrollmentId, "milestones", cancellationToken);

    [HttpPost("/api/v1/runtime-enrollments/{enrollmentId}/critical-recoveries/refetch")]
    [EnableRateLimiting("RuntimeEnrollmentPublicAPI")]
    public Task<IActionResult> RefetchCriticalRecoveryForClient(
        string enrollmentId,
        CancellationToken cancellationToken) =>
        ExecutePublicAsync(enrollmentId, "critical-recoveries/refetch", cancellationToken);

    [HttpPost("/api/v1/runtime-enrollments/{enrollmentId}/license-bootstrap")]
    [EnableRateLimiting("RuntimeEnrollmentPublicAPI")]
    public Task<IActionResult> LicenseBootstrap(string enrollmentId, CancellationToken cancellationToken) =>
        ExecutePublicAsync(enrollmentId, "license-bootstrap", cancellationToken);

    /// <summary>
    /// Transitions the authenticated Runtime installation from its legacy hardware identity
    /// to the deterministic V2 identity without allocating another license seat.
    /// </summary>
    /// <param name="enrollmentId">Canonical Runtime enrollment identifier.</param>
    /// <param name="cancellationToken">Request cancellation token.</param>
    /// <returns>The exact replay-safe migration response.</returns>
    [HttpPost("/api/v1/runtime-enrollments/{enrollmentId}/hardware-authority-migrations")]
    [EnableRateLimiting("RuntimeEnrollmentPublicAPI")]
    public Task<IActionResult> MigrateHardwareAuthority(string enrollmentId, CancellationToken cancellationToken) =>
        ExecutePublicAsync(enrollmentId, "hardware-authority-migrations", cancellationToken);

    /// <summary>Executes a strict public Runtime operation over exact body bytes and proof headers.</summary>
    private async Task<IActionResult> ExecutePublicAsync(
        string enrollmentId,
        string operation,
        CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled")
            return Unavailable();
        try
        {
            if (!TryCanonicalUuid(enrollmentId, out var parsedEnrollmentId))
                throw new InvalidDataException("invalid_request");
            EnsureExactTarget($"/api/v1/runtime-enrollments/{enrollmentId}/{operation}");
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var proof = new RuntimeProofHeaders(
                ReadSingletonHeader(Request.Headers, "X-Runtime-Enrollment-Timestamp"),
                ReadSingletonHeader(Request.Headers, "X-Runtime-Enrollment-Jti"),
                ReadSingletonHeader(Request.Headers, "X-Runtime-Enrollment-Signature"));
            var digest = Digest(exactBody.Span);
            if (operation == "license-bootstrap")
            {
                var request = Deserialize<RuntimeLicenseBootstrapRedeemRequest>(exactBody);
                var result = await _enrollments.RedeemLicenseBootstrapAsync(
                    parsedEnrollmentId, digest, request, proof,
                    HttpContext.Connection.RemoteIpAddress, cancellationToken);
                return File(result.ExactResponseBody, "application/json");
            }
            else if (operation == "hardware-authority-migrations")
            {
                var request = Deserialize<RuntimeHardwareAuthorityMigrationRequest>(exactBody);
                var result = await _enrollments.MigrateHardwareAuthorityAsync(
                    parsedEnrollmentId, digest, request, proof,
                    HttpContext.Connection.RemoteIpAddress, cancellationToken);
                return File(result.ExactResponseBody, "application/json");
            }
            else if (operation == "confirm")
            {
                var request = Deserialize<RuntimeEnrollmentConfirmRequest>(exactBody);
                var result = await _enrollments.ConfirmAsync(
                    parsedEnrollmentId, digest, request, proof,
                    HttpContext.Connection.RemoteIpAddress, cancellationToken);
                return File(result.ExactResponseBody, "application/json");
            }
            else if (operation == "capabilities")
            {
                var request = Deserialize<RuntimeEnrollmentCapabilityRequest>(exactBody);
                var result = await _enrollments.CreateCapabilityAsync(
                    parsedEnrollmentId, digest, request, proof,
                    HttpContext.Connection.RemoteIpAddress, cancellationToken);
                return File(result.ExactResponseBody, "application/json");
            }
            else if (operation == "milestones")
            {
                var request = Deserialize<RuntimeMilestoneRequest>(exactBody);
                var result = await _enrollments.RecordMilestoneAsync(
                    parsedEnrollmentId, digest, request, proof,
                    HttpContext.Connection.RemoteIpAddress, cancellationToken);
                return File(result.ExactResponseBody, "application/json");
            }
            else
            {
                var request = Deserialize<RuntimeCriticalRecoveryClientRefetchRequest>(exactBody);
                var result = await _enrollments.RefetchCriticalRecoveryForClientAsync(
                    parsedEnrollmentId, digest, request, proof,
                    HttpContext.Connection.RemoteIpAddress, cancellationToken);
                return File(result.ExactResponseBody, "application/json");
            }
        }
        catch (RuntimeEnrollmentException exception)
        {
            if (exception.StatusCode == StatusCodes.Status401Unauthorized
                && string.Equals(
                    exception.DiagnosticCode,
                    RuntimeEnrollmentService.ProofClockSkewDiagnosticCode,
                    StringComparison.Ordinal))
            {
                // This request-scoped value is produced only from the server's verified proof-time
                // check. The public response deliberately remains the generic authentication_failed.
                HttpContext.Items[LogKeys.RuntimeAuthenticationDisposition] =
                    RuntimeEnrollmentService.ProofClockSkewDiagnosticCode;
            }
            return StatusCode(exception.StatusCode, new RuntimeEnrollmentApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            return TransportError(exception);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new RuntimeEnrollmentApiError("internal_error"));
        }
    }

    private void EnsureExactTarget(string expectedPath)
    {
        if (!string.Equals(Request.Path.Value, expectedPath, StringComparison.Ordinal)
            || Request.QueryString.HasValue
            || Request.Headers.ContainsKey("Transfer-Encoding"))
            throw new InvalidDataException("invalid_request");
    }

    private static async Task<ReadOnlyMemory<byte>> ReadStrictBodyAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength is null or <= 0 or > MaximumBodyBytes)
            throw new RuntimeTransportException(
                request.ContentLength > MaximumBodyBytes ? StatusCodes.Status413PayloadTooLarge : StatusCodes.Status400BadRequest);
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType)
            || !string.Equals(mediaType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
            || mediaType.Parameters.Count > 1
            || mediaType.Parameters.Any(parameter =>
                !string.Equals(parameter.Name, "charset", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(parameter.Value?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase)))
            throw new RuntimeTransportException(StatusCodes.Status415UnsupportedMediaType);

        var expected = checked((int)request.ContentLength.Value);
        var bytes = new byte[expected];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = await request.Body.ReadAsync(bytes.AsMemory(offset), cancellationToken);
            if (read == 0)
                throw new InvalidDataException("invalid_request");
            offset += read;
        }
        if (await request.Body.ReadAsync(new byte[1], cancellationToken) != 0
            || bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble))
            throw new InvalidDataException("invalid_request");
        _ = StrictUtf8.GetString(bytes);
        return bytes;
    }

    private static void ValidateJsonStructure(ReadOnlyMemory<byte> exactBody)
    {
        using var document = JsonDocument.Parse(exactBody);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new JsonException("invalid_request");
        ValidateNoDuplicateProperties(document.RootElement);
    }

    private static void ValidateNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!seen.Add(property.Name))
                    throw new JsonException("invalid_request");
                ValidateNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
                ValidateNoDuplicateProperties(item);
        }
    }

    private static string ExtractUniqueString(ReadOnlyMemory<byte> exactBody, string propertyName)
    {
        using var document = JsonDocument.Parse(exactBody);
        string? value = null;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Name != propertyName)
                continue;
            if (value != null || property.Value.ValueKind != JsonValueKind.String)
                throw new JsonException("invalid_request");
            value = property.Value.GetString();
        }
        return value ?? throw new JsonException("invalid_request");
    }

    private static byte[] DecodeBase64Url(string? value)
    {
        if (value is not { Length: >= 1 and <= 3500 } || value.Contains('=')
            || value.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            throw new JsonException("invalid_request");
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        var decoded = Convert.FromBase64String(base64);
        var canonical = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (!string.Equals(canonical, value, StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new JsonException("invalid_request");
        }
        return decoded;
    }

    private static T Deserialize<T>(ReadOnlyMemory<byte> exactBody) where T : class =>
        JsonSerializer.Deserialize<T>(exactBody.Span, RequestJsonOptions) ?? throw new JsonException("invalid_request");

    private static string ReadSingletonHeader(IHeaderDictionary headers, string name)
    {
        if (!headers.TryGetValue(name, out StringValues values) || values.Count != 1)
            throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
        var value = values[0] ?? string.Empty;
        if (value.Length == 0 || value.Contains(',') || value.Any(character => char.IsControl(character)))
            throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
        return value;
    }

    private static bool TryCanonicalUuid(string value, out Guid parsed)
    {
        parsed = default;
        return Guid.TryParseExact(value, "D", out parsed) && value == parsed.ToString("D");
    }

    private void SetNoStore()
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
    }

    private ObjectResult Unavailable() => StatusCode(
        StatusCodes.Status503ServiceUnavailable,
        new RuntimeEnrollmentApiError("runtime_enrollment_unavailable"));

    private IActionResult TransportError(Exception exception)
    {
        var status = exception is RuntimeTransportException transport
            ? transport.StatusCode
            : StatusCodes.Status400BadRequest;
        return StatusCode(status, new RuntimeEnrollmentApiError(
            status == StatusCodes.Status413PayloadTooLarge ? "payload_too_large"
            : status == StatusCodes.Status415UnsupportedMediaType ? "unsupported_media_type"
            : "invalid_request"));
    }

    private static bool IsTransportFailure(Exception exception) =>
        exception is RuntimeTransportException or InvalidDataException or JsonException or DecoderFallbackException;

    private static string Digest(ReadOnlySpan<byte> body) =>
        Convert.ToHexStringLower(SHA256.HashData(body));

    private sealed class RuntimeTransportException(int statusCode) : Exception
    {
        public int StatusCode { get; } = statusCode;
    }
    /// <summary>
    /// Owns the bounded request buffer, authenticates HTTPS/path/method/body/product and the distinct
    /// transport nonce before semantics, requires AllowRuntimeUpgrade, and returns exact frozen bytes.
    /// Transport authentication failures never create a semantic v2 terminal result.
    /// </summary>
    [HttpPost("/api/internal/v2/runtime-enrollment-authority/generations")]
    public async Task<IActionResult> IssueAuthorityGenerationV2(CancellationToken cancellationToken)
    {
        SetNoStore();
        // Feature-off is a pre-authentication configuration outcome, not an authenticated authority terminal.
        if (_options.Mode != "enabled" || _options.AuthorityGenerationV2.Mode != "enabled")
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new RuntimeEnrollmentApiError("RUNTIME_ENROLLMENT_UNSUPPORTED"));
        try
        {
            const string path = "/api/internal/v2/runtime-enrollment-authority/generations";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowRuntimeUpgrade)
                return AuthorityFailure(StatusCodes.Status403Forbidden, "RUNTIME_ENROLLMENT_DENIED");
            if (!Request.Headers.TryGetValue(AuthorityAttemptHeader, out var attemptValues)
                || attemptValues.Count != 1 || !TryCanonicalUuid(attemptValues[0]!, out var attemptId))
                throw new InvalidDataException("invalid_attempt_id");
            var result = await _enrollments.IssueAuthorityGenerationV2Async(
                principal.ClientId, principal.KeyId, attemptId, exactBody,
                ReadOptionalUniqueHeader(AuthorityRecoveryKeyHeader),
                ReadOptionalUniqueHeader(AuthorityRecoverySignatureHeader), cancellationToken);
            EmitAuthorityDiagnostics(result.Idempotent ? "REA-V2-REPLAYED" : "REA-V2-ACCEPTED");
            Response.StatusCode = result.StatusCode;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (RuntimeEnrollmentException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (Exception exception) when (IsTransportFailure(exception))
        { return AuthorityFailure(exception is RuntimeTransportException transport ? transport.StatusCode : 400,
            "RUNTIME_ENROLLMENT_INTEGRITY_FAILURE"); }
    }

    /// <summary>
    /// Authenticates one exact S2S readback request and returns only the current provider-owned
    /// public authority key-registry snapshot as frozen canonical bytes.
    /// </summary>
    /// <param name="cancellationToken">Caller cancellation propagated without conversion to a provider error.</param>
    /// <returns>Canonical JSON bytes, or the existing closed JSON error envelope with no-store headers.</returns>
    [HttpPost("/api/internal/v2/runtime-enrollment-authority/key-registry-snapshots")]
    [EnableRateLimiting("DistributionS2SAPI")]
    public async Task<IActionResult> ReadAuthorityKeyRegistrySnapshotV2(CancellationToken cancellationToken)
    {
        SetNoStore();
        if (_options.Mode != "enabled" || _options.AuthorityGenerationV2.Mode != "enabled"
            || _keyRegistrySnapshots is null)
            return AuthorityFailure(StatusCodes.Status503ServiceUnavailable, "RUNTIME_ENROLLMENT_UNSUPPORTED");
        try
        {
            const string path = "/api/internal/v2/runtime-enrollment-authority/key-registry-snapshots";
            EnsureExactTarget(path);
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var productId = ExtractUniqueString(exactBody, "productId");
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.AllowRuntimeUpgrade)
                return AuthorityFailure(StatusCodes.Status403Forbidden, "RUNTIME_ENROLLMENT_DENIED");
            var response = await _keyRegistrySnapshots.ReadCurrentAsync(
                principal.ClientId, exactBody, cancellationToken);
            EmitAuthorityDiagnostics("REA-V2-KEY-REGISTRY-CURRENT");
            return File(response, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (RuntimeAuthorityKeyRegistryContractException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            && RuntimeAuthorityKeyRegistrySnapshotService.IsClosedProviderFailure(exception))
        {
            return AuthorityFailure(StatusCodes.Status503ServiceUnavailable,
                "RUNTIME_ENROLLMENT_TEMPORARILY_UNAVAILABLE");
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            var statusCode = exception is RuntimeTransportException transport
                ? transport.StatusCode : StatusCodes.Status400BadRequest;
            var error = statusCode switch
            {
                StatusCodes.Status413PayloadTooLarge => "payload_too_large",
                StatusCodes.Status415UnsupportedMediaType => "unsupported_media_type",
                _ => "RUNTIME_ENROLLMENT_INTEGRITY_FAILURE"
            };
            return AuthorityFailure(statusCode, error);
        }
    }

    /// <summary>Authenticates and prepares exact server-owned recovery payload bytes under the current head lock.</summary>
    [HttpPost("/api/internal/v2/runtime-enrollment-authority/recovery-preparations")]
    public async Task<IActionResult> PrepareAuthorityRecoveryV2(CancellationToken cancellationToken)
    {
        SetNoStore();
        // Feature-off is a pre-authentication configuration outcome, not an authenticated authority terminal.
        if (_options.Mode != "enabled" || _options.AuthorityGenerationV2.Mode != "enabled")
            return StatusCode(503, new RuntimeEnrollmentApiError("RUNTIME_ENROLLMENT_UNSUPPORTED"));
        try
        {
            EnsureExactTarget("/api/internal/v2/runtime-enrollment-authority/recovery-preparations");
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, ExtractUniqueString(exactBody, "productId"), cancellationToken);
            if (!principal.AllowRuntimeUpgrade)
                return AuthorityFailure(StatusCodes.Status403Forbidden, "RUNTIME_ENROLLMENT_DENIED");
            if (!Request.Headers.TryGetValue(AuthorityAttemptHeader, out var attempts)
                || attempts.Count != 1 || !TryCanonicalUuid(attempts[0]!, out var attemptId))
                throw new InvalidDataException("invalid_attempt_id");
            var result = await _enrollments.PrepareAuthorityRecoveryV2Async(
                principal.ClientId, principal.KeyId, attemptId, exactBody, cancellationToken);
            EmitAuthorityDiagnostics("REA-V2-RECOVERY-PREPARED");
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (RuntimeEnrollmentException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (Exception exception) when (IsTransportFailure(exception))
        { return AuthorityFailure(exception is RuntimeTransportException transport ? transport.StatusCode : 400,
            "RUNTIME_ENROLLMENT_INTEGRITY_FAILURE"); }
    }

    /// <summary>Reauthenticates and finalizes one exact signed recovery preparation.</summary>
    [HttpPost("/api/internal/v2/runtime-enrollment-authority/recovery-finalizations")]
    public async Task<IActionResult> FinalizeAuthorityRecoveryV2(CancellationToken cancellationToken)
    {
        SetNoStore();
        // Feature-off is a pre-authentication configuration outcome, not an authenticated authority terminal.
        if (_options.Mode != "enabled" || _options.AuthorityGenerationV2.Mode != "enabled")
            return StatusCode(503, new RuntimeEnrollmentApiError("RUNTIME_ENROLLMENT_UNSUPPORTED"));
        try
        {
            EnsureExactTarget("/api/internal/v2/runtime-enrollment-authority/recovery-finalizations");
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            ValidateJsonStructure(exactBody);
            var principal = await _s2s.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, ExtractUniqueString(exactBody, "productId"), cancellationToken);
            if (!principal.AllowRuntimeUpgrade)
                return AuthorityFailure(StatusCodes.Status403Forbidden, "RUNTIME_ENROLLMENT_DENIED");
            if (!Request.Headers.TryGetValue(AuthorityAttemptHeader, out var attempts)
                || attempts.Count != 1 || !TryCanonicalUuid(attempts[0]!, out var attemptId))
                throw new InvalidDataException("invalid_attempt_id");
            var result = await _enrollments.FinalizeAuthorityRecoveryV2Async(
                principal.ClientId, principal.KeyId, attemptId, exactBody,
                ReadOptionalUniqueHeader(AuthorityRecoveryPreparationHeader)
                    ?? throw new InvalidDataException("missing_recovery_preparation"),
                ReadOptionalUniqueHeader(AuthorityRecoveryKeyHeader)
                    ?? throw new InvalidDataException("missing_recovery_key"),
                ReadOptionalUniqueHeader(AuthorityRecoverySignatureHeader)
                    ?? throw new InvalidDataException("missing_recovery_signature"), cancellationToken);
            EmitAuthorityDiagnostics(result.Idempotent ? "REA-V2-REPLAYED" : "REA-V2-ACCEPTED");
            Response.StatusCode = result.StatusCode;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (RuntimeEnrollmentException exception)
        { return AuthorityFailure(exception.StatusCode, exception.ErrorCode); }
        catch (Exception exception) when (IsTransportFailure(exception))
        { return AuthorityFailure(exception is RuntimeTransportException transport ? transport.StatusCode : 400,
            "RUNTIME_ENROLLMENT_INTEGRITY_FAILURE"); }
    }

    /// <summary>
    /// Emits the existing exact request correlation identifier and one closed support code without
    /// logging or transforming any authority identity, credential, signature, or payload dimension.
    /// </summary>
    /// <param name="supportCode">A controller-owned allowlisted support code.</param>
    private void EmitAuthorityDiagnostics(string supportCode)
    {
        Response.Headers[CorrelationHeader] = HttpContext.TraceIdentifier;
        Response.Headers[SupportCodeHeader] = supportCode;
    }

    /// <summary>
    /// Produces one refused terminal diagnostic using only closed status-derived classifications.
    /// The public error remains unchanged; exception text and request-owned values never reach the log.
    /// </summary>
    /// <param name="statusCode">The HTTP status selected by the authenticated transport or authority service.</param>
    /// <param name="publicError">The existing public error code returned without normalization.</param>
    /// <returns>The existing public error response with correlation and support headers.</returns>
    private ObjectResult AuthorityFailure(int statusCode, string publicError)
    {
        var (supportCode, internalCause) = statusCode switch
        {
            StatusCodes.Status401Unauthorized => ("REA-V2-AUTHENTICATION", "TRANSPORT_AUTHENTICATION"),
            StatusCodes.Status403Forbidden => ("REA-V2-AUTHORIZATION", "AUTHORITY_AUTHORIZATION"),
            StatusCodes.Status409Conflict => ("REA-V2-CONFLICT", "REPLAY_OR_HEAD_CONFLICT"),
            StatusCodes.Status410Gone => ("REA-V2-EXPIRED", "AUTHORITY_PROOF_EXPIRED"),
            StatusCodes.Status422UnprocessableEntity => ("REA-V2-INELIGIBLE", "AUTHORITY_POLICY_REFUSAL"),
            StatusCodes.Status429TooManyRequests => ("REA-V2-THROTTLED", "AUTHORITY_THROTTLED"),
            StatusCodes.Status503ServiceUnavailable => ("REA-V2-UNAVAILABLE", "AUTHORITY_UNAVAILABLE"),
            _ => ("REA-V2-INTEGRITY", "REQUEST_INTEGRITY")
        };
        EmitAuthorityDiagnostics(supportCode);
        _logger?.LogWarning(
            "Runtime enrollment authority terminal {TerminalState}; support {SupportCode}; correlation {CorrelationId}; cause {InternalCause}",
            "REFUSED", supportCode, HttpContext.TraceIdentifier, internalCause);
        return StatusCode(statusCode, new RuntimeEnrollmentApiError(publicError));
    }

    /// <summary>Returns an absent or single exact detached header and rejects ambiguous values.</summary>
    private string? ReadOptionalUniqueHeader(string name)
    {
        if (!Request.Headers.TryGetValue(name, out var values)) return null;
        if (values.Count != 1 || string.IsNullOrEmpty(values[0]))
            throw new InvalidDataException("ambiguous_recovery_header");
        return values[0];
    }
}

using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/admin/products/{productId:guid}/approved-binaries")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
public sealed class ApprovedBinariesController : ControllerBase
{
    private readonly AdminSecretAuthenticationService _authentication;
    private readonly ApprovedBinaryService _approvedBinaries;

    public ApprovedBinariesController(
        AdminSecretAuthenticationService authentication,
        ApprovedBinaryService approvedBinaries)
    {
        _authentication = authentication;
        _approvedBinaries = approvedBinaries;
    }

    [HttpPut("{version}")]
    public async Task<IActionResult> Register(
        Guid productId,
        string version,
        [FromBody] RegisterApprovedBinariesRequest? request,
        CancellationToken cancellationToken)
    {
        var authentication = await _authentication.AuthenticateAsync(HttpContext);
        if (!authentication.Authorized)
            return Unauthorized(new { error = "unauthorized" });
        if (authentication.ScopedProductId.HasValue && authentication.ScopedProductId.Value != productId)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "product_scope_forbidden" });

        var artifacts = request?.Artifacts?
            .Select(artifact => new ApprovedBinaryArtifact(artifact.Key ?? string.Empty, artifact.Sha256 ?? string.Empty))
            .ToList();
        var (productExists, result) = await _approvedBinaries.RegisterReleaseBaselineAsync(
            productId,
            version,
            request?.RegistrationId,
            request?.ManifestDigestSha256,
            artifacts,
            cancellationToken);

        if (!productExists)
            return NotFound(new { error = "product_not_found" });
        if (result.Verdict == ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted)
            return BadRequest(new { error = result.ErrorCode });
        if (result.Verdict != ApprovedBinaryVerdict.Approved)
            return Conflict(new { error = result.ErrorCode, verdict = result.Verdict.ToString() });

        var response = BuildResponse(productId, version.Trim(), result);
        return result.Idempotent
            ? Ok(response)
            : Created($"/api/admin/products/{productId:D}/approved-binaries/{Uri.EscapeDataString(version.Trim())}", response);
    }

    [HttpGet("{version}")]
    public async Task<IActionResult> Get(
        Guid productId,
        string version,
        CancellationToken cancellationToken)
    {
        var authentication = await _authentication.AuthenticateAsync(HttpContext);
        if (!authentication.Authorized)
            return Unauthorized(new { error = "unauthorized" });
        if (authentication.ScopedProductId.HasValue && authentication.ScopedProductId.Value != productId)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "product_scope_forbidden" });

        var (productExists, result) = await _approvedBinaries.GetAuthoritativeBaselineAsync(
            productId,
            version,
            cancellationToken);

        if (!productExists)
            return NotFound(new { error = "product_not_found" });
        if (result.Verdict == ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted)
            return BadRequest(new { error = result.ErrorCode });
        if (result.Verdict != ApprovedBinaryVerdict.Approved)
            return Conflict(new { error = result.ErrorCode, verdict = result.Verdict.ToString() });

        return Ok(BuildResponse(productId, version.Trim(), result));
    }

    [HttpPut("{version}/legacy-adoption")]
    public async Task<IActionResult> AdoptLegacyTiaConnect2362(
        Guid productId,
        string version,
        [FromBody] RegisterApprovedBinariesRequest? request,
        CancellationToken cancellationToken)
    {
        var authentication = await _authentication.AuthenticateAsync(HttpContext);
        if (!authentication.Authorized)
            return Unauthorized(new { error = "unauthorized" });
        if (authentication.ScopedProductId.HasValue)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "global_admin_required" });

        var artifacts = request?.Artifacts?
            .Select(artifact => new ApprovedBinaryArtifact(artifact.Key ?? string.Empty, artifact.Sha256 ?? string.Empty))
            .ToList();
        var (productExists, result) = await _approvedBinaries.AdoptTiaConnect2362LegacyBaselineAsync(
            productId,
            version,
            request?.RegistrationId,
            request?.ManifestDigestSha256,
            artifacts,
            cancellationToken);

        if (!productExists)
            return NotFound(new { error = "product_not_found" });
        if (result.Verdict == ApprovedBinaryVerdict.EvidenceInvalidOrUntrusted)
            return BadRequest(new { error = result.ErrorCode });
        if (result.Verdict != ApprovedBinaryVerdict.Approved)
            return Conflict(new { error = result.ErrorCode, verdict = result.Verdict.ToString() });

        var response = BuildResponse(productId, version, result);
        return result.Idempotent ? Ok(response) : Created(
            $"/api/admin/products/{productId:D}/approved-binaries/{Uri.EscapeDataString(version)}",
            response);
    }

    private static object BuildResponse(
        Guid productId,
        string version,
        ApprovedBinaryVerificationResult result) => new
        {
            productId,
            version,
            verdict = result.Verdict.ToString(),
            authoritative = true,
            source = result.Source,
            result.Idempotent,
            registrationId = result.RegistrationId,
            baselineId = result.BaselineId,
            manifestDigestSha256 = result.ManifestDigestSha256,
            baselineDigestSha256 = result.BaselineDigestSha256,
            artifacts = result.Artifacts.Select(artifact => new
            {
                key = artifact.Key,
                sha256 = artifact.Sha256
            })
        };

    public sealed class RegisterApprovedBinariesRequest
    {
        public string? RegistrationId { get; set; }
        public string? ManifestDigestSha256 { get; set; }
        public List<ApprovedBinaryArtifactRequest>? Artifacts { get; set; }
    }

    public sealed class ApprovedBinaryArtifactRequest
    {
        public string? Key { get; set; }
        public string? Sha256 { get; set; }
    }
}

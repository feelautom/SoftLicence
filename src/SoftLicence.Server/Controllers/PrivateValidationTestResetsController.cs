using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/admin/private-validation/test-identity-resets")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
public sealed class PrivateValidationTestResetsController : ControllerBase
{
    private readonly AdminSecretAuthenticationService _authentication;
    private readonly IPrivateValidationTestResetService _resetService;

    public PrivateValidationTestResetsController(
        AdminSecretAuthenticationService authentication,
        IPrivateValidationTestResetService resetService)
    {
        _authentication = authentication;
        _resetService = resetService;
    }

    [HttpPost("validate")]
    public Task<IActionResult> Validate(
        [FromBody] PrivateValidationTestResetRequest? request,
        CancellationToken cancellationToken) =>
        HandleAsync(request, execute: false, cancellationToken);

    [HttpPost("execute")]
    public Task<IActionResult> Execute(
        [FromBody] PrivateValidationTestResetRequest? request,
        CancellationToken cancellationToken) =>
        HandleAsync(request, execute: true, cancellationToken);

    private async Task<IActionResult> HandleAsync(
        PrivateValidationTestResetRequest? request,
        bool execute,
        CancellationToken cancellationToken)
    {
        var authentication = await _authentication.AuthenticateAsync(HttpContext);
        if (!authentication.Authorized)
            return Unauthorized(new { error = "unauthorized" });
        if (request == null)
            return BadRequest(new { error = "invalid_request" });
        if (authentication.ScopedProductId.HasValue)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "global_admin_required" });
        }

        try
        {
            var result = execute
                ? await _resetService.ExecuteAsync(request, cancellationToken)
                : await _resetService.ValidateAsync(request, cancellationToken);
            return Ok(result);
        }
        catch (PrivateValidationTestResetException exception)
        {
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
    }
}

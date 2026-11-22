using Microsoft.AspNetCore.Mvc;

namespace SoftLicence.Server.Controllers
{
    /// <summary>
    /// TKT-004085: response builders for the legitimate refusals that public activation routes used to answer as an
    /// outage (503 <c>authority_unavailable</c>, empty HTTP 500 or "Signature key unreadable"). Anti-piracy refusals do
    /// not go through these helpers and keep their opaque responses.
    /// </summary>
    public partial class ActivationController
    {
        /// <summary>English message of the licence exclusion refusal; clients render their own localized text.</summary>
        internal const string LicenseHardwareExcludedMessage =
            "This computer has been excluded from this license. Use another license, or ask the license owner or support to lift the exclusion.";

        /// <summary>
        /// Answers a <see cref="Services.DistributionOperationException"/> raised by the seat-release or seat-cleanup
        /// authority. A named assignment refusal (<c>assignment_reconciliation_required</c>, <c>seat_assignment_busy</c>)
        /// returns <c>{error, reasonCode, message, correlationId}</c>, sets the activation error headers and, for the busy
        /// code, <c>Retry-After</c>. Every other code keeps the historical body <c>{"error":"code"}</c> unchanged.
        /// </summary>
        /// <param name="exception">The refusal; its bounded reason is returned only for a named code.</param>
        /// <returns>The response with the exception's own status code.</returns>
        private IActionResult DistributionRefusalResult(Services.DistributionOperationException exception)
        {
            if (!Services.AssignmentRefusals.IsNamed(exception.ErrorCode))
                return StatusCode(exception.StatusCode, new { Error = exception.ErrorCode });
            TagActivationFailure(exception.ErrorCode);
            Services.AssignmentRefusals.ApplyRetryAfter(Response, exception.ErrorCode);
            return StatusCode(exception.StatusCode, new
            {
                Error = exception.ErrorCode,
                exception.ReasonCode,
                Message = Services.AssignmentRefusals.MessageFor(exception.ErrorCode),
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        /// <summary>
        /// Answers an assignment-trigger refusal raised while an activation saved or committed its transaction. The
        /// database refused the statement or the commit, so nothing was written; the client receives the named refusal
        /// instead of the misleading "Signature key unreadable" HTTP 500.
        /// </summary>
        /// <param name="exception">The original database exception, logged with its stack.</param>
        /// <param name="refusal">The named refusal translated from it.</param>
        /// <param name="phase">Bounded activation phase written to the log.</param>
        /// <returns>The named refusal response.</returns>
        private IActionResult AssignmentTriggerRefusal(
            Exception exception, Services.DistributionOperationException refusal, string phase)
        {
            _logger.LogWarning(exception,
                "ASSIGNMENT_REFUSAL Phase={Phase} Code={Code} Reason={Reason}", phase, refusal.ErrorCode, refusal.ReasonCode);
            return DistributionRefusalResult(refusal);
        }

        /// <summary>
        /// Builds the 403 refusal for a machine excluded from the licence (TKT-002041). The code is the public
        /// <c>license_hardware_excluded</c> already returned by the Runtime routes; before TKT-004085 the activation
        /// routes let the exception escape and the client received an empty HTTP 500.
        /// </summary>
        /// <returns>The <c>ActivationJsonFailure</c> body with HTTP 403.</returns>
        private IActionResult LicenseHardwareExcludedFailure() =>
            ActivationJsonFailure(
                Services.LicenseHardwareExclusionChecker.PublicErrorCode,
                LicenseHardwareExcludedMessage,
                StatusCodes.Status403Forbidden);

        /// <summary>Returns whether the exception is the licence exclusion refusal of <see cref="Services.LicenseHardwareExclusionChecker"/>.</summary>
        /// <param name="exception">The caught distribution refusal.</param>
        private static bool IsLicenseHardwareExclusion(Services.DistributionOperationException exception) =>
            string.Equals(exception.ErrorCode, Services.LicenseHardwareExclusionChecker.PublicErrorCode, StringComparison.Ordinal);
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using Microsoft.Extensions.Localization;

namespace SoftLicence.Server.Controllers
{
    /// <summary>Serves legacy licence issuance and status while enforcing product, hardware and commercial authority.</summary>
    [ApiController]
    [Route("api/activation")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("PublicAPI")]
    public partial class ActivationController : ControllerBase
    {
        private const string ActivationErrorCodeHeader = "X-SoftLicence-Error-Code";
        private const string ActivationCorrelationIdHeader = "X-SoftLicence-Correlation-Id";
        private const string ActivationErrorContractVersionHeader = "X-SoftLicence-Error-Contract";
        private static readonly TimeSpan AnonymousDeactivationGuardWindow = TimeSpan.FromMinutes(5);
        /// <summary>History source recorded when activation replaces the held identifier (TKT-001277 lot 2b).</summary>
        private const string HardwareIdSwitchSource = "hardware_id_switch";

        private readonly LicenseDbContext _db;
        private readonly ILogger<ActivationController> _logger;
        private readonly Services.EncryptionService _encryption;
        private readonly Services.EmailService _mailer;
        private readonly Services.TelemetryService _telemetry;
        private readonly Services.GeoIpService _geoIp;
        private readonly IConfiguration _config;
        private readonly IStringLocalizer<SharedResource> _localizer;
        private readonly Services.NotificationService _notifier;
        private readonly Services.SecurityService _security;
        private readonly Services.FingerprintService _fingerprint;
        private readonly Services.SeatCleanupService _seatCleanup;
        private readonly Services.HwidReuseAlertService _hwidReuseAlerts;
        private readonly Services.ISignedLicenseFileService _signedLicenseFiles;
        private readonly Services.IHardwareAuthorityAliasResolver _hardwareAuthorityAliases;
        private readonly Services.MachineIdentityObservationService _machineIdentityObservations;
        /// <summary>Stops bounded history finalization when the application shuts down, independently of HTTP cancellation.</summary>
        private readonly CancellationToken _legacyApplicationStopping;

        /// <summary>
        /// Creates the public activation API with centralized signing, ban enforcement, and authenticated hardware-authority resolution.
        /// </summary>
        /// <param name="db">Scoped licensing database context.</param>
        /// <param name="logger">Structured controller logger.</param>
        /// <param name="encryption">Legacy encryption service retained by activation flows outside centralized signing.</param>
        /// <param name="mailer">Customer reset email service.</param>
        /// <param name="telemetry">Activation telemetry service.</param>
        /// <param name="geoIp">Remote address enrichment service.</param>
        /// <param name="config">Server configuration.</param>
        /// <param name="localizer">Customer-facing response localizer.</param>
        /// <param name="notifier">Operational notification service.</param>
        /// <param name="security">Submitted and canonical hardware ban authority.</param>
        /// <param name="fingerprint">Optional component fingerprint persistence service.</param>
        /// <param name="seatCleanup">Cross-license seat cleanup service.</param>
        /// <param name="hwidReuseAlerts">Hardware reuse alert service.</param>
        /// <param name="signedLicenseFiles">Central signer used by activation and status responses.</param>
        /// <param name="hardwareAuthorityAliases">Fail-closed resolver for server-authenticated legacy aliases.</param>
        /// <param name="machineIdentityObservations">UUID machine-identity rule and evidence store for UUID-aware clients (TKT-001277).</param>
        /// <param name="applicationLifetime">Host shutdown signal for bounded decision persistence; isolated tests may omit a host.</param>
        public ActivationController(
            LicenseDbContext db,
            ILogger<ActivationController> logger,
            Services.EncryptionService encryption,
            Services.EmailService mailer,
            Services.TelemetryService telemetry,
            Services.GeoIpService geoIp,
            IConfiguration config,
            IStringLocalizer<SharedResource> localizer,
            Services.NotificationService notifier,
            Services.SecurityService security,
            Services.FingerprintService fingerprint,
            Services.SeatCleanupService seatCleanup,
            Services.HwidReuseAlertService hwidReuseAlerts,
            Services.ISignedLicenseFileService signedLicenseFiles,
            Services.IHardwareAuthorityAliasResolver hardwareAuthorityAliases,
            Services.MachineIdentityObservationService machineIdentityObservations,
            IHostApplicationLifetime? applicationLifetime = null)
        {
            _db = db;
            _logger = logger;
            _encryption = encryption;
            _mailer = mailer;
            _telemetry = telemetry;
            _geoIp = geoIp;
            _config = config;
            _localizer = localizer;
            _notifier = notifier;
            _security = security;
            _fingerprint = fingerprint;
            _seatCleanup = seatCleanup;
            _hwidReuseAlerts = hwidReuseAlerts;
            _signedLicenseFiles = signedLicenseFiles;
            _hardwareAuthorityAliases = hardwareAuthorityAliases;
            _machineIdentityObservations = machineIdentityObservations;
            _legacyApplicationStopping = applicationLifetime?.ApplicationStopping ?? CancellationToken.None;
        }

        /// <summary>
        /// TEMP-FAIL-OPEN(TKT-001262): temporary compatibility only. Strict Runtime-graph authority
        /// is the intended behavior, but the current code or persisted graph is known to be buggy;
        /// The product owner requested logging instead of refusing legitimate clients. Every logged case must
        /// be analysed and corrected, then this branch must return to the strict decision and this
        /// marker must be removed. Cross-authority aliases remain closed, active bans stay enforced,
        /// and the warning is deliberately identifier-free.
        /// </summary>
        private async Task<string?> TryResolveLoggedCompatibilityAliasAsync(
            License license,
            Services.HardwareAuthorityResolution resolution)
        {
            if (resolution.RefusalReason != Services.HardwareAuthorityRefusalReason.AuthorityGraphDiverged
                || resolution.AliasId is not Guid aliasId
                || resolution.LicenseSeatId is not Guid seatId
                || !license.IsActive
                || license.RevokedAt != null
                || (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= DateTime.UtcNow))
                return null;

            var candidate = await _db.HardwareAuthorityAliases.AsNoTracking()
                .Where(alias => alias.Id == aliasId
                    && alias.IsActive && alias.DisabledAtUtc == null
                    && alias.ProductId == license.ProductId && alias.LicenseId == license.Id
                    && alias.LicenseSeatId == seatId
                    && alias.LicenseSeat!.IsActive
                    && alias.LicenseSeat.LicenseId == license.Id
                    && alias.Binding!.ProductId == license.ProductId
                    && alias.Binding.LicenseId == license.Id
                    && alias.Binding.LicenseSeatId == seatId
                    && alias.RuntimeEnrollment!.ProductId == license.ProductId
                    && alias.RuntimeEnrollment.LicenseId == license.Id
                    && alias.RuntimeEnrollment.LicenseSeatId == seatId)
                .Select(alias => new
                {
                    SeatHardwareId = alias.LicenseSeat!.HardwareId,
                    BindingId = alias.Binding!.Id
                })
                .SingleOrDefaultAsync(HttpContext.RequestAborted);
            if (candidate == null
                || !Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(candidate.SeatHardwareId))
                return null;

            var binding = await _db.DistributionInstallationBindings.AsNoTracking()
                .SingleAsync(item => item.Id == candidate.BindingId, HttpContext.RequestAborted);
            var enrollmentRows = await _db.RuntimeEnrollments.AsNoTracking()
                .Where(enrollment => enrollment.BindingId == candidate.BindingId)
                .ToListAsync(HttpContext.RequestAborted);
            var now = DateTime.UtcNow;
            var coherentSeatRelease = Services.RuntimeAuthorityTransitionResolver.IsCoherentSeatRelease(
                binding, enrollmentRows, now);
            var enrollments = enrollmentRows
                .Select(enrollment => new Services.RuntimeAuthorityEnrollmentSnapshot(
                    enrollment.State,
                    enrollment.InvalidationReason,
                    enrollment.ChallengeExpiresAtUtc,
                    enrollment.ChallengeConsumedAtUtc,
                    enrollment.ActivatedAtUtc,
                    enrollment.InvalidatedAtUtc))
                .ToList();
            var enrollmentDecision = Services.RuntimeAuthorityTransitionResolver.ClassifyEnrollments(
                enrollments, now);

            _logger.LogWarning(
                "TEMP-FAIL-OPEN(TKT-001262) Hardware authority compatibility fail-open used for alias {AliasId}, product {ProductId}, licence {LicenseId}, seat {LicenseSeatId}, binding {BindingId}; reason {RefusalReason}, binding state {BindingState}, binding invalidation {BindingInvalidationReason}, enrollment count {EnrollmentCount}, enrollment states {EnrollmentStates}, enrollment invalidations {EnrollmentInvalidationReasons}, coherent seat release {CoherentSeatRelease}, enrollment decision {EnrollmentDecision}.",
                aliasId,
                license.ProductId,
                license.Id,
                seatId,
                binding.Id,
                resolution.RefusalReason,
                binding.State,
                binding.InvalidationReason ?? "none",
                enrollmentRows.Count,
                string.Join(',', enrollmentRows.Select(item => item.State).OrderBy(value => value, StringComparer.Ordinal)),
                string.Join(',', enrollmentRows.Select(item => item.InvalidationReason ?? "none").OrderBy(value => value, StringComparer.Ordinal)),
                coherentSeatRelease,
                enrollmentDecision);
            return candidate.SeatHardwareId;
        }

        public class ActivationRequest
        {
            public required string LicenseKey { get; set; }
            public required string HardwareId { get; set; }
            // LEGACY-EXPIRY(TKT-001430, 2026-12-31): identifier switch from the pre-UUID identifier (TKT-001277 lot 2b).
            // Remove by 31/12/2026 once every active seat carries a UUID identifier: property, validation, call and
            // DetachPreviousHardwareIdAsync.
            /// <summary>
            /// Gets or sets the identifier of the licence file the client currently holds (TKT-001277 lot 2b). When it is
            /// an active seat of this licence and differs from <see cref="HardwareId"/>, activation atomically detaches it
            /// and attaches <see cref="HardwareId"/>, consuming one daily seat change.
            /// </summary>
            public string? PreviousHardwareId { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; } // Identifiant unique du produit
            public string? AppVersion { get; set; } // Nouvelle version client
            public string? CustomerEmail { get; set; }
            public string? CustomerName { get; set; }
            public Dictionary<string, string>? ExtraParams { get; set; } // Legacy input: any non-null presence is rejected by public activation.
            // LEGACY-EXPIRY(TKT-001430, 2026-12-31): ComponentFingerprints and HardwareIdV2* are sent only by pre-2.0 SDKs.
            // Remove these request fields and AddHardwareIdV2Observation by 31/12/2026.
            public Dictionary<string, string>? ComponentFingerprints { get; set; }
            public string? HardwareIdV2 { get; set; }
            public bool? HardwareIdV2Differs { get; set; }
            public string? HardwareIdAlgorithm { get; set; }
            public string? HardwareIdV2Algorithm { get; set; }
            public string? SdkVersion { get; set; }
            public string? BuildHash { get; set; }
            /// <summary>Gets or sets the raw system UUID sent by UUID-aware clients (TKT-001277); <c>null</c> for legacy clients.</summary>
            public string? SystemUuid { get; set; }
            /// <summary>Gets or sets current machine observations for UUID validation and restricted-offer policy; historical public observations never grant authority.</summary>
            public JsonElement? MachineEvidence { get; set; }
            /// <summary>
            /// Gets or sets the single-use control token pair of a guard-aware managed check (TKT-003615), or
            /// <see langword="null"/> for installed versions and the native heartbeat, whose answer stays unchanged.
            /// Read only by <see cref="CheckStatus"/>; ignored by activation.
            /// </summary>
            public Services.CloneGuard.CloneGuardCheckRequest? CloneGuard { get; set; }
        }

        public class TrialRequest
        {
            public required string HardwareId { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; } // Identifiant unique du produit
            public required string TypeSlug { get; set; } // ex: "TRIAL"
            public string? AppVersion { get; set; }
            public string? CustomerEmail { get; set; }
            public string? CustomerName { get; set; }
            // LEGACY-EXPIRY(TKT-001430, 2026-12-31): ComponentFingerprints and HardwareIdV2* are sent only by pre-2.0 SDKs.
            // Remove these request fields and AddHardwareIdV2Observation by 31/12/2026.
            public Dictionary<string, string>? ComponentFingerprints { get; set; }
            public string? HardwareIdV2 { get; set; }
            public bool? HardwareIdV2Differs { get; set; }
            public string? HardwareIdAlgorithm { get; set; }
            public string? HardwareIdV2Algorithm { get; set; }
            public string? SdkVersion { get; set; }
            public string? BuildHash { get; set; }
            /// <summary>Gets or sets the raw system UUID sent by UUID-aware clients (TKT-001277); <c>null</c> for legacy clients.</summary>
            public string? SystemUuid { get; set; }
            /// <summary>Gets or sets current machine observations for UUID validation and restricted-offer policy; historical public observations never grant authority.</summary>
            public JsonElement? MachineEvidence { get; set; }
        }

        private async Task<Product?> FindProductAsync(string name, string? id)
        {
            // 1. Recherche par ID si fourni et valide
            if (!string.IsNullOrEmpty(id) && Guid.TryParse(id, out var appId))
            {
                var p = await _db.Products.FirstOrDefaultAsync(p => p.Id == appId);
                if (p != null) return p;
            }

            // 2. Repli sur le nom
            return await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == name.ToLower());
        }

        private void TagLog(ActivationRequest req, string endpoint)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            if (!string.IsNullOrEmpty(req.AppId)) HttpContext.Items["AppId"] = req.AppId;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey.Trim().ToUpper();
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = endpoint;
            HttpContext.Items[LogKeys.Version] = req.AppVersion ?? "Unknown";
        }

        private void TagLog(TrialRequest req, string endpoint)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            if (!string.IsNullOrEmpty(req.AppId)) HttpContext.Items["AppId"] = req.AppId;
            HttpContext.Items[LogKeys.LicenseKey] = "AUTO-TRIAL";
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = endpoint;
            HttpContext.Items[LogKeys.Version] = req.AppVersion ?? "Unknown";
        }

        private void TagActivationFailure(string resultStatus)
        {
            HttpContext.Items[LogKeys.ResultStatusOverride] = resultStatus;
            Response.Headers[ActivationErrorCodeHeader] = resultStatus;
            Response.Headers[ActivationCorrelationIdHeader] = HttpContext.TraceIdentifier;
            Response.Headers[ActivationErrorContractVersionHeader] = "1";
        }

        // LEGACY-EXPIRY(TKT-001430, 2026-12-31): pre-UUID to UUID identifier switch. Remove by 31/12/2026 (see TKT-001430).
        /// <summary>
        /// Detaches the seat of the identifier the client previously held so the new identifier can take it
        /// (TKT-001277 lot 2b). Runs inside the activation transaction, after its savepoint: a later refusal of the
        /// same activation rolls the detachment back, so the licence never ends without a seat.
        /// </summary>
        /// <param name="license">Licence loaded with its seats by the activation.</param>
        /// <param name="previousHardwareId">Canonical identifier sent by the client from its current licence file.</param>
        /// <param name="newHardwareId">Canonical identifier being attached.</param>
        /// <param name="cleanKey">Normalized licence key, for logs.</param>
        /// <returns>
        /// <c>null</c> to continue the activation (detached, or nothing to detach); otherwise the refusal response
        /// when the daily hardware quota refuses the new identifier (TKT-003751) or the release graph is unsafe.
        /// </returns>
        /// <remarks>
        /// The previous identifier is used only when it is an active seat of this exact licence and differs from the
        /// new one; any other value is ignored and the ordinary seat-limit rule applies. The detachment is recorded as
        /// an uncounted <c>UNLINKED_API</c> history row and reuses the release authority of
        /// <c>/api/activation/deactivate</c> so the commercial assignment ends exactly as for a manual detachment.
        /// <see cref="Services.SeatChangeQuota"/> counts the arrival of the key on the new identifier, checked here
        /// before anything is detached. The anonymous five-minute guard of that endpoint does not apply: the caller
        /// proves the licence key and the held identifier, and the quota bounds the number of identifiers per day.
        /// </remarks>
        private async Task<IActionResult?> DetachPreviousHardwareIdAsync(
            License license, string previousHardwareId, string newHardwareId, string cleanKey)
        {
            if (string.Equals(previousHardwareId, newHardwareId, StringComparison.Ordinal))
                return null;

            var previousSeat = license.Seats?.FirstOrDefault(seat => seat.IsActive
                && string.Equals(seat.HardwareId, previousHardwareId, StringComparison.Ordinal));
            if (previousSeat == null)
            {
                _logger.LogWarning(
                    "HARDWARE_ID_SWITCH_IGNORED licence {LicenseId}: previous identifier {PreviousHardwareId} is not an active seat.",
                    license.Id, previousHardwareId);
                return null;
            }

            Services.SeatRuntimeReleaseAuthority.SeatReleaseScope releaseScope;
            try
            {
                releaseScope = await Services.SeatRuntimeReleaseAuthority.PrepareAsync(
                    _db, license.ProductId, license, [previousSeat], DateTime.UtcNow, HttpContext.RequestAborted);
            }
            catch (Services.DistributionOperationException exception)
            {
                TagActivationFailure("HARDWARE_ID_SWITCH_UNAVAILABLE");
                return DistributionRefusalResult(exception);
            }
            var now = releaseScope.ObservedAtUtc;

            // TKT-003751: the daily hardware quota limits the arrival on the new identifier, never the
            // release of the previous one. Refuse that arrival here, before detaching, so a refusal leaves
            // the previous seat exactly as it was (a quota refusal never blocks the licence).
            if (await Services.SeatChangeQuota.IsActivationRefusedAsync(
                    _db, license, newHardwareId, now, HttpContext.RequestAborted))
            {
                var limit = Services.SeatChangeQuota.GetDailyLimit(license);
                _logger.LogWarning(
                    "HARDWARE_ID_SWITCH_REFUSED licence {LicenseId}: daily hardware limit reached ({Max}/day) for key '{LicenseKey}'.",
                    license.Id, limit, cleanKey);
                TagActivationFailure("MAX_DAILY_ACTIVATIONS_REACHED");
                return BadRequest(string.Format(_localizer["Api_MaxDailyActivationsReached"].Value, limit));
            }

            previousSeat.IsActive = false;
            previousSeat.UnlinkedAt = now;
            SyncLegacyHardwareStateFromSeats(license);
            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.UnlinkedApi,
                Details = string.Format(_localizer["Licenses_Action_UnlinkedApi"].Value, previousHardwareId, HardwareIdSwitchSource),
                PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });

            try
            {
                await Services.SeatRuntimeReleaseAuthority.CompleteAsync(
                    _db, releaseScope, [previousSeat], HttpContext.RequestAborted);
            }
            catch (Services.DistributionOperationException exception)
            {
                TagActivationFailure("HARDWARE_ID_SWITCH_UNAVAILABLE");
                return DistributionRefusalResult(exception);
            }

            _logger.LogInformation(
                "HARDWARE_ID_SWITCH licence {LicenseId}: {PreviousHardwareId} detached, {NewHardwareId} attaching.",
                license.Id, previousHardwareId, newHardwareId);
            return null;
        }

        /// <summary>Builds the localized "device refused" message carrying only the support code (TKT-001277).</summary>
        /// <param name="identity">A refused machine-identity outcome.</param>
        /// <returns>For example "Appareil refusé (code AR-04)."; the refusal reason itself is never exposed.</returns>
        private string DeviceRefusedMessage(Services.MachineIdentityObservationOutcome identity) =>
            string.Format(_localizer["Api_DeviceRefused"].Value, identity.SupportCode);

        private IActionResult ActivationJsonFailure(string errorCode, string errorMessage, int statusCode = StatusCodes.Status200OK)
        {
            TagActivationFailure(errorCode);
            var payload = new
            {
                isSuccess = false,
                errorCode,
                message = errorMessage,
                // Keep the historical property until a separately announced breaking contract version.
                errorMessage,
                correlationId = HttpContext.TraceIdentifier,
                contractVersion = 1
            };
            return statusCode == StatusCodes.Status200OK ? Ok(payload) : StatusCode(statusCode, payload);
        }

        /// <summary>Generic English refusal message; the client renders its own text from the closed code.</summary>
        internal const string KeyActivationDisabledMessage =
            "Key activation is disabled for this license. Activate this device through the publisher's sign-in.";

        /// <summary>Builds the closed 409 <c>key_activation_disabled</c> refusal (TKT-002475).</summary>
        private IActionResult KeyActivationDisabledFailure() =>
            ActivationJsonFailure(
                Services.LicenseKeyActivationChecker.RefusalCode,
                KeyActivationDisabledMessage,
                StatusCodes.Status409Conflict);

        /// <summary>
        /// Returns whether a trial path would admit a new seat on a licence whose key activation is disabled:
        /// the setting is posed and the machine holds no active seat on that licence (TKT-002475).
        /// </summary>
        /// <param name="licenseId">The existing licence found for the machine.</param>
        /// <param name="hardwareId">The exact requesting hardware identifier.</param>
        private async Task<bool> KeyActivationRefusesNewSeatAsync(Guid licenseId, string hardwareId) =>
            await Services.LicenseKeyActivationChecker.IsDisabledAsync(_db, licenseId, HttpContext.RequestAborted)
            && !await _db.LicenseSeats.AnyAsync(
                seat => seat.LicenseId == licenseId && seat.HardwareId == hardwareId && seat.IsActive,
                HttpContext.RequestAborted);

        /// <summary>
        /// Rejects a primary hardware identity that violates the exact uppercase ASCII hexadecimal wire contract.
        /// The value is never normalized because doing so could turn attacker-controlled input into a known alias.
        /// </summary>
        /// <returns>A typed bad-request response emitted before any alias, ban, quota, fingerprint, or seat decision.</returns>
        private IActionResult RejectInvalidPrimaryHardwareId()
        {
            TagActivationFailure("INVALID_HARDWARE_ID");
            return BadRequest(new
            {
                error = "invalid_hardware_id",
                message = "HardwareId must contain exactly 16 uppercase ASCII hexadecimal characters."
            });
        }

        private static Dictionary<string, string> BuildFeatures(IEnumerable<LicenseTypeCustomParam>? customParams)
            => Services.SignedLicenseFileService.BuildFeatures(customParams);

        private static void SyncLegacyHardwareStateFromSeats(License license)
        {
            var activeSeat = license.Seats
                .Where(s => s.IsActive)
                .OrderByDescending(s => s.LastCheckInAt)
                .ThenByDescending(s => s.FirstActivatedAt)
                .FirstOrDefault();

            license.HardwareId = activeSeat?.HardwareId;
            license.ActivationDate = activeSeat?.FirstActivatedAt;

            if (activeSeat == null)
                license.RecoveryCount = 0;
        }

        /// <summary>
        /// Maps anonymous client hints to the persisted audit vocabulary. Portal is deliberately
        /// not a public authority and therefore collapses to the fail-closed unknown value.
        /// </summary>
        private static string NormalizeDeactivationSource(string? source, string? deactivationSource)
        {
            var raw = string.IsNullOrWhiteSpace(source) ? deactivationSource : source;
            if (string.IsNullOrWhiteSpace(raw))
                return "legacy_unknown";

            return raw.Trim().ToLowerInvariant() switch
            {
                "settings_button" or "settings" or "settings-button" => "settings_button",
                "uninstall" or "uninstaller" => "uninstall",
                "admin" => "admin",
                "legacy_unknown" => "legacy_unknown",
                "unknown" => "unknown",
                _ => "unknown"
            };
        }

        /// <summary>
        /// Determines whether a canonical audited client source may bypass the five-minute
        /// anonymous-deactivation guard. Only the documented settings and uninstall interactions
        /// remain trusted; provider portal authority is available exclusively on the internal S2S route.
        /// </summary>
        private static bool IsTrustedImmediateDeactivationSource(string source)
        {
            return source is "settings_button" or "uninstall";
        }

        private static void ApplyPluginMetadataFromReference(LicenseModel model)
            => Services.SignedLicenseFileService.ApplyPluginMetadataFromReference(model);

        private static bool IsValidEmailSyntax(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            return Regex.IsMatch(email.Trim(), @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase);
        }

        private static bool HasValidMxRecord(string email)
        {
            try
            {
                var domain = email.Trim().Split('@').LastOrDefault();
                if (string.IsNullOrEmpty(domain)) return false;
                var hostEntry = Dns.GetHostEntry(domain);
                return hostEntry.AddressList.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool EnforcesSingleUsePerHardwareId(LicenseType? type)
        {
            return type?.EnforceSingleUsePerHardwareId == true;
        }

        private static bool HasHardwareIdV2Observation(string? hardwareIdV2)
        {
            return !string.IsNullOrWhiteSpace(hardwareIdV2);
        }

        // LEGACY-EXPIRY(TKT-001430, 2026-12-31): observation of the pre-2.0 HWID V2 fields. Remove the three overloads by 31/12/2026.
        private void AddHardwareIdV2Observation(License license, Product product, string endpoint, string hardwareId, string? hardwareIdV2, bool? hardwareIdV2Differs, string? appVersion, string? sdkVersion, string? buildHash, string? hardwareIdAlgorithm, string? hardwareIdV2Algorithm)
        {
            if (!HasHardwareIdV2Observation(hardwareIdV2))
            {
                return;
            }

            var activeSeat = license.Seats?
                .Where(s => s.IsActive && string.Equals(s.HardwareId, hardwareId, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(s => s.LastCheckInAt)
                .FirstOrDefault();

            var details = JsonSerializer.Serialize(new
            {
                endpoint,
                productId = product.Id,
                productName = product.Name,
                licenseId = license.Id,
                seatId = activeSeat?.Id,
                legacyHardwareId = hardwareId,
                hardwareIdV2 = hardwareIdV2!.Trim(),
                hardwareIdV2Differs = hardwareIdV2Differs ?? !string.Equals(hardwareId, hardwareIdV2, StringComparison.OrdinalIgnoreCase),
                appVersion,
                sdkVersion,
                buildHash,
                hardwareIdAlgorithm,
                hardwareIdV2Algorithm,
                observedAtUtc = DateTime.UtcNow
            });

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.HardwareIdV2Observed,
                Details = details,
                PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });
        }

        private void AddHardwareIdV2Observation(License license, Product product, string endpoint, ActivationRequest req)
        {
            AddHardwareIdV2Observation(license, product, endpoint, req.HardwareId, req.HardwareIdV2, req.HardwareIdV2Differs, req.AppVersion, req.SdkVersion, req.BuildHash, req.HardwareIdAlgorithm, req.HardwareIdV2Algorithm);
        }

        private void AddHardwareIdV2Observation(License license, Product product, string endpoint, TrialRequest req)
        {
            AddHardwareIdV2Observation(license, product, endpoint, req.HardwareId, req.HardwareIdV2, req.HardwareIdV2Differs, req.AppVersion, req.SdkVersion, req.BuildHash, req.HardwareIdAlgorithm, req.HardwareIdV2Algorithm);
        }

        private async Task<bool> HasRecentHardwareIdV2ObservationAsync(Guid licenseId, string legacyHardwareId, string hardwareIdV2)
        {
            var cutoff = DateTime.UtcNow.AddHours(-24);
            var stableHardwareId = hardwareIdV2.Trim();

            return await _db.LicenseHistories.AnyAsync(h =>
                h.LicenseId == licenseId
                && h.Action == HistoryActions.HardwareIdV2Observed
                && h.Timestamp >= cutoff
                && h.Details != null
                && h.Details.Contains(legacyHardwareId)
                && h.Details.Contains(stableHardwareId));
        }

        private static bool DisablesNewActivations(LicenseType? type)
        {
            return type?.DisableNewActivations == true;
        }

        private async Task<bool> HasConsumedLicenseTypeOnHardwareAsync(
            Guid productId,
            Guid licenseTypeId,
            string hardwareId,
            Guid? currentLicenseId = null)
        {
            return await _db.Licenses
                .AsNoTracking()
                .Where(l => l.ProductId == productId
                    && l.LicenseTypeId == licenseTypeId
                    && (!currentLicenseId.HasValue || l.Id != currentLicenseId.Value)
                    && (l.HardwareId == hardwareId
                        || l.Seats.Any(s => s.HardwareId == hardwareId)))
                .AnyAsync();
        }

        private async Task<IActionResult?> RejectIfSingleUseHardwareAlreadyConsumedAsync(
            Guid productId,
            LicenseType? type,
            string hardwareId,
            Guid? currentLicenseId = null)
        {
            if (!EnforcesSingleUsePerHardwareId(type))
                return null;

            if (!await HasConsumedLicenseTypeOnHardwareAsync(productId, type!.Id, hardwareId, currentLicenseId))
                return null;

            TagActivationFailure("FREEMIUM_HWID_ALREADY_CONSUMED");
            _logger.LogWarning(
                "Activation refused: hardware has already consumed license type {LicenseTypeId} for product {ProductId}. CurrentLicenseId={CurrentLicenseId}",
                type.Id,
                productId,
                currentLicenseId);

            return BadRequest("Freemium access has already been used on this machine.");
        }

        /// <summary>Public refusal code returned when an anonymous trial route targets a type that is not opted in.</summary>
        internal const string PublicTrialNotAllowedCode = "LICENSE_TYPE_PUBLIC_TRIAL_NOT_ALLOWED";

        /// <summary>
        /// Refuses, before any write, an anonymous public trial route that would create or renew rights for a type
        /// whose <see cref="LicenseType.AllowPublicTrial"/> is false (TKT-002466). The decision reads only the stored
        /// per-type setting: no slug, product or commercial rule is evaluated here.
        /// </summary>
        /// <param name="type">The resolved license type; a missing type is refused.</param>
        /// <returns><c>null</c> when the type is opted in, otherwise the typed activation failure.</returns>
        private IActionResult? RejectIfPublicTrialNotAllowed(LicenseType? type)
        {
            if (type?.AllowPublicTrial == true)
                return null;

            _logger.LogWarning(
                "Public trial refused: license type {LicenseTypeSlug} ({LicenseTypeId}) is not enabled for public trials.",
                type?.Slug,
                type?.Id);

            return ActivationJsonFailure(PublicTrialNotAllowedCode, "This license type is not available as a public trial.");
        }

        private IActionResult? RejectIfNewActivationsDisabled(LicenseType? type)
        {
            if (!DisablesNewActivations(type))
                return null;

            TagActivationFailure("LICENSE_TYPE_NEW_ACTIVATIONS_DISABLED");
            _logger.LogWarning(
                "Activation refused: new activations are disabled for license type {LicenseTypeSlug} ({LicenseTypeId}).",
                type?.Slug,
                type?.Id);

            return BadRequest("New activations are no longer available for this license type.");
        }

        /// <summary>
        /// Retourne tous les IDs de la hiérarchie produit (racine + enfants + petits-enfants, max 3 niveaux).
        /// </summary>
        private async Task<List<Guid>> GetProductHierarchyIds(Guid rootProductId)
        {
            var ids = new List<Guid> { rootProductId };
            var childIds = await _db.Products
                .Where(p => p.ParentProductId == rootProductId)
                .Select(p => p.Id).ToListAsync();
            ids.AddRange(childIds);
            if (childIds.Count > 0)
            {
                var grandChildIds = await _db.Products
                    .Where(p => p.ParentProductId != null && childIds.Contains(p.ParentProductId.Value))
                    .Select(p => p.Id).ToListAsync();
                ids.AddRange(grandChildIds);
            }
            return ids;
        }

        private bool IsVersionAllowed(string? clientVersion, string allowedMask)
        {
            if (string.IsNullOrEmpty(allowedMask) || allowedMask == "*") return true;
            if (string.IsNullOrEmpty(clientVersion)) return false;

            // Logique simple de préfixe (ex: "1.*" autorise "1.0", "1.2.3")
            if (allowedMask.EndsWith(".*"))
            {
                var prefix = allowedMask.Substring(0, allowedMask.Length - 1); // ex: "1."
                return clientVersion.StartsWith(prefix);
            }

            // Correspondance exacte
            return clientVersion == allowedMask;
        }

        private static bool IsVersionBelow(string? current, string? minimum)
        {
            if (string.IsNullOrWhiteSpace(current) || string.IsNullOrWhiteSpace(minimum))
                return false;

            if (Version.TryParse(current, out var cur) && Version.TryParse(minimum, out var min))
                return cur < min;

            return string.Compare(current, minimum, StringComparison.Ordinal) < 0;
        }

        /// <summary>Issues or reuses a trial licence using existing hardware-lock rules. Creating, renewing or returning a licence requires the requested type's AllowPublicTrial opt-in (TKT-002466); a held licence is returned only when it is of that type and not of a paid nature, a current licence of another type is refused, and the stored customer e-mail and name are never replaced (TKT-002468). The reserved paid-pass type is always refused. A configured TIAConnect minimum requires an eligible current declaration before renewal, seat mutation or signing.</summary>
        /// <remarks>New public trials are FREE; restricted existing rights require current physical evidence, while PAID/UNKNOWN recoveries remain exempt. Machine refusals issue no rights and revoke nothing. Pre-identity refusals are not attributed to a claimed licence. Existing-licence refusal history commits after the business savepoint is rolled back; accepted history shares the existing commit after successful signing. Product-scope ownership changes acquire global and item2 authority before hardware or seat rows, end losing assignments without changing Runtime identity, and roll back with signing failure. History faults use existing technical failure handling. The created or returned seat records the PC display name from MachineEvidence through Services.SeatMachineName (TKT-003404), never erasing a stored name.</remarks>
        [HttpPost("trial")]
        public async Task<IActionResult> GetTrial([FromBody] TrialRequest req)
        {
            TagLog(req, "TRIAL_AUTO");

            var hwidBanned = await _security.IsHardwareIdBannedAsync(req.HardwareId);
            var compBanned = false;
            if (!hwidBanned && req.ComponentFingerprints != null)
            {
                var (cb, _, _) = await _security.IsComponentBannedAsync(req.ComponentFingerprints);
                compBanned = cb;
            }
            if (hwidBanned || compBanned)
                return ActivationJsonFailure(compBanned ? "COMPONENT_BANNED" : "BANNED", "Access denied by server");

            if (req.ComponentFingerprints != null)
            {
                _ = Task.Run(async () => { try { await _fingerprint.UpsertFingerprintAsync(req.HardwareId, req.ComponentFingerprints); } catch { } });
            }

            var product = await FindProductAsync(req.AppName, req.AppId);
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            var trialIdentity = await _machineIdentityObservations.ObserveAsync(
                product.Id, req.HardwareId, req.SystemUuid, req.MachineEvidence, Services.MachineEvidenceEndpoints.Trial, req.AppVersion,
                HttpContext.RequestAborted);
            if (trialIdentity.IsRefused)
                return ActivationJsonFailure("DEVICE_REFUSED", DeviceRefusedMessage(trialIdentity));
            
            var type = await _db.LicenseTypes
                .Include(t => t.CustomParams)
                .FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug.ToUpper() == req.TypeSlug.Trim().ToUpper());
            if (type == null)
            {
                TagActivationFailure("LICENSE_TYPE_UNKNOWN");
                return BadRequest(string.Format(_localizer["Api_LicenseTypeUnknown"].Value, req.TypeSlug));
            }

            // A reserved paid pass is never delivered by this anonymous route, not even as a recovery (TKT-002468).
            if (Services.PersonalDayPassPolicy.IsPassType(type.Slug))
                return ActivationJsonFailure("PAYMENT_REQUIRED", "A confirmed payment is required for this license type.");

            // TKT-002466/TKT-002468: only an opted-in type may be created, renewed or returned by this anonymous route.
            var trialNotAllowed = RejectIfPublicTrialNotAllowed(type);
            if (trialNotAllowed != null)
                return trialNotAllowed;

            // TKT-002468: a licence held by this HWID is processed only when it is of the requested type and not paid;
            // a current licence of another type is refused, an expired one leads to creation (switch to the free type).
            // Renewal on this route stays limited to the hard-coded Community slug (TKT-001889).
            var heldSelection = await SelectHeldLicenceForPublicTrialAsync(product.Id, type, req.HardwareId,
                held => string.Equals(held.Type?.Slug, "YOUR_APP_NAME-COMMUNITY", StringComparison.OrdinalIgnoreCase)
                    && held.Type?.IsRecurring == true && held.Type.AllowPublicTrial);
            if (heldSelection.Refusal != null)
                return heldSelection.Refusal;
            var existing = heldSelection.Held;

            if (existing != null)
            {
                await using var existingTrialTransaction = await _seatCleanup
                    .BeginProductScopeCleanupAsync(product.Id, req.HardwareId);
                await _db.Entry(existing).ReloadAsync();

                var trialHistory = await CaptureTrialHistoryAsync(existing, existingTrialTransaction,
                    req.HardwareId, req.AppVersion, "trial_existing");
                await BeginLegacyHistorySavepointAsync(trialHistory);
                // TKT-002041: an excluded machine cannot re-create or reactivate its seat on this
                // existing licence, before any renewal or seat write.
                try
                {
                    await Services.LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
                        _db, existing.Id, req.HardwareId, req.HardwareId, HttpContext.RequestAborted);
                }
                catch (Services.DistributionOperationException exception) when (IsLicenseHardwareExclusion(exception))
                {
                    // TKT-004085: answered like every other refusal of this path instead of escaping as an empty 500.
                    TagActivationFailure(exception.ErrorCode);
                    return await PersistLegacyRefusalAsync(trialHistory, LicenseHardwareExcludedFailure());
                }

                // Révoquée → 403 Forbidden
                if (!existing.IsActive || Services.LegacyMinimumVersionPolicy.AppliesTo(product.Name) && existing.RevokedAt != null)
                {
                    TagActivationFailure("LICENSE_DISABLED");
                    return await PersistLegacyRefusalAsync(trialHistory, StatusCode(403, _localizer["Api_AccessRevoked"].Value));
                }

                var trialVersionRefusal = RejectMinimumVersion(product, req.AppVersion, existing);
                var trialMachineRefusal = Services.VirtualMachinePolicy.Refusal(existing.CommercialNature,
                    Services.VirtualMachinePolicy.Classify(req.MachineEvidence));
                if (trialMachineRefusal != null)
                    return await PersistLegacyRefusalAsync(trialHistory, ActivationJsonFailure(
                        trialMachineRefusal, Services.VirtualMachinePolicy.Message(trialMachineRefusal)!));
                if (trialVersionRefusal != null)
                    return await PersistLegacyRefusalAsync(trialHistory, trialVersionRefusal);

                bool isExpired = existing.ExpirationDate.HasValue && DateTime.UtcNow > existing.ExpirationDate.Value;

                // TKT-002475: only the creation of a new seat on the held licence of the requested type is refused
                // when its key activation is disabled; an active seat of this machine keeps recovering. An expired
                // licence of another type never reaches this block (TKT-002468 selection), so creating another
                // licence is untouched. The refusal never revokes the licence and precedes any renewal or seat write.
                if (await KeyActivationRefusesNewSeatAsync(existing.Id, req.HardwareId))
                    return await PersistLegacyRefusalAsync(trialHistory, KeyActivationDisabledFailure());

                bool isCommunitySlug = string.Equals(existing.Type?.Slug, "YOUR_APP_NAME-COMMUNITY", StringComparison.OrdinalIgnoreCase);

                // Renouvellement automatique : UNIQUEMENT Community gratuite expirée qui redemande Community.
                // La sélection ci-dessus garantit le même type, ouvert à l'essai public (TKT-002466) ; une licence de ce type
                // expirée et non renouvelable a déjà été refusée en LICENSE_EXPIRED (TKT-002468). Le slug en dur reste
                // suivi par TKT-001889.
                if (isCommunitySlug && existing.Type?.IsRecurring == true && existing.Type.AllowPublicTrial && isExpired)
                {
                    existing.ExpirationDate = DateTime.UtcNow.AddDays(existing.Type.DefaultDurationDays);
                    _db.LicenseHistories.Add(new LicenseHistory {
                        LicenseId = existing.Id,
                        Action = HistoryActions.Renewed,
                        Details = $"Renouvellement automatique ({existing.Type.Name}) : +{existing.Type.DefaultDurationDays} jours",
                        PerformedBy = "System"
                    });
                    await _db.SaveChangesAsync();
                    _logger.LogInformation("Renouvellement Community : {HardwareId} → expiration {Expiry}", req.HardwareId, existing.ExpirationDate);
                }

                // Renvoi de la licence du type demandé (valide ou tout juste renouvelée). TKT-002468 : l'e-mail et le nom
                // enregistrés ne sont jamais remplacés par ceux de la demande. Une licence expirée d'un autre type n'arrive
                // pas ici : la sélection laisse alors la création ci-dessous (bascule vers le type gratuit).
                {
                    var seat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == existing.Id && s.HardwareId == req.HardwareId && s.IsActive);
                    if (seat == null)
                    {
                        seat = new LicenseSeat {
                            LicenseId = existing.Id, HardwareId = req.HardwareId,
                            FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow,
                            IsActive = true
                        };
                        _db.LicenseSeats.Add(seat);
                    }
                    // TKT-003404: display name of the PC, never erased by a request without evidence.
                    Services.SeatMachineName.Apply(seat, req.MachineEvidence);
                    AddHardwareIdV2Observation(existing, product, "TRIAL_EXISTING", req);
                    await _db.SaveChangesAsync();
                    try
                    {
                        await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                            req.HardwareId, existing.Id, product.Id);
                    }
                    catch (Services.DistributionOperationException exception)
                    {
                        return DistributionRefusalResult(exception);
                    }

                    var model = new LicenseModel
                    {
                        Id = existing.Id,
                        LicenseKey = existing.LicenseKey,
                        CustomerName = existing.CustomerName,
                        CustomerEmail = existing.CustomerEmail,
                        TypeSlug = existing.Type?.Slug ?? "STANDARD",
                        Reference = existing.Reference,
                        CreationDate = existing.CreationDate,
                        ExpirationDate = existing.ExpirationDate,
                        HardwareId = existing.HardwareId ?? string.Empty,
                        Features = BuildFeatures(existing.Type?.CustomParams)
                    };

                    try
                    {
                        var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                        if (decryptedKey == "ERROR_DECRYPTION_FAILED") return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                        var signed = LicenseService.GenerateLicense(model, decryptedKey);
                        await SaveTrialAcceptanceAsync(trialHistory, existing.HardwareId);
                        if (existingTrialTransaction != null)
                            await existingTrialTransaction.CommitAsync();
                        _logger.LogInformation("Licence recovery : Renvoi de la licence existante ({TypeSlug}) pour {HardwareId}", existing.Type?.Slug, req.HardwareId);
                        return Ok(new { LicenseFile = signed });
                    }
                    catch (Exception ex) when (Services.AssignmentRefusals.TryTranslate(ex, out var assignmentRefusal))
                    {
                        // TKT-004085: the database refused the write or the commit itself, so nothing was committed.
                        return AssignmentTriggerRefusal(ex, assignmentRefusal, "trial_existing");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Erreur signature licence recovery pour {HardwareId}", req.HardwareId);
                        return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    }
                }
            }

            // Sinon, création d'une nouvelle licence Trial (type ouvert, aucune licence en cours d'un autre type)
            var newTrialMachineRefusal = Services.VirtualMachinePolicy.Refusal("FREE",
                Services.VirtualMachinePolicy.Classify(req.MachineEvidence));
            if (newTrialMachineRefusal != null)
                return ActivationJsonFailure(newTrialMachineRefusal, Services.VirtualMachinePolicy.Message(newTrialMachineRefusal)!);
            var newTrialVersionRefusal = RejectMinimumVersion(product, req.AppVersion);
            if (newTrialVersionRefusal != null) return newTrialVersionRefusal;

            var trialNewActivationsDisabled = RejectIfNewActivationsDisabled(type);
            if (trialNewActivationsDisabled != null)
                return trialNewActivationsDisabled;

            await using var trialTransaction = await _seatCleanup
                .BeginProductScopeCleanupAsync(product.Id, req.HardwareId);
            var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(product.Id, type, req.HardwareId);
            if (freemiumAlreadyConsumed != null)
                return freemiumAlreadyConsumed;

            // Once commit starts, acknowledgement failure cannot establish absence.
            // Dispose the owned transaction without attempting rollback of a completed commit.
            var trialCommitStarted = false;
            try
            {
            var newKey = Guid.NewGuid().ToString("D").ToUpper();
            var license = new License
            {
                ProductId = product.Id,
                LicenseTypeId = type.Id,
                LicenseKey = newKey,
                CustomerName = req.CustomerName ?? "Auto Trial",
                CommercialNature = "FREE",
                CustomerEmail = req.CustomerEmail ?? "trial@auto.local",
                HardwareId = req.HardwareId,
                ActivationDate = DateTime.UtcNow,
                CreationDate = DateTime.UtcNow,
                ExpirationDate = DateTime.UtcNow.AddDays(type.DefaultDurationDays),
                IsActive = true
            };

            _db.Licenses.Add(license);

            var newTrialHistory = await CaptureTrialHistoryAsync(license, trialTransaction,
                req.HardwareId, req.AppVersion, "trial_create", newlyCreated: true);

            // Création du siège initial pour le multi-postes
            var firstSeat = new LicenseSeat
            {
                LicenseId = license.Id,
                HardwareId = req.HardwareId,
                FirstActivatedAt = DateTime.UtcNow,
                LastCheckInAt = DateTime.UtcNow,
                IsActive = true
            };
            // TKT-003404: display name of the PC reported in the evidence.
            Services.SeatMachineName.Apply(firstSeat, req.MachineEvidence);
            _db.LicenseSeats.Add(firstSeat);

            _db.LicenseHistories.Add(new LicenseHistory {
                LicenseId = license.Id,
                Action = HistoryActions.Created,
                Details = string.Format(_localizer["Licenses_Action_Created"].Value, type.Name, 1),
                PerformedBy = "System"
            });
            AddHardwareIdV2Observation(license, product, "TRIAL_CREATE", req);

            await _db.SaveChangesAsync();

            // Enforcement : un HWID ne peut être actif que sur une seule licence par produit
            await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                req.HardwareId, license.Id, product.Id);

            _logger.LogInformation("Nouveau Trial cree : {TypeSlug} ({Days} jours) pour {HardwareId}", type.Slug, type.DefaultDurationDays, req.HardwareId);

            var licenseModel = new LicenseModel
            {
                Id = license.Id,
                LicenseKey = license.LicenseKey,
                CustomerName = license.CustomerName,
                CustomerEmail = license.CustomerEmail,
                TypeSlug = type.Slug,
                Reference = license.Reference,
                CreationDate = license.CreationDate,
                ExpirationDate = license.ExpirationDate,
                HardwareId = license.HardwareId ?? string.Empty,
                Features = BuildFeatures(type.CustomParams)
            };

            var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
            if (decryptedKey == "ERROR_DECRYPTION_FAILED")
            {
                if (trialTransaction != null) await trialTransaction.RollbackAsync();
                return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
            }
            var signedLicenseString = LicenseService.GenerateLicense(licenseModel, decryptedKey);
            await SaveTrialAcceptanceAsync(newTrialHistory, license.HardwareId);
            trialCommitStarted = true;
            if (trialTransaction != null) await trialTransaction.CommitAsync();
            return Ok(new { LicenseFile = signedLicenseString });
            }
            catch (Services.DistributionOperationException exception)
            {
                if (trialTransaction != null && !trialCommitStarted)
                    await trialTransaction.RollbackAsync();
                return DistributionRefusalResult(exception);
            }
            catch (Exception ex) when (Services.AssignmentRefusals.TryTranslate(ex, out var assignmentRefusal))
            {
                // TKT-004085: the database refused the write or the commit itself, so nothing was committed.
                if (trialTransaction != null && !trialCommitStarted) await trialTransaction.RollbackAsync();
                return AssignmentTriggerRefusal(ex, assignmentRefusal, "trial_create");
            }
            catch (Exception ex)
            {
                if (trialTransaction != null && !trialCommitStarted) await trialTransaction.RollbackAsync();
                if (trialCommitStarted)
                {
                    _logger.LogError("LicenseDecisionPersistenceFailed Phase=trial_create CommitOutcome=indeterminate");
                    return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                }
                _logger.LogError(ex, "Erreur creation trial pour {HardwareId}", req.HardwareId);
                return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
            }
        }

        /// <summary>
        /// Activates a public online license only when the primary HWID already satisfies the exact canonical wire contract.
        /// Invalid casing, alphabet, or length is rejected without normalization before extra parameters or business state are evaluated.
        /// </summary>
        /// <param name="req">Public activation request containing an exact uppercase 16-character ASCII hexadecimal HWID.</param>
        /// <returns>The normal activation workflow, or INVALID_HARDWARE_ID before any licensing side effect.</returns>
        [HttpPost]
        public Task<IActionResult> Activate([FromBody] ActivationRequest req)
        {
            if (!Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(req.HardwareId))
                return Task.FromResult(RejectInvalidPrimaryHardwareId());
            // LEGACY-EXPIRY(TKT-001430, 2026-12-31): PreviousHardwareId validation, remove with the switch by 31/12/2026.
            if (req.PreviousHardwareId != null
                && !Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(req.PreviousHardwareId))
            {
                TagActivationFailure("INVALID_PREVIOUS_HARDWARE_ID");
                return Task.FromResult<IActionResult>(BadRequest(new
                {
                    error = "invalid_previous_hardware_id",
                    message = "PreviousHardwareId must contain exactly 16 uppercase ASCII hexadecimal characters."
                }));
            }

            if (req.ExtraParams != null)
            {
                HttpContext.Items[LogKeys.AppName] = string.IsNullOrWhiteSpace(req.AppName) ? "API_CLIENT" : req.AppName;
                HttpContext.Items[LogKeys.Endpoint] = "ACTIVATE_REJECTED";
                TagActivationFailure("EXTRA_PARAMS_NOT_ALLOWED");
                return Task.FromResult<IActionResult>(BadRequest(new { error = "extra_params_not_allowed" }));
            }

            return ActivateCoreAsync(req);
        }

        /// <summary>
        /// Activates or reactivates exactly one canonical seat after resolving any authenticated legacy alias.
        /// Known invalid aliases fail closed before quota or seat creation, while successful responses are signed for the authenticated identifier presented by the caller.
        /// Restricted online licenses require current physical machine evidence before first-order revocation or business mutation; PAID and UNKNOWN commercial natures remain exempt.
        /// Auto-trial always refuses the reserved paid-pass type, even as a recovery (TKT-002468).
        /// Auto-trial creation, recurring renewal and return of a held licence require the type's AllowPublicTrial opt-in, and creation honours DisableNewActivations (TKT-002466).
        /// Auto-trial returns a held licence only when it is of the resolved type and not of a paid nature (PAID, PAID_TRIAL), refuses a current licence of another type and an expired non-renewable one with typed codes, and never replaces the stored customer e-mail or name (TKT-002468).
        /// Configured TIAConnect minimums require an eligible declared version before paid auto-unban, seat mutation, pass consumption or signing.
        /// </summary>
        /// <remarks>Existing-license decisions are frozen under global commercial authority followed by item2 and exact hardware locks. Product-scope cleanup deactivates losing seats and ends their assignments without invalidating Runtime identity; signing failure rolls back both winner and loser mutations. Classic first-order-free cross-subject refusal revokes only the new license atomically with history after business savepoint rollback; all other refusals commit history only; unconfirmed history returns the existing technical error while retaining correlation. Auto-trial creation remains a separate producer. Every seat this path creates, resumes or keeps records the PC display name from MachineEvidence through Services.SeatMachineName (TKT-003404); a request without a usable name leaves the stored one untouched.</remarks>
        /// <param name="req">Validated JSON request containing the submitted primary hardware identity.</param>
        /// <returns>An activation response, including typed compatibility refusal without creating a legacy seat.</returns>
        private async Task<IActionResult> ActivateCoreAsync(ActivationRequest req)
        {
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, "ACTIVATE");

            if (req.ComponentFingerprints != null)
            {
                _ = Task.Run(async () => { try { await _fingerprint.UpsertFingerprintAsync(req.HardwareId, req.ComponentFingerprints); } catch { } });
            }

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                _logger.LogWarning("Activation echouee : Application '{AppName}' inconnue.", req.AppName);
                return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            var activationIdentity = await _machineIdentityObservations.ObserveAsync(
                product.Id, req.HardwareId, req.SystemUuid, req.MachineEvidence, Services.MachineEvidenceEndpoints.Activate, req.AppVersion,
                HttpContext.RequestAborted);
            if (activationIdentity.IsRefused)
                return ActivationJsonFailure("DEVICE_REFUSED", DeviceRefusedMessage(activationIdentity));

            // Check ban status. HWID auto-unban is deferred until the license is fully validated.
            var hwidBanned = await _security.IsHardwareIdBannedAsync(req.HardwareId);
            var compBanned = false;
            if (!hwidBanned && req.ComponentFingerprints != null)
            {
                var (cb, _, _) = await _security.IsComponentBannedAsync(req.ComponentFingerprints);
                compBanned = cb;
            }
            if (compBanned)
                return ActivationJsonFailure("COMPONENT_BANNED", "Access denied by server");

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            // --- INTERCEPTION AUTO-TRIAL ---
            if (cleanKey.EndsWith("-FREE-TRIAL") || cleanKey == "FREE-TRIAL")
            {
                if (hwidBanned)
                    return ActivationJsonFailure("BANNED", "Access denied by server");

                _logger.LogInformation("Detection d'une demande AUTO-TRIAL pour {AppName}", product.Name);
                HttpContext.Items[LogKeys.Endpoint] = "TRIAL_AUTO";
                
                // On cherche d'abord une correspondance exacte du Slug avec la clé, sinon le slug "TRIAL", toujours filtré par produit
                var type = await _db.LicenseTypes.Include(t => t.CustomParams).FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug.ToLower() == cleanKey.ToLower())
                           ?? await _db.LicenseTypes.Include(t => t.CustomParams).FirstOrDefaultAsync(t => t.ProductId == product.Id && t.Slug.ToLower() == "trial");

                if (type == null) 
                {
                    TagActivationFailure("TRIAL_NOT_ENABLED");
                    _logger.LogWarning("Demande Trial echouee : Aucun type de licence 'TRIAL' n'est configure.");
                    return BadRequest(_localizer["Api_TrialNotEnabled"].Value);
                }

                // A reserved paid pass is never delivered by this anonymous route, not even as a recovery (TKT-002468).
                if (Services.PersonalDayPassPolicy.IsPassType(type.Slug))
                    return ActivationJsonFailure("PAYMENT_REQUIRED", "A confirmed payment is required for this license type.");

                // TKT-002466/TKT-002468: same per-type opt-in as the trial route, for creation, renewal and return alike.
                var autoTrialNotAllowed = RejectIfPublicTrialNotAllowed(type);
                if (autoTrialNotAllowed != null)
                    return autoTrialNotAllowed;

                // TKT-002468: only a held licence of the resolved type, not paid, is processed; a current licence of
                // another type is refused; an expired one of another type leads to creation. Recurring types renew.
                var autoHeldSelection = await SelectHeldLicenceForPublicTrialAsync(product.Id, type, req.HardwareId,
                    held => held.Type?.IsRecurring == true && held.Type.AllowPublicTrial
                        && !Services.PersonalDayPassPolicy.IsPassType(held.Type.Slug));
                if (autoHeldSelection.Refusal != null)
                    return autoHeldSelection.Refusal;
                var existing = autoHeldSelection.Held;

                if (existing != null)
                {
                    await using var existingAutoTrialTransaction = await _seatCleanup
                        .BeginProductScopeCleanupAsync(product.Id, req.HardwareId);
                    await _db.Entry(existing).ReloadAsync();

                    var autoTrialHistory = await CaptureTrialHistoryAsync(existing, existingAutoTrialTransaction,
                        req.HardwareId, req.AppVersion, "auto_trial_existing");
                    await BeginLegacyHistorySavepointAsync(autoTrialHistory);
                    // TKT-002041: an excluded machine cannot re-create or reactivate its seat on
                    // this existing licence, before any renewal or seat write.
                    try
                    {
                        await Services.LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
                            _db, existing.Id, req.HardwareId, req.HardwareId, HttpContext.RequestAborted);
                    }
                    catch (Services.DistributionOperationException exception) when (IsLicenseHardwareExclusion(exception))
                    {
                        // TKT-004085: answered like every other refusal of this path instead of escaping as an empty 500.
                        TagActivationFailure(exception.ErrorCode);
                        return await PersistLegacyRefusalAsync(autoTrialHistory, LicenseHardwareExcludedFailure());
                    }

                    // Révoquée → 403 Forbidden
                    if (!existing.IsActive || Services.LegacyMinimumVersionPolicy.AppliesTo(product.Name) && existing.RevokedAt != null)
                    {
                        TagActivationFailure("LICENSE_DISABLED");
                        return await PersistLegacyRefusalAsync(autoTrialHistory, StatusCode(403, _localizer["Api_AccessRevoked"].Value));
                    }

                    var autoTrialVersionRefusal = RejectMinimumVersion(product, req.AppVersion, existing);
                    var autoTrialMachineRefusal = Services.VirtualMachinePolicy.Refusal(existing.CommercialNature,
                        Services.VirtualMachinePolicy.Classify(req.MachineEvidence));
                    if (autoTrialMachineRefusal != null)
                        return await PersistLegacyRefusalAsync(autoTrialHistory, ActivationJsonFailure(
                            autoTrialMachineRefusal, Services.VirtualMachinePolicy.Message(autoTrialMachineRefusal)!));
                    if (autoTrialVersionRefusal != null)
                        return await PersistLegacyRefusalAsync(autoTrialHistory, autoTrialVersionRefusal);

                    // TKT-002475: same guard as the trial route. The licence was found by this machine, so
                    // only a missing active seat would be a new admission; recovery of an active seat stays.
                    if (await KeyActivationRefusesNewSeatAsync(existing.Id, req.HardwareId))
                        return await PersistLegacyRefusalAsync(autoTrialHistory, KeyActivationDisabledFailure());

                    // Récurrent (Community) + expirée → renouvellement automatique
                    // Reserved paid passes never receive free time, even after an erroneous admin recurring toggle.
                    // TKT-002466: a renewal creates new rights, so it also requires AllowPublicTrial on the held type.
                    if (!Services.PersonalDayPassPolicy.IsPassType(existing.Type?.Slug)
                        && existing.Type?.IsRecurring == true && existing.Type.AllowPublicTrial
                        && existing.ExpirationDate.HasValue && DateTime.UtcNow > existing.ExpirationDate.Value)
                    {
                        existing.ExpirationDate = DateTime.UtcNow.AddDays(existing.Type.DefaultDurationDays);
                        _db.LicenseHistories.Add(new LicenseHistory {
                            LicenseId = existing.Id,
                            Action = HistoryActions.Renewed,
                            Details = $"Renouvellement automatique ({existing.Type.Name}) : +{existing.Type.DefaultDurationDays} jours",
                            PerformedBy = "System"
                        });
                        await _db.SaveChangesAsync();
                        _logger.LogInformation("Renouvellement {TypeSlug} : {HardwareId} → expiration {Expiry}", existing.Type.Slug, req.HardwareId, existing.ExpirationDate);
                    }

                    // Une licence de ce type expirée et non renouvelable a déjà été refusée en LICENSE_EXPIRED par la
                    // sélection (TKT-002468) : il n'y a pas de « renvoi tel quel » d'une licence expirée.

                    // S'assurer que le siège existe (pour les licences créées avant le système de seats)
                    var seat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == existing.Id && s.HardwareId == req.HardwareId && s.IsActive);
                    if (seat == null)
                    {
                        var autoTrialSeat = new LicenseSeat {
                            LicenseId = existing.Id, HardwareId = req.HardwareId,
                            FirstActivatedAt = DateTime.UtcNow, LastCheckInAt = DateTime.UtcNow,
                            IsActive = true
                        };
                        // TKT-003404: display name of the PC reported in the evidence.
                        Services.SeatMachineName.Apply(autoTrialSeat, req.MachineEvidence);
                        _db.LicenseSeats.Add(autoTrialSeat);
                        AddHardwareIdV2Observation(existing, product, "TRIAL_AUTO_EXISTING", req);
                        await _db.SaveChangesAsync();
                    }
                    else {
                        seat.LastCheckInAt = DateTime.UtcNow;
                        // TKT-003404: refresh the PC name when it changed, never erase it.
                        Services.SeatMachineName.Apply(seat, req.MachineEvidence);
                        AddHardwareIdV2Observation(existing, product, "TRIAL_AUTO_EXISTING", req);
                        await _db.SaveChangesAsync();
                    }
                    try
                    {
                        await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                            req.HardwareId, existing.Id, product.Id);
                    }
                    catch (Services.DistributionOperationException exception)
                    {
                        return DistributionRefusalResult(exception);
                    }

                    // TKT-002468 : l'e-mail et le nom enregistrés ne sont jamais remplacés par ceux de la demande.

                    // On met à jour le log avec la vraie clé trouvée
                    HttpContext.Items[LogKeys.LicenseKey] = existing.LicenseKey;

                    var recoveryModel = new LicenseModel {
                        Id = existing.Id, LicenseKey = existing.LicenseKey, CustomerName = existing.CustomerName,
                        CustomerEmail = existing.CustomerEmail, TypeSlug = existing.Type?.Slug ?? "TRIAL",
                        Reference = existing.Reference,
                        CreationDate = existing.CreationDate, ExpirationDate = existing.ExpirationDate, HardwareId = existing.HardwareId ?? string.Empty,
                        Features = BuildFeatures(existing.Type?.CustomParams)
                    };

                    try
                    {
                        var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                        if (decryptedKey == "ERROR_DECRYPTION_FAILED") return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                        var signed = LicenseService.GenerateLicense(recoveryModel, decryptedKey);
                        await SaveTrialAcceptanceAsync(autoTrialHistory, existing.HardwareId);
                        if (existingAutoTrialTransaction != null)
                            await existingAutoTrialTransaction.CommitAsync();
                        return Ok(new { LicenseFile = signed });
                    }
                    catch (Exception ex) when (Services.AssignmentRefusals.TryTranslate(ex, out var assignmentRefusal))
                    {
                        // TKT-004085: the database refused the write or the commit itself, so nothing was committed.
                        return AssignmentTriggerRefusal(ex, assignmentRefusal, "auto_trial_existing");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Erreur signature recovery trial");
                        return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    }
                }

                // TKT-002466: creation also honours the closure switch of the type.
                var autoTrialNewActivationsDisabled = RejectIfNewActivationsDisabled(type);
                if (autoTrialNewActivationsDisabled != null)
                    return autoTrialNewActivationsDisabled;

                // Création auto (atomique)
                var newAutoTrialMachineRefusal = Services.VirtualMachinePolicy.Refusal("FREE",
                    Services.VirtualMachinePolicy.Classify(req.MachineEvidence));
                if (newAutoTrialMachineRefusal != null)
                    return ActivationJsonFailure(newAutoTrialMachineRefusal, Services.VirtualMachinePolicy.Message(newAutoTrialMachineRefusal)!);
                var newAutoTrialVersionRefusal = RejectMinimumVersion(product, req.AppVersion);
                if (newAutoTrialVersionRefusal != null) return newAutoTrialVersionRefusal;

                await using var autoTrialTx = await _seatCleanup
                    .BeginProductScopeCleanupAsync(product.Id, req.HardwareId);
                var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(product.Id, type, req.HardwareId);
                if (freemiumAlreadyConsumed != null)
                    return freemiumAlreadyConsumed;

                // A failed acknowledgement may follow a committed creation; disposal
                // owns cleanup and must not replace the existing technical response.
                var autoTrialCommitStarted = false;
                try
                {
                var newKey = Guid.NewGuid().ToString("D").ToUpper();
                var newLic = new License {
                    CommercialNature = "FREE",
                    ProductId = product.Id, LicenseTypeId = type.Id, LicenseKey = newKey,
                    CustomerName = req.CustomerName ?? "Auto Trial", CustomerEmail = req.CustomerEmail ?? "trial@auto.local",
                    HardwareId = req.HardwareId, ActivationDate = DateTime.UtcNow, CreationDate = DateTime.UtcNow,
                    ExpirationDate = DateTime.UtcNow.AddDays(type.DefaultDurationDays), IsActive = true
                };
                _db.Licenses.Add(newLic);

                var newAutoTrialHistory = await CaptureTrialHistoryAsync(newLic, autoTrialTx,
                    req.HardwareId, req.AppVersion, "auto_trial_create", newlyCreated: true);

                // Création du siège initial pour le multi-postes
                var firstSeat = new LicenseSeat
                {
                    LicenseId = newLic.Id,
                    HardwareId = req.HardwareId,
                    FirstActivatedAt = DateTime.UtcNow,
                    LastCheckInAt = DateTime.UtcNow,
                    IsActive = true
                };
                // TKT-003404: display name of the PC reported in the evidence.
                Services.SeatMachineName.Apply(firstSeat, req.MachineEvidence);
                _db.LicenseSeats.Add(firstSeat);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = newLic.Id,
                    Action = HistoryActions.Created,
                    Details = string.Format(_localizer["Licenses_Action_Created"].Value, type.Name, 1),
                    PerformedBy = "System"
                });
                AddHardwareIdV2Observation(newLic, product, "TRIAL_AUTO_CREATE", req);

                await _db.SaveChangesAsync();

                // Enforcement : un HWID ne peut être actif que sur une seule licence par produit
                await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                    req.HardwareId, newLic.Id, product.Id);

                await _hwidReuseAlerts.CheckAndNotifyAsync(product.Id, req.HardwareId, newLic.Id);

                // On met à jour le log avec la clé générée
                HttpContext.Items[LogKeys.LicenseKey] = newKey;

                var newModel = new LicenseModel {
                    Id = newLic.Id, LicenseKey = newLic.LicenseKey, CustomerName = newLic.CustomerName,
                    CustomerEmail = newLic.CustomerEmail, TypeSlug = type.Slug,
                    Reference = newLic.Reference,
                    CreationDate = newLic.CreationDate, ExpirationDate = newLic.ExpirationDate, HardwareId = newLic.HardwareId ?? string.Empty,
                    Features = BuildFeatures(type.CustomParams)
                };

                var decryptedKey = _encryption.Decrypt(product.PrivateKeyXml);
                if (decryptedKey == "ERROR_DECRYPTION_FAILED")
                {
                    if (autoTrialTx != null) await autoTrialTx.RollbackAsync();
                    return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                }
                var signed = LicenseService.GenerateLicense(newModel, decryptedKey);
                await SaveTrialAcceptanceAsync(newAutoTrialHistory, newLic.HardwareId);
                autoTrialCommitStarted = true;
                if (autoTrialTx != null) await autoTrialTx.CommitAsync();
                return Ok(new { LicenseFile = signed });
                }
                catch (Services.DistributionOperationException exception)
                {
                    if (autoTrialTx != null && !autoTrialCommitStarted)
                        await autoTrialTx.RollbackAsync();
                    return DistributionRefusalResult(exception);
                }
                catch (Exception ex) when (Services.AssignmentRefusals.TryTranslate(ex, out var assignmentRefusal))
                {
                    // TKT-004085: the database refused the write or the commit itself, so nothing was committed.
                    if (autoTrialTx != null && !autoTrialCommitStarted) await autoTrialTx.RollbackAsync();
                    return AssignmentTriggerRefusal(ex, assignmentRefusal, "auto_trial_create");
                }
                catch (Exception ex)
                {
                    if (autoTrialTx != null && !autoTrialCommitStarted) await autoTrialTx.RollbackAsync();
                    if (autoTrialCommitStarted)
                    {
                        _logger.LogError("LicenseDecisionPersistenceFailed Phase=auto_trial_create CommitOutcome=indeterminate");
                        return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                    }
                    _logger.LogError(ex, "Erreur creation auto-trial pour {AppName}", req.AppName);
                    return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
                }
            }
            // --- FIN INTERCEPTION ---

            var productIds = await GetProductHierarchyIds(product.Id);
            await using var activationTransaction = await _seatCleanup
                .BeginProductScopeCleanupAsync(product.Id, req.HardwareId);
            var license = await _db.Licenses
                .Include(l => l.Product)
                .Include(l => l.Type).ThenInclude(t => t!.CustomParams)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && productIds.Contains(l.ProductId));

            Services.SecurityService.DeferredNotification? deferredAutoUnbanNotification = null;
            Services.SecurityService.DeferredNotification? deferredActivationNotification = null;

            if (license == null) 
            {
                TagActivationFailure("INVALID_LICENSE_KEY");
                _logger.LogWarning("Activation refused: license not found for product {ProductId}.", product.Id);
                return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            }

            var legacyHistory = new LegacyHistoryObservation
            {
                Snapshot = Services.LicenseDecisionHistoryWriter.CaptureObserved(license, DateTimeOffset.UtcNow, null),
                Transaction = activationTransaction,
                SubmittedHardwareId = req.HardwareId,
                Phase = "legacy_activation",
                AppVersion = req.AppVersion
            };
            var hardwareResolution = await _hardwareAuthorityAliases.ResolveAsync(
                _db,
                license.ProductId,
                license.Id,
                req.HardwareId,
                Services.HardwareAuthorityResolutionIntent.Activation,
                HttpContext.RequestAborted);
            var authoritativeHardwareId = hardwareResolution.EffectiveHardwareId;
            var compatibilityAliasUsed = false;
            if (hardwareResolution.Refused)
            {
                var compatibilityHardwareId = await TryResolveLoggedCompatibilityAliasAsync(
                    license, hardwareResolution);
                if (compatibilityHardwareId == null)
                {
                    _logger.LogWarning(
                        "Hardware authority refusal retained for alias {AliasId}, licence {LicenseId}; reason {RefusalReason}.",
                        hardwareResolution.AliasId,
                        license.Id,
                        hardwareResolution.RefusalReason);
                    return await PersistLegacyRefusalAsync(legacyHistory, ActivationJsonFailure(
                        "HARDWARE_AUTHORITY_REFUSED",
                        "The legacy hardware identity is no longer accepted. Use the authoritative V2 identity."));
                }
                authoritativeHardwareId = compatibilityHardwareId;
                compatibilityAliasUsed = true;
            }
            legacyHistory.ResolvedHardwareId = authoritativeHardwareId;
            legacyHistory.ResolutionSource = hardwareResolution.UsedAlias ? "provider_alias" : "provider_direct";
            legacyHistory.Snapshot = Services.LicenseDecisionHistoryWriter.CaptureObserved(
                license, DateTimeOffset.UtcNow, authoritativeHardwareId);
            // TKT-002041: a licence-scoped machine exclusion is a commercial admission refusal
            // checked before any seat mutation, quota consumption or authority lock.
            try
            {
                await Services.LicenseHardwareExclusionChecker.EnsureNotExcludedAsync(
                    _db, license.Id, req.HardwareId, authoritativeHardwareId, HttpContext.RequestAborted);
            }
            catch (Services.DistributionOperationException exception) when (IsLicenseHardwareExclusion(exception))
            {
                // TKT-004085: answered like every other refusal of this path instead of escaping as an empty 500.
                TagActivationFailure(exception.ErrorCode);
                return await PersistLegacyRefusalAsync(legacyHistory, LicenseHardwareExcludedFailure());
            }
            if (hardwareResolution.UsedAlias || compatibilityAliasUsed)
            {
                await Services.ProductHardwareSeatLockAuthority.AcquireAsync(
                    _db, product.Id, authoritativeHardwareId);
                if (await _security.IsHardwareIdBannedAsync(authoritativeHardwareId))
                    return await PersistLegacyRefusalAsync(legacyHistory, ActivationJsonFailure("BANNED", "Access denied by server"));
            }
            
            await BeginLegacyHistorySavepointAsync(legacyHistory);
            if (!license.IsActive || license.RevokedAt != null
                && (Services.LegacyMinimumVersionPolicy.AppliesTo(product.Name)
                    || Services.LegacyMinimumVersionPolicy.AppliesTo(license.Product?.Name ?? string.Empty)))
            {
                TagActivationFailure("LICENSE_DISABLED");
                _logger.LogWarning("Activation refused: license {LicenseId} is disabled.", license.Id);
                return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(_localizer["Api_LicenseDisabled"].Value));
            }
            
            if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value)
            {
                TagActivationFailure("LICENSE_EXPIRED");
                _logger.LogWarning(
                    "Activation refused: license {LicenseId} expired for product {ProductId}, type {TypeSlug}, expiry {Expiry}.",
                    license.Id,
                    product.Id,
                    license.Type?.Slug ?? "UNKNOWN",
                    license.ExpirationDate);
                return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(_localizer["Api_LicenseExpired"].Value));
            }

            // Decide before auto-unban, first-activation time, seat switch or product cleanup can mutate authority.
            // Refuse before the separate first-order rule can revoke this licence or unlink another seat.
            var machineRefusal = Services.VirtualMachinePolicy.Refusal(license.CommercialNature,
                Services.VirtualMachinePolicy.Classify(req.MachineEvidence));
            if (machineRefusal != null)
                return await PersistLegacyRefusalAsync(legacyHistory, ActivationJsonFailure(
                    machineRefusal, Services.VirtualMachinePolicy.Message(machineRefusal)!));

            if (await Services.FirstOrderFreeActivationPolicy.MustRefuseAsync(
                _db, license, authoritativeHardwareId, HttpContext.RequestAborted))
                return await PersistLegacyRefusalAsync(legacyHistory, ActivationJsonFailure(
                    Services.FirstOrderFreeActivationPolicy.RefusalCode,
                    "This first-order free license cannot be activated on this computer."), license.Id);

            // The licence's own TIAConnect policy also applies when a parent product resolves it.
            var versionProduct = license.Product != null && Services.LegacyMinimumVersionPolicy.AppliesTo(license.Product.Name)
                ? license.Product : product;
            var minimumVersionReason = Services.LegacyMinimumVersionPolicy.Evaluate(
                versionProduct.Name, req.AppVersion, versionProduct.MinimumAllowedVersion);
            if (minimumVersionReason != null)
            {
                // A version declaration cannot bypass a ban or trigger paid auto-unban.
                if (hwidBanned)
                    return await PersistLegacyRefusalAsync(legacyHistory, ActivationJsonFailure("BANNED", "Access denied by server"));
                return await PersistLegacyRefusalAsync(legacyHistory,
                    MinimumVersionRefusal(versionProduct, minimumVersionReason, license.Id, false, req.AppVersion));
            }

            // Vérification de version
            if (!IsVersionAllowed(req.AppVersion, license.AllowedVersions))
            {
                TagActivationFailure("VERSION_NOT_ALLOWED");
                _logger.LogWarning("Activation refused: version not allowed for license {LicenseId}.", license.Id);
                return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(string.Format(_localizer["Api_VersionNotAllowed"].Value, req.AppVersion)));
            }

            // --- VÉRIFICATION PARTENAIRE ---
            bool isResellerLicense = !string.IsNullOrWhiteSpace(license.PartnerCode);
            if (isResellerLicense)
            {
                var partnerExists = await _db.ResellerPartners.AnyAsync(p => p.Code == license.PartnerCode);
                var partner = partnerExists
                    ? await _db.ResellerPartners.FirstOrDefaultAsync(p => p.Code == license.PartnerCode && p.IsActive)
                    : null;
                if (partner == null)
                {
                    if (!partnerExists)
                        _logger.LogError("Activation refused: partner configuration is missing for license {LicenseId}.", license.Id);
                    else
                        _logger.LogError("Activation refused: partner is disabled for license {LicenseId}.", license.Id);
                    TagActivationFailure("PARTNER_INVALID");
                    return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(_localizer["Api_LicenseDisabled"].Value));
                }
            }

            // --- VÉRIFICATION EMAIL ---
            bool isAnonymousType = license.Type?.AllowAnonymous == true;
            bool licenseHasEmail = !string.IsNullOrWhiteSpace(license.CustomerEmail);
            bool requestHasEmail = !string.IsNullOrWhiteSpace(req.CustomerEmail);

            if (isResellerLicense)
            {
                // Reseller license: email is optional, just capture it if provided
                if (requestHasEmail && !licenseHasEmail)
                {
                    license.CustomerEmail = req.CustomerEmail!.Trim();
                    if (!string.IsNullOrWhiteSpace(req.CustomerName))
                        license.CustomerName = req.CustomerName.Trim();
                }
            }
            else if (licenseHasEmail && requestHasEmail)
            {
                // Licence avec email : vérifier la correspondance
                if (!string.Equals(license.CustomerEmail.Trim(), req.CustomerEmail!.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    TagActivationFailure("EMAIL_MISMATCH");
                    _logger.LogWarning("Activation refused: customer identity mismatch for license {LicenseId}.", license.Id);
                    return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(_localizer["Api_EmailMismatch"].Value));
                }
            }
            else if (!licenseHasEmail && isAnonymousType)
            {
                // Licence anonyme sans email : l'email est obligatoire pour la réclamer
                if (!requestHasEmail)
                {
                    TagActivationFailure("EMAIL_REQUIRED");
                    _logger.LogWarning("Activation refused: customer identity is required for license {LicenseId}.", license.Id);
                    return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(_localizer["Api_EmailRequiredAnonymous"].Value));
                }

                // Vérification syntaxe + MX
                if (!IsValidEmailSyntax(req.CustomerEmail!))
                {
                    TagActivationFailure("EMAIL_INVALID");
                    return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(_localizer["Api_InvalidEmail"].Value));
                }
                if (!HasValidMxRecord(req.CustomerEmail!))
                {
                    TagActivationFailure("EMAIL_DOMAIN_INVALID");
                    _logger.LogWarning("Activation refused: customer email domain is invalid for license {LicenseId}.", license.Id);
                    return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(_localizer["Api_InvalidEmailDomain"].Value));
                }

                // Associer l'email et le nom à la licence
                license.CustomerEmail = req.CustomerEmail!.Trim();
                if (!string.IsNullOrWhiteSpace(req.CustomerName))
                    license.CustomerName = req.CustomerName.Trim();

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = "CLAIMED",
                    Details = $"Clé anonyme réclamée par {req.CustomerEmail}",
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
            }

            if (hwidBanned)
            {
                if (!Services.SecurityService.IsPaidLicenseEligibleForAutoUnban(license, DateTime.UtcNow))
                    return await PersistLegacyRefusalAsync(legacyHistory, ActivationJsonFailure("BANNED", "Access denied by server"));

                var autoUnban = await _security.TryAutoUnbanForPaidLicenseAsync(
                    _db,
                    req.HardwareId,
                    license.ProductId);
                if (!autoUnban.CanProceed)
                    return await PersistLegacyRefusalAsync(legacyHistory, ActivationJsonFailure(
                        "BANNED",
                        autoUnban.PermanentBan ? "Access permanently denied" : "Access denied by server"));

                hwidBanned = false;
                deferredAutoUnbanNotification = autoUnban.Notification;
            }

            // --- GESTION MULTI-POSTES (SEATS) ---
            var existingSeat = await _db.LicenseSeats.FirstOrDefaultAsync(s => s.LicenseId == license.Id && s.HardwareId == authoritativeHardwareId && s.IsActive);
            
            if (existingSeat != null)
            {
                // Poste déjà connu : On met à jour la date de passage
                existingSeat.LastCheckInAt = DateTime.UtcNow;
                if (!string.IsNullOrEmpty(req.AppVersion)) existingSeat.AppVersion = req.AppVersion;
                // TKT-003404: refresh the PC name when it changed, never erase it.
                Services.SeatMachineName.Apply(existingSeat, req.MachineEvidence);
                license.HardwareId = authoritativeHardwareId;
                license.ActivationDate = existingSeat.FirstActivatedAt;
                var resolvedVersion = req.AppVersion ?? existingSeat.AppVersion ?? "Unknown";
                license.RecoveryCount++;
                TagLog(req, "RECOVERY");
                _logger.LogInformation("License recovery succeeded for license {LicenseId}.", license.Id);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Recovery,
                    Details = string.Format(_localizer["Licenses_Action_Activated"].Value, authoritativeHardwareId, resolvedVersion),
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
            }
            else
            {
                // TKT-002475: the publisher-owned setting refuses every new seat admission by key
                // (first activation, identifier switch and automatic switch) while recoveries of an
                // already-active seat keep working above. No seat or quota write happens on refusal.
                if (await Services.LicenseKeyActivationChecker.IsDisabledAsync(_db, license.Id, HttpContext.RequestAborted))
                {
                    _logger.LogWarning(
                        "Activation refused: key activation is disabled for license {LicenseId}.",
                        license.Id);
                    // Never pass the licence as commercial revocation target: this refusal keeps it active.
                    return await PersistLegacyRefusalAsync(legacyHistory, KeyActivationDisabledFailure());
                }

                var newActivationsDisabled = RejectIfNewActivationsDisabled(license.Type);
                if (newActivationsDisabled != null)
                    return await PersistLegacyRefusalAsync(legacyHistory, newActivationsDisabled);

                var freemiumAlreadyConsumed = await RejectIfSingleUseHardwareAlreadyConsumedAsync(license.ProductId, license.Type, authoritativeHardwareId, license.Id);
                if (freemiumAlreadyConsumed != null)
                    return await PersistLegacyRefusalAsync(legacyHistory, freemiumAlreadyConsumed);

                // LEGACY-EXPIRY(TKT-001430, 2026-12-31): identifier switch, remove by 31/12/2026.
                if (req.PreviousHardwareId != null)
                {
                    var switchRefusal = await DetachPreviousHardwareIdAsync(license, req.PreviousHardwareId, authoritativeHardwareId, cleanKey);
                    if (switchRefusal != null)
                        return await PersistLegacyRefusalAsync(legacyHistory, switchRefusal);
                }

                // TKT-001510: an explicit PreviousHardwareId keeps its existing migration
                // contract. Ordinary single-seat activation uses the shared change authority.
                if (req.PreviousHardwareId == null && license.MaxSeats == 1)
                {
                    try
                    {
                        // Prepare reloads current authority under row locks. Preserve only
                        // the contact changes already validated above, not stale policy fields.
                        var customerEmail = license.CustomerEmail;
                        var customerName = license.CustomerName;
                        var customerEmailChanged = customerEmail != _db.Entry(license).Property(row => row.CustomerEmail).OriginalValue;
                        var customerNameChanged = customerName != _db.Entry(license).Property(row => row.CustomerName).OriginalValue;
                        var automaticSwitch = await Services.AutomaticSeatSwitch.PrepareAsync(
                            _db, license, authoritativeHardwareId, DateTime.UtcNow, HttpContext.RequestAborted);
                        if (automaticSwitch != null)
                        {
                            if (customerEmailChanged) license.CustomerEmail = customerEmail;
                            if (customerNameChanged) license.CustomerName = customerName;
                            await Services.AutomaticSeatSwitch.CompleteAsync(
                                _db, license, automaticSwitch, authoritativeHardwareId,
                                HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                                HttpContext.RequestAborted);
                        }
                    }
                    catch (Services.DistributionOperationException exception)
                    {
                        // TKT-003751: the switch is refused as an activation on one PC too many
                        // today, never as an unlink; same code and message as the main new-seat check.
                        if (exception.ReasonCode == "seat_change_quota_exhausted")
                        {
                            TagActivationFailure("MAX_DAILY_ACTIVATIONS_REACHED");
                            return await PersistLegacyRefusalAsync(legacyHistory,
                                BadRequest(string.Format(_localizer["Api_MaxDailyActivationsReached"].Value,
                                    Services.SeatChangeQuota.GetDailyLimit(license))));
                        }
                        TagActivationFailure(exception.ErrorCode == "entitlement_ineligible"
                            ? "LICENSE_DISABLED" : "AUTOMATIC_SEAT_SWITCH_UNAVAILABLE");
                        return await PersistLegacyRefusalAsync(legacyHistory,
                            DistributionRefusalResult(exception));
                    }
                }

                // Nouveau poste : On vérifie si on a encore de la place
                // Count and hardware evidence come from the same statement snapshot; the
                // predicate and existing lock scope remain unchanged.
                var observedActiveSeats = await _db.LicenseSeats.AsNoTracking()
                    .Where(s => s.LicenseId == license.Id && s.IsActive).ToListAsync();
                var currentSeatsCount = observedActiveSeats.Count;
                legacyHistory.Snapshot = Services.LicenseDecisionHistoryWriter.WithObservedActiveSeats(
                    legacyHistory.Snapshot, observedActiveSeats, authoritativeHardwareId);

                if (currentSeatsCount >= license.MaxSeats)
                {
                    TagActivationFailure("SEAT_LIMIT");
                    _logger.LogWarning("Activation refused: seat limit reached for license {LicenseId}.", license.Id);
                    return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(string.Format(_localizer["Api_MaxActivationsReached"].Value, license.MaxSeats)));
                }

                // TKT-003751 (owner rule): a key may not be activated on more than N different
                // identifiers in one UTC day, N = MaxActivationsPerDay x seats read live from the type.
                // It applies to every seat count; an identifier already activated today and the last
                // PC of the key are always accepted. Automatic switch and identifier switch above
                // already ran the same check before releasing anything.
                var maxPerDay = Services.SeatChangeQuota.GetDailyLimit(license);
                if (maxPerDay > 0)
                {
                    var quotaNow = DateTime.UtcNow;
                    var dailyQuota = await Services.SeatChangeQuota.GetStatusAsync(_db, license, quotaNow, HttpContext.RequestAborted);
                    legacyHistory.Snapshot = legacyHistory.Snapshot with { ActivationsToday = dailyQuota.UsedToday };
                    if (await Services.SeatChangeQuota.IsActivationRefusedAsync(
                            _db, license, authoritativeHardwareId, quotaNow, HttpContext.RequestAborted))
                    {
                        TagActivationFailure("MAX_DAILY_ACTIVATIONS_REACHED");
                        _logger.LogWarning("Activation refused: daily activation limit reached for license {LicenseId}.", license.Id);
                        return await PersistLegacyRefusalAsync(legacyHistory, BadRequest(string.Format(_localizer["Api_MaxDailyActivationsReached"].Value, maxPerDay)));
                    }
                }

                var acceptedAtUtc = DateTime.UtcNow;
                await Services.PersonalDayPassActivationService.StartPendingAsync(
                    _db,
                    license,
                    acceptedAtUtc,
                    HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                    HttpContext.RequestAborted);
                var newSeat = license.Seats
                    .Where(candidate => !candidate.IsActive
                        && string.Equals(candidate.HardwareId, authoritativeHardwareId, StringComparison.Ordinal))
                    .OrderByDescending(candidate => candidate.FirstActivatedAt)
                    .FirstOrDefault();
                if (newSeat == null)
                {
                    newSeat = new LicenseSeat
                    {
                        LicenseId = license.Id,
                        HardwareId = authoritativeHardwareId,
                        FirstActivatedAt = acceptedAtUtc
                    };
                    _db.LicenseSeats.Add(newSeat);
                }
                newSeat.IsActive = true;
                newSeat.UnlinkedAt = null;
                newSeat.LastCheckInAt = acceptedAtUtc;
                newSeat.AppVersion = req.AppVersion;
                // TKT-003404: a resumed seat keeps its previous name unless the evidence carries one.
                Services.SeatMachineName.Apply(newSeat, req.MachineEvidence);

                _db.LicenseHistories.Add(new LicenseHistory {
                    LicenseId = license.Id,
                    Action = HistoryActions.Activated,
                    Details = string.Format(_localizer["Licenses_Action_Activated"].Value, authoritativeHardwareId, req.AppVersion ?? "Unknown"),
                    PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });

                // Pour la compatibilité v1, on garde le champ principal aligné sur le premier poste actif.
                if (currentSeatsCount == 0 || string.IsNullOrEmpty(license.HardwareId))
                {
                    license.HardwareId = authoritativeHardwareId;
                    license.ActivationDate = newSeat.FirstActivatedAt;

                    // Démarrer le décompte de validité à la première activation
                    if (license.ValidityDays.HasValue && !license.ExpirationDate.HasValue)
                    {
                        license.ExpirationDate = DateTime.UtcNow.AddDays(license.ValidityDays.Value);
                    }
                }

                _logger.LogInformation("New seat activated ({Count}/{Max}) for license {LicenseId}.", currentSeatsCount + 1, license.MaxSeats, license.Id);

                deferredActivationNotification = new Services.SecurityService.DeferredNotification(
                    Services.NotificationService.Triggers.LicenseActivated,
                    "✅ Licence Activée",
                    $"Produit: {product.Name}\nType: {license.Type?.Name ?? license.Type?.Slug ?? "Standard"}\nLicence: {license.Id}\nPoste: {currentSeatsCount + 1}/{license.MaxSeats}");
            }

            // Mise à jour du nom client uniquement si la licence n'en avait pas (anonyme réclamée)
            // L'email est géré dans la section VÉRIFICATION EMAIL ci-dessus, on ne l'écrase jamais
            if (string.IsNullOrWhiteSpace(license.CustomerName) && !string.IsNullOrWhiteSpace(req.CustomerName))
                license.CustomerName = req.CustomerName.Trim();

            AddHardwareIdV2Observation(license, product, "ACTIVATE", req);
            var acceptedDecision = await AddLegacyDecisionAsync(legacyHistory, "accepted", "accepted", 200, HttpContext.RequestAborted);
            legacyHistory.AcceptedEventId = acceptedDecision.Id;
            await _db.SaveChangesAsync();

            // Enforcement : un HWID ne peut être actif que sur une seule licence par produit
            try
            {
                await _seatCleanup.UnlinkHwidFromOtherProductLicensesAsync(
                    authoritativeHardwareId, license.Id, license.ProductId, redactSensitiveDetails: false);
            }
            catch (Services.DistributionOperationException exception)
            {
                return DistributionRefusalResult(exception);
            }

            // Génération du fichier signé
            var features = BuildFeatures(license.Type?.CustomParams);

            try
            {
                // Seat ownership remains canonical, but an authenticated alias caller needs a
                // licence bound to the exact identifier it presented. Direct callers retain the
                // authoritative seat identifier used by the historical path.
                var signingHardwareId = hardwareResolution.UsedAlias || compatibilityAliasUsed
                    ? hardwareResolution.SubmittedHardwareId
                    : authoritativeHardwareId;
                var signedLicenseString = _signedLicenseFiles.Generate(license, signingHardwareId, features);
                if (activationTransaction != null)
                    await activationTransaction.CommitAsync();
                if (deferredAutoUnbanNotification != null)
                {
                    _logger.LogWarning(
                        "AUTO-UNBAN PAID LICENSE committed for {HardwareId}: {Title}",
                        req.HardwareId,
                        deferredAutoUnbanNotification.Title);
                    _notifier.Notify(
                        deferredAutoUnbanNotification.Trigger,
                        deferredAutoUnbanNotification.Title,
                        deferredAutoUnbanNotification.Message);
                }
                if (deferredActivationNotification != null)
                {
                    _notifier.Notify(
                        deferredActivationNotification.Trigger,
                        deferredActivationNotification.Title,
                        deferredActivationNotification.Message + BuildAcceptedDecisionNotificationContext(legacyHistory));
                }
                if (existingSeat == null)
                    await _hwidReuseAlerts.CheckAndNotifyAsync(license.ProductId, authoritativeHardwareId, license.Id);
                return Ok(new { LicenseFile = signedLicenseString });
            }
            catch (Exception ex) when (Services.AssignmentRefusals.TryTranslate(ex, out var assignmentRefusal))
            {
                // TKT-004085: the database refused the write or the commit itself, so nothing was committed.
                return AssignmentTriggerRefusal(ex, assignmentRefusal, "key_activation");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la signature de la licence pour '{AppName}'", req.AppName);
                return StatusCode(500, _localizer["Api_InternalErrorSignature"].Value);
            }
        }

        /// <summary>
        /// Single source of the licence status shared by <see cref="CheckStatus"/> and the clone guard reactivation
        /// (TKT-003615, review 2439): canonical identifier, product, machine identity, hardware and component bans,
        /// licence lookup, legacy alias resolution, revocation, expiry, seat ownership, minimum version, single use per
        /// hardware identifier (Freemium) and disabled new activations, in this exact order.
        /// </summary>
        /// <param name="req">Status request; <c>LicenseKey</c>, <c>HardwareId</c> and <c>AppName</c> are required.</param>
        /// <param name="endpoint">Audit tag and machine-identity endpoint label, <see cref="Services.MachineEvidenceEndpoints.Check"/> or <see cref="Services.MachineEvidenceEndpoints.CloneGuardReactivate"/>.</param>
        /// <param name="evaluation">Filled with the product, licence, authoritative identifier, alias resolution and logical status when the method returns <see langword="null"/>.</param>
        /// <returns>
        /// The early answer of a refusal that ends the request before any status-dependent write (400 non-canonical
        /// identifier, 404 unknown product or key, 200 <c>DEVICE_REFUSED</c>, <c>REVOKED</c>, <c>UPDATE_REQUIRED</c>,
        /// <c>HARDWARE_AUTHORITY_REFUSED</c>, minimum-version refusal); <see langword="null"/> when a logical status was
        /// computed, which may itself be a refusal such as <c>FREEMIUM_HWID_ALREADY_CONSUMED</c>.
        /// </returns>
        /// <remarks>
        /// Any route that can sign a licence file for a check-like request must call this method and sign only when the
        /// status is <c>VALID</c>, so the two routes can never diverge again (the first reactivation route skipped the
        /// single-use refusal). Side effects are those the check always had: machine-identity observation, background
        /// component fingerprint upsert, audit tags.
        /// </remarks>
        private async Task<IActionResult?> EvaluateStatusAsync(ActivationRequest req, string endpoint, StatusEvaluation evaluation)
        {
            if (!Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(req.HardwareId))
                return RejectInvalidPrimaryHardwareId();

            var cleanKey = req.LicenseKey.Trim().ToUpper();
            TagLog(req, endpoint);

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                return NotFound(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            var checkIdentity = await _machineIdentityObservations.ObserveAsync(
                product.Id, req.HardwareId, req.SystemUuid, req.MachineEvidence, endpoint, req.AppVersion,
                HttpContext.RequestAborted);
            if (checkIdentity.IsRefused)
            {
                TagActivationFailure("DEVICE_REFUSED");
                return Ok(new
                {
                    isSuccess = true,
                    status = "DEVICE_REFUSED",
                    supportCode = checkIdentity.SupportCode,
                    errorMessage = DeviceRefusedMessage(checkIdentity)
                });
            }

            // For CheckStatus, return a logical status instead of 403 so the IP scoring middleware
            // doesn't penalize heartbeat callers. Version-enforcement bans are not license revocations.
            var hwidBan = await _security.GetActiveHardwareBanAsync(req.HardwareId, product.Id);
            if (hwidBan != null)
            {
                if (hwidBan.BanCategory == BannedHardwareId.Categories.OutdatedVersion)
                    return Ok(new { isSuccess = true, status = "UPDATE_REQUIRED", errorMessage = "Update required by server" });

                return Ok(new { isSuccess = true, status = "REVOKED", errorMessage = "Access denied by server" });
            }

            if (req.ComponentFingerprints != null)
            {
                var (compBanned, compType, compReason) = await _security.IsComponentBannedAsync(req.ComponentFingerprints);
                if (compBanned) return Ok(new { isSuccess = true, status = "REVOKED", errorMessage = "Access denied by server" });
                _ = Task.Run(async () => { try { await _fingerprint.UpsertFingerprintAsync(req.HardwareId, req.ComponentFingerprints); } catch { } });
            }

            var checkProductIds = await GetProductHierarchyIds(product.Id);
            var license = await _db.Licenses
                .Include(l => l.Type)
                    .ThenInclude(t => t!.CustomParams)
                .Include(l => l.Product)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && checkProductIds.Contains(l.ProductId));

            if (license == null)
            {
                TagActivationFailure("INVALID_LICENSE_KEY");
                return NotFound(_localizer["Api_LicenseNotFound"].Value);
            }

            var hardwareResolution = await _hardwareAuthorityAliases.ResolveAsync(
                _db,
                license.ProductId,
                license.Id,
                req.HardwareId,
                Services.HardwareAuthorityResolutionIntent.StatusCheck,
                HttpContext.RequestAborted);
            var authoritativeHardwareId = hardwareResolution.EffectiveHardwareId;
            var compatibilityAliasUsed = false;
            if (hardwareResolution.Refused)
            {
                var compatibilityHardwareId = await TryResolveLoggedCompatibilityAliasAsync(
                    license, hardwareResolution);
                if (compatibilityHardwareId == null)
                {
                    _logger.LogWarning(
                        "Hardware authority refusal retained for alias {AliasId}, licence {LicenseId}; reason {RefusalReason}.",
                        hardwareResolution.AliasId,
                        license.Id,
                        hardwareResolution.RefusalReason);
                    TagActivationFailure("HARDWARE_AUTHORITY_REFUSED");
                    return Ok(new
                    {
                        isSuccess = true,
                        status = "HARDWARE_AUTHORITY_REFUSED",
                        errorMessage = "The legacy hardware identity is no longer accepted. Use the authoritative V2 identity."
                    });
                }
                authoritativeHardwareId = compatibilityHardwareId;
                compatibilityAliasUsed = true;
            }
            if (hardwareResolution.UsedAlias || compatibilityAliasUsed)
            {
                var authoritativeBan = await _security.GetActiveHardwareBanAsync(authoritativeHardwareId, license.ProductId);
                if (authoritativeBan != null)
                {
                    if (authoritativeBan.BanCategory == BannedHardwareId.Categories.OutdatedVersion)
                        return Ok(new { isSuccess = true, status = "UPDATE_REQUIRED", errorMessage = "Update required by server" });

                    return Ok(new { isSuccess = true, status = "REVOKED", errorMessage = "Access denied by server" });
                }
            }

            string status = "VALID";
            if (!license.IsActive || license.RevokedAt != null) status = "REVOKED";
            else if (license.ExpirationDate.HasValue && DateTime.UtcNow > license.ExpirationDate.Value) status = "EXPIRED";
            else
            {
                // Vérifier via les seats (multi-postes) au lieu du champ legacy HardwareId.
                var hasAnySeat = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id);
                var hasAnyActiveSeat = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.IsActive);
                if (hasAnyActiveSeat)
                {
                    var hasSeatForHwid = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.HardwareId == authoritativeHardwareId && s.IsActive);
                    if (!hasSeatForHwid)
                    {
                        var hasInactiveSeatForHwid = await _db.LicenseSeats.AnyAsync(s => s.LicenseId == license.Id && s.HardwareId == authoritativeHardwareId && !s.IsActive);
                        status = hasInactiveSeatForHwid ? "HARDWARE_NOT_ACTIVATED" : "HARDWARE_MISMATCH";
                    }
                }
                else if (hasAnySeat)
                    status = "HARDWARE_NOT_ACTIVATED";
                else if (string.IsNullOrEmpty(license.HardwareId))
                    status = "REQUIRES_ACTIVATION";
                else if (license.HardwareId != authoritativeHardwareId)
                    status = "HARDWARE_MISMATCH";
            }

            string? errorMessage = null;
            var versionProduct = license.Product != null && Services.LegacyMinimumVersionPolicy.AppliesTo(license.Product.Name)
                ? license.Product : product;
            var minimumVersionReason = Services.LegacyMinimumVersionPolicy.Evaluate(
                versionProduct.Name, req.AppVersion, versionProduct.MinimumAllowedVersion);
            if (status is "VALID" or "REQUIRES_ACTIVATION" && minimumVersionReason != null)
                return MinimumVersionRefusal(versionProduct, minimumVersionReason, license.Id, true, req.AppVersion);

            if (status == "VALID" && !Services.LegacyMinimumVersionPolicy.AppliesTo(product.Name)
                && IsVersionBelow(req.AppVersion, product.MinimumAllowedVersion))
            {
                status = "UPDATE_REQUIRED";
                errorMessage = "Update required by server";
                TagActivationFailure("UPDATE_REQUIRED");
                _logger.LogWarning(
                    "Check requires update: HWID {HardwareId}, app {AppName}, version {Version}, minimum {MinimumAllowedVersion}, license {LicenseId}.",
                    req.HardwareId,
                    product.Name,
                    req.AppVersion ?? "Unknown",
                    product.MinimumAllowedVersion,
                    license.Id);
            }

            if (status is "VALID" or "REQUIRES_ACTIVATION"
                && EnforcesSingleUsePerHardwareId(license.Type)
                && await HasConsumedLicenseTypeOnHardwareAsync(license.ProductId, license.LicenseTypeId, authoritativeHardwareId, license.Id))
            {
                status = "FREEMIUM_HWID_ALREADY_CONSUMED";
                errorMessage = "Freemium access has already been used on this machine.";
                TagActivationFailure("FREEMIUM_HWID_ALREADY_CONSUMED");
                _logger.LogWarning(
                    "Check Freemium refused: HWID {HardwareId} has already consumed a Freemium license for product {ProductId}. LicenseId={LicenseId}",
                    req.HardwareId,
                    license.ProductId,
                    license.Id);
            }

            if (status == "REQUIRES_ACTIVATION" && DisablesNewActivations(license.Type))
            {
                status = "LICENSE_TYPE_NEW_ACTIVATIONS_DISABLED";
                errorMessage = "New activations are no longer available for this license type.";
                TagActivationFailure("LICENSE_TYPE_NEW_ACTIVATIONS_DISABLED");
                _logger.LogWarning(
                    "Check refused: new activations are disabled for license type {LicenseTypeSlug} ({LicenseTypeId}). HWID={HardwareId}, LicenseId={LicenseId}",
                    license.Type?.Slug,
                    license.Type?.Id,
                    req.HardwareId,
                    license.Id);
            }

            evaluation.Product = product;
            evaluation.License = license;
            evaluation.AuthoritativeHardwareId = authoritativeHardwareId;
            evaluation.HardwareResolution = hardwareResolution;
            evaluation.CompatibilityAliasUsed = compatibilityAliasUsed;
            evaluation.Status = status;
            evaluation.ErrorMessage = errorMessage;
            return null;
        }

        /// <summary>
        /// Result of <see cref="EvaluateStatusAsync"/> when no early answer was returned. Mutable on purpose: the check
        /// keeps updating <see cref="Status"/> and <see cref="ErrorMessage"/> with the clone guard decision.
        /// </summary>
        private sealed class StatusEvaluation
        {
            /// <summary>Gets or sets the product matched by name.</summary>
            public Product Product { get; set; } = null!;
            /// <summary>Gets or sets the licence of the key, with type, custom parameters, product and seats loaded and tracked.</summary>
            public License License { get; set; } = null!;
            /// <summary>Gets or sets the identifier the status was computed for (after alias resolution).</summary>
            public string AuthoritativeHardwareId { get; set; } = string.Empty;
            /// <summary>Gets or sets the alias resolution, used to choose the identifier a licence file is signed for.</summary>
            public Services.HardwareAuthorityResolution HardwareResolution { get; set; } = null!;
            /// <summary>Gets or sets whether a logged compatibility alias replaced a refused one.</summary>
            public bool CompatibilityAliasUsed { get; set; }
            /// <summary>Gets or sets the logical status (<c>VALID</c> or a refusal status).</summary>
            public string Status { get; set; } = string.Empty;
            /// <summary>Gets or sets the message that goes with a refusal status, or <see langword="null"/>.</summary>
            public string? ErrorMessage { get; set; }
            /// <summary>Gets the identifier a licence file must be signed for: the submitted one when an alias was used.</summary>
            public string SigningHardwareId => HardwareResolution.UsedAlias || CompatibilityAliasUsed
                ? HardwareResolution.SubmittedHardwareId
                : AuthoritativeHardwareId;
        }

        /// <summary>
        /// Returns the current license status for the submitted or resolved canonical authority and refreshes a valid signed license for that same authority.
        /// Non-canonical primary input is rejected without normalization, while known divergent aliases return HARDWARE_AUTHORITY_REFUSED and never fall back to direct legacy identity.
        /// Ineligible TIAConnect versions return no signed licence, independently of telemetry and commercial tier.
        /// </summary>
        /// <param name="req">Status request whose hardware identity is checked against submitted and canonical bans.</param>
        /// <returns>An HTTP status contract with a centralized signed license when the logical status is VALID.</returns>
        /// <remarks>Security, revocation, expiry and hardware ownership retain priority. Missing client versions are never inferred from historical seats. After the ban and device refusals, the caller's own active seat takes the PC display name from MachineEvidence when it changed (TKT-003404); the check never creates a seat and never erases a stored name.</remarks>
        /// <param name="cloneGuards">Single-use control token authority (TKT-003615); used only when <see cref="ActivationRequest.CloneGuard"/> is present and the status is VALID, and then may turn the answer into the logical status <c>DUPLICATE_DETECTED</c> without licence file.</param>
        [HttpPost("check")]
        public async Task<IActionResult> CheckStatus(
            [FromBody] ActivationRequest req,
            [FromServices] Services.CloneGuard.SeatCloneGuardService cloneGuards)
        {
            var evaluation = new StatusEvaluation();
            var refusal = await EvaluateStatusAsync(req, Services.MachineEvidenceEndpoints.Check, evaluation);
            if (refusal != null)
                return refusal;
            var product = evaluation.Product;
            var license = evaluation.License;
            var authoritativeHardwareId = evaluation.AuthoritativeHardwareId;
            var hardwareResolution = evaluation.HardwareResolution;
            var compatibilityAliasUsed = evaluation.CompatibilityAliasUsed;
            var status = evaluation.Status;
            var errorMessage = evaluation.ErrorMessage;
            var cleanKey = req.LicenseKey.Trim().ToUpper();

            // TKT-003615: the single-use control token is evaluated last, only for a guard-aware client whose status is
            // VALID on an active seat, so every existing refusal keeps priority and consumes no token. A collision
            // suspends this copy only (no licence file, logical status, HTTP 200: never a ban nor a threat score).
            var cloneGuardResponse = await EvaluateCloneGuardAsync(
                req, license, authoritativeHardwareId, status, cloneGuards, HttpContext.RequestAborted);
            if (cloneGuardResponse?.Outcome == Services.CloneGuard.CloneGuardOutcomes.DuplicateDetected)
            {
                status = DuplicateDetectedStatus;
                errorMessage = DuplicateDetectedMessage;
                TagActivationFailure(DuplicateDetectedStatus);
            }

            // Générer un fichier de licence frais avec les paramètres actuels du LicenseType
            string? licenseFile = null;
            if (status == "VALID")
            {
                try
                {
                    var signingHardwareId = hardwareResolution.UsedAlias || compatibilityAliasUsed
                        ? hardwareResolution.SubmittedHardwareId
                        : authoritativeHardwareId;
                    licenseFile = _signedLicenseFiles.Generate(
                        license,
                        signingHardwareId,
                        BuildFeatures(license.Type?.CustomParams));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Impossible de generer le fichier de licence frais lors du check pour '{LicenseKey}'", cleanKey);
                }
            }

            var addedObservation = HasHardwareIdV2Observation(req.HardwareIdV2)
                && !await HasRecentHardwareIdV2ObservationAsync(license.Id, req.HardwareId, req.HardwareIdV2!);
            if (addedObservation)
            {
                AddHardwareIdV2Observation(license, product, "CHECK", req);
            }
            // TKT-003404: the periodic check refreshes the PC name of the caller's active seat only. It never creates
            // a seat, never touches another machine's seat, and runs after the ban and device refusals above, which
            // return early, so a refused caller cannot rename a seat. No evidence means no change.
            var checkedSeat = license.Seats.FirstOrDefault(seat => seat.IsActive
                && string.Equals(seat.HardwareId, authoritativeHardwareId, StringComparison.Ordinal));
            var renamedSeat = checkedSeat != null && Services.SeatMachineName.Apply(checkedSeat, req.MachineEvidence);
            if (addedObservation || hardwareResolution.UsedAlias || renamedSeat)
                await _db.SaveChangesAsync();

            // TKT-003615: the clone guard member is serialized only for a request that carried one, so the answer to an
            // installed version (and to the native heartbeat) keeps exactly its historical shape.
            if (cloneGuardResponse == null)
                return Ok(new { Status = status, LicenseFile = licenseFile, ErrorMessage = errorMessage });
            return Ok(new { Status = status, LicenseFile = licenseFile, ErrorMessage = errorMessage, CloneGuard = cloneGuardResponse });
        }

        public class ResetRequest
        {
            public required string LicenseKey { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; } // Identifiant unique du produit
        }

        public class ResetConfirmRequest : ResetRequest
        {
            public required string ResetCode { get; set; }
        }

        [HttpPost("reset-request")]
        public async Task<IActionResult> RequestReset([FromBody] ResetRequest req)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey;
            HttpContext.Items[LogKeys.Endpoint] = "RESET_REQUEST";

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            var resetProductIds = await GetProductHierarchyIds(product.Id);
            var cleanKey = req.LicenseKey.Trim().ToUpper();            var license = await _db.Licenses.FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && resetProductIds.Contains(l.ProductId));
            if (license == null) return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            
            HttpContext.Items[LogKeys.HardwareId] = license.HardwareId; // On logge le HWID actuel qui va etre delie

            if (string.IsNullOrEmpty(license.CustomerEmail)) return BadRequest(_localizer["Api_NoEmail"].Value);

            // Génération Code (6 chiffres sécure)
            var code = System.Security.Cryptography.RandomNumberGenerator.GetInt32(100000, 999999).ToString();
            license.ResetCode = code;
            license.ResetCodeExpiry = DateTime.UtcNow.AddMinutes(15);

            await _db.SaveChangesAsync();

            try
            {
                await _mailer.SendResetCodeEmailAsync(license.CustomerEmail, license.CustomerName, product.Name, code);
                return Ok(new { Message = _localizer["Api_CodeSent"].Value });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur envoi email de reset pour {LicenseKey}", req.LicenseKey);
                return StatusCode(500, _localizer["Api_EmailError"].Value);
            }
        }

        /// <summary>
        /// Consumes an authorized reset code and atomically releases all active commercial seat assignments.
        /// Never counted nor refused by the daily hardware quota of
        /// <see cref="Services.SeatChangeQuota"/> (TKT-003751), which limits only activations on new identifiers.
        /// </summary>
        [HttpPost("reset-confirm")]
        public async Task<IActionResult> ConfirmReset([FromBody] ResetConfirmRequest req)
        {
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = req.LicenseKey;
            HttpContext.Items[LogKeys.Endpoint] = "RESET_CONFIRM";

            await using var releaseTransaction = await Services.SeatRuntimeReleaseAuthority.BeginAsync(_db, HttpContext.RequestAborted);
            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null) return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));

            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;

            var confirmProductIds = await GetProductHierarchyIds(product.Id);
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            var license = await _db.Licenses
                .Include(l => l.Type)
                .Include(l => l.Seats)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && confirmProductIds.Contains(l.ProductId));

            if (license == null) return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);

            var activeSeats = license.Seats?.Where(seat => seat.IsActive).ToArray() ?? [];
            Services.SeatRuntimeReleaseAuthority.SeatReleaseScope releaseScope;
            try
            {
                releaseScope = await Services.SeatRuntimeReleaseAuthority.PrepareAsync(
                    _db, license.ProductId, license, activeSeats, DateTime.UtcNow, HttpContext.RequestAborted);
            }
            catch (Services.DistributionOperationException exception)
            {
                return DistributionRefusalResult(exception);
            }
            var now = releaseScope.ObservedAtUtc;

            if (license.ResetCode == null || license.ResetCodeExpiry < now ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(license.ResetCode),
                    Encoding.UTF8.GetBytes(req.ResetCode)))
            {
                return BadRequest(_localizer["Api_InvalidResetCode"].Value);
            }

            // TKT-003751 (owner rule): a reset releases seats and is never counted nor refused by
            // the daily hardware quota, which limits only activations on new identifiers.

            // Reset effectif
            license.HardwareId = null;
            license.ActivationDate = null;
            license.ResetCode = null; // Usage unique
            license.ResetCodeExpiry = null;
            license.RecoveryCount = 0; // On reset le compteur d'abus

            if (license.Seats != null) 
            {
                foreach (var seat in activeSeats)
                {
                    seat.IsActive = false;
                    seat.UnlinkedAt = now;
                    
                    _db.LicenseHistories.Add(new LicenseHistory {
                        LicenseId = license.Id,
                        Action = HistoryActions.UnlinkedApi,
                        Details = string.Format(_localizer["Licenses_Action_UnlinkedApiResetCode"].Value, seat.HardwareId),
                        PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                    });
                }

                SyncLegacyHardwareStateFromSeats(license);
            }

            try
            {
                await Services.SeatRuntimeReleaseAuthority.CompleteAsync(
                    _db, releaseScope, activeSeats, HttpContext.RequestAborted);
            }
            catch (Services.DistributionOperationException exception)
            {
                return DistributionRefusalResult(exception);
            }
            if (releaseTransaction != null)
                await releaseTransaction.CommitAsync(HttpContext.RequestAborted);

            return Ok(new { Message = _localizer["Api_UnlinkSuccess"].Value });
        }

        public class DeactivateRequest
        {
            public required string LicenseKey { get; set; }
            public required string HardwareId { get; set; }
            public required string AppName { get; set; }
            public string? AppId { get; set; }
            public string? Source { get; set; }
            public string? DeactivationSource { get; set; }
            // LEGACY-EXPIRY(TKT-001430, 2026-12-31): ComponentFingerprints is sent only by pre-2.0 SDKs; remove by 31/12/2026.
            public Dictionary<string, string>? ComponentFingerprints { get; set; }
        }

        /// <summary>
        /// Atomically deactivates the proven canonical seat and ends its commercial assignment while preserving Runtime identity for later authenticated reactivation.
        /// Non-canonical primary input, alias divergence, compatibility retirement, and bans fail before any seat mutation.
        /// Never counted nor refused by the daily hardware quota (TKT-003751), which limits only activations on new identifiers.
        /// </summary>
        /// <param name="req">Deactivation request containing the submitted identity and audited source.</param>
        /// <returns>A success response only after the exact active canonical seat is deactivated and persisted.</returns>
        [HttpPost("deactivate")]
        public async Task<IActionResult> Deactivate([FromBody] DeactivateRequest req)
        {
            if (!Services.HardwareAuthorityAliasResolver.IsCanonicalHardwareId(req.HardwareId))
                return RejectInvalidPrimaryHardwareId();

            await using var releaseTransaction = await Services.SeatRuntimeReleaseAuthority.BeginAsync(_db, HttpContext.RequestAborted);
            var cleanKey = req.LicenseKey.Trim().ToUpper();
            var source = NormalizeDeactivationSource(req.Source, req.DeactivationSource);
            HttpContext.Items[LogKeys.AppName] = req.AppName;
            HttpContext.Items[LogKeys.LicenseKey] = cleanKey;
            HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
            HttpContext.Items[LogKeys.Endpoint] = "DEACTIVATE";
            HttpContext.Items["DeactivationSource"] = source;

            if (await _security.IsHardwareIdBannedAsync(req.HardwareId))
            {
                TagActivationFailure("BANNED");
                return StatusCode(403, "Access denied");
            }

            var product = await _db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
            if (product == null)
            {
                TagActivationFailure("APP_UNKNOWN");
                return BadRequest(string.Format(_localizer["Api_AppUnknown"].Value, req.AppName));
            }

            HttpContext.Items[LogKeys.AppName] = product.Name;

            var deactivateProductIds = await GetProductHierarchyIds(product.Id);
            var license = await _db.Licenses
                .Include(l => l.Seats)
                .Include(l => l.Type)
                .FirstOrDefaultAsync(l => l.LicenseKey.ToUpper() == cleanKey && deactivateProductIds.Contains(l.ProductId));

            if (license == null)
            {
                TagActivationFailure("INVALID_LICENSE_KEY");
                return BadRequest(_localizer["Api_InvalidLicenseKey"].Value);
            }

            var hardwareResolution = await _hardwareAuthorityAliases.ResolveAsync(
                _db,
                license.ProductId,
                license.Id,
                req.HardwareId,
                Services.HardwareAuthorityResolutionIntent.Deactivation,
                HttpContext.RequestAborted);
            var authoritativeHardwareId = hardwareResolution.EffectiveHardwareId;
            if (hardwareResolution.Refused)
            {
                TagActivationFailure("HARDWARE_AUTHORITY_REFUSED");
                return StatusCode(
                    StatusCodes.Status409Conflict,
                    "The legacy hardware identity is no longer accepted. Use the authoritative V2 identity.");
            }
            if (hardwareResolution.UsedAlias
                && await _security.IsHardwareIdBannedAsync(authoritativeHardwareId))
            {
                TagActivationFailure("BANNED");
                return StatusCode(403, "Access denied");
            }

            var seat = license.Seats?.FirstOrDefault(s => s.HardwareId == authoritativeHardwareId && s.IsActive);
            if (seat == null)
            {
                TagActivationFailure("SEAT_NOT_FOUND");
                return NotFound("Appareil non trouvé ou déjà délié.");
            }

            Services.SeatRuntimeReleaseAuthority.SeatReleaseScope releaseScope;
            try
            {
                releaseScope = await Services.SeatRuntimeReleaseAuthority.PrepareAsync(
                    _db, license.ProductId, license, [seat], DateTime.UtcNow, HttpContext.RequestAborted);
            }
            catch (Services.DistributionOperationException exception)
            {
                return DistributionRefusalResult(exception);
            }
            var now = releaseScope.ObservedAtUtc;
            if (await _security.IsHardwareIdBannedAsync(authoritativeHardwareId))
            {
                TagActivationFailure("BANNED");
                return StatusCode(403, "Access denied");
            }

            // TKT-003751 (owner rule): signing out or deactivating is never counted nor refused by
            // the daily hardware quota; only an activation on a new identifier can be refused.

            var seatAge = now - seat.FirstActivatedAt;
            if (seatAge < AnonymousDeactivationGuardWindow
                && !IsTrustedImmediateDeactivationSource(source))
            {
                _logger.LogWarning(
                    "Immediate deactivation refused for license {LicenseId}, HWID {HardwareId}, source {DeactivationSource}, seat age {SeatAgeSeconds}s.",
                    license.Id,
                    authoritativeHardwareId,
                    source,
                    Math.Round(seatAge.TotalSeconds));
                TagActivationFailure("DEACTIVATION_SOURCE_REQUIRED");
                return BadRequest(_localizer["Api_DeactivationTooRecentRequiresSource"].Value);
            }

            seat.IsActive = false;
            seat.UnlinkedAt = now;
            SyncLegacyHardwareStateFromSeats(license);

            _logger.LogInformation(
                "Client deactivation accepted for license {LicenseId}, HWID {HardwareId}, source {DeactivationSource}, seat age {SeatAgeSeconds}s.",
                license.Id,
                authoritativeHardwareId,
                source,
                Math.Round(seatAge.TotalSeconds));

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = license.Id,
                Action = HistoryActions.UnlinkedApi,
                Details = string.Format(_localizer["Licenses_Action_UnlinkedApi"].Value, authoritativeHardwareId, source),
                PerformedBy = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });

            try
            {
                await Services.SeatRuntimeReleaseAuthority.CompleteAsync(
                    _db, releaseScope, [seat], HttpContext.RequestAborted);
            }
            catch (Services.DistributionOperationException exception)
            {
                return DistributionRefusalResult(exception);
            }
            if (releaseTransaction != null)
                await releaseTransaction.CommitAsync(HttpContext.RequestAborted);

            return Ok(new { Message = _localizer["Api_UnlinkSuccess"].Value });
        }
    }
}

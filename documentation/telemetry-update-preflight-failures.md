# UPD startup-shell observability

`Update_PreflightFailureShown` is a mandatory operational event emitted by Desktop only after an
UPD-1001 through UPD-1004 shell is actually presented. SoftLicence validates the closed property
contract before alerting; malformed public telemetry remains non-authoritative and cannot affect a
licence, ban, update decision, or runtime capability.

Every valid occurrence is stored as raw telemetry and is exempt from generic flood suppression.
Insights report total occurrences, distinct hardware identifiers, first and last appearance, plus a
breakdown by support code, decision reason, and installed version.

For notifications, SoftLicence computes a SHA-256 signature over the product-scoped, allowlisted
support code. Diagnostic versions and reasons remain visible in raw analytics but cannot multiply
notifications because public telemetry is informational and forgeable. Identical support codes share
one fixed 30-minute UTC aggregate. Every occurrence increments the durable aggregate, while only its
first occurrence schedules the `Update.PreflightFailureShown` webhook/ntfy trigger.
The next UTC window can notify again, making persistent incidents visible without phone flooding.
Failed or unconfigured delivery releases its durable claim for a later occurrence. An uncompleted
claim expires after five minutes so a server interruption cannot suppress every later presentation in
the same window; claim identifiers prevent an expired sender from completing a newer claim.

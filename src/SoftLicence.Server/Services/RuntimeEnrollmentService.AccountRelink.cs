using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Frozen or fresh outcome of one account relink request.</summary>
/// <param name="ExactBody">Exact UTF-8 JSON returned with HTTP 200.</param>
/// <param name="Replayed">True when the bytes come from a previously completed identical request.</param>
public sealed record RuntimeAccountRelinkResult(byte[] ExactBody, bool Replayed);

/// <summary>
/// TKT-002919: account relink of a Runtime installation whose seat was released. The website authenticates the
/// account signed in inside the application and calls with a dedicated S2S identity; SoftLicence proves the
/// installation (its PS256 key), the same account (enrollment subject digest) and the same registry owner, then
/// restores seat and assignment through <see cref="RuntimeCommercialAssignmentResolver.ResolveOrRelinkAsync"/>
/// with all its existing seat rules. SoftLicence decides nothing commercial: which licence the account may use,
/// and the Team rule R9 (an administrator's unlink is not undone), belong to the website.
/// </summary>
public sealed partial class RuntimeEnrollmentService
{
    /// <summary>Licence history action written by a successful account relink (no secret, no identifier of the account).</summary>
    internal const string AccountRelinkHistoryAction = "RUNTIME_ACCOUNT_RELINK";

    /// <summary>Per-enrollment hourly quota of authenticated account relink attempts (frozen replays excluded).</summary>
    internal const int AccountRelinkHourlyLimit = 10;

    /// <summary>Quota scope recorded in <c>RuntimeEnrollmentQuotas</c>.</summary>
    internal const string AccountRelinkQuotaScope = "account-relink-enrollment";

    /// <summary>Exposes the canonical release-version grammar to the account relink contract parser.</summary>
    /// <param name="value">Untrusted version text, matched without rewriting.</param>
    /// <returns>True for a canonical SemVer release version.</returns>
    internal static bool IsCanonicalReleaseVersion(string value) => ReleaseVersionPattern.IsMatch(value);

    /// <summary>
    /// Relinks the installation of an authenticated account relink request, or returns the frozen response of an
    /// identical earlier request.
    /// </summary>
    /// <remarks>
    /// <para>Order (frozen with the website and the review of 31/10/2026):</para>
    /// <list type="number">
    /// <item>Frozen response lookup by authenticated client and request identifier, before any quota: a retry of a
    /// completed request never consumes quota and is not re-evaluated; a different body is 409 <c>request_conflict</c>.
    /// The lookup is repeated under the enrollment lock, so a retry that waited behind the first call gets the
    /// same frozen bytes.</item>
    /// <item>Hourly per-enrollment quota in its own committed transaction (429 <c>rate_limited</c>); it counts every
    /// authenticated attempt and writes no business row.</item>
    /// <item>Scope: the enrollment exists, is of the request product and was created by a client listed for this
    /// relink identity; otherwise 404 <c>enrollment_not_found</c> without revealing existence.</item>
    /// <item>Under the binding authority lease and the locked enrollment: installation identifier (400), security
    /// epoch (409), installation proof, single-use jti, time window and machine digest (403), release (422), account
    /// digest, then either the registry owner of both licences or, when the website sends a null owner, the
    /// installation's own licence as target (409 <c>installation_other_account</c>, TKT-003350) or another licence
    /// attested by the website as owned by the same account (<c>ownerAttestation</c>, TKT-003753), current assignment
    /// (200 not relinked or 409 <c>assignment_conflict</c>), then the shared seat-released entry condition of
    /// TKT-002904 (422).</item>
    /// <item>Commercial write barrier, decision again, PENDING ledger row, seat and assignment by the resolver and
    /// the PostgreSQL writer, full eligibility check, frozen response, proof nonce and history, one commit. The
    /// daily hardware quota of the licence type (TKT-003751: at most N different identifiers per key and UTC day)
    /// refuses with 422 <c>activation_rate_limited</c> only a new identifier beyond N; returning to the machine's
    /// own released seat is free.</item>
    /// </list>
    /// <para>A refusal writes nothing besides the quota counter and the S2S nonce, consumes no installation proof,
    /// and is evaluated again on the next attempt.</para>
    /// </remarks>
    /// <param name="principal">Authenticated principal holding <c>AllowRuntimeAccountRelink</c>.</param>
    /// <param name="command">Strictly parsed request, see <see cref="RuntimeAccountRelinkContract.Parse"/>.</param>
    /// <param name="cancellationToken">Cancels without committing a partial relink.</param>
    /// <returns>The 200 body, fresh or frozen.</returns>
    /// <exception cref="RuntimeEnrollmentException">Every refusal, with the exact public code and status of the contract.</exception>
    /// <inheritdoc cref="IRuntimeEnrollmentService.RelinkAccountAsync"/>
    public async Task<RuntimeAccountRelinkResult> RelinkAccountAsync(
        DistributionS2SPrincipal principal,
        RuntimeAccountRelinkCommand command,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        if (!principal.AllowRuntimeAccountRelink)
            throw new RuntimeEnrollmentException("account_relink_not_authorized", StatusCodes.Status403Forbidden);

        var frozen = await FindFrozenAccountRelinkAsync(principal.ClientId, command, cancellationToken);
        if (frozen is not null)
            return frozen;

        await ReserveAccountRelinkQuotaAsync(command.EnrollmentId, cancellationToken);

        var linkedClients = principal.AccountRelinkForClientIds ?? [];
        ProofPreflight preflight;
        await using (var scopeDb = await _dbFactory.CreateDbContextAsync(cancellationToken))
        {
            var scoped = await scopeDb.RuntimeEnrollments.AsNoTracking()
                .Where(row => row.Id == command.EnrollmentId)
                .Select(row => new { row.ProductId, row.ClientId })
                .SingleOrDefaultAsync(cancellationToken);
            if (scoped is null || scoped.ProductId != command.ProductId
                || !linkedClients.Contains(scoped.ClientId, StringComparer.Ordinal))
                throw EnrollmentNotFound();
        }
        try
        {
            preflight = await LoadProofPreflightAsync(command.EnrollmentId, cancellationToken);
        }
        catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status404NotFound)
        {
            throw EnrollmentNotFound();
        }

        try
        {
            return await ExecuteWithRetriesAsync(
                () => RelinkAccountOnceAsync(principal, linkedClients, command, preflight, cancellationToken),
                cancellationToken);
        }
        catch (DbUpdateException exception) when (IsAccountRelinkRequestRace(exception))
        {
            // A concurrent identical request committed first: answer with its frozen bytes, or the conflict.
            return await FindFrozenAccountRelinkAsync(principal.ClientId, command, cancellationToken)
                ?? throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        }
    }

    /// <summary>
    /// One transactional relink attempt; see <see cref="RelinkAccountAsync"/> for the order of checks, the
    /// optional owner rule and the daily hardware quota.
    /// </summary>
    private async Task<RuntimeAccountRelinkResult> RelinkAccountOnceAsync(
        DistributionS2SPrincipal principal,
        IReadOnlyList<string> linkedClients,
        RuntimeAccountRelinkCommand command,
        ProofPreflight preflight,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var lease = await _authority.AcquireAsync(db, preflight.BindingId, cancellationToken);
        await _keyRegistry.ValidateConfiguredKeysAsync(db, cancellationToken);
        RuntimeEnrollment enrollment;
        try
        {
            enrollment = await LoadEnrollmentForUpdateAsync(db, command.EnrollmentId, cancellationToken);
        }
        catch (RuntimeEnrollmentException exception) when (exception.StatusCode == StatusCodes.Status404NotFound)
        {
            throw EnrollmentNotFound();
        }
        EnsurePreflightUnchanged(enrollment, preflight);
        // A concurrent identical request may have committed while this one waited for the enrollment lock: answer
        // with its frozen bytes before the proof check, which would otherwise see the jti it just consumed.
        var frozenUnderLock = await FindFrozenAccountRelinkAsync(db, principal.ClientId, command, cancellationToken);
        if (frozenUnderLock is not null)
            return frozenUnderLock;
        if (enrollment.ProductId != command.ProductId
            || !linkedClients.Contains(enrollment.ClientId, StringComparer.Ordinal))
            throw EnrollmentNotFound();
        if (!string.Equals(enrollment.InstallationId, command.InstallationId, StringComparison.Ordinal))
            throw Invalid();
        if (command.SecurityEpoch != enrollment.SecurityEpoch)
            throw Conflict("security_epoch_mismatch");

        var now = await DatabaseNowAsync(db, cancellationToken);
        var proof = await VerifyAccountRelinkProofAsync(db, enrollment, preflight, command, now, cancellationToken);
        if (!string.Equals(enrollment.ReleaseVersion, command.ReleaseVersion, StringComparison.Ordinal))
            throw AccountRelinkIneligible("release_version_mismatch");

        // Same account: the website digest of the signed-in account must be the one pushed at installation
        // (ordinal, exact value). With a declared owner, that owner must own both licences in the registry.
        // TKT-003350: without an owner, only the installation's own licence may be targeted. The digest, an HMAC of
        // account and licence, already proves the account for that licence, and the registry adds nothing; this is
        // the TKT-002904 rule for licences without a known owner. Another licence needs the registry proof, or
        // (TKT-003753) the website attestation that the signed-in account owns both licences: the website is the
        // authenticated commercial authority (SoftLicence decides nothing commercial), the account digest still has to
        // match, and the target product, the seat rules and the PostgreSQL writer are checked as for any relink.
        if (!string.Equals(enrollment.SubjectRefDigestSha256, command.InstallationSubjectRefDigestSha256, StringComparison.Ordinal))
            throw Conflict("installation_other_account");
        if (command.OwnerSubjectId is not { } owner)
        {
            if (command.LicenseId != enrollment.LicenseId
                && !string.Equals(command.OwnerAttestation, RuntimeAccountRelinkContract.WebsiteSameAccountAttestation,
                    StringComparison.Ordinal))
                throw Conflict("installation_other_account");
        }
        else if (!await IsActiveOwnerAsync(db, enrollment.ProductId, command.LicenseId, owner, cancellationToken)
            || !await IsActiveOwnerAsync(db, enrollment.ProductId, enrollment.LicenseId, owner, cancellationToken))
            throw Conflict("installation_other_account");

        var active = await db.EnrollmentLicenseAssignments.AsNoTracking()
            .Where(row => row.EnrollmentId == enrollment.Id && row.State == "ACTIVE")
            .OrderBy(row => row.Id)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (active.Count > 1)
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable,
                "assignment_duplicate_active");
        if (active.Count == 1)
        {
            if (active[0].LicenseId != command.LicenseId)
                throw Conflict("assignment_conflict");
            return await CompleteAccountRelinkAsync(db, lease, principal, enrollment, command, proof,
                active[0].LicenseId, active[0].Revision, relinked: false, now, cancellationToken);
        }

        IReadOnlyDictionary<string, string> binaries;
        try
        {
            binaries = (await RuntimeEnrollmentIdentityValidator.ValidateAsync(
                db, enrollment, "ACTIVE", false, null, cancellationToken)).Binaries;
        }
        catch (RuntimeEnrollmentException exception) when (exception.StatusCode is StatusCodes.Status422UnprocessableEntity
            or StatusCodes.Status409Conflict)
        {
            throw AccountRelinkIneligible(exception.DiagnosticCode ?? exception.ErrorCode);
        }

        await EnsureSeatReleasedEntryAsync(db, enrollment, binaries, now, cancellationToken);
        // The relink is a commercial write: exclusive item-2 barrier after the enrollment row lock, then decide
        // again so a concurrent release, ban or exclusion is not missed (same lock order as TKT-002904).
        await RuntimeCommercialEligibilityValidator.AcquireWriteBarrierAsync(db, cancellationToken);
        now = await DatabaseNowAsync(db, cancellationToken);
        await EnsureSeatReleasedEntryAsync(db, enrollment, binaries, now, cancellationToken);

        var ledger = new RuntimeAccountRelinkRequest
        {
            Id = Guid.NewGuid(),
            AuthenticatedClientId = principal.ClientId,
            EnrollmentClientId = enrollment.ClientId,
            RequestId = command.RequestId,
            BodyDigestSha256 = command.BodyDigestSha256,
            ProductId = enrollment.ProductId,
            EnrollmentId = enrollment.Id,
            LicenseId = command.LicenseId,
            OwnerSubjectId = command.OwnerSubjectId,
            OwnerAttestation = command.OwnerAttestation,
            SubjectRefDigestSha256 = command.InstallationSubjectRefDigestSha256,
            State = "PENDING",
            CreatedAtUtc = now.UtcDateTime
        };
        db.RuntimeAccountRelinkRequests.Add(ledger);
        await db.SaveChangesAsync(cancellationToken);

        var license = await db.Licenses
            .Include(row => row.Product)
            .Include(row => row.Type)
            .Include(row => row.Seats)
            .SingleOrDefaultAsync(row => row.Id == command.LicenseId, cancellationToken)
            ?? throw AccountRelinkIneligible("license_missing");
        try
        {
            await RuntimeCommercialAssignmentResolver.ResolveOrRelinkAsync(
                db, enrollment, license, command.InstallationSubjectRefDigestSha256, command.HardwareId,
                enrollment.ReleaseVersion, principal.ClientId,
                RuntimeCommercialAssignmentResolver.AuthorityProof.AccountRelink(principal.ClientId, command.OwnerSubjectId),
                now, cancellationToken, countKnownSeatTakeover: true);
        }
        catch (RuntimeEnrollmentException exception)
        {
            throw MapResolverRefusal(exception);
        }
        await db.SaveChangesAsync(cancellationToken);

        // The relinked assignment must pass the complete current policy, as a capability would.
        var assignment = await RuntimeCommercialEligibilityValidator.ValidateAsync(
            db, enrollment, binaries, now, cancellationToken);
        return await CompleteAccountRelinkAsync(db, lease, principal, enrollment, command, proof,
            assignment.LicenseId, assignment.Revision, relinked: true, now, cancellationToken, ledger);
    }

    /// <summary>
    /// Freezes the success: ledger row COMPLETED with the exact body, the installation proof recorded as used
    /// (sealed response, operation <c>account-relink</c>), licence history, then the single commit.
    /// </summary>
    private async Task<RuntimeAccountRelinkResult> CompleteAccountRelinkAsync(
        LicenseDbContext db,
        RuntimeAuthorityLease lease,
        DistributionS2SPrincipal principal,
        RuntimeEnrollment enrollment,
        RuntimeAccountRelinkCommand command,
        ProofValidated proof,
        Guid licenseId,
        int revision,
        bool relinked,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        RuntimeAccountRelinkRequest? ledger = null)
    {
        var body = RuntimeAccountRelinkContract.BuildResponse(enrollment.Id, licenseId, revision, relinked);
        var bytes = Encoding.UTF8.GetBytes(body);
        if (ledger is null)
        {
            ledger = new RuntimeAccountRelinkRequest
            {
                Id = Guid.NewGuid(),
                AuthenticatedClientId = principal.ClientId,
                EnrollmentClientId = enrollment.ClientId,
                RequestId = command.RequestId,
                BodyDigestSha256 = command.BodyDigestSha256,
                ProductId = enrollment.ProductId,
                EnrollmentId = enrollment.Id,
                LicenseId = licenseId,
                OwnerSubjectId = command.OwnerSubjectId,
                OwnerAttestation = command.OwnerAttestation,
                SubjectRefDigestSha256 = command.InstallationSubjectRefDigestSha256,
                CreatedAtUtc = now.UtcDateTime
            };
            db.RuntimeAccountRelinkRequests.Add(ledger);
        }
        ledger.State = "COMPLETED";
        ledger.ResponseBody = body;
        ledger.CompletedAtUtc = now.UtcDateTime;

        var envelope = await _crypto.SealAsync(db, "account-relink-response", proof.Jti, enrollment.Epoch, bytes,
            ProofResponseReference(enrollment.Id, RuntimeAccountRelinkContract.ProofOperation, proof.Jti), cancellationToken);
        db.RuntimeEnrollmentProofNonces.Add(NewProofNonce(enrollment, RuntimeAccountRelinkContract.ProofOperation,
            proof, command.BodyDigestSha256, envelope, lease.AuthorityEpoch, now));
        if (relinked)
            db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = licenseId,
                Timestamp = now.UtcDateTime,
                Action = AccountRelinkHistoryAction,
                // TKT-003753: the history names the website attestation when it authorised another licence.
                Details = command.OwnerAttestation is null
                    ? "The account signed in inside the application took back the seat of its Runtime installation."
                    : "The account signed in inside the application took back the seat of its Runtime installation "
                        + $"on another licence of the same account (website attestation {command.OwnerAttestation}).",
                PerformedBy = principal.ClientId
            });
        await db.SaveChangesAsync(cancellationToken);
        await lease.CommitAsync(cancellationToken);
        return new RuntimeAccountRelinkResult(bytes, false);
    }

    /// <summary>
    /// Validates the installation proof relayed by the website: present and well formed, jti never used by this
    /// enrollment for any operation, PS256 signature by the enrollment key over the account-relink payload, time
    /// within the proof skew, and the request machine digest equal to the enrollment's. Every failure is 403
    /// <c>installation_proof_invalid</c>; nothing is consumed here, the jti is recorded only on success.
    /// </summary>
    private async Task<ProofValidated> VerifyAccountRelinkProofAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        ProofPreflight preflight,
        RuntimeAccountRelinkCommand command,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (command.Proof is null)
            throw ProofInvalid("proof_missing");
        ProofValidated proof;
        try
        {
            proof = ValidateProofHeaders(new RuntimeProofHeaders(
                command.Proof.Timestamp, command.Proof.Jti, command.Proof.Signature));
        }
        catch (RuntimeEnrollmentException)
        {
            throw ProofInvalid("proof_malformed");
        }
        var jti = proof.Jti.ToString("D");
        if (await db.RuntimeEnrollmentProofNonces.AsNoTracking()
                .AnyAsync(row => row.EnrollmentId == enrollment.Id && row.Jti == jti, cancellationToken))
            throw ProofInvalid("proof_replayed");

        byte[]? signature = null;
        try
        {
            signature = DecodeBase64Url(proof.SignatureBase64Url);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(preflight.Spki, out var consumed);
            var payload = RuntimeAccountRelinkContract.BuildProofPayload(command, proof.Timestamp, jti);
            if (consumed != preflight.Spki.Length || rsa.KeySize != 3072
                || !rsa.VerifyData(Encoding.UTF8.GetBytes(payload), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw ProofInvalid("proof_signature_invalid");
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or FormatException)
        {
            throw ProofInvalid("proof_signature_invalid");
        }
        finally
        {
            if (signature != null)
                CryptographicOperations.ZeroMemory(signature);
        }

        var skew = TimeSpan.FromSeconds(_options.ProofClockSkewSeconds);
        if (proof.SentAtUtc < now - skew || proof.SentAtUtc > now + skew)
            throw ProofInvalid(ProofClockSkewDiagnosticCode);

        // The statement binds the website-relayed machine; it must also be the machine of this installation.
        if (!string.Equals(RuntimeAccountRelinkContract.HardwareDigest(command.HardwareId), enrollment.HardwareIdHash,
                StringComparison.Ordinal))
            throw ProofInvalid("hardware_mismatch");
        return proof;
    }

    /// <summary>
    /// Applies the shared TKT-002904 entry condition: only a healthy installation whose seat was released may be
    /// relinked. An excluded machine is 422 <c>license_hardware_excluded</c> (contract with the website); every
    /// other unhealthy state (quarantine, ban, revoked or invalidated authority, other end reason) is 422
    /// <c>authority_ineligible</c>.
    /// </summary>
    private static async Task EnsureSeatReleasedEntryAsync(
        LicenseDbContext db,
        RuntimeEnrollment enrollment,
        IReadOnlyDictionary<string, string> binaries,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var entry = await RuntimeCapabilityReattachment.AssessReleasedSeatAsync(db, enrollment, binaries, now, cancellationToken);
        if (entry.Excluded)
            throw new RuntimeEnrollmentException(LicenseHardwareExclusionChecker.PublicErrorCode,
                StatusCodes.Status422UnprocessableEntity, "license_hardware_excluded");
        if (entry.Seat is null)
            throw AccountRelinkIneligible("seat_not_released");
    }

    /// <summary>
    /// Maps resolver refusals to the public contract: seat capacity and the seat-change quota keep their own 422
    /// codes, an exclusion of the target licence becomes 422 <c>license_hardware_excluded</c>, the named refusals of
    /// the relink writer (TKT-004085: <c>license_ineligible</c>, <c>seat_ineligible</c>, <c>seat_capacity_exceeded</c>,
    /// <c>enrollment_inactive</c>) keep their code, any other policy refusal is 422 <c>authority_ineligible</c>, and
    /// 409 refusals (<c>assignment_conflict</c>, <c>assignment_reconciliation_required</c>, <c>seat_assignment_busy</c>)
    /// and infrastructure failures (503) pass through.
    /// </summary>
    /// <param name="exception">The resolver refusal; its diagnostic stays server-only and is never written to the body.</param>
    /// <returns>The refusal answered with the exact relink body <c>{"error":"code"}</c>.</returns>
    private static RuntimeEnrollmentException MapResolverRefusal(RuntimeEnrollmentException exception)
    {
        if (string.Equals(exception.ErrorCode, LicenseHardwareExclusionChecker.PublicErrorCode, StringComparison.Ordinal))
            return new RuntimeEnrollmentException(exception.ErrorCode, StatusCodes.Status422UnprocessableEntity,
                exception.DiagnosticCode);
        if (string.Equals(exception.ErrorCode, "activation_rate_limited", StringComparison.Ordinal))
            return exception;
        // TKT-004085: checked before the generic 422 branch below, which would collapse them into authority_ineligible.
        if (exception.StatusCode == StatusCodes.Status422UnprocessableEntity
            && exception.ErrorCode is "license_ineligible" or "seat_ineligible" or "seat_capacity_exceeded" or "enrollment_inactive")
            return exception;
        if (string.Equals(exception.DiagnosticCode, "seat_capacity_exceeded", StringComparison.Ordinal))
            return new RuntimeEnrollmentException("seat_capacity_exceeded", StatusCodes.Status422UnprocessableEntity,
                "seat_capacity_exceeded");
        if (exception.StatusCode == StatusCodes.Status422UnprocessableEntity)
            return AccountRelinkIneligible(exception.DiagnosticCode ?? exception.ErrorCode);
        return exception;
    }

    /// <summary>
    /// Returns the frozen response of a completed request of the same client and request identifier, null when
    /// none exists, and 409 <c>request_conflict</c> when the stored body digest differs from this request.
    /// </summary>
    private async Task<RuntimeAccountRelinkResult?> FindFrozenAccountRelinkAsync(
        string clientId,
        RuntimeAccountRelinkCommand command,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await FindFrozenAccountRelinkAsync(db, clientId, command, cancellationToken);
    }

    /// <summary>
    /// Same lookup on a caller-owned context. Called inside the relink transaction right after the enrollment row
    /// lock is taken: a concurrent identical request that committed while this one waited for the lock is visible
    /// there (READ COMMITTED, new statement), so the retry receives the frozen 200 instead of a 403 for the
    /// installation proof the first call has just consumed (review of PR #462, remark 1).
    /// </summary>
    /// <param name="db">Context of the caller; read-only here.</param>
    /// <param name="clientId">Authenticated S2S client.</param>
    /// <param name="command">Parsed request whose request identifier and body digest are matched ordinally.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The frozen bytes, or null when no completed request exists.</returns>
    /// <exception cref="RuntimeEnrollmentException">409 <c>request_conflict</c> when the stored body differs.</exception>
    private static async Task<RuntimeAccountRelinkResult?> FindFrozenAccountRelinkAsync(
        LicenseDbContext db,
        string clientId,
        RuntimeAccountRelinkCommand command,
        CancellationToken cancellationToken)
    {
        var frozen = await db.RuntimeAccountRelinkRequests.AsNoTracking()
            .Where(row => row.AuthenticatedClientId == clientId && row.RequestId == command.RequestId
                && row.State == "COMPLETED")
            .Select(row => new { row.BodyDigestSha256, row.ResponseBody })
            .SingleOrDefaultAsync(cancellationToken);
        if (frozen is null)
            return null;
        if (!string.Equals(frozen.BodyDigestSha256, command.BodyDigestSha256, StringComparison.Ordinal))
            throw Conflict("request_conflict");
        return new RuntimeAccountRelinkResult(Encoding.UTF8.GetBytes(frozen.ResponseBody!), true);
    }

    /// <summary>
    /// Counts one authenticated attempt in the hourly per-enrollment window and commits it at once, so a refused
    /// attempt is still counted while no business row is written. Over the limit: 429 <c>rate_limited</c>.
    /// The row expires two minutes after its window and is purged by the Runtime cleanup routine.
    /// </summary>
    private async Task ReserveAccountRelinkQuotaAsync(Guid enrollmentId, CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        if (!db.Database.IsNpgsql())
            throw new RuntimeEnrollmentException("authority_unavailable", StatusCodes.Status503ServiceUnavailable);
        // Raw commands below run outside any EF transaction: the connection must be opened explicitly first.
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open)
            await connection.OpenAsync(cancellationToken);
        var now = await DatabaseNowAsync(db, cancellationToken);
        var window = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO public."RuntimeEnrollmentQuotas"
                ("Scope", "SubjectPseudonym", "WindowStartedAtUtc", "Count", "ExpiresAtUtc")
            VALUES (@scope, @subject, @window, 1, @expires)
            ON CONFLICT ("Scope", "SubjectPseudonym", "WindowStartedAtUtc") DO UPDATE
            SET "Count" = public."RuntimeEnrollmentQuotas"."Count" + 1
            WHERE public."RuntimeEnrollmentQuotas"."Count" < @limit
            RETURNING "Count";
            """;
        command.Parameters.AddWithValue("scope", AccountRelinkQuotaScope);
        command.Parameters.AddWithValue("subject", enrollmentId.ToString("D"));
        command.Parameters.AddWithValue("window", window);
        command.Parameters.AddWithValue("expires", window.AddHours(1).AddMinutes(2));
        command.Parameters.AddWithValue("limit", AccountRelinkHourlyLimit);
        if (await command.ExecuteScalarAsync(cancellationToken) == null)
            throw new RuntimeEnrollmentException("rate_limited", StatusCodes.Status429TooManyRequests);
    }

    /// <summary>True when the exact registry row ACTIVE for this product and licence names this owner.</summary>
    private static Task<bool> IsActiveOwnerAsync(
        LicenseDbContext db, Guid productId, Guid licenseId, Guid ownerSubjectId, CancellationToken cancellationToken) =>
        db.RuntimeRecoveryCommercialOwnerships.AsNoTracking().AnyAsync(row =>
            row.ProductId == productId && row.LicenseId == licenseId
            && row.OwnerSubjectId == ownerSubjectId && row.State == "ACTIVE", cancellationToken);

    /// <summary>True for the unique index race of two identical first requests committed concurrently.</summary>
    private static bool IsAccountRelinkRequestRace(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation } postgres
        && postgres.ConstraintName == "IX_RuntimeAccountRelinkRequests_AuthenticatedClientId_RequestId";

    /// <summary>404 that never reveals whether an enrollment exists outside the caller's scope.</summary>
    private static RuntimeEnrollmentException EnrollmentNotFound() =>
        new("enrollment_not_found", StatusCodes.Status404NotFound);

    /// <summary>403 for every installation proof failure, with a server-only diagnostic.</summary>
    private static RuntimeEnrollmentException ProofInvalid(string diagnosticCode) =>
        new("installation_proof_invalid", StatusCodes.Status403Forbidden, diagnosticCode);

    /// <summary>Terminal 422 for an installation that is not in the repairable state; the diagnostic stays internal.</summary>
    private static RuntimeEnrollmentException AccountRelinkIneligible(string diagnosticCode) =>
        new("authority_ineligible", StatusCodes.Status422UnprocessableEntity, diagnosticCode);
}

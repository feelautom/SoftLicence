using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Executes authenticated provider-owned commercial ownership transitions without touching recovery state.
/// </summary>
public interface IRuntimeRecoveryCommercialOwnershipCommandService
{
    /// <summary>
    /// Executes or exactly replays one command under product, license, and ownership-version CAS scope.
    /// </summary>
    /// <param name="productId">Exact product scope already authorized by the transport boundary.</param>
    /// <param name="request">Closed typed command whose UUID and payload define idempotency.</param>
    /// <param name="cancellationToken">Caller cancellation propagated through locks and transaction rollback.</param>
    /// <returns>The frozen canonical response JSON returned for both first execution and exact replay.</returns>
    /// <exception cref="RuntimeRecoveryCommercialOwnershipCommandException">
    /// Thrown when validation, authority scope, CAS, or idempotency fails closed.
    /// </exception>
    Task<RuntimeRecoveryCommercialOwnershipCommandResult> ExecuteAsync(
        Guid productId,
        RuntimeRecoveryCommercialOwnershipCommandRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Implements the PostgreSQL command ledger, deterministic lock order, versioned transition, and frozen readback.
/// </summary>
/// <param name="contextFactory">
/// Creates the transaction-scoped PostgreSQL context used for every lock, authority reread, mutation, and replay.
/// </param>
public sealed class RuntimeRecoveryCommercialOwnershipCommandService(
    IDbContextFactory<LicenseDbContext> contextFactory)
    : IRuntimeRecoveryCommercialOwnershipCommandService
{
    /// <summary>Defines the exact ordinal protocol token for a versioned ownership transfer.</summary>
    private const string TransferOperation = "TRANSFER_OWNERSHIP";
    /// <summary>Defines the exact ordinal protocol token for an irreversible ownership revocation.</summary>
    private const string RevokeOperation = "REVOKE_OWNERSHIP";
    /// <summary>
    /// Keeps the advisory-lock namespace stable across concurrently deployed service versions; changing it would
    /// allow identical command UUIDs to bypass mutual serialization during a rolling deployment.
    /// </summary>
    private const long CommandLockSalt = 782;

    /// <inheritdoc/>
    public async Task<RuntimeRecoveryCommercialOwnershipCommandResult> ExecuteAsync(
        Guid productId,
        RuntimeRecoveryCommercialOwnershipCommandRequest request,
        CancellationToken cancellationToken)
    {
        Validate(productId, request);
        var digest = ComputeRequestDigest(productId, request);
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
        if (!db.Database.IsNpgsql())
            throw Failure("provider_unavailable", StatusCodes.Status503ServiceUnavailable);

        await using var transaction = await db.Database.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        try
        {
            await LockCommandAsync(db, request.CommandId, cancellationToken);
            var replay = await db.RuntimeRecoveryCommercialOwnershipCommands
                .AsNoTracking()
                .SingleOrDefaultAsync(item => item.Id == request.CommandId, cancellationToken);
            if (replay is not null)
            {
                EnsureExactReplay(replay, productId, request, digest);
                await transaction.CommitAsync(cancellationToken);
                return new RuntimeRecoveryCommercialOwnershipCommandResult(replay.ResponseJson);
            }

            var license = await db.Licenses.FromSqlInterpolated($"""
                SELECT * FROM public."Licenses"
                WHERE "ProductId" = {productId} AND "Id" = {request.LicenseId}
                FOR UPDATE
                """).AsNoTracking().SingleOrDefaultAsync(cancellationToken);
            if (license is null)
                throw Failure("ownership_not_found", StatusCodes.Status404NotFound);

            var active = await db.RuntimeRecoveryCommercialOwnerships.FromSqlInterpolated($"""
                SELECT * FROM public."RuntimeRecoveryCommercialOwnerships"
                WHERE "ProductId" = {productId} AND "LicenseId" = {request.LicenseId}
                  AND "State" = 'ACTIVE'
                ORDER BY "Id"
                FOR UPDATE
                """).AsNoTracking().ToListAsync(cancellationToken);
            if (active.Count != 1)
                throw Failure("ownership_not_active", StatusCodes.Status409Conflict);

            var current = active[0];
            if (current.Id != request.ExpectedOwnershipId)
                throw Failure("ownership_version_conflict", StatusCodes.Status409Conflict);

            if (request.Operation == TransferOperation)
            {
                if (request.TargetCommercialSubjectId == current.OwnerSubjectId)
                    throw Failure("target_subject_invalid", StatusCodes.Status409Conflict);

                var targetExists = await db.RuntimeRecoveryCommercialSubjects.FromSqlInterpolated($"""
                    SELECT * FROM public."RuntimeRecoveryCommercialSubjects"
                    WHERE "ProductId" = {productId} AND "Id" = {request.TargetCommercialSubjectId!.Value}
                    FOR KEY SHARE
                    """).AsNoTracking().AnyAsync(cancellationToken);
                if (!targetExists)
                    throw Failure("target_subject_invalid", StatusCodes.Status409Conflict);
            }

            var occurredAtUtc = await ReadDatabaseNowAsync(db, cancellationToken);
            var terminalState = request.Operation == TransferOperation ? "TRANSFERRED" : "REVOKED";
            var affected = await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE public."RuntimeRecoveryCommercialOwnerships"
                SET "State" = {terminalState}, "EndedAtUtc" = {occurredAtUtc}
                WHERE "ProductId" = {productId} AND "LicenseId" = {request.LicenseId}
                  AND "Id" = {request.ExpectedOwnershipId}
                  AND "State" = 'ACTIVE' AND "EndedAtUtc" IS NULL
                """, cancellationToken);
            if (affected != 1)
                throw Failure("ownership_version_conflict", StatusCodes.Status409Conflict);

            RuntimeRecoveryCommercialOwnership? successor = null;
            if (request.Operation == TransferOperation)
            {
                successor = new RuntimeRecoveryCommercialOwnership
                {
                    Id = Guid.NewGuid(),
                    ProductId = productId,
                    LicenseId = request.LicenseId,
                    PreviousOwnershipId = current.Id,
                    OwnerSubjectId = request.TargetCommercialSubjectId!.Value,
                    State = "ACTIVE",
                    CreatedAtUtc = occurredAtUtc
                };
                db.RuntimeRecoveryCommercialOwnerships.Add(successor);
            }

            var responseJson = BuildResponseJson(
                request, productId, current.Id, successor?.Id, terminalState, occurredAtUtc);
            db.RuntimeRecoveryCommercialOwnershipCommands.Add(
                new RuntimeRecoveryCommercialOwnershipCommand
                {
                    Id = request.CommandId,
                    ProductId = productId,
                    LicenseId = request.LicenseId,
                    Operation = request.Operation,
                    RequestDigestSha256 = digest,
                    ExpectedOwnershipId = request.ExpectedOwnershipId,
                    TargetCommercialSubjectId = request.TargetCommercialSubjectId,
                    ResultOwnershipId = successor?.Id,
                    OccurredAtUtc = occurredAtUtc,
                    ResponseJson = responseJson
                });
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new RuntimeRecoveryCommercialOwnershipCommandResult(responseJson);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }

    /// <summary>Rejects every value outside the closed command grammar before opening a transaction.</summary>
    private static void Validate(
        Guid productId,
        RuntimeRecoveryCommercialOwnershipCommandRequest request)
    {
        if (productId == Guid.Empty || request.CommandId == Guid.Empty
            || request.LicenseId == Guid.Empty || request.ExpectedOwnershipId == Guid.Empty)
            throw Failure("invalid_request", StatusCodes.Status400BadRequest);

        if (!string.Equals(request.Operation, TransferOperation, StringComparison.Ordinal)
            && !string.Equals(request.Operation, RevokeOperation, StringComparison.Ordinal))
            throw Failure("invalid_request", StatusCodes.Status400BadRequest);

        var transferTargetIsValid = request.Operation == TransferOperation
            && request.TargetCommercialSubjectId is { } target && target != Guid.Empty;
        var revokeTargetIsValid = request.Operation == RevokeOperation
            && request.TargetCommercialSubjectId is null;
        if (!transferTargetIsValid && !revokeTargetIsValid)
            throw Failure("invalid_request", StatusCodes.Status400BadRequest);
    }

    /// <summary>Serializes identical command UUIDs before any ledger read or commercial mutation.</summary>
    private static Task LockCommandAsync(
        LicenseDbContext db,
        Guid commandId,
        CancellationToken cancellationToken)
    {
        var lockName = $"runtime-recovery-commercial-ownership-command:{commandId:D}";
        return db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({lockName}, {CommandLockSalt}))",
            cancellationToken);
    }

    /// <summary>Reads the single authoritative transition instant after every decisive lock and check.</summary>
    private static Task<DateTime> ReadDatabaseNowAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken) =>
        db.Database.SqlQueryRaw<DateTime>(
            "SELECT pg_catalog.clock_timestamp() AS \"Value\"")
            .SingleAsync(cancellationToken);

    /// <summary>Rejects a reused command UUID unless every typed field and digest are exactly identical.</summary>
    private static void EnsureExactReplay(
        RuntimeRecoveryCommercialOwnershipCommand existing,
        Guid productId,
        RuntimeRecoveryCommercialOwnershipCommandRequest request,
        string digest)
    {
        if (existing.ProductId != productId || existing.LicenseId != request.LicenseId
            || existing.ExpectedOwnershipId != request.ExpectedOwnershipId
            || existing.TargetCommercialSubjectId != request.TargetCommercialSubjectId
            || !string.Equals(existing.Operation, request.Operation, StringComparison.Ordinal)
            || !string.Equals(existing.RequestDigestSha256, digest, StringComparison.Ordinal))
            throw Failure("idempotency_conflict", StatusCodes.Status409Conflict);
    }

    /// <summary>Computes lowercase SHA-256 over a fixed-order, typed, ordinal command representation.</summary>
    private static string ComputeRequestDigest(
        Guid productId,
        RuntimeRecoveryCommercialOwnershipCommandRequest request)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("schema", "runtime-recovery-commercial-ownership-command-v1");
            writer.WriteNumber("contractVersion", 1);
            writer.WriteString("commandId", request.CommandId);
            writer.WriteString("operation", request.Operation);
            writer.WriteString("productId", productId);
            writer.WriteString("licenseId", request.LicenseId);
            writer.WriteString("expectedOwnershipId", request.ExpectedOwnershipId);
            if (request.TargetCommercialSubjectId is { } target)
                writer.WriteString("targetCommercialSubjectId", target);
            else
                writer.WriteNull("targetCommercialSubjectId");
            writer.WriteEndObject();
        }

        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    /// <summary>Freezes one minimal response without exposing provider-private subject identity.</summary>
    private static string BuildResponseJson(
        RuntimeRecoveryCommercialOwnershipCommandRequest request,
        Guid productId,
        Guid previousOwnershipId,
        Guid? currentOwnershipId,
        string previousState,
        DateTime occurredAtUtc)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("schema", "runtime-recovery-commercial-ownership-command-result-v1");
            writer.WriteNumber("contractVersion", 1);
            writer.WriteString("commandId", request.CommandId);
            writer.WriteString("operation", request.Operation);
            writer.WriteString("productId", productId);
            writer.WriteString("licenseId", request.LicenseId);
            writer.WriteString("previousOwnershipId", previousOwnershipId);
            if (currentOwnershipId is { } current)
                writer.WriteString("currentOwnershipId", current);
            else
                writer.WriteNull("currentOwnershipId");
            writer.WriteString("previousState", previousState);
            writer.WriteString("currentState", currentOwnershipId.HasValue ? "ACTIVE" : "REVOKED");
            writer.WriteString("occurredAtUtc", occurredAtUtc.ToUniversalTime().ToString(
                "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>Creates one stable command failure without exposing cross-product authority details.</summary>
    private static RuntimeRecoveryCommercialOwnershipCommandException Failure(
        string errorCode,
        int statusCode) => new(errorCode, statusCode);
}

/// <summary>Represents the closed typed provider command accepted after transport authentication.</summary>
/// <param name="CommandId">Global opaque UUID reserving exactly one command payload.</param>
/// <param name="Operation">Exact TRANSFER_OWNERSHIP or REVOKE_OWNERSHIP token.</param>
/// <param name="LicenseId">Exact license inside the route product scope.</param>
/// <param name="ExpectedOwnershipId">Opaque ACTIVE ownership UUID used as the CAS token.</param>
/// <param name="TargetCommercialSubjectId">Explicit transfer target UUID, or null only for revocation.</param>
public sealed record RuntimeRecoveryCommercialOwnershipCommandRequest(
    Guid CommandId,
    string Operation,
    Guid LicenseId,
    Guid ExpectedOwnershipId,
    Guid? TargetCommercialSubjectId);

/// <summary>Returns only the frozen canonical JSON persisted in the provider command ledger.</summary>
/// <param name="ResponseJson">Exact UTF-8-compatible JSON text for first execution and replay.</param>
public sealed record RuntimeRecoveryCommercialOwnershipCommandResult(string ResponseJson);

/// <summary>Represents one closed HTTP-safe validation, authority, CAS, or idempotency rejection.</summary>
/// <param name="errorCode">The stable non-oracular error token returned by the controller.</param>
/// <param name="statusCode">The exact HTTP status associated with the closed failure.</param>
public sealed class RuntimeRecoveryCommercialOwnershipCommandException(
    string errorCode,
    int statusCode) : Exception(errorCode)
{
    /// <summary>Gets the stable response error token.</summary>
    public string ErrorCode { get; } = errorCode;

    /// <summary>Gets the exact HTTP status selected by the command boundary.</summary>
    public int StatusCode { get; } = statusCode;
}

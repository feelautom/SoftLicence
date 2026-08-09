using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed partial class CanaryAckService
{
    public const string Schema = "canary-ack-v1";
    public const string Algorithm = "RS256";
    public const string KeyId = CanaryAckOptions.InitialKeyId;

    private const string StorePrefix = "CanaryAckReceipt_v1_";
    private static readonly TimeSpan ReceiptLifetime = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan MaximumPastRequestAge = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumFutureRequestSkew = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan ReceiptRetention = TimeSpan.FromHours(24);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromHours(1);
    private static readonly JsonSerializerOptions StoreJsonOptions = new(JsonSerializerDefaults.Web);
    private static long _nextCleanupUtcTicks;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly TimeProvider _timeProvider;
    private readonly ICanaryAckKeyring _keyring;

    public CanaryAckService(
        IDbContextFactory<LicenseDbContext> dbFactory,
        IConfiguration configuration,
        TimeProvider timeProvider,
        ICanaryAckKeyring? keyring = null)
    {
        _dbFactory = dbFactory;
        _timeProvider = timeProvider;
        if (keyring != null)
        {
            _keyring = keyring;
        }
        else
        {
            var options = new CanaryAckOptions();
            configuration.GetSection("CanaryAck").Bind(options);
            _keyring = new CanaryAckKeyring(Options.Create(options));
        }
    }

    public CanaryAckValidatedRequest ValidateCriticalRequest(CanaryPingRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.Equals(request.Schema, Schema, StringComparison.Ordinal))
            throw new CanaryAckValidationException("schema_invalid");
        if (request.ExtensionData is { Count: > 0 })
            throw new CanaryAckValidationException("unexpected_field");
        if (!TryParseCanonicalUuid(request.EventId, out var eventId))
            throw new CanaryAckValidationException("event_id_invalid");
        if (!TryParseCanonicalUtc(request.SentAtUtc, out var sentAtUtc))
            throw new CanaryAckValidationException("sent_at_invalid");

        var now = _timeProvider.GetUtcNow();
        if (sentAtUtc < now - MaximumPastRequestAge || sentAtUtc > now + MaximumFutureRequestSkew)
            throw new CanaryAckValidationException("sent_at_outside_window");

        RejectLegacyCriticalFields(request);
        var hardwareId = ValidateAscii(request.HardwareId, 1, 128, HardwareIdRegex(), "hardware_id_invalid");
        if (!string.Equals(hardwareId, hardwareId.ToUpperInvariant(), StringComparison.Ordinal))
            throw new CanaryAckValidationException("hardware_id_not_canonical");
        var appVersion = ValidateAscii(request.AppVersion, 1, 64, AppVersionRegex(), "app_version_invalid");
        var trigger = ValidateAscii(request.Trigger, 1, 128, TriggerRegex(), "trigger_invalid");
        if (request.Severity != 3)
            throw new CanaryAckValidationException("severity_invalid");

        return new CanaryAckValidatedRequest(
            eventId,
            request.SentAtUtc!,
            hardwareId,
            appVersion,
            trigger,
            request.Severity);
    }

    public async Task<CanaryAckResponse> IssueAsync(
        CanaryAckValidatedRequest request,
        string decision,
        CancellationToken cancellationToken = default)
    {
        if (!string.Equals(decision, "ack", StringComparison.Ordinal)
            && !string.Equals(decision, "kill", StringComparison.Ordinal))
        {
            throw new ArgumentOutOfRangeException(nameof(decision));
        }

        var issuedAt = _timeProvider.GetUtcNow();
        var response = CreateReceipt(request, decision, issuedAt);

        var stored = new StoredCanaryReceipt(RequestBinding(request), response);
        return await InsertOrReadAsync(request.EventId, stored, cancellationToken);
    }

    public CanaryAckResponse CreateReceipt(
        CanaryAckValidatedRequest request,
        string decision,
        DateTimeOffset issuedAt)
    {
        if (!string.Equals(decision, "ack", StringComparison.Ordinal)
            && !string.Equals(decision, "kill", StringComparison.Ordinal))
        {
            throw new ArgumentOutOfRangeException(nameof(decision));
        }

        using var rsa = _keyring.LoadActivePrivateKey();
        var response = new CanaryAckResponse
        {
            Schema = Schema,
            Alg = Algorithm,
            KeyId = _keyring.Configuration.ActiveKeyId,
            EventId = request.EventId,
            HardwareId = request.HardwareId,
            AppVersion = request.AppVersion,
            Decision = decision,
            IssuedAtUtc = FormatUtc(issuedAt),
            ExpiresAtUtc = FormatUtc(issuedAt + ReceiptLifetime),
            ReceiptId = Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture),
            Signature = string.Empty
        };

        response = response with { Signature = Sign(rsa, BuildCanonicalPayload(response)) };
        return response;
    }

    public CanaryAckPublicKeyResponse GetPublicKey()
    {
        if (!_keyring.TryGetPublicKey(_keyring.Configuration.ActiveKeyId, out var response))
            throw new CanaryAckConfigurationException("Canary ACK active public key is unavailable.");
        return response;
    }

    public bool TryGetPublicKey(string keyId, out CanaryAckPublicKeyResponse response) =>
        _keyring.TryGetPublicKey(keyId, out response);

    public static string BuildCanonicalPayload(CanaryAckResponse response) => string.Join('\n',
        response.Schema,
        response.Alg,
        response.KeyId,
        response.EventId,
        response.HardwareId,
        response.AppVersion,
        response.Decision,
        response.IssuedAtUtc,
        response.ExpiresAtUtc,
        response.ReceiptId);

    private async Task<CanaryAckResponse> InsertOrReadAsync(
        string eventId,
        StoredCanaryReceipt candidate,
        CancellationToken cancellationToken)
    {
        var key = StorePrefix + eventId;
        var value = JsonSerializer.Serialize(candidate, StoreJsonOptions);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await CleanupExpiredReceiptsIfDueAsync(db, cancellationToken);

        if (db.Database.IsNpgsql())
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"INSERT INTO \"SystemSettings\" (\"Key\", \"Value\", \"LastUpdated\") VALUES ({key}, {value}, {_timeProvider.GetUtcNow().UtcDateTime}) ON CONFLICT (\"Key\") DO NOTHING",
                cancellationToken);
        }
        else if (db.Database.IsSqlite())
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"INSERT OR IGNORE INTO \"SystemSettings\" (\"Key\", \"Value\", \"LastUpdated\") VALUES ({key}, {value}, {_timeProvider.GetUtcNow().UtcDateTime})",
                cancellationToken);
        }
        else
        {
            var existing = await db.SystemSettings.FindAsync([key], cancellationToken);
            if (existing == null)
            {
                db.SystemSettings.Add(new SystemSetting
                {
                    Key = key,
                    Value = value,
                    LastUpdated = _timeProvider.GetUtcNow().UtcDateTime
                });
                await db.SaveChangesAsync(cancellationToken);
            }
        }

        var persistedValue = await db.SystemSettings.AsNoTracking()
            .Where(setting => setting.Key == key)
            .Select(setting => setting.Value)
            .SingleAsync(cancellationToken);
        var persisted = JsonSerializer.Deserialize<StoredCanaryReceipt>(persistedValue, StoreJsonOptions)
            ?? throw new InvalidOperationException("Persisted canary receipt is invalid.");

        if (!string.Equals(persisted.RequestBinding, candidate.RequestBinding, StringComparison.Ordinal))
            throw new CanaryAckReplayException();

        return persisted.Response;
    }

    private async Task CleanupExpiredReceiptsIfDueAsync(
        LicenseDbContext db,
        CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var observedTicks = Interlocked.Read(ref _nextCleanupUtcTicks);
        if (now.UtcTicks < observedTicks)
            return;

        var nextTicks = (now + CleanupInterval).UtcTicks;
        if (Interlocked.CompareExchange(ref _nextCleanupUtcTicks, nextTicks, observedTicks) != observedTicks)
            return;

        try
        {
            var cutoff = (now - ReceiptRetention).UtcDateTime;
            var expired = db.SystemSettings.Where(setting =>
                setting.Key.StartsWith(StorePrefix) && setting.LastUpdated < cutoff);
            if (db.Database.IsRelational())
            {
                await expired.ExecuteDeleteAsync(cancellationToken);
            }
            else
            {
                db.SystemSettings.RemoveRange(await expired.ToListAsync(cancellationToken));
                await db.SaveChangesAsync(cancellationToken);
            }
        }
        catch
        {
            Interlocked.Exchange(ref _nextCleanupUtcTicks, 0);
            throw;
        }
    }

    private static string Sign(RSA rsa, string canonicalPayload)
    {
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes(canonicalPayload),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string RequestBinding(CanaryAckValidatedRequest request) => string.Join('\n',
        Schema,
        request.EventId,
        request.SentAtUtc,
        request.HardwareId,
        request.AppVersion,
        request.Trigger,
        request.Severity.ToString(CultureInfo.InvariantCulture));

    private static bool TryParseCanonicalUuid(string? value, out string canonical)
    {
        canonical = string.Empty;
        if (!Guid.TryParseExact(value, "D", out var parsed))
            return false;
        canonical = parsed.ToString("D", CultureInfo.InvariantCulture);
        return string.Equals(value, canonical, StringComparison.Ordinal);
    }

    private static bool TryParseCanonicalUtc(string? value, out DateTimeOffset parsed)
    {
        return DateTimeOffset.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out parsed);
    }

    private static string FormatUtc(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);

    private static void RejectLegacyCriticalFields(CanaryPingRequest request)
    {
        if (request.MachineName is not null
            || request.UserName is not null
            || request.Details is not null
            || request.Timestamp is not null
            || request.OsVersion is not null
            || request.ClrVersion is not null
            || request.DebuggerAttached is not null
            || request.BuildConfiguration is not null
            || request.BaseDirectory is not null
            || request.ProcessPath is not null
            || request.AssemblyLocation is not null
            || request.IsLocalDevBuild is not null
            || request.LocalDevBuildReason is not null
            || request.FpExe is not null
            || request.FpDll is not null
            || request.FpCore is not null
            || request.BinaryFingerprints is not null)
        {
            throw new CanaryAckValidationException("unexpected_field");
        }
    }

    private static string ValidateAscii(string? value, int minLength, int maxLength, Regex regex, string error)
    {
        if (value is null
            || value.Length < minLength
            || value.Length > maxLength
            || value.Any(character => character > 0x7f)
            || !regex.IsMatch(value))
        {
            throw new CanaryAckValidationException(error);
        }

        return value;
    }

    [GeneratedRegex("^[A-Z0-9_.-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex HardwareIdRegex();

    [GeneratedRegex("^[0-9A-Za-z.+-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex AppVersionRegex();

    [GeneratedRegex("^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex TriggerRegex();

    private sealed record StoredCanaryReceipt(string RequestBinding, CanaryAckResponse Response);
}

public sealed record CanaryAckValidatedRequest(
    string EventId,
    string SentAtUtc,
    string HardwareId,
    string AppVersion,
    string Trigger,
    int Severity);

public sealed class CanaryAckValidationException(string errorCode) : Exception(errorCode)
{
    public string ErrorCode { get; } = errorCode;
}

public sealed class CanaryAckReplayException() : Exception("event_id_binding_conflict");

public sealed class CanaryAckConfigurationException : Exception
{
    public CanaryAckConfigurationException(string message) : base(message) { }
    public CanaryAckConfigurationException(string message, Exception innerException) : base(message, innerException) { }
}

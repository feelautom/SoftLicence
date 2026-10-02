using System.Security.Cryptography;
using System.Text;

namespace SoftLicence.Server.Services;

/// <summary>
/// Bounds SUP work atomically within one server process. Provider idempotency remains durable;
/// this admission cache is not a distributed quota and resets on process restart.
/// </summary>
public sealed class BugTraceSupportQuota
{
    /// <summary>Serializes quota checks and replay reservations as one admission operation.</summary>
    private readonly object _gate = new();
    /// <summary>Stores only hashed identity boundaries and bounded fixed-window state.</summary>
    private readonly Dictionary<string, Window> _windows = new(StringComparer.Ordinal);

    /// <summary>
    /// Admits one operation or exact replay. A different payload under the same opaque key conflicts.
    /// Reservations survive ambiguous provider failures until the ten-minute window expires.
    /// </summary>
    /// <param name="licenseId">Authoritative licence UUID; HWID never selects a quota bucket.</param>
    /// <param name="operation">Server-selected exact operation namespace, not client input.</param>
    /// <param name="limit">Positive fixed maximum consistently selected by callers for this operation.</param>
    /// <param name="key">Exact optional opaque replay key; null means a distinct attempt on every call.</param>
    /// <param name="payload">Exact serialized request or content digest, hashed before retention; null means empty fingerprint.</param>
    /// <exception cref="BugTraceSupportException">409 changed payload under same key,429 exhausted window,503 at10000 live operation windows.</exception>
    /// <remarks>Admission/replay/reservation are atomic under one process lock. Provider failure does not undo reservation. Windows expire10min after first admission; restart clears state. No distributed coordination or durable replay. Synchronous work retains only hashes, counts and expiry.</remarks>
    public void Admit(Guid licenseId, string operation, int limit, string? key = null, string? payload = null)
    {
        var identity = Digest(licenseId.ToString("D") + ":" + operation);
        var now = DateTimeOffset.UtcNow;
        lock (_gate)
        {
            foreach (var expired in _windows.Where(pair => pair.Value.Expires <= now).Select(pair => pair.Key).ToArray())
                _windows.Remove(expired);
            if (!_windows.TryGetValue(identity, out var window))
            {
                if (_windows.Count >= 10000) throw new BugTraceSupportException(503, "support_capacity_exceeded");
                _windows.Add(identity, window = new Window(now.AddMinutes(10)));
            }
            var replay = key == null ? null : Digest(key);
            var fingerprint = payload == null ? string.Empty : Digest(payload);
            if (replay != null && window.Replays.TryGetValue(replay, out var previous))
            {
                if (!string.Equals(previous, fingerprint, StringComparison.Ordinal))
                    throw new BugTraceSupportException(409, "support_idempotency_conflict");
                return;
            }
            if (window.Count >= limit) throw new BugTraceSupportException(429, "rate_limited", 600);
            window.Count++;
            if (replay != null) window.Replays.Add(replay, fingerprint);
        }
    }

    /// <summary>Hashes exact opaque strings without retaining client content in the quota cache.</summary>
    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Contains at most the admitted quota's number of replay bindings.</summary>
    private sealed class Window(DateTimeOffset expires)
    {
        /// <summary>Gets the fixed expiration; replay traffic never extends it.</summary>
        public DateTimeOffset Expires { get; } = expires;
        /// <summary>Gets or sets the number of distinct admitted attempts.</summary>
        public int Count { get; set; }
        /// <summary>Gets exact key-to-payload digest bindings for admitted idempotent operations.</summary>
        public Dictionary<string, string> Replays { get; } = new(StringComparer.Ordinal);
    }
}

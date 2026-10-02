using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Pure paid-time accounting for DOC-864. No activation, billing or wall-clock grants occur here.</summary>
public static class PersonalDayPassPolicy
{
    /// <summary>Canonical T-IA Connect Pro type; every paid cadence adjusts one account-owned Pro key.</summary>
    public const string TypeSlug = "TIA-CONNECT-PRO";

    /// <summary>Requires the canonical paid recurring type and bounded provider-owned capabilities without duplicating their values.</summary>
    public static bool IsValidPassType(LicenseType type) => type.Slug == TypeSlug
        && !type.IsFree && type.IsRecurring && !type.AllowAnonymous && !type.EnforceSingleUsePerHardwareId
        && type.CustomParams.Count is >= 1 and <= 128
        && type.CustomParams.Select(p => p.Key).Distinct(StringComparer.Ordinal).Count() == type.CustomParams.Count
        && type.CustomParams.All(p => p.Key.Length is >= 1 and <= 128
            && p.Name.Length is >= 1 and <= 256 && p.Value.Length <= 1024);

    /// <summary>Matches the reserved slug using legacy type lookup casing, without treating opaque payment IDs similarly.</summary>
    public static bool IsPassType(string? slug) => string.Equals(slug, TypeSlug, StringComparison.OrdinalIgnoreCase);

    /// <summary>Each confirmed EUR10 payment buys exactly 86,400 elapsed seconds.</summary>
    public static readonly TimeSpan Duration = TimeSpan.FromSeconds(86_400);

    /// <summary>One immutable payment input; identity is exact and seat count belongs to its paid period.</summary>
    public sealed record Payment(string Identity, DateTime PaidAtUtc, int MaxSeats, int DurationSeconds = 86_400, bool PrioritySupport = false);

    /// <summary>A chronological projection, which can change when an earlier payment arrives.</summary>
    public sealed record Period(string Identity, DateTime StartsAtUtc, DateTime ExpiresAtUtc, int MaxSeats, bool PrioritySupport);

    /// <summary>
    /// Validates an opaque provider token without trimming, case folding or Unicode normalization.
    /// ECMAScript boundary whitespace, ASCII controls and isolated UTF-16 surrogates are rejected. Valid non-BMP pairs
    /// remain exact, matching Website evidence validation without Unicode normalization.
    /// </summary>
    public static bool IsOpaqueIdentity(string? value)
    {
        if (value is not { Length: > 0 and <= 200 } || IsBoundaryWhitespace(value[0]) || IsBoundaryWhitespace(value[^1])) return false;
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] <= '\u001f' || value[index] == '\u007f') return false;
            if (!char.IsSurrogate(value[index])) continue;
            if (!char.IsHighSurrogate(value[index]) || index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1])) return false;
            index++;
        }
        return true;
    }

    /// <summary>Matches JavaScript String.trim whitespace exactly, including BOM and excluding C1 NEXT LINE.</summary>
    private static bool IsBoundaryWhitespace(char c) => c is '\u0009' or '\u000a' or '\u000b' or '\u000c' or '\u000d'
        or '\u0020' or '\u00a0' or '\u1680' or (>= '\u2000' and <= '\u200a')
        or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' or '\ufeff';

    /// <summary>Requires a UTC, millisecond-aligned positive instant, representable with one paid day added.</summary>
    public static bool IsPaidInstant(DateTime value) => value.Kind == DateTimeKind.Utc
        && value > DateTime.UnixEpoch && value.Ticks % TimeSpan.TicksPerMillisecond == 0
        && value <= DateTime.MaxValue - Duration;

    /// <summary>Frames exact tuple components without ambiguous separators; callers must validate each component.</summary>
    public static string Identity(string provider, string account, string environment, string payment) =>
        $"{provider.Length}:{provider}{account.Length}:{account}{environment.Length}:{environment}{payment.Length}:{payment}";

    /// <summary>
    /// Sorts by immutable paid instant then ordinal identity and assigns each payment one exact day.
    /// Active repurchase keeps paid time; gaps start at payment, never at processing time. Input order
    /// cannot alter the result. Duplicate identities and invalid/overflowing dates throw before persistence.
    /// Receipts must store historical results separately from this recomputable projection.
    /// </summary>
    public static IReadOnlyList<Period> Allocate(IEnumerable<Payment> payments, DateTime? paidThroughBeforePass = null)
    {
        var ordered = payments.OrderBy(p => p.PaidAtUtc).ThenBy(p => p.Identity, StringComparer.Ordinal).ToArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<Period>(ordered.Length);
        DateTime? horizon = paidThroughBeforePass;
        if (horizon.HasValue && (horizon.Value.Kind != DateTimeKind.Utc
            || horizon.Value.Ticks % TimeSpan.TicksPerMillisecond != 0))
            throw new ArgumentException("Invalid paid horizon.", nameof(paidThroughBeforePass));
        foreach (var payment in ordered)
        {
            if (!IsPaidInstant(payment.PaidAtUtc) || payment.MaxSeats is < 1 or > 10
                || payment.DurationSeconds is < 1 or > 31_622_400 || !seen.Add(payment.Identity))
                throw new ArgumentException("Invalid or repeated paid-pass payment.", nameof(payments));
            var start = horizon.HasValue && horizon > payment.PaidAtUtc ? horizon.Value : payment.PaidAtUtc;
            if (start > DateTime.MaxValue.AddSeconds(-payment.DurationSeconds))
                throw new ArgumentException("Paid period overflows UTC.", nameof(payments));
            horizon = start.AddSeconds(payment.DurationSeconds);
            result.Add(new Period(payment.Identity, start, horizon.Value, payment.MaxSeats, payment.PrioritySupport));
        }
        return result;
    }
}

using System.Globalization;
using System.Text;
using System.Text.Json;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Records the computer name a client reports in its <c>MachineEvidence</c> on the licence seat it uses, so the
/// licence owner can recognise each device by name (TKT-003404).
/// </summary>
/// <remarks>
/// The value is human display text only: it never takes part in identity, authority, quota, ban or commercial
/// decisions, is never compared in SQL, and SoftLicence stores it without any product-specific rule.
/// A request that sends no usable name never erases a stored one, because legacy clients (old hardware
/// identifier format) send no evidence at all and a transient read failure must not blank the device list.
/// </remarks>
public static class SeatMachineName
{
    /// <summary>
    /// Maximum stored length in UTF-16 code units. A Windows NetBIOS name is at most 15 characters and a DNS
    /// host label at most 63; 64 keeps every real name while bounding what an untrusted public client can store.
    /// </summary>
    public const int MaxLength = 64;

    /// <summary>JSON property of <c>MachineEvidence</c> carrying the name, matched case-insensitively.</summary>
    private const string PropertyName = "MachineName";

    /// <summary>
    /// Extracts and cleans the computer name from the raw <c>MachineEvidence</c> of a public activation, trial
    /// or check request.
    /// </summary>
    /// <param name="evidence">Raw evidence object sent by the client, or <c>null</c> for clients that send none.</param>
    /// <returns>
    /// The cleaned name (see <see cref="Clean"/>), or <c>null</c> when the evidence is absent, is not a JSON
    /// object, carries no <c>MachineName</c> string, carries the property more than once under different casings
    /// (ambiguous, so ignored rather than picking one), or holds nothing displayable once cleaned.
    /// Never throws for malformed input: the name is cosmetic and must never refuse a licence operation.
    /// </returns>
    public static string? Read(JsonElement? evidence)
    {
        if (evidence is not { ValueKind: JsonValueKind.Object } root)
            return null;

        string? raw = null;
        var matches = 0;
        foreach (var property in root.EnumerateObject())
        {
            if (!string.Equals(property.Name, PropertyName, StringComparison.OrdinalIgnoreCase))
                continue;
            matches++;
            raw = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
        }

        return matches == 1 ? Clean(raw) : null;
    }

    /// <summary>
    /// Turns an untrusted computer name into the stored display form.
    /// </summary>
    /// <param name="raw">Name as received; may be <c>null</c>, empty or contain any code point.</param>
    /// <returns>
    /// The name without control, format (zero-width, bidirectional override), line/paragraph separator,
    /// private-use, replacement and unpaired surrogate characters, in Unicode NFC, trimmed, and cut to at most <see cref="MaxLength"/> UTF-16
    /// code units without splitting a surrogate pair; <c>null</c> when nothing remains. Casing is preserved
    /// because it is what the customer sees on the machine.
    /// </returns>
    /// <remarks>
    /// Unsafe characters are removed before normalisation because <see cref="string.Normalize()"/> throws on
    /// ill-formed UTF-16, and the length bound is applied last so it measures what is actually stored.
    /// </remarks>
    public static string? Clean(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
            return null;

        var kept = new StringBuilder(Math.Min(raw.Length, MaxLength * 2));
        for (var index = 0; index < raw.Length; index++)
        {
            if (!Rune.TryGetRuneAt(raw, index, out var rune))
                continue; // Unpaired surrogate: dropped, it cannot be stored or displayed safely.
            if (rune.IsBmp is false)
                index++;
            if (IsRemoved(rune))
                continue;
            kept.Append(rune.ToString());
        }

        var normalized = kept.ToString().Normalize(NormalizationForm.FormC).Trim();
        if (normalized.Length > MaxLength)
        {
            var cut = MaxLength;
            // Never keep half of a surrogate pair at the cut point.
            if (char.IsHighSurrogate(normalized[cut - 1]))
                cut--;
            normalized = normalized[..cut].TrimEnd();
        }

        return normalized.Length == 0 ? null : normalized;
    }

    /// <summary>
    /// Copies the reported name onto a seat when it is usable and differs from the stored one.
    /// </summary>
    /// <param name="seat">Tracked seat being created, resumed or checked in; only its <c>MachineName</c> changes.</param>
    /// <param name="evidence">Raw <c>MachineEvidence</c> of the request.</param>
    /// <returns><c>true</c> when the seat was modified and needs saving; <c>false</c> when nothing changed.</returns>
    /// <remarks>
    /// Comparison is ordinal on the cleaned form so a casing change on the PC is reflected, while an identical
    /// name causes no write. An absent or unusable name leaves the stored value untouched (never erased).
    /// The caller owns <c>SaveChangesAsync</c>.
    /// </remarks>
    public static bool Apply(LicenseSeat seat, JsonElement? evidence)
    {
        var name = Read(evidence);
        if (name is null || string.Equals(seat.MachineName, name, StringComparison.Ordinal))
            return false;
        seat.MachineName = name;
        return true;
    }

    /// <summary>
    /// Tells whether a code point is invisible or layout-breaking and must not reach the stored name.
    /// </summary>
    /// <param name="rune">Well-formed code point of the received name.</param>
    /// <returns>
    /// <c>true</c> for control, format, line separator, paragraph separator, private-use and replacement
    /// characters: none of them belongs in a Windows computer name and each can hide or spoof displayed text.
    /// </returns>
    private static bool IsRemoved(Rune rune)
    {
        if (rune.Value == 0xFFFD)
            return true; // Replacement character: marks a decoding loss, not part of the real name.
        return Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control
            or UnicodeCategory.Format
            or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator
            or UnicodeCategory.Surrogate
            or UnicodeCategory.PrivateUse;
    }
}

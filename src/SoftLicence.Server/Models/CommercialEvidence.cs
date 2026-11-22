using System.Text.Json;
using System.Text.Json.Serialization;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Models;

/// <summary>Versioned Website purchase facts, distinct from catalogue prices and license-type flags.</summary>
/// <param name="Version">Exact supported contract version 2; unknown versions fail validation.</param>
/// <param name="OperationId">Nonempty globally unique attempt UUID, stable for an exact replay.</param>
/// <param name="OrderId">Immutable opaque order identity, 1..200 UTF-16 units with no normalization.</param>
/// <param name="CommercialSubjectId">Nonempty Website subject UUID; new attribution must match active ownership.</param>
/// <param name="Nature">Exact FIRST_ORDER_FREE, FREE, PAID_TRIAL or PAID; no heuristic classification.</param>
/// <param name="PaidAmountMinor">Actual collected EUR cents as Int32, coherent with the explicit nature; PAID_TRIAL is
/// exactly 9700 (introductory offer) or 10000 (orders opened before it, TKT-002098).</param>
/// <param name="Currency">Exact lowercase eur for V2; owner-authorized non-EUR requests retain V1.</param>
[JsonConverter(typeof(CommercialEvidenceConverter))]
public sealed record CommercialEvidence(int Version, Guid OperationId, string OrderId,
    Guid CommercialSubjectId, string Nature, int PaidAmountMinor, string Currency)
{
    /// <summary>Rejects incomplete or incoherent evidence without inferring a nature from price alone.</summary>
    public bool IsValid => Version == 2 && OperationId != Guid.Empty && CommercialSubjectId != Guid.Empty
        && PersonalDayPassPolicy.IsOpaqueIdentity(OrderId) && Currency == "eur"
        && (Nature is "FIRST_ORDER_FREE" or "FREE" ? PaidAmountMinor == 0
            : Nature == "PAID_TRIAL" ? PaidAmountMinor is 9700 or 10000 : Nature == "PAID" && PaidAmountMinor > 0);
}

/// <summary>Reads a complete, duplicate-free object and emits canonical field ordering for V2 fingerprints.</summary>
public sealed class CommercialEvidenceConverter : JsonConverter<CommercialEvidence>
{
    /// <summary>Invalid input remains an explicit invalid value so the endpoint emits its stable commercial error.</summary>
    private static readonly CommercialEvidence Invalid = new(0, Guid.Empty, "", Guid.Empty, "", -1, "");

    /// <summary>Rejects unknown members, numeric coercion and incomplete evidence without normalizing opaque strings.</summary>
    public override CommercialEvidence Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        if (document.RootElement.ValueKind != JsonValueKind.Object) return Invalid;
        var fields = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in document.RootElement.EnumerateObject())
            if (!fields.TryAdd(field.Name, field.Value)) return Invalid;
        string[] names = ["version", "operationId", "orderId", "commercialSubjectId", "nature", "paidAmountMinor", "currency"];
        if (fields.Count != names.Length || names.Any(name => !fields.ContainsKey(name))) return Invalid;
        try
        {
            // GetInt32 accepts JSON integers only; exponent/fraction forms are deliberately refused.
            if (!fields["version"].TryGetInt32(out var version) || !fields["paidAmountMinor"].TryGetInt32(out var amount)) return Invalid;
            return new(version, fields["operationId"].GetGuid(), fields["orderId"].GetString() ?? "",
                fields["commercialSubjectId"].GetGuid(), fields["nature"].GetString() ?? "", amount, fields["currency"].GetString() ?? "");
        }
        catch (Exception error) when (error is InvalidOperationException or FormatException) { return Invalid; }
    }

    /// <summary>Writes the single canonical V2 representation; absent evidence is omitted by its parent DTO.</summary>
    public override void Write(Utf8JsonWriter writer, CommercialEvidence value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteNumber("version", value.Version);
        writer.WriteString("operationId", value.OperationId);
        writer.WriteString("orderId", value.OrderId);
        writer.WriteString("commercialSubjectId", value.CommercialSubjectId);
        writer.WriteString("nature", value.Nature);
        writer.WriteNumber("paidAmountMinor", value.PaidAmountMinor);
        writer.WriteString("currency", value.Currency);
        writer.WriteEndObject();
    }
}

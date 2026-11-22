using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftLicence.Server.Models;

/// <summary>
/// Reads the optional compatibility <c>req</c> member of an event request without ever failing model
/// binding because of its shape. Deployed producers disagree on it: T-IA Connect sends a nested
/// request object while YOUR_APP_NAME and its uninstall script send the literal string <c>event</c>.
/// </summary>
/// <remarks>
/// <para>
/// A JSON object yields an envelope carrying its usable <c>type</c> and <c>properties</c> members;
/// an empty object yields an empty envelope. Any other JSON value yields <see langword="null"/>. In
/// every case exactly one value is consumed, leaving the reader on its last token as the converter
/// contract requires.
/// </para>
/// <para>
/// The value is read forward-only. No document model is built, so an ignored value costs no
/// allocation beyond the request buffer and a retained object allocates only the same string
/// dictionary the outer <c>properties</c> member already allows. Nesting depth stays bounded by the
/// reader's own maximum depth, which rejects the whole body exactly as it did before this member
/// was mapped.
/// </para>
/// <para>
/// Member names follow the serializer options in effect (naming policy and case sensitivity). When
/// a member is repeated, the last occurrence wins, which is the rule System.Text.Json applies to
/// every other member of the request.
/// </para>
/// </remarks>
public sealed class TelemetryEventCompatibilityEnvelopeConverter
    : JsonConverter<TelemetryEventCompatibilityEnvelope?>
{
    /// <summary>
    /// Consumes exactly one JSON value and returns the envelope when the value is an object.
    /// </summary>
    /// <param name="reader">The reader positioned on the first token of the <c>req</c> value.</param>
    /// <param name="typeToConvert">The declared envelope type.</param>
    /// <param name="options">The endpoint serializer options that define member-name matching.</param>
    /// <returns>The nested envelope, or <see langword="null"/> when the value is not an object.</returns>
    /// <exception cref="JsonException">The JSON text itself is malformed or truncated.</exception>
    public override TelemetryEventCompatibilityEnvelope? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            // Skip is a no-op on a scalar and consumes the whole subtree of an array.
            reader.Skip();
            return null;
        }

        var comparison = options.PropertyNameCaseInsensitive
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        var typeName = ResolveMemberName(options, nameof(TelemetryEventCompatibilityEnvelope.Type));
        var propertiesName = ResolveMemberName(options, nameof(TelemetryEventCompatibilityEnvelope.Properties));
        var envelope = new TelemetryEventCompatibilityEnvelope();

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
                return envelope;

            var memberName = reader.GetString();
            if (!reader.Read())
                break;

            if (string.Equals(memberName, typeName, comparison))
                envelope.Type = ReadExactStringOrSkip(ref reader);
            else if (string.Equals(memberName, propertiesName, comparison))
                envelope.Properties = ReadStringPropertiesOrSkip(ref reader);
            else
                reader.Skip();
        }

        throw new JsonException("The telemetry compatibility envelope is truncated.");
    }

    /// <summary>
    /// Writes the envelope member by member; the server never emits this member on the wire, the
    /// override exists to keep the converter complete.
    /// </summary>
    /// <param name="writer">The destination writer.</param>
    /// <param name="value">The envelope to write, or <see langword="null"/>.</param>
    /// <param name="options">The serializer options in effect.</param>
    public override void Write(
        Utf8JsonWriter writer,
        TelemetryEventCompatibilityEnvelope? value,
        JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteStartObject();
        writer.WriteString(
            ResolveMemberName(options, nameof(TelemetryEventCompatibilityEnvelope.Type)),
            value.Type);
        writer.WritePropertyName(
            ResolveMemberName(options, nameof(TelemetryEventCompatibilityEnvelope.Properties)));
        JsonSerializer.Serialize(writer, value.Properties, options);
        writer.WriteEndObject();
    }

    /// <summary>
    /// Applies the configured naming policy to a CLR member name so nested members are matched the
    /// same way the serializer matches the members of the outer request.
    /// </summary>
    /// <param name="options">The serializer options in effect.</param>
    /// <param name="clrName">The CLR property name.</param>
    /// <returns>The wire name expected for the property.</returns>
    private static string ResolveMemberName(JsonSerializerOptions options, string clrName) =>
        options.PropertyNamingPolicy?.ConvertName(clrName) ?? clrName;

    /// <summary>
    /// Consumes exactly one JSON value and returns it only when it is a string. The string is kept
    /// byte for byte: no trimming, case folding, or normalization, because the ingestion service
    /// compares the classification ordinally.
    /// </summary>
    /// <param name="reader">The reader positioned on the first token of the value.</param>
    /// <returns>The exact string, or <see langword="null"/> for every other JSON value.</returns>
    private static string? ReadExactStringOrSkip(ref Utf8JsonReader reader)
    {
        if (reader.TokenType == JsonTokenType.String)
            return reader.GetString();

        // Skip is a no-op on a scalar and consumes the whole subtree of an array or object.
        reader.Skip();
        return null;
    }

    /// <summary>
    /// Reads a nested property bag whose values are all strings or JSON null, the two value kinds the
    /// string dictionary of the outer request accepts. Any other shape is consumed and discarded as
    /// a whole so a partially readable bag can never be stored.
    /// </summary>
    /// <param name="reader">The reader positioned on the first token of the nested value.</param>
    /// <returns>The property bag, or <see langword="null"/> when the value must be ignored.</returns>
    /// <exception cref="JsonException">The JSON text itself is malformed or truncated.</exception>
    private static Dictionary<string, string>? ReadStringPropertiesOrSkip(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            reader.Skip();
            return null;
        }

        // Keys are compared ordinally, like the dictionary the serializer builds for the outer bag.
        var properties = new Dictionary<string, string>(StringComparer.Ordinal);
        var usable = true;
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
                return usable ? properties : null;

            var key = reader.GetString()!;
            if (!reader.Read())
                break;

            if (reader.TokenType is JsonTokenType.String or JsonTokenType.Null)
            {
                // A repeated key keeps its last value, as System.Text.Json does for dictionaries.
                properties[key] = reader.GetString()!;
            }
            else
            {
                usable = false;
                reader.Skip();
            }
        }

        throw new JsonException("The telemetry compatibility properties are truncated.");
    }
}

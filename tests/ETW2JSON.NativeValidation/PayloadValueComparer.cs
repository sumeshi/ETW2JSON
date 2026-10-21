using System.Collections;
using System.Globalization;
using System.Text.Json;

namespace ETW2JSON.NativeValidation;

internal enum ValueResult { Match, Mismatch, Unsupported }
internal readonly record struct ValueComparison(ValueResult Result, string? Reason = null);

internal static class PayloadValueComparer
{
    internal static ValueComparison Compare(object? reference, JsonElement actual, int depth = 0)
    {
        if (depth > 16) return Unsupported("reference_value_nesting_exceeds_limit");
        if (ReferenceFailure(reference) != null) return Unsupported("reference_reported_value_lookup_failure");
        if (reference == null) return Result(actual.ValueKind == JsonValueKind.Null);
        if (reference is byte[] binary)
        {
            if (actual.ValueKind != JsonValueKind.String) return Result(false);
            try { return Result(binary.AsSpan().SequenceEqual(actual.GetBytesFromBase64())); }
            catch (FormatException) { return Result(false); }
        }
        if (reference is IDictionary<string, object> structure)
        {
            if (actual.ValueKind != JsonValueKind.Object || actual.EnumerateObject().Count() != structure.Count) return Result(false);
            ValueComparison outcome = Result(true);
            foreach (var pair in structure)
            {
                if (!actual.TryGetProperty(pair.Key, out var member)) return Result(false);
                var comparison = Compare(pair.Value, member, depth + 1);
                if (comparison.Result == ValueResult.Mismatch) return comparison;
                if (comparison.Result == ValueResult.Unsupported) outcome = comparison;
            }
            return outcome;
        }
        if (reference is Array array)
        {
            if (actual.ValueKind != JsonValueKind.Array || actual.GetArrayLength() != array.Length) return Result(false);
            if (array.Rank != 1) return Unsupported("multidimensional_reference_array");
            ValueComparison outcome = Result(true);
            int index = 0;
            foreach (object? item in array)
            {
                var comparison = Compare(item, actual[index++], depth + 1);
                if (comparison.Result == ValueResult.Mismatch) return comparison;
                if (comparison.Result == ValueResult.Unsupported) outcome = comparison;
            }
            return outcome;
        }
        if (reference is string text) return Result(actual.ValueKind == JsonValueKind.String && actual.GetString() == text);
        if (reference is bool boolean)
            return Result((actual.ValueKind is JsonValueKind.True or JsonValueKind.False) && actual.GetBoolean() == boolean);
        if (reference is Guid guid)
            return Result(actual.ValueKind == JsonValueKind.String && actual.TryGetGuid(out Guid value) && value == guid);
        if (reference is char character)
        {
            if (actual.ValueKind == JsonValueKind.String) return Result(actual.GetString() == character.ToString());
            return Result(actual.ValueKind == JsonValueKind.Number && actual.TryGetUInt32(out uint code) && code == character);
        }
        if (reference is DateTime timestamp)
        {
            if (actual.ValueKind != JsonValueKind.String || !actual.TryGetDateTime(out DateTime parsed)) return Result(false);
            if (timestamp.Kind == DateTimeKind.Unspecified || parsed.Kind == DateTimeKind.Unspecified)
                return timestamp.Kind == parsed.Kind ? Result(timestamp.Ticks == parsed.Ticks) : Unsupported("unspecified_reference_datetime_zone");
            return Result(timestamp.ToUniversalTime().Ticks == parsed.ToUniversalTime().Ticks);
        }
        if (reference is DateTimeOffset offset)
            return Result(actual.ValueKind == JsonValueKind.String && actual.TryGetDateTimeOffset(out var parsed) && parsed.UtcTicks == offset.UtcTicks);
        if (reference is float single)
        {
            if (!float.IsFinite(single)) return Unsupported("nonfinite_reference_float");
            // JSON's shortest round-trip float spelling is not necessarily exactly
            // equal as a double. Compare at the declared reference precision.
            return Result(actual.ValueKind == JsonValueKind.Number && actual.TryGetSingle(out float value) && value.Equals(single));
        }
        if (reference is double number)
        {
            if (!double.IsFinite(number)) return Unsupported("nonfinite_reference_double");
            return Result(actual.ValueKind == JsonValueKind.Number && actual.TryGetDouble(out double value) && value.Equals(number));
        }
        if (reference is sbyte or byte or short or ushort or int or uint or long or ulong or decimal || reference is Enum)
        {
            decimal expected = Convert.ToDecimal(reference, CultureInfo.InvariantCulture);
            return Result(actual.ValueKind == JsonValueKind.Number && actual.TryGetDecimal(out decimal value) && value == expected);
        }
        if (reference is IntPtr pointer)
            return Result(actual.ValueKind == JsonValueKind.Number && actual.TryGetInt64(out long value) && value == pointer.ToInt64());
        if (reference is UIntPtr unsignedPointer)
            return Result(actual.ValueKind == JsonValueKind.Number && actual.TryGetUInt64(out ulong value) && value == unsignedPointer.ToUInt64());
        return Unsupported("unsupported_reference_type:" + reference.GetType().FullName);
    }

    private static ValueComparison Result(bool equal) => new(equal ? ValueResult.Match : ValueResult.Mismatch);
    private static ValueComparison Unsupported(string reason) => new(ValueResult.Unsupported, reason);

    internal static string? ReferenceFailure(object? value)
    {
        // TraceEvent's public PayloadValue can return these diagnostic sentinels
        // instead of throwing. They are not successfully decoded payload strings.
        return value is string text && (text.StartsWith("<<<EXCEPTION_DURING_VALUE_LOOKUP ", StringComparison.Ordinal)
            || text == "[UNSUPPORTED TYPE]") ? text : null;
    }
}

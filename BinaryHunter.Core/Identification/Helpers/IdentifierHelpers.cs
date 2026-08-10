using System.Text;
using System.Text.RegularExpressions;

namespace BinaryHunter.Core.Identification.Helpers;

internal static class IdentifierHelpers
{
    public static string? ReadFixedNumericId(byte[] bytes, int offset)
    {
        const int length = 8;
        if (offset < 0 || offset + length > bytes.Length) return null;
        var span = bytes.AsSpan(offset, length);
        if (span.IndexOfAnyExceptInRange((byte)'0', (byte)'9') >= 0) return null;
        return Encoding.ASCII.GetString(span);
    }

    public static string? ReadToken(byte[] bytes, int offset, int maximumLength)
    {
        if (offset < 0 || offset >= bytes.Length) return null;
        var end = offset;
        var limit = Math.Min(bytes.Length, offset + maximumLength);
        while (end < limit && bytes[end] is >= 0x20 and <= 0x7E) end++;
        if (end == offset) return null;
        return Encoding.ASCII.GetString(bytes, offset, end - offset).Trim();
    }

    public static bool IsValidVin(string value)
    {
        if (value.Length != 17 || value.Distinct().Count() == 1 || value.Any(character => character is 'I' or 'O' or 'Q')) return false;
        const string characters = "0123456789.ABCDEFGH..JKLMN.P.R..STUVWXYZ";
        ReadOnlySpan<int> weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
        var total = 0;
        for (var index = 0; index < value.Length; index++)
        {
            var characterIndex = characters.IndexOf(value[index]);
            if (characterIndex < 0) return false;
            total += (characterIndex % 10) * weights[index];
        }
        var checkDigit = total % 11 == 10 ? 'X' : (char)('0' + total % 11);
        return value[8] == checkDigit;
    }

    private static readonly Regex VinPrefixPattern = new(
        @"WBA[A-HJ-NPR-Z0-9]{7}",
        RegexOptions.Compiled);

    private static readonly Regex VinSuffixPattern = new(
        @"(?<![A-Z0-9])[A-HJ-NPR-Z0-9]\d{6}(?![A-Z0-9])",
        RegexOptions.Compiled);

    public static bool TryFindSplitVin(string text, long evidenceOffset, out string value, out long offset)
    {
        var start = Math.Max(0, (int)evidenceOffset - 512);
        var length = Math.Min(2_048, text.Length - start);
        if (length <= 0)
        {
            value = string.Empty;
            offset = 0;
            return false;
        }

        var context = text.Substring(start, length);
        foreach (Match prefix in VinPrefixPattern.Matches(context))
        foreach (Match suffix in VinSuffixPattern.Matches(context))
        {
            var candidate = prefix.Value + suffix.Value;
            if (IsValidVin(candidate))
            {
                value = candidate;
                offset = start + prefix.Index;
                return true;
            }
        }

        value = string.Empty;
        offset = 0;
        return false;
    }
}

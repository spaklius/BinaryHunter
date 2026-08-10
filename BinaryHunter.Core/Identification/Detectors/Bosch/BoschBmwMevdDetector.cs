using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// MEVD17.2 BMW images expose customer-facing software numbers as repeated BCD
// records beside a Bosch module reference, not as internal 1037xxxxxx values.
internal sealed class BoschBmwMevdDetector : IEcuDetectionModule
{
    public string Name => "Bosch BMW MEVD17.2";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var marker = Regex.Match(image.AsciiText, @"MEVD17(?<minor>\d)(?=_)", RegexOptions.IgnoreCase);
        if (!marker.Success) return [];

        var family = $"MEVD17.{marker.Groups["minor"].Value}";
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "ECU family", Value = $"Bosch {family}", Offset = marker.Index },
            new() { Type = "ECU type", Value = family, Offset = marker.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index }
        };

        var software = FindBcdSoftware(image.Bytes);
        if (software is null) return matches;
        matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Value.Value, Offset = software.Value.Offset });

        var upgrade = FindRelatedUpgrade(image.Bytes, software.Value);
        if (upgrade is not null)
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Value.Value, Offset = upgrade.Value.Offset });
        return matches;
    }

    private static BcdRecord? FindBcdSoftware(byte[] bytes)
    {
        var candidates = new List<BcdRecord>();
        for (var index = 0; index <= bytes.Length - 18; index++)
        {
            if (!TryReadBcd(bytes, index, out var first) || !TryReadBcd(bytes, index + 6, out var second) || !TryReadBcd(bytes, index + 12, out var third)) continue;
            if (!string.Equals(first, second, StringComparison.Ordinal) || !string.Equals(second, third, StringComparison.Ordinal)) continue;
            if (bytes[index + 2] != 0x08) continue;
            if (!ContainsBoschModuleReference(bytes, index + 18, 160)) continue;
            candidates.Add(new BcdRecord(first, index + 2L));
        }

        return candidates.GroupBy(candidate => candidate.Value)
            .OrderByDescending(group => group.Count())
            .ThenByDescending(group => group.Max(candidate => candidate.Offset))
            .FirstOrDefault()?
            .OrderByDescending(candidate => candidate.Offset)
            .FirstOrDefault();
    }

    private static BcdRecord? FindRelatedUpgrade(byte[] bytes, BcdRecord software)
    {
        const int searchRadius = 16_384;
        var start = Math.Max(0, (int)software.Offset - 1 - searchRadius);
        var end = Math.Min(bytes.Length - 12, (int)software.Offset - 1 + searchRadius);
        BcdRecord? closest = null;
        for (var index = start; index <= end; index++)
        {
            if (!TryReadBcd(bytes, index, out var first) || !TryReadBcd(bytes, index + 6, out var second)) continue;
            if (string.Equals(first, second, StringComparison.Ordinal) || !string.Equals(first[..7], second[..7], StringComparison.Ordinal)) continue;
            if (!string.Equals(first[..6], software.Value[..6], StringComparison.Ordinal)) continue;

            var candidate = new BcdRecord(second, index + 8L);
            if (closest is null || Math.Abs(candidate.Offset - software.Offset) < Math.Abs(closest.Value.Offset - software.Offset))
                closest = candidate;
        }
        return closest;
    }

    private static bool ContainsBoschModuleReference(byte[] bytes, int start, int length)
    {
        var end = Math.Min(bytes.Length, start + length);
        return Regex.IsMatch(Encoding.ASCII.GetString(bytes, start, end - start), @"0261S\d{5}", RegexOptions.IgnoreCase);
    }

    private static bool TryReadBcd(byte[] bytes, int offset, out string value)
    {
        value = string.Empty;
        if (offset < 0 || offset + 6 > bytes.Length || bytes[offset] != 0 || bytes[offset + 1] != 0) return false;
        Span<char> digits = stackalloc char[8];
        for (var index = 0; index < 4; index++)
        {
            var current = bytes[offset + index + 2];
            var high = current >> 4;
            var low = current & 0x0F;
            if (high > 9 || low > 9) return false;
            digits[index * 2] = (char)('0' + high);
            digits[index * 2 + 1] = (char)('0' + low);
        }
        value = new string(digits);
        return value != "00000000";
    }

    private readonly record struct BcdRecord(string Value, long Offset);
}

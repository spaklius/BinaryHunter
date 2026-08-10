using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// PSA EDC17C60 full reads contain an explicit RBIN platform path, a TC1791/3
// marker, repeated Bosch/ASAM software records and two adjacent copies of the
// active ten-digit PSA identifier encoded as packed BCD near the flash header.
internal sealed class BoschPsaEdc17C60Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;
    private const int BcdSearchStart = 0x80;
    private const int BcdSearchEnd = 0x180;

    private static readonly Regex PlatformPattern = new(
        @"(?<![A-Z0-9])\d{2,3}/1/(?<type>EDC17C60)/(?<variant>\d{3})/(?<project>P?\d{4})//" +
        @"(?<calibration>C[A-Z0-9]{3})/(?<build>[A-Z0-9]+(?:_[A-Z0-9]+){2})_(?<upgrade>\d{10})//",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"(?<![A-Z0-9])TC179[13](?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch PSA EDC17C60";
    public string Manufacturer => "PSA / STELLANTIS";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var platform = PlatformPattern.Match(image.AsciiText);
        var processor = ProcessorPattern.Match(image.AsciiText);
        var boschSoftware = FindRepeatedIdentifier(image.AsciiText, @"(?<!\d)1037\d{6}(?!\d)", minimumCount: 3);
        var asamSoftware = FindRepeatedIdentifier(image.AsciiText, @"(?<![A-Z0-9])10SW\d{6}(?![A-Z0-9])", minimumCount: 1);
        if (!platform.Success || !processor.Success || (boschSoftware is null && asamSoftware is null))
            return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Full flash image (4 MB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = "PSA / Stellantis", Offset = platform.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Groups["type"].Index },
            new() { Type = "ECU family", Value = "Bosch EDC17C60", Offset = platform.Groups["type"].Index },
            new() { Type = "ECU type", Value = "EDC17C60", Offset = platform.Groups["type"].Index },
            new() { Type = "Processor", Value = $"Infineon {processor.Value.ToUpperInvariant()}", Offset = processor.Index },
            new() { Type = "Software Upgrade Nr.", Value = platform.Groups["upgrade"].Value, Offset = platform.Groups["upgrade"].Index }
        };

        if (boschSoftware is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = boschSoftware.Value, Offset = boschSoftware.Index });
            matches.Add(new IdentifierMatch { Type = "Bosch software Nr.", Value = boschSoftware.Value, Offset = boschSoftware.Index });
        }
        else if (asamSoftware is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = asamSoftware.Value, Offset = asamSoftware.Index });
        }

        if (asamSoftware is not null)
            matches.Add(new IdentifierMatch { Type = "ASAM software Nr.", Value = asamSoftware.Value, Offset = asamSoftware.Index });

        var psaIdentifier = FindRepeatedBcdIdentifier(image.Bytes);
        if (psaIdentifier is not null)
        {
            var bcdOffset = psaIdentifier.Value.Offset;
            var bcdValue = psaIdentifier.Value.Value;
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = bcdValue, Offset = bcdOffset });
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = bcdValue, Offset = bcdOffset + 5 });
        }

        return matches;
    }

    private static BcdIdentifier? FindRepeatedBcdIdentifier(byte[] bytes)
    {
        for (var offset = BcdSearchStart; offset <= BcdSearchEnd - 10; offset++)
        {
            var first = bytes.AsSpan(offset, 5);
            var second = bytes.AsSpan(offset + 5, 5);
            if (!first.SequenceEqual(second) || !IsPackedBcd(first) || IsAllZero(first))
                continue;

            var value = new StringBuilder(10);
            foreach (var item in first)
            {
                value.Append((char)('0' + (item >> 4)));
                value.Append((char)('0' + (item & 0x0F)));
            }
            return new BcdIdentifier(offset, value.ToString());
        }

        return null;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
        {
            if (item != 0) return false;
        }
        return true;
    }

    private static bool IsPackedBcd(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
        {
            if ((item >> 4) > 9 || (item & 0x0F) > 9)
                return false;
        }
        return true;
    }

    private static Match? FindRepeatedIdentifier(string text, string pattern, int minimumCount) =>
        Regex.Matches(text, pattern, RegexOptions.IgnoreCase)
            .Cast<Match>()
            .GroupBy(match => match.Value, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Min(match => match.Index))
            .FirstOrDefault(group => group.Count() >= minimumCount)?
            .OrderBy(match => match.Index)
            .First();

    private readonly record struct BcdIdentifier(int Offset, string Value);
}
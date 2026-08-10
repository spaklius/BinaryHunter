using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Mercedes-Benz EDC17CP46 full images expose two matching P695 platform paths
// and a four-field Mercedes OEM identification block. The OEM software and
// upgrade fields are authoritative; repeated 1037 records belong to internal
// Bosch code/calibration segments.
internal sealed class BoschMercedesEdc17Cp46Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;
    private const int PartialImageSize = 0x11E000;
    private const int CompactPartialImageSize = 0xC0000;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/(?<type>EDC17CP46)/1/(?<profile>P[A-Z0-9]+)//(?<calibration>P_[A-Z0-9_]+)///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationPattern = new(
        @"(?<!\d)(?<part>\d{10})\x00" +
        @"(?<hardware>\d{10})\x00" +
        @"(?<software>\d{3}902\d{4})\x00" +
        @"(?<upgrade>\d{3}903\d{4})(?!\d)",
        RegexOptions.Compiled);

    private static readonly Regex SystemTypePattern = new(
        @"CR\d{2}-[A-Z0-9_-]{10,80}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Mercedes-Benz EDC17CP46";
    public string Manufacturer => "Mercedes-Benz";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length is not (FullImageSize or PartialImageSize or CompactPartialImageSize)) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToList();
        var isFullImage = image.Bytes.Length == FullImageSize;
        var requiredPlatformCount = isFullImage ? 2 : 1;
        if (platforms.Count < requiredPlatformCount) return [];
        var platform = platforms[0];
        if (platforms.Skip(1).Any(candidate =>
                !string.Equals(candidate.Value, platform.Value, StringComparison.OrdinalIgnoreCase)))
            return [];

        var identifications = IdentificationPattern.Matches(text).Cast<Match>().ToList();
        var requiredIdentificationCount = image.Bytes.Length == PartialImageSize ? 2 : 1;
        if (identifications.Count < requiredIdentificationCount) return [];
        var identification = identifications[^1];
        if (identifications.Any(candidate =>
                !string.Equals(candidate.Value, identification.Value, StringComparison.OrdinalIgnoreCase)))
            return [];

        var matches = new List<IdentifierMatch>
        {
            new()
            {
                Type = "Read format",
                Value = image.Bytes.Length switch
                {
                    FullImageSize => "Full flash image (4 MB)",
                    PartialImageSize => "Partial calibration image (OBD protocol, 1171456 bytes)",
                    _ => "Partial calibration image (OBD protocol, 786432 bytes)"
                },
                Offset = 0
            },
            new() { Type = "Vehicle group", Value = "Mercedes-Benz (high confidence; EDC17CP46 OEM block)", Offset = identification.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch (high confidence; EDC17CP46 structural evidence)", Offset = platform.Index },
            new() { Type = "ECU type", Value = "EDC17CP46", Offset = platform.Groups["type"].Index },
            new() { Type = "Processor", Value = "Infineon TC1797 (EDC17CP46 platform inference)", Offset = platform.Index },
            new() { Type = "Software Nr.", Value = identification.Groups["software"].Value, Offset = identification.Groups["software"].Index },
            new() { Type = "Software Upgrade Nr.", Value = identification.Groups["upgrade"].Value, Offset = identification.Groups["upgrade"].Index },
            new() { Type = "ECU profile", Value = platform.Groups["profile"].Value.ToUpperInvariant(), Offset = platform.Groups["profile"].Index },
            new() { Type = "Calibration version", Value = platform.Groups["calibration"].Value, Offset = platform.Groups["calibration"].Index }
        };

        if (!identification.Groups["part"].Value.All(character => character == '0'))
            matches.Add(new IdentifierMatch
            {
                Type = "Spare part number",
                Value = identification.Groups["part"].Value,
                Offset = identification.Groups["part"].Index
            });

        if (!identification.Groups["hardware"].Value.All(character => character == '0'))
            matches.Add(new IdentifierMatch
            {
                Type = "Hardware Nr.",
                Value = identification.Groups["hardware"].Value,
                Offset = identification.Groups["hardware"].Index
            });

        var systemType = SystemTypePattern.Match(text, identification.Index);
        if (systemType.Success && systemType.Index - identification.Index < 0x100)
            matches.Add(new IdentifierMatch { Type = "System type", Value = systemType.Value, Offset = systemType.Index });

        return matches;
    }
}

using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Mercedes-Benz EDC17CP10 full images expose two matching P695 platform paths,
// repeated Bosch software headers and two identical three-field Mercedes OEM
// records. Requiring the complete relationship distinguishes them from VAG
// CP10-like calibration evidence.
internal sealed class BoschMercedesEdc17Cp10Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/(?<type>EDC17CP10)/1/(?<profile>P(?<family>\d{3}))//(?<calibration>P_\d{3}_(?<version>[A-Z0-9]+)_CV[A-Z0-9]+)///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BoschSoftwarePattern = new(
        @"(?<software>1037\d{6})P(?<family>\d{3})(?<version>[A-Z0-9]{4,12})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationPattern = new(
        @"(?<!\d)(?<part>\d{10})\x00" +
        @"(?<software>\d{3}902\d{4})\x00" +
        @"(?<upgrade>\d{3}903\d{4})(?!\d)",
        RegexOptions.Compiled);

    private static readonly Regex SystemTypePattern = new(
        @"CR[A-Z0-9]+-[A-Z0-9_-]{10,80}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Mercedes-Benz EDC17CP10";
    public string Manufacturer => "Mercedes-Benz";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToList();
        if (platforms.Count < 2) return [];
        var platform = platforms[0];
        if (platforms.Skip(1).Any(candidate =>
                !string.Equals(candidate.Value, platform.Value, StringComparison.OrdinalIgnoreCase)))
            return [];

        var softwareHeaders = BoschSoftwarePattern.Matches(text)
            .Cast<Match>()
            .Where(match => string.Equals(match.Groups["family"].Value,
                platform.Groups["family"].Value, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(match.Groups["version"].Value,
                    platform.Groups["version"].Value, StringComparison.OrdinalIgnoreCase))
            .GroupBy(match => match.Groups["software"].Value, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault();
        if (softwareHeaders is null || softwareHeaders.Count() < 2) return [];
        var boschSoftware = softwareHeaders.First();

        var identifications = IdentificationPattern.Matches(text).Cast<Match>().ToList();
        if (identifications.Count < 2) return [];
        var identification = identifications[^1];
        if (identifications.Any(candidate =>
                !string.Equals(candidate.Value, identification.Value, StringComparison.OrdinalIgnoreCase)))
            return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Full flash image (2 MB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Mercedes-Benz (high confidence; EDC17CP10 OEM structure)", Offset = identification.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch (high confidence; EDC17CP10 structural evidence)", Offset = platform.Index },
            new() { Type = "ECU type", Value = "EDC17CP10", Offset = platform.Groups["type"].Index },
            new() { Type = "Processor", Value = "Infineon TC1796 (EDC17CP10 platform inference)", Offset = platform.Index },
            new() { Type = "Software Nr.", Value = boschSoftware.Groups["software"].Value, Offset = boschSoftware.Groups["software"].Index },
            new() { Type = "OEM software Nr.", Value = identification.Groups["software"].Value, Offset = identification.Groups["software"].Index },
            new() { Type = "Software Upgrade Nr.", Value = identification.Groups["upgrade"].Value, Offset = identification.Groups["upgrade"].Index },
            new() { Type = "Spare part number", Value = identification.Groups["part"].Value, Offset = identification.Groups["part"].Index },
            new() { Type = "ECU profile", Value = platform.Groups["profile"].Value.ToUpperInvariant(), Offset = platform.Groups["profile"].Index },
            new() { Type = "Calibration version", Value = platform.Groups["calibration"].Value, Offset = platform.Groups["calibration"].Index }
        };

        var systemType = SystemTypePattern.Match(text, identification.Index);
        if (systemType.Success && systemType.Index - identification.Index < 0x100)
            matches.Add(new IdentifierMatch { Type = "System type", Value = systemType.Value, Offset = systemType.Index });

        return matches;
    }
}

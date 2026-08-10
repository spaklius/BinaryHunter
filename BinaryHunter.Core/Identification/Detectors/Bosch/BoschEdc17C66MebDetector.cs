using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Mercedes-Benz Bosch EDC17C66 reads contain a structured four-field OEM ID
// block. Full images retain two C66 runtime descriptors; 0xE0000 OBD partials
// retain one. Requiring the complete size-specific structure prevents isolated
// 10-digit Mercedes part numbers from selecting this profile.
internal sealed class BoschEdc17C66MebDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;
    private const int PartialObdImageSize = 0xE0000;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/(?<type>EDC17C66)/1/(?<platform>P[A-Z0-9]+)//(?<calibration>P_[A-Z0-9_]+)///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationPattern = new(
        @"(?<!\d)(?<part>\d{3}901\d{4})\x00" +
        @"(?<hardware>\d{3}904\d{4})\x00" +
        @"(?<software>\d{3}902\d{4})\x00" +
        @"(?<upgrade>\d{3}903\d{4})\x00",
        RegexOptions.Compiled);

    public string Name => "Bosch EDC17C66 MEB";
    public string Manufacturer => "Mercedes-Benz";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length is not (FullImageSize or PartialObdImageSize)) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToList();
        var identification = IdentificationPattern.Matches(text).Cast<Match>()
            .OrderByDescending(match => match.Index)
            .FirstOrDefault();
        var requiredPlatformCount = image.Bytes.Length == FullImageSize ? 2 : 1;
        if (platforms.Count < requiredPlatformCount || identification is null)
            return [];

        var platform = platforms[0].Groups["type"];
        return
        [
            new IdentifierMatch { Type = "Read format", Value = GetReadFormat(image.Bytes.Length), Offset = platform.Index },
            new IdentifierMatch { Type = "Vehicle group", Value = "Mercedes-Benz", Offset = identification.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC17C66", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC17C66", Offset = platform.Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon TC1791/TC1793 (EDC17C66 platform inference)", Offset = platform.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "Software Nr.", Value = identification.Groups["software"].Value, Offset = identification.Groups["software"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = identification.Groups["upgrade"].Value, Offset = identification.Groups["upgrade"].Index }
        ];
    }

    private static string GetReadFormat(int imageSize) => imageSize == FullImageSize
        ? "Full flash image (4 MB)"
        : "Partial calibration image (OBD protocol, 917504 bytes)";
}
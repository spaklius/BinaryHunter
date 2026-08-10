using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Honda EDC17CP06 full reads carry two matching EDC17_CP06 platform records,
// a Honda-format 37805-xxx-xxxx ECU reference and mirrored Bosch software
// fields. These signals distinguish the profile from BMW heuristics triggered
// by incidental DDE-like bytes in calibration data.
internal sealed class BoschHondaEdc17Cp06Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int BaseSoftwareOffset = 0x401A;
    private const int SoftwareOffset = 0x4001A;

    private static readonly Regex PlatformPattern = new(
        @"EDC17_CP06/(?<variant>\d{3})/(?<generation>P\d+)//(?<calibration>[A-Z0-9]+)///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HondaEcuPartPattern = new(
        @"(?<![A-Z0-9])37805-[A-Z0-9]{3}-[A-Z0-9]{4}(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"^1037\d{6}$",
        RegexOptions.Compiled);

    public string Name => "Bosch Honda EDC17CP06";
    public string Manufacturer => "HONDA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var platforms = PlatformPattern.Matches(image.AsciiText).Cast<Match>().ToArray();
        if (platforms.Length < 2) return [];
        if (!platforms.Skip(1).All(match =>
                string.Equals(match.Groups["calibration"].Value, platforms[0].Groups["calibration"].Value, StringComparison.OrdinalIgnoreCase)))
            return [];

        var hondaPart = HondaEcuPartPattern.Match(image.AsciiText);
        if (!hondaPart.Success) return [];

        var baseSoftware = Encoding.ASCII.GetString(image.Bytes, BaseSoftwareOffset, 10);
        var software = Encoding.ASCII.GetString(image.Bytes, SoftwareOffset, 10);
        if (!SoftwarePattern.IsMatch(baseSoftware) || !SoftwarePattern.IsMatch(software)) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Full flash image (2 MB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Honda Motor Company", Offset = hondaPart.Index },
            new() { Type = "Vehicle manufacturer", Value = "Honda", Offset = hondaPart.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platforms[0].Index },
            new() { Type = "ECU family", Value = "Bosch EDC17CP06", Offset = platforms[0].Index },
            new() { Type = "ECU type", Value = "EDC17CP06", Offset = platforms[0].Index },
            new() { Type = "Processor", Value = "Infineon TC1792 (EDC17CP06 platform inference)", Offset = platforms[0].Index },
            new() { Type = "Software Nr.", Value = software, Offset = SoftwareOffset },
            new() { Type = "Platform version", Value = platforms[0].Groups["calibration"].Value, Offset = platforms[0].Groups["calibration"].Index },
            new() { Type = "Honda ECU part Nr.", Value = hondaPart.Value.ToUpperInvariant(), Offset = hondaPart.Index }
        };

        if (!string.Equals(baseSoftware, software, StringComparison.Ordinal))
            matches.Add(new IdentifierMatch { Type = "Base software Nr.", Value = baseSoftware, Offset = BaseSoftwareOffset });

        return matches;
    }
}

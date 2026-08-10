using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Jaguar/Land Rover Bosch MEDC17.9 full reads carry two independent Bosch
// runtime descriptors plus fixed-position JLR hardware and software records.
// Requiring the complete structure avoids identifying other Ford-format Bosch
// ECUs from a single shared 12B684/14C204 component number.
internal sealed class BoschMedc179JaguarLandRoverDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;
    private const int HardwareOffset = 0xFD00;
    private const int SoftwareOffset = 0x1FFF02;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/(?<type>MEDC17_9)/190/(?<platform>P[A-Z0-9]+)//(?<calibration>P[A-Z0-9_]+)///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HardwarePattern = new(
        @"(?<![A-Z0-9])(?<hardware>[A-Z0-9]{4}-12B684-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>[A-Z0-9]{4}-14C204-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>[A-Z0-9]{4}-12K532-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch MEDC17.9 Jaguar/Land Rover";
    public string Manufacturer => "Jaguar/Land Rover";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToList();
        var hardware = HardwarePattern.Match(text, HardwareOffset);
        var software = SoftwarePattern.Match(text, SoftwareOffset);
        if (platforms.Count < 2 ||
            !hardware.Success || hardware.Groups["hardware"].Index != HardwareOffset ||
            !software.Success || software.Groups["software"].Index != SoftwareOffset)
            return [];

        var platform = platforms[0].Groups["type"];
        var upgrade = UpgradePattern.Matches(text).Cast<Match>()
            .OrderByDescending(match => match.Index)
            .FirstOrDefault();

        List<IdentifierMatch> matches =
        [
            new() { Type = "Read format", Value = "Full flash image (4 MB)", Offset = platform.Index },
            new() { Type = "Vehicle group", Value = "Jaguar/Land Rover", Offset = hardware.Groups["hardware"].Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new() { Type = "ECU family", Value = "Bosch MEDC17.9", Offset = platform.Index },
            new() { Type = "ECU type", Value = "MEDC17.9", Offset = platform.Index },
            new() { Type = "Processor", Value = "Infineon TC1791/TC1793 (MEDC17.9 platform inference)", Offset = platform.Index },
            new() { Type = "Hardware Nr.", Value = hardware.Groups["hardware"].Value, Offset = hardware.Groups["hardware"].Index },
            new() { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index }
        ];

        if (upgrade is not null)
            matches.Add(new IdentifierMatch
            {
                Type = "Software Upgrade Nr.",
                Value = upgrade.Groups["upgrade"].Value,
                Offset = upgrade.Groups["upgrade"].Index
            });

        return matches;
    }
}
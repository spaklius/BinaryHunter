using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Jaguar/Land Rover/PSA Bosch EDC17CP11 full reads contain two independent
// CP11 runtime descriptors, a fixed Bosch software record and Ford/JLR-format
// 12K532 calibration identifiers. The complete combination prevents a generic
// EDC17 runtime or an isolated part number from selecting this profile.
internal sealed class BoschEdc17Cp11JaguarLandRoverPsaDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int SoftwareOffset = 0x10001A;

    private static readonly Regex PlatformPattern = new(
        @"[A-Z]?\d{2,3}/1/(?<type>EDC17_CP11)/57/(?<platform>P[A-Z0-9]+)//(?<calibration>P[A-Z0-9_]+)///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<!\d)(?<software>1037\d{6})(?!\d)",
        RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>[A-Z0-9]{4}-12K532-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch EDC17CP11 Jaguar/Land Rover/PSA";
    public string Manufacturer => "Jaguar/Land Rover/PSA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToList();
        var software = SoftwarePattern.Match(text, SoftwareOffset);
        var upgrades = UpgradePattern.Matches(text).Cast<Match>().ToList();
        if (platforms.Count < 2 ||
            !software.Success || software.Groups["software"].Index != SoftwareOffset ||
            upgrades.Count == 0)
            return [];

        var platform = platforms[0].Groups["type"];
        var upgrade = upgrades.OrderByDescending(match => match.Index).First();

        return
        [
            new IdentifierMatch { Type = "Read format", Value = "Full flash image (2 MB)", Offset = platform.Index },
            new IdentifierMatch { Type = "Vehicle group", Value = "Jaguar/Land Rover/PSA", Offset = upgrade.Groups["upgrade"].Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC17CP11", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC17CP11", Offset = platform.Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon TC1796 (EDC17CP11 platform inference)", Offset = platform.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Value, Offset = upgrade.Groups["upgrade"].Index }
        ];
    }
}
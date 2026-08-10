using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Honda EDC17C58 full images (P1271, 1.6L i-DTEC) carry a repeating platform
// path banner and Honda-format software identifiers. The 4 MiB layout plus the
// platform path repetition avoids false positives from unrelated Bosch metadata.
internal sealed class BoschHondaEdc17C58Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex PlatformPattern = new(
        @"(?<![A-Z0-9])\d{2,3}/1/(?<type>EDC17C58)/\d{2,}/P[0-9A-Z]+//[A-Z0-9_]+///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>37820[A-Z0-9]{9})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>37805-[A-Z0-9]{3}-[A-Z0-9]{3,4})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"(?<![A-Z0-9])TC179[13](?!\d)",
        RegexOptions.Compiled);

    public string Name => "Bosch Honda EDC17C58";
    public string Manufacturer => "HONDA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToArray();
        if (platforms.Length < 2) return [];

        var processor = ProcessorPattern.Match(text);
        var software = SoftwarePattern.Match(text);
        var upgrades = UpgradePattern.Matches(text).Cast<Match>().ToArray();
        var upgrade = upgrades.Length > 0 ? upgrades[0] : null;

        if (!software.Success && upgrade is null) return [];

        var platform = platforms[^1];
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Honda Motor Company", Offset = platform.Index },
            new() { Type = "Vehicle manufacturer", Value = "Honda", Offset = platform.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new() { Type = "ECU family", Value = "Bosch EDC17C58", Offset = platform.Index },
            new() { Type = "ECU type", Value = "EDC17C58", Offset = platform.Index }
        };
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = $"Infineon {processor.Value}", Offset = processor.Index });
        if (software.Success)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index });
        if (upgrade is not null)
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Value, Offset = upgrade.Groups["upgrade"].Index });

        return matches;
    }
}

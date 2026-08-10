using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Ford Bosch EDC17C70 full images contain two independent platform paths, a
// repeated Bosch 1037+version program header, and Ford component-number blocks.
// Requiring all three structures avoids identifying a file from a lone library
// string or from one known Ford part number.
internal sealed class BoschFordEdc17C70Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex PlatformPattern = new(
        @"(?<![A-Z0-9])\d{2,3}/1/(?<type>EDC17C70)/\d{2}/[A-Z0-9]+//(?<platformVersion>P[A-Z0-9]+)///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BoschSoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>(?:1037\d{6}|10SW\d{6}))(?<version>[A-Z0-9]{8})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FordHardwarePattern = new(
        @"(?<![A-Z0-9])(?<hardware>[A-Z0-9]{4}-12B684-[A-Z0-9]{2})(?<componentRevision>[A-Z0-9])?(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FordSoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>(?<prefix>[A-Z0-9]{4})-12A650-(?<suffix>[A-Z0-9]{2,3}))(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FordUpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>(?<prefix>[A-Z0-9]{4})-14C204-(?<suffix>[A-Z0-9]{2,3}))(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HardwareVersionPattern = new(
        @"(?<![A-Z0-9])(?<version>[A-Z0-9]{4}-14C558-[A-Z0-9]{2})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Ford EDC17C70";
    public string Manufacturer => "FORD";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToList();
        var softwareHeaders = BoschSoftwarePattern.Matches(text).Cast<Match>().ToList();
        var hardware = FordHardwarePattern.Match(text);
        var oemSoftwareCandidates = FordSoftwarePattern.Matches(text).Cast<Match>().ToList();
        var upgrade = FordUpgradePattern.Match(text);
        var hardwareVersion = HardwareVersionPattern.Match(text);

        if (platforms.Count < 2 || softwareHeaders.Count < 2 ||
            !hardware.Success || oemSoftwareCandidates.Count == 0 || !upgrade.Success)
            return [];

        var platformVersions = platforms
            .Select(match => match.Groups["platformVersion"].Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var dominantSoftware = softwareHeaders.FirstOrDefault(match =>
                                   platformVersions.Contains(NormalizePlatformVersion(match.Groups["version"].Value))) ??
                               softwareHeaders
            .GroupBy(match => (Software: match.Groups["software"].Value.ToUpperInvariant(),
                               Version: match.Groups["version"].Value.ToUpperInvariant()))
            .OrderByDescending(group => group.Count())
            .Select(group => group.First())
            .First();
        var oemSoftware = oemSoftwareCandidates.FirstOrDefault(match =>
                              string.Equals(match.Groups["prefix"].Value, upgrade.Groups["prefix"].Value, StringComparison.OrdinalIgnoreCase) &&
                              string.Equals(match.Groups["suffix"].Value, upgrade.Groups["suffix"].Value, StringComparison.OrdinalIgnoreCase)) ??
                          oemSoftwareCandidates[0];
        var platform = platforms[0].Groups["type"];

        List<IdentifierMatch> matches =
        [
            new() { Type = "Vehicle group", Value = "Ford Motor Company", Offset = oemSoftware.Groups["software"].Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new() { Type = "ECU family", Value = "Bosch EDC17C70", Offset = platform.Index },
            new() { Type = "ECU type", Value = "EDC17C70", Offset = platform.Index },
            new() { Type = "Processor", Value = "Infineon TC1793 (EDC17C70 platform inference)", Offset = platform.Index },
            new() { Type = "Hardware Nr.", Value = hardware.Groups["hardware"].Value, Offset = hardware.Groups["hardware"].Index },
            new() { Type = "Software Nr.", Value = dominantSoftware.Groups["software"].Value, Offset = dominantSoftware.Groups["software"].Index },
            new() { Type = "Calibration version", Value = dominantSoftware.Groups["version"].Value, Offset = dominantSoftware.Groups["version"].Index },
            new() { Type = "OEM software Nr.", Value = oemSoftware.Groups["software"].Value, Offset = oemSoftware.Groups["software"].Index },
            new() { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Value, Offset = upgrade.Groups["upgrade"].Index }
        ];
        if (hardwareVersion.Success)
            matches.Insert(6, new IdentifierMatch { Type = "Hardware version", Value = hardwareVersion.Groups["version"].Value, Offset = hardwareVersion.Groups["version"].Index });

        return matches;
    }

    private static string NormalizePlatformVersion(string version) =>
        version.StartsWith('P') ? version : $"P{version}";
}

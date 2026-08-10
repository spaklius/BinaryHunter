using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Bosch EDC16CP33/C36/C41 full images used by the shared Renault/Nissan/Opel light-
// commercial and passenger-car platform. Identification is based on the
// platform path, repeated active Bosch software record, OEM upgrade block and
// the matching MPC561 firmware banner rather than a catalogue of part numbers.
internal sealed class BoschRenaultNissanOpelEdc16Cp33Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int PartialImageSize = 0x40000;

    private static readonly Regex PlatformPathPattern = new(
        @"(?<platform>\d{2,3}/1/(?<type>EDC16(?:CP33|C36|C41))/(?<revision>[^/\x00]+)/C(?<family>\d{3})/(?:[^/\x00]+/){1,3}(?<calibration>[A-Z0-9]+_XXX))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CalibrationHeaderPattern = new(
        @"(?<software>1037\d{6})P(?<family>\d{3})(?<version>[A-Z0-9_]{2,10})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex NissanCalibrationHeaderPattern = new(
        @"(?<software>1037\d{6})(?<family>\d{3})(?<version>[A-Z][A-Z0-9_]{2,10})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex NissanUpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>[A-Z]{2}\d{2}[A-Z])!(?<version>\d{3})(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FirmwareBannerPattern = new(
        @"BOSCH\s+EDC16\+/(?<type>EDC16(?:CP33|C36|C41))\s+(?<processor>MPC561)/Rev[A-Z0-9]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<!\d)1037\d{6}(?!\d)",
        RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"(?<!\d)82\d{8}(?!\d)",
        RegexOptions.Compiled);

    private static readonly Regex EnginePattern = new(
        @"(?<![A-Z0-9])M9R[A-Z0-9-]{3,8}(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Renault/Nissan/Opel EDC16CP33/C36/C41";
    public string Manufacturer => "RENAULT / NISSAN / OPEL";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platform = PlatformPathPattern.Match(text);
        var banner = FirmwareBannerPattern.Match(text);
        if (!platform.Success || !banner.Success) return [];
        if (!string.Equals(platform.Groups["type"].Value, banner.Groups["type"].Value,
                StringComparison.OrdinalIgnoreCase)) return [];

        Match activeSoftware;
        Match? baseSoftware;
        Match upgrade;
        var isNissanStructure = false;

        var nissanHeaders = NissanCalibrationHeaderPattern.Matches(text)
            .Cast<Match>()
            .Where(match => string.Equals(match.Groups["family"].Value, platform.Groups["family"].Value,
                StringComparison.OrdinalIgnoreCase))
            .ToList();
        var nissanUpgrade = NissanUpgradePattern.Matches(text)
            .Cast<Match>()
            .Select(match => new
            {
                Match = match,
                Count = Regex.Matches(text, Regex.Escape(match.Groups["upgrade"].Value), RegexOptions.IgnoreCase).Count
            })
            .Where(candidate => candidate.Count >= 2)
            .OrderByDescending(candidate => candidate.Count)
            .ThenByDescending(candidate => candidate.Match.Index)
            .Select(candidate => candidate.Match)
            .FirstOrDefault();

        if (nissanHeaders.Count > 0 && nissanUpgrade is not null)
        {
            isNissanStructure = true;
            activeSoftware = nissanHeaders
                .Where(match => match.Index < platform.Index)
                .OrderByDescending(match => match.Index)
                .FirstOrDefault() ?? nissanHeaders[^1];
            baseSoftware = nissanHeaders
                .Where(match => !string.Equals(match.Groups["software"].Value,
                    activeSoftware.Groups["software"].Value, StringComparison.OrdinalIgnoreCase))
                .GroupBy(match => match.Groups["software"].Value, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(group => group.Count())
                .SelectMany(group => group)
                .FirstOrDefault();
            upgrade = nissanUpgrade;
        }
        else
        {
            var softwareGroups = SoftwarePattern.Matches(text)
                .Cast<Match>()
                .GroupBy(match => match.Value, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(group => group.Count())
                .ThenBy(group => group.Min(match => match.Index))
                .ToList();
            if (softwareGroups.Count == 0 || softwareGroups[0].Count() < 2) return [];

            activeSoftware = softwareGroups[0].OrderBy(match => match.Index).First();
            baseSoftware = softwareGroups.Skip(1)
                .SelectMany(group => group)
                .Where(match => match.Index < platform.Index)
                .OrderByDescending(match => match.Index)
                .FirstOrDefault();
            upgrade = UpgradePattern.Matches(text)
                .Cast<Match>()
                .Where(match => match.Index < platform.Index && platform.Index - match.Index < 0x400)
                .OrderByDescending(match => match.Index)
                .FirstOrDefault()!;
            if (upgrade is null) return [];
        }

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Full flash image (2 MB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = $"Renault / Nissan / Opel (high confidence; {platform.Groups["type"].Value.ToUpperInvariant()} shared platform)", Offset = platform.Index },
            new() { Type = "ECU manufacturer", Value = $"Bosch (high confidence; {platform.Groups["type"].Value.ToUpperInvariant()} structural evidence)", Offset = banner.Index },
            new() { Type = "ECU type", Value = platform.Groups["type"].Value.ToUpperInvariant(), Offset = platform.Groups["type"].Index },
            new() { Type = "Processor", Value = "MPC561", Offset = banner.Groups["processor"].Index },
            new() { Type = "Software Nr.", Value = activeSoftware.Groups["software"].Success ? activeSoftware.Groups["software"].Value : activeSoftware.Value, Offset = activeSoftware.Groups["software"].Success ? activeSoftware.Groups["software"].Index : activeSoftware.Index },
            new() { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Success ? upgrade.Groups["upgrade"].Value : upgrade.Value, Offset = upgrade.Groups["upgrade"].Success ? upgrade.Groups["upgrade"].Index : upgrade.Index }
        };

        if (isNissanStructure)
            matches.Insert(2, new IdentifierMatch
            {
                Type = "Vehicle manufacturer",
                Value = "Nissan (high confidence; repeated Nissan OEM identifier)",
                Offset = upgrade.Groups["upgrade"].Index
            });

        var activeSoftwareValue = activeSoftware.Groups["software"].Success
            ? activeSoftware.Groups["software"].Value
            : activeSoftware.Value;
        var baseSoftwareValue = baseSoftware?.Groups["software"].Success == true
            ? baseSoftware.Groups["software"].Value
            : baseSoftware?.Value;
        var baseSoftwareOffset = baseSoftware?.Groups["software"].Success == true
            ? baseSoftware.Groups["software"].Index
            : baseSoftware?.Index ?? 0;
        if (baseSoftware is not null && !string.Equals(baseSoftwareValue, activeSoftwareValue, StringComparison.OrdinalIgnoreCase))
            matches.Add(new IdentifierMatch { Type = "Base software Nr.", Value = baseSoftwareValue!, Offset = baseSoftwareOffset });

        var engine = EnginePattern.Match(text, Math.Max(0, platform.Index - 0x80));
        if (engine.Success && engine.Index < platform.Index)
            matches.Add(new IdentifierMatch { Type = "Engine code", Value = engine.Value.ToUpperInvariant(), Offset = engine.Index });

        matches.Add(new IdentifierMatch
        {
            Type = "Calibration version",
            Value = platform.Groups["calibration"].Value,
            Offset = platform.Groups["calibration"].Index
        });

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectPartial(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        var platform = PlatformPathPattern.Match(text);
        if (!platform.Success) return [];

        var header = CalibrationHeaderPattern.Match(text, 0, Math.Min(0x40, text.Length));
        if (!header.Success ||
            !string.Equals(header.Groups["family"].Value, platform.Groups["family"].Value,
                StringComparison.OrdinalIgnoreCase))
            return [];

        var type = platform.Groups["type"].Value.ToUpperInvariant();
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Partial calibration image (256 KB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = $"Renault / Nissan / Opel (high confidence; {type} calibration structure)", Offset = platform.Index },
            new() { Type = "ECU manufacturer", Value = $"Bosch (high confidence; {type} calibration structure)", Offset = platform.Groups["type"].Index },
            new() { Type = "ECU type", Value = type, Offset = platform.Groups["type"].Index },
            new() { Type = "Processor", Value = $"MPC561 ({type} platform inference)", Offset = platform.Groups["type"].Index },
            new() { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
            new() { Type = "Calibration version", Value = platform.Groups["calibration"].Value, Offset = platform.Groups["calibration"].Index }
        };

        var upgrade = UpgradePattern.Matches(text)
            .Cast<Match>()
            .Where(match => match.Index < platform.Index)
            .OrderByDescending(match => match.Index)
            .FirstOrDefault();
        if (upgrade is not null)
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Value, Offset = upgrade.Index });

        return matches;
    }
}

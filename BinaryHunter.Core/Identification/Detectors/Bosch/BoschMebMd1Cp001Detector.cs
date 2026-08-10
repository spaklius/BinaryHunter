using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Bosch MD1CP001 MEB full reads are 8 MB (0x800000). The binary exposes
// a platform path `46/1/MD1CP001/1/DA_MDG1` and the software number is
// stored as plain ASCII immediately before it. The hardware number is at a
// fixed offset near the end of the image, and the software upgrade number
// is stored as plain ASCII elsewhere in the image.
internal sealed class BoschMebMd1Cp001Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x800000;

    private static readonly Regex PlatformPathPattern = new(
        @"\d{2,3}/1/MD1CP001/1/DA_MDG1",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwareUpgradePattern = new(
        @"\d{4}03\d{4}",
        RegexOptions.Compiled);

    private static readonly Regex EngineTypePattern = new(
        @"\d{3}[-_]?[A-Z0-9]*-OM\d{3}[A-Z]\d{2}_\d+kW-[A-Za-z0-9_-]+",
        RegexOptions.Compiled);

    public string Name => "Bosch Mercedes-Benz MD1CP001";
    public string Manufacturer => "Mercedes-Benz";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platform = PlatformPathPattern.Match(text);
        if (!platform.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Mercedes-Benz", Offset = platform.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new() { Type = "ECU family", Value = "Bosch MD1CP001", Offset = platform.Index },
            new() { Type = "ECU type", Value = "MD1CP001", Offset = platform.Index }
        };

        // Software Nr. is stored as plain ASCII near the platform path.
        // Search backward from the platform path marker to find the nearest 10-digit decimal number.
        var softwareMatch = Regex.Match(text.Substring(0, platform.Index), @"\d{10}(?=[^0-9]*$)", RegexOptions.RightToLeft);
        var softwareValue = softwareMatch.Success ? softwareMatch.Value : null;
        if (!string.IsNullOrEmpty(softwareValue) && softwareValue.All(char.IsAsciiDigit))
        {
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = softwareValue, Offset = softwareMatch.Index });
        }

        // Hardware Nr. is at a fixed offset near the end of the image
        const int hardwareOffset = 0x7D86D5;
        if (hardwareOffset + 10 <= image.Bytes.Length)
        {
            var hardware = text.Substring(hardwareOffset, 10);
            if (long.TryParse(hardware, out _))
                matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware, Offset = hardwareOffset });
        }

        // Software Upgrade Nr. is stored as plain ASCII elsewhere in the image.
        // Exclude the software number found above.
        var upgrade = SoftwareUpgradePattern.Matches(text)
            .Cast<Match>()
            .FirstOrDefault(m => m.Value != softwareValue);
        if (upgrade is not null)
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Value, Offset = upgrade.Index });

        // Engine type is stored as plain ASCII in the image.
        var engine = EngineTypePattern.Match(text);
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });

        return matches;
    }
}

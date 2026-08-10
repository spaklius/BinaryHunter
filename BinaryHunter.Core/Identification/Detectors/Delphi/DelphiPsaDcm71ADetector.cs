using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Delphi;

// PSA/Stellantis Delphi DCM7.1A full and partial reads are 6,291,456 bytes.
// The binary exposes a repeated APSA header marker and the software upgrade
// number inside an FOS_<upgrade>_<version>_<processor> block. Hardware and
// software numbers are not stored as readable ASCII in this layout, so the
// detector confirms from the APSA marker and emits the upgrade when present.
internal sealed class DelphiPsaDcm71ADetector : IEcuDetectionModule
{
    private const int ImageSize = 0x600000;

    private static readonly Regex HeaderPattern = new(
        @"APSA",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"FOS_(?<upgrade>\d{10})_",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Delphi PSA DCM7.1A";
    public string Manufacturer => "PSA / STELLANTIS";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != ImageSize) return [];

        if (!HeaderPattern.IsMatch(image.AsciiText)) return [];

        var upgrade = UpgradePattern.Match(image.AsciiText);
        if (!upgrade.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "PSA / Stellantis", Offset = 0 },
            new() { Type = "ECU manufacturer", Value = "Delphi", Offset = 0 },
            new() { Type = "ECU family", Value = "Delphi DCM7.1A", Offset = 0 },
            new() { Type = "ECU type", Value = "DCM7.1A", Offset = 0 },
            new() { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Value, Offset = upgrade.Index }
        };

        return matches;
    }
}

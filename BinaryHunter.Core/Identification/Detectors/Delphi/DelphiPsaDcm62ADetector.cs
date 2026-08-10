using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Delphi;

// PSA/Stellantis Delphi DCM6.2A full reads are 4,194,304 bytes. The binary
// exposes repeated PSA project markers and an FOS_<variant>_<software> block
// that carries the software upgrade number. Hardware/software numbers are not
// stored as readable ASCII in this layout, so the detector confirms from the
// PSA marker and emits the upgrade when present.
internal sealed class DelphiPsaDcm62ADetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex PsaHeaderPattern = new(
        @"1MPSA[A-Z0-9_]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"FOS_(?:[A-Z0-9]+_)*?(?<upgrade>\d{10})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Delphi PSA DCM6.2A";
    public string Manufacturer => "PSA / STELLANTIS";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        if (!PsaHeaderPattern.IsMatch(image.AsciiText)) return [];

        var upgrade = UpgradePattern.Match(image.AsciiText);
        if (!upgrade.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Full flash image (4 MB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = "PSA / Stellantis", Offset = 0 },
            new() { Type = "ECU manufacturer", Value = "Delphi", Offset = 0 },
            new() { Type = "ECU family", Value = "Delphi DCM6.2A", Offset = 0 },
            new() { Type = "ECU type", Value = "DCM6.2A", Offset = 0 },
            new() { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Value, Offset = upgrade.Index }
        };

        return matches;
    }
}

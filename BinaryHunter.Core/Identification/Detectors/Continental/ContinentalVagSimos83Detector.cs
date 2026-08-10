using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// SIMOS8.3 uses CAS83/S83 dataset records. Its compact VAG ID block contains
// an upgrade part/revision followed by a base software reference and engine
// code; unlike SIMOS8.5 it does not expose the EV_ECM/J623 tail.
internal sealed class ContinentalVagSimos83Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int MinimumS83ModuleCount = 6;

    private static readonly Regex DatasetPattern = new(
        @"CAS83[A-Z0-9]{2,8}\.DAT",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ModulePattern = new(
        @"S83[A-Z0-9]{4,14}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<upgradePart>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<engine>\d\.\d\s+V\d\s+(?:TFSI|TDI|TSI))[ \x00]+" +
        @"(?<revision>\d{4})(?<baseSoftware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<engineCode>[A-Z0-9]{3,5})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental VAG SIMOS8.3";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var dataset = DatasetPattern.Match(image.AsciiText);
        if (!dataset.Success || ModulePattern.Matches(image.AsciiText).Count < MinimumS83ModuleCount) return [];

        var identification = IdentificationBlockPattern.Match(image.AsciiText);
        if (!identification.Success) return [];

        var upgradePart = identification.Groups["upgradePart"];
        var revision = identification.Groups["revision"];
        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group (SIMOS OEM-block evidence)", Offset = upgradePart.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental SIMOS8", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU type", Value = "SIMOS8.3", Offset = dataset.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{upgradePart.Value} {revision.Value}", Offset = upgradePart.Index },
            new IdentifierMatch { Type = "Base software Nr.", Value = identification.Groups["baseSoftware"].Value, Offset = identification.Groups["baseSoftware"].Index },
            new IdentifierMatch { Type = "Engine", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engineCode"].Value, Offset = identification.Groups["engineCode"].Index }
        ];
    }
}

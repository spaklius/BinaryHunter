using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// VAG SIMOS8.5 full images expose their platform through CAS85/S85 dataset
// records. The ID block repeats the OEM software number around engine, revision,
// ASAM and control-unit fields, allowing extraction without a part-number list.
internal sealed class ContinentalVagSimos85Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int MinimumS85ModuleCount = 6;

    private static readonly Regex DatasetPattern = new(
        @"CAS85[A-Z0-9]{2,8}\.DAT",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ModulePattern = new(
        @"S85[A-Z0-9]{4,14}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<software>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<engine>\d\.\dl\s+V\d\s+(?:TFSI|TDI|TSI))[ \x00]+" +
        @"(?<revision>\d{4})(?<baseSoftware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<engineCode>[A-Z0-9]{3,5})(?<asam>EV_ECM[A-Z0-9]+?)\k<software>[\x00 ]+" +
        @"(?<calibration>\d{6})(?<control>J\d{3})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AudiMarkerPattern = new(
        @"AUDI",
        RegexOptions.Compiled);

    public string Name => "Continental VAG SIMOS8.5";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var dataset = DatasetPattern.Match(image.AsciiText);
        if (!dataset.Success || ModulePattern.Matches(image.AsciiText).Count < MinimumS85ModuleCount) return [];

        var identification = IdentificationBlockPattern.Match(image.AsciiText);
        if (!identification.Success) return [];
        var software = identification.Groups["software"];
        if (Regex.Matches(image.AsciiText, Regex.Escape(software.Value), RegexOptions.IgnoreCase).Count < 2) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group (SIMOS OEM-block evidence)", Offset = software.Index },
            new() { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = dataset.Index },
            new() { Type = "ECU family", Value = "Siemens/Continental SIMOS8", Offset = dataset.Index },
            new() { Type = "ECU type", Value = "SIMOS8.5", Offset = dataset.Index },
            new() { Type = "Processor", Value = "Infineon TC1796 (SIMOS8.5 platform inference)", Offset = dataset.Index },
            new() { Type = "Software Nr.", Value = software.Value, Offset = software.Index },
            new() { Type = "Software Upgrade Nr.", Value = $"{software.Value} {identification.Groups["revision"].Value}", Offset = identification.Groups["revision"].Index },
            new() { Type = "Engine", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index },
            new() { Type = "Engine code", Value = identification.Groups["engineCode"].Value, Offset = identification.Groups["engineCode"].Index },
            new() { Type = "ASAM software Nr.", Value = identification.Groups["asam"].Value, Offset = identification.Groups["asam"].Index },
            new() { Type = "Calibration Nr.", Value = identification.Groups["calibration"].Value, Offset = identification.Groups["calibration"].Index },
            new() { Type = "Control unit", Value = identification.Groups["control"].Value, Offset = identification.Groups["control"].Index }
        };

        var baseSoftware = identification.Groups["baseSoftware"];
        if (!string.Equals(baseSoftware.Value, software.Value, StringComparison.OrdinalIgnoreCase))
            matches.Add(new IdentifierMatch { Type = "Base software Nr.", Value = baseSoftware.Value, Offset = baseSoftware.Index });

        var audiMarker = AudiMarkerPattern.Match(image.AsciiText);
        if (audiMarker.Success)
            matches.Add(new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi (raw/OEM evidence)", Offset = audiMarker.Index });

        return matches;
    }
}

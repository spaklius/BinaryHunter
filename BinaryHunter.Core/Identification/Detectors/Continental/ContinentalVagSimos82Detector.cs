using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// SIMOS8.2 calibration reads expose the same compact OEM block as full SIMOS8
// images even when code, processor and VIN areas are absent. CAS82/S82 dataset
// records plus the repeated software reference make the block self-validating.
internal sealed class ContinentalVagSimos82Detector : IEcuDetectionModule
{
    private const int CommonPartialImageSize = 0x40000;
    private const int IdentificationSearchLimit = 1024;

    private static readonly Regex DatasetPattern = new(
        @"(?<dataset>CAS82[A-Z0-9]{2,8})\.DAT",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ModulePattern = new(
        @"S82[A-Z0-9]{4,14}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<software>[A-Z0-9]{3}\d{6}[A-Z]{0,2})\s*\x00" +
        @"(?<displacement>\d\.\d)\s+SIMOS8\.2\s*\x00" +
        @"(?<revision>\d{4})(?<baseSoftware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})\s*\x00" +
        @"(?<engineCode>[A-Z0-9]{3,5})(?<asam>EV_ECM[A-Z0-9]+?)\k<software>\s*\x00" +
        @"(?<calibration>[A-Z0-9]{6})(?<control>J\d{3})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental VAG SIMOS8.2";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var searchLength = Math.Min(IdentificationSearchLimit, image.AsciiText.Length);
        var headerText = image.AsciiText[..searchLength];
        var dataset = DatasetPattern.Match(headerText);
        if (!dataset.Success || ModulePattern.Matches(headerText).Count < 3) return [];

        var identification = IdentificationBlockPattern.Match(headerText);
        if (!identification.Success) return [];

        var software = identification.Groups["software"];
        if (Regex.Matches(headerText, Regex.Escape(software.Value), RegexOptions.IgnoreCase).Count < 2)
            return [];

        var revision = identification.Groups["revision"];
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group (SIMOS OEM-block evidence)", Offset = software.Index },
            new() { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = dataset.Index },
            new() { Type = "ECU family", Value = "Siemens/Continental SIMOS8", Offset = dataset.Index },
            new() { Type = "ECU type", Value = "SIMOS8.2", Offset = dataset.Index },
            new() { Type = "Software Nr.", Value = software.Value, Offset = software.Index },
            new() { Type = "Software Upgrade Nr.", Value = $"{software.Value} {revision.Value}", Offset = software.Index },
            new() { Type = "Base software Nr.", Value = identification.Groups["baseSoftware"].Value, Offset = identification.Groups["baseSoftware"].Index },
            new() { Type = "Engine", Value = $"{identification.Groups["displacement"].Value} FSI", Offset = identification.Groups["displacement"].Index },
            new() { Type = "Engine code", Value = identification.Groups["engineCode"].Value, Offset = identification.Groups["engineCode"].Index },
            new() { Type = "ASAM software Nr.", Value = identification.Groups["asam"].Value, Offset = identification.Groups["asam"].Index },
            new() { Type = "Calibration Nr.", Value = identification.Groups["calibration"].Value, Offset = identification.Groups["calibration"].Index },
            new() { Type = "Control unit", Value = identification.Groups["control"].Value, Offset = identification.Groups["control"].Index }
        };

        if (image.Bytes.Length == CommonPartialImageSize)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = $"Partial calibration image ({image.DisplaySize})", Offset = 0 });

        return matches;
    }
}

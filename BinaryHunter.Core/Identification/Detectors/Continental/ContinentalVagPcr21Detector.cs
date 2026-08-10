using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// PCR2.1 OBD reads retain the same compact SIMOS-M2 identification header in
// partial and full images. CASM2 dataset data, three repeated SM2 modules and
// the EV_ECM16TDI ASAM/software pair independently confirm the platform before
// identifiers are read from the neighboring VAG OEM block.
internal sealed class ContinentalVagPcr21Detector : IEcuDetectionModule
{
    private const int PartialObdImageSize = 0x7AE00;
    private const int FullImageSize = 0x200000;
    private const int FullObdImageSize = 0x220000;
    private const int IdentificationSearchDistance = 256;

    private const string SoftwareShape = @"03L(?:906023|99755[78])[A-Z]{0,2}";
    private const string PartNumberShape = @"03L\d{6}[A-Z]{0,2}";

    private static readonly Regex DatasetPattern = new(
        @"(?<dataset>CASM2[A-Z0-9]{2,8}\.DAT)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ModulePattern = new(
        @"SM2[A-Z0-9]{8,14}?(?=111SM2|CASM2|\x00)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AsamSoftwarePattern = new(
        $@"(?<asam>EV_ECM16TDI\d{{3}})(?<software>{SoftwareShape})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationPattern = new(
        $@"(?<calibration>\d{{12,18}})--[ \x00]*" +
        $@"(?<datasetPart>{PartNumberShape})[ \x00]+" +
        $@"(?<baseSoftware>{SoftwareShape})[ \x00\x01]+" +
        @"(?<system>(?:\d[,.]\dl\s+R4\s+CR\s+tdi|R4\s+1[,.]6l\s+TDI))[ \x00]+" +
        @"(?<revision>\d{4})---\x00" +
        @"(?<hardware>CAY[A-Z])(?<control>J\d{3})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental VAG PCR2.1";
    public string Manufacturer => "AUDI / VW / \u0160KODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length is not (PartialObdImageSize or FullImageSize or FullObdImageSize))
            return [];

        var text = image.AsciiText;
        var dataset = DatasetPattern.Match(text);
        if (!dataset.Success) return [];

        var blockStart = dataset.Index;
        var blockLength = Math.Min(IdentificationSearchDistance, text.Length - blockStart);
        var blockText = text.Substring(blockStart, blockLength);
        if (!ModulePattern.Matches(blockText).Cast<Match>()
                .GroupBy(match => match.Value, StringComparer.OrdinalIgnoreCase)
                .Any(group => group.Count() >= 3)) return [];

        var asamSoftware = AsamSoftwarePattern.Match(blockText);
        var identification = IdentificationPattern.Match(blockText);
        if (!asamSoftware.Success || !identification.Success) return [];

        var software = asamSoftware.Groups["software"];
        var datasetPart = identification.Groups["datasetPart"];
        var revision = identification.Groups["revision"];
        var hardware = identification.Groups["hardware"];

        return
        [
            new IdentifierMatch { Type = "Read format", Value = GetReadFormat(image.Bytes.Length), Offset = blockStart },
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = blockStart + datasetPart.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental PCR2", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU type", Value = "PCR2.1", Offset = dataset.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Value, Offset = blockStart + software.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{software.Value}  {revision.Value}", Offset = blockStart + software.Index },
            new IdentifierMatch { Type = "Base software Nr.", Value = identification.Groups["baseSoftware"].Value, Offset = blockStart + identification.Groups["baseSoftware"].Index },
            new IdentifierMatch { Type = "ASAM software Nr.", Value = asamSoftware.Groups["asam"].Value, Offset = blockStart + asamSoftware.Groups["asam"].Index },
            new IdentifierMatch { Type = "Calibration Nr.", Value = identification.Groups["calibration"].Value, Offset = blockStart + identification.Groups["calibration"].Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = blockStart + hardware.Index },
            new IdentifierMatch { Type = "System type", Value = identification.Groups["system"].Value, Offset = blockStart + identification.Groups["system"].Index },
            new IdentifierMatch { Type = "Control unit", Value = identification.Groups["control"].Value, Offset = blockStart + identification.Groups["control"].Index }
        ];
    }

    private static string GetReadFormat(int imageSize) => imageSize switch
    {
        PartialObdImageSize => "Partial calibration image (OBD protocol, 503296 bytes)",
        FullImageSize => "Full flash image (2 MB)",
        FullObdImageSize => "Full OBD image (2.125 MB)",
        _ => "Binary image"
    };
}

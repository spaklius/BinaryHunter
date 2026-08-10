using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// SIMOS8.1 full images use CAS81/S81 dataset records. Their ID block mirrors
// later SIMOS layouts but separates engine/revision with a NUL byte and carries
// a TriCore runtime banner elsewhere in the image.
internal sealed class ContinentalVagSimos81Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int SoftwareSearchDistance = 256;
    private const int IdentificationSearchDistance = 256;

    private static readonly Regex DatasetPattern = new(
        @"CAS81[A-Z0-9]{2,8}\.DAT",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ModulePattern = new(
        @"S81[A-Z0-9]{4,14}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"ERCOSEK\s+V\d+(?:\.\d+){1,3}\s+TriCore",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<!\d)(?<software>\d{10})--",
        RegexOptions.Compiled);

    private static readonly Regex IdentificationTailPattern = new(
        @"(?<upgradePart>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<engine>\d\.\dl?\s+V\d{1,2}\s+(?:FSI|TFSI|TDI|TSI))[ \x00]+" +
        @"(?<revision>\d{4})(?<baseSoftware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<engineCode>[A-Z0-9]{3,5})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental VAG SIMOS8.1";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var dataset = DatasetPattern.Match(text);
        var processor = ProcessorPattern.Match(text);
        if (!dataset.Success || !processor.Success || ModulePattern.Matches(text).Count < 3) return [];

        var softwareSearchStart = Math.Max(0, dataset.Index - SoftwareSearchDistance);
        var softwareSearchLength = dataset.Index - softwareSearchStart;
        var softwareMatches = SoftwarePattern.Matches(text.Substring(softwareSearchStart, softwareSearchLength));
        if (softwareMatches.Count == 0) return [];
        var software = softwareMatches[^1].Groups["software"];
        var softwareOffset = softwareSearchStart + software.Index;

        var tailStart = dataset.Index + dataset.Length;
        var tailLength = Math.Min(IdentificationSearchDistance, text.Length - tailStart);
        var identification = IdentificationTailPattern.Match(text, tailStart, tailLength);
        if (!identification.Success) return [];

        var upgradePart = identification.Groups["upgradePart"];
        var revision = identification.Groups["revision"];
        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = upgradePart.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental SIMOS8", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU type", Value = "SIMOS8.1", Offset = dataset.Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon TriCore (raw runtime marker)", Offset = processor.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Value, Offset = softwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{upgradePart.Value} {revision.Value}", Offset = upgradePart.Index },
            new IdentifierMatch { Type = "Base software Nr.", Value = identification.Groups["baseSoftware"].Value, Offset = identification.Groups["baseSoftware"].Index },
            new IdentifierMatch { Type = "Engine", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engineCode"].Value, Offset = identification.Groups["engineCode"].Index }
        ];
    }
}

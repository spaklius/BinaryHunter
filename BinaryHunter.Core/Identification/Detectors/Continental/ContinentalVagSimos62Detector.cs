using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// SIMOS6.2 images identify their platform through CAS62/S62 dataset records.
// Full images also carry the C6MB processor-area marker; calibration-only reads
// retain the complete OEM block and can be identified without guessing fields
// from the missing code area.
internal sealed class ContinentalVagSimos62Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int SoftwareSearchDistance = 256;
    private const int IdentificationSearchDistance = 256;

    private static readonly Regex PlatformPattern = new(
        @"(?<![A-Z0-9])C6MB[_-][A-Z0-9]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DatasetPattern = new(
        @"CAS62[A-Z0-9]{2,8}\.DAT",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ModulePattern = new(
        @"S62[A-Z0-9]{4,14}",
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

    public string Name => "Continental VAG SIMOS6.2";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length < 512 || image.Bytes.Length > FullImageSize) return [];

        var text = image.AsciiText;
        var platform = PlatformPattern.Match(text);
        var dataset = DatasetPattern.Match(text);
        if (!dataset.Success || ModulePattern.Matches(text).Count < 3) return [];

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
        var matches = new List<IdentifierMatch>
        {
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = upgradePart.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental SIMOS6", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU type", Value = "SIMOS6.2", Offset = dataset.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Value, Offset = softwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{upgradePart.Value} {revision.Value}", Offset = upgradePart.Index },
            new IdentifierMatch { Type = "Base software Nr.", Value = identification.Groups["baseSoftware"].Value, Offset = identification.Groups["baseSoftware"].Index },
            new IdentifierMatch { Type = "Engine", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engineCode"].Value, Offset = identification.Groups["engineCode"].Index }
        };

        if (platform.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = "Motorola MPC563 (SIMOS6.2 platform inference)", Offset = platform.Index });
        if (image.Bytes.Length < FullImageSize)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = $"Partial calibration image ({image.DisplaySize})", Offset = 0 });

        return matches;
    }
}

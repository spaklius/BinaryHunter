using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Full VAG MED9.1.1 images carry three independent pieces of structural
// evidence: the MED911/5 platform banner, an MPC56x runtime banner, and a
// NUL-delimited Bosch/VAG identification block. Requiring all three keeps the
// detector independent of a catalogue of known part or software numbers.
internal sealed class BoschVagMed911Detector : IEcuDetectionModule
{
    private const int MaximumTailDistance = 256;

    private static readonly Regex PlatformPattern = new(
        @"(?<![A-Z0-9])MED9(?:[._-]?1){2}/5/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"ERCOSEK\s+V\d+(?:\.\d+){1,3}\s+MPC56x",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationHeaderPattern = new(
        @"(?<![A-Z0-9])(?<hardware>0261S\d{5})\x00" +
        @"(?<software>1037\d{6})\x00" +
        @"(?<softwareVersion>[A-Z]\d(?:\.\d+){2})\s*\x00" +
        @"(?<project>P\d{3,5})\s*\x00",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationTailPattern = new(
        @"(?<engineCode>[A-Z][A-Z0-9]{2,4})\x00" +
        @"(?<control>J\d{3})\s*\x00" +
        @"(?<upgradePart>[A-Z0-9]{3}\d{6}[A-Z]{0,2})\s*\x00" +
        @"(?<engine>\d(?:\.\d)?l\s+V\d{1,2}/\dV)\s*\x00" +
        @"(?<revision>\d{4})\x00",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch VAG MED9.1.1";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        var platform = PlatformPattern.Match(text);
        var processor = ProcessorPattern.Match(text);
        if (!platform.Success || !processor.Success) return [];

        foreach (Match header in IdentificationHeaderPattern.Matches(text))
        {
            var tailStart = header.Index + header.Length;
            var tailLength = Math.Min(MaximumTailDistance, text.Length - tailStart);
            if (tailLength <= 0) continue;

            var tail = IdentificationTailPattern.Match(text, tailStart, tailLength);
            if (!tail.Success) continue;

            var upgradePart = tail.Groups["upgradePart"];
            var revision = tail.Groups["revision"];
            return
            [
                new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = upgradePart.Index },
                new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
                new IdentifierMatch { Type = "ECU family", Value = "Bosch MED9.1.1", Offset = platform.Index },
                new IdentifierMatch { Type = "ECU type", Value = "MED9.1.1", Offset = platform.Index },
                new IdentifierMatch { Type = "Processor", Value = "MPC56x", Offset = processor.Index },
                new IdentifierMatch { Type = "Hardware Nr.", Value = header.Groups["hardware"].Value, Offset = header.Groups["hardware"].Index },
                new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
                new IdentifierMatch { Type = "Software version", Value = header.Groups["softwareVersion"].Value, Offset = header.Groups["softwareVersion"].Index },
                new IdentifierMatch { Type = "Project Nr.", Value = header.Groups["project"].Value, Offset = header.Groups["project"].Index },
                new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{upgradePart.Value} {revision.Value}", Offset = upgradePart.Index },
                new IdentifierMatch { Type = "Engine", Value = tail.Groups["engine"].Value.Trim(), Offset = tail.Groups["engine"].Index },
                new IdentifierMatch { Type = "Engine code", Value = tail.Groups["engineCode"].Value, Offset = tail.Groups["engineCode"].Index },
                new IdentifierMatch { Type = "Control unit", Value = tail.Groups["control"].Value.Trim(), Offset = tail.Groups["control"].Index }
            ];
        }

        return [];
    }
}

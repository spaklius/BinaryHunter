using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// VAG MED17.1-family images combine a Bosch MED17.1 platform banner and
// TriCore runtime with a repeated OEM software block. The ASAM field refines
// the exact MED17.1 versus MED17.1.1 type; the remaining fields are extracted
// without relying on a catalogue of known VAG part numbers.
internal sealed class BoschVagMed1711Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/MED17/5/MED17\.1//[A-Z0-9_./-]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"ERCOSEK\s+V\d+(?:\.\d+){1,3}\s+TriCore_g",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<hardware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<asam>EV_ECM[A-Z0-9]+?)(?<oemSoftware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<calibration>[A-Z0-9]{6})[ \x00]+\k<oemSoftware>[ \x00]+" +
        @"(?<revision>\d{4})[ \x00]+\(MEDC17\)[ \x00]+" +
        @"(?<engine>\d\.\dl\s+R\d/\dV\s+(?:FSI|TFSI|TDI|TSI))[ \x00]+" +
        @"(?<engineCodes>(?:[A-Z0-9]{3,5}[ \x00]+){1,12})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BoschNumericSoftwarePattern = new(
        @"(?<![A-Z0-9])1037\d{6}(?!\d)",
        RegexOptions.Compiled);

    private static readonly Regex BoschTenSoftwarePattern = new(
        @"(?<![A-Z0-9])10SW\d{6}(?=0{4,})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch VAG MED17.1 family";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platform = PlatformPattern.Match(text);
        var processor = ProcessorPattern.Match(text);
        var identification = IdentificationBlockPattern.Match(text);
        if (!platform.Success || !processor.Success || !identification.Success) return [];

        var asam = identification.Groups["asam"];
        var ecuType = asam.Value.EndsWith("011", StringComparison.OrdinalIgnoreCase)
            ? "MED17.1.1"
            : string.Equals(asam.Value, "EV_ECM20TFS", StringComparison.OrdinalIgnoreCase)
                ? "MED17.1"
                : null;
        if (ecuType is null) return [];

        var software = FindRepeatedSoftware(text, BoschNumericSoftwarePattern) ??
                       FindRepeatedSoftware(text, BoschTenSoftwarePattern);
        if (software is null) return [];

        var oemSoftware = identification.Groups["oemSoftware"];
        var revision = identification.Groups["revision"];
        var matches = new List<IdentifierMatch>
        {
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = oemSoftware.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = $"Bosch", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU family", Value = $"Bosch {ecuType}", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU type", Value = ecuType, Offset = platform.Index },
            new IdentifierMatch { Type = "Processor", Value = $"Infineon TC1796 ({ecuType} platform inference)", Offset = processor.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Value, Offset = software.Index },
            new IdentifierMatch { Type = "OEM software Nr.", Value = oemSoftware.Value, Offset = oemSoftware.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{oemSoftware.Value} {revision.Value}", Offset = oemSoftware.Index },
            new IdentifierMatch { Type = "ASAM software Nr.", Value = asam.Value, Offset = asam.Index },
            new IdentifierMatch { Type = "Calibration Nr.", Value = identification.Groups["calibration"].Value, Offset = identification.Groups["calibration"].Index },
            new IdentifierMatch { Type = "Engine", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index }
        };

        var engineCodes = identification.Groups["engineCodes"];
        foreach (var engineCode in Regex.Matches(engineCodes.Value, @"[A-Z0-9]{3,5}")
                     .Cast<Match>()
                     .Where(match => !string.Equals(match.Value, "XXXX", StringComparison.OrdinalIgnoreCase))
                     .DistinctBy(match => match.Value, StringComparer.OrdinalIgnoreCase))
            matches.Add(new IdentifierMatch { Type = "Engine code", Value = engineCode.Value, Offset = engineCodes.Index + engineCode.Index });

        return matches;
    }

    private static Match? FindRepeatedSoftware(string text, Regex pattern)
    {
        var group = pattern.Matches(text)
            .Cast<Match>()
            .GroupBy(match => match.Value, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Min(match => match.Index))
            .FirstOrDefault(group => group.Count() >= 2);
        return group?.OrderBy(match => match.Index).First();
    }
}

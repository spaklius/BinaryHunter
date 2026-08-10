using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// VAG EDC17C54 full images repeat an exact C54 platform path, expose TC1797
// directly, and carry a UDS block with hardware, ASAM, calibration, active OEM
// software, engine, engine-code and J623 fields. A CTPROT marker near the
// processor provides an additional independent confirmation.
internal sealed class BoschVagEdc17C54Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/EDC17_?C54/5/P\d+//[A-Z0-9]+///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RuntimePattern = new(
        @"ERCOSEK\s+V\d+(?:\.\d+){1,3}\s+TriCore_g",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"(?<![A-Z0-9])TC1797(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CtprotMarkerPattern = new(
        @"EDC17C54\s+CTPROT_V\d+\.\d+UDS\.\d+\s+TC1797",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<hardware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<asam>EV_ECM[A-Z0-9]+?)(?<oemSoftware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<calibration>[A-Z0-9]{6})[ \x00]+\k<oemSoftware>[ \x00]+" +
        @"(?<revision>\d{4})[ \x00]+" +
        @"(?<engine>R\d\s+\d[,.]\dL\s+EDC)[ \x00]+" +
        @"(?<engineCodes>(?:[A-Z][A-Z0-9]{2,4}[ \x00\x01-\x1F-]+){1,16})" +
        @"[\x00-\x1F ]*J\s*(?<control>\d{3})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch VAG EDC17C54";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToArray();
        var runtime = RuntimePattern.Match(text);
        var processor = ProcessorPattern.Match(text);
        var ctprot = CtprotMarkerPattern.Match(text);
        var identification = IdentificationBlockPattern.Match(text);
        if (platforms.Length < 2 || !runtime.Success || !processor.Success || !ctprot.Success || !identification.Success) return [];

        var oemSoftware = identification.Groups["oemSoftware"];
        var revision = identification.Groups["revision"];
        var engine = identification.Groups["engine"].Value.Replace(',', '.');
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = oemSoftware.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platforms[^1].Index },
            new() { Type = "ECU family", Value = "Bosch EDC17C54", Offset = platforms[^1].Index },
            new() { Type = "ECU type", Value = "EDC17C54", Offset = platforms[^1].Index },
            new() { Type = "Processor", Value = "Infineon TC1797", Offset = processor.Index },
            new() { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new() { Type = "OEM software Nr.", Value = oemSoftware.Value, Offset = oemSoftware.Index },
            new() { Type = "Software Upgrade Nr.", Value = $"{oemSoftware.Value} {revision.Value}", Offset = oemSoftware.Index },
            new() { Type = "ASAM software Nr.", Value = identification.Groups["asam"].Value, Offset = identification.Groups["asam"].Index },
            new() { Type = "Calibration Nr.", Value = identification.Groups["calibration"].Value, Offset = identification.Groups["calibration"].Index },
            new() { Type = "Engine", Value = engine, Offset = identification.Groups["engine"].Index },
            new() { Type = "Control unit", Value = $"J{identification.Groups["control"].Value}", Offset = identification.Groups["control"].Index }
        };

        var engineCodes = identification.Groups["engineCodes"];
        foreach (var engineCode in Regex.Matches(engineCodes.Value, @"[A-Z][A-Z0-9]{2,4}")
                     .Cast<Match>()
                     .Where(match => !string.Equals(match.Value, "XXXX", StringComparison.OrdinalIgnoreCase))
                     .DistinctBy(match => match.Value, StringComparer.OrdinalIgnoreCase))
            matches.Add(new IdentifierMatch { Type = "Engine code", Value = engineCode.Value, Offset = engineCodes.Index + engineCode.Index });

        return matches;
    }
}
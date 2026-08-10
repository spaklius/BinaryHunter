using System.Globalization;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// VAG Continental SIMOS18.10 full images contain a mirrored CASC dataset
// header followed by the OEM part, engine, revision, ASAM, J623 and SC110
// records. Requiring the complete relationship avoids classifying isolated
// VAG-looking strings or calibration noise as a SIMOS18 ECU.
internal sealed class ContinentalVagSimos1810Detector : IEcuDetectionModule
{
    private static readonly HashSet<int> SupportedImageSizes = [0x480000, 0x600000];

    private static readonly Regex DatasetPattern = new(
        @"(?<dataset>CASC[A-Z0-9]{4})\.DAT",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"^(?:10\d{6}[A-Z]{2})$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CalibrationRowPattern = new(
        @"^111(?<calibration>SC[A-Z0-9]{11})$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TailPattern = new(
        @"(?<part>[A-Z0-9]{3}906259[A-Z]?)[ \x00]+" +
        @"(?<engine>(?:\d[,.]\dl\s+R4|R4\s+\d[,.]\dl)\s+TFSI?)[ \x00]+" +
        @"(?<revision>\d{4})[ \x00]+----" +
        @"(?<asam>EV_ECM20TFS020)(?<asamPart>[A-Z0-9]{3}906259[A-Z]?)[\x00 ]+" +
        @"(?<calibration>\d{6})(?<control>J623)[\x00 ]+(?<module>SC110)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental VAG SIMOS18.10";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT / PORSCHE";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (!SupportedImageSizes.Contains(image.Bytes.Length)) return [];

        var text = image.AsciiText;
        var dataset = DatasetPattern.Match(text);
        if (!dataset.Success || dataset.Index < 0x50) return [];

        var datasetName = dataset.Groups["dataset"].Value;
        if (!text.AsSpan(dataset.Index - 0x50, datasetName.Length)
                .Equals(datasetName.AsSpan(), StringComparison.OrdinalIgnoreCase))
            return [];

        var softwareOffset = dataset.Index - 0x40;
        var software = text.Substring(softwareOffset, 10);
        if (!SoftwarePattern.IsMatch(software)) return [];

        var rows = new string[3];
        for (var rowIndex = 0; rowIndex < rows.Length; rowIndex++)
        {
            var row = text.Substring(dataset.Index - 0x30 + (rowIndex * 0x10), 16);
            var rowMatch = CalibrationRowPattern.Match(row);
            if (!rowMatch.Success) return [];
            rows[rowIndex] = rowMatch.Groups["calibration"].Value;
        }

        if (!rows.Skip(1).All(row => string.Equals(row, rows[0], StringComparison.OrdinalIgnoreCase)))
            return [];

        var tailLength = Math.Min(0x80, text.Length - dataset.Index);
        var tail = text.Substring(dataset.Index, tailLength);
        var identification = TailPattern.Match(tail);
        if (!identification.Success) return [];

        var part = identification.Groups["part"];
        var asamPart = identification.Groups["asamPart"];
        if (!string.Equals(part.Value, asamPart.Value, StringComparison.OrdinalIgnoreCase)) return [];

        var absolutePartOffset = dataset.Index + part.Index;
        var engine = identification.Groups["engine"];
        var engineValue = Regex.Replace(engine.Value, @"(?<=\d)l\b", "L", RegexOptions.IgnoreCase);
        var revision = identification.Groups["revision"];
        var asam = identification.Groups["asam"];
        var calibration = identification.Groups["calibration"];
        var control = identification.Groups["control"];
        var module = identification.Groups["module"];

        var imageSizeMb = (image.Bytes.Length / 1048576d).ToString("0.#", CultureInfo.InvariantCulture);
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({imageSizeMb} MB)", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group (high confidence; SIMOS18.10 OEM block)", Offset = absolutePartOffset },
            new IdentifierMatch { Type = "ECU type", Value = "SIMOS18.10", Offset = dataset.Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon TC1791 (SIMOS18.10 platform inference)", Offset = dataset.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = softwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{part.Value} {revision.Value}", Offset = absolutePartOffset },
            new IdentifierMatch { Type = "ASAM software Nr.", Value = asam.Value, Offset = dataset.Index + asam.Index },
            new IdentifierMatch { Type = "Calibration Nr.", Value = calibration.Value, Offset = dataset.Index + calibration.Index },
            new IdentifierMatch { Type = "Calibration dataset", Value = $"{datasetName}.DAT", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU profile", Value = module.Value.ToUpperInvariant(), Offset = dataset.Index + module.Index },
            new IdentifierMatch { Type = "Engine", Value = engineValue, Offset = dataset.Index + engine.Index },
            new IdentifierMatch { Type = "Control unit", Value = control.Value.ToUpperInvariant(), Offset = dataset.Index + control.Index }
        };

        if (part.Value.StartsWith("95B", StringComparison.OrdinalIgnoreCase))
            matches.Insert(2, new IdentifierMatch
            {
                Type = "Vehicle manufacturer",
                Value = "Porsche (high confidence; 95B OEM software identifier)",
                Offset = absolutePartOffset
            });

        return matches;
    }
}

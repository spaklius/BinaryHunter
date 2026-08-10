using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// VAG EDC17CP20 full reads repeat an exact P755 platform banner, expose TC1796
// and contain an OEM block where ASAM, active OEM software, calibration,
// revision, engine and engine-code fields validate each other. The active Bosch
// software/version record is repeated separately in the image.
internal sealed class BoschVagEdc17Cp20Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/EDC17_?CP20/5/P\d+//[A-Z0-9]+///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"(?<![A-Z0-9])TC1796(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<hardware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<asam>EV_ECM[A-Z0-9]+?)(?<oemSoftware>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<calibration>[A-Z0-9]{6})[ \x00]+\k<oemSoftware>[ \x00]+" +
        @"(?<revision>\d{4})[ \x00]+" +
        @"(?<engine>R\d\s+\d[,.]\dL\s+(?:EDC|TDI|BTD))[ \x00]+" +
        @"(?<engineCode>[A-Z0-9]{3,5})-?(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwareRecordPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>P\d{3}[A-Z0-9]{4})(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch VAG EDC17CP20";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var evidence = FindEvidence(image);
        if (evidence is null || evidence.Value.Platforms.Length < 2 || evidence.Value.Software is null)
            return [];

        return BuildEvidence(evidence.Value, confirmedProfile: true);
    }

    public IEnumerable<IdentifierMatch> ExtractGenericEvidence(EcuBinaryImage image)
    {
        var evidence = FindEvidence(image);
        if (evidence is null || evidence.Value.Platforms.Length == 0)
            return [];

        return BuildEvidence(evidence.Value, confirmedProfile: false);
    }

    private static Cp20Evidence? FindEvidence(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToArray();
        var processor = ProcessorPattern.Match(text);
        var identification = IdentificationBlockPattern.Match(text);
        if (!identification.Success) return null;

        var softwareGroup = SoftwareRecordPattern.Matches(text)
            .Cast<Match>()
            .GroupBy(match => (Software: match.Groups["software"].Value, Version: match.Groups["version"].Value))
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Min(match => match.Index))
            .FirstOrDefault(group => group.Count() >= 2);
        var software = softwareGroup?.OrderBy(match => match.Index).First();
        return new Cp20Evidence(platforms, processor, identification, software);
    }

    private static IEnumerable<IdentifierMatch> BuildEvidence(Cp20Evidence evidence, bool confirmedProfile)
    {
        var platformOffset = evidence.Platforms.Length > 0
            ? evidence.Platforms[^1].Index
            : evidence.Processor.Index;
        var identification = evidence.Identification;
        var oemSoftware = identification.Groups["oemSoftware"];
        var revision = identification.Groups["revision"];
        var asam = identification.Groups["asam"];
        var engine = identification.Groups["engine"].Value.Replace(',', '.');
        if (asam.Value.Contains("BTD", StringComparison.OrdinalIgnoreCase))
            engine = Regex.Replace(engine, @"EDC$", "BTD", RegexOptions.IgnoreCase);
        else if (asam.Value.Contains("TDI", StringComparison.OrdinalIgnoreCase))
            engine = Regex.Replace(engine, @"EDC$", "TDI", RegexOptions.IgnoreCase);

        var matches = new List<IdentifierMatch>();
        if (confirmedProfile)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = "Full flash image (2 MB)", Offset = 0 });

        matches.AddRange(
        [
            new IdentifierMatch
            {
                Type = "Vehicle group",
                Value = confirmedProfile
                    ? "Volkswagen Group"
                    : "Volkswagen Group (EDC17CP20 OEM-block evidence)",
                Offset = oemSoftware.Index
            },
            new IdentifierMatch
            {
                Type = "ECU manufacturer",
                Value = confirmedProfile
                    ? "Bosch"
                    : "Bosch",
                Offset = platformOffset
            },
            new IdentifierMatch { Type = "Processor",
                Value = evidence.Processor.Success
                    ? "Infineon TC1796"
                    : "Infineon TC1796",
                Offset = evidence.Processor.Success ? evidence.Processor.Index : platformOffset
            },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "OEM software Nr.", Value = oemSoftware.Value, Offset = oemSoftware.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{oemSoftware.Value} {revision.Value}", Offset = oemSoftware.Index },
            new IdentifierMatch { Type = "ASAM software Nr.", Value = $"{asam.Value}{oemSoftware.Value}", Offset = asam.Index },
            new IdentifierMatch { Type = "Calibration Nr.", Value = identification.Groups["calibration"].Value, Offset = identification.Groups["calibration"].Index },
            new IdentifierMatch { Type = "Engine", Value = engine, Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engineCode"].Value, Offset = identification.Groups["engineCode"].Index }
        ]);

        if (confirmedProfile)
        {
            matches.Add(new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC17CP20", Offset = platformOffset });
            matches.Add(new IdentifierMatch { Type = "ECU type", Value = "EDC17CP20", Offset = platformOffset });
        }

        if (evidence.Software is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = evidence.Software.Groups["software"].Value, Offset = evidence.Software.Groups["software"].Index });
            matches.Add(new IdentifierMatch { Type = "Calibration version", Value = evidence.Software.Groups["version"].Value, Offset = evidence.Software.Groups["version"].Index });
        }

        return matches;
    }

    private readonly record struct Cp20Evidence(
        Match[] Platforms,
        Match Processor,
        Match Identification,
        Match? Software);
}

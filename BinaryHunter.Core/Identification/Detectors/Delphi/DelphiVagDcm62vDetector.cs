using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Delphi;

// VAG DCM6.2V full reads contain a compact 1MVAGAPP record. The ASAM name
// embeds the active OEM software number, followed by fixed 0xFF separators, a
// six-digit application-data ID, a duplicated four-digit revision and the same
// OEM software number again. This validates the layout without known ID values.
internal sealed class DelphiVagDcm62vDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex IdentificationPattern = new(
        @"(?<application>1MVAGAPP_[A-Z0-9]{5,8})\x00{0,2}" +
        @"(?<asam>EV_ECM(?<engineClass>\d{2})(?<dieselType>TDI|BTD)030(?<software>[A-Z0-9]{3}\d{6}[A-Z]{0,2}))" +
        @"(?<separator1>\?{3})(?<data>\d{6})(?<separator2>\?{2})" +
        @"(?<revision>\d{4})\k<revision>\k<software>(?<padding>\?{8})",
        RegexOptions.Compiled);

    private static readonly Regex EnginePattern = new(
        @"R4\s+(?<displacement>\d[\.,]\d)l\s+(?<dieselType>TDI|BTD)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex EngineCodeBlockPattern = new(
        @"(?<![A-Z])(?<codes>[CD][A-Z]{3}(?:[CD][A-Z]{3}){0,3})(?![A-Z])",
        RegexOptions.Compiled);

    public string Name => "Delphi VAG DCM6.2V";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var identification = FindIdentification(image);
        var engine = EnginePattern.Match(image.AsciiText);
        if (identification is null || !engine.Success) return [];

        return BuildEvidence(image, identification, engine, confirmedProfile: true);
    }

    public IEnumerable<IdentifierMatch> ExtractGenericEvidence(EcuBinaryImage image)
    {
        var identification = FindIdentification(image);
        if (identification is null) return [];

        var engine = EnginePattern.Match(image.AsciiText);
        return BuildEvidence(image, identification, engine, confirmedProfile: false);
    }

    private static Match? FindIdentification(EcuBinaryImage image)
    {
        foreach (Match candidate in IdentificationPattern.Matches(image.AsciiText))
        {
            if (IsFfField(image.Bytes, candidate.Groups["separator1"]) &&
                IsFfField(image.Bytes, candidate.Groups["separator2"]) &&
                IsFfField(image.Bytes, candidate.Groups["padding"]))
                return candidate;
        }

        return null;
    }

    private static IEnumerable<IdentifierMatch> BuildEvidence(
        EcuBinaryImage image,
        Match identification,
        Match engine,
        bool confirmedProfile)
    {
        var application = identification.Groups["application"];
        var software = identification.Groups["software"];
        var revision = identification.Groups["revision"];
        var matches = new List<IdentifierMatch>();

        if (confirmedProfile)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = "Full flash image (4 MB)", Offset = 0 });

        matches.AddRange(
        [
            new IdentifierMatch
            {
                Type = "Vehicle group",
                Value = confirmedProfile
                    ? "Volkswagen Group"
                    : "Volkswagen Group (VAG application-block evidence)",
                Offset = application.Index
            },
            new IdentifierMatch
            {
                Type = "ECU manufacturer",
                Value = confirmedProfile
                    ? "Delphi"
                    : "Delphi (DCM6.2V application-structure evidence)",
                Offset = application.Index
            }
        ]);
        if (confirmedProfile)
        {
            matches.Add(new IdentifierMatch { Type = "ECU family", Value = "Delphi DCM6.2V", Offset = application.Index });
            matches.Add(new IdentifierMatch { Type = "ECU type", Value = "DCM6.2V", Offset = application.Index });
        }
        matches.Add(new IdentifierMatch { Type = "Processor", Value = "NXP SPC5674 (DCM6.2V profile inference)", Offset = application.Index });
        matches.Add(new IdentifierMatch { Type = "Application Nr.", Value = application.Value, Offset = application.Index });
        matches.Add(new IdentifierMatch { Type = "ASAM software Nr.", Value = identification.Groups["asam"].Value, Offset = identification.Groups["asam"].Index });
        matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Value, Offset = software.Index });
        matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{software.Value} {revision.Value}", Offset = revision.Index });
        matches.Add(new IdentifierMatch { Type = "Application data Nr.", Value = identification.Groups["data"].Value, Offset = identification.Groups["data"].Index });

        if (engine.Success)
        {
            matches.Add(new IdentifierMatch
            {
                Type = "Engine",
                Value = engine.Value.Replace(',', '.'),
                Offset = engine.Index
            });
            AddEngineCodes(image.AsciiText, engine, matches);
        }

        return matches;
    }

    private static void AddEngineCodes(string text, Match engine, ICollection<IdentifierMatch> matches)
    {
        var length = Math.Min(4_096, text.Length - engine.Index);
        var context = text.Substring(engine.Index, length);
        var codes = EngineCodeBlockPattern.Matches(context)
            .Cast<Match>()
            .SelectMany(match => Enumerable.Range(0, match.Groups["codes"].Length / 4)
                .Select(index => (Value: match.Groups["codes"].Value.Substring(index * 4, 4),
                                  Offset: engine.Index + match.Groups["codes"].Index + index * 4)))
            .Where(code => code.Value.Distinct().Count() > 1)
            .DistinctBy(code => code.Value)
            .Take(8)
            .ToArray();
        if (codes.Length == 0) return;

        matches.Add(new IdentifierMatch
        {
            Type = codes.Length == 1 ? "Engine code" : "Engine code candidates",
            Value = string.Join(", ", codes.Select(code => code.Value)),
            Offset = codes[0].Offset
        });
    }

    private static bool IsFfField(byte[] bytes, Group group)
    {
        if (!group.Success || group.Index < 0 || group.Index + group.Length > bytes.Length) return false;
        return bytes.AsSpan(group.Index, group.Length).IndexOfAnyExcept((byte)0xFF) < 0;
    }
}

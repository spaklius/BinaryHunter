using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// VAG EDC16U1 full external-flash reads are 1 MiB images. The active Bosch
// software/version record is repeated across the image and a compact OEM block
// near the calibration metadata links Bosch hardware, VAG software, revision
// and engine text. No known identifier value is required by this profile.
internal sealed class BoschVagEdc16U1Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x100000;

    private static readonly Regex SoftwareRecordPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]{6,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<hardware>0281\d{6})[\x00-\x20\x64]{1,16}" +
        @"(?<oemSoftware>[A-Z0-9]{3}9060\d{2}[A-Z]{1,2})[ \x00]+" +
        @"(?<revision>\d{4})[ \x00]+" +
        @"(?<engine>R[45]\s+\d[,.]\dL\s+EDC)(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch VAG EDC16U1";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var evidence = FindEvidence(image, minimumSoftwareRepetitions: 3);
        return evidence is null
            ? []
            : BuildEvidence(evidence.Value, confirmedProfile: true);
    }

    public IEnumerable<IdentifierMatch> ExtractGenericEvidence(EcuBinaryImage image)
    {
        var evidence = FindEvidence(image, minimumSoftwareRepetitions: 2);
        return evidence is null
            ? []
            : BuildEvidence(evidence.Value, confirmedProfile: false);
    }

    private static U1Evidence? FindEvidence(EcuBinaryImage image, int minimumSoftwareRepetitions)
    {
        var text = image.AsciiText;
        var identification = IdentificationBlockPattern.Match(text);
        if (!identification.Success) return null;

        var softwareGroup = SoftwareRecordPattern.Matches(text)
            .Cast<Match>()
            .GroupBy(match => (Software: match.Groups["software"].Value, Version: match.Groups["version"].Value))
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Min(match => match.Index))
            .FirstOrDefault(group => group.Count() >= minimumSoftwareRepetitions);
        if (softwareGroup is null) return null;

        return new U1Evidence(
            softwareGroup.OrderBy(match => match.Index).First(),
            identification);
    }

    private static IEnumerable<IdentifierMatch> BuildEvidence(U1Evidence evidence, bool confirmedProfile)
    {
        var software = evidence.Software;
        var identification = evidence.Identification;
        var oemSoftware = identification.Groups["oemSoftware"];
        var revision = identification.Groups["revision"];

        var matches = new List<IdentifierMatch>();
        if (confirmedProfile)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = "Full flash image (1 MB)", Offset = 0 });

        matches.AddRange(
        [
            new IdentifierMatch
            {
                Type = "Vehicle group",
                Value = confirmedProfile
                    ? "Volkswagen Group"
                    : "Volkswagen Group (EDC16U1 OEM-block evidence)",
                Offset = oemSoftware.Index
            },
            new IdentifierMatch
            {
                Type = "ECU manufacturer",
                Value = confirmedProfile
                    ? "Bosch"
                    : "Bosch",
                Offset = software.Index
            }
        ]);
        if (confirmedProfile)
        {
            matches.Add(new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16U1", Offset = identification.Index });
            matches.Add(new IdentifierMatch { Type = "ECU type", Value = "EDC16U1", Offset = identification.Index });
        }
        matches.Add(new IdentifierMatch { Type = "Processor", Value = "Freescale MPC555 (EDC16U1 profile inference)", Offset = identification.Index });
        matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index });
        matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index });
        matches.Add(new IdentifierMatch { Type = "Calibration version", Value = software.Groups["version"].Value, Offset = software.Groups["version"].Index });
        matches.Add(new IdentifierMatch { Type = "OEM software Nr.", Value = oemSoftware.Value, Offset = oemSoftware.Index });
        matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{oemSoftware.Value} {revision.Value}", Offset = oemSoftware.Index });
        matches.Add(new IdentifierMatch { Type = "Engine", Value = identification.Groups["engine"].Value.Replace(',', '.'), Offset = identification.Groups["engine"].Index });

        return matches;
    }

    private readonly record struct U1Evidence(Match Software, Match Identification);
}

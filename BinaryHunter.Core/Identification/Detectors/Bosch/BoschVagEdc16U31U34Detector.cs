using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// VAG EDC16U31/U34 calibration reads are 0x80000-byte windows from a 2 MiB
// flash. Full images carry the EDC16U34 platform marker, mirrored software
// records 0x40000 bytes apart, and a compact OEM block: hardware, active OEM
// software, revision and engine text. Partial reads carry the OEM block and
// software record but not the platform marker.
//
// The rule intentionally validates the layout rather than any known ID value.
internal sealed class BoschVagEdc16U31U34Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int PartialImageSize = 0x80000;
    private const int CalibrationMirrorDistance = 0x40000;

    // EDC16U34 platform marker (full reads only)
    private static readonly Regex PlatformMarkerPattern = new(
        @"EDC16U34[-.]?\d[\.\d]*\s+MPC56[0-9]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Bosch software number (1037xxxxxx) followed by a version string
    private static readonly Regex SoftwareRecordPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]{6,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<hardware>[A-Z0-9]{10,11})[ \x00]+" +
        @"(?<oemSoftware>0[A-Z0-9]{8,10})[ \x00]+" +
        @"(?<revision>\d{4})[ \x00]+" +
        @"(?<engine>R4\s+\d[,.]\dL\s+EDC)(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch VAG EDC16U31/U34";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;

        // Preferred path: platform marker + mirrored software record
        var platform = PlatformMarkerPattern.Match(text);
        if (platform.Success)
        {
            var platformSoftware = FindMirroredSoftwareRecord(text);
            if (platformSoftware is not null)
            {
                var platformIdentification = IdentificationBlockPattern.Match(text);
                if (platformIdentification.Success)
                    return BuildEvidence(platformSoftware, platformIdentification, confirmedProfile: true, isFullImage: true);
            }
        }

        // Fallback for full images without platform marker: identification block
        // plus mirrored software records at 0x40000 distance.
        var fallbackIdentification = IdentificationBlockPattern.Match(text);
        if (!fallbackIdentification.Success) return [];

        var fallbackSoftware = FindMirroredSoftwareRecord(text);
        if (fallbackSoftware is null) return [];

        return BuildEvidence(fallbackSoftware, fallbackIdentification, confirmedProfile: true, isFullImage: true);
    }

    public IEnumerable<IdentifierMatch> ExtractGenericEvidence(EcuBinaryImage image)
    {
        if (image.Bytes.Length == PartialImageSize)
        {
            var evidence = FindPartialEvidence(image);
            return evidence is null
                ? []
                : BuildEvidence(evidence.Value.Software, evidence.Value.Identification, confirmedProfile: false, isFullImage: false);
        }

        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;

        // Preferred path: platform marker + mirrored software record
        var platform = PlatformMarkerPattern.Match(text);
        if (platform.Success)
        {
            var platformSoftware = FindMirroredSoftwareRecord(text);
            if (platformSoftware is not null)
            {
                var platformIdentification = IdentificationBlockPattern.Match(text);
                if (platformIdentification.Success)
                    return BuildEvidence(platformSoftware, platformIdentification, confirmedProfile: false, isFullImage: true);
            }
        }

        // Fallback: identification block + mirrored software records
        var fallbackIdentification = IdentificationBlockPattern.Match(text);
        if (!fallbackIdentification.Success) return [];

        var fallbackSoftware = FindMirroredSoftwareRecord(text);
        if (fallbackSoftware is null) return [];

        return BuildEvidence(fallbackSoftware, fallbackIdentification, confirmedProfile: false, isFullImage: true);
    }

    private static IEnumerable<IdentifierMatch> DetectPartial(EcuBinaryImage image)
    {
        var evidence = FindPartialEvidence(image);
        if (evidence is null) return [];

        return BuildEvidence(evidence.Value.Software, evidence.Value.Identification, confirmedProfile: true, isFullImage: false);
    }

    private static U31U34PartialEvidence? FindPartialEvidence(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        var identification = IdentificationBlockPattern.Match(text);
        if (!identification.Success) return null;

        var softwareGroup = SoftwareRecordPattern.Matches(text)
            .Cast<Match>()
            .GroupBy(match => (Software: match.Groups["software"].Value, Version: match.Groups["version"].Value))
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Min(match => match.Index))
            .FirstOrDefault(group => group.Count() >= 2);
        if (softwareGroup is null) return null;

        return new U31U34PartialEvidence(
            softwareGroup.OrderBy(match => match.Index).First(),
            identification);
    }

    private static IEnumerable<IdentifierMatch> BuildEvidence(Match software, Match identification, bool confirmedProfile, bool isFullImage = false)
    {
        var oemSoftware = identification.Groups["oemSoftware"];
        var revision = identification.Groups["revision"];

        var matches = new List<IdentifierMatch>();
        if (confirmedProfile)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = isFullImage ? "Full flash image (2 MB)" : "Partial calibration image (512 KB)", Offset = 0 });

        matches.AddRange(
        [
            new IdentifierMatch
            {
                Type = "Vehicle group",
                Value = "Volkswagen Group",
                Offset = oemSoftware.Index
            },
            new IdentifierMatch
            {
                Type = "ECU manufacturer",
                Value = "Bosch",
                Offset = software.Index
            }
        ]);
        if (confirmedProfile)
        {
            matches.Add(new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16U31 / U34", Offset = identification.Index });
            matches.Add(new IdentifierMatch { Type = "ECU type", Value = "EDC16U31/U34", Offset = identification.Index });
        }
        matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index });
        matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index });
        matches.Add(new IdentifierMatch { Type = "Calibration version", Value = software.Groups["version"].Value, Offset = software.Groups["version"].Index });
        matches.Add(new IdentifierMatch { Type = "OEM software Nr.", Value = oemSoftware.Value, Offset = oemSoftware.Index });
        matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{oemSoftware.Value} {revision.Value}", Offset = oemSoftware.Index });
        matches.Add(new IdentifierMatch { Type = "Engine", Value = identification.Groups["engine"].Value.Replace(',', '.'), Offset = identification.Groups["engine"].Index });

        return matches;
    }

    private static Match? FindMirroredSoftwareRecord(string text)
    {
        var records = SoftwareRecordPattern.Matches(text).Cast<Match>().OrderBy(match => match.Index).ToArray();
        foreach (var record in records)
        {
            var mirror = records.FirstOrDefault(candidate =>
                candidate.Index == record.Index + CalibrationMirrorDistance &&
                string.Equals(candidate.Groups["software"].Value, record.Groups["software"].Value, StringComparison.Ordinal) &&
                string.Equals(candidate.Groups["version"].Value, record.Groups["version"].Value, StringComparison.Ordinal));
            if (mirror is not null)
                return record;
        }

        return null;
    }

    private readonly record struct U31U34PartialEvidence(Match Software, Match Identification);
}

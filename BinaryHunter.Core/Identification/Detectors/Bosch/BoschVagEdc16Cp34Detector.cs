using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// VAG EDC16CP34 full reads (2 MB) and partial reads (512 KB starting at
// 0x00180000). Full images carry the EDC16CP34 platform marker, mirrored
// software records 0x40000 bytes apart, and a VAG-specific upgrade/engine
// block. Partial reads carry the software record and upgrade block but not
// the platform marker.
//
// The detector is universal across VAG EDC16CP34 variants:
// - Audi V6 TDI (2.7L/3.0L V6TDI) with 907401/910401 hardware patterns
// - VW Crafter R5 TDI (2.5L EDC) with 074906032AN upgrade pattern
// - Other VAG variants with different engine types
internal sealed class BoschVagEdc16Cp34Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int PartialImageSize = 0x80000;
    private const int CalibrationMirrorDistance = 0x40000;

    // EDC16CP34 platform marker (full reads only)
    private static readonly Regex PlatformMarkerPattern = new(
        @"EDC16CP34[-.]?\d[\.\d]*\s+MPC56[0-9]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Bosch software number (1037xxxxxx) followed by a version string
    private static readonly Regex SoftwareRecordPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]{6,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    // VAG-specific upgrade number pattern (e.g. 074906032AN 5170)
    private static readonly Regex UpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>0\d{7,8}[A-Z]{2})\s*\x00*(?<revision>\d{3,4})",
        RegexOptions.Compiled);

    // Engine type pattern (e.g. R5 2,5L EDC, 2.7L V6TDI, 3.0L V6TDI)
    private static readonly Regex EnginePattern = new(
        @"(?<engine>(?:R[0-9]\s+)?\d[.,]\dL\s+(?:V6TDI|EDC|TDI))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // EDC16U31/U34 identification block (exclusion for CP34 partial reads)
    private static readonly Regex U31U34IdentificationBlockPattern = new(
        @"(?<hardware>[A-Z0-9]{10,11})[ \x00]+" +
        @"(?<oemSoftware>0[A-Z0-9]{8,10})[ \x00]+" +
        @"(?<revision>\d{4})[ \x00]+" +
        @"(?<engine>R4\s+\d[,.]\dL\s+EDC)(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Audi-specific identification block (optional, not present in all variants)
    private static readonly Regex AudiIdentificationBlockPattern = new(
        @"(?<hardware>[A-Z0-9]{3}907401[A-Z]{0,2})[ \x00]{4,16}" +
        @"(?<oemSoftware>[A-Z0-9]{3}910401[A-Z]{0,2})[ \x00]+" +
        @"(?<revision>\d{4})\x00" +
        @"(?<engine>(?:2\.7|3\.0)L\s+V6TDI)(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch VAG EDC16CP34";
    public string Manufacturer => "AUDI / VW / \u0160KODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;

        // Platform marker is required for full reads
        var platform = PlatformMarkerPattern.Match(text);
        if (!platform.Success) return [];

        // Mirrored software record is required
        var software = FindMirroredSoftwareRecord(text);
        if (software is null) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Full flash image (2 MB)", Offset = platform.Index },
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = platform.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new() { Type = "ECU family", Value = "Bosch EDC16CP34", Offset = platform.Index },
            new() { Type = "ECU type", Value = "EDC16CP34", Offset = platform.Index },
            new() { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index },
            new() { Type = "Calibration version", Value = software.Groups["version"].Value, Offset = software.Groups["version"].Index }
        };

        // Try Audi-specific identification block first
        var audiId = AudiIdentificationBlockPattern.Match(text);
        if (audiId.Success)
        {
            var hardware = audiId.Groups["hardware"];
            var oemSoftware = audiId.Groups["oemSoftware"];
            var revision = audiId.Groups["revision"];
            var engine = audiId.Groups["engine"];

            matches.Add(new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi", Offset = hardware.Index });
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{oemSoftware.Value} {revision.Value}", Offset = oemSoftware.Index });
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        }
        else
        {
            // Try universal VAG upgrade pattern (e.g. VW Crafter)
            var upgrade = UpgradePattern.Match(text);
            if (upgrade.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Software Upgrade Nr.",
                    Value = $"{upgrade.Groups["upgrade"].Value} {upgrade.Groups["revision"].Value}",
                    Offset = upgrade.Groups["upgrade"].Index
                });
            }

            // Try engine pattern
            var engine = EnginePattern.Match(text);
            if (engine.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Engine",
                    Value = engine.Groups["engine"].Value,
                    Offset = engine.Groups["engine"].Index
                });
            }
        }

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectPartial(EcuBinaryImage image)
    {
        var text = image.AsciiText;

        // Partial reads carry the software record but not the platform marker.
        // Exclude EDC16U31/U34 identification blocks — those belong to the
        // dedicated U31/U34 detector and would otherwise cause duplicate Engine rows.
        if (U31U34IdentificationBlockPattern.IsMatch(text)) return [];

        // Partial reads carry the software record but not the platform marker
        var software = SoftwareRecordPattern.Match(text);
        if (!software.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Partial flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = software.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = software.Index },
            new() { Type = "ECU family", Value = "Bosch EDC16CP34", Offset = software.Index },
            new() { Type = "ECU type", Value = "EDC16CP34", Offset = software.Index },
            new() { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index },
            new() { Type = "Calibration version", Value = software.Groups["version"].Value, Offset = software.Groups["version"].Index }
        };

        // Try VAG upgrade pattern
        var upgrade = UpgradePattern.Match(text);
        if (upgrade.Success)
        {
            matches.Add(new IdentifierMatch
            {
                Type = "Software Upgrade Nr.",
                Value = $"{upgrade.Groups["upgrade"].Value} {upgrade.Groups["revision"].Value}",
                Offset = upgrade.Groups["upgrade"].Index
            });
        }

        // Try engine pattern
        var engine = EnginePattern.Match(text);
        if (engine.Success)
        {
            matches.Add(new IdentifierMatch
            {
                Type = "Engine",
                Value = engine.Groups["engine"].Value,
                Offset = engine.Groups["engine"].Index
            });
        }

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
}
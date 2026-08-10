using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// PSA EDC16C34 calibration reads are 0xA0000-byte windows from a 2 MiB flash.
// They contain an explicit EDC16C34 RBIN platform path and mirror the active
// Bosch software/calibration record 0x60000 bytes apart.
internal sealed class BoschPsaEdc16C34Detector : IEcuDetectionModule
{
    private const int PartialImageSize = 0xA0000;
    private const int CalibrationMirrorDistance = 0x60000;

    private static readonly Regex PlatformPattern = new(
        @"(?<![A-Z0-9])\d{2,3}/1/(?<type>EDC16C34)/(?<variant>\d{3})/(?<project>C\d{3})/RBIN/EDR2-",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwareRecordPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>C\d{3}[A-Z0-9_]{4})(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch PSA EDC16C34";
    public string Manufacturer => "PSA / STELLANTIS";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != PartialImageSize) return [];

        var platform = PlatformPattern.Match(image.AsciiText);
        if (!platform.Success) return [];

        var software = FindMirroredSoftwareRecord(image.AsciiText);
        if (software is null || !software.Groups["version"].Value.StartsWith(
                platform.Groups["project"].Value, StringComparison.OrdinalIgnoreCase))
            return [];

        return
        [
            new IdentifierMatch { Type = "Read format", Value = "Partial calibration image (655360 bytes; base 0x00160000)", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "PSA / Stellantis", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C34", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C34", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = software.Groups["software"].Value, Offset = software.Groups["software"].Index },
            new IdentifierMatch { Type = "Calibration version", Value = software.Groups["version"].Value, Offset = software.Groups["version"].Index }
        ];
    }

    private static Match? FindMirroredSoftwareRecord(string text)
    {
        var records = SoftwareRecordPattern.Matches(text).Cast<Match>().OrderBy(match => match.Index).ToArray();
        foreach (var record in records)
        {
            var mirror = records.FirstOrDefault(candidate =>
                candidate.Index == record.Index + CalibrationMirrorDistance &&
                string.Equals(candidate.Value, record.Value, StringComparison.Ordinal));
            if (mirror is not null)
                return record;
        }

        return null;
    }
}
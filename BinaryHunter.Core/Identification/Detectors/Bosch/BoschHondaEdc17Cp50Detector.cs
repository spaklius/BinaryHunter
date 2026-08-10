using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Bosch EDC17_CP50 images (2 MB partial or 4 MB full) carry a platform path
// banner like `39/1/EDC17_CP50/159/P872//P872V123_2///`. Full images repeat the
// banner twice; partial 2 MB images contain one banner but the active software ID
// appears multiple times, so either ≥2 platform matches or ≥2 software IDs is
// sufficient confirmation. Calibration ID/version are stored at fixed offsets
// near the start of the image.
internal sealed class BoschHondaEdc17Cp50Detector : IEcuDetectionModule
{
    private const int CalibrationIdOffset = 26;
    private const int CalibrationIdLength = 10;
    private const int CalibrationVersionOffset = 36;
    private const int CalibrationVersionLength = 8;

    private static readonly Regex PlatformPattern = new(
        @"(?<![A-Z0-9])\d{2,3}/1/(?<type>EDC17_CP50)/\d{2,}/P[0-9A-Z]+//[A-Z0-9_]+///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?=[A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch Honda EDC17CP50";
    public string Manufacturer => "HONDA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var length = image.Bytes.Length;
        if (length != 0x200000 && length != 0x400000) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToArray();
        if (platforms.Length == 0) return [];

        var softwareMatches = SoftwarePattern.Matches(text).Cast<Match>().ToArray();
        if (platforms.Length < 2 && softwareMatches.Length < 2) return [];

        var platform = platforms[^1];
        var familyOffset = platform.Index + 5;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Honda Motor Company", Offset = familyOffset },
            new() { Type = "Vehicle manufacturer", Value = "Honda", Offset = familyOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = familyOffset },
            new() { Type = "ECU family", Value = "Bosch EDC17CP50", Offset = familyOffset },
            new() { Type = "ECU type", Value = "EDC17CP50", Offset = familyOffset }
        };

        if (length > CalibrationIdOffset + CalibrationIdLength)
        {
            var calibrationId = text.Substring(CalibrationIdOffset, CalibrationIdLength);
            matches.Add(new IdentifierMatch { Type = "Calibration Nr.", Value = calibrationId, Offset = CalibrationIdOffset });
        }
        if (length > CalibrationVersionOffset + CalibrationVersionLength)
        {
            var calibrationVersion = text.Substring(CalibrationVersionOffset, CalibrationVersionLength);
            matches.Add(new IdentifierMatch { Type = "Calibration version", Value = calibrationVersion, Offset = CalibrationVersionOffset });
        }

        foreach (var sw in softwareMatches)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = sw.Groups["software"].Value, Offset = sw.Groups["software"].Index });

        return matches;
    }
}

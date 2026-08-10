using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW DDE3/EDC15M calibration reads are commonly 0x8000-byte partial images.
// They contain two independent records: a repeated calibration descriptor and
// a Bosch hardware descriptor close to the end of the image. Requiring both
// layouts avoids identifying an ECU from a lone part-number-shaped string.
internal sealed class BoschEdc15MDetector : IEcuDetectionModule
{
    private const int PartialImageSize = 0x8000;
    private const int MaximumHardwareBlockDistanceFromEnd = 2_048;

    private static readonly Regex CalibrationBlockPattern = new(
        @"(?<![A-Z0-9])(?<prefix>\d{6})(?<data>\d{4})(?<upgrade>[A-Z]\d{3})0000(?<segment>\d{4}C5)0{10}\k<segment>0{10}\k<segment>0{6}(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex HardwareBlockPattern = new(
        @"(?<!\d)(?<descriptor>\d{12})(?<hardware>0281\d{6})C50{8,16}(?!\d)",
        RegexOptions.Compiled);

    public string Name => "Bosch EDC15M partial image";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != PartialImageSize) return [];

        var calibration = CalibrationBlockPattern.Match(image.AsciiText);
        var hardware = HardwareBlockPattern.Matches(image.AsciiText)
            .Cast<Match>()
            .LastOrDefault(match => match.Groups["hardware"].Index >= image.Bytes.Length - MaximumHardwareBlockDistanceFromEnd);
        if (!calibration.Success || hardware is null) return [];

        var evidenceOffset = calibration.Index;
        return
        [
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = evidenceOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC15M", Offset = evidenceOffset },
            new IdentifierMatch { Type = "ECU type", Value = "EDC15M", Offset = evidenceOffset },
            new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Groups["hardware"].Value, Offset = hardware.Groups["hardware"].Index },
            new IdentifierMatch { Type = "Data software Nr.", Value = calibration.Groups["data"].Value, Offset = calibration.Groups["data"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = calibration.Groups["upgrade"].Value, Offset = calibration.Groups["upgrade"].Index }
        ];
    }
}

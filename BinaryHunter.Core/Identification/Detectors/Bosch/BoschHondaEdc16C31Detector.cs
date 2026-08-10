using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Honda EDC16C31 full reads share the generic 99/1/EDC16C31/999 platform
// banner with BMW and Volvo. Honda's 1 MiB layout is distinguished by a Bosch
// software/calibration record at 0x10 that is mirrored in three flash regions.
// Requiring the exact record to repeat avoids treating the shared banner alone
// as vehicle-manufacturer evidence.
internal sealed class BoschHondaEdc16C31Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x100000;
    private const int CalibrationOffset = 0x10;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/EDC16C31/999/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CalibrationPattern = new(
        @"^(?<software>1037\d{6})(?<version>P[A-Z0-9_]{4,16})(?![A-Z0-9_])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Honda EDC16C31";
    public string Manufacturer => "HONDA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (!TryGetMirroredCalibration(image, out var calibration)) return [];

        var platform = PlatformPattern.Match(image.AsciiText);
        if (!platform.Success) return [];

        return
        [
            new() { Type = "Read format", Value = "Full flash image (1 MB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Honda Motor Company", Offset = platform.Index },
            new() { Type = "Vehicle manufacturer", Value = "Honda", Offset = platform.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new() { Type = "ECU family", Value = "Bosch EDC16C31", Offset = platform.Index },
            new() { Type = "ECU type", Value = "EDC16C31", Offset = platform.Index },
            new() { Type = "Software Nr.", Value = calibration.Groups["software"].Value, Offset = CalibrationOffset },
            new() { Type = "Calibration version", Value = calibration.Groups["version"].Value, Offset = CalibrationOffset + calibration.Groups["version"].Index }
        ];
    }

    internal static bool HasHondaMirroredCalibration(EcuBinaryImage image) =>
        TryGetMirroredCalibration(image, out _);

    private static bool TryGetMirroredCalibration(EcuBinaryImage image, out Match calibration)
    {
        calibration = Match.Empty;
        if (image.Bytes.Length != FullImageSize || CalibrationOffset + 40 > image.Bytes.Length) return false;

        var header = Encoding.ASCII.GetString(image.Bytes, CalibrationOffset, 40);
        calibration = CalibrationPattern.Match(header);
        if (!calibration.Success) return false;

        var exactRecord = calibration.Value;
        var occurrenceCount = 0;
        var searchOffset = 0;
        while (searchOffset < image.AsciiText.Length)
        {
            var index = image.AsciiText.IndexOf(exactRecord, searchOffset, StringComparison.OrdinalIgnoreCase);
            if (index < 0) break;
            occurrenceCount++;
            if (occurrenceCount >= 3) return true;
            searchOffset = index + exactRecord.Length;
        }

        return false;
    }
}

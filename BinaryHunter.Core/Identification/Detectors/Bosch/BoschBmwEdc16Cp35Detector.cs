using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// 1 MiB full images for the Bosch BMW EDC16CP35 family. The platform path
// banner contains `99/1/EDC16CP35/...`, which is structurally analogous to
// the EDC16C31 case. This detector confirms the family from that banner and
// surfaces the nearby software / calibration / hardware / engine strings.
internal sealed class BoschBmwEdc16Cp35Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x100000;

    private static readonly Regex PlatformPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC16CP35)/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HardwarePattern = new(
        @"(?<![A-Z0-9])(?:0281\d{6}|0781\d{4})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex CalibrationPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]{4,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex EnginePattern = new(
        @"(?<![A-Z0-9])Z\d{2}[A-Z]{2,4}(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch BMW EDC16CP35";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var platform = PlatformPattern.Match(image.AsciiText);
        if (!platform.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new() { Type = "ECU family", Value = "Bosch EDC16CP35", Offset = platform.Index },
            new() { Type = "ECU type", Value = "EDC16CP35", Offset = platform.Index },
            new() { Type = "Vehicle group", Value = "BMW Group", Offset = platform.Index }
        };

        foreach (Match hardware in HardwarePattern.Matches(image.AsciiText))
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });

        foreach (Match calibration in CalibrationPattern.Matches(image.AsciiText))
        {
            var version = calibration.Groups["version"].Value;
            if (version.Length >= 4 && !Regex.IsMatch(version, "[A-Za-z]"))
                continue;
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = calibration.Groups["software"].Value, Offset = calibration.Groups["software"].Index });
            if (calibration.Groups["version"].Success)
                matches.Add(new IdentifierMatch { Type = "Calibration version", Value = version, Offset = calibration.Groups["version"].Index });
        }

        foreach (Match engine in EnginePattern.Matches(image.AsciiText))
            matches.Add(new IdentifierMatch { Type = "Engine code", Value = engine.Value, Offset = engine.Index });

        return matches;
    }
}

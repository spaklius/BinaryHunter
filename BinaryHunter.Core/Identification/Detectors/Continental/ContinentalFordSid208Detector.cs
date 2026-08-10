using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// Ford-family SID208 images carry a compact header containing the 12B684
// hardware reference, CONTI_SID208 system type and 12A650 PCM software. A
// separate component block confirms the 14C204 upgrade and DS-P software
// version, so identification does not depend on a catalogue of known prefixes.
internal sealed class ContinentalFordSid208Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex HeaderPattern = new(
        @"(?<hardware>[A-Z0-9]{4}-12B684-[A-Z0-9]{2})\x00{4,64}" +
        @"(?<system>CONTI_SID208(?:_[A-Z0-9]+){3})" +
        @"(?<software>[A-Z0-9]{4}-12A650-[A-Z0-9]{2})\x00",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>[A-Z0-9]{4}-14C204-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwareVersionPattern = new(
        @"(?<![A-Z0-9])(?<version>DS-P[A-Z0-9]{4}-12A650-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BaseHardwarePattern = new(
        @"(?<![A-Z0-9])(?<hardware>[A-Z0-9]{4}-12B684-[A-Z0-9]{2})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BaseSoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>[A-Z0-9]{4}-12A650-[A-Z0-9]{2})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CalibrationComponentPattern = new(
        @"(?<![A-Z0-9])(?<calibration>[A-Z0-9]{4}-14C273-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CompactCalibrationPattern = new(
        @"(?<![A-Z0-9])(?<calibration>[A-Z0-9]{4}14C275[A-Z0-9]{2})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental Ford SID208";
    public string Manufacturer => "FORD";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var header = HeaderPattern.Match(text);
        var upgrade = UpgradePattern.Match(text);
        var version = SoftwareVersionPattern.Match(text);
        if (!header.Success || !upgrade.Success || !version.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Ford Motor Company", Offset = header.Groups["software"].Index },
            new() { Type = "ECU manufacturer", Value = "Continental", Offset = header.Groups["system"].Index },
            new() { Type = "ECU family", Value = "Continental SID208", Offset = header.Groups["system"].Index },
            new() { Type = "ECU type", Value = "SID208", Offset = header.Groups["system"].Index },
            new() { Type = "System type", Value = header.Groups["system"].Value, Offset = header.Groups["system"].Index },
            new() { Type = "Hardware Nr.", Value = header.Groups["hardware"].Value, Offset = header.Groups["hardware"].Index },
            new() { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
            new() { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Value, Offset = upgrade.Groups["upgrade"].Index },
            new() { Type = "Software version", Value = version.Groups["version"].Value, Offset = version.Groups["version"].Index }
        };

        var baseHardware = BaseHardwarePattern.Matches(text).Cast<Match>()
            .Select(match => match.Groups["hardware"])
            .FirstOrDefault(group => !string.Equals(group.Value, header.Groups["hardware"].Value, StringComparison.OrdinalIgnoreCase));
        if (baseHardware is not null)
            matches.Add(new IdentifierMatch { Type = "Base hardware Nr.", Value = baseHardware.Value, Offset = baseHardware.Index });

        var baseSoftware = BaseSoftwarePattern.Matches(text).Cast<Match>()
            .Select(match => match.Groups["software"])
            .FirstOrDefault(group => !string.Equals(group.Value, header.Groups["software"].Value, StringComparison.OrdinalIgnoreCase));
        if (baseSoftware is not null)
            matches.Add(new IdentifierMatch { Type = "Base software Nr.", Value = baseSoftware.Value, Offset = baseSoftware.Index });

        var calibrationComponent = CalibrationComponentPattern.Match(text);
        if (calibrationComponent.Success)
            matches.Add(new IdentifierMatch { Type = "Calibration component Nr.", Value = calibrationComponent.Groups["calibration"].Value, Offset = calibrationComponent.Groups["calibration"].Index });

        var compactCalibration = CompactCalibrationPattern.Match(text);
        if (compactCalibration.Success)
            matches.Add(new IdentifierMatch { Type = "Calibration Nr.", Value = compactCalibration.Groups["calibration"].Value, Offset = compactCalibration.Groups["calibration"].Index });

        return matches;
    }
}

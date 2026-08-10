using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// Ford SID211 full images retain CONTI_SID209 as their internal software-system
// marker.  The SID211 platform is identified by the complete FRK header layout:
// Ford 12B684 hardware, the two-segment SID209 system marker, 12A650 software,
// and an independent 14C204 upgrade component.  This deliberately does not map
// every raw SID209 marker to SID211.
internal sealed class ContinentalFordSid211Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex HeaderPattern = new(
        @"(?<hardware>[A-Z0-9]{4}-12B684-[A-Z0-9]{2})\x00{4,64}" +
        @"(?<system>CONTI_SID209_FRK_[A-Z0-9]+)\x00{0,16}" +
        @"(?<software>[A-Z0-9]{4}-12A650-[A-Z0-9]{2})\x00",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>[A-Z0-9]{4}-14C204-[A-Z0-9]{3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental Ford SID211";
    public string Manufacturer => "FORD";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var header = HeaderPattern.Match(text);
        var upgrade = UpgradePattern.Match(text);
        if (!header.Success || !upgrade.Success) return [];

        var system = header.Groups["system"];
        var hardware = header.Groups["hardware"];
        var software = header.Groups["software"];

        return
        [
            new() { Type = "Vehicle group", Value = "Ford Motor Company", Offset = software.Index },
            new() { Type = "ECU manufacturer", Value = "Continental", Offset = system.Index },
            new() { Type = "ECU family", Value = "Continental SID211", Offset = system.Index },
            new() { Type = "ECU type", Value = "SID211", Offset = system.Index },
            new() { Type = "System type", Value = system.Value, Offset = system.Index },
            new() { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new() { Type = "Software Nr.", Value = software.Value, Offset = software.Index },
            new() { Type = "Software Upgrade Nr.", Value = upgrade.Groups["upgrade"].Value, Offset = upgrade.Groups["upgrade"].Index }
        ];
    }
}

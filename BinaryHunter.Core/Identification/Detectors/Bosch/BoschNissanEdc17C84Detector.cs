using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Nissan/Renault EDC17C84 images are either full 2.5 MB (0x280000) or partial
// 2.375 MB reads starting at 0x00020000 (0x260000). The binary exposes either
// a platform marker `ME(D)/EDC17 SB_V...` or a platform path banner like
// `39/1/EDC17_C84/...`. The Bosch software number sits at offset 0x1A and may
// include a `_720` calibration suffix. In full images, the software upgrade
// number may also appear at offset 0x2001A.
internal sealed class BoschNissanEdc17C84Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x280000;
    private const int PartialImageSize = 0x260000;
    private const int SoftwareOffset = 0x1A;
    private const int FullUpgradeOffset = 0x2001A;
    private const int PartialUpgradeOffset = 0x1E001A;

    private static readonly Regex PlatformMarkerPattern = new(
        @"ME\(D\)/EDC17 SB_V\d+\.\d+\.\d+/\d+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PlatformPathPattern = new(
        @"\|?\d{2,3}/1/EDC17_C84/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BoschSoftwarePattern = new(
        @"^(?<software>1037\d{6})(?:_\d+)?",
        RegexOptions.Compiled);

    private static readonly Regex BoschCopyrightPattern = new(
        @"Robert Bosch France S\.A\.",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Nissan EDC17C84";
    public string Manufacturer => "RENAULT / NISSAN / DACIA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize && image.Bytes.Length != PartialImageSize) return [];

        var text = image.AsciiText;
        var platform = PlatformMarkerPattern.Match(text);
        var path = PlatformPathPattern.Match(text);
        var copyright = BoschCopyrightPattern.Match(text);
        if (!platform.Success && !path.Success && !copyright.Success) return [];

        var anchorOffset = platform.Success ? platform.Index : path.Success ? path.Index : copyright.Index;
        var isFull = image.Bytes.Length == FullImageSize;

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = isFull ? $"Full flash image ({image.DisplaySize})" : $"Partial calibration image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Nissan/Renault", Offset = anchorOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorOffset },
            new() { Type = "ECU family", Value = "Bosch EDC17C84", Offset = anchorOffset },
            new() { Type = "ECU type", Value = "EDC17C84", Offset = anchorOffset }
        };

        // Bosch software number at fixed offset 0x1A
        if (SoftwareOffset + 14 <= image.Bytes.Length)
        {
            var softwareText = text.Substring(SoftwareOffset, 14);
            var softwareMatch = BoschSoftwarePattern.Match(softwareText);
            if (softwareMatch.Success)
            {
                matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = softwareMatch.Groups["software"].Value, Offset = SoftwareOffset });
            }
        }

        // Software Upgrade Nr. at offset 0x2001A in full images, 0x1E001A in partials
        var upgradeOffset = isFull ? FullUpgradeOffset : PartialUpgradeOffset;
        if (upgradeOffset + 14 <= image.Bytes.Length)
        {
            var upgradeText = text.Substring(upgradeOffset, 14);
            var upgradeMatch = BoschSoftwarePattern.Match(upgradeText);
            if (upgradeMatch.Success)
            {
                matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgradeMatch.Groups["software"].Value, Offset = upgradeOffset });
            }
        }

        return matches;
    }
}

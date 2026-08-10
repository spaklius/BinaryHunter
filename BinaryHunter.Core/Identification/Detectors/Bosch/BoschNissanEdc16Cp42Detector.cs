using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Nissan/Renault Bosch EDC16CP42 partial and full images. The platform path
// banner contains `99/1/EDC16CP42/...`, and the binary carries a Bosch
// software number at a fixed offset together with a separate hardware/upgrade
// record. These binaries are produced as partial reads from EEPROM dumps and
// may be accompanied by a full-image reference size.
internal sealed class BoschNissanEdc16Cp42Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int PartialImageSize = 0x50000;
    private const int SoftwareOffset = 0x10;
    private const int HardwareOffset = 0x31991;
    private const int UpgradeOffset = 0x31996;

    private static readonly Regex PlatformPathPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC16CP42)/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PlatformMarkerPattern = new(
        @"EDC16CP42[-.]?\d",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]{4,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex HardwarePattern = new(
        @"(?<![A-Z0-9])(?<hardware>\d[A-Z0-9]{4})",
        RegexOptions.Compiled);

    private static readonly Regex UpgradePattern = new(
        @"(?<![A-Z0-9])(?<upgrade>\d[A-Z0-9]{4,5})(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch Nissan/Renault EDC16CP42";
    public string Manufacturer => "RENAULT / NISSAN / DACIA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
        if (image.Bytes.Length != FullImageSize) return [];

        return DetectFull(image);
    }

    private static IEnumerable<IdentifierMatch> DetectPartial(EcuBinaryImage image)
    {
        var text = image.AsciiText;

        var platform = PlatformPathPattern.Match(text);
        var marker = PlatformMarkerPattern.Match(text);
        if (!platform.Success && !marker.Success) return [];

        var anchorOffset = platform.Success ? platform.Index : marker.Index;

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Partial flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "RENAULT / NISSAN / DACIA", Offset = anchorOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorOffset },
            new() { Type = "ECU family", Value = "Bosch EDC16CP42", Offset = anchorOffset },
            new() { Type = "ECU type", Value = "EDC16CP42", Offset = anchorOffset }
        };

        if (SoftwareOffset + 20 <= text.Length)
        {
            var softwareWindow = text.Substring(SoftwareOffset, 20);
            var software = SoftwarePattern.Match(softwareWindow);
            if (software.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Software Nr.",
                    Value = software.Groups["software"].Value,
                    Offset = SoftwareOffset + software.Groups["software"].Index
                });

                var version = software.Groups["version"].Value;
                if (!string.IsNullOrEmpty(version))
                {
                    matches.Add(new IdentifierMatch
                    {
                        Type = "Software Upgrade Nr.",
                        Value = version,
                        Offset = SoftwareOffset + software.Groups["version"].Index
                    });
                }
            }
        }

        if (HardwareOffset + 5 <= text.Length)
        {
            var hardware = HardwarePattern.Match(text, HardwareOffset, 5);
            if (hardware.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Hardware Nr.",
                    Value = hardware.Groups["hardware"].Value,
                    Offset = HardwareOffset + hardware.Groups["hardware"].Index
                });
            }
        }

        if (UpgradeOffset + 5 <= text.Length)
        {
            var upgrade = UpgradePattern.Match(text, UpgradeOffset, 5);
            if (upgrade.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Software Upgrade Nr.",
                    Value = upgrade.Groups["upgrade"].Value,
                    Offset = UpgradeOffset + upgrade.Groups["upgrade"].Index
                });
            }
        }

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectFull(EcuBinaryImage image)
    {
        var text = image.AsciiText;

        var platform = PlatformPathPattern.Match(text);
        var marker = PlatformMarkerPattern.Match(text);
        if (!platform.Success && !marker.Success) return [];

        var anchorOffset = platform.Success ? platform.Index : marker.Index;

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "RENAULT / NISSAN / DACIA", Offset = anchorOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorOffset },
            new() { Type = "ECU family", Value = "Bosch EDC16CP42", Offset = anchorOffset },
            new() { Type = "ECU type", Value = "EDC16CP42", Offset = anchorOffset }
        };

        if (SoftwareOffset + 20 <= text.Length)
        {
            var softwareWindow = text.Substring(SoftwareOffset, 20);
            var software = SoftwarePattern.Match(softwareWindow);
            if (software.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Software Nr.",
                    Value = software.Groups["software"].Value,
                    Offset = SoftwareOffset + software.Groups["software"].Index
                });

                var version = software.Groups["version"].Value;
                if (!string.IsNullOrEmpty(version))
                {
                    matches.Add(new IdentifierMatch
                    {
                        Type = "Software Upgrade Nr.",
                        Value = version,
                        Offset = SoftwareOffset + software.Groups["version"].Index
                    });
                }
            }
        }

        if (HardwareOffset + 5 <= text.Length)
        {
            var hardware = HardwarePattern.Match(text, HardwareOffset, 5);
            if (hardware.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Hardware Nr.",
                    Value = hardware.Groups["hardware"].Value,
                    Offset = HardwareOffset + hardware.Groups["hardware"].Index
                });
            }
        }

        if (UpgradeOffset + 5 <= text.Length)
        {
            var upgrade = UpgradePattern.Match(text, UpgradeOffset, 5);
            if (upgrade.Success)
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Software Upgrade Nr.",
                    Value = upgrade.Groups["upgrade"].Value,
                    Offset = UpgradeOffset + upgrade.Groups["upgrade"].Index
                });
            }
        }

        return matches;
    }
}

using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Mercedes-Benz Bosch EDC16CP36 full images (2 MB). The platform path banner
// contains `99/1/EDC16CP36/...` which distinguishes these from the BMW
// EDC16C35/CP35 family that uses the same 2 MB size and 1037xxxxxx software
// number format. The Mercedes-specific identifiers are stored in a compact
// OEM block with the software number followed by a Pxxx/xxx version string.
internal sealed class BoschMebEdc16Cp36Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;

    private static readonly Regex PlatformPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC16CP36)/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // EDC16CP36 platform marker (e.g. "EDC16CP36-3.x MPC563")
    private static readonly Regex PlatformMarkerPattern = new(
        @"EDC16CP36[-.]?\d",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Bosch software number (1037xxxxxx) followed by a version string (e.g. P380/811)
    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>P\d{3,4}/\d{3,4})(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch Mercedes-Benz EDC16CP36";
    public string Manufacturer => "Mercedes-Benz";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;

        // Require either the platform path or the platform marker
        var platform = PlatformPattern.Match(text);
        var marker = PlatformMarkerPattern.Match(text);
        if (!platform.Success && !marker.Success) return [];

        var anchorOffset = platform.Success ? platform.Index : marker.Index;

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Mercedes-Benz", Offset = anchorOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorOffset },
            new() { Type = "ECU family", Value = "Bosch EDC16CP36", Offset = anchorOffset },
            new() { Type = "ECU type", Value = "EDC16CP36", Offset = anchorOffset }
        };

        // Extract the Bosch software number and version
        var software = SoftwarePattern.Match(text);
        if (software.Success)
        {
            matches.Add(new IdentifierMatch
            {
                Type = "Software Nr.",
                Value = software.Groups["software"].Value,
                Offset = software.Groups["software"].Index
            });
            matches.Add(new IdentifierMatch
            {
                Type = "Software Upgrade Nr.",
                Value = software.Groups["version"].Value,
                Offset = software.Groups["version"].Index
            });
        }

        return matches;
    }
}
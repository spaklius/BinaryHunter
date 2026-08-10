using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Mercedes-Benz Bosch EDC16CP31 full images (2 MB). The platform marker
// `EDC16CP31-x.x MPC563` appears in the binary, and the platform path may
// use `99/1/EDC16C31/999/` (without P). This distinguishes these from the
// BMW EDC16C35/CP35 family that uses the same 2 MB size and 1037xxxxxx
// software number format. The Mercedes-specific identifiers use a Pxxx/xxx
// version string format (e.g. P409/705, P20942PA).
internal sealed class BoschMebEdc16Cp31Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;

    // Platform path (may use EDC16C31 without P, e.g. `99/1/EDC16C31/999/`)
    private static readonly Regex PlatformPathPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC16C3[01])/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Platform marker (e.g. "EDC16CP31-6.x MPC563")
    private static readonly Regex PlatformMarkerPattern = new(
        @"EDC16CP31[-.]?\d",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Bosch software number (1037xxxxxx) followed by a version string
    // Version can be Pxxx/xxx (e.g. P409/705) or alphanumeric (e.g. P20942PA)
    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>P\d{3,4}/\d{3,4}|[A-Z0-9]{4,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch Mercedes-Benz EDC16CP31";
    public string Manufacturer => "Mercedes-Benz";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;

        // Require either the platform path or the platform marker
        var platform = PlatformPathPattern.Match(text);
        var marker = PlatformMarkerPattern.Match(text);
        if (!platform.Success && !marker.Success) return [];

        // If the platform path uses EDC16C31 without the P prefix, require the
        // EDC16CP31 platform marker elsewhere to avoid false-positive matches
        // on BMW EDC16C31 binaries that share the same 2 MB size and layout.
        if (platform.Success && platform.Groups["type"].Value.Equals("EDC16C31", StringComparison.OrdinalIgnoreCase) && !marker.Success)
            return [];

        var anchorOffset = platform.Success ? platform.Index : marker.Index;

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Mercedes-Benz", Offset = anchorOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorOffset },
            new() { Type = "ECU family", Value = "Bosch EDC16CP31", Offset = anchorOffset },
            new() { Type = "ECU type", Value = "EDC16CP31", Offset = anchorOffset }
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

            var version = software.Groups["version"].Value;
            if (!string.IsNullOrEmpty(version))
            {
                matches.Add(new IdentifierMatch
                {
                    Type = "Software Upgrade Nr.",
                    Value = version,
                    Offset = software.Groups["version"].Index
                });
            }
        }

        return matches;
    }
}
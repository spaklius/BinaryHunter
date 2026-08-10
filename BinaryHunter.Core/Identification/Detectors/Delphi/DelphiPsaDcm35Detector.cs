using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Delphi;

// PSA/Stellantis Delphi DCM3.5 partial reads are consistently 3,080,192 bytes
// starting at offset 0x00010000. The binary exposes a stable delivery/protocol
// marker of the form <code>_DELIV_<version>, but hardware/software numbers
// are NOT present as readable ASCII or standard BCD in this partial layout.
// The catalog metadata catalog confirms these fields exist externally but
// are stored in an encoding not currently accessible from the binary alone.
internal sealed class DelphiPsaDcm35Detector : IEcuDetectionModule
{
    private const int PartialImageSize = 0x2F0000;

    private static readonly Regex DeliveryPattern = new(
        @"(?<code>[A-Z0-9]{6,12})_DELIV_(?<version>\d+(?:_[A-Z0-9_]+)?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Delphi PSA DCM3.5";
    public string Manufacturer => "PSA / STELLANTIS";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != PartialImageSize) return [];

        var delivery = DeliveryPattern.Match(image.AsciiText);
        if (!delivery.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Partial read ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "PSA / Stellantis", Offset = delivery.Index },
            new() { Type = "ECU manufacturer", Value = "Delphi", Offset = delivery.Index },
            new() { Type = "ECU family", Value = "Delphi DCM3.5", Offset = delivery.Index },
            new() { Type = "ECU type", Value = "DCM3.5", Offset = delivery.Index },
            new() { Type = "Calibration version", Value = $"{delivery.Groups["code"].Value}_DELIV_{delivery.Groups["version"].Value}", Offset = delivery.Index },
            new() { Type = "Note", Value = "No hardware/software/upgrade numbers present in this partial layout", Offset = 0 }
        };

        return matches;
    }
}

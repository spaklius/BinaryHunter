using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Denso;

// Subaru Denso SH7058/SH7059 partial reads are 1,032,192 bytes (0xFC000)
// starting at offset 0x00004000. The binary exposes a compact identification
// block at the start of the file: hardware number (8 chars), software number
// (8 chars), and software upgrade number (variable, space-terminated) are
// stored consecutively without separators. A repeated DENSO copyright marker
// provides secondary confirmation.
internal sealed class DensoSubaruSh705xDetector : IEcuDetectionModule
{
    private const int PartialImageSize = 0xFC000;

    public string Name => "Denso Subaru SH705x";
    public string Manufacturer => "SUBARU";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != PartialImageSize) return [];

        var text = image.AsciiText;
        var firstDenso = text.IndexOf("Cpyr.DENSO", StringComparison.OrdinalIgnoreCase);
        var secondDenso = firstDenso < 0
            ? -1
            : text.IndexOf("Cpyr.DENSO", firstDenso + 1, StringComparison.OrdinalIgnoreCase);
        if (firstDenso < 0 || secondDenso < 0) return [];

        var upgradeEnd = text.IndexOf(' ', 16);
        if (upgradeEnd < 0 || upgradeEnd > 32) return [];
        var upgrade = text.Substring(16, upgradeEnd - 16);
        if (upgrade.Length < 2) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Partial read ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Subaru", Offset = 0 },
            new() { Type = "ECU manufacturer", Value = "Denso", Offset = firstDenso + 5 },
            new() { Type = "ECU family", Value = "Denso SH705x", Offset = firstDenso + 5 },
            new() { Type = "ECU type", Value = "SH7058/SH7059", Offset = firstDenso + 5 },
            new() { Type = "Hardware Nr.", Value = text.Substring(0, 8), Offset = 0 },
            new() { Type = "Software Nr.", Value = text.Substring(8, 8), Offset = 8 },
            new() { Type = "Software Upgrade Nr.", Value = upgrade, Offset = 16 }
        };

        return matches;
    }
}

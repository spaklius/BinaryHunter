using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// Continental-Siemens-VDO SID208 PSA (P1009) is a 4 MB Tricore image used on
// Citroen / Peugeot 2.2 HDi applications. The identifier block sits at fixed
// offsets near the end of the image; its exact anchor text varies between
// reads, so identification relies on the fixed block layout rather than a
// textual anchor:
//
//   1. Exact image size (4 MB).
//   2. Two 10-digit software-number fields at 0x00200200 and 0x0020020C.
//   3. 6-digit spare-part number at fixed offset 0x00200218.
//
// The reference tool reported hardware number as not_found across the analysed
// group, so it is deliberately omitted.
internal sealed class ContinentalSiemensVdoSid208PsaDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;
    private const int SoftwareOffset = 0x00200200;
    private const int SoftwareUpgradeOffset = 0x0020020C;
    private const int SparePartNumberOffset = 0x00200218;

    private static readonly Regex SoftwarePattern = new(@"^\d{10}$", RegexOptions.Compiled);
    private static readonly Regex SparePartPattern = new(@"^\d{6}$", RegexOptions.Compiled);

    public string Name => "Continental-Siemens-VDO SID208 PSA";
    public string Manufacturer => "PSA / STELLANTIS";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var softwareToken = IdentifierHelpers.ReadToken(image.Bytes, SoftwareOffset, 11);
        var upgradeToken = IdentifierHelpers.ReadToken(image.Bytes, SoftwareUpgradeOffset, 11);
        var spareToken = IdentifierHelpers.ReadToken(image.Bytes, SparePartNumberOffset, 6);
        if (softwareToken is null || upgradeToken is null || spareToken is null) return [];

        var software = softwareToken.Trim();
        var upgrade = upgradeToken.Trim();
        if (!SoftwarePattern.IsMatch(software) || !SoftwarePattern.IsMatch(upgrade)) return [];
        if (!SparePartPattern.IsMatch(spareToken)) return [];

        var matches = new List<IdentifierMatch>
        {
            new IdentifierMatch { Type = "Vehicle group", Value = "PSA Group", Offset = SoftwareOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Continental / Siemens-VDO", Offset = SoftwareOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Continental SID208", Offset = SoftwareOffset },
            new IdentifierMatch { Type = "ECU type", Value = "SID208", Offset = SoftwareOffset },
            new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = SoftwareOffset },
            new IdentifierMatch { Type = "Spare Part Nr.", Value = spareToken, Offset = SparePartNumberOffset },
            new IdentifierMatch { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 }
        };

        return matches;
    }
}

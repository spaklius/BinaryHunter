using System.Text;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW DDE4.0 / EDC15C4 images are typically 512 KiB reads. They do not carry
// readable Bosch/BMW banners, so identification relies on the fixed-offset
// software number and software version layout used across this family.
internal sealed class BoschBmwEdc15C4Detector : IEcuDetectionModule
{
    private const int ExpectedSize = 0x80000;
    private const int SoftwareIdOffset = 507_824;
    private const int SoftwareVersionOffset = 393_108;

    public string Name => "Bosch BMW EDC15C4 / DDE4.0";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != ExpectedSize) return [];

        var text = Encoding.ASCII.GetString(image.Bytes);
        var softwareId = text.Substring(SoftwareIdOffset, 10);
        if (!System.Text.RegularExpressions.Regex.IsMatch(softwareId, @"^1037\d{6}$"))
            return [];

        var softwareVersion = text.Substring(SoftwareVersionOffset, 7);
        if (!System.Text.RegularExpressions.Regex.IsMatch(softwareVersion, @"^\d{7}$"))
            return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "ECU manufacturer", Value = "Bosch (EDC15C4 / DDE4.0 fixed-offset evidence)", Offset = SoftwareIdOffset },
            new() { Type = "ECU family", Value = "Bosch EDC15C4", Offset = SoftwareIdOffset },
            new() { Type = "ECU type", Value = "EDC15C4", Offset = SoftwareIdOffset },
            new() { Type = "Vehicle group", Value = "BMW Group (EDC15C4 / DDE4.0 profile evidence)", Offset = SoftwareIdOffset },
            new() { Type = "Software Nr.", Value = softwareId, Offset = SoftwareIdOffset },
            new() { Type = "Software version", Value = softwareVersion, Offset = SoftwareVersionOffset }
        };

        return matches;
    }
}

using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// VAG Siemens/Continental SIMOS PPD1.x images. The platform exposes its
// identity through CASN dataset records and an OEM block containing the VAG
// part number, engine text, ECU type, software number, and version date.
// Module identifiers may vary across PPD variants and are not required.
internal sealed class ContinentalVagSimosPpd15Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;

    private static readonly Regex DatasetPattern = new(
        @"CASN[A-Z0-9]{2,8}\.DAT",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<upgrade>[A-Z0-9]{3}\d{6}[A-Z]{0,2})[ \x00]+" +
        @"(?<engine>R4\s+\d[,.]\dl?)\s+(?<type>PPD1\.\d+)(?:[ \x00]+(?<revision>\d{4}))?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Continental VAG SIMOS PPD1.x";
    public string Manufacturer => "AUDI / VW / ŠKODA / SEAT";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == FullImageSize || image.Bytes.Length == 0x40000)
        {
            var text = image.AsciiText;
            var dataset = DatasetPattern.Match(text);
            if (!dataset.Success) return [];

            var identification = IdentificationBlockPattern.Match(text);
            if (!identification.Success) return [];

            var upgrade = identification.Groups["upgrade"];
            var revision = identification.Groups["revision"];
            var engine = identification.Groups["engine"];
            var type = identification.Groups["type"];

            // Software number is at a fixed offset relative to the CASN dataset
            // marker. In both partial and full images, the software number sits
            // 0x40 bytes before the CASN record.
            var softwareOffset = dataset.Index - 0x40;
            if (softwareOffset < 0 || softwareOffset + 10 > image.Bytes.Length) return [];
            var software = text.Substring((int)softwareOffset, 10);

            var upgradeValue = revision.Success ? $"{upgrade.Value} {revision.Value}" : upgrade.Value;

            return
            [
                new IdentifierMatch { Type = "Read format", Value = image.Bytes.Length == FullImageSize ? "Full flash image (2 MB)" : $"Partial calibration image ({image.DisplaySize})", Offset = 0 },
                new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = upgrade.Index },
                new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = dataset.Index },
                new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental SIMOS PPD", Offset = dataset.Index },
                new IdentifierMatch { Type = "ECU type", Value = type.Value.ToUpperInvariant(), Offset = identification.Index },
                new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = softwareOffset },
                new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgradeValue, Offset = upgrade.Index },
                new IdentifierMatch { Type = "Engine", Value = $"{engine.Value} {type.Value}", Offset = engine.Index },
                new IdentifierMatch { Type = "Processor", Value = "Infineon TC1796 (SIMOS PPD platform inference)", Offset = dataset.Index }
            ];
        }

        return [];
    }
}

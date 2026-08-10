using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Opel/GM EDC16C39 calibration exports are commonly 0x40000-byte images. The
// active Bosch software and upgrade record at the start carries the same
// three-digit platform code as the embedded EDC16C39 path. A separate runtime
// identification block supplies the ECU type, engine code and Bosch hardware.
// Requiring all three records avoids identifying the ECU from an isolated
// library string or from a known identifier catalogue.
internal sealed class BoschOpelEdc16C39Detector : IEcuDetectionModule
{
    private const int PartialImageSize = 0x40000;
    private const int BaseAddressOffset = 0x34;
    private const int ContainerSignatureOffset = 0x3C;

    private static readonly byte[] ContainerSignature =
    [
        0xFA, 0xDE, 0xCA, 0xFE, 0xCA, 0xFE, 0xAF, 0xFE
    ];

    private static readonly Regex HeaderPattern = new(
        @"(?<![A-Z0-9])(?<software>1037[A-Z0-9]{6})(?<upgrade>P(?<code>\d{3})_[A-Z]\d{2,3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PlatformPattern = new(
        @"\|\d{2,3}/1/(?<type>EDC16C39)/\d{3}/C(?<code>\d{3})/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<type>EDC16C39)[ \x00-\x1F]+" +
        @"(?<oem>\d{8}[A-Z]{0,2})[ \x00-\x1F]+" +
        @"(?:[A-Z]{2}[ \x00-\x1F]+)?" +
        @"(?<calibration>[A-Z0-9]{6,15}(?:_[A-Z])?)[ \x00-\x1F]+" +
        @"(?<version>[A-Z0-9]{6,12})[ \x00-\x1F]+.{0,2}?" +
        @"(?<engine>Z\d{2}[A-Z]{2,4})[ \x00-\x1F]+" +
        @"(?<hardware>0281\d{6})(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    public string Name => "Bosch Opel/GM EDC16C39 partial image";
    public string Manufacturer => "OPEL / VAUXHALL / GM";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != PartialImageSize) return [];

        var header = HeaderPattern.Match(image.AsciiText);
        var platform = PlatformPattern.Match(image.AsciiText);
        var identification = IdentificationBlockPattern.Match(image.AsciiText);
        if (!header.Success || !platform.Success || !identification.Success) return [];
        if (!string.Equals(header.Groups["code"].Value, platform.Groups["code"].Value, StringComparison.OrdinalIgnoreCase)) return [];

        var baseAddress = TryReadBaseAddress(image.Bytes);
        var format = baseAddress is null
            ? $"Partial calibration image ({image.DisplaySize})"
            : $"Partial calibration image ({image.DisplaySize}; base 0x{baseAddress.Value:X8})";

        return
        [
            new IdentifierMatch { Type = "Read format", Value = format, Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "General Motors / Opel (EDC16C39 engine-code evidence)", Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C39", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C39", Offset = identification.Groups["type"].Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = header.Groups["upgrade"].Value, Offset = header.Groups["upgrade"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "OEM reference", Value = identification.Groups["oem"].Value, Offset = identification.Groups["oem"].Index }
        ];
    }

    private static uint? TryReadBaseAddress(byte[] bytes)
    {
        if (bytes.Length < ContainerSignatureOffset + ContainerSignature.Length ||
            !bytes.AsSpan(ContainerSignatureOffset, ContainerSignature.Length).SequenceEqual(ContainerSignature))
            return null;

        return ((uint)bytes[BaseAddressOffset] << 24) |
               ((uint)bytes[BaseAddressOffset + 1] << 16) |
               ((uint)bytes[BaseAddressOffset + 2] << 8) |
               bytes[BaseAddressOffset + 3];
    }
}

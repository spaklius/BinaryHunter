using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Opel/GM EDC15M full PLCC images share the 0x40000-byte C3-padded container
// with EDC15M1, but the confirmed EDC15M identification layouts carry a DTH
// engine code, optionally followed by a two-character variant such as "D3".
// A three-byte hardware-field marker may contain a printable P or a binary
// revision byte, so it is treated as layout metadata rather than an identifier.
internal sealed class BoschOpelEdc15MDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x40000;
    private const int MinimumC3PrefixLength = 0x8000;

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<upgrade>\d{8}) [A-Z]{2}.{3}" +
        @"(?<calibration>[A-Z0-9]{6,12}_S)\x00" +
        @"(?<revision>[\x01-\x1F])" +
        @"(?<variant>B\d{5})" +
        @"(?<engine>[XYZ]\d{2}[A-Z]{2}H(?: [A-Z0-9]{2})?)[ \x00-\x1F]*.{0,3}?" +
        @"P?(?<hardware>0281\d{6})(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex OpelMarkerPattern = new(
        @"(?<![A-Z])OPEL(?![A-Z])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Opel/GM EDC15M full PLCC image";
    public string Manufacturer => "OPEL / VAUXHALL / GM";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize || !HasC3Prefix(image.Bytes)) return [];

        var identification = IdentificationBlockPattern.Match(image.AsciiText);
        var opelMarker = OpelMarkerPattern.Match(image.AsciiText);
        if (!identification.Success || !opelMarker.Success) return [];

        var revision = (byte)identification.Groups["revision"].Value[0];
        var upgrade = $"{identification.Groups["upgrade"].Value}.{revision:D2}";
        return
        [
            new IdentifierMatch { Type = "Read format", Value = $"Full PLCC flash image ({image.DisplaySize})", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "General Motors / Opel (raw OEM marker)", Offset = opelMarker.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch (EDC15M identification-block evidence)", Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC15M", Offset = identification.Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC15M", Offset = identification.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade, Offset = identification.Groups["upgrade"].Index },
            new IdentifierMatch { Type = "Calibration reference", Value = identification.Groups["calibration"].Value, Offset = identification.Groups["calibration"].Index },
            new IdentifierMatch { Type = "Calibration Nr.", Value = identification.Groups["variant"].Value, Offset = identification.Groups["variant"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index }
        ];
    }

    private static bool HasC3Prefix(byte[] bytes)
    {
        for (var index = 0; index < MinimumC3PrefixLength; index++)
            if (bytes[index] != 0xC3) return false;
        return true;
    }
}

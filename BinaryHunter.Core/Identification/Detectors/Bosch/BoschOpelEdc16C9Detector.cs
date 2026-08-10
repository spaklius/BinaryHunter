using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Opel/GM EDC16C9 full flash images carry a Bosch software/upgrade record,
// an EDC16C9 platform path with the same three-digit code, and one or more
// runtime identification blocks. Selecting the first identification block
// after the platform path avoids returning an older repeated calibration bank.
internal sealed class BoschOpelEdc16C9Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x100000;

    private static readonly Regex HeaderPattern = new(
        @"(?<![A-Z0-9])(?<software>1037[A-Z0-9]{6})(?<upgrade>P(?<code>\d{3})_[A-Z]\d{2,3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PlatformPattern = new(
        @"\|\d{2,3}/1/(?<type>EDC16C9)/\d{3}/P(?<code>\d{3})/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdentificationBlockPattern = new(
        @"(?<type>EDC16)[ \x00-\x1F]+" +
        @"(?<oem>\d{8}[A-Z]{0,2})[ \x00-\x1F]+" +
        @"(?:[A-Z]{2}[ \x00-\x1F]+)?" +
        @"(?<calibration>[A-Z0-9]{6,15}(?:_[A-Z])?)[ \x00-\x1F]+" +
        @"(?:(?<version>[A-Z0-9]{6,12})[ \x00-\x1F]+)?.{0,2}?" +
        @"(?<engine>Z\d{2}[A-Z]{2,4})[ \x00-\x1F]+" +
        @"(?<hardware>0281\d{6})(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    public string Name => "Bosch Opel/GM EDC16C9 full flash";
    public string Manufacturer => "OPEL / VAUXHALL / GM";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var platform = PlatformPattern.Match(image.AsciiText);
        if (!platform.Success) return [];

        var platformCode = platform.Groups["code"].Value;
        var header = HeaderPattern.Matches(image.AsciiText)
            .Cast<Match>()
            .Where(match => string.Equals(match.Groups["code"].Value, platformCode, StringComparison.OrdinalIgnoreCase))
            .OrderBy(match => Math.Abs(match.Index - platform.Index))
            .FirstOrDefault();
        var identification = IdentificationBlockPattern.Matches(image.AsciiText)
            .Cast<Match>()
            .Where(match => match.Index > platform.Index)
            .OrderBy(match => match.Index - platform.Index)
            .FirstOrDefault();
        if (header is null || identification is null) return [];

        var matches = new List<IdentifierMatch>
        {
            new IdentifierMatch { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "General Motors / Opel (EDC16C9 engine-code evidence)", Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C9", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C9", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "Processor", Value = "Freescale MPC555 (EDC16C9 platform inference)", Offset = platform.Groups["type"].Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "OEM reference", Value = identification.Groups["oem"].Value, Offset = identification.Groups["oem"].Index }
        };

        if (identification.Groups["version"].Success)
        {
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = header.Groups["upgrade"].Value, Offset = header.Groups["upgrade"].Index });
        }
        else
        {
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index });
            matches.Add(new IdentifierMatch { Type = "Calibration reference", Value = header.Groups["upgrade"].Value, Offset = header.Groups["upgrade"].Index });
        }

        return matches;
    }
}

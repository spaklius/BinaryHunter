using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// A full Opel/GM EDC16C39 flash contains an EDC16C39/MPC runtime signature,
// a Bosch P-project record, a C-platform path and an OEM identification block.
// The three-digit project code must agree across all records. This also lets us
// select the active identification block after the platform path when older
// calibration banks are present elsewhere in the image.
internal sealed class BoschOpelEdc16C39FullDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;

    private static readonly Regex HeaderPattern = new(
        @"(?<![A-Z0-9])(?<software>1037[A-Z0-9]{6})(?<upgrade>P(?<code>\d{3})_[A-Z]\d{2,3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProjectPattern = new(
        @"Bosch\.p_(?<code>\d{3})\.Project\.EDC16\.[A-Z]\d{3}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RuntimePattern = new(
        @"BOSCH\s+BOSCH0100/(?<type>EDC16C39)\s+(?<processor>MPC\d{3})/",
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

    private static readonly Regex OpelMarkerPattern = new(
        @"(?<![A-Z])OPEL(?![A-Z])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Opel/GM EDC16C39 full flash";
    public string Manufacturer => "OPEL / VAUXHALL / GM";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var project = ProjectPattern.Match(image.AsciiText);
        var platform = PlatformPattern.Match(image.AsciiText);
        var runtimes = RuntimePattern.Matches(image.AsciiText).Cast<Match>().ToArray();
        var opelMarker = OpelMarkerPattern.Match(image.AsciiText);
        if (!project.Success || !platform.Success || runtimes.Length < 2 || !opelMarker.Success) return [];

        var platformCode = platform.Groups["code"].Value;
        if (!string.Equals(project.Groups["code"].Value, platformCode, StringComparison.OrdinalIgnoreCase)) return [];
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

        var runtime = runtimes.OrderBy(match => Math.Abs(match.Index - project.Index)).First();
        return
        [
            new IdentifierMatch { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "General Motors / Opel (raw OEM marker)", Offset = opelMarker.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = runtime.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C39", Offset = runtime.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C39", Offset = runtime.Groups["type"].Index },
            new IdentifierMatch { Type = "Processor", Value = runtime.Groups["processor"].Value, Offset = runtime.Groups["processor"].Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = header.Groups["upgrade"].Value, Offset = header.Groups["upgrade"].Index },
            new IdentifierMatch { Type = "Engine code", Value = identification.Groups["engine"].Value, Offset = identification.Groups["engine"].Index },
            new IdentifierMatch { Type = "OEM reference", Value = identification.Groups["oem"].Value, Offset = identification.Groups["oem"].Index }
        ];
    }
}

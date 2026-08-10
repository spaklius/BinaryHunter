using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// An EDC16C9 MPC processor read does not contain the external-flash OEM/HW
// identification block. It does contain repeated EDC16C9/MPC555 runtime
// signatures plus a Bosch P-project record whose numeric code must agree with
// the software/upgrade header. These independent signals distinguish the real
// ECU profile from generic EDC16.C000 library labels in the same image.
internal sealed class BoschOpelEdc16C9MpcDetector : IEcuDetectionModule
{
    private const int ProcessorImageSize = 0x71000;

    private static readonly Regex HeaderPattern = new(
        @"(?<![A-Z0-9])(?<software>1037[A-Z0-9]{6})(?<upgrade>P(?<code>\d{3})_[A-Z]\d{2,3})(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProjectPattern = new(
        @"Bosch\.p_(?<code>\d{3})\.Project\.EDC16\.C000",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RuntimePattern = new(
        @"BOSCH\s+BOSCH0100/(?<type>EDC16C9)\s+(?<processor>MPC555)/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch Opel/GM EDC16C9 MPC processor image";
    public string Manufacturer => "OPEL / VAUXHALL / GM";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != ProcessorImageSize) return [];

        var project = ProjectPattern.Match(image.AsciiText);
        var runtimes = RuntimePattern.Matches(image.AsciiText).Cast<Match>().ToArray();
        if (!project.Success || runtimes.Length < 2) return [];

        var projectCode = project.Groups["code"].Value;
        var header = HeaderPattern.Matches(image.AsciiText)
            .Cast<Match>()
            .Where(match => string.Equals(match.Groups["code"].Value, projectCode, StringComparison.OrdinalIgnoreCase))
            .OrderBy(match => Math.Abs(match.Index - project.Index))
            .FirstOrDefault();
        if (header is null) return [];

        var runtime = runtimes.OrderBy(match => Math.Abs(match.Index - project.Index)).First();
        return
        [
            new IdentifierMatch { Type = "Read format", Value = $"Partial MPC processor image ({image.DisplaySize})", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "General Motors / Opel (EDC16C9 P-project inference)", Offset = project.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch (repeated EDC16C9 runtime evidence)", Offset = runtime.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C9", Offset = runtime.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C9", Offset = runtime.Groups["type"].Index },
            new IdentifierMatch { Type = "Processor", Value = runtime.Groups["processor"].Value, Offset = runtime.Groups["processor"].Index },
            new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = header.Groups["upgrade"].Value, Offset = header.Groups["upgrade"].Index }
        ];
    }
}

using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Denso;

// Mazda RF7-series Denso images contain a repeated Denso project identifier,
// repeated copyright blocks, an explicit SH7058 processor tag and a compact
// hardware/region/software record. These independent signals identify the family
// without relying on a known hardware number, filename or external ID report.
internal sealed class DensoMazdaRf7Sh7058Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x100000;

    private static readonly Regex ProjectPattern = new(
        @"(?<![A-Z0-9])(?<project>G[A-Z0-9]{11})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex IdentificationPattern = new(
        @"(?<![A-Z0-9])(?<hardware>[A-Z0-9]{9})(?<region>[A-Z])(?<software>SW-[A-Z0-9]{6,16}\.HEX)(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex CalibrationPattern = new(
        @"(?<![A-Z0-9])(?<calibration>RF7[A-Z0-9]{13})(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Denso Mazda RF7-series SH7058 full flash";
    public string Manufacturer => "MAZDA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var firstDenso = text.IndexOf("Copr.DENSO", StringComparison.OrdinalIgnoreCase);
        var secondDenso = firstDenso < 0
            ? -1
            : text.IndexOf("Copr.DENSO", firstDenso + 1, StringComparison.OrdinalIgnoreCase);
        var mazdaMarker = text.IndexOf("Mazda", StringComparison.OrdinalIgnoreCase);
        var processorMarker = text.IndexOf("J56XSH7058", StringComparison.OrdinalIgnoreCase);
        var project = ProjectPattern.Match(text);
        var identification = IdentificationPattern.Match(text);
        if (firstDenso < 0 || secondDenso < 0 || mazdaMarker < 0 || processorMarker < 0 ||
            !project.Success || !identification.Success)
            return [];

        var repeatedProject = text.IndexOf(
            project.Groups["project"].Value,
            project.Index + project.Length,
            StringComparison.Ordinal);
        if (repeatedProject < 0) return [];

        var processorOffset = processorMarker + "J56X".Length;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = "Full flash image (1 MB)", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Mazda (raw OEM and Denso project evidence)", Offset = mazdaMarker },
            new() { Type = "ECU manufacturer", Value = "Denso", Offset = firstDenso + 5 },
            new() { Type = "ECU family", Value = "Denso RF7/RF8-series PCM SH7058", Offset = processorOffset },
            new() { Type = "ECU type", Value = "RF7/RF8-series PCM SH7058", Offset = processorOffset },
            new() { Type = "Processor", Value = "Renesas SH7058 (raw processor marker)", Offset = processorOffset },
            new() { Type = "Denso project Nr.", Value = project.Groups["project"].Value, Offset = project.Groups["project"].Index },
            new() { Type = "Hardware Nr.", Value = identification.Groups["hardware"].Value, Offset = identification.Groups["hardware"].Index },
            new() { Type = "Software Nr.", Value = identification.Groups["software"].Value, Offset = identification.Groups["software"].Index }
        };

        var calibration = CalibrationPattern.Match(text);
        if (calibration.Success)
            matches.Add(new IdentifierMatch
            {
                Type = "Calibration Nr.",
                Value = calibration.Groups["calibration"].Value,
                Offset = calibration.Groups["calibration"].Index
            });

        return matches;
    }
}

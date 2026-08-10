using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Denso;

// Mazda R2AA Denso full reads separate the boot hardware/version pair from the
// active software/upgrade pair. Repeated Denso project blocks, the Mazda marker
// and an explicit JxxxSH7058 tag validate the profile without known ID values.
internal sealed class DensoMazdaR2aaSh7058Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x100000;
    private const int AltImageSize = 0x180000;

    private static readonly Regex ProjectPattern = new(
        @"(?<![A-Z0-9])(?<project>G[A-Z0-9]{11})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"J[A-Z0-9]{3}(?<processor>SH705[89])",
        RegexOptions.Compiled);

    private static readonly Regex BootIdentificationPattern = new(
        @"(?<hardware>[A-Z0-9]{4}-188K1-[A-Z]?).{0,32}(?<version>[A-Z0-9]{4}-18881-[A-Z])",
        RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex ActiveIdentificationPattern = new(
        @"(?<software>[A-Z0-9]{4}-18881-[A-Z]).{0,32}(?<upgrade>[A-Z0-9]{4}-188K2-[A-Z])",
        RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex CalibrationPattern = new(
        @"(?<![A-Z0-9])(?<calibration>[A-Z0-9]{9}R[A-Z0-9]D6060)(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Denso Mazda R2AA SH7058 full flash";
    public string Manufacturer => "MAZDA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize && image.Bytes.Length != AltImageSize) return [];

        var text = image.AsciiText;
        var firstDenso = text.IndexOf("Copr.DENSO", StringComparison.OrdinalIgnoreCase);
        var secondDenso = firstDenso < 0
            ? -1
            : text.IndexOf("Copr.DENSO", firstDenso + 1, StringComparison.OrdinalIgnoreCase);
        var mazdaMarker = text.IndexOf("Mazda", StringComparison.OrdinalIgnoreCase);
        var project = ProjectPattern.Match(text);
        var processor = ProcessorPattern.Match(text);
        var boot = BootIdentificationPattern.Match(text);
        var active = ActiveIdentificationPattern.Match(text);
        if (firstDenso < 0 || secondDenso < 0 || mazdaMarker < 0 || !project.Success ||
            !processor.Success || !boot.Success || !active.Success)
            return [];

        // Mazda hardware and software revisions may legitimately use adjacent
        // family prefixes (for example R2AA hardware with R2AB software). The
        // three software-side identifiers must agree with each other instead.
        var softwarePrefix = active.Groups["software"].Value[..4];
        if (!boot.Groups["version"].Value.StartsWith(softwarePrefix, StringComparison.Ordinal) ||
            !active.Groups["upgrade"].Value.StartsWith(softwarePrefix, StringComparison.Ordinal))
            return [];

        var repeatedProject = text.IndexOf(
            project.Groups["project"].Value,
            project.Index + project.Length,
            StringComparison.Ordinal);
        if (repeatedProject < 0 ||
            !project.Groups["project"].Value.Contains(softwarePrefix, StringComparison.Ordinal))
            return [];

        var processorOffset = processor.Groups["processor"].Index;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "Mazda (raw OEM and Denso project evidence)", Offset = mazdaMarker },
            new() { Type = "ECU manufacturer", Value = "Denso", Offset = firstDenso + 5 },
            new() { Type = "ECU family", Value = "Denso R2AA PCM SH7058", Offset = processorOffset },
            new() { Type = "ECU type", Value = "R2AA PCM SH7058", Offset = processorOffset },
            new() { Type = "Processor", Value = "Renesas SH7058 (raw processor marker)", Offset = processorOffset },
            new() { Type = "Denso project Nr.", Value = project.Groups["project"].Value, Offset = project.Groups["project"].Index },
            new() { Type = "Hardware Nr.", Value = boot.Groups["hardware"].Value, Offset = boot.Groups["hardware"].Index },
            new() { Type = "Software Nr.", Value = boot.Groups["version"].Value, Offset = boot.Groups["version"].Index },
            new() { Type = "Software Nr.", Value = active.Groups["software"].Value, Offset = active.Groups["software"].Index },
            new() { Type = "Software Upgrade Nr.", Value = active.Groups["upgrade"].Value, Offset = active.Groups["upgrade"].Index }
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

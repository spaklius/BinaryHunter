using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Denso;

// Mazda Denso partial and OBD-map reads expose two fixed-width Mazda software
// records in the image header and repeat the Denso project identity in code and
// calibration regions. Multiple Denso, Mazda and POSTSH725x markers make the
// profile independent of any one known software number or the source filename.
internal sealed class DensoMazdaSh725xDetector : IEcuDetectionModule
{
    private const int PartialImageSize = 0x1F7D00;
    private const int ObdImageSize = 0x200000;

    private static readonly Regex MazdaSoftwarePattern = new(
        @"^[A-Z0-9]{4}-18[A-Z0-9]{3}-[A-Z]$",
        RegexOptions.Compiled);

    public string Name => "Denso Mazda SH725x partial PCM";
    public string Manufacturer => "MAZDA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var layout = DetectLayout(image.Bytes);
        if (layout is null) return [];

        var headerOffset = layout.Value.HeaderOffset;
        var softwareOffset = headerOffset + 0x20;
        var upgradeOffset = headerOffset + 0x40;
        var projectOffset = headerOffset + 0x100;

        var header = IdentifierHelpers.ReadToken(image.Bytes, headerOffset, 16);
        var software = IdentifierHelpers.ReadToken(image.Bytes, softwareOffset, 16);
        var upgrade = IdentifierHelpers.ReadToken(image.Bytes, upgradeOffset, 16);
        var project = IdentifierHelpers.ReadToken(image.Bytes, projectOffset, 12);
        if (header is null || software is null || upgrade is null || project is null ||
            !MazdaSoftwarePattern.IsMatch(software) ||
            !MazdaSoftwarePattern.IsMatch(upgrade) ||
            !header.StartsWith(software[..4], StringComparison.Ordinal) ||
            !upgrade.StartsWith(software[..4], StringComparison.Ordinal) ||
            !Regex.IsMatch(project, @"^G[A-Z0-9]{11}$"))
            return [];

        var text = image.AsciiText;
        var firstDenso = text.IndexOf("Copr.DENSO", StringComparison.OrdinalIgnoreCase);
        var secondDenso = firstDenso < 0
            ? -1
            : text.IndexOf("Copr.DENSO", firstDenso + 1, StringComparison.OrdinalIgnoreCase);
        var pcmMarker = text.IndexOf("DENSO_PCM_MEPS", StringComparison.OrdinalIgnoreCase);
        var mazdaMarker = text.IndexOf("Mazda", StringComparison.OrdinalIgnoreCase);
        var processorMarker = text.IndexOf("POSTSH725x", StringComparison.OrdinalIgnoreCase);
        var repeatedProject = text.IndexOf(project, projectOffset + project.Length, StringComparison.Ordinal);
        if (firstDenso < 0 || secondDenso < 0 || pcmMarker < 0 || mazdaMarker < 0 ||
            processorMarker < 0 || repeatedProject < 0)
            return [];

        var processorOffset = processorMarker + "POST".Length;
        return
        [
            new IdentifierMatch { Type = "Read format", Value = layout.Value.Description, Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "Mazda (raw OEM and Denso PCM evidence)", Offset = mazdaMarker },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Denso", Offset = firstDenso + 5 },
            new IdentifierMatch { Type = "ECU family", Value = "Denso PCM SH725x", Offset = processorOffset },
            new IdentifierMatch { Type = "ECU type", Value = "PCM SH725x", Offset = processorOffset },
            new IdentifierMatch { Type = "Processor", Value = "Renesas SH725x (raw POST marker)", Offset = processorOffset },
            new IdentifierMatch { Type = "Platform Nr.", Value = software[..4], Offset = headerOffset },
            new IdentifierMatch { Type = "Denso project Nr.", Value = project, Offset = projectOffset },
            new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = softwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade, Offset = upgradeOffset }
        ];
    }

    private static MazdaLayout? DetectLayout(byte[] bytes)
    {
        if (bytes.Length == PartialImageSize)
            return new MazdaLayout(0, "Partial flash image (2,063,616 bytes / 1.968 MB; base 0x00008000 of 0x00220000)");

        if (bytes.Length == ObdImageSize &&
            bytes.AsSpan(0, 0x8000).IndexOfAnyExcept((byte)0xFF) < 0)
            return new MazdaLayout(0x8000, "OBD maps image (2 MB; calibration header at 0x00008000)");

        return null;
    }

    private readonly record struct MazdaLayout(int HeaderOffset, string Description);
}

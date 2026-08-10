using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Denso;

// Volvo Denso MB279700-96XX diesel calibration reads use a 3.75 MB window of
// the SH72546 flash. The Volvo identifiers are packed BCD values rather than
// plain ASCII: hardware is mirrored near the beginning of the image, while
// software and upgrade records live in separate calibration/code regions.
// The detector validates those relationships together with independent raw
// SH72546, VED and repeated Denso copyright evidence.
internal sealed class DensoVolvoMb27970096xxDetector : IEcuDetectionModule
{
    private const int PartialImageSize = 0x3C0000;
    private const int HardwareOffset = 0xD800;
    private const int MirroredHardwareOffset = 0xDA00;
    private const int SoftwareOffset = 0x3FFE0;
    private const int UpgradeOffset = 0x3BFA80;
    private const int AsciiHardwareOffset = 0xDA00;
    private const int AsciiMirroredHardwareOffset = 0xDC00;
    private const int AsciiSoftwareOffset = 0x3BFAB0;
    private const int AsciiUpgradeOffset = 0x3BFA80;

    public string Name => "Denso Volvo MB279700-96XX SH72546";
    public string Manufacturer => "VOLVO";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != PartialImageSize) return [];

        var bytes = image.Bytes;
        var text = image.AsciiText;
        var processorOffset = text.IndexOf("R5F72546", StringComparison.Ordinal);
        var firstDenso = text.IndexOf("DENSO CORPORATION", StringComparison.OrdinalIgnoreCase);
        var secondDenso = firstDenso < 0
            ? -1
            : text.IndexOf("DENSO CORPORATION", firstDenso + 1, StringComparison.OrdinalIgnoreCase);
        if (firstDenso < 0 || secondDenso < 0)
            return [];

        VolvoIdentification identification = default;
        var hasRawProcessor = processorOffset >= 0;
        var detectedCompleteLayout = hasRawProcessor &&
            (TryDetectPackedBcdLayout(bytes, text, out identification) ||
             TryDetectAsciiLayout(bytes, text, out identification));
        if (!detectedCompleteLayout && !TryDetectObdAsciiLayout(bytes, text, out identification))
            return [];

        var identityOffset = hasRawProcessor ? processorOffset : identification.ProjectOffset;
        var matches = new List<IdentifierMatch>
        {
            new IdentifierMatch { Type = "Read format", Value = identification.ReadFormat, Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "Volvo (high confidence; Denso SH72546 structural evidence)", Offset = identification.ProjectOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Denso", Offset = firstDenso },
            new IdentifierMatch { Type = "ECU family", Value = "Denso MB279700-96XX", Offset = identityOffset },
            new IdentifierMatch { Type = "ECU type", Value = "MB279700-96XX", Offset = identityOffset },
            new IdentifierMatch
            {
                Type = "Processor",
                Value = hasRawProcessor
                    ? "Renesas SH72546 (raw processor marker)"
                    : "Renesas SH72546 (MB279700-96XX platform inference)",
                Offset = hasRawProcessor ? processorOffset + 3 : identification.ProjectOffset
            },
            new IdentifierMatch { Type = "Software Nr.", Value = identification.Software, Offset = identification.SoftwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = identification.Upgrade, Offset = identification.UpgradeOffset }
        };
        if (!string.IsNullOrEmpty(identification.Hardware))
            matches.Insert(6, new IdentifierMatch
            {
                Type = "Hardware Nr.",
                Value = identification.Hardware,
                Offset = identification.HardwareOffset
            });
        return matches;
    }

    private static bool TryDetectPackedBcdLayout(byte[] bytes, string text, out VolvoIdentification identification)
    {
        identification = default;
        var vedMarker = text.IndexOf("V2AS8WENPBL_VED_SPA", StringComparison.Ordinal);
        var volvoProject = text.IndexOf("V526_AUT_AWD", StringComparison.Ordinal);
        var platformProject = Regex.Match(text, @"H_VED_X{1,2}_X{1,2}_\d{2}[A-Z]\d{3}");
        var repeatedPlatformProject = platformProject.Success
            ? text.IndexOf(platformProject.Value, platformProject.Index + platformProject.Length, StringComparison.Ordinal)
            : -1;
        if (vedMarker < 0 || (volvoProject < 0 && repeatedPlatformProject < 0) ||
            !TryReadPackedBcd(bytes, HardwareOffset, out var hardware) ||
            !TryReadPackedBcd(bytes, MirroredHardwareOffset, out var mirroredHardware) ||
            !string.Equals(hardware, mirroredHardware, StringComparison.Ordinal) ||
            !HasHardwareRecordTail(bytes, HardwareOffset) ||
            !HasHardwareRecordTail(bytes, MirroredHardwareOffset) ||
            !bytes.AsSpan(HardwareOffset + 4, 4).SequenceEqual(bytes.AsSpan(MirroredHardwareOffset + 4, 4)) ||
            !TryReadVersionedPackedBcd(bytes, SoftwareOffset, out var software) ||
            !TryReadVersionedPackedBcd(bytes, UpgradeOffset, out var upgrade))
            return false;

        var projectOffset = volvoProject >= 0 ? volvoProject : platformProject.Index;
        identification = new VolvoIdentification(
            hardware, HardwareOffset, software, SoftwareOffset, upgrade, UpgradeOffset, projectOffset,
            "Partial flash image (3.75 MB; SH72546 calibration/code window)");
        return true;
    }

    private static bool TryDetectAsciiLayout(byte[] bytes, string text, out VolvoIdentification identification)
    {
        identification = default;
        var bootMarker = text.IndexOf("V2AS8WENPBL_VED Ver", StringComparison.Ordinal);
        var project = Regex.Match(text, @"Y\d{3}_[A-Z]{1,4}_MP(?:_|\x00)");
        var vedProject = Regex.Match(text, @"E_VED_X{1,2}_X{1,2}_\d{2}[A-Z]\d{3}");
        var repeatedVedProject = vedProject.Success
            ? text.IndexOf(vedProject.Value, vedProject.Index + vedProject.Length, StringComparison.Ordinal)
            : -1;
        if (bootMarker < 0 || !project.Success || !vedProject.Success || repeatedVedProject < 0 ||
            !TryReadAsciiDigits(bytes, AsciiHardwareOffset, 8, out var hardware) ||
            !TryReadAsciiDigits(bytes, AsciiMirroredHardwareOffset, 8, out var mirroredHardware) ||
            !string.Equals(hardware, mirroredHardware, StringComparison.Ordinal) ||
            !TryReadAsciiSoftware(bytes, AsciiSoftwareOffset, out var software) ||
            !TryReadAsciiUpgrade(bytes, AsciiUpgradeOffset, out var upgrade))
            return false;

        identification = new VolvoIdentification(
            hardware, AsciiHardwareOffset, software, AsciiSoftwareOffset,
            upgrade, AsciiUpgradeOffset, project.Index,
            "Partial flash image (3.75 MB; SH72546 calibration/code window)");
        return true;
    }

    private static bool TryDetectObdAsciiLayout(byte[] bytes, string text, out VolvoIdentification identification)
    {
        identification = default;
        if (bytes.AsSpan(0, 0x10000).IndexOfAnyExcept((byte)0xFF) >= 0)
            return false;

        var project = Regex.Match(text, @"Y\d{3}_[A-Z]{1,4}_MP(?:_|\x00)");
        var vedProject = Regex.Match(text, @"E_VED_X{1,2}_X{1,2}_\d{2}[A-Z]\d{3}");
        var repeatedVedProject = vedProject.Success
            ? text.IndexOf(vedProject.Value, vedProject.Index + vedProject.Length, StringComparison.Ordinal)
            : -1;
        var bswMarker = text.IndexOf("BSW_VED Ver.", StringComparison.Ordinal);
        if (!project.Success || !vedProject.Success || repeatedVedProject < 0 || bswMarker < 0 ||
            !TryReadAsciiSoftware(bytes, AsciiSoftwareOffset, out var software) ||
            !TryReadAsciiUpgrade(bytes, AsciiUpgradeOffset, out var upgrade))
            return false;

        identification = new VolvoIdentification(
            string.Empty, -1, software, AsciiSoftwareOffset, upgrade, AsciiUpgradeOffset,
            project.Index, "OBD calibration image (3.75 MB; boot/hardware region omitted)");
        return true;
    }

    private static bool HasHardwareRecordTail(byte[] bytes, int offset)
    {
        var padding = bytes[offset + 4];
        return padding is 0x00 or 0x20 &&
               bytes[offset + 5] == padding &&
               bytes[offset + 6] == padding &&
               bytes[offset + 7] != 0xFF;
    }

    private static bool TryReadVersionedPackedBcd(byte[] bytes, int offset, out string value)
    {
        value = string.Empty;
        if (!TryReadPackedBcd(bytes, offset, out var number) ||
            bytes[offset + 4] != 0x20 ||
            !IsUpperAscii(bytes[offset + 5]) ||
            !IsUpperAscii(bytes[offset + 6]) ||
            bytes[offset + 7] != 0xFF)
            return false;

        value = $"{number}_{Encoding.ASCII.GetString(bytes, offset + 5, 2)}";
        return true;
    }

    private static bool TryReadPackedBcd(byte[] bytes, int offset, out string value)
    {
        value = string.Empty;
        if (offset < 0 || offset + 4 > bytes.Length) return false;

        Span<char> digits = stackalloc char[8];
        for (var index = 0; index < 4; index++)
        {
            var current = bytes[offset + index];
            var high = current >> 4;
            var low = current & 0x0F;
            if (high > 9 || low > 9) return false;
            digits[index * 2] = (char)('0' + high);
            digits[index * 2 + 1] = (char)('0' + low);
        }

        value = new string(digits);
        return true;
    }

    private static bool IsUpperAscii(byte value) => value is >= (byte)'A' and <= (byte)'Z';

    private static bool TryReadAsciiDigits(byte[] bytes, int offset, int length, out string value)
    {
        value = string.Empty;
        if (offset < 0 || offset + length > bytes.Length ||
            bytes.AsSpan(offset, length).ContainsAnyExceptInRange((byte)'0', (byte)'9'))
            return false;

        value = Encoding.ASCII.GetString(bytes, offset, length);
        return true;
    }

    private static bool TryReadAsciiSoftware(byte[] bytes, int offset, out string value)
    {
        value = string.Empty;
        if (!TryReadAsciiDigits(bytes, offset, 8, out var number) ||
            bytes[offset + 8] != 0x20 || !IsUpperAscii(bytes[offset + 9]) ||
            !IsUpperAscii(bytes[offset + 10]) || bytes[offset + 11] != 0x00)
            return false;

        value = $"{number} {Encoding.ASCII.GetString(bytes, offset + 9, 2)}";
        return true;
    }

    private static bool TryReadAsciiUpgrade(byte[] bytes, int offset, out string value)
    {
        value = string.Empty;
        if (!TryReadAsciiDigits(bytes, offset, 8, out var number) ||
            !IsUpperAscii(bytes[offset + 8]) || !IsUpperAscii(bytes[offset + 9]) ||
            bytes[offset + 10] != 0x00)
            return false;

        value = $"{number}{Encoding.ASCII.GetString(bytes, offset + 8, 2)}";
        return true;
    }

    private readonly record struct VolvoIdentification(
        string Hardware,
        int HardwareOffset,
        string Software,
        int SoftwareOffset,
        string Upgrade,
        int UpgradeOffset,
        int ProjectOffset,
        string ReadFormat);
}

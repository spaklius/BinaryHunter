using System.Text.RegularExpressions;
using BinaryHunter.Core.Identification.Helpers;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// Volvo Siemens SID803A full reads expose a compact Siemens identification
// block, an MPC555 ERCOSEK runtime and a separate Volvo calibration dataset.
// All relationships are validated so the generic SID803 library marker alone
// cannot promote an unrelated 2 MB image to this profile.
internal sealed class ContinentalSiemensVolvoSid803ADetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int PartialImageSize = 0x170000;
    private const int IdentificationStart = 0x6290;
    private const int IdentificationLength = 0x40;
    private const int HardwareOffset = 0x6300;

    private static readonly Regex HardwarePattern = new(
        @"^5WS40[A-Z0-9]{3,8}(?:-[A-Z0-9])?$",
        RegexOptions.Compiled);

    private static readonly Regex RuntimePattern = new(
        @"ERCOSEK\s+V(?<version>\d+(?:\.\d+){2,3})\s+MPC555\b",
        RegexOptions.Compiled);

    private static readonly Regex VolvoDatasetPattern = new(
        @"(?<rows>(?<row>111VO\d{11})\k<row>\k<row>)[\x00\xFF]{0,32}(?<dataset>CA(?<profile>VO\d{4})\.DAT)",
        RegexOptions.Compiled);

    public string Name => "Siemens/Continental Volvo SID803A";
    public string Manufacturer => "VOLVO";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == FullImageSize) return DetectFull(image);
        if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
        return [];
    }

    private static IEnumerable<IdentifierMatch> DetectFull(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        var sidMarker = Regex.Match(text, @"SID803(?:\r?\n|\x00)", RegexOptions.IgnoreCase);
        var runtime = RuntimePattern.Match(text);
        var dataset = VolvoDatasetPattern.Match(text);
        var hardware = IdentifierHelpers.ReadToken(image.Bytes, HardwareOffset, 16);
        if (!sidMarker.Success || !runtime.Success || !dataset.Success ||
            hardware is null || !HardwarePattern.IsMatch(hardware))
            return [];

        var identificationText = text.Substring(IdentificationStart, IdentificationLength);
        var software = Regex.Match(identificationText, @"(?<![A-Z0-9])(?<software>\d{9})(?![A-Z0-9])");
        var leadingIdentifier = Regex.Match(identificationText, @"^S[A-Z0-9]{11}");
        var trailingIdentifier = Regex.Match(identificationText, @"S[A-Z0-9]{11}\s*$");
        if (!software.Success || !leadingIdentifier.Success || !trailingIdentifier.Success)
            return [];

        var softwareOffset = IdentificationStart + software.Groups["software"].Index;
        var datasetOffset = dataset.Groups["dataset"].Index;
        return
        [
            new IdentifierMatch { Type = "Read format", Value = "Full flash image (2 MB)", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "Volvo (high confidence; SID803A OEM dataset)", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = hardware.IndexOf("5WS", StringComparison.Ordinal) + HardwareOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental SID803A", Offset = sidMarker.Index },
            new IdentifierMatch { Type = "ECU type", Value = "SID803A", Offset = sidMarker.Index },
            new IdentifierMatch { Type = "Processor", Value = "Motorola MPC555 (raw ERCOSEK marker)", Offset = runtime.Value.IndexOf("MPC555", StringComparison.Ordinal) + runtime.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = hardware, Offset = HardwareOffset },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Groups["software"].Value, Offset = softwareOffset },
            new IdentifierMatch { Type = "Runtime version", Value = $"V{runtime.Groups["version"].Value}", Offset = runtime.Groups["version"].Index - 1 },
            new IdentifierMatch { Type = "Calibration dataset", Value = dataset.Groups["dataset"].Value, Offset = datasetOffset },
            new IdentifierMatch { Type = "ECU profile", Value = dataset.Groups["profile"].Value, Offset = dataset.Groups["profile"].Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> DetectPartial(EcuBinaryImage image)
    {
        var bytes = image.Bytes;
        var text = image.AsciiText;
        var sidMarker = Regex.Match(text, @"SID803(?:\r?\n|\x00)", RegexOptions.IgnoreCase);
        var runtime = RuntimePattern.Match(text);
        var dataset = VolvoDatasetPattern.Match(text);
        if (!sidMarker.Success || !runtime.Success || !dataset.Success)
            return [];

        var hardwareOffset = sidMarker.Index + 0x21F8;
        var identificationStart = hardwareOffset - 0x70;
        if (hardwareOffset < 0 || hardwareOffset + 16 > bytes.Length || identificationStart < 0)
            return [];

        var hardwareIdentification = IdentifierHelpers.ReadToken(bytes, hardwareOffset, 16);
        if (hardwareIdentification is null || !HardwarePattern.IsMatch(hardwareIdentification))
            return [];

        var identificationText = text.Substring(identificationStart, IdentificationLength);
        var versionRecord = Regex.Match(
            identificationText,
            @"(?<![A-Z0-9])(?<version>\d{9})(?![A-Z0-9])");
        var leadingIdentifier = Regex.Match(identificationText, @"^S[A-Z0-9]{11}");
        var trailingIdentifier = Regex.Match(identificationText, @"S[A-Z0-9]{11}\s*$");
        if (!versionRecord.Success || !leadingIdentifier.Success || !trailingIdentifier.Success)
            return [];

        var oemHardwareOffset = sidMarker.Index + 9;
        if (!TryReadPackedBcd(bytes, oemHardwareOffset, out var oemHardware) ||
            bytes[oemHardwareOffset + 4] != 0x20 || bytes[oemHardwareOffset + 5] != 0x20 ||
            !TryFindVersionedPackedBcd(bytes, 0x401F0, 0x90, out var upgrade, out var upgradeOffset))
            return [];

        var datasetOffset = dataset.Groups["dataset"].Index;
        var profile = dataset.Groups["profile"].Value;
        return
        [
            new IdentifierMatch { Type = "Read format", Value = "Partial flash image (1,507,328 bytes)", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "Volvo (high confidence; SID803A OEM dataset)", Offset = dataset.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental", Offset = hardwareOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental SID803A", Offset = sidMarker.Index },
            new IdentifierMatch { Type = "ECU type", Value = "SID803A", Offset = sidMarker.Index },
            new IdentifierMatch { Type = "Processor", Value = "Motorola MPC555 (raw ERCOSEK marker)", Offset = runtime.Value.IndexOf("MPC555", StringComparison.Ordinal) + runtime.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = oemHardware, Offset = oemHardwareOffset },
            new IdentifierMatch { Type = "Hardware identification", Value = hardwareIdentification, Offset = hardwareOffset },
            new IdentifierMatch { Type = "Hardware version", Value = versionRecord.Groups["version"].Value[..8], Offset = identificationStart + versionRecord.Groups["version"].Index },
            new IdentifierMatch { Type = "Software Nr.", Value = profile, Offset = dataset.Groups["profile"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade, Offset = upgradeOffset },
            new IdentifierMatch { Type = "Runtime version", Value = $"V{runtime.Groups["version"].Value}", Offset = runtime.Groups["version"].Index - 1 },
            new IdentifierMatch { Type = "Calibration dataset", Value = dataset.Groups["dataset"].Value, Offset = datasetOffset }
        ];
    }

    private static bool TryFindVersionedPackedBcd(
        byte[] bytes,
        int start,
        int length,
        out string value,
        out int offset)
    {
        value = string.Empty;
        offset = -1;
        var end = Math.Min(bytes.Length - 8, start + length);
        for (var candidate = start; candidate <= end; candidate++)
        {
            if (!TryReadPackedBcd(bytes, candidate, out var number) ||
                bytes[candidate + 4] != 0x20 ||
                bytes[candidate + 5] is < (byte)'A' or > (byte)'Z' ||
                bytes[candidate + 6] is < (byte)'A' or > (byte)'Z' ||
                bytes[candidate + 7] != 0xFF)
                continue;

            value = $"{number} {new string([(char)bytes[candidate + 5], (char)bytes[candidate + 6]])}";
            offset = candidate;
            return true;
        }
        return false;
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
}

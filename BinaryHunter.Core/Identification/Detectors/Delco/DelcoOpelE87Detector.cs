using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Delco;

// Opel/Vauxhall Delco E87 images use repeated 20 03 50 identification records.
// The active upgrade/software pair is separated by one of two stable layout
// distances across partial and full reads. An E87-style Gxxxxx version, the
// paired records and either Delphi runtime copyright or a dense ID block are required.
internal sealed class DelcoOpelE87Detector : IEcuDetectionModule
{
    private const int PartialObdImageSize = 0xA0000;
    private const int LargePartialImageSize = 0x1F0000;
    private const int FullImageSize = 0x200000;
    private const int HardwareOffset = 0xFDB0;
    private const int ForwardSoftwareDistance = 0x90000;
    private const int ForwardUpgradeDistance = 0x1B0000;
    private const string DelphiCopyright = "Delphi Technologies, Inc.";

    private static readonly Regex VersionPattern = new(
        @"(?<![A-Z0-9])G\d{5}(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Delco Opel/Vauxhall E87";
    public string Manufacturer => "OPEL / VAUXHALL / GM";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var bytes = image.Bytes;
        if (bytes.Length is not (PartialObdImageSize or LargePartialImageSize or FullImageSize))
            return [];

        var copyrightOffset = image.AsciiText.IndexOf(DelphiCopyright, StringComparison.OrdinalIgnoreCase);
        var version = VersionPattern.Match(image.AsciiText);
        var records = FindIdentificationRecords(bytes);
        var layout = DetectLayout(records);
        if (!version.Success || layout is null || (copyrightOffset < 0 && records.Count < 4))
            return [];

        var manufacturerEvidenceOffset = copyrightOffset >= 0
            ? copyrightOffset
            : layout.Value.Upgrade.HeaderOffset;

        List<IdentifierMatch> matches =
        [
            new IdentifierMatch { Type = "Read format", Value = GetReadFormat(bytes.Length), Offset = layout.Value.Upgrade.HeaderOffset },
            new IdentifierMatch { Type = "Vehicle group", Value = "General Motors / Opel", Offset = layout.Value.Upgrade.ValueOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Delco", Offset = manufacturerEvidenceOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Delco E87", Offset = layout.Value.Upgrade.HeaderOffset },
            new IdentifierMatch { Type = "ECU type", Value = "E87", Offset = layout.Value.Upgrade.HeaderOffset },
            new IdentifierMatch { Type = "Software Nr.", Value = layout.Value.Software.Value, Offset = layout.Value.Software.ValueOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = layout.Value.Upgrade.Value, Offset = layout.Value.Upgrade.ValueOffset },
            new IdentifierMatch { Type = "Software version", Value = version.Value, Offset = version.Index }
        ];

        var hardware = ReadFixedNumericId(bytes, HardwareOffset);
        if (hardware is not null)
            matches.Insert(5, new IdentifierMatch { Type = "Hardware Nr.", Value = hardware, Offset = HardwareOffset });
        return matches;
    }

    private static E87Layout? DetectLayout(IReadOnlyList<IdentificationRecord> records)
    {
        foreach (var record in records)
        {
            var forwardSoftware = records.FirstOrDefault(candidate =>
                candidate.HeaderOffset == record.HeaderOffset + ForwardSoftwareDistance);
            if (forwardSoftware is not null)
                return new E87Layout(record, forwardSoftware);

            var forwardUpgrade = records.FirstOrDefault(candidate =>
                candidate.HeaderOffset == record.HeaderOffset + ForwardUpgradeDistance);
            if (forwardUpgrade is not null)
                return new E87Layout(forwardUpgrade, record);
        }

        return null;
    }

    private static List<IdentificationRecord> FindIdentificationRecords(byte[] bytes)
    {
        var records = new List<IdentificationRecord>();
        for (var offset = 0; offset <= bytes.Length - 24; offset++)
        {
            if (bytes[offset + 4] != 0x20 || bytes[offset + 5] != 0x03 || bytes[offset + 6] != 0x50 ||
                bytes[offset + 9] != 0x41 || bytes[offset + 10] is < 0x41 or > 0x46 ||
                bytes[offset + 11] != 0xFF || bytes[offset + 12] != 0xFF ||
                bytes[offset + 13] != 0 || bytes[offset + 14] != 0 || bytes[offset + 15] != 0)
                continue;

            var value = Encoding.ASCII.GetString(bytes, offset + 16, 8);
            if (value.StartsWith("555", StringComparison.Ordinal) && value.All(char.IsDigit))
                records.Add(new IdentificationRecord(offset, offset + 16, value));
        }

        return records;
    }

    private static string? ReadFixedNumericId(byte[] bytes, int offset)
    {
        if (offset < 0 || offset + 8 > bytes.Length) return null;
        var value = Encoding.ASCII.GetString(bytes, offset, 8);
        return value.StartsWith("555", StringComparison.Ordinal) && value.All(char.IsDigit) ? value : null;
    }

    private static string GetReadFormat(int imageSize) => imageSize switch
    {
        PartialObdImageSize => "Partial calibration image (OBD protocol, 655360 bytes; base 0x00030000)",
        LargePartialImageSize => "Partial flash image (2031616 bytes)",
        FullImageSize => "Full flash image (2 MB)",
        _ => "Binary image"
    };

    private sealed record IdentificationRecord(int HeaderOffset, int ValueOffset, string Value);
    private readonly record struct E87Layout(IdentificationRecord Upgrade, IdentificationRecord Software);
}
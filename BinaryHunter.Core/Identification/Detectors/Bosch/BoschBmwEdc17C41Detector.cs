using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW EDC17C41 readouts come in two layouts:
//
// 1. DDE-tagged layout: the active software record sits at a fixed offset
//    (0x1001A) marked by a 0x08 record type, often alongside a DDE701/721
//    ASCII banner and TC1766 processor marker.
//
// 2. Platform-path / BCD layout: no DDE marker. The platform path banner
//    `32/1/EDC17_C41/...` and the `ME(D)/EDC17 SB_V10.00.00/1797` processor
//    marker identify the family. Customer software / upgrade / spare numbers
//    are stored as repeated BCD records (`00 00 08 <4 BCD bytes>`) beside the
//    Bosch 1037xxxxxx software records, and the hardware number is a Bosch
//    0281xxxxxx part number.
internal sealed class BoschBmwEdc17C41Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;
    private const int SoftwareOffset = 0x1001A;
    private const int UpgradeOffset = 0x10122;

    // Platform path banner (may use underscore: EDC17_C41)
    private static readonly Regex PlatformPathPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC17_?C41)/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DdePattern = new(
        @"(?<![A-Z0-9])DDE(701|721)[A-Z]?(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Processor marker: TC1766 (DDE layout) or TC1797 (platform-path layout)
    private static readonly Regex ProcessorPattern = new(
        @"EDC17\s+SB_[^\x00]{0,48}/(?<processor>1766|1797)(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Bosch hardware part number (0281xxxxxx)
    private static readonly Regex HardwarePattern = new(
        @"(?<![A-Z0-9])(?:0281\d{6}|0261\d{6})(?![A-Z0-9])",
        RegexOptions.Compiled);

    // BMW OEM hardware identification code (e.g. O_7CWCUE223A or
    // O_7DPA-00000500-052 embedded in #DME__DDE721b# marker context)
    private static readonly Regex OemHardwareIdPattern = new(
        @"(?<![A-Z0-9])O_[A-Z0-9-]{8,20}(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex EngineCodePattern = new(
        @"#DST#(?<engine>[A-Z0-9]+)-",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ControlUnitPattern = new(
        @"(?<![A-Z0-9])J\d{3}(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch BMW EDC17C41";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var bytes = image.Bytes;
        var ddeMarker = DdePattern.Match(image.AsciiText);
        var platform = PlatformPathPattern.Match(image.AsciiText);

        // Require at least one independent identification signal.
        if (!ddeMarker.Success && !platform.Success) return [];

        var anchorOffset = ddeMarker.Success ? ddeMarker.Index : platform.Index;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "BMW Group", Offset = anchorOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorOffset },
            new() { Type = "ECU type", Value = "EDC17C41", Offset = anchorOffset }
        };

        if (ddeMarker.Success)
            matches.Add(new IdentifierMatch { Type = "BMW system type", Value = ddeMarker.Value.ToUpperInvariant(), Offset = ddeMarker.Index });

        var processor = ProcessorPattern.Match(image.AsciiText);
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = $"Infineon TC{processor.Groups["processor"].Value}", Offset = processor.Groups["processor"].Index });

        // Extract hardware from Bosch part number (platform-path layout).
        var hardware = HardwarePattern.Match(image.AsciiText);
        if (hardware.Success)
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });

        // Extract BMW OEM hardware identification code (e.g. O_7CWCUE223A).
        var oemHardwareId = OemHardwareIdPattern.Match(image.AsciiText);
        if (oemHardwareId.Success)
            matches.Add(new IdentifierMatch { Type = "Hardware identification", Value = oemHardwareId.Value, Offset = oemHardwareId.Index });

        // DDE layout: fixed-offset software/upgrade records.
        if (ddeMarker.Success && bytes.Length > SoftwareOffset + 8 && bytes[SoftwareOffset] == 0x08)
        {
            var software = IdentifierHelpers.ReadFixedNumericId(bytes, SoftwareOffset);
            var upgrade = bytes.Length > UpgradeOffset + 8 && bytes[UpgradeOffset] == 0x08
                ? IdentifierHelpers.ReadFixedNumericId(bytes, UpgradeOffset)
                : null;
            if (software is not null)
                matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = SoftwareOffset });
            if (upgrade is not null)
                matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade, Offset = UpgradeOffset });
        }

        // Tuned DDE721b files may store the software number at a secondary offset
        // (e.g. 0x7ebd1e) as an ASCII string. The 7-byte structured identifier
        // provides the upgrade number; this secondary record provides the software.
        if (ddeMarker.Success && bytes.Length > 0x7ebd1e + 16)
        {
            var secondarySoftware = Encoding.ASCII.GetString(bytes, 0x7ebd1e, 14);
            if (Regex.IsMatch(secondarySoftware, @"^\d{14}$"))
                matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = secondarySoftware, Offset = 0x7ebd1e });
        }

        // BCD layout: extract the repeated `00 00 08 <4 BCD bytes>` records.
        var bcdIds = ExtractBcdIdentifiers(bytes);
        if (bcdIds.Software is not null)
            matches.Add(bcdIds.Software);
        if (bcdIds.Upgrade is not null)
            matches.Add(bcdIds.Upgrade);
        if (bcdIds.Spare is not null)
            matches.Add(bcdIds.Spare);

        var engineCode = EngineCodePattern.Match(image.AsciiText);
        if (engineCode.Success)
            matches.Add(new IdentifierMatch { Type = "Engine code", Value = engineCode.Groups["engine"].Value.ToUpperInvariant(), Offset = engineCode.Groups["engine"].Index });

        var controlUnit = ControlUnitPattern.Match(image.AsciiText);
        if (controlUnit.Success)
            matches.Add(new IdentifierMatch { Type = "Control unit", Value = controlUnit.Value.ToUpperInvariant(), Offset = controlUnit.Index });

        foreach (var id in ExtractStructuredIdentifiers(bytes))
            matches.Add(id);

        return matches;
    }

    // The BCD layout stores customer-facing numbers as repeated records of the
    // form `00 00 08 <3 BCD bytes>` where the 0x08 byte is the first BCD digit
    // pair (e.g. 00 00 08 57 43 51 = 08574351). The software record repeats
    // several times; the upgrade and spare records appear once each near the
    // software records. Only records in the identification block region
    // (0xFE00-0x10100) are considered to avoid false positives from random
    // binary data elsewhere in the image.
    private static (IdentifierMatch? Software, IdentifierMatch? Upgrade, IdentifierMatch? Spare) ExtractBcdIdentifiers(byte[] bytes)
    {
        const int idBlockStart = 0xFE00;
        const int idBlockEnd = 0x10100;
        var records = new List<(long Offset, string Value)>();
        for (var index = idBlockStart; index <= Math.Min(idBlockEnd, bytes.Length - 8); index++)
        {
            if (bytes[index] != 0 || bytes[index + 1] != 0 || bytes[index + 2] != 0x08) continue;
            // The 0x08 byte is the first BCD digit pair (0,8), so the full
            // 4-byte BCD value is bytes[index+2 .. index+6]. A valid record is
            // terminated by `00 00` (e.g. `00 00 08 57 43 51 00 00`).
            if (bytes[index + 6] != 0 || bytes[index + 7] != 0) continue;
            var value = bytes.AsSpan(index + 2, 4);
            if (value[0] == 0 && value[1] == 0 && value[2] == 0 && value[3] == 0) continue;
            if (!IsBcd(value)) continue;
            records.Add((index + 2L, Convert.ToHexString(value)));
        }

        if (records.Count == 0) return (null, null, null);

        // The software record is the one that repeats (or appears most often).
        var softwareGroup = records
            .GroupBy(record => record.Value)
            .OrderByDescending(group => group.Count())
            .ThenByDescending(group => group.Max(record => record.Offset))
            .First();
        var softwareRecord = softwareGroup.First();

        // Upgrade and spare are the other distinct values. The upgrade record
        // appears after the spare in the identification block, so the last
        // distinct value is the upgrade and the second-to-last is the spare.
        var others = records
            .Where(record => record.Value != softwareRecord.Value)
            .GroupBy(record => record.Value)
            .Select(group => group.OrderBy(record => record.Offset).First())
            .OrderBy(record => record.Offset)
            .ToArray();

        IdentifierMatch? upgrade = null;
        IdentifierMatch? spare = null;
        if (others.Length > 0)
            upgrade = new IdentifierMatch { Type = "Software Upgrade Nr.", Value = others[^1].Value, Offset = others[^1].Offset };
        if (others.Length > 1)
            spare = new IdentifierMatch { Type = "Spare Part Number", Value = others[^2].Value, Offset = others[^2].Offset };

        var software = new IdentifierMatch { Type = "Software Nr.", Value = softwareRecord.Value, Offset = softwareRecord.Offset };
        return (software, upgrade, spare);
    }

    private static bool IsBcd(ReadOnlySpan<byte> value)
    {
        foreach (var b in value)
        {
            if ((b >> 4) > 9 || (b & 0x0F) > 9) return false;
        }
        return true;
    }

    private static IEnumerable<IdentifierMatch> ExtractStructuredIdentifiers(byte[] bytes)
    {
        for (var index = 0; index <= bytes.Length - 18; index++)
        {
            if (bytes[index] != (byte)'D' || bytes[index + 1] != (byte)'D' || bytes[index + 2] != (byte)'E') continue;

            // DDE markers may be followed by underscores (e.g. DDE721b___)
            // which are still valid structured identifier records.
            if (index + 6 > bytes.Length) continue;
            if (!char.IsAsciiDigit((char)bytes[index + 3]) ||
                !char.IsAsciiDigit((char)bytes[index + 4]) ||
                !char.IsAsciiDigit((char)bytes[index + 5])) continue;

            var marker = index + 10;
            if (marker + 8 > bytes.Length) continue;
            if (bytes[marker + 1] != 0 || bytes[marker + 2] != 0) continue;
            var codeOffset = marker + 1;
            if (codeOffset + 7 > bytes.Length) continue;
            var code = bytes.AsSpan(codeOffset, 7);
            if (code.SequenceEqual(stackalloc byte[7])) continue;

            var type = code[2] switch
            {
                0x03 => "Hardware Nr.",
                0x05 => code[3] switch
                {
                    0x03 => "Software Nr.",
                    0x00 => "Software Upgrade Nr.",
                    _ => "Software Nr."
                },
                0x0B => "Software Upgrade Nr.",
                _ => "Software Upgrade Nr."
            };
            yield return new IdentifierMatch
            {
                Type = type,
                Value = Convert.ToHexString(code),
                Offset = codeOffset
            };
        }
    }
}
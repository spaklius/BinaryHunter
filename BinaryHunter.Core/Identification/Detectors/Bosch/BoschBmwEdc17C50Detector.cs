using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW EDC17C50/C56 readouts use DDE701a markers with a different identifier
// structure than EDC17C41. The type byte at marker+1 varies:
// - 0x06 at offset 0x1a: hardware identifier (7 bytes)
// - 0x08 at offsets 0x2001a/0x22001a/0x30001a: software/upgrade identifiers
//
// The ECU type is EDC17C50 or EDC17C56 depending on the variant.
internal sealed class BoschBmwEdc17C50Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x400000;

    private static readonly Regex DdePattern = new(
        @"(?<![A-Z0-9])DDE701[A-Z]?(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PlatformPathPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC17_?C5[06])/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"EDC17\s+SB_[^\x00]{0,48}/(?<processor>1797|1766)(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // BMW OEM hardware identification code (e.g. O_7DUW-00000A11-006)
    private static readonly Regex OemHardwareIdPattern = new(
        @"(?<![A-Z0-9])O_[A-Z0-9-]{8,20}(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex EngineCodePattern = new(
        @"#DST#(?<engine>[A-Z0-9]+)-",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ControlUnitPattern = new(
        @"(?<![A-Z0-9])J\d{3}(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch BMW EDC17C50/C56";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var bytes = image.Bytes;
        var ddeMarker = DdePattern.Match(image.AsciiText);
        var platform = PlatformPathPattern.Match(image.AsciiText);

        if (!ddeMarker.Success && !platform.Success) return [];

        var anchorOffset = ddeMarker.Success ? ddeMarker.Index : platform.Index;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Vehicle group", Value = "BMW Group", Offset = anchorOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorOffset }
        };

        // Determine ECU type from platform path or DDE context
        var ecuType = DetermineEcuType(image.AsciiText, platform);
        matches.Add(new IdentifierMatch { Type = "ECU type", Value = ecuType, Offset = anchorOffset });

        if (ddeMarker.Success)
            matches.Add(new IdentifierMatch { Type = "BMW system type", Value = ddeMarker.Value.ToUpperInvariant(), Offset = ddeMarker.Index });

        var processor = ProcessorPattern.Match(image.AsciiText);
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = $"Infineon TC{processor.Groups["processor"].Value}", Offset = processor.Groups["processor"].Index });

        // Extract OEM hardware identification code
        var oemHardwareId = OemHardwareIdPattern.Match(image.AsciiText);
        if (oemHardwareId.Success)
            matches.Add(new IdentifierMatch { Type = "Hardware identification", Value = oemHardwareId.Value, Offset = oemHardwareId.Index });

        // Extract engine code
        var engineCode = EngineCodePattern.Match(image.AsciiText);
        if (engineCode.Success)
            matches.Add(new IdentifierMatch { Type = "Engine code", Value = engineCode.Groups["engine"].Value.ToUpperInvariant(), Offset = engineCode.Groups["engine"].Index });

        // Extract control unit
        var controlUnit = ControlUnitPattern.Match(image.AsciiText);
        if (controlUnit.Success)
            matches.Add(new IdentifierMatch { Type = "Control unit", Value = controlUnit.Value.ToUpperInvariant(), Offset = controlUnit.Index });

        // Extract structured identifiers from DDE701a markers
        foreach (var id in ExtractStructuredIdentifiers(bytes))
            matches.Add(id);

        return matches;
    }

    private static string DetermineEcuType(string asciiText, Match platform)
    {
        // Search for DDE context (#C3#HWE##EDC17Cxx or #HWE##EDC17Cxx) anywhere in the binary.
        // The #C3# prefix is present in some variants but not all.
        var ddeContext = Regex.Match(asciiText, @"#C3?#HWE##(EDC17C\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        if (ddeContext.Success) return ddeContext.Groups[1].Value.ToUpperInvariant();

        // Platform path as fallback (e.g. "32/1/EDC17_C56/...") - may be generic/reused across variants
        if (platform.Success)
        {
            var type = platform.Groups["type"].Value.ToUpperInvariant();
            if (type.Contains("C50")) return "EDC17C50";
            if (type.Contains("C56")) return "EDC17C56";
        }

        return "EDC17C50"; // Default to C50 for DDE701a files
    }

    private static IEnumerable<IdentifierMatch> ExtractStructuredIdentifiers(byte[] bytes)
    {
        for (var index = 0; index <= bytes.Length - 18; index++)
        {
            if (bytes[index] != (byte)'D' || bytes[index + 1] != (byte)'D' || bytes[index + 2] != (byte)'E') continue;

            if (index + 6 > bytes.Length) continue;
            if (!char.IsAsciiDigit((char)bytes[index + 3]) ||
                !char.IsAsciiDigit((char)bytes[index + 4]) ||
                !char.IsAsciiDigit((char)bytes[index + 5])) continue;
            if (index + 6 < bytes.Length && bytes[index + 6] is >= (byte)'A' and <= (byte)'Z') { }
            else if (index + 6 < bytes.Length && bytes[index + 6] is >= (byte)'a' and <= (byte)'z') { }
            else if (index + 6 < bytes.Length && bytes[index + 6] != 0 && bytes[index + 6] != (byte)'_') continue;

            var marker = index + 10;
            if (marker + 8 > bytes.Length) continue;
            if (bytes[marker + 1] != 0 || bytes[marker + 2] != 0) continue;
            var codeOffset = marker + 1;
            if (codeOffset + 7 > bytes.Length) continue;
            var code = bytes.AsSpan(codeOffset, 7);
            if (code.SequenceEqual(stackalloc byte[7])) continue;

            // EDC17C50/C56 type classification based on type byte (index 3):
            // - 0x0A = Hardware Nr.
            // - 0x0B = Software Nr.
            // - 0x11 = Software Upgrade Nr.
            var type = code[3] switch
            {
                0x0A => "Hardware Nr.",
                0x0B => "Software Nr.",
                0x11 => "Software Upgrade Nr.",
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
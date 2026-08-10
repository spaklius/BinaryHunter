using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW EDC17CP45 and DDE731 full images expose their variant in EDC17_CP45/11/P_xxx
// banners or DDE731 engine-code headers. The layout matches the CP02/C06 family:
// repeated BCD software records, a spare/upgrade pair later in the metadata area,
// and optional VIN evidence.
internal sealed class BoschBmwEdc17Cp45Detector : IEcuDetectionModule
{
    private const int RelatedIdentifierSearchLength = 2_048;

    private static readonly Regex FamilyPattern = new(
        @"EDC17_(?<variant>CP45)/11/P_[A-Z0-9]+//[A-Z0-9]+///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DdePattern = new(
        @"DME__?(?<type>DDE731A?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"EDC17\s+SB_[^\x00]{0,48}/(?<processor>1766)(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HardwarePattern = new(
        @"(?<![A-Z0-9])0281\d{6}(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch BMW EDC17CP45";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var familyMarkers = FamilyPattern.Matches(image.AsciiText).Cast<Match>().ToArray();
        var ddeMarker = DdePattern.Match(image.AsciiText);
        var processor = ProcessorPattern.Match(image.AsciiText);

        string? rawVariant = null;
        long familyOffset = 0;
        var confirmedByBanner = familyMarkers.Length > 0;
        var confirmedByDde = false;
        if (confirmedByBanner)
        {
            rawVariant = familyMarkers[^1].Groups["variant"].Value.ToUpperInvariant();
            familyOffset = familyMarkers[^1].Index;
        }
        else if (ddeMarker.Success)
        {
            rawVariant = "CP45";
            familyOffset = ddeMarker.Index;
            confirmedByDde = true;
        }
        if (rawVariant is null) return [];

        var asciiSoftware = Regex.Match(image.AsciiText, @"1037\d{6}");
        var software = FindRepeatedBcdSoftware(image.Bytes);
        if (software is null && asciiSoftware.Success)
            software = new BcdIdentifier(asciiSoftware.Value, asciiSoftware.Index);
        var typedIdentifiers = FindTypedIdentifiers(image.Bytes, familyOffset);

        var matches = new List<IdentifierMatch>();
        var ecuType = $"EDC17{rawVariant}";
        if (image.Bytes.Length == 0x400000)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = "Full flash image (4 MB)", Offset = 0 });
        matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = familyOffset });
        matches.Add(new IdentifierMatch { Type = "ECU manufacturer", Value = $"Bosch", Offset = familyOffset });
        matches.Add(new IdentifierMatch { Type = "ECU family", Value = $"Bosch {ecuType}", Offset = familyOffset });
        matches.Add(new IdentifierMatch { Type = "ECU type", Value = ecuType, Offset = familyOffset });
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = $"Infineon TC{processor.Groups["processor"].Value}", Offset = processor.Groups["processor"].Index });
        else if (image.Bytes.Length == 0x400000)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = "Infineon TC1797 (EDC17CP45 platform inference)", Offset = familyOffset });
        if (typedIdentifiers is not null)
        {
            if (typedIdentifiers.Value.Hardware is not null)
                matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = typedIdentifiers.Value.Hardware, Offset = typedIdentifiers.Value.HardwareOffset });
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = typedIdentifiers.Value.Software, Offset = typedIdentifiers.Value.SoftwareOffset });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = typedIdentifiers.Value.Upgrade, Offset = typedIdentifiers.Value.UpgradeOffset });
            if (asciiSoftware.Success)
                matches.Add(new IdentifierMatch { Type = "Bosch software Nr.", Value = asciiSoftware.Value, Offset = asciiSoftware.Index });
        }
        else if (software is not null)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Value.Value, Offset = software.Value.Offset });
        if (confirmedByDde)
        {
            matches.Add(new IdentifierMatch { Type = "BMW system type", Value = ddeMarker.Groups["type"].Value.ToUpperInvariant(), Offset = ddeMarker.Groups["type"].Index });
        }

        var hardware = HardwarePattern.Match(image.AsciiText);
        if (typedIdentifiers is null && hardware.Success)
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });

        var related = typedIdentifiers is not null || software is null ? null : FindRelatedIdentifiers(image.Bytes, software.Value.Offset + 18);
        if (related is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Spare part number", Value = related.Value.SparePart, Offset = related.Value.Offset });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = related.Value.Upgrade, Offset = related.Value.Offset + 6 });
        }

        SplitVin? vin = IdentifierHelpers.TryFindSplitVin(image.AsciiText, software?.Offset ?? familyOffset, out var vinValue, out var vinOffset)
            ? new SplitVin(vinValue, vinOffset)
            : null;
        if (vin is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group (VIN evidence)", Offset = vin.Value.Offset });
            matches.Add(new IdentifierMatch { Type = "Vehicle manufacturer", Value = "BMW (VIN evidence)", Offset = vin.Value.Offset });
            matches.Add(new IdentifierMatch { Type = "VIN", Value = vin.Value.Value, Offset = vin.Value.Offset });
        }

        return matches;
    }

    private static BcdIdentifier? FindRepeatedBcdSoftware(byte[] bytes)
    {
        for (var index = 0; index <= bytes.Length - 16; index++)
        {
            if (!IsBcdIdentifier(bytes, index) || bytes[index] != 0x08 ||
                bytes[index + 4] != 0 || bytes[index + 5] != 0 ||
                bytes[index + 10] != 0 || bytes[index + 11] != 0)
                continue;

            var repeated = true;
            for (var byteIndex = 0; byteIndex < 4; byteIndex++)
            {
                if (bytes[index + byteIndex] == bytes[index + 6 + byteIndex] &&
                    bytes[index + byteIndex] == bytes[index + 12 + byteIndex])
                    continue;
                repeated = false;
                break;
            }

            if (repeated)
                return new BcdIdentifier(Convert.ToHexString(bytes, index, 4), index);
        }

        return null;
    }

    private static RelatedIdentifiers? FindRelatedIdentifiers(byte[] bytes, long searchStart)
    {
        var start = Math.Clamp((int)searchStart, 0, bytes.Length);
        var end = Math.Min(bytes.Length - 10, start + RelatedIdentifierSearchLength);
        for (var index = start; index <= end; index++)
        {
            if (bytes[index] != 0x08 || bytes[index + 4] != 0 || bytes[index + 5] != 0 || bytes[index + 6] != 0x08 ||
                !IsBcdIdentifier(bytes, index) || !IsBcdIdentifier(bytes, index + 6))
                continue;
            if (bytes[index] != bytes[index + 6] || bytes[index + 1] != bytes[index + 7] || bytes[index + 2] != bytes[index + 8])
                continue;

            var sparePart = Convert.ToHexString(bytes, index, 4);
            var upgrade = Convert.ToHexString(bytes, index + 6, 4);
            if (!string.Equals(sparePart, upgrade, StringComparison.Ordinal))
                return new RelatedIdentifiers(sparePart, upgrade, index);
        }

        return null;
    }

    private static TypedIdentifiers? FindTypedIdentifiers(byte[] bytes, long familyOffset)
    {
        var familyIndex = Math.Clamp((int)familyOffset, 0, bytes.Length);
        var hardwareOffset = -1;
        for (var index = Math.Max(0, familyIndex - 8_192); index <= Math.Min(familyIndex, bytes.Length - 9); index++)
        {
            if (bytes[index] == 0x02 && bytes[index + 1] == 0x06 && IsSevenByteIdentifier(bytes, index + 2))
                hardwareOffset = index + 2;
        }
        var softwareOffset = -1;
        for (var index = familyIndex; index <= bytes.Length - 10; index++)
        {
            if (bytes[index] == 0x01 && bytes[index + 1] == 0x08 &&
                IsSevenByteIdentifier(bytes, index + 2) && bytes[index + 9] == (byte)'#')
                softwareOffset = index + 2;
        }
        if (softwareOffset < 0) return null;

        var upgradeOffset = -1;
        for (var index = softwareOffset - 2; index >= Math.Max(0, softwareOffset - 512); index--)
        {
            if (bytes[index] is not (0x08 or 0x0D) || !IsSevenByteIdentifier(bytes, index + 1))
                continue;
            if (bytes.AsSpan(index + 1, 7).SequenceEqual(bytes.AsSpan(softwareOffset, 7)))
                continue;
            upgradeOffset = index + 1;
            break;
        }
        if (upgradeOffset < 0) return null;

        return new TypedIdentifiers(
            hardwareOffset >= 0 ? Convert.ToHexString(bytes, hardwareOffset, 7) : null, hardwareOffset,
            Convert.ToHexString(bytes, softwareOffset, 7), softwareOffset,
            Convert.ToHexString(bytes, upgradeOffset, 7), upgradeOffset);
    }

    private static bool IsSevenByteIdentifier(byte[] bytes, int offset)
    {
        if (offset < 0 || offset + 7 > bytes.Length || bytes[offset] != 0 || bytes[offset + 1] != 0)
            return false;
        for (var index = 2; index < 7; index++)
        {
            if (bytes[offset + index] != 0) return true;
        }
        return false;
    }
    private static bool IsBcdIdentifier(byte[] bytes, int offset)
    {
        if (offset < 0 || offset + 4 > bytes.Length) return false;
        for (var index = 0; index < 4; index++)
        {
            var value = bytes[offset + index];
            if ((value >> 4) > 9 || (value & 0x0F) > 9) return false;
        }

        return true;
    }

    private readonly record struct TypedIdentifiers(string? Hardware, long HardwareOffset, string Software, long SoftwareOffset, string Upgrade, long UpgradeOffset);
    private readonly record struct BcdIdentifier(string Value, long Offset);
    private readonly record struct RelatedIdentifiers(string SparePart, string Upgrade, long Offset);
    private readonly record struct SplitVin(string Value, long Offset);
}

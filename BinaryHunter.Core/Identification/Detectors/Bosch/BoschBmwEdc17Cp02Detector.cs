using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW EDC17CP02/C06 and DDE70/DDE71 images identify the exact variant in
// CP02/11/P_xxx, C06/11/P_xxx banners, or DDE70/DDE71 engine-code headers.
// Their user-facing BMW identifiers are packed BCD records rather than ASCII:
// software is repeated three times and the spare/upgrade pair is stored later
// in the same metadata area.
internal sealed class BoschBmwEdc17Cp02Detector : IEcuDetectionModule
{
    private const int RelatedIdentifierSearchLength = 2_048;
    private const int PartialCalibrationImageSize = 0x42000;

    private static readonly Regex FamilyPattern = new(
        @"(?<![A-Z0-9])EDC17_(?<variant>CP02|C06)/11/P_[A-Z0-9]+//[A-Z0-9]+///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DdePattern = new(
        @"(?<![A-Z0-9])DDE(?<code>70|71)(?![A-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"EDC17\s+SB_[^\x00]{0,48}/(?<processor>1766)(?!\d)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HardwarePattern = new(
        @"(?<![A-Z0-9])0281\d{6}(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex CalibrationHeaderPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]{6,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Bosch BMW EDC17CP02/C06";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var familyMarkers = FamilyPattern.Matches(image.AsciiText).Cast<Match>().ToArray();
        var ddeMarker = DdePattern.Match(image.AsciiText);
        var processor = ProcessorPattern.Match(image.AsciiText);
        var headerLength = Math.Min(512, image.Bytes.Length);
        var calibrationHeader = CalibrationHeaderPattern.Match(image.AsciiText, 0, headerLength);

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
            var ddeCode = ddeMarker.Groups["code"].Value;
            rawVariant = ddeCode == "70" ? "C06" : "CP02";
            familyOffset = ddeMarker.Index;
            confirmedByDde = true;
        }
        if (rawVariant is null) return [];

        var isFullImage = (confirmedByBanner ? familyMarkers.Length >= 2 : true) && processor.Success;
        var isPartialCalibrationImage = image.Bytes.Length == PartialCalibrationImageSize &&
                                        (confirmedByBanner || confirmedByDde) &&
                                        (confirmedByBanner ? familyMarkers[0].Index < 1_024 : true) &&
                                        calibrationHeader.Success;
        if (!isFullImage && !isPartialCalibrationImage) return [];

        var software = isFullImage ? FindRepeatedBcdSoftware(image.Bytes) : null;
        if (isFullImage && software is null) return [];

        var matches = new List<IdentifierMatch>();
        var ecuType = rawVariant == "CP02" ? "EDC17CP02" : "EDC17C06";
        matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = $"BMW Group", Offset = familyOffset });
        matches.Add(new IdentifierMatch { Type = "ECU manufacturer", Value = $"Bosch", Offset = familyOffset });
        matches.Add(new IdentifierMatch { Type = "ECU family", Value = $"Bosch {ecuType}", Offset = familyOffset });
        matches.Add(new IdentifierMatch { Type = "ECU type", Value = ecuType, Offset = familyOffset });
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = $"Infineon TC{processor.Groups["processor"].Value}", Offset = processor.Groups["processor"].Index });
        if (confirmedByDde)
        {
            matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = familyOffset });
            matches.Add(new IdentifierMatch { Type = "BMW system type", Value = $"DDE{ddeMarker.Groups["code"].Value}", Offset = familyOffset });
        }

        if (software is not null)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Value.Value, Offset = software.Value.Offset });
        else
        {
            matches.Add(new IdentifierMatch { Type = "Read format", Value = $"Partial calibration image ({image.DisplaySize})", Offset = 0 });
            matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = $"BMW Group ({ecuType} calibration structure)", Offset = familyOffset });
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = calibrationHeader.Groups["software"].Value, Offset = calibrationHeader.Groups["software"].Index });
            matches.Add(new IdentifierMatch { Type = "Calibration version", Value = calibrationHeader.Groups["version"].Value, Offset = calibrationHeader.Groups["version"].Index });
        }

        var hardware = HardwarePattern.Match(image.AsciiText);
        if (hardware.Success)
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });

        var related = software is null ? null : FindRelatedIdentifiers(image.Bytes, software.Value.Offset + 18);
        if (related is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Spare part number", Value = related.Value.SparePart, Offset = related.Value.Offset });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = related.Value.Upgrade, Offset = related.Value.Offset + 6 });
        }

        var vin = software is null ? null : (SplitVin?)(IdentifierHelpers.TryFindSplitVin(image.AsciiText, software.Value.Offset, out var vinValue, out var vinOffset)
            ? new SplitVin(vinValue, vinOffset)
            : null);
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

    private readonly record struct BcdIdentifier(string Value, long Offset);
    private readonly record struct RelatedIdentifiers(string SparePart, string Upgrade, long Offset);
    private readonly record struct SplitVin(string Value, long Offset);
}

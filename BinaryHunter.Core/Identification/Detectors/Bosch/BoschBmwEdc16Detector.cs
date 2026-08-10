using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Handles full and partial reads of the Bosch BMW EDC16C35/CP35 family.
//
// Variant coverage
// ----------------
// Sparse virtual image (existing path)
//   * Exactly 2 MiB
//   * Mostly-FF virtual image; real data concentrated in 0x0C0000–0x0FFFF0
//   * Identified by calibration header + EDC16C31/999/ library marker
//
// Full flash — size-known (fixed-offset path)
//   * Exactly 2 MiB   — calibration at 0xC0A30
//   * Exactly 1,941,568 bytes (0x1E8000)
//   * Identified by calibration header at known offset + "BOSCH EDC16C35/C" anchor
//
// Partial read (search-based fallback)
//   * Any size below the known full-read sizes that still carries the ECU markers
//   * Searches the full ASCII text for the anchor string, then looks backward
//     for the calibration header to locate the Software ID and version without
//     relying on a hard-coded offset.
//
// All paths emit the same ECU family/type so that full and partial reads of
// the same ECU are classified consistently regardless of file size.
internal sealed class BoschBmwEdc16Detector : IEcuDetectionModule
{
    private const int VirtualImageSize = 0x200000;
    private const int CalibrationStart = 0x0C0000;
    private const int MinimumCalibrationEnd = 0x0F0000;
    private const int MaximumCalibrationEnd = 0x100000;

    private static readonly Regex CalibrationHeaderPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]*[A-Z][A-Z0-9]*)(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex SharedLibraryMarkerPattern = new(
        @"(?<![A-Z0-9])EDC16C31/999/",
        RegexOptions.Compiled);

    private static readonly Regex AnchorPattern = new(
        @"BOSCH\s+EDC16C3[56]/C\s+\(BMW\)\s+MPC563/Rev[^[]+\[F_PA_P_316_GrO\.\d+\.\d+\]",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex PartialKeywordPattern = new(
        @"(?:EDC16C3[56]|MPC563|F_PA_P_316_GrO\.\d+\.\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex VolvoSoftwarePattern = new(
        @"(?<![A-Z0-9])1037\d{6}(?=P(?:323|441)|[^A-Z0-9]|$)",
        RegexOptions.Compiled);

    private static readonly Regex VolvoCalibrationPattern = new(
        @"(?<![A-Z0-9])P(?:323|441)[A-Z0-9]+(?![A-Z0-9])",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static bool HasVolvoSoftware(EcuBinaryImage image)
    {
        if (Regex.IsMatch(image.AsciiText,
            @"(?<![A-Z0-9])1037\d{6}P(?:323|441)[A-Z0-9]+",
            RegexOptions.IgnoreCase))
            return true;

        var swMatches = VolvoSoftwarePattern.Matches(image.AsciiText);
        if (swMatches.Count == 0) return false;

        var calibrationMatches = VolvoCalibrationPattern.Matches(image.AsciiText);
        if (calibrationMatches.Count == 0) return false;

        foreach (Match sw in swMatches)
        {
            foreach (Match cal in calibrationMatches)
            {
                if (Math.Abs(sw.Index - cal.Index) < 0x200)
                    return true;
            }
        }

        return false;
    }

    public string Name => "Bosch BMW EDC16C35/CP35 full + partial";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (HasVolvoSoftware(image)) return [];

        // Skip Mercedes-Benz EDC16CP31 images — they share the 2 MB size and
        // 1037xxxxxx software number format but have a distinct platform marker.
        if (Regex.IsMatch(image.AsciiText, @"EDC16CP31[-.]?\d", RegexOptions.IgnoreCase))
            return [];

        // Skip VAG EDC16CP34 images — they share the 2 MB size and 1037xxxxxx
        // software number format but have a distinct platform marker.
        if (Regex.IsMatch(image.AsciiText, @"EDC16CP34[-.]?\d", RegexOptions.IgnoreCase))
            return [];

        // Skip Mercedes-Benz EDC16CP36 images — they share the 2 MB size and
        // 1037xxxxxx software number format but have a distinct platform marker.
        if (Regex.IsMatch(image.AsciiText, @"EDC16CP36[-.]?\d", RegexOptions.IgnoreCase))
            return [];

        // Renault/Nissan/Opel EDC16CP33 images share the 2 MB size and Bosch
        // software header but expose their own validated platform path.
        if (Regex.IsMatch(image.AsciiText, @"\d{2,3}/1/EDC16(?:CP33|C36|C41)/", RegexOptions.IgnoreCase))
            return [];

        // Skip VAG EDC16U31/U34 images — they share the 2 MB size and 1037xxxxxx
        // software number format but have a distinct platform marker / OEM block.
        if (Regex.IsMatch(image.AsciiText, @"EDC16U34[-.]?\d", RegexOptions.IgnoreCase))
            return [];

        // Skip VAG EDC16U31/U34 images without platform marker — identified by
        // the compact OEM block: 10-char hardware, VAG part number, revision,
        // R4 x,xL EDC engine.
        if (Regex.IsMatch(image.AsciiText,
            @"[A-Z0-9]{10,11}[ \x00]+0[A-Z0-9]{8,10}[ \x00]+\d{4}[ \x00]+R4\s+\d[,.]\dL\s+EDC",
            RegexOptions.IgnoreCase))
            return [];

        var bytes = image.Bytes;
        var length = bytes.Length;

        if (length == VirtualImageSize && TryGetNonErasedRange(bytes, out var firstDataOffset, out var lastDataOffset))
        {
            if (firstDataOffset == CalibrationStart && lastDataOffset >= MinimumCalibrationEnd && lastDataOffset < MaximumCalibrationEnd)
            {
                var sparse = DetectSparseCalibration(image, bytes, firstDataOffset, lastDataOffset);
                if (sparse.Any()) return sparse;
                return DetectFullFlashCalibration(image, bytes, firstDataOffset);
            }

            return DetectFullFlashCalibration(image, bytes, firstDataOffset);
        }

        if (length == 0x1F0040)
            return DetectFullFlash(image, bytes, calibrationOffset: 0xB0010);

        return DetectPartialRead(image, bytes);
    }

    private static IEnumerable<IdentifierMatch> DetectSparseCalibration(
        EcuBinaryImage image, byte[] bytes, int firstDataOffset, int lastDataOffset)
    {
        var headerLength = Math.Min(512, lastDataOffset - firstDataOffset + 1);
        var headerText = Encoding.ASCII.GetString(bytes, firstDataOffset, headerLength);
        var header = CalibrationHeaderPattern.Match(headerText);
        var libraryMarker = SharedLibraryMarkerPattern.Match(image.AsciiText, firstDataOffset);
        if (!header.Success || !libraryMarker.Success || libraryMarker.Index > lastDataOffset) return [];

        return
        [
            new IdentifierMatch { Type = "Read format", Value = "Sparse calibration-only (virtual 2 MB image)", Offset = firstDataOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch (sparse EDC16 calibration evidence)", Offset = libraryMarker.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C35", Offset = libraryMarker.Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C35", Offset = libraryMarker.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = firstDataOffset + header.Groups["software"].Index },
            new IdentifierMatch { Type = "Calibration version", Value = header.Groups["version"].Value, Offset = firstDataOffset + header.Groups["version"].Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> DetectFullFlash(EcuBinaryImage image, byte[] bytes, int calibrationOffset)
    {
        if (calibrationOffset + 64 > bytes.Length) return [];

        var headerWindow = Encoding.ASCII.GetString(bytes, calibrationOffset, 64);
        var header = CalibrationHeaderPattern.Match(headerWindow);
        if (!header.Success) return [];

        var readFormat = calibrationOffset switch
        {
            0xC0A30 => "Full flash image (2 MB)",
            0xB0010 => "Full flash image (~1.94 MB, OBD protocol)",
            _ => "Full flash image"
        };

        return
        [
            new IdentifierMatch { Type = "Read format", Value = readFormat, Offset = calibrationOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch (EDC16C35 full-flash evidence)", Offset = calibrationOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C35", Offset = calibrationOffset },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C35", Offset = calibrationOffset },
            new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = calibrationOffset + header.Groups["software"].Index },
            new IdentifierMatch { Type = "Calibration version", Value = header.Groups["version"].Value, Offset = calibrationOffset + header.Groups["version"].Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> DetectPartialRead(EcuBinaryImage image, byte[] bytes)
    {
        var anchor = AnchorPattern.Match(image.AsciiText);
        if (!anchor.Success && !PartialKeywordPattern.IsMatch(image.AsciiText)) return [];

        var windowRadius = 8192;
        var anchorIndex = anchor.Success
            ? anchor.Index
            : 0;
        var bpStart = Math.Max(0, anchorIndex - windowRadius);
        var bpEnd = anchor.Success
            ? Math.Min(image.AsciiText.Length, anchorIndex + windowRadius)
            : Math.Min(image.AsciiText.Length, 65536);
        var searchWindow = image.AsciiText.Substring(bpStart, bpEnd - bpStart);

        var header = CalibrationHeaderPattern.Matches(searchWindow)
            .Cast<Match>()
            .OrderBy(match => match.Index)
            .FirstOrDefault();
        var headerOffset = header is null ? 0 : bpStart + header.Index;

        var matches = new List<IdentifierMatch>
        {
            new IdentifierMatch { Type = "Read format", Value = "Partial calibration image", Offset = headerOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = anchorIndex },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C35", Offset = anchorIndex },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C35", Offset = anchorIndex },
            new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = anchorIndex }
        };

        if (header is not null)
        {
            matches.AddRange(new[]
            {
                new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = headerOffset + header.Groups["software"].Index },
                new IdentifierMatch { Type = "Calibration version", Value = header.Groups["version"].Value, Offset = headerOffset + header.Groups["version"].Index }
            });
        }

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectFullFlashCalibration(EcuBinaryImage image, byte[] bytes, int firstDataOffset)
    {
        var header = CalibrationHeaderPattern.Match(image.AsciiText, firstDataOffset);
        if (!header.Success) return [];

        return
        [
            new IdentifierMatch { Type = "Read format", Value = "Full flash image (2 MB)", Offset = firstDataOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch (EDC16C35 full-flash evidence)", Offset = firstDataOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C35", Offset = firstDataOffset },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C35", Offset = firstDataOffset },
            new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = firstDataOffset },
            new IdentifierMatch { Type = "Software Nr.", Value = header.Groups["software"].Value, Offset = header.Groups["software"].Index },
            new IdentifierMatch { Type = "Calibration version", Value = header.Groups["version"].Value, Offset = header.Groups["version"].Index }
        ];
    }

    private static bool TryGetNonErasedRange(byte[] bytes, out int firstDataOffset, out int lastDataOffset)
    {
        firstDataOffset = Array.FindIndex(bytes, value => value != 0xFF);
        lastDataOffset = Array.FindLastIndex(bytes, value => value != 0xFF);
        return firstDataOffset >= 0 && lastDataOffset >= firstDataOffset;
    }
}

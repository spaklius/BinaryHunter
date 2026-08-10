using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Siemens;

// Siemens/Continental BMW MSV, MSS and MSD images use BCD metadata blocks rather
// than printable part numbers. This module keeps that family-specific layout out
// of the common identification pipeline.
internal sealed class SiemensBmwDetector : IEcuDetectionModule
{
    public string Name => "Siemens BMW MSV/MSS/MSD";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image) =>
        DetectMsvMss70Structure(image)
            .Concat(DetectMsvMss70Identifiers(image))
            .Concat(DetectMsvMsd80Structure(image))
            .Concat(DetectMsv80Identifiers(image));

    private static IEnumerable<IdentifierMatch> DetectMsvMsd80Structure(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        var runtime = Regex.Match(text, @"\bERCOSEK\s+V4\.3\.\d+\s+TriCore\b", RegexOptions.IgnoreCase);
        if (!IsSiemensTriCoreCandidate(text) || !runtime.Success) return [];

        var exactMsdFamily = Regex.Match(text, @"MSD8[01](?=_{2,})", RegexOptions.IgnoreCase);
        if (exactMsdFamily.Success)
        {
            var family = exactMsdFamily.Value.ToUpperInvariant();
            var matches = new List<IdentifierMatch>
            {
                new() { Type = "ECU manufacturer", Value = "Siemens/Continental (structural inference)", Offset = exactMsdFamily.Index },
                new() { Type = "ECU family", Value = $"Siemens/Continental {family}", Offset = exactMsdFamily.Index },
                new() { Type = "ECU type", Value = family, Offset = exactMsdFamily.Index },
                new() { Type = "Processor", Value = "Infineon TriCore (raw runtime marker)", Offset = runtime.Index }
            };
            var bmw = Regex.Match(text, @"(?<![A-Z0-9])BMW(?![A-Z0-9])", RegexOptions.IgnoreCase);
            if (bmw.Success)
                matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = bmw.Index });
            return matches;
        }

        var reference = Regex.Match(text, @"(?<![A-Z0-9])5WK9\d{4}(?![A-Z0-9])", RegexOptions.IgnoreCase);
        if (reference.Success)
        {
            return
            [
                new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = reference.Index },
                new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental (structural inference)", Offset = reference.Index },
                new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental MSV80/MSD80 family", Offset = runtime.Index },
                new IdentifierMatch { Type = "ECU type", Value = "MSV80/MSD80 family", Offset = runtime.Index },
                new IdentifierMatch { Type = "Processor", Value = "Infineon TriCore (raw runtime marker)", Offset = runtime.Index },
                new IdentifierMatch { Type = "Siemens reference", Value = reference.Value, Offset = reference.Index }
            ];
        }

        if (image.Bytes.Length != 2_097_152) return [];
        return
        [
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental MSV/MSD80 family", Offset = runtime.Index },
            new IdentifierMatch { Type = "ECU type", Value = "MSV/MSD80 family", Offset = runtime.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental (structural inference)", Offset = runtime.Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon TriCore", Offset = runtime.Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> DetectMsvMss70Structure(EcuBinaryImage image)
    {
        if (image.Bytes.Length != 2_097_152) return [];
        var reference = Regex.Match(image.AsciiText, @"(?<![A-Z0-9])5WK9\d{4}(?![A-Z0-9])", RegexOptions.IgnoreCase);
        if (!reference.Success) return [];

        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = reference.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Siemens/Continental (structural inference)", Offset = reference.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Siemens/Continental MSV/MSS70 family", Offset = reference.Index },
            new IdentifierMatch { Type = "ECU type", Value = "MSV/MSS70 family", Offset = reference.Index },
            new IdentifierMatch { Type = "Processor", Value = "Freescale MPC5xx (structural inference)", Offset = reference.Index },
            new IdentifierMatch { Type = "Siemens reference", Value = reference.Value, Offset = reference.Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> DetectMsvMss70Identifiers(EcuBinaryImage image)
    {
        var bytes = image.Bytes;
        if (bytes.Length != 2_097_152 || !HasSiemensReference(image.AsciiText)) return [];

        var softwarePairs = new List<(string Upgrade, string Software, long UpgradeOffset, long SoftwareOffset)>();
        var repeatedHardware = new List<(string Value, long Offset)>();
        for (var index = 0; index <= bytes.Length - 18; index++)
        {
            if (!TryReadBcdIdentifier(bytes, index, out var first) ||
                !TryReadBcdIdentifier(bytes, index + 6, out var second) ||
                !TryReadBcdIdentifier(bytes, index + 12, out var third)) continue;

            if (IsMss70SoftwarePair(first, second, third) && HasBcdHeaderContext(bytes, index, recordCount: 3))
                softwarePairs.Add((first, second, index + 2L, index + 8L));

            if (string.Equals(first, second, StringComparison.Ordinal) && string.Equals(second, third, StringComparison.Ordinal))
                repeatedHardware.Add((first, index + 2L));
        }

        var matches = new List<IdentifierMatch>();
        var softwarePair = softwarePairs
            .GroupBy(pair => (pair.Upgrade, pair.Software))
            .OrderByDescending(group => group.Count())
            .ThenByDescending(group => group.Max(pair => pair.UpgradeOffset))
            .FirstOrDefault();
        if (softwarePair is not null)
        {
            var selected = softwarePair.OrderByDescending(pair => pair.UpgradeOffset).First();
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = selected.Software, Offset = selected.SoftwareOffset });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = selected.Upgrade, Offset = selected.UpgradeOffset });
        }

        var hardware = softwarePair is null ? null : repeatedHardware
            .Where(entry => entry.Value.StartsWith(softwarePair.Key.Upgrade[..3], StringComparison.Ordinal))
            .GroupBy(entry => entry.Value)
            .OrderByDescending(group => group.Count())
            .ThenByDescending(group => group.Max(entry => entry.Offset))
            .FirstOrDefault();
        if (hardware is not null)
        {
            var selected = hardware.OrderByDescending(entry => entry.Offset).First();
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = selected.Value, Offset = selected.Offset });
        }

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectMsv80Identifiers(EcuBinaryImage image)
    {
        var bytes = image.Bytes;
        if (!IsSiemensTriCoreCandidate(image.AsciiText)) return [];

        var softwareCandidates = new List<(string Value, long Offset)>();
        var repeatedHardware = new List<(string Value, long Offset)>();
        for (var index = 0; index <= bytes.Length - 18; index++)
        {
            if (!TryReadBcdIdentifier(bytes, index, out var first) || !TryReadBcdIdentifier(bytes, index + 6, out var second)) continue;

            if (!string.Equals(first, second, StringComparison.Ordinal) &&
                string.Equals(first[..7], second[..7], StringComparison.Ordinal) &&
                HasBcdHeaderContext(bytes, index, recordCount: 2))
                softwareCandidates.Add((first, index + 2L));

            if (TryReadBcdIdentifier(bytes, index + 12, out var third) &&
                string.Equals(first, second, StringComparison.Ordinal) && string.Equals(second, third, StringComparison.Ordinal))
                repeatedHardware.Add((first, index + 2L));
        }

        var software = softwareCandidates.GroupBy(candidate => candidate.Value)
            .OrderByDescending(group => group.Count())
            .ThenByDescending(group => group.Max(candidate => candidate.Offset))
            .FirstOrDefault();

        var matches = new List<IdentifierMatch>();
        if (software is not null)
        {
            var selectedSoftware = software.OrderByDescending(candidate => candidate.Offset).First();
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = selectedSoftware.Value, Offset = selectedSoftware.Offset });
        }

        // Hardware must originate from the labelled Siemens metadata block. A
        // matching numeric prefix is not enough: calibration areas may contain
        // repeated BCD values such as 075xxxxxx without any ECU-ID context.
        var hardware = repeatedHardware
            .Where(candidate => HasPrintableAsciiRun(
                bytes,
                Math.Max(0, (int)candidate.Offset - 66),
                (int)candidate.Offset - 2,
                minimumRun: 6))
            .GroupBy(candidate => candidate.Value)
            .OrderByDescending(group => group.Count())
            .ThenByDescending(group => group.Max(candidate => candidate.Offset))
            .FirstOrDefault();
        if (hardware is not null)
        {
            var selectedHardware = hardware.OrderByDescending(candidate => candidate.Offset).First();
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = selectedHardware.Value, Offset = selectedHardware.Offset });
        }

        return matches;
    }

    private static bool IsSiemensTriCoreCandidate(string text) =>
        Regex.IsMatch(text, @"\bERCOSEK\s+V4\.3\.\d+\s+TriCore\b", RegexOptions.IgnoreCase) &&
        // VAG SIMOS images use the same ETAS TriCore runtime. A CASxx.DAT
        // dataset record is direct SIMOS evidence and must never be treated as
        // a standalone BMW MSV/MSD marker.
        !Regex.IsMatch(text, @"CAS\d{2}[A-Z0-9]{2,8}\.DAT(?![A-Z0-9])", RegexOptions.IgnoreCase) &&
        !Regex.IsMatch(text, @"\b(?:BOSCH|EDC\d{2,}|MED\d{2,}|MEVD\d{2,}|MD1[A-Z0-9._-]*|MG1[A-Z0-9._-]*)\b", RegexOptions.IgnoreCase);

    private static bool HasSiemensReference(string text) =>
        Regex.IsMatch(text, @"(?<![A-Z0-9])5WK9\d{4}(?![A-Z0-9])", RegexOptions.IgnoreCase);

    private static bool IsMss70SoftwarePair(string upgrade, string software, string relatedRecord) =>
        !string.Equals(upgrade, software, StringComparison.Ordinal) &&
        string.Equals(upgrade[..7], software[..7], StringComparison.Ordinal) &&
        string.Equals(upgrade[..3], relatedRecord[..3], StringComparison.Ordinal);

    private static bool HasBcdHeaderContext(byte[] bytes, int recordOffset, int recordCount) =>
        HasSiemensHeaderPreamble(bytes, Math.Max(0, recordOffset - 64), recordOffset, minimumRun: 6) &&
        HasPrintableAsciiRun(bytes, recordOffset + recordCount * 6, Math.Min(bytes.Length, recordOffset + 128), minimumRun: 5);

    private static bool HasSiemensHeaderPreamble(byte[] bytes, int start, int end, int minimumRun)
    {
        for (var index = start; index < end; index++)
        {
            // Known Siemens BCD metadata headers begin either with '@' or a 01
            // delimiter followed by the module/VIN text. Both forms carry the
            // same structured records; raw calibration tables do not.
            if (bytes[index] is not ((byte)'@') and not 0x01) continue;
            var runLength = 0;
            for (var next = index + 1; next < end && bytes[next] is >= 0x20 and <= 0x7E; next++) runLength++;
            if (runLength >= minimumRun) return true;
        }
        return false;
    }

    private static bool HasPrintableAsciiRun(byte[] bytes, int start, int end, int minimumRun)
    {
        var consecutivePrintable = 0;
        for (var index = start; index < end; index++)
        {
            if (bytes[index] is >= 0x20 and <= 0x7E)
            {
                consecutivePrintable++;
                if (consecutivePrintable >= minimumRun) return true;
            }
            else consecutivePrintable = 0;
        }
        return false;
    }

    private static bool TryReadBcdIdentifier(byte[] bytes, int offset, out string value)
    {
        value = string.Empty;
        if (offset < 0 || offset + 6 > bytes.Length || bytes[offset] != 0 || bytes[offset + 1] != 0) return false;
        Span<char> digits = stackalloc char[8];
        for (var index = 0; index < 4; index++)
        {
            var current = bytes[offset + 2 + index];
            var high = current >> 4;
            var low = current & 0x0F;
            if (high > 9 || low > 9) return false;
            digits[index * 2] = (char)('0' + high);
            digits[index * 2 + 1] = (char)('0' + low);
        }
        value = new string(digits);
        return value.Any(character => character != '0');
    }
}

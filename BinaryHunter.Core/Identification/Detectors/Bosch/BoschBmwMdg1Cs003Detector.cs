using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW MG1 / MG1CS003 images (MDG1 / E-GPT family). The legacy MG1 layout uses
// #DME_ metadata headers combined with 06/08/0D identifier triplets in
// calibration space. The newer MG1CS003 layout (P1390) is an 8 MB image that
// stores IDs in a fixed-location record block: hardware/software are BCD-encoded
// near the start/middle and the upgrade reference is a raw hex string near the
// end. Both formats share the same platform evidence ("MG1" / "DME__840" / "DME__860" /
// vehicle strings), so they are handled by this single detector.
internal sealed class BoschBmwMdg1Cs003Detector : IEcuDetectionModule
{
    public string Name => "Bosch BMW MG1CS003";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        if (!text.Contains("MG1", StringComparison.OrdinalIgnoreCase)) return [];

        var matches = new List<IdentifierMatch>();

        if (TryIdentifyMdg1Cs003(image, matches) || TryIdentifyLegacyMdg1(image, text, matches))
        {
            if (!matches.Any(match => match.Type is "ECU family" or "ECU type"))
            {
                matches.Add(new IdentifierMatch { Type = "ECU family", Value = "Bosch MG1CS003", Offset = 0 });
                matches.Add(new IdentifierMatch { Type = "ECU type", Value = "MG1CS003", Offset = 0 });
            }
            return matches;
        }

        return [];
    }

    private static bool TryIdentifyMdg1Cs003(EcuBinaryImage image, List<IdentifierMatch> matches)
    {
        if (image.Bytes.Length != 8 << 20) return false;

        var text = image.AsciiText;
        if (!text.Contains("DME__860", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("DME__840", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("DME__880", StringComparison.OrdinalIgnoreCase)) return false;

        var hardware = ReadBcd(image.Bytes, 0x145, 7) ?? ReadHex(image.Bytes, 0x145, 7);
        var software = ReadBcd(image.Bytes, 0x40145, 7) ?? ReadHex(image.Bytes, 0x40145, 7);
        var upgrade = ReadUpgrade(image.Bytes, 0x77FD03, 5);

        if (hardware is null && software is null) return false;

        matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = 0 });
        matches.Add(new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = 0 });
        matches.Add(new IdentifierMatch { Type = "ECU family", Value = "Bosch MG1CS003", Offset = 0 });
        matches.Add(new IdentifierMatch { Type = "ECU type", Value = "MG1CS003", Offset = 0 });
        matches.Add(new IdentifierMatch { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 });

        if (hardware is not null)
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware, Offset = 0x145 });
        if (software is not null)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = 0x40145 });
        if (upgrade is not null)
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade, Offset = 0x77FD03 });

        return true;
    }

    private static bool TryIdentifyLegacyMdg1(EcuBinaryImage image, string text, List<IdentifierMatch> matches)
    {
        var markers = Regex.Matches(text, @"#DME_[A-Z0-9]{4}", RegexOptions.IgnoreCase)
            .Cast<Match>()
            .ToArray();
        if (markers.Length == 0) return false;

        var hardwareCandidates = new List<TaggedIdentifier>();
        var softwareCandidates = new List<TaggedIdentifier>();
        foreach (var marker in markers)
        {
            var start = Math.Max(0, marker.Index - 1_024);
            for (var index = start; index <= marker.Index - 8; index++)
            {
                if (image.Bytes[index] is not (0x06 or 0x08) || !TryReadIdentifier(image.Bytes, index, out var code)) continue;
                if (code[0] != 0 || code[1] != 0) continue;

                var candidate = new TaggedIdentifier(Convert.ToHexString(code), code.ToArray(), index + 1L);
                if (image.Bytes[index] == 0x06) hardwareCandidates.Add(candidate);
                else softwareCandidates.Add(candidate);
            }
        }

        var software = SelectConfirmedCandidate(softwareCandidates);
        if (software is null) return false;

        matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Value.Value, Offset = software.Value.Offset });
        var baseSoftware = SelectEarliestCandidate(softwareCandidates);
        if (baseSoftware is not null && !string.Equals(baseSoftware.Value.Value, software.Value.Value, StringComparison.OrdinalIgnoreCase))
            matches.Add(new IdentifierMatch { Type = "Base software Nr.", Value = baseSoftware.Value.Value, Offset = baseSoftware.Value.Offset });

        var hardware = SelectConfirmedCandidate(hardwareCandidates);
        if (hardware is not null)
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value.Value, Offset = hardware.Value.Offset });

        var upgrade = FindRelatedUpgrade(image.Bytes, software.Value);
        if (upgrade is not null)
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Value.Value, Offset = upgrade.Value.Offset });

        return true;
    }

    private static string? ReadBcd(byte[] bytes, int offset, int byteCount)
    {
        if (offset < 0 || offset + byteCount > bytes.Length) return null;
        var sb = new StringBuilder(byteCount * 2);
        for (int i = offset; i < offset + byteCount; i++)
        {
            var high = (bytes[i] >> 4) & 0x0F;
            var low = bytes[i] & 0x0F;
            if (high > 9 || low > 9) return null;
            sb.Append((char)('0' + high));
            sb.Append((char)('0' + low));
        }
        return sb.ToString();
    }

    private static string? ReadHex(byte[] bytes, int offset, int byteCount)
    {
        if (offset < 0 || offset + byteCount > bytes.Length) return null;
        var sb = new StringBuilder(byteCount * 2);
        for (int i = offset; i < offset + byteCount; i++)
            sb.Append(bytes[i].ToString("X2"));
        return sb.ToString();
    }

    private static string? ReadUpgrade(byte[] bytes, int offset, int byteCount)
    {
        if (offset < 0 || offset + byteCount > bytes.Length) return null;
        var sb = new StringBuilder(byteCount * 2);
        for (int i = offset; i < offset + byteCount; i++)
            sb.Append(bytes[i].ToString("X2"));
        return "0000" + sb.ToString();
    }

    private static TaggedIdentifier? SelectConfirmedCandidate(IEnumerable<TaggedIdentifier> candidates)
    {
        var group = candidates
            .GroupBy(candidate => candidate.Value)
            .OrderByDescending(group => group.Count())
            .ThenByDescending(group => group.Max(candidate => candidate.Offset))
            .FirstOrDefault();
        return group?.OrderByDescending(candidate => candidate.Offset).FirstOrDefault();
    }

    private static TaggedIdentifier? SelectEarliestCandidate(IEnumerable<TaggedIdentifier> candidates) =>
        candidates.OrderBy(candidate => candidate.Offset).Select(candidate => (TaggedIdentifier?)candidate).FirstOrDefault();

    private static TaggedIdentifier? FindRelatedUpgrade(byte[] bytes, TaggedIdentifier software)
    {
        const int searchRadius = 8_192;
        var start = Math.Max(0, (int)software.Offset - 1 - searchRadius);
        var end = Math.Min(bytes.Length - 8, (int)software.Offset - 1 + searchRadius);
        TaggedIdentifier? closest = null;
        for (var index = start; index <= end; index++)
        {
            if (bytes[index] != 0x0D || !TryReadIdentifier(bytes, index, out var code)) continue;
            if (code[0] != 0 || code[1] != 0 || code.SequenceEqual(software.Code)) continue;
            if (code[4] != software.Code[4] || code[5] != software.Code[5]) continue;

            var candidate = new TaggedIdentifier(Convert.ToHexString(code), code.ToArray(), index + 1L);
            if (closest is null || Math.Abs(candidate.Offset - software.Offset) < Math.Abs(closest.Value.Offset - software.Offset))
                closest = candidate;
        }

        return closest;
    }

    private static bool TryReadIdentifier(byte[] bytes, int markerOffset, out ReadOnlySpan<byte> code)
    {
        code = default;
        if (markerOffset < 0 || markerOffset + 8 > bytes.Length) return false;
        code = bytes.AsSpan(markerOffset + 1, 7);
        return true;
    }

    private readonly record struct TaggedIdentifier(string Value, byte[] Code, long Offset);
}

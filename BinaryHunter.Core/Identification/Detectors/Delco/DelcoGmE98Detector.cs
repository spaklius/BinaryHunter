using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Delco;

// Delco E98 partial reads omit the first 0x20000 bytes of the 4 MB flash.
// Identification is based on the container layout: two independent AA55-backed
// identification blocks, fixed-width numeric IDs, a GM platform handshake marker
// and the local Gxxxxx software-version record. No known ECU number is required.
internal sealed class DelcoGmE98Detector : IEcuDetectionModule
{
    private const int PartialImageSize = 0x3E0000;
    private const int SoftwareOffset = 0x20;
    private const string GmPlatformMarker = "RREQWREQRACKWACKGM_";

    private static readonly Regex VersionPattern = new(
        @"(?<![A-Z0-9])G\d{5}(?![A-Z0-9])",
        RegexOptions.Compiled);

    public string Name => "Delco GM E98 partial flash";
    public string Manufacturer => "OPEL / VAUXHALL / GM";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var bytes = image.Bytes;
        if (bytes.Length != PartialImageSize ||
            !HasMagic(bytes, 0) ||
            !HasBlockSignature(bytes, 0x14))
            return [];

        var layout = DetectLayout(bytes);
        if (layout is null) return [];

        var upgradeOffset = layout.Value.UpgradeHeaderOffset + 0x10;
        var software = IdentifierHelpers.ReadFixedNumericId(bytes, SoftwareOffset);
        var upgrade = IdentifierHelpers.ReadFixedNumericId(bytes, upgradeOffset);
        if (software is null || upgrade is null) return [];

        var platformOffset = image.AsciiText.IndexOf(GmPlatformMarker, StringComparison.Ordinal);
        if (platformOffset < 0) return [];

        var version = VersionPattern.Match(image.AsciiText, layout.Value.UpgradeHeaderOffset);
        if (!version.Success || version.Index >= layout.Value.UpgradeHeaderOffset + 0x10000) return [];

        var ecuType = layout.Value.Generation == 2 ? "E98 GEN2" : "E98";

        return
        [
            new IdentifierMatch { Type = "Read format", Value = "Partial flash image (3.875 MB / 3,968 KB; base 0x00020000 of 4 MB)", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "General Motors / Opel (E98 GM platform evidence)", Offset = platformOffset + 16 },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Delco / Continental", Offset = 0 },
            new IdentifierMatch { Type = "ECU family", Value = $"Delco/Continental {ecuType}", Offset = 0 },
            new IdentifierMatch { Type = "ECU type", Value = ecuType, Offset = 0 },
            new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = SoftwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade, Offset = upgradeOffset },
            new IdentifierMatch { Type = "Software version", Value = version.Value, Offset = version.Index }
        ];
    }

    private static E98Layout? DetectLayout(byte[] bytes)
    {
        // GEN1 calibration metadata starts at raw offset 0x20000; GEN2 moves the
        // same independently validated block to 0x40000.
        foreach (var layout in new[] { new E98Layout(1, 0x20000), new E98Layout(2, 0x40000) })
        {
            if (HasBlockSignature(bytes, layout.UpgradeHeaderOffset + 4) &&
                HasMagic(bytes, layout.UpgradeHeaderOffset + 0x30))
                return layout;
        }

        return null;
    }

    private static bool HasMagic(byte[] bytes, int offset) =>
        offset >= 0 && offset + 1 < bytes.Length && bytes[offset] == 0xAA && bytes[offset + 1] == 0x55;

    private static bool HasBlockSignature(byte[] bytes, int offset) =>
        offset >= 0 && offset + 2 < bytes.Length &&
        bytes[offset] == 0x20 && bytes[offset + 1] == 0x03 &&
        bytes[offset + 2] is 0x4E or 0x4F;

    private readonly record struct E98Layout(int Generation, int UpgradeHeaderOffset);
}

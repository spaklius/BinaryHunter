using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Renault/Nissan/Opel EDC17C42 full images repeat an exact C42 platform path,
// expose TC1767 directly, and carry a UDS block with a fixed-offset software
// number plus paired upgrade/hardware records. A TPROT marker and the ERCOSEK
// runtime provide additional independent confirmation.
internal sealed class BoschEdc17C42RenaultNissanOpelDetector : IEcuDetectionModule
{
    private const int FullImageSize = 0x200000;
    private const int PartialImageSize = 0x80000;
    private const int SoftwareOffset = 0x18001A;
    private const int PartialSoftwareOffset = 0x1A;

    private static readonly Regex PlatformPattern = new(
        @"\d{2,3}/1/EDC17_?C42/\d+/P?_?[A-Z0-9]+//[A-Za-z0-9_]+_",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RuntimePattern = new(
        @"ERCOSEK\s+V\d+(?:\.\d+){1,3}\s+TriCore_g",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessorPattern = new(
        @"TC1767",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TprotMarkerPattern = new(
        @"TPROT_V\d+\.\d+\.\d+/1767",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?:10SW\d{6}|10375\d{4,5})",
        RegexOptions.Compiled);

    // Software number at fixed offset may be followed by additional digits
    // (e.g. "1037545140" followed by "1194"), so validate the prefix only.
    private static readonly Regex SoftwarePrefixPattern = new(
        @"^(?:10SW\d{6}|10375\d{4,5})",
        RegexOptions.Compiled);

    private static readonly Regex UpgradeHardwarePattern = new(
        @"(?<upgrade>[0-9]{4}R).{1}[0-9]{3}(?<hardware>[0-9]{4}R)\x17.{2}",
        RegexOptions.Compiled);

    public string Name => "Bosch EDC17C42 Nissan/Opel/Renault";
    public string Manufacturer => "RENAULT / NISSAN / DACIA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
        if (image.Bytes.Length != FullImageSize) return [];

        var text = image.AsciiText;
        var platforms = PlatformPattern.Matches(text).Cast<Match>().ToArray();
        var runtime = RuntimePattern.Match(text);
        var tprot = TprotMarkerPattern.Match(text);
        if (platforms.Length < 2 || !runtime.Success || !tprot.Success) return [];

        // The software number sits at a fixed offset in every EDC17C42 image.
        if (SoftwareOffset + 10 > text.Length) return [];
        var software = text.Substring(SoftwareOffset, 10);
        if (!SoftwarePrefixPattern.IsMatch(software)) return [];

        // The upgrade/hardware pair is the only R-suffixed record pair that is
        // terminated by the 0x17 0x08 record marker, which disambiguates it from
        // unrelated 4-digit+R strings elsewhere in the image.
        var pair = UpgradeHardwarePattern.Match(text);
        if (!pair.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Renault–Nissan–Dacia / Opel–Vauxhall", Offset = platforms[^1].Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = platforms[^1].Index },
            new() { Type = "ECU family", Value = "Bosch EDC17C42", Offset = platforms[^1].Index },
            new() { Type = "ECU type", Value = "EDC17C42", Offset = platforms[^1].Index },
            // Processor marker varies across EDC17C42 variants; omitted from strict profile.
            new() { Type = "Software Nr.", Value = software, Offset = SoftwareOffset },
            new() { Type = "Software Upgrade Nr.", Value = pair.Groups["upgrade"].Value, Offset = pair.Groups["upgrade"].Index },
            new() { Type = "Hardware Nr.", Value = pair.Groups["hardware"].Value, Offset = pair.Groups["hardware"].Index }
        };

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectPartial(EcuBinaryImage image)
    {
        // Partial reads (e.g. 512 KB starting at 0x00180000) carry the software
        // number at offset 0x1A, but hardware/upgrade records may use a different
        // encoding. Report software number as the confirmed identifier; other
        // fields are omitted unless their encoding is mapped later.
        if (PartialSoftwareOffset + 10 > image.AsciiText.Length) return [];
        var software = image.AsciiText.Substring(PartialSoftwareOffset, 10);
        if (!SoftwarePrefixPattern.IsMatch(software)) return [];

        return
        [
            new() { Type = "Vehicle group", Value = "Renault–Nissan–Dacia / Opel–Vauxhall", Offset = PartialSoftwareOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = PartialSoftwareOffset },
            new() { Type = "ECU family", Value = "Bosch EDC17C42", Offset = PartialSoftwareOffset },
            new() { Type = "ECU type", Value = "EDC17C42", Offset = PartialSoftwareOffset },
            new() { Type = "Read format", Value = $"Partial flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Software Nr.", Value = software, Offset = PartialSoftwareOffset }
        ];
    }
}

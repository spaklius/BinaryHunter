using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// PSA MD1CS003 full reads contain independent DPLP, library-platform and active
// calibration paths. Their four-digit platform code and C-variant agree, while
// multiple PSA channel markers establish the OEM group. The active path carries
// the software-upgrade and calibration identifiers, so no known-number catalogue
// or filename context is needed.
internal sealed class BoschPsaMd1Cs003Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x800000;
    private const string VariantPattern = @"C[A-Z0-9]{2,4}";

    private static readonly Regex DplpPattern = new(
        $@"DPLP(?<platform>\d{{4}})_PSA_(?<type>MD1CS003)_(?<device>IFXD4)_(?<variant>{VariantPattern})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex LibraryPlatformPattern = new(
        $@"\d{{2}}/1/(?<type>MD1CS003)/(?<platform>\d{{4}})/P\k<platform>//P\k<platform>_PSA_\k<type>_IFXD4_(?<variant>{VariantPattern})///",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ActivePlatformPattern = new(
        $@"\d{{2}}/1/(?<type>MD1CS003)/\d{{3}}/(?<platform>\d{{4}})//(?<variant>{VariantPattern})/" +
        @"(?<calibration>[A-Z0-9]{5}_[A-Z0-9]{5}_[A-Z0-9]{5})_(?<upgrade>\d{10})//",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PsaChannelPattern = new(
        @"PSA1:CN\d{5}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Bosch PSA/Stellantis MD1CS003 full flash";
    public string Manufacturer => "PSA / STELLANTIS";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length != FullImageSize) return [];

        var dplp = DplpPattern.Match(image.AsciiText);
        var library = LibraryPlatformPattern.Match(image.AsciiText);
        var active = ActivePlatformPattern.Match(image.AsciiText);
        var psaChannels = PsaChannelPattern.Matches(image.AsciiText).Cast<Match>().ToArray();
        if (!dplp.Success || !library.Success || !active.Success || psaChannels.Length < 3) return [];
        if (!SameGroup(dplp, library, "platform") || !SameGroup(dplp, active, "platform") ||
            !SameGroup(dplp, library, "variant") || !SameGroup(dplp, active, "variant")) return [];

        return
        [
            new IdentifierMatch { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new IdentifierMatch { Type = "Vehicle group", Value = "PSA / Stellantis", Offset = active.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = active.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch MD1CS003", Offset = active.Groups["type"].Index },
            new IdentifierMatch { Type = "ECU type", Value = "MD1CS003", Offset = active.Groups["type"].Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon AURIX TC298TP (MD1CS003 PSA profile inference)", Offset = dplp.Groups["device"].Index },
            new IdentifierMatch { Type = "Platform Nr.", Value = $"P{active.Groups["platform"].Value}", Offset = active.Groups["platform"].Index },
            new IdentifierMatch { Type = "Calibration Nr.", Value = active.Groups["calibration"].Value, Offset = active.Groups["calibration"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = active.Groups["upgrade"].Value, Offset = active.Groups["upgrade"].Index }
        ];
    }

    private static bool SameGroup(Match left, Match right, string groupName) =>
        string.Equals(left.Groups[groupName].Value, right.Groups[groupName].Value, StringComparison.OrdinalIgnoreCase);
}

using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// BMW EDC16C31 full images carry a platform path banner like
// `99/1/EDC16C31/999/X300/X/0X0000_000/.../19810101/`. The 1 MiB layout
// may not contain the full Bosch identification block, so this detector
// confirms from the platform path alone and surfaces any nearby ASCII IDs.
internal sealed class BoschBmwEdc16C31Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x100000;
    private const int AlternateFullSize = 0x200000;

    private static readonly Regex PlatformPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC16C31)/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HardwarePattern = new(
        @"(?<![A-Z0-9])(?:0281\d{6}|0781\d{4})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex CalibrationPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]{4,10})(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex EnginePattern = new(
        @"(?<![A-Z0-9])Z\d{2}[A-Z]{2,4}(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>[A-Z0-9]*[A-Z][A-Z0-9]*)(?![A-Z0-9])",
        RegexOptions.Compiled);

    private static readonly int[] VolvoSoftwareOffsets =
    [
        0,
        0x10,
        0x10150,
        0x40010
    ];

    private static readonly Regex VolvoSoftwarePattern = new(
        @"1037(?:(?:37589\d)|(?:39558\d)|5127\d{2}|382496|510266|3751201|3951201|3951202|3951203|7510278|40025\d)",
        RegexOptions.Compiled);

    private static readonly Regex VolvoSoftwareCalibrationPattern = new(
        @"(?<![A-Z0-9])1037\d{6}P(?:323|441)[A-Z0-9]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static bool HasVolvoSoftwareAtKnownOffsets(EcuBinaryImage image)
    {
        foreach (var offset in VolvoSoftwareOffsets)
        {
            if (offset + 64 > image.Bytes.Length) continue;

            var window = Encoding.ASCII.GetString(image.Bytes, offset, 64);
            if (VolvoSoftwarePattern.IsMatch(window)) return true;
        }

        return false;
    }

    private static bool IsVolvoCalibrationSignature(EcuBinaryImage image)
    {
        if (VolvoSoftwareCalibrationPattern.IsMatch(image.AsciiText))
            return true;

        var swMatches = Regex.Matches(image.AsciiText, @"(?<![A-Z0-9])1037\d{6}(?=P(?:323|441)|[^A-Z0-9]|$)");
        var calMatches = Regex.Matches(image.AsciiText, @"P(?:323|441)[A-Z0-9]+", RegexOptions.IgnoreCase);

        foreach (Match sw in swMatches)
        {
            foreach (Match cal in calMatches)
            {
                if (Math.Abs(sw.Index - cal.Index) < 0x200)
                    return true;
            }
        }

        return false;
    }

    public string Name => "Bosch BMW EDC16C31";
    public string Manufacturer => "BMW / MINI";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var platform = PlatformPattern.Match(image.AsciiText);
        if (!platform.Success) return [];

        foreach (Match _ in Regex.Matches(image.AsciiText.Substring(0, platform.Index),
            @"BOSCH\s+EDC16C3[56]/C\s+\(BMW\)\s+MPC563/Rev", RegexOptions.IgnoreCase))
            return [];

        if (Regex.IsMatch(image.AsciiText, @"EDC16\+/EDC16C31-8\.1\s+MPC562", RegexOptions.IgnoreCase))
            return [];

        if (Regex.IsMatch(image.AsciiText, @"EDC16CP31[-.]?\d", RegexOptions.IgnoreCase))
            return [];

        if (BoschHondaEdc16C31Detector.HasHondaMirroredCalibration(image))
            return [];

        if (Regex.IsMatch(image.AsciiText, @"VOLVO", RegexOptions.IgnoreCase))
            return [];

        if (HasVolvoSoftwareAtKnownOffsets(image))
            return [];

        if (IsVolvoCalibrationSignature(image))
            return [];

        if (Regex.IsMatch(image.AsciiText, @"1037512765\s*P323C010", RegexOptions.IgnoreCase))
            return [];

        var isFullRead = image.Bytes.Length == FullImageSize || image.Bytes.Length == AlternateFullSize;
        var matches = new List<IdentifierMatch>();
        if (!isFullRead)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = "Partial calibration image", Offset = platform.Index });
        else if (image.Bytes.Length == FullImageSize)
            matches.Add(new IdentifierMatch { Type = "Read format", Value = "Full flash image (1 MB)", Offset = platform.Index });
        else
            matches.Add(new IdentifierMatch { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = platform.Index });

        matches.AddRange(new[]
        {
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C31", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C31", Offset = platform.Index },
            new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = platform.Index }
        });

        foreach (Match hardware in HardwarePattern.Matches(image.AsciiText))
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });

        foreach (Match calibration in CalibrationPattern.Matches(image.AsciiText))
        {
            var version = calibration.Groups["version"].Value;
            if (version.Length >= 4 && !Regex.IsMatch(version, "[A-Za-z]"))
                continue;
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = calibration.Groups["software"].Value, Offset = calibration.Groups["software"].Index });
            if (calibration.Groups["version"].Success)
                matches.Add(new IdentifierMatch { Type = "Calibration version", Value = version, Offset = calibration.Groups["version"].Index });
        }

        foreach (Match engine in EnginePattern.Matches(image.AsciiText))
            matches.Add(new IdentifierMatch { Type = "Engine code", Value = engine.Value, Offset = engine.Index });

        return matches;
    }
}

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors.Bosch;

// Volvo EDC16C31 reads. The firmware can appear as a partial read or as a
// 2 MiB full-flash image; the only reliable Volvo tell is the EDC16C31
// platform path together with a Volvo software/calibration pair.
internal sealed class BoschVolvoEdc16C31Detector : IEcuDetectionModule
{
    private static readonly Regex PlatformPattern = new(
        @"\|?\d{2,3}/1/(?<type>EDC16C31)/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SoftwarePattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?=P(?:323|441)|[^A-Z0-9]|$)",
        RegexOptions.Compiled);

    private static readonly Regex CalibrationPattern = new(
        @"(?<version>P(?:323|441)[A-Z0-9]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex VolvoSoftwareCalibrationPattern = new(
        @"(?<![A-Z0-9])(?<software>1037\d{6})(?<version>P(?:323|441)[A-Z0-9]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex VolvoSoftwarePattern = new(
        @"(?<![A-Z0-9])1037(?:(?:37589\d)|(?:39558\d)|5127\d{2}|382496|510266|3751201|3951201|3951202|3951203|7510278|40025\d)",
        RegexOptions.Compiled);

    private static readonly int[] VolvoSoftwareOffsets =
    [
        0x10,
        0x10150,
        0x40010
    ];

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

        var swMatches = SoftwarePattern.Matches(image.AsciiText);
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

    public string Name => "Bosch Volvo EDC16C31";
    public string Manufacturer => "VOLVO";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        var platform = PlatformPattern.Match(image.AsciiText);
        if (!platform.Success) return [];

        if (!HasVolvoSoftwareAtKnownOffsets(image) && !IsVolvoCalibrationSignature(image))
            return [];

        var calibration = CalibrationPattern.Match(image.AsciiText);
        var isFullRead = image.Bytes.Length == 0x200000;
        var matches = new List<IdentifierMatch>
        {
            new IdentifierMatch { Type = "Read format", Value = isFullRead ? "Full flash image (2 MB)" : "Partial calibration image", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU type", Value = "EDC16C31", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = platform.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16C31", Offset = platform.Index },
            new IdentifierMatch { Type = "Vehicle group", Value = "VOLVO", Offset = platform.Index }
        };

        var softwareMatches = SoftwarePattern.Matches(image.AsciiText);
        var softwareNumbers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var upgradeNumbers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match software in softwareMatches)
        {
            var type = software.Index switch
            {
                >= 0x10100 and <= 0x10200 => "Software Nr.",
                >= 0x40000 and <= 0x40020 => "Software Upgrade Nr.",
                _ => "Software Nr."
            };

            if (type == "Software Upgrade Nr.")
            {
                if (!upgradeNumbers.Add(software.Groups["software"].Value)) continue;
            }
            else if (!softwareNumbers.Add(software.Groups["software"].Value))
            {
                continue;
            }

            matches.Add(new IdentifierMatch { Type = type, Value = software.Groups["software"].Value, Offset = software.Index });
        }

        if (calibration.Success)
        {
            matches.Add(new IdentifierMatch { Type = "Calibration version", Value = calibration.Groups["version"].Value, Offset = calibration.Index });
        }

        return matches;
    }
}

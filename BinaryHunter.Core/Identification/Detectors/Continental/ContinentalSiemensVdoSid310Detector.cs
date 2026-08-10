using System.Text.RegularExpressions;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Identification.Helpers;

namespace BinaryHunter.Core.Identification.Detectors.Continental;

// SID310 full reads (Dacia/Nissan/Renault, Continental/Siemens-VDO) do not carry
// any readable ASCII platform-path marker like the Bosch/PSA families - the
// identification block is pure fixed-width fields with no surrounding text
// anchor. Confidence instead comes from three independent checks: the exact
// full-image size, a fixed hardware-number offset, and a fixed software-number
// offset that is deliberately written TWICE nearby (offsets 0x1C31 and 0x1C3D)
// - requiring both copies to match is the substitute for a textual anchor.
// Chassis (VIN) and software-upgrade number are optional corroborating fields:
// not every read carries them (VIN is often blanked/unavailable, and the
// upgrade number sits in a separate calibration-footer area near the end of
// the image that is not always populated), so neither gates detection.
//
// Partial (0xC0000) SID310 reads use a length-prefixed record layout. Record
// addresses move between firmware generations (observed at 0x86DF, 0x871F and
// 0x8807), so detection searches only the small identification area instead of
// assuming one universal offset. The repeated CARFE9/RFZRFE header is required
// as independent structural evidence before a 23710<code> record is accepted.
internal sealed class ContinentalSiemensVdoSid310Detector : IEcuDetectionModule
{
    private const int FullImageSize = 0x300000;
    private const int PartialImageSize = 0xC0000;

    private const int HardwareNrOffset = 0x1C05;
    private const int SoftwareNrOffsetPrimary = 0x1C31;
    private const int SoftwareNrOffsetSecondary = 0x1C3D;
    private const int ChassisNumberOffset = 0x1A00;
    private const int SoftwareUpgradeNrOffset = 0x248484;

    private const int PartialIdentificationStart = 0x8000;
    private const int PartialIdentificationLength = 0x1000;

    // All observed hardware/software codes are 5-char uppercase alphanumeric
    // (e.g. "7137R", "HX43B", "6282R") - used as a lightweight validity check
    // in the absence of any textual anchor.
    private static readonly Regex CodePattern = new(@"^[0-9A-Z]{5}$", RegexOptions.Compiled);

    private static readonly Regex PartialHeaderPattern = new(
        @"\ACARFE9(?<variant>[A-Z0-9])0RFE9\k<variant>00010\d{6}AA\s+" +
        @"RFZRFE429\k<variant>000000RFZRFE429\k<variant>000000RFZRFE429\k<variant>000000",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex APlatformPartialHeaderPattern = new(
        @"\ACARFEA(?<variant>\d)0RFEA\k<variant>00010\d{6}AA\s+" +
        @"RFZRFE45A\k<variant>000000RFZRFE45A\k<variant>000000RFZRFE45A\k<variant>000000",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CitanPartialHeaderPattern = new(
        @"\ACARFE(?<variant>7P)0RFE\k<variant>00010\d{6}AA\s+" +
        @"RFZRFE45\k<variant>000000RFZRFE45\k<variant>000000RFZRFE45\k<variant>000000",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex JPlatformPartialHeaderPattern = new(
        @"\ACARFJ(?<variant>\d{2})0RFJ\k<variant>00010\d{6}AA\s+" +
        @"RFZRFJ42\k<variant>000000RFZRFJ42\k<variant>000000RFZRFJ42\k<variant>000000",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PartialSoftwareRecordPattern = new(
        @"23710(?<software>[0-9A-Z]{5})(?![0-9A-Z])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PartialUpgradeRecordPattern = new(
        @"2(?<suffix>[RS])\x00{6}3761(?<upgrade>\d{4})H",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex JPlatformIdentificationPattern = new(
        @"3701(?<primary>[0-9A-Z]{4})2[A-Z]3710(?<secondary>[0-9A-Z]{4})ECM\x00-EngineControl\x00",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex JPlatformUpgradeRecordPattern = new(
        @"23701(?<upgrade>[0-9A-Z]{5})(?![0-9A-Z])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Loose VIN shape check (17 chars, VIN alphabet excludes I/O/Q) - optional,
    // does not gate detection since chassis number is not always present.
    private static readonly Regex VinPattern = new(@"^[A-HJ-NPR-Z0-9]{17}$", RegexOptions.Compiled);

    public string Name => "Continental-Siemens-VDO SID310 Dacia/Nissan/Renault";
    public string Manufacturer => "MERCEDES-BENZ / RENAULT / NISSAN / DACIA";

    public IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
        if (image.Bytes.Length != FullImageSize) return [];
        var hardware = IdentifierHelpers.ReadToken(image.Bytes, HardwareNrOffset, 8);

        var softwarePrimary = IdentifierHelpers.ReadToken(image.Bytes, SoftwareNrOffsetPrimary, 8);

        var softwareSecondary = IdentifierHelpers.ReadToken(image.Bytes, SoftwareNrOffsetSecondary, 8);
        if (hardware is null || softwarePrimary is null || softwareSecondary is null) return [];
        if (!CodePattern.IsMatch(hardware) || !CodePattern.IsMatch(softwarePrimary)) return [];

        // The software number is deliberately duplicated a few bytes later in
        // every known sample - requiring the two copies to agree is the
        // stand-in for a textual platform anchor.
        if (!string.Equals(softwarePrimary, softwareSecondary, StringComparison.Ordinal)) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Renault-Nissan-Dacia Alliance", Offset = HardwareNrOffset },
            new() { Type = "ECU manufacturer", Value = "Continental / Siemens-VDO (SID310 fixed-layout evidence)", Offset = HardwareNrOffset },
            new() { Type = "ECU family", Value = "Continental SID310", Offset = HardwareNrOffset },
            new() { Type = "ECU type", Value = "SID310", Offset = HardwareNrOffset },
            new() { Type = "Read format", Value = $"Full flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Hardware Nr.", Value = hardware, Offset = HardwareNrOffset },
            new() { Type = "Software Nr.", Value = softwarePrimary, Offset = SoftwareNrOffsetPrimary }
        };

        // Optional corroborating fields - present in some but not all reads.
        var chassis = IdentifierHelpers.ReadToken(image.Bytes, ChassisNumberOffset, 17);
        if (chassis is not null && VinPattern.IsMatch(chassis))
            matches.Add(new IdentifierMatch { Type = "Chassis number (VIN)", Value = chassis, Offset = ChassisNumberOffset });

        var upgrade = IdentifierHelpers.ReadToken(image.Bytes, SoftwareUpgradeNrOffset, 8);
        if (upgrade is not null && CodePattern.IsMatch(upgrade))
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade, Offset = SoftwareUpgradeNrOffset });

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectPartial(EcuBinaryImage image)
    {
        var text = image.AsciiText;
        var header = PartialHeaderPattern.Match(text);
        var isMercedesCitan = false;
        if (!header.Success) header = APlatformPartialHeaderPattern.Match(text);
        if (!header.Success)
        {
            header = CitanPartialHeaderPattern.Match(text);
            isMercedesCitan = header.Success;
        }
        if (!header.Success) return DetectJPlatformPartial(image, text);

        var identificationEnd = Math.Min(text.Length, PartialIdentificationStart + PartialIdentificationLength);
        var identificationArea = text[PartialIdentificationStart..identificationEnd];
        var software = PartialSoftwareRecordPattern.Match(identificationArea);
        if (!software.Success) return [];

        var softwareGroup = software.Groups["software"];
        var softwareOffset = PartialIdentificationStart + softwareGroup.Index;
        var softwareCode = softwareGroup.Value.ToUpperInvariant();
        if (!CodePattern.IsMatch(softwareCode)) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = isMercedesCitan ? "Mercedes-Benz" : "Renault-Nissan-Dacia Alliance", Offset = header.Index },
            new() { Type = "ECU manufacturer", Value = "Continental / Siemens-VDO (SID310 partial-layout evidence)", Offset = header.Index },
            new() { Type = "ECU family", Value = "Continental SID310", Offset = header.Index },
            new() { Type = "ECU type", Value = "SID310", Offset = header.Index },
            new() { Type = "Read format", Value = $"Partial flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Software Nr.", Value = softwareCode, Offset = softwareOffset }
        };

        // The upgrade layout is 2<suffix><padding>3761<digits>H... . Preserve
        // the independent R/S suffix byte rather than assuming one generation.
        var upgrade = PartialUpgradeRecordPattern.Match(identificationArea);
        if (upgrade.Success)
        {
            var upgradeGroup = upgrade.Groups["upgrade"];
            matches.Add(new IdentifierMatch
            {
                Type = "Software Upgrade Nr.",
                Value = upgradeGroup.Value + upgrade.Groups["suffix"].Value.ToUpperInvariant(),
                Offset = PartialIdentificationStart + upgradeGroup.Index
            });
        }

        return matches;
    }

    private static IEnumerable<IdentifierMatch> DetectJPlatformPartial(EcuBinaryImage image, string text)
    {
        var header = JPlatformPartialHeaderPattern.Match(text);
        if (!header.Success) return [];

        var identificationEnd = Math.Min(text.Length, PartialIdentificationStart + PartialIdentificationLength);
        var identificationArea = text[PartialIdentificationStart..identificationEnd];
        var identification = JPlatformIdentificationPattern.Match(identificationArea);
        var upgrade = JPlatformUpgradeRecordPattern.Match(identificationArea);
        if (!identification.Success || !upgrade.Success) return [];

        var upgradeGroup = upgrade.Groups["upgrade"];
        var upgradeCode = upgradeGroup.Value.ToUpperInvariant();
        var upgradeOffset = PartialIdentificationStart + upgradeGroup.Index;
        var vehicleGroup = upgradeCode.StartsWith("5XF", StringComparison.Ordinal)
            ? "Mercedes-Benz"
            : "Renault-Nissan Alliance";
        return
        [
            new() { Type = "Vehicle group", Value = vehicleGroup, Offset = header.Index },
            new() { Type = "ECU manufacturer", Value = "Continental / Siemens-VDO (SID310 J-platform evidence)", Offset = header.Index },
            new() { Type = "ECU family", Value = "Continental SID310", Offset = header.Index },
            new() { Type = "ECU type", Value = "SID310", Offset = header.Index },
            new() { Type = "Read format", Value = $"Partial flash image ({image.DisplaySize})", Offset = 0 },
            new() { Type = "Software Upgrade Nr.", Value = upgradeCode, Offset = upgradeOffset }
        ];
    }
}

using BinaryHunter.Core.Identification.Detectors;
using BinaryHunter.UI.Models;

namespace BinaryHunter.UI.Services;

internal static class SupportedEcuCatalog
{
    private sealed record Presentation(string Name, string ImageSize, bool Full, bool Partial);

    private static readonly IReadOnlyDictionary<string, Presentation> Presentations =
        new Dictionary<string, Presentation>(StringComparer.OrdinalIgnoreCase)
        {
            ["Bosch EDC15M partial image"] = new("Bosch EDC15M", "32 KB calibration", false, true),
            ["Bosch BMW EDC15C4 / DDE4.0"] = new("Bosch EDC15C4 / DDE4.0", "512 KB partial", false, true),
            ["Bosch BMW EDC16C31"] = new("Bosch EDC16C31", "1 MB full / partial", true, true),
            ["Bosch BMW EDC16CP35"] = new("Bosch EDC16CP35", "1 MB full", true, false),
            ["Bosch BMW EDC16C35/CP35 full + partial"] = new("Bosch EDC16C35 / CP35", "2 MB virtual / partial", true, true),
            ["Bosch BMW EDC17CP02/C06"] = new("Bosch EDC17CP02 / C06", "Full or 264 KB calibration", true, true),
            ["Bosch BMW EDC17C41"] = new("Bosch EDC17C41", "2 MB", true, false),
            ["Bosch BMW EDC17C50"] = new("Bosch EDC17C50", "2 MB", true, false),
            ["Bosch BMW EDC17CP45"] = new("Bosch EDC17CP45", "4 MB", true, false),
            ["Bosch BMW MG1CS003"] = new("Bosch MG1CS003", "Structure-based full read", true, false),
            ["Bosch BMW MEVD17.2"] = new("Bosch MEVD17.2 / MEV946", "Structure-based full read", true, false),
            ["Siemens BMW MSV/MSS/MSD"] = new("Siemens/Continental MSV / MSS / MSD", "2 MB", true, false),
            ["Bosch Volvo EDC16C31"] = new("Bosch EDC16C31", "384 KB partial or 2 MB full", true, true),

            ["Bosch Mercedes-Benz EDC16CP31"] = new("Bosch EDC16CP31", "2 MB full", true, false),
            ["Bosch Mercedes-Benz EDC16CP36"] = new("Bosch EDC16CP36", "2 MB full", true, false),

            ["Bosch VAG EDC16U1"] = new("Bosch EDC16U1", "1 MB full", true, false),
            ["Bosch VAG EDC16U31/U34"] = new("Bosch EDC16U31 / U34", "512 KB partial", false, true),
            ["Bosch VAG EDC16CP34"] = new("Bosch EDC16CP34", "2 MB full", true, false),
            ["Bosch VAG EDC17C46"] = new("Bosch EDC17C46", "2 MB", true, false),
            ["Bosch VAG EDC17C54"] = new("Bosch EDC17C54", "4 MB", true, false),
            ["Bosch VAG EDC17C64"] = new("Bosch EDC17C64", "4 MB", true, false),
            ["Bosch VAG EDC17C74"] = new("Bosch EDC17C74", "4 MB", true, false),
            ["Bosch VAG EDC17CP20"] = new("Bosch EDC17CP20", "2 MB", true, false),
            ["Bosch VAG EDC17CP44"] = new("Bosch EDC17CP44", "4 MB", true, false),
            ["Bosch VAG MED17.1 family"] = new("Bosch MED17.1 / MED17.1.1", "Full read", true, false),
            ["Bosch VAG MED9.1.1"] = new("Bosch MED9.1.1", "Full read", true, false),
            ["Delphi VAG DCM6.2V"] = new("Delphi DCM6.2V", "4 MB", true, false),
            ["Delphi PSA DCM6.2A"] = new("Delphi DCM6.2A", "4 MB", true, false),
            ["Continental VAG PCR2.1"] = new("Continental PCR2.1", "503296-byte OBD partial or full image", true, true),
            ["Continental VAG SIMOS6.2"] = new("Continental SIMOS6.2", "Up to 2 MB", true, true),
            ["Continental VAG SIMOS8.1"] = new("Continental SIMOS8.1", "2 MB", true, false),
            ["Continental VAG SIMOS8.2"] = new("Continental SIMOS8.2", "256 KB or full read", true, true),
            ["Continental VAG SIMOS8.3"] = new("Continental SIMOS8.3", "2 MB", true, false),
            ["Continental VAG SIMOS8.5"] = new("Continental SIMOS8.5", "2 MB", true, false),
            ["Continental VAG SIMOS PPD1.x"] = new("Continental SIMOS PPD1.x", "2 MB full or 256 KB partial", true, true),

            ["Bosch Ford EDC17C70"] = new("Bosch EDC17C70", "4 MB", true, false),
            ["Continental Ford SID208"] = new("Continental SID208", "4 MB", true, false),
            ["Continental Ford SID211"] = new("Continental SID211", "4 MB", true, false),
            ["Bosch Honda EDC17CP50"] = new("Bosch EDC17CP50", "2 MB partial or 4 MB full", true, true),
            ["Bosch Honda EDC17C58"] = new("Bosch EDC17C58", "4 MB", true, false),

            ["Bosch EDC17CP55 Jaguar/Land Rover"] = new("Bosch EDC17CP55", "4 MB full", true, false),
            ["Bosch MEDC17.9 Jaguar/Land Rover"] = new("Bosch MEDC17.9", "4 MB full", true, false),
            ["Bosch EDC17CP11 Jaguar/Land Rover/PSA"] = new("Bosch EDC17CP11", "2 MB full", true, false),
            ["Bosch EDC17C66 MEB"] = new("Bosch EDC17C66", "896 KB OBD partial or 4 MB full", true, true),

            ["Denso Mazda SH725x partial PCM"] = new("Denso PCM SH725x", "2 MB OBD maps or 2,063,616-byte partial", false, true),
            ["Denso Mazda RF7-series SH7058 full flash"] = new("Denso RF7/RF8-series PCM SH7058", "1 MB full flash", true, false),
            ["Denso Mazda R2AA SH7058 full flash"] = new("Denso R2AA PCM SH7058", "1 MB full flash", true, false),
            ["Denso Subaru SH705x"] = new("Denso Subaru SH705x", "1008 KB partial", false, true),
            ["Denso Volvo MB279700-96XX SH72546"] = new("Denso MB279700-96XX SH72546", "3.75 MB partial / OBD", false, true),

            ["Bosch Opel/GM EDC15M full PLCC image"] = new("Bosch EDC15M", "256 KB full PLCC flash", true, false),
            ["Bosch Opel/GM EDC15M1 full PLCC image"] = new("Bosch EDC15M1", "256 KB full PLCC flash", true, false),
            ["Bosch Opel/GM EDC16C9 full flash"] = new("Bosch EDC16C9 full flash", "1 MB", true, false),
            ["Bosch Opel/GM EDC16C9 MPC processor image"] = new("Bosch EDC16C9 MPC image", "452 KB", false, true),
            ["Bosch Opel/GM EDC16C39 full flash"] = new("Bosch EDC16C39 full flash", "2 MB", true, false),
            ["Bosch Opel/GM EDC16C39 partial image"] = new("Bosch EDC16C39 partial image", "256 KB", false, true),
            ["Delco GM E98 partial flash"] = new("Delco E98 / E98 GEN2", "3.875 MB partial flash", false, true),
            ["Delco Opel/Vauxhall E87"] = new("Delco E87", "640 KB / 1.9375 MB partial or 2 MB full", true, true),

            ["Delphi PSA DCM3.5"] = new("Delphi DCM3.5", "Up to 512 KB", true, true),
            ["Delphi PSA DCM7.1A"] = new("Delphi DCM7.1A", "Up to 512 KB", true, true),
            ["Bosch PSA EDC16C34"] = new("Bosch EDC16C34", "640 KB calibration", false, true),
            ["Bosch PSA EDC17C60"] = new("Bosch EDC17C60", "4 MB full", true, false),
            ["Bosch PSA/Stellantis MD1CS003 full flash"] = new("Bosch MD1CS003", "8 MB full flash", true, false),
            ["Bosch Mercedes-Benz MD1CP001"] = new("Bosch MD1CP001", "8 MB full flash", true, false),
            ["Bosch EDC17C42 Nissan/Opel/Renault"] = new("Bosch EDC17C42", "2 MB", true, false),
            ["Bosch Nissan/Renault EDC16CP42"] = new("Bosch EDC16CP42", "320 KB partial or 2 MB full", true, true),
            ["Bosch Nissan EDC17C84"] = new("Bosch EDC17C84", "2560 KB full or 2464 KB partial", true, true),
            ["Continental-Siemens-VDO SID208 PSA"] = new("Continental SID208", "4 MB", true, false),
            ["Continental-Siemens-VDO SID310 Dacia/Nissan/Renault"] = new("Continental-Siemens-VDO SID310", "768 KB partial or 3 MB full", true, true),
            ["Siemens/Continental Volvo SID803A"] = new("Siemens/Continental SID803A", "2 MB full / 1.44 MB partial", true, true)
        };

    private const string VagGroupName = "AUDI / VW / ŠKODA / SEAT / PORSCHE";

    private static readonly IReadOnlyDictionary<string, string> GroupCodes =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [VagGroupName] = "VAG",
            ["BMW / MINI"] = "BMW",
            ["FORD"] = "FORD",
            ["HONDA"] = "HONDA",
            ["Jaguar/Land Rover"] = "JLR",
            ["Jaguar/Land Rover/PSA"] = "JLR/PSA",
            ["Mercedes-Benz"] = "MB",
            ["MAZDA"] = "MZD",
            ["OPEL / VAUXHALL / GM"] = "GM",
            ["PSA / STELLANTIS"] = "PSA",
            ["RENAULT / NISSAN / DACIA"] = "RN",
            ["VOLVO"] = "VOLVO"
        };

    public static IReadOnlyList<SupportedEcuGroup> CreateGroups()
    {
        var groups = AutomaticDetectorRegistry.DetectModules
            .DistinctBy(module => module.Name, StringComparer.OrdinalIgnoreCase)
            .Select(module => new
            {
                Module = module,
                VehicleGroup = NormalizeVehicleGroup(module.Manufacturer)
            })
            .GroupBy(item => item.VehicleGroup, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group => new SupportedEcuGroup(
                group.Key,
                GroupCodes.GetValueOrDefault(group.Key, group.Key),
                group.Select(item => CreateProfile(item.Module))
                    .OrderBy(profile => profile.Name, StringComparer.OrdinalIgnoreCase)
                    .ToArray()))
            .ToList();

        groups.Add(new SupportedEcuGroup(
            "GENERIC / UNKNOWN",
            "GEN",
            [new SupportedEcuProfile("Generic structural analysis", "Any binary image", true, true)]));

        return groups;
    }

    private static string NormalizeVehicleGroup(string manufacturer) =>
        manufacturer.StartsWith("AUDI / VW /", StringComparison.OrdinalIgnoreCase)
            ? VagGroupName
            : manufacturer;

    private static SupportedEcuProfile CreateProfile(IEcuDetectionModule module)
    {
        var isDraft = module is IBaseDetector;
        var presentation = Presentations.GetValueOrDefault(module.Name);
        return presentation is null
            ? new SupportedEcuProfile(module.Name, "Automatic structure detection", false, false, isDraft)
            : new SupportedEcuProfile(
                presentation.Name,
                presentation.ImageSize,
                presentation.Full,
                presentation.Partial,
                isDraft);
    }
}

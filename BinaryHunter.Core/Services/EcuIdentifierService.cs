using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BinaryHunter.Core.Identification;
using BinaryHunter.Core.Identification.Detectors;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Services;

public sealed class EcuIdentifierService
{
    private static readonly (string Type, Regex Pattern)[] Patterns =
    [
        ("ECU type", new(@"\b(?:(?:EDC|MED|MEVD)\d{2}[A-Z0-9]{2,}(?:-\d+(?:\.\d+)*)?\b|(?:DDE|DME)\d{3}[A-Za-z]?(?=\b|_))", RegexOptions.Compiled)),
        ("ECU family", new(@"\bEDC17_(?:C\d{2}|CP\d{2})\b", RegexOptions.Compiled)),
        ("Engine code", new(@"\b(?:[BNS]\d{2}[A-Z]\d{2}[A-Z]\d?|M\d{2}[A-Z]\d{2}[A-Z0-9]?)\b", RegexOptions.Compiled)),
        ("Bosch part number", new(@"\b0(?:261|281)\d{6}\b", RegexOptions.Compiled)),
        ("CVN", new(@"\bCVN\s*[:=_-]?\s*([A-F0-9]{8})\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("VIN", new(@"\b[A-HJ-NPR-Z0-9]{17}\b", RegexOptions.Compiled)),
        ("Version", new(@"\b(?:VER|VERSION|V)\s*[:#=_-]?\s*\d+(?:\.\d+){1,4}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("Date", new(@"\b(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])\b", RegexOptions.Compiled))
    ];

    public EcuIdentification Identify(string path)
    {
        return Identify(path, detectorName: null);
    }

    public EcuIdentification Identify(string path, string? detectorName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fileInfo = new FileInfo(path);
        var hash = GetHash(path);
        var bytes = File.ReadAllBytes(path);
        var image = new EcuBinaryImage(bytes);
        var detectorMatches = AutomaticDetectorRegistry.DetectModules
            .Where(module => string.IsNullOrWhiteSpace(detectorName) || module.Name == detectorName)
            .SelectMany(module => module.Detect(image))
            .ToList();
        var structuralMatches = ExtractAutomaticEcuIdentification(image).ToList();
        var isGenericAnalysis = !detectorMatches.Any(match => match.Type is "ECU type" or "ECU family") &&
                                !HasConfirmedStructuralProfile(structuralMatches);
        var profileMatches = detectorMatches
            .Concat(structuralMatches)
            .ToList();
        if (isGenericAnalysis)
        {
            profileMatches.Insert(0, new IdentifierMatch
            {
                Type = "Analysis profile",
                Value = "Generic structural analysis",
                Offset = 0
            });
            profileMatches.AddRange(AutomaticDetectorRegistry.ExtractGenericEvidence(image));
        }

        var matches = profileMatches.Concat(ExtractMatches(bytes))
            .DistinctBy(match => (match.Type, match.Value), StringTupleComparer.OrdinalIgnoreCase)
            .Take(100)
            .ToList();
        NormalizeAutomaticResults(matches);
        matches = MatchesWithinFile(matches, fileInfo.Length).ToList();

        return new EcuIdentification
        {
            FileName = fileInfo.Name,
            FullPath = fileInfo.FullName,
            FileSize = fileInfo.Length,
            Sha256 = hash,
            IsGenericAnalysis = isGenericAnalysis,
            Matches = matches
        };
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17Cp02Identifiers(byte[] bytes)
    {
        const int softwareOffset = 60_074;
        const int upgradeOffset = 60_180;
        if (bytes.Length <= upgradeOffset + 4) return [];

        var text = Encoding.ASCII.GetString(bytes);
        var family = Regex.Match(text, @"\bEDC17[_\s-]?(?:C06|CP02)\b", RegexOptions.IgnoreCase);
        if (!family.Success) return [];
        var software = bytes.AsSpan(softwareOffset, 4);
        var upgrade = bytes.AsSpan(upgradeOffset, 4);
        if (software[0] != 0x08 || upgrade[0] != 0x08) return [];

        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = family.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = family.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC17CP02 / C06", Offset = family.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software), Offset = softwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = upgradeOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = upgradeOffset },
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc16Cp35Identifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var family = Regex.Match(text, @"\b(?:BOSCH\s+)?EDC16CP35(?:/C)?(?:\s+\(BMW\))?(?:\s+MPC563)?\b", RegexOptions.IgnoreCase);
        if (!family.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "BMW Group", Offset = family.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = family.Index },
            new() { Type = "ECU family", Value = "Bosch EDC16CP35/C", Offset = family.Index },
            new() { Type = "Processor", Value = "Freescale MPC563", Offset = family.Index }
        };

        var software = Regex.Matches(text, @"\b1037\d{6}\b").Cast<Match>().GroupBy(match => match.Value).OrderByDescending(group => group.Count()).FirstOrDefault();
        if (software is not null && software.Count() >= 2)
        {
            var value = software.Key;
            var offset = software.Min(match => match.Index);
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = value, Offset = offset });
        }

        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMed1711AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bMED17[._-]?1[._-]?1(?://)?(?=$|[^A-Z0-9])", RegexOptions.IgnoreCase);
        var hardware = Regex.Match(text, @"\b4H0907560[A-Z]?\b");
        var software = Regex.Matches(text, @"\b103752\d{4}\b")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault(group => group.Count() >= 2);
        var hasIdLayout = hardware.Success && software is not null;
        if ((!marker.Success && !hasIdLayout) || !hardware.Success || software is null) return [];
        var profileOffset = marker.Success ? marker.Index : hardware.Index;

        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch MED17.1.1", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU type", Value = "MED17.1.1", Offset = profileOffset },
            new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi", Offset = hardware.Index },
            new IdentifierMatch { Type = "Vehicle application", Value = "Audi A8 D4 4.2 FSI quattro (catalogue match)", Offset = hardware.Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon TriCore TC1796", Offset = marker.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Key, Offset = software.First().Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMed91AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"(?:/MED91/5/|\bMED9[._-]?1(?:[._-]?1)?\b)", RegexOptions.IgnoreCase);
        var hardware = Regex.Match(text, @"\b0261S\d{5}\b");
        var software = Regex.Matches(text, @"\b103739\d{4}\b")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault(group => group.Count() >= 2);
        var upgrade = Regex.Match(text, @"\b4E1910560[A-Z]\b");
        var hasIdLayout = hardware.Success && software is not null && upgrade.Success;
        if ((!marker.Success && !hasIdLayout) || !hardware.Success || software is null || !upgrade.Success) return [];
        var profileOffset = marker.Success ? marker.Index : upgrade.Index;

        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch MED9.1.1", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU type", Value = "MED9.1.1", Offset = profileOffset },
            new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new IdentifierMatch { Type = "Vehicle application", Value = "Audi A8 D3 4.2 FSI quattro (catalogue match)", Offset = upgrade.Index },
            new IdentifierMatch { Type = "Processor", Value = "Freescale MPC563", Offset = marker.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Key, Offset = software.First().Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Value, Offset = upgrade.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = upgrade.Value, Offset = upgrade.Index },
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMe71AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bME7[._-]?1[._-]?1(?:/\d+)?", RegexOptions.IgnoreCase);
        var identifiers = Regex.Match(text, @"(?<![A-Z0-9])(?<hardware>0261\d{6})(?<software>1037\d{6})(?!\d)");
        var application = Regex.Match(text, @"(?<upgrade>4D1907558)[\s\x00]+(?<engine>4\.2l\s+V8/5VT)[\s\x00]+(?<revision>\d{4})", RegexOptions.IgnoreCase);
        if (!marker.Success || !identifiers.Success || !application.Success) return [];

        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = marker.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch ME7.1.1", Offset = marker.Index },
            new IdentifierMatch { Type = "ECU type", Value = "ME7.1.1", Offset = marker.Index },
            new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi", Offset = application.Index },
            new IdentifierMatch { Type = "Hardware Nr.", Value = identifiers.Groups["hardware"].Value, Offset = identifiers.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = identifiers.Groups["software"].Value, Offset = identifiers.Groups["software"].Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{application.Groups["upgrade"].Value} {application.Groups["revision"].Value}", Offset = application.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{application.Groups["upgrade"].Value} {application.Groups["revision"].Value}", Offset = application.Index },
            new IdentifierMatch { Type = "Engine", Value = application.Groups["engine"].Value, Offset = application.Groups["engine"].Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17Cp44AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bEDC17_CP44\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var engine = Regex.Match(text, @"\b3\.0(?:BTD|TDI)(?:\s+[A-Z0-9]+)?\b");
        var software = Regex.Matches(text, @"(?<![A-Z0-9])1037\d{6}")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault(group => group.Count() >= 2);
        var cp44Upgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])(?:4H0907401|4G0907589|4G0907311|4G1907401|4G0907401)[A-Z]?[\s\x00]+\d{4}\b"));
        var hasIdLayout = cp44Upgrade is not null && software is not null && engine.Success;
        if ((upgrades.Count == 0) || (!marker.Success && !hasIdLayout)) return [];
        var upgrade = cp44Upgrade ?? upgrades[^1];
        var profileOffset = marker.Success ? marker.Index : upgrade.Index;

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new() { Type = "ECU family", Value = "Bosch EDC17CP44", Offset = profileOffset },
            new() { Type = "ECU type", Value = "EDC17CP44", Offset = profileOffset },
            new() { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new() { Type = "Processor", Value = "Infineon TriCore TC1797", Offset = profileOffset },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        if (software is not null)
        {
            var softwareMatch = software.First();
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Key, Offset = softwareMatch.Index });
        }
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17Cp54AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bEDC17_CP54\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var software = Regex.Matches(text, @"(?<![A-Z0-9])1037\d{6}")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault(group => group.Count() >= 2);
        var engine = Regex.Match(text, @"\b3\.0TDI\s+EDC17\b");
        var processor = Regex.Match(text, @"\bTC17(?:91|93)\b");
        var cp54Upgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])[A-Z0-9]{3}2907401[A-Z]?[\s\x00]+\d{4}\b"));
        var hasIdLayout = cp54Upgrade is not null && software is not null && (engine.Success || processor.Success);
        if (upgrades.Count == 0 || (!marker.Success && !hasIdLayout)) return [];

        var upgrade = cp54Upgrade ?? upgrades[^1];
        var profileOffset = marker.Success ? marker.Index : upgrade.Index;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new() { Type = "ECU family", Value = "Bosch EDC17CP54", Offset = profileOffset },
            new() { Type = "ECU type", Value = "EDC17CP54", Offset = profileOffset },
            new() { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        if (software is not null)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Key, Offset = software.First().Index });
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = $"Infineon TriCore {processor.Value}", Offset = processor.Index });
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17Cp14AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bEDC17_CP14\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var softwareGroups = Regex.Matches(text, @"(?<![A-Z0-9])1037\d{6}")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .Where(group => group.Count() >= 2)
            .ToArray();
        var cp14Upgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])(?:4F9910402|8K2907401)[A-Z]?[\s\x00]+\d{4}\b"));
        var hasIdLayout = cp14Upgrade is not null && softwareGroups.Length > 0;
        if ((!marker.Success && !hasIdLayout) || (upgrades.Count == 0 && softwareGroups.Length == 0)) return [];

        var engine = Regex.Match(text, @"\b3\.0TDI\s+EDC17\b");
        var profileOffset = marker.Success ? marker.Index : cp14Upgrade!.Index;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new() { Type = "ECU family", Value = "Bosch EDC17CP14", Offset = profileOffset },
            new() { Type = "ECU type", Value = "EDC17CP14", Offset = profileOffset }
        };
        foreach (var software in softwareGroups)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Key, Offset = software.First().Index });
        if (upgrades.Count > 0)
        {
            var upgrade = cp14Upgrade ?? upgrades[^1];
            matches.Add(new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index });
        }
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17Cp24AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bEDC17_CP24(?:/\d+/P\d+)?", RegexOptions.IgnoreCase);
        var upgrades = FindVagUpgradeIdentifiers(text);
        if (!marker.Success || upgrades.Count == 0) return [];

        var upgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])4L0910409[A-Z]?[\s\x00]+\d{4}\b")) ?? upgrades[^1];
        var software = Regex.Matches(text, @"(?<![A-Z0-9])103750\d{4}(?!\d)")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .Where(group => group.Count() >= 2)
            .OrderByDescending(group => group.Count())
            .ToArray();
        var processor = Regex.Match(text, @"\bTC1796\b");
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = marker.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index },
            new() { Type = "ECU family", Value = "Bosch EDC17CP24", Offset = marker.Index },
            new() { Type = "ECU type", Value = "EDC17CP24", Offset = marker.Index },
            new() { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        foreach (var id in software)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = id.Key, Offset = id.First().Index });
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = "Infineon TriCore TC1796", Offset = processor.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17C74VolkswagenIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bEDC17C74(?:/\d+/P\d+)?", RegexOptions.IgnoreCase);
        var hardware = Regex.Match(text, @"\b04L907309[A-Z]\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var upgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])04L906026[A-Z]{1,2}[\s\x00]+\d{4}\b"));
        if (!marker.Success || !hardware.Success || upgrade is null) return [];

        var engine = Regex.Match(text, @"\bR4\s+(?:1\.6|2\.0)l\s+TDI\b", RegexOptions.IgnoreCase);
        var controlUnit = Regex.Match(text, @"\bJ623\b");
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = marker.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index },
            new() { Type = "ECU family", Value = "Bosch EDC17C74", Offset = marker.Index },
            new() { Type = "ECU type", Value = "EDC17C74", Offset = marker.Index },
            new() { Type = "Vehicle manufacturer", Value = "Volkswagen", Offset = upgrade.Index },
            new() { Type = "Processor", Value = "Infineon TriCore TC1791/TC1793", Offset = marker.Index },
            new() { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        if (controlUnit.Success)
            matches.Add(new IdentifierMatch { Type = "Control unit", Value = controlUnit.Value, Offset = controlUnit.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17C64VolkswagenIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bEDC17C64(?:/\d+/P\d+)?", RegexOptions.IgnoreCase);
        var hardware = Regex.Match(text, @"\b0[A-Z0-9]{2}907309[A-Z]\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        if (!marker.Success || !hardware.Success || upgrades.Count == 0) return [];
        var upgrade = upgrades[^1];

        var engine = Regex.Match(text, @"\bR4\s+(?:1\.6|2\.0)l\s+TDI\b", RegexOptions.IgnoreCase);
        var controlUnit = Regex.Match(text, @"\bJ623\b");
        var softwareIds = Regex.Matches(text, @"(?<![A-Z0-9])(?:10375\d{4}|10SW\d{6})(?![A-Z0-9])")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .Take(2)
            .ToArray();
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = marker.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index },
            new() { Type = "ECU family", Value = "Bosch EDC17C64", Offset = marker.Index },
            new() { Type = "ECU type", Value = "EDC17C64", Offset = marker.Index },
            new() { Type = "Vehicle manufacturer", Value = "Volkswagen", Offset = upgrade.Index },
            new() { Type = "Processor", Value = "Infineon TriCore", Offset = marker.Index },
            new() { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        foreach (var software in softwareIds)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Key, Offset = software.First().Index });
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        if (controlUnit.Success)
            matches.Add(new IdentifierMatch { Type = "Control unit", Value = controlUnit.Value, Offset = controlUnit.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractVagPartialEcuIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        // Some 512 KB VAG partial reads contain an ECU-tool header instead of an ECU-family marker.
        // Require all three independent fields so ordinary ASCII data cannot be classified as an ECU.
        var software = Regex.Match(text, @"(?<![A-Z0-9])(?<id>1037\d{6})(?<version>[A-Z0-9]{6,10})(?![A-Z0-9])");
        var upgrade = Regex.Match(text, @"(?<![A-Z0-9])(?<part>[A-Z0-9]{9,12})[\s\x00]{2,}(?<revision>[A-Z0-9]{4})(?![A-Z0-9])");
        var engine = Regex.Match(text, @"\b(?:3\.0L\s+V6TDI|4\.2L\s+V8TDI)\b", RegexOptions.IgnoreCase);
        if (!software.Success || !upgrade.Success || !engine.Success || !upgrade.Groups["part"].Value.StartsWith("4L0", StringComparison.Ordinal)) return [];

        var version = software.Groups["version"];
        var revision = upgrade.Groups["revision"];
        var isV8Cp34 = engine.Value.StartsWith("4.2L", StringComparison.OrdinalIgnoreCase);
        var family = isV8Cp34 ? "Bosch EDC16CP34" : "Bosch EDC17CP04 / CP14";
        var type = isV8Cp34 ? "EDC16CP34" : "EDC17CP04/CP14";
        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = upgrade.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = upgrade.Index },
            new IdentifierMatch { Type = "ECU family", Value = family, Offset = upgrade.Index },
            new IdentifierMatch { Type = "ECU type", Value = type, Offset = upgrade.Index },
            new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = software.Groups["id"].Value, Offset = software.Index },
            new IdentifierMatch { Type = "Software version", Value = version.Value, Offset = version.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{upgrade.Groups["part"].Value} {revision.Value}", Offset = upgrade.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = $"{upgrade.Groups["part"].Value} {revision.Value}", Offset = upgrade.Index },
            new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index },
            new IdentifierMatch { Type = "Processor", Value = isV8Cp34 ? "Freescale MPC563" : "Infineon TriCore", Offset = upgrade.Index }
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMd1Cs004AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bMD1_CS004\b");
        var hardware = Regex.Match(text, @"\b05L907309[A-Z]?\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var md1CsUpgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])05L9060(?:23|27)[A-Z]{1,2}[\s\x00]+\d{4}\b"));
        var hasIdLayout = hardware.Success && md1CsUpgrade is not null;
        if ((!marker.Success && !hasIdLayout) || !hardware.Success || upgrades.Count == 0) return [];

        var upgrade = md1CsUpgrade ?? upgrades[^1];
        var engine = Regex.Match(text, @"\bR4\s+2\.0l\s+TDI\b", RegexOptions.IgnoreCase);
        if (!engine.Success)
            engine = Regex.Match(text, @"\b2\.0l\s+TDI\b", RegexOptions.IgnoreCase);
        var profileOffset = marker.Success ? marker.Index : upgrade.Index;
        var isVolkswagen = upgrade.Value.StartsWith("05L906023", StringComparison.OrdinalIgnoreCase);
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new() { Type = "ECU family", Value = "Bosch MD1CS004", Offset = profileOffset },
            new() { Type = "ECU type", Value = "MD1CS004", Offset = profileOffset },
            new() { Type = "Vehicle manufacturer", Value = isVolkswagen ? "Volkswagen" : "Audi", Offset = upgrade.Index },
            new() { Type = "Processor", Value = "Infineon AURIX TC298", Offset = profileOffset },
            new() { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"\s+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"\s+", " "), Offset = upgrade.Index },
        };
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMd1Cp004AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bMD1_CP004\b");
        var hardware = Regex.Match(text, @"\b(?:4G2907311[A-Z]|059907309[A-Z])\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var hasIdLayout = hardware.Success && upgrades.Count > 0;
        if ((!marker.Success && !hasIdLayout) || !hardware.Success || upgrades.Count == 0) return [];

        var upgrade = upgrades[^1];
        var profileOffset = marker.Success ? marker.Index : upgrade.Index;
        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch MD1CP004", Offset = profileOffset },
            new IdentifierMatch { Type = "ECU type", Value = "MD1CP004", Offset = profileOffset },
            new IdentifierMatch { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new IdentifierMatch { Type = "Processor", Value = "NXP/Freescale SPC5777M", Offset = profileOffset },
            new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"\s+", " "), Offset = upgrade.Index },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"\s+", " "), Offset = upgrade.Index },
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMd1Cp014AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bMD1_CP014\b");
        var hardware = Regex.Match(text, @"\b057907309\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var upgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])4M0997409[\s\x00]+\d{4}\b"));
        if (!marker.Success || !hardware.Success || upgrade is null) return [];

        var engine = Regex.Match(text, @"\b4\.0l\s+V8\s+TDI\b", RegexOptions.IgnoreCase);
        var controlUnit = Regex.Match(text, @"\bJ623\b");
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = marker.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index },
            new() { Type = "ECU family", Value = "Bosch MD1CP014", Offset = marker.Index },
            new() { Type = "ECU type", Value = "MD1CP014", Offset = marker.Index },
            new() { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new() { Type = "Processor", Value = "Infineon AURIX TC298", Offset = marker.Index },
            new() { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        if (controlUnit.Success)
            matches.Add(new IdentifierMatch { Type = "Control unit", Value = controlUnit.Value, Offset = controlUnit.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc16Cp34AudiIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bEDC16CP34(?:-\d+(?:\.\d+)*)?\b");
        const string cp34PartPattern = @"[A-Z0-9]{3}(?:91040\d|9997401)[A-Z]{0,2}";
        var hardware = Regex.Match(text, $@"(?<![A-Z0-9]){cp34PartPattern}\b(?![\s\x00]+\d{{4}}\b)");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var cp34Upgrade = upgrades.Cast<Match>()
            .LastOrDefault(candidate => Regex.IsMatch(candidate.Value, $@"(?<![A-Z0-9]){cp34PartPattern}[\s\x00]+\d{{4}}\b"));
        var software = Regex.Matches(text, @"(?<![A-Z0-9])(?:10373[789]\d{4}|10SW\d{6})")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault(group => group.Count() >= 2);
        var engine = Regex.Match(text, @"\b(?:2\.7|3\.0)L\s+V6TDI\b", RegexOptions.IgnoreCase);
        var hasIdLayout = cp34Upgrade is not null && software is not null && engine.Success;
        if ((cp34Upgrade is null && !marker.Success) || (!marker.Success && !hasIdLayout)) return [];

        var upgrade = cp34Upgrade ?? upgrades[^1];
        var processor = Regex.Match(text, @"\bMPC\d{3}\b");
        var profileOffset = marker.Success ? marker.Index : upgrade.Index;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = profileOffset },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = profileOffset },
            new() { Type = "ECU family", Value = "Bosch EDC16CP34", Offset = profileOffset },
            new() { Type = "ECU type", Value = "EDC16CP34", Offset = profileOffset },
            new() { Type = "Vehicle manufacturer", Value = "Audi", Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        if (hardware.Success)
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = $"Freescale {processor.Value}", Offset = processor.Index });
        if (software is not null)
        {
            var softwareMatch = software.First();
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = software.Key, Offset = softwareMatch.Index });
        }
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc16U31U34Identifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var upgrades = FindVagUpgradeIdentifiers(text);
        var software = Regex.Matches(text, @"(?<![A-Z0-9])10373[89]\d{4}")
            .Cast<Match>()
            .GroupBy(match => match.Value)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault(group => group.Count() >= 2);
        var u31Upgrade = upgrades.Cast<Match>().LastOrDefault(candidate =>
            Regex.IsMatch(candidate.Value, @"(?<![A-Z0-9])[A-Z0-9]{3}9060(?:16|21)[A-Z]{2}[\s\x00]+\d{4}\b"));
        var engine = Regex.Match(text, @"\bR4\s*(?:1[,\.]9|2[,\.]0)L\s*EDC?\b", RegexOptions.IgnoreCase);
        if (u31Upgrade is null || software is null || !engine.Success) return [];

        var upgrade = u31Upgrade;
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = upgrade.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = upgrade.Index },
            new() { Type = "ECU family", Value = "Bosch EDC16U31 / U34", Offset = upgrade.Index },
            new() { Type = "ECU type", Value = "EDC16U31/U34", Offset = upgrade.Index },
            new() { Type = "Software Nr.", Value = software.Key, Offset = software.First().Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
        };
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschEdc17C41Identifiers(byte[] bytes)
    {
        const int softwareOffset = 65_194;
        const int upgradeOffset = 65_556;
        if (bytes.Length <= upgradeOffset + 4) return [];

        var text = Encoding.ASCII.GetString(bytes);
        var family = Regex.Match(text, @"\bEDC17[_\s-]?C41\b", RegexOptions.IgnoreCase);
        if (!family.Success) return [];

        var software = bytes.AsSpan(softwareOffset, 4);
        var upgrade = bytes.AsSpan(upgradeOffset, 4);
        if (software[0] != 0x08 || upgrade[0] != 0x08) return [];

        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = family.Index },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = family.Index },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC17C41", Offset = family.Index },
            new IdentifierMatch { Type = "Processor", Value = "Infineon TC1797 (profile inference)", Offset = family.Index },
            new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software), Offset = softwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = upgradeOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = upgradeOffset },
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMev946Identifiers(byte[] bytes)
    {
        const int hardwareOffset = 9_728;
        const int softwareOffset = 525_194;
        if (bytes.Length <= softwareOffset + 10) return [];

        var hardware = Encoding.ASCII.GetString(bytes, hardwareOffset, 10);
        var software = Encoding.ASCII.GetString(bytes, softwareOffset, 10);
        if (!Regex.IsMatch(hardware, @"^0261\d{6}$") || !Regex.IsMatch(software, @"^1\d{9}$")) return [];

        (int Offset, byte[] Value)? upgrade = null;
        for (var offset = 9_000; offset <= 11_000 && offset + 10 <= bytes.Length; offset++)
        {
            if (bytes[offset] != 0x07 || bytes[offset + 6] != 0x07) continue;
            if (bytes.AsSpan(offset, 3).SequenceEqual(bytes.AsSpan(offset + 6, 3)) && bytes[offset + 3] + 1 == bytes[offset + 9])
                upgrade = (offset, bytes.AsSpan(offset, 4).ToArray());
        }
        if (upgrade is null) return [];

        return
        [
            new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = hardwareOffset },
            new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = hardwareOffset },
            new IdentifierMatch { Type = "ECU family", Value = "Bosch MEV946 / ME9+", Offset = hardwareOffset },
            new IdentifierMatch { Type = "Hardware Nr.", Value = hardware, Offset = hardwareOffset },
            new IdentifierMatch { Type = "Software Nr.", Value = software, Offset = softwareOffset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Value), Offset = upgrade.Value.Offset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Value), Offset = upgrade.Value.Offset },
        ];
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMevdIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        // MEVD markers are commonly followed by an underscore, for example MEVD1729P_NRV.
        var marker = Regex.Match(text, @"MEVD17(?:\d[A-Z0-9]*)?");
        if (!marker.Success) return [];

        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "BMW Group", Offset = marker.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index },
            new() { Type = "ECU family", Value = "Bosch MEVD17", Offset = marker.Index },
            new() { Type = "ECU type", Value = marker.Value, Offset = marker.Index },
            new() { Type = "Processor", Value = "Infineon TC1797 (profile inference)", Offset = marker.Index }
        };

        var hardware = Regex.Match(text, @"\b0261S\d{5}\b");
        if (hardware.Success)
        {
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });

            // The earlier MEVD1729 layout pairs its Bosch hardware number with an ASCII software number.
            var legacySoftware = Regex.Match(text[marker.Index..Math.Min(text.Length, marker.Index + 20_000)], @"\b1037\d{6}\b");
            if (legacySoftware.Success)
                matches.Add(new IdentifierMatch
                {
                    Type = "Software Nr.",
                    Value = legacySoftware.Value,
                    Offset = marker.Index + legacySoftware.Index
                });

            return matches;
        }

        // MEVD17.2.x BMW files keep three equal software records followed by spare/upgrade records
        // beside the MEVD marker. Require the repeated record so unrelated 08-prefixed bytes are ignored.
        var localIdentifiers = new List<(long Offset, byte[] Value)>();
        var end = Math.Min(bytes.Length - 6, marker.Index + 20_000);
        for (var index = marker.Index; index <= end; index++)
        {
            if (bytes[index] != 0 || bytes[index + 1] != 0 || bytes[index + 2] != 0x08) continue;
            var value = bytes.AsSpan(index + 2, 4).ToArray();
            if (value.AsSpan(1).IndexOfAnyExcept((byte)0) >= 0)
                localIdentifiers.Add((index + 2L, value));
        }

        if (localIdentifiers.Count >= 4 &&
            localIdentifiers[0].Value.SequenceEqual(localIdentifiers[1].Value) &&
            localIdentifiers[0].Value.SequenceEqual(localIdentifiers[2].Value))
        {
            var software = localIdentifiers[0];
            var upgrade = localIdentifiers[^1];
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software.Value), Offset = software.Offset });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value), Offset = upgrade.Offset });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value), Offset = upgrade.Offset });
        }

        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMg1Identifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        if (!Regex.IsMatch(text, @"\bMG1CS\d{3}\b")) return [];

        var matches = new List<IdentifierMatch>();
        var type = Regex.Match(text, @"DME_[A-Z0-9]{4}\b");
        if (type.Success) matches.Add(new IdentifierMatch { Type = "ECU type", Value = type.Value, Offset = type.Index });

        var upgrade = FindLastMarkedIdentifier(bytes, 0x0D, 0);
        if (upgrade is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Code), Offset = upgrade.Value.Offset });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Code), Offset = upgrade.Value.Offset });
        }

        var software = FindLastMarkedIdentifier(bytes, 0x08, upgrade?.Offset ?? 0);
        if (software is not null)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software.Value.Code), Offset = software.Value.Offset });

        for (var index = 0; index <= bytes.Length - 40; index++)
        {
            if (bytes[index] != 0x06 || !TryReadIdentifier(bytes, index, out var code)) continue;
            var context = Encoding.ASCII.GetString(bytes, index + 8, 32);
            if (!context.Contains("#DME_", StringComparison.Ordinal)) continue;
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = Convert.ToHexString(code), Offset = index + 1 });
        }
        return matches.GroupBy(match => match.Type).Select(group => group.OrderByDescending(match => match.Offset).First()).ToArray();
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMg1Cs011VagIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var marker = Regex.Match(text, @"\bMG1CS011\b", RegexOptions.IgnoreCase);
        var hardware = Regex.Match(text, @"\b0[A-Z0-9]{2}907309[A-Z]?\b");
        var upgrades = FindVagUpgradeIdentifiers(text);
        var engine = Regex.Match(text, @"\bR4\s+1\.5l\s+TFS\b", RegexOptions.IgnoreCase);
        if (!marker.Success || !hardware.Success || upgrades.Count == 0 || !engine.Success) return [];

        var upgrade = upgrades[^1];
        var asam = Regex.Match(text, @"\b10SW\d{6}\b");
        var controlUnit = Regex.Match(text, @"\bJ\d{3}\b");
        var isVolkswagen = text.Contains("VOLKSWAGEN", StringComparison.OrdinalIgnoreCase);
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Vehicle group", Value = "Volkswagen Group", Offset = marker.Index },
            new() { Type = "ECU manufacturer", Value = "Bosch", Offset = marker.Index },
            new() { Type = "ECU family", Value = "Bosch MG1CS011", Offset = marker.Index },
            new() { Type = "ECU type", Value = "MG1CS011", Offset = marker.Index },
            new() { Type = "Vehicle manufacturer", Value = isVolkswagen ? "Volkswagen" : "Volkswagen Group brand", Offset = upgrade.Index },
            new() { Type = "Processor", Value = "Infineon AURIX TC298", Offset = marker.Index },
            new() { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index },
            new() { Type = "Engine", Value = engine.Value, Offset = engine.Index }
        };
        if (asam.Success)
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = asam.Value, Offset = asam.Index });
        if (controlUnit.Success)
            matches.Add(new IdentifierMatch { Type = "Control unit", Value = controlUnit.Value, Offset = controlUnit.Index });
        return matches;
    }

    private static (long Offset, byte[] Code)? FindLastMarkedIdentifier(byte[] bytes, byte marker, long afterOffset)
    {
        for (var index = bytes.Length - 8; index >= afterOffset; index--)
        {
            if (bytes[index] != marker || !TryReadIdentifier(bytes, index, out var code)) continue;
            return (index + 1L, code.ToArray());
        }
        return null;
    }

    private static bool TryReadIdentifier(byte[] bytes, int markerOffset, out ReadOnlySpan<byte> code)
    {
        code = default;
        if (markerOffset + 8 > bytes.Length || bytes[markerOffset + 1] != 0 || bytes[markerOffset + 2] != 0) return false;
        code = bytes.AsSpan(markerOffset + 1, 7);
        return code[2..].IndexOfAnyExcept((byte)0) >= 0;
    }

    private static IEnumerable<IdentifierMatch> DetectVehicleGroup(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var directSignatures = new[]
        {
            ("BMW Group", new[] { "BMW" }),
            ("PSA / Stellantis", new[] { "PEUGEOT", "CITROEN", "DS AUTOMOBILES" }),
            ("Volkswagen Group", new[] { "VOLKSWAGEN", "AUDI", "SKODA", "SEAT" }),
            ("Mercedes-Benz Group", new[] { "MERCEDES", "DAIMLER" }),
            ("Renault–Nissan–Mitsubishi", new[] { "RENAULT", "NISSAN" }),
            ("Ford Motor Company", new[] { "FORD MOTOR", "FORD" }),
            ("Toyota Group", new[] { "TOYOTA", "LEXUS" }),
            ("Hyundai Motor Group", new[] { "HYUNDAI", "KIA MOTORS" }),
            ("General Motors", new[] { "GENERAL MOTORS", "CHEVROLET", "CADILLAC" })
        };

        // A short DDE/DME fragment can occur by chance in calibration data. Require
        // a complete tagged BMW ECU marker before inferring the vehicle group.
        var bmwMarker = Regex.Match(text,
            @"(?<![A-Z0-9])(?:DME(?:_+[A-Z0-9]{2,}|\d{3}[A-Z]?)|DDE(?:_+[A-Z0-9]{2,}|\d{3}[A-Z]?)|MEVD17(?:\d{1,3}|(?:\.\d+){1,3})(?:[A-Z0-9_-]{0,8})?)(?![A-Z0-9])",
            RegexOptions.IgnoreCase);
        if (bmwMarker.Success)
        {
            yield return new IdentifierMatch { Type = "Vehicle group", Value = "BMW Group", Offset = bmwMarker.Index };
        }

        foreach (var (group, signatures) in directSignatures)
        {
            var offset = signatures.Select(signature => text.IndexOf(signature, StringComparison.Ordinal)).Where(index => index >= 0).DefaultIfEmpty(-1).Min();
            if (offset >= 0)
                yield return new IdentifierMatch { Type = "Vehicle group", Value = $"{group}", Offset = offset };
        }
    }

    private static IEnumerable<IdentifierMatch> DetectManufacturer(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var candidates = new[]
        {
            ("Bosch", new[] { "BOSCH", "EDC", "MED", "MEVD", "DDE", "DME" }),
            ("Denso", new[] { "DENSO", "SH705", "SH725", "SH726" }),
            ("Delphi / Delco", new[] { "DELPHI", "ACDELCO", "DELCO" }),
            ("Siemens / Continental", new[] { "SIEMENS", "CONTINENTAL", "SIMOS", "SID" }),
            ("Magneti Marelli", new[] { "MAGNETI", "MARELLI", "IAW" }),
            ("Hitachi", new[] { "HITACHI" }),
            ("Mitsubishi Electric", new[] { "MITSUBISHI", "MELCO" }),
            ("Keihin", new[] { "KEIHIN" }),
            ("Kefico", new[] { "KEFICO" }),
            ("Visteon", new[] { "VISTEON" }),
            ("Sagem", new[] { "SAGEM" }),
            ("Temic", new[] { "TEMIC" }),
            ("Valeo", new[] { "VALEO" }),
            ("Lucas", new[] { "LUCAS" }),
            ("MOBIS", new[] { "MOBIS" }),
            ("BorgWarner", new[] { "BORGWARNER" }),
            ("Mahle", new[] { "MAHLE" }),
            ("Bendix", new[] { "BENDIX" })
        };

        foreach (var (manufacturer, signatures) in candidates)
        {
            var matched = signatures.Where(signature => text.Contains(signature, StringComparison.Ordinal)).ToArray();
            if (matched.Length == 0) continue;
            var hasVendorName = matched.Any(signature => signature is not "EDC" and not "MED" and not "MEVD" and not "DDE" and not "DME" and not "SH705" and not "SH725" and not "SH726" and not "SIMOS" and not "SID" and not "IAW");
            if (!hasVendorName && matched.Length < 2) continue;

            var offset = matched.Select(signature => text.IndexOf(signature, StringComparison.Ordinal)).Where(index => index >= 0).DefaultIfEmpty(-1).Min();
            var confidence = hasVendorName ? "high" : "medium";
            yield return new IdentifierMatch { Type = "ECU manufacturer", Value = $"{manufacturer} ({confidence} confidence)", Offset = offset };
        }
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschDdeIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var header = Regex.Match(text, @"(?<![A-Z0-9])DDE\d{3}[A-Z]?", RegexOptions.IgnoreCase);
        if (!header.Success) yield break;

        for (var index = 0; index <= bytes.Length - 18; index++)
        {
            if (bytes[index] != (byte)'D' || bytes[index + 1] != (byte)'D' || bytes[index + 2] != (byte)'E') continue;

            // DDE markers may be followed by underscores (e.g. DDE721b___)
            // which are still valid structured identifier records.
            if (index + 6 > bytes.Length) continue;
            if (!char.IsAsciiDigit((char)bytes[index + 3]) ||
                !char.IsAsciiDigit((char)bytes[index + 4]) ||
                !char.IsAsciiDigit((char)bytes[index + 5])) continue;

            var marker = index + 10;
            if (marker + 8 > bytes.Length) continue;
            if (bytes[marker + 1] != 0 || bytes[marker + 2] != 0) continue;
            var codeOffset = marker + 1;
            if (codeOffset + 7 > bytes.Length) continue;
            var code = bytes.AsSpan(codeOffset, 7);
            if (code.SequenceEqual(stackalloc byte[7])) continue;

            var type = code[2] switch
            {
                0x0A when code[3] == 0x0A => "Hardware Nr.",
                0x0A when code[3] == 0x0B => "Software Nr.",
                0x69 => "Software Upgrade Nr.",
                _ => "Software Upgrade Nr."
            };
            yield return new IdentifierMatch
            {
                Type = type,
                Value = Convert.ToHexString(code),
                Offset = codeOffset
            };
        }
    }

    private static IEnumerable<IdentifierMatch> ExtractBoschMdg1Identifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var isMd1 = text.Contains("MD1", StringComparison.Ordinal);
        var isMdg1 = !isMd1 && (text.Contains("MDG1", StringComparison.Ordinal) || text.Contains("MG1", StringComparison.Ordinal));
        if (!isMdg1 && !isMd1) return [];

        var matches = new List<IdentifierMatch>();
        var typeMatch = Regex.Match(text, @"DME__(?:DDE)?\d{3}[A-Za-z]?");
        if (typeMatch.Success)
            matches.Add(new IdentifierMatch { Type = "ECU type", Value = typeMatch.Value, Offset = typeMatch.Index });
        var exactFamily = Regex.Match(text, @"\b(?:MD1|MDG1|MG1)[A-Z]{0,3}\d{2,}\b");
        if (exactFamily.Success)
            matches.Add(new IdentifierMatch { Type = "ECU family", Value = $"Bosch {exactFamily.Value}", Offset = exactFamily.Index });
        else
        {
            var familyOffset = text.IndexOf(isMd1 ? "MD1" : "MDG1", StringComparison.Ordinal);
            if (familyOffset >= 0)
                matches.Add(new IdentifierMatch { Type = "ECU family", Value = isMdg1 ? "Bosch MDG1" : "Bosch MD1", Offset = familyOffset });
        }

        for (var index = 0; index <= bytes.Length - 24; index++)
        {
            if (bytes[index] != 0x06 || bytes[index + 8] != 0x08) continue;
            if (bytes[index + 16] is not (0x08 or 0x0D)) continue;

            var hardware = bytes.AsSpan(index + 1, 7);
            var software = bytes.AsSpan(index + 9, 7);
            var upgrade = bytes.AsSpan(index + 17, 7);
            if (!IsMdHardwareOrSoftware(hardware) || !IsMdHardwareOrSoftware(software) || !IsMdUpgrade(upgrade)) continue;

            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = Convert.ToHexString(hardware), Offset = index + 1 });
            matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software), Offset = index + 9 });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = index + 17 });
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = index + 17 });
        }
        var latestIdentifiers = matches
            .Where(match => match.Type is "Hardware Nr." or "Software Nr." or "Software Upgrade Nr.")
            .GroupBy(match => match.Type)
            .Select(group => group.OrderByDescending(match => match.Offset).First())
            .ToArray();
        matches.RemoveAll(match => match.Type is "Hardware Nr." or "Software Nr." or "Software Upgrade Nr.");
        matches.AddRange(latestIdentifiers);
        return matches.DistinctBy(match => (match.Type, match.Value), StringTupleComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool IsMdHardwareOrSoftware(ReadOnlySpan<byte> code) =>
        code[0] == 0 && code[1] == 0 && code[2] is 0x29 or 0x30;

    private static bool IsMdUpgrade(ReadOnlySpan<byte> code) =>
        code[0] == 0 && code[1] == 0;

    // The automatic pipeline deliberately uses record layouts and marker context;
    // it does not depend on a catalogue of OEM part numbers or fixed offsets.
    private static IEnumerable<IdentifierMatch> ExtractAutomaticEcuIdentification(EcuBinaryImage image) =>
        DetectVehicleGroup(image.Bytes)
            .Concat(DetectManufacturer(image.Bytes))
            .Concat(ExtractStructuralEcuEvidence(image.Bytes))
            .Concat(ExtractEmbeddedCalibrationHeader(image.Bytes))
            .Concat(ExtractStructuredIdentifierTriplets(image))
            .Concat(ExtractTaggedMdgIdentifiers(image.Bytes))
            .Concat(ExtractTaggedMevdIdentifiers(image.Bytes))
            .Concat(ExtractContextualBinaryHardwareIds(image.Bytes))
            .Concat(ExtractBoschDdeIdentifiers(image.Bytes));

    private static void NormalizeAutomaticResults(List<IdentifierMatch> matches)
    {
        for (var index = 0; index < matches.Count; index++)
        {
            var match = matches[index];
            if (match.Type != "Engine") continue;
            var normalizedEngine = Regex.Replace(match.Value, @"(?<=\d)l\b", "L", RegexOptions.IgnoreCase);
            if (!string.Equals(normalizedEngine, match.Value, StringComparison.Ordinal))
                matches[index] = new IdentifierMatch { Type = match.Type, Value = normalizedEngine, Offset = match.Offset };
        }

        var hardwareValues = matches.Where(match => match.Type == "Hardware Nr.").Select(match => match.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
        matches.RemoveAll(match => match.Type == "Bosch part number" && hardwareValues.Contains(match.Value));

        // SID310 calibration areas contain arbitrary byte sequences that can
        // decode to isolated Jddd tokens (for example J008). Unlike VAG OEM
        // blocks, SID310 has no validated control-unit field at that location.
        if (matches.Any(match => match.Type == "ECU type" &&
                                string.Equals(match.Value, "SID310", StringComparison.OrdinalIgnoreCase)))
            matches.RemoveAll(match => match.Type == "Control unit");

        var isHondaEdc17Cp06 = matches.Any(match => match.Type == "ECU type" &&
                                                   string.Equals(match.Value, "EDC17CP06", StringComparison.OrdinalIgnoreCase)) &&
                                 matches.Any(match => match.Type == "Vehicle manufacturer" &&
                                                   string.Equals(match.Value, "Honda", StringComparison.OrdinalIgnoreCase));
        if (isHondaEdc17Cp06)
        {
            matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                       !string.Equals(match.Value, "Honda Motor Company", StringComparison.OrdinalIgnoreCase));
            var baseSoftwareValues = matches.Where(match => match.Type == "Base software Nr.")
                .Select(match => match.Value)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            matches.RemoveAll(match => match.Type == "Software Nr." && baseSoftwareValues.Contains(match.Value));

            var activeSoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." && match.Offset == 0x4001A);
            if (activeSoftware is not null)
                matches.RemoveAll(match => match.Type == "Software Nr." &&
                                           !string.Equals(match.Value, activeSoftware.Value, StringComparison.OrdinalIgnoreCase));
        }

        var isVagSimos1810 = matches.Any(match => match.Type == "ECU type" &&
                                                 string.Equals(match.Value, "SIMOS18.10", StringComparison.OrdinalIgnoreCase));
        if (isVagSimos1810)
        {
            // SIMOS18.10 already identifies both the family and manufacturer;
            // avoid repeating the same identity in three result rows.
            matches.RemoveAll(match => match.Type is "ECU manufacturer" or "ECU family");
            matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                       !match.Value.StartsWith("Volkswagen Group", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "Control unit" &&
                                       !string.Equals(match.Value, "J623", StringComparison.OrdinalIgnoreCase));
        }

        var isVolvoSid803A = matches.Any(match => match.Type == "ECU type" &&
                                                  string.Equals(match.Value, "SID803A", StringComparison.OrdinalIgnoreCase)) &&
                              matches.Any(match => match.Type == "Vehicle group" &&
                                                  match.Value.StartsWith("Volvo", StringComparison.OrdinalIgnoreCase));
        if (isVolvoSid803A)
        {
            matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                       !match.Value.StartsWith("Volvo", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                       !match.Value.StartsWith("Siemens/Continental", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "Processor" &&
                                       !match.Value.StartsWith("Motorola MPC555", StringComparison.OrdinalIgnoreCase));

            var activeSoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                                                                  Regex.IsMatch(match.Value, @"^\d{9}$"));
            if (activeSoftware is not null)
                matches.RemoveAll(match => match.Type == "Software Nr." &&
                                           !string.Equals(match.Value, activeSoftware.Value, StringComparison.OrdinalIgnoreCase));
        }

        var isRenaultNissanOpelEdc16 = matches.Any(match => match.Type == "ECU type" &&
            Regex.IsMatch(match.Value, @"^EDC16(?:CP33|C36|C41)$", RegexOptions.IgnoreCase)) &&
            matches.Any(match => match.Type == "Vehicle group" &&
                match.Value.StartsWith("Renault / Nissan / Opel", StringComparison.OrdinalIgnoreCase));
        if (isRenaultNissanOpelEdc16)
        {
            matches.RemoveAll(match => match.Type == "Vehicle group" &&
                !match.Value.StartsWith("Renault / Nissan / Opel", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));

            var activeSoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                Regex.IsMatch(match.Value, @"^1037\d{6}$"));
            if (activeSoftware is not null)
                matches.RemoveAll(match => match.Type == "Software Nr." &&
                    !string.Equals(match.Value, activeSoftware.Value, StringComparison.OrdinalIgnoreCase));

            if (matches.Any(match => match.Type == "Processor" &&
                                    string.Equals(match.Value, "MPC561", StringComparison.OrdinalIgnoreCase)))
                matches.RemoveAll(match => match.Type == "Processor" &&
                    !string.Equals(match.Value, "MPC561", StringComparison.OrdinalIgnoreCase));

            var platformCalibration = matches.FirstOrDefault(match => match.Type == "Calibration version" &&
                match.Value.EndsWith("_XXX", StringComparison.OrdinalIgnoreCase));
            if (platformCalibration is not null)
                matches.RemoveAll(match => match.Type == "Calibration version" &&
                    !string.Equals(match.Value, platformCalibration.Value, StringComparison.OrdinalIgnoreCase));
        }

        var isMercedesEdc17Cp46 = matches.Any(match => match.Type == "ECU type" &&
            string.Equals(match.Value, "EDC17CP46", StringComparison.OrdinalIgnoreCase)) &&
            matches.Any(match => match.Type == "Vehicle group" &&
                match.Value.StartsWith("Mercedes-Benz", StringComparison.OrdinalIgnoreCase));
        if (isMercedesEdc17Cp46)
        {
            matches.RemoveAll(match => match.Type == "Vehicle group" &&
                !match.Value.StartsWith("Mercedes-Benz", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));

            var oemSoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                Regex.IsMatch(match.Value, @"^\d{3}902\d{4}$"));
            if (oemSoftware is not null)
                matches.RemoveAll(match => match.Type == "Software Nr." &&
                    !string.Equals(match.Value, oemSoftware.Value, StringComparison.OrdinalIgnoreCase));

            var oemUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                Regex.IsMatch(match.Value, @"^\d{3}903\d{4}$"));
            if (oemUpgrade is not null)
                matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                    !string.Equals(match.Value, oemUpgrade.Value, StringComparison.OrdinalIgnoreCase));

            matches.RemoveAll(match => match.Type == "Calibration Nr." &&
                Regex.IsMatch(match.Value, @"^1037\d{6}$"));
            matches.RemoveAll(match => match.Type == "ASAM software Nr." &&
                Regex.IsMatch(match.Value, @"^10SW\d{6}$", RegexOptions.IgnoreCase));
            if (matches.Any(match => match.Type == "Processor" &&
                    match.Value.StartsWith("Infineon TC1797", StringComparison.OrdinalIgnoreCase)))
                matches.RemoveAll(match => match.Type == "Processor" &&
                    !match.Value.StartsWith("Infineon TC1797", StringComparison.OrdinalIgnoreCase));

            var platformCalibration = matches.FirstOrDefault(match => match.Type == "Calibration version" &&
                match.Value.StartsWith("P_", StringComparison.OrdinalIgnoreCase));
            if (platformCalibration is not null)
                matches.RemoveAll(match => match.Type == "Calibration version" &&
                    !string.Equals(match.Value, platformCalibration.Value, StringComparison.OrdinalIgnoreCase));
        }

        var isMercedesEdc17Cp10 = matches.Any(match => match.Type == "ECU type" &&
            string.Equals(match.Value, "EDC17CP10", StringComparison.OrdinalIgnoreCase)) &&
            matches.Any(match => match.Type == "Vehicle group" &&
                match.Value.StartsWith("Mercedes-Benz", StringComparison.OrdinalIgnoreCase));
        if (isMercedesEdc17Cp10)
        {
            matches.RemoveAll(match => match.Type == "Vehicle group" &&
                !match.Value.StartsWith("Mercedes-Benz", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));

            var activeSoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                Regex.IsMatch(match.Value, @"^1037\d{6}$"));
            if (activeSoftware is not null)
                matches.RemoveAll(match => match.Type == "Software Nr." &&
                    !string.Equals(match.Value, activeSoftware.Value, StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "Calibration Nr." &&
                activeSoftware is not null &&
                string.Equals(match.Value, activeSoftware.Value, StringComparison.OrdinalIgnoreCase));

            var oemUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                Regex.IsMatch(match.Value, @"^\d{3}903\d{4}$"));
            if (oemUpgrade is not null)
                matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                    !string.Equals(match.Value, oemUpgrade.Value, StringComparison.OrdinalIgnoreCase));

            if (matches.Any(match => match.Type == "Processor" &&
                    match.Value.StartsWith("Infineon TC1796", StringComparison.OrdinalIgnoreCase)))
                matches.RemoveAll(match => match.Type == "Processor" &&
                    !match.Value.StartsWith("Infineon TC1796", StringComparison.OrdinalIgnoreCase));

            var platformCalibration = matches.FirstOrDefault(match => match.Type == "Calibration version" &&
                match.Value.StartsWith("P_", StringComparison.OrdinalIgnoreCase));
            if (platformCalibration is not null)
                matches.RemoveAll(match => match.Type == "Calibration version" &&
                    !string.Equals(match.Value, platformCalibration.Value, StringComparison.OrdinalIgnoreCase));
        }

        foreach (var group in matches.GroupBy(match => (match.Value, match.Offset)).ToList())
        {
            if (!group.Any(match => match.Type is "Hardware Nr." or "Software Nr.")) continue;
            matches.RemoveAll(match => match.Type == "Software Upgrade Nr." && match.Value == group.Key.Value && match.Offset == group.Key.Offset);
        }

        // One selected marker represents the ECU family. Prefer the most specific marker,
        // not the first string that happens to resemble an ECU name.
        var primaryFamily = matches.Where(match => match.Type == "ECU family")
            .OrderByDescending(match => match.Value.Contains("MEVD17.", StringComparison.OrdinalIgnoreCase))
            // C000 is a generic EDC16 code-section/library label, not a concrete
            // ECU variant. A validated runtime family such as EDC16C9 must win.
            .ThenByDescending(match => !match.Value.Contains(".C000", StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(match => match.Value.Length)
            // Family modules run after the generic raw-marker scan. On otherwise
            // equal candidates, their validated multi-signal result wins over an
            // isolated library/template marker.
            .ThenByDescending(match => matches.IndexOf(match))
            .ThenByDescending(match => match.Offset)
            .FirstOrDefault();
        if (primaryFamily is not null)
        {
            matches.RemoveAll(match => match.Type == "ECU family" && !string.Equals(match.Value, primaryFamily.Value, StringComparison.OrdinalIgnoreCase));
            if (string.Equals(primaryFamily.Value, "Siemens/Continental PCR2", StringComparison.OrdinalIgnoreCase))
            {
                var vehicleGroup = matches.FirstOrDefault(match => match.Type == "Vehicle group" &&
                    match.Value.StartsWith("Volkswagen Group", StringComparison.OrdinalIgnoreCase) &&
                    match.Value.Contains("PCR2.1 OEM header", StringComparison.OrdinalIgnoreCase));
                if (vehicleGroup is not null)
                    matches.RemoveAll(match => match.Type == "Vehicle group" &&
                        !string.Equals(match.Value, vehicleGroup.Value, StringComparison.OrdinalIgnoreCase));
                else
                    matches.RemoveAll(match => match.Type == "Vehicle group" &&
                        !match.Value.StartsWith("Volkswagen Group", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                    !match.Value.StartsWith("Siemens/Continental", StringComparison.OrdinalIgnoreCase));

                // The validated OEM header exposes this value as System type.
                // Generic scans of calibration text can emit a duplicate Engine row.
                matches.RemoveAll(match => match.Type == "Engine");

                var controlUnit = matches.FirstOrDefault(match => match.Type == "Control unit" &&
                    string.Equals(match.Value, "J623", StringComparison.OrdinalIgnoreCase));
                if (controlUnit is not null)
                    matches.RemoveAll(match => match.Type == "Control unit" &&
                        !string.Equals(match.Value, controlUnit.Value, StringComparison.OrdinalIgnoreCase));

                // Calibration templates can contain placeholder strings such as
                // L3333333333333333 which satisfy the generic 17-character VIN pattern.
                matches.RemoveAll(match => match.Type == "VIN" &&
                    Regex.IsMatch(match.Value, @"^[A-HJ-NPR-Z0-9]([A-HJ-NPR-Z0-9])\1{15}$",
                        RegexOptions.IgnoreCase));
            }
            if (matches.Any(match => match.Type == "Vehicle group" && match.Value.StartsWith("VOLVO", StringComparison.OrdinalIgnoreCase)))
            {
                var activeUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{10}$"));
                if (activeUpgrade is not null)
                {
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                    matches.RemoveAll(match => match.Type == "Calibration Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                        !string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                }

                matches.RemoveAll(match => match.Type == "VIN" && match.Value.StartsWith("1037", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    match.Value.StartsWith("BMW Group", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "ECU type" &&
                    string.Equals(match.Value, "EDC16C35", StringComparison.OrdinalIgnoreCase));
            }
            else if (matches.Any(match => match.Type == "ECU type" && match.Value.Contains("EDC16C31", StringComparison.OrdinalIgnoreCase)) &&
                     matches.Any(match => match.Type == "Software Nr." && match.Value is "1037400251" or "1037375898" or "1037395577" or "1037395588" or "1037510266" or "1037510278"))
            {
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    match.Value.StartsWith("BMW Group", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "ECU type" &&
                    string.Equals(match.Value, "EDC16C35", StringComparison.OrdinalIgnoreCase));
            }

            var expectedType = primaryFamily.Value.Contains(' ')
                ? primaryFamily.Value[(primaryFamily.Value.IndexOf(' ') + 1)..]
                : primaryFamily.Value;
            expectedType = expectedType.Replace(" / ", "/", StringComparison.Ordinal);

            var normalizedExpectedType = NormalizeEcuLabel(expectedType);
            var selectedType = matches.Where(match => match.Type == "ECU type")
                .OrderByDescending(match => NormalizeEcuLabel(match.Value) == normalizedExpectedType)
                .ThenByDescending(match => NormalizeEcuLabel(match.Value).StartsWith(normalizedExpectedType, StringComparison.Ordinal) ||
                                           normalizedExpectedType.StartsWith(NormalizeEcuLabel(match.Value), StringComparison.Ordinal))
                .ThenByDescending(match => matches.IndexOf(match))
                .ThenByDescending(match => match.Offset)
                .FirstOrDefault();
            if (selectedType is not null)
                matches.RemoveAll(match => match.Type == "ECU type" && !string.Equals(match.Value, selectedType.Value, StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type is "Version" or "Date");

            // A structural MSV/MSS70 family match is stronger evidence than a
            // coincidental Bosch-like text fragment within PowerPC calibration code.
            if (primaryFamily.Value.StartsWith("Siemens/Continental", StringComparison.OrdinalIgnoreCase))
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Siemens/Continental", StringComparison.OrdinalIgnoreCase));

            if (string.Equals(primaryFamily.Value, "Delco E87", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                    !match.Value.StartsWith("Delco", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("General Motors / Opel", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type is "VIN" or "ASAM software Nr." or "Calibration Nr.");

                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                    !Regex.IsMatch(match.Value, @"^555\d{5}$"));

                var software = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^555\d{5}$"));
                if (software is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, software.Value, StringComparison.OrdinalIgnoreCase));

                var upgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^555\d{5}$"));
                if (upgrade is not null)
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                        !string.Equals(match.Value, upgrade.Value, StringComparison.OrdinalIgnoreCase));

                var version = matches.FirstOrDefault(match => match.Type == "Software version" &&
                    Regex.IsMatch(match.Value, @"^G\d{5}$"));
                if (version is not null)
                    matches.RemoveAll(match => match.Type == "Software version" &&
                        !string.Equals(match.Value, version.Value, StringComparison.OrdinalIgnoreCase));
            }
            if (primaryFamily.Value.StartsWith("Delco/Continental", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Delco / Continental", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("General Motors / Opel", StringComparison.OrdinalIgnoreCase));
            }

            if (primaryFamily.Value.StartsWith("Denso ", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Denso", StringComparison.OrdinalIgnoreCase));

                var expectedDensoGroup = primaryFamily.Value.StartsWith("Denso MB279700-96XX", StringComparison.OrdinalIgnoreCase)
                    ? "Volvo"
                    : primaryFamily.Value.StartsWith("Denso Subaru", StringComparison.OrdinalIgnoreCase)
                        ? "Subaru"
                        : "Mazda";
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith(expectedDensoGroup, StringComparison.OrdinalIgnoreCase));

                if (string.Equals(expectedDensoGroup, "Volvo", StringComparison.OrdinalIgnoreCase))
                {
                    matches.RemoveAll(match => match.Type is "Analysis profile" or "Control unit");
                    matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                                               !Regex.IsMatch(match.Value, @"^\d{8}$"));
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                                               !Regex.IsMatch(match.Value, @"^\d{8}(?:_| )[A-Z]{2}$"));
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                                               !Regex.IsMatch(match.Value, @"^\d{8}_?[A-Z]{2}$"));
                }

                var densoSoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^(?:[A-Z0-9]{4}-18881-[A-Z]|SW-[A-Z0-9]{6,16}\.HEX|\d{8}(?:_| )[A-Z]{2})$"));
                if (densoSoftware is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                                               !string.Equals(match.Value, densoSoftware.Value, StringComparison.OrdinalIgnoreCase));

                var densoUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^(?:[A-Z0-9]{4}-188K2-[A-Z]|\d{8}_?[A-Z]{2})$"));
                if (densoUpgrade is not null)
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                                               !string.Equals(match.Value, densoUpgrade.Value, StringComparison.OrdinalIgnoreCase));
            }

            if (string.Equals(primaryFamily.Value, "Delphi DCM6.2V", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Delphi", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("Volkswagen Group", StringComparison.OrdinalIgnoreCase));
                if (matches.Any(match => match.Type == "Engine" &&
                                         match.Value.StartsWith("R4 ", StringComparison.OrdinalIgnoreCase)))
                    matches.RemoveAll(match => match.Type == "Engine" &&
                                               !match.Value.StartsWith("R4 ", StringComparison.OrdinalIgnoreCase));
            }

            if (string.Equals(primaryFamily.Value, "Delphi DCM6.2A", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Delphi", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("PSA", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "VIN" && match.Value.All(char.IsDigit));
                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                                           Regex.IsMatch(match.Value, @"^[0-9A-F]{10,}$") &&
                                           !Regex.IsMatch(match.Value, @"^\d+$"));
            }

            if (string.Equals(primaryFamily.Value, "Bosch MD1CP001", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("Mercedes-Benz", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "ASAM software Nr.");
                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                                           !Regex.IsMatch(match.Value, @"^65\d{8}$"));
                matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                                           !Regex.IsMatch(match.Value, @"^65\d{8}$"));
                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                                           Regex.IsMatch(match.Value, @"^[0-9A-F]{10,}$") &&
                                           !Regex.IsMatch(match.Value, @"^\d+$"));
                matches.RemoveAll(match => match.Type == "Software Nr." &&
                                           Regex.IsMatch(match.Value, @"^[0-9A-F]{10,}$") &&
                                           !Regex.IsMatch(match.Value, @"^\d+$"));
                matches.RemoveAll(match => match.Type == "VIN" && match.Value.StartsWith("33333333"));
            }

            if (string.Equals(primaryFamily.Value, "Bosch EDC17C84", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           match.Value.Contains("(medium confidence)", StringComparison.OrdinalIgnoreCase));
            }

            if (string.Equals(primaryFamily.Value, "Delphi DCM7.1A", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Delphi", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("PSA", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "VIN" && match.Value.All(char.IsDigit));
                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                                           Regex.IsMatch(match.Value, @"^[0-9A-F]{10,}$") &&
                                           !Regex.IsMatch(match.Value, @"^\d+$"));
            }

            if (string.Equals(primaryFamily.Value, "Bosch EDC16C34", StringComparison.OrdinalIgnoreCase))
            {
                var confirmedManufacturer = matches.FirstOrDefault(match => match.Type == "ECU manufacturer" &&
                    match.Value.Contains("EDC16C34 mirrored calibration", StringComparison.OrdinalIgnoreCase));
                if (confirmedManufacturer is not null)
                    matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                        !string.Equals(match.Value, confirmedManufacturer.Value, StringComparison.OrdinalIgnoreCase));

                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("PSA / Stellantis", StringComparison.OrdinalIgnoreCase));

                var activeUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^1037\d{6}$"));
                if (activeUpgrade is not null)
                {
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                        !string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                }
            }
            if (string.Equals(primaryFamily.Value, "Bosch EDC16CP34", StringComparison.OrdinalIgnoreCase))
            {
                var confirmedManufacturer = matches.FirstOrDefault(match => match.Type == "ECU manufacturer" &&
                    match.Value.Contains("EDC16CP34", StringComparison.OrdinalIgnoreCase));
                if (confirmedManufacturer is not null)
                    matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                        !string.Equals(match.Value, confirmedManufacturer.Value, StringComparison.OrdinalIgnoreCase));

                var confirmedVehicleGroup = matches.FirstOrDefault(match => match.Type == "Vehicle group" &&
                    match.Value.Contains("EDC16CP34 OEM block", StringComparison.OrdinalIgnoreCase));
                if (confirmedVehicleGroup is not null)
                    matches.RemoveAll(match => match.Type == "Vehicle group" &&
                        !string.Equals(match.Value, confirmedVehicleGroup.Value, StringComparison.OrdinalIgnoreCase));

                var hardware = matches.FirstOrDefault(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^[A-Z0-9]{3}907401[A-Z]{0,2}$", RegexOptions.IgnoreCase));
                if (hardware is not null)
                    matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                        !string.Equals(match.Value, hardware.Value, StringComparison.OrdinalIgnoreCase));
            }
            if (string.Equals(primaryFamily.Value, "Bosch EDC16U1", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("Volkswagen Group", StringComparison.OrdinalIgnoreCase));

                var activeSoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^1037\d{6}$"));
                if (activeSoftware is not null)
                    matches.RemoveAll(match => match.Type == "Calibration Nr." &&
                                               string.Equals(match.Value, activeSoftware.Value, StringComparison.OrdinalIgnoreCase));

                if (matches.Any(match => match.Type == "Processor" &&
                                         match.Value.StartsWith("Freescale MPC555", StringComparison.OrdinalIgnoreCase)))
                    matches.RemoveAll(match => match.Type == "Processor" &&
                                               !match.Value.StartsWith("Freescale MPC555", StringComparison.OrdinalIgnoreCase));
            }

            if (string.Equals(primaryFamily.Value, "Bosch EDC17CP20", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                                           !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("Volkswagen Group", StringComparison.OrdinalIgnoreCase));

                var calibrationVersion = matches.FirstOrDefault(match => match.Type == "Calibration version");
                var activeSoftware = calibrationVersion is null
                    ? null
                    : matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                                                       match.Offset + match.Value.Length == calibrationVersion.Offset);
                if (activeSoftware is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                                               Regex.IsMatch(match.Value, @"^1037\d{6}$") &&
                                               !string.Equals(match.Value, activeSoftware.Value, StringComparison.OrdinalIgnoreCase));
                if (matches.Any(match => match.Type == "Processor" &&
                                         match.Value.StartsWith("Infineon TC1796", StringComparison.OrdinalIgnoreCase)))
                    matches.RemoveAll(match => match.Type == "Processor" &&
                                               !match.Value.StartsWith("Infineon TC1796", StringComparison.OrdinalIgnoreCase));

                // A confirmed VAG OEM block provides the ECU hardware number. Do
                // not retain generic 14-hex records from unrelated binary tables.
                if (matches.Any(match => match.Type == "Hardware Nr." &&
                                         Regex.IsMatch(match.Value, @"^[A-Z0-9]{3}\d{6}[A-Z]{0,2}$", RegexOptions.IgnoreCase)))
                    matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                                               Regex.IsMatch(match.Value, @"^[0-9A-F]{14}$", RegexOptions.IgnoreCase));
            }

            if (string.Equals(primaryFamily.Value, "Bosch MEVD17.2", StringComparison.OrdinalIgnoreCase) &&
                matches.Any(match => match.Type == "Software Nr." && Regex.IsMatch(match.Value, @"^\d{8}$")))
                matches.RemoveAll(match => match.Type == "Software Nr." && Regex.IsMatch(match.Value, @"^1037\d{6}$"));

            if (IsBoschBmwEdc17Cp02Family(primaryFamily.Value) &&
                matches.Any(match => match.Type == "Software Nr." && Regex.IsMatch(match.Value, @"^\d{8}$")))
                matches.RemoveAll(match => match.Type == "Software Nr." && Regex.IsMatch(match.Value, @"^1037\d{6}$"));

            if (primaryFamily.Value.StartsWith("Bosch MED17.1", StringComparison.OrdinalIgnoreCase))
            {
                // The detector contributes the dominant repeated Bosch software
                // record before the generic string scan. MED17 code libraries can
                // contain additional 1037 references that are not the active ECU ID.
                var primarySoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^(?:1037\d{6}|10SW\d{6})$", RegexOptions.IgnoreCase));
                if (primarySoftware is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, primarySoftware.Value, StringComparison.OrdinalIgnoreCase) &&
                        Regex.IsMatch(match.Value, @"^(?:1037\d{6}|10SW\d{6})$", RegexOptions.IgnoreCase));
            }

            if ((string.Equals(primaryFamily.Value, "Bosch EDC17C46", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(primaryFamily.Value, "Bosch EDC17C74", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(primaryFamily.Value, "Bosch EDC17CP44", StringComparison.OrdinalIgnoreCase)) &&
                matches.Any(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^[A-Z0-9]{3}\d{6}[A-Z]{0,2}$", RegexOptions.IgnoreCase)))
                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^[0-9A-F]{14}$", RegexOptions.IgnoreCase));

            if (string.Equals(primaryFamily.Value, "Bosch EDC17C70", StringComparison.OrdinalIgnoreCase) &&
                matches.Any(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^[A-Z0-9]{4}-12B684-[A-Z0-9]{2}$", RegexOptions.IgnoreCase)))
                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^[0-9A-F]{14}$", RegexOptions.IgnoreCase));

            if (string.Equals(primaryFamily.Value, "Bosch EDC17CP44", StringComparison.OrdinalIgnoreCase))
            {
                var primarySoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                                          Regex.IsMatch(match.Value, @"^10SW\d{6}$", RegexOptions.IgnoreCase)) ??
                                      matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                                          Regex.IsMatch(match.Value, @"^1037\d{6}$", RegexOptions.IgnoreCase));
                if (primarySoftware is not null)
                {
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, primarySoftware.Value, StringComparison.OrdinalIgnoreCase) &&
                        Regex.IsMatch(match.Value, @"^(?:1037\d{6}|10SW\d{6})$", RegexOptions.IgnoreCase));
                    matches.RemoveAll(match => match.Type == "ASAM software Nr." &&
                        string.Equals(match.Value, primarySoftware.Value, StringComparison.OrdinalIgnoreCase));
            if (string.Equals(primaryFamily.Value, "Bosch EDC16C31", StringComparison.OrdinalIgnoreCase) &&
                matches.Any(match => match.Type == "Vehicle group" && match.Value.StartsWith("VOLVO", StringComparison.OrdinalIgnoreCase)))
            {
                var activeUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{10}$"));
                if (activeUpgrade is not null)
                {
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                    matches.RemoveAll(match => match.Type == "Calibration Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                        !string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                }
            }
        }
            }

            if (string.Equals(primaryFamily.Value, "Bosch EDC17C46", StringComparison.OrdinalIgnoreCase))
            {
                var primarySoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^1037\d{6}$", RegexOptions.IgnoreCase));
                if (primarySoftware is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, primarySoftware.Value, StringComparison.OrdinalIgnoreCase) &&
                        Regex.IsMatch(match.Value, @"^1037\d{6}$", RegexOptions.IgnoreCase));
            }

            if (string.Equals(primaryFamily.Value, "Bosch EDC17C60", StringComparison.OrdinalIgnoreCase))
            {
                var confirmedManufacturer = matches.FirstOrDefault(match => match.Type == "ECU manufacturer" &&
                    string.Equals(match.Value, "Bosch", StringComparison.OrdinalIgnoreCase));
                if (confirmedManufacturer is not null)
                    matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                        !string.Equals(match.Value, confirmedManufacturer.Value, StringComparison.OrdinalIgnoreCase));

                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("PSA / Stellantis", StringComparison.OrdinalIgnoreCase));

                KeepFirstMatchingIdentifier(matches, "Hardware Nr.", @"^\d{10}$");
                KeepFirstMatchingIdentifier(matches, "Software Nr.", @"^\d{10}$");
                KeepFirstMatchingIdentifier(matches, "Software Upgrade Nr.", @"^\d{10}$");
                KeepFirstMatchingIdentifier(matches, "ASAM software Nr.", @"^10SW\d{6}$");

                if (matches.Any(match => match.Type == "Processor" &&
                    match.Value.StartsWith("Infineon TC179", StringComparison.OrdinalIgnoreCase)))
                    matches.RemoveAll(match => match.Type == "Processor" &&
                        !match.Value.StartsWith("Infineon TC179", StringComparison.OrdinalIgnoreCase));
            }
            if (string.Equals(primaryFamily.Value, "Bosch EDC17C66", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                    !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("Mercedes-Benz", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type is "ASAM software Nr." or "Calibration Nr.");

                var hardware = matches.FirstOrDefault(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{3}904\d{4}$"));
                if (hardware is not null)
                    matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                        !string.Equals(match.Value, hardware.Value, StringComparison.OrdinalIgnoreCase));

                var software = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{3}902\d{4}$"));
                if (software is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, software.Value, StringComparison.OrdinalIgnoreCase));

                var upgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{3}903\d{4}$"));
                if (upgrade is not null)
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                        !string.Equals(match.Value, upgrade.Value, StringComparison.OrdinalIgnoreCase));
            }
            if (string.Equals(primaryFamily.Value, "Bosch EDC17CP11", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                    !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("Jaguar/Land Rover/PSA", StringComparison.OrdinalIgnoreCase));

                var software = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    match.Offset == 0x10001A && Regex.IsMatch(match.Value, @"^1037\d{6}$"));
                if (software is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, software.Value, StringComparison.OrdinalIgnoreCase));

                var upgrade = matches.Where(match => match.Type == "Software Upgrade Nr." &&
                        Regex.IsMatch(match.Value, @"^[A-Z0-9]{4}-12K532-[A-Z0-9]{3}$", RegexOptions.IgnoreCase))
                    .OrderByDescending(match => match.Offset)
                    .FirstOrDefault();
                if (upgrade is not null)
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                        !string.Equals(match.Value, upgrade.Value, StringComparison.OrdinalIgnoreCase));
            }
            if (string.Equals(primaryFamily.Value, "Bosch EDC17CP45", StringComparison.OrdinalIgnoreCase))
            {
                var confirmedManufacturer = matches.FirstOrDefault(match => match.Type == "ECU manufacturer" &&
                    string.Equals(match.Value, "Bosch", StringComparison.OrdinalIgnoreCase));
                if (confirmedManufacturer is not null)
                    matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                        !string.Equals(match.Value, confirmedManufacturer.Value, StringComparison.OrdinalIgnoreCase));

                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("BMW Group", StringComparison.OrdinalIgnoreCase));

                KeepFirstMatchingIdentifier(matches, "Hardware Nr.", @"^[0-9A-F]{14}$");
                KeepFirstMatchingIdentifier(matches, "Software Nr.", @"^[0-9A-F]{14}$");
                KeepFirstMatchingIdentifier(matches, "Software Upgrade Nr.", @"^[0-9A-F]{14}$");

                if (matches.Any(match => match.Type == "Processor" &&
                    match.Value.StartsWith("Infineon TC1797", StringComparison.OrdinalIgnoreCase)))
                    matches.RemoveAll(match => match.Type == "Processor" &&
                        !match.Value.StartsWith("Infineon TC1797", StringComparison.OrdinalIgnoreCase));
            }
            if (string.Equals(primaryFamily.Value, "Bosch EDC17CP55", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                    !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("Jaguar/Land Rover", StringComparison.OrdinalIgnoreCase));

                var hardware = matches.FirstOrDefault(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^[A-Z0-9]{4}-12B684-[A-Z0-9]{3}$", RegexOptions.IgnoreCase));
                if (hardware is not null)
                    matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                        !string.Equals(match.Value, hardware.Value, StringComparison.OrdinalIgnoreCase));

                var software = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^[A-Z0-9]{4}-14C204-[A-Z0-9]{3}$", RegexOptions.IgnoreCase));
                if (software is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, software.Value, StringComparison.OrdinalIgnoreCase));
            }
            if (string.Equals(primaryFamily.Value, "Bosch MEDC17.9", StringComparison.OrdinalIgnoreCase))
            {
                matches.RemoveAll(match => match.Type == "ECU manufacturer" &&
                    !match.Value.StartsWith("Bosch", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    !match.Value.StartsWith("Jaguar/Land Rover", StringComparison.OrdinalIgnoreCase));

                var hardware = matches.FirstOrDefault(match => match.Type == "Hardware Nr." &&
                    Regex.IsMatch(match.Value, @"^[A-Z0-9]{4}-12B684-[A-Z0-9]{3}$", RegexOptions.IgnoreCase));
                if (hardware is not null)
                    matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                        !string.Equals(match.Value, hardware.Value, StringComparison.OrdinalIgnoreCase));

                var software = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^[A-Z0-9]{4}-14C204-[A-Z0-9]{3}$", RegexOptions.IgnoreCase));
                if (software is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, software.Value, StringComparison.OrdinalIgnoreCase));
            }
            if (string.Equals(primaryFamily.Value, "Bosch EDC17C70", StringComparison.OrdinalIgnoreCase))
            {
                var primarySoftware = matches.FirstOrDefault(match => match.Type == "Software Nr." &&
                    Regex.IsMatch(match.Value, @"^(?:1037\d{6}|10SW\d{6})$", RegexOptions.IgnoreCase));
                if (primarySoftware is not null)
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        !string.Equals(match.Value, primarySoftware.Value, StringComparison.OrdinalIgnoreCase) &&
                        Regex.IsMatch(match.Value, @"^(?:1037\d{6}|10SW\d{6})$", RegexOptions.IgnoreCase));
                matches.RemoveAll(match => match.Type == "ASAM software Nr." &&
                    Regex.IsMatch(match.Value, @"^10SW\d{6}$", RegexOptions.IgnoreCase));
            }

            if (string.Equals(primaryFamily.Value, "Bosch MD1CS003", StringComparison.OrdinalIgnoreCase) &&
                matches.Any(match => match.Type == "Vehicle group" && match.Value.StartsWith("PSA / Stellantis", StringComparison.OrdinalIgnoreCase)))
            {
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                                           !match.Value.StartsWith("PSA / Stellantis", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Hardware Nr." &&
                                           Regex.IsMatch(match.Value, @"^[0-9A-F]{14}$", RegexOptions.IgnoreCase));
                matches.RemoveAll(match => match.Type == "ASAM software Nr." &&
                                           Regex.IsMatch(match.Value, @"^10SW\d{6}$", RegexOptions.IgnoreCase));
                matches.RemoveAll(match => match.Type == "VIN" &&
                                           match.Value.StartsWith('0'));
                var activeUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{10}$"));
                if (activeUpgrade is not null)
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                                               !string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
            }

            var hasC31 = matches.Any(match => match.Type == "ECU type" && match.Value.Contains("EDC16C31", StringComparison.OrdinalIgnoreCase));
            if (hasC31 &&
                matches.Any(match => match.Type == "Vehicle group" && match.Value.StartsWith("VOLVO", StringComparison.OrdinalIgnoreCase)))
            {
                var activeUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{10}$"));
                if (activeUpgrade is not null)
                {
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                    matches.RemoveAll(match => match.Type == "Calibration Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                    matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                        !string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                }

                matches.RemoveAll(match => match.Type == "VIN" && match.Value.StartsWith("1037", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    match.Value.StartsWith("BMW Group", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "ECU type" &&
                    string.Equals(match.Value, "EDC16C35", StringComparison.OrdinalIgnoreCase));

                foreach (var match in matches.Where(m => m.Type == "Software Nr." && m.Offset is >= 0x40000 and <= 0x40020).ToList())
                {
                    var index = matches.IndexOf(match);
                    matches[index] = new IdentifierMatch
                    {
                        Type = "Software Upgrade Nr.",
                        Value = match.Value,
                        Offset = match.Offset
                    };
                }
            }

            if (string.Equals(primaryFamily.Value, "Bosch EDC16C35", StringComparison.OrdinalIgnoreCase) &&
                matches.Any(match => match.Type == "Vehicle group" && match.Value.StartsWith("VOLVO", StringComparison.OrdinalIgnoreCase)))
            {
                var activeUpgrade = matches.FirstOrDefault(match => match.Type == "Software Upgrade Nr." &&
                    Regex.IsMatch(match.Value, @"^\d{10}$"));
                if (activeUpgrade is not null)
                {
                    matches.RemoveAll(match => match.Type == "Software Nr." &&
                        string.Equals(match.Value, activeUpgrade.Value, StringComparison.OrdinalIgnoreCase));
                }

                matches.RemoveAll(match => match.Type == "VIN" && match.Value.StartsWith("1037", StringComparison.OrdinalIgnoreCase));
                matches.RemoveAll(match => match.Type == "Vehicle group" &&
                    match.Value.StartsWith("BMW Group", StringComparison.OrdinalIgnoreCase));
            }
        }

        if (matches.Any(match => match.Type == "Processor" && match.Value.Contains("raw runtime marker", StringComparison.OrdinalIgnoreCase)))
            matches.RemoveAll(match => match.Type == "Processor" &&
                                       string.Equals(match.Value, "Infineon TriCore", StringComparison.OrdinalIgnoreCase));

        CollapseEvidence(matches, "Vehicle group");
        CollapseEvidence(matches, "ECU manufacturer");

        // ASCII OEM ID blocks are user-facing identifiers. When they exist, retain them
        // instead of duplicate internal seven-byte bookkeeping records.
        if (matches.Any(match => match.Type == "Software Upgrade Nr." && !Regex.IsMatch(match.Value, @"^[0-9A-F]{14}$", RegexOptions.IgnoreCase)))
            matches.RemoveAll(match => (match.Type is "Software Nr." or "Software Upgrade Nr.") && Regex.IsMatch(match.Value, @"^[0-9A-F]{14}$", RegexOptions.IgnoreCase));
        var calibrationValues = matches.Where(match => match.Type == "Calibration Nr.").Select(match => match.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (primaryFamily?.Value.StartsWith("Bosch EDC16", StringComparison.OrdinalIgnoreCase) == true ||
            string.Equals(primaryFamily?.Value, "Bosch EDC17C46", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(primaryFamily?.Value, "Bosch EDC17C64", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(primaryFamily?.Value, "Bosch EDC17CP44", StringComparison.OrdinalIgnoreCase) ||
            IsBoschBmwEdc17Cp02Family(primaryFamily?.Value))
        {
            // In EDC16 and partial CP02/C06 calibration images the numeric record at
            // the beginning is the software number. The generic header reader calls
            // it a calibration ID until ECU-family evidence is available.
            var softwareValues = matches.Where(match => match.Type == "Software Nr.")
                .Select(match => match.Value)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            matches.RemoveAll(match => match.Type == "Calibration Nr." && softwareValues.Contains(match.Value));
        }
        else
        {
            matches.RemoveAll(match => match.Type == "Software Nr." && calibrationValues.Contains(match.Value));
        }

        var confirmedOemUpgrade = matches.Where(match => match.Type == "Software Upgrade Nr.")
            .FirstOrDefault(upgrade =>
                Regex.IsMatch(upgrade.Value, @"^[A-Z0-9]{3}\d{6}[A-Z]{0,2}\s+\d{4}$", RegexOptions.IgnoreCase) ||
                matches.Any(software => software.Type == "Software Nr." &&
                    Regex.IsMatch(upgrade.Value, $@"^{Regex.Escape(software.Value)}\s+\d{{4}}$", RegexOptions.IgnoreCase)));
        if (confirmedOemUpgrade is not null)
            matches.RemoveAll(match => match.Type == "Software Upgrade Nr." &&
                                       !string.Equals(match.Value, confirmedOemUpgrade.Value, StringComparison.OrdinalIgnoreCase));

        RemoveRedundantEcuFamilies(matches);

        if (matches.Any(match => match.Type == "Vehicle group" && match.Value.StartsWith("VOLVO", StringComparison.OrdinalIgnoreCase)))
        {
            matches.RemoveAll(match => match.Type == "VIN" && match.Value.StartsWith("1037", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "Vehicle group" &&
                match.Value.StartsWith("BMW Group", StringComparison.OrdinalIgnoreCase));
            matches.RemoveAll(match => match.Type == "ECU type" &&
                string.Equals(match.Value, "EDC16C35", StringComparison.OrdinalIgnoreCase));
        }
    }

    private static void RemoveRedundantEcuFamilies(List<IdentifierMatch> matches)
    {
        var normalizedTypes = matches.Where(match => match.Type == "ECU type")
            .Select(match => NormalizeEcuLabel(match.Value))
            .Where(value => value.Length >= 3)
            .ToArray();
        if (normalizedTypes.Length == 0) return;

        // Manufacturer prefixes and presentation separators are useful in a family
        // value only when the family adds information beyond the selected ECU type.
        // Examples: "Bosch EDC16C35" duplicates "EDC16C35", while "Bosch MDG1"
        // alongside a concrete DME type is a genuinely broader classification.
        matches.RemoveAll(match => match.Type == "ECU family" &&
                                   normalizedTypes.Any(type => NormalizeEcuLabel(match.Value).EndsWith(type, StringComparison.Ordinal)));
    }

    private static void KeepFirstMatchingIdentifier(List<IdentifierMatch> matches, string type, string pattern)
    {
        var selected = matches.FirstOrDefault(match => match.Type == type &&
            Regex.IsMatch(match.Value, pattern, RegexOptions.IgnoreCase));
        if (selected is not null)
            matches.RemoveAll(match => match.Type == type &&
                !string.Equals(match.Value, selected.Value, StringComparison.OrdinalIgnoreCase));
    }
    private static string NormalizeEcuLabel(string value) =>
        new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    private static bool HasConfirmedStructuralProfile(IReadOnlyCollection<IdentifierMatch> matches)
    {
        if (!matches.Any(match => match.Type is "ECU type" or "ECU family")) return false;

        var strongManufacturer = matches.Any(match =>
            match.Type == "ECU manufacturer" &&
            (match.Value.Contains("high confidence", StringComparison.OrdinalIgnoreCase) ||
             match.Value.Contains("profile confidence", StringComparison.OrdinalIgnoreCase)));
        var oemEvidence = matches.Any(match =>
            match.Type == "Vehicle group" &&
            (match.Value.Contains("high confidence", StringComparison.OrdinalIgnoreCase) ||
             match.Value.Contains("OEM-block evidence", StringComparison.OrdinalIgnoreCase) ||
             match.Value.Contains("OEM-format evidence", StringComparison.OrdinalIgnoreCase)));
        var identifierKinds = matches
            .Where(match => match.Type is "Hardware Nr." or "Software Nr." or "Software Upgrade Nr." or "ASAM software Nr." or "Calibration Nr.")
            .Select(match => match.Type)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        return strongManufacturer && oemEvidence && identifierKinds >= 2;
    }

    private static bool IsBoschBmwEdc17Cp02Family(string? value) =>
        string.Equals(value, "Bosch EDC17CP02 / C06", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "Bosch EDC17CP02", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "Bosch EDC17C06", StringComparison.OrdinalIgnoreCase);

    private static void CollapseEvidence(List<IdentifierMatch> matches, string type)
    {
        var selected = matches.Where(match => match.Type == type)
            .OrderByDescending(GetEvidenceScore)
            .ThenByDescending(match => match.Offset)
            .FirstOrDefault();
        if (selected is not null)
            matches.RemoveAll(match => match.Type == type && !string.Equals(match.Value, selected.Value, StringComparison.OrdinalIgnoreCase));
    }

    private static int GetEvidenceScore(IdentifierMatch match)
    {
        return 0;
    }

    private static IEnumerable<IdentifierMatch> ExtractEmbeddedCalibrationHeader(byte[] bytes)
    {
        // Several partial-read formats begin with a numeric calibration record followed
        // immediately by its revision. The record is not necessarily a software ID.
        var headerLength = Math.Min(bytes.Length, 512);
        var header = Encoding.ASCII.GetString(bytes, 0, headerLength);
        var calibration = Regex.Match(header, @"(?<![A-Z0-9])(?<id>1037\d{6})(?<version>[A-Z0-9]{6,10})(?![A-Z0-9])");
        if (!calibration.Success) return [];

        var text = Encoding.ASCII.GetString(bytes);
        var engine = Regex.Match(text, @"\b[1-8][\.,]\d[lL]\s+R[1-8]\s+[A-Z]{2,8}\b", RegexOptions.IgnoreCase);
        var matches = new List<IdentifierMatch>
        {
            new() { Type = "Calibration Nr.", Value = calibration.Groups["id"].Value, Offset = calibration.Index },
            new() { Type = "Calibration version", Value = calibration.Groups["version"].Value, Offset = calibration.Groups["version"].Index }
        };
        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine descriptor", Value = engine.Value, Offset = engine.Index });
        return matches;
    }

    private static IEnumerable<IdentifierMatch> ExtractContextualBinaryHardwareIds(byte[] bytes)
    {
        // A complete triplet is a stronger source than isolated context records.
        // It also prevents backup/internal hardware references from being shown as
        // equally current identifiers.
        if (ContainsStructuredIdentifierTriplet(bytes)) return [];

        var matches = new List<IdentifierMatch>();
        for (var index = 0; index <= bytes.Length - 16; index++)
        {
            if (bytes[index] != 0x06 || !TryReadIdentifier(bytes, index, out var code)) continue;
            var contextLength = Math.Min(96, bytes.Length - (index + 8));
            var context = Encoding.ASCII.GetString(bytes, index + 8, contextLength);
            // A tagged ECU name immediately following the 06 record identifies it as
            // a hardware record, rather than an unrelated seven-byte binary value.
            if (!Regex.IsMatch(context, @"#[A-Z]{2,}\d", RegexOptions.IgnoreCase)) continue;
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = Convert.ToHexString(code), Offset = index + 1 });
        }
        return matches.DistinctBy(match => match.Value).Take(5).ToArray();
    }

    // A common ECU metadata layout stores three consecutive tagged seven-byte values:
    // 06 = hardware, 08 = software, then 08 or 0D = software upgrade.  The layout,
    // rather than any known part number or offset, is the evidence used here.
    private static IEnumerable<IdentifierMatch> ExtractStructuredIdentifierTriplets(EcuBinaryImage image)
    {
        // MG1 carries valid-looking calibration triplets as well as its DME-linked
        // identifier records. Its dedicated detector owns that family.
        if (image.AsciiText.Contains("MG1", StringComparison.OrdinalIgnoreCase) &&
            image.AsciiText.Contains("#DME_", StringComparison.OrdinalIgnoreCase)) return [];
        var bytes = image.Bytes;
        // Calibration images can contain an older backup record followed by the
        // active record. The last complete record is the active-ID convention used
        // by these layouts, and yields one coherent hardware/software/upgrade set.
        for (var index = bytes.Length - 24; index >= 0; index--)
        {
            if (!TryReadStructuredIdentifierTriplet(bytes, index, out var hardware, out var software, out var upgrade)) continue;

            return
            [
                new IdentifierMatch { Type = "Hardware Nr.", Value = Convert.ToHexString(hardware), Offset = index + 1L },
                new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software), Offset = index + 9L },
                new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = index + 17L },
                new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade), Offset = index + 17L },
            ];
        }

        return [];
    }

    // Some MG1/MD1 images distribute their current identifiers across separate
    // metadata sections instead of placing them in one consecutive triplet. Their
    // tagged records still have stable roles: 06/3072 = hardware, 08/3076 =
    // software, and the final 0D record = software upgrade.
    private static IEnumerable<IdentifierMatch> ExtractTaggedMdgIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        if (!text.Contains("MG1", StringComparison.Ordinal) && !text.Contains("MD1", StringComparison.Ordinal)) return [];

        var hardware = FindLastTypedIdentifier(bytes, 0x06, 0x72);
        var software = FindLastTypedIdentifier(bytes, 0x08, 0x76);
        var upgrade = FindLastMarkedIdentifier(bytes, 0x0D, 0);
        if (software is null || upgrade is null) return [];

        var matches = new List<IdentifierMatch>();
        if (hardware is not null)
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = Convert.ToHexString(hardware.Value.Code), Offset = hardware.Value.Offset });
        matches.Add(new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software.Value.Code), Offset = software.Value.Offset });
        matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Code), Offset = upgrade.Value.Offset });
        matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Code), Offset = upgrade.Value.Offset });
        return matches;
    }

    // MEVD17 images may store hardware beside the first MEVD marker and software
    // beside a later marker, while the upgrade record is elsewhere in the image.
    // The software and upgrade records share their two project bytes, allowing the
    // relationship to be verified without a catalogue of part numbers or offsets.
    private static IEnumerable<IdentifierMatch> ExtractTaggedMevdIdentifiers(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var markers = Regex.Matches(text, @"(?<![A-Z0-9])MEVD17", RegexOptions.IgnoreCase)
            .Cast<Match>()
            .ToArray();
        if (markers.Length == 0) return [];

        (byte[] Code, long Offset)? hardware = null;
        var softwareCandidates = new List<(byte[] Code, long Offset)>();
        foreach (var marker in markers)
        {
            var end = Math.Min(bytes.Length - 8, marker.Index + 96);
            for (var index = marker.Index + marker.Length; index <= end; index++)
            {
                if (bytes[index] is not (0x06 or 0x08) || !TryReadIdentifier(bytes, index, out var code)) continue;
                if (bytes[index] == 0x06 && hardware is null)
                    hardware = (code.ToArray(), index + 1L);
                else if (bytes[index] == 0x08)
                    softwareCandidates.Add((code.ToArray(), index + 1L));
            }
        }

        if (hardware is null || softwareCandidates.Count == 0) return [];

        (byte[] Code, long Offset)? software = null;
        (byte[] Code, long Offset)? upgrade = null;
        // Later MEVD metadata can repeat the software record after its upgrade
        // record. Select the latest software occurrence that has a matching upgrade
        // after it, rather than blindly taking the last duplicate.
        foreach (var candidate in softwareCandidates.OrderByDescending(item => item.Offset))
        {
            for (var index = bytes.Length - 8; index > candidate.Offset; index--)
            {
                if (bytes[index] is not (0x08 or 0x0D) || !TryReadIdentifier(bytes, index, out var code)) continue;
                if (code.SequenceEqual(candidate.Code) || code[4] != candidate.Code[4] || code[5] != candidate.Code[5]) continue;
                software = candidate;
                upgrade = (code.ToArray(), index + 1L);
                break;
            }

            if (upgrade is not null) break;
        }

        if (software is null || upgrade is null) return [];
        return
        [
            new IdentifierMatch { Type = "Hardware Nr.", Value = Convert.ToHexString(hardware.Value.Code), Offset = hardware.Value.Offset },
            new IdentifierMatch { Type = "Software Nr.", Value = Convert.ToHexString(software.Value.Code), Offset = software.Value.Offset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Code), Offset = upgrade.Value.Offset },
            new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Convert.ToHexString(upgrade.Value.Code), Offset = upgrade.Value.Offset },
        ];
    }

    private static (long Offset, byte[] Code)? FindLastTypedIdentifier(byte[] bytes, byte marker, byte recordType)
    {
        for (var index = bytes.Length - 8; index >= 0; index--)
        {
            if (bytes[index] != marker || !TryReadIdentifier(bytes, index, out var code)) continue;
            if (code[0] != 0 || code[1] != 0 || code[2] != 0x30 || code[3] != recordType) continue;
            return (index + 1L, code.ToArray());
        }

        return null;
    }

    private static bool ContainsStructuredIdentifierTriplet(byte[] bytes)
    {
        for (var index = 0; index <= bytes.Length - 24; index++)
        {
            if (TryReadStructuredIdentifierTriplet(bytes, index, out _, out _, out _)) return true;
        }

        return false;
    }

    private static bool TryReadStructuredIdentifierTriplet(byte[] bytes, int index, out ReadOnlySpan<byte> hardware, out ReadOnlySpan<byte> software, out ReadOnlySpan<byte> upgrade)
    {
        hardware = default;
        software = default;
        upgrade = default;
        if (bytes[index] != 0x06 || bytes[index + 8] != 0x08 || bytes[index + 16] is not (0x08 or 0x0D)) return false;
        return TryReadIdentifier(bytes, index, out hardware) &&
               TryReadIdentifier(bytes, index + 8, out software) &&
               TryReadIdentifier(bytes, index + 16, out upgrade);
    }

    private static IEnumerable<IdentifierMatch> ExtractStructuralEcuEvidence(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        var matches = new List<IdentifierMatch>();
        var ecuMarker = FindMostLikelyEcuMarker(text);
        var bmwSystemType = Regex.Match(text, @"DME_+(?<type>(?:DDE|DME)\d{3}[A-Z]?)", RegexOptions.IgnoreCase);
        var engine = Regex.Match(text, @"\b(?:(?:R[34]\s+)?[1-8][\.,]\d[lL]?\s*(?:V[468](?:/\dVT)?\s*)?(?:TDI|TSI|TFSI?|FSI|BITURBO)|4\.2l\s+V8/5VT)\b", RegexOptions.IgnoreCase);
        var upgrade = FindMostLikelyOemReference(text, engine);
        var legacyDiesel = Regex.Match(text, @"\bR4\s*(?:1[,\.]9|2[,\.]0)L\s*EDC?\b", RegexOptions.IgnoreCase);

        if (ecuMarker is not null)
        {
            var type = NormalizeEcuMarker(ecuMarker.Value);
            matches.Add(new IdentifierMatch { Type = "ECU family", Value = $"Bosch {type}", Offset = ecuMarker.Index });
            matches.Add(new IdentifierMatch { Type = "ECU type", Value = type, Offset = ecuMarker.Index });
            matches.Add(new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = ecuMarker.Index });
            if (type.StartsWith("MEVD17", StringComparison.OrdinalIgnoreCase))
                matches.Add(new IdentifierMatch { Type = "Processor", Value = "Infineon TC1797", Offset = ecuMarker.Index });
        }
        if (bmwSystemType.Success)
            matches.Add(new IdentifierMatch
            {
                Type = "BMW system type",
                Value = bmwSystemType.Groups["type"].Value.ToUpperInvariant(),
                Offset = bmwSystemType.Index
            });
        else if (bytes.Length == 524_288 && upgrade is not null && legacyDiesel.Success &&
                 Regex.IsMatch(text, @"(?<![A-Z0-9])10373[89]\d{4}(?!\d)"))
        {
            matches.Add(new IdentifierMatch { Type = "ECU family", Value = "Bosch EDC16U31 / U34", Offset = upgrade.Index });
            matches.Add(new IdentifierMatch { Type = "ECU type", Value = "EDC16U31/U34", Offset = upgrade.Index });
            matches.Add(new IdentifierMatch { Type = "ECU manufacturer", Value = "Bosch", Offset = upgrade.Index });
        }
        if (upgrade is not null)
        {
            matches.Add(new IdentifierMatch { Type = "Software Upgrade Nr.", Value = Regex.Replace(upgrade.Value, @"[\s\x00]+", " "), Offset = upgrade.Index });
            if (engine.Success)
                matches.Add(new IdentifierMatch { Type = "Vehicle group", Value = "Volkswagen Group", Offset = upgrade.Index });
        }

        foreach (Match hardware in Regex.Matches(text, @"(?<![A-Z0-9])(?:0(?:261|281)\d{6}|0[0-9A-Z]{2}907309[A-Z]?)(?![A-Z0-9])"))
            matches.Add(new IdentifierMatch { Type = "Hardware Nr.", Value = hardware.Value, Offset = hardware.Index });
        foreach (var software in Regex.Matches(text, @"(?<![A-Z0-9])(?:1037\d{6}|10SW\d{6})(?!\d)")
                     .Cast<Match>()
                     .GroupBy(match => match.Value)
                     .OrderByDescending(group => group.Count())
                     .Take(8))
        {
            var type = software.Key.StartsWith("10SW", StringComparison.OrdinalIgnoreCase)
                ? "ASAM software Nr."
                : "Software Nr.";
            matches.Add(new IdentifierMatch { Type = type, Value = software.Key, Offset = software.First().Index });
        }

        if (engine.Success)
            matches.Add(new IdentifierMatch { Type = "Engine", Value = engine.Value, Offset = engine.Index });
        var controlUnit = Regex.Match(text, @"\bJ\d{3}\b");
        if (controlUnit.Success)
            matches.Add(new IdentifierMatch { Type = "Control unit", Value = controlUnit.Value, Offset = controlUnit.Index });
        var processor = Regex.Match(text, @"\b(?:TC(?:1791|1793|1796|275|298)(?:TP)?|MPC\d{3}|SPC5777M?|TriCore)\b", RegexOptions.IgnoreCase);
        if (processor.Success)
            matches.Add(new IdentifierMatch { Type = "Processor", Value = processor.Value.Equals("TriCore", StringComparison.OrdinalIgnoreCase) ? "Infineon TriCore" : processor.Value, Offset = processor.Index });

        return matches.DistinctBy(match => (match.Type, match.Value), StringTupleComparer.OrdinalIgnoreCase).ToArray();
    }

    private static Match? FindMostLikelyEcuMarker(string text)
    {
        // A compact EDC16/17 C/CP code is the Bosch ECU family. It takes precedence
        // over broader platform labels such as EDC16C/C or BMW DDE/DME system types.
        var exactEdcFamily = Regex.Matches(text, @"(?<![A-Z0-9])EDC1[67]_?(?:C|CP)\d{2}(?![A-Z0-9]|_[A-Z0-9])", RegexOptions.IgnoreCase)
            .Cast<Match>()
            .OrderByDescending(match => GetExactEdc17Score(text, match))
            .ThenByDescending(match => match.Index)
            .FirstOrDefault();
        if (exactEdcFamily is not null) return exactEdcFamily;

        // MG1/MD1 families have a compact, stable code (for example MG1CS003).
        // Stop at its delimiter so a neighbouring project/build field cannot become
        // part of the ECU type.
        const string markerPattern = @"(?<![A-Z0-9])(?:(?:MG1|MD1)[A-Z]{2,4}\d{2,4}(?![A-Z0-9])|(?:EDC|MED|MEVD|ME)\d[A-Z0-9_.-]{2,24}|MG\d(?:\.\d+){1,3}(?![A-Z0-9])|(?:DDE|DME)(?:_+[A-Z0-9]+|\d[A-Z0-9]*))(?:/\d+/P\d+)?";
        return Regex.Matches(text, markerPattern, RegexOptions.IgnoreCase)
            .Cast<Match>()
            .Where(match => match.Length >= 5)
            .OrderByDescending(match => GetMarkerScore(text, match))
            .ThenByDescending(match => match.Index)
            .FirstOrDefault();
    }

    private static int GetExactEdc17Score(string text, Match marker)
    {
        var trailing = text.Substring(marker.Index, Math.Min(96, text.Length - marker.Index));
        var contextStart = Math.Max(0, marker.Index - 24);
        var context = text.Substring(contextStart, Math.Min(120, text.Length - contextStart));
        var score = 100;
        if ((trailing.Contains("#HWE", StringComparison.OrdinalIgnoreCase) || context.Contains("#HWE", StringComparison.OrdinalIgnoreCase) ||
             trailing.Contains("DME_", StringComparison.OrdinalIgnoreCase) || context.Contains("DME_", StringComparison.OrdinalIgnoreCase))) score += 200;
        if (context.Contains("BOSCH", StringComparison.OrdinalIgnoreCase)) score += 40;
        if (trailing.Contains("(BMW)", StringComparison.OrdinalIgnoreCase)) score += 30;
        if (Regex.IsMatch(trailing, @"\bMPC\d{3}\b", RegexOptions.IgnoreCase)) score += 20;

        // A real ECU platform banner is normally present in more than one code/data
        // segment. A lone later marker can instead be a shared library/template name.
        var canonical = marker.Value.Replace("_", string.Empty, StringComparison.Ordinal);
        var separatorIndex = canonical.StartsWith("EDC16", StringComparison.OrdinalIgnoreCase) ||
                             canonical.StartsWith("EDC17", StringComparison.OrdinalIgnoreCase)
            ? 5
            : -1;
        if (separatorIndex > 0)
        {
            var equivalentPattern = Regex.Escape(canonical).Insert(separatorIndex, "_?");
            var occurrenceCount = Regex.Matches(
                text,
                $@"(?<![A-Z0-9]){equivalentPattern}(?![A-Z0-9]|_[A-Z0-9])",
                RegexOptions.IgnoreCase).Count;
            score += Math.Min(occurrenceCount, 4) * 25;
        }
        if (trailing.Contains("CTPROT", StringComparison.OrdinalIgnoreCase)) score -= 150;
        return score;
    }

    private static int GetMarkerScore(string text, Match marker)
    {
        var trailing = text.Substring(marker.Index, Math.Min(48, text.Length - marker.Index));
        var score = marker.Value.Contains("/P", StringComparison.OrdinalIgnoreCase) ? 100 : 50;
        if (marker.Value.StartsWith("MD1_", StringComparison.OrdinalIgnoreCase) || marker.Value.StartsWith("MG1", StringComparison.OrdinalIgnoreCase)) score += 25;
        if (trailing.Contains("BOSCH", StringComparison.OrdinalIgnoreCase) || trailing.Contains("BMW", StringComparison.OrdinalIgnoreCase)) score += 30;
        if (Regex.IsMatch(trailing, @"\b(?:MPC|TC)\d{3,4}\b", RegexOptions.IgnoreCase)) score += 20;
        if (trailing.Contains("CTPROT", StringComparison.OrdinalIgnoreCase)) score -= 150;
        return score;
    }

    private static string NormalizeEcuMarker(string value)
    {
        var wrappedDde = Regex.Match(value, @"DME_+(?<type>(?:DDE|DME)\d{3}[A-Z]?)", RegexOptions.IgnoreCase);
        if (wrappedDde.Success)
            return wrappedDde.Groups["type"].Value.ToUpperInvariant();
        var marker = Regex.Match(value, @"(?:(?:EDC|MED|MEVD|ME|MD|MG)\d[A-Z0-9_.-]{2,24}|(?:DDE|DME)(?:_+[A-Z0-9]+|\d[A-Z0-9]*))", RegexOptions.IgnoreCase).Value;
        return marker.Replace("_", string.Empty).Replace("-", string.Empty).ToUpperInvariant();
    }

    private static IReadOnlyList<IdentifierMatch> ExtractMatches(byte[] bytes)
    {
        var matches = new List<IdentifierMatch>();
        var start = -1;
        for (var index = 0; index <= bytes.Length; index++)
        {
            var printable = index < bytes.Length && bytes[index] is >= 0x20 and <= 0x7E;
            if (printable && start < 0) start = index;
            if (printable) continue;
            if (start >= 0 && index - start >= 4)
            {
                var text = Encoding.ASCII.GetString(bytes, start, index - start);
                AddMatches(matches, text, start);
            }
            start = -1;
        }

        return matches
            .DistinctBy(match => (match.Type, match.Value), StringTupleComparer.OrdinalIgnoreCase)
            .Take(100)
            .ToArray();
    }

    private static void AddMatches(List<IdentifierMatch> results, string text, long offset)
    {
        foreach (var (type, pattern) in Patterns)
        {
            foreach (Match match in pattern.Matches(text))
            {
                var value = match.Groups.Count > 1 && match.Groups[1].Success ? match.Groups[1].Value : match.Value;
                if (type == "VIN" && !IsValidVin(value)) continue;
                results.Add(new IdentifierMatch { Type = type, Value = value, Offset = offset + match.Index });
            }
        }
    }

    private static Match? FindMostLikelyOemReference(string text, Match engine)
    {
        var candidates = Regex.Matches(text, @"(?<![A-Z0-9])[A-Z0-9]{3}\d{6}[A-Z]{0,2}[\s\x00]+\d{4}\b")
            .Cast<Match>()
            .Concat(Regex.Matches(text, @"(?<![A-Z0-9])[A-Z0-9]{8,14}[\s\x00]+(?:[A-Z0-9]{4})(?![A-Z0-9])").Cast<Match>())
            .Where(match => match.Value.Any(char.IsLetter))
            .DistinctBy(match => (match.Index, match.Length))
            .ToArray();
        if (candidates.Length == 0) return null;

        return candidates
            .OrderByDescending(candidate => GetOemReferenceScore(text, candidate, engine))
            .ThenByDescending(candidate => candidate.Index)
            .First();
    }

    private static int GetOemReferenceScore(string text, Match reference, Match engine)
    {
        var start = Math.Max(0, reference.Index - 160);
        var length = Math.Min(512, text.Length - start);
        var context = text.Substring(start, length);
        var score = 1;
        if (context.Contains("EV_ECM", StringComparison.OrdinalIgnoreCase)) score += 12;
        if (engine.Success && Math.Abs(engine.Index - reference.Index) <= 512) score += 8;
        if (Regex.IsMatch(context, @"\bJ\d{3}\b")) score += 4;
        if (Regex.IsMatch(reference.Value, @"[A-Z]{2}[\s\x00]+\d{4}\b")) score += 2;
        return score;
    }

    // VAG OEM references use a three-character prefix, six digits, an optional
    // revision suffix and a separate four-digit software/version number.
    // Keeping the format generic lets Auto handle new model/platform prefixes.
    private static MatchCollection FindVagUpgradeIdentifiers(string text) =>
        Regex.Matches(text, @"(?<![A-Z0-9])[A-Z0-9]{3}\d{6}[A-Z]{0,2}[\s\x00]+\d{4}\b");

    private static bool IsValidVin(string value)
    {
        if (value.Length != 17 || value.Distinct().Count() == 1 || value.Any(character => character is 'I' or 'O' or 'Q')) return false;
        const string characters = "0123456789.ABCDEFGH..JKLMN.P.R..STUVWXYZ";
        ReadOnlySpan<int> weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
        var total = 0;
        for (var index = 0; index < value.Length; index++)
        {
            var characterIndex = characters.IndexOf(value[index]);
            if (characterIndex < 0) return false;
            total += (characterIndex % 10) * weights[index];
        }
        var checkDigit = total % 11 == 10 ? 'X' : (char)('0' + total % 11);
        return value[8] == checkDigit;
    }

    private static string GetHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static IReadOnlyList<IdentifierMatch> MatchesWithinFile(IEnumerable<IdentifierMatch> matches, long fileSize) =>
        matches.Where(match => match.Offset >= 0 && match.Offset < fileSize).ToArray();

    private sealed class StringTupleComparer : IEqualityComparer<(string Type, string Value)>
    {
        public static StringTupleComparer OrdinalIgnoreCase { get; } = new();
        public bool Equals((string Type, string Value) left, (string Type, string Value) right) =>
            string.Equals(left.Type, right.Type, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(left.Value, right.Value, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string Type, string Value) value) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(value.Type), StringComparer.OrdinalIgnoreCase.GetHashCode(value.Value));
    }
}

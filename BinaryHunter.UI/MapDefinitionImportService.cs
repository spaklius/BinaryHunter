using BinaryHunter.Core.Projects;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace BinaryHunter.UI;

public sealed record MapDefinitionImportResult(
    string Format, IReadOnlyList<EcuProjectMapDefinition> Maps, IReadOnlyList<string> Warnings);

internal static partial class MapDefinitionImportService
{
    private sealed record AxisSource(long Address, int Count, EcuMapValueType ValueType,
        bool LittleEndian, double Factor, double Offset, string Unit);
    private sealed record Conversion(double Factor, double Offset, string Unit);

    public static MapDefinitionImportResult Import(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is ".json" or ".bhmap") return ImportJson(path);
        if (extension is ".xdf") return ImportXdf(path);
        if (extension is ".xml")
        {
            var xml = XDocument.Load(path, LoadOptions.None);
            return IsXdfRoot(xml.Root)
                ? ImportXdf(xml, path) : ImportXml(path);
        }

        var text = File.ReadAllText(path, DetectEncoding(path));
        if (extension is ".a2l" or ".damos" or ".dam" ||
            text.Contains("/begin CHARACTERISTIC", StringComparison.OrdinalIgnoreCase))
            return ImportA2l(text);
        return ImportDelimited(text, extension);
    }

    public static void ExportJson(string path, IEnumerable<EcuProjectMapDefinition> maps)
    {
        var document = new
        {
            format = "BinaryHunter Map Pack",
            version = 1,
            exportedUtc = DateTimeOffset.UtcNow,
            maps = maps.Select(EcuMapTools.Clone).ToList()
        };
        File.WriteAllText(path, JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(false));
    }

    private static MapDefinitionImportResult ImportA2l(string text)
    {
        var warnings = new List<string>();
        var maps = new List<EcuProjectMapDefinition>();
        var littleEndian = !Regex.IsMatch(text, @"\bBYTE_ORDER\s+MSB_FIRST\b", RegexOptions.IgnoreCase);
        var recordLayouts = ParseRecordLayouts(text);
        var conversions = ParseConversions(text);
        var axes = ParseAxisPoints(text, recordLayouts, conversions, littleEndian);

        foreach (Match match in CharacteristicBlockRegex().Matches(text))
        {
            var block = match.Value;
            var header = CharacteristicHeaderRegex().Match(block);
            if (!header.Success)
            {
                warnings.Add("Skipped a CHARACTERISTIC block with an unsupported header.");
                continue;
            }

            if (!TryInteger(header.Groups["address"].Value, out var address)) continue;
            var name = CleanName(header.Groups["name"].Value);
            var description = header.Groups["description"].Value.Trim();
            var kind = header.Groups["kind"].Value.ToUpperInvariant();
            var layoutName = header.Groups["layout"].Value;
            var conversionName = header.Groups["conversion"].Value;
            var valueType = recordLayouts.GetValueOrDefault(layoutName, EcuMapValueType.Unsigned16);
            var conversion = conversions.GetValueOrDefault(conversionName, new Conversion(1, 0, string.Empty));
            var dimensions = ParseDimensions(block, kind);
            var axisBlocks = AxisDescriptionBlockRegex().Matches(block).Cast<Match>().ToList();
            if (dimensions.Width == 1 && axisBlocks.Count > 0)
                dimensions = (ParseAxisCount(axisBlocks[0].Value, 16), dimensions.Height);
            if (dimensions.Height == 1 && axisBlocks.Count > 1)
                dimensions = (dimensions.Width, ParseAxisCount(axisBlocks[1].Value, 16));

            var map = new EcuProjectMapDefinition
            {
                Name = string.IsNullOrWhiteSpace(description) ? name : description,
                Category = MapCategoryClassifier.Classify(name + " " + description),
                StartOffset = address,
                Width = Math.Clamp(dimensions.Width, 1, 4096),
                Height = Math.Clamp(dimensions.Height, 1, 4096),
                ValueType = valueType,
                LittleEndian = littleEndian,
                Factor = conversion.Factor,
                Offset = conversion.Offset,
                Unit = conversion.Unit,
                Comment = $"Imported from ASAM A2L CHARACTERISTIC {name}; record layout {layoutName}; conversion {conversionName}.",
                XAxis = ParseAxisDescription(axisBlocks.ElementAtOrDefault(0)?.Value, axes,
                    "X axis", dimensions.Width, valueType, littleEndian, conversions),
                YAxis = ParseAxisDescription(axisBlocks.ElementAtOrDefault(1)?.Value, axes,
                    "Y axis", dimensions.Height, valueType, littleEndian, conversions)
            };
            maps.Add(map);
        }

        if (maps.Count == 0) warnings.Add("No supported A2L CHARACTERISTIC definitions were found.");
        return new MapDefinitionImportResult("ASAM A2L / DAMOS", maps, warnings);
    }

    private static Dictionary<string, EcuMapValueType> ParseRecordLayouts(string text)
    {
        var result = new Dictionary<string, EcuMapValueType>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in RecordLayoutBlockRegex().Matches(text))
        {
            var name = match.Groups["name"].Value;
            result[name] = ParseA2lValueType(match.Value);
        }
        return result;
    }

    private static Dictionary<string, Conversion> ParseConversions(string text)
    {
        var result = new Dictionary<string, Conversion>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in CompuMethodBlockRegex().Matches(text))
        {
            var name = match.Groups["name"].Value;
            var unit = match.Groups["unit"].Value;
            var linear = Regex.Match(match.Value,
                @"\bCOEFFS_LINEAR\s+(?<factor>[-+0-9.eE]+)\s+(?<offset>[-+0-9.eE]+)", RegexOptions.IgnoreCase);
            var factor = 1d; var offset = 0d;
            if (linear.Success)
            {
                double.TryParse(linear.Groups["factor"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out factor);
                double.TryParse(linear.Groups["offset"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out offset);
                if (!double.IsFinite(factor) || factor == 0) factor = 1;
                if (!double.IsFinite(offset)) offset = 0;
            }
            result[name] = new Conversion(factor, offset, unit);
        }
        return result;
    }

    private static Dictionary<string, AxisSource> ParseAxisPoints(string text,
        IReadOnlyDictionary<string, EcuMapValueType> layouts,
        IReadOnlyDictionary<string, Conversion> conversions, bool littleEndian)
    {
        var result = new Dictionary<string, AxisSource>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in AxisPointsBlockRegex().Matches(text))
        {
            var header = AxisPointsHeaderRegex().Match(match.Value);
            if (!header.Success || !TryInteger(header.Groups["address"].Value, out var address)) continue;
            var count = int.TryParse(header.Groups["count"].Value, out var parsed) ? Math.Clamp(parsed, 1, 4096) : 1;
            var type = layouts.GetValueOrDefault(header.Groups["layout"].Value, EcuMapValueType.Unsigned16);
            var conversion = conversions.GetValueOrDefault(header.Groups["conversion"].Value, new Conversion(1, 0, string.Empty));
            result[header.Groups["name"].Value] = new AxisSource(address, count, type, littleEndian,
                conversion.Factor, conversion.Offset, conversion.Unit);
        }
        return result;
    }

    private static EcuProjectAxisDefinition ParseAxisDescription(string? block,
        IReadOnlyDictionary<string, AxisSource> axes, string name, int fallbackCount,
        EcuMapValueType fallbackType, bool littleEndian,
        IReadOnlyDictionary<string, Conversion> conversions)
    {
        var result = new EcuProjectAxisDefinition
        {
            Name = name, Offset = -1, Count = Math.Clamp(fallbackCount, 1, 4096),
            ValueType = fallbackType, LittleEndian = littleEndian
        };
        if (string.IsNullOrWhiteSpace(block)) return result;
        var reference = Regex.Match(block, @"\bAXIS_PTS_REF\s+(?<name>\S+)", RegexOptions.IgnoreCase);
        if (reference.Success && axes.TryGetValue(reference.Groups["name"].Value, out var source))
        {
            result.Offset = source.Address; result.Count = source.Count; result.ValueType = source.ValueType;
            result.LittleEndian = source.LittleEndian; result.Factor = source.Factor;
            result.ValueOffset = source.Offset; result.Unit = source.Unit; result.Confidence = 1;
            return result;
        }
        var header = Regex.Match(block,
            @"/begin\s+AXIS_DESCR\s+\S+\s+\S+\s+(?<conversion>\S+)\s+(?<count>\d+)", RegexOptions.IgnoreCase);
        if (header.Success)
        {
            if (int.TryParse(header.Groups["count"].Value, out var count)) result.Count = Math.Clamp(count, 1, 4096);
            if (conversions.TryGetValue(header.Groups["conversion"].Value, out var conversion))
            {
                result.Factor = conversion.Factor; result.ValueOffset = conversion.Offset; result.Unit = conversion.Unit;
            }
        }
        return result;
    }

    private static (int Width, int Height) ParseDimensions(string block, string kind)
    {
        var matrix = Regex.Match(block, @"\bMATRIX_DIM\s+(?<x>\d+)(?:\s+(?<y>\d+))?", RegexOptions.IgnoreCase);
        if (matrix.Success)
        {
            var width = int.Parse(matrix.Groups["x"].Value, CultureInfo.InvariantCulture);
            var height = matrix.Groups["y"].Success
                ? int.Parse(matrix.Groups["y"].Value, CultureInfo.InvariantCulture) : 1;
            return (width, height);
        }
        return kind switch { "VALUE" => (1, 1), "CURVE" => (16, 1), "MAP" => (16, 16), _ => (16, 1) };
    }

    private static int ParseAxisCount(string block, int fallback)
    {
        var match = Regex.Match(block, @"/begin\s+AXIS_DESCR\s+\S+\s+\S+\s+\S+\s+(?<count>\d+)", RegexOptions.IgnoreCase);
        return match.Success && int.TryParse(match.Groups["count"].Value, out var count)
            ? Math.Clamp(count, 1, 4096) : fallback;
    }

    private static EcuMapValueType ParseA2lValueType(string text)
    {
        var signed = Regex.IsMatch(text, @"\b(SBYTE|SWORD|SLONG|A_INT64)\b", RegexOptions.IgnoreCase);
        if (Regex.IsMatch(text, @"\bFLOAT32_IEEE\b", RegexOptions.IgnoreCase)) return EcuMapValueType.Float32;
        if (Regex.IsMatch(text, @"\b(ULONG|SLONG)\b", RegexOptions.IgnoreCase)) return signed ? EcuMapValueType.Signed32 : EcuMapValueType.Unsigned32;
        if (Regex.IsMatch(text, @"\b(UWORD|SWORD)\b", RegexOptions.IgnoreCase)) return signed ? EcuMapValueType.Signed16 : EcuMapValueType.Unsigned16;
        return signed ? EcuMapValueType.Signed8 : EcuMapValueType.Unsigned8;
    }

    private static MapDefinitionImportResult ImportJson(string path)
    {
        var warnings = new List<string>();
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var mapsElement = root.ValueKind == JsonValueKind.Array ? root :
            root.TryGetProperty("maps", out var mapsProperty) ? mapsProperty : default;
        if (mapsElement.ValueKind != JsonValueKind.Array)
            return new MapDefinitionImportResult("JSON Driver / Map Pack",
                Array.Empty<EcuProjectMapDefinition>(), new[] { "The JSON file does not contain a maps array." });
        var maps = JsonSerializer.Deserialize<List<EcuProjectMapDefinition>>(mapsElement.GetRawText(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? [];
        NormalizeMaps(maps, "JSON Driver / Map Pack", warnings);
        return new MapDefinitionImportResult("JSON Driver / Map Pack", maps, warnings);
    }

    private static MapDefinitionImportResult ImportXml(string path)
    {
        var warnings = new List<string>();
        var maps = new List<EcuProjectMapDefinition>();
        var document = XDocument.Load(path, LoadOptions.None);
        foreach (var element in document.Descendants().Where(element =>
                     element.Name.LocalName.Equals("map", StringComparison.OrdinalIgnoreCase)))
        {
            var values = element.Attributes().ToDictionary(attribute => attribute.Name.LocalName,
                attribute => attribute.Value, StringComparer.OrdinalIgnoreCase);
            maps.Add(CreateFromFields(values));
        }
        NormalizeMaps(maps, "XML Driver / Map Pack", warnings);
        if (maps.Count == 0) warnings.Add("No <map> elements were found.");
        return new MapDefinitionImportResult("XML Driver / Map Pack", maps, warnings);
    }

    private static MapDefinitionImportResult ImportXdf(string path) =>
        ImportXdf(XDocument.Load(path, LoadOptions.None), path);

    private static MapDefinitionImportResult ImportXdf(XDocument document, string path)
    {
        var warnings = new List<string>();
        var maps = new List<EcuProjectMapDefinition>();
        var root = document.Root;
        if (root is null || !IsXdfRoot(root))
            return new MapDefinitionImportResult("TunerPro XDF", [],
                ["The document root is not a supported <XDFFORMAT> or <XDF> document."]);
        var header = Child(root, "XDFHEADER");
        var baseElement = header is null ? null : Descendant(header, "BASEOFFSET");
        var baseOffset = TryInteger(Attribute(baseElement, "offset"), out var parsedBase) ? parsedBase : 0;
        var subtractBase = Attribute(baseElement, "subtract") is "1" or "true" or "TRUE";
        var defaults = header is null ? null : Descendant(header, "DEFAULTS");
        var defaultBits = ParseInt(Attribute(defaults, "datasizeinbits"), 16);
        var defaultFlags = ParseFlags(Attribute(defaults, "mmedtypeflags"));
        var defaultSigned = Attribute(defaults, "signed") is "1" or "true" or "TRUE";
        var defaultLittleEndian = Attribute(defaults, "lsbfirst") is not "0" and not "false" and not "FALSE";
        var categories = root.Descendants().Where(element => Is(element, "XDFCATEGORY"))
            .Select(element => new
            {
                Id = Attribute(element, "index"),
                Name = Child(element, "name")?.Value.Trim() ?? string.Empty
            }).Where(item => item.Id.Length > 0).GroupBy(item => item.Id)
            .ToDictionary(group => group.Key, group => group.First().Name, StringComparer.OrdinalIgnoreCase);

        foreach (var item in root.Elements().Where(element => Is(element, "XDFTABLE") || Is(element, "XDFCONSTANT")))
        {
            var embedded = item.Elements().FirstOrDefault(element => Is(element, "EMBEDDEDDATA"));
            if (embedded is null || !TryInteger(Attribute(embedded, "mmedaddress"), out var rawAddress))
            {
                warnings.Add($"Skipped XDF item '{Child(item, "title")?.Value.Trim()}' without an embedded address.");
                continue;
            }
            var address = rawAddress + (subtractBase ? -baseOffset : baseOffset);
            var bits = ParseInt(Attribute(embedded, "mmedelementsizebits"), defaultBits);
            var flags = Attribute(embedded, "mmedtypeflags").Length > 0
                ? ParseFlags(Attribute(embedded, "mmedtypeflags")) : defaultFlags;
            var signed = defaultSigned || (flags & 0x01) != 0;
            var littleEndian = bits <= 8 || (flags & 0x02) != 0 ||
                               flags == 0 && defaultLittleEndian;
            var valueType = XdfValueType(bits, signed, (flags & 0x100) != 0);
            var width = Is(item, "XDFCONSTANT") ? 1 : ParseInt(Attribute(embedded, "mmedcolcount"), 1);
            var height = Is(item, "XDFCONSTANT") ? 1 : ParseInt(Attribute(embedded, "mmedrowcount"), 1);
            var title = Child(item, "title")?.Value.Trim();
            var description = Child(item, "description")?.Value.Trim() ?? string.Empty;
            var categoryId = Descendant(item, "CATEGORYMEM") is { } categoryMember
                ? Attribute(categoryMember, "category") : string.Empty;
            var category = categories.GetValueOrDefault(categoryId, string.Empty);
            var zAxis = item.Elements().FirstOrDefault(element => Is(element, "XDFAXIS") &&
                Attribute(element, "id").Equals("z", StringComparison.OrdinalIgnoreCase));
            var conversion = ParseXdfConversion(zAxis);
            var map = new EcuProjectMapDefinition
            {
                Name = string.IsNullOrWhiteSpace(title) ? $"XDF item @ 0x{address:X}" : title,
                Category = string.IsNullOrWhiteSpace(category)
                    ? MapCategoryClassifier.Classify((title ?? string.Empty) + " " + description) : category,
                StartOffset = address,
                Width = width,
                Height = height,
                ValueType = valueType,
                LittleEndian = littleEndian,
                Factor = conversion.Factor,
                Offset = conversion.Offset,
                Unit = conversion.Unit,
                Comment = string.IsNullOrWhiteSpace(description)
                    ? $"Imported from TunerPro XDF {Path.GetFileName(path)}."
                    : description + $" Imported from TunerPro XDF {Path.GetFileName(path)}.",
                XAxis = ParseXdfAxis(item, "x", width, baseOffset, subtractBase, valueType, littleEndian),
                YAxis = ParseXdfAxis(item, "y", height, baseOffset, subtractBase, valueType, littleEndian)
            };
            maps.Add(map);
        }
        NormalizeMaps(maps, "TunerPro XDF", warnings);
        if (maps.Count == 0) warnings.Add("No supported XDFTABLE or XDFCONSTANT definitions were found.");
        return new MapDefinitionImportResult("TunerPro XDF", maps, warnings);
    }

    private static EcuProjectAxisDefinition ParseXdfAxis(XElement item, string id, int fallbackCount,
        long baseOffset, bool subtractBase, EcuMapValueType fallbackType, bool fallbackLittleEndian)
    {
        var axis = item.Elements().FirstOrDefault(element => Is(element, "XDFAXIS") &&
            Attribute(element, "id").Equals(id, StringComparison.OrdinalIgnoreCase));
        var embedded = axis?.Elements().FirstOrDefault(element => Is(element, "EMBEDDEDDATA"));
        var address = embedded is not null && TryInteger(Attribute(embedded, "mmedaddress"), out var raw)
            ? raw + (subtractBase ? -baseOffset : baseOffset) : -1;
        var bits = embedded is null ? EcuMapTools.ValueSize(fallbackType) * 8 :
            ParseInt(Attribute(embedded, "mmedelementsizebits"), EcuMapTools.ValueSize(fallbackType) * 8);
        var flags = embedded is null ? 0 : ParseFlags(Attribute(embedded, "mmedtypeflags"));
        var conversion = ParseXdfConversion(axis);
        var labelCount = axis?.Elements().Count(element => Is(element, "LABEL")) ?? 0;
        var count = embedded is null ? Math.Max(fallbackCount, labelCount) :
            ParseInt(Attribute(embedded, "mmedelementcount"), Math.Max(fallbackCount, labelCount));
        return new EcuProjectAxisDefinition
        {
            Name = id.ToUpperInvariant() + " axis", Offset = address, Count = count,
            ValueType = XdfValueType(bits, (flags & 0x01) != 0, (flags & 0x100) != 0),
            LittleEndian = bits <= 8 || (flags & 0x02) != 0 || flags == 0 && fallbackLittleEndian,
            Factor = conversion.Factor, ValueOffset = conversion.Offset, Unit = conversion.Unit,
            Confidence = address >= 0 ? 1 : labelCount > 0 ? 0.9 : 0
        };
    }

    private static Conversion ParseXdfConversion(XElement? axis)
    {
        var unit = axis is null ? string.Empty : Child(axis, "units")?.Value.Trim() ?? string.Empty;
        var math = axis is null ? null : Descendant(axis, "MATH");
        var equation = Attribute(math, "equation");
        if (equation.Length == 0) return new Conversion(1, 0, unit);
        var normalized = equation.Replace(" ", string.Empty).Replace("(", string.Empty).Replace(")", string.Empty)
            .Replace("x", "X", StringComparison.OrdinalIgnoreCase);
        var multiply = Regex.Match(normalized,
            @"^X\*(?<factor>[-+0-9.eE]+)(?<offset>[-+][0-9.eE]+)?$", RegexOptions.IgnoreCase);
        var leading = Regex.Match(normalized,
            @"^(?<factor>[-+0-9.eE]+)\*X(?<offset>[-+][0-9.eE]+)?$", RegexOptions.IgnoreCase);
        var divide = Regex.Match(normalized,
            @"^X/(?<divisor>[-+0-9.eE]+)(?<offset>[-+][0-9.eE]+)?$", RegexOptions.IgnoreCase);
        var additive = Regex.Match(normalized, @"^X(?<offset>[-+][0-9.eE]+)$", RegexOptions.IgnoreCase);
        if (multiply.Success || leading.Success)
        {
            var match = multiply.Success ? multiply : leading;
            return new Conversion(ParseDouble(match.Groups["factor"].Value, 1),
                ParseDouble(match.Groups["offset"].Value, 0), unit);
        }
        if (divide.Success)
        {
            var divisor = ParseDouble(divide.Groups["divisor"].Value, 1);
            return new Conversion(divisor == 0 ? 1 : 1 / divisor,
                ParseDouble(divide.Groups["offset"].Value, 0), unit);
        }
        if (additive.Success) return new Conversion(1, ParseDouble(additive.Groups["offset"].Value, 0), unit);
        return new Conversion(1, 0, unit);
    }

    private static EcuMapValueType XdfValueType(int bits, bool signed, bool floating) =>
        floating && bits == 32 ? EcuMapValueType.Float32 : bits switch
        {
            <= 8 => signed ? EcuMapValueType.Signed8 : EcuMapValueType.Unsigned8,
            <= 16 => signed ? EcuMapValueType.Signed16 : EcuMapValueType.Unsigned16,
            <= 24 => signed ? EcuMapValueType.Signed24 : EcuMapValueType.Unsigned24,
            _ => signed ? EcuMapValueType.Signed32 : EcuMapValueType.Unsigned32
        };

    private static int ParseFlags(string text) => TryInteger(text, out var value) ? unchecked((int)value) : 0;
    private static bool Is(XElement? element, string name) =>
        element?.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase) == true;
    private static bool IsXdfRoot(XElement? element) =>
        Is(element, "XDFFORMAT") || Is(element, "XDF");
    private static XElement? Child(XElement element, string name) =>
        element.Elements().FirstOrDefault(child => Is(child, name));
    private static XElement? Descendant(XElement element, string name) =>
        element.Descendants().FirstOrDefault(child => Is(child, name));
    private static string Attribute(XElement? element, string name) =>
        element?.Attributes().FirstOrDefault(attribute =>
            attribute.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value.Trim() ?? string.Empty;

    private static MapDefinitionImportResult ImportDelimited(string text, string extension)
    {
        var warnings = new List<string>();
        var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.TrimStart().StartsWith('#')).ToList();
        if (lines.Count == 0) return new MapDefinitionImportResult("Driver / Map Pack",
            Array.Empty<EcuProjectMapDefinition>(), new[] { "The file is empty." });
        var delimiter = extension == ".tsv" ? '\t' : DetectDelimiter(lines[0]);
        var headers = SplitDelimited(lines[0], delimiter).Select(NormalizeHeader).ToList();
        var maps = new List<EcuProjectMapDefinition>();
        for (var index = 1; index < lines.Count; index++)
        {
            var cells = SplitDelimited(lines[index], delimiter);
            if (cells.All(string.IsNullOrWhiteSpace)) continue;
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var column = 0; column < Math.Min(headers.Count, cells.Count); column++) fields[headers[column]] = cells[column];
            try { maps.Add(CreateFromFields(fields)); }
            catch (Exception exception) { warnings.Add($"Line {index + 1}: {exception.Message}"); }
        }
        NormalizeMaps(maps, "Delimited Driver / Map Pack", warnings);
        return new MapDefinitionImportResult("Delimited Driver / Map Pack", maps, warnings);
    }

    private static EcuProjectMapDefinition CreateFromFields(IReadOnlyDictionary<string, string> fields)
    {
        string Get(params string[] names) => names.Select(name => fields.GetValueOrDefault(name, string.Empty))
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
        if (!TryInteger(Get("offset", "address", "start", "startoffset"), out var address))
            throw new FormatException("Map address/offset is missing or invalid.");
        var width = ParseInt(Get("width", "xcount", "columns"), 1);
        var height = ParseInt(Get("height", "ycount", "rows"), 1);
        var type = ParseValueType(Get("type", "valuetype", "datatype"));
        var endian = Get("endian", "byteorder");
        var factor = ParseDouble(Get("factor", "scale", "scaling"), 1);
        var valueOffset = ParseDouble(Get("valueoffset", "add", "bias"), 0);
        var map = new EcuProjectMapDefinition
        {
            Name = Get("name", "map", "label", "symbol"), Category = Get("category", "group"),
            StartOffset = address, Width = width, Height = height, ValueType = type,
            LittleEndian = !endian.Contains("big", StringComparison.OrdinalIgnoreCase) &&
                           !endian.Contains("motorola", StringComparison.OrdinalIgnoreCase) &&
                           !endian.Contains("msb_first", StringComparison.OrdinalIgnoreCase),
            Factor = factor, Offset = valueOffset, Unit = Get("unit"), Comment = Get("comment", "description")
        };
        map.XAxis = CreateAxis(fields, "x", width, map);
        map.YAxis = CreateAxis(fields, "y", height, map);
        return map;
    }

    private static EcuProjectAxisDefinition CreateAxis(IReadOnlyDictionary<string, string> fields,
        string prefix, int count, EcuProjectMapDefinition map)
    {
        var offsetText = fields.GetValueOrDefault(prefix + "axis", fields.GetValueOrDefault(prefix + "offset", string.Empty));
        var address = TryInteger(offsetText, out var parsed) ? parsed : -1;
        return new EcuProjectAxisDefinition
        {
            Name = prefix.ToUpperInvariant() + " axis", Offset = address, Count = count,
            ValueType = map.ValueType, LittleEndian = map.LittleEndian,
            Factor = map.Factor, ValueOffset = map.Offset, Unit = map.Unit,
            Confidence = address >= 0 ? 1 : 0
        };
    }

    private static void NormalizeMaps(List<EcuProjectMapDefinition> maps, string source, List<string> warnings)
    {
        for (var index = maps.Count - 1; index >= 0; index--)
        {
            var map = maps[index];
            if (map.Width is < 1 or > 4096 || map.Height is < 1 or > 4096 || map.StartOffset < 0)
            {
                warnings.Add($"Skipped invalid map '{map.Name}'."); maps.RemoveAt(index); continue;
            }
            map.Id = Guid.NewGuid().ToString("N");
            if (string.IsNullOrWhiteSpace(map.Name)) map.Name = $"Map @ 0x{map.StartOffset:X}";
            if (string.IsNullOrWhiteSpace(map.Category)) map.Category = MapCategoryClassifier.Classify(map.Name + " " + map.Comment);
            map.XAxis ??= new EcuProjectAxisDefinition { Name = "X axis", Count = map.Width };
            map.YAxis ??= new EcuProjectAxisDefinition { Name = "Y axis", Count = map.Height };
            map.Comment = string.IsNullOrWhiteSpace(map.Comment) ? $"Imported from {source}." : map.Comment + $" Imported from {source}.";
        }
    }

    private static EcuMapValueType ParseValueType(string value)
    {
        var normalized = value.Replace("_", string.Empty).Replace(" ", string.Empty).ToUpperInvariant();
        if (normalized.Contains("FLOAT")) return EcuMapValueType.Float32;
        var signed = normalized.StartsWith('S') || normalized.Contains("SIGNED") && !normalized.Contains("UNSIGNED");
        if (normalized.Contains("32") || normalized.Contains("LONG")) return signed ? EcuMapValueType.Signed32 : EcuMapValueType.Unsigned32;
        if (normalized.Contains("24")) return signed ? EcuMapValueType.Signed24 : EcuMapValueType.Unsigned24;
        if (normalized.Contains("8") || normalized.Contains("BYTE")) return signed ? EcuMapValueType.Signed8 : EcuMapValueType.Unsigned8;
        return signed ? EcuMapValueType.Signed16 : EcuMapValueType.Unsigned16;
    }

    private static bool TryInteger(string text, out long value)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static int ParseInt(string text, int fallback) =>
        int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? Math.Clamp(value, 1, 4096) : fallback;
    private static double ParseDouble(string text, double fallback) =>
        double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value) && double.IsFinite(value) ? value : fallback;
    private static string CleanName(string value) => value.Trim().Trim('"');
    private static string NormalizeHeader(string value) => value.Trim().Trim('"').Replace(" ", string.Empty).Replace("_", string.Empty).ToLowerInvariant();
    private static char DetectDelimiter(string header) => header.Count(character => character == ';') >= header.Count(character => character == ',') ? ';' : ',';

    private static List<string> SplitDelimited(string line, char delimiter)
    {
        var result = new List<string>(); var builder = new StringBuilder(); var quoted = false;
        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character == '"' && index + 1 < line.Length && line[index + 1] == '"') { builder.Append('"'); index++; continue; }
            if (character == '"') { quoted = !quoted; continue; }
            if (character == delimiter && !quoted) { result.Add(builder.ToString().Trim()); builder.Clear(); continue; }
            builder.Append(character);
        }
        result.Add(builder.ToString().Trim()); return result;
    }

    private static Encoding DetectEncoding(string path)
    {
        using var stream = File.OpenRead(path); Span<byte> prefix = stackalloc byte[3];
        var count = stream.Read(prefix);
        return count >= 2 && prefix[0] == 0xFF && prefix[1] == 0xFE ? Encoding.Unicode : Encoding.UTF8;
    }

    [GeneratedRegex(@"/begin\s+CHARACTERISTIC\b.*?/end\s+CHARACTERISTIC", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex CharacteristicBlockRegex();
    [GeneratedRegex("""/begin\s+CHARACTERISTIC\s+(?<name>\S+)\s+"(?<description>[^"]*)"\s+(?<kind>\S+)\s+(?<address>0x[0-9A-Fa-f]+|\d+)\s+(?<layout>\S+)\s+\S+\s+(?<conversion>\S+)""", RegexOptions.IgnoreCase)]
    private static partial Regex CharacteristicHeaderRegex();
    [GeneratedRegex(@"/begin\s+AXIS_DESCR\b.*?/end\s+AXIS_DESCR", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex AxisDescriptionBlockRegex();
    [GeneratedRegex(@"/begin\s+RECORD_LAYOUT\s+(?<name>\S+).*?/end\s+RECORD_LAYOUT", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex RecordLayoutBlockRegex();
    [GeneratedRegex("""/begin\s+COMPU_METHOD\s+(?<name>\S+)\s+"[^"]*"\s+\S+\s+"[^"]*"\s+"(?<unit>[^"]*)".*?/end\s+COMPU_METHOD""", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex CompuMethodBlockRegex();
    [GeneratedRegex(@"/begin\s+AXIS_PTS\b.*?/end\s+AXIS_PTS", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex AxisPointsBlockRegex();
    [GeneratedRegex("""/begin\s+AXIS_PTS\s+(?<name>\S+)\s+"[^"]*"\s+(?<address>0x[0-9A-Fa-f]+|\d+)\s+\S+\s+(?<layout>\S+)\s+\S+\s+(?<conversion>\S+)\s+(?<count>\d+)""", RegexOptions.IgnoreCase)]
    private static partial Regex AxisPointsHeaderRegex();
}

internal static class MapCategoryClassifier
{
    private static readonly (string Category, string[] Keywords)[] Rules =
    {
        ("Driver wish", new[] { "DRIVER", "PEDAL", "WISH", "FAHRERWUNSCH" }),
        ("Torque", new[] { "TORQUE", "MOMENT", "DREHMOMENT" }),
        ("Boost", new[] { "BOOST", "TURBO", "CHARGE", "LADEDRUCK" }),
        ("Rail pressure", new[] { "RAIL", "FUEL_PRESS", "KRAFTSTOFFDRUCK" }),
        ("Smoke limiter", new[] { "SMOKE", "RUSS", "SOOT" }),
        ("Duration", new[] { "DURATION", "INJECTION_TIME", "EINSPRITZDAUER" }),
        ("Lambda", new[] { "LAMBDA", "AFR", "AIR_FUEL" }),
        ("N75", new[] { "N75", "WASTEGATE", "VNT" }),
        ("Ignition", new[] { "IGNITION", "SPARK", "ZUEND" }),
        ("VVT", new[] { "VVT", "CAMSHAFT", "NOCKENWELLE" }),
        ("EGR", new[] { "EGR", "AGR" }),
        ("DPF", new[] { "DPF", "PARTICULATE", "PARTIKEL" }),
        ("SCR / AdBlue", new[] { "SCR", "ADBLUE", "UREA" }),
        ("Temperature", new[] { "TEMP", "TEMPERATURE", "THERMAL" }),
        ("Diagnostics", new[] { "DTC", "DIAG", "ERROR", "FEHLER" }),
        ("Fuel", new[] { "FUEL", "INJECTION", "EINSPRITZ" })
    };

    public static string Classify(string text)
    {
        var normalized = text.ToUpperInvariant();
        return Rules.FirstOrDefault(rule => rule.Keywords.Any(keyword =>
            normalized.Contains(keyword, StringComparison.Ordinal))).Category ?? "Unclassified";
    }
}

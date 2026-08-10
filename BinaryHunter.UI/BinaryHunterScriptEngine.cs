using BinaryHunter.Core.Projects;
using System.Globalization;
using System.Text.RegularExpressions;

namespace BinaryHunter.UI;

public sealed record BinaryHunterScriptResult(bool Success, byte[] Bytes,
    IReadOnlyList<EcuProjectMapDefinition> Maps, IReadOnlyList<string> Log, int ChangedBytes);

internal static class BinaryHunterScriptEngine
{
    public static BinaryHunterScriptResult Preview(string script, byte[] source)
    {
        var bytes = source.ToArray(); var maps = new List<EcuProjectMapDefinition>(); var log = new List<string>();
        try
        {
            var lines = script.Replace("\r", string.Empty).Split('\n');
            for (var lineNumber = 0; lineNumber < lines.Length; lineNumber++)
            {
                var line = lines[lineNumber].Trim();
                if (line.Length == 0 || line.StartsWith("//") || line.StartsWith('#')) continue;
                var tokens = Tokenize(line);
                if (tokens.Count == 0) continue;
                Execute(tokens, bytes, maps, log, lineNumber + 1);
            }
            var changed = bytes.Where((value, index) => value != source[index]).Count();
            log.Add($"Preview complete: {changed:N0} changed byte(s), {maps.Count:N0} map definition(s).");
            return new BinaryHunterScriptResult(true, bytes, maps, log, changed);
        }
        catch (Exception exception)
        {
            log.Add("Stopped: " + exception.Message);
            return new BinaryHunterScriptResult(false, source.ToArray(), [], log, 0);
        }
    }

    private static void Execute(IReadOnlyList<string> tokens, byte[] bytes,
        List<EcuProjectMapDefinition> maps, List<string> log, int lineNumber)
    {
        var command = tokens[0].ToLowerInvariant();
        try
        {
            switch (command)
            {
                case "require_size":
                    Require(tokens.Count == 3, "require_size <minimum> <maximum>");
                    var minimum = Number(tokens[1]); var maximum = Number(tokens[2]);
                    Require(bytes.LongLength >= minimum && bytes.LongLength <= maximum,
                        $"file size {bytes.LongLength:N0} is outside {minimum:N0}..{maximum:N0}");
                    log.Add($"Line {lineNumber}: size requirement passed."); break;
                case "assert":
                    Require(tokens.Count == 3, "assert <offset> \"AA BB ...\"");
                    var assertOffset = Number(tokens[1]); var expected = Hex(tokens[2]); ValidateRange(bytes, assertOffset, expected.Length);
                    Require(bytes.AsSpan((int)assertOffset, expected.Length).SequenceEqual(expected), $"assertion failed at 0x{assertOffset:X}");
                    log.Add($"Line {lineNumber}: assertion passed at 0x{assertOffset:X}."); break;
                case "set":
                    Require(tokens.Count == 3, "set <offset> \"AA BB ...\"");
                    var setOffset = Number(tokens[1]); var replacement = Hex(tokens[2]); ValidateRange(bytes, setOffset, replacement.Length);
                    Buffer.BlockCopy(replacement, 0, bytes, (int)setOffset, replacement.Length);
                    log.Add($"Line {lineNumber}: staged {replacement.Length:N0} byte(s) at 0x{setOffset:X}."); break;
                case "fill":
                    Require(tokens.Count == 4, "fill <offset> <length> <byte>");
                    var fillOffset = Number(tokens[1]); var length = checked((int)Number(tokens[2])); var fill = Hex(tokens[3]);
                    Require(fill.Length == 1, "fill value must contain one byte"); ValidateRange(bytes, fillOffset, length);
                    Array.Fill(bytes, fill[0], (int)fillOffset, length); log.Add($"Line {lineNumber}: staged fill of {length:N0} byte(s)."); break;
                case "replace_all":
                    Require(tokens.Count == 3, "replace_all \"AA BB\" \"CC DD\"");
                    var find = Hex(tokens[1]); var replace = Hex(tokens[2]); Require(find.Length > 0 && find.Length == replace.Length, "search and replacement lengths must match");
                    var count = 0; for (var offset = 0; offset <= bytes.Length - find.Length; offset++) if (bytes.AsSpan(offset, find.Length).SequenceEqual(find)) { Buffer.BlockCopy(replace, 0, bytes, offset, replace.Length); count++; offset += find.Length - 1; }
                    Require(count > 0, "replace_all pattern was not found"); log.Add($"Line {lineNumber}: staged {count:N0} replacement(s)."); break;
                case "map":
                    Require(tokens.Count >= 8, "map \"name\" <offset> <width> <height> <type> <intel|motorola> \"category\"");
                    var type = Enum.Parse<EcuMapValueType>(tokens[5], true); var width = checked((int)Number(tokens[3])); var height = checked((int)Number(tokens[4])); var mapOffset = Number(tokens[2]);
                    var map = new EcuProjectMapDefinition { Name = tokens[1], StartOffset = mapOffset, Width = width, Height = height, ValueType = type, LittleEndian = !tokens[6].Equals("motorola", StringComparison.OrdinalIgnoreCase), Category = tokens[7], Comment = "Created by BinaryHunter script preview." };
                    ValidateRange(bytes, mapOffset, checked(width * height * EcuMapTools.ValueSize(type))); maps.Add(map); log.Add($"Line {lineNumber}: staged map '{map.Name}'."); break;
                case "message":
                    Require(tokens.Count >= 2, "message \"text\""); log.Add($"Line {lineNumber}: {tokens[1]}"); break;
                default: throw new InvalidOperationException($"unknown command '{tokens[0]}'");
            }
        }
        catch (Exception exception) { throw new InvalidOperationException($"Line {lineNumber}: {exception.Message}", exception); }
    }

    private static List<string> Tokenize(string line) => Regex.Matches(line, "\"(?:\\\\.|[^\"])*\"|\\S+").Cast<Match>()
        .Select(match => match.Value.StartsWith('"') ? Regex.Unescape(match.Value[1..^1]) : match.Value).ToList();
    private static long Number(string text) => MapDefinitionWindow.TryParseOffset(text, out var value) && value >= 0
        ? value : throw new FormatException($"invalid number '{text}'");
    private static byte[] Hex(string text)
    {
        var compact = Regex.Replace(text, "[^0-9A-Fa-f]", string.Empty);
        Require(compact.Length > 0 && compact.Length % 2 == 0, "hex data must contain complete bytes");
        return Convert.FromHexString(compact);
    }
    private static void ValidateRange(byte[] bytes, long offset, int length) =>
        Require(offset >= 0 && length >= 0 && offset + length <= bytes.LongLength, $"range 0x{offset:X}+{length:N0} is outside the file");
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}

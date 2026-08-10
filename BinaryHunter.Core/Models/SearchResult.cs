namespace BinaryHunter.Core.Models;

public class SearchResult
{
    public string FileName { get; init; } = string.Empty;

    public string FullPath { get; init; } = string.Empty;

    public long Offset { get; init; }

    public string MatchType { get; init; } = string.Empty;

    public string Value { get; init; } = string.Empty;

    public string ContextHex { get; init; } = string.Empty;

    public string HexOffset => $"0x{Offset:X8}";
}

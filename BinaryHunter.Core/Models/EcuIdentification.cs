namespace BinaryHunter.Core.Models;

public sealed class EcuIdentification
{
    public string FileName { get; init; } = string.Empty;
    public string FullPath { get; init; } = string.Empty;
    public long FileSize { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public bool IsGenericAnalysis { get; init; }
    public IReadOnlyList<IdentifierMatch> Matches { get; init; } = [];
}

public sealed class IdentifierMatch
{
    public string Type { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public long Offset { get; init; }

    public string HexOffset => $"0x{Offset:X8}";
}

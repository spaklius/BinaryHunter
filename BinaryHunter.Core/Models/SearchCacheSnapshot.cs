namespace BinaryHunter.Core.Models;

public sealed class SearchCacheSnapshot
{
    public int FileCount { get; init; }

    public string Fingerprint { get; init; } = string.Empty;
}

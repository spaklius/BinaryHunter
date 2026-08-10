using BinaryHunter.Core.Enums;

namespace BinaryHunter.Core.Models;

public class SearchOptions
{
    public string Folder { get; init; } = string.Empty;

    public string SearchText { get; init; } = string.Empty;

    public SearchType SearchType { get; init; } = SearchType.Auto;

    public bool SearchSubFolders { get; init; } = true;

    public bool StopAfterFirstMatch { get; init; } = false;

    public int MaxResults { get; init; } = 1_000;

    public int MaxDegreeOfParallelism { get; init; } = Math.Min(4, Environment.ProcessorCount);

    public bool SkipCommonBuildFolders { get; init; } = true;
}

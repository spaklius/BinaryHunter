namespace BinaryHunter.Core.Models;

public sealed class SearchRequest
{
    public string SearchText { get; init; } = "";

    public Enums.SearchType SearchType { get; init; } = Enums.SearchType.Auto;

    public bool IncludeSubfolders { get; init; } = true;

    public bool StopAfterFirstMatch { get; init; } = false;
}

namespace BinaryHunter.Core.Models;

public sealed class FileEntry
{
    public string Name { get; init; } = "";

    public string FullPath { get; init; } = "";

    public string Extension { get; init; } = "";

    public long Size { get; init; }
}
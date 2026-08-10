namespace BinaryHunter.UI.Models;

public sealed class LoadedBinaryFile
{
    public string Name { get; init; } = string.Empty;

    public string FullPath { get; init; } = string.Empty;

    public long Size { get; init; }

    public DateTime LastModified { get; init; }

    public string SizeSummary =>
        Size >= 1024 * 1024
            ? $"{Size / (1024d * 1024d):0.##} MB ({Size:N0} B)"
            : $"{Size / 1024d:0} KB ({Size:N0} B)";
}

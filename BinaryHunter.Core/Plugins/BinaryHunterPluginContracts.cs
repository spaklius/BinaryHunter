namespace BinaryHunter.Core.Plugins;

public interface IBinaryHunterPlugin
{
    string Id { get; }
    string Name { get; }
    string Author { get; }
    Version Version { get; }
    string Description { get; }
}

public sealed record ChecksumPluginCandidate(
    string Name, long RangeStart, long RangeLength, long StoreOffset,
    int StoredByteCount, bool LittleEndian, string Description);

public interface IChecksumPlugin : IBinaryHunterPlugin
{
    IReadOnlyList<ChecksumPluginCandidate> Detect(ReadOnlyMemory<byte> file, CancellationToken cancellationToken);
    byte[] Calculate(ReadOnlyMemory<byte> file, ChecksumPluginCandidate candidate);
}

public interface IAnalysisPlugin : IBinaryHunterPlugin
{
    string AnalysisKind { get; }
}

public interface IImportExportPlugin : IBinaryHunterPlugin
{
    IReadOnlyList<string> FileExtensions { get; }
    bool CanImport { get; }
    bool CanExport { get; }
}

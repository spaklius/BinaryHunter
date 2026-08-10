using System.Text.Json.Serialization;

namespace BinaryHunter.Core.Projects;

public enum EcuSourceFormat
{
    RawBinary,
    IntelHex,
    MotorolaSRecord,
    FrfContainer,
    OdxDocument,
    Unknown
}

public enum EcuProjectHistoryKind
{
    ProjectCreated,
    SourceImported,
    VersionCreated,
    ProjectOpened,
    BackupCreated,
    Note
}

public sealed class EcuProjectManifest
{
    public int SchemaVersion { get; set; } = 1;
    public Guid ProjectId { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string ActiveVersionId { get; set; } = string.Empty;
    public List<EcuProjectSource> Sources { get; set; } = [];
    public List<EcuProjectVersion> Versions { get; set; } = [];
    public List<EcuProjectHistoryEntry> History { get; set; } = [];
    public List<EcuProjectBookmark> Bookmarks { get; set; } = [];
    public List<EcuProjectMapDefinition> Maps { get; set; } = [];
    public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public enum EcuMapValueType
{
    Unsigned8,
    Signed8,
    Unsigned16,
    Signed16,
    Unsigned24,
    Signed24,
    Unsigned32,
    Signed32,
    Float32
}

public sealed class EcuProjectMapDefinition
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "New map";
    public string Category { get; set; } = "Unclassified";
    public long StartOffset { get; set; }
    public int Width { get; set; } = 16;
    public int Height { get; set; } = 16;
    public EcuMapValueType ValueType { get; set; } = EcuMapValueType.Unsigned16;
    public bool LittleEndian { get; set; } = true;
    public double Factor { get; set; } = 1;
    public double Offset { get; set; }
    public string Unit { get; set; } = string.Empty;
    public string Comment { get; set; } = string.Empty;
    public EcuProjectAxisDefinition XAxis { get; set; } = new() { Name = "X axis", Count = 16 };
    public EcuProjectAxisDefinition YAxis { get; set; } = new() { Name = "Y axis", Count = 16 };
}

public sealed class EcuProjectAxisDefinition
{
    public string Name { get; set; } = "Axis";
    public long Offset { get; set; } = -1;
    public int Count { get; set; }
    public EcuMapValueType ValueType { get; set; } = EcuMapValueType.Unsigned16;
    public bool LittleEndian { get; set; } = true;
    public double Factor { get; set; } = 1;
    public double ValueOffset { get; set; }
    public string Unit { get; set; } = string.Empty;
    public double Confidence { get; set; }
}

public sealed class EcuProjectBookmark
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public int Slot { get; set; } = -1;
    public string Name { get; set; } = string.Empty;
    public long Offset { get; set; }
    public int Length { get; set; } = 1;
    public string Note { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class EcuProjectSource
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string OriginalFileName { get; set; } = string.Empty;
    public string StoredRelativePath { get; set; } = string.Empty;
    public EcuSourceFormat Format { get; set; }
    public long Size { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public long BaseAddress { get; set; }
    public DateTimeOffset ImportedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string ImportNote { get; set; } = string.Empty;
}

public sealed class EcuProjectVersion
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public int Number { get; set; }
    public string Name { get; set; } = string.Empty;
    public string StoredRelativePath { get; set; } = string.Empty;
    public string SourceId { get; set; } = string.Empty;
    public string ParentVersionId { get; set; } = string.Empty;
    public long Size { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Comment { get; set; } = string.Empty;
}

public sealed class EcuProjectHistoryEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public EcuProjectHistoryKind Kind { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string VersionId { get; set; } = string.Empty;
}

public sealed class EcuProjectSession
{
    public required string ManifestPath { get; init; }
    public required string DataDirectory { get; init; }
    public required EcuProjectManifest Manifest { get; init; }

    [JsonIgnore]
    public EcuProjectVersion? ActiveVersion =>
        Manifest.Versions.FirstOrDefault(version =>
            string.Equals(version.Id, Manifest.ActiveVersionId, StringComparison.OrdinalIgnoreCase));
}

public sealed class EcuFileImportResult
{
    public required byte[] EditableBytes { get; init; }
    public required EcuSourceFormat Format { get; init; }
    public long BaseAddress { get; init; }
    public string Note { get; init; } = string.Empty;
}

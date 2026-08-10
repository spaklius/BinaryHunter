using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BinaryHunter.Core.Projects;

public sealed class EcuProjectService
{
    public const string ProjectExtension = ".bhproj";
    public const string BackupExtension = ".bhbackup";

    private readonly EcuFileImportService _importService;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public EcuProjectService(EcuFileImportService? importService = null) =>
        _importService = importService ?? new EcuFileImportService();

    public EcuProjectSession Create(string manifestPath, string sourcePath, string? projectName = null)
    {
        manifestPath = NormalizeProjectPath(manifestPath);
        sourcePath = Path.GetFullPath(sourcePath);
        if (File.Exists(manifestPath))
            throw new IOException($"Project already exists: {manifestPath}");

        var dataDirectory = GetDataDirectory(manifestPath);
        Directory.CreateDirectory(Path.Combine(dataDirectory, "sources"));
        Directory.CreateDirectory(Path.Combine(dataDirectory, "versions"));

        var import = _importService.Import(sourcePath);
        var source = StoreSource(dataDirectory, sourcePath, import);
        var now = DateTimeOffset.UtcNow;
        var manifest = new EcuProjectManifest
        {
            Name = string.IsNullOrWhiteSpace(projectName)
                ? Path.GetFileNameWithoutExtension(manifestPath)
                : projectName.Trim(),
            CreatedUtc = now,
            UpdatedUtc = now,
            Sources = [source]
        };
        var session = new EcuProjectSession
        {
            ManifestPath = manifestPath,
            DataDirectory = dataDirectory,
            Manifest = manifest
        };

        var version = AddVersion(session, import.EditableBytes, "Original", "Initial imported ECU image", source.Id);
        manifest.ActiveVersionId = version.Id;
        manifest.History.Insert(0, NewHistory(EcuProjectHistoryKind.ProjectCreated,
            "Project created", $"Created from {source.OriginalFileName} ({source.Format}).", version.Id));
        SaveManifest(session);
        return session;
    }

    public EcuProjectSession Open(string manifestPath)
    {
        manifestPath = Path.GetFullPath(manifestPath);
        var json = File.ReadAllText(manifestPath);
        var manifest = JsonSerializer.Deserialize<EcuProjectManifest>(json, _jsonOptions)
            ?? throw new InvalidDataException("Project manifest is empty or invalid.");
        if (manifest.SchemaVersion != 1)
            throw new InvalidDataException($"Unsupported project schema version {manifest.SchemaVersion}.");

        var session = new EcuProjectSession
        {
            ManifestPath = manifestPath,
            DataDirectory = GetDataDirectory(manifestPath),
            Manifest = manifest
        };
        _ = GetActiveVersionPath(session);
        manifest.History.Insert(0, NewHistory(EcuProjectHistoryKind.ProjectOpened,
            "Project opened", Path.GetFileName(manifestPath), manifest.ActiveVersionId));
        SaveManifest(session);
        return session;
    }

    public string GetActiveVersionPath(EcuProjectSession session)
    {
        var version = session.ActiveVersion
            ?? throw new InvalidDataException("The project has no active version.");
        var path = ResolveDataPath(session, version.StoredRelativePath);
        if (!File.Exists(path)) throw new FileNotFoundException("Active project version is missing.", path);
        return path;
    }

    public EcuProjectVersion ImportAsVersion(EcuProjectSession session, string sourcePath)
    {
        sourcePath = Path.GetFullPath(sourcePath);
        var import = _importService.Import(sourcePath);
        var source = StoreSource(session.DataDirectory, sourcePath, import);
        session.Manifest.Sources.Add(source);
        var version = AddVersion(session, import.EditableBytes,
            $"Imported {Path.GetFileNameWithoutExtension(sourcePath)}",
            import.Note, source.Id);
        session.Manifest.ActiveVersionId = version.Id;
        session.Manifest.History.Insert(0, NewHistory(EcuProjectHistoryKind.SourceImported,
            "ECU source imported", $"{source.OriginalFileName} ({source.Format}, {source.Size:N0} bytes).",
            version.Id));
        SaveManifest(session);
        return version;
    }

    public EcuProjectVersion CreateVersion(EcuProjectSession session, byte[] bytes, string? comment = null)
    {
        var version = AddVersion(session, bytes, $"Version {NextVersionNumber(session.Manifest):D4}",
            string.IsNullOrWhiteSpace(comment) ? "Manual editor snapshot" : comment.Trim(),
            session.ActiveVersion?.SourceId ?? string.Empty);
        session.Manifest.ActiveVersionId = version.Id;
        session.Manifest.History.Insert(0, NewHistory(EcuProjectHistoryKind.VersionCreated,
            $"Version {version.Number:D4} saved", version.Comment, version.Id));
        SaveManifest(session);
        return version;
    }

    public string CreateBackup(EcuProjectSession session, string destinationPath)
    {
        destinationPath = Path.GetFullPath(destinationPath);
        if (!destinationPath.EndsWith(BackupExtension, StringComparison.OrdinalIgnoreCase))
            destinationPath += BackupExtension;
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);

        session.Manifest.History.Insert(0, NewHistory(EcuProjectHistoryKind.BackupCreated,
            "Backup created", Path.GetFileName(destinationPath), session.Manifest.ActiveVersionId));
        SaveManifest(session);

        var temporary = destinationPath + ".tmp";
        if (File.Exists(temporary)) File.Delete(temporary);
        try
        {
            using (var archive = ZipFile.Open(temporary, ZipArchiveMode.Create))
            {
                archive.CreateEntryFromFile(session.ManifestPath, Path.GetFileName(session.ManifestPath),
                    CompressionLevel.Optimal);
                foreach (var file in Directory.EnumerateFiles(session.DataDirectory, "*", SearchOption.AllDirectories))
                {
                    if (string.Equals(Path.GetFullPath(file), destinationPath, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(Path.GetFullPath(file), temporary, StringComparison.OrdinalIgnoreCase))
                        continue;
                    var relative = Path.GetRelativePath(Path.GetDirectoryName(session.ManifestPath)!, file)
                        .Replace('\\', '/');
                    archive.CreateEntryFromFile(file, relative, CompressionLevel.Optimal);
                }
            }
            File.Move(temporary, destinationPath, true);
            return destinationPath;
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public string GetVersionPath(EcuProjectSession session, EcuProjectVersion version) =>
        ResolveDataPath(session, version.StoredRelativePath);

    public string ActivateVersion(EcuProjectSession session, EcuProjectVersion version)
    {
        if (!session.Manifest.Versions.Any(candidate =>
                string.Equals(candidate.Id, version.Id, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("The selected version does not belong to this project.");
        var path = GetVersionPath(session, version);
        if (!File.Exists(path)) throw new FileNotFoundException("Selected project version is missing.", path);
        session.Manifest.ActiveVersionId = version.Id;
        session.Manifest.History.Insert(0, NewHistory(EcuProjectHistoryKind.ProjectOpened,
            $"Version {version.Number:D4} activated", version.Comment, version.Id));
        SaveManifest(session);
        return path;
    }
    public void SaveManifest(EcuProjectSession session)
    {
        session.Manifest.UpdatedUtc = DateTimeOffset.UtcNow;
        var json = JsonSerializer.Serialize(session.Manifest, _jsonOptions);
        var directory = Path.GetDirectoryName(session.ManifestPath)!;
        Directory.CreateDirectory(directory);
        var temporary = session.ManifestPath + ".tmp";
        File.WriteAllText(temporary, json);
        File.Move(temporary, session.ManifestPath, true);
    }

    private EcuProjectSource StoreSource(string dataDirectory, string sourcePath, EcuFileImportResult import)
    {
        var safeName = SanitizeFileName(Path.GetFileName(sourcePath));
        var storedName = $"{DateTime.UtcNow:yyyyMMdd_HHmmssfff}_{Guid.NewGuid():N}_{safeName}";
        var relativePath = Path.Combine("sources", storedName);
        var destination = Path.Combine(dataDirectory, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(sourcePath, destination, overwrite: false);
        return new EcuProjectSource
        {
            OriginalFileName = Path.GetFileName(sourcePath),
            StoredRelativePath = relativePath.Replace('\\', '/'),
            Format = import.Format,
            Size = new FileInfo(sourcePath).Length,
            Sha256 = CalculateSha256(destination),
            BaseAddress = import.BaseAddress,
            ImportNote = import.Note
        };
    }

    private EcuProjectVersion AddVersion(EcuProjectSession session, byte[] bytes, string name,
        string comment, string sourceId)
    {
        var number = NextVersionNumber(session.Manifest);
        var fileName = $"{number:D4}_{DateTime.UtcNow:yyyyMMdd_HHmmss}_calibration.bin";
        var relativePath = Path.Combine("versions", fileName);
        var destination = Path.Combine(session.DataDirectory, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        WriteBytesAtomically(destination, bytes);
        var version = new EcuProjectVersion
        {
            Number = number,
            Name = name,
            StoredRelativePath = relativePath.Replace('\\', '/'),
            SourceId = sourceId,
            ParentVersionId = session.Manifest.ActiveVersionId,
            Size = bytes.LongLength,
            Sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
            Comment = comment
        };
        session.Manifest.Versions.Add(version);
        return version;
    }

    private static int NextVersionNumber(EcuProjectManifest manifest) =>
        manifest.Versions.Count == 0 ? 1 : manifest.Versions.Max(version => version.Number) + 1;

    private static EcuProjectHistoryEntry NewHistory(EcuProjectHistoryKind kind, string title,
        string details, string versionId) => new()
    {
        Kind = kind,
        Title = title,
        Details = details,
        VersionId = versionId
    };

    private static string NormalizeProjectPath(string path)
    {
        path = Path.GetFullPath(path);
        return path.EndsWith(ProjectExtension, StringComparison.OrdinalIgnoreCase)
            ? path
            : path + ProjectExtension;
    }

    private static string GetDataDirectory(string manifestPath) =>
        Path.Combine(Path.GetDirectoryName(manifestPath)!,
            Path.GetFileNameWithoutExtension(manifestPath) + ".bhdata");

    private static string ResolveDataPath(EcuProjectSession session, string relativePath)
    {
        var root = Path.GetFullPath(session.DataDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var path = Path.GetFullPath(Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Project contains an unsafe relative path.");
        return path;
    }

    private static string CalculateSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void WriteBytesAtomically(string destination, byte[] bytes)
    {
        var temporary = destination + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);
            File.Move(temporary, destination, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var result = new string(value.Select(character => invalid.Contains(character) ? '_' : character).ToArray());
        return string.IsNullOrWhiteSpace(result) ? "ecu-source.bin" : result;
    }
}
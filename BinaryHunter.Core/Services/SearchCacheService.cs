using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Services;

public sealed class SearchCacheService
{
    private const int CacheVersion = 1;
    private static readonly string CachePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BinaryHunter", "search-cache.json");

    public SearchCacheSnapshot CreateSnapshot(SearchOptions options, Action<int>? reportFilesIndexed = null)
    {
        var files = new FileScanner()
            .Scan(options.Folder, options.SearchSubFolders, options.SkipCommonBuildFolders)
            .OrderBy(file => file.FullPath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var includedFiles = 0;
        for (var index = 0; index < files.Length; index++)
        {
            var file = files[index];
            if (!TryGetLastWriteTimeUtc(file.FullPath, out var lastWriteTicks)) continue;

            var entry = $"{file.FullPath}\u001F{file.Size}\u001F{lastWriteTicks}\n";
            hash.AppendData(Encoding.UTF8.GetBytes(entry));
            includedFiles++;
            if (includedFiles % 100 == 0) reportFilesIndexed?.Invoke(includedFiles);
        }

        reportFilesIndexed?.Invoke(includedFiles);
        return new SearchCacheSnapshot
        {
            FileCount = includedFiles,
            Fingerprint = Convert.ToHexString(hash.GetHashAndReset())
        };
    }

    public bool TryGet(SearchOptions options, SearchCacheSnapshot snapshot, out IReadOnlyList<SearchResult> results)
    {
        results = [];
        var entry = LoadEntries().FirstOrDefault(candidate =>
            candidate.Version == CacheVersion &&
            candidate.QueryKey == CreateQueryKey(options) &&
            candidate.FileCount == snapshot.FileCount &&
            candidate.Fingerprint == snapshot.Fingerprint);
        if (entry is null) return false;

        results = entry.Results;
        return true;
    }

    public void Store(SearchOptions options, SearchCacheSnapshot snapshot, IReadOnlyList<SearchResult> results)
    {
        try
        {
            var entries = LoadEntries()
                .Where(entry => entry.QueryKey != CreateQueryKey(options))
                .Take(49)
                .ToList();
            entries.Insert(0, new CacheEntry
            {
                Version = CacheVersion,
                QueryKey = CreateQueryKey(options),
                FileCount = snapshot.FileCount,
                Fingerprint = snapshot.Fingerprint,
                Results = results.ToList()
            });

            Directory.CreateDirectory(Path.GetDirectoryName(CachePath)!);
            var temporaryPath = CachePath + ".tmp";
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(entries));
            File.Move(temporaryPath, CachePath, true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static List<CacheEntry> LoadEntries()
    {
        try
        {
            return JsonSerializer.Deserialize<List<CacheEntry>>(File.ReadAllText(CachePath)) ?? [];
        }
        catch (IOException) { return []; }
        catch (UnauthorizedAccessException) { return []; }
        catch (JsonException) { return []; }
    }

    private static string CreateQueryKey(SearchOptions options) => string.Join("\u001F",
        CacheVersion, options.Folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
        options.SearchText, options.SearchType, options.SearchSubFolders, options.StopAfterFirstMatch,
        options.MaxResults, options.SkipCommonBuildFolders);

    private sealed class CacheEntry
    {
        public int Version { get; set; }
        public string QueryKey { get; set; } = string.Empty;
        public int FileCount { get; set; }
        public string Fingerprint { get; set; } = string.Empty;
        public List<SearchResult> Results { get; set; } = [];
    }

    private static bool TryGetLastWriteTimeUtc(string path, out long ticks)
    {
        try
        {
            ticks = File.GetLastWriteTimeUtc(path).Ticks;
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            ticks = 0;
            return false;
        }
        catch (PathTooLongException)
        {
            ticks = 0;
            return false;
        }
        catch (IOException)
        {
            ticks = 0;
            return false;
        }
    }
}

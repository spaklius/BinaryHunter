using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using BinaryHunter.Core.Enums;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Services;

public sealed class BinarySearchService
{
    private const int BufferSize = 64 * 1024;

    public IReadOnlyList<SearchResult> Search(
        SearchOptions options,
        CancellationToken cancellationToken = default,
        Action<int>? reportFilesScanned = null,
        Action<SearchResult>? reportMatch = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var patterns = CreatePatterns(options.SearchText, options.SearchType);
        if (patterns.Count == 0 || !Directory.Exists(options.Folder)) return [];

        var results = new ConcurrentBag<SearchResult>();
        var filesScanned = 0;
        var matchesFound = 0;
        var files = new FileScanner().Scan(options.Folder, options.SearchSubFolders, options.SkipCommonBuildFolders);
        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.MaxDegreeOfParallelism) };

        Parallel.ForEach(files, parallelOptions, file =>
        {
            if (cancellationToken.IsCancellationRequested) return;
            var scanned = Interlocked.Increment(ref filesScanned);
            if (scanned % 100 == 0) reportFilesScanned?.Invoke(scanned);
            foreach (var (pattern, matchType) in patterns)
            {
                foreach (var offset in FindMatches(file.FullPath, pattern, options.StopAfterFirstMatch, cancellationToken))
                {
                    if (Interlocked.Increment(ref matchesFound) > options.MaxResults) return;
                    var result = new SearchResult
                    {
                        FileName = file.Name,
                        FullPath = file.FullPath,
                        Offset = offset,
                        MatchType = matchType,
                        Value = options.SearchText,
                        ContextHex = ReadHexContext(file.FullPath, offset)
                    };
                    results.Add(result);
                    reportMatch?.Invoke(result);
                }
            }
        });

        reportFilesScanned?.Invoke(filesScanned);
        return results.OrderBy(result => result.FullPath).ThenBy(result => result.Offset).ToArray();
    }

    public IReadOnlyList<SearchResult> SearchFiles(
        IReadOnlyList<string> paths,
        string searchText,
        SearchType searchType,
        bool stopAfterFirstMatch,
        int maxResults,
        CancellationToken cancellationToken = default,
        Action<int>? reportFilesScanned = null,
        Action<SearchResult>? reportMatch = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var patterns = CreatePatterns(searchText, searchType);
        if (patterns.Count == 0 || paths.Count == 0) return [];

        var results = new List<SearchResult>();
        var filesScanned = 0;
        foreach (var path in paths.Where(File.Exists))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var (pattern, matchType) in patterns)
            {
                foreach (var offset in FindMatches(path, pattern, stopAfterFirstMatch, cancellationToken))
                {
                    if (results.Count >= maxResults) return results;
                    var result = new SearchResult
                    {
                        FileName = Path.GetFileName(path),
                        FullPath = Path.GetFullPath(path),
                        Offset = offset,
                        MatchType = matchType,
                        Value = searchText,
                        ContextHex = ReadHexContext(path, offset)
                    };
                    results.Add(result);
                    reportMatch?.Invoke(result);
                }
            }

            reportFilesScanned?.Invoke(++filesScanned);
        }

        return results;
    }

    private static IReadOnlyList<(byte[] Pattern, string MatchType)> CreatePatterns(string value, SearchType type)
    {
        if (string.IsNullOrEmpty(value)) return [];
        if (type != SearchType.Auto) return [(CreatePattern(value, type), type.ToString())];

        var candidates = new List<(byte[] Pattern, string MatchType)>
        {
            (Encoding.UTF8.GetBytes(value), "UTF-8"),
            (Encoding.Unicode.GetBytes(value), "UTF-16 LE"),
            (Encoding.BigEndianUnicode.GetBytes(value), "UTF-16 BE")
        };
        if (TryParseHex(value, out var hexPattern)) candidates.Add((hexPattern, "Hex"));
        return candidates
            .GroupBy(candidate => Convert.ToHexString(candidate.Item1))
            .Select(candidate => (candidate.First().Item1, candidate.First().Item2))
            .ToArray();
    }

    public static byte[] CreatePattern(string value, SearchType type) => type switch
    {
        SearchType.Hex => ParseHex(value),
        SearchType.Utf16 => Encoding.Unicode.GetBytes(value),
        SearchType.Int16 => BitConverter.GetBytes(short.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.UInt16 => BitConverter.GetBytes(ushort.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.Int32 => BitConverter.GetBytes(int.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.UInt32 => BitConverter.GetBytes(uint.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.Int64 => BitConverter.GetBytes(long.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.UInt64 => BitConverter.GetBytes(ulong.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.Float => BitConverter.GetBytes(float.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.Double => BitConverter.GetBytes(double.Parse(value, CultureInfo.InvariantCulture)),
        SearchType.Ascii => Encoding.ASCII.GetBytes(value),
        _ => Encoding.UTF8.GetBytes(value)
    };

    private static IReadOnlyList<long> FindMatches(string path, byte[] pattern, bool firstOnly, CancellationToken token)
    {
        var matches = new List<long>();
        byte[]? buffer = null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, BufferSize, FileOptions.SequentialScan);
            buffer = ArrayPool<byte>.Shared.Rent(BufferSize + pattern.Length - 1);
            var carry = 0;
            long position = 0;
            while (true)
            {
                if (token.IsCancellationRequested) return matches;
                var read = stream.Read(buffer, carry, BufferSize);
                if (read == 0) break;
                var available = carry + read;
                var searchStart = 0;
                while (searchStart <= available - pattern.Length)
                {
                    var relativeIndex = buffer.AsSpan(searchStart, available - searchStart).IndexOf(pattern);
                    if (relativeIndex < 0) break;
                    var index = searchStart + relativeIndex;
                    matches.Add(position - carry + index);
                    if (firstOnly) return matches;
                    searchStart = index + 1;
                }
                carry = Math.Min(pattern.Length - 1, available);
                Buffer.BlockCopy(buffer, available - carry, buffer, 0, carry);
                position += read;
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        finally
        {
            if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
        }
        return matches;
    }

    private static string ReadHexContext(string path, long offset)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var start = Math.Max(0, offset - 8);
            stream.Position = start;
            var buffer = new byte[Math.Min(32, (int)Math.Max(0, stream.Length - start))];
            var read = stream.Read(buffer, 0, buffer.Length);
            return string.Join(" ", buffer.AsSpan(0, read).ToArray().Select(value => value.ToString("X2")));
        }
        catch (IOException)
        {
            return string.Empty;
        }
        catch (UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    private static byte[] ParseHex(string value)
    {
        if (!TryParseHex(value, out var bytes)) throw new FormatException("Hexadecimal values must contain complete byte pairs.");
        return bytes;
    }

    private static bool TryParseHex(string value, out byte[] bytes)
    {
        var compact = new string(value.Where(character => !char.IsWhiteSpace(character) && character != '-').ToArray());
        if (compact.Length == 0 || compact.Length % 2 != 0)
        {
            bytes = [];
            return false;
        }
        try
        {
            bytes = Convert.FromHexString(compact);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}

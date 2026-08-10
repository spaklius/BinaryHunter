using System.Security;

namespace BinaryHunter.Core.Services;

public sealed class FileScanner
{
    public IEnumerable<BinaryHunter.Core.Models.FileEntry> Scan(string rootFolder, bool includeSubfolders, bool skipCommonBuildFolders = false)
    {
        if (!Directory.Exists(rootFolder))
            yield break;

        if (!includeSubfolders)
        {
            foreach (var file in SafeEnumerateFiles(rootFolder))
            {
                var entry = ToFileEntry(file);
                if (entry is not null) yield return entry;
            }

            yield break;
        }

        var folders = new Stack<string>();
        folders.Push(rootFolder);

        while (folders.Count > 0)
        {
            var currentFolder = folders.Pop();

            foreach (var file in SafeEnumerateFiles(currentFolder))
            {
                var entry = ToFileEntry(file);
                if (entry is not null) yield return entry;
            }

            foreach (var folder in SafeEnumerateDirectories(currentFolder))
            {
                if (!skipCommonBuildFolders || !IsExcludedFolder(folder)) folders.Push(folder);
            }
        }
    }

    private static BinaryHunter.Core.Models.FileEntry? ToFileEntry(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return new BinaryHunter.Core.Models.FileEntry
            {
                Name = info.Name,
                FullPath = info.FullName,
                Extension = info.Extension,
                Size = info.Length
            };
        }
        catch (PathTooLongException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (SecurityException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static bool IsExcludedFolder(string path) => Path.GetFileName(path) is "bin" or "obj" or ".git" or ".vs";

    private static IEnumerable<string> SafeEnumerateFiles(string folder)
    {
        IEnumerator<string>? enumerator = null;

        try
        {
            enumerator = Directory.EnumerateFiles(folder).GetEnumerator();
        }
        catch
        {
            yield break;
        }

        using (enumerator)
        {
            while (enumerator.MoveNext())
                yield return enumerator.Current;
        }
    }

    private static IEnumerable<string> SafeEnumerateDirectories(string folder)
    {
        IEnumerator<string>? enumerator = null;

        try
        {
            enumerator = Directory.EnumerateDirectories(folder).GetEnumerator();
        }
        catch
        {
            yield break;
        }

        using (enumerator)
        {
            while (enumerator.MoveNext())
                yield return enumerator.Current;
        }
    }
}

using BinaryHunter.Core.Plugins;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;

namespace BinaryHunter.UI;

public sealed record PluginCatalogItem(IBinaryHunterPlugin? Plugin, string Name, string Type,
    string Version, string Author, string Description, string Source, string Status);

internal static class PluginCatalog
{
    private static readonly object Gate = new();
    private static IReadOnlyList<PluginCatalogItem>? _cached;

    public static IReadOnlyList<PluginCatalogItem> Load(bool refresh = false)
    {
        lock (Gate)
        {
            if (!refresh && _cached is not null) return _cached;
            var items = new List<PluginCatalogItem>
            {
                BuiltIn("BinaryHunter checksum engine", "Checksum", "Additive, XOR, CRC16 and CRC32 manual checksum blocks"),
                BuiltIn("BinaryHunter script engine", "Automation", "Sandboxed preview-first binary and map automation"),
                BuiltIn("BinaryHunter calibration importer", "Import / Export", "A2L, DAMOS and Driver / Map Pack definitions")
            };
            var directory = Path.Combine(AppContext.BaseDirectory, "Plugins");
            if (Directory.Exists(directory))
            {
                foreach (var path in Directory.EnumerateFiles(directory, "*.dll", SearchOption.TopDirectoryOnly))
                    LoadAssembly(path, items);
            }
            _cached = items;
            return _cached;
        }
    }

    public static IReadOnlyList<IChecksumPlugin> ChecksumPlugins() =>
        Load().Select(item => item.Plugin).OfType<IChecksumPlugin>().ToList();

    private static void LoadAssembly(string path, List<PluginCatalogItem> items)
    {
        try
        {
            var assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(path));
            var types = assembly.GetTypes().Where(type => !type.IsAbstract && typeof(IBinaryHunterPlugin).IsAssignableFrom(type));
            var found = false;
            foreach (var type in types)
            {
                found = true;
                try
                {
                    if (Activator.CreateInstance(type) is not IBinaryHunterPlugin plugin) continue;
                    items.Add(new PluginCatalogItem(plugin, plugin.Name, PluginType(plugin), plugin.Version.ToString(),
                        plugin.Author, plugin.Description, Path.GetFileName(path), "Loaded"));
                }
                catch (Exception exception)
                {
                    items.Add(new PluginCatalogItem(null, type.Name, "Unknown", "-", "-", exception.Message,
                        Path.GetFileName(path), "Failed"));
                }
            }
            if (!found) items.Add(new PluginCatalogItem(null, Path.GetFileNameWithoutExtension(path), "Unknown", "-", "-",
                "Assembly contains no IBinaryHunterPlugin implementation.", Path.GetFileName(path), "Ignored"));
        }
        catch (Exception exception)
        {
            items.Add(new PluginCatalogItem(null, Path.GetFileNameWithoutExtension(path), "Unknown", "-", "-",
                exception.Message, Path.GetFileName(path), "Failed"));
        }
    }

    private static string PluginType(IBinaryHunterPlugin plugin)
    {
        var types = new List<string>();
        if (plugin is IChecksumPlugin) types.Add("Checksum");
        if (plugin is IImportExportPlugin) types.Add("Import / Export");
        if (plugin is IAnalysisPlugin) types.Add("Analysis");
        return types.Count == 0 ? "General" : string.Join(", ", types);
    }

    private static PluginCatalogItem BuiltIn(string name, string type, string description) =>
        new(null, name, type, "1.0", "BinaryHunter", description, "Built-in", "Ready");
}

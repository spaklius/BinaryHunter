using System.Collections.ObjectModel;
using System.Windows;

namespace BinaryHunter.UI;

public sealed class HexBookmarkItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public int Slot { get; set; } = -1;
    public string Name { get; set; } = string.Empty;
    public int Offset { get; set; }
    public int Length { get; set; } = 1;
    public string Note { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string SlotLabel => Slot >= 0 ? Slot.ToString() : "—";
    public string HexOffset => $"0x{Offset:X8}";

    public HexBookmarkItem Clone() => new()
    {
        Id = Id,
        Slot = Slot,
        Name = Name,
        Offset = Offset,
        Length = Length,
        Note = Note,
        CreatedUtc = CreatedUtc
    };
}

public partial class BookmarkManagerWindow : Window
{
    private readonly int _currentOffset;
    private readonly int _currentLength;

    public ObservableCollection<HexBookmarkItem> Bookmarks { get; }
    public HexBookmarkItem? NavigateToBookmark { get; private set; }

    public BookmarkManagerWindow(IEnumerable<HexBookmarkItem> bookmarks, int currentOffset, int currentLength)
    {
        InitializeComponent();
        _currentOffset = currentOffset;
        _currentLength = Math.Max(1, currentLength);
        Bookmarks = new ObservableCollection<HexBookmarkItem>(bookmarks.Select(item => item.Clone()));
        DataContext = this;
    }

    private void AddButton_Click(object sender, RoutedEventArgs e)
    {
        var item = new HexBookmarkItem
        {
            Name = $"Bookmark at 0x{_currentOffset:X8}",
            Offset = _currentOffset,
            Length = _currentLength
        };
        Bookmarks.Add(item);
        BookmarksGrid.SelectedItem = item;
        BookmarksGrid.ScrollIntoView(item);
    }

    private void RemoveButton_Click(object sender, RoutedEventArgs e)
    {
        if (BookmarksGrid.SelectedItem is HexBookmarkItem item)
            Bookmarks.Remove(item);
    }

    private void GoButton_Click(object sender, RoutedEventArgs e)
    {
        if (BookmarksGrid.SelectedItem is not HexBookmarkItem item) return;
        NavigateToBookmark = item;
        DialogResult = true;
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}

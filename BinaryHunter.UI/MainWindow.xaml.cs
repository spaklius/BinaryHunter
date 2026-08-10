using BinaryHunter.Core.Enums;
using BinaryHunter.Core.Models;
using BinaryHunter.Core.Services;
using BinaryHunter.Core.Identification.Detectors;
using BinaryHunter.UI.Models;
using BinaryHunter.UI.Services;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Forms = System.Windows.Forms;

namespace BinaryHunter.UI;

public partial class MainWindow : Window
{
    private enum ApplicationWorkspace
    {
        Identifier,
        BinarySearch
    }

    public static MainWindow? Instance { get; private set; }

    private readonly ObservableCollection<SearchResult> _results = [];
    private readonly ObservableCollection<IdentifierMatch> _identifiers = [];
    private readonly ObservableCollection<LoadedBinaryFile> _loadedFiles = [];
    private CancellationTokenSource? _searchCancellation;
    private bool _isIdentifying;
    private string? _selectedSearchFolder;
    private EcuIdentification? _currentIdentification;
    private IReadOnlyList<SupportedEcuGroup> _supportedEcuGroups = [];
    internal string? _selectedDetectorName;
    private ApplicationWorkspace _currentWorkspace;

    public MainWindow()
    {
        InitializeComponent();
        WindowSizing.Configure(this, preferredWidth: 1280, preferredHeight: 840);
        Instance = this;
        SearchTypeComboBox.ItemsSource = Enum.GetValues<SearchType>();
        FilesGrid.ItemsSource = _results;
        IdentificationGrid.ItemsSource = _identifiers;
        LoadedFilesControl.ItemsSource = _loadedFiles;
        RefreshSupportedEcuList();
        RefreshDetectorSelector();
        AutomaticDetectorRegistry.ModulesChanged += () => Dispatcher.Invoke(() =>
        {
            RefreshSupportedEcuList();
            RefreshDetectorSelector();
        });
        LocationChanged += (_, _) => DetectorToggle.IsChecked = false;
        ShowWorkspace(ApplicationWorkspace.Identifier);
        UpdateLoadedFileUi();
    }

    private void RefreshDetectorSelector()
    {
        var modules = AutomaticDetectorRegistry.DetectModules.ToList();

        var grouped = modules
            .Select(m => new DetectorItem { Name = m.Name, Manufacturer = m.Manufacturer })
            .GroupBy(d => d.Manufacturer, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key)
            .Select(g => new DetectorGroup
            {
                ManufacturerName = g.Key,
                Detectors = g.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToList()
            })
            .ToList();

        DetectorGroupsControl.ItemsSource = grouped;
        _selectedDetectorName = null;
        UpdateDetectorToggleText("Auto — all detectors");
    }

    private void UpdateDetectorToggleText(string text)
    {
        DetectorToggle.Content = text;
    }

    private void AutoOption_Click(object sender, MouseButtonEventArgs e)
    {
        _selectedDetectorName = null;
        UpdateDetectorToggleText("Auto — all detectors");
        DetectorToggle.IsChecked = false;
    }

    private void DetectorItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button button && button.DataContext is DetectorItem item)
        {
            _selectedDetectorName = item.Name;
            UpdateDetectorToggleText(item.Name);
            DetectorToggle.IsChecked = false;
        }
    }

    public sealed class DetectorItem
    {
        public string Name { get; init; } = string.Empty;
        public string Manufacturer { get; init; } = string.Empty;
        public bool IsAuto { get; init; }
    }

    public sealed class DetectorGroup
    {
        public string ManufacturerName { get; init; } = string.Empty;
        public IReadOnlyList<DetectorItem> Detectors { get; init; } = Array.Empty<DetectorItem>();
    }

    private void RefreshSupportedEcuList()
    {
        _supportedEcuGroups = SupportedEcuCatalog.CreateGroups();
        SupportedProfileCountText.Text = $"{_supportedEcuGroups.Count} vehicle groups  •  {_supportedEcuGroups.Sum(group => group.Count)} automatic profiles";
    }

    private void IdentifyNavigationToggle_Click(object sender, RoutedEventArgs e)
    {
        ShowWorkspace(ApplicationWorkspace.Identifier);
    }

    private void SearchNavigationToggle_Click(object sender, RoutedEventArgs e)
    {
        ShowWorkspace(ApplicationWorkspace.BinarySearch);
    }

    private void ShowWorkspace(int index) => ShowWorkspace((ApplicationWorkspace)index);

    private void ShowWorkspace(ApplicationWorkspace workspace)
    {
        if (IdentifyNavigationToggle is null || SearchNavigationToggle is null ||
            IdentifyWorkspacePanel is null || SearchWorkspacePanel is null) return;
        var showIdentify = workspace == ApplicationWorkspace.Identifier;
        var showSearch = workspace == ApplicationWorkspace.BinarySearch;
        IdentifyNavigationToggle.IsChecked = showIdentify;
        SearchNavigationToggle.IsChecked = showSearch;
        IdentifyWorkspacePanel.Visibility = showIdentify ? Visibility.Visible : Visibility.Collapsed;
        SearchWorkspacePanel.Visibility = showSearch ? Visibility.Visible : Visibility.Collapsed;
        _currentWorkspace = workspace;
        WorkspaceContent.MaxWidth = double.PositiveInfinity;
        WorkspaceContent.Margin = new Thickness(16);
        WorkspaceContent.HorizontalAlignment = System.Windows.HorizontalAlignment.Stretch;
        FooterContentGrid.MaxWidth = double.PositiveInfinity;
        FooterContentGrid.HorizontalAlignment = System.Windows.HorizontalAlignment.Stretch;
        RestoreStandardFooter();
    }

#if false // Hex Editor workspace removed from the application.
    private void UpdateHexFooter(HexEditorStatus status)
    {
        StatusText.Text =
            $"{status.FileName}   |   ADDR 0x{status.CursorOffset:X8}   |   " +
            $"VALUE {status.CurrentValue}   |   ORG {status.ReferenceValue}";
        StatusText.Foreground = status.IsDirty
            ? System.Windows.Media.Brushes.Gold
            : System.Windows.Media.Brushes.Gray;
        FooterLoadedFilesCountText.Text = status.IsDirty
            ? $"MODIFIED {status.ModifiedByteCount:N0} BYTE(S) • UNSAVED"
            : "NO UNSAVED CHANGES";
        FooterLoadedFilesCountText.Foreground = status.IsDirty
            ? System.Windows.Media.Brushes.Gold
            : System.Windows.Media.Brushes.Gray;
        var selection = status.SelectionLength > 0
            ? $" • SEL {status.SelectionLength:N0} B"
            : string.Empty;
        var connection = status.IsConnected
            ? $" • LINK {status.ConnectedFileName}"
            : string.Empty;
        FooterModeText.Text =
            $"{status.DataWidthBits}-BIT {status.Endian}{selection}{connection}";
    }

    private void RestoreStandardFooter()
    {
        FooterLoadedFilesCountText.Foreground = System.Windows.Media.Brushes.Gray;
        FooterModeText.Text = "Automotive ECU Micro, Calibration & Maps Analyzer";
        UpdateLoadedFileUi();
    }

    private HexEditorControl ActiveHexEditor =>
        HexDocumentList.SelectedItem is HexDocumentSession document
            ? document.Editor
            : _emptyHexWorkspaceEditor ?? IntegratedHexEditor;

    private HexEditorControl EmptyHexWorkspaceEditor
    {
        get
        {
            if (_emptyHexWorkspaceEditor is not null) return _emptyHexWorkspaceEditor;
            _emptyHexWorkspaceEditor = new HexEditorControl();
            ConfigureHexEditor(_emptyHexWorkspaceEditor);
            return _emptyHexWorkspaceEditor;
        }
    }

    private void ConfigureHexEditor(HexEditorControl editor)
    {
        editor.ShowCloseButton = false;
        editor.ShowInternalStatusBar = false;
        editor.StatusChanged += (_, status) =>
        {
            var document = _hexDocuments.FirstOrDefault(candidate => ReferenceEquals(candidate.Editor, editor));
            if (document is not null) HexDocumentList.Items.Refresh();
            if (_currentWorkspace == ApplicationWorkspace.HexEditor && ReferenceEquals(ActiveHexEditor, editor))
                UpdateHexFooter(status);
        };
        editor.CloseRequested += (_, _) => CloseHexDocument(editor);
        editor.OpenFileRequested += path => OpenHexDocument(path, enterWorkspace: true);
        editor.DocumentMinimizeRequested += (_, _) => MinimizeHexDocument(editor);
        editor.DocumentRestoreRequested += (_, _) => RestoreHexDocument(editor);
        editor.DocumentMaximizeRequested += (_, _) => ToggleHexDocumentMaximize(editor);
        editor.DocumentListRequested += (_, _) => ShowHexDocumentMenu(editor);
        editor.ProjectNavigatorVisibilityChanged += visible =>
        {
            if (ReferenceEquals(ActiveHexEditor, editor))
                ApplyHexProjectNavigatorVisibility(visible);
        };
    }

    private void AttachHexEditorChrome(HexEditorControl editor)
    {
        editor.DetachEditorChrome();
        HexMenuHost.Content = editor.MenuChrome;
        HexToolbarHost.Content = editor.ToolbarChrome;
        HexProjectNavigatorHost.Content = editor.ProjectNavigatorChrome;
        ApplyHexProjectNavigatorVisibility(editor.IsProjectNavigatorVisible);
    }

    private void ApplyHexProjectNavigatorVisibility(bool visible)
    {
        HexProjectNavigatorHost.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        HexProjectNavigatorSplitter.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        HexProjectNavigatorColumn.Width = visible ? new GridLength(238) : new GridLength(0);
        HexProjectNavigatorSplitterColumn.Width = visible ? new GridLength(5) : new GridLength(0);
    }

    private HexDocumentSession CreateHexDocumentSession(HexEditorControl editor)
    {
        if (ReferenceEquals(editor, IntegratedHexEditor))
            IntegratedHexEditorHost.Content = null;
        editor.PrepareForMdiDocument();
        var frame = new MdiDocumentFrame
        {
            DocumentTitle = Path.GetFileName(editor.CurrentPath) ?? "Untitled project",
            DocumentContent = editor,
            Width = Math.Max(620, Math.Min(980, HexDocumentDesktop.ActualWidth - 48)),
            Height = Math.Max(420, Math.Min(680, HexDocumentDesktop.ActualHeight - 48))
        };
        var cascade = _hexDocuments.Count * 28d;
        var session = new HexDocumentSession(editor, frame)
        {
            RestoreBounds = new Rect(24 + cascade, 24 + cascade, frame.Width, frame.Height)
        };
        Canvas.SetLeft(frame, session.RestoreBounds.X);
        Canvas.SetTop(frame, session.RestoreBounds.Y);
        frame.Activated += (_, _) => ActivateHexDocument(session);
        frame.MinimizeRequested += (_, _) => MinimizeHexDocument(editor);
        frame.MaximizeRestoreRequested += (_, _) => ToggleHexDocumentMaximize(editor);
        frame.CloseRequested += (_, _) => CloseHexDocument(editor);
        frame.BoundsChanged += (_, _) => CaptureHexDocumentBounds(session);
        HexDocumentDesktop.Children.Add(frame);
        return session;
    }

    private void CaptureHexDocumentBounds(HexDocumentSession session)
    {
        if (session.State != MdiDocumentState.Normal) return;
        session.RestoreBounds = new Rect(
            double.IsNaN(Canvas.GetLeft(session.Frame)) ? 0 : Canvas.GetLeft(session.Frame),
            double.IsNaN(Canvas.GetTop(session.Frame)) ? 0 : Canvas.GetTop(session.Frame),
            session.Frame.ActualWidth > 0 ? session.Frame.ActualWidth : session.Frame.Width,
            session.Frame.ActualHeight > 0 ? session.Frame.ActualHeight : session.Frame.Height);
    }

    private void ActivateHexDocument(HexDocumentSession session)
    {
        if (!ReferenceEquals(HexDocumentList.SelectedItem, session))
        {
            HexDocumentList.SelectedItem = session;
            return;
        }
        var nextZ = _hexDocuments.Count == 0
            ? 1
            : _hexDocuments.Max(document => System.Windows.Controls.Panel.GetZIndex(document.Frame)) + 1;
        System.Windows.Controls.Panel.SetZIndex(session.Frame, nextZ);
        foreach (var document in _hexDocuments)
            document.Frame.IsActive = ReferenceEquals(document, session);
        AttachHexEditorChrome(session.Editor);
        UpdateHexFooter(session.Editor.CurrentStatus);
        Dispatcher.BeginInvoke(() => session.Editor.Focus());
    }

    private HexEditorControl? OpenHexDocument(string path, long offset = 0, int length = 1,
        bool enterWorkspace = true, bool activate = true)
    {
        if (!File.Exists(path)) return null;
        var fullPath = Path.GetFullPath(path);
        var existing = _hexDocuments.FirstOrDefault(document =>
            string.Equals(document.FullPath, fullPath, StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            RestoreHexDocument(existing.Editor, activate: false);
            existing.Editor.NavigateTo(offset, length);
            if (activate) HexDocumentList.SelectedItem = existing;
            if (enterWorkspace) ShowWorkspace(ApplicationWorkspace.HexEditor);
            return existing.Editor;
        }

        var editor = _hexDocuments.Count == 0 && IntegratedHexEditor.CurrentPath is null
            ? IntegratedHexEditor
            : new HexEditorControl();
        if (!ReferenceEquals(editor, IntegratedHexEditor)) ConfigureHexEditor(editor);
        if (!editor.LoadFile(fullPath, offset, length)) return null;

        var session = CreateHexDocumentSession(editor);
        _hexDocuments.Add(session);
        if (activate || HexDocumentList.SelectedItem is null)
            HexDocumentList.SelectedItem = session;
        RefreshHexDocumentWorkspace();
        if (enterWorkspace) ShowWorkspace(ApplicationWorkspace.HexEditor);
        return editor;
    }

    private void CloseHexDocument(HexEditorControl editor)
    {
        var session = _hexDocuments.FirstOrDefault(document => ReferenceEquals(document.Editor, editor));
        if (session is null || !editor.ConfirmClose()) return;

        var closedIndex = _hexDocuments.IndexOf(session);
        var wasActive = ReferenceEquals(ActiveHexEditor, editor);
        session.Frame.DocumentContent = null;
        HexDocumentDesktop.Children.Remove(session.Frame);
        _hexDocuments.Remove(session);
        if (ReferenceEquals(editor, IntegratedHexEditor)) IntegratedHexEditor.ResetDocument();

        if (_hexDocuments.Count == 0)
        {
            HexDocumentList.SelectedItem = null;
            AttachHexEditorChrome(IntegratedHexEditor);
        }
        else if (wasActive)
        {
            HexDocumentList.SelectedIndex = Math.Min(closedIndex, _hexDocuments.Count - 1);
        }
        RefreshHexDocumentWorkspace();
    }

    private void RefreshHexDocumentWorkspace()
    {
        HexDocumentList.Items.Refresh();
        EmptyHexDocumentDesktop.Visibility = _hexDocuments.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
        foreach (var document in _hexDocuments)
        {
            document.Frame.DocumentTitle = document.DisplayName;
            document.Editor.OpenDocumentCount = _hexDocuments.Count;
            document.Editor.IsDocumentMaximized = document.IsMaximized;
            document.Frame.ApplyState(document.State);
        }
        ApplyHexDocumentBounds();
        if (_currentWorkspace == ApplicationWorkspace.HexEditor)
            UpdateHexFooter(ActiveHexEditor.CurrentStatus);
    }

    private void HexDocumentList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HexDocumentList.SelectedItem is HexDocumentSession selected)
            ActivateHexDocument(selected);
    }

    private void MinimizeHexDocument(HexEditorControl editor)
    {
        var session = _hexDocuments.FirstOrDefault(document => ReferenceEquals(document.Editor, editor));
        if (session is null) return;
        CaptureHexDocumentBounds(session);
        session.State = MdiDocumentState.Minimized;
        session.Frame.ApplyState(session.State);
        ArrangeMinimizedHexDocuments();
        var next = _hexDocuments.FirstOrDefault(document => !document.IsMinimized && !ReferenceEquals(document, session));
        if (next is not null)
            HexDocumentList.SelectedItem = next;
        else
            ActivateHexDocument(session);
        RefreshHexDocumentWorkspace();
    }

    private void RestoreHexDocument(HexEditorControl editor, bool activate = true)
    {
        var session = _hexDocuments.FirstOrDefault(document => ReferenceEquals(document.Editor, editor));
        if (session is null) return;
        session.State = MdiDocumentState.Normal;
        session.Frame.ApplyState(session.State);
        ApplyNormalHexDocumentBounds(session);
        ArrangeMinimizedHexDocuments();
        if (activate) ActivateHexDocument(session);
        RefreshHexDocumentWorkspace();
    }

    private void ToggleHexDocumentMaximize(HexEditorControl editor)
    {
        var session = _hexDocuments.FirstOrDefault(document => ReferenceEquals(document.Editor, editor));
        if (session is null) return;
        if (session.State == MdiDocumentState.Normal)
        {
            CaptureHexDocumentBounds(session);
            session.State = MdiDocumentState.Maximized;
            ApplyMaximizedHexDocumentBounds(session);
        }
        else
        {
            session.State = MdiDocumentState.Normal;
            ApplyNormalHexDocumentBounds(session);
        }
        session.Frame.ApplyState(session.State);
        editor.IsDocumentMaximized = session.IsMaximized;
        ActivateHexDocument(session);
        RefreshHexDocumentWorkspace();
    }

    private void ApplyHexDocumentBounds()
    {
        foreach (var document in _hexDocuments)
        {
            if (document.State == MdiDocumentState.Maximized)
                ApplyMaximizedHexDocumentBounds(document);
            else if (document.State == MdiDocumentState.Normal)
                ApplyNormalHexDocumentBounds(document);
        }
        ArrangeMinimizedHexDocuments();
    }

    private void ApplyNormalHexDocumentBounds(HexDocumentSession session)
    {
        var workspaceWidth = Math.Max(MdiDocumentFrame.MinimumDocumentWidth, HexDocumentDesktop.ActualWidth);
        var workspaceHeight = Math.Max(MdiDocumentFrame.MinimumDocumentHeight, HexDocumentDesktop.ActualHeight);
        var width = Math.Min(Math.Max(MdiDocumentFrame.MinimumDocumentWidth, session.RestoreBounds.Width), workspaceWidth);
        var height = Math.Min(Math.Max(MdiDocumentFrame.MinimumDocumentHeight, session.RestoreBounds.Height), workspaceHeight);
        var left = Math.Clamp(session.RestoreBounds.X, 0, Math.Max(0, workspaceWidth - width));
        var top = Math.Clamp(session.RestoreBounds.Y, 0, Math.Max(0, workspaceHeight - height));
        session.Frame.Width = width;
        session.Frame.Height = height;
        Canvas.SetLeft(session.Frame, left);
        Canvas.SetTop(session.Frame, top);
    }

    private void ApplyMaximizedHexDocumentBounds(HexDocumentSession session)
    {
        session.Frame.Width = Math.Max(0, HexDocumentDesktop.ActualWidth);
        session.Frame.Height = Math.Max(0, HexDocumentDesktop.ActualHeight);
        Canvas.SetLeft(session.Frame, 0);
        Canvas.SetTop(session.Frame, 0);
    }

    private void ArrangeMinimizedHexDocuments()
    {
        const double tileWidth = 252;
        const double tileHeight = 32;
        const double gap = 6;
        var workspaceWidth = Math.Max(tileWidth, HexDocumentDesktop.ActualWidth);
        var columns = Math.Max(1, (int)((workspaceWidth - gap) / (tileWidth + gap)));
        var minimized = _hexDocuments.Where(document => document.IsMinimized).ToList();
        for (var index = 0; index < minimized.Count; index++)
        {
            var row = index / columns;
            var column = index % columns;
            var frame = minimized[index].Frame;
            frame.Width = Math.Min(tileWidth, workspaceWidth - gap * 2);
            frame.Height = tileHeight;
            Canvas.SetLeft(frame, gap + column * (tileWidth + gap));
            Canvas.SetTop(frame, Math.Max(0, HexDocumentDesktop.ActualHeight - gap - tileHeight - row * (tileHeight + gap)));
        }
    }

    private void HexEditorWorkspacePanel_SizeChanged(object sender, SizeChangedEventArgs e) =>
        ApplyHexDocumentBounds();

    private void ShowHexDocumentMenu(HexEditorControl requestingEditor)
    {
        var menu = new ContextMenu
        {
            PlacementTarget = HexToolbarHost,
            Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom
        };
        foreach (var document in _hexDocuments)
        {
            var item = new MenuItem
            {
                Header = document.IsMinimized ? $"{document.DisplayName}  [minimized]" : document.DisplayName,
                IsCheckable = true,
                IsChecked = ReferenceEquals(document.Editor, ActiveHexEditor),
                Tag = document
            };
            item.Click += (_, _) =>
            {
                RestoreHexDocument(document.Editor);
            };
            menu.Items.Add(item);
        }
        if (_hexDocuments.Count == 0)
        {
            menu.Items.Add(new MenuItem { Header = "No open documents", IsEnabled = false });
        }
        else
        {
            menu.Items.Add(new Separator());
        }
        var open = new MenuItem { Header = "Open ECU/BIN document..." };
        open.Click += (_, _) => OpenHexEditorButton_Click(open, new RoutedEventArgs());
        menu.Items.Add(open);
        menu.IsOpen = true;
    }

    private void OpenHexEditorButton_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.OpenFileDialog
        {
            Title = "Open binary in Hex Editor",
            Filter = "ECU and binary files|*.bin;*.dtf;*.ori;*.hex;*.srec;*.s19;*.mot|All files|*.*"
        };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
        OpenHexDocument(dialog.FileName, enterWorkspace: true);
    }

    private void CompareHexFilesButton_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.OpenFileDialog
        {
            Title = "Select exactly two files to compare",
            Filter = "ECU and binary files|*.bin;*.dtf;*.ori;*.hex;*.srec;*.s19;*.mot|All files|*.*",
            Multiselect = true
        };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
        if (dialog.FileNames.Length != 2)
        {
            System.Windows.MessageBox.Show("Select exactly two files for comparison.", "Hex Editor",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var primary = OpenHexDocument(dialog.FileNames[0], enterWorkspace: false);
        if (primary is null) return;
        OpenHexDocument(dialog.FileNames[1], enterWorkspace: false, activate: false);
        primary.LoadComparison(dialog.FileNames[1]);
        var primarySession = _hexDocuments.First(document => ReferenceEquals(document.Editor, primary));
        HexDocumentList.SelectedItem = primarySession;
        ShowWorkspace(ApplicationWorkspace.HexEditor);
    }

#endif

    private void RestoreStandardFooter()
    {
        FooterLoadedFilesCountText.Foreground = System.Windows.Media.Brushes.Gray;
        UpdateLoadedFileUi();
    }

    private void SupportedEcusButton_Click(object sender, RoutedEventArgs e)
    {
        new SupportedEcuWindow(_supportedEcuGroups) { Owner = this }.ShowDialog();
    }

    private async void IdentifyButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isIdentifying) return;

        using var dialog = new Forms.OpenFileDialog { Filter = "ECU and binary files|*.bin;*.dtf;*.ori;*.hex;*.srec;*.s19;*.mot|All files|*.*" };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;

        await IdentifyFileAsync(dialog.FileName);
    }

    private void AddFilesButton_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.OpenFileDialog
        {
            Filter = "ECU and binary files|*.bin;*.dtf;*.ori;*.hex;*.srec;*.s19;*.mot|All files|*.*",
            Multiselect = true
        };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
        foreach (var path in dialog.FileNames) AddLoadedFile(SampleEcuService.FromPath(path));
        if (_currentIdentification is null && dialog.FileNames.Length > 0)
            _ = IdentifyFileAsync(dialog.FileNames[0], addToLoadedFiles: false);
    }

    private void SearchFolderButton_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog
        {
            Description = "Choose a folder to search, including its subfolders",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false,
            InitialDirectory = _selectedSearchFolder ?? string.Empty
        };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;

        _selectedSearchFolder = Path.GetFullPath(dialog.SelectedPath);
        UpdateLoadedFileUi();
        StatusText.Text = $"Folder source added: {_selectedSearchFolder}";
    }

    private void RemoveSearchFolderButton_Click(object sender, RoutedEventArgs e)
    {
        _selectedSearchFolder = null;
        UpdateLoadedFileUi();
        StatusText.Text = "Folder source removed.";
    }

    private void RemoveLoadedFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: LoadedBinaryFile file }) return;
        _loadedFiles.Remove(file);
        UpdateLoadedFileUi();
    }

    private void AddLoadedFile(LoadedBinaryFile file)
    {
        var existing = _loadedFiles.FirstOrDefault(candidate =>
            string.Equals(candidate.FullPath, file.FullPath, StringComparison.OrdinalIgnoreCase));
        if (existing is not null) _loadedFiles.Remove(existing);
        _loadedFiles.Insert(0, file);
        UpdateLoadedFileUi();
    }

    private void UpdateLoadedFileUi()
    {
        var hasFolder = !string.IsNullOrWhiteSpace(_selectedSearchFolder);
        var sourceCount = _loadedFiles.Count + (hasFolder ? 1 : 0);
        if (LoadedFilesCountText is not null)
            LoadedFilesCountText.Text = $"Target Binary Sources ({sourceCount})";
        if (FooterLoadedFilesCountText is not null)
            FooterLoadedFilesCountText.Text = hasFolder
                ? $"{_loadedFiles.Count} File(s) + 1 Folder"
                : $"{_loadedFiles.Count} File(s) in Memory";
        if (FolderSourcePanel is not null)
            FolderSourcePanel.Visibility = hasFolder ? Visibility.Visible : Visibility.Collapsed;
        if (FolderSourceNameText is not null)
            FolderSourceNameText.Text = hasFolder ? Path.GetFileName(_selectedSearchFolder) : string.Empty;
        if (FolderSourcePathText is not null)
            FolderSourcePathText.Text = _selectedSearchFolder ?? string.Empty;
        if (EmptyLoadedFilesPanel is not null)
            EmptyLoadedFilesPanel.Visibility = sourceCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (SearchButton is not null)
            SearchButton.IsEnabled = sourceCount > 0 && !string.IsNullOrWhiteSpace(SearchTextBox?.Text);
    }

    private async void Window_Drop(object sender, System.Windows.DragEventArgs e)
    {
        if (_isIdentifying) return;
        if (!e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop)) return;
        var files = ((string[]?)e.Data.GetData(System.Windows.DataFormats.FileDrop))?.Where(File.Exists).ToArray() ?? [];
        if (files.Length == 0) return;

        foreach (var file in files) AddLoadedFile(SampleEcuService.FromPath(file));
        await IdentifyFileAsync(files[0], addToLoadedFiles: false);
        if (files.Length > 1) StatusText.Text = $"Identified the first of {files.Length:N0} dropped files.";
    }

    private void Window_PreviewDragOver(object sender, System.Windows.DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop) ? System.Windows.DragDropEffects.Copy : System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private async Task IdentifyFileAsync(string path, bool addToLoadedFiles = true)
    {
        if (addToLoadedFiles) AddLoadedFile(SampleEcuService.FromPath(path));
        _isIdentifying = true;
        AnalyzingPanel.Visibility = Visibility.Visible;
        ShowWorkspace(0);
        IdentificationTitleText.Text = Path.GetFileName(path);
        IdentificationSummaryText.Text = "Reading ECU file and locating identifiers…";
        IdentificationStatusText.Text = string.Empty;
        StatusText.Text = "Identifying file…";
        SetLiveIdentificationLoading();
        try
        {
            var detectorName = _selectedDetectorName;
            var identification = await Task.Run(() => string.IsNullOrWhiteSpace(detectorName)
                ? new EcuIdentifierService().Identify(path)
                : new EcuIdentifierService().Identify(path, detectorName));
            _currentIdentification = identification;
            _identifiers.Clear();
            foreach (var match in identification.Matches)
            {
                if (string.Equals(match.Type, "Calibration version", StringComparison.OrdinalIgnoreCase))
                    continue;

                _identifiers.Add(match);
            }
            ApplyIdentifierFilter();
            UpdateLiveIdentification(identification);
            IdentificationSummaryText.Text = $"{identification.FileSize:N0} bytes  •  SHA-256 {identification.Sha256[..16]}…  •  {_identifiers.Count:N0} identifiers found";
            IdentificationStatusText.Text = "Analyzed";
            IdentifierCountBadgeText.Text = $"{_identifiers.Count:N0} identifiers found";
            CopyDataButton.Content = "COPY DATA";
            StatusText.Text = $"Found {_identifiers.Count:N0} identifiers.";
        }
        catch (IOException exception)
        {
            SetLiveIdentificationError();
            System.Windows.MessageBox.Show(exception.Message, "Could not read file", MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Ready";
        }
        catch (UnauthorizedAccessException exception)
        {
            SetLiveIdentificationError();
            System.Windows.MessageBox.Show(exception.Message, "Could not read file", MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Ready";
        }
        catch (Exception exception) when (exception is OutOfMemoryException or JsonException or FormatException)
        {
            // Corrupt file, an unusually huge image, or a damaged cache entry.
            // Caught explicitly (rather than letting the global handler take it)
            // so the workspace resets to a usable state instead of staying stuck mid-scan.
            SetLiveIdentificationError();
            System.Windows.MessageBox.Show(
                $"Could not analyze this file: {exception.Message}",
                "Analysis failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Ready";
        }
        finally
        {
            _isIdentifying = false;
            AnalyzingPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void SetLiveIdentificationLoading()
    {
        SetReadFormatVisual("...", "Analyzing", "Reading binary structure", "#242424", "#555555", "#D51E27", "#FFFFFF");
        SetBrandVisual("--", "Detecting...", "Vehicle / ECU maker", "#242424", "#555555", "#3A3A3A");
        SetEcuProfileVisual("ECU", "Detecting...", "Scanning identifiers", "#242424", "#555555", "#3A3A3A");
    }

    private void IdentificationFilterTextBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyIdentifierFilter();

    private void ApplyIdentifierFilter()
    {
        if (IdentificationGrid is null) return;
        var filter = IdentificationFilterTextBox?.Text?.Trim() ?? string.Empty;
        var view = CollectionViewSource.GetDefaultView(_identifiers);
        view.Filter = item =>
        {
            if (filter.Length == 0 || item is not IdentifierMatch match) return true;
            return match.Type.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   match.Value.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   match.Offset.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   match.HexOffset.Contains(filter, StringComparison.OrdinalIgnoreCase);
        };
        view.Refresh();
        if (IdentificationRowsText is not null)
            IdentificationRowsText.Text = $"Showing {view.Cast<object>().Count():N0} of {_identifiers.Count:N0} rows";
    }

    private async void CopyDataButton_Click(object sender, RoutedEventArgs e)
    {
        if (_currentIdentification is null) return;
        var text = string.Join(Environment.NewLine, _identifiers.Select(match =>
            $"{match.Type}\t{match.Value}"));

        CopyDataButton.IsEnabled = false;
        CopyDataButton.Content = "Copying...";
        if (!await ClipboardService.TrySetTextAsync(text))
        {
            CopyDataButton.IsEnabled = true;
            CopyDataButton.Content = "COPY DATA";
            StatusText.Text = "Clipboard is busy. Try copying again.";
            return;
        }

        CopyDataButton.IsEnabled = true;
        CopyDataButton.Content = "Copied";
        StatusText.Text = "Identification data copied to the clipboard.";
        await Task.Delay(1500);
        if (Equals(CopyDataButton.Content, "Copied"))
            CopyDataButton.Content = "COPY DATA";
    }

    private async void CopyIdentifierButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: IdentifierMatch match }) return;
        if (!await ClipboardService.TrySetTextAsync($"{match.Type}: {match.Value} (Offset: {match.HexOffset})"))
        {
            StatusText.Text = "Clipboard is busy. Try copying again.";
            return;
        }

        StatusText.Text = $"{match.Type} copied to the clipboard.";
    }

    private void OpenResultFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: SearchResult result }) return;
        var fullPath = Path.GetFullPath(result.FullPath);
        if (!File.Exists(fullPath))
        {
            System.Windows.MessageBox.Show(
                "The result file no longer exists at this location.",
                "Binary Hunter",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"/select,\"{fullPath}\"",
                UseShellExecute = true
            });
        }
        catch (Win32Exception exception)
        {
            System.Windows.MessageBox.Show(
                exception.Message,
                "Could not open folder",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void SetLiveIdentificationError()
    {
        SetReadFormatVisual("!", "Read failed", "Could not analyze file", "#351F21", "#8C3035", "#A52A32", "#FFFFFF");
        SetBrandVisual("--", "Not detected", "File could not be read", "#242424", "#555555", "#3A3A3A");
        SetEcuProfileVisual("ECU", "Not detected", "0 identifiers", "#242424", "#555555", "#3A3A3A");
    }

    private void UpdateLiveIdentification(EcuIdentification identification)
    {
        var readFormat = identification.Matches.FirstOrDefault(match =>
            string.Equals(match.Type, "Read format", StringComparison.OrdinalIgnoreCase));
        var ecuType = identification.Matches.FirstOrDefault(match =>
            string.Equals(match.Type, "ECU type", StringComparison.OrdinalIgnoreCase));
        var ecuFamily = identification.Matches.FirstOrDefault(match =>
            string.Equals(match.Type, "ECU family", StringComparison.OrdinalIgnoreCase));
        var isGenericAnalysis = identification.IsGenericAnalysis && ecuType is null && ecuFamily is null;
        var explicitFormat = readFormat?.Value ?? string.Empty;
        var isPartial = explicitFormat.Contains("partial", StringComparison.OrdinalIgnoreCase) ||
                        explicitFormat.Contains("calibration-only", StringComparison.OrdinalIgnoreCase) ||
                        explicitFormat.Contains("sparse", StringComparison.OrdinalIgnoreCase);
        var isFull = explicitFormat.Contains("full", StringComparison.OrdinalIgnoreCase) ||
                     (!isGenericAnalysis && !isPartial && (ecuType is not null || ecuFamily is not null));
        var size = FormatFileSize(identification.FileSize);

        if (isPartial)
        {
            SetReadFormatVisual("PART", "Partial read", size, "#342C1C", "#8B6925", "#A87517", "#FFE09A");
        }
        else if (isFull)
        {
            SetReadFormatVisual("FULL", "Full read", size, "#1C3326", "#347A50", "#2F8F55", "#E4FFEC");
        }
        else
        {
            SetReadFormatVisual("?", "Unconfirmed", size, "#242424", "#555555", "#3A3A3A", "#D0D0D0");
        }

        var vehicleGroup = identification.Matches.FirstOrDefault(match =>
            string.Equals(match.Type, "Vehicle group", StringComparison.OrdinalIgnoreCase));
        var ecuManufacturer = identification.Matches.FirstOrDefault(match =>
            string.Equals(match.Type, "ECU manufacturer", StringComparison.OrdinalIgnoreCase));
        if (isGenericAnalysis)
        {
            SetBrandVisual("GEN", "Generic", "No confirmed vehicle / ECU profile", "#24292D", "#56636B", "#46535B");
        }
        else
        {
            var brandMatch = vehicleGroup ?? ecuManufacturer;
            var brand = brandMatch is null ? "Not detected" : CleanEvidenceLabel(brandMatch.Value);
            var (brandBadge, brandColor) = GetBrandEmblem(brand);
            SetBrandVisual(
                brandBadge,
                brand,
                vehicleGroup is not null ? "Vehicle group" : ecuManufacturer is not null ? "ECU manufacturer" : "Vehicle / ECU maker",
                brandMatch is null ? "#242424" : "#20262D",
                brandMatch is null ? "#555555" : brandColor,
                brandMatch is null ? "#3A3A3A" : brandColor);
        }

        if (isGenericAnalysis)
        {
            var possibleIdentifiers = identification.Matches.Count(match =>
                !string.Equals(match.Type, "Analysis profile", StringComparison.OrdinalIgnoreCase));
            SetEcuProfileVisual("RAW", "Generic analysis", $"{possibleIdentifiers:N0} possible identifiers", "#29271F", "#756A3A", "#8A7628");
        }
        else
        {
            var profileManufacturer = ecuManufacturer is null ? string.Empty : CleanEvidenceLabel(ecuManufacturer.Value);
            var profile = CleanEvidenceLabel(ecuType?.Value ?? ecuFamily?.Value ?? "Not detected");
            if (string.Equals(profile, "E87", StringComparison.OrdinalIgnoreCase) &&
                profileManufacturer.StartsWith("Delco", StringComparison.OrdinalIgnoreCase))
            {
                profile = "Delco E87";
            }
            var profileDetail = string.IsNullOrEmpty(profileManufacturer)
                ? $"{identification.Matches.Count:N0} identifiers"
                : $"{profileManufacturer} | {identification.Matches.Count:N0} identifiers";
            var profileDetected = ecuType is not null || ecuFamily is not null;
            SetEcuProfileVisual(
                "ECU",
                profile,
                profileDetail,
                profileDetected ? "#2B2021" : "#242424",
                profileDetected ? "#8F3036" : "#555555",
                profileDetected ? "#D51E27" : "#3A3A3A");
        }
    }

    private void SetReadFormatVisual(string badge, string value, string detail, string background, string border, string badgeBackground, string badgeForeground)
    {
        ReadFormatBadgeText.Text = badge;
        ReadFormatValueText.Text = value;
        ReadFormatDetailText.Text = detail;
        ReadFormatCard.Background = UiBrush(background);
        ReadFormatCard.BorderBrush = UiBrush(border);
        ReadFormatBadge.Background = UiBrush(badgeBackground);
        ReadFormatBadgeText.Foreground = UiBrush(badgeForeground);
    }

    private void SetBrandVisual(string badge, string value, string detail, string background, string border, string badgeBackground)
    {
        DetectedBrandBadgeText.Text = badge;
        DetectedBrandValueText.Text = value;
        DetectedBrandDetailText.Text = detail;
        DetectedBrandCard.Background = UiBrush(background);
        DetectedBrandCard.BorderBrush = UiBrush(border);
        DetectedBrandBadge.Background = UiBrush(badgeBackground);

        var backgroundResource = GetBrandBackgroundResource(value);
        if (backgroundResource is null)
        {
            DetectedBrandBackgroundBrush.ImageSource = null;
            DetectedBrandBackgroundLayer.Visibility = Visibility.Collapsed;
        }
        else
        {
            DetectedBrandBackgroundBrush.ImageSource = new System.Windows.Media.Imaging.BitmapImage(
                new Uri(backgroundResource, UriKind.Absolute));
            DetectedBrandBackgroundLayer.Visibility = Visibility.Visible;
        }

        var iconResource = GetBrandIconResource(value);
        if (iconResource is null)
        {
            DetectedBrandBadgeImage.Source = null;
            DetectedBrandBadgeImage.Visibility = Visibility.Collapsed;
            DetectedBrandBadgeText.Visibility = Visibility.Visible;
            return;
        }

        DetectedBrandBadgeImage.Source = new System.Windows.Media.Imaging.BitmapImage(
            new Uri(iconResource, UriKind.Absolute));
        DetectedBrandBadgeImage.Visibility = Visibility.Visible;
        DetectedBrandBadgeText.Visibility = Visibility.Collapsed;
        DetectedBrandBadge.Background = UiBrush("#171717");
    }
    private void SetEcuProfileVisual(string badge, string value, string detail, string background, string border, string badgeBackground)
    {
        EcuProfileBadgeText.Text = badge;
        EcuProfileValueText.Text = value;
        EcuProfileDetailText.Text = detail;
        EcuProfileCard.Background = UiBrush(background);
        EcuProfileCard.BorderBrush = UiBrush(border);
        EcuProfileBadge.Background = UiBrush(badgeBackground);
    }

    private static string CleanEvidenceLabel(string value)
    {
        var evidenceStart = value.IndexOf(" (", StringComparison.Ordinal);
        return evidenceStart > 0 ? value[..evidenceStart].Trim() : value.Trim();
    }

    private static (string Emblem, string Color) GetBrandEmblem(string brand)
    {
        if (brand.Contains("Generic", StringComparison.OrdinalIgnoreCase)) return ("GEN", "#56636B");
        if (brand.Contains("BMW", StringComparison.OrdinalIgnoreCase)) return ("BMW", "#1C69D4");
        if (brand.Contains("Jaguar", StringComparison.OrdinalIgnoreCase) || brand.Contains("Land Rover", StringComparison.OrdinalIgnoreCase)) return ("JLR", "#6F8794");
        if (brand.Contains("Honda", StringComparison.OrdinalIgnoreCase)) return ("HON", "#C62828");
        if (brand.Contains("Volvo", StringComparison.OrdinalIgnoreCase)) return ("VOL", "#3974A8");
        if (brand.Contains("Volkswagen", StringComparison.OrdinalIgnoreCase) || brand.Contains("VAG", StringComparison.OrdinalIgnoreCase)) return ("VW", "#1974A8");
        if (brand.Contains("Ford", StringComparison.OrdinalIgnoreCase)) return ("FORD", "#1F65A2");
        if (brand.Contains("Mazda", StringComparison.OrdinalIgnoreCase)) return ("MZD", "#A71930");
        if (brand.Contains("Mercedes", StringComparison.OrdinalIgnoreCase)) return ("MB", "#6F8794");
        if (brand.Contains("PSA", StringComparison.OrdinalIgnoreCase) || brand.Contains("Stellantis", StringComparison.OrdinalIgnoreCase)) return ("PSA", "#315EAA");
        if (brand.Contains("Renault", StringComparison.OrdinalIgnoreCase) || brand.Contains("Nissan", StringComparison.OrdinalIgnoreCase)) return ("RN", "#C69A20");
        if (brand.Contains("Hyundai", StringComparison.OrdinalIgnoreCase) || brand.Contains("Kia", StringComparison.OrdinalIgnoreCase)) return ("HMG", "#164A83");
        if (brand.Contains("Toyota", StringComparison.OrdinalIgnoreCase) || brand.Contains("Lexus", StringComparison.OrdinalIgnoreCase)) return ("TOY", "#C62828");
        if (brand.Contains("General Motors", StringComparison.OrdinalIgnoreCase) || brand.Contains("Opel", StringComparison.OrdinalIgnoreCase) || brand.Contains("Vauxhall", StringComparison.OrdinalIgnoreCase) || brand.Equals("GM", StringComparison.OrdinalIgnoreCase)) return ("GM", "#3476A8");
        if (brand.Contains("Bosch", StringComparison.OrdinalIgnoreCase)) return ("BSH", "#C92B32");
        if (brand.Contains("Continental", StringComparison.OrdinalIgnoreCase) || brand.Contains("Siemens", StringComparison.OrdinalIgnoreCase)) return ("CTL", "#D98C19");
        if (brand.Contains("Denso", StringComparison.OrdinalIgnoreCase)) return ("DEN", "#397446");
        if (brand.Contains("Delphi", StringComparison.OrdinalIgnoreCase) || brand.Contains("Delco", StringComparison.OrdinalIgnoreCase)) return ("DLP", "#4969A7");
        if (brand.Contains("Marelli", StringComparison.OrdinalIgnoreCase)) return ("MAG", "#4277B3");
        return ("ECU", "#666666");
    }

    private static string? GetBrandBackgroundResource(string brand)
    {
        if (brand.Contains("Jaguar/Land Rover/PSA", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/JaguarLandRoverPsaGroupMark.png";
        if (brand.Contains("Jaguar", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("Land Rover", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/JaguarLandRoverGroupMark.png";
        if (brand.Contains("BMW", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/BmwMiniGroupMark.png";
        if (brand.Contains("Volkswagen", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("VAG", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("Audi", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/VagGroupMark.png";
        if (brand.Contains("Ford", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/FordGroupMark.png";
        if (brand.Contains("Honda", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/HondaGroupMark.png";
        if (brand.Contains("Mercedes", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/MercedesBenzGroupMark.png";
        if (brand.Contains("Mazda", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/MazdaGroupMark.png";
        if (brand.Contains("General Motors", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("Opel", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("Vauxhall", StringComparison.OrdinalIgnoreCase) ||
            brand.Equals("GM", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/OpelVauxhallGmGroupMark.png";
        if (brand.Contains("PSA", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("Stellantis", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/PsaStellantisGroupMark.png";
        if (brand.Contains("Renault", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("Nissan", StringComparison.OrdinalIgnoreCase) ||
            brand.Contains("Dacia", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/RenaultNissanDaciaGroupMark.png";
        if (brand.Contains("Volvo", StringComparison.OrdinalIgnoreCase))
            return "pack://application:,,,/Assets/VolvoGroupMark.png";

        return null;
    }
    private static string? GetBrandIconResource(string brand)
    {
        return null;
    }
    private static string FormatFileSize(long bytes)
    {
        const double kilobyte = 1024d;
        const double megabyte = kilobyte * 1024d;
        if (bytes >= megabyte) return $"{bytes / megabyte:0.##} MB | {bytes:N0} bytes";
        if (bytes >= kilobyte) return $"{bytes / kilobyte:0.##} KB | {bytes:N0} bytes";
        return $"{bytes:N0} bytes";
    }

    private static readonly Dictionary<string, SolidColorBrush> BrushCache = new(StringComparer.OrdinalIgnoreCase);

    private static SolidColorBrush UiBrush(string color)
    {
        if (BrushCache.TryGetValue(color, out var cached)) return cached;

        var brush = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(color));
        brush.Freeze();
        BrushCache[color] = brush;
        return brush;
    }

    private async void RunLoadedFilesSearchButton_Click(object sender, RoutedEventArgs e)
    {
        if (_searchCancellation is not null)
        {
            _searchCancellation.Cancel();
            return;
        }
        if (_loadedFiles.Count == 0 && string.IsNullOrWhiteSpace(_selectedSearchFolder))
        {
            System.Windows.MessageBox.Show("Add at least one target file or search folder.", "Binary Hunter",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrWhiteSpace(SearchTextBox.Text))
        {
            System.Windows.MessageBox.Show("Enter a value to search for.", "Binary Hunter",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!int.TryParse(MaxResultsTextBox.Text, out var maxResults)) maxResults = 1000;
        maxResults = Math.Max(10, maxResults);
        MaxResultsTextBox.Text = maxResults.ToString();
        var query = SearchTextBox.Text;
        var searchType = (SearchType)SearchTypeComboBox.SelectedItem;
        var stopAfterFirstMatch = FirstMatchCheckBox.IsChecked == true;
        var explicitPaths = _loadedFiles.Select(file => file.FullPath).ToArray();
        var selectedFolder = _selectedSearchFolder;

        _results.Clear();
        SearchResultsCard.Visibility = Visibility.Visible;
        ResultsHeaderText.Text = "Found 0 Matches in 0 File(s)";
        ResultsQueryText.Text = $"Query: \"{query}\" [{searchType}]";
        _searchCancellation = new CancellationTokenSource();
        var cancellationToken = _searchCancellation.Token;
        SetLoadedFilesSearchingState(true);
        try
        {
            var filesScanned = 0;
            IProgress<int> progress = new Progress<int>(count =>
            {
                filesScanned = count;
                StatusText.Text = $"Searching {count:N0} files...";
            });
            IProgress<SearchResult> matchProgress = new Progress<SearchResult>(result => _results.Add(result));
            var results = await Task.Run(() =>
            {
                var service = new BinarySearchService();
                var combined = new List<SearchResult>();
                var seen = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
                var folderFilesScanned = 0;

                void ReportUnique(SearchResult result)
                {
                    var key = $"{result.FullPath}\u001F{result.Offset}\u001F{result.MatchType}";
                    if (seen.TryAdd(key, 0)) matchProgress.Report(result);
                }

                if (!string.IsNullOrWhiteSpace(selectedFolder))
                {
                    var folderOptions = new SearchOptions
                    {
                        Folder = selectedFolder,
                        SearchText = query,
                        SearchType = searchType,
                        SearchSubFolders = true,
                        StopAfterFirstMatch = stopAfterFirstMatch,
                        MaxResults = maxResults,
                        SkipCommonBuildFolders = true
                    };
                    var folderResults = service.Search(
                        folderOptions,
                        cancellationToken,
                        count =>
                        {
                            folderFilesScanned = count;
                            progress.Report(count);
                        },
                        ReportUnique);
                    combined.AddRange(folderResults);
                }

                var standalonePaths = explicitPaths
                    .Where(path => string.IsNullOrWhiteSpace(selectedFolder) ||
                                   !IsPathInsideFolder(path, selectedFolder))
                    .ToArray();
                var remaining = Math.Max(0, maxResults - combined.Count);
                if (standalonePaths.Length > 0 && remaining > 0)
                {
                    var fileResults = service.SearchFiles(
                        standalonePaths,
                        query,
                        searchType,
                        stopAfterFirstMatch,
                        remaining,
                        cancellationToken,
                        count => progress.Report(folderFilesScanned + count),
                        ReportUnique);
                    combined.AddRange(fileResults);
                }

                return combined
                    .GroupBy(result => $"{result.FullPath}\u001F{result.Offset}\u001F{result.MatchType}",
                        StringComparer.OrdinalIgnoreCase)
                    .Select(group => group.First())
                    .Take(maxResults)
                    .ToArray();
            });
            if (cancellationToken.IsCancellationRequested)
            {
                StatusText.Text = "Search cancelled.";
                return;
            }
            ResultsHeaderText.Text = $"Found {results.Length:N0} Matches in {filesScanned:N0} File(s)";
            StatusText.Text = results.Length == maxResults
                ? $"Showing the first {results.Length:N0} matches."
                : $"Found {results.Length:N0} matches in {filesScanned:N0} files.";
        }
        catch (FormatException exception)
        {
            System.Windows.MessageBox.Show(exception.Message, "Invalid search value",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Ready";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Search cancelled.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            System.Windows.MessageBox.Show(exception.Message, "Search failed",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Ready";
        }
        finally
        {
            _searchCancellation?.Dispose();
            _searchCancellation = null;
            SetLoadedFilesSearchingState(false);
        }
    }

    private void SetLoadedFilesSearchingState(bool searching)
    {
        SearchButtonText.Text = searching ? "Cancel" : "Run Search";
        SearchButton.IsEnabled = searching ||
                                 ((_loadedFiles.Count > 0 || !string.IsNullOrWhiteSpace(_selectedSearchFolder)) &&
                                  !string.IsNullOrWhiteSpace(SearchTextBox.Text));
        SearchProgressBar.Visibility = searching ? Visibility.Visible : Visibility.Collapsed;
        if (searching) StatusText.Text = "Searching files...";
    }

    private static bool IsPathInsideFolder(string path, string folder)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(folder), Path.GetFullPath(path));
        return !Path.IsPathRooted(relative) &&
               !relative.Equals("..", StringComparison.Ordinal) &&
               !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }

    private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e) => UpdateLoadedFileUi();

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (_searchCancellation is not null)
        {
            _searchCancellation.Cancel();
            return;
        }
        if (!Directory.Exists(FolderTextBox.Text))
        {
            System.Windows.MessageBox.Show("Choose an existing folder.", "Binary Hunter", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (string.IsNullOrWhiteSpace(SearchTextBox.Text))
        {
            System.Windows.MessageBox.Show("Enter a value to search for.", "Binary Hunter", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var options = new SearchOptions
        {
            Folder = FolderTextBox.Text,
            SearchText = SearchTextBox.Text,
            SearchType = (SearchType)SearchTypeComboBox.SelectedItem,
            SearchSubFolders = SubfoldersCheckBox.IsChecked == true,
            StopAfterFirstMatch = FirstMatchCheckBox.IsChecked == true,
            SkipCommonBuildFolders = SkipBuildFoldersCheckBox.IsChecked == true
        };

        _results.Clear();
        _searchCancellation = new CancellationTokenSource();
        SetSearchingState(true);
        try
        {
            var cache = new SearchCacheService();
            var filesIndexed = 0;
            IProgress<int> cacheProgress = new Progress<int>(count =>
            {
                filesIndexed = count;
                StatusText.Text = $"Checking cache: {count:N0} files…";
            });
            var snapshot = await Task.Run(() => cache.CreateSnapshot(options, cacheProgress.Report));
            if (_searchCancellation.IsCancellationRequested)
            {
                StatusText.Text = "Search cancelled.";
                return;
            }
            if (UseCacheCheckBox.IsChecked == true && cache.TryGet(options, snapshot, out var cachedResults))
            {
                foreach (var result in cachedResults) _results.Add(result);
                StatusText.Text = $"Loaded {cachedResults.Count:N0} cached matches (verified {filesIndexed:N0} files).";
                return;
            }

            var filesScanned = 0;
            IProgress<int> progress = new Progress<int>(count =>
            {
                filesScanned = count;
                StatusText.Text = $"Searching {count:N0} files…";
            });
            IProgress<SearchResult> matchProgress = new Progress<SearchResult>(result => _results.Add(result));
            var results = await Task.Run(() => new BinarySearchService().Search(options, _searchCancellation.Token, progress.Report, matchProgress.Report));
            if (_searchCancellation.IsCancellationRequested)
            {
                StatusText.Text = "Search cancelled.";
                return;
            }
            if (UseCacheCheckBox.IsChecked == true && results.Count > 0)
                await Task.Run(() => cache.Store(options, snapshot, results));
            StatusText.Text = results.Count == options.MaxResults
                ? $"Showing the first {results.Count:N0} matches."
                : $"Found {results.Count:N0} matches in {filesScanned:N0} files.";
        }
        catch (FormatException exception)
        {
            System.Windows.MessageBox.Show(exception.Message, "Invalid search value", MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Ready";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            System.Windows.MessageBox.Show(exception.Message, "Search failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Ready";
        }
        finally
        {
            _searchCancellation?.Dispose();
            _searchCancellation = null;
            SetSearchingState(false);
        }
    }

    private void SetSearchingState(bool searching)
    {
        SearchButton.Content = searching ? "Cancel" : "Search";
        SearchProgressBar.Visibility = searching ? Visibility.Visible : Visibility.Collapsed;
        StatusText.Text = searching ? "Searching files…" : StatusText.Text;
    }


}

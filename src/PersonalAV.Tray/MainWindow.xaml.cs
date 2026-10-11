using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using PersonalAV.Core;
using PersonalAV.Core.Ipc;

namespace PersonalAV.Tray;

/// <summary>Dashboard: protection status, scan controls with live progress, and engine maintenance.</summary>
public partial class MainWindow : Window
{
    private static readonly Brush Good = Frozen(0x2E, 0x7D, 0x32);
    private static readonly Brush Busy = Frozen(0x15, 0x65, 0xC0);
    private static readonly Brush Attention = Frozen(0xB2, 0x6A, 0x00);
    private static readonly Brush Bad = Frozen(0xC6, 0x28, 0x28);
    private static readonly Brush Offline = Frozen(0x61, 0x61, 0x61);

    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private int _ticks;
    private bool _updateRunning;

    public MainWindow()
    {
        InitializeComponent();
        _timer.Tick += async (_, _) =>
        {
            await RefreshStatus();
            // Update status changes rarely, except while a check runs.
            if (_updateRunning || ++_ticks % 15 == 0)
            {
                await RefreshUpdates();
            }
        };
        Loaded += async (_, _) =>
        {
            _timer.Start();
            await RefreshStatus();
            await RefreshEngine();
            await RefreshUpdates();
        };
        Closed += (_, _) => _timer.Stop();
    }

    private static App TrayApp => (App)Application.Current;

    private async Task RefreshStatus()
    {
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.GetStatus), quiet: true);
        if (response is not { Ok: true })
        {
            SetBand(Offline, "Service unavailable",
                response?.Error ?? "Start the PersonalAV service, and run this app as Administrator.");
            SetScanControls(serviceUp: false, running: false);
            CountsText.Text = CurrentText.Text = "";
            return;
        }

        var s = response.DataAs<ScanStatus>()!;
        bool running = s.State == ScanState.Running;
        SetScanControls(serviceUp: true, running);
        Progress.IsIndeterminate = running;

        string kind = s.Kind?.ToString() ?? "Last";
        string finished = s.FinishedAt is { } at ? $" on {at.ToLocalTime():yyyy-MM-dd HH:mm}" : "";
        switch (s.State)
        {
            case ScanState.Running:
                SetBand(Busy, $"{kind} scan in progress...", s.Detections == 0
                    ? "No threats found so far."
                    : $"{s.Detections} threat(s) found so far and quarantined.");
                break;
            case ScanState.Idle when s.ScanId is null:
                SetBand(Attention, "No scan yet", "Run a Quick scan to check the places malware usually hides.");
                break;
            case ScanState.Completed when s.Detections == 0:
                SetBand(Good, "No threats found", $"{kind} scan finished{finished}.");
                break;
            case ScanState.Completed:
                SetBand(Bad, $"{s.Detections} threat(s) found",
                    $"{kind} scan finished{finished}. Detected files were quarantined; see Scan results.");
                break;
            case ScanState.Cancelled:
                SetBand(Attention, "Scan cancelled", $"{kind} scan was cancelled{finished}.");
                break;
            case ScanState.Failed:
                SetBand(Bad, "Scan failed", s.Message ?? $"{kind} scan failed{finished}.");
                break;
            default:
                SetBand(Attention, s.State.ToString(), s.Message ?? "");
                break;
        }

        CountsText.Text = s.ScanId is null
            ? ""
            : $"{s.FilesScanned:N0} scanned  ·  {s.FilesSkipped:N0} skipped  ·  {s.Errors:N0} errors  ·  {s.Detections} detections";
        CurrentText.Text = running ? s.CurrentPath ?? "" : s.Target ?? "";
    }

    private async Task RefreshEngine()
    {
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.GetEngineInfo), quiet: true);
        if (response is not { Ok: true })
        {
            HashText.Text = RulesText.Text = "-";
            return;
        }
        var info = response.DataAs<EngineInfo>()!;
        HashText.Text = $"{info.HashCount:N0} known-bad {(info.HashCount == 1 ? "hash" : "hashes")}";
        RulesText.Text = $"{info.YaraRuleCount:N0} rules from {info.YaraFilesLoaded} file(s)"
            + (info.YaraFailedFiles.Count == 0 ? "" : $", {info.YaraFailedFiles.Count} file(s) failed to compile");
    }

    private async Task RefreshUpdates()
    {
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.GetUpdateStatus), quiet: true);
        if (response is not { Ok: true } || response.DataAs<UpdateStatus>() is not { } u)
        {
            UpdatesText.Text = "-";
            UpdateButton.IsEnabled = false;
            return;
        }

        bool finished = _updateRunning && !u.Checking;
        _updateRunning = u.Checking;
        UpdateButton.IsEnabled = !u.Checking;
        bool failed = u.Rules.Error is not null || u.Hashes.Error is not null;
        UpdatesText.Foreground = failed && !u.Checking ? Attention : SystemColors.ControlTextBrush;
        if (u.Checking)
        {
            UpdatesText.Text = "Checking for updates...";
        }
        else if (u.Hashes.CheckedAt is null && u.Rules.CheckedAt is null)
        {
            UpdatesText.Text = "Not checked yet." + Next(u);
        }
        else
        {
            var last = new[] { u.Rules.CheckedAt, u.Hashes.CheckedAt }.Max()!.Value;
            UpdatesText.Text = $"Rules: {Describe(u.Rules)}\nHashes: {Describe(u.Hashes)}\nChecked {last.ToLocalTime():yyyy-MM-dd HH:mm}." + Next(u);
        }

        if (finished)
        {
            await RefreshEngine();
        }

        static string Describe(DefinitionSourceStatus s) =>
            s.Error is not null ? "failed, " + s.Error : s.Result ?? "not checked";

        static string Next(UpdateStatus u) =>
            u.NextCheck is { } next ? $" Next check {next.ToLocalTime():HH:mm}." : u.AutomaticChecks ? "" : " Automatic checks are off.";
    }

    private void SetBand(Brush brush, string title, string detail)
    {
        StatusBand.Background = brush;
        StatusTitle.Text = title;
        StatusDetail.Text = detail;
    }

    private void SetScanControls(bool serviceUp, bool running)
    {
        QuickButton.IsEnabled = FullButton.IsEnabled = FolderButton.IsEnabled = serviceUp && !running;
        CancelButton.IsEnabled = serviceUp && running;
        ImportButton.IsEnabled = ReloadButton.IsEnabled = serviceUp;
        if (!serviceUp)
        {
            UpdateButton.IsEnabled = false;
        }
        if (!running)
        {
            Progress.IsIndeterminate = false;
        }
    }

    private async void Quick_Click(object sender, RoutedEventArgs e) =>
        await StartScan(new PipeRequest(Commands.StartScan, ScanKind.Quick));

    private async void Full_Click(object sender, RoutedEventArgs e) =>
        await StartScan(new PipeRequest(Commands.StartScan, ScanKind.Full));

    private async void Folder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder to scan" };
        if (dialog.ShowDialog(this) == true)
        {
            await StartScan(new PipeRequest(Commands.StartScan, ScanKind.Path, dialog.FolderName));
        }
    }

    private async Task StartScan(PipeRequest request)
    {
        await TrayApp.StartScan(request);
        await RefreshStatus();
    }

    private async void Cancel_Click(object sender, RoutedEventArgs e)
    {
        await ServiceApi.TrySend(new PipeRequest(Commands.CancelScan));
        await RefreshStatus();
    }

    private async void Update_Click(object sender, RoutedEventArgs e)
    {
        UpdateButton.IsEnabled = false;
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.CheckUpdates));
        if (response is { Ok: true })
        {
            _updateRunning = true;
            UpdatesText.Foreground = SystemColors.ControlTextBrush;
            UpdatesText.Text = "Checking for updates...";
        }
        else
        {
            UpdateButton.IsEnabled = true;
            EngineStatus.Text = response?.Error ?? "Could not start the update check.";
        }
    }

    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Import a hash list",
            Filter = "Hash lists (*.txt;*.csv;*.zip)|*.txt;*.csv;*.zip|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        ImportButton.IsEnabled = false;
        EngineStatus.Text = "Importing, this can take a minute for large lists...";
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.ImportHashes, Path: dialog.FileName));
        if (response is { Ok: true } && response.DataAs<ImportResult>() is { } result)
        {
            EngineStatus.Text = $"Read {result.Read:N0} hashes, added {result.Added:N0} new.";
        }
        else
        {
            EngineStatus.Text = response?.Error ?? "Import failed.";
        }
        ImportButton.IsEnabled = true;
        await RefreshEngine();
    }

    private async void Reload_Click(object sender, RoutedEventArgs e)
    {
        ReloadButton.IsEnabled = false;
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.ReloadRules));
        if (response is { Ok: true } && response.DataAs<RuleLoadReport>() is { } report)
        {
            var failed = report.FailedFiles.Select(f => $"{f.Key}: {f.Value}");
            EngineStatus.Text = report.Error
                ?? $"Loaded {report.RuleCount:N0} rules from {report.FilesLoaded} file(s)."
                   + (report.FailedFiles.Count == 0 ? "" : "\nSkipped: " + string.Join("\n", failed));
        }
        else
        {
            EngineStatus.Text = response?.Error ?? "Reload failed.";
        }
        ReloadButton.IsEnabled = true;
        await RefreshEngine();
    }

    private void Results_Click(object sender, RoutedEventArgs e) => TrayApp.ShowResults();

    private void Quarantine_Click(object sender, RoutedEventArgs e) => TrayApp.ShowQuarantine();

    private static Brush Frozen(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    private sealed record ImportResult(long Read, long Added, long Total);
}

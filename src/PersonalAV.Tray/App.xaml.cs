using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using PersonalAV.Core;
using PersonalAV.Core.Ipc;
using Forms = System.Windows.Forms;

namespace PersonalAV.Tray;

/// <summary>
/// Notification-area app with a dashboard window. Closing the window leaves the icon running; Exit quits.
/// Started with --tray (as the logon task does) it begins hidden in the tray.
/// </summary>
public partial class App : Application
{
    private const string ShowEventName = @"Local\PersonalAV.Tray.Show";

    private Mutex? _singleInstance;
    private EventWaitHandle? _showRequested;
    private RegisteredWaitHandle? _showWait;
    private Forms.NotifyIcon? _icon;
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(3) };
    private ScanState? _lastState;
    private MainWindow? _main;
    private ResultsWindow? _results;
    private QuarantineWindow? _quarantine;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _singleInstance = new Mutex(true, @"Local\PersonalAV.Tray", out var created);
        _showRequested = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        if (!created)
        {
            // Already running: bring its window forward instead of starting a second copy.
            _showRequested.Set();
            Shutdown();
            return;
        }
        _showWait = ThreadPool.RegisterWaitForSingleObject(_showRequested,
            (_, _) => Dispatcher.BeginInvoke(ShowMain), null, Timeout.Infinite, executeOnlyOnce: false);

        var menu = new Forms.ContextMenuStrip();
        var open = menu.Items.Add("Open PersonalAV", null, (_, _) => ShowMain());
        open.Font = new System.Drawing.Font(open.Font, System.Drawing.FontStyle.Bold);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Quick scan", null, async (_, _) => await StartScan(new PipeRequest(Commands.StartScan, ScanKind.Quick)));
        menu.Items.Add("Full scan", null, async (_, _) => await StartScan(new PipeRequest(Commands.StartScan, ScanKind.Full)));
        menu.Items.Add("Scan folder...", null, async (_, _) => await ScanFolder());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Results", null, (_, _) => ShowResults());
        menu.Items.Add("Quarantine", null, (_, _) => ShowQuarantine());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => Shutdown());

        _icon = new Forms.NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Shield,
            Text = "PersonalAV",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.DoubleClick += (_, _) => ShowMain();

        _poll.Tick += async (_, _) => await PollStatus();
        _poll.Start();
        _ = PollStatus();

        if (!e.Args.Contains("--tray", StringComparer.OrdinalIgnoreCase))
        {
            ShowMain();
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _poll.Stop();
        _showWait?.Unregister(null);
        _showRequested?.Dispose();
        if (_icon is not null)
        {
            _icon.Visible = false;
            _icon.Dispose();
        }
        _singleInstance?.Dispose();
        base.OnExit(e);
    }

    internal async Task StartScan(PipeRequest request)
    {
        var response = await ServiceApi.TrySend(request);
        if (response is { Ok: true })
        {
            _lastState = ScanState.Running;
            ShowMain();
        }
        else if (response is not null)
        {
            Notify("Scan not started", response.Error ?? "unknown error", Forms.ToolTipIcon.Warning);
        }
    }

    private async Task ScanFolder()
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder to scan" };
        if (dialog.ShowDialog() == true)
        {
            await StartScan(new PipeRequest(Commands.StartScan, ScanKind.Path, dialog.FolderName));
        }
    }

    internal void ShowMain()
    {
        if (_main is null)
        {
            _main = new MainWindow();
            _main.Closed += (_, _) => _main = null;
        }
        _main.Show();
        if (_main.WindowState == WindowState.Minimized)
        {
            _main.WindowState = WindowState.Normal;
        }
        _main.Activate();
    }

    internal void ShowResults()
    {
        if (_results is null)
        {
            _results = new ResultsWindow();
            _results.Closed += (_, _) => _results = null;
        }
        _results.Show();
        _results.Activate();
    }

    internal void ShowQuarantine()
    {
        if (_quarantine is null)
        {
            _quarantine = new QuarantineWindow();
            _quarantine.Closed += (_, _) => _quarantine = null;
        }
        _quarantine.Show();
        _quarantine.Activate();
    }

    /// <summary>Keeps the tooltip current and pops a balloon when a scan finishes.</summary>
    private async Task PollStatus()
    {
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.GetStatus), quiet: true);
        if (_icon is null)
        {
            return;
        }
        if (response is not { Ok: true })
        {
            _icon.Text = "PersonalAV: service unavailable";
            return;
        }
        var status = response.DataAs<ScanStatus>()!;
        _icon.Text = status.State == ScanState.Running
            ? Truncate($"PersonalAV: scanning ({status.FilesScanned:N0} files, {status.Detections} detections)")
            : "PersonalAV: protected (on-demand)";

        if (_lastState == ScanState.Running && status.State != ScanState.Running)
        {
            var icon = status.Detections > 0 ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info;
            Notify($"Scan {status.State.ToString().ToLowerInvariant()}",
                $"{status.FilesScanned:N0} files scanned, {status.Detections} threats found.", icon);
        }
        _lastState = status.State;
    }

    private void Notify(string title, string text, Forms.ToolTipIcon icon) =>
        _icon?.ShowBalloonTip(5000, title, text, icon);

    // NotifyIcon.Text is limited to 127 characters.
    private static string Truncate(string text) => text.Length <= 127 ? text : text[..127];
}

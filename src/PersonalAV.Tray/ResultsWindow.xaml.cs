using System.Windows;
using System.Windows.Threading;
using PersonalAV.Core;
using PersonalAV.Core.Ipc;

namespace PersonalAV.Tray;

public partial class ResultsWindow : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private string? _shownKey;

    public ResultsWindow()
    {
        InitializeComponent();
        _timer.Tick += async (_, _) => await Refresh();
        Loaded += async (_, _) =>
        {
            _timer.Start();
            await Refresh(forceDetections: true);
        };
        Closed += (_, _) => _timer.Stop();
    }

    private async Task Refresh(bool forceDetections = false)
    {
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.GetStatus), quiet: true);
        if (response is not { Ok: true })
        {
            StateText.Text = "Service unavailable";
            CountsText.Text = response?.Error ?? "Start the PersonalAV service, and run this app as Administrator.";
            CancelButton.IsEnabled = false;
            return;
        }

        var s = response.DataAs<ScanStatus>()!;
        bool running = s.State == ScanState.Running;
        StateText.Text = s.ScanId is null ? "No scan yet" : $"{s.Kind} scan: {s.State}";
        CountsText.Text = s.ScanId is null
            ? "Use the tray menu to start a scan."
            : $"{s.FilesScanned:N0} scanned  ·  {s.FilesSkipped:N0} skipped  ·  {s.Errors:N0} errors  ·  {s.Detections} detections"
              + (s.Message is null ? "" : $"  ·  {s.Message}");
        CurrentText.Text = running ? s.CurrentPath ?? "" : s.Target ?? "";
        Progress.IsIndeterminate = running;
        CancelButton.IsEnabled = running;

        // Reload the list only when the scan, its state or its detection count changes, not every second.
        var key = $"{s.ScanId}|{s.State}|{s.Detections}";
        if (forceDetections || key != _shownKey)
        {
            _shownKey = key;
            var list = await ServiceApi.TrySend(new PipeRequest(Commands.ListDetections, Limit: 200), quiet: true);
            if (list is { Ok: true })
            {
                Detections.ItemsSource = list.DataAs<List<DetectionRecord>>()!
                    .Select(d => d with { DetectedAt = d.DetectedAt.ToLocalTime() })
                    .ToList();
            }
        }
    }

    private async void Cancel_Click(object sender, RoutedEventArgs e) =>
        await ServiceApi.TrySend(new PipeRequest(Commands.CancelScan));

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await Refresh(forceDetections: true);
}

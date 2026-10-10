using System.Windows;
using System.Windows.Controls;
using PersonalAV.Core;
using PersonalAV.Core.Ipc;

namespace PersonalAV.Tray;

public partial class QuarantineWindow : Window
{
    public QuarantineWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await Reload();
    }

    private QuarantineEntry? Selected => Entries.SelectedItem as QuarantineEntry;

    private async Task Reload()
    {
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.ListQuarantine), quiet: true);
        if (response is not { Ok: true })
        {
            StatusText.Text = response?.Error ?? "Service unavailable.";
            return;
        }
        var entries = response.DataAs<List<QuarantineEntry>>()!
            .Select(q => q with { QuarantinedAt = q.QuarantinedAt.ToLocalTime() })
            .ToList();
        Entries.ItemsSource = entries;
        StatusText.Text = entries.Count == 0 ? "Quarantine is empty." : $"{entries.Count} item(s).";
    }

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } entry)
        {
            return;
        }
        var confirm = MessageBox.Show(this,
            $"Restore {entry.ThreatName} to\n{entry.OriginalPath}?\n\nOnly do this if you are sure the file is safe. " +
            "Until exclusions arrive, the next scan will detect it again.",
            "Restore file", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }
        var response = await ServiceApi.TrySend(new PipeRequest(Commands.Restore, Id: entry.Id));
        if (response is { Ok: false } && response.Error?.Contains("already exists", StringComparison.OrdinalIgnoreCase) == true)
        {
            var overwrite = MessageBox.Show(this, response.Error + "\n\nOverwrite it?", "Restore file",
                MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (overwrite == MessageBoxResult.Yes)
            {
                response = await ServiceApi.TrySend(new PipeRequest(Commands.Restore, Id: entry.Id, Overwrite: true));
            }
            else
            {
                return;
            }
        }
        ShowResult(response, "Restored.");
        await Reload();
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } entry)
        {
            return;
        }
        var confirm = MessageBox.Show(this, $"Permanently delete {entry.ThreatName}?\n{entry.OriginalPath}",
            "Delete file", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }
        ShowResult(await ServiceApi.TrySend(new PipeRequest(Commands.Delete, Id: entry.Id)), "Deleted.");
        await Reload();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await Reload();

    private void Entries_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        RestoreButton.IsEnabled = DeleteButton.IsEnabled = Selected is not null;
    }

    private void ShowResult(PipeResponse? response, string success)
    {
        if (response is { Ok: false })
        {
            MessageBox.Show(this, response.Error, "PersonalAV", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        else if (response is not null)
        {
            StatusText.Text = success;
        }
    }
}

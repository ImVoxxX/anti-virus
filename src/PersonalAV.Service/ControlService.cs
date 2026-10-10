using PersonalAV.Core;
using PersonalAV.Core.Ipc;
using PersonalAV.Core.Scanning;

namespace PersonalAV.Service;

/// <summary>Loads the rules, then serves the admin-only control pipe until the service stops.</summary>
public sealed class ControlService(
    AppPaths paths,
    AvDatabase db,
    YaraRuleSet yara,
    ScanCoordinator scans,
    CommandDispatcher dispatcher,
    ILogger<ControlService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var report = yara.Load(paths.Rules);
        foreach (var (file, error) in report.FailedFiles)
        {
            logger.LogWarning("Rule file {File} skipped: {Error}", file, error);
        }
        logger.LogInformation("Engine ready: {Hashes} hashes, {Rules} YARA rules from {Files} files{Note}",
            db.HashCount(), yara.RuleCount, report.FilesLoaded, report.Error is null ? "" : $" ({report.Error})");

        var server = new PipeServerHost(PipeProtocol.PipeName, PipeServerHost.AdminOnlySecurity(), dispatcher.Handle, logger);
        try
        {
            await server.RunAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        scans.Cancel();
        await base.StopAsync(cancellationToken);
        await Task.WhenAny(scans.WaitAsync(), Task.Delay(TimeSpan.FromSeconds(10), cancellationToken));
    }
}

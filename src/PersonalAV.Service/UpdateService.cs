using PersonalAV.Core.Updates;

namespace PersonalAV.Service;

/// <summary>Runs definition update checks on their schedule and when the dashboard or CLI asks for one.</summary>
public sealed class UpdateService(DefinitionUpdater updater) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => updater.RunAsync(stoppingToken);
}

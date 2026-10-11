using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAV.Core.Quarantine;
using PersonalAV.Core.Scanning;
using PersonalAV.Core.Updates;

namespace PersonalAV.Core.Ipc;

/// <summary>Maps pipe requests onto the engine. Every failure becomes an error response, never an exception.</summary>
public sealed class CommandDispatcher
{
    private readonly ScanCoordinator _scans;
    private readonly QuarantineStore _quarantine;
    private readonly AvDatabase _db;
    private readonly YaraRuleSet _yara;
    private readonly AppPaths _paths;
    private readonly DefinitionUpdater? _updates;
    private readonly ILogger _logger;

    public CommandDispatcher(ScanCoordinator scans, QuarantineStore quarantine, AvDatabase db, YaraRuleSet yara,
        AppPaths paths, DefinitionUpdater? updates = null, ILogger<CommandDispatcher>? logger = null)
    {
        _scans = scans;
        _quarantine = quarantine;
        _db = db;
        _yara = yara;
        _paths = paths;
        _updates = updates;
        _logger = logger ?? NullLogger<CommandDispatcher>.Instance;
    }

    public PipeResponse Handle(PipeRequest request)
    {
        try
        {
            return request.Command switch
            {
                Commands.StartScan => StartScan(request),
                Commands.CancelScan => _scans.Cancel()
                    ? PipeResponse.Success()
                    : PipeResponse.Failure("no scan is running"),
                Commands.GetStatus => PipeResponse.Success(_scans.GetStatus()),
                Commands.ListDetections => PipeResponse.Success(_db.ListDetections(request.Limit ?? 200)),
                Commands.ListQuarantine => PipeResponse.Success(_quarantine.List()),
                Commands.Restore => PipeResponse.Success(new
                {
                    RestoredTo = _quarantine.Restore(RequireId(request), request.Overwrite ?? false),
                }),
                Commands.Delete => Delete(request),
                Commands.ReloadRules => PipeResponse.Success(_yara.Load(_paths.Rules)),
                Commands.ImportHashes => ImportHashes(request),
                Commands.GetEngineInfo => PipeResponse.Success(EngineInfo()),
                Commands.CheckUpdates => CheckUpdates(),
                Commands.GetUpdateStatus => PipeResponse.Success(Updater().GetStatus()),
                _ => PipeResponse.Failure($"unknown command '{request.Command}'"),
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Command {Command} failed", request.Command);
            return PipeResponse.Failure(ex.Message);
        }
    }

    private PipeResponse StartScan(PipeRequest request)
    {
        var id = _scans.TryStart(request.Kind ?? ScanKind.Quick, request.Path, out var error);
        return id is null ? PipeResponse.Failure(error!) : PipeResponse.Success(new { ScanId = id });
    }

    /// <summary>Starts a check in the background; poll GetUpdateStatus until Checking is false.</summary>
    private PipeResponse CheckUpdates()
    {
        var started = Updater().RequestCheck();
        return PipeResponse.Success(new { Started = started });
    }

    private DefinitionUpdater Updater() => _updates ?? throw new InvalidOperationException("updates are not available");

    private PipeResponse Delete(PipeRequest request)
    {
        _quarantine.Delete(RequireId(request));
        return PipeResponse.Success();
    }

    private PipeResponse ImportHashes(PipeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Path) || !File.Exists(request.Path))
        {
            return PipeResponse.Failure($"file not found: {request.Path}");
        }
        var hashes = HashListParser.ParseFile(request.Path);
        var added = _db.ImportHashes(hashes, "import:" + Path.GetFileName(request.Path));
        _logger.LogInformation("Imported {Added} new hashes ({Read} read) from {Path}", added, hashes.Count, request.Path);
        return PipeResponse.Success(new { Read = hashes.Count, Added = added, Total = _db.HashCount() });
    }

    private EngineInfo EngineInfo()
    {
        var report = _yara.LastReport;
        return new EngineInfo(_db.HashCount(), _yara.RuleCount, report.FilesLoaded, report.FailedFiles);
    }

    private static string RequireId(PipeRequest request) =>
        string.IsNullOrWhiteSpace(request.Id) ? throw new ArgumentException("an id is required") : request.Id;
}

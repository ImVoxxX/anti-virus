using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAV.Core.Quarantine;

namespace PersonalAV.Core.Scanning;

/// <summary>Runs one scan job at a time on a background task; detections are quarantined automatically.</summary>
public sealed class ScanCoordinator
{
    private readonly ScanEngine _engine;
    private readonly QuarantineStore _quarantine;
    private readonly AvDatabase _db;
    private readonly AppPaths _paths;
    private readonly ILogger _logger;
    private readonly object _gate = new();

    private Job? _current;
    private ScanStatus _last = new();

    public ScanCoordinator(ScanEngine engine, QuarantineStore quarantine, AvDatabase db, AppPaths paths,
        ILogger<ScanCoordinator>? logger = null)
    {
        _engine = engine;
        _quarantine = quarantine;
        _db = db;
        _paths = paths;
        _logger = logger ?? NullLogger<ScanCoordinator>.Instance;
    }

    public ScanStatus GetStatus()
    {
        lock (_gate)
        {
            return _current?.Snapshot() ?? _last;
        }
    }

    /// <summary>Starts a scan unless one is running. Returns the scan id, or null with an error.</summary>
    public string? TryStart(ScanKind kind, string? path, out string? error)
    {
        if (kind == ScanKind.Path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                error = "a path is required for a path scan";
                return null;
            }
            path = Path.GetFullPath(path);
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                error = $"path not found: {path}";
                return null;
            }
        }

        lock (_gate)
        {
            if (_current is not null)
            {
                error = $"scan {_current.Id} is already running";
                return null;
            }
            var job = new Job(Guid.NewGuid().ToString("N")[..12], kind, kind == ScanKind.Path ? path : kind.ToString().ToLowerInvariant());
            _current = job;
            job.Task = Task.Run(() => Run(job));
            error = null;
            return job.Id;
        }
    }

    public bool Cancel()
    {
        lock (_gate)
        {
            if (_current is null)
            {
                return false;
            }
            _current.Cts.Cancel();
            return true;
        }
    }

    /// <summary>Waits for the running scan, if any (used by tests and shutdown).</summary>
    public Task WaitAsync()
    {
        lock (_gate)
        {
            return _current?.Task ?? Task.CompletedTask;
        }
    }

    private void Run(Job job)
    {
        _logger.LogInformation("Scan {ScanId} started: {Kind} {Target}", job.Id, job.Kind, job.Target);
        ScanState final = ScanState.Completed;
        string? message = null;
        try
        {
            foreach (var file in Targets(job))
            {
                job.Cts.Token.ThrowIfCancellationRequested();
                ScanOne(job, file);
            }
        }
        catch (OperationCanceledException)
        {
            final = ScanState.Cancelled;
        }
        catch (Exception ex)
        {
            final = ScanState.Failed;
            message = ex.Message;
            _logger.LogError(ex, "Scan {ScanId} failed", job.Id);
        }

        lock (_gate)
        {
            _last = job.Snapshot() with
            {
                State = final,
                FinishedAt = DateTimeOffset.UtcNow,
                CurrentPath = null,
                Message = message,
            };
            _current = null;
        }
        _logger.LogInformation(
            "Scan {ScanId} {State}: {Scanned} scanned, {Skipped} skipped, {Errors} errors, {Detections} detections",
            job.Id, final, job.Scanned, job.Skipped, job.Errors, job.Detections);
    }

    private IEnumerable<string> Targets(Job job)
    {
        var excluded = new[] { _paths.Root };
        var token = job.Cts.Token;
        void OnSkip(string _, string __) => Interlocked.Increment(ref job.Skipped);

        switch (job.Kind)
        {
            case ScanKind.Path:
                foreach (var f in FileEnumerator.Enumerate(job.Target!, excluded, OnSkip, token))
                {
                    yield return f.FullName;
                }
                break;

            case ScanKind.Full:
                foreach (var root in ScanTargets.Full())
                {
                    foreach (var f in FileEnumerator.Enumerate(root, excluded, OnSkip, token))
                    {
                        yield return f.FullName;
                    }
                }
                break;

            case ScanKind.Quick:
                // Process images often live inside the folders below; scan each path once.
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var (files, folders) = ScanTargets.Quick();
                foreach (var file in files.Where(seen.Add))
                {
                    yield return file;
                }
                foreach (var folder in folders)
                {
                    foreach (var f in FileEnumerator.Enumerate(folder, excluded, OnSkip, token))
                    {
                        if (seen.Add(f.FullName))
                        {
                            yield return f.FullName;
                        }
                    }
                }
                break;
        }
    }

    private void ScanOne(Job job, string path)
    {
        job.CurrentPath = path;
        FileVerdict verdict;
        try
        {
            verdict = _engine.ScanFile(path);
        }
        catch (Exception ex)
        {
            verdict = FileVerdict.Failed(path, ex.Message);
        }

        switch (verdict.Kind)
        {
            case VerdictKind.Clean:
                Interlocked.Increment(ref job.Scanned);
                if (verdict.Reason is not null)
                {
                    _logger.LogWarning("Not quarantining {Path}: {Reason}", path, verdict.Reason);
                }
                break;
            case VerdictKind.Skipped:
                Interlocked.Increment(ref job.Skipped);
                break;
            case VerdictKind.Error:
                Interlocked.Increment(ref job.Errors);
                _logger.LogWarning("Error scanning {Path}: {Reason}", path, verdict.Reason);
                break;
            case VerdictKind.Detected:
                Interlocked.Increment(ref job.Scanned);
                Interlocked.Increment(ref job.Detections);
                HandleDetection(job, verdict);
                break;
        }
    }

    private void HandleDetection(Job job, FileVerdict verdict)
    {
        _logger.LogWarning("Detected {Threat} ({Engine}) in {Path}", verdict.ThreatName, verdict.Engine, verdict.Path);
        var record = new DetectionRecord
        {
            ScanId = job.Id,
            Path = verdict.Path,
            Sha256 = verdict.Sha256,
            ThreatName = verdict.ThreatName!,
            Engine = verdict.Engine!,
            DetectedAt = DateTimeOffset.UtcNow,
        };
        try
        {
            var entry = _quarantine.Quarantine(verdict.Path, verdict.ThreatName!);
            record = record with { Action = DetectionAction.Quarantined, QuarantineId = entry.Id };
            _logger.LogWarning("Quarantined {Path} as {QuarantineId}", verdict.Path, entry.Id);
        }
        catch (Exception ex)
        {
            record = record with { Action = DetectionAction.QuarantineFailed, Error = ex.Message };
            _logger.LogError(ex, "Could not quarantine {Path}", verdict.Path);
        }
        _db.AddDetection(record);
    }

    private sealed class Job(string id, ScanKind kind, string? target)
    {
        public string Id { get; } = id;
        public ScanKind Kind { get; } = kind;
        public string? Target { get; } = target;
        public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
        public CancellationTokenSource Cts { get; } = new();
        public Task? Task { get; set; }
        public volatile string? CurrentPath;
        public long Scanned, Skipped, Errors, Detections;

        public ScanStatus Snapshot() => new()
        {
            ScanId = Id,
            State = ScanState.Running,
            Kind = Kind,
            Target = Target,
            StartedAt = StartedAt,
            FilesScanned = Interlocked.Read(ref Scanned),
            FilesSkipped = Interlocked.Read(ref Skipped),
            Errors = Interlocked.Read(ref Errors),
            Detections = Interlocked.Read(ref Detections),
            CurrentPath = CurrentPath,
        };
    }
}

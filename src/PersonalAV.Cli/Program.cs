using PersonalAV.Core;
using PersonalAV.Core.Ipc;

const string Usage = """
    PersonalAV command-line client (run from an elevated prompt)

    Usage:
      pav scan quick|full [--wait]       Start a Quick or Full scan
      pav scan <path> [--wait]           Scan a file or folder
      pav cancel                         Cancel the running scan
      pav status                         Show scan progress or the last result
      pav detections [limit]             List recent detections
      pav quarantine                     List quarantined files
      pav restore <id> [--overwrite]     Restore a quarantined file to its original path
      pav delete <id>                    Permanently delete a quarantined file
      pav reload-rules                   Recompile the YARA rules folder
      pav import-hashes <file>           Add SHA-256 hashes (plain list, MalwareBazaar CSV, or .zip)
      pav info                           Show engine statistics
      pav testfile <path>                Write a harmless file that the bundled test rule detects
    """;

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    Console.WriteLine(Usage);
    return 0;
}

var flags = args.Where(a => a.StartsWith("--", StringComparison.Ordinal)).ToHashSet(StringComparer.OrdinalIgnoreCase);
var positional = args.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToArray();
string? Arg(int i) => positional.Length > i ? positional[i] : null;

try
{
    switch (positional[0].ToLowerInvariant())
    {
        case "scan":
        {
            var target = Arg(1) ?? throw new UsageException("scan needs quick, full or a path");
            var request = target.ToLowerInvariant() switch
            {
                "quick" => new PipeRequest(Commands.StartScan, ScanKind.Quick),
                "full" => new PipeRequest(Commands.StartScan, ScanKind.Full),
                _ => new PipeRequest(Commands.StartScan, ScanKind.Path, Path.GetFullPath(target)),
            };
            var started = Check(await Send(request));
            Console.WriteLine($"Scan started: {started.Data?.GetProperty("scanId").GetString()}");
            if (flags.Contains("--wait"))
            {
                return await WaitForScan();
            }
            return 0;
        }
        case "cancel":
            Check(await Send(new PipeRequest(Commands.CancelScan)));
            Console.WriteLine("Cancellation requested.");
            return 0;

        case "status":
            PrintStatus(Check(await Send(new PipeRequest(Commands.GetStatus))).DataAs<ScanStatus>()!);
            return 0;

        case "detections":
        {
            var limit = int.TryParse(Arg(1), out var n) ? n : 50;
            var rows = Check(await Send(new PipeRequest(Commands.ListDetections, Limit: limit))).DataAs<List<DetectionRecord>>()!;
            if (rows.Count == 0)
            {
                Console.WriteLine("No detections.");
            }
            foreach (var d in rows)
            {
                Console.WriteLine($"{d.DetectedAt.ToLocalTime():yyyy-MM-dd HH:mm}  {d.ThreatName}  [{d.Engine}]  {d.Action}" +
                                  (d.QuarantineId is null ? "" : $" ({d.QuarantineId})"));
                Console.WriteLine($"    {d.Path}" + (d.Error is null ? "" : $"\n    error: {d.Error}"));
            }
            return 0;
        }
        case "quarantine":
        {
            var rows = Check(await Send(new PipeRequest(Commands.ListQuarantine))).DataAs<List<QuarantineEntry>>()!;
            if (rows.Count == 0)
            {
                Console.WriteLine("Quarantine is empty.");
            }
            foreach (var q in rows)
            {
                Console.WriteLine($"{q.Id}  {q.QuarantinedAt.ToLocalTime():yyyy-MM-dd HH:mm}  {q.ThreatName}  {q.Size:N0} bytes");
                Console.WriteLine($"    {q.OriginalPath}");
            }
            return 0;
        }
        case "restore":
        {
            var id = Arg(1) ?? throw new UsageException("restore needs an id");
            var result = Check(await Send(new PipeRequest(Commands.Restore, Id: id, Overwrite: flags.Contains("--overwrite"))));
            Console.WriteLine($"Restored to {result.Data?.GetProperty("restoredTo").GetString()}");
            Console.WriteLine("Note: until exclusions arrive in Part 2, the next scan will detect it again.");
            return 0;
        }
        case "delete":
            Check(await Send(new PipeRequest(Commands.Delete, Id: Arg(1) ?? throw new UsageException("delete needs an id"))));
            Console.WriteLine("Deleted.");
            return 0;

        case "reload-rules":
        {
            var report = Check(await Send(new PipeRequest(Commands.ReloadRules))).DataAs<RuleLoadReport>()!;
            Console.WriteLine($"{report.RuleCount} rules active from {report.FilesLoaded} files." +
                              (report.Error is null ? "" : $" {report.Error}"));
            foreach (var (file, error) in report.FailedFiles)
            {
                Console.WriteLine($"  skipped {file}: {error}");
            }
            return 0;
        }
        case "import-hashes":
        {
            var file = Path.GetFullPath(Arg(1) ?? throw new UsageException("import-hashes needs a file"));
            var result = Check(await Send(new PipeRequest(Commands.ImportHashes, Path: file), TimeSpan.FromMinutes(5)));
            var data = result.Data!.Value;
            Console.WriteLine($"Read {data.GetProperty("read").GetInt32():N0}, added {data.GetProperty("added").GetInt32():N0}; " +
                              $"blocklist now {data.GetProperty("total").GetInt64():N0} hashes.");
            return 0;
        }
        case "info":
        {
            var info = Check(await Send(new PipeRequest(Commands.GetEngineInfo))).DataAs<EngineInfo>()!;
            Console.WriteLine($"Blocklisted hashes: {info.HashCount:N0}");
            Console.WriteLine($"YARA rules:         {info.YaraRuleCount} (from {info.YaraFilesLoaded} files)");
            foreach (var (file, error) in info.YaraFailedFiles)
            {
                Console.WriteLine($"  skipped {file}: {error}");
            }
            return 0;
        }
        case "testfile":
        {
            var path = Path.GetFullPath(Arg(1) ?? throw new UsageException("testfile needs a path"));
            // The bundled rule only matches the marker at the start of a file under 256 bytes.
            File.WriteAllText(path, TestMarker.Value + Environment.NewLine + "This harmless file is the PersonalAV test marker." + Environment.NewLine);
            Console.WriteLine($"Wrote {path}");
            return 0;
        }
        default:
            throw new UsageException($"unknown command '{positional[0]}'");
    }
}
catch (UsageException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine();
    Console.Error.WriteLine(Usage);
    return 2;
}
catch (Exception ex) when (ex is ServiceUnavailableException or CommandFailedException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static Task<PipeResponse> Send(PipeRequest request, TimeSpan? timeout = null) =>
    timeout is null
        ? PipeClient.RequestAsync(request)
        : PipeClient.RequestAsync(request).WaitAsync(timeout.Value);

static PipeResponse Check(PipeResponse response) =>
    response.Ok ? response : throw new CommandFailedException(response.Error ?? "command failed");

static async Task<int> WaitForScan()
{
    ScanStatus status;
    var lastLine = 0;
    while (true)
    {
        status = Check(await Send(new PipeRequest(Commands.GetStatus))).DataAs<ScanStatus>()!;
        if (status.State != ScanState.Running)
        {
            break;
        }
        if (!Console.IsOutputRedirected)
        {
            var line = $"{status.FilesScanned:N0} scanned, {status.Detections} detections  {Shorten(status.CurrentPath, 70)}";
            Console.Write("\r" + line.PadRight(lastLine));
            lastLine = line.Length;
        }
        await Task.Delay(500);
    }
    if (lastLine > 0)
    {
        Console.WriteLine();
    }
    PrintStatus(status);
    return status.State == ScanState.Completed ? (status.Detections > 0 ? 3 : 0) : 1;
}

static void PrintStatus(ScanStatus s)
{
    if (s.ScanId is null)
    {
        Console.WriteLine("No scan has run since the service started.");
        return;
    }
    Console.WriteLine($"Scan {s.ScanId} ({s.Kind} {s.Target}): {s.State}");
    Console.WriteLine($"  scanned {s.FilesScanned:N0}, skipped {s.FilesSkipped:N0}, errors {s.Errors:N0}, detections {s.Detections}");
    if (s.StartedAt is { } started)
    {
        var end = s.FinishedAt ?? DateTimeOffset.UtcNow;
        Console.WriteLine($"  started {started.ToLocalTime():HH:mm:ss}, elapsed {(end - started):hh\\:mm\\:ss}");
    }
    if (s.CurrentPath is not null)
    {
        Console.WriteLine($"  current: {s.CurrentPath}");
    }
    if (s.Message is not null)
    {
        Console.WriteLine($"  {s.Message}");
    }
}

static string Shorten(string? path, int max) =>
    path is null ? "" : path.Length <= max ? path : "..." + path[^(max - 3)..];

sealed class UsageException(string message) : Exception(message);

sealed class CommandFailedException(string message) : Exception(message);

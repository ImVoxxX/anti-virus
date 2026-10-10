namespace PersonalAV.Core;

public enum ScanKind
{
    Quick,
    Full,
    Path,
}

public enum ScanState
{
    Idle,
    Running,
    Completed,
    Cancelled,
    Failed,
}

public enum VerdictKind
{
    Clean,
    Detected,
    Skipped,
    Error,
}

public enum DetectionAction
{
    Quarantined,
    QuarantineFailed,
}

/// <summary>Result of scanning a single file.</summary>
public sealed record FileVerdict(
    string Path,
    VerdictKind Kind,
    string? Sha256 = null,
    string? ThreatName = null,
    string? Engine = null,
    string? Reason = null)
{
    public static FileVerdict Skipped(string path, string reason) => new(path, VerdictKind.Skipped, Reason: reason);
    public static FileVerdict Failed(string path, string reason) => new(path, VerdictKind.Error, Reason: reason);
}

/// <summary>Snapshot of the current (or last) scan job, as returned by GetStatus.</summary>
public sealed record ScanStatus
{
    public string? ScanId { get; init; }
    public ScanState State { get; init; } = ScanState.Idle;
    public ScanKind? Kind { get; init; }
    public string? Target { get; init; }
    public DateTimeOffset? StartedAt { get; init; }
    public DateTimeOffset? FinishedAt { get; init; }
    public long FilesScanned { get; init; }
    public long FilesSkipped { get; init; }
    public long Errors { get; init; }
    public long Detections { get; init; }
    public string? CurrentPath { get; init; }
    public string? Message { get; init; }
}

public sealed record DetectionRecord
{
    public long Id { get; init; }
    public string? ScanId { get; init; }
    public required string Path { get; init; }
    public string? Sha256 { get; init; }
    public required string ThreatName { get; init; }
    public required string Engine { get; init; }
    public DateTimeOffset DetectedAt { get; init; }
    public DetectionAction Action { get; init; }
    public string? QuarantineId { get; init; }
    public string? Error { get; init; }
}

public sealed record QuarantineEntry
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string Sha256 { get; init; }
    public required string ThreatName { get; init; }
    public DateTimeOffset QuarantinedAt { get; init; }
    public long Size { get; init; }
    /// <summary>DACL of the original file in SDDL form, reapplied on restore. Null if it could not be read.</summary>
    public string? OriginalSddl { get; init; }
}

public sealed record RuleLoadReport(int FilesLoaded, int RuleCount, IReadOnlyDictionary<string, string> FailedFiles, string? Error);

public sealed record EngineInfo(long HashCount, int YaraRuleCount, int YaraFilesLoaded, IReadOnlyDictionary<string, string> YaraFailedFiles);

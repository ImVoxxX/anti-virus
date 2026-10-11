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

/// <summary>State of one definition source (the signed rules manifest or the hash feed).</summary>
public sealed record DefinitionSourceStatus
{
    /// <summary>When the source was last contacted, successfully or not.</summary>
    public DateTimeOffset? CheckedAt { get; init; }
    /// <summary>When the last check that changed something finished.</summary>
    public DateTimeOffset? UpdatedAt { get; init; }
    /// <summary>Rules: the installed manifest version. Hashes: the feed's Last-Modified time.</summary>
    public string? Version { get; init; }
    /// <summary>Outcome of the last successful check, e.g. "Up to date" or "Added 120 hashes".</summary>
    public string? Result { get; init; }
    /// <summary>Why the last check failed; null when it succeeded.</summary>
    public string? Error { get; init; }
}

public sealed record UpdateStatus
{
    public bool AutomaticChecks { get; init; }
    public bool Checking { get; init; }
    public DateTimeOffset? NextCheck { get; init; }
    public DefinitionSourceStatus Rules { get; init; } = new();
    public DefinitionSourceStatus Hashes { get; init; } = new();
    /// <summary>New PersonalAV versions; null when app update checks are turned off.</summary>
    public AppUpdateStatus? App { get; init; }
}

/// <summary>State of the PersonalAV app update check.</summary>
public sealed record AppUpdateStatus
{
    public string InstalledVersion { get; init; } = "";
    /// <summary>Installer variant ("framework" or "selfcontained"); null when not installed by the .msi.</summary>
    public string? Variant { get; init; }
    /// <summary>Newest published version, whether or not it is newer than this one.</summary>
    public string? LatestVersion { get; init; }
    /// <summary>A published version newer than the installed one, or null.</summary>
    public string? AvailableVersion { get; init; }
    public string? Notes { get; init; }
    public string? ReleaseUrl { get; init; }
    public DateTimeOffset? Published { get; init; }
    /// <summary>The verified installer for <see cref="AvailableVersion"/> is downloaded and can be installed.</summary>
    public bool InstallerReady { get; init; }
    public DateTimeOffset? CheckedAt { get; init; }
    public string? Result { get; init; }
    public string? Error { get; init; }
}

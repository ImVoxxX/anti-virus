using System.Text;
using PersonalAV.Core;
using PersonalAV.Core.Scanning;

namespace PersonalAV.Tests;

public sealed class QuarantineTests : IDisposable
{
    private readonly TestEnvironment _env = new();

    public void Dispose() => _env.Dispose();

    [Fact]
    public void Quarantine_and_restore_round_trip()
    {
        var content = "secret payload " + TestMarker.Value;
        var path = _env.WriteFile(@"docs\threat.txt", content);
        var original = File.ReadAllBytes(path);

        var entry = _env.Quarantine.Quarantine(path, "Test.Threat");

        Assert.False(File.Exists(path));
        var stored = Directory.GetFiles(_env.Paths.Quarantine, entry.Id + ".*").Single();
        var storedBytes = File.ReadAllBytes(stored);
        // Encrypted at rest: neither the payload nor the marker appear in the stored file.
        Assert.DoesNotContain(TestMarker.Value, Encoding.ASCII.GetString(storedBytes));
        Assert.Single(_env.Quarantine.List());

        var restoredTo = _env.Quarantine.Restore(entry.Id);

        Assert.Equal(path, restoredTo);
        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.False(File.Exists(stored));
        Assert.Empty(_env.Quarantine.List());
    }

    [Fact]
    public void Restore_refuses_to_overwrite_unless_asked()
    {
        var path = _env.WriteFile("x.txt", "original");
        var entry = _env.Quarantine.Quarantine(path, "Test.Threat");
        File.WriteAllText(path, "something new");

        Assert.Throws<IOException>(() => _env.Quarantine.Restore(entry.Id));
        Assert.Equal("something new", File.ReadAllText(path));

        _env.Quarantine.Restore(entry.Id, overwrite: true);
        Assert.Equal("original", File.ReadAllText(path));
    }

    [Fact]
    public void Restore_into_deleted_folder_recreates_it()
    {
        var path = _env.WriteFile(@"gone\x.txt", "data");
        var entry = _env.Quarantine.Quarantine(path, "Test.Threat");
        Directory.Delete(Path.GetDirectoryName(path)!);

        _env.Quarantine.Restore(entry.Id);

        Assert.Equal("data", File.ReadAllText(path));
    }

    [Fact]
    public void Read_only_files_can_be_quarantined()
    {
        var path = _env.WriteFile("ro.txt", "data");
        File.SetAttributes(path, FileAttributes.ReadOnly);

        _env.Quarantine.Quarantine(path, "Test.Threat");

        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Tampered_quarantine_file_is_not_restored()
    {
        var path = _env.WriteFile("t.txt", "data data data");
        var entry = _env.Quarantine.Quarantine(path, "Test.Threat");
        var stored = Directory.GetFiles(_env.Paths.Quarantine, entry.Id + ".*").Single();
        var bytes = File.ReadAllBytes(stored);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(stored, bytes);

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => _env.Quarantine.Restore(entry.Id));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Locked_file_quarantine_fails_and_leaves_original()
    {
        var path = _env.WriteFile("busy.txt", "busy");
        // Readable (so it can be copied) but not deletable.
        using var holder = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        Assert.ThrowsAny<IOException>(() => _env.Quarantine.Quarantine(path, "Test.Threat"));
        Assert.True(File.Exists(path));
        Assert.Empty(_env.Quarantine.List());
        Assert.Empty(Directory.GetFiles(_env.Paths.Quarantine, "*.pavq"));
    }

    [Fact]
    public void Delete_removes_entry_permanently()
    {
        var path = _env.WriteFile("d.txt", "data");
        var entry = _env.Quarantine.Quarantine(path, "Test.Threat");

        _env.Quarantine.Delete(entry.Id);

        Assert.Empty(_env.Quarantine.List());
        Assert.Empty(Directory.GetFiles(_env.Paths.Quarantine, "*.pavq"));
        Assert.Throws<KeyNotFoundException>(() => _env.Quarantine.Restore(entry.Id));
    }

    [Fact]
    public async Task Path_scan_detects_and_quarantines()
    {
        _env.LoadMarkerRule();
        _env.WriteFile(@"tree\clean.txt", "fine");
        var bad = _env.WriteFile(@"tree\nested\bad.txt", TestMarker.Value + " x");
        var scans = new ScanCoordinator(_env.Engine, _env.Quarantine, _env.Db, _env.Paths);

        var id = scans.TryStart(ScanKind.Path, Path.Combine(_env.Work, "tree"), out var error);
        Assert.NotNull(id);
        Assert.Null(error);
        await scans.WaitAsync();

        var status = scans.GetStatus();
        Assert.Equal(ScanState.Completed, status.State);
        Assert.Equal(2, status.FilesScanned);
        Assert.Equal(1, status.Detections);
        Assert.False(File.Exists(bad));
        var detection = Assert.Single(_env.Db.ListDetections());
        Assert.Equal(DetectionAction.Quarantined, detection.Action);
        Assert.Equal(bad, detection.Path);
        Assert.NotNull(_env.Db.GetQuarantine(detection.QuarantineId!));
    }

    [Fact]
    public void Path_scan_of_missing_path_is_rejected()
    {
        var scans = new ScanCoordinator(_env.Engine, _env.Quarantine, _env.Db, _env.Paths);

        Assert.Null(scans.TryStart(ScanKind.Path, Path.Combine(_env.Work, "missing"), out var error));
        Assert.Contains("not found", error);
    }
}

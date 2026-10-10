using System.Diagnostics;
using PersonalAV.Core.Scanning;

namespace PersonalAV.Tests;

public sealed class FileEnumeratorTests : IDisposable
{
    private readonly TestEnvironment _env = new();

    public void Dispose() => _env.Dispose();

    [Fact]
    public void Enumerates_nested_files()
    {
        _env.WriteFile("a.txt", "a");
        _env.WriteFile(@"sub\b.txt", "b");
        _env.WriteFile(@"sub\deeper\c.txt", "c");

        var names = FileEnumerator.Enumerate(_env.Work).Select(f => f.Name).Order().ToList();

        Assert.Equal(new[] { "a.txt", "b.txt", "c.txt" }, names);
    }

    [Fact]
    public void Does_not_follow_junctions()
    {
        _env.WriteFile(@"real\inside.txt", "x");
        var junction = Path.Combine(_env.Work, "loop");
        // A junction back to the root would loop forever if followed. mklink /J needs no elevation.
        var mklink = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{junction}\" \"{_env.Work}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
        })!;
        mklink.WaitForExit();
        Assert.True(Directory.Exists(junction), "junction was not created");

        var skipped = new List<(string Path, string Reason)>();
        var files = FileEnumerator.Enumerate(_env.Work, onSkip: (p, r) => skipped.Add((p, r))).ToList();

        Assert.Single(files);
        Assert.Contains(skipped, s => s.Path == junction && s.Reason == "link");
    }

    [Fact]
    public void Skips_excluded_roots()
    {
        _env.WriteFile(@"keep\a.txt", "a");
        _env.WriteFile(@"skip\b.txt", "b");

        var files = FileEnumerator.Enumerate(_env.Work, new[] { Path.Combine(_env.Work, "skip") }).ToList();

        Assert.Equal("a.txt", Assert.Single(files).Name);
    }

    [Fact]
    public void Single_file_root_yields_that_file()
    {
        var path = _env.WriteFile("one.txt", "1");

        Assert.Equal(path, Assert.Single(FileEnumerator.Enumerate(path)).FullName);
    }

    [Fact]
    public void Missing_root_is_reported_not_thrown()
    {
        var skipped = new List<string>();

        var files = FileEnumerator.Enumerate(Path.Combine(_env.Work, "nope"), onSkip: (p, _) => skipped.Add(p)).ToList();

        Assert.Empty(files);
        Assert.Single(skipped);
    }

    [Fact]
    public void Cancellation_stops_enumeration()
    {
        _env.WriteFile(@"a\1.txt", "1");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() => FileEnumerator.Enumerate(_env.Work, cancellationToken: cts.Token).ToList());
    }
}

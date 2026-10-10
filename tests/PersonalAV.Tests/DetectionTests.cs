using System.Security.Cryptography;
using System.Text;
using PersonalAV.Core;
using PersonalAV.Core.Scanning;

namespace PersonalAV.Tests;

public sealed class DetectionTests : IDisposable
{
    private readonly TestEnvironment _env = new();

    public void Dispose() => _env.Dispose();

    [Fact]
    public void Rule_loader_compiles_good_files_and_reports_broken_ones()
    {
        File.WriteAllText(Path.Combine(_env.Paths.Rules, "broken.yar"), "rule Broken { condition: nonsense_identifier }");
        File.WriteAllText(Path.Combine(_env.Paths.Rules, "ignored.txt"), "not a rule file");

        var report = _env.LoadMarkerRule();

        Assert.Null(report.Error);
        Assert.Equal(1, report.FilesLoaded);
        Assert.Equal(1, report.RuleCount);
        Assert.True(report.FailedFiles.ContainsKey("broken.yar"));
    }

    [Fact]
    public void Rule_loader_keeps_previous_rules_when_nothing_compiles()
    {
        _env.LoadMarkerRule();
        File.Delete(Path.Combine(_env.Paths.Rules, "marker.yar"));
        File.WriteAllText(Path.Combine(_env.Paths.Rules, "broken.yar"), "rule Broken {");

        var report = _env.Yara.Load(_env.Paths.Rules);

        Assert.NotNull(report.Error);
        Assert.Equal(1, _env.Yara.RuleCount);
        Assert.NotEmpty(_env.Yara.Match(Encoding.ASCII.GetBytes(TestMarker.Value)));
    }

    [Fact]
    public void Repo_rules_compile()
    {
        var repoRules = Path.Combine(FindRepoRoot(), "rules");

        var report = _env.Yara.Load(repoRules);

        Assert.Null(report.Error);
        Assert.Empty(report.FailedFiles);
        Assert.True(report.RuleCount >= 2);
        // The bundled test rule must match the marker the CLI writes.
        Assert.Contains(TestEnvironment.MarkerRule, _env.Yara.Match(Encoding.ASCII.GetBytes("x " + TestMarker.Value + " y")));
    }

    [Fact]
    public void Detects_by_yara_rule()
    {
        _env.LoadMarkerRule();
        var path = _env.WriteFile("marked.txt", "prefix " + TestMarker.Value + " suffix");

        var verdict = _env.Engine.ScanFile(path);

        Assert.Equal(VerdictKind.Detected, verdict.Kind);
        Assert.Equal("yara", verdict.Engine);
        Assert.Equal("Yara." + TestEnvironment.MarkerRule, verdict.ThreatName);
    }

    [Fact]
    public void Detects_by_blocklisted_hash()
    {
        var path = _env.WriteFile("bad.bin", "pretend this is malware " + Guid.NewGuid());
        var sha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        _env.Db.ImportHashes(new[] { (sha, (string?)"Test.Hash") }, "test");

        var verdict = _env.Engine.ScanFile(path);

        Assert.Equal(VerdictKind.Detected, verdict.Kind);
        Assert.Equal("hash", verdict.Engine);
        Assert.Equal("Test.Hash", verdict.ThreatName);
    }

    [Fact]
    public void Eicar_hash_is_seeded()
    {
        Assert.Equal("EICAR-Test-File", _env.Db.LookupHash(AvDatabase.EicarSha256));
    }

    [Fact]
    public void Clean_file_is_clean_and_oversized_file_is_skipped()
    {
        _env.LoadMarkerRule();
        var clean = _env.WriteFile("clean.txt", "nothing to see");
        var big = Path.Combine(_env.Work, "big.bin");
        File.WriteAllBytes(big, new byte[_env.Engine.MaxFileSize + 1]);

        Assert.Equal(VerdictKind.Clean, _env.Engine.ScanFile(clean).Kind);
        Assert.Equal(VerdictKind.Skipped, _env.Engine.ScanFile(big).Kind);
    }

    [Fact]
    public void Locked_file_is_skipped_not_thrown()
    {
        var path = _env.WriteFile("locked.txt", "locked");
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        Assert.Equal(VerdictKind.Skipped, _env.Engine.ScanFile(path).Kind);
    }

    [Fact]
    public void Hash_parser_reads_plain_lists_and_malwarebazaar_csv()
    {
        var a = new string('a', 64);
        var b = new string('B', 64);
        var plain = $"# comment\n{a}\nnot-a-hash\n\n{b}\n";
        var csv = $"""
            ################################################################
            # MalwareBazaar full data dump (CSV)                           #
            ################################################################
            # "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
            "2026-01-01 00:00:00", "{a}", "x", "y", "someone", "evil.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "50", "n/a", "n/a", "n/a"
            "2026-01-01 00:00:01", "{b}", "x", "y", "someone", "evil2.exe", "exe", "application/x-dosexec", "n/a", "n/a", "50", "n/a", "n/a", "n/a"
            """;

        var fromPlain = HashListParser.Parse(new StringReader(plain)).ToList();
        var fromCsv = HashListParser.Parse(new StringReader(csv)).ToList();

        Assert.Equal(new[] { (a, (string?)null), (b.ToLowerInvariant(), null) }, fromPlain);
        Assert.Equal(new[] { (a, (string?)"MalwareBazaar.AgentTesla"), (b.ToLowerInvariant(), null) }, fromCsv);
    }

    internal static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "PersonalAV.sln")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new DirectoryNotFoundException("repo root not found");
    }
}

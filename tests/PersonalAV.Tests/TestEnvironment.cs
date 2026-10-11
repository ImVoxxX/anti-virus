using PersonalAV.Core;
using PersonalAV.Core.Quarantine;
using PersonalAV.Core.Scanning;

namespace PersonalAV.Tests;

/// <summary>A throwaway data root with a real database, rule set and quarantine, deleted on dispose.</summary>
public sealed class TestEnvironment : IDisposable
{
    public TestEnvironment()
    {
        Root = Path.Combine(Path.GetTempPath(), "PersonalAV.Tests", Guid.NewGuid().ToString("N"));
        Paths = new AppPaths(Path.Combine(Root, "data"));
        Paths.EnsureCreated(restrictAcl: false);
        Work = Directory.CreateDirectory(Path.Combine(Root, "work")).FullName;
        Db = new AvDatabase(Paths.Database);
        Db.Initialize();
        Yara = new YaraRuleSet();
        Engine = new ScanEngine(Db, Yara, maxFileSize: 1024 * 1024);
        Quarantine = new QuarantineStore(Paths, Db);
    }

    public string Root { get; }
    public string Work { get; }
    public AppPaths Paths { get; }
    public AvDatabase Db { get; }
    public YaraRuleSet Yara { get; }
    public ScanEngine Engine { get; }
    public QuarantineStore Quarantine { get; }

    public const string MarkerRule = "PersonalAV_Test_Marker";

    /// <summary>Installs the repo's test-marker rule into the rules folder and loads it.</summary>
    public RuleLoadReport LoadMarkerRule()
    {
        File.WriteAllText(Path.Combine(Paths.Rules, "marker.yar"), $$"""
            rule {{MarkerRule}}
            {
                strings:
                    $marker = "{{TestMarker.Value}}"
                condition:
                    $marker at 0 and filesize < 256
            }
            """);
        return Yara.Load(Paths.Rules);
    }

    public string WriteFile(string relativePath, string content)
    {
        var path = Path.Combine(Work, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        Yara.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

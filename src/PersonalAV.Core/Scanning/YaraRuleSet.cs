using libyaraNET;

namespace PersonalAV.Core.Scanning;

/// <summary>
/// Compiles every .yar/.yara file in the rules folder and scans buffers against them.
/// A file that fails to compile is skipped and reported; if the combined set fails, or no file compiles,
/// the previously loaded rules stay active so the engine is never left without rules.
/// </summary>
public sealed class YaraRuleSet : IDisposable
{
    // yr_initialize/yr_finalize are process-wide; keep one context for the life of the process.
    private static readonly YaraContext Context = new();

    private readonly ReaderWriterLockSlim _lock = new();
    private Rules? _rules;

    public int RuleCount { get; private set; }
    public RuleLoadReport LastReport { get; private set; } =
        new(0, 0, new Dictionary<string, string>(), "rules not loaded");

    public RuleLoadReport Load(string rulesDirectory)
    {
        GC.KeepAlive(Context);
        var files = Directory.Exists(rulesDirectory)
            ? Directory.EnumerateFiles(rulesDirectory)
                .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase)
                         || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToList()
            : new List<string>();

        var failed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var good = new List<string>();
        foreach (var file in files)
        {
            var error = TryCompile(new[] { file }, out var rules);
            rules?.Dispose();
            if (error is null)
            {
                good.Add(file);
            }
            else
            {
                failed[Path.GetFileName(file)] = error;
            }
        }

        if (good.Count == 0)
        {
            return LastReport = new RuleLoadReport(0, RuleCount, failed,
                files.Count == 0 ? "no rule files found" : "no rule file compiled; previous rules kept");
        }

        var combinedError = TryCompile(good, out var combined);
        if (combinedError is not null || combined is null)
        {
            return LastReport = new RuleLoadReport(0, RuleCount, failed,
                $"combined compile failed ({combinedError}); previous rules kept");
        }

        var count = combined.GetRules().Count;
        _lock.EnterWriteLock();
        try
        {
            _rules?.Dispose();
            _rules = combined;
            RuleCount = count;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
        return LastReport = new RuleLoadReport(good.Count, count, failed, null);
    }

    /// <summary>Returns the identifiers of the rules that match <paramref name="data"/>.</summary>
    public IReadOnlyList<string> Match(byte[] data)
    {
        _lock.EnterReadLock();
        try
        {
            if (_rules is null || data.Length == 0)
            {
                return Array.Empty<string>();
            }
            var results = new Scanner().ScanMemory(data, _rules);
            return results.Select(r => r.MatchingRule.Identifier).ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    private static string? TryCompile(IEnumerable<string> files, out Rules? rules)
    {
        rules = null;
        try
        {
            using var compiler = new Compiler();
            foreach (var file in files)
            {
                compiler.AddRuleFile(file);
            }
            rules = compiler.GetRules();
            return null;
        }
        catch (CompilationException ex)
        {
            return string.Join("; ", ex.Errors);
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    public void Dispose()
    {
        _lock.EnterWriteLock();
        try
        {
            _rules?.Dispose();
            _rules = null;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }
}

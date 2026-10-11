using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAV.Core.Ipc;
using PersonalAV.Core.Scanning;

namespace PersonalAV.Core.Updates;

/// <summary>
/// Keeps the detection definitions current from two sources:
/// <list type="bullet">
/// <item>YARA rules from a signed manifest (the repository's rules folder). Changed files are downloaded, checked
/// against the signed hashes, test-compiled together with the local rules, and only then swapped in.</item>
/// <item>SHA-256 hashes from the MalwareBazaar recent feed, fetched conditionally and merged into the blocklist.</item>
/// </list>
/// Checks run one at a time, on a schedule (<see cref="RunAsync"/>) or on request (<see cref="RequestCheck"/>).
/// A failure in one source is recorded and does not stop the other.
/// </summary>
public sealed class DefinitionUpdater : IDisposable
{
    public const string HashSource = "feed:malwarebazaar";

    private const long MaxManifestBytes = 1024 * 1024;
    private const long MaxFeedBytes = 200L * 1024 * 1024;

    private readonly AvDatabase _db;
    private readonly YaraRuleSet _yara;
    private readonly AppPaths _paths;
    private readonly HttpClient _http;
    private readonly UpdateOptions _options;
    private readonly AppUpdateChecker? _app;
    private readonly ILogger _logger;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0, 1);
    private volatile bool _checking;
    private DateTimeOffset? _nextCheck;

    /// <param name="app">Optional app update check, run after the definitions; null when app updates are off.</param>
    public DefinitionUpdater(AvDatabase db, YaraRuleSet yara, AppPaths paths, HttpClient http, UpdateOptions options,
        AppUpdateChecker? app = null, ILogger<DefinitionUpdater>? logger = null)
    {
        _db = db;
        _yara = yara;
        _paths = paths;
        _http = http;
        _options = options;
        _app = app;
        _logger = logger ?? NullLogger<DefinitionUpdater>.Instance;
    }

    public UpdateStatus GetStatus() => new()
    {
        AutomaticChecks = _options.Enabled,
        Checking = _checking,
        NextCheck = _checking ? null : _nextCheck,
        Rules = ReadStatus("rules"),
        Hashes = ReadStatus("hashes"),
        App = _app?.GetStatus(),
    };

    /// <summary>Asks <see cref="RunAsync"/> to check now. Returns false if a check is already running.</summary>
    public bool RequestCheck()
    {
        if (_checking)
        {
            return false;
        }
        try
        {
            _wake.Release();
        }
        catch (SemaphoreFullException)
        {
            // Already requested.
        }
        return true;
    }

    /// <summary>
    /// Runs until cancelled: checks when the interval since the last check has passed (but not in the first minute
    /// after start, so the machine can settle), and whenever <see cref="RequestCheck"/> is called.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        bool first = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            var wait = Timeout.InfiniteTimeSpan;
            _nextCheck = null;
            if (_options.Enabled)
            {
                var last = ParseTime(_db.GetSetting("update.last_check"));
                var due = last is null ? TimeSpan.Zero : last.Value + _options.Interval - DateTimeOffset.UtcNow;
                wait = first ? Max(due, TimeSpan.FromMinutes(1)) : Max(due, TimeSpan.Zero);
                _nextCheck = DateTimeOffset.UtcNow + wait;
            }
            first = false;

            try
            {
                await _wake.WaitAsync(wait, cancellationToken).ConfigureAwait(false);
                await CheckNowAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>Checks both sources now, waiting for a check already in progress to finish first.</summary>
    public async Task<UpdateStatus> CheckNowAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        _checking = true;
        try
        {
            await RunSource("rules", UpdateRulesAsync, cancellationToken).ConfigureAwait(false);
            await RunSource("hashes", UpdateHashesAsync, cancellationToken).ConfigureAwait(false);
            if (_app is not null)
            {
                await _app.CheckAsync(cancellationToken).ConfigureAwait(false);
            }
            _db.SetSetting("update.last_check", FormatTime(DateTimeOffset.UtcNow));
        }
        finally
        {
            _checking = false;
            _gate.Release();
        }
        return GetStatus();
    }

    private async Task RunSource(string source, Func<CancellationToken, Task<Outcome>> update, CancellationToken cancellationToken)
    {
        var previous = ReadStatus(source);
        var now = DateTimeOffset.UtcNow;
        try
        {
            var outcome = await update(cancellationToken).ConfigureAwait(false);
            WriteStatus(source, previous with
            {
                CheckedAt = now,
                UpdatedAt = outcome.Changed ? now : previous.UpdatedAt,
                Version = outcome.Version ?? previous.Version,
                Result = outcome.Result,
                Error = null,
            });
            _logger.LogInformation("Definition update ({Source}): {Result}", source, outcome.Result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            var message = DescribeFailure(ex);
            WriteStatus(source, previous with { CheckedAt = now, Error = message });
            _logger.LogWarning(ex, "Definition update ({Source}) failed: {Message}", source, message);
        }
    }

    /// <summary>A failure as the user sees it in the update status.</summary>
    internal static string DescribeFailure(Exception ex) => ex switch
    {
        UpdateException or InvalidDataException => ex.Message,
        TaskCanceledException => "the download timed out",
        HttpRequestException => "could not connect: " + ex.Message,
        _ => ex.Message,
    };

    // ---- rules ----

    private async Task<Outcome> UpdateRulesAsync(CancellationToken cancellationToken)
    {
        var baseUrl = _options.RulesBaseUrl.EndsWith('/') ? _options.RulesBaseUrl : _options.RulesBaseUrl + "/";
        var manifestBytes = await DownloadAsync(baseUrl + RulesManifest.FileName, MaxManifestBytes, "rules manifest", true, cancellationToken)
            .ConfigureAwait(false);
        var signature = Encoding.ASCII.GetString(
            await DownloadAsync(baseUrl + RulesManifest.SignatureFileName, 4096, "rules signature", true, cancellationToken).ConfigureAwait(false));
        var manifest = RulesManifest.ParseVerified(manifestBytes, signature, _options.PublisherPublicKey);

        long.TryParse(_db.GetSetting("update.rules.version"), NumberStyles.None, CultureInfo.InvariantCulture, out var installed);
        if (manifest.Version < installed)
        {
            throw new UpdateException($"refused rules version {manifest.Version}: version {installed} is already installed");
        }

        var rulesDir = _paths.Rules;
        var managed = ReadManagedFiles();
        var listed = manifest.Files.Select(f => f.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var changed = manifest.Files
            .Where(f => !File.Exists(Path.Combine(rulesDir, f.Name)) || RulesManifest.Sha256OfFile(Path.Combine(rulesDir, f.Name)) != f.Sha256)
            .ToList();
        // Only files an earlier update installed are ever removed; the user's own rule files are left alone.
        var removed = managed.Where(n => !listed.Contains(n) && File.Exists(Path.Combine(rulesDir, n))).ToList();
        var version = manifest.Version.ToString(CultureInfo.InvariantCulture);

        if (changed.Count == 0 && removed.Count == 0)
        {
            SaveRulesState(manifest.Version, listed);
            return new Outcome(false, $"Up to date (version {version})", version);
        }

        var staging = ResetDirectory(Path.Combine(_paths.Updates, "staging"));
        var candidate = ResetDirectory(Path.Combine(_paths.Updates, "candidate"));
        try
        {
            foreach (var file in changed)
            {
                var data = await DownloadAsync(baseUrl + Uri.EscapeDataString(file.Name), RulesManifest.MaxRuleFileBytes,
                    file.Name, true, cancellationToken).ConfigureAwait(false);
                var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)).ToLowerInvariant();
                if (data.LongLength != file.Size || hash != file.Sha256)
                {
                    throw new UpdateException($"{file.Name} does not match the signed manifest; nothing was changed");
                }
                await File.WriteAllBytesAsync(Path.Combine(staging, file.Name), data, cancellationToken).ConfigureAwait(false);
            }

            // Compile what the rules folder will hold afterwards, so a bad update never reaches the live engine.
            var changedNames = changed.Select(f => f.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var path in Directory.EnumerateFiles(rulesDir))
            {
                var name = Path.GetFileName(path);
                if (IsRuleFile(name) && !changedNames.Contains(name) && !removed.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    File.Copy(path, Path.Combine(candidate, name));
                }
            }
            foreach (var name in changedNames)
            {
                File.Copy(Path.Combine(staging, name), Path.Combine(candidate, name));
            }
            using (var test = new YaraRuleSet())
            {
                var report = test.Load(candidate);
                var broken = changedNames.Where(report.FailedFiles.ContainsKey).ToList();
                if (report.Error is not null || broken.Count > 0)
                {
                    var detail = report.Error ?? string.Join("; ", broken.Select(n => $"{n}: {report.FailedFiles[n]}"));
                    throw new UpdateException($"rules version {version} does not compile here, so it was not installed ({detail})");
                }
            }

            foreach (var name in changedNames)
            {
                File.Move(Path.Combine(staging, name), Path.Combine(rulesDir, name), overwrite: true);
            }
            foreach (var name in removed)
            {
                File.Delete(Path.Combine(rulesDir, name));
            }
        }
        finally
        {
            TryDelete(staging);
            TryDelete(candidate);
        }

        SaveRulesState(manifest.Version, listed);
        var loaded = _yara.Load(rulesDir);
        return new Outcome(true,
            $"Updated to version {version}: {Count(changed.Count, "file")} updated, {removed.Count} removed; {loaded.RuleCount} rules active",
            version);
    }

    private HashSet<string> ReadManagedFiles()
    {
        var json = _db.GetSetting("update.rules.files");
        var names = json is null ? null : JsonSerializer.Deserialize<List<string>>(json);
        return new HashSet<string>(names ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
    }

    private void SaveRulesState(long version, IEnumerable<string> files)
    {
        _db.SetSetting("update.rules.version", version.ToString(CultureInfo.InvariantCulture));
        _db.SetSetting("update.rules.files", JsonSerializer.Serialize(files.Order(StringComparer.OrdinalIgnoreCase).ToList()));
    }

    // ---- hashes ----

    private async Task<Outcome> UpdateHashesAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, _options.EffectiveHashFeedUrl);
        if (_db.GetSetting("update.hashes.etag") is { } etag && EntityTagHeaderValue.TryParse(etag, out var tag))
        {
            request.Headers.IfNoneMatch.Add(tag);
        }
        if (ParseTime(_db.GetSetting("update.hashes.last_modified")) is { } since)
        {
            request.Headers.IfModifiedSince = since;
        }

        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return new Outcome(false, "Up to date (feed unchanged)", null);
        }
        UpdateHttp.EnsureSuccess(response, "hash feed", code => Hint(false, code));
        var data = await UpdateHttp.ReadLimitedAsync(response.Content, MaxFeedBytes, "hash feed", cancellationToken).ConfigureAwait(false);

        var hashes = ParseFeed(data);
        if (hashes.Count == 0)
        {
            throw new UpdateException("the hash feed contained no hashes");
        }
        var added = _db.ImportHashes(hashes, HashSource);

        _db.SetSetting("update.hashes.etag", response.Headers.ETag?.ToString());
        var lastModified = response.Content.Headers.LastModified;
        _db.SetSetting("update.hashes.last_modified", lastModified is null ? null : FormatTime(lastModified.Value));
        var version = lastModified?.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
        return added > 0
            ? new Outcome(true, $"Added {Count(added, "new hash", "new hashes")} ({hashes.Count:N0} in feed)", version)
            : new Outcome(false, $"Up to date (all {hashes.Count:N0} feed hashes already known)", version);
    }

    private static List<(string Sha256, string? ThreatName)> ParseFeed(byte[] data)
    {
        // The authenticated API may serve a .zip; the public export is plain CSV.
        if (data.Length > 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4)
        {
            using var zip = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
            var result = new List<(string, string?)>();
            foreach (var entry in zip.Entries.Where(e => e.Length > 0))
            {
                using var reader = new StreamReader(entry.Open());
                result.AddRange(HashListParser.Parse(reader));
            }
            return result;
        }
        using var text = new StreamReader(new MemoryStream(data));
        return HashListParser.Parse(text).ToList();
    }

    // ---- HTTP ----

    private Task<byte[]> DownloadAsync(string url, long maxBytes, string what, bool rules, CancellationToken cancellationToken) =>
        UpdateHttp.GetBytesAsync(_http, url, maxBytes, what, rules ? _options.RulesToken : null,
            code => Hint(rules, code), cancellationToken);

    private string Hint(bool rules, HttpStatusCode code) => (rules, code) switch
    {
        (true, HttpStatusCode.NotFound or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) =>
            string.IsNullOrWhiteSpace(_options.RulesToken)
                ? ". Check the connection, or set Updates:RulesToken if you were given one"
                : ". Check that Updates:RulesToken is valid",
        (false, HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) =>
            string.IsNullOrWhiteSpace(_options.MalwareBazaarAuthKey)
                ? ". abuse.ch now needs an Auth-Key: get a free one at https://auth.abuse.ch and set Updates:MalwareBazaarAuthKey"
                : ". Check that Updates:MalwareBazaarAuthKey is valid",
        _ => "",
    };

    // ---- state ----

    private DefinitionSourceStatus ReadStatus(string source)
    {
        var json = _db.GetSetting($"update.{source}.status");
        return json is null ? new DefinitionSourceStatus() : JsonSerializer.Deserialize<DefinitionSourceStatus>(json, PipeProtocol.Json) ?? new();
    }

    private void WriteStatus(string source, DefinitionSourceStatus status) =>
        _db.SetSetting($"update.{source}.status", JsonSerializer.Serialize(status, PipeProtocol.Json));

    private static bool IsRuleFile(string name) =>
        name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".yara", StringComparison.OrdinalIgnoreCase);

    private static string ResetDirectory(string path)
    {
        TryDelete(path);
        return Directory.CreateDirectory(path).FullName;
    }

    private static void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static string Count(int n, string singular, string? plural = null) =>
        n == 1 ? $"1 {singular}" : $"{n:N0} {plural ?? singular + "s"}";

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    private static string FormatTime(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset? ParseTime(string? value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) ? parsed : null;

    public void Dispose()
    {
        _gate.Dispose();
        _wake.Dispose();
    }

    private sealed record Outcome(bool Changed, string Result, string? Version);
}

/// <summary>An update failure with a message meant for the user.</summary>
public sealed class UpdateException(string message, HttpStatusCode? statusCode = null) : Exception(message)
{
    /// <summary>The HTTP status when the failure was an error response.</summary>
    public HttpStatusCode? StatusCode { get; } = statusCode;
}

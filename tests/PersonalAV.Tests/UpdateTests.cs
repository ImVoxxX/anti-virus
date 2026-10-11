using System.Net;
using System.Security.Cryptography;
using System.Text;
using PersonalAV.Core;
using PersonalAV.Core.Updates;

namespace PersonalAV.Tests;

public sealed class UpdateTests : IDisposable
{
    private const string RulesUrl = "https://rules.test/rules/";
    private const string FeedUrl = "https://feed.test/recent.csv";

    private readonly TestEnvironment _env = new();
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly FakeServer _server = new();
    private readonly DefinitionUpdater _updater;

    public UpdateTests()
    {
        var options = new UpdateOptions
        {
            RulesBaseUrl = RulesUrl,
            HashFeedUrl = FeedUrl,
            RulesPublicKey = Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo()),
        };
        _updater = new DefinitionUpdater(_env.Db, _env.Yara, _env.Paths, new HttpClient(_server), options);
        _server.Respond(FeedUrl, HttpStatusCode.OK, Feed());
    }

    public void Dispose()
    {
        _updater.Dispose();
        _key.Dispose();
        _env.Dispose();
    }

    [Fact]
    public void Repo_manifest_is_signed_with_the_shipped_key_and_matches_the_rule_files()
    {
        var rules = Path.Combine(DetectionTests.FindRepoRoot(), "rules");

        var manifest = RulesManifest.ParseVerified(
            File.ReadAllBytes(Path.Combine(rules, RulesManifest.FileName)),
            File.ReadAllText(Path.Combine(rules, RulesManifest.SignatureFileName)),
            UpdateKeys.RulesPublicKey);

        // Fails when a rule file changes without re-running: pav-rulesigner sign <key>
        Assert.Equal(RulesManifest.FromDirectory(rules, 0, default).Files, manifest.Files);
        Assert.DoesNotContain((byte)'\r', File.ReadAllBytes(Path.Combine(rules, RulesManifest.FileName)));
    }

    [Fact]
    public async Task Installs_new_rules_and_keeps_the_users_own_files()
    {
        var own = WriteLocalRule("my_rule.yar", Rule("My_Own_Rule", "mine"));
        Publish(1, ("published.yar", Rule("Published_Rule", "published-marker")));

        var status = await _updater.CheckNowAsync();

        Assert.Null(status.Rules.Error);
        Assert.Equal("1", status.Rules.Version);
        Assert.True(File.Exists(Path.Combine(_env.Paths.Rules, "published.yar")));
        Assert.True(File.Exists(own));
        Assert.Contains("Published_Rule", _env.Yara.Match(Encoding.ASCII.GetBytes("published-marker")));
        Assert.Contains("My_Own_Rule", _env.Yara.Match(Encoding.ASCII.GetBytes("mine")));
    }

    [Fact]
    public async Task Second_check_with_the_same_manifest_downloads_nothing()
    {
        Publish(1, ("published.yar", Rule("Published_Rule", "published-marker")));
        await _updater.CheckNowAsync();
        _server.Requests.Clear();

        var status = await _updater.CheckNowAsync();

        Assert.StartsWith("Up to date", status.Rules.Result);
        Assert.DoesNotContain(_server.Requests, u => u.EndsWith(".yar", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Removes_files_dropped_from_the_manifest_but_only_ones_it_installed()
    {
        WriteLocalRule("my_rule.yar", Rule("My_Own_Rule", "mine"));
        Publish(1, ("a.yar", Rule("Rule_A", "aaa")), ("b.yar", Rule("Rule_B", "bbb")));
        await _updater.CheckNowAsync();

        Publish(2, ("a.yar", Rule("Rule_A", "aaa")));
        var status = await _updater.CheckNowAsync();

        Assert.Null(status.Rules.Error);
        Assert.False(File.Exists(Path.Combine(_env.Paths.Rules, "b.yar")));
        Assert.True(File.Exists(Path.Combine(_env.Paths.Rules, "a.yar")));
        Assert.True(File.Exists(Path.Combine(_env.Paths.Rules, "my_rule.yar")));
        Assert.Empty(_env.Yara.Match(Encoding.ASCII.GetBytes("bbb")));
    }

    [Fact]
    public async Task Refuses_a_manifest_with_a_bad_signature()
    {
        Publish(1, ("published.yar", Rule("Published_Rule", "x")));
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _server.Respond(RulesUrl + RulesManifest.SignatureFileName, HttpStatusCode.OK,
            Encoding.ASCII.GetBytes(RulesManifest.Sign(_server.Body(RulesUrl + RulesManifest.FileName), otherKey)));

        var status = await _updater.CheckNowAsync();

        Assert.Contains("signature", status.Rules.Error);
        Assert.False(File.Exists(Path.Combine(_env.Paths.Rules, "published.yar")));
    }

    [Fact]
    public async Task Refuses_a_file_that_does_not_match_the_signed_hash()
    {
        Publish(1, ("published.yar", Rule("Published_Rule", "x")));
        _server.Respond(RulesUrl + "published.yar", HttpStatusCode.OK, Encoding.ASCII.GetBytes(Rule("Evil_Rule", "y")));

        var status = await _updater.CheckNowAsync();

        Assert.Contains("does not match the signed manifest", status.Rules.Error);
        Assert.False(File.Exists(Path.Combine(_env.Paths.Rules, "published.yar")));
    }

    [Fact]
    public async Task Refuses_an_older_manifest_than_the_installed_one()
    {
        Publish(2, ("published.yar", Rule("Published_Rule", "new")));
        await _updater.CheckNowAsync();

        Publish(1, ("published.yar", Rule("Published_Rule", "old")));
        var status = await _updater.CheckNowAsync();

        Assert.Contains("refused rules version 1", status.Rules.Error);
        Assert.Contains("Published_Rule", _env.Yara.Match(Encoding.ASCII.GetBytes("new")));
    }

    [Fact]
    public async Task Rules_that_do_not_compile_are_not_installed_and_the_old_ones_stay_active()
    {
        Publish(1, ("published.yar", Rule("Published_Rule", "good")));
        await _updater.CheckNowAsync();

        Publish(2, ("published.yar", "rule Broken { condition: nonsense }"));
        var status = await _updater.CheckNowAsync();

        Assert.Contains("does not compile", status.Rules.Error);
        Assert.Equal("1", status.Rules.Version);
        Assert.Contains("Published_Rule", File.ReadAllText(Path.Combine(_env.Paths.Rules, "published.yar")));
        Assert.Contains("Published_Rule", _env.Yara.Match(Encoding.ASCII.GetBytes("good")));
    }

    [Fact]
    public async Task Imports_feed_hashes_with_threat_names_then_uses_a_conditional_request()
    {
        Publish(1);
        _server.Respond(FeedUrl, HttpStatusCode.OK, Feed(), etag: "\"v1\"");

        var first = await _updater.CheckNowAsync();

        Assert.Null(first.Hashes.Error);
        Assert.StartsWith("Added 2 new hashes", first.Hashes.Result);
        Assert.Equal("MalwareBazaar.Formbook", _env.Db.LookupHash(new string('a', 64)));

        _server.Respond(FeedUrl, HttpStatusCode.NotModified, Array.Empty<byte>());
        var second = await _updater.CheckNowAsync();

        Assert.Equal("\"v1\"", _server.LastIfNoneMatch);
        Assert.StartsWith("Up to date", second.Hashes.Result);
        Assert.NotNull(second.Hashes.UpdatedAt);
    }

    [Fact]
    public async Task A_feed_failure_is_reported_and_does_not_block_rule_updates()
    {
        Publish(1, ("published.yar", Rule("Published_Rule", "x")));
        _server.Respond(FeedUrl, HttpStatusCode.Unauthorized, Encoding.ASCII.GetBytes("{\"status\":401}"));

        var status = await _updater.CheckNowAsync();

        Assert.Contains("Auth-Key", status.Hashes.Error);
        Assert.Null(status.Rules.Error);
        Assert.True(File.Exists(Path.Combine(_env.Paths.Rules, "published.yar")));
    }

    [Fact]
    public async Task A_private_repository_gets_a_hint_about_the_token()
    {
        var status = await _updater.CheckNowAsync();

        Assert.Contains("HTTP 404", status.Rules.Error);
        Assert.Contains("RulesToken", status.Rules.Error);
    }

    [Fact]
    public void Manifest_with_a_path_in_a_file_name_is_rejected()
    {
        var manifest = new RulesManifest
        {
            Version = 1,
            Files = new[] { new RuleFileEntry(@"..\evil.yar", new string('0', 64), 1) },
        };
        var bytes = manifest.ToBytes();

        var ex = Assert.Throws<InvalidDataException>(() =>
            RulesManifest.ParseVerified(bytes, RulesManifest.Sign(bytes, _key), Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo())));
        Assert.Contains("invalid or duplicate file name", ex.Message);
    }

    private void Publish(long version, params (string Name, string Content)[] files)
    {
        var dir = Directory.CreateDirectory(Path.Combine(_env.Root, "publish", version.ToString())).FullName;
        foreach (var (name, content) in files)
        {
            File.WriteAllText(Path.Combine(dir, name), content);
            _server.Respond(RulesUrl + name, HttpStatusCode.OK, File.ReadAllBytes(Path.Combine(dir, name)));
        }
        var bytes = RulesManifest.FromDirectory(dir, version, DateTimeOffset.UtcNow).ToBytes();
        _server.Respond(RulesUrl + RulesManifest.FileName, HttpStatusCode.OK, bytes);
        _server.Respond(RulesUrl + RulesManifest.SignatureFileName, HttpStatusCode.OK, Encoding.ASCII.GetBytes(RulesManifest.Sign(bytes, _key)));
    }

    private string WriteLocalRule(string name, string content)
    {
        var path = Path.Combine(_env.Paths.Rules, name);
        File.WriteAllText(path, content);
        _env.Yara.Load(_env.Paths.Rules);
        return path;
    }

    private static string Rule(string name, string marker) =>
        $$"""rule {{name}} { strings: $m = "{{marker}}" condition: $m }""";

    private static byte[] Feed() => Encoding.UTF8.GetBytes($"""
        ################################################################
        # MalwareBazaar recent malware samples (CSV)                   #
        ################################################################
        # "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature"
        "2026-10-10 22:40:45", "{new string('a', 64)}", "x", "y", "anonymous", "s3.exe", "exe", "application/x-dosexec", "Formbook"
        "2026-10-10 22:30:26", "{new string('b', 64)}", "x", "y", "abuse_ch", "mips", "elf", "application/x-executable", "n/a"
        """);

    /// <summary>Serves canned responses by URL and records what was asked for.</summary>
    private sealed class FakeServer : HttpMessageHandler
    {
        private readonly Dictionary<string, (HttpStatusCode Code, byte[] Body, string? ETag)> _routes = new();

        public List<string> Requests { get; } = new();
        public string? LastIfNoneMatch { get; private set; }

        public void Respond(string url, HttpStatusCode code, byte[] body, string? etag = null) => _routes[url] = (code, body, etag);

        public byte[] Body(string url) => _routes[url].Body;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            Requests.Add(url);
            LastIfNoneMatch = request.Headers.IfNoneMatch.FirstOrDefault()?.ToString();
            var response = _routes.TryGetValue(url, out var route)
                ? new HttpResponseMessage(route.Code) { Content = new ByteArrayContent(route.Body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new ByteArrayContent(Array.Empty<byte>()) };
            if (route.ETag is not null)
            {
                response.Headers.ETag = System.Net.Http.Headers.EntityTagHeaderValue.Parse(route.ETag);
            }
            response.RequestMessage = request;
            return Task.FromResult(response);
        }
    }
}

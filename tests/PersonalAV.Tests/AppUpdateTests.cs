using System.Net;
using System.Security.Cryptography;
using System.Text;
using PersonalAV.Core.Updates;

namespace PersonalAV.Tests;

public sealed class AppUpdateTests : IDisposable
{
    private const string ManifestUrl = "https://rel.test/app/latest.json";

    private readonly TestEnvironment _env = new();
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly FakeServer _server = new();
    private readonly UpdateOptions _options;

    public AppUpdateTests()
    {
        _options = new UpdateOptions
        {
            ReleaseManifestUrl = ManifestUrl,
            RulesToken = "secret-token",
            PublisherPublicKey = PublicKey,
        };
    }

    private string PublicKey => Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo());

    public void Dispose()
    {
        _key.Dispose();
        _env.Dispose();
    }

    [Fact]
    public async Task Downloads_and_verifies_a_newer_version()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("new build")));

        var status = await CheckAsync(Installed("0.1.0"));

        Assert.Null(status.Error);
        Assert.Equal("0.2.0", status.AvailableVersion);
        Assert.True(status.InstallerReady);
        Assert.Equal("Short notes", status.Notes);
        Assert.Equal(Msi("new build"), File.ReadAllBytes(InstallerPath("0.2.0")));
        Assert.True(File.Exists(Path.Combine(_env.Paths.AppUpdates, ReleaseManifest.FileName)));
    }

    [Fact]
    public async Task Same_or_older_version_is_up_to_date_and_downloads_nothing()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));

        var status = await CheckAsync(Installed("0.2.0"));

        Assert.Null(status.AvailableVersion);
        Assert.StartsWith("Up to date", status.Result);
        Assert.DoesNotContain(_server.Requests, u => u.EndsWith(".msi", StringComparison.Ordinal));
    }

    [Fact]
    public async Task No_published_release_is_not_an_error()
    {
        var status = await CheckAsync(Installed("0.1.0"));

        Assert.Null(status.Error);
        Assert.Equal("No releases published yet", status.Result);
    }

    [Fact]
    public async Task Installer_not_uploaded_yet_is_pending_not_an_error()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));
        _server.Respond(AssetUrl("0.2.0", AppInstallInfo.Framework), HttpStatusCode.NotFound, Array.Empty<byte>());

        var status = await CheckAsync(Installed("0.1.0"));

        Assert.Null(status.Error);
        Assert.False(status.InstallerReady);
        Assert.Contains("not published yet", status.Result);
    }

    [Fact]
    public async Task Installer_that_does_not_match_the_signed_hash_is_discarded()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("signed")));
        // Same size as the signed file, so only the hash can catch it.
        _server.Respond(AssetUrl("0.2.0", AppInstallInfo.Framework), HttpStatusCode.OK, Msi("SIGNED"));

        var status = await CheckAsync(Installed("0.1.0"));

        Assert.Contains("does not match the signed manifest", status.Error);
        Assert.False(status.InstallerReady);
        Assert.Empty(Directory.GetFiles(_env.Paths.AppUpdates, "*.msi*"));
    }

    [Fact]
    public async Task Bad_signature_is_refused()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _server.Respond(ManifestUrl + ".sig", HttpStatusCode.OK, Encoding.ASCII.GetBytes(ManifestSigning.Sign(_server.Body(ManifestUrl), other)));

        var status = await CheckAsync(Installed("0.1.0"));

        Assert.Contains("signature", status.Error);
        Assert.False(Directory.Exists(_env.Paths.AppUpdates) && Directory.GetFiles(_env.Paths.AppUpdates, "*.msi").Length > 0);
    }

    [Fact]
    public async Task Older_manifest_after_a_newer_one_is_refused()
    {
        Publish("0.3.0", (AppInstallInfo.Framework, Msi("three")));
        await CheckAsync(Installed("0.1.0"));

        Publish("0.2.0", (AppInstallInfo.Framework, Msi("two")));
        var status = await CheckAsync(Installed("0.1.0"));

        Assert.Contains("refused release manifest 0.2.0", status.Error);
        Assert.Equal("0.3.0", status.AvailableVersion);
    }

    [Fact]
    public async Task Second_check_does_not_download_again_and_a_newer_release_replaces_the_old_installer()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("two")));
        var install = Installed("0.1.0");
        await CheckAsync(install);
        _server.Requests.Clear();

        await CheckAsync(install);
        Assert.DoesNotContain(_server.Requests, u => u.EndsWith(".msi", StringComparison.Ordinal));

        Publish("0.3.0", (AppInstallInfo.Framework, Msi("three")));
        var status = await CheckAsync(install);

        Assert.Equal("0.3.0", status.AvailableVersion);
        Assert.True(File.Exists(InstallerPath("0.3.0")));
        Assert.False(File.Exists(InstallerPath("0.2.0")));
    }

    [Fact]
    public async Task Copy_not_installed_by_the_msi_is_only_told()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));

        var status = await CheckAsync(new AppInstallInfo(new Version(0, 1, 0), null));

        Assert.Equal("0.2.0", status.AvailableVersion);
        Assert.False(status.InstallerReady);
        Assert.Contains("install it by hand", status.Result);
        Assert.DoesNotContain(_server.Requests, u => u.EndsWith(".msi", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Picks_the_installer_for_the_installed_variant()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("fd")), (AppInstallInfo.SelfContained, Msi("sc")));

        var status = await CheckAsync(new AppInstallInfo(new Version(0, 1, 0), AppInstallInfo.SelfContained));

        Assert.True(status.InstallerReady);
        var path = AppUpdateChecker.InstallerPath(_env.Paths, new Version(0, 2, 0), AppInstallInfo.SelfContained);
        Assert.EndsWith("-selfcontained.msi", path);
        Assert.Equal(Msi("sc"), File.ReadAllBytes(path));
    }

    [Fact]
    public async Task Missing_installer_for_the_variant_is_reported()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("fd")));

        var status = await CheckAsync(new AppInstallInfo(new Version(0, 1, 0), AppInstallInfo.SelfContained));

        Assert.Null(status.Error);
        Assert.Contains("has no selfcontained installer", status.Result);
    }

    [Fact]
    public async Task Never_sends_the_rules_token_with_release_downloads()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));

        await CheckAsync(Installed("0.1.0"));

        Assert.All(_server.Authorization.Values, Assert.Null);
    }

    [Fact]
    public async Task Offer_disappears_once_that_version_is_installed()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));
        await CheckAsync(Installed("0.1.0"));

        var afterUpgrade = Checker(Installed("0.2.0")).GetStatus();

        Assert.Equal("0.2.0", afterUpgrade.InstalledVersion);
        Assert.Null(afterUpgrade.AvailableVersion);
        Assert.False(afterUpgrade.InstallerReady);
    }

    [Fact]
    public async Task Prepare_accepts_the_verified_installer()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));
        var install = Installed("0.1.0");
        await CheckAsync(install);

        var prepared = AppUpdatePackage.Prepare(_env.Paths, install, PublicKey);

        Assert.Equal(new Version(0, 2, 0), prepared.Version);
        Assert.Equal(InstallerPath("0.2.0"), prepared.InstallerPath);
    }

    [Fact]
    public async Task Prepare_refuses_a_tampered_installer_or_manifest_or_a_version_that_is_not_newer()
    {
        Publish("0.2.0", (AppInstallInfo.Framework, Msi("x")));
        var install = Installed("0.1.0");
        await CheckAsync(install);

        Assert.Throws<UpdateException>(() => AppUpdatePackage.Prepare(_env.Paths, Installed("0.2.0"), PublicKey));
        Assert.Throws<UpdateException>(() => AppUpdatePackage.Prepare(_env.Paths, new AppInstallInfo(new Version(0, 1, 0), null), PublicKey));

        File.AppendAllText(InstallerPath("0.2.0"), "!");
        var ex = Assert.Throws<UpdateException>(() => AppUpdatePackage.Prepare(_env.Paths, install, PublicKey));
        Assert.Contains("does not match", ex.Message);

        var manifest = Path.Combine(_env.Paths.AppUpdates, ReleaseManifest.FileName);
        File.WriteAllText(manifest, File.ReadAllText(manifest).Replace("0.2.0", "0.9.0"));
        ex = Assert.Throws<UpdateException>(() => AppUpdatePackage.Prepare(_env.Paths, install, PublicKey));
        Assert.Contains("failed verification", ex.Message);
    }

    private AppInstallInfo Installed(string version)
    {
        Assert.True(AppVersion.TryParse(version, out var v));
        return new AppInstallInfo(v, AppInstallInfo.Framework);
    }

    private AppUpdateChecker Checker(AppInstallInfo install) =>
        new(_env.Db, _env.Paths, new HttpClient(_server), _options, install, restrictAcl: false);

    private async Task<Core.AppUpdateStatus> CheckAsync(AppInstallInfo install)
    {
        var checker = Checker(install);
        await checker.CheckAsync(CancellationToken.None);
        return checker.GetStatus();
    }

    private string InstallerPath(string version)
    {
        Assert.True(AppVersion.TryParse(version, out var v));
        return AppUpdateChecker.InstallerPath(_env.Paths, v, AppInstallInfo.Framework);
    }

    private static string AssetUrl(string version, string variant) => $"https://github.test/v{version}/{variant}.msi";

    private static byte[] Msi(string content) => Encoding.ASCII.GetBytes("MSI:" + content);

    private void Publish(string version, params (string Variant, byte[] Body)[] assets)
    {
        foreach (var (variant, body) in assets)
        {
            _server.Respond(AssetUrl(version, variant), HttpStatusCode.OK, body);
        }
        var manifest = new ReleaseManifest
        {
            Type = ReleaseManifest.TypeValue,
            Version = version,
            Published = DateTimeOffset.UtcNow,
            Notes = "Short notes",
            ReleaseUrl = "https://github.test/release",
            Assets = assets.Select(a => new ReleaseAsset(a.Variant, AssetUrl(version, a.Variant),
                Convert.ToHexString(SHA256.HashData(a.Body)).ToLowerInvariant(), a.Body.Length)).ToList(),
        };
        var bytes = manifest.ToBytes();
        _server.Respond(ManifestUrl, HttpStatusCode.OK, bytes);
        _server.Respond(ManifestUrl + ".sig", HttpStatusCode.OK, Encoding.ASCII.GetBytes(ManifestSigning.Sign(bytes, _key)));
    }
}

public sealed class ReleaseManifestTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose() => _key.Dispose();

    private string PublicKey => Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo());

    [Theory]
    [InlineData("0.2")]
    [InlineData("0.2.0-beta")]
    [InlineData("256.0.0")]
    [InlineData("v0.2.0")]
    public void Rejects_invalid_versions(string version) =>
        AssertRejected(Manifest() with { Version = version }, "invalid version");

    [Fact]
    public void Rejects_http_urls_unknown_or_duplicate_variants_and_oversized_assets()
    {
        AssertRejected(Manifest() with { Assets = new[] { Asset() with { Url = "http://github.test/a.msi" } } }, "invalid");
        AssertRejected(Manifest() with { Assets = new[] { Asset() with { Variant = "portable" } } }, "unknown or duplicate");
        AssertRejected(Manifest() with { Assets = new[] { Asset(), Asset() } }, "unknown or duplicate");
        AssertRejected(Manifest() with { Assets = new[] { Asset() with { Size = ReleaseManifest.MaxInstallerBytes + 1 } } }, "invalid");
        AssertRejected(Manifest() with { Type = "something-else" }, "wrong type");
    }

    [Fact]
    public void A_rules_manifest_signed_with_the_same_key_is_not_a_release()
    {
        var rules = new RulesManifest { Version = 5, Files = Array.Empty<RuleFileEntry>() }.ToBytes();

        Assert.Throws<InvalidDataException>(() => ReleaseManifest.ParseVerified(rules, ManifestSigning.Sign(rules, _key), PublicKey));
    }

    [Fact]
    public void Accepts_a_valid_manifest()
    {
        var bytes = Manifest().ToBytes();

        var parsed = ReleaseManifest.ParseVerified(bytes, ManifestSigning.Sign(bytes, _key), PublicKey);

        Assert.Equal(new Version(0, 2, 0), parsed.GetVersion());
        Assert.Equal(Asset(), parsed.AssetFor(AppInstallInfo.Framework));
    }

    [Fact]
    public void Versions_compare_as_three_parts()
    {
        Assert.True(AppVersion.TryParse("0.10.0", out var ten));
        Assert.True(AppVersion.TryParse("0.9.0", out var nine));
        Assert.True(ten > nine);
        Assert.Equal(new Version(0, 2, 0), AppVersion.Normalize(new Version(0, 2, 0, 0)));
        // The running version is three parts and round-trips, whatever Directory.Build.props says.
        Assert.Equal(-1, AppVersion.Current.Revision);
        Assert.True(AppVersion.TryParse(AppVersion.Format(AppVersion.Current), out var current));
        Assert.Equal(AppVersion.Current, current);
    }

    [Fact]
    public void Repo_release_manifest_if_present_is_signed_with_the_shipped_key()
    {
        var app = Path.Combine(DetectionTests.FindRepoRoot(), "app");
        var path = Path.Combine(app, ReleaseManifest.FileName);
        if (!File.Exists(path))
        {
            return; // Nothing published yet.
        }
        var bytes = File.ReadAllBytes(path);

        ReleaseManifest.ParseVerified(bytes, File.ReadAllText(Path.Combine(app, ReleaseManifest.SignatureFileName)), UpdateKeys.PublisherPublicKey);
        Assert.DoesNotContain((byte)'\r', bytes);
    }

    private void AssertRejected(ReleaseManifest manifest, string message)
    {
        var bytes = manifest.ToBytes();
        var ex = Assert.Throws<InvalidDataException>(() => ReleaseManifest.ParseVerified(bytes, ManifestSigning.Sign(bytes, _key), PublicKey));
        Assert.Contains(message, ex.Message);
    }

    private static ReleaseManifest Manifest() => new()
    {
        Type = ReleaseManifest.TypeValue,
        Version = "0.2.0",
        Assets = new[] { Asset() },
    };

    private static ReleaseAsset Asset() => new(AppInstallInfo.Framework, "https://github.test/a.msi", new string('a', 64), 100);
}

using System.Security.Cryptography;
using PersonalAV.Core.Scanning;
using PersonalAV.Core.Updates;

// Maintainer tool: signs the manifests installed copies check before using an update
// (rules/manifest.json for rule files, app/latest.json for app installers).

const string Usage = """
    PersonalAV signer

    Usage:
      pav-rulesigner keygen <private-key.pem>          Create a new signing key (keep it out of the repository)
      pav-rulesigner sign <private-key.pem> [rules]    Rebuild and sign rules\manifest.json after changing rules
      pav-rulesigner release <private-key.pem> [--notes "text"] [--version X.Y.Z] [--dir folder] [--repo owner/name]
                                                       Sign app\latest.json for the installers built in --dir
                                                       (default artifacts\installer, version from Directory.Build.props)
      pav-rulesigner verify [--online] [rules]         Check the signed manifests; --online also downloads the
                                                       published installers and checks them

    [rules] defaults to the rules folder of the repository containing the current directory.
    """;

const string DefaultRepo = "ImVoxxX/anti-virus";

try
{
    var options = args.Skip(1).Where(a => a.StartsWith("--", StringComparison.Ordinal)).ToList();
    var positional = args.Skip(1).Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToList();
    return args.FirstOrDefault()?.ToLowerInvariant() switch
    {
        "keygen" when args.Length == 2 => KeyGen(args[1]),
        "sign" when args.Length is 2 or 3 => Sign(args[1], RulesDir(args.ElementAtOrDefault(2))),
        "release" when args.Length >= 2 => Release(args[1], Option(args, "--notes"), Option(args, "--version"),
            Option(args, "--dir"), Option(args, "--repo") ?? DefaultRepo),
        "verify" when positional.Count <= 1 && options.All(o => o == "--online") =>
            await Verify(RulesDir(positional.FirstOrDefault()), options.Contains("--online")),
        _ => Fail(Usage),
    };
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException
                               or ArgumentException or HttpRequestException)
{
    return Fail(ex.Message);
}

static int KeyGen(string privateKeyPath)
{
    if (File.Exists(privateKeyPath))
    {
        return Fail($"{privateKeyPath} already exists; refusing to overwrite a signing key.");
    }
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(privateKeyPath))!);
    File.WriteAllText(privateKeyPath, key.ExportPkcs8PrivateKeyPem());
    Console.WriteLine($"Private key written to {Path.GetFullPath(privateKeyPath)}. Back it up and never commit it.");
    Console.WriteLine("Put this public key in src\\PersonalAV.Core\\Updates\\UpdateKeys.cs (PublisherPublicKey):");
    Console.WriteLine(Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    return 0;
}

static int Sign(string privateKeyPath, string rulesDir)
{
    using var key = LoadKey(privateKeyPath);

    // Never publish rules that do not compile: the services would refuse them anyway.
    using (var yara = new YaraRuleSet())
    {
        var report = yara.Load(rulesDir);
        if (report.Error is not null || report.FailedFiles.Count > 0)
        {
            foreach (var (file, error) in report.FailedFiles)
            {
                Console.Error.WriteLine($"  {file}: {error}");
            }
            return Fail("Rules do not compile: " + (report.Error ?? "see the errors above"));
        }
        Console.WriteLine($"{report.RuleCount} rules from {report.FilesLoaded} files compile.");
    }

    var manifestPath = Path.Combine(rulesDir, RulesManifest.FileName);
    var signaturePath = Path.Combine(rulesDir, RulesManifest.SignatureFileName);
    RulesManifest? previous = null;
    if (File.Exists(manifestPath) && File.Exists(signaturePath))
    {
        previous = RulesManifest.ParseVerified(File.ReadAllBytes(manifestPath), File.ReadAllText(signaturePath), UpdateKeys.PublisherPublicKey);
    }

    var files = RulesManifest.FromDirectory(rulesDir, 0, DateTimeOffset.UtcNow).Files;
    if (previous is not null && previous.Files.SequenceEqual(files))
    {
        Console.WriteLine($"No rule changes; manifest stays at version {previous.Version}.");
        return 0;
    }

    var manifest = new RulesManifest
    {
        Version = (previous?.Version ?? 0) + 1,
        Published = DateTimeOffset.UtcNow,
        Files = files,
    };
    var bytes = manifest.ToBytes();
    File.WriteAllBytes(manifestPath, bytes);
    File.WriteAllText(signaturePath, RulesManifest.Sign(bytes, key) + "\n");
    Console.WriteLine($"Signed version {manifest.Version} with {files.Count} files.");
    return 0;
}

static int Release(string privateKeyPath, string? notes, string? versionText, string? dir, string repo)
{
    using var key = LoadKey(privateKeyPath);
    var root = RepoRoot();
    var version = AppVersion.Current;
    if (versionText is not null && !AppVersion.TryParse(versionText, out version))
    {
        return Fail($"'{versionText}' is not a version like 1.2.3.");
    }
    var v = AppVersion.Format(version);

    var appDir = Path.Combine(root, "app");
    var manifestPath = Path.Combine(appDir, ReleaseManifest.FileName);
    var signaturePath = Path.Combine(appDir, ReleaseManifest.SignatureFileName);
    if (File.Exists(manifestPath))
    {
        var current = ReleaseManifest.ParseVerified(File.ReadAllBytes(manifestPath), File.ReadAllText(signaturePath), UpdateKeys.PublisherPublicKey);
        if (current.GetVersion() >= version)
        {
            return Fail($"app\\latest.json already announces {current.Version}. Bump <Version> in Directory.Build.props, rebuild the installers, and try again.");
        }
    }

    var installerDir = Path.GetFullPath(dir ?? Path.Combine(root, "artifacts", "installer"));
    var assets = new List<ReleaseAsset>();
    var uploads = new List<string>();
    foreach (var variant in new[] { AppInstallInfo.Framework, AppInstallInfo.SelfContained })
    {
        var name = ReleaseManifest.LocalFileName(version, variant);
        var path = Path.Combine(installerDir, name);
        if (!File.Exists(path))
        {
            continue;
        }
        assets.Add(new ReleaseAsset(variant, $"https://github.com/{repo}/releases/download/v{v}/{name}",
            ManifestSigning.Sha256OfFile(path), new FileInfo(path).Length));
        uploads.Add(path);
        Console.WriteLine($"  {variant,-14} {name}  {new FileInfo(path).Length:N0} bytes");
    }
    if (assets.Count == 0)
    {
        return Fail($"No installers for {v} in {installerDir}. Build them with: dotnet build installer -c Release [-p:SelfContained=true]");
    }
    if (notes?.Length > ReleaseManifest.MaxNotesLength)
    {
        return Fail($"--notes is longer than {ReleaseManifest.MaxNotesLength} characters.");
    }

    var manifest = new ReleaseManifest
    {
        Type = ReleaseManifest.TypeValue,
        Version = v,
        Published = DateTimeOffset.UtcNow,
        Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim(),
        ReleaseUrl = $"https://github.com/{repo}/releases/tag/v{v}",
        Assets = assets,
    };
    var bytes = manifest.ToBytes();
    var signature = ManifestSigning.Sign(bytes, key);
    // Make sure what we write is exactly what installed copies will accept.
    ReleaseManifest.ParseVerified(bytes, signature, UpdateKeys.PublisherPublicKey);
    Directory.CreateDirectory(appDir);
    File.WriteAllBytes(manifestPath, bytes);
    File.WriteAllText(signaturePath, signature + "\n");

    Console.WriteLine($"Signed app\\latest.json for PersonalAV {v}. Upload these files with exactly these names:");
    uploads.ForEach(u => Console.WriteLine("  " + u));
    Console.WriteLine("Then continue with your publishing notes.");
    return 0;
}

static async Task<int> Verify(string rulesDir, bool online)
{
    var rules = RulesManifest.ParseVerified(
        File.ReadAllBytes(Path.Combine(rulesDir, RulesManifest.FileName)),
        File.ReadAllText(Path.Combine(rulesDir, RulesManifest.SignatureFileName)),
        UpdateKeys.PublisherPublicKey);
    var current = RulesManifest.FromDirectory(rulesDir, 0, DateTimeOffset.UtcNow).Files;
    if (!rules.Files.SequenceEqual(current))
    {
        return Fail($"Rules manifest version {rules.Version} is signed, but the rule files have changed since. Run sign again.");
    }
    Console.WriteLine($"Rules manifest version {rules.Version} is signed and matches all {current.Count} rule files.");

    var appDir = Path.Combine(Path.GetDirectoryName(rulesDir)!, "app");
    var releasePath = Path.Combine(appDir, ReleaseManifest.FileName);
    if (!File.Exists(releasePath))
    {
        Console.WriteLine("No app release published yet (app\\latest.json).");
        return 0;
    }
    var release = ReleaseManifest.ParseVerified(File.ReadAllBytes(releasePath),
        File.ReadAllText(Path.Combine(appDir, ReleaseManifest.SignatureFileName)), UpdateKeys.PublisherPublicKey);
    Console.WriteLine($"Release manifest for PersonalAV {release.Version} is signed ({release.Assets.Count} installers).");
    if (!online)
    {
        return 0;
    }

    using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
    int failures = 0;
    foreach (var asset in release.Assets)
    {
        using var response = await http.GetAsync(asset.Url, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            Console.Error.WriteLine($"  {asset.Variant}: HTTP {(int)response.StatusCode} for {asset.Url}");
            failures++;
            continue;
        }
        var data = await response.Content.ReadAsByteArrayAsync();
        var hash = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        bool ok = data.LongLength == asset.Size && hash == asset.Sha256;
        Console.WriteLine($"  {asset.Variant}: {(ok ? "matches" : "DOES NOT MATCH")} ({data.LongLength:N0} bytes)");
        failures += ok ? 0 : 1;
    }
    return failures == 0 ? 0 : Fail("Some installers are missing or differ from the signed manifest; do not push app\\ yet.");
}

static ECDsa LoadKey(string privateKeyPath)
{
    var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(privateKeyPath));
    if (Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) != UpdateKeys.PublisherPublicKey)
    {
        key.Dispose();
        throw new ArgumentException("This key does not match UpdateKeys.PublisherPublicKey, so installed copies would reject what it signs.");
    }
    return key;
}

static string? Option(string[] args, string name)
{
    var i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static string RulesDir(string? path) => path is not null ? Path.GetFullPath(path) : Path.Combine(RepoRoot(), "rules");

static string RepoRoot()
{
    for (var dir = new DirectoryInfo(Environment.CurrentDirectory); dir is not null; dir = dir.Parent)
    {
        if (File.Exists(Path.Combine(dir.FullName, "PersonalAV.sln")))
        {
            return dir.FullName;
        }
    }
    throw new ArgumentException("Run this inside the repository, or pass the rules folder.");
}

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}

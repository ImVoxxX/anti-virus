using System.Security.Cryptography;
using PersonalAV.Core.Scanning;
using PersonalAV.Core.Updates;

// Maintainer tool: signs the manifests installed copies check before using an update
// (rules/manifest.json for rule files, app/latest.json for app installers).

const string Usage = """
    PersonalAV rule signer

    Usage:
      pav-rulesigner keygen <private-key.pem>          Create a new signing key (keep it out of the repository)
      pav-rulesigner sign <private-key.pem> [rules]    Rebuild and sign rules\manifest.json after changing rules
      pav-rulesigner verify [rules]                    Check the manifest, its signature and the files

    [rules] defaults to the rules folder of the repository containing the current directory.
    """;

try
{
    return args.FirstOrDefault()?.ToLowerInvariant() switch
    {
        "keygen" when args.Length == 2 => KeyGen(args[1]),
        "sign" when args.Length is 2 or 3 => Sign(args[1], RulesDir(args.ElementAtOrDefault(2))),
        "verify" when args.Length is 1 or 2 => Verify(RulesDir(args.ElementAtOrDefault(1))),
        _ => Fail(Usage),
    };
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException or ArgumentException)
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
    Console.WriteLine("Put this public key in src\\PersonalAV.Core\\Updates\\UpdateKeys.cs (RulesPublicKey):");
    Console.WriteLine(Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    return 0;
}

static int Sign(string privateKeyPath, string rulesDir)
{
    using var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(privateKeyPath));
    var publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    if (publicKey != UpdateKeys.RulesPublicKey)
    {
        return Fail("This key does not match UpdateKeys.RulesPublicKey, so installed copies would reject the manifest.");
    }

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
        previous = RulesManifest.ParseVerified(File.ReadAllBytes(manifestPath), File.ReadAllText(signaturePath), publicKey);
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

static int Verify(string rulesDir)
{
    var manifest = RulesManifest.ParseVerified(
        File.ReadAllBytes(Path.Combine(rulesDir, RulesManifest.FileName)),
        File.ReadAllText(Path.Combine(rulesDir, RulesManifest.SignatureFileName)),
        UpdateKeys.RulesPublicKey);
    var current = RulesManifest.FromDirectory(rulesDir, 0, DateTimeOffset.UtcNow).Files;
    if (!manifest.Files.SequenceEqual(current))
    {
        return Fail($"Manifest version {manifest.Version} is signed, but the rule files have changed since. Run sign again.");
    }
    Console.WriteLine($"Manifest version {manifest.Version} is signed and matches all {current.Count} rule files.");
    return 0;
}

static string RulesDir(string? path)
{
    if (path is not null)
    {
        return Path.GetFullPath(path);
    }
    for (var dir = new DirectoryInfo(Environment.CurrentDirectory); dir is not null; dir = dir.Parent)
    {
        if (File.Exists(Path.Combine(dir.FullName, "PersonalAV.sln")))
        {
            return Path.Combine(dir.FullName, "rules");
        }
    }
    throw new ArgumentException("Run this inside the repository, or pass the rules folder.");
}

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}

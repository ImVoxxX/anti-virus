using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace PersonalAV.Core.Updates;

/// <summary>
/// The list of published rule files, kept as <c>rules/manifest.json</c> in the repository and signed by
/// <c>rules/manifest.json.sig</c> (see <see cref="ManifestSigning"/>). The service only acts on a manifest whose
/// signature checks out, so whoever hosts the files cannot change what gets installed.
/// </summary>
public sealed partial record RulesManifest
{
    public const string FileName = "manifest.json";
    public const string SignatureFileName = "manifest.json.sig";

    /// <summary>Largest rule file the updater accepts.</summary>
    public const long MaxRuleFileBytes = 10 * 1024 * 1024;

    /// <summary>Increases with every publish. A manifest older than the installed one is refused (replay protection).</summary>
    public required long Version { get; init; }

    public DateTimeOffset Published { get; init; }

    public required IReadOnlyList<RuleFileEntry> Files { get; init; }

    // A bare file name: no folders, so a manifest can never write outside the rules folder.
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,99}\.(yar|yara)$", RegexOptions.IgnoreCase)]
    private static partial Regex SafeNameRegex();

    [GeneratedRegex("^[0-9a-f]{64}$")]
    internal static partial Regex Sha256Regex();

    /// <summary>Builds a manifest from the .yar/.yara files in <paramref name="rulesDirectory"/>.</summary>
    public static RulesManifest FromDirectory(string rulesDirectory, long version, DateTimeOffset published)
    {
        var files = Directory.EnumerateFiles(rulesDirectory)
            .Where(f => SafeNameRegex().IsMatch(Path.GetFileName(f)))
            .Order(StringComparer.OrdinalIgnoreCase)
            .Select(f => new RuleFileEntry(Path.GetFileName(f), Sha256OfFile(f), new FileInfo(f).Length))
            .ToList();
        return new RulesManifest { Version = version, Published = published, Files = files };
    }

    public byte[] ToBytes() => ManifestSigning.ToCanonicalBytes(this);

    /// <summary>Checks the signature first, then parses and validates. Throws <see cref="InvalidDataException"/> on any problem.</summary>
    public static RulesManifest ParseVerified(byte[] manifestBytes, string signatureBase64, string publicKeyBase64)
    {
        var manifest = ManifestSigning.ParseSigned<RulesManifest>(manifestBytes, signatureBase64, publicKeyBase64, "rules manifest");
        if (manifest.Version < 1)
        {
            throw new InvalidDataException("the rules manifest has no version");
        }
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in manifest.Files)
        {
            if (!SafeNameRegex().IsMatch(file.Name) || !names.Add(file.Name))
            {
                throw new InvalidDataException($"the rules manifest lists an invalid or duplicate file name '{file.Name}'");
            }
            if (!Sha256Regex().IsMatch(file.Sha256) || file.Size is < 0 or > MaxRuleFileBytes)
            {
                throw new InvalidDataException($"the rules manifest entry for '{file.Name}' is invalid");
            }
        }
        return manifest;
    }

    public static string Sign(byte[] manifestBytes, ECDsa privateKey) => ManifestSigning.Sign(manifestBytes, privateKey);

    public static bool VerifySignature(byte[] manifestBytes, string signatureBase64, string publicKeyBase64) =>
        ManifestSigning.Verify(manifestBytes, signatureBase64, publicKeyBase64);

    public static string Sha256OfFile(string path) => ManifestSigning.Sha256OfFile(path);
}

public sealed record RuleFileEntry(string Name, string Sha256, long Size);

namespace PersonalAV.Core.Updates;

/// <summary>
/// The latest published PersonalAV version, kept as <c>app/latest.json</c> in the repository and signed like the
/// rules manifest (see <see cref="ManifestSigning"/>). It pins the SHA-256 and size of each installer, so a
/// downloaded .msi is only ever run when it is byte for byte the one the publisher signed.
/// </summary>
public sealed record ReleaseManifest
{
    public const string FileName = "latest.json";
    public const string SignatureFileName = "latest.json.sig";

    /// <summary>Required marker, so a rules manifest signed with the same key can never pass as a release.</summary>
    public const string TypeValue = "personalav-release";

    public const long MaxInstallerBytes = 300L * 1024 * 1024;
    public const int MaxNotesLength = 2000;

    public required string Type { get; init; }

    /// <summary>Three-part version, see <see cref="AppVersion"/>.</summary>
    public required string Version { get; init; }

    public DateTimeOffset Published { get; init; }

    /// <summary>Short plain-text summary shown on the dashboard.</summary>
    public string? Notes { get; init; }

    /// <summary>Release page, opened by "What's new".</summary>
    public string? ReleaseUrl { get; init; }

    public required IReadOnlyList<ReleaseAsset> Assets { get; init; }

    public Version GetVersion() =>
        AppVersion.TryParse(Version, out var version) ? version : throw new InvalidDataException($"invalid version '{Version}'");

    public ReleaseAsset? AssetFor(string variant) => Assets.FirstOrDefault(a => a.Variant == variant);

    public byte[] ToBytes() => ManifestSigning.ToCanonicalBytes(this);

    /// <summary>The installer's file name, as the installer project names it. Never taken from the download URL.</summary>
    public static string LocalFileName(Version version, string variant) =>
        $"PersonalAV-{AppVersion.Format(version)}-x64{(variant == AppInstallInfo.SelfContained ? "-selfcontained" : "")}.msi";

    /// <summary>Checks the signature first, then parses and validates. Throws <see cref="InvalidDataException"/> on any problem.</summary>
    public static ReleaseManifest ParseVerified(byte[] manifestBytes, string signatureBase64, string publicKeyBase64)
    {
        var manifest = ManifestSigning.ParseSigned<ReleaseManifest>(manifestBytes, signatureBase64, publicKeyBase64, "release manifest");
        if (manifest.Type != TypeValue)
        {
            throw new InvalidDataException("the release manifest has the wrong type");
        }
        if (!AppVersion.TryParse(manifest.Version, out _))
        {
            throw new InvalidDataException($"the release manifest has an invalid version '{manifest.Version}'");
        }
        if (manifest.Notes?.Length > MaxNotesLength)
        {
            throw new InvalidDataException("the release notes are too long");
        }
        if (manifest.ReleaseUrl is not null && !IsHttps(manifest.ReleaseUrl))
        {
            throw new InvalidDataException("the release page URL must be https");
        }
        var variants = new HashSet<string>();
        foreach (var asset in manifest.Assets)
        {
            if (asset.Variant is not (AppInstallInfo.Framework or AppInstallInfo.SelfContained) || !variants.Add(asset.Variant))
            {
                throw new InvalidDataException($"the release manifest lists an unknown or duplicate variant '{asset.Variant}'");
            }
            if (!IsHttps(asset.Url) || !RulesManifest.Sha256Regex().IsMatch(asset.Sha256) || asset.Size is <= 0 or > MaxInstallerBytes)
            {
                throw new InvalidDataException($"the release manifest entry for '{asset.Variant}' is invalid");
            }
        }
        return manifest;
    }

    private static bool IsHttps(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
}

public sealed record ReleaseAsset(string Variant, string Url, string Sha256, long Size);

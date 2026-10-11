using System.Text.RegularExpressions;

namespace PersonalAV.Core.Updates;

/// <summary>
/// PersonalAV versions are always three parts (major.minor.build), the form MSI compares. Comparing a 3-part and a
/// 4-part <see cref="Version"/> directly is wrong (0.2.0 &lt; 0.2.0.0), so every version goes through here.
/// </summary>
public static partial class AppVersion
{
    /// <summary>The running build's version, from Directory.Build.props.</summary>
    public static Version Current { get; } = Normalize(typeof(AppVersion).Assembly.GetName().Version ?? new Version(0, 0, 0));

    public static Version Normalize(Version version) => new(version.Major, version.Minor, Math.Max(version.Build, 0));

    /// <summary>Parses "1.2.3" within MSI's limits (255.255.65535). No prefixes, suffixes or fourth part.</summary>
    public static bool TryParse(string? text, out Version version)
    {
        version = new Version(0, 0, 0);
        var match = text is null ? null : VersionRegex().Match(text);
        if (match is not { Success: true }
            || !int.TryParse(match.Groups[1].Value, out var major) || major > 255
            || !int.TryParse(match.Groups[2].Value, out var minor) || minor > 255
            || !int.TryParse(match.Groups[3].Value, out var build) || build > 65535)
        {
            return false;
        }
        version = new Version(major, minor, build);
        return true;
    }

    public static string Format(Version version) => Normalize(version).ToString(3);

    [GeneratedRegex(@"^(\d{1,3})\.(\d{1,3})\.(\d{1,5})$")]
    private static partial Regex VersionRegex();
}

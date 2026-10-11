using Microsoft.Win32;

namespace PersonalAV.Core.Updates;

/// <summary>
/// What is installed: the running version, and which installer variant put it there. The .msi records its variant
/// under HKLM\SOFTWARE\PersonalAV; a copy installed by scripts\install.ps1 or run from a build has none, so it is
/// only told about new versions (the .msi refuses to install over a script install).
/// </summary>
public sealed record AppInstallInfo(Version Version, string? Variant)
{
    public const string Framework = "framework";
    public const string SelfContained = "selfcontained";
    public const string RegistryPath = @"SOFTWARE\PersonalAV";

    /// <summary>True when the .msi installed this copy, so its update installer can upgrade it.</summary>
    public bool InstalledByMsi => Variant is not null;

    public static AppInstallInfo Detect()
    {
        string? variant = null;
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(RegistryPath);
            variant = key?.GetValue("Variant") as string;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
        }
        return new AppInstallInfo(AppVersion.Current, variant is Framework or SelfContained ? variant : null);
    }
}

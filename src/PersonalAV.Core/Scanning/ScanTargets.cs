using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace PersonalAV.Core.Scanning;

/// <summary>
/// Works out what Quick and Full scans cover. The service runs as SYSTEM, so per-user folders are found
/// from the profile list and each signed-in user's shell-folder settings, not from the service's own profile.
/// </summary>
public static class ScanTargets
{
    private const string DownloadsFolderGuid = "{374DE290-123F-4565-9164-39C4925E467B}";

    /// <summary>Files (running process images) and folders covered by a Quick scan.</summary>
    public static (IReadOnlyList<string> Files, IReadOnlyList<string> Folders) Quick()
    {
        var folders = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };
        foreach (var profile in UserProfiles())
        {
            var shell = UserShellFolders(profile.Sid, profile.Path);
            folders.Add(shell.Desktop);
            folders.Add(shell.Downloads);
            folders.Add(Path.Combine(profile.Path, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
            // Roaming and Local cover %Temp% (AppData\Local\Temp) as well.
            folders.Add(Path.Combine(profile.Path, "AppData", "Roaming"));
            folders.Add(Path.Combine(profile.Path, "AppData", "Local"));
        }
        return (RunningProcessImages(), Collapse(folders));
    }

    /// <summary>Roots of every fixed drive.</summary>
    public static IReadOnlyList<string> Full() =>
        DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName)
            .ToList();

    /// <summary>Removes missing folders, duplicates and folders already inside another listed folder.</summary>
    internal static IReadOnlyList<string> Collapse(IEnumerable<string> folders)
    {
        var existing = folders
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .Select(f => Path.TrimEndingDirectorySeparator(Path.GetFullPath(f)))
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(f => f.Length)
            .ToList();
        var result = new List<string>();
        foreach (var folder in existing)
        {
            bool covered = result.Any(parent =>
                folder.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
            if (!covered)
            {
                result.Add(folder);
            }
        }
        return result;
    }

    private static IEnumerable<(string Sid, string Path)> UserProfiles()
    {
        using var list = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (list is null)
        {
            yield break;
        }
        foreach (var sid in list.GetSubKeyNames())
        {
            // Real user accounts only (local and domain/Microsoft accounts), not SYSTEM or service profiles.
            if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !sid.StartsWith("S-1-12-1-", StringComparison.Ordinal))
            {
                continue;
            }
            using var key = list.OpenSubKey(sid);
            if (key?.GetValue("ProfileImagePath") is string path)
            {
                path = Environment.ExpandEnvironmentVariables(path);
                if (Directory.Exists(path))
                {
                    yield return (sid, path);
                }
            }
        }
    }

    private static (string Desktop, string Downloads) UserShellFolders(string sid, string profilePath)
    {
        string desktop = Path.Combine(profilePath, "Desktop");
        string downloads = Path.Combine(profilePath, "Downloads");
        try
        {
            // Only loaded while the user is signed in; otherwise the profile defaults are used.
            using var key = Registry.Users.OpenSubKey(
                $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
            desktop = Resolve(key?.GetValue("Desktop", null, RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? desktop;
            downloads = Resolve(key?.GetValue(DownloadsFolderGuid, null, RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? downloads;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }
        return (desktop, downloads);

        string? Resolve(object? value) =>
            value is string s && s.Length > 0
                ? Environment.ExpandEnvironmentVariables(s.Replace("%USERPROFILE%", profilePath, StringComparison.OrdinalIgnoreCase))
                : null;
    }

    private static IReadOnlyList<string> RunningProcessImages()
    {
        var images = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                var path = TryGetImagePath(process.Id);
                if (path is not null && File.Exists(path))
                {
                    images.Add(path);
                }
            }
        }
        return images.ToList();
    }

    private static string? TryGetImagePath(int pid)
    {
        const uint ProcessQueryLimitedInformation = 0x1000;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            var buffer = new StringBuilder(1024);
            int size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}

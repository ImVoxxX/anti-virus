namespace PersonalAV.Core.Scanning;

/// <summary>
/// Walks a folder tree defensively: never follows symlinks or junctions (no loops, no escaping the target),
/// never hydrates cloud placeholders such as OneDrive files-on-demand, and treats access-denied or vanished
/// entries as skips instead of failures.
/// </summary>
public static class FileEnumerator
{
    // Not all of these are named members of FileAttributes, but they are stable Win32 values.
    private const FileAttributes RecallOnOpen = (FileAttributes)0x0004_0000;
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x0040_0000;
    private const FileAttributes NotLocal = FileAttributes.Offline | RecallOnOpen | RecallOnDataAccess;

    private static readonly EnumerationOptions Options = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = true,
        ReturnSpecialDirectories = false,
        AttributesToSkip = 0,
    };

    /// <param name="root">A folder to walk, or a single file.</param>
    /// <param name="excludedRoots">Folders never entered (for example the quarantine folder).</param>
    /// <param name="onSkip">Called with a path and reason for each entry that is skipped.</param>
    public static IEnumerable<FileInfo> Enumerate(
        string root,
        IReadOnlyCollection<string>? excludedRoots = null,
        Action<string, string>? onSkip = null,
        CancellationToken cancellationToken = default)
    {
        onSkip ??= static (_, _) => { };
        var excluded = (excludedRoots ?? Array.Empty<string>())
            .Select(p => Path.TrimEndingDirectorySeparator(Path.GetFullPath(p)))
            .ToArray();

        if (File.Exists(root))
        {
            yield return new FileInfo(root);
            yield break;
        }
        if (!Directory.Exists(root))
        {
            onSkip(root, "not found");
            yield break;
        }

        var pending = new Stack<DirectoryInfo>();
        pending.Push(new DirectoryInfo(root));
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dir = pending.Pop();
            if (IsExcluded(dir.FullName, excluded))
            {
                continue;
            }

            IEnumerator<FileSystemInfo> entries;
            try
            {
                entries = dir.EnumerateFileSystemInfos("*", Options).GetEnumerator();
            }
            catch (Exception ex) when (IsSkippable(ex))
            {
                onSkip(dir.FullName, ex.GetType().Name);
                continue;
            }

            using (entries)
            {
                while (true)
                {
                    FileSystemInfo entry;
                    try
                    {
                        if (!entries.MoveNext())
                        {
                            break;
                        }
                        entry = entries.Current;
                    }
                    catch (Exception ex) when (IsSkippable(ex))
                    {
                        onSkip(dir.FullName, ex.GetType().Name);
                        break;
                    }

                    var reason = SkipReason(entry);
                    if (reason is not null)
                    {
                        onSkip(entry.FullName, reason);
                    }
                    else if (entry is DirectoryInfo sub)
                    {
                        pending.Push(sub);
                    }
                    else if (entry is FileInfo file)
                    {
                        yield return file;
                    }
                }
            }
        }
    }

    private static string? SkipReason(FileSystemInfo entry)
    {
        var attributes = entry.Attributes;
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            // Symlinks and junctions report a link target; cloud-file reparse points (OneDrive) do not
            // and are safe to walk, as long as the data is local.
            try
            {
                if (entry.LinkTarget is not null)
                {
                    return "link";
                }
            }
            catch (Exception ex) when (IsSkippable(ex))
            {
                return "link";
            }
        }
        if (entry is FileInfo && (attributes & NotLocal) != 0)
        {
            return "cloud placeholder";
        }
        return null;
    }

    private static bool IsExcluded(string path, string[] excluded)
    {
        foreach (var root in excluded)
        {
            if (path.Equals(root, StringComparison.OrdinalIgnoreCase)
                || (path.StartsWith(root, StringComparison.OrdinalIgnoreCase) && path.Length > root.Length
                    && path[root.Length] == Path.DirectorySeparatorChar))
            {
                return true;
            }
        }
        return false;
    }

    internal static bool IsSkippable(Exception ex) =>
        ex is UnauthorizedAccessException or IOException or System.Security.SecurityException;
}

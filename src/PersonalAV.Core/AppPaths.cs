using System.Security.AccessControl;
using System.Security.Principal;

namespace PersonalAV.Core;

/// <summary>Locations of everything the service keeps on disk, rooted at %ProgramData%\PersonalAV by default.</summary>
public sealed class AppPaths
{
    public const string AppName = "PersonalAV";

    public AppPaths(string root)
    {
        Root = Path.GetFullPath(root);
    }

    public static AppPaths Default { get; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppName));

    public string Root { get; }
    public string Logs => Path.Combine(Root, "logs");
    public string Rules => Path.Combine(Root, "rules");
    public string Quarantine => Path.Combine(Root, "quarantine");
    /// <summary>Scratch space for definition updates (downloads are staged and test-compiled here).</summary>
    public string Updates => Path.Combine(Root, "updates");
    /// <summary>Verified app installers and the signed manifest they came with.</summary>
    public string AppUpdates => Path.Combine(Updates, "app");
    public string Database => Path.Combine(Root, "personalav.db");
    public string QuarantineKey => Path.Combine(Quarantine, "quarantine.key");

    /// <summary>
    /// Creates the folder tree. With <paramref name="restrictAcl"/> the quarantine folder is locked to
    /// SYSTEM and Administrators only (the service passes true; tests running unelevated pass false).
    /// </summary>
    public void EnsureCreated(bool restrictAcl)
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(Rules);
        Directory.CreateDirectory(Quarantine);
        if (restrictAcl)
        {
            ApplyAdminOnlyAcl(Quarantine);
        }
    }

    public static void ApplyAdminOnlyAcl(string directory)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null), FileSystemRights.FullControl, inherit,
                PropagationFlags.None, AccessControlType.Allow));
        }
        new DirectoryInfo(directory).SetAccessControl(security);
    }
}

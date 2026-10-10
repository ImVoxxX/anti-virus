using System.Security.Cryptography;

namespace PersonalAV.Core.Quarantine;

/// <summary>
/// The 256-bit quarantine key, stored DPAPI-protected (machine scope) inside the quarantine folder.
/// The goal is that quarantined files are inert, not secret: the folder's ACL already limits who can read it.
/// </summary>
internal static class QuarantineKey
{
    private static readonly byte[] Entropy = "PersonalAV.QuarantineKey.v1"u8.ToArray();

    public static byte[] LoadOrCreate(string path)
    {
        if (File.Exists(path))
        {
            return ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy, DataProtectionScope.LocalMachine);
        }

        var key = RandomNumberGenerator.GetBytes(32);
        var protectedKey = ProtectedData.Protect(key, Entropy, DataProtectionScope.LocalMachine);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            output.Write(protectedKey);
        }
        return key;
    }
}

using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace PersonalAV.Core.Scanning;

/// <summary>
/// Checks whether a file carries a valid Authenticode signature that chains to a trusted root, either embedded
/// in the file or through a Windows catalog (most Windows system files are catalog-signed only).
/// Only called for files that matched a hash or rule, so its cost does not matter for clean files.
/// </summary>
public static class SignatureCheck
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_IGNORE = 0;
    private const uint WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x80;

    // Revocation could not be checked (offline, or no CRL published): the signature is otherwise valid.
    private const int CRYPT_E_NO_REVOCATION_CHECK = unchecked((int)0x80092012);
    private const int CRYPT_E_REVOCATION_OFFLINE = unchecked((int)0x80092013);

    /// <summary>Describes the trusted signature on the file, or returns null if it has none.</summary>
    public static string? TrustedSigner(string path)
    {
        try
        {
            if (IsTrusted(VerifyEmbedded(path)))
            {
                return "signed by " + EmbeddedSubject(path);
            }
            var catalog = VerifyCatalog(path);
            return catalog is not null ? "catalog-signed (" + Path.GetFileName(catalog) + ")" : null;
        }
        catch (Exception ex) when (FileEnumerator.IsSkippable(ex))
        {
            return null;
        }
    }

    private static bool IsTrusted(int result) =>
        result is 0 or CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE;

    private static string EmbeddedSubject(string path)
    {
        try
        {
            return X509Certificate.CreateFromSignedFile(path).Subject;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return "a trusted publisher";
        }
    }

    private static int VerifyEmbedded(string path)
    {
        var info = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };
        return Verify(WTD_CHOICE_FILE, info);
    }

    /// <summary>Returns the path of a catalog that vouches for the file, or null.</summary>
    private static string? VerifyCatalog(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        // Newer catalogs index files by SHA-256, older ones by SHA-1.
        foreach (var algorithm in new[] { "SHA256", "SHA1" })
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            {
                continue;
            }
            try
            {
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, null, 0);
                if (size == 0)
                {
                    continue;
                }
                var hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, hash, 0))
                {
                    continue;
                }

                var catalogContext = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                while (catalogContext != IntPtr.Zero)
                {
                    var catalog = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (CryptCATCatalogInfoFromContext(catalogContext, ref catalog, 0)
                        && IsTrusted(VerifyMember(admin, catalog.wszCatalogFile, path, stream.SafeFileHandle, hash)))
                    {
                        CryptCATAdminReleaseCatalogContext(admin, catalogContext, 0);
                        return catalog.wszCatalogFile;
                    }
                    // Enumerating with the previous context as the cursor releases it.
                    var previous = catalogContext;
                    catalogContext = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref previous);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }
        return null;
    }

    private static int VerifyMember(IntPtr admin, string catalogPath, string path, SafeFileHandle file, byte[] hash)
    {
        var hashBuffer = Marshal.AllocHGlobal(hash.Length);
        try
        {
            Marshal.Copy(hash, 0, hashBuffer, hash.Length);
            var info = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catalogPath,
                pcwszMemberTag = Convert.ToHexString(hash),
                pcwszMemberFilePath = path,
                hMemberFile = file.DangerousGetHandle(),
                pbCalculatedFileHash = hashBuffer,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = admin,
            };
            return Verify(WTD_CHOICE_CATALOG, info);
        }
        finally
        {
            Marshal.FreeHGlobal(hashBuffer);
        }
    }

    private static int Verify<T>(uint choice, T info) where T : struct
    {
        var union = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        try
        {
            Marshal.StructureToPtr(info, union, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                // Catches certificates revoked after abuse; offline results are accepted in IsTrusted.
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = choice,
                pUnion = union,
                dwStateAction = WTD_STATEACTION_IGNORE,
                dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            };
            var action = GenericVerifyV2;
            return WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
        finally
        {
            Marshal.DestroyStructure<T>(union);
            Marshal.FreeHGlobal(union);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string hashAlgorithm,
        IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, SafeFileHandle file, ref uint hashSize,
        byte[]? hash, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize, uint flags,
        IntPtr previousCatalog);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize, uint flags,
        ref IntPtr previousCatalog);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalogContext, ref CATALOG_INFO info, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catalogContext, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);
}

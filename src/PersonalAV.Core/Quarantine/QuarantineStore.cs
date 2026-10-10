using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

namespace PersonalAV.Core.Quarantine;

/// <summary>
/// Moves detected files into the quarantine folder encrypted with AES-GCM, so they cannot run or be
/// opened by accident, and restores them byte-for-byte to their original path.
/// </summary>
/// <remarks>
/// Stored file layout: "PAVQ" | version (1 byte) | nonce (12) | tag (16) | ciphertext.
/// The entry id is bound in as associated data, so stored files cannot be swapped between entries.
/// </remarks>
public sealed class QuarantineStore
{
    private static readonly byte[] Magic = "PAVQ"u8.ToArray();
    private const byte FormatVersion = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int HeaderSize = 4 + 1 + NonceSize + TagSize;

    private readonly AppPaths _paths;
    private readonly AvDatabase _db;
    private readonly Lazy<byte[]> _key;

    public QuarantineStore(AppPaths paths, AvDatabase db)
    {
        _paths = paths;
        _db = db;
        _key = new Lazy<byte[]>(() => QuarantineKey.LoadOrCreate(paths.QuarantineKey));
    }

    public IReadOnlyList<QuarantineEntry> List() => _db.ListQuarantine();

    /// <summary>Encrypts the file into quarantine, records it, then deletes the original.</summary>
    public QuarantineEntry Quarantine(string path, string threatName)
    {
        path = Path.GetFullPath(path);
        byte[] plain;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            plain = new byte[stream.Length];
            stream.ReadExactly(plain);
        }

        var entry = new QuarantineEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            OriginalPath = path,
            // Hash what is actually stored, in case the file changed since it was scanned.
            Sha256 = Convert.ToHexString(SHA256.HashData(plain)).ToLowerInvariant(),
            ThreatName = threatName,
            QuarantinedAt = DateTimeOffset.UtcNow,
            Size = plain.Length,
            OriginalSddl = TryReadSddl(path),
        };

        var stored = StoredPath(entry.Id);
        WriteEncrypted(stored, entry.Id, plain);
        _db.AddQuarantine(entry);
        try
        {
            var info = new FileInfo(path);
            if (info.IsReadOnly)
            {
                info.IsReadOnly = false;
            }
            info.Delete();
            if (File.Exists(path))
            {
                throw new IOException("the file is still present (delete is pending until it is closed)");
            }
        }
        catch
        {
            // Roll back: the original stays where it was and the quarantine copy is discarded.
            _db.RemoveQuarantine(entry.Id);
            TryDelete(stored);
            throw;
        }
        return entry;
    }

    /// <summary>Decrypts the entry back to its original path and removes it from quarantine.</summary>
    /// <returns>The path the file was restored to.</returns>
    public string Restore(string id, bool overwrite = false)
    {
        var entry = _db.GetQuarantine(id) ?? throw new KeyNotFoundException($"No quarantine entry '{id}'.");
        var plain = ReadDecrypted(StoredPath(entry.Id), entry.Id);
        var hash = Convert.ToHexString(SHA256.HashData(plain)).ToLowerInvariant();
        if (hash != entry.Sha256)
        {
            throw new InvalidDataException("Quarantined data does not match its recorded hash; not restoring.");
        }

        if (File.Exists(entry.OriginalPath) && !overwrite)
        {
            throw new IOException($"A file already exists at {entry.OriginalPath}.");
        }
        Directory.CreateDirectory(Path.GetDirectoryName(entry.OriginalPath)!);
        using (var output = new FileStream(entry.OriginalPath, overwrite ? FileMode.Create : FileMode.CreateNew,
                   FileAccess.Write, FileShare.None))
        {
            output.Write(plain);
        }
        if (entry.OriginalSddl is not null)
        {
            TryApplySddl(entry.OriginalPath, entry.OriginalSddl);
        }

        _db.RemoveQuarantine(entry.Id);
        TryDelete(StoredPath(entry.Id));
        return entry.OriginalPath;
    }

    /// <summary>Permanently deletes a quarantined file.</summary>
    public void Delete(string id)
    {
        var entry = _db.GetQuarantine(id) ?? throw new KeyNotFoundException($"No quarantine entry '{id}'.");
        File.Delete(StoredPath(entry.Id));
        _db.RemoveQuarantine(entry.Id);
    }

    private string StoredPath(string id) => Path.Combine(_paths.Quarantine, id + ".pavq");

    private void WriteEncrypted(string destination, string id, byte[] plain)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var tag = new byte[TagSize];
        var cipher = new byte[plain.Length];
        using (var aes = new AesGcm(_key.Value, TagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(id));
        }

        var temp = destination + ".tmp";
        using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            output.Write(Magic);
            output.WriteByte(FormatVersion);
            output.Write(nonce);
            output.Write(tag);
            output.Write(cipher);
            output.Flush(flushToDisk: true);
        }
        File.Move(temp, destination, overwrite: true);
    }

    private byte[] ReadDecrypted(string source, string id)
    {
        var data = File.ReadAllBytes(source);
        if (data.Length < HeaderSize || !data.AsSpan(0, 4).SequenceEqual(Magic) || data[4] != FormatVersion)
        {
            throw new InvalidDataException("Not a PersonalAV quarantine file.");
        }
        var nonce = data.AsSpan(5, NonceSize);
        var tag = data.AsSpan(5 + NonceSize, TagSize);
        var cipher = data.AsSpan(HeaderSize);
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(_key.Value, TagSize);
        aes.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(id));
        return plain;
    }

    private static string? TryReadSddl(string path)
    {
        try
        {
            return new FileInfo(path).GetAccessControl(AccessControlSections.Access)
                .GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PrivilegeNotHeldException)
        {
            return null;
        }
    }

    private static void TryApplySddl(string path, string sddl)
    {
        try
        {
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
            new FileInfo(path).SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PrivilegeNotHeldException or ArgumentException)
        {
            // The file is restored with inherited permissions instead; not worth failing the restore over.
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
        }
    }
}

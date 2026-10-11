using System.Security.Cryptography;

namespace PersonalAV.Core.Scanning;

/// <summary>Scans one file: SHA-256 against the blocklist, then YARA over the same bytes.</summary>
public sealed class ScanEngine
{
    public const long DefaultMaxFileSize = 100L * 1024 * 1024;

    private readonly AvDatabase _db;
    private readonly YaraRuleSet _yara;

    public ScanEngine(AvDatabase db, YaraRuleSet yara, long maxFileSize = DefaultMaxFileSize)
    {
        _db = db;
        _yara = yara;
        MaxFileSize = maxFileSize;
    }

    public long MaxFileSize { get; }

    public FileVerdict ScanFile(string path)
    {
        byte[] data;
        try
        {
            // Share everything so scanning never blocks the owner of the file.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, bufferSize: 1, FileOptions.SequentialScan);
            var length = stream.Length;
            if (length > MaxFileSize)
            {
                return FileVerdict.Skipped(path, $"larger than {MaxFileSize / (1024 * 1024)} MB");
            }
            data = new byte[length];
            stream.ReadExactly(data);
        }
        catch (Exception ex) when (FileEnumerator.IsSkippable(ex) || ex is EndOfStreamException)
        {
            return FileVerdict.Skipped(path, ex.Message);
        }

        var sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        var hashThreat = _db.LookupHash(sha256);
        if (hashThreat is not null)
        {
            return Detected(path, sha256, hashThreat, "hash");
        }

        try
        {
            var matches = _yara.Match(data);
            if (matches.Count > 0)
            {
                return Detected(path, sha256, "Yara." + matches[0], "yara");
            }
        }
        catch (Exception ex)
        {
            return new FileVerdict(path, VerdictKind.Error, sha256, Reason: "yara: " + ex.Message);
        }

        return new FileVerdict(path, VerdictKind.Clean, sha256);
    }

    /// <summary>
    /// A match on a file with a valid trusted signature is reported as clean, with the reason: hash feeds such as
    /// MalwareBazaar contain genuine Windows files, and quarantining those breaks the system.
    /// </summary>
    private static FileVerdict Detected(string path, string sha256, string threatName, string engine)
    {
        var signer = SignatureCheck.TrustedSigner(path);
        return signer is null
            ? new FileVerdict(path, VerdictKind.Detected, sha256, threatName, engine)
            : new FileVerdict(path, VerdictKind.Clean, sha256, threatName, engine, $"{threatName} ignored: {signer}");
    }
}

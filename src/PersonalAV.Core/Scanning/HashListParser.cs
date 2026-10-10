using System.IO.Compression;
using System.Text.RegularExpressions;

namespace PersonalAV.Core.Scanning;

/// <summary>
/// Reads SHA-256 blocklists: plain one-hash-per-line files, MalwareBazaar CSV exports
/// (using the "signature" column as the threat name), or a .zip containing either.
/// </summary>
public static partial class HashListParser
{
    [GeneratedRegex("^[0-9a-fA-F]{64}$")]
    private static partial Regex Sha256Regex();

    public static List<(string Sha256, string? ThreatName)> ParseFile(string path)
    {
        if (Path.GetExtension(path).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using var zip = ZipFile.OpenRead(path);
            var result = new List<(string, string?)>();
            foreach (var entry in zip.Entries.Where(e => e.Length > 0))
            {
                using var reader = new StreamReader(entry.Open());
                result.AddRange(Parse(reader));
            }
            return result;
        }
        using var file = new StreamReader(path);
        return Parse(file).ToList();
    }

    public static IEnumerable<(string Sha256, string? ThreatName)> Parse(TextReader reader)
    {
        int shaColumn = -1, signatureColumn = -1;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }
            if (trimmed.StartsWith('#'))
            {
                // MalwareBazaar puts the CSV header in a comment: # "first_seen_utc","sha256_hash",...
                var header = SplitCsv(trimmed.TrimStart('#').Trim());
                var sha = header.FindIndex(h => h.Equals("sha256_hash", StringComparison.OrdinalIgnoreCase));
                if (sha >= 0)
                {
                    shaColumn = sha;
                    signatureColumn = header.FindIndex(h => h.Equals("signature", StringComparison.OrdinalIgnoreCase));
                }
                continue;
            }

            if (Sha256Regex().IsMatch(trimmed))
            {
                yield return (trimmed.ToLowerInvariant(), null);
                continue;
            }

            var fields = SplitCsv(trimmed);
            if (shaColumn < 0)
            {
                var headerSha = fields.FindIndex(h => h.Equals("sha256_hash", StringComparison.OrdinalIgnoreCase));
                if (headerSha >= 0)
                {
                    shaColumn = headerSha;
                    signatureColumn = fields.FindIndex(h => h.Equals("signature", StringComparison.OrdinalIgnoreCase));
                    continue;
                }
            }

            var hash = shaColumn >= 0 && shaColumn < fields.Count
                ? fields[shaColumn]
                : fields.FirstOrDefault(f => Sha256Regex().IsMatch(f));
            if (hash is null || !Sha256Regex().IsMatch(hash))
            {
                continue;
            }
            string? name = null;
            if (signatureColumn >= 0 && signatureColumn < fields.Count)
            {
                var signature = fields[signatureColumn];
                if (signature.Length > 0 && !signature.Equals("n/a", StringComparison.OrdinalIgnoreCase))
                {
                    name = "MalwareBazaar." + signature;
                }
            }
            yield return (hash.ToLowerInvariant(), name);
        }
    }

    /// <summary>Minimal CSV split: comma-separated, optional double quotes, surrounding spaces trimmed.</summary>
    internal static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else if (c == '"')
                {
                    inQuotes = false;
                }
                else
                {
                    current.Append(c);
                }
            }
            else if (c == '"')
            {
                inQuotes = true;
            }
            else if (c == ',')
            {
                fields.Add(current.ToString().Trim());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
        fields.Add(current.ToString().Trim());
        return fields;
    }
}

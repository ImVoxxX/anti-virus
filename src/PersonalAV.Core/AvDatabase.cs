using System.Globalization;
using Microsoft.Data.Sqlite;

namespace PersonalAV.Core;

/// <summary>SQLite store for the hash blocklist, detection history and quarantine index.</summary>
public sealed class AvDatabase
{
    /// <summary>SHA-256 of the standard 68-byte EICAR test file, seeded so a fresh install detects it by hash too.</summary>
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private readonly string _connectionString;

    public AvDatabase(string path)
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
        }.ToString();
    }

    public void Initialize()
    {
        using var conn = Open();
        Execute(conn, """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS hashes (
                sha256      TEXT PRIMARY KEY,
                threat_name TEXT NOT NULL,
                source      TEXT NOT NULL,
                added_at    TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS detections (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id       TEXT,
                path          TEXT NOT NULL,
                sha256        TEXT,
                threat_name   TEXT NOT NULL,
                engine        TEXT NOT NULL,
                detected_at   TEXT NOT NULL,
                action        TEXT NOT NULL,
                quarantine_id TEXT,
                error         TEXT
            );
            CREATE TABLE IF NOT EXISTS quarantine (
                id             TEXT PRIMARY KEY,
                original_path  TEXT NOT NULL,
                sha256         TEXT NOT NULL,
                threat_name    TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                size           INTEGER NOT NULL,
                original_sddl  TEXT
            );
            """);
        ImportHashes(new[] { (EicarSha256, (string?)"EICAR-Test-File") }, "builtin");
    }

    // ---- hash blocklist ----

    public string? LookupHash(string sha256)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT threat_name FROM hashes WHERE sha256 = $sha";
        cmd.Parameters.AddWithValue("$sha", sha256.ToLowerInvariant());
        return cmd.ExecuteScalar() as string;
    }

    /// <summary>Inserts hashes, ignoring ones already present. Returns the number of new rows.</summary>
    public int ImportHashes(IEnumerable<(string Sha256, string? ThreatName)> hashes, string source)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT OR IGNORE INTO hashes (sha256, threat_name, source, added_at)
            VALUES ($sha, $name, $source, $now)
            """;
        var sha = cmd.Parameters.Add("$sha", SqliteType.Text);
        var name = cmd.Parameters.Add("$name", SqliteType.Text);
        cmd.Parameters.AddWithValue("$source", source);
        cmd.Parameters.AddWithValue("$now", Now());
        int added = 0;
        foreach (var (hash, threat) in hashes)
        {
            sha.Value = hash.ToLowerInvariant();
            name.Value = string.IsNullOrWhiteSpace(threat) ? "Blocklisted.Hash" : threat;
            added += cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return added;
    }

    public long HashCount()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM hashes";
        return (long)cmd.ExecuteScalar()!;
    }

    // ---- detections ----

    public long AddDetection(DetectionRecord d)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO detections (scan_id, path, sha256, threat_name, engine, detected_at, action, quarantine_id, error)
            VALUES ($scan, $path, $sha, $name, $engine, $at, $action, $qid, $error);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$scan", (object?)d.ScanId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$path", d.Path);
        cmd.Parameters.AddWithValue("$sha", (object?)d.Sha256 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$name", d.ThreatName);
        cmd.Parameters.AddWithValue("$engine", d.Engine);
        cmd.Parameters.AddWithValue("$at", Format(d.DetectedAt));
        cmd.Parameters.AddWithValue("$action", d.Action.ToString());
        cmd.Parameters.AddWithValue("$qid", (object?)d.QuarantineId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$error", (object?)d.Error ?? DBNull.Value);
        return (long)cmd.ExecuteScalar()!;
    }

    public IReadOnlyList<DetectionRecord> ListDetections(int limit = 200)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, scan_id, path, sha256, threat_name, engine, detected_at, action, quarantine_id, error
            FROM detections ORDER BY id DESC LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 10_000));
        using var r = cmd.ExecuteReader();
        var list = new List<DetectionRecord>();
        while (r.Read())
        {
            list.Add(new DetectionRecord
            {
                Id = r.GetInt64(0),
                ScanId = r.IsDBNull(1) ? null : r.GetString(1),
                Path = r.GetString(2),
                Sha256 = r.IsDBNull(3) ? null : r.GetString(3),
                ThreatName = r.GetString(4),
                Engine = r.GetString(5),
                DetectedAt = Parse(r.GetString(6)),
                Action = Enum.Parse<DetectionAction>(r.GetString(7)),
                QuarantineId = r.IsDBNull(8) ? null : r.GetString(8),
                Error = r.IsDBNull(9) ? null : r.GetString(9),
            });
        }
        return list;
    }

    // ---- quarantine index ----

    public void AddQuarantine(QuarantineEntry e)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO quarantine (id, original_path, sha256, threat_name, quarantined_at, size, original_sddl)
            VALUES ($id, $path, $sha, $name, $at, $size, $sddl)
            """;
        cmd.Parameters.AddWithValue("$id", e.Id);
        cmd.Parameters.AddWithValue("$path", e.OriginalPath);
        cmd.Parameters.AddWithValue("$sha", e.Sha256);
        cmd.Parameters.AddWithValue("$name", e.ThreatName);
        cmd.Parameters.AddWithValue("$at", Format(e.QuarantinedAt));
        cmd.Parameters.AddWithValue("$size", e.Size);
        cmd.Parameters.AddWithValue("$sddl", (object?)e.OriginalSddl ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public QuarantineEntry? GetQuarantine(string id) => QueryQuarantine("WHERE id = $id", id).FirstOrDefault();

    public IReadOnlyList<QuarantineEntry> ListQuarantine() => QueryQuarantine("ORDER BY quarantined_at DESC", null);

    public bool RemoveQuarantine(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM quarantine WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteNonQuery() > 0;
    }

    private List<QuarantineEntry> QueryQuarantine(string clause, string? id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT id, original_path, sha256, threat_name, quarantined_at, size, original_sddl FROM quarantine {clause}";
        if (id is not null)
        {
            cmd.Parameters.AddWithValue("$id", id);
        }
        using var r = cmd.ExecuteReader();
        var list = new List<QuarantineEntry>();
        while (r.Read())
        {
            list.Add(new QuarantineEntry
            {
                Id = r.GetString(0),
                OriginalPath = r.GetString(1),
                Sha256 = r.GetString(2),
                ThreatName = r.GetString(3),
                QuarantinedAt = Parse(r.GetString(4)),
                Size = r.GetInt64(5),
                OriginalSddl = r.IsDBNull(6) ? null : r.GetString(6),
            });
        }
        return list;
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    private static void Execute(SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static string Now() => Format(DateTimeOffset.UtcNow);
    private static string Format(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static DateTimeOffset Parse(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}

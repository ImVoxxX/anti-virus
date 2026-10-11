namespace PersonalAV.Core.Updates;

/// <summary>The "Updates" configuration section (appsettings.json, or %ProgramData%\PersonalAV\settings.json).</summary>
public sealed class UpdateOptions
{
    /// <summary>Check on a schedule. With false, updates only run when asked for (dashboard or "pav update").</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Hours between automatic checks. The MalwareBazaar recent feed covers 48 hours, so keep this well under that;
    /// a PC that is off for longer misses the hashes published meanwhile.
    /// </summary>
    public double IntervalHours { get; set; } = 6;

    /// <summary>Folder URL holding manifest.json, manifest.json.sig and the rule files (with a trailing slash).</summary>
    public string RulesBaseUrl { get; set; } = "https://raw.githubusercontent.com/ImVoxxX/anti-virus/main/rules/";

    /// <summary>
    /// Optional token for a private repository: a GitHub fine-grained token with read-only "Contents" access,
    /// sent as a Bearer token with rule downloads. Not needed when the repository is public.
    /// </summary>
    public string? RulesToken { get; set; }

    /// <summary>Recent MalwareBazaar samples (last 48 hours) as CSV, used when no auth key is set.</summary>
    public string HashFeedUrl { get; set; } = "https://bazaar.abuse.ch/export/csv/recent/";

    /// <summary>The same feed through abuse.ch's authenticated API; {key} is replaced by <see cref="MalwareBazaarAuthKey"/>.</summary>
    public string HashFeedKeyedUrl { get; set; } = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv";

    /// <summary>Optional free abuse.ch Auth-Key (https://auth.abuse.ch). Needed if abuse.ch stops serving the public export.</summary>
    public string? MalwareBazaarAuthKey { get; set; }

    /// <summary>Public key the rules manifest must be signed with. Overridable for tests only.</summary>
    public string RulesPublicKey { get; set; } = UpdateKeys.RulesPublicKey;

    public TimeSpan Interval => TimeSpan.FromHours(Math.Clamp(IntervalHours, 0.25, 24 * 7));

    public string EffectiveHashFeedUrl => string.IsNullOrWhiteSpace(MalwareBazaarAuthKey)
        ? HashFeedUrl
        : HashFeedKeyedUrl.Replace("{key}", Uri.EscapeDataString(MalwareBazaarAuthKey.Trim()), StringComparison.Ordinal);
}

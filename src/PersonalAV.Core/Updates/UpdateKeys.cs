namespace PersonalAV.Core.Updates;

public static class UpdateKeys
{
    /// <summary>
    /// Public half (SubjectPublicKeyInfo, base64) of the key that signs rules/manifest.json and app/latest.json.
    /// Because a release manifest decides which installer runs, this key guards code execution. The private half
    /// stays with the publisher, outside the repository; see tools/PersonalAV.RuleSigner.
    /// </summary>
    public const string PublisherPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+40Rn5AeqjZkUlyJaevukhNy8CHU4rO1nPfOjZFoDvALusjyvpFcwW4OyrQnXzdxR5XcszC1KSQoWbUVBF8GiA==";
}

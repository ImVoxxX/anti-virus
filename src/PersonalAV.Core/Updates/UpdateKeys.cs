namespace PersonalAV.Core.Updates;

public static class UpdateKeys
{
    /// <summary>
    /// Public half (SubjectPublicKeyInfo, base64) of the key that signs rules/manifest.json. The private half stays
    /// with whoever publishes rules, outside the repository; see tools/PersonalAV.RuleSigner.
    /// </summary>
    public const string RulesPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+40Rn5AeqjZkUlyJaevukhNy8CHU4rO1nPfOjZFoDvALusjyvpFcwW4OyrQnXzdxR5XcszC1KSQoWbUVBF8GiA==";
}

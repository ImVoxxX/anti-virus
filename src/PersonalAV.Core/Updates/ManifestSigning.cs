using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PersonalAV.Core.Updates;

/// <summary>
/// Signing scheme shared by the rules manifest and the release manifest: an ECDSA P-256 / SHA-256 signature,
/// base64, over the manifest's exact bytes, checked against <see cref="UpdateKeys.PublisherPublicKey"/>.
/// </summary>
public static class ManifestSigning
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Indented JSON with LF line endings on every platform, so the signed bytes never depend on the OS.</summary>
    public static byte[] ToCanonicalBytes<T>(T manifest) =>
        System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(manifest, Json).ReplaceLineEndings("\n") + "\n");

    public static string Sign(byte[] manifestBytes, ECDsa privateKey) =>
        Convert.ToBase64String(privateKey.SignData(manifestBytes, HashAlgorithmName.SHA256));

    public static bool Verify(byte[] manifestBytes, string signatureBase64, string publicKeyBase64)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            return key.VerifyData(manifestBytes, Convert.FromBase64String(signatureBase64.Trim()), HashAlgorithmName.SHA256);
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static string Sha256OfFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    /// <summary>Checks the signature, then deserializes. Throws <see cref="InvalidDataException"/> naming <paramref name="what"/>.</summary>
    internal static T ParseSigned<T>(byte[] manifestBytes, string signatureBase64, string publicKeyBase64, string what) where T : class
    {
        if (!Verify(manifestBytes, signatureBase64, publicKeyBase64))
        {
            throw new InvalidDataException($"the {what} signature is not valid");
        }
        try
        {
            return JsonSerializer.Deserialize<T>(manifestBytes, Json)
                ?? throw new InvalidDataException($"the {what} is empty");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"the {what} is not valid: {ex.Message}");
        }
    }
}

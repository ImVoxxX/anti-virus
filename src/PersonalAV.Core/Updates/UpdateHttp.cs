using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace PersonalAV.Core.Updates;

/// <summary>Bounded HTTP downloads for the updaters. Every failure is an <see cref="UpdateException"/> with a readable message.</summary>
internal static class UpdateHttp
{
    /// <summary>GETs <paramref name="url"/> into memory, refusing more than <paramref name="maxBytes"/>.</summary>
    /// <param name="bearer">Optional token; only ever pass it for hosts that need it.</param>
    /// <param name="hint">Extra advice appended to an HTTP error, chosen by status code.</param>
    public static async Task<byte[]> GetBytesAsync(HttpClient http, string url, long maxBytes, string what, string? bearer,
        Func<HttpStatusCode, string>? hint, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (!string.IsNullOrWhiteSpace(bearer))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer.Trim());
        }
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        EnsureSuccess(response, what, hint);
        return await ReadLimitedAsync(response.Content, maxBytes, what, cancellationToken).ConfigureAwait(false);
    }

    public static void EnsureSuccess(HttpResponseMessage response, string what, Func<HttpStatusCode, string>? hint)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }
        throw new UpdateException(
            $"{what}: HTTP {(int)response.StatusCode} from {response.RequestMessage?.RequestUri?.Host}{hint?.Invoke(response.StatusCode)}",
            response.StatusCode);
    }

    public static async Task<byte[]> ReadLimitedAsync(HttpContent content, long maxBytes, string what, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > maxBytes)
        {
            throw new UpdateException($"{what} is larger than {maxBytes / (1024 * 1024)} MB");
        }
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > maxBytes)
            {
                throw new UpdateException($"{what} is larger than {maxBytes / (1024 * 1024)} MB");
            }
        }
        return buffer.ToArray();
    }

    /// <summary>
    /// Streams <paramref name="url"/> to <paramref name="path"/>, hashing as it goes, and keeps the file only when its
    /// size and SHA-256 match the signed values. Data goes to "<paramref name="path"/>.partial" first, so a failed or
    /// interrupted download never leaves a file at <paramref name="path"/>. No credentials are ever sent.
    /// </summary>
    public static async Task DownloadToFileAsync(HttpClient http, string url, string path, long size, string sha256,
        TimeSpan timeout, string what, CancellationToken cancellationToken)
    {
        // HttpClient.Timeout stops at the response headers; the body is bounded by this token instead.
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var token = timeoutSource.Token;
        var partial = path + ".partial";
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            EnsureSuccess(response, what, null);
            if (response.Content.Headers.ContentLength is { } length && length != size)
            {
                throw new UpdateException($"{what} is {length:N0} bytes, but the signed manifest says {size:N0}");
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;
            await using (var input = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false))
            await using (var output = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = await input.ReadAsync(buffer, token).ConfigureAwait(false)) > 0)
                {
                    total += read;
                    if (total > size)
                    {
                        throw new UpdateException($"{what} is larger than the signed manifest says");
                    }
                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                }
            }
            if (total != size || Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant() != sha256)
            {
                throw new UpdateException($"{what} does not match the signed manifest");
            }
            File.Move(partial, path, overwrite: true);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new UpdateException($"{what}: the download timed out");
        }
        finally
        {
            try
            {
                File.Delete(partial);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}

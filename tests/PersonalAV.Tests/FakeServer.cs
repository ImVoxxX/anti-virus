using System.Net;
using System.Net.Http.Headers;

namespace PersonalAV.Tests;

/// <summary>Serves canned responses by URL and records what was asked for.</summary>
internal sealed class FakeServer : HttpMessageHandler
{
    private readonly Dictionary<string, (HttpStatusCode Code, byte[] Body, string? ETag)> _routes = new();

    public List<string> Requests { get; } = new();

    /// <summary>The Authorization header sent with each request, by URL (null when none was sent).</summary>
    public Dictionary<string, string?> Authorization { get; } = new();

    public string? LastIfNoneMatch { get; private set; }

    public void Respond(string url, HttpStatusCode code, byte[] body, string? etag = null) => _routes[url] = (code, body, etag);

    public byte[] Body(string url) => _routes[url].Body;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        Requests.Add(url);
        Authorization[url] = request.Headers.Authorization?.ToString();
        LastIfNoneMatch = request.Headers.IfNoneMatch.FirstOrDefault()?.ToString();
        var response = _routes.TryGetValue(url, out var route)
            ? new HttpResponseMessage(route.Code) { Content = new ByteArrayContent(route.Body) }
            : new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new ByteArrayContent(Array.Empty<byte>()) };
        if (route.ETag is not null)
        {
            response.Headers.ETag = EntityTagHeaderValue.Parse(route.ETag);
        }
        response.RequestMessage = request;
        return Task.FromResult(response);
    }
}

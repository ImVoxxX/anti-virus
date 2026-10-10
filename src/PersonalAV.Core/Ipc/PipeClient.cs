using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace PersonalAV.Core.Ipc;

public sealed class ServiceUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Client side of the control pipe, used by the CLI and the tray app.</summary>
public sealed class PipeClient : IAsyncDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;

    public PipeClient(string pipeName = PipeProtocol.PipeName)
    {
        // Identification only: whoever owns the pipe can see who we are but cannot act as us.
        _pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification);
    }

    public async Task ConnectAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        try
        {
            await _pipe.ConnectAsync(timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            throw new ServiceUnavailableException("The PersonalAV service is not running (pipe not found).", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new ServiceUnavailableException("Access denied: run this as an elevated Administrator.", ex);
        }
        _reader = new StreamReader(_pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
        _writer = new StreamWriter(_pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
    }

    public async Task<PipeResponse> SendAsync(PipeRequest request, CancellationToken cancellationToken = default)
    {
        if (_reader is null || _writer is null)
        {
            throw new InvalidOperationException("Not connected.");
        }
        await _writer.WriteLineAsync(JsonSerializer.Serialize(request, PipeProtocol.Json)).ConfigureAwait(false);
        var line = await _reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new ServiceUnavailableException("The service closed the connection.");
        return JsonSerializer.Deserialize<PipeResponse>(line, PipeProtocol.Json)
            ?? throw new InvalidDataException("Empty response from service.");
    }

    /// <summary>Connects, sends one request and disconnects.</summary>
    public static async Task<PipeResponse> RequestAsync(PipeRequest request, TimeSpan? timeout = null,
        string pipeName = PipeProtocol.PipeName, CancellationToken cancellationToken = default)
    {
        await using var client = new PipeClient(pipeName);
        await client.ConnectAsync(timeout ?? TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        _reader?.Dispose();
        if (_writer is not null)
        {
            await _writer.DisposeAsync().ConfigureAwait(false);
        }
        await _pipe.DisposeAsync().ConfigureAwait(false);
    }
}

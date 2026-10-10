using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace PersonalAV.Core.Ipc;

/// <summary>Accepts pipe connections and answers each request line through a handler.</summary>
public sealed class PipeServerHost
{
    private const int MaxInstances = 4;

    private readonly string _pipeName;
    private readonly PipeSecurity _security;
    private readonly Func<PipeRequest, PipeResponse> _handler;
    private readonly ILogger _logger;

    public PipeServerHost(string pipeName, PipeSecurity security, Func<PipeRequest, PipeResponse> handler, ILogger? logger = null)
    {
        _pipeName = pipeName;
        _security = security;
        _handler = handler;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>Only SYSTEM and elevated local Administrators may connect.</summary>
    public static PipeSecurity AdminOnlySecurity()
    {
        var security = new PipeSecurity();
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid, null),
                PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
        }
        return security;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var connections = new List<Task>();
        bool first = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                // The first instance must create the name, so a process that grabbed it earlier
                // (with its own ACL) is detected instead of silently shared.
                var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
                pipe = NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, MaxInstances,
                    PipeTransmissionMode.Byte, options, 0, 0, _security);
                first = false;
            }
            catch (UnauthorizedAccessException) when (first)
            {
                _logger.LogError("Pipe {PipeName} is already owned by another process; retrying", _pipeName);
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
                continue;
            }
            catch (IOException ex)
            {
                // All instances busy: wait for one to free up.
                _logger.LogDebug(ex, "Pipe instance unavailable");
                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }

            connections.RemoveAll(t => t.IsCompleted);
            connections.Add(ServeAsync(pipe, cancellationToken));
        }
        await Task.WhenAll(connections).ConfigureAwait(false);
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
                while (!cancellationToken.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (line is null)
                    {
                        break;
                    }
                    var response = Respond(line);
                    await writer.WriteLineAsync(JsonSerializer.Serialize(response, PipeProtocol.Json)).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // Client went away or service is stopping.
            }
        }
    }

    private PipeResponse Respond(string line)
    {
        if (line.Length > PipeProtocol.MaxRequestChars)
        {
            return PipeResponse.Failure("request too large");
        }
        PipeRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<PipeRequest>(line, PipeProtocol.Json);
        }
        catch (JsonException ex)
        {
            return PipeResponse.Failure("malformed request: " + ex.Message);
        }
        if (request is null || string.IsNullOrWhiteSpace(request.Command))
        {
            return PipeResponse.Failure("missing command");
        }
        return _handler(request);
    }
}

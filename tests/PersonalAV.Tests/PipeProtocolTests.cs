using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using PersonalAV.Core;
using PersonalAV.Core.Ipc;
using PersonalAV.Core.Scanning;

namespace PersonalAV.Tests;

public sealed class PipeProtocolTests : IAsyncLifetime
{
    private readonly TestEnvironment _env = new();
    private readonly string _pipeName = "PersonalAV.Tests." + Guid.NewGuid().ToString("N");
    private readonly CancellationTokenSource _stop = new();
    private Task _server = Task.CompletedTask;

    public async Task InitializeAsync()
    {
        _env.LoadMarkerRule();
        var scans = new ScanCoordinator(_env.Engine, _env.Quarantine, _env.Db, _env.Paths);
        var dispatcher = new CommandDispatcher(scans, _env.Quarantine, _env.Db, _env.Yara, _env.Paths);
        // The real service uses the admin-only ACL; tests run unelevated, so allow the current user.
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        var host = new PipeServerHost(_pipeName, security, dispatcher.Handle);
        _server = Task.Run(() => host.RunAsync(_stop.Token));
        await Task.Delay(100);
    }

    public async Task DisposeAsync()
    {
        _stop.Cancel();
        try
        {
            await _server.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (OperationCanceledException)
        {
        }
        _env.Dispose();
    }

    private Task<PipeResponse> Send(PipeRequest request) => PipeClient.RequestAsync(request, pipeName: _pipeName);

    [Fact]
    public async Task Status_round_trips_as_typed_data()
    {
        var response = await Send(new PipeRequest(Commands.GetStatus));

        Assert.True(response.Ok);
        Assert.Equal(ScanState.Idle, response.DataAs<ScanStatus>()!.State);
    }

    [Fact]
    public async Task Scan_then_list_then_restore_over_the_pipe()
    {
        var bad = _env.WriteFile("bad.txt", TestMarker.Value);

        var start = await Send(new PipeRequest(Commands.StartScan, ScanKind.Path, _env.Work));
        Assert.True(start.Ok, start.Error);

        ScanStatus status;
        do
        {
            await Task.Delay(50);
            status = (await Send(new PipeRequest(Commands.GetStatus))).DataAs<ScanStatus>()!;
        } while (status.State == ScanState.Running);

        Assert.Equal(1, status.Detections);
        var detections = (await Send(new PipeRequest(Commands.ListDetections))).DataAs<List<DetectionRecord>>()!;
        Assert.Equal(DetectionAction.Quarantined, Assert.Single(detections).Action);
        var entry = Assert.Single((await Send(new PipeRequest(Commands.ListQuarantine))).DataAs<List<QuarantineEntry>>()!);

        var restore = await Send(new PipeRequest(Commands.Restore, Id: entry.Id));

        Assert.True(restore.Ok, restore.Error);
        Assert.True(File.Exists(bad));
    }

    [Fact]
    public async Task Several_requests_share_one_connection()
    {
        await using var client = new PipeClient(_pipeName);
        await client.ConnectAsync(TimeSpan.FromSeconds(3));

        for (int i = 0; i < 3; i++)
        {
            Assert.True((await client.SendAsync(new PipeRequest(Commands.GetEngineInfo))).Ok);
        }
    }

    [Fact]
    public async Task Bad_requests_get_error_responses()
    {
        Assert.Contains("unknown command", (await Send(new PipeRequest("Explode"))).Error);
        Assert.False((await Send(new PipeRequest(Commands.Restore))).Ok);
        Assert.False((await Send(new PipeRequest(Commands.CancelScan))).Ok);

        // Raw malformed JSON, then a valid request on the same connection still works.
        using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut);
        await pipe.ConnectAsync(3000);
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync("{not json");
        Assert.Contains("malformed", await reader.ReadLineAsync());
        await writer.WriteLineAsync("""{"command":"GetStatus"}""");
        Assert.Contains("\"ok\":true", await reader.ReadLineAsync());
    }

    [Fact]
    public void Admin_only_pipe_acl_grants_only_system_and_administrators()
    {
        var rules = PipeServerHost.AdminOnlySecurity()
            .GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Select(r => ((SecurityIdentifier)r.IdentityReference).Value)
            .Order()
            .ToList();

        Assert.Equal(new[] { "S-1-5-18", "S-1-5-32-544" }, rules);
    }
}

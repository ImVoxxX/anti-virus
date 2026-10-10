using PersonalAV.Core;
using PersonalAV.Core.Ipc;
using PersonalAV.Core.Quarantine;
using PersonalAV.Core.Scanning;
using PersonalAV.Service;
using Serilog;

var paths = AppPaths.Default;
paths.EnsureCreated(restrictAcl: true);

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.File(Path.Combine(paths.Logs, "service-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        fileSizeLimitBytes: 20 * 1024 * 1024,
        rollOnFileSizeLimit: true)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(o => o.ServiceName = AppPaths.AppName);
    builder.Services.AddSerilog();

    builder.Services.AddSingleton(paths);
    builder.Services.AddSingleton(_ =>
    {
        var db = new AvDatabase(paths.Database);
        db.Initialize();
        return db;
    });
    builder.Services.AddSingleton<YaraRuleSet>();
    builder.Services.AddSingleton(sp => new ScanEngine(sp.GetRequiredService<AvDatabase>(), sp.GetRequiredService<YaraRuleSet>()));
    builder.Services.AddSingleton<QuarantineStore>();
    builder.Services.AddSingleton<ScanCoordinator>();
    builder.Services.AddSingleton<CommandDispatcher>();
    builder.Services.AddHostedService<ControlService>();

    builder.Build().Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Service terminated unexpectedly");
    throw;
}
finally
{
    Log.CloseAndFlush();
}

using PersonalAV.Core;
using PersonalAV.Core.Ipc;
using PersonalAV.Core.Quarantine;
using PersonalAV.Core.Scanning;
using PersonalAV.Core.Updates;
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
    // Machine settings that survive reinstalls and upgrades (the data folder is admin-only).
    builder.Configuration.AddJsonFile(Path.Combine(paths.Root, "settings.json"), optional: true, reloadOnChange: false);
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
    var updateOptions = builder.Configuration.GetSection("Updates").Get<UpdateOptions>() ?? new UpdateOptions();
    builder.Services.AddSingleton(updateOptions);
    builder.Services.AddSingleton(_ =>
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"PersonalAV/{AppVersion.Format(AppVersion.Current)}");
        return http;
    });
    if (updateOptions.AppUpdates)
    {
        builder.Services.AddSingleton(sp => new AppUpdateChecker(sp.GetRequiredService<AvDatabase>(), paths,
            sp.GetRequiredService<HttpClient>(), updateOptions, AppInstallInfo.Detect(), restrictAcl: true,
            sp.GetRequiredService<ILogger<AppUpdateChecker>>()));
    }
    builder.Services.AddSingleton<DefinitionUpdater>();
    builder.Services.AddSingleton<CommandDispatcher>();
    builder.Services.AddHostedService<ControlService>();
    builder.Services.AddHostedService<UpdateService>();

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

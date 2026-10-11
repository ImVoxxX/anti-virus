using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAV.Core.Ipc;

namespace PersonalAV.Core.Updates;

/// <summary>
/// Looks for a newer PersonalAV release in the signed release manifest and, for a copy the .msi installed, downloads
/// that version's installer into the admin-only updates folder after checking it against the signed SHA-256.
/// Nothing is installed here: the dashboard or "pav install-update" starts the installer when the user asks.
/// Runs as the last step of <see cref="DefinitionUpdater.CheckNowAsync"/>.
/// </summary>
public sealed class AppUpdateChecker
{
    private const long MaxManifestBytes = 1024 * 1024;
    private const string StatusKey = "update.app.status";
    private const string MaxSeenKey = "update.app.max_seen";
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(30);

    private readonly AvDatabase _db;
    private readonly AppPaths _paths;
    private readonly HttpClient _http;
    private readonly UpdateOptions _options;
    private readonly AppInstallInfo _install;
    private readonly bool _restrictAcl;
    private readonly ILogger _logger;

    /// <param name="restrictAcl">Lock the installer folder to SYSTEM and Administrators (the service; tests pass false).</param>
    public AppUpdateChecker(AvDatabase db, AppPaths paths, HttpClient http, UpdateOptions options, AppInstallInfo install,
        bool restrictAcl = true, ILogger<AppUpdateChecker>? logger = null)
    {
        _db = db;
        _paths = paths;
        _http = http;
        _options = options;
        _install = install;
        _restrictAcl = restrictAcl;
        _logger = logger ?? NullLogger<AppUpdateChecker>.Instance;
    }

    /// <summary>The last check's result, corrected for the version running now (an offer disappears once installed).</summary>
    public AppUpdateStatus GetStatus()
    {
        var status = ReadStatus() with
        {
            InstalledVersion = AppVersion.Format(_install.Version),
            Variant = _install.Variant,
        };
        if (status.AvailableVersion is not null
            && (!AppVersion.TryParse(status.AvailableVersion, out var available) || available <= _install.Version))
        {
            status = status with { AvailableVersion = null, InstallerReady = false, Result = $"Up to date ({status.InstalledVersion})" };
        }
        if (status.InstallerReady && (status.AvailableVersion is null || _install.Variant is null
            || !File.Exists(InstallerPath(_paths, AppVersionOf(status.AvailableVersion), _install.Variant))))
        {
            status = status with { InstallerReady = false };
        }
        return status;
    }

    public async Task CheckAsync(CancellationToken cancellationToken)
    {
        var previous = ReadStatus();
        var now = DateTimeOffset.UtcNow;
        try
        {
            var status = await CheckCoreAsync(cancellationToken).ConfigureAwait(false);
            WriteStatus(status with { CheckedAt = now });
            _logger.LogInformation("App update check: {Result}", status.Result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            var message = DefinitionUpdater.DescribeFailure(ex);
            WriteStatus(previous with { CheckedAt = now, Error = message });
            _logger.LogWarning(ex, "App update check failed: {Message}", message);
        }
    }

    /// <summary>Where the installer for <paramref name="version"/> is kept once verified.</summary>
    public static string InstallerPath(AppPaths paths, Version version, string variant) =>
        Path.Combine(paths.AppUpdates, ReleaseManifest.LocalFileName(version, variant));

    private async Task<AppUpdateStatus> CheckCoreAsync(CancellationToken cancellationToken)
    {
        var installed = _install.Version;
        var status = new AppUpdateStatus { InstalledVersion = AppVersion.Format(installed), Variant = _install.Variant };

        byte[] manifestBytes;
        string signature;
        try
        {
            manifestBytes = await UpdateHttp.GetBytesAsync(_http, _options.ReleaseManifestUrl, MaxManifestBytes,
                "release manifest", null, null, cancellationToken).ConfigureAwait(false);
            signature = Encoding.ASCII.GetString(await UpdateHttp.GetBytesAsync(_http, _options.ReleaseManifestUrl + ".sig", 4096,
                "release signature", null, null, cancellationToken).ConfigureAwait(false));
        }
        catch (UpdateException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            CleanUp(keep: null);
            return status with { Result = "No releases published yet" };
        }

        var manifest = ReleaseManifest.ParseVerified(manifestBytes, signature, _options.PublisherPublicKey);
        var latest = manifest.GetVersion();
        var version = AppVersion.Format(latest);
        // A replayed older manifest could hide a newer release (and its fixes); never go back.
        if (AppVersion.TryParse(_db.GetSetting(MaxSeenKey), out var maxSeen) && latest < maxSeen)
        {
            throw new UpdateException($"refused release manifest {version}: version {AppVersion.Format(maxSeen)} was already published");
        }
        _db.SetSetting(MaxSeenKey, version);

        status = status with
        {
            LatestVersion = version,
            Notes = manifest.Notes,
            ReleaseUrl = manifest.ReleaseUrl,
            Published = manifest.Published,
        };
        if (latest <= installed)
        {
            CleanUp(keep: null);
            return status with { Result = $"Up to date ({status.InstalledVersion})" };
        }

        status = status with { AvailableVersion = version };
        if (_install.Variant is not { } variant)
        {
            return status with { Result = $"Version {version} is available; this copy was not installed with the .msi, so install it by hand" };
        }
        if (manifest.AssetFor(variant) is not { } asset)
        {
            return status with { Result = $"Version {version} is available, but has no {variant} installer" };
        }

        var folder = EnsureFolder();
        var path = InstallerPath(_paths, latest, variant);
        if (!IsVerified(path, asset))
        {
            try
            {
                await UpdateHttp.DownloadToFileAsync(_http, asset.Url, path, asset.Size, asset.Sha256, DownloadTimeout,
                    Path.GetFileName(path), cancellationToken).ConfigureAwait(false);
            }
            catch (UpdateException ex) when (ex.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden)
            {
                // The manifest went up before the release assets; try again next time.
                return status with { Result = $"Version {version} is announced, but its installer is not published yet" };
            }
        }
        // Kept next to the installer so the dashboard and CLI can re-check everything before running it.
        File.WriteAllBytes(Path.Combine(folder, ReleaseManifest.FileName), manifestBytes);
        File.WriteAllText(Path.Combine(folder, ReleaseManifest.SignatureFileName), signature);
        CleanUp(keep: Path.GetFileName(path));
        return status with { InstallerReady = true, Result = $"Version {version} is ready to install" };
    }

    private static bool IsVerified(string path, ReleaseAsset asset) =>
        File.Exists(path) && new FileInfo(path).Length == asset.Size && ManifestSigning.Sha256OfFile(path) == asset.Sha256;

    private string EnsureFolder()
    {
        var folder = Directory.CreateDirectory(_paths.AppUpdates).FullName;
        if (_restrictAcl)
        {
            // Nobody but administrators may swap the installer between verification and msiexec opening it.
            AppPaths.ApplyAdminOnlyAcl(folder);
        }
        return folder;
    }

    /// <summary>
    /// Deletes installers other than <paramref name="keep"/> and the one for the installed version (Windows Installer
    /// may ask for it during a repair). With nothing to keep, the saved manifest goes too.
    /// </summary>
    private void CleanUp(string? keep)
    {
        if (!Directory.Exists(_paths.AppUpdates))
        {
            return;
        }
        var installed = _install.Variant is { } variant ? ReleaseManifest.LocalFileName(_install.Version, variant) : null;
        foreach (var file in Directory.EnumerateFiles(_paths.AppUpdates))
        {
            var name = Path.GetFileName(file);
            bool isInstaller = name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".partial", StringComparison.OrdinalIgnoreCase);
            bool isManifest = name is ReleaseManifest.FileName or ReleaseManifest.SignatureFileName;
            if ((isInstaller && !name.Equals(keep, StringComparison.OrdinalIgnoreCase) && !name.Equals(installed, StringComparison.OrdinalIgnoreCase))
                || (isManifest && keep is null))
            {
                try
                {
                    File.Delete(file);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    _logger.LogDebug(ex, "Could not delete {File}", file);
                }
            }
        }
    }

    private static Version AppVersionOf(string text) => AppVersion.TryParse(text, out var version) ? version : new Version(0, 0, 0);

    private AppUpdateStatus ReadStatus()
    {
        var json = _db.GetSetting(StatusKey);
        return json is null ? new AppUpdateStatus() : JsonSerializer.Deserialize<AppUpdateStatus>(json, PipeProtocol.Json) ?? new();
    }

    private void WriteStatus(AppUpdateStatus status) => _db.SetSetting(StatusKey, JsonSerializer.Serialize(status, PipeProtocol.Json));
}

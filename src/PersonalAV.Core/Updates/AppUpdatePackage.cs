using System.Diagnostics;

namespace PersonalAV.Core.Updates;

/// <summary>
/// Starts a downloaded app update, for the dashboard and "pav install-update" (both elevated). Everything is checked
/// again here, independently of the service: the saved release manifest's signature against the compiled-in key,
/// the installer's size and SHA-256, the variant, and that the version is newer. The installer path is built
/// locally, never taken from the service.
/// </summary>
public static class AppUpdatePackage
{
    public sealed record Prepared(Version Version, string InstallerPath);

    /// <summary>Returns the verified installer, or throws <see cref="UpdateException"/> saying why it cannot be used.</summary>
    public static Prepared Prepare(AppPaths paths, AppInstallInfo install) => Prepare(paths, install, UpdateKeys.PublisherPublicKey);

    internal static Prepared Prepare(AppPaths paths, AppInstallInfo install, string publicKey)
    {
        if (install.Variant is not { } variant)
        {
            throw new UpdateException("this copy was not installed with the .msi; download and install the new version by hand");
        }
        var manifestPath = Path.Combine(paths.AppUpdates, ReleaseManifest.FileName);
        var signaturePath = Path.Combine(paths.AppUpdates, ReleaseManifest.SignatureFileName);
        if (!File.Exists(manifestPath) || !File.Exists(signaturePath))
        {
            throw new UpdateException("no update has been downloaded; check for updates first");
        }

        ReleaseManifest manifest;
        try
        {
            manifest = ReleaseManifest.ParseVerified(File.ReadAllBytes(manifestPath), File.ReadAllText(signaturePath), publicKey);
        }
        catch (InvalidDataException ex)
        {
            throw new UpdateException("the downloaded update failed verification: " + ex.Message);
        }
        var version = manifest.GetVersion();
        if (version <= install.Version)
        {
            throw new UpdateException($"version {AppVersion.Format(install.Version)} is installed, so {manifest.Version} is not an update");
        }
        var asset = manifest.AssetFor(variant)
            ?? throw new UpdateException($"version {manifest.Version} has no {variant} installer");
        var path = AppUpdateChecker.InstallerPath(paths, version, variant);
        if (!File.Exists(path) || new FileInfo(path).Length != asset.Size || ManifestSigning.Sha256OfFile(path) != asset.Sha256)
        {
            throw new UpdateException("the downloaded installer does not match the signed manifest; check for updates again");
        }
        return new Prepared(version, path);
    }

    /// <summary>
    /// Starts the installer with its normal UI and returns at once. The upgrade stops the service and closes the tray;
    /// the installer's last page offers to open PersonalAV again. A verbose log goes to <paramref name="logsDirectory"/>.
    /// </summary>
    public static void Launch(Prepared prepared, string logsDirectory)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe"))
        {
            UseShellExecute = false,
            // Not the caller's folder: that is inside the install directory the upgrade replaces.
            WorkingDirectory = Environment.SystemDirectory,
        };
        info.ArgumentList.Add("/i");
        info.ArgumentList.Add(prepared.InstallerPath);
        info.ArgumentList.Add("/l*v");
        info.ArgumentList.Add(Path.Combine(logsDirectory, $"upgrade-{AppVersion.Format(prepared.Version)}.log"));
        Process.Start(info)?.Dispose();
    }
}

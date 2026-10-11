# PersonalAV

A personal, user-mode antivirus for Windows 10/11 x64 that runs alongside Microsoft Defender.
This is **Part 1, the minimum working antivirus**: on-demand scanning, detection by SHA-256 blocklist
and YARA rules, encrypted quarantine with restore, a Windows service, a CLI and a tray app.
There is no real-time protection yet.

## Layout

| Path | What it is |
| --- | --- |
| `src/PersonalAV.Core` | Engine: file enumerator, hash and YARA detection, quarantine, scan coordinator, SQLite store, pipe protocol |
| `src/PersonalAV.Service` | Windows Service (LocalSystem) that owns the engine and serves the control pipe |
| `src/PersonalAV.Cli` | `pav.exe`, a thin client over the pipe |
| `src/PersonalAV.Tray` | WPF tray app with a dashboard window: status, Quick/Full/folder scans with progress, hash import, rule reload, Results, Quarantine |
| `tests/PersonalAV.Tests` | xUnit tests for the enumerator, detection, quarantine round-trip and pipe protocol |
| `installer/` | WiX project that builds the `.msi` installer |
| `rules/` | Bundled YARA rules (EICAR and a harmless PersonalAV test marker) |
| `scripts/` | `install.ps1` / `uninstall.ps1` (install from source without an `.msi`) |

Runtime data lives in `%ProgramData%\PersonalAV` (`personalav.db`, `rules\`, `quarantine\`, `logs\`),
readable only by SYSTEM and Administrators.

## Build and test

Requires the .NET 8 SDK (pinned in `global.json`).

```powershell
dotnet build
dotnet test
```

## Install

### With the installer (recommended)

Build the `.msi`. It publishes the apps itself, so this is the only command needed:

```powershell
dotnet build installer -c Release                         # artifacts\installer\PersonalAV-0.1.0-x64.msi (about 4 MB)
dotnet build installer -c Release -p:SelfContained=true   # ...-x64-selfcontained.msi, bundles .NET (about 90 MB)
```

Double-click the `.msi`, or run `msiexec /i PersonalAV-0.1.0-x64.msi /qn` from an elevated prompt for a silent install.
It installs to `%ProgramFiles%\PersonalAV`, creates and starts the `PersonalAV` service (automatic start, restarts
on failure), adds `pav` to the system `PATH`, adds a **PersonalAV** Start menu entry, and registers a logon task that
starts the tray app elevated for every administrator. The last page offers to open PersonalAV right away.

Prerequisites, checked before anything is installed:

- [Microsoft Visual C++ 2015-2022 Redistributable (x64)](https://aka.ms/vs/17/release/vc_redist.x64.exe), needed by the YARA engine.
- [.NET 8 Desktop Runtime (x64)](https://dotnet.microsoft.com/download/dotnet/8.0), unless you built the self-contained `.msi`.

Uninstall from **Settings > Apps > Installed apps > PersonalAV**. The data folder (database, logs, your rules,
quarantine) is kept; delete `%ProgramData%\PersonalAV` by hand to remove it too. Running a newer (or rebuilt) `.msi`
upgrades in place.

The installer and the scripts below install to the same places, so use one or the other. If you already used
`install.ps1`, run `scripts\uninstall.ps1` first; the `.msi` refuses to install until you do.

### With the scripts

From an **elevated** PowerShell in the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

This publishes the apps, installs them to `%ProgramFiles%\PersonalAV`, creates and starts the `PersonalAV`
service (automatic start, restarts on failure), and registers the tray app to start elevated at logon.
`scripts\uninstall.ps1` removes everything except the data folder; add `-RemoveData` to remove that too.

## Use

The control pipe only accepts elevated Administrators, so run `pav` from an elevated prompt.
The tray app is started elevated (and hidden, with `--tray`) by its logon task. Double-click the shield icon,
or choose **Open PersonalAV**, to open the dashboard; closing the dashboard leaves the icon running.
Launching `PersonalAV.Tray.exe` again brings the existing dashboard forward.

```powershell
$pav = "$env:ProgramFiles\PersonalAV\Cli\pav.exe"
& $pav scan quick --wait          # or: scan full, scan C:\some\folder
& $pav status
& $pav detections
& $pav quarantine
& $pav restore <id>               # --overwrite to replace a file now at that path
& $pav delete <id>
& $pav import-hashes full_sha256.zip
& $pav reload-rules
& $pav update                     # download new rules and hashes now
& $pav info                       # includes definition update status
```

### What gets scanned

- **Quick scan:** executables of running processes; the all-users Startup folder; `C:\Windows\Temp`; and for
  each user profile, Desktop and Downloads (including OneDrive-redirected ones for signed-in users), the
  Startup folder, `AppData\Roaming` and `AppData\Local` (which contains `%Temp%`).
- **Full scan:** every fixed drive.
- Files over 100 MB, symlinks and junctions, OneDrive online-only placeholders, and locked or
  access-denied files are skipped and counted, never fatal. Detections are quarantined automatically.
- A hash or YARA match on a file with a valid, trusted Authenticode signature (embedded or through a Windows
  catalog) is not a detection: it is logged as "Not quarantining ..." in the service log instead. Hash feeds
  contain genuine Windows files, and quarantining those breaks the system.

### Seeding the hash blocklist

The EICAR hash is built in. To add real malware hashes, download a MalwareBazaar export
(for example the SHA-256 list or the recent CSV from https://bazaar.abuse.ch/export/) and import it:

```powershell
& $pav import-hashes C:\Downloads\full_sha256.zip
```

Plain one-hash-per-line files, MalwareBazaar CSVs (the `signature` column becomes the threat name) and
`.zip` archives of either are accepted. After that, definition updates keep the blocklist current.

### Definition updates

The service checks for new definitions a minute after it starts and then every 6 hours. You can also click
**Check for updates** on the dashboard or run `pav update`. Each check covers two sources, and one failing
doesn't stop the other:

- **Hashes** come from the MalwareBazaar recent feed (samples from the last 48 hours) and are added to the
  blocklist. The download is skipped when the feed hasn't changed. A PC that stays off for more than 48 hours
  misses the hashes published meanwhile; import a full export to catch up.
- **YARA rules** come from PersonalAV's published rules, through a signed manifest.
  The service checks the manifest's signature and refuses a version older than the installed one. It
  downloads only changed files and checks each one against its signed hash. It then test-compiles them
  together with your local rules, and only then swaps them in. A bad update never replaces working rules.
  The service only removes files that an earlier update installed. Your own rule files are left alone, so
  give them names that aren't used in `rules/`.

Settings live in the `Updates` section of the service's `appsettings.json`. To keep your changes across
upgrades, put them in `%ProgramData%\PersonalAV\settings.json` instead:

```json
{
  "Updates": {
    "Enabled": true,
    "IntervalHours": 6,
    "RulesToken": "",
    "MalwareBazaarAuthKey": ""
  }
}
```

- `RulesToken`: leave empty unless you were given a token for downloading rules.
- `MalwareBazaarAuthKey`: the public feed works without a key today. If abuse.ch starts requiring one, the
  update status says so; get a free key at <https://auth.abuse.ch> and set it here.

Restart the `PersonalAV` service after changing settings.

### Adding YARA rules

Drop `.yar` / `.yara` files into `%ProgramData%\PersonalAV\rules` and run `pav reload-rules`.
A file that fails to compile is skipped and reported; if nothing compiles, the previous rules stay active.
Add only a few well-tested rules at first: large community sets produce false positives.

## Testing detection safely

Defender usually removes EICAR before PersonalAV sees it. To test without fighting Defender, use the
bundled harmless marker:

```powershell
& $pav testfile "$env:USERPROFILE\Downloads\pav-test.txt"
& $pav scan quick --wait     # detects Yara.PersonalAV_Test_Marker and quarantines it
& $pav quarantine
& $pav restore <id>          # file comes back byte-for-byte
```

Until Part 2 adds exclusions, a restored file is detected again on the next scan.

## Part 1 definition of done

Checked by hand after installing:

- [x] EICAR (or the test marker) in Downloads is detected by Quick scan and Full scan
- [x] Detected file is quarantined, cannot be opened in place, and restores to its original path intact
- [x] A Full scan of `C:\` finishes without crashing on locked, huge or permission-denied files
- [x] A clean Windows install produces zero detections
- [x] Service starts after reboot and recovers after being killed
- [x] A non-admin process cannot send commands over the pipe

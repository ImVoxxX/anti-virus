#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds and installs PersonalAV: the Windows service, the pav CLI and the tray app.

.DESCRIPTION
    - Publishes the three apps (unless -SkipBuild) into artifacts\publish.
    - Copies them to %ProgramFiles%\PersonalAV.
    - Creates %ProgramData%\PersonalAV (SYSTEM and Administrators only) and copies the bundled rules.
    - Registers the PersonalAV service (LocalSystem, automatic start, restart on failure) and starts it.
    - Registers a logon task that starts the tray app elevated, without a UAC prompt.
    Re-running it upgrades in place; data, quarantine and your own rule files are kept.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$NoTray
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$serviceName = 'PersonalAV'
$installDir = Join-Path $env:ProgramFiles 'PersonalAV'
$dataDir = Join-Path $env:ProgramData 'PersonalAV'
$publishDir = Join-Path $repo 'artifacts\publish'
$taskName = 'PersonalAV Tray'

# Well-known SIDs, so the script works on any Windows display language.
$sidSystem = '*S-1-5-18'
$sidAdmins = '*S-1-5-32-544'

function Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }

if (-not $SkipBuild) {
    Step 'Publishing'
    $projects = @{
        'Service' = 'src\PersonalAV.Service\PersonalAV.Service.csproj'
        'Cli'     = 'src\PersonalAV.Cli\PersonalAV.Cli.csproj'
        'Tray'    = 'src\PersonalAV.Tray\PersonalAV.Tray.csproj'
    }
    foreach ($name in $projects.Keys) {
        $out = Join-Path $publishDir $name
        if (Test-Path $out) { Remove-Item $out -Recurse -Force }
        & dotnet publish (Join-Path $repo $projects[$name]) -c Release -o $out --nologo -v q
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $name" }
    }
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Step 'Stopping the existing service'
    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
Get-Process -Name 'PersonalAV.Tray' -ErrorAction SilentlyContinue | Stop-Process -Force

Step "Copying binaries to $installDir"
foreach ($name in 'Service', 'Cli', 'Tray') {
    $source = Join-Path $publishDir $name
    if (-not (Test-Path $source)) { throw "Missing $source. Run without -SkipBuild." }
    $target = Join-Path $installDir $name
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $target -Recurse -Force
}

Step "Preparing $dataDir"
foreach ($sub in '', 'logs', 'rules', 'quarantine') {
    New-Item -ItemType Directory -Force -Path (Join-Path $dataDir $sub) | Out-Null
}
# Only SYSTEM and Administrators: standard users can neither read the quarantine nor change rules.
& icacls $dataDir /inheritance:r /grant:r "${sidSystem}:(OI)(CI)F" "${sidAdmins}:(OI)(CI)F" /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls failed on the data folder' }
# Bundled rules are overwritten on upgrade; other files in the rules folder are left alone.
Copy-Item -Path (Join-Path $repo 'rules\*.yar') -Destination (Join-Path $dataDir 'rules') -Force

$exe = Join-Path $installDir 'Service\PersonalAV.Service.exe'
if (-not $existing) {
    Step 'Creating the service'
    New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName 'PersonalAV' `
        -Description 'PersonalAV on-demand malware scanner.' -StartupType Automatic | Out-Null
} else {
    & sc.exe config $serviceName binPath= "`"$exe`"" start= auto | Out-Null
}
# Restart after 5 s on the first two failures and 30 s after that; reset the count after a day.
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
& sc.exe failureflag $serviceName 1 | Out-Null

Step 'Starting the service'
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

if (-not $NoTray) {
    Step 'Registering the tray app at logon'
    $trayExe = Join-Path $installDir 'Tray\PersonalAV.Tray.exe'
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $trayExe -Argument '--tray'
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
}

Write-Host ''
Write-Host 'PersonalAV is installed.' -ForegroundColor Green
Write-Host "  CLI:  `"$(Join-Path $installDir 'Cli\pav.exe')`" status   (from an elevated prompt)"
Write-Host "  Data: $dataDir"

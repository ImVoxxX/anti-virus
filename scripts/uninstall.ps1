#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the PersonalAV service, tray task and program files.

.DESCRIPTION
    By default the data folder (%ProgramData%\PersonalAV: database, logs, rules and quarantine) is kept,
    so a reinstall picks up where it left off. -RemoveData deletes it, including every quarantined file.
#>
[CmdletBinding()]
param(
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$serviceName = 'PersonalAV'
$installDir = Join-Path $env:ProgramFiles 'PersonalAV'
$dataDir = Join-Path $env:ProgramData 'PersonalAV'
$taskName = 'PersonalAV Tray'

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Get-Process -Name 'PersonalAV.Tray' -ErrorAction SilentlyContinue | Stop-Process -Force

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $serviceName | Out-Null
}

if (Test-Path $installDir) {
    Remove-Item $installDir -Recurse -Force
}

if ($RemoveData) {
    if (Test-Path $dataDir) {
        Remove-Item $dataDir -Recurse -Force
        Write-Host "Removed $dataDir, including all quarantined files."
    }
} else {
    Write-Host "Kept $dataDir (database, logs, rules, quarantine). Use -RemoveData to delete it."
}

Write-Host 'PersonalAV is uninstalled.' -ForegroundColor Green

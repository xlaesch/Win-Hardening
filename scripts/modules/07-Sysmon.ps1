# 07-Sysmon.ps1 - deploy Sysmon with the SwiftOnSecurity community config.
# Sysmon gives process/network/registry telemetry the Windows event log lacks;
# every researched team shipped it (BYU to Splunk, UW-Stout to Wazuh).
# Binaries are local-first: tools\sysinternals\Sysmon64.exe ships with this repo,
# so no internet access is required on the target.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [string]$SysmonPath,     # default: <repo>\tools\sysinternals\Sysmon64.exe
    [string]$ConfigPath      # default: <repo>\scripts\files\sysmonconfig-export.xml
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'sysmon' -BackupRoot $BackupRoot
$installDir = 'C:\ProgramData\Hardening\Sysmon'
try {
    # ---------- locate binaries ----------
    if (-not $SysmonPath) {
        $candidates = @(
            (Join-Path $PSScriptRoot '..\..\tools\sysinternals\Sysmon64.exe'),
            (Join-Path $installDir 'Sysmon64.exe')
        )
        $SysmonPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $ConfigPath) {
        $candidates = @(
            (Join-Path $PSScriptRoot '..\files\sysmonconfig-export.xml'),
            (Join-Path $PSScriptRoot '..\..\tools\sysinternals\sysmonconfig.xml')
        )
        $ConfigPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $SysmonPath -or -not (Test-Path $SysmonPath)) {
        throw "Sysmon64.exe not found. Pass -SysmonPath or place it in tools\sysinternals\."
    }
    if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
        throw "Sysmon config not found. Pass -ConfigPath or place one in scripts\files\."
    }
    Write-Log "Sysmon binary: $SysmonPath"
    Write-Log "Sysmon config: $ConfigPath"

    # ---------- stage to a stable directory (never run from a share/USB) ----------
    if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
    Copy-Item $SysmonPath (Join-Path $installDir 'Sysmon64.exe') -Force
    Copy-Item $ConfigPath (Join-Path $installDir 'sysmon-config.xml') -Force
    $localExe = Join-Path $installDir 'Sysmon64.exe'
    $localCfg = Join-Path $installDir 'sysmon-config.xml'

    # ---------- install or update ----------
    $svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    if ($svc) {
        if ($PSCmdlet.ShouldProcess('Sysmon', 'update configuration')) {
            $outFile = Join-Path $env:TEMP 'sysmon-update.txt'
            & cmd.exe /c "`"$localExe`" -accepteula -c `"$localCfg`" > `"$outFile`" 2>&1"
            Get-Content $outFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Log "  sysmon: $_" }
            Write-Log 'Sysmon configuration updated' 'CHANGE'
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess('Sysmon', 'install with config')) {
            # Run via cmd with file redirect: over WinRM, Sysmon's status output on
            # stderr wraps into error records that abort the pipeline mid-install.
            $outFile = Join-Path $env:TEMP 'sysmon-install.txt'
            & cmd.exe /c "`"$localExe`" -accepteula -i `"$localCfg`" > `"$outFile`" 2>&1"
            Get-Content $outFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Log "  sysmon: $_" }
            Write-Log 'Sysmon install executed' 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'Sysmon' -Action 'Install' `
                -Target 'Sysmon64' -NewValue 'Installed'
        }
    }

    # 512 MB log retention (default 16 MB wraps in minutes under red-team activity).
    if ($PSCmdlet.ShouldProcess('Sysmon event log', 'set max size 512 MB')) {
        & wevtutil.exe sl Microsoft-Windows-Sysmon/Operational /ms:536870912
        Write-Log 'Sysmon log max size set to 512 MB' 'CHANGE'
    }

    # ---------- verify ----------
    Write-Log '--- verify ---'
    # Service registration can lag the installer on fresh installs; poll before judging.
    $svc = $null
    for ($i = 0; $i -lt 10 -and -not $svc; $i++) {
        Start-Sleep -Seconds 2
        $svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    }
    if ($svc -and $svc.Status -eq 'Running') { Write-Log "Sysmon64 service: Running" 'OK' }
    else { Write-Log "Sysmon64 service: $($svc.Status)" 'FAIL'; $exitCode = 1 }
    $evt = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($evt) { Write-Log "Sysmon operational log active (latest event: $($evt.TimeCreated))" 'OK' }
    else { Write-Log 'Sysmon operational log has no events yet (may need a minute)' 'WARN' }
    Write-Log 'Sysmon module complete.' 'OK'
}
catch {
    Write-Log "Sysmon module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode

# 18-Iis.ps1 - IIS hardening.
# CPP Log.ps1 parity: make sure IIS request logging is ON (red teams turn it
# off to hide webshell access; event logs then have nothing about the web app).
# No-op if IIS is not installed.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'iis' -BackupRoot $BackupRoot
try {
    $appcmd = "$env:WINDIR\System32\inetsrv\appcmd.exe"
    if (-not (Test-Path $appcmd)) {
        Write-Log 'IIS not installed (no appcmd) - nothing to do.' 'OK'
        exit 0
    }

    # dontLog:False = logging ENABLED for all sites.
    if ($PSCmdlet.ShouldProcess('IIS httpLogging', 'set dontLog=False')) {
        & $appcmd set config /section:httpLogging /dontLog:False
        Write-Log 'IIS request logging enabled (dontLog=False)' 'CHANGE'
        Add-ChangeRecord -BackupDir $BackupDir -Module 'Iis' -Action 'EnableLogging' `
            -Target 'httpLogging/dontLog' -NewValue 'False'
    }

    Write-Log '--- verify ---'
    $out = & $appcmd list config /section:httpLogging
    Write-Log ("  {0}" -f ($out -join ' '))
    Write-Log 'Iis module complete.' 'OK'
}
catch {
    Write-Log "Iis module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode

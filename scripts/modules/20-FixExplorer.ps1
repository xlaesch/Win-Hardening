# 20-FixExplorer.ps1 - Explorer visibility for incident response.
# The IR-relevant slice of CPP Fix.ps1: show hidden files, show file extensions,
# show protected OS files. Teams that can't see .php.webshell or hidden
# persistence take longer to find the red team. (The rest of CPP Fix.ps1 -
# fonts, keyboard layout, UI language - is QOL, not hardening.)
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
# No admin strictly required (HKCU only), but toolkit convention is admin.
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'fixexp' -BackupRoot $BackupRoot
try {
    $adv = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    # 1 = show hidden files
    Set-RegistryValue -Path $adv -Name 'Hidden' -Type DWord -Value 1 -Module 'FixExplorer' -BackupDir $BackupDir
    # 0 = do NOT hide file extensions
    Set-RegistryValue -Path $adv -Name 'HideFileExt' -Type DWord -Value 0 -Module 'FixExplorer' -BackupDir $BackupDir
    # 1 = show protected operating system files
    Set-RegistryValue -Path $adv -Name 'ShowSuperHidden' -Type DWord -Value 1 -Module 'FixExplorer' -BackupDir $BackupDir

    Write-Log '--- verify ---'
    $now = Get-ItemProperty $adv
    Write-Log ("  Hidden={0} HideFileExt={1} ShowSuperHidden={2} (applies to current user; new Explorer windows)" -f `
        $now.Hidden, $now.HideFileExt, $now.ShowSuperHidden)
    Write-Log 'FixExplorer module complete.' 'OK'
}
catch {
    Write-Log "FixExplorer module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode

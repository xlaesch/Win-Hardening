# 03-Lsass.ps1 - protect credential material in LSASS.
# WDigest stores plaintext passwords in memory when enabled (Mimikatz favorite);
# RunAsPPL runs LSASS as a protected process so credential dumpers can't open it.
# Both were in every researched top-team playbook (BYU, Cal Poly Pomona).
# NOTE: RunAsPPL takes effect after the next reboot.
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
$null = Start-RunLog -Name 'lsass' -BackupRoot $BackupRoot
try {
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
        -Name 'UseLogonCredential' -Type DWord -Value 0 -Module 'Lsass' -BackupDir $BackupDir

    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RunAsPPL' -Type DWord -Value 1 -Module 'Lsass' -BackupDir $BackupDir

    # Audit attempts to open LSASS as a protected process (CPP Hard.ps1 parity):
    # AuditLevel=8 raises events 3065/3066 when non-protected code touches LSASS.
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' `
        -Name 'AuditLevel' -Type DWord -Value 8 -Module 'Lsass' -BackupDir $BackupDir

    Write-Log '--- verify ---'
    $wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
    $ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RunAsPPL
    Write-Log ("  WDigest.UseLogonCredential={0} (0 = plaintext logon creds NOT cached)" -f $wdigest)
    Write-Log ("  Lsa.RunAsPPL={0} (effective after next reboot)" -f $ppl)
    Write-Log 'Lsass module complete.' 'OK'
}
catch {
    Write-Log "Lsass module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode

# 08-Uac.ps1 - full UAC and remote-UAC hardening.
# CPP Hard.ps1 parity: EnableLUA + prompt-on-secure-desktop + installer detection,
# plus LocalAccountTokenFilterPolicy=0 which stops pass-the-hash from a NON-admin
# local account getting unfiltered remote admin tokens.
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
$null = Start-RunLog -Name 'uac' -BackupRoot $BackupRoot
try {
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegistryValue -Path $pol -Name 'EnableLUA' -Type DWord -Value 1 -Module 'Uac' -BackupDir $BackupDir
    # 2 = prompt for consent on the secure desktop for admins
    Set-RegistryValue -Path $pol -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 2 -Module 'Uac' -BackupDir $BackupDir
    # 0 = automatically deny elevation requests for standard users
    Set-RegistryValue -Path $pol -Name 'ConsentPromptBehaviorUser' -Type DWord -Value 0 -Module 'Uac' -BackupDir $BackupDir
    Set-RegistryValue -Path $pol -Name 'PromptOnSecureDesktop' -Type DWord -Value 1 -Module 'Uac' -BackupDir $BackupDir
    Set-RegistryValue -Path $pol -Name 'EnableInstallerDetection' -Type DWord -Value 1 -Module 'Uac' -BackupDir $BackupDir
    # 0 = remote UAC filtering stays ON for local accounts (PTH mitigation)
    Set-RegistryValue -Path $pol -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0 -Module 'Uac' -BackupDir $BackupDir

    Write-Log '--- verify ---'
    $now = Get-ItemProperty $pol
    Write-Log ("  EnableLUA={0} AdminPrompt={1} SecureDesktop={2} LocalAccountTokenFilterPolicy={3}" -f `
        $now.EnableLUA, $now.ConsentPromptBehaviorAdmin, $now.PromptOnSecureDesktop, $now.LocalAccountTokenFilterPolicy)
    Write-Log 'Uac module complete.' 'OK'
}
catch {
    Write-Log "Uac module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode

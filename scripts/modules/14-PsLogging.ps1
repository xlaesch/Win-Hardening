# 14-PsLogging.ps1 - full PowerShell telemetry.
# CPP Log.ps1 parity: script block logging (de-obfuscated commands), module
# logging, and transcription. This is how you catch the red team's PowerShell -
# including encoded/obfuscated commands, which appear DECODED in event 4104.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [string]$TranscriptDir = 'C:\ProgramData\Hardening\PSLogs'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'pslogging' -BackupRoot $BackupRoot
try {
    if (-not (Test-Path $TranscriptDir)) {
        New-Item -ItemType Directory -Path $TranscriptDir -Force | Out-Null
    }

    # ---------- script block logging (event 4104, de-obfuscated) ----------
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 -Module 'PsLogging' -BackupDir $BackupDir

    # ---------- module logging (which modules a session imported) ----------
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        -Name 'EnableModuleLogging' -Type DWord -Value 1 -Module 'PsLogging' -BackupDir $BackupDir
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
        -Name '*' -Type String -Value '*' -Module 'PsLogging' -BackupDir $BackupDir

    # ---------- transcription (full over-the-shoulder record) ----------
    # NOTE: CPP writes to the user's Desktop; SYSTEM-run sessions (WinRM) have no
    # useful Desktop, so transcripts go to a stable ProgramData path instead.
    $tr = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    Set-RegistryValue -Path $tr -Name 'EnableTranscripting' -Type DWord -Value 1 -Module 'PsLogging' -BackupDir $BackupDir
    Set-RegistryValue -Path $tr -Name 'EnableInvocationHeader' -Type DWord -Value 1 -Module 'PsLogging' -BackupDir $BackupDir
    Set-RegistryValue -Path $tr -Name 'OutputDirectory' -Type String -Value $TranscriptDir -Module 'PsLogging' -BackupDir $BackupDir

    Write-Log '--- verify ---'
    $sb = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    $ml = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging
    $trn = (Get-ItemProperty $tr -ErrorAction SilentlyContinue).EnableTranscripting
    Write-Log ("  ScriptBlockLogging={0} ModuleLogging={1} Transcription={2} -> {3}" -f $sb, $ml, $trn, $TranscriptDir)
    Write-Log 'PsLogging module complete. Effective for NEW PowerShell sessions.' 'OK'
}
catch {
    Write-Log "PsLogging module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode

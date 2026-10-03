# 19-AccessInsurance.ps1 - CPP's emergency-access trick, OPT-IN.
# CPP Hard.ps1 replaces Narrator.exe with cmd.exe (plus a Defender exclusion):
# from the RDP logon screen, Windows Key+U then Narrator drops a SYSTEM cmd -
# insurance against the red team locking the team out of its own box.
#
# THIS IS A DELIBERATE BACKDOOR. It must be a conscious team decision:
#   - it does not run under -All (requires -AcceptRisk)
#   - it survives Invoke-Restore only until the gold snapshot is reverted
#   - disclose it in your incident documentation if organizers ask
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$AcceptRisk    # required; without it the module explains and exits
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'accessins' -BackupRoot $BackupRoot
try {
    if (-not $AcceptRisk) {
        Write-Log 'AccessInsurance SKIPPED: pass -AcceptRisk to arm the Utilman/Narrator emergency console.' 'WARN'
        Write-Log 'Usage: RDP logon screen -> Ease of Access (Utilman) or Win+U -> Narrator -> SYSTEM cmd.' 'WARN'
        exit 0
    }

    # The RDP logon screen's Ease-of-Access launches these accessibility binaries
    # as SYSTEM; swapping one for cmd.exe yields an unauthenticated-feeling
    # SYSTEM console for the team. Narrator is the CPP choice.
    foreach ($target in 'Narrator.exe', 'Utilman.exe', 'Sethc.exe') {
        $path = "C:\Windows\System32\$target"
        if (-not (Test-Path $path)) { Write-Log "$target not present" 'WARN'; continue }
        $existing = Get-Item $path
        $isCmd = ($existing.Length -eq (Get-Item 'C:\Windows\System32\cmd.exe').Length)
        if ($isCmd) { Write-Log "$target already swapped" 'OK'; continue }

        if ($PSCmdlet.ShouldProcess($path, 'replace with cmd.exe (EMERGENCY BACKDOOR)')) {
            # Keep a pristine copy for restore.
            $keepDir = Join-Path $BackupDir 'state\access-binary-backups'
            New-Item -ItemType Directory -Path $keepDir -Force | Out-Null
            Copy-Item $path (Join-Path $keepDir $target) -Force
            # Defender would instantly remove the swapped binary otherwise.
            Add-MpPreference -ExclusionProcess $path -ErrorAction SilentlyContinue
            & takeown.exe /f $path | Out-Null
            & icacls.exe $path /grant 'Administrators:F' | Out-Null
            Copy-Item 'C:\Windows\System32\cmd.exe' $path -Force
            Write-Log "$target replaced with cmd.exe (backup in preflight state\access-binary-backups)" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'AccessInsurance' -Action 'SwapAccessBinary' `
                -Target $path -NewValue 'cmd.exe copy' -OldValue 'original (backed up)'
        }
    }
    Write-Log 'AccessInsurance armed. Document this in the team runbook; remove after the event.' 'WARN'
    Write-Log 'AccessInsurance module complete.' 'OK'
}
catch {
    Write-Log "AccessInsurance module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode

# 13-Gpo.ps1 - neutralize inherited group policy.
# CPP Gpo.ps1 + Fix.ps1 parity. On DCs: set every GPO to AllSettingsDisabled
# (kills red-team-planted or weak inherited policy domain-wide). On members:
# back up and reset the LOCAL group policy cache (C:\Windows\System32\GroupPolicy*).
# Original states are recorded in the change log for restore.
# CAUTION on DCs: this also disables Default Domain Policy/Domain Controllers
# Policy enforcement until you rebuild policy deliberately - that is the point.
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
$null = Start-RunLog -Name 'gpo' -BackupRoot $BackupRoot
try {
    $isDC = Test-IsDomainController

    if ($isDC -and (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        # ---------- DC: disable every GPO ----------
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop
        $gpos = Get-GPO -All
        foreach ($gpo in $gpos) {
            if ($gpo.GpoStatus -ne 'AllSettingsDisabled') {
                if ($PSCmdlet.ShouldProcess("GPO '$($gpo.DisplayName)'", 'set AllSettingsDisabled')) {
                    $orig = $gpo.GpoStatus
                    # GPMGMT COM writes are denied over WinRM network logons (E_ACCESSDENIED);
                    # GPO status is the AD 'flags' attribute on the groupPolicyContainer, and a
                    # plain LDAP write works remotely. 3 = user+computer settings disabled.
                    $adObj = Get-ADObject -Identity $gpo.Path -Properties flags
                    $origFlags = [int]($adObj.flags)
                    Set-ADObject -Identity $gpo.Path -Replace @{ flags = 3 }
                    Write-Log "GPO '$($gpo.DisplayName)' disabled (was $orig, flags $origFlags -> 3)" 'CHANGE'
                    Add-ChangeRecord -BackupDir $BackupDir -Module 'Gpo' -Action 'DisableGpo' `
                        -Target $gpo.DisplayName -NewValue '3' -OldValue "$origFlags"
                }
            }
            else { Write-Log "GPO '$($gpo.DisplayName)' already disabled" 'OK' }
        }
    }
    elseif ($isDC) {
        Write-Log 'DC without GroupPolicy module (RSAT?) - skipping GPO disable' 'WARN'
    }
    else {
        # ---------- Member: reset local GPO cache (CPP Fix.ps1 parity) ----------
        $targets = 'C:\Windows\System32\GroupPolicy', 'C:\Windows\System32\GroupPolicyUser'
        $hadAny = $false
        foreach ($t in $targets) {
            if (Test-Path $t) {
                $hadAny = $true
                if ($PSCmdlet.ShouldProcess($t, 'reset local group policy cache')) {
                    Remove-Item $t -Recurse -Force
                    Write-Log "Reset $t (backup in preflight state\local-gpo)" 'CHANGE'
                    Add-ChangeRecord -BackupDir $BackupDir -Module 'Gpo' -Action 'ResetLocalGpo' -Target $t
                }
            }
        }
        if (-not $hadAny) { Write-Log 'No local GPO cache present' 'OK' }
        if ($hadAny -or $PSCmdlet.ShouldProcess('group policy', 'gpupdate /force')) {
            & gpupdate.exe /force | Out-Null
            Write-Log 'gpupdate /force completed' 'CHANGE'
        }
    }

    Write-Log 'Gpo module complete.' 'OK'
}
catch {
    Write-Log "Gpo module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
